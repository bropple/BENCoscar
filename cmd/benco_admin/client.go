package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// defaultAPIAddr mirrors config.APIListener's default in config/config.go.
//
// A unix socket rather than a loopback port, because the socket is what
// authenticates the management API: it lives in a directory only the admin
// group can traverse, so the kernel refuses everyone else before the server
// reads a byte. There is no token in this scheme -- membership of the group IS
// the credential.
const defaultAPIAddr = "unix:/run/bencoscar/mgmt.sock"

// unixPrefix marks an --api value as a socket path rather than a host:port.
const unixPrefix = "unix:"

// unixHostPlaceholder stands in for the host in URLs sent over a unix socket. A
// unix connection has no hostname, but net/http still needs a syntactically
// valid URL and puts the value in the Host header, so it has to be something
// stable and self-evidently not a real name.
const unixHostPlaceholder = "bencoscar-mgmt.invalid"

// requestTimeout is generous because account creation runs argon2id server-side,
// which deliberately costs ~19 MiB and real milliseconds per hash.
const requestTimeout = 30 * time.Second

type apiClient struct {
	baseURL string
	token   string
	// socketPath is set when talking over a unix socket, and is used to explain
	// a permission failure in terms of the socket rather than of a URL.
	socketPath string
	http       *http.Client
}

func newAPIClient(addr string, token string) *apiClient {
	base := strings.TrimSpace(addr)

	if path, ok := unixSocketPath(base); ok {
		return &apiClient{
			// The path travels in the transport's dialer, not in the URL.
			baseURL:    "http://" + unixHostPlaceholder,
			token:      token,
			socketPath: path,
			http: &http.Client{
				Timeout: requestTimeout,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						var d net.Dialer
						return d.DialContext(ctx, "unix", path)
					},
				},
			},
		}
	}

	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	return &apiClient{
		baseURL: strings.TrimSuffix(base, "/"),
		token:   token,
		http:    &http.Client{Timeout: requestTimeout},
	}
}

// unixSocketPath recognises the unix: form of an --api value, tolerating the
// unix:// spelling for anyone who reaches for URL syntax out of habit.
func unixSocketPath(addr string) (string, bool) {
	if !strings.HasPrefix(addr, unixPrefix) {
		return "", false
	}
	path := strings.TrimPrefix(strings.TrimPrefix(addr, unixPrefix), "//")
	if path == "" {
		return "", false
	}
	return path, true
}

// connectionError explains a transport failure in terms of the thing the
// operator configured. Over a unix socket the two failures worth telling apart
// are "the server is not running" and "you may not open this socket", which the
// stdlib renders as near-identical noise wrapped around a URL that is not even
// a real address.
func (c *apiClient) connectionError(err error) error {
	if c.socketPath == "" {
		return fmt.Errorf("contacting management API at %s: %w", c.baseURL, err)
	}
	if isPermissionDenied(err) {
		return notInGroupError(c.socketPath, adminGroupName())
	}
	if errors.Is(err, fs.ErrNotExist) {
		// A missing socket does NOT mean a dead server, and saying so sends
		// someone to `systemctl status` for a service that is running perfectly.
		// The likelier cause by far is a server on a TCP listener -- which every
		// deployment is until API_LISTENER is switched over, so this is the first
		// thing a fresh install hits.
		return fmt.Errorf("no management socket at %s.\n"+
			"  The server is most likely listening on TCP instead, which is the default\n"+
			"  until API_LISTENER is changed. Point at it:\n"+
			"\tbenco_admin <command> --api 127.0.0.1:8080\n"+
			"  If it should be on a socket, check API_LISTENER in the server's environment,\n"+
			"  and `systemctl status bencoscar` to confirm the service is up", c.socketPath)
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("the management socket %s exists but nothing is listening on it, which usually "+
			"means the server stopped without cleaning up. Check `systemctl status bencoscar`", c.socketPath)
	}
	return fmt.Errorf("contacting management API over %s: %w", c.socketPath, err)
}

// apiError carries the server's own message rather than a generic one, so an
// operator sees "user already exists" instead of "request failed: 409".
type apiError struct {
	StatusCode int
	Message    string
}

func (e *apiError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("server returned %d %s", e.StatusCode, http.StatusText(e.StatusCode))
	}
	return fmt.Sprintf("server returned %d: %s", e.StatusCode, e.Message)
}

// do issues a request against the management API. reqBody, if non-nil, is sent
// as JSON; out, if non-nil, receives the decoded JSON response.
func (c *apiClient) do(ctx context.Context, method string, path string, reqBody any, out any) error {
	var body io.Reader
	if reqBody != nil {
		buf := &bytes.Buffer{}
		if err := json.NewEncoder(buf).Encode(reqBody); err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		body = buf
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		// BENCoscar itself does not check this header -- the management API has
		// no authentication. It is sent for deployments that put an
		// authenticating reverse proxy in front of the API, which is the only
		// way this API is safe to expose beyond loopback today.
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return c.connectionError(err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &apiError{StatusCode: resp.StatusCode, Message: serverMessage(respBody)}
	}

	if out == nil || len(bytes.TrimSpace(respBody)) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

// serverMessage extracts the human-readable error the server sent. The
// management API is inconsistent about this: most handlers use http.Error (bare
// text), while the newer ones use errorMsg (JSON {"message": ...}). Handle both
// rather than showing an operator a raw JSON blob.
func serverMessage(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return ""
	}
	var msg struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(trimmed), &msg); err == nil && msg.Message != "" {
		return msg.Message
	}
	return trimmed
}

// Response shapes below mirror server/http/types.go. They are duplicated rather
// than imported because those types are unexported -- and because a client that
// pins the field names it relies on will fail loudly if the API changes shape,
// instead of silently decoding into zero values.

type userHandle struct {
	ID              string `json:"id"`
	ScreenName      string `json:"screen_name"`
	IsICQ           bool   `json:"is_icq"`
	SuspendedStatus string `json:"suspended_status"`
	IsBot           bool   `json:"is_bot"`
}

type sessionHandle struct {
	ID            string `json:"id"`
	ScreenName    string `json:"screen_name"`
	OnlineSeconds int    `json:"online_seconds"`
	IsAway        bool   `json:"is_away"`
	AwayMessage   string `json:"away_message"`
	IdleSeconds   int    `json:"idle_seconds"`
	IsInvisible   bool   `json:"is_invisible"`
	IsICQ         bool   `json:"is_icq"`
	InstanceCount int    `json:"instance_count"`
}

type onlineUsers struct {
	Count    int             `json:"count"`
	Sessions []sessionHandle `json:"sessions"`
}

type chatUserHandle struct {
	ID         string `json:"id"`
	ScreenName string `json:"screen_name"`
}

type chatRoom struct {
	Name         string           `json:"name"`
	CreateTime   time.Time        `json:"create_time"`
	CreatorID    string           `json:"creator_id,omitempty"`
	URL          string           `json:"url"`
	Participants []chatUserHandle `json:"participants"`
}

// userWithPassword is the request body for POST /user, DELETE /user and
// PUT /user/password. Password is omitempty so a delete never serialises an
// empty password field.
type userWithPassword struct {
	ScreenName string `json:"screen_name"`
	Password   string `json:"password,omitempty"`
}

type chatRoomDelete struct {
	Names []string `json:"names"`
}

func (c *apiClient) listUsers(ctx context.Context) ([]userHandle, error) {
	var users []userHandle
	err := c.do(ctx, http.MethodGet, "/user", nil, &users)
	return users, err
}

func (c *apiClient) addUser(ctx context.Context, screenName string, password string) error {
	return c.do(ctx, http.MethodPost, "/user",
		userWithPassword{ScreenName: screenName, Password: password}, nil)
}

func (c *apiClient) setPassword(ctx context.Context, screenName string, password string) error {
	return c.do(ctx, http.MethodPut, "/user/password",
		userWithPassword{ScreenName: screenName, Password: password}, nil)
}

func (c *apiClient) deleteUser(ctx context.Context, screenName string) error {
	return c.do(ctx, http.MethodDelete, "/user",
		userWithPassword{ScreenName: screenName}, nil)
}

// clearKeyDirectory resets an account's encryption identity: it clears the
// device manifest AND the identity backup, returning the account to the
// zero-device state where password auth stands alone. This is the documented
// recovery for an account that has lost access to all its devices.
func (c *apiClient) clearKeyDirectory(ctx context.Context, screenName string) error {
	return c.do(ctx, http.MethodDelete, "/user/"+urlPathEscape(screenName)+"/keydir", nil, nil)
}

func (c *apiClient) listSessions(ctx context.Context) (onlineUsers, error) {
	var out onlineUsers
	err := c.do(ctx, http.MethodGet, "/session", nil, &out)
	return out, err
}

// session looks up a single session so a kick can name exactly what it is about
// to disconnect before asking for confirmation.
func (c *apiClient) session(ctx context.Context, screenName string) (onlineUsers, error) {
	var out onlineUsers
	err := c.do(ctx, http.MethodGet, "/session/"+urlPathEscape(screenName), nil, &out)
	return out, err
}

func (c *apiClient) kickSession(ctx context.Context, screenName string) error {
	return c.do(ctx, http.MethodDelete, "/session/"+urlPathEscape(screenName), nil, nil)
}

func (c *apiClient) listRooms(ctx context.Context, exchange string) ([]chatRoom, error) {
	var rooms []chatRoom
	err := c.do(ctx, http.MethodGet, "/chat/room/"+exchange, nil, &rooms)
	return rooms, err
}

func (c *apiClient) deletePublicRoom(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/chat/room/public",
		chatRoomDelete{Names: []string{name}}, nil)
}
