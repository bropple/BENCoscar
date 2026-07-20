package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// defaultAPIAddr mirrors config.APIListener's default in config/config.go.
//
// The management API binds to loopback because it has no authentication of its
// own (see the note in printUsage). Defaulting the client to loopback keeps the
// common case -- running on the server, or through an SSH tunnel -- a no-op, and
// makes talking to anything else an explicit, visible choice.
const defaultAPIAddr = "127.0.0.1:8080"

// requestTimeout is generous because account creation runs argon2id server-side,
// which deliberately costs ~19 MiB and real milliseconds per hash.
const requestTimeout = 30 * time.Second

type apiClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func newAPIClient(addr string, token string) *apiClient {
	base := strings.TrimSpace(addr)
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	return &apiClient{
		baseURL: strings.TrimSuffix(base, "/"),
		token:   token,
		http:    &http.Client{Timeout: requestTimeout},
	}
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
		return fmt.Errorf("contacting management API at %s: %w", c.baseURL, err)
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
