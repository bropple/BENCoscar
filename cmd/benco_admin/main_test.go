package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withPipedStdin replaces the shared stdin reader with fixed content and makes
// the tool believe stdin is a pipe, exercising the scripted (non-terminal) path.
func withPipedStdin(t *testing.T, content string) {
	t.Helper()

	restoreReader := stdin
	stdin = bufio.NewReader(strings.NewReader(content))
	t.Cleanup(func() { stdin = restoreReader })

	restoreTerm := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = restoreTerm })
}

// silenceStdout swallows the tool's human-facing output during a test. Several
// commands print to os.Stdout directly (a generated password, for one), and a
// test run should not scatter that across the report.
func silenceStdout(t *testing.T) {
	t.Helper()

	restore := os.Stdout
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	os.Stdout = devNull
	t.Cleanup(func() {
		os.Stdout = restore
		_ = devNull.Close()
	})
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantOpts       commonOpts
		wantPositional []string
		wantErr        string
	}{
		{
			name:     "defaults to the loopback management API",
			args:     nil,
			wantOpts: commonOpts{api: defaultAPIAddr},
		},
		{
			name:           "positional argument only",
			args:           []string{"chattingchuck"},
			wantOpts:       commonOpts{api: defaultAPIAddr},
			wantPositional: []string{"chattingchuck"},
		},
		{
			name:           "flags may follow the positional argument",
			args:           []string{"chattingchuck", "--yes"},
			wantOpts:       commonOpts{api: defaultAPIAddr, yes: true},
			wantPositional: []string{"chattingchuck"},
		},
		{
			name:           "flags may precede the positional argument",
			args:           []string{"--yes", "chattingchuck"},
			wantOpts:       commonOpts{api: defaultAPIAddr, yes: true},
			wantPositional: []string{"chattingchuck"},
		},
		{
			name:     "api address as a separate value",
			args:     []string{"--api", "10.0.0.1:9999"},
			wantOpts: commonOpts{api: "10.0.0.1:9999"},
		},
		{
			name:     "api address in --flag=value form",
			args:     []string{"--api=10.0.0.1:9999"},
			wantOpts: commonOpts{api: "10.0.0.1:9999"},
		},
		{
			name:     "token file",
			args:     []string{"--token-file", "/etc/benco/token"},
			wantOpts: commonOpts{api: defaultAPIAddr, tokenFile: "/etc/benco/token"},
		},
		{
			name:     "generate and yes together",
			args:     []string{"--generate", "--yes"},
			wantOpts: commonOpts{api: defaultAPIAddr, generate: true, yes: true},
		},
		{
			name:     "-y is accepted as shorthand for --yes",
			args:     []string{"-y"},
			wantOpts: commonOpts{api: defaultAPIAddr, yes: true},
		},
		{
			name:    "--api without a value",
			args:    []string{"--api"},
			wantErr: "--api requires a value",
		},
		{
			name:    "--token-file without a value",
			args:    []string{"--token-file"},
			wantErr: "--token-file requires a value",
		},
		{
			name:    "unknown flag",
			args:    []string{"--nope"},
			wantErr: "unknown flag: --nope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, positional, err := parseArgs(tt.args)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantOpts, opts)
			assert.Equal(t, tt.wantPositional, positional)
		})
	}
}

// TestParseArgsRejectsSecretsInArgv is the regression guard for the rule this
// tool exists to enforce. If a --password flag is ever added, this fails.
func TestParseArgsRejectsSecretsInArgv(t *testing.T) {
	for _, flag := range []string{"--password", "-p", "--pass", "--token", "--api-token"} {
		t.Run(flag, func(t *testing.T) {
			_, _, err := parseArgs([]string{flag, "hunter2hunter2"})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not a valid flag")
			// The explanation must say why, since the absence looks like an
			// oversight to anyone who does not know the reason.
			assert.Contains(t, err.Error(), "shell history")
		})
	}

	t.Run("also rejected in --flag=value form", func(t *testing.T) {
		_, _, err := parseArgs([]string{"--password=hunter2hunter2"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a valid flag")
	})
}

// capturedRequest records what the client actually put on the wire.
type capturedRequest struct {
	method string
	path   string
	auth   string
	body   []byte
}

// newTestServer returns an httptest server that records requests and replies
// with the supplied status and body.
func newTestServer(t *testing.T, status int, body string, captured *capturedRequest) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if captured != nil {
			captured.method = r.Method
			captured.path = r.URL.Path
			captured.auth = r.Header.Get("Authorization")
			captured.body = b
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestNewAPIClientNormalisesAddress(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"http://127.0.0.1:8080/", "http://127.0.0.1:8080"},
		{"https://oscar.example:443", "https://oscar.example:443"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, newAPIClient(tt.addr, "").baseURL)
	}
}

func TestAddUserRequestConstruction(t *testing.T) {
	var got capturedRequest
	srv := newTestServer(t, http.StatusCreated, "", &got)

	c := newAPIClient(srv.URL, "")
	require.NoError(t, c.addUser(context.Background(), "chattingchuck", "hunter2hunter2"))

	assert.Equal(t, http.MethodPost, got.method)
	assert.Equal(t, "/user", got.path)

	var body userWithPassword
	require.NoError(t, json.Unmarshal(got.body, &body))
	assert.Equal(t, "chattingchuck", body.ScreenName)
	assert.Equal(t, "hunter2hunter2", body.Password)
}

func TestSetPasswordRequestConstruction(t *testing.T) {
	var got capturedRequest
	srv := newTestServer(t, http.StatusNoContent, "", &got)

	c := newAPIClient(srv.URL, "")
	require.NoError(t, c.setPassword(context.Background(), "chattingchuck", "hunter2hunter2"))

	assert.Equal(t, http.MethodPut, got.method)
	assert.Equal(t, "/user/password", got.path)

	var body userWithPassword
	require.NoError(t, json.Unmarshal(got.body, &body))
	assert.Equal(t, "chattingchuck", body.ScreenName)
	assert.Equal(t, "hunter2hunter2", body.Password)
}

// TestDeleteUserOmitsPassword pins the omitempty on userWithPassword.Password:
// a delete has no password and must not serialise an empty one.
func TestDeleteUserOmitsPassword(t *testing.T) {
	var got capturedRequest
	srv := newTestServer(t, http.StatusNoContent, "", &got)

	c := newAPIClient(srv.URL, "")
	require.NoError(t, c.deleteUser(context.Background(), "chattingchuck"))

	assert.Equal(t, http.MethodDelete, got.method)
	assert.Equal(t, "/user", got.path)
	assert.NotContains(t, string(got.body), "password")
}

func TestKickSessionRequestConstruction(t *testing.T) {
	var got capturedRequest
	srv := newTestServer(t, http.StatusNoContent, "", &got)

	c := newAPIClient(srv.URL, "")
	require.NoError(t, c.kickSession(context.Background(), "chatting chuck"))

	assert.Equal(t, http.MethodDelete, got.method)
	// The screen name is path-escaped, so a name with a space does not produce
	// a malformed request line.
	assert.Equal(t, "/session/chatting chuck", got.path)
}

func TestDeletePublicRoomRequestConstruction(t *testing.T) {
	var got capturedRequest
	srv := newTestServer(t, http.StatusNoContent, "", &got)

	c := newAPIClient(srv.URL, "")
	require.NoError(t, c.deletePublicRoom(context.Background(), "Office Hijinks"))

	assert.Equal(t, http.MethodDelete, got.method)
	assert.Equal(t, "/chat/room/public", got.path)

	var body chatRoomDelete
	require.NoError(t, json.Unmarshal(got.body, &body))
	assert.Equal(t, []string{"Office Hijinks"}, body.Names)
}

func TestTokenIsSentAsBearerHeader(t *testing.T) {
	var got capturedRequest
	srv := newTestServer(t, http.StatusOK, "[]", &got)

	c := newAPIClient(srv.URL, "s3cret-token")
	_, err := c.listUsers(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "Bearer s3cret-token", got.auth)
}

func TestNoAuthHeaderWhenTokenAbsent(t *testing.T) {
	var got capturedRequest
	srv := newTestServer(t, http.StatusOK, "[]", &got)

	c := newAPIClient(srv.URL, "")
	_, err := c.listUsers(context.Background())
	require.NoError(t, err)

	assert.Empty(t, got.auth)
}

// TestServerErrorMessageIsSurfaced covers both error shapes the management API
// emits: bare text from http.Error and JSON from errorMsg.
func TestServerErrorMessageIsSurfaced(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{
			name:   "plain text from http.Error",
			status: http.StatusConflict,
			body:   "user already exists\n",
			want:   "user already exists",
		},
		{
			name:   "JSON from errorMsg",
			status: http.StatusNotFound,
			body:   `{"message":"session not found"}`,
			want:   "session not found",
		},
		{
			name:   "invalid password is reported verbatim",
			status: http.StatusBadRequest,
			body:   "invalid password: invalid password length: password length must be between 8-128 characters\n",
			want:   "password length must be between 8-128 characters",
		},
		{
			name:   "empty body falls back to the status text",
			status: http.StatusInternalServerError,
			body:   "",
			want:   "500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t, tt.status, tt.body, nil)

			c := newAPIClient(srv.URL, "")
			err := c.addUser(context.Background(), "chattingchuck", "hunter2hunter2")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)

			var apiErr *apiError
			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, tt.status, apiErr.StatusCode)
		})
	}
}

func TestUserListOutput(t *testing.T) {
	body := `[
		{"id":"chattingchuck","screen_name":"chattingchuck","is_icq":false,"suspended_status":"","is_bot":false},
		{"id":"100000","screen_name":"100000","is_icq":true,"suspended_status":"suspended","is_bot":false},
		{"id":"rtriy","screen_name":"rtriy","is_icq":false,"suspended_status":"","is_bot":true}
	]`
	srv := newTestServer(t, http.StatusOK, body, nil)

	out := &bytes.Buffer{}
	require.NoError(t, userList(commonOpts{api: srv.URL}, out))

	got := out.String()
	assert.Contains(t, got, "SCREEN NAME")
	assert.Contains(t, got, "chattingchuck")
	// An unsuspended account reads as "active" rather than as an empty column.
	assert.Contains(t, got, "active")
	assert.Contains(t, got, "suspended")
	assert.Contains(t, got, "ICQ")
	assert.Contains(t, got, "AIM")
}

func TestUserListEmpty(t *testing.T) {
	srv := newTestServer(t, http.StatusOK, "[]", nil)

	out := &bytes.Buffer{}
	require.NoError(t, userList(commonOpts{api: srv.URL}, out))
	assert.Contains(t, out.String(), "No accounts.")
}

func TestSessionListOutput(t *testing.T) {
	body := `{"count":1,"sessions":[
		{"id":"chattingchuck","screen_name":"chattingchuck","online_seconds":3720,
		 "is_away":true,"away_message":"brb","idle_seconds":90,"is_invisible":false,
		 "is_icq":false,"instance_count":2}
	]}`
	srv := newTestServer(t, http.StatusOK, body, nil)

	out := &bytes.Buffer{}
	require.NoError(t, sessionList(commonOpts{api: srv.URL}, out))

	got := out.String()
	assert.Contains(t, got, "chattingchuck")
	assert.Contains(t, got, "1h2m")
	assert.Contains(t, got, "away")
}

func TestSessionListEmpty(t *testing.T) {
	srv := newTestServer(t, http.StatusOK, `{"count":0,"sessions":[]}`, nil)

	out := &bytes.Buffer{}
	require.NoError(t, sessionList(commonOpts{api: srv.URL}, out))
	assert.Contains(t, out.String(), "Nobody is online.")
}

func TestHumanDuration(t *testing.T) {
	tests := []struct {
		seconds int
		want    string
	}{
		{0, "-"},
		{-1, "-"},
		{45, "45s"},
		{90, "1m"},
		{3720, "1h2m"},
		{90000, "1d1h"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, humanDuration(tt.seconds), "humanDuration(%d)", tt.seconds)
	}
}

func TestPresence(t *testing.T) {
	assert.Equal(t, "online", presence(sessionHandle{}))
	assert.Equal(t, "away", presence(sessionHandle{IsAway: true}))
	assert.Equal(t, "invisible", presence(sessionHandle{IsInvisible: true}))
	assert.Equal(t, "away+invisible", presence(sessionHandle{IsAway: true, IsInvisible: true}))
}

// roomServer serves the two chat room endpoints, since room commands consult
// both exchanges.
func roomServer(t *testing.T, public string, private string, captured *capturedRequest) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			b, _ := io.ReadAll(r.Body)
			if captured != nil {
				captured.method = r.Method
				captured.path = r.URL.Path
				captured.body = b
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		switch r.URL.Path {
		case "/chat/room/public":
			_, _ = io.WriteString(w, public)
		case "/chat/room/private":
			_, _ = io.WriteString(w, private)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRoomListOutput(t *testing.T) {
	public := `[{"name":"Office Hijinks","create_time":"2026-07-01T00:00:00Z","url":"aim:gochat?roomname=Office+Hijinks&exchange=5","participants":[{"id":"a","screen_name":"a"}]}]`
	private := `[{"name":"Secret Den","create_time":"2026-07-02T00:00:00Z","creator_id":"chattingchuck","url":"aim:gochat?roomname=Secret+Den&exchange=4","participants":[]}]`
	srv := roomServer(t, public, private, nil)

	out := &bytes.Buffer{}
	require.NoError(t, roomList(commonOpts{api: srv.URL}, out))

	got := out.String()
	assert.Contains(t, got, "Office Hijinks")
	assert.Contains(t, got, "public")
	assert.Contains(t, got, "Secret Den")
	assert.Contains(t, got, "private")
	assert.Contains(t, got, "chattingchuck")
}

func TestRoomListEmpty(t *testing.T) {
	srv := roomServer(t, "[]", "[]", nil)

	out := &bytes.Buffer{}
	require.NoError(t, roomList(commonOpts{api: srv.URL}, out))
	assert.Contains(t, out.String(), "No chat rooms.")
}

// TestRoomRmPrivateRoomExplains covers the requirement that a private room
// removal says plainly that it cannot be done, rather than failing silently or
// pretending to have worked.
func TestRoomRmPrivateRoomExplains(t *testing.T) {
	private := `[{"name":"Secret Den","create_time":"2026-07-02T00:00:00Z","url":"","participants":[]}]`
	var got capturedRequest
	srv := roomServer(t, "[]", private, &got)

	err := roomRm(commonOpts{api: srv.URL, yes: true}, "Secret Den")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private chat room")
	assert.Contains(t, err.Error(), "management API cannot delete it")

	// Crucially, no DELETE was attempted: issuing one against the public
	// exchange would have returned 204 and changed nothing.
	assert.Empty(t, got.method)
}

func TestRoomRmPublicRoom(t *testing.T) {
	public := `[{"name":"Office Hijinks","create_time":"2026-07-01T00:00:00Z","url":"","participants":[]}]`
	var got capturedRequest
	srv := roomServer(t, public, "[]", &got)

	require.NoError(t, roomRm(commonOpts{api: srv.URL, yes: true}, "Office Hijinks"))

	assert.Equal(t, http.MethodDelete, got.method)
	var body chatRoomDelete
	require.NoError(t, json.Unmarshal(got.body, &body))
	assert.Equal(t, []string{"Office Hijinks"}, body.Names)
}

func TestRoomRmUnknownRoom(t *testing.T) {
	srv := roomServer(t, "[]", "[]", nil)

	err := roomRm(commonOpts{api: srv.URL, yes: true}, "Nowhere")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `no public chat room named "Nowhere"`)
}

// TestConfirmRefusesWithoutTerminal pins the safe default: a script that forgot
// --yes must stop rather than have EOF read as consent.
func TestConfirmRefusesWithoutTerminal(t *testing.T) {
	withPipedStdin(t, "")

	err := confirm("This will delete everything.", commonOpts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a terminal")
	assert.Contains(t, err.Error(), "--yes")
}

func TestConfirmSkippedWithYes(t *testing.T) {
	withPipedStdin(t, "")
	assert.NoError(t, confirm("This will delete everything.", commonOpts{yes: true}))
}

func TestConfirmAcceptsYesOnTerminal(t *testing.T) {
	withPipedStdin(t, "yes\n")
	stdinIsTerminal = func() bool { return true }

	assert.NoError(t, confirm("This will delete everything.", commonOpts{}))
}

func TestConfirmRejectsAnythingButYes(t *testing.T) {
	for _, answer := range []string{"y\n", "no\n", "YES\n", "\n"} {
		withPipedStdin(t, answer)
		stdinIsTerminal = func() bool { return true }

		err := confirm("This will delete everything.", commonOpts{})
		require.Error(t, err, "answer %q should not confirm", answer)
		assert.Contains(t, err.Error(), "aborted")
	}
}

// TestUserRmConfirmationGuardsTheRequest checks that a declined confirmation
// stops before anything is sent.
func TestUserRmConfirmationGuardsTheRequest(t *testing.T) {
	var got capturedRequest
	srv := newTestServer(t, http.StatusNoContent, "", &got)

	withPipedStdin(t, "no\n")
	stdinIsTerminal = func() bool { return true }

	err := userRm(commonOpts{api: srv.URL}, "chattingchuck")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aborted")
	assert.Empty(t, got.method, "no request should be sent when confirmation is declined")
}

// TestUserAddGeneratedPasswordIsSent checks the --generate path end to end: the
// password that reaches the server is the generated one, and it is valid.
func TestUserAddGeneratedPasswordIsSent(t *testing.T) {
	silenceStdout(t)

	var got capturedRequest
	srv := newTestServer(t, http.StatusCreated, "", &got)

	require.NoError(t, userAdd(commonOpts{api: srv.URL, generate: true}, "chattingchuck"))

	var body userWithPassword
	require.NoError(t, json.Unmarshal(got.body, &body))
	assert.Equal(t, "chattingchuck", body.ScreenName)
	assert.NoError(t, validatePassword("chattingchuck", body.Password))
	assert.Len(t, strings.Split(body.Password, groupSeparator), genAIMSymbols/genGroupSize)
}

// TestUserAddRejectsShortPasswordLocally checks that a password too short for
// the server is refused before any request is made, so the operator gets an
// immediate answer rather than a round trip.
func TestUserAddRejectsShortPasswordLocally(t *testing.T) {
	var got capturedRequest
	srv := newTestServer(t, http.StatusCreated, "", &got)

	withPipedStdin(t, "short\n")

	err := userAdd(commonOpts{api: srv.URL}, "chattingchuck")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "between 8 and 128")
	assert.Empty(t, got.method, "no request should be sent for a locally invalid password")
}

func TestRunUnknownGroup(t *testing.T) {
	err := run([]string{"bogus"}, io.Discard)
	assert.ErrorIs(t, err, errUsage)
}

func TestRunNoArgs(t *testing.T) {
	err := run(nil, io.Discard)
	assert.ErrorIs(t, err, errUsage)
}

func TestRunHelp(t *testing.T) {
	assert.NoError(t, run([]string{"help"}, io.Discard))
}

func TestUnknownSubcommands(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"user", "bogus"}, "unknown user command"},
		{[]string{"session", "bogus"}, "unknown session command"},
		{[]string{"room", "bogus"}, "unknown room command"},
	}
	for _, tt := range tests {
		err := run(tt.args, io.Discard)
		require.Error(t, err)
		assert.Contains(t, err.Error(), tt.want)
	}
}

func TestCommandsRequireTheirArgument(t *testing.T) {
	tests := [][]string{
		{"user", "add"},
		{"user", "passwd"},
		{"user", "rm"},
		{"session", "kick"},
		{"room", "rm"},
	}
	for _, args := range tests {
		err := run(args, io.Discard)
		require.Error(t, err, "%v", args)
		assert.Contains(t, err.Error(), "usage:")
	}
}
