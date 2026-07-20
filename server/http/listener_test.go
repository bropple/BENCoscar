package http

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mk6i/open-oscar-server/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func mustParse(t *testing.T, raw string) config.APIListenerSpec {
	t.Helper()
	spec, err := config.ParseAPIListener(raw)
	if err != nil {
		t.Fatalf("ParseAPIListener(%q): %v", raw, err)
	}
	return spec
}

// TestListenUnixServesRequests is the end-to-end check that the socket is a
// working transport, not just a file: bind it, serve a handler on it, and make
// a real HTTP request through it with a client that dials the path.
func TestListenUnixServesRequests(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "sub", "mgmt.sock")

	ln, err := listen(mustParse(t, "unix:"+sock), config.APIConfig{}, discardLogger())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "hello from "+r.URL.Path)
		}),
		ConnContext: connContext,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}

	resp, err := client.Get("http://mgmt.invalid/user")
	if err != nil {
		t.Fatalf("request over unix socket: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if got, want := string(body), "hello from /user"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// TestListenUnixPermissions pins the two modes the scheme depends on. The
// directory mode is the one that actually matters -- see the comment on
// socketMode for why the socket's own mode cannot be relied on alone -- so a
// change to either should have to be deliberate.
func TestListenUnixPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	sock := filepath.Join(dir, "mgmt.sock")

	ln, err := listen(mustParse(t, "unix:"+sock), config.APIConfig{}, discardLogger())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat socket directory: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != socketDirMode {
		t.Errorf("socket directory mode = %#o, want %#o -- this is the permission that "+
			"substitutes for authentication", got, socketDirMode)
	}

	sockInfo, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got := sockInfo.Mode().Perm(); got != socketMode {
		t.Errorf("socket mode = %#o, want %#o", got, socketMode)
	}
	if sockInfo.Mode()&os.ModeSocket == 0 {
		t.Errorf("%s is not a socket (mode %s)", sock, sockInfo.Mode())
	}
	// The thing being asserted: nobody outside the owner and group can reach it.
	if sockInfo.Mode().Perm()&0o007 != 0 {
		t.Errorf("socket is accessible to other (mode %#o)", sockInfo.Mode().Perm())
	}
}

// TestListenUnixTightensAnExistingWideDirectory covers an upgrade landing on a
// directory somebody created by hand at 0755.
func TestListenUnixTightensAnExistingWideDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	ln, err := listen(mustParse(t, "unix:"+filepath.Join(dir, "mgmt.sock")), config.APIConfig{}, discardLogger())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != socketDirMode {
		t.Errorf("socket directory mode = %#o, want it tightened to %#o", got, socketDirMode)
	}
}

// TestListenUnixRemovesStaleSocket reproduces the crash-and-restart case: a
// socket file with nothing behind it, which bind would otherwise reject with
// "address already in use".
func TestListenUnixRemovesStaleSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "mgmt.sock")

	// Create a socket and abandon the file, exactly as a killed process would.
	stale, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("creating stale socket: %v", err)
	}
	if unixLn, ok := stale.(*net.UnixListener); ok {
		unixLn.SetUnlinkOnClose(false)
	}
	if err := stale.Close(); err != nil {
		t.Fatalf("closing stale socket: %v", err)
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("stale socket should still be on disk: %v", err)
	}

	ln, err := listen(mustParse(t, "unix:"+sock), config.APIConfig{}, discardLogger())
	if err != nil {
		t.Fatalf("listen over a stale socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("new listener is not reachable: %v", err)
	}
	_ = conn.Close()
}

// TestListenUnixRefusesLiveSocket is the other half of stale-socket removal:
// unlinking a socket something is serving would silently take the address away
// from a running server.
func TestListenUnixRefusesLiveSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "mgmt.sock")

	live, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("creating live socket: %v", err)
	}
	t.Cleanup(func() { _ = live.Close() })
	go func() {
		for {
			conn, err := live.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	_, err = listen(mustParse(t, "unix:"+sock), config.APIConfig{}, discardLogger())
	if err == nil {
		t.Fatal("listen() stole a socket that another process was serving")
	}
	if !strings.Contains(err.Error(), "already being served") {
		t.Errorf("error = %v, want it to say the socket is in use", err)
	}
}

// TestListenUnixRefusesNonSocketPath guards the delete: the stale-socket
// cleanup must never remove a regular file it was pointed at by mistake.
func TestListenUnixRefusesNonSocketPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "important.db")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	_, err := listen(mustParse(t, "unix:"+path), config.APIConfig{}, discardLogger())
	if err == nil {
		t.Fatal("listen() accepted a path holding a regular file")
	}
	if !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("error = %v, want it to say the path is not a socket", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Errorf("the file was deleted: %v", statErr)
	}
}

func TestListenUnixRejectsUnknownGroup(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "mgmt.sock")
	cfg := config.APIConfig{SocketGroup: "no-such-group-ffffffff"}

	_, err := listen(mustParse(t, "unix:"+sock), cfg, discardLogger())
	if err == nil {
		t.Fatal("listen() accepted a socket group that does not exist")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error = %v, want it to name the missing group", err)
	}
	// A server that cannot hand the socket to the right group must not serve on
	// it anyway, or the API ends up quietly narrower or wider than intended.
	if _, statErr := os.Stat(sock); statErr == nil {
		t.Error("a socket was created despite the group lookup failing")
	}
}

// TestListenTCPRefusesNonLoopback duplicates the config-level check at the
// point of binding, because NewManagementAPI can be constructed without going
// through Config.Validate.
func TestListenTCPRefusesNonLoopback(t *testing.T) {
	_, err := listen(mustParse(t, "0.0.0.0:0"), config.APIConfig{}, discardLogger())
	if err == nil {
		t.Fatal("listen() bound the management API to a wildcard address")
	}
	if !strings.Contains(err.Error(), "API_ALLOW_NONLOOPBACK") {
		t.Errorf("error = %v, want it to name the override", err)
	}
}

func TestListenTCPLoopbackAndOverride(t *testing.T) {
	tests := []struct {
		name  string
		addr  string
		allow bool
	}{
		{name: "loopback needs no override", addr: "127.0.0.1:0"},
		{name: "wildcard with explicit override", addr: "0.0.0.0:0", allow: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := listen(mustParse(t, tt.addr), config.APIConfig{AllowNonLoopback: tt.allow}, discardLogger())
			if err != nil {
				t.Fatalf("listen(%q): %v", tt.addr, err)
			}
			_ = ln.Close()
		})
	}
}
