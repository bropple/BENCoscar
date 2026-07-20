package http

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mk6i/open-oscar-server/config"
)

// TestAuditLogRecordsPeerUID is the point of the whole SO_PEERCRED exercise:
// before this, the management API left no record of which administrator reset
// which password. Over a unix socket the kernel can answer that exactly.
func TestAuditLogRecordsPeerUID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED is Linux-only; other platforms log the action without a uid")
	}

	sock := filepath.Join(t.TempDir(), "mgmt.sock")
	ln, err := listen(mustParse(t, "unix:"+sock), config.APIConfig{}, discardLogger())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Handler: auditLogger(inner, logger), ConnContext: connContext}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	client := unixClient(sock)
	req, err := http.NewRequest(http.MethodDelete, "http://mgmt.invalid/user", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()

	logged := logBuf.String()
	if !strings.Contains(logged, "management API action") {
		t.Fatalf("a DELETE was not logged as an action:\n%s", logged)
	}
	wantUID := "peer_uid=" + strconv.Itoa(os.Getuid())
	if !strings.Contains(logged, wantUID) {
		t.Errorf("log does not attribute the action to %s:\n%s", wantUID, logged)
	}
	if !strings.Contains(logged, "method=DELETE") || !strings.Contains(logged, "path=/user") {
		t.Errorf("log does not say what was done:\n%s", logged)
	}
}

// TestAuditLogSeparatesReadsFromWrites: polling the session list should not
// bury the password reset that happened between two polls.
func TestAuditLogSeparatesReadsFromWrites(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	handler := auditLogger(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), logger)

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		req, err := http.NewRequest(method, "/session", nil)
		if err != nil {
			t.Fatalf("building %s request: %v", method, err)
		}
		handler.ServeHTTP(discardResponseWriter{}, req)
	}
	if logBuf.Len() != 0 {
		t.Errorf("reads were logged at info level:\n%s", logBuf.String())
	}

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		logBuf.Reset()
		req, err := http.NewRequest(method, "/user/password", nil)
		if err != nil {
			t.Fatalf("building %s request: %v", method, err)
		}
		handler.ServeHTTP(discardResponseWriter{}, req)
		if !strings.Contains(logBuf.String(), "management API action") {
			t.Errorf("%s was not logged as an action:\n%s", method, logBuf.String())
		}
	}
}

// TestAuditLogMarksUnattributableActions: over TCP there are no peer
// credentials, and the log should say so rather than silently omitting the
// field -- "peer_uid=unknown" is itself an argument for the socket.
func TestAuditLogMarksUnattributableActions(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	handler := auditLogger(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}), logger)
	req, err := http.NewRequest(http.MethodPost, "/user", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	handler.ServeHTTP(discardResponseWriter{}, req)

	if !strings.Contains(logBuf.String(), "peer_uid=unknown") {
		t.Errorf("log does not mark the action as unattributable:\n%s", logBuf.String())
	}
}

func TestPeerCredentialsAbsentOnNonUnixConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	done := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- nil
			return
		}
		done <- conn
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	server := <-done
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = server.Close() })

	if _, ok := peerCredentials(server); ok {
		t.Error("peerCredentials reported credentials for a TCP connection")
	}
	if ctx := connContext(context.Background(), server); ctx.Value(peerIdentityKey{}) != nil {
		t.Error("connContext attached an identity to a TCP connection")
	}
}

func unixClient(sock string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
}

type discardResponseWriter struct{}

func (discardResponseWriter) Header() http.Header         { return http.Header{} }
func (discardResponseWriter) Write(b []byte) (int, error) { return io.Discard.Write(b) }
func (discardResponseWriter) WriteHeader(int)             {}
