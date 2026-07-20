package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestUnixSocketPath(t *testing.T) {
	tests := []struct {
		addr     string
		wantPath string
		wantOK   bool
	}{
		{addr: "unix:/run/bencoscar/mgmt.sock", wantPath: "/run/bencoscar/mgmt.sock", wantOK: true},
		{addr: "unix:///run/bencoscar/mgmt.sock", wantPath: "/run/bencoscar/mgmt.sock", wantOK: true},
		{addr: "unix:./relative.sock", wantPath: "./relative.sock", wantOK: true},
		{addr: "unix:", wantOK: false},
		{addr: "127.0.0.1:8080", wantOK: false},
		{addr: "http://127.0.0.1:8080", wantOK: false},
	}
	for _, tt := range tests {
		gotPath, gotOK := unixSocketPath(tt.addr)
		if gotOK != tt.wantOK {
			t.Errorf("unixSocketPath(%q) ok = %v, want %v", tt.addr, gotOK, tt.wantOK)
			continue
		}
		if gotOK && gotPath != tt.wantPath {
			t.Errorf("unixSocketPath(%q) = %q, want %q", tt.addr, gotPath, tt.wantPath)
		}
	}
}

// TestClientOverUnixSocket is the real thing end to end: a server on a socket,
// a client built from a unix: address, and a request that comes back with the
// server's answer.
func TestClientOverUnixSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "mgmt.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var gotPath, gotMethod string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"id":"1","screen_name":"chattingchuck"}]`)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	c := newAPIClient("unix:"+sock, "")
	if c.socketPath != sock {
		t.Fatalf("socketPath = %q, want %q", c.socketPath, sock)
	}

	users, err := c.listUsers(context.Background())
	if err != nil {
		t.Fatalf("listUsers over unix socket: %v", err)
	}
	if len(users) != 1 || users[0].ScreenName != "chattingchuck" {
		t.Errorf("users = %+v, want one account named chattingchuck", users)
	}
	if gotMethod != http.MethodGet || gotPath != "/user" {
		t.Errorf("server saw %s %s, want GET /user", gotMethod, gotPath)
	}
}

// TestClientTCPAddressStillWorks: the socket is the default, not the only
// option. Existing deployments on a loopback port must keep working.
func TestClientTCPAddressUnaffected(t *testing.T) {
	c := newAPIClient("127.0.0.1:8080", "")
	if c.socketPath != "" {
		t.Errorf("socketPath = %q, want empty for a TCP address", c.socketPath)
	}
	if c.baseURL != "http://127.0.0.1:8080" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
}

// TestMissingSocketErrorNamesTheServer checks the message an operator gets when
// the server simply is not running -- the most common failure, and one that
// must not be confused with a permissions problem.
func TestMissingSocketErrorNamesTheServer(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")
	c := newAPIClient("unix:"+sock, "")

	err := c.do(context.Background(), http.MethodGet, "/user", nil, nil)
	if err == nil {
		t.Fatal("expected an error talking to a socket that does not exist")
	}
	if !strings.Contains(err.Error(), "does not appear to be running") {
		t.Errorf("error = %v, want it to point at the server not running", err)
	}
	// The opposite diagnosis would send someone to fix their group membership
	// when nothing is wrong with it.
	if strings.Contains(err.Error(), defaultAdminGroup) {
		t.Errorf("error = %v, want it NOT to blame group membership", err)
	}
}

func TestNotInGroupErrorIsActionable(t *testing.T) {
	err := notInGroupError("/run/bencoscar/mgmt.sock", "bencoscar-admin")
	for _, want := range []string{
		"not in the bencoscar-admin group", // the actual diagnosis
		"usermod -aG bencoscar-admin",      // the fix, ready to paste
		"log out and back in",              // the step people forget
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message is missing %q:\n%v", want, err)
		}
	}
}

func TestAdminGroupNameOverride(t *testing.T) {
	if got := adminGroupName(); got != defaultAdminGroup {
		t.Errorf("adminGroupName() = %q, want %q", got, defaultAdminGroup)
	}
	t.Setenv(adminGroupEnvVar, "other-admins")
	if got := adminGroupName(); got != "other-admins" {
		t.Errorf("adminGroupName() = %q, want the override", got)
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{args: []string{"benco_admin", "user", "list"}, want: `'benco_admin' 'user' 'list'`},
		{args: []string{"a b"}, want: `'a b'`},
		// The cases that would otherwise let a screen name run commands.
		{args: []string{"it's"}, want: `'it'\''s'`},
		{args: []string{"$(id)"}, want: `'$(id)'`},
		{args: []string{"a;rm -rf /"}, want: `'a;rm -rf /'`},
	}
	for _, tt := range tests {
		if got := shellQuote(tt.args); got != tt.want {
			t.Errorf("shellQuote(%q) = %s, want %s", tt.args, got, tt.want)
		}
	}
}

// sgShim writes a stand-in for sg(1) that accepts `shim GROUP -c COMMAND` and
// runs COMMAND through a shell, which is the part of sg's behaviour that
// matters here. Using a shim keeps the test honest without needing the real sg,
// a real group, or root.
func sgShim(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sg-shim")
	script := "#!/bin/sh\n" +
		"# args: GROUP -c COMMAND\n" +
		"echo \"shim-group=$1\" >&2\n" +
		"exec /bin/sh -c \"$3\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("writing sg shim: %v", err)
	}
	return path
}

// TestRunUnderSGPassesStdinThrough is the test the retry most needs. A password
// arriving on a pipe has to survive the re-exec: if stdin were captured,
// buffered, or left unattached, `benco_admin user add someone < password-file`
// would break in a way that only shows up on a machine where the group is stale.
func TestRunUnderSGPassesStdinThrough(t *testing.T) {
	shim := sgShim(t)

	// A program that proves stdin reached it, by echoing what it read.
	echoStdin := filepath.Join(t.TempDir(), "echo-stdin")
	if err := os.WriteFile(echoStdin, []byte("#!/bin/sh\nread line\necho \"got:$line\"\n"), 0o755); err != nil {
		t.Fatalf("writing helper: %v", err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := io.WriteString(w, "hunter2hunter2\n"); err != nil {
		t.Fatalf("writing to pipe: %v", err)
	}
	_ = w.Close()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = r, outW
	runErr := runUnderSG(shim, "bencoscar-admin", []string{echoStdin})
	os.Stdin, os.Stdout = oldIn, oldOut
	_ = outW.Close()

	out, _ := io.ReadAll(outR)

	var retried *retriedError
	if !errors.As(runErr, &retried) {
		t.Fatalf("runUnderSG returned %v, want a retriedError", runErr)
	}
	if retried.code != 0 {
		t.Errorf("retry exit code = %d, want 0", retried.code)
	}
	if got := strings.TrimSpace(string(out)); got != "got:hunter2hunter2" {
		t.Errorf("child read %q from stdin, want the piped password -- stdin did not survive the re-exec", got)
	}
}

// TestRunUnderSGPropagatesExitCode: the retry has already printed its own
// error, so the parent must not print a second one -- it just has to carry the
// status out.
func TestRunUnderSGPropagatesExitCode(t *testing.T) {
	shim := sgShim(t)

	failing := filepath.Join(t.TempDir(), "fail")
	if err := os.WriteFile(failing, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatalf("writing helper: %v", err)
	}

	err := runUnderSG(shim, "bencoscar-admin", []string{failing})

	var retried *retriedError
	if !errors.As(err, &retried) {
		t.Fatalf("runUnderSG returned %v, want a retriedError", err)
	}
	if retried.code != 3 {
		t.Errorf("exit code = %d, want 3", retried.code)
	}
}

// TestRunUnderSGSetsSentinel: without it, a permission failure sg cannot fix
// would re-exec forever.
func TestRunUnderSGSetsSentinel(t *testing.T) {
	shim := sgShim(t)

	probe := filepath.Join(t.TempDir(), "probe")
	script := "#!/bin/sh\nif [ \"$" + sgSentinel + "\" = \"1\" ]; then exit 0; fi\nexit 9\n"
	if err := os.WriteFile(probe, []byte(script), 0o755); err != nil {
		t.Fatalf("writing helper: %v", err)
	}

	err := runUnderSG(shim, "bencoscar-admin", []string{probe})

	var retried *retriedError
	if !errors.As(err, &retried) {
		t.Fatalf("runUnderSG returned %v, want a retriedError", err)
	}
	if retried.code != 0 {
		t.Errorf("exit code = %d: the child did not see %s=1", retried.code, sgSentinel)
	}
}

// TestRetryUnderSGRefusesToLoop: once the sentinel is set, a second failure has
// to become an explanation rather than another retry.
func TestRetryUnderSGRefusesToLoop(t *testing.T) {
	t.Setenv(sgSentinel, "1")

	err := retryUnderSG("bencoscar-admin")
	if err == nil {
		t.Fatal("expected an error rather than a second retry")
	}
	var retried *retriedError
	if errors.As(err, &retried) {
		t.Fatal("retried again despite the sentinel being set")
	}
	for _, want := range []string{"even after retrying", "newgrp bencoscar-admin"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message is missing %q:\n%v", want, err)
		}
	}
}

// TestProbeSocketIgnoresNonPermissionFailures: a missing socket is the server's
// problem to report, in terms of the command the operator actually ran.
func TestProbeSocketIgnoresNonPermissionFailures(t *testing.T) {
	if err := probeSocket(filepath.Join(t.TempDir(), "absent.sock")); err != nil {
		t.Errorf("probeSocket on a missing socket = %v, want it to defer to the real request", err)
	}
}

func TestProbeSocketAcceptsReachableSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "mgmt.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	if err := probeSocket(sock); err != nil {
		t.Errorf("probeSocket on a reachable socket = %v, want nil", err)
	}
}

// TestDiagnoseGroupMembershipUnknownGroup: a group that does not exist means
// nothing was ever granted, which is the "you are not in the group" case rather
// than the stale-shell one.
func TestDiagnoseGroupMembershipUnknownGroup(t *testing.T) {
	if got := diagnoseGroupMembership("no-such-group-ffffffff"); got != membershipMissing {
		t.Errorf("diagnoseGroupMembership() = %v, want membershipMissing", got)
	}
}

// TestProcessHasGroupMatchesRealCredentials sanity-checks the credential
// comparison against a group this process definitely has.
func TestProcessHasGroupMatchesRealCredentials(t *testing.T) {
	if !processHasGroup(strconv.Itoa(os.Getegid())) {
		t.Errorf("processHasGroup(%d) = false for our own effective gid", os.Getegid())
	}
	if processHasGroup("999999") {
		t.Error("processHasGroup reported a group this process cannot have")
	}
}
