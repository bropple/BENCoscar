package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

// defaultAdminGroup is the group whose members may connect to the management
// socket. It matches ADMIN_GROUP in scripts/benco-deploy/install.sh; the
// environment variable exists so a deployment that chose a different name can
// say so without recompiling.
const defaultAdminGroup = "bencoscar-admin"

const adminGroupEnvVar = "BENCO_ADMIN_GROUP"

// sgSentinel marks a process that is already the product of an sg re-exec.
// Without it, a permission failure that sg cannot fix would re-exec forever.
const sgSentinel = "BENCO_ADMIN_SG_RETRY"

func adminGroupName() string {
	if g := strings.TrimSpace(os.Getenv(adminGroupEnvVar)); g != "" {
		return g
	}
	return defaultAdminGroup
}

// probeSocket connects to the management socket once, before the command does
// anything else, and turns a permission failure into either an explanation or a
// transparent retry.
//
// Doing this up front rather than on the real request is deliberate: the retry
// re-executes this process, and a re-exec after a password has been prompted
// for or read from a pipe would either ask twice or find stdin already at EOF.
// Probing before any input is consumed keeps `benco_admin user add x < pwfile`
// working across the retry.
func probeSocket(path string) error {
	conn, err := net.Dial("unix", path)
	if err == nil {
		_ = conn.Close()
		return nil
	}

	if !isPermissionDenied(err) {
		// Not a permissions problem. Let the real request report it, so the
		// error the operator sees describes the operation they asked for.
		return nil
	}

	group := adminGroupName()
	switch diagnoseGroupMembership(group) {
	case membershipStale:
		// The group exists and the user is in it, but this process's
		// credentials predate that. Credentials are fixed when a process is
		// created and inherited from the parent, so nothing this process --
		// or the installer -- can do will add a group to an already-running
		// shell. Re-running ourselves under sg is the only way to acquire it
		// without the operator logging out.
		return retryUnderSG(group)
	case membershipMissing:
		return notInGroupError(path, group)
	default:
		return fmt.Errorf(
			"permission denied connecting to the management socket %s.\n"+
				"You are in the %s group and this shell has it, so the group is not the problem. Check that\n"+
				"the server is running and that the socket and its directory have the expected ownership:\n"+
				"\tsystemctl status bencoscar\n"+
				"\tls -ld %s %s",
			path, group, dirOf(path), path)
	}
}

type membership int

const (
	// membershipOK means the group is in this process's own credentials.
	membershipOK membership = iota
	// membershipStale means the group database says the user is a member but
	// this process's credentials do not carry it -- a shell started before the
	// membership existed.
	membershipStale
	// membershipMissing means the user is not a member at all, or the group
	// does not exist on this machine.
	membershipMissing
)

// diagnoseGroupMembership compares what the group database says against what
// this process actually holds. The gap between those two is the entire reason a
// fresh install appears broken exactly once.
func diagnoseGroupMembership(group string) membership {
	grp, err := user.LookupGroup(group)
	if err != nil {
		// No such group: nothing was ever granted here.
		return membershipMissing
	}

	if processHasGroup(grp.Gid) {
		return membershipOK
	}
	if databaseHasGroup(grp.Gid) {
		return membershipStale
	}
	return membershipMissing
}

// processHasGroup reports whether this process's credential set includes gid.
// The effective gid is checked alongside the supplementary groups because
// getgroups(2) is not required to include it.
func processHasGroup(gid string) bool {
	want, err := strconv.Atoi(gid)
	if err != nil {
		return false
	}
	if os.Getegid() == want || os.Getgid() == want {
		return true
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, g := range groups {
		if g == want {
			return true
		}
	}
	return false
}

// databaseHasGroup reports whether /etc/group (or whatever NSS resolves to)
// lists the current user as a member.
func databaseHasGroup(gid string) bool {
	u, err := user.Current()
	if err != nil {
		return false
	}
	if u.Gid == gid {
		return true
	}
	ids, err := u.GroupIds()
	if err != nil {
		return false
	}
	for _, id := range ids {
		if id == gid {
			return true
		}
	}
	return false
}

// retryUnderSG re-runs this command with the admin group added, via sg(1).
//
// sg is preferred over newgrp because `sg GROUP -c CMD` runs one command and
// exits, whereas newgrp starts an interactive shell -- which is the right tool
// for a human and the wrong one for a program trying to complete a request.
func retryUnderSG(group string) error {
	if os.Getenv(sgSentinel) != "" {
		// Already retried once and still denied. Retrying again would loop.
		return fmt.Errorf(
			"permission denied connecting to the management socket, even after retrying under `sg %s`.\n"+
				"Start a session that has the group for real:\n"+
				"\tnewgrp %s\n"+
				"or log out and back in, then try again. If that still fails, the socket's ownership is\n"+
				"probably not what the installer set up -- check `ls -ld` on it and its directory.",
			group, group)
	}

	sgPath, err := exec.LookPath("sg")
	if err != nil {
		return fmt.Errorf(
			"you are a member of the %s group, but this shell was started before that was true, so it does\n"+
				"not carry the group yet. Group membership is fixed when a process starts and inherited from\n"+
				"its parent, so nothing can add it to a shell that is already running.\n\n"+
				"Log out and back in, or start a shell that has it:\n"+
				"\tnewgrp %s\n\n"+
				"(This would normally be retried automatically via `sg`, but sg is not installed here.)",
			group, group)
	}

	// os.Args[0] is whatever the shell typed, which may rely on a PATH lookup
	// the child would repeat differently. Resolve it here so the retry re-runs
	// this exact binary.
	argv := append([]string{}, os.Args...)
	if self, err := os.Executable(); err == nil && self != "" {
		argv[0] = self
	}

	fmt.Fprintf(os.Stderr, "note: this shell is not in the %s group yet; retrying via sg\n", group)
	return runUnderSG(sgPath, group, argv)
}

// retriedError reports that the command has already been run to completion by a
// child process, and carries the status that child exited with. main turns it
// into this process's exit status; nothing else should be printed, because the
// child has already said everything there is to say.
type retriedError struct {
	code int
}

func (e *retriedError) Error() string {
	return fmt.Sprintf("command completed in a retry that exited %d", e.code)
}

// runUnderSG re-runs argv under `sg GROUP -c ...`, wiring the child's standard
// streams straight through.
//
// Passing stdin through is the part that matters: `benco_admin user add someone
// < password-file` has to keep working across the retry, and a password prompt
// on a terminal has to reach the same terminal. This is why the whole scheme
// probes the socket before reading any input -- if a byte of stdin had already
// been consumed here, the child would find it missing.
func runUnderSG(sgPath string, group string, argv []string) error {
	// sg hands its -c argument to a shell, so every word has to survive one
	// round of shell parsing intact -- screen names are not guaranteed to be
	// free of characters a shell would otherwise act on.
	command := shellQuote(argv)

	cmd := exec.Command(sgPath, group, "-c", command)
	cmd.Env = append(os.Environ(), sgSentinel+"=1")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return &retriedError{code: exitErr.ExitCode()}
		}
		return fmt.Errorf("retrying under `sg %s`: %w", group, err)
	}
	return &retriedError{code: 0}
}

func notInGroupError(path string, group string) error {
	name := currentUsername()
	return fmt.Errorf(
		"permission denied connecting to the management socket %s.\n\n"+
			"This means you are not in the %s group. That group is the authentication: the socket sits in a\n"+
			"directory only its members can open, so the kernel refuses the connection before the server\n"+
			"sees it. There is no password or token that would help.\n\n"+
			"Add yourself, then log out and back in (or run `newgrp %s`):\n"+
			"\tsudo usermod -aG %s %s",
		path, group, group, group, name)
}

func currentUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if n := os.Getenv("USER"); n != "" {
		return n
	}
	return "<your-user>"
}

// isPermissionDenied reports whether a dial failed because the kernel refused
// access, as opposed to the server being absent.
func isPermissionDenied(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, os.ErrPermission)
}

// shellQuote renders an argv as a single shell command line, single-quoting
// each word so the shell sg spawns reproduces it exactly.
func shellQuote(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, a := range args {
		quoted = append(quoted, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
	}
	return strings.Join(quoted, " ")
}

func dirOf(path string) string {
	if i := strings.LastIndex(path, "/"); i > 0 {
		return path[:i]
	}
	return "/"
}
