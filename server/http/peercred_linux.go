//go:build linux

package http

import (
	"net"
	"syscall"
)

// peerCredentials reads the connecting process's credentials off a unix socket
// using SO_PEERCRED.
//
// The kernel fills these in at connect time from the peer's real credentials,
// so they cannot be forged the way a header or a self-reported name could be.
// That is what makes them worth logging: "uid 1001 deleted an account" is a
// fact, not a claim.
func peerCredentials(conn net.Conn) (peerIdentity, bool) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return peerIdentity{}, false
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return peerIdentity{}, false
	}

	var (
		ucred   *syscall.Ucred
		sockErr error
	)
	if err := raw.Control(func(fd uintptr) {
		ucred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return peerIdentity{}, false
	}
	if sockErr != nil || ucred == nil {
		return peerIdentity{}, false
	}

	return peerIdentity{
		UID:   int(ucred.Uid),
		GID:   int(ucred.Gid),
		PID:   int(ucred.Pid),
		Known: true,
	}, true
}
