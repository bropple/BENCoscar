//go:build !linux

package http

import "net"

// peerCredentials degrades gracefully off Linux.
//
// SO_PEERCRED is a Linux interface. The BSDs and macOS have equivalents
// (LOCAL_PEERCRED, getpeereid) with different shapes, and this server is
// deployed on Linux, so the others simply report "unknown" and the audit log
// records the action without an attributed uid. The access control itself is
// unaffected -- that is the socket's file permissions, which every unix has.
func peerCredentials(net.Conn) (peerIdentity, bool) {
	return peerIdentity{}, false
}
