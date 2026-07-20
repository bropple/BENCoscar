package config

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

// unixPrefix is the scheme that selects a unix domain socket listener for the
// management API.
const unixPrefix = "unix:"

// APIConfig is everything the management API server needs to know about how to
// expose itself. It is a struct rather than three arguments because the three
// settings only make sense read together: the group is meaningless without the
// socket, and the override is meaningless without the TCP bind.
type APIConfig struct {
	Listener         string
	AllowNonLoopback bool
	SocketGroup      string
}

// APIConfig extracts the management API's slice of the configuration.
func (c Config) APIConfig() APIConfig {
	return APIConfig{
		Listener:         c.APIListener,
		AllowNonLoopback: c.APIAllowNonLoopback,
		SocketGroup:      c.APISocketGroup,
	}
}

// APIListenerKind distinguishes the two things API_LISTENER can name.
type APIListenerKind int

const (
	// APIListenerTCP is a host:port bind.
	APIListenerTCP APIListenerKind = iota
	// APIListenerUnix is a filesystem path to a unix domain socket.
	APIListenerUnix
)

// APIListenerSpec is a parsed API_LISTENER value.
//
// The management API has no authentication of its own. A unix socket is the
// recommended configuration because it replaces authentication with filesystem
// permissions: the kernel refuses a connection from a process whose credentials
// do not permit opening the socket, before the server reads a byte. There is no
// token to leak, rotate or forget, and a socket path cannot be accidentally
// widened to the network the way a bind address can.
type APIListenerSpec struct {
	Kind APIListenerKind
	// Network is "unix" or "tcp", suitable for net.Listen.
	Network string
	// Address is the socket path, or the host:port pair.
	Address string
	// Loopback reports whether a TCP bind is restricted to the local machine.
	// Always true for unix sockets, which have no network exposure at all.
	Loopback bool
}

// ParseAPIListener interprets an API_LISTENER value.
//
// Two forms are accepted:
//
//	unix:/run/bencoscar/mgmt.sock   a unix domain socket (recommended)
//	127.0.0.1:8080                  a TCP bind
//
// The unix form also tolerates unix:///run/... so that a value copied from a
// URL-shaped setting still works.
func ParseAPIListener(raw string) (APIListenerSpec, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return APIListenerSpec{}, fmt.Errorf("APIListener is required and cannot be empty")
	}

	if strings.HasPrefix(v, unixPrefix) {
		path := strings.TrimPrefix(v, unixPrefix)
		path = strings.TrimPrefix(path, "//")
		if path == "" {
			return APIListenerSpec{}, fmt.Errorf("invalid API listener %q: missing socket path. "+
				"Valid format: unix:/PATH/TO.sock (e.g. unix:/run/bencoscar/mgmt.sock)", raw)
		}
		if !filepath.IsAbs(path) {
			return APIListenerSpec{}, fmt.Errorf("invalid API listener %q: socket path must be absolute, "+
				"because the server's working directory is not somewhere an administrator can predict. "+
				"Valid format: unix:/PATH/TO.sock (e.g. unix:/run/bencoscar/mgmt.sock)", raw)
		}
		return APIListenerSpec{
			Kind:     APIListenerUnix,
			Network:  "unix",
			Address:  filepath.Clean(path),
			Loopback: true,
		}, nil
	}

	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return APIListenerSpec{}, fmt.Errorf("invalid API listener %q: %v. "+
			"Valid formats: unix:/PATH/TO.sock (recommended) or HOST:PORT (e.g. 127.0.0.1:8080)", raw, err)
	}
	if host == "" {
		return APIListenerSpec{}, fmt.Errorf("invalid API listener %q: missing host. "+
			"Valid formats: unix:/PATH/TO.sock (recommended) or HOST:PORT (e.g. 127.0.0.1:8080)", raw)
	}
	if port == "" {
		return APIListenerSpec{}, fmt.Errorf("invalid API listener %q: missing port. "+
			"Valid formats: unix:/PATH/TO.sock (recommended) or HOST:PORT (e.g. 127.0.0.1:8080)", raw)
	}

	return APIListenerSpec{
		Kind:     APIListenerTCP,
		Network:  "tcp",
		Address:  v,
		Loopback: isLoopbackHost(host),
	}, nil
}

// isLoopbackHost reports whether a bind host reaches only the local machine.
//
// Anything that is not demonstrably loopback counts as exposed: a wildcard
// bind, a routable address, and a hostname whose resolution the server cannot
// vouch for at config-parse time all fall on the same side of the line.
func isLoopbackHost(host string) bool {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(host, "localhost")
}
