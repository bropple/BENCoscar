package http

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/mk6i/open-oscar-server/config"
)

// socketMode is the permission bit set applied to the management API's unix
// socket: owner and group may connect, nobody else.
//
// This mode is defence in depth rather than the actual control. Go's
// net.Listen("unix", ...) creates the socket with 0777 &^ umask and there is no
// way to bind it atomically with a tighter mode, so between bind and chmod
// there is a window in which the socket is world-writable. The real protection
// is the containing directory: it is created 0750, so nothing outside the
// owning user and group can traverse into it and reach the socket at all,
// whatever the socket's own mode says during that window.
const socketMode os.FileMode = 0o660

// socketDirMode is the permission bit set for the directory holding the socket.
// This one IS load-bearing -- see socketMode.
const socketDirMode os.FileMode = 0o750

// listen opens the management API's listener.
//
// For a unix socket this is where the "filesystem permissions are the
// authentication" property is established, so the ordering below matters:
// directory first, then bind, then mode.
func listen(spec config.APIListenerSpec, cfg config.APIConfig, logger *slog.Logger) (net.Listener, error) {
	if spec.Kind == config.APIListenerUnix {
		return listenUnix(spec.Address, cfg.SocketGroup, logger)
	}

	// Belt and braces: config validation already refuses this, but the check is
	// cheap and NewManagementAPI is callable without going through Config.
	if !spec.Loopback && !cfg.AllowNonLoopback {
		return nil, fmt.Errorf("refusing to bind the management API to %q, which is reachable from off "+
			"this machine, because the API has no authentication of its own. Use a unix socket "+
			"(API_LISTENER=unix:/run/bencoscar/mgmt.sock), keep it on loopback, or set "+
			"API_ALLOW_NONLOOPBACK=true if access control is genuinely being provided elsewhere",
			spec.Address)
	}

	ln, err := net.Listen(spec.Network, spec.Address)
	if err != nil {
		return nil, fmt.Errorf("unable to bind management API to %s: %w", spec.Address, err)
	}
	return ln, nil
}

// listenUnix binds the management socket and establishes the permission chain
// that stands in for authentication:
//
//	/run/bencoscar        0750  service-user:admin-group   traverse
//	/run/bencoscar/*.sock 0660  service-user:admin-group   connect
//
// The server does the chown itself, rather than leaving it to systemd or to a
// setgid directory, because it is the one component that can state the rule and
// fail loudly when it does not hold. systemd's RuntimeDirectory= gives the
// directory the unit's own Group, which is the service account -- so something
// has to widen it to the admin group, and doing that here keeps the whole chain
// in one readable place.
func listenUnix(path string, groupName string, logger *slog.Logger) (net.Listener, error) {
	gid := -1
	if groupName != "" {
		g, err := user.LookupGroup(groupName)
		if err != nil {
			return nil, fmt.Errorf("API_SOCKET_GROUP names the group allowed to administer this server, "+
				"but group %q does not exist on this machine: %w. Create it (groupadd --system %s) or "+
				"unset API_SOCKET_GROUP", groupName, err, groupName)
		}
		gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			return nil, fmt.Errorf("group %q has a non-numeric gid %q", groupName, g.Gid)
		}
	}

	dir := filepath.Dir(path)
	// Under systemd the directory already exists, created by RuntimeDirectory=
	// with RuntimeDirectoryMode=0750. Creating it here covers everything else
	// (containers, a hand-started server) with the same mode.
	if err := os.MkdirAll(dir, socketDirMode); err != nil {
		return nil, fmt.Errorf("unable to create management API socket directory %s: %w", dir, err)
	}
	if gid >= 0 {
		if err := os.Chown(dir, -1, gid); err != nil {
			return nil, fmt.Errorf("unable to give management API socket directory %s to group %q: %w. "+
				"The server must own that directory and be a member of the group to hand it over -- "+
				"under systemd that means SupplementaryGroups=%s on the unit",
				dir, groupName, err, groupName)
		}
	}
	// MkdirAll applies umask, and an existing directory keeps whatever mode it
	// had. Neither is allowed to leave this directory wider than 0750, since
	// that mode is what stands in for authentication.
	if err := os.Chmod(dir, socketDirMode); err != nil {
		return nil, fmt.Errorf("unable to set mode %#o on management API socket directory %s: %w",
			socketDirMode, dir, err)
	}

	if err := clearStaleSocket(path, logger); err != nil {
		return nil, err
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("unable to bind management API to unix socket %s: %w", path, err)
	}

	// From here on, any failure means the socket's access control is not what
	// was asked for. Close rather than serve: a management API is not something
	// to expose on best-effort permissions.
	if gid >= 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("unable to give management API socket %s to group %q: %w",
				path, groupName, err)
		}
	}
	if err := os.Chmod(path, socketMode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("unable to set mode %#o on management API socket %s: %w", socketMode, path, err)
	}

	return ln, nil
}

// clearStaleSocket removes a socket file left behind by a previous run.
//
// A process that died without unlinking its socket leaves the path occupied,
// and bind then fails with "address already in use" -- which reads like a port
// conflict and sends an operator looking for a second server that is not there.
// Removing it is safe only once we know it is (a) a socket and (b) not one
// something is currently serving, so both are checked before unlinking.
func clearStaleSocket(path string, logger *slog.Logger) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("unable to inspect existing management API socket path %s: %w", path, err)
	}

	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("management API socket path %s already exists and is not a socket (mode %s); "+
			"refusing to delete it -- move it aside or point API_LISTENER somewhere else",
			path, info.Mode())
	}

	// Unlinking a socket something is serving would silently steal the address
	// from a running server, leaving it accepting connections nothing can
	// reach. So only a socket that is provably dead gets removed: a connection
	// refused means the file outlived its process, which is the case this is
	// here to fix. Anything else -- it answered, or the dial failed for a reason
	// we cannot interpret -- is treated as "possibly alive" and left alone.
	conn, dialErr := net.Dial("unix", path)
	if dialErr == nil {
		_ = conn.Close()
		return fmt.Errorf("management API socket %s is already being served by another process; "+
			"stop it before starting this one", path)
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		return fmt.Errorf("management API socket %s already exists and could not be shown to be dead "+
			"(%v); refusing to remove it in case another process is serving it. Remove it by hand if "+
			"you are sure nothing is using it", path, dialErr)
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("unable to remove stale management API socket %s: %w", path, err)
	}
	if logger != nil {
		logger.Info("removed stale management API socket left by a previous run", "path", path)
	}
	return nil
}
