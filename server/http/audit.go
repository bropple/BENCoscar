package http

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os/user"
	"strconv"
)

// peerIdentity is what the kernel says about the process on the other end of a
// unix socket connection. Zero-valued with Known false when the transport
// cannot supply it (a TCP listener, or a platform without SO_PEERCRED).
type peerIdentity struct {
	UID   int
	GID   int
	PID   int
	Known bool
}

type peerIdentityKey struct{}

// connContext stashes the peer's credentials on the connection's context, which
// http.Server then hands to every request served over that connection. This is
// the only point at which the underlying net.Conn is available -- by the time a
// handler runs, the socket is behind the http machinery.
func connContext(ctx context.Context, conn net.Conn) context.Context {
	id, ok := peerCredentials(conn)
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, peerIdentityKey{}, id)
}

// peerFromContext returns the credentials recorded by connContext.
func peerFromContext(ctx context.Context) (peerIdentity, bool) {
	id, ok := ctx.Value(peerIdentityKey{}).(peerIdentity)
	return id, ok && id.Known
}

// auditLogger records who invoked each administrative action.
//
// The management API grants total control over every account on the server, and
// until now left no trace of which operator used it. On a unix socket the
// kernel can answer that question exactly, so the answer gets written down.
//
// Reads are logged at debug and writes at info: a password reset is something
// you want in the journal by default, whereas polling the session list is not.
func auditLogger(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attrs := []any{"method", r.Method, "path", r.URL.Path}
		if id, ok := peerFromContext(r.Context()); ok {
			attrs = append(attrs, "peer_uid", id.UID, "peer_pid", id.PID)
			if name := lookupUsername(id.UID); name != "" {
				attrs = append(attrs, "peer_user", name)
			}
		} else {
			// Worth distinguishing in the log: an action over TCP is one nobody
			// can attribute afterwards, which is itself a reason to prefer the
			// socket.
			attrs = append(attrs, "peer_uid", "unknown")
		}

		if isMutation(r.Method) {
			logger.Info("management API action", attrs...)
		} else {
			logger.Debug("management API request", attrs...)
		}

		next.ServeHTTP(w, r)
	})
}

func isMutation(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// lookupUsername resolves a uid to a login name for the log. Best effort: a uid
// with no passwd entry is still a perfectly good audit record.
func lookupUsername(uid int) string {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return ""
	}
	return u.Username
}
