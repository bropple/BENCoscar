package oscar

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/mk6i/open-oscar-server/config"
)

// BENCO addition. See config/tls.go for the configuration model.

// listenBOS opens the BOS socket for one configured listener, wrapping it in TLS
// when the deployment terminates TLS natively.
//
// Wrapping is safe to do this bluntly because nothing downstream depends on the
// concrete connection type: the accept loop stores connections as net.Conn, the
// only conn-specific call in the auth path is SetDeadline (which *tls.Conn
// implements), and wire.FlapClient asks for no more than io.Reader/io.Writer.
// So a *tls.Conn satisfies every existing call site unchanged.
//
// The TLS handshake itself is deferred by tls.NewListener until the first read,
// which means a client that connects in plaintext to a TLS port fails during
// FLAP framing rather than at Accept. That is the correct trade: it keeps the
// accept loop non-blocking and unable to be stalled by a peer that connects and
// then says nothing.
func listenBOS(l config.Listener) (net.Listener, error) {
	tlsCfg, err := l.TLS.ServerConfig()
	if err != nil {
		return nil, fmt.Errorf("invalid TLS config for listener %s: %w", l.BOSListenAddress, err)
	}

	ln, err := net.Listen("tcp", l.BOSListenAddress)
	if err != nil {
		return nil, err
	}

	if tlsCfg == nil {
		return ln, nil
	}
	return tls.NewListener(ln, tlsCfg), nil
}
