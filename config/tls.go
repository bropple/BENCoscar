package config

import (
	"crypto/tls"
	"errors"
	"fmt"
)

// BENCO addition. Upstream terminates TLS with an external stunnel process
// sitting in front of the plaintext OSCAR port (see Dockerfile.stunnel and
// config/ssl/stunnel.conf). This file lets the server terminate TLS itself, so
// a deployment can run without a proxy and without a plaintext port existing at
// all.
//
// The two models coexist deliberately. Leaving OSCAR_TLS_CERT_FILE unset keeps
// upstream's behaviour byte for byte, which is what upstream's own tests assert.

// errPartialTLSConfig is returned when exactly one of the certificate and key
// paths is set.
//
// This fails loudly on purpose. The dangerous outcome for a half-configured
// server is not a crash — it is silently listening in plaintext while the
// operator believes TLS is on, which is precisely the mistake this whole
// feature exists to make impossible.
var errPartialTLSConfig = errors.New("OSCAR_TLS_CERT_FILE and OSCAR_TLS_KEY_FILE must be set together")

// TLSConfig configures native TLS termination for the OSCAR listeners.
//
// Certificates are read from disk rather than fetched over ACME. A server
// behind a real certificate is expected to have one renewed out of band (certbot
// or similar); pulling an ACME client into the server would add a network
// dependency to startup for no gain, and would need port 80 besides.
type TLSConfig struct {
	CertFile string `envconfig:"OSCAR_TLS_CERT_FILE" required:"false" basic:"" ssl:"" description:"Path to a PEM certificate chain. When set (together with OSCAR_TLS_KEY_FILE) the OSCAR listeners terminate TLS themselves and no plaintext OSCAR port is opened. Leave empty to keep the upstream model, where an external stunnel terminates TLS in front of a plaintext port."`
	KeyFile  string `envconfig:"OSCAR_TLS_KEY_FILE" required:"false" basic:"" ssl:"" description:"Path to the PEM private key matching OSCAR_TLS_CERT_FILE. Both must be set together; setting only one is a configuration error rather than a silent fallback to plaintext."`
}

// Enabled reports whether native TLS has been configured at all.
//
// Note this is deliberately an OR and not an AND: a config with only one of the
// two paths set counts as "TLS was intended", so that ServerConfig can reject it
// instead of quietly serving plaintext. See errPartialTLSConfig.
func (t TLSConfig) Enabled() bool {
	return t.CertFile != "" || t.KeyFile != ""
}

// ServerConfig builds the *tls.Config for the listeners, loading the keypair
// from disk. It returns (nil, nil) when native TLS is not configured, which the
// caller treats as "listen in plaintext".
//
// Loading happens once at startup rather than per connection, so a bad path or
// an unreadable key stops the server immediately instead of failing every
// sign-on attempt at runtime.
func (t TLSConfig) ServerConfig() (*tls.Config, error) {
	if !t.Enabled() {
		return nil, nil
	}
	if t.CertFile == "" || t.KeyFile == "" {
		return nil, errPartialTLSConfig
	}

	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS keypair (cert=%s key=%s): %w", t.CertFile, t.KeyFile, err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// TLS 1.2 floor. Upstream's stunnel.conf disables SSLv2/SSLv3/TLSv1.1
		// but still permits TLS 1.0 for period AIM clients; BENCO does not
		// support those clients, so there is nothing to trade away here.
		MinVersion: tls.VersionTLS12,
	}, nil
}

// UsesTLS reports whether this listener's socket is TLS-terminated by the server
// itself.
//
// This is NOT the same as HasSSL. HasSSL means "an SSL hostname was advertised
// for this listener", which under the stunnel model describes a socket belonging
// to a different process on a different port. UsesTLS means "the socket this
// server accepted the connection on is encrypted". Conflating the two is how you
// end up advertising a plaintext port to a client that arrived over TLS.
func (l Listener) UsesTLS() bool {
	return l.TLS.Enabled()
}

// AdvertisedHost returns the host:port this listener should tell clients to
// reconnect to.
//
// Under native TLS the reconnect target is the same encrypted socket, so the
// plaintext advertised host is the right answer unless the operator published a
// separate SSL hostname (useful when the public DNS name differs from the bind
// address). Under the stunnel model this is always the plaintext host, matching
// upstream.
func (l Listener) AdvertisedHost() string {
	if l.UsesTLS() && l.BOSAdvertisedHostSSL != "" {
		return l.BOSAdvertisedHostSSL
	}
	return l.BOSAdvertisedHostPlain
}
