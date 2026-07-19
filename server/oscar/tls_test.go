package oscar

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/config"
)

// BENCO addition. These exercise the real socket rather than the config
// structs: the question "is this port actually encrypted" is not answerable by
// unit-testing a *tls.Config, and getting it wrong is silent.

func testKeypair(t *testing.T) config.TLSConfig {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	require.NoError(t, os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))

	return config.TLSConfig{CertFile: certPath, KeyFile: keyPath}
}

// echoOnce accepts a single connection and echoes one small read back, standing
// in for the FLAP handler. It exists so the test can prove bytes survive the
// round trip, not merely that a handshake completed.
func echoOnce(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write(buf[:n])
	}()
}

func TestListenBOS_PlaintextByDefault(t *testing.T) {
	ln, err := listenBOS(config.Listener{BOSListenAddress: "127.0.0.1:0"})
	require.NoError(t, err)
	defer ln.Close()

	echoOnce(t, ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)

	buf := make([]byte, 5)
	_, err = conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf))
}

func TestListenBOS_TLSHandshakeSucceeds(t *testing.T) {
	ln, err := listenBOS(config.Listener{
		BOSListenAddress: "127.0.0.1:0",
		TLS:              testKeypair(t),
	})
	require.NoError(t, err)
	defer ln.Close()

	echoOnce(t, ln)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		// Self-signed test certificate; the point here is that the transport is
		// encrypted, not that a test CA is trusted.
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.Handshake())

	state := conn.ConnectionState()
	assert.True(t, state.HandshakeComplete)
	assert.GreaterOrEqual(t, state.Version, uint16(tls.VersionTLS12))

	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)

	buf := make([]byte, 5)
	_, err = conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf))
}

// A plaintext client must not be able to talk to a TLS listener. This is the
// test that would catch a regression where the wrapping is dropped and the port
// silently downgrades to cleartext — the failure mode that motivated the whole
// change.
func TestListenBOS_PlaintextClientRejectedByTLSListener(t *testing.T) {
	ln, err := listenBOS(config.Listener{
		BOSListenAddress: "127.0.0.1:0",
		TLS:              testKeypair(t),
	})
	require.NoError(t, err)
	defer ln.Close()

	echoOnce(t, ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// The TCP connect succeeds — tls.NewListener defers the handshake to the
	// first read, so this is expected. What must not happen is the payload
	// coming back.
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 5)
	n, err := conn.Read(buf)

	assert.Error(t, err, "plaintext client should never get a clean read from a TLS listener")
	assert.NotEqual(t, "hello", string(buf[:n]), "payload was echoed back in cleartext")
}

func TestListenBOS_PartialTLSConfigRefusesToListen(t *testing.T) {
	// Half-configured TLS must stop the server, not fall back to plaintext.
	_, err := listenBOS(config.Listener{
		BOSListenAddress: "127.0.0.1:0",
		TLS:              config.TLSConfig{CertFile: "cert.pem"},
	})
	assert.Error(t, err)
}
