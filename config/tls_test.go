package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTestKeypair generates a throwaway self-signed certificate and returns the
// paths to the PEM cert and key.
//
// Generated rather than checked in as a fixture: a committed certificate expires
// and turns into a mystery test failure years later, and a committed private key
// is a private key in a public repo even if it guards nothing.
func writeTestKeypair(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bencoscar-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	return certPath, keyPath
}

func TestTLSConfig_Enabled(t *testing.T) {
	cases := []struct {
		name string
		cfg  TLSConfig
		want bool
	}{
		{
			name: "unset is disabled",
			cfg:  TLSConfig{},
			want: false,
		},
		{
			// Half-configured counts as enabled so ServerConfig can reject it.
			// If this returned false the server would silently listen in
			// plaintext, which is the exact failure this feature exists to
			// prevent.
			name: "cert only is enabled, so it can be rejected",
			cfg:  TLSConfig{CertFile: "cert.pem"},
			want: true,
		},
		{
			name: "key only is enabled, so it can be rejected",
			cfg:  TLSConfig{KeyFile: "key.pem"},
			want: true,
		},
		{
			name: "both set",
			cfg:  TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.cfg.Enabled())
		})
	}
}

func TestTLSConfig_ServerConfig(t *testing.T) {
	certPath, keyPath := writeTestKeypair(t)

	t.Run("disabled returns no config and no error", func(t *testing.T) {
		got, err := TLSConfig{}.ServerConfig()
		assert.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("cert without key is an error", func(t *testing.T) {
		_, err := TLSConfig{CertFile: certPath}.ServerConfig()
		assert.ErrorIs(t, err, errPartialTLSConfig)
	})

	t.Run("key without cert is an error", func(t *testing.T) {
		_, err := TLSConfig{KeyFile: keyPath}.ServerConfig()
		assert.ErrorIs(t, err, errPartialTLSConfig)
	})

	t.Run("missing file is an error", func(t *testing.T) {
		_, err := TLSConfig{
			CertFile: filepath.Join(t.TempDir(), "absent.pem"),
			KeyFile:  filepath.Join(t.TempDir(), "absent-key.pem"),
		}.ServerConfig()
		assert.Error(t, err)
	})

	t.Run("valid keypair loads", func(t *testing.T) {
		got, err := TLSConfig{CertFile: certPath, KeyFile: keyPath}.ServerConfig()
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Len(t, got.Certificates, 1)
		// Anything below TLS 1.2 is refused. BENCO does not support the period
		// clients that were the only reason to allow TLS 1.0.
		assert.Equal(t, uint16(0x0303), got.MinVersion)
	})
}

func TestListener_AdvertisedHost(t *testing.T) {
	tlsOn := TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"}

	cases := []struct {
		name     string
		listener Listener
		wantHost string
		wantTLS  bool
	}{
		{
			// Upstream behaviour must be preserved exactly: under stunnel, the
			// SSL host names a different process on a different port, and the
			// socket this server accepted is plaintext. Advertising the SSL
			// host here would be wrong.
			name: "stunnel model advertises the plaintext host",
			listener: Listener{
				BOSAdvertisedHostPlain: "aim.example.com:5190",
				BOSAdvertisedHostSSL:   "aim.example.com:5193",
				HasSSL:                 true,
			},
			wantHost: "aim.example.com:5190",
			wantTLS:  false,
		},
		{
			name: "native TLS with no SSL host advertises the plain host",
			listener: Listener{
				BOSAdvertisedHostPlain: "aim.example.com:5190",
				TLS:                    tlsOn,
			},
			wantHost: "aim.example.com:5190",
			wantTLS:  true,
		},
		{
			// The SSL entry is how an operator publishes a public DNS name that
			// differs from the bind address.
			name: "native TLS prefers an explicit SSL host",
			listener: Listener{
				BOSAdvertisedHostPlain: "10.0.0.5:5190",
				BOSAdvertisedHostSSL:   "aim.example.com:5190",
				HasSSL:                 true,
				TLS:                    tlsOn,
			},
			wantHost: "aim.example.com:5190",
			wantTLS:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantHost, tc.listener.AdvertisedHost())
			assert.Equal(t, tc.wantTLS, tc.listener.UsesTLS())
		})
	}
}

func TestConfig_ParseListenersCfg_CopiesTLS(t *testing.T) {
	cfg := Config{
		BOSListeners:            []string{"LOCAL://0.0.0.0:5190", "WAN://0.0.0.0:5191"},
		BOSAdvertisedHostsPlain: []string{"LOCAL://127.0.0.1:5190", "WAN://aim.example.com:5191"},
		TLS:                     TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
	}

	got, err := cfg.ParseListenersCfg()
	require.NoError(t, err)
	require.Len(t, got, 2)

	// Native TLS is server-wide: every OSCAR socket is encrypted or none is.
	// A listener that missed the copy would silently serve plaintext.
	for _, l := range got {
		assert.True(t, l.UsesTLS(), "listener %s did not inherit TLS config", l.BOSListenAddress)
	}
}

func TestConfig_ParseListenersCfg_NoTLSByDefault(t *testing.T) {
	// Guards the upstream default. Absent TLS config must leave listeners
	// plaintext, which is what upstream's own tests and the stunnel setup
	// assume.
	cfg := Config{
		BOSListeners:            []string{"LOCAL://0.0.0.0:5190"},
		BOSAdvertisedHostsPlain: []string{"LOCAL://127.0.0.1:5190"},
	}

	got, err := cfg.ParseListenersCfg()
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.False(t, got[0].UsesTLS())
}
