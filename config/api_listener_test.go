package config

import (
	"strings"
	"testing"
)

func TestParseAPIListener(t *testing.T) {
	tests := []struct {
		name         string
		in           string
		wantErr      string
		wantKind     APIListenerKind
		wantNetwork  string
		wantAddress  string
		wantLoopback bool
	}{
		{
			name:         "unix socket",
			in:           "unix:/run/bencoscar/mgmt.sock",
			wantKind:     APIListenerUnix,
			wantNetwork:  "unix",
			wantAddress:  "/run/bencoscar/mgmt.sock",
			wantLoopback: true,
		},
		{
			name:         "unix socket with URL-style slashes",
			in:           "unix:///run/bencoscar/mgmt.sock",
			wantKind:     APIListenerUnix,
			wantNetwork:  "unix",
			wantAddress:  "/run/bencoscar/mgmt.sock",
			wantLoopback: true,
		},
		{
			name:         "unix socket path is cleaned",
			in:           "unix:/run/bencoscar/../bencoscar/mgmt.sock",
			wantKind:     APIListenerUnix,
			wantAddress:  "/run/bencoscar/mgmt.sock",
			wantNetwork:  "unix",
			wantLoopback: true,
		},
		{
			name:         "surrounding whitespace is tolerated",
			in:           "  unix:/run/bencoscar/mgmt.sock  ",
			wantKind:     APIListenerUnix,
			wantNetwork:  "unix",
			wantAddress:  "/run/bencoscar/mgmt.sock",
			wantLoopback: true,
		},
		{
			name:    "unix socket with no path",
			in:      "unix:",
			wantErr: "missing socket path",
		},
		{
			// The server's working directory is not something an operator can
			// predict, so a relative socket path is a bug rather than a choice.
			name:    "relative unix socket path",
			in:      "unix:mgmt.sock",
			wantErr: "must be absolute",
		},
		{
			name:         "loopback IPv4",
			in:           "127.0.0.1:8080",
			wantKind:     APIListenerTCP,
			wantNetwork:  "tcp",
			wantAddress:  "127.0.0.1:8080",
			wantLoopback: true,
		},
		{
			name:         "loopback IPv4 outside 127.0.0.1",
			in:           "127.9.9.9:8080",
			wantKind:     APIListenerTCP,
			wantAddress:  "127.9.9.9:8080",
			wantNetwork:  "tcp",
			wantLoopback: true,
		},
		{
			name:         "loopback IPv6",
			in:           "[::1]:8080",
			wantKind:     APIListenerTCP,
			wantAddress:  "[::1]:8080",
			wantNetwork:  "tcp",
			wantLoopback: true,
		},
		{
			name:         "localhost counts as loopback",
			in:           "localhost:8080",
			wantKind:     APIListenerTCP,
			wantAddress:  "localhost:8080",
			wantNetwork:  "tcp",
			wantLoopback: true,
		},
		{
			// The single most dangerous typo this parser exists to catch.
			name:         "IPv4 wildcard is not loopback",
			in:           "0.0.0.0:8080",
			wantKind:     APIListenerTCP,
			wantAddress:  "0.0.0.0:8080",
			wantNetwork:  "tcp",
			wantLoopback: false,
		},
		{
			name:         "IPv6 wildcard is not loopback",
			in:           "[::]:8080",
			wantKind:     APIListenerTCP,
			wantAddress:  "[::]:8080",
			wantNetwork:  "tcp",
			wantLoopback: false,
		},
		{
			name:         "routable address is not loopback",
			in:           "192.168.1.10:8080",
			wantKind:     APIListenerTCP,
			wantAddress:  "192.168.1.10:8080",
			wantNetwork:  "tcp",
			wantLoopback: false,
		},
		{
			// Resolution can change under the server's feet, so a hostname is
			// never taken on trust.
			name:         "hostname is not assumed loopback",
			in:           "chat.example.com:8080",
			wantKind:     APIListenerTCP,
			wantAddress:  "chat.example.com:8080",
			wantNetwork:  "tcp",
			wantLoopback: false,
		},
		{
			name:    "empty",
			in:      "",
			wantErr: "required and cannot be empty",
		},
		{
			name:    "whitespace only",
			in:      "   ",
			wantErr: "required and cannot be empty",
		},
		{
			name:    "missing port",
			in:      "127.0.0.1",
			wantErr: "missing port",
		},
		{
			name:    "missing host",
			in:      ":8080",
			wantErr: "missing host",
		},
		{
			name:    "not an address at all",
			in:      "invalid-format",
			wantErr: "invalid API listener",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAPIListener(tt.in)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseAPIListener(%q) = %+v, want error containing %q", tt.in, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseAPIListener(%q) error = %v, want it to contain %q", tt.in, err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseAPIListener(%q) unexpected error: %v", tt.in, err)
			}
			if got.Kind != tt.wantKind {
				t.Errorf("Kind = %v, want %v", got.Kind, tt.wantKind)
			}
			if got.Network != tt.wantNetwork {
				t.Errorf("Network = %q, want %q", got.Network, tt.wantNetwork)
			}
			if got.Address != tt.wantAddress {
				t.Errorf("Address = %q, want %q", got.Address, tt.wantAddress)
			}
			if got.Loopback != tt.wantLoopback {
				t.Errorf("Loopback = %v, want %v", got.Loopback, tt.wantLoopback)
			}
		})
	}
}

// TestValidateRefusesExposedAPI covers the check that exists because
// API_LISTENER is an environment variable: one edit turns an unauthenticated
// admin API into a public one, and nothing else in the system would notice.
func TestValidateRefusesExposedAPI(t *testing.T) {
	tests := []struct {
		name     string
		listener string
		allow    bool
		wantErr  bool
	}{
		{name: "loopback TCP is fine", listener: "127.0.0.1:8080", wantErr: false},
		{name: "localhost is fine", listener: "localhost:8080", wantErr: false},
		{name: "unix socket is fine", listener: "unix:/run/bencoscar/mgmt.sock", wantErr: false},
		{name: "wildcard bind is refused", listener: "0.0.0.0:8080", wantErr: true},
		{name: "IPv6 wildcard bind is refused", listener: "[::]:8080", wantErr: true},
		{name: "routable bind is refused", listener: "10.0.0.5:8080", wantErr: true},
		{name: "hostname bind is refused", listener: "chat.example.com:8080", wantErr: true},
		{
			name:     "explicit override permits a wildcard bind",
			listener: "0.0.0.0:8080",
			allow:    true,
			wantErr:  false,
		},
		{
			// The override is about network exposure; it must not quietly
			// legitimise a malformed value.
			name:     "override does not excuse a malformed listener",
			listener: "not-an-address",
			allow:    true,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				TOCListeners:        []string{"0.0.0.0:9898"},
				APIListener:         tt.listener,
				APIAllowNonLoopback: tt.allow,
			}

			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("Validate() with API listener %q: expected an error, got none", tt.listener)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() with API listener %q: unexpected error: %v", tt.listener, err)
			}
		})
	}
}

// TestExposedAPIErrorExplainsItself checks the message, not just the refusal.
// An operator who hits this is mid-deploy and needs the alternative spelled
// out, not a policy statement.
func TestExposedAPIErrorExplainsItself(t *testing.T) {
	cfg := Config{TOCListeners: []string{"0.0.0.0:9898"}, APIListener: "0.0.0.0:8080"}

	err := cfg.Validate()
	if err != nil {
		for _, want := range []string{
			"NO authentication",             // why
			"unix:/run/bencoscar/mgmt.sock", // the recommended fix
			"API_ALLOW_NONLOOPBACK=true",    // the escape hatch, if they meant it
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error message is missing %q:\n%v", want, err)
			}
		}
		return
	}
	t.Fatal("Validate() accepted a wildcard management API bind")
}
