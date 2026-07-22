package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

var (
	// Simple error for duplicate listener definitions
	errDuplicateListener = errors.New("duplicate listener definition")
	// Simple error for missing BOS listeners
	errNoBOSListeners = errors.New("at least one BOS listener is required")
)

// Custom error types for URI-related errors
type uriFormatError struct {
	URI string
	Err error
}

func (e uriFormatError) Error() string {
	return fmt.Sprintf("invalid listener URI %q: %v. Valid format: SCHEME://HOST:PORT (e.g., LOCAL://0.0.0.0:5190)", e.URI, e.Err)
}

type Build struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

type Listener struct {
	BOSListenAddress       string
	BOSAdvertisedHostPlain string
	BOSAdvertisedHostSSL   string
	KerberosListenAddress  string
	HasSSL                 bool
	// TLS is the BENCO native-TLS config, copied onto every listener by
	// ParseListenersCfg. It lives here rather than being threaded separately
	// because config.Listener is already passed down to every place that needs
	// to know how a connection arrived — the accept loop and the two advertised
	// -host decisions. See config/tls.go.
	TLS TLSConfig
}

//go:generate go run ../cmd/config_generator unix settings.env ssl
type Config struct {
	BOSListeners            []string `envconfig:"OSCAR_LISTENERS" required:"true" basic:"LOCAL://0.0.0.0:5190" ssl:"LOCAL://0.0.0.0:5190" description:"Network listeners for core OSCAR services. For multi-homed servers, allows users to connect from multiple networks. For example, you can allow both LAN and Internet clients to connect to the same server using different connection settings.\n\nFormat:\n\t- Comma-separated list of [NAME]://[HOSTNAME]:[PORT]\n\t- Listener names and ports must be unique\n\t- Listener names are user-defined\n\t- Each listener needs a listener in OSCAR_ADVERTISED_LISTENERS_PLAIN\n\nExamples:\n\t// Listen on all interfaces\n\tLAN://0.0.0.0:5190\n\t// Separate Internet and LAN config\n\tWAN://142.250.176.206:5190,LAN://192.168.1.10:5191"`
	BOSAdvertisedHostsPlain []string `envconfig:"OSCAR_ADVERTISED_LISTENERS_PLAIN" required:"true" basic:"LOCAL://127.0.0.1:5190" ssl:"LOCAL://127.0.0.1:5190" description:"Hostnames published by the server that clients connect to for accessing various OSCAR services. These hostnames are NOT the bind addresses. For multi-homed use servers, allows clients to connect using separate hostnames per network.\n\nFormat:\n\t- Comma-separated list of [NAME]://[HOSTNAME]:[PORT]\n\t- Each listener config must correspond to a config in OSCAR_LISTENERS\n\t- Clients MUST be able to connect to these hostnames\n\nExamples:\n\t// Local LAN config, server behind NAT\n\tLAN://192.168.1.10:5190\n\t// Separate Internet and LAN config\n\tWAN://aim.example.com:5190,LAN://192.168.1.10:5191"`
	BOSAdvertisedHostsSSL   []string `envconfig:"OSCAR_ADVERTISED_LISTENERS_SSL" required:"false" basic:"" ssl:"LOCAL://ras.dev:5193" description:"Same as OSCAR_ADVERTISED_LISTENERS_PLAIN, except the hostname is for the server that terminates SSL."`
	KerberosListeners       []string `envconfig:"KERBEROS_LISTENERS" required:"false" basic:"" ssl:"LOCAL://0.0.0.0:1088" description:"Network listeners for Kerberos authentication. See OSCAR_LISTENERS doc for more details.\n\nExamples:\n\t// Listen on all interfaces\n\tLAN://0.0.0.0:1088\n\t// Separate Internet and LAN config\n\tWAN://142.250.176.206:1088,LAN://192.168.1.10:1087"`
	TOCListeners            []string `envconfig:"TOC_LISTENERS" required:"true" basic:"0.0.0.0:9898" ssl:"0.0.0.0:9898" description:"Network listeners for TOC protocol service.\n\nFormat: Comma-separated list of hostname:port pairs.\n\nExamples:\n\t// All interfaces\n\t0.0.0.0:9898\n\t// Multiple listeners\n\t0.0.0.0:9898,192.168.1.10:9899"`
	APIListener             string   `envconfig:"API_LISTENER" required:"true" basic:"unix:/run/bencoscar/mgmt.sock" ssl:"unix:/run/bencoscar/mgmt.sock" description:"Listener the management API binds to. Only 1 listener can be specified.\n\nFormat:\n\t- unix:/PATH/TO.sock for a unix domain socket (RECOMMENDED)\n\t- HOST:PORT for a TCP bind\n\nThe management API has NO authentication of its own: anything that can reach it has full administrative control, including creating accounts and resetting any password. A unix socket makes the filesystem the authentication -- the kernel refuses a connection before the server reads a byte, there is no token to leak or rotate, and a socket path cannot be typo'd onto the network.\n\nSet API_SOCKET_GROUP alongside this when using a socket. Without it the socket keeps the service account's own group, so only that account and root may administer the server -- which is secure but grants nothing to the operators you meant to grant it to.\n\nA TCP bind still works, but a non-loopback one requires API_ALLOW_NONLOOPBACK=true, so that exposing the API is a deliberate act rather than an editing accident.\n\nExamples:\n\t// Unix socket (recommended)\n\tunix:/run/bencoscar/mgmt.sock\n\t// Loopback TCP\n\t127.0.0.1:8080"`
	APISocketGroup          string   `envconfig:"API_SOCKET_GROUP" required:"false" basic:"" ssl:"" description:"Unix group permitted to administer this server through the management socket. Ignored unless API_LISTENER names a unix socket.\n\nThe server gives the socket and its directory to this group at startup, which is what makes group membership the credential for administration -- there is nothing else to hold. The server must itself be a member of the group to be able to hand it over; under systemd that means SupplementaryGroups=.\n\nLeft empty, the socket keeps the service account's own group, which means only that account and root may administer the server.\n\nExample:\n\tbencoscar-admin"`
	APIAllowNonLoopback     bool     `envconfig:"API_ALLOW_NONLOOPBACK" required:"false" basic:"false" ssl:"false" description:"Permit API_LISTENER to bind a TCP address reachable from off this machine. The server refuses to start otherwise, because the management API has no authentication of its own and a non-loopback bind hands full administrative control to whoever can route to it. Only set this when something else -- an authenticating reverse proxy, or a network only trusted operators can reach -- supplies the access control the API does not."`

	DBPath string `envconfig:"DB_PATH" required:"true" basic:"oscar.sqlite" ssl:"oscar.sqlite" description:"The path to the SQLite database file. The file and DB schema are auto-created if they doesn't exist.\n\nIf this path lives on a separate or encrypted volume, set DB_REQUIRE_EXISTING=true as well, so that a volume which failed to mount is a startup error rather than a brand new empty database created on the bare mountpoint."`
	// BENCO addition. See state/db_require_existing.go for what this prevents.
	DBRequireExisting      bool   `envconfig:"DB_REQUIRE_EXISTING" required:"false" basic:"false" ssl:"false" description:"Refuse to start when DB_PATH does not already exist, instead of creating a new database there. Leave this false for a first run; set it true afterwards on any server whose database lives on a separate or encrypted volume.\n\nSQLite creates a database file on demand, so if the volume holding DB_PATH fails to mount, the mountpoint is an empty directory and the server starts healthy with no accounts. Sign-on then reports a wrong password, nothing logs anything alarming, and the next backup overwrites a good database with the empty one. This setting turns that silent data loss into a refusal to start."`
	DeviceAuth             string `envconfig:"BENCO_DEVICE_AUTH" required:"false" default:"log" basic:"log" ssl:"log" description:"BENCO device attestation mode: off, log, or enforce. A password proves an ACCOUNT; attestation proves which DEVICE of it is talking, which is what makes removing a device mean anything. Accounts with no published devices always sign in with a password alone -- that is how a new account gets its first device in, and how an operator restores access to somebody who lost every device. Start on log: enforcing before real sessions have been seen passing means a bug locks out every account that has a device."`
	DisableAuth            bool   `envconfig:"DISABLE_AUTH" required:"true" basic:"true" ssl:"true" description:"Disable password check and auto-create new users at login time. Useful for quickly creating new accounts during development without having to register new users via the management API."`
	DisableMultiLoginNotif bool   `envconfig:"DISABLE_MULTI_LOGIN_NOTIF" required:"false" basic:"true" ssl:"true" description:"Disable notification sent when another client signs in with the same screen name."`
	LogLevel               string `envconfig:"LOG_LEVEL" required:"true" basic:"info" ssl:"info" description:"Set logging granularity. Possible values: 'trace', 'debug', 'info', 'warn', 'error'."`

	// ICQ Legacy Protocol Configuration
	ICQLegacy ICQLegacyConfig

	// TLS configures native TLS termination for the OSCAR listeners (BENCO
	// addition — see config/tls.go). Unset means upstream behaviour: plaintext
	// sockets, with TLS terminated by an external stunnel if at all.
	TLS TLSConfig
}

// ICQLegacyConfig holds configuration for legacy ICQ protocol support (v2-v5)
type ICQLegacyConfig struct {
	Enabled            bool          `envconfig:"ICQ_LEGACY_ENABLED" required:"false" basic:"true" ssl:"true" description:"Enable legacy ICQ protocol support (v2-v5). Allows vintage ICQ clients to connect."`
	UDPListener        string        `envconfig:"ICQ_LEGACY_UDP_LISTENER" required:"false" basic:"0.0.0.0:4000" ssl:"0.0.0.0:4000" description:"UDP listener address for legacy ICQ protocols.\n\nFormat: HOST:PORT\n\nExamples:\n\t// All interfaces\n\t0.0.0.0:4000\n\t// Specific interface\n\t192.168.1.10:4000"`
	SupportedVersions  []int         `envconfig:"ICQ_LEGACY_VERSIONS" required:"false" basic:"2,3,4,5" ssl:"2,3,4,5" description:"Comma-separated list of supported ICQ protocol versions. Valid values: 1, 2, 3, 4, 5 (V1 is experimental)."`
	SessionTimeout     time.Duration `envconfig:"ICQ_LEGACY_SESSION_TIMEOUT" required:"false" basic:"120s" ssl:"120s" description:"Session timeout for legacy ICQ connections. Sessions are cleaned up after this duration of inactivity."`
	KeepAliveInterval  time.Duration `envconfig:"ICQ_LEGACY_KEEPALIVE_INTERVAL" required:"false" basic:"120s" ssl:"120s" description:"Expected keep-alive interval from clients. Used for timeout calculations."`
	AutoRegistration   bool          `envconfig:"ICQ_LEGACY_AUTO_REGISTRATION" required:"false" basic:"false" ssl:"false" description:"Allow automatic user registration from legacy clients. When enabled, new UINs can be created via the legacy protocol."`
	DepartmentsEnabled bool          `envconfig:"ICQ_LEGACY_DEPARTMENTS_ENABLED" required:"false" basic:"false" ssl:"false" description:"Enable department listing feature (groupware functionality)."`
	BroadcastEnabled   bool          `envconfig:"ICQ_LEGACY_BROADCAST_ENABLED" required:"false" basic:"true" ssl:"true" description:"Enable broadcast message functionality."`
	WWPEnabled         bool          `envconfig:"ICQ_LEGACY_WWP_ENABLED" required:"false" basic:"true" ssl:"true" description:"Enable Web Pager (WWP) message support."`
	DirectConnections  []int         `envconfig:"ICQ_LEGACY_DIRECT_CONNECTIONS" required:"false" basic:"5" ssl:"5" description:"Comma-separated list of protocol versions that send real connection info (IP, port) in user online notifications. Disabled for privacy and interoperability. Required for peer-to-peer features (file transfer, direct chat). Example: 5 or 3,4,5"`
}

// DefaultICQLegacyConfig returns the default configuration for ICQ legacy protocol
func DefaultICQLegacyConfig() ICQLegacyConfig {
	return ICQLegacyConfig{
		Enabled:            true,
		UDPListener:        "0.0.0.0:4000",
		SupportedVersions:  []int{2, 3, 4, 5},
		SessionTimeout:     120 * time.Second,
		KeepAliveInterval:  120 * time.Second,
		AutoRegistration:   false,
		DepartmentsEnabled: false,
		BroadcastEnabled:   true,
		WWPEnabled:         true,
	}
}

// SupportsVersion checks if a specific protocol version is enabled
func (c *ICQLegacyConfig) SupportsVersion(version int) bool {
	for _, v := range c.SupportedVersions {
		if v == version {
			return true
		}
	}
	return false
}

// DirectConnectionEnabled checks if direct connections are enabled for a specific protocol version
func (c *ICQLegacyConfig) DirectConnectionEnabled(version int) bool {
	for _, v := range c.DirectConnections {
		if v == version {
			return true
		}
	}
	return false
}

func (c *Config) ParseListenersCfg() ([]Listener, error) {
	// Helper function to parse and validate a single URI
	parseURI := func(uriStr string) (*url.URL, error) {
		uriStr = strings.TrimSpace(uriStr)
		if uriStr == "" {
			return nil, nil
		}

		u, err := url.Parse(uriStr)
		if err != nil {
			return nil, uriFormatError{URI: uriStr, Err: err}
		}
		switch {
		case u.Scheme == "":
			return nil, uriFormatError{URI: uriStr, Err: errors.New("missing scheme")}
		case u.Hostname() == "":
			return nil, uriFormatError{URI: uriStr, Err: errors.New("missing host")}
		case u.Port() == "":
			return nil, uriFormatError{URI: uriStr, Err: errors.New("missing port")}
		}

		return u, nil
	}

	m := make(map[string]*Listener)

	// Parse BOS listeners
	for _, uriStr := range c.BOSListeners {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &Listener{}
		}
		if m[u.Scheme].BOSListenAddress != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].BOSListenAddress = net.JoinHostPort(u.Hostname(), u.Port())
	}

	// Parse plaintext BOS advertised listeners
	for _, uriStr := range c.BOSAdvertisedHostsPlain {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &Listener{}
		}
		if m[u.Scheme].BOSAdvertisedHostPlain != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].BOSAdvertisedHostPlain = net.JoinHostPort(u.Hostname(), u.Port())
	}

	// Parse SSL BOS advertised listeners
	for _, uriStr := range c.BOSAdvertisedHostsSSL {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &Listener{}
		}
		if m[u.Scheme].BOSAdvertisedHostSSL != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].HasSSL = true
		m[u.Scheme].BOSAdvertisedHostSSL = net.JoinHostPort(u.Hostname(), u.Port())
	}

	// Parse Kerberos listeners
	for _, uriStr := range c.KerberosListeners {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &Listener{}
		}
		if m[u.Scheme].KerberosListenAddress != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].KerberosListenAddress = net.JoinHostPort(u.Hostname(), u.Port())
	}

	ret := make([]Listener, 0, len(m))

	for k, v := range m {
		switch {
		case v.BOSAdvertisedHostPlain == "":
			return nil, fmt.Errorf("missing BOS advertise address for listener `%s://`", k)
		case v.BOSListenAddress == "":
			return nil, fmt.Errorf("missing BOS listen address for listener `%s://`", k)
		}
		// BENCO: native TLS is server-wide rather than per-listener — every
		// OSCAR socket is encrypted or none is. Copying it onto each listener
		// keeps the accept loop and the advertised-host logic reading a single
		// value they already hold, instead of reaching back up to Config.
		v.TLS = c.TLS
		ret = append(ret, *v)
	}

	if len(ret) == 0 {
		return nil, errNoBOSListeners
	}

	return ret, nil
}

func (c *Config) Validate() error {
	// Validate TOCListeners (format: hostname:port pairs)
	for _, listener := range c.TOCListeners {
		listener = strings.TrimSpace(listener)
		if listener == "" {
			continue
		}

		host, port, err := net.SplitHostPort(listener)
		if err != nil {
			return fmt.Errorf("invalid TOC listener %q: %v. Valid format: HOST:PORT (e.g., 0.0.0.0:9898)", listener, err)
		}

		if host == "" {
			return fmt.Errorf("invalid TOC listener %q: missing host. Valid format: HOST:PORT (e.g., 0.0.0.0:9898)", listener)
		}

		if port == "" {
			return fmt.Errorf("invalid TOC listener %q: missing port. Valid format: HOST:PORT (e.g., 0.0.0.0:9898)", listener)
		}
	}

	// Validate APIListener: either unix:/PATH/TO.sock or HOST:PORT.
	spec, err := ParseAPIListener(c.APIListener)
	if err != nil {
		return err
	}

	// A non-loopback management API is not a configuration this server will
	// adopt by accident. The API authenticates nobody, so binding it to a
	// routable address is equivalent to publishing an unauthenticated "reset
	// any password" endpoint -- which is a decision, not a default.
	if spec.Kind == APIListenerTCP && !spec.Loopback && !c.APIAllowNonLoopback {
		return fmt.Errorf("refusing to start: API listener %q is reachable from off this machine. "+
			"The management API has NO authentication of its own -- anything that can connect to it can "+
			"create accounts, delete them, reset any password and disconnect any session. Either use a "+
			"unix socket, which makes filesystem permissions the authentication:\n"+
			"\tAPI_LISTENER=unix:/run/bencoscar/mgmt.sock\n"+
			"or keep it on loopback and reach it through an SSH tunnel:\n"+
			"\tAPI_LISTENER=127.0.0.1:8080\n"+
			"If something else is genuinely providing access control (an authenticating reverse proxy, "+
			"or a network only trusted operators can reach), say so explicitly with "+
			"API_ALLOW_NONLOOPBACK=true", c.APIListener)
	}

	return nil
}
