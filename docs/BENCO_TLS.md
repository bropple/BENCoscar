# Native TLS (BENCO)

This is a BENCO fork addition. Upstream terminates TLS with an external
[stunnel](https://www.stunnel.org/) process in front of the plaintext OSCAR port;
this lets the server terminate TLS itself, so a deployment can run with **no
plaintext OSCAR port in existence at all**.

Both models are supported. Leaving the new settings unset reproduces upstream's
behaviour exactly, which is what upstream's own tests assert.

## Configuration

| Variable | Meaning |
|---|---|
| `OSCAR_TLS_CERT_FILE` | Path to a PEM certificate chain |
| `OSCAR_TLS_KEY_FILE` | Path to the matching PEM private key |

Setting **both** makes every OSCAR listener a TLS listener. Setting **neither**
keeps them plaintext. Setting exactly one is a startup error, not a fallback —
see "Failure modes" below.

```sh
export OSCAR_TLS_CERT_FILE=/etc/letsencrypt/live/example.com/fullchain.pem
export OSCAR_TLS_KEY_FILE=/etc/letsencrypt/live/example.com/privkey.pem
```

These do not appear in `config/settings.env` or `config/ssl/settings.env`. That
is deliberate on both counts: the config generator skips optional settings with
no default (`cmd/config_generator/main.go:79`, the same treatment upstream gives
`OSCAR_ADVERTISED_LISTENERS_SSL` in the basic profile), and the stock `ssl`
profile *is* the stunnel profile — giving it a native-TLS default would point a
working configuration at a certificate path that doesn't exist.

Certificates are read from disk rather than fetched over ACME. Renewal is
expected to happen out of band (certbot or similar). Pulling an ACME client into
the server would add a network dependency to startup and would want port 80
besides. **The keypair is loaded once at startup**, so a renewed certificate
needs a restart to take effect.

### Advertised hosts

OSCAR tells the client where to reconnect after authenticating, and again for
each service redirect (BOS reconnect, chat rooms). Under native TLS that target
is the same encrypted socket, so `OSCAR_ADVERTISED_LISTENERS_PLAIN` is normally
the right answer despite the name.

`OSCAR_ADVERTISED_LISTENERS_SSL` remains available and takes precedence when
native TLS is on. Use it when the public DNS name differs from the bind address:

```sh
OSCAR_LISTENERS=WAN://0.0.0.0:5190
OSCAR_ADVERTISED_LISTENERS_PLAIN=WAN://10.0.0.5:5190     # bind-side reality
OSCAR_ADVERTISED_LISTENERS_SSL=WAN://chat.example.com:5190 # what clients dial
```

## What changed, and why

Three places. All are small hooks into upstream files; the logic itself lives in
new files (`config/tls.go`, `server/oscar/tls.go`) so it rebases cheaply.

**1. The listener** — `server/oscar/server.go`, via `listenBOS` in
`server/oscar/tls.go`. Wrapping is safe to do bluntly because nothing downstream
depends on the concrete connection type: the accept loop stores `net.Conn`, the
only conn-specific call in the auth path is `SetDeadline` (which `*tls.Conn`
implements), and `wire.FlapClient` asks for no more than `io.Reader`/`io.Writer`.

**2. The login response** — `foodgroup/auth.go`, in `loginSuccessResponse`.
Upstream hardcoded the SSL-state TLV to `NotUsed` here with no check at all, so
the initial login response always claimed the session was unencrypted. Under
stunnel that was merely inaccurate — the client had dialled the TLS port itself
and knew better. Under native TLS it is actively wrong: it invites a reconnect in
cleartext to a port that does not exist.

**3. The service redirect** — `foodgroup/oservice.go`, in `ServiceRequest`. This
covers BOS reconnects and chat room redirects. Native TLS is checked *before*
the client's use-SSL request tag, because a client that sends that tag must not
fall through to the stunnel branch: that branch hands back
`OSCAR_ADVERTISED_LISTENERS_SSL`, which under the stunnel model names a separate
proxy port this deployment does not run.

## Failure modes

**Half-configured TLS refuses to start.** Setting only the cert or only the key
is a hard error (`errPartialTLSConfig`). The dangerous outcome for a
half-configured server is not a crash — it is listening in cleartext while the
operator believes TLS is on, which is the exact mistake this feature exists to
prevent.

**A bad path fails at startup, not at sign-on.** The keypair loads once when the
listener opens, so a typo stops the server immediately rather than breaking every
login attempt at runtime.

**A plaintext client gets nothing.** `tls.NewListener` defers the handshake to
the first read, so the TCP connect itself succeeds and then the connection
fails during FLAP framing. This is the correct trade: it keeps the accept loop
from being stalled by a peer that connects and then says nothing.

## Verifying a deployment

Confirm the log line at startup:

```
msg="starting server" svc=OSCAR listen_address=... native_tls=true
```

Then check the socket really is encrypted:

```sh
openssl s_client -connect chat.example.com:5190 -servername chat.example.com </dev/null
```

A plaintext connection to the same port should hang and time out rather than
returning a FLAP frame (which begins with the byte `0x2A`).

## Tests

- `config/tls_test.go` — enable/disable logic, partial-config rejection, keypair
  loading, advertised-host selection under both models, and that
  `ParseListenersCfg` copies TLS onto every listener.
- `server/oscar/tls_test.go` — real sockets: a completed TLS 1.2+ handshake with
  a payload round trip, plaintext listening still working by default, a partial
  config refusing to listen, and a plaintext client getting **no** cleartext
  response from a TLS listener. That last one is the regression guard for a
  silent downgrade.

Verified end to end against the real binary: a TLS 1.3 sign-on returns
`SSLState = Resume` with the reconnect host pointing at the TLS socket, while the
same build with TLS unset returns `SSLState = NotUsed`, matching upstream.
