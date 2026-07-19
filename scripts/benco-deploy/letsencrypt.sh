#!/usr/bin/env bash
# Get a real TLS certificate for BENCoscar and keep it renewed.
#
#   sudo HOSTNAME_FQDN=chat.example.com ./letsencrypt.sh
#
# Uses DNS-01 via Cloudflare, so port 80 never has to be open and renewal is
# unattended. If your DNS is elsewhere, swap the certbot plugin below.
#
# IMPORTANT: BENCoscar loads the keypair ONCE at startup, so a renewed
# certificate does not take effect until the service restarts. The deploy hook
# installed here does that restart — without it the server would quietly serve
# an expired certificate until someone noticed.
#
# Safe to re-run.

set -euo pipefail

HOSTNAME_FQDN="${HOSTNAME_FQDN:-}"
EMAIL="${EMAIL:-}"
CF_TOKEN_FILE="${CF_TOKEN_FILE:-/etc/letsencrypt/cloudflare.ini}"
CONF_DIR=/etc/bencoscar
TLS_DIR="$CONF_DIR/tls"
SVC_USER="${SVC_USER:-bencoscar}"

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run this with sudo:  sudo HOSTNAME_FQDN=... ./letsencrypt.sh"
[ -n "$HOSTNAME_FQDN" ] || die "Set the hostname the certificate is for:
       sudo HOSTNAME_FQDN=chat.example.com ./letsencrypt.sh"

LIVE="/etc/letsencrypt/live/$HOSTNAME_FQDN"

# --- certbot ---------------------------------------------------------------
if ! command -v certbot >/dev/null 2>&1; then
  say "Installing certbot"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y certbot python3-certbot-dns-cloudflare
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y certbot python3-certbot-dns-cloudflare
  else
    die "Install certbot and the dns-cloudflare plugin manually, then re-run."
  fi
fi

# --- Cloudflare credentials ------------------------------------------------
if [ ! -s "$CF_TOKEN_FILE" ]; then
  cat >&2 <<EOF

Cloudflare API token needed at $CF_TOKEN_FILE

  Create a token with Zone:DNS:Edit on the zone, then:

    sudo install -m 600 /dev/null $CF_TOKEN_FILE
    sudo tee $CF_TOKEN_FILE >/dev/null <<'INI'
dns_cloudflare_api_token = your-token-here
INI

EOF
  die "missing $CF_TOKEN_FILE"
fi
chmod 600 "$CF_TOKEN_FILE"

# --- issue -----------------------------------------------------------------
if [ -s "$LIVE/fullchain.pem" ]; then
  say "Certificate for $HOSTNAME_FQDN already exists"
else
  say "Requesting a certificate for $HOSTNAME_FQDN"
  EMAIL_ARG=(--register-unsafely-without-email)
  [ -n "$EMAIL" ] && EMAIL_ARG=(--email "$EMAIL")

  certbot certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials "$CF_TOKEN_FILE" \
    --dns-cloudflare-propagation-seconds 30 \
    -d "$HOSTNAME_FQDN" \
    --agree-tos --non-interactive "${EMAIL_ARG[@]}"
fi

[ -s "$LIVE/fullchain.pem" ] || die "certbot did not produce $LIVE/fullchain.pem"

# --- deploy hook -----------------------------------------------------------
# Copies rather than symlinks: certbot's live/ paths are symlinks into archive/,
# and the service user cannot traverse /etc/letsencrypt. Copying also means the
# running server keeps working if certbot's tree is disturbed.
say "Installing the renewal hook"
HOOK=/etc/letsencrypt/renewal-hooks/deploy/bencoscar.sh
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > "$HOOK" <<EOF
#!/usr/bin/env bash
# Installed by BENCoscar letsencrypt.sh. Runs after every successful renewal.
set -euo pipefail

install -m 0644 -o root -g $SVC_USER -T "$LIVE/fullchain.pem" "$TLS_DIR/fullchain.pem"
install -m 0640 -o root -g $SVC_USER -T "$LIVE/privkey.pem"   "$TLS_DIR/privkey.pem"

# BENCoscar reads the keypair once at startup, so a renewal is invisible until
# the service restarts. Without this it would serve the old certificate until it
# expired and clients started failing.
systemctl restart bencoscar
EOF
chmod +x "$HOOK"

say "Installing the certificate now"
"$HOOK"

say "Starting bencoscar"
systemctl enable --now bencoscar
sleep 2
if systemctl is-active --quiet bencoscar; then
  say "Running with a real certificate"
else
  warn "Service did not come up. Recent log:"
  journalctl -u bencoscar -n 30 --no-pager
  exit 1
fi

cat <<EOF

$(printf '\033[1;32m==>\033[0m') TLS ready, auto-renewing.

  Verify the certificate a client will actually see:

    openssl s_client -connect $HOSTNAME_FQDN:\${OSCAR_PORT:-5191} \\
      -servername $HOSTNAME_FQDN </dev/null 2>/dev/null | openssl x509 -noout -subject -dates

  Test renewal without changing anything:

    sudo certbot renew --dry-run

  A plaintext connection to that port should hang and time out rather than
  answering — there is no cleartext OSCAR listener any more.
EOF
