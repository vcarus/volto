#!/usr/bin/env bash
#
# One-shot installer for volto with a self-signed certificate.
#
# For the deployment where you do not want to own a domain: the certificate is
# generated here, on this machine, and the client is told to trust exactly that
# one certificate by its SHA-256 fingerprint. Surge calls this
# `server-cert-fingerprint-sha256`.
#
# The trade-off against the ACME path is in docs/deployment.md. The short
# version: no domain and no renewals, but the fingerprint has to reach every
# client through a channel you trust, and there is no revocation if it leaks.
#
# Safe to re-run: anything that already exists is left alone.

set -euo pipefail

# --- defaults ---------------------------------------------------------------

BINARY="${BINARY:-./target/release/volto}"
# Remembered so an unset name can be asked for interactively later; an explicit
# --sni or a SNI in the environment must never be second-guessed.
SNI_GIVEN=0
[ -z "${SNI:-}" ] || SNI_GIVEN=1
SNI="${SNI:-volto.internal}"
PORT="${PORT:-443}"
USERNAME="${USERNAME:-surge}"
PASSWORD="${PASSWORD:-}"
FORCE=0
PRINT_CONFIG=0

CONF_DIR=/etc/volto
CONF="$CONF_DIR/config.toml"
CERT="$CONF_DIR/cert.pem"
KEY="$CONF_DIR/key.pem"
SERVICE_NAME=volto
UNIT="/etc/systemd/system/$SERVICE_NAME.service"
CERT_DAYS=3650

usage() {
    cat <<'USAGE'
Usage: sudo script/install-selfsigned.sh [options]

Installs volto with a freshly generated self-signed certificate, a systemd unit
and one user, then prints the Surge policy line to paste into your config.

Options:
  -b, --binary PATH    volto binary to install   (default: ./target/release/volto)
  -s, --sni NAME       certificate name and SNI  (asked for interactively when
                       neither this nor $SNI is set; default: volto.internal)
  -p, --port PORT      UDP port to listen on     (default: 443)
  -u, --username NAME  proxy username            (default: surge)
  -w, --password PASS  proxy password            (default: generated)
  -f, --force          regenerate the certificate even if one exists
      --print-config   print the config that would be generated, then exit
                       (changes nothing, needs no root; used by the test suite)
  -h, --help           show this help

Every option can also be given as an environment variable: BINARY, SNI, PORT,
USERNAME, PASSWORD.

Re-running is safe: an existing config file, certificate or user is kept as it
is. --force regenerates the certificate only; it never rewrites config.toml, so
edits you made there survive. Note that regenerating the certificate changes the
fingerprint, so every client has to be updated.
USAGE
}

die() {
    echo "error: $*" >&2
    exit 1
}

note() {
    echo "  $*"
}

# --- arguments --------------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        -b|--binary)   [ $# -ge 2 ] || die "$1 needs a value"; BINARY="$2"; shift 2 ;;
        -s|--sni)      [ $# -ge 2 ] || die "$1 needs a value"; SNI="$2"; SNI_GIVEN=1; shift 2 ;;
        -p|--port)     [ $# -ge 2 ] || die "$1 needs a value"; PORT="$2"; shift 2 ;;
        -u|--username) [ $# -ge 2 ] || die "$1 needs a value"; USERNAME="$2"; shift 2 ;;
        -w|--password) [ $# -ge 2 ] || die "$1 needs a value"; PASSWORD="$2"; shift 2 ;;
        -f|--force)    FORCE=1; shift ;;
        --print-config) PRINT_CONFIG=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             usage >&2; die "unknown option: $1" ;;
    esac
done

# --- sources ----------------------------------------------------------------

# The unit and the example config live next to this script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UNIT_SRC="$SCRIPT_DIR/masque.service"
EXAMPLE_SRC="$SCRIPT_DIR/config.example.toml"

# Derives the installed config from the shipped example, so the generated file
# keeps every comment explaining the keys it does not touch. Only four values are
# substituted, each anchored to the start of its line so a value cannot match a
# comment or the commented-out second user.
generate_config() {
    sed \
        -e "s|^listen = .*|listen = \"0.0.0.0:$PORT\"|" \
        -e "s|^cert = .*|cert = \"$CERT\"|" \
        -e "s|^key = .*|key = \"$KEY\"|" \
        -e "s|^  { username = .*|  { username = \"$USERNAME\", password = \"$PASSWORD\" },|" \
        "$EXAMPLE_SRC"
}

if [ "$PRINT_CONFIG" -eq 1 ]; then
    [ -f "$EXAMPLE_SRC" ] || die "missing $EXAMPLE_SRC"
    [ -n "$PASSWORD" ] || PASSWORD="$(openssl rand -base64 18)"
    generate_config
    exit 0
fi

# --- preflight --------------------------------------------------------------

[ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0)"

command -v apt-get >/dev/null 2>&1 ||
    die "this script targets Debian/Ubuntu; install manually elsewhere (see docs/deployment.md)"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
command -v openssl >/dev/null 2>&1 || die "openssl is required (apt install openssl)"

case "$PORT" in
    ''|*[!0-9]*) die "port must be a number, got: $PORT" ;;
esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "port out of range: $PORT"

# A username with a colon cannot be expressed in HTTP Basic (RFC 7617), and volto
# rejects one at startup. Catch it here, where the message can be clearer.
case "$USERNAME" in
    *:*) die "username must not contain a colon (RFC 7617)" ;;
    '')  die "username must not be empty" ;;
esac
case "$USERNAME$PASSWORD" in
    *'"'*|*\\*) die "username and password must not contain quotes or backslashes" ;;
esac

[ -f "$BINARY" ] || die "no volto binary at $BINARY — build it first: cargo build --release"
[ -x "$BINARY" ] || die "$BINARY is not executable"

[ -f "$UNIT_SRC" ] || die "missing $UNIT_SRC"
[ -f "$EXAMPLE_SRC" ] || die "missing $EXAMPLE_SRC"

# --- certificate name -------------------------------------------------------

# The name goes into the certificate (CN and SAN) and has to match what the
# client sends as `sni=`, so it is worth asking for rather than defaulting
# silently. Only when a human is there to answer: with no terminal (cloud-init,
# CI, a pipe) the default stands and the run remains non-interactive.
if [ "$SNI_GIVEN" -eq 0 ] && [ -t 0 ]; then
    answer=""
    read -r -p "Certificate domain/SNI [$SNI]: " answer || answer=""
    [ -z "$answer" ] || SNI="$answer"
fi

echo "==> installing volto (self-signed, sni=$SNI, port=$PORT)"

# --- user and directories ---------------------------------------------------

if id -u volto >/dev/null 2>&1; then
    note "system user 'volto' already exists, keeping it"
else
    useradd --system --no-create-home --shell /usr/sbin/nologin volto
    note "created system user 'volto'"
fi

install -m 0755 "$BINARY" /usr/local/bin/volto
note "installed $(/usr/local/bin/volto --version 2>/dev/null || echo volto) to /usr/local/bin/volto"

install -d -o volto -g volto -m 0750 "$CONF_DIR"

# --- certificate ------------------------------------------------------------

if [ -f "$CERT" ] && [ -f "$KEY" ] && [ "$FORCE" -eq 0 ]; then
    note "certificate already exists, keeping it (use --force to regenerate)"
else
    if [ -f "$CERT" ]; then
        backup="$CERT.$(date +%Y%m%d%H%M%S).bak"
        mv "$CERT" "$backup"
        if [ -f "$KEY" ]; then
            mv "$KEY" "$KEY.$(date +%Y%m%d%H%M%S).bak"
        fi
        note "backed up the previous certificate to $backup"
    fi

    # EC P-256: smaller handshake than RSA, and universally supported by TLS 1.3.
    # The SAN is what actually gets matched -- a bare CN has not been accepted for
    # years -- so it must be present even though the name is fictional.
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$KEY" -out "$CERT" \
        -days "$CERT_DAYS" -nodes \
        -subj "/CN=$SNI" \
        -addext "subjectAltName=DNS:$SNI" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" \
        >/dev/null 2>&1 ||
        die "openssl failed to generate the certificate"

    note "generated a self-signed certificate for $SNI, valid $CERT_DAYS days"
fi

chown volto:volto "$CERT" "$KEY"
chmod 0644 "$CERT"
chmod 0640 "$KEY"

# --- configuration ----------------------------------------------------------

if [ -f "$CONF" ]; then
    note "$CONF already exists, keeping it (edit it by hand if you need changes)"
else
    [ -n "$PASSWORD" ] || PASSWORD="$(openssl rand -base64 18)"

    # Built from the shipped example so the generated file keeps every comment
    # explaining what the other keys do. Only four things are substituted, each
    # anchored to the start of its line so a value cannot match a comment.
    tmp="$(mktemp)"
    # shellcheck disable=SC2064  # $tmp must expand now, not at trap time.
    trap "rm -f '$tmp'" EXIT

    generate_config >"$tmp"

    # Every substitution must have taken: a silent miss would leave the example's
    # placeholder password in a live config.
    grep -q "^listen = \"0.0.0.0:$PORT\"$" "$tmp" || die "failed to set listen in the config"
    grep -q "^cert = \"$CERT\"$" "$tmp" || die "failed to set cert in the config"
    grep -q "^key = \"$KEY\"$" "$tmp" || die "failed to set key in the config"
    grep -q "password = \"$PASSWORD\"" "$tmp" || die "failed to set the user in the config"
    if grep -q 'replace-me-with-something-long' "$tmp"; then
        die "the example placeholder password survived; refusing to install this config"
    fi

    install -o volto -g volto -m 0640 "$tmp" "$CONF"
    rm -f "$tmp"
    trap - EXIT
    note "wrote $CONF"
fi

# --- service ----------------------------------------------------------------

install -m 0644 "$UNIT_SRC" "$UNIT"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true

if systemctl is-active --quiet "$SERVICE_NAME"; then
    systemctl restart "$SERVICE_NAME"
else
    systemctl start "$SERVICE_NAME"
fi

# --- firewall ---------------------------------------------------------------

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow "$PORT/udp" >/dev/null
    note "ufw: allowed $PORT/udp"
else
    note "no active ufw detected — open UDP $PORT yourself if a firewall is in the way"
fi

# --- report -----------------------------------------------------------------

sleep 1
status="$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"

fingerprint="$(openssl x509 -in "$CERT" -noout -fingerprint -sha256)"
expiry="$(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2)"
# Only for the pasteable policy line; the operator substitutes the real address if
# this box is behind a relay.
address="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$address" ] || address="<server-ip>"

# The password is read back out of the config so a re-run prints the one actually
# in force rather than a freshly generated one that was never installed.
configured_user="$(grep -o '{ username = "[^"]*", password = "[^"]*" }' "$CONF" | head -n1)"
conf_username="$(echo "$configured_user" | sed -n 's/.*username = "\([^"]*\)".*/\1/p')"
conf_password="$(echo "$configured_user" | sed -n 's/.*password = "\([^"]*\)".*/\1/p')"

echo
echo "==> done"
echo "service:     $SERVICE_NAME is $status  (journalctl -u $SERVICE_NAME -f)"
echo "certificate: $fingerprint"
echo "expires:     $expiry"
echo
echo "Surge policy line (replace the address if this host is behind a relay):"
echo
echo "  volto = masque, $address, $PORT, sni=$SNI, server-cert-fingerprint-sha256=${fingerprint#*=}, username=$conf_username, password=$conf_password"
echo
echo "Security notes:"
echo "  * The fingerprint above IS the trust anchor. Carry it to your device over a"
echo "    channel you trust and type it in yourself. Never use skip-cert-verify instead."
echo "  * $KEY must never leave this machine. There is no revocation: if it leaks,"
echo "    regenerate with --force and update the fingerprint on every client."
echo
