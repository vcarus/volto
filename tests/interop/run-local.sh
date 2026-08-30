#!/usr/bin/env bash
# Runs both cross-implementation interop suites (masque-go, then aioquic)
# against a locally built volto, mirroring the `interop` job in
# .github/workflows/ci.yml step for step so a local pass predicts a CI pass.
#
# Everything it creates lives under target/interop-local/ -- covered by the
# existing /target ignore rule and removed by `cargo clean` -- and the two
# slow pieces are cached there between runs: the self-signed certificate is
# reused until within an hour of expiry, and the aioquic virtualenv is rebuilt
# only when requirements.txt changes.
#
# Needs: go (version per ../go.mod), python3, openssl. Exits non-zero on the
# first failing suite, and finishes by holding the server log to the same two
# permitted warnings the ops runbook allows (the private-networks notice from
# this config, and the 407 the missing-credentials test draws on purpose).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$ROOT/target/interop-local"
mkdir -p "$WORK"

export VOLTO_ADDR="127.0.0.1:14443"
export VOLTO_SNI="localhost"
export VOLTO_USER="interop"
export VOLTO_PASSWORD="interop-password-not-a-secret"
export VOLTO_CERT="$WORK/cert.pem"

# The certificate: regenerate only when absent or about to expire, so repeated
# runs skip openssl. One day of validity, exactly as in CI.
if ! openssl x509 -checkend 3600 -noout -in "$VOLTO_CERT" 2>/dev/null; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$WORK/key.pem" -out "$VOLTO_CERT" \
        -days 1 -nodes -subj "/CN=$VOLTO_SNI" \
        -addext "subjectAltName=DNS:$VOLTO_SNI"
fi

# The configuration is cheap enough to write every run, and writing it keeps
# it honest against this script's environment rather than a previous run's.
cat > "$WORK/config.toml" <<EOF
[server]
listen = "$VOLTO_ADDR"
cert = "$VOLTO_CERT"
key = "$WORK/key.pem"

[auth]
users = [{ username = "$VOLTO_USER", password = "$VOLTO_PASSWORD" }]

[security]
# The interop targets are echo servers on loopback, which the default policy
# refuses -- as it must in production. Port 25 stays denied by default, which
# is what the refusal test drives.
allow_private_networks = true

[log]
# Every inbound request is logged with its headers, so a client-side failure
# can be read off the server side too.
level = "debug"
EOF

cargo build --locked --manifest-path "$ROOT/Cargo.toml"

"$ROOT/target/debug/volto" --config "$WORK/config.toml" \
    > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true' EXIT

# Poll for the line the accept loop logs once it is bound, rather than
# sleeping: QUIC listens on UDP, so there is no TCP connect to probe with.
for _ in $(seq 1 60); do
    grep -q "accepting QUIC connections" "$WORK/server.log" && break
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "the server exited during startup:" >&2
        cat "$WORK/server.log" >&2
        exit 1
    fi
    sleep 0.5
done
grep -q "accepting QUIC connections" "$WORK/server.log" || {
    echo "the server did not become ready within 30s" >&2
    exit 1
}

# masque-go. `-count=1` defeats Go's test result cache, which knows nothing
# about the server on the other end -- a restored entry would pass this suite
# without a single packet being sent.
(cd "$ROOT/tests/interop" && go test -v -count=1 -timeout 120s ./...)

# aioquic, in a virtualenv rebuilt only when its requirements change.
VENV="$WORK/venv"
REQS="$ROOT/tests/interop/aioquic/requirements.txt"
STAMP="$VENV/.requirements.sha256"
if [ ! -x "$VENV/bin/python" ] \
    || ! shasum -a 256 -c "$STAMP" --status 2>/dev/null; then
    rm -rf "$VENV"
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install --quiet -r "$REQS"
    shasum -a 256 "$REQS" > "$STAMP"
fi
"$VENV/bin/python" "$ROOT/tests/interop/aioquic/interop_test.py"

# The ops runbook's final step, automated: the only WARN the server may have
# written are the private-networks notice this config asks for and the
# missing-credentials 407 one test draws on purpose. Anything else -- or any
# ERROR -- is a finding, even with both suites green.
UNEXPECTED=$(grep -E ' (WARN|ERROR) ' "$WORK/server.log" \
    | grep -v "allow_private_networks is on" \
    | grep -v 'authentication failed.*reason="no credentials"' || true)
if [ -n "$UNEXPECTED" ]; then
    echo "unexpected WARN/ERROR in the server log:" >&2
    echo "$UNEXPECTED" >&2
    exit 1
fi

echo "interop: both suites green, server log clean ($WORK/server.log)"
