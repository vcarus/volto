#!/usr/bin/env bash
# Runs both cross-implementation interop suites (masque-go, then aioquic)
# against a locally built volto, mirroring the `interop` job in
# .github/workflows/ci.yml step for step so a local pass predicts a CI pass.
# The certificate, the configuration and the readiness wait are not mirrored
# but shared: both this script and that job call ./serve.sh for them.
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

# The certificate and the configuration, from the fixture CI uses.
"$ROOT/tests/interop/serve.sh" prepare "$WORK"

cargo build --locked --manifest-path "$ROOT/Cargo.toml"

"$ROOT/target/debug/volto" --config "$WORK/config.toml" \
    > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true' EXIT

"$ROOT/tests/interop/serve.sh" wait "$WORK/server.log" "$SERVER_PID"

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
