#!/usr/bin/env bash
# Runs the three cross-implementation interop suites (masque-go, then
# aioquic, then sing-box) against a locally built volto, mirroring the
# `interop` job in .github/workflows/ci.yml step for step so a local pass
# predicts a CI pass.
# The certificate, the configuration and the readiness wait are not mirrored
# but shared: both this script and that job call ./serve.sh for them.
#
# Everything it creates lives under target/interop-local/ -- covered by the
# existing /target ignore rule and removed by `cargo clean` -- and the two
# slow pieces are cached there between runs: the self-signed certificate is
# reused until within an hour of expiry, and the aioquic virtualenv is rebuilt
# only when requirements.txt changes or the virtualenv no longer imports.
#
# A second volto process runs beside the first, with an ECH key and
# `require_ech = true`, for the masque-go ECH case (ech_test.go); its
# configuration and the two ECHConfigLists come from `serve.sh prepare-ech`,
# and its log is checked like the first one's. The sing-box suite drives both
# servers as well.
#
# The sing-box suite (singbox/) is a Go module of its own, which pins the
# sing-box release and builds it from source on its first test. A cold build
# takes minutes; Go's build cache makes the next one take seconds.
#
# Needs: go (version per singbox/go.mod, which asks for the newer Go of the two
# modules), python3, openssl. Exits non-zero on the
# first failing suite, and finishes by handing the server log to
# `./serve.sh check`, which holds it to the two permitted warnings the ops
# runbook allows (the private-networks notice from this config, and the 407 the
# missing-credentials tests draw on purpose). That check is in the fixture
# rather than here so the CI job runs the same one.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$ROOT/target/interop-local"
mkdir -p "$WORK"

# Two free UDP ports on loopback, chosen by binding port 0, so a process that
# already holds a fixed port cannot fail the run. CI sets fixed ones. The
# sockets close before volto binds, so another process could take a port in
# between; `serve.sh wait` then reports the server dead, as it did for a
# fixed port in use.
PORTS="$(python3 -c '
import socket
sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
for s in sockets:
    s.bind(("127.0.0.1", 0))
print(*(s.getsockname()[1] for s in sockets))
')"
read -r PORT ECH_PORT <<< "$PORTS"
export VOLTO_ADDR="127.0.0.1:$PORT"
export VOLTO_SNI="localhost"
export VOLTO_USER="interop"
export VOLTO_PASSWORD="interop-password-not-a-secret"
export VOLTO_CERT="$WORK/cert.pem"
# The second server, which holds an ECH key and requires ECH (serve.sh prepare-ech).
export VOLTO_ECH_ADDR="127.0.0.1:$ECH_PORT"

# The certificate and the configuration, from the fixture CI uses.
"$ROOT/tests/interop/serve.sh" prepare "$WORK"

cargo build --locked --manifest-path "$ROOT/Cargo.toml"

"$ROOT/tests/interop/serve.sh" prepare-ech "$WORK" "$ROOT/target/debug/volto"

"$ROOT/target/debug/volto" --config "$WORK/config.toml" \
    > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
"$ROOT/target/debug/volto" --config "$WORK/config-ech.toml" \
    > "$WORK/server-ech.log" 2>&1 &
ECH_PID=$!
trap 'kill "$SERVER_PID" "$ECH_PID" 2>/dev/null; wait "$SERVER_PID" "$ECH_PID" 2>/dev/null || true' EXIT

"$ROOT/tests/interop/serve.sh" wait "$WORK/server.log" "$SERVER_PID"
"$ROOT/tests/interop/serve.sh" wait "$WORK/server-ech.log" "$ECH_PID"
VOLTO_ECH_CONFIG="$(cat "$WORK/ech.list")"
VOLTO_ECH_OTHER_CONFIG="$(cat "$WORK/ech-other.list")"
export VOLTO_ECH_CONFIG VOLTO_ECH_OTHER_CONFIG

# masque-go. `-count=1` defeats Go's test result cache, which knows nothing
# about the server on the other end -- a restored entry would pass this suite
# without a single packet being sent.
(cd "$ROOT/tests/interop" && go test -v -count=1 -timeout 120s ./...)

# aioquic, in a virtualenv rebuilt when its requirements change or when it no
# longer imports. Where no wheel fits the local Python, pip builds cryptography
# from source and links it to the system OpenSSL; removing that OpenSSL breaks
# the import, and a rebuild is the repair.
VENV="$WORK/venv"
REQS="$ROOT/tests/interop/aioquic/requirements.txt"
STAMP="$VENV/.requirements.sha256"
if [ ! -x "$VENV/bin/python" ] \
    || ! shasum -a 256 -c "$STAMP" --status 2>/dev/null \
    || ! "$VENV/bin/python" -c 'import aioquic.h3.connection' 2>/dev/null; then
    rm -rf "$VENV"
    python3 -m venv "$VENV"
    # A source build finds OpenSSL through OPENSSL_DIR or pkg-config. MacPorts
    # installs OpenSSL 4 outside the pkg-config path, so it is named here
    # unless the caller set OPENSSL_DIR.
    if [ -z "${OPENSSL_DIR:-}" ] && [ -d /opt/local/libexec/openssl4 ]; then
        export OPENSSL_DIR=/opt/local/libexec/openssl4
    fi
    # No cache: a cached wheel can be linked to the OpenSSL that was removed.
    "$VENV/bin/pip" install --quiet --no-cache-dir -r "$REQS"
    shasum -a 256 "$REQS" > "$STAMP"
fi
"$VENV/bin/python" "$ROOT/tests/interop/aioquic/interop_test.py"

# sing-box, built from the version singbox/go.mod pins and driven through its
# SOCKS5 inbounds. `-count=1` for the reason the masque-go step gives. The
# timeout covers a cold build of sing-box as well as the tests.
(cd "$ROOT/tests/interop/singbox" && go test -v -count=1 -timeout 600s ./...)

# The ops runbook's final step, automated, from the fixture the CI job calls
# too.
"$ROOT/tests/interop/serve.sh" check "$WORK/server.log"
"$ROOT/tests/interop/serve.sh" check "$WORK/server-ech.log"

echo "interop: all three suites green"
