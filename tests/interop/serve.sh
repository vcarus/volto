#!/usr/bin/env bash
# The interop fixture, shared by the `interop` job in .github/workflows/ci.yml
# and by ./run-local.sh.
#
# Both need the same three things before either suite can run: a self-signed
# certificate the clients will validate, a server configuration that matches
# the VOLTO_* environment the suites read, and a way to wait for the server to
# be listening. Both used to write all three out, and run-local.sh's header
# promised it mirrored CI "step for step" with nothing enforcing it. This file
# is that enforcement.
#
# What is deliberately *not* here is starting and stopping the server. The two
# callers differ there for a structural reason rather than by accident: a CI
# step is its own process, so the server has to outlive the step that started
# it and is reaped by a later `if: always()` step through a pid file, while
# run-local.sh is one shell from beginning to end and kills its own child from
# an EXIT trap. Six lines apiece, and no shared shape worth naming.
#
# Usage, with VOLTO_ADDR / VOLTO_SNI / VOLTO_USER / VOLTO_PASSWORD in the
# environment:
#
#   serve.sh prepare <workdir>        # cert.pem, key.pem, config.toml
#   serve.sh wait    <logfile> <pid>  # block until the server is accepting
#
# `prepare` leaves the certificate at <workdir>/cert.pem, the key beside it,
# and the configuration at <workdir>/config.toml.
set -euo pipefail

# The certificate: regenerated only when absent or within an hour of expiring,
# so a repeated local run skips openssl. One day of validity, which is a
# runner's whole life and long enough for a local afternoon.
prepare_certificate() {
    local work="$1"
    if openssl x509 -checkend 3600 -noout -in "$work/cert.pem" 2>/dev/null; then
        return 0
    fi
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$work/key.pem" -out "$work/cert.pem" \
        -days 1 -nodes -subj "/CN=$VOLTO_SNI" \
        -addext "subjectAltName=DNS:$VOLTO_SNI"
}

# The configuration is cheap enough to write every run, and writing it keeps it
# honest against this run's environment rather than a previous run's.
write_config() {
    local work="$1"
    cat > "$work/config.toml" <<EOF
[server]
listen = "$VOLTO_ADDR"
cert = "$work/cert.pem"
key = "$work/key.pem"

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
}

# Poll for the line the accept loop logs once it is bound, rather than sleeping:
# a fixed sleep is either flaky or slow, and QUIC listens on UDP so there is no
# TCP connect to probe with. A server that died on the way up is reported as
# that rather than as a timeout.
wait_until_ready() {
    local log="$1" pid="$2"
    for _ in $(seq 1 60); do
        if grep -q "accepting QUIC connections" "$log" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "the server exited during startup:" >&2
            cat "$log" >&2
            return 1
        fi
        sleep 0.5
    done
    echo "the server did not become ready within 30s" >&2
    cat "$log" >&2
    return 1
}

case "${1:-}" in
    prepare)
        work="${2:?usage: serve.sh prepare <workdir>}"
        mkdir -p "$work"
        prepare_certificate "$work"
        write_config "$work"
        ;;
    wait)
        wait_until_ready "${2:?usage: serve.sh wait <logfile> <pid>}" \
            "${3:?usage: serve.sh wait <logfile> <pid>}"
        ;;
    *)
        echo "usage: serve.sh {prepare <workdir>|wait <logfile> <pid>}" >&2
        exit 2
        ;;
esac
