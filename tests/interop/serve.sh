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
#   serve.sh check   <logfile>        # judge the log the run left behind
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

# The server log is judged rather than only printed. CLAUDE.md names the interop
# job as the only independent judge of src/h3, because the in-tree test client is
# built on volto::h3; a run in which both foreign clients are satisfied while the
# server logs an error is exactly what that job exists to catch, and neither
# suite can see the server side. The filter list lives here so that ./run-local.sh
# and the CI job apply the same one.
#
# Two lines are permitted, and only two: the private-networks notice this
# configuration asks for, and the 407 the missing-credentials test draws on
# purpose. Anything else at WARN, and any ERROR at all, is a finding.
#
# The authentication filter is keyed by log_id, which D100's 2026-09-05 addendum
# makes the stable half of a line. 3gmzhaq7 is the "authentication failed"
# statement in src/conn.rs.
# The `reason=` field stays in the pattern: the id covers every authentication
# failure, including a wrong password, and only the credential-less one is
# expected here. The private-networks filter stays on the message text, because
# that warning reaches the log through the generic configuration-warning
# statement at src/main.rs:266, whose id f9be058r covers every configuration
# warning there is; keying on it would suppress the rest of them too.
check_log() {
    local log="$1"
    [ -s "$log" ] || {
        echo "the server log at $log is missing or empty" >&2
        return 1
    }

    # The server colours its output unless journald is reading it: init_tracing
    # only turns ANSI off under $JOURNAL_STREAM, and tracing-subscriber's own
    # default consults NO_COLOR and nothing else. A log redirected into a file
    # therefore holds " WARN\033[0m " rather than " WARN ", and every pattern
    # below would read a line that is not there. Measured on 2026-09-07: the
    # filter matched 0 lines of a log holding one WARN before this strip and 1
    # after, so this check reported every local run clean without ever looking
    # at one.
    local esc plain
    esc="$(printf '\033')"
    plain="$(sed "s/${esc}\[[0-9;]*m//g" "$log")"

    # Floor, in D100's shape. This configuration always draws the
    # private-networks warning at startup, so a reader that cannot see that one
    # line is broken and must say so rather than report a clean log.
    printf '%s\n' "$plain" | grep -q "allow_private_networks is on" || {
        echo "the private-networks warning this configuration always draws is not in $log:" >&2
        echo "this check cannot read the log, so it cannot judge it" >&2
        return 1
    }

    local unexpected
    unexpected="$(printf '%s\n' "$plain" | grep -E ' (WARN|ERROR) ' \
        | grep -v "allow_private_networks is on" \
        | grep -vE 'log_id="3gmzhaq7".*reason="no credentials"' || true)"
    if [ -n "$unexpected" ]; then
        echo "unexpected WARN/ERROR in $log:" >&2
        echo "$unexpected" >&2
        return 1
    fi

    echo "server log clean ($log)"
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
    check)
        check_log "${2:?usage: serve.sh check <logfile>}"
        ;;
    *)
        echo "usage: serve.sh {prepare <workdir>|wait <logfile> <pid>|check <logfile>}" >&2
        exit 2
        ;;
esac
