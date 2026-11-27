#!/usr/bin/env bash
#
# The shipped unit under a real systemd: readiness, the start timeout and the
# watchdog (D124).
#
# No cargo test can reach these. They need systemd as PID 1, the unit's sandbox
# and root, so this runs in the `test` job of .github/workflows/ci.yml after
# `cargo test`, on a hosted runner, where systemd is PID 1 and sudo asks for no
# password. It cannot run on the macOS development host.
#
# The binary is installed by script/install-selfsigned.sh, so the tracked unit
# reaches systemd unchanged, through the real installer. Test timings come from
# drop-ins only.
#
# The checks:
#   1. `systemctl restart` returns 0, the service is active, and the UDP port
#      is bound at the moment it returns.
#   2. With NOTIFY_SOCKET unset by a drop-in, the start fails at the start
#      timeout: the start waits for the server's own READY=1.
#   3. With a short WatchdogSec the service stays active, under the same main
#      PID and with no restart, over four intervals: the keep-alives pass the
#      unit's sandbox.
#   4. After `systemctl daemon-reexec` the service stays active under the same
#      main PID with no restart: the keep-alives reach the re-executed manager.
#   5. After `kill -STOP` on the main PID, systemd logs its watchdog timeout,
#      NRestarts grows, and the service is active again under a new main PID.
#   6. With `WatchdogSec=0` in a drop-in the server's environment has
#      NOTIFY_SOCKET and no WATCHDOG_USEC.
# On any failure the script prints `systemctl status` and the unit's journal.
#
# Usage: tests/systemd-check.sh BINARY

set -euo pipefail

BINARY="${1:?usage: tests/systemd-check.sh BINARY}"
UNIT=volto
PORT=14443
DROPINS=/etc/systemd/system/$UNIT.service.d

# The timings of checks 2 to 5, in seconds. The watchdog leaves a keep-alive 2 s
# of delay on a busy runner before systemd acts, so check 3 does not fail on
# scheduling alone.
START_TIMEOUT=5
WATCHDOG=4
ABORT_TIMEOUT=5
RESTART_DELAY=1

fail() {
    echo "::error::$*" >&2
    sudo systemctl status "$UNIT" --no-pager --full || true
    sudo journalctl -u "$UNIT" --no-pager -o short-precise || true
    exit 1
}
trap 'fail "the command on line $LINENO failed"' ERR

main_pid() { systemctl show -p MainPID --value "$UNIT"; }
restarts() { systemctl show -p NRestarts --value "$UNIT"; }
active() { [ "$(systemctl is-active "$UNIT" || true)" = active ]; }
port_bound() { [ -n "$(ss -Hlun "sport = :$PORT")" ]; }

# Writes the drop-in $1 with the [Service] lines $2 and reloads systemd.
write_dropin() {
    sudo mkdir -p "$DROPINS"
    printf '[Service]\n%s\n' "$2" | sudo tee "$DROPINS/$1.conf" >/dev/null
    sudo systemctl daemon-reload
}

# Removes the drop-in $1 and reloads systemd.
remove_dropin() {
    sudo rm -f "$DROPINS/$1.conf"
    sudo systemctl daemon-reload
}

systemctl --version | head -n 1

echo "==> installing $BINARY with script/install-selfsigned.sh"
sudo env PASSWORD=systemd-check-not-a-secret script/install-selfsigned.sh \
    --binary "$BINARY" --sni localhost --port "$PORT" --username check
active || fail "the service is not active after the install"

echo "==> 1. systemctl restart returns once the listener is bound"
sudo systemctl restart "$UNIT" || fail "systemctl restart failed"
port_bound || fail "UDP $PORT is not bound when systemctl restart has returned"
active || fail "the service is not active after systemctl restart returned"

echo "==> 2. without NOTIFY_SOCKET the start fails at the start timeout"
# Restart=no, so that the failed start is not retried while it is judged.
write_dropin no-notify "UnsetEnvironment=NOTIFY_SOCKET
TimeoutStartSec=$START_TIMEOUT
Restart=no"
began=$SECONDS
if sudo systemctl restart "$UNIT"; then
    fail "the start succeeded although the server could not report ready"
fi
took=$((SECONDS - began))
[ "$took" -ge $((START_TIMEOUT - 1)) ] ||
    fail "the start failed after ${took}s, before the ${START_TIMEOUT}s start timeout"
result="$(systemctl show -p Result --value "$UNIT")"
[ "$result" = timeout ] || fail "the start ended with Result=$result and not timeout"
echo "the start failed after ${took}s with Result=$result"
remove_dropin no-notify
sudo systemctl reset-failed "$UNIT"
sudo systemctl restart "$UNIT" || fail "the start failed once NOTIFY_SOCKET was back"

echo "==> 3. with WatchdogSec=$WATCHDOG the keep-alives keep the service up"
write_dropin watchdog "WatchdogSec=$WATCHDOG
TimeoutAbortSec=$ABORT_TIMEOUT
RestartSec=$RESTART_DELAY"
sudo systemctl restart "$UNIT" || fail "the restart under the watchdog drop-in failed"
pid="$(main_pid)"
before="$(restarts)"
sleep $((4 * WATCHDOG))
active || fail "the service is not active after $((4 * WATCHDOG))s under WatchdogSec=$WATCHDOG"
[ "$(main_pid)" = "$pid" ] || fail "the main PID moved from $pid to $(main_pid)"
[ "$(restarts)" = "$before" ] || fail "NRestarts moved from $before to $(restarts)"
[ "$before" = 0 ] || fail "NRestarts is $before and not 0"
echo "main PID $pid, NRestarts $before, after $((4 * WATCHDOG))s"

echo "==> 4. the keep-alives still arrive after systemd re-executes itself"
# volto connects its notification socket once, at startup. A package upgrade of
# systemd runs daemon-reexec, and the keep-alives have to reach the manager
# that comes out of it, or every such upgrade would end in a watchdog restart.
sudo systemctl daemon-reexec
sleep $((3 * WATCHDOG))
active || fail "the service is not active $((3 * WATCHDOG))s after daemon-reexec"
[ "$(main_pid)" = "$pid" ] || fail "the main PID moved from $pid to $(main_pid) after daemon-reexec"
[ "$(restarts)" = "$before" ] || fail "NRestarts moved from $before to $(restarts) after daemon-reexec"
echo "main PID $pid, NRestarts $before, $((3 * WATCHDOG))s after daemon-reexec"

echo "==> 5. a stopped process is restarted by the watchdog"
since="$(date +%s)"
sudo kill -STOP "$pid"
deadline=$((SECONDS + WATCHDOG + ABORT_TIMEOUT + RESTART_DELAY + 20))
until active && [ "$(main_pid)" != "$pid" ] && [ "$(main_pid)" != 0 ]; do
    [ "$SECONDS" -lt "$deadline" ] ||
        fail "the service was not active under a new main PID within the watchdog, abort and restart times plus 20s"
    sleep 1
done
[ "$(restarts)" -ge 1 ] || fail "NRestarts is $(restarts) after the watchdog restart"
# Read once into a variable: `grep -q` on a pipe can end journalctl with
# SIGPIPE, which pipefail would report as a failure.
journal="$(sudo journalctl -u "$UNIT" --no-pager --since "@$since")"
grep -q 'Watchdog timeout' <<<"$journal" ||
    fail "the journal has no watchdog timeout for $UNIT since the process was stopped"
grep -i 'watchdog\|abrt' <<<"$journal" || true
echo "main PID $pid was replaced by $(main_pid), NRestarts $(restarts)"

remove_dropin watchdog

echo "==> 6. WatchdogSec=0 leaves the server without the watchdog variables"
# docs/deployment.md gives this drop-in as the way to switch the watchdog off.
write_dropin no-watchdog "WatchdogSec=0"
sudo systemctl restart "$UNIT" || fail "the restart under WatchdogSec=0 failed"
pid="$(main_pid)"
environment="$(sudo cat "/proc/$pid/environ" | tr '\0' '\n')"
grep -q '^NOTIFY_SOCKET=' <<<"$environment" ||
    fail "the server's environment has no NOTIFY_SOCKET, so this check read the wrong process"
if grep -q '^WATCHDOG_USEC=' <<<"$environment"; then
    fail "WatchdogSec=0 still gives the server $(grep '^WATCHDOG_USEC=' <<<"$environment")"
fi
remove_dropin no-watchdog

echo "==> every check passed"
