#!/usr/bin/env bash
#
# Deploy or update volto from a GitHub release.
#
# One script for both days. On a host with no existing install it downloads the
# newest release, verifies it against SHA256SUMS and hands the bundled binary to
# install-selfsigned.sh, which does the full first-time setup. On a host that
# already runs volto it swaps the binary, refreshes the systemd unit and
# restarts the service -- after keeping the previous binary, so a release that
# fails to start is rolled back automatically. When the installed version
# already matches the release and config and unit are in place, nothing is
# touched at all.
#
# That no-op path is what makes the script safe to run on a schedule:
# --enable-timer installs a systemd timer that re-runs it daily.
#
# Rolling back by hand is the same flow pinned to an older release:
#   sudo volto-deploy --tag v0.1.0
#
# Before the binary is swapped, the one that is about to replace it is asked
# whether it can even read this host's /etc/volto/config.toml -- `volto
# --check-config`. A "no" refuses the install outright and leaves the running
# service alone, which is the only useful moment to say it: afterwards the
# service is already down and the rollback guard below has restored the release
# the operator was trying to leave. That path still prints an advisory too,
# because it has two hazards the everyday direction does not: the config file is
# never rewritten and an older volto refuses the whole file over one key it does
# not know, and --tag is not a pin -- the update timer, if enabled, converges
# forward again. On a candidate too old to know the flag, the advisory is all
# there is, and the run continues.
#
# --dry-run is the test seam, in the spirit of install-selfsigned.sh's
# --print-config: it skips the preflight, prints the convergence decision it
# would act on and stops before touching anything. Together with
# VOLTO_DEPLOY_ROOT, which prefixes every install path, and
# VOLTO_DEPLOY_CANDIDATE, which names a binary to check the config against
# instead of downloading one, that puts the three branches which have broken (or
# would break silently) in production -- the convergence check, refresh_self
# under a piped bootstrap, and the config check above -- inside reach of
# tests/it_deploy.rs, with no root, no systemd and no network.

set -euo pipefail

# --- defaults ----------------------------------------------------------------

REPO="${REPO:-vcarus/volto}"
TAG="${TAG:-}" # empty means: resolve the latest release

# Empty in every real run, so the paths below are the absolute ones; a test sets
# it to a temporary directory to relocate the whole install.
ROOT="${VOLTO_DEPLOY_ROOT:-}"

# The binary whose verdict on the config decides whether the install proceeds.
# Empty in every real run until the release has been unpacked, when it becomes
# the binary out of the verified tarball; a --dry-run test names one here
# instead, since a dry run downloads nothing.
CANDIDATE="${VOLTO_DEPLOY_CANDIDATE:-}"

BIN="$ROOT/usr/local/bin/volto"
SELF_INSTALLED="$ROOT/usr/local/sbin/volto-deploy"
CONF="$ROOT/etc/volto/config.toml"
SERVICE_NAME=volto
UNIT="$ROOT/etc/systemd/system/$SERVICE_NAME.service"
TIMER_NAME=volto-deploy
TIMER_SERVICE="$ROOT/etc/systemd/system/$TIMER_NAME.service"
TIMER_UNIT="$ROOT/etc/systemd/system/$TIMER_NAME.timer"
ENABLE_TIMER=0
DRY_RUN=0
INSTALL_ARGS=()

usage() {
    cat <<'USAGE'
Usage: sudo script/deploy.sh [options]

Fetches a volto release from GitHub, verifies its checksum and installs it. On
a host without an existing install this runs the bundled self-signed installer
(install-selfsigned.sh) for the full first-time setup; on a host that already
runs volto only the binary and the systemd unit are refreshed and the service
is restarted, keeping the previous binary for automatic rollback. When the
installed version already matches the release and the config and unit are in
place, nothing is touched.

Before the binary is swapped the new one is asked whether it can load
/etc/volto/config.toml (volto --check-config); if it cannot, nothing is
installed and the running service is left alone. A release too old to know
that flag is not checked, only warned about.

Options:
  -t, --tag vX.Y.Z     deploy this release instead of the latest one (this is
                       also how you roll back)
      --enable-timer   install and start a systemd timer that re-runs this
                       script daily, keeping the host on the newest release
      --dry-run        print the decision this run would act on and stop;
                       needs --tag, downloads nothing, changes nothing
  -s, --sni NAME       first install only: passed to install-selfsigned.sh
  -p, --port PORT      first install only: passed to install-selfsigned.sh
  -u, --username NAME  first install only: passed to install-selfsigned.sh
  -w, --password PASS  first install only: passed to install-selfsigned.sh
  -h, --help           show this help

REPO and TAG can also be given as environment variables, as can the
install-selfsigned.sh variables (SNI, PORT, USERNAME, PASSWORD) on a first
install. VOLTO_DEPLOY_ROOT prefixes every install path (/usr/local/bin,
/etc/volto, /etc/systemd/system) and VOLTO_DEPLOY_CANDIDATE names the binary
the config check runs; both exist for --dry-run tests.

Re-running is safe: the version check turns a run with nothing new into a
no-op, and the first-install path inherits install-selfsigned.sh's guarantees
(an existing config file, certificate or user is kept as it is).
USAGE
}

die() {
    echo "error: $*" >&2
    exit 1
}

note() {
    echo "  $*"
}

# True when version $1 is strictly older than version $2, comparing the dotted
# numeric fields left to right.
#
# Anything that is not plain dotted digits answers false, which covers the two
# cases that matter: no install yet, so INSTALLED is empty, and a binary whose
# --version could not be read. An advisory drawn from a comparison that cannot
# be trusted is worse than no advisory.
is_older_version() {
    case "$1" in ''|*[!0-9.]*) return 1 ;; esac
    case "$2" in ''|*[!0-9.]*) return 1 ;; esac

    local a b i x y
    local IFS=.
    # shellcheck disable=SC2206  # splitting on IFS is exactly the point here
    a=($1)
    # shellcheck disable=SC2206
    b=($2)

    for i in 0 1 2; do
        x="${a[$i]:-0}"
        y="${b[$i]:-0}"
        [ "$x" -eq "$y" ] || { [ "$x" -lt "$y" ]; return; }
    done
    return 1
}

# Refuses the install when the binary in $1 cannot load this host's config.
#
# The hazard this closes is the rollback one: every table in the config file is
# `deny_unknown_fields`, so a binary older than a key in the file refuses the
# whole file and does not start. Nothing rewrites the config on the way back
# either, so the answer is already fixed by the time the tarball is unpacked --
# and the only moment it is worth anything is before the swap, since afterwards
# the service is down and the guard below has restored the very release the
# operator was trying to leave.
#
# The candidate is run rather than inspected, which costs no trust that was not
# already spent: its checksum has been verified against the release's
# SHA256SUMS by the time we get here, and the next thing that happens to it
# either way is being installed and started as root.
#
# Whether the candidate can be asked at all is settled by looking for the flag
# in its own --help, not by running it and reading the failure. A volto from
# before the flag existed answers an unknown argument with clap's usage error,
# and taking that for "your configuration is broken" would refuse every rollback
# to a release older than this one -- the exact opposite of the point. The help
# text goes into a variable rather than through a pipe to grep, because `grep -q`
# closes the pipe on its first match and `set -o pipefail` would then report the
# producer's SIGPIPE as a failure.
#
# A candidate that cannot be asked leaves the run exactly as it was before any
# of this existed: the downgrade advisory above is what the operator gets.
check_config_with() {
    local binary="$1" help output

    help="$("$binary" --help 2>&1)" || help=""
    case "$help" in
        *--check-config*) ;;
        *)
            note "volto $VERSION predates --check-config, so it cannot be asked whether it"
            note "can load $CONF; the advisory above is all there is"
            return 0
            ;;
    esac

    if output="$("$binary" --check-config --config "$CONF" 2>&1)"; then
        note "$CONF loads on volto $VERSION"
        return 0
    fi

    # Everything about the refusal, on stderr, where a failing run's output is
    # read from -- including the candidate's own message, which names the file,
    # the line and the column but not the key (a parse error redacts every
    # quoted segment, because the same message can quote a password).
    {
        echo "==> volto $VERSION cannot load $CONF"
        echo "$output"
        note "nothing was installed; the $SERVICE_NAME service still runs ${INSTALLED:-what it had}"
        note "the position above names the line to comment out in $CONF"
        note "(docs/configuration.md, version compatibility, says which key arrived when)"
    } >&2
    die "refusing to install volto $VERSION over a config it cannot load"
}

# --- arguments ---------------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        -t|--tag)       [ $# -ge 2 ] || die "$1 needs a value"; TAG="$2"; shift 2 ;;
        --enable-timer) ENABLE_TIMER=1; shift ;;
        --dry-run)      DRY_RUN=1; shift ;;
        -s|--sni|-p|--port|-u|--username|-w|--password)
                        [ $# -ge 2 ] || die "$1 needs a value"
                        INSTALL_ARGS+=("$1" "$2"); shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *)              usage >&2; die "unknown option: $1" ;;
    esac
done

# --- preflight ---------------------------------------------------------------

# A dry run neither installs nor downloads, so none of this applies to it -- and
# demanding it would put the decision logic out of reach of every dev host.
if [ "$DRY_RUN" -eq 0 ]; then
    [ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0)"
    [ "$(uname -s)" = Linux ] ||
        die "this script deploys releases to a Linux host; on a dev machine build with cargo instead"
    command -v systemctl >/dev/null 2>&1 || die "systemd is required"
    for tool in curl tar sha256sum; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
    done

    case "$(uname -m)" in
        x86_64)        TARGET=x86_64-unknown-linux-musl ;;
        aarch64|arm64) TARGET=aarch64-unknown-linux-musl ;;
        *)             die "no release build for this architecture: $(uname -m)" ;;
    esac
fi

if [ -n "$TAG" ]; then
    case "$TAG" in
        v[0-9]*) ;;
        *) die "--tag expects the tag name as on the releases page, e.g. v0.1.0" ;;
    esac
elif [ "$DRY_RUN" -eq 1 ]; then
    die "--dry-run needs --tag: resolving the latest release would need the network"
else
    # The /releases/latest redirect carries the tag; following it with HEAD asks
    # GitHub for one URL instead of an API call, so there is no rate limit to
    # think about on a timer.
    location="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/$REPO/releases/latest")" ||
        die "could not reach github.com to resolve the latest release"
    TAG="${location##*/}"
    case "$TAG" in
        v[0-9]*) ;;
        *) die "$REPO has no release yet (the latest-release redirect went to $location)" ;;
    esac
fi
VERSION="${TAG#v}"

INSTALLED=""
if [ -x "$BIN" ]; then
    INSTALLED="$("$BIN" --version 2>/dev/null | awk '{print $2}')" || INSTALLED=""
fi

# A downgrade is the incident-response path, and it is the one path nobody
# rehearses. Two of its hazards are invisible from the outside until they bite,
# and both are cheaper to say here than to rediscover from a service that will
# not start at three in the morning. Printed before the decision below, and in a
# dry run as much as in a real one, because deciding is what a dry run is for.
if is_older_version "$VERSION" "$INSTALLED"; then
    echo "==> $INSTALLED -> $VERSION is a downgrade"
    note "nothing here rewrites the config, and an older volto refuses a key it does not know"
    note "-- the whole file, not the key -- so if the service does not come up, look for"
    note "'unknown field' in 'journalctl -u $SERVICE_NAME -e': it names the line to comment"
    note "out in $CONF (see docs/configuration.md, version compatibility)"
    note "and --tag pins nothing: an enabled $TIMER_NAME.timer puts this host back on the"
    note "latest release within a day ('systemctl disable --now $TIMER_NAME.timer' holds it)"
fi

# --- download and verify -----------------------------------------------------

# The source this script re-installs itself from; a downloaded release carries a
# fresher copy and overrides this below.
SELF_SOURCE="$0"

# Converging means the whole install, not just the binary: a deleted config or
# unit must be regenerated even when the version already matches, and doing so
# needs the tarball (it carries the installer and the example config).
if [ "$INSTALLED" = "$VERSION" ] && [ -f "$CONF" ] && [ -f "$UNIT" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "dry-run: already deployed and intact ($TAG)"
    else
        note "volto $INSTALLED is already deployed and intact ($TAG), nothing to do"
    fi
elif [ "$DRY_RUN" -eq 1 ]; then
    # The check the real path makes before it swaps the binary, made here in the
    # same place in the order: after the advisory, before the decision. A dry run
    # has no downloaded binary to ask, so it asks the one a test named.
    if [ -f "$CONF" ] && [ -n "$CANDIDATE" ]; then
        check_config_with "$CANDIDATE"
    fi

    # Same two questions the real branches below ask, in the same order: a
    # missing config means the first-install path, anything else an update.
    MISSING=""
    [ -f "$CONF" ] || MISSING="$MISSING config"
    [ -f "$UNIT" ] || MISSING="$MISSING unit"
    [ -z "$MISSING" ] || MISSING=" (missing:$MISSING)"

    if [ ! -f "$CONF" ]; then
        echo "dry-run: would install $TAG$MISSING"
    else
        echo "dry-run: would update ${INSTALLED:-(unknown)} -> $TAG$MISSING"
    fi
else
    NAME="volto-${VERSION}-${TARGET}"
    BASE="https://github.com/$REPO/releases/download/$TAG"

    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT

    echo "==> downloading $NAME.tar.gz ($TAG)"
    curl -fsSL --retry 3 -o "$TMP/$NAME.tar.gz" "$BASE/$NAME.tar.gz" ||
        die "download failed: $BASE/$NAME.tar.gz"
    curl -fsSL --retry 3 -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS" ||
        die "download failed: $BASE/SHA256SUMS"

    grep -F "  $NAME.tar.gz" "$TMP/SHA256SUMS" >"$TMP/expected" ||
        die "SHA256SUMS in $TAG does not list $NAME.tar.gz"
    (cd "$TMP" && sha256sum --check --status expected) ||
        die "checksum mismatch for $NAME.tar.gz -- refusing to install it"
    note "checksum verified against SHA256SUMS"

    tar -xzf "$TMP/$NAME.tar.gz" -C "$TMP"
    SRC="$TMP/$NAME"
    [ -x "$SRC/volto" ] || die "the archive did not contain a volto binary"
    [ ! -f "$SRC/script/deploy.sh" ] || SELF_SOURCE="$SRC/script/deploy.sh"

    # --- install -------------------------------------------------------------

    if [ ! -f "$CONF" ]; then
        echo "==> no existing install, running the bundled self-signed installer"
        bash "$SRC/script/install-selfsigned.sh" --binary "$SRC/volto" \
            ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}
    else
        # Before anything on this host moves: the binary about to be installed
        # is asked whether it can read the config that is already here. It
        # either says yes, says nothing useful because it predates the flag, or
        # ends the run with the service still up.
        check_config_with "$SRC/volto"

        echo "==> updating volto ${INSTALLED:-(unknown)} -> $VERSION"

        if [ -x "$BIN" ]; then
            install -m 0755 "$BIN" "$BIN.prev"
            note "previous binary kept at $BIN.prev"
        fi
        install -m 0755 "$SRC/volto" "$BIN"
        install -m 0644 "$SRC/script/masque.service" "$UNIT"
        systemctl daemon-reload
        systemctl restart "$SERVICE_NAME"

        # An immediately-crashing release is the failure worth catching here;
        # under Restart=on-failure the service is not "active" again by now.
        sleep 3
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            note "volto $VERSION is running"
        elif [ -x "$BIN.prev" ]; then
            install -m 0755 "$BIN.prev" "$BIN"
            systemctl restart "$SERVICE_NAME" || true
            die "volto $VERSION failed to start; rolled back to ${INSTALLED:-the previous binary} -- see: journalctl -u $SERVICE_NAME -e"
        else
            die "volto $VERSION failed to start and there is no previous binary to roll back to -- see: journalctl -u $SERVICE_NAME -e"
        fi
    fi
fi

# --- timer -------------------------------------------------------------------

# The installed copy under /usr/local/sbin is what the timer executes; keep it
# in step with the release just deployed. `install` truncates its target, which
# must never hit the file bash is currently reading, hence the copy-then-rename.
refresh_self() {
    local resolved
    resolved="$(readlink -f "$SELF_SOURCE" 2>/dev/null || echo "$SELF_SOURCE")"
    # Piped from curl, $0 is not a file; the release download normally overrides
    # SELF_SOURCE with the tarball copy, but on an already-current host there is
    # nothing to copy from -- and nothing that needs refreshing either.
    [ -f "$resolved" ] || return 0
    [ "$resolved" != "$SELF_INSTALLED" ] || return 0
    ! cmp -s "$resolved" "$SELF_INSTALLED" 2>/dev/null || return 0
    install -m 0755 "$resolved" "$SELF_INSTALLED.new"
    mv -f "$SELF_INSTALLED.new" "$SELF_INSTALLED"
    note "installed this script as $SELF_INSTALLED"
}

if [ "$ENABLE_TIMER" -eq 1 ] || [ -f "$TIMER_UNIT" ]; then
    # refresh_self runs in a dry run too: copying this script to $SELF_INSTALLED
    # is the guardrail that broke under `curl ... | bash`, and it is the one step
    # here that a test can exercise for real under VOLTO_DEPLOY_ROOT.
    refresh_self

    if [ "$DRY_RUN" -eq 1 ]; then
        echo "dry-run: would enable timer"
        exit 0
    fi

    cat >"$TIMER_SERVICE" <<'EOF'
[Unit]
Description=Deploy or update volto from the latest GitHub release
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/volto-deploy
EOF

    cat >"$TIMER_UNIT" <<'EOF'
[Unit]
Description=Daily volto update check

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    if [ "$ENABLE_TIMER" -eq 1 ]; then
        systemctl enable --now "$TIMER_NAME.timer"
        note "enabled $TIMER_NAME.timer (daily, randomized by up to an hour)"
    fi
fi

# --- report ------------------------------------------------------------------

# The report queries the installed binary and systemd; a dry run has decided
# everything it can decide by here.
[ "$DRY_RUN" -eq 0 ] || exit 0

echo
echo "==> done"
echo "volto:   $("$BIN" --version 2>/dev/null || echo "not installed") ($BIN)"
echo "service: $SERVICE_NAME is $(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo unknown)"
if systemctl is-active --quiet "$TIMER_NAME.timer" 2>/dev/null; then
    echo "timer:   $TIMER_NAME.timer is active; it deploys new releases daily"
    echo "         (journalctl -u $TIMER_NAME.service shows what each run did)"
fi
