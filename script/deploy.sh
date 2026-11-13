#!/usr/bin/env bash
#
# Deploy or update volto from a GitHub release.
#
# One script for both days. On a host with no existing install it downloads the
# newest release, verifies its signature and checksum and hands the bundled binary to
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
# The version string is the whole of that test, which is why --force exists. A
# release deleted and published again under the same tag leaves a host whose
# volto --version matches the tag and whose binary is not the release's, and
# nothing here can tell the two apart. --force takes the download, verify,
# install and restart path anyway, rollback guard included, and needs --tag for
# the same reason --dry-run does: the point is to put one named release's bytes
# on this host.
#
# A release is trusted for one reason: its SHA256SUMS carries a signature made
# with the release key, whose public half is RELEASE_SIGNER below. The private
# half is not on GitHub, so nobody who controls the repository or the release
# page can produce a file this script accepts. The checksum only ties the
# tarball to that signed list. The signature is checked with ssh-keygen, which
# every host already has, and a release without a valid one is refused with the
# running service left alone.
#
# Releases older than the signature exist and stay reachable: --allow-unsigned
# installs one whose SHA256SUMS.sig is absent, and needs --tag, so it is a
# decision somebody makes for one named release and never what the timer does.
# It applies to releases before FIRST_SIGNED_VERSION and to no later one. A
# signature that is present and wrong is refused either way. The installed copy
# of this script is never replaced from an unsigned release, because the copy
# such a release carries verifies nothing.
#
# Rolling back by hand is the same flow pinned to an older release:
#   sudo volto-deploy --tag v1.4.0
#   sudo volto-deploy --tag v1.3.7 --allow-unsigned   # from before signing
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

# `-E` so the ERR trap the update block arms is inherited by functions;
# nothing else in this script installs one.
set -eEuo pipefail

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
FORCE=0
ALLOW_UNSIGNED=0

# The public half of the release key, in OpenSSH form. Every release's
# SHA256SUMS is signed with the private half, under the namespace below. This
# line is the only trust anchor: the installed copy of this script is owned by
# root, and a new key reaches a host inside a release the old key signed.
RELEASE_SIGNER='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIChpIMVExa8wenp/vVCQr8t/7Vt2vt00byMqvX9Csbee'
# The sshsig namespace, which keeps a signature made for anything else (a git
# commit, a login) from being presented as a release signature.
SIGN_NAMESPACE=volto-release
# The first release whose SHA256SUMS is signed. --allow-unsigned applies to the
# releases before it and to no other, so a release that should carry a
# signature cannot be installed without one by removing the signature and
# naming the flag.
FIRST_SIGNED_VERSION=1.4.0
# Set by --verify-signature: the two files to check, instead of deploying.
VERIFY_ONLY=0
VERIFY_SUMS=""
VERIFY_SIG=""
# Set when no release was named and the latest one was looked up, which is what
# the timer does. Such a run never installs a release older than the one that
# is installed.
TAG_WAS_RESOLVED=0
# Set once the release being installed has had its signature verified. Only
# then does this script replace its installed copy from the release.
RELEASE_IS_SIGNED=0
INSTALL_ARGS=()

usage() {
    cat <<'USAGE'
Usage: sudo script/deploy.sh [options]

Fetches a volto release from GitHub, verifies its signature and checksum and
installs it. The signature is over SHA256SUMS, made with the release key this
script carries the public half of; a release without a valid one is refused. On
a host without an existing install this runs the bundled self-signed installer
(install-selfsigned.sh) for the full first-time setup; on a host that already
runs volto only the binary and the systemd unit are refreshed and the service
is restarted, keeping the previous binary for automatic rollback. When the
installed version already matches the release and the config and unit are in
place, nothing is touched. That check is the version string and nothing else,
so a binary that reports the wanted version is left alone even when its bytes
are not the release's; --force (with --tag) is how such a binary is replaced.

Before the binary is swapped the new one is asked whether it can load
/etc/volto/config.toml (volto --check-config); if it cannot, nothing is
installed and the running service is left alone. A release too old to know
that flag is not checked, only warned about.

Options:
  -t, --tag vX.Y.Z     deploy this release instead of the latest one (this is
                       also how you roll back). Without it the latest release
                       is installed, unless it is older than the installed
                       one, which is refused
      --enable-timer   install and start a systemd timer that re-runs this
                       script daily, keeping the host on the newest release
      --dry-run        print the decision this run would act on and stop;
                       needs --tag, downloads nothing, changes nothing
      --force          install the release even when the installed version
                       already matches it; needs --tag, keeps the rollback
                       guard, and rewrites neither the config nor the
                       certificate
      --allow-unsigned install a release that carries no SHA256SUMS.sig, which
                       is every release from before releases were signed and
                       no later one; needs --tag, and a signature that is
                       present must still be valid. The installed copy of
                       this script is not replaced from such a release
      --verify-signature SUMS SIG
                       check that SIG is the release key's signature over the
                       file SUMS, then stop; needs neither root nor network
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
(an existing config file, certificate or user is kept as it is). --force is the
one way to get past that no-op.
USAGE
}

die() {
    echo "error: $*" >&2
    exit 1
}

note() {
    echo "  $*"
}

# Puts the previous binary and unit back, then ends the run.
#
# Armed as an ERR trap over the window between the `.prev` copies and the health
# check, and disarmed once the service is up. Without it `set -e` ends the run
# with whatever the failure left behind: an `install` that truncated its target
# before failing leaves no usable binary, and a failure between the binary copy
# and the unit copy leaves the new binary under the old unit. The rollback
# branch further down answers neither, because it runs only after `systemctl
# is-active` has been asked, which is past this window.
#
# The service is started here as well. Before the health check it is normally
# still running the release it was already running, or systemd is bringing it
# back under Restart=on-failure. That assumption does not hold when the restart
# itself failed after stopping the unit: the restored files are in place and the
# unit is inactive, so it is started here. `start` rather than `restart`,
# because `start` does nothing to an active unit: when the failure came before
# the restart, the old process keeps serving its tunnels. `|| true` because a
# failed start must not mask the original failure, which `die` reports either
# way.
restore_previous() {
    trap - ERR
    local restored=""

    if [ -f "$BIN.prev" ] && install -m 0755 "$BIN.prev" "$BIN"; then
        restored="binary"
    fi
    if [ -f "$UNIT.prev" ] && install -m 0644 "$UNIT.prev" "$UNIT"; then
        restored="${restored:+$restored and }unit"
    fi
    systemctl daemon-reload || true
    systemctl start "$SERVICE_NAME" || true

    [ -n "$restored" ] ||
        die "installing volto $VERSION failed and there was nothing to restore -- see: journalctl -u $SERVICE_NAME -e"
    die "installing volto $VERSION failed; restored the previous $restored -- see: journalctl -u $SERVICE_NAME -e"
}

# True when the file $3 is a signature over the file $2 made by the key $1.
#
# `ssh-keygen -Y verify` reads the message on standard input and takes the
# trusted keys from an allowed-signers file, so one is written for the single
# key and removed again. The principal is a label that the file and the call
# must agree on; it names nobody. Everything ssh-keygen prints is dropped: the
# callers say what was being verified, which its own message does not.
signature_is_valid() {
    local signer="$1" sums="$2" sig="$3" allowed status=0

    allowed="$(mktemp)"
    printf 'release namespaces="%s" %s\n' "$SIGN_NAMESPACE" "$signer" >"$allowed"
    ssh-keygen -Y verify -f "$allowed" -I release -n "$SIGN_NAMESPACE" \
        -s "$sig" <"$sums" >/dev/null 2>&1 || status=$?
    rm -f "$allowed"
    return "$status"
}

# Verifies the downloaded release in $TMP: the signature over SHA256SUMS, then
# the archive $NAME.tar.gz against the one line of that list that names it.
# Ends the run on any failure. Sets RELEASE_IS_SIGNED when a signature was
# verified.
#
# The signature comes first, because it is what makes the list worth reading.
# SHA256SUMS.sig is in $TMP when its download succeeded. A download that failed
# is treated as a signature that is absent: telling the two apart would mean
# trusting an HTTP status, and both end the same way.
#
# The list is then read by this function and not by `sha256sum --check`. That
# tool's idea of a valid line differs between implementations: GNU accepts a
# line that starts with a backslash or a space, and another implementation
# skips the same line and reports success. A list that one tool checked when it
# was signed and another tool reads here could then name an archive nobody
# checked. So every line must be exactly 64 lowercase hex digits, two spaces and
# an archive name, exactly one line must name this archive, and the digest is
# compared as text.
verify_release() {
    local line expected actual

    if [ -f "$TMP/SHA256SUMS.sig" ]; then
        signature_is_valid "$RELEASE_SIGNER" "$TMP/SHA256SUMS" "$TMP/SHA256SUMS.sig" ||
            die "SHA256SUMS in $TAG is not signed by the release key -- refusing to install it"
        RELEASE_IS_SIGNED=1
        note "SHA256SUMS is signed by the release key"
    elif [ "$ALLOW_UNSIGNED" -eq 1 ]; then
        note "$TAG carries no SHA256SUMS.sig; continuing because --allow-unsigned was given"
    else
        die "$TAG carries no SHA256SUMS.sig -- refusing to install an unsigned release"
    fi

    while IFS= read -r line || [ -n "$line" ]; do
        [[ "$line" =~ ^[0-9a-f]{64}\ \ volto-[0-9A-Za-z._-]+\.tar\.gz$ ]] ||
            die "SHA256SUMS in $TAG has a line that is not a checksum and an archive name -- refusing to install it"
    done <"$TMP/SHA256SUMS"

    expected="$(awk -v file="$NAME.tar.gz" 'substr($0, 67) == file { print substr($0, 1, 64) }' "$TMP/SHA256SUMS")"
    [ -n "$expected" ] || die "SHA256SUMS in $TAG does not list $NAME.tar.gz"
    [ "${#expected}" -eq 64 ] ||
        die "SHA256SUMS in $TAG lists $NAME.tar.gz more than once -- refusing to install it"

    actual="$(sha256sum <"$TMP/$NAME.tar.gz")"
    [ "${actual:0:64}" = "$expected" ] ||
        die "checksum mismatch for $NAME.tar.gz -- refusing to install it"
    note "checksum verified against SHA256SUMS"
}

# Ends the run when it was not told which release to install and the latest one
# is older than the one installed.
#
# "Latest" is a mark on the release page, and whoever controls that page can
# move it to an older release. Every older release from 1.4.0 on carries a valid
# signature, so the signature does not stop this: without the refusal a host
# could be walked back to a release with a known defect. Going back is a
# decision made at the host, with --tag. The run fails rather than passing
# quietly, so the timer's unit shows that the release page and the host
# disagree.
refuse_automatic_downgrade() {
    [ "$TAG_WAS_RESOLVED" -eq 1 ] || return 0
    is_older_version "$VERSION" "$INSTALLED" || return 0
    die "the latest release is $TAG and this host runs $INSTALLED -- refusing to go back without being told to (a rollback is: $0 --tag $TAG)"
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
# already spent: the release's signature and the archive's checksum have been
# verified by the time we get here, and the next thing that happens to it
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
        --force)        FORCE=1; shift ;;
        --allow-unsigned) ALLOW_UNSIGNED=1; shift ;;
        --verify-signature)
                        [ $# -ge 3 ] || die "$1 needs two values: SUMS and SIG"
                        VERIFY_ONLY=1; VERIFY_SUMS="$2"; VERIFY_SIG="$3"; shift 3 ;;
        -s|--sni|-p|--port|-u|--username|-w|--password)
                        [ $# -ge 2 ] || die "$1 needs a value"
                        INSTALL_ARGS+=("$1" "$2"); shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *)              usage >&2; die "unknown option: $1" ;;
    esac
done

# Asked here rather than beside the --dry-run check below, so the answer does
# not depend on the host: a forced run on a dev machine is refused for the
# reason it is actually wrong, and not by the root check in front of it.
if [ "$FORCE" -eq 1 ] && [ -z "$TAG" ]; then
    die "--force needs --tag: reinstalling means putting one named release's bytes on this host"
fi

if [ "$ALLOW_UNSIGNED" -eq 1 ] && [ -z "$TAG" ]; then
    die "--allow-unsigned needs --tag: an unsigned release is installed by name, never as the latest one"
fi

# --- verify only -------------------------------------------------------------

# The same function the install path calls, on two files somebody already has.
# It is how the release is checked before it is published, and how a test
# reaches the verification without root or the network. VOLTO_DEPLOY_SIGNER
# replaces the key here and nowhere else: the install path below reads
# RELEASE_SIGNER and no variable, so the environment cannot change which key a
# host trusts.
if [ "$VERIFY_ONLY" -eq 1 ]; then
    command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen is required"
    [ -f "$VERIFY_SUMS" ] || die "no such file: $VERIFY_SUMS"
    [ -f "$VERIFY_SIG" ] || die "no such file: $VERIFY_SIG"
    signature_is_valid "${VOLTO_DEPLOY_SIGNER:-$RELEASE_SIGNER}" "$VERIFY_SUMS" "$VERIFY_SIG" ||
        die "$VERIFY_SIG is not the release key's signature over $VERIFY_SUMS"
    echo "signature verified: $VERIFY_SIG over $VERIFY_SUMS"
    exit 0
fi

# --- preflight ---------------------------------------------------------------

# A dry run neither installs nor downloads, so none of this applies to it -- and
# demanding it would put the decision logic out of reach of every dev host.
if [ "$DRY_RUN" -eq 0 ]; then
    [ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0)"
    [ "$(uname -s)" = Linux ] ||
        die "this script deploys releases to a Linux host; on a dev machine build with cargo instead"
    command -v systemctl >/dev/null 2>&1 || die "systemd is required"
    for tool in curl tar sha256sum ssh-keygen; do
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
    location="$(curl -fsSLI --connect-timeout 10 --max-time 30 -o /dev/null \
        -w '%{url_effective}' "https://github.com/$REPO/releases/latest")" ||
        die "could not reach github.com to resolve the latest release"
    TAG="${location##*/}"
    TAG_WAS_RESOLVED=1
    case "$TAG" in
        v[0-9]*) ;;
        *) die "$REPO has no release yet (the latest-release redirect went to $location)" ;;
    esac
fi
VERSION="${TAG#v}"

if [ "$ALLOW_UNSIGNED" -eq 1 ] && ! is_older_version "$VERSION" "$FIRST_SIGNED_VERSION"; then
    die "--allow-unsigned applies to releases before $FIRST_SIGNED_VERSION; $TAG must carry a signature"
fi

INSTALLED=""
if [ -x "$BIN" ]; then
    INSTALLED="$("$BIN" --version 2>/dev/null | awk '{print $2}')" || INSTALLED=""
fi

refuse_automatic_downgrade

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
if [ "$INSTALLED" = "$VERSION" ] && [ -f "$CONF" ] && [ -f "$UNIT" ] && [ "$FORCE" -eq 0 ]; then
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
    elif [ "$FORCE" -eq 1 ] && [ "$INSTALLED" = "$VERSION" ] && [ -z "$MISSING" ]; then
        # The only decision --force adds: everything else it reaches is already
        # an install or an update, and is reported as one.
        echo "dry-run: would reinstall $TAG"
    else
        echo "dry-run: would update ${INSTALLED:-(unknown)} -> $TAG$MISSING"
    fi
else
    NAME="volto-${VERSION}-${TARGET}"
    BASE="https://github.com/$REPO/releases/download/$TAG"

    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT

    # Every network call fits inside the timer service's TimeoutStartSec=15min
    # (900 s), so systemd cannot stop the run inside the binary swap window
    # below. curl starts no retry after --retry-max-time, and the longest
    # default backoff sleep before the third retry is 4 s, so one call takes at
    # most --retry-max-time + 4 + --max-time. The tarball takes at most
    # 120 + 4 + 300 = 424 s, and SHA256SUMS and its signature 60 + 4 + 60 =
    # 124 s each. With the 30 s latest-release request that is 702 s, which
    # leaves 198 s for the rest of the run. --retry-max-time also stops a server's Retry-After header from
    # setting a longer sleep.
    echo "==> downloading $NAME.tar.gz ($TAG)"
    curl -fsSL --retry 3 --retry-max-time 120 --connect-timeout 10 --max-time 300 \
        -o "$TMP/$NAME.tar.gz" "$BASE/$NAME.tar.gz" ||
        die "download failed: $BASE/$NAME.tar.gz"
    curl -fsSL --retry 3 --retry-max-time 60 --connect-timeout 10 --max-time 60 \
        -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS" ||
        die "download failed: $BASE/SHA256SUMS"

    # A failed download leaves no file, and verify_release reads that as a
    # release without a signature.
    curl -fsSL --retry 3 --retry-max-time 60 --connect-timeout 10 --max-time 60 \
        -o "$TMP/SHA256SUMS.sig" "$BASE/SHA256SUMS.sig" ||
        rm -f "$TMP/SHA256SUMS.sig"

    verify_release

    tar -xzf "$TMP/$NAME.tar.gz" -C "$TMP"
    SRC="$TMP/$NAME"
    [ -x "$SRC/volto" ] || die "the archive did not contain a volto binary"
    # The installed copy of this script is replaced only from a release whose
    # signature was verified. A release from before signing carries a script
    # that verifies nothing, and installing that one would end the check for
    # every later release.
    if [ "$RELEASE_IS_SIGNED" -eq 1 ] && [ -f "$SRC/script/deploy.sh" ]; then
        SELF_SOURCE="$SRC/script/deploy.sh"
    elif [ "$RELEASE_IS_SIGNED" -eq 0 ]; then
        note "keeping this script as it is: $TAG is not signed, so its copy is not installed"
    fi

    # --- install -------------------------------------------------------------

    if [ ! -f "$CONF" ]; then
        echo "==> no existing install, running the bundled self-signed installer"
        # VOLTO_DEPLOY_ROOT prefixes every path this script decides; the
        # installer has the same seam under its own name, and without this the
        # first-install branch of a run with the deploy root set would write to
        # the real /etc and /usr/local. Set on the call itself rather than
        # exported for the whole script, so the two seams compose and nothing
        # else inherits it. Empty in every real run, which is what the two
        # variables mean.
        VOLTO_INSTALL_ROOT="$ROOT" \
            bash "$SRC/script/install-selfsigned.sh" --binary "$SRC/volto" \
            ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}

        # The update path's health check applied to a first install. The
        # installer already exits nonzero on a failed start; this catches a
        # service that dies in the seconds after the installer's one-second
        # check.
        sleep 3
        systemctl is-active --quiet "$SERVICE_NAME" ||
            die "the first install left $SERVICE_NAME not running -- see: journalctl -u $SERVICE_NAME -e"
    else
        # Before anything on this host moves: the binary about to be installed
        # is asked whether it can read the config that is already here. It
        # either says yes, says nothing useful because it predates the flag, or
        # ends the run with the service still up.
        check_config_with "$SRC/volto"

        if [ "$FORCE" -eq 1 ] && [ "$INSTALLED" = "$VERSION" ]; then
            echo "==> reinstalling volto $VERSION over the same version"
        else
            echo "==> updating volto ${INSTALLED:-(unknown)} -> $VERSION"
        fi

        if [ -x "$BIN" ]; then
            install -m 0755 "$BIN" "$BIN.prev"
            note "previous binary kept at $BIN.prev"
        fi
        # The unit is refreshed on every update and carries the version-dependent
        # hardening directives (ProtectProc, RestrictAddressFamilies,
        # SystemCallFilter, LimitNOFILE), which makes it the half most likely to
        # be what stops an older host from coming up. Keep it beside the binary,
        # or the rollback below puts the old binary under the new unit and
        # reports a rollback that did not happen.
        if [ -f "$UNIT" ]; then
            install -m 0644 "$UNIT" "$UNIT.prev"
            note "previous unit kept at $UNIT.prev"
        fi
        # Both `.prev` copies exist from here on, so every failure until the
        # service answers is a failure this can undo. A command inside the `if`
        # below is a tested command and does not fire the trap, which is what
        # leaves the rollback branch reachable for a service that comes up and
        # then dies.
        trap restore_previous ERR
        install -m 0755 "$SRC/volto" "$BIN"
        install -m 0644 "$SRC/script/masque.service" "$UNIT"
        systemctl daemon-reload
        systemctl restart "$SERVICE_NAME"

        # An immediately-crashing release is the failure worth catching here;
        # under Restart=on-failure the service is not "active" again by now.
        sleep 3
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            trap - ERR
            note "volto $VERSION is running"
        elif [ -x "$BIN.prev" ]; then
            install -m 0755 "$BIN.prev" "$BIN"
            RESTORED="binary"
            if [ -f "$UNIT.prev" ]; then
                install -m 0644 "$UNIT.prev" "$UNIT"
                RESTORED="binary and unit"
            fi
            # daemon-reload before the restart, not after: without it systemd
            # starts the service from the unit it has already parsed, which is
            # the one being rolled back.
            systemctl daemon-reload || true
            systemctl restart "$SERVICE_NAME" || true
            die "volto $VERSION failed to start; rolled the $RESTORED back to ${INSTALLED:-the previous release} -- see: journalctl -u $SERVICE_NAME -e"
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
    # A dry run touches nothing, and the installed copy is a root-owned system
    # file. The one exception is the test seam: VOLTO_DEPLOY_ROOT relocates every
    # path, so a dry-run test still exercises refresh_self for real.
    if [ "$DRY_RUN" -eq 0 ] || [ -n "$ROOT" ]; then
        refresh_self
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        echo "dry-run: would enable timer"
        exit 0
    fi

    # systemd disables the start timeout for Type=oneshot, and this oneshot runs
    # a network download. Without a bound a stalled path holds the daily run
    # indefinitely, and the next tick cannot start.
    cat >"$TIMER_SERVICE" <<'EOF'
[Unit]
Description=Deploy or update volto from the latest GitHub release
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
TimeoutStartSec=15min
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
