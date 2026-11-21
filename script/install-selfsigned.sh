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
# Safe to re-run: on a host that already has a config, the config, the
# certificate, the user, the binary and the unit are kept and the service is
# not restarted. --force regenerates the certificate and reloads the service;
# --replace-binary replaces the binary and the unit, after asking the new
# binary about the existing config, keeping .prev copies and rolling back if
# the service does not stay up.
#
# The config this generates is not installed until the volto binary has been
# asked whether it can load it (check_generated_config).
#
# --print-config and --check-config are the test seams: both stop after
# generating the config, neither needs root, and between them they put
# generate_config, verify_config and check_generated_config -- everything the
# install path decides the config on -- within reach of tests/it_installer.rs.
# VOLTO_INSTALL_ROOT prefixes every path this script installs into, so a
# temporary directory can stand in for /etc and /usr/local, the same way
# VOLTO_DEPLOY_ROOT works for deploy.sh.

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
REPLACE_BINARY=0
PRINT_CONFIG=0
CHECK_CONFIG=0

# volto's own bound on a user-id, repeated here only so the refusal arrives
# before anything is installed rather than out of the service's first log line.
# The binary is the authority: it is `logfmt::MAX_TOKEN`, and since the generated
# config now goes past `volto --check-config` before it is installed, a copy that
# has drifted from it can no longer let a config through that the service would
# refuse -- it only makes the message worse. `it_installer.rs` pins the two
# together by asking the server for its limit and this script for its verdict.
MAX_USERNAME_BYTES=32

# Empty in every real run, so the paths below are the absolute ones; a test sets
# it to a temporary directory to relocate the whole install.
ROOT="${VOLTO_INSTALL_ROOT:-}"

CONF_DIR="$ROOT/etc/volto"
CONF="$CONF_DIR/config.toml"
CERT="$CONF_DIR/cert.pem"
KEY="$CONF_DIR/key.pem"
SERVICE_NAME=volto
BIN="$ROOT/usr/local/bin/volto"
UNIT="$ROOT/etc/systemd/system/$SERVICE_NAME.service"
CERT_DAYS=3650

usage() {
    cat <<'USAGE'
Usage: sudo script/install-selfsigned.sh [options]

Installs volto with a freshly generated self-signed certificate, a systemd unit
and one user, then prints the Surge policy line to paste into your config.

Options:
  -b, --binary PATH    volto binary to install   (default: ./target/release/volto)
  -s, --sni NAME       certificate name and SNI  (asked for interactively when
                       neither this nor $SNI is set; default: volto.internal);
                       a host name: letters, digits, hyphens and dots, not
                       ending in a number
  -p, --port PORT      UDP port to listen on     (default: 443)
  -u, --username NAME  proxy username            (default: surge)
  -w, --password PASS  proxy password            (default: generated)
  -f, --force          regenerate the certificate even if one exists, and
                       reload the service so it serves the new one
      --replace-binary on a host that already has /etc/volto/config.toml,
                       replace the installed binary and unit too: the new
                       binary is asked about the existing config first, the
                       old ones are kept as .prev, and the service is restarted
                       and rolled back if it does not stay up
      --print-config   print the config that would be generated, then exit
                       (changes nothing, needs no root; used by the test suite)
      --check-config   generate the config this run would install and ask the
                       volto binary whether it can load it, then exit (changes
                       nothing, needs no root, needs the certificate and key to
                       be in place already; used by the test suite)
  -h, --help           show this help

Every option can also be given as an environment variable: BINARY, SNI, PORT,
USERNAME, PASSWORD. VOLTO_INSTALL_ROOT prefixes every path this script installs
into (/etc/volto, /etc/systemd/system, /usr/local/bin); it exists for the tests.

The username must not contain a colon (RFC 7617) and must be at most 32 bytes.
That bound is volto's, not this script's -- the binary refuses a longer user-id
at startup, and repeating it here only moves the complaint earlier. Neither the
username nor the password may contain " or \, which would need escaping in the
generated TOML and in the Surge policy line, or a control character. Neither
may contain a comma or whitespace, because the Surge policy line carries the
pair as `username=..., password=...`. Every other printable character is fine,
| and & included, and a generated password is never affected.

A password given with -w is on this script's command line, which every local
user can read while the run lasts (/proc/<pid>/cmdline). Leaving it out has one
generated, and PASSWORD exported in a root shell reaches the script without
being on any command line. The script itself never passes the password to
another program as an argument.

Before the generated config is installed, the volto binary is asked whether it
can load it (volto --check-config); if it cannot, nothing is written and the
binary's own complaint is printed. A volto too old to know that flag is not
asked, and the install goes ahead unchecked.

Re-running is safe: on a host that already has /etc/volto/config.toml, the
config file, the certificate, the user, the binary and the unit are kept as
they are, and the service is not restarted; a missing binary or unit is
installed. --force regenerates the certificate only; it never rewrites
config.toml, so edits you made there survive. Note that regenerating the
certificate changes the fingerprint, so every client has to be updated.
--replace-binary is the one way this script replaces an installed binary.
USAGE
}

die() {
    echo "error: $*" >&2
    exit 1
}

note() {
    echo "  $*"
}

# Rejects credentials that the generated config or the Surge policy line could
# not carry as written.
#
# Called from the two flags that stop after generating a config as well as from
# the preflight, because they run the same generator.
check_credentials() {
    # A username with a colon cannot be expressed in HTTP Basic (RFC 7617), and
    # volto rejects one at startup. Catch it here, where the message can be
    # clearer.
    case "$USERNAME" in
        *:*) die "username must not contain a colon (RFC 7617)" ;;
        '')  die "username must not be empty" ;;
    esac
    # volto refuses a longer username at startup (that is the length a user-id
    # is carried at in the logs and the authentication failure counters). The
    # generated config is now put to the binary before it is installed, so this
    # is no longer the only thing between a too-long name and a service that
    # loops under Restart=on-failure -- it is the copy that can say so in one
    # line, and say it before the certificate is generated.
    # Bytes, not characters: ${#var} counts characters in some shells, and the
    # limit volto enforces is a byte length.
    if [ "$(printf %s "$USERNAME" | wc -c)" -gt "$MAX_USERNAME_BYTES" ]; then
        die "username must be at most $MAX_USERNAME_BYTES bytes"
    fi
    case "$USERNAME$PASSWORD" in
        # Both would need an escape in the double-quoted TOML string and in the
        # policy line printed at the end, and the report reads the pair back out
        # of the config by its quotes. Refused rather than escaped, so what is
        # installed and printed is exactly what was asked for.
        *'"'*|*\\*) die "username and password must not contain quotes or backslashes" ;;
        # A TOML basic string cannot carry them as written.
        *[[:cntrl:]]*) die "username and password must not contain control characters" ;;
    esac
    # The Surge policy line carries the pair as `username=..., password=...` on
    # one line, so a comma or any whitespace cannot be expressed there.
    case "$USERNAME" in
        *[[:space:]]*|*,*) die "username must not contain a comma or whitespace" ;;
    esac
    case "$PASSWORD" in
        *[[:space:]]*|*,*) die "password must not contain a comma or whitespace" ;;
    esac
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
        --replace-binary) REPLACE_BINARY=1; shift ;;
        --print-config) PRINT_CONFIG=1; shift ;;
        --check-config) CHECK_CONFIG=1; shift ;;
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
# keeps every comment explaining the keys it does not touch. Only four lines are
# replaced, each matched from the start of the line so a value cannot match a
# comment or the commented-out second user.
#
# Shell builtins only, here and in verify_config: the password must never be
# an argument of another program, because every local user can read a
# process's arguments in /proc/<pid>/cmdline. `read` and `printf` run inside
# this shell, and a value is written as data, so no character in it has a
# meaning to the generator.
generate_config() {
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            'listen = '*) printf 'listen = "0.0.0.0:%s"\n' "$PORT" ;;
            'cert = '*) printf 'cert = "%s"\n' "$CERT" ;;
            'key = '*) printf 'key = "%s"\n' "$KEY" ;;
            '  { username = '*)
                printf '  { username = "%s", password = "%s" },\n' "$USERNAME" "$PASSWORD" ;;
            *) printf '%s\n' "$line" ;;
        esac
    done <"$EXAMPLE_SRC"
}

# Every replacement must have taken: a silent miss would leave the example's
# placeholder password in a live config. The file is matched as text, with
# every quoted part of a pattern taken literally.
verify_config() {
    local text
    text=$'\n'"$(<"$1")"$'\n'
    [[ "$text" == *$'\n'"listen = \"0.0.0.0:$PORT\""$'\n'* ]] || die "failed to set listen in the config"
    [[ "$text" == *$'\n'"cert = \"$CERT\""$'\n'* ]] || die "failed to set cert in the config"
    [[ "$text" == *$'\n'"key = \"$KEY\""$'\n'* ]] || die "failed to set key in the config"
    [[ "$text" == *$'\n'"  { username = \"$USERNAME\", password = \"$PASSWORD\" },"$'\n'* ]] ||
        die "failed to set the user in the config"
    [[ "$text" != *'replace-me-with-something-long'* ]] ||
        die "the example placeholder password survived; refusing to install this config"
}

# Asks the volto binary whether it can load the config generated in $1, and ends
# the run when it cannot.
#
# verify_config above only checks that the four substitutions landed. Everything
# else in the file comes from the shipped example, where every table is
# `deny_unknown_fields` -- so one key the binary being installed does not know
# refuses the whole file, and the service never starts. On a first install there
# is no running service to fall back to and no previous config to compare
# against, which makes this the one moment the question can still be answered
# cheaply. deploy.sh asks the same question on the update path
# (`check_config_with`); this is the first-install half of it.
#
# The temporary file is asked about rather than the installed one, so a refusal
# leaves no configuration behind and the service is never started on it.
# Installing first and checking after would write a config that the "already
# exists, keeping it" branch then preserves on every later run -- the failure
# would outlive the run that caused it. It cannot move any earlier than this:
# one of the rules being checked is that the certificate and key the file names
# exist and are files, and the certificate is generated a few lines above. A
# binary too old to be asked leaves the run as it was before the check existed.
check_generated_config() {
    ask_binary "$1"
    case "$ASK_VERDICT" in
        loads) note "the generated config loads on this volto" ;;
        unasked) note "this volto predates --check-config, so the generated config goes in unchecked" ;;
        *)
            {
                echo "==> volto cannot load the config this install would write"
                echo "$ASK_OUTPUT"
                note "no configuration was written and the service was not started"
                note "the position above is a line of $EXAMPLE_SRC, which is this"
                note "config with four values substituted into it"
                note "(docs/configuration.md, version compatibility, says which key arrived when)"
            } >&2
            die "refusing to install a config volto cannot load"
            ;;
    esac
}

# Reads the RUST_LOG the $SERVICE_NAME unit starts the service with, so that the
# config check can be run with it: the service reads RUST_LOG at startup and
# refuses a value that turns its own log lines off, and this script's own
# environment is not the unit's. Sets UNIT_RUST_LOG to the value and
# UNIT_RUST_LOG_STATE to `found`, `none`, or `unreadable`: the unit sets a value
# this function cannot read safely, and the check then runs without one.
#
# systemd's order is followed (systemd.exec(5)): the Environment= assignments
# as `systemctl show` lists them, the last one winning, then the files
# EnvironmentFile= names, in order, whose assignments override Environment=.
# `systemctl show -p Environment --value` prints the assignments as
# space-separated KEY=value words and puts a word that needs it in double
# quotes with systemd's own escaping. That is not shell syntax, and nothing
# here evaluates it: only an unquoted RUST_LOG=value word is read, and a quoted
# RUST_LOG word, a backslash anywhere in the output, or a quote in the value is
# `unreadable`. An environment file is read line by line the same way: a
# RUST_LOG= line, with its value in plain text or inside one pair of quotes
# with no quote or backslash in it.
#
# Not covered: RUST_LOG from systemd's manager environment (DefaultEnvironment=,
# `systemctl set-environment`) through PassEnvironment=, UnsetEnvironment=, a
# specifier such as %h or a $VAR reference in the value, and an environment
# file that ExecStartPre= writes.
UNIT_RUST_LOG=""
UNIT_RUST_LOG_STATE=none
read_unit_rust_log() {
    local shown word value quotes in_quote=0 files listed path entry key
    local -a words=()

    UNIT_RUST_LOG=""
    UNIT_RUST_LOG_STATE=none

    shown="$(systemctl show -p Environment --value "$SERVICE_NAME" 2>/dev/null)" || shown=""
    case "$shown" in
        *RUST_LOG=*\\* | *\\*RUST_LOG=*) UNIT_RUST_LOG_STATE=unreadable ;;
        *RUST_LOG=*)
            read -r -a words <<<"$shown"
            for word in "${words[@]}"; do
                if [ "$in_quote" -eq 0 ]; then
                    case "$word" in
                        RUST_LOG=*\"* | RUST_LOG=*\'* | \"RUST_LOG=*)
                            UNIT_RUST_LOG=""
                            UNIT_RUST_LOG_STATE=unreadable
                            ;;
                        RUST_LOG=*)
                            UNIT_RUST_LOG="${word#RUST_LOG=}"
                            UNIT_RUST_LOG_STATE=found
                            ;;
                    esac
                fi
                # A word inside a quoted assignment is not an assignment.
                quotes="${word//[^\"]/}"
                [ $((${#quotes} % 2)) -eq 0 ] || in_quote=$((1 - in_quote))
            done
            ;;
    esac

    files="$(systemctl show -p EnvironmentFiles --value "$SERVICE_NAME" 2>/dev/null)" || files=""
    while IFS= read -r listed; do
        # Each line is "PATH (ignore_errors=yes|no)".
        path="${listed% (ignore_errors=*}"
        [ -n "$path" ] && [ -r "$path" ] || continue
        while IFS= read -r entry || [ -n "$entry" ]; do
            case "$entry" in
                *=*) ;;
                *) continue ;;
            esac
            key="${entry%%=*}"
            key="${key#"${key%%[![:space:]]*}"}"
            key="${key%"${key##*[![:space:]]}"}"
            [ "$key" = RUST_LOG ] || continue
            value="${entry#*=}"
            value="${value#"${value%%[![:space:]]*}"}"
            value="${value%"${value##*[![:space:]]}"}"
            case "$value" in
                \"*\") value="${value#\"}"; value="${value%\"}" ;;
                \'*\') value="${value#\'}"; value="${value%\'}" ;;
            esac
            case "$value" in
                *\"* | *\'* | *\\*)
                    UNIT_RUST_LOG=""
                    UNIT_RUST_LOG_STATE=unreadable
                    ;;
                *)
                    UNIT_RUST_LOG="$value"
                    UNIT_RUST_LOG_STATE=found
                    ;;
            esac
        done <"$path"
    done <<<"$files"
}

# Runs `$1 --check-config --config $2` with the unit's RUST_LOG as
# read_unit_rust_log left it, exported for this one command, and without
# RUST_LOG when the unit sets none or one that could not be read: the service
# does not inherit this script's environment, so neither does its check.
check_config_as_the_unit() {
    if [ "$UNIT_RUST_LOG_STATE" = found ]; then
        RUST_LOG="$UNIT_RUST_LOG" "$1" --check-config --config "$2"
    else
        (
            unset RUST_LOG
            "$1" --check-config --config "$2"
        )
    fi
}

# Asks $BINARY whether it can load the config file $1. Sets ASK_VERDICT to
# `loads`, `refuses`, or `unasked` for a binary too old to know the flag, and
# ASK_OUTPUT to the binary's own message, which the caller prints on stderr: it
# names the line and the column but not the key, because a parse error redacts
# every quoted segment, which can be a password.
#
# The flag is looked for in the binary's --help first, for the reason
# deploy.sh's check_config_with gives. The binary is asked with the RUST_LOG
# the installed unit sets when there is one (read_unit_rust_log), as
# deploy.sh asks it, and without RUST_LOG otherwise.
ASK_VERDICT=""
ASK_OUTPUT=""
ask_binary() {
    local help

    ASK_OUTPUT=""
    help="$("$BINARY" --help 2>&1)" || help=""
    case "$help" in
        *--check-config*) ;;
        *) ASK_VERDICT=unasked; return 0 ;;
    esac
    read_unit_rust_log
    case "$UNIT_RUST_LOG_STATE" in
        found) note "asking with the RUST_LOG the $SERVICE_NAME unit sets: $UNIT_RUST_LOG" ;;
        unreadable) note "the $SERVICE_NAME unit's RUST_LOG was not checked: systemd's quoting of it cannot be read safely here" ;;
    esac
    if ASK_OUTPUT="$(check_config_as_the_unit "$BINARY" "$1" 2>&1)"; then
        ASK_VERDICT=loads
    else
        ASK_VERDICT=refuses
    fi
}

# Asks $BINARY about the config this host already has, before a run that
# replaces the installed binary, and ends the run when it cannot load it. The
# same question deploy.sh asks before its swap (check_config_with).
check_existing_config() {
    ask_binary "$CONF"
    case "$ASK_VERDICT" in
        loads) note "$CONF loads on this volto" ;;
        unasked) note "this volto predates --check-config, so it cannot be asked about $CONF" ;;
        *)
            {
                echo "==> volto cannot load $CONF"
                echo "$ASK_OUTPUT"
                note "nothing was installed; the binary, the unit and the service are as they were"
                note "the position above names the line to comment out in $CONF"
                note "(docs/configuration.md, version compatibility, says which key arrived when)"
                if [ "$UNIT_RUST_LOG_STATE" = found ]; then
                    note "a refusal that names RUST_LOG is the $SERVICE_NAME unit's RUST_LOG=$UNIT_RUST_LOG,"
                    note "not $CONF: change it in the unit's drop-in (docs/deployment.md, RUST_LOG)"
                fi
            } >&2
            die "refusing to install $BINARY over a config it cannot load"
            ;;
    esac
}

# The port is validated here rather than in the preflight below, because both
# flags that stop after generating a config reach that generation, and a config
# naming a port the install path would refuse must not be printed or loaded as
# if it were installable.
case "$PORT" in
    ''|*[!0-9]*) die "port must be a number, got: $PORT" ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    die "port out of range: $PORT"
fi

# Both flags below stop after the config has been generated, and both reach it
# through the same temporary file the install path writes. That is what puts
# generate_config, verify_config and check_generated_config within reach of the
# test suite, which cannot run the rest of the script.
if [ "$PRINT_CONFIG" -eq 1 ] || [ "$CHECK_CONFIG" -eq 1 ]; then
    [ -f "$EXAMPLE_SRC" ] || die "missing $EXAMPLE_SRC"
    check_credentials
    [ -n "$PASSWORD" ] || PASSWORD="$(openssl rand -base64 18)"

    tmp="$(mktemp)"
    # shellcheck disable=SC2064  # $tmp must expand now, not at trap time.
    trap "rm -f '$tmp'" EXIT
    generate_config >"$tmp"
    verify_config "$tmp"

    [ "$PRINT_CONFIG" -eq 0 ] || cat "$tmp"

    if [ "$CHECK_CONFIG" -eq 1 ]; then
        # The binary is needed here and only here: --print-config never runs it,
        # which is why it works in a checkout with nothing built.
        [ -f "$BINARY" ] || die "no volto binary at $BINARY — pass --binary PATH (a release tarball unpacks it as ./volto) or build it first: cargo build --release"
        [ -x "$BINARY" ] || die "$BINARY is not executable"
        check_generated_config "$tmp"
    fi

    exit 0
fi

# --- preflight --------------------------------------------------------------

[ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0)"

command -v apt-get >/dev/null 2>&1 ||
    die "this script targets Debian/Ubuntu; install manually elsewhere (see docs/deployment.md)"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
command -v openssl >/dev/null 2>&1 || die "openssl is required (apt install openssl)"

# PORT was validated above, before the flags branch. Both of those paths stop
# after generating a config, so the check cannot wait until here.
check_credentials

[ -f "$BINARY" ] || die "no volto binary at $BINARY — pass --binary PATH (a release tarball unpacks it as ./volto) or build it first: cargo build --release"
[ -x "$BINARY" ] || die "$BINARY is not executable"

[ -f "$UNIT_SRC" ] || die "missing $UNIT_SRC"
[ -f "$EXAMPLE_SRC" ] || die "missing $EXAMPLE_SRC"

# A host with a config is a configured host: its binary and unit are replaced
# only when they are missing or --replace-binary asks for it. Whether the new
# binary can load the config that is already here is asked now, before
# anything on the host changes, so a refusal leaves the host as it was.
HAD_CONFIG=0
[ ! -f "$CONF" ] || HAD_CONFIG=1
PLACE_BINARY=1
PLACE_UNIT=1
if [ "$HAD_CONFIG" -eq 1 ] && [ "$REPLACE_BINARY" -eq 0 ]; then
    [ ! -x "$BIN" ] || PLACE_BINARY=0
    [ ! -f "$UNIT" ] || PLACE_UNIT=0
fi
if [ "$HAD_CONFIG" -eq 1 ] && [ "$PLACE_BINARY" -eq 1 ]; then
    check_existing_config
fi

# A run with no terminal on stdout is the update timer's (its output goes to
# the journal) or another program's. Where the config is missing on a host that
# already has a binary or a unit, generating a password would replace the one
# every client uses, and the new one would be printed nowhere (see the report).
# So such a run is refused unless the password is given.
if [ "$HAD_CONFIG" -eq 0 ] && [ -z "$PASSWORD" ] && [ ! -t 1 ] &&
    { [ -e "$BIN" ] || [ -e "$UNIT" ]; }; then
    die "$CONF is missing on a host that already has $BIN or $UNIT, and this run has no terminal: a generated password would replace the one the clients use without anybody seeing it -- run this from a terminal, or set PASSWORD"
fi

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

# The name goes into openssl's -subj and -addext arguments and into the printed
# policy line, where a comma adds a second subjectAltName entry (an IP address
# among them) and a slash a subject field. So it must be a host name by our
# rule: dot-separated labels of ASCII letters, digits and inner hyphens, each
# at most 63 bytes, at most 253 in all, and a last label that is not all
# digits, so no IPv4 address passes. In the C locale, so the ranges are ASCII
# and the length is in bytes.
check_sni() {
    local LC_ALL=C
    local label='[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
    if [ "${#SNI}" -gt 253 ] || ! [[ "$SNI" =~ ^($label\.)*$label$ ]] || [[ "${SNI##*.}" =~ ^[0-9]+$ ]]; then
        die "the certificate name must be a host name (letters, digits, hyphens and dots, not ending in a number), got: $SNI"
    fi
}
check_sni

echo "==> installing volto (self-signed, sni=$SNI, port=$PORT)"

# --- user and directories ---------------------------------------------------

if id -u volto >/dev/null 2>&1; then
    note "system user 'volto' already exists, keeping it"
else
    useradd --system --no-create-home --shell /usr/sbin/nologin volto
    note "created system user 'volto'"
fi

# /etc/volto belongs to root, and the service reads it through its group:
# root:volto 0750 for the directory, 0640 for the config and the key, 0644 for
# the certificate. The service user can then add, rename or remove nothing in
# it, so a name this script checks below still names the same file when root
# writes, renames, chowns or chmods it. Releases before this one made the
# directory and its files the service user's; the chown and chmod here move a
# directory from that layout, and deploy.sh moves the rest of its files.
install -d -m 0750 "$CONF_DIR"
chown root:volto "$CONF_DIR"
chmod 0750 "$CONF_DIR"

# Ends the run when the name $1 is anything but missing or a regular file with
# one link. `test -f`, `chown` and `chmod` follow a symbolic link, and openssl
# writes through one, so a link planted while the service user still owned the
# directory would turn the steps below into changes to the file it points at.
refuse_unsafe_entry() {
    [ ! -L "$1" ] || die "$1 is a symbolic link; refusing to use it (put the file itself there)"
    [ -e "$1" ] || return 0
    [ -f "$1" ] || die "$1 is not a regular file; refusing to use it"
    [ -z "$(find "$1" -prune -links +1)" ] ||
        die "$1 has more than one hard link; refusing to use it (copy it to a file of its own)"
}
for entry in "$CERT" "$KEY" "$CONF"; do
    refuse_unsafe_entry "$entry"
done

# --- certificate ------------------------------------------------------------

# Puts back whatever the certificate swap had moved, removes the new pair, then
# ends the run.
#
# Armed as an ERR trap over the four renames of the swap and the ownership and
# mode that follow them, and disarmed after the chmod block. Without it `set -e`
# ends the run with the configured pair split, or with the new pair in place and
# the key still root:root and mode 0600 from openssl's umask, which the next
# restart cannot read.
# A failure at the key backup leaves the old key with no certificate. A failure
# at either move into place leaves the new certificate, or no certificate,
# beside the old key's backup. The running service keeps the pair it loaded, so
# the next restart is what fails.
#
# The moves are undone in reverse order. The old certificate replaces the new
# one in a single rename, so the certificate path is not left empty while there
# is an old certificate to restore.
restore_previous_pair() {
    trap - ERR
    local restored="" removed=""

    # A new file with no previous one to give way to is removed. Leaving a new
    # key behind would put it beside a restored certificate it does not match,
    # or leave half a pair after a first install.
    if [ -n "$key_backup" ]; then
        if mv -f "$key_backup" "$KEY"; then
            restored="$KEY"
        fi
    elif [ "$key_placed" -eq 1 ]; then
        if rm -f "$KEY"; then
            removed="$KEY"
        fi
    fi
    if [ -n "$cert_backup" ]; then
        if mv -f "$cert_backup" "$CERT"; then
            restored="$CERT${restored:+ and $restored}"
        fi
    elif [ "$cert_placed" -eq 1 ]; then
        if rm -f "$CERT"; then
            removed="$CERT${removed:+ and $removed}"
        fi
    fi
    rm -f "$CERT.new" "$KEY.new"

    if [ -n "$restored" ] && [ -n "$removed" ]; then
        die "installing the new certificate failed; restored the previous $restored and removed the new $removed"
    elif [ -n "$restored" ]; then
        die "installing the new certificate failed; restored the previous $restored"
    elif [ -n "$removed" ]; then
        die "installing the new certificate failed; there was no previous pair to restore, and removed the new $removed"
    fi
    die "installing the new certificate failed before anything was moved into place"
}

CERT_CHANGED=0
if [ -f "$CERT" ] && [ -f "$KEY" ] && [ "$FORCE" -eq 0 ]; then
    note "certificate already exists, keeping it (use --force to regenerate)"
else
    CERT_CHANGED=1
    # The new pair is written beside the old one and moved into place only after
    # openssl has succeeded. A renewal that fails -- a full filesystem, a
    # provider that will not initialize, an extension this openssl does not know
    # -- therefore leaves the configured paths holding the pair that already
    # worked, which is the pair the next restart has to load.
    #
    # EC P-256: smaller handshake than RSA, and universally supported by TLS 1.3.
    # The SAN is what actually gets matched -- a bare CN has not been accepted for
    # years -- so it must be present even though the name is fictional.
    #
    # keyUsage names digitalSignature alone. RFC 8446 section 4.4.2.2: "the
    # digitalSignature bit MUST be set if the Key Usage extension is present".
    # keyEncipherment is the bit for RSA key transport, which an EC key cannot
    # perform.
    #
    # `umask 077` in a subshell around the generation: openssl creates -keyout
    # with the process umask, so without it the new key is world-readable from
    # its creation until the chmod below. The subshell keeps the umask off the
    # rest of the script.
    #
    # One timestamp for both backups, so the pair keeps a name that says it is a
    # pair. Every name the swap writes is cleared or checked first, for the
    # reason refuse_unsafe_entry gives.
    stamp="$(date +%Y%m%d%H%M%S)"
    rm -f "$CERT.new" "$KEY.new"
    for entry in "$CERT.$stamp.bak" "$KEY.$stamp.bak"; do
        if [ -e "$entry" ] || [ -L "$entry" ]; then
            die "$entry already exists; refusing to overwrite it"
        fi
    done
    (
        umask 077
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -keyout "$KEY.new" -out "$CERT.new" \
            -days "$CERT_DAYS" -nodes \
            -subj "/CN=$SNI" \
            -addext "subjectAltName=DNS:$SNI" \
            -addext "basicConstraints=critical,CA:FALSE" \
            -addext "keyUsage=critical,digitalSignature" \
            -addext "extendedKeyUsage=serverAuth" \
            >/dev/null 2>&1
    ) || {
        rm -f "$CERT.new" "$KEY.new"
        die "openssl failed to generate the certificate; the previous certificate and key are untouched at $CERT and $KEY"
    }

    # What restore_previous_pair needs to know about how far the swap got.
    cert_backup=""
    key_backup=""
    cert_placed=0
    key_placed=0
    trap restore_previous_pair ERR

    if [ -f "$CERT" ]; then
        mv "$CERT" "$CERT.$stamp.bak"
        cert_backup="$CERT.$stamp.bak"
        if [ -f "$KEY" ]; then
            mv "$KEY" "$KEY.$stamp.bak"
            key_backup="$KEY.$stamp.bak"
        fi
        note "backed up the previous certificate to $cert_backup"
    fi

    mv "$CERT.new" "$CERT"
    cert_placed=1
    mv "$KEY.new" "$KEY"
    key_placed=1

    note "generated a self-signed certificate for $SNI, valid $CERT_DAYS days"
fi

chown root:volto "$CERT" "$KEY"
chmod 0644 "$CERT"
chmod 0640 "$KEY"
# The transaction is complete. restore_previous_pair removes the new pair and
# restores the old one, so a kept-certificate run armed no trap and disarms
# nothing here.
trap - ERR

# --- configuration ----------------------------------------------------------

if [ -f "$CONF" ]; then
    note "$CONF already exists, keeping it (edit it by hand if you need changes)"
    # Its content is kept; its owner and mode become those of the new layout.
    chown root:volto "$CONF"
    chmod 0640 "$CONF"
else
    [ -n "$PASSWORD" ] || PASSWORD="$(openssl rand -base64 18)"

    tmp="$(mktemp)"
    # shellcheck disable=SC2064  # $tmp must expand now, not at trap time.
    trap "rm -f '$tmp'" EXIT

    generate_config >"$tmp"
    verify_config "$tmp"
    # Last thing before the file becomes this host's configuration, and after
    # the certificate exists -- one of the rules the binary checks is that the
    # paths in the file exist and are files.
    check_generated_config "$tmp"

    install -o root -g volto -m 0640 "$tmp" "$CONF"
    rm -f "$tmp"
    trap - EXIT
    note "wrote $CONF"
fi

# --- binary, unit and service -----------------------------------------------

# Puts back the binary and unit this run kept as .prev, reloads systemd, runs
# `systemctl $1`, then ends the run. The ERR trap of the swap below calls it
# with `start` and the health check with `restart`, as deploy.sh's put_back
# does, for the reasons given there.
#
# As in deploy.sh, a run that replaced the binary puts the unit back only
# together with the binary: a unit's .prev without a binary's, from a host
# whose binary was not executable, would put the new binary under the old unit.
# A run that placed only the unit (the binary was kept) puts the unit back
# alone, which is the pair the host had.
put_back() {
    trap - ERR
    local restored=""

    rm -f "$BIN.new"
    if [ "$PLACE_BINARY" -eq 1 ]; then
        if [ -f "$BIN.prev" ] && install -m 0755 "$BIN.prev" "$BIN.new" && mv -f "$BIN.new" "$BIN"; then
            restored="binary"
            if [ -f "$UNIT.prev" ] && install -m 0644 "$UNIT.prev" "$UNIT"; then
                restored="binary and unit"
            fi
        fi
    elif [ -f "$UNIT.prev" ] && install -m 0644 "$UNIT.prev" "$UNIT"; then
        restored="unit"
    fi
    systemctl daemon-reload || true
    systemctl "$1" "$SERVICE_NAME" || true

    [ -n "$restored" ] ||
        die "replacing the binary and unit failed and there was nothing to restore -- see: journalctl -u $SERVICE_NAME -e"
    die "replacing the binary and unit failed; restored the previous $restored -- see: journalctl -u $SERVICE_NAME -e"
}

if [ "$HAD_CONFIG" -eq 1 ] && [ "$PLACE_BINARY" -eq 0 ] && [ "$PLACE_UNIT" -eq 0 ]; then
    note "kept the installed binary and unit (--replace-binary replaces them)"
    # A reload makes the running service read the new certificate, and keeps
    # every established tunnel.
    if [ "$CERT_CHANGED" -eq 1 ] && systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl reload "$SERVICE_NAME"
        note "reloaded $SERVICE_NAME, which serves the new certificate from now on"
    fi
elif [ "$HAD_CONFIG" -eq 1 ]; then
    # A configured host: the files being replaced are kept as .prev first, as
    # deploy.sh keeps them, and put back if the service does not come up. A
    # .prev left by an earlier run is removed, so it is never restored as if
    # it were what this run replaced.
    rm -f "$BIN.prev" "$UNIT.prev" "$BIN.new"
    if [ "$PLACE_BINARY" -eq 1 ] && [ -x "$BIN" ]; then
        install -m 0755 "$BIN" "$BIN.prev"
        note "previous binary kept at $BIN.prev"
    fi
    if [ "$PLACE_UNIT" -eq 1 ] && [ -f "$UNIT" ]; then
        install -m 0644 "$UNIT" "$UNIT.prev"
        note "previous unit kept at $UNIT.prev"
    fi
    # The commands are written out here rather than in a function, because
    # this script does not set -E and a function would not inherit the trap.
    trap 'put_back start' ERR
    if [ "$PLACE_BINARY" -eq 1 ]; then
        install -m 0755 "$BINARY" "$BIN.new"
        mv -f "$BIN.new" "$BIN"
        note "installed $("$BIN" --version 2>/dev/null || echo volto) to $BIN"
    fi
    [ "$PLACE_UNIT" -eq 0 ] || install -m 0644 "$UNIT_SRC" "$UNIT"
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl restart "$SERVICE_NAME"
    else
        systemctl start "$SERVICE_NAME"
    fi
    # A command inside `if` does not fire the trap, so a service that came up
    # and then died reaches the else branch.
    sleep 3
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        trap - ERR
    else
        put_back restart
    fi
else
    # A first install, or a host whose config was deleted: the config was just
    # generated and asked about with this binary, so the binary and unit go in
    # with it and no previous copy is kept.
    install -m 0755 "$BINARY" "$BIN.new"
    mv -f "$BIN.new" "$BIN"
    note "installed $("$BIN" --version 2>/dev/null || echo volto) to $BIN"
    install -m 0644 "$UNIT_SRC" "$UNIT"
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true

    # Under Type=exec a start fails at once when the binary cannot be executed
    # (a noexec mount, the wrong architecture). That failure must not end the
    # run here: the report below prints the fingerprint and the policy line,
    # which are the point of a first install, and then fails the run on the
    # service's status.
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl restart "$SERVICE_NAME" ||
            note "systemctl restart $SERVICE_NAME failed; the report follows, then the run fails"
    else
        systemctl start "$SERVICE_NAME" ||
            note "systemctl start $SERVICE_NAME failed; the report follows, then the run fails"
    fi
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

# Every substitution from here to the end of the report ends in `|| true`, and
# each has a fallback value. Under `set -euo pipefail` the exit status of a plain
# assignment is the command substitution's, and pipefail makes a pipeline fail
# when any stage does, so a failing `openssl x509`, `hostname` or a `grep` with no
# match would end the script here. By this point the certificate has been
# regenerated and the service restarted, so that exit is silent, prints no
# fingerprint, and lands exactly when every client's pinned fingerprint has just
# gone stale. The report is the point of a re-run.
fingerprint="$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 || true)"
expiry="$(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2 || true)"
[ -n "$fingerprint" ] || fingerprint="<unknown>"
[ -n "$expiry" ] || expiry="<unknown>"

# Only for the pasteable policy line; the operator substitutes the real address if
# this box is behind a relay.
address="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
[ -n "$address" ] || address="<server-ip>"

# The password is read back out of the config so a re-run prints the one actually
# in force rather than a freshly generated one that was never installed. Read
# with builtins, for the reason generate_config gives. Nothing matches a config
# whose user line was hand-edited into another spelling, or one with
# `users = []`, and the documentation invites both; an unreadable line prints as
# <unknown> and says so rather than ending the run.
conf_username=""
conf_password=""
user_line='\{ username = "([^"]*)", password = "([^"]*)" \}'
while IFS= read -r line || [ -n "$line" ]; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ $user_line ]]; then
        conf_username="${BASH_REMATCH[1]}"
        conf_password="${BASH_REMATCH[2]}"
        break
    fi
done <"$CONF" || true
if [ -z "$conf_username" ] || [ -z "$conf_password" ]; then
    note "no '{ username = ..., password = ... }' entry could be read out of $CONF;"
    note "the policy line below names the credential as <unknown>"
    [ -n "$conf_username" ] || conf_username="<unknown>"
    [ -n "$conf_password" ] || conf_password="<unknown>"
fi

echo
echo "==> done"
echo "service:     $SERVICE_NAME is $status  (journalctl -u $SERVICE_NAME -f)"
echo "certificate: $fingerprint"
echo "expires:     $expiry"
echo
echo "Surge policy line (replace the address if this host is behind a relay):"
echo
# The password is printed only to a terminal. Without one, stdout is the
# journal of the timer's service or a log file, which other users can read.
if [ -t 1 ]; then
    shown_password="$conf_password"
else
    shown_password="<as in $CONF>"
fi
echo "  volto = masque, $address, $PORT, sni=$SNI, server-cert-fingerprint-sha256=${fingerprint#*=}, username=$conf_username, password=$shown_password"
echo
echo "Security notes:"
echo "  * The fingerprint above IS the trust anchor. Carry it to your device over a"
echo "    channel you trust and type it in yourself. Never use skip-cert-verify instead."
echo "  * $KEY must never leave this machine. There is no revocation: if it leaks,"
echo "    regenerate with --force and update the fingerprint on every client."
echo

# After the report, so the fingerprint and the policy line are printed even when
# the service did not come up. A port already bound is the common cause, and it
# leaves the host without a proxy while the install would otherwise report
# success.
[ "$status" = active ] ||
    die "$SERVICE_NAME is $status after the install; the proxy is not serving -- see: journalctl -u $SERVICE_NAME -e"
