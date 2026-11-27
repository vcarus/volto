//! The release deploy script must stay runnable and honest about its decisions.
//!
//! `script/deploy.sh` is the only channel a release reaches a host through, and
//! it runs unattended from a daily timer. Downloading, verifying and installing
//! needs root, a Linux host and the network, none of which a test should touch —
//! but the *decision* in front of all that is pure logic, and both of its most
//! fragile branches have already broken in production once: the convergence
//! check ("already deployed and intact") and `refresh_self` under a piped
//! bootstrap, where `$0` is `bash` rather than a file.
//!
//! `--dry-run` exists for this test, in the spirit of the installer's
//! `--print-config`: it skips the preflight, prints the decision it would act on
//! and stops. `VOLTO_DEPLOY_ROOT` prefixes every install path, so a temporary
//! directory stands in for `/usr/local` and `/etc`.
//!
//! The real install path runs as well, end to end and without root: `Host`
//! below puts stand-ins for `id`, `uname`, `sleep`, `sha256sum`, `systemctl` and
//! `curl` first on `PATH`, and serves a local archive in place of the release
//! page. It installs a release from before signing with `--allow-unsigned`,
//! because no test holds the release key. The signed half of `verify_release`
//! therefore runs on its own, with a test key, as do `acquire_lock` and
//! `refuse_automatic_downgrade`.

#[path = "common/scripts.rs"]
mod scripts;

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use scripts::{
    Scratch, loadable_config_text, path_with_stubs, plant_binary_without_the_flag,
    plant_placeholder_certificates, real_binary, real_tool, repo_root, run_within_deadline,
    scratch_tree, shell_function_body, stderr_of, stdout_of, write_executable,
};

fn deploy_script() -> PathBuf {
    repo_root().join("script/deploy.sh")
}

/// The variables `deploy.sh` reads from its environment or hands on to the
/// bundled installer, which a run clears so that an operator's shell cannot
/// change it.
const DEPLOY_ENVIRONMENT: [&str; 12] = [
    "TAG",
    "REPO",
    "PASSWORD",
    "SNI",
    "PORT",
    "USERNAME",
    "BINARY",
    "RUST_LOG",
    "JOURNAL_STREAM",
    "VOLTO_DEPLOY_CANDIDATE",
    "VOLTO_DEPLOY_SIGNER",
    "VOLTO_INSTALL_ROOT",
];

/// `bash`, run from the checkout with a null stdin, the variables in
/// [`DEPLOY_ENVIRONMENT`] cleared, `VOLTO_DEPLOY_ROOT` set to `root` and
/// `stubs` first on `PATH`. A caller adds the script, or `-s` to pipe it in.
///
/// `stubs` gets a `curl` and a `systemctl` that fail, unless the caller has
/// planted its own, so a run that gets further than it should reaches neither
/// the network nor the host's systemd.
fn deploy_shell(root: &Path, stubs: &Path) -> Command {
    fs::create_dir_all(stubs).expect("the stub directory must be creatable");
    for tool in ["curl", "systemctl"] {
        let stand_in = stubs.join(tool);
        if !stand_in.exists() {
            write_executable(
                &stand_in,
                &format!("#!/bin/sh\necho \"the test's {tool} refuses: $*\" >&2\nexit 97\n"),
            );
        }
    }
    let mut command = Command::new(real_tool("bash"));
    command
        .current_dir(repo_root())
        .stdin(Stdio::null())
        .env("PATH", path_with_stubs(stubs))
        .env("VOLTO_DEPLOY_ROOT", root);
    for variable in DEPLOY_ENVIRONMENT {
        command.env_remove(variable);
    }
    command
}

/// [`deploy_shell`] running `script/deploy.sh`. Every run of the script starts
/// here; a caller adds the arguments and what it sets.
fn deploy(root: &Path, stubs: &Path) -> Command {
    let mut command = deploy_shell(root, stubs);
    command.arg(deploy_script());
    command
}

/// Runs the script with `args`, its install paths under `root` and the
/// stand-ins in `root/stubs`.
fn run_deploy(root: &Path, args: &[&str]) -> Output {
    run_within_deadline(deploy(root, &root.join("stubs")).args(args))
}

/// Runs the script with a binary standing in for the one a release would carry.
///
/// `VOLTO_DEPLOY_CANDIDATE` is the second test seam, alongside
/// `VOLTO_DEPLOY_ROOT`: in a real run the candidate is the binary just unpacked
/// from the verified tarball, which a dry run never downloads, so a dry run
/// takes it from here instead. The capability probe and the check itself are
/// `check_config_with` either way. The call site is not: the dry run calls it
/// from a branch of its own, and the real path's call is run by
/// `the_real_update_path_refuses_a_release_that_cannot_load_the_config`.
fn run_deploy_with_candidate(root: &Path, candidate: &Path, args: &[&str]) -> Output {
    run_within_deadline(
        deploy(root, &root.join("stubs"))
            .args(args)
            .env("VOLTO_DEPLOY_CANDIDATE", candidate),
    )
}

/// A stand-in for a host's filesystem: the directories a Linux host already has,
/// under a directory of this test's own.
fn install_root(name: &str) -> Scratch {
    scratch_tree(
        "deploy",
        name,
        &[
            "usr/local/bin",
            "usr/local/sbin",
            "etc/volto",
            "etc/systemd/system",
        ],
    )
}

/// Plants an installed binary that answers `--version` like the real one.
fn plant_binary(root: &Path, version: &str) {
    write_executable(
        &root.join("usr/local/bin/volto"),
        &format!("#!/bin/sh\necho \"volto {version}\"\n"),
    );
}

fn plant_config(root: &Path) {
    fs::write(root.join("etc/volto/config.toml"), "# planted\n").expect("config must be writable");
}

fn plant_unit(root: &Path) {
    fs::write(root.join("etc/systemd/system/volto.service"), "# planted\n")
        .expect("the unit must be writable");
}

/// Plants a configuration the real binary can be asked a real question about,
/// with `body` appended verbatim so a test can add a key from the future.
///
/// The certificate pair is planted with it because `Config::validate` insists
/// both paths are files; nothing reads them.
fn plant_loadable_config(root: &Path, body: &str) {
    let dir = root.join("etc/volto");
    let (cert, key) = plant_placeholder_certificates(&dir);
    fs::write(
        dir.join("config.toml"),
        loadable_config_text(&cert, &key, "127.0.0.1:4433", "planted", body),
    )
    .expect("config must be writable");
}

/// `-h` must work and describe the flags the documentation relies on.
#[test]
fn the_script_documents_itself() {
    let output = run_deploy(&install_root("usage"), &["-h"]);

    assert!(output.status.success());
    let usage = stdout_of(&output);
    for expected in [
        "--tag",
        "--enable-timer",
        "--dry-run",
        "--force",
        "--allow-unsigned",
        "--verify-signature",
        "--sni",
        "Re-running is safe",
    ] {
        assert!(
            usage.contains(expected),
            "usage must mention {expected}: {usage}"
        );
    }
}

/// Arguments the script refuses before anything privileged or networked is
/// attempted, each with the words that name what is wrong.
#[test]
fn arguments_that_cannot_be_acted_on_are_refused() {
    let root = install_root("refused-arguments");
    for (args, refusal) in [
        // Garbage flags, named back.
        (
            &["--definitely-not-a-flag"][..],
            "unknown option: --definitely-not-a-flag",
        ),
        // Caught before any download starts.
        (&["--tag"][..], "--tag needs a value"),
        // The shape check on the tag sits after the preflight, so only the dry
        // run reaches it on a dev host.
        (
            &["--dry-run", "--tag", "0.2.4"][..],
            "--tag expects the tag name as on the releases page",
        ),
        // Resolving "latest" is a network call, which a dry run never makes.
        (&["--dry-run"][..], "--dry-run needs --tag"),
        // `--force` puts a named release's bytes on the host, so it has to be
        // told which release.
        (&["--force"][..], "--force needs --tag"),
        // An unsigned release is installed by name. Without a tag the run
        // would resolve the latest release, the path the timer takes, which
        // must never accept a release without a signature.
        (&["--allow-unsigned"][..], "--allow-unsigned needs --tag"),
    ] {
        let output = run_deploy(&root, args);

        assert!(!output.status.success(), "{args:?} must be refused");
        assert!(
            stderr_of(&output).contains(refusal),
            "{args:?} must be refused with `{refusal}`: {}",
            stderr_of(&output)
        );
    }
}

/// The gap `--force` closes: the version string is the whole convergence test,
/// so a host reporting the release's version keeps whatever binary it has.
///
/// A release deleted and published again under the same tag leaves exactly
/// that, and on 2026-09-05 it left a host running the bytes of the first
/// upload. Without `--force` the run is the no-op below; with it the same
/// intact install is downloaded, verified and installed again.
#[test]
fn an_intact_install_is_reinstalled_when_the_run_is_forced() {
    let root = install_root("forced-reinstall");
    plant_binary(&root, "0.2.4");
    plant_config(&root);
    plant_unit(&root);

    let output = run_deploy(&root, &["--dry-run", "--tag", "v0.2.4", "--force"]);

    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(
        stdout_of(&output),
        "dry-run: would reinstall v0.2.4
"
    );
}

/// The no-op that makes the daily timer safe: same version, config and unit in
/// place, so nothing is downloaded, installed or restarted.
#[test]
fn an_intact_install_of_the_release_version_is_left_alone() {
    let root = install_root("intact");
    plant_binary(&root, "0.2.4");
    plant_config(&root);
    plant_unit(&root);

    let output = run_deploy(&root, &["--dry-run", "--tag", "v0.2.4"]);

    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(
        stdout_of(&output),
        "dry-run: already deployed and intact (v0.2.4)\n"
    );
}

/// The regression the v0.2.1 fix was about: a deleted config must pull the run
/// back onto the first-install path even though the version already matches.
#[test]
fn a_missing_config_reinstalls_at_the_matching_version() {
    let root = install_root("missing-config");
    plant_binary(&root, "0.2.4");
    plant_unit(&root);

    let output = run_deploy(&root, &["--dry-run", "--tag", "v0.2.4"]);

    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(
        stdout_of(&output),
        "dry-run: would install v0.2.4 (missing: config)\n"
    );
}

/// A deleted unit, on the other hand, is the update path: the config is what
/// tells the script an install already exists.
#[test]
fn a_missing_unit_at_the_matching_version_is_an_update() {
    let root = install_root("missing-unit");
    plant_binary(&root, "0.2.4");
    plant_config(&root);

    let output = run_deploy(&root, &["--dry-run", "--tag", "v0.2.4"]);

    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(
        stdout_of(&output),
        "dry-run: would update 0.2.4 -> v0.2.4 (missing: unit)\n"
    );
}

/// The everyday path of a timered host: a newer release exists. The whole
/// output is the decision, with no downgrade advisory, since a warning printed
/// on every timer tick is a warning nobody reads.
#[test]
fn an_older_installed_version_becomes_an_update() {
    let root = install_root("older");
    plant_binary(&root, "0.2.3");
    plant_config(&root);
    plant_unit(&root);

    let output = run_deploy(&root, &["--dry-run", "--tag", "v0.2.4"]);

    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(
        stdout_of(&output),
        "dry-run: would update 0.2.3 -> v0.2.4\n"
    );
}

/// A downgrade is the incident path, and two of its hazards are invisible from
/// the outside until they bite.
///
/// The config file is never rewritten by anything here, so it may name keys the
/// older binary refuses outright — `mtu_upper_bound` reached the shipped example
/// in v0.4.5, and every install is derived from that example — and an older
/// volto rejects the whole file rather than the one key, so the service simply
/// does not start. And `--tag` pins nothing: the update timer resolves the
/// latest release, so a rollback left alone is undone on the next tick.
///
/// Both belong in front of the operator running the rollback, not in a document
/// they are not reading at the time.
#[test]
fn a_downgrade_says_what_bites_on_the_way_back() {
    let root = install_root("downgrade");
    plant_binary(&root, "0.5.1");
    plant_config(&root);
    plant_unit(&root);

    let output = run_deploy(&root, &["--dry-run", "--tag", "v0.4.4"]);

    assert!(output.status.success(), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);
    for expected in [
        "0.5.1 -> 0.4.4 is a downgrade",
        // The config hazard, and the string to grep the journal for.
        "unknown field",
        // The timer hazard, and the command that holds the rollback.
        "volto-deploy.timer",
    ] {
        assert!(
            stdout.contains(expected),
            "a downgrade must warn about {expected}: {stdout}"
        );
    }

    // The advisory goes in front of the decision, which stays the last line and
    // keeps its exact shape.
    assert!(
        stdout.ends_with("dry-run: would update 0.5.1 -> v0.4.4\n"),
        "the decision must still be the last thing printed: {stdout}"
    );
}

/// The advisory's successor: a downgrade the candidate binary cannot survive is
/// refused at the door rather than announced and then attempted.
///
/// This is the D93 shape end to end, with the real binary as the judge: the
/// config carries a key it does not know, every table is `deny_unknown_fields`,
/// so it refuses the whole file and would not start. Saying so is only useful
/// before the swap — afterwards the service is already down and the automatic
/// rollback restores the release the operator was trying to leave.
#[test]
fn a_candidate_that_cannot_load_this_hosts_config_is_refused_before_anything_moves() {
    let root = install_root("candidate-refuses");
    plant_binary(&root, "0.5.1");
    plant_loadable_config(&root, "\n[limits]\na_key_a_later_release_added = 2\n");
    plant_unit(&root);

    let output =
        run_deploy_with_candidate(&root, &real_binary(), &["--dry-run", "--tag", "v0.4.4"]);

    assert!(
        !output.status.success(),
        "an install that cannot come up must not be attempted: {}",
        stdout_of(&output)
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("unknown field"),
        "the candidate's own account of the refusal must reach the operator: {stderr}"
    );
    assert!(
        stderr.contains("at line "),
        "including the position, which is the only thread back to the key: {stderr}"
    );

    let stdout = stdout_of(&output);
    assert!(
        !stdout.contains("would update"),
        "the run must stop before the decision it would have acted on: {stdout}"
    );
}

/// The config check does not pass the script's `JOURNAL_STREAM` on (S9-L9).
///
/// Under the timer the script's own output goes to the journal, so systemd sets
/// `JOURNAL_STREAM` for it, and volto takes the variable alone as the cue to
/// put a `<N>` priority before each line. The check's output is captured and
/// printed by the script, so the refusal carried a literal `<3>`. The run here
/// sets the variable as the timer's service does, and the real binary refuses
/// the config.
#[test]
fn the_config_check_does_not_write_for_the_journal() {
    let root = install_root("candidate-journal");
    plant_binary(&root, "0.5.1");
    plant_loadable_config(&root, "\n[limits]\na_key_a_later_release_added = 2\n");
    plant_unit(&root);

    let output = run_within_deadline(
        deploy(&root, &root.join("stubs"))
            .args(["--dry-run", "--tag", "v0.4.4"])
            .env("VOLTO_DEPLOY_CANDIDATE", real_binary())
            .env("JOURNAL_STREAM", "8:12345"),
    );

    let stderr = stderr_of(&output);
    assert!(
        !output.status.success() && stderr.contains("Error: failed to parse config file"),
        "the real binary must refuse the planted config: {stderr}"
    );
    assert!(
        !stderr.contains("<3>"),
        "the captured refusal must carry no journal priority prefix: {stderr}"
    );
}

/// The other verdict: a configuration the candidate loads is not in the way, and
/// the run carries on to the decision it was going to make anyway.
#[test]
fn a_candidate_that_loads_the_config_lets_the_run_continue() {
    let root = install_root("candidate-accepts");
    plant_binary(&root, "0.5.1");
    plant_loadable_config(&root, "");
    plant_unit(&root);

    let output =
        run_deploy_with_candidate(&root, &real_binary(), &["--dry-run", "--tag", "v0.4.4"]);

    assert!(output.status.success(), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("loads on volto 0.4.4"),
        "the run must say the config was checked and by which version: {stdout}"
    );
    assert!(
        stdout.ends_with("dry-run: would update 0.5.1 -> v0.4.4\n"),
        "the decision must still be the last thing printed: {stdout}"
    );
}

/// The branch that decides whether any of this can be trusted: a candidate from
/// before the flag existed.
///
/// Such a binary answers `--check-config` with clap's usage error, and reading
/// that as "your configuration is broken" would refuse every rollback to a
/// release older than this one — the exact opposite of what the check is for.
/// So the flag is detected by name in the candidate's own `--help` before it is
/// used at all, and a candidate without it falls back to the advisory the script
/// printed before any of this existed. The stand-in fails loudly on an unknown
/// argument, so an implementation that tried the flag first would be caught
/// here rather than on a host.
#[test]
fn a_candidate_that_predates_the_flag_falls_back_to_the_advisory() {
    let root = install_root("candidate-too-old");
    plant_binary(&root, "0.5.1");
    plant_loadable_config(&root, "\n[limits]\na_key_a_later_release_added = 2\n");
    plant_unit(&root);
    let candidate = plant_binary_without_the_flag(&root, "candidate-old");

    let output = run_deploy_with_candidate(&root, &candidate, &["--dry-run", "--tag", "v0.4.4"]);

    assert!(
        output.status.success(),
        "a candidate that cannot be asked must not be treated as a refusal: {}",
        stderr_of(&output)
    );
    let stderr = stderr_of(&output);
    assert!(
        !stderr.contains("unexpected argument"),
        "the flag must never be tried on a binary whose help does not name it: {stderr}"
    );

    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("cannot be asked"),
        "the run must say why the config went unchecked: {stdout}"
    );
    assert!(
        stdout.contains("unknown field"),
        "and fall back to the advisory, which is all it has left: {stdout}"
    );
    assert!(
        stdout.ends_with("dry-run: would update 0.5.1 -> v0.4.4\n"),
        "the decision must still be the last thing printed: {stdout}"
    );
}

/// There is nothing to check before a first install: the file the check would
/// read is the one the installer is about to create.
#[test]
fn there_is_nothing_to_check_before_a_first_install() {
    let root = install_root("candidate-first-install");
    let output =
        run_deploy_with_candidate(&root, &real_binary(), &["--dry-run", "--tag", "v0.4.4"]);

    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(
        stdout_of(&output),
        "dry-run: would install v0.4.4 (missing: config unit)\n",
        "a first install has no configuration to check"
    );
}

/// `refresh_self` keeps the copy the timer executes in step with the release,
/// and must do so exactly once: a second run has nothing to copy.
#[test]
fn the_timer_copy_is_installed_once_and_then_left_alone() {
    let root = install_root("refresh-self");
    plant_binary(&root, "0.2.3");
    plant_config(&root);
    plant_unit(&root);

    let first = run_deploy(&root, &["--dry-run", "--enable-timer", "--tag", "v0.2.4"]);
    assert!(first.status.success(), "{}", stderr_of(&first));

    let installed = root.join("usr/local/sbin/volto-deploy");
    assert_eq!(
        fs::read(&installed).expect("the timer copy must exist"),
        fs::read(deploy_script()).expect("the script must be readable"),
        "the installed copy must be this script, byte for byte"
    );
    let mode = fs::metadata(&installed)
        .expect("the timer copy must be there")
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, 0o111, "the timer copy must be executable");

    let first_out = stdout_of(&first);
    assert!(
        first_out.contains("installed this script as"),
        "the first run must say it installed itself: {first_out}"
    );
    assert!(
        first_out.ends_with("dry-run: would enable timer\n"),
        "the timer decision must be the last thing printed: {first_out}"
    );

    let second = run_deploy(&root, &["--dry-run", "--enable-timer", "--tag", "v0.2.4"]);
    assert!(second.status.success(), "{}", stderr_of(&second));
    let second_out = stdout_of(&second);
    assert!(
        !second_out.contains("installed this script as"),
        "an unchanged copy must not be reinstalled: {second_out}"
    );

    // And no systemd unit was written anywhere under the root.
    assert!(!root.join("etc/systemd/system/volto-deploy.timer").exists());
    assert!(
        !root
            .join("etc/systemd/system/volto-deploy.service")
            .exists()
    );
}

/// A dry run must not rewrite the root-owned installed copy of this script.
///
/// The timer branch used to call `refresh_self` before the dry-run exit, and
/// `refresh_self` installs the running copy over `/usr/local/sbin/volto-deploy`.
/// The help text and docs/deployment.md promise a dry run changes nothing, and
/// that path is a root-owned system file.
///
/// The stubs make the assertion meaningful on any host. `install` records its
/// arguments and fails, so a regression cannot reach the real `/usr/local/sbin`.
/// `cmp` fails, so the "already equal" early return cannot let the run pass for
/// the wrong reason. `readlink` resolves the script, which is what
/// `refresh_self` needs to see a file.
#[test]
fn a_dry_run_does_not_rewrite_the_installed_script() {
    let dir = scratch_tree("deploy", "dry-run-timer", &["stubs"]);
    let stubs = dir.join("stubs");
    let marker = stubs.join("install-called");

    write_executable(
        &stubs.join("install"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexit 1\n",
            marker.display()
        ),
    );
    write_executable(&stubs.join("cmp"), "#!/bin/sh\nexit 1\n");
    write_executable(
        &stubs.join("readlink"),
        &format!("#!/bin/sh\necho '{}'\n", deploy_script().display()),
    );

    // No VOLTO_DEPLOY_ROOT: the paths are the host's own, which is the case
    // under test.
    let output = run_within_deadline(deploy(&dir, &stubs).env_remove("VOLTO_DEPLOY_ROOT").args([
        "--dry-run",
        "--enable-timer",
        "--tag",
        "v0.2.4",
    ]));

    assert!(
        output.status.success(),
        "a dry run must succeed: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    assert!(
        stdout.ends_with("dry-run: would enable timer\n"),
        "the timer decision must be the last thing printed: {stdout}"
    );
    assert!(
        !marker.exists(),
        "a dry run installed the script over the system path; the stub recorded:\n{}",
        fs::read_to_string(&marker).unwrap_or_default()
    );
}

/// Runs the shell function `name` from `script` on its own, with the stubs in
/// `stubs` first on `PATH` and `prelude` run before the call.
///
/// `die` is defined as a recorder that exits nonzero, so a test can read what
/// the function reported. The function runs under `set -eEuo pipefail`, as in
/// the script.
fn run_shell_function(script: &str, name: &str, stubs: &Path, prelude: &str) -> Output {
    run_shell_call(script, name, "", &path_with_stubs(stubs), prelude)
}

/// [`run_shell_function`], with `then` after the function's name in the call
/// and `path` as the whole `PATH`.
fn run_shell_call(script: &str, name: &str, then: &str, path: &OsStr, prelude: &str) -> Output {
    let body = shell_function_body(script, name);
    let program = format!(
        "set -eEuo pipefail\ndie() {{ printf 'die: %s\\n' \"$*\" >&2; exit 1; }}\nnote() {{ printf 'note: %s\\n' \"$*\"; }}\n{body}\n}}\n{prelude}\n{name} {then}\n"
    );

    run_within_deadline(
        Command::new(real_tool("bash"))
            .args(["-c", &program])
            .env("PATH", path)
            .stdin(Stdio::null()),
    )
}

/// Opens the RUST_LOG reader both scripts carry.
const RUST_LOG_READER_OPEN: &str =
    "# >>> mirrored RUST_LOG reader (deploy.sh <-> install-selfsigned.sh) >>>\n";
/// And closes it.
const RUST_LOG_READER_CLOSE: &str =
    "# <<< mirrored RUST_LOG reader (deploy.sh <-> install-selfsigned.sh) <<<\n";

/// The text between the RUST_LOG reader's markers in `script`, which must open
/// and close the block once each.
fn rust_log_reader(script: &str) -> String {
    let text = fs::read_to_string(repo_root().join(script)).expect("the script must be readable");
    for marker in [RUST_LOG_READER_OPEN, RUST_LOG_READER_CLOSE] {
        assert_eq!(
            text.matches(marker).count(),
            1,
            "{script} must carry the marker {marker:?} once"
        );
    }
    let start =
        text.find(RUST_LOG_READER_OPEN).expect("counted above") + RUST_LOG_READER_OPEN.len();
    let end = text.find(RUST_LOG_READER_CLOSE).expect("counted above");
    assert!(
        start < end,
        "{script} closes the RUST_LOG reader before it opens it"
    );
    text[start..end].to_owned()
}

/// `read_unit_rust_log` and `check_config_as_the_unit` are the same in both
/// scripts, comments included (S9-D2).
///
/// `deploy.sh` runs piped from curl with no file of its own, so it cannot
/// source a shared file, and each script's behaviour tests exercise only its own
/// copy. A change to systemd's quoting rules made in one copy fails here until
/// the other matches.
#[test]
fn both_scripts_carry_the_same_rust_log_reader() {
    let deploy = rust_log_reader("script/deploy.sh");
    let installer = rust_log_reader("script/install-selfsigned.sh");
    assert!(
        deploy.contains("\nread_unit_rust_log() {\n")
            && deploy.contains("\ncheck_config_as_the_unit() {\n"),
        "the marked block must hold both functions: {deploy}"
    );
    assert_eq!(
        deploy, installer,
        "the RUST_LOG reader in script/install-selfsigned.sh has drifted from the \
         one in script/deploy.sh"
    );
}

/// Whether the shell line `line` runs `curl` as a command.
///
/// `curl` counts as a command word at the start of the line, after a `$(`, a
/// `(`, a backtick, a pipe, `&&`, `||`, `;`, `{` or a glued backslash, after a
/// word that precedes a command (`if`, `then`, `else`, `elif`, `do`, `while`,
/// `until`, `!`, `exec`, `time`, `command`), and after a variable assignment.
/// A `curl` in an argument list, such as the preflight's `for tool in curl tar
/// ...`, is not a call.
fn runs_curl(line: &str) -> bool {
    const SEPARATORS: [&str; 8] = ["$(", "(", "`", "|", "&", ";", "{", "\\"];
    const KEYWORDS: [&str; 11] = [
        "if", "then", "else", "elif", "do", "while", "until", "!", "exec", "time", "command",
    ];

    line.match_indices("curl").any(|(at, _)| {
        let after = &line[at + "curl".len()..];
        if !(after.is_empty() || after.starts_with(char::is_whitespace)) {
            return false;
        }
        let before = &line[..at];
        if !before.is_empty() && !before.ends_with(char::is_whitespace) {
            // Something is glued to the word, as in `$(curl` or `libcurl`.
            return SEPARATORS
                .iter()
                .any(|separator| before.ends_with(separator));
        }
        let Some(previous) = before.split_whitespace().last() else {
            return true;
        };
        SEPARATORS
            .iter()
            .any(|separator| previous.ends_with(separator))
            || KEYWORDS.contains(&previous)
            || (previous.contains('=') && !previous.starts_with('-'))
    })
}

#[test]
fn runs_curl_finds_curl_in_every_command_position() {
    for line in [
        "curl -fsSL \"$URL\"",
        "curl \"$BASE/NOTES\" -fsSL -o \"$TMP/notes\"",
        "location=\"$(curl -fsSLI \"$URL\")\"",
        "printf x | curl -d @- \"$URL\"",
        "true && curl \"$URL\"",
        "false || curl \"$URL\"",
        "if curl \"$URL\"; then",
        "X=1 curl \"$URL\"",
        "exec curl \"$URL\"",
        "command curl \"$URL\"",
        "\\curl \"$URL\"",
    ] {
        assert!(runs_curl(line), "a curl call was not seen: {line}");
    }
    for line in [
        "for tool in curl tar sha256sum ssh-keygen; do",
        "echo curl is required",
        "command -v curl",
        "libcurl --version",
    ] {
        assert!(!runs_curl(line), "this line runs no curl: {line}");
    }
}

/// The value of `flag` on a curl command line, as whole seconds.
fn curl_seconds(call: &str, flag: &str) -> Option<u64> {
    let mut words = call.split_whitespace();
    words.find(|word| *word == flag)?;
    let value = words
        .next()
        .unwrap_or_else(|| panic!("{flag} has no value in: {call}"));
    Some(
        value
            .parse()
            .unwrap_or_else(|_| panic!("{flag} {value} is not whole seconds in: {call}")),
    )
}

/// Every network call is bounded, and together they fit inside the timer
/// service's start timeout.
///
/// systemd disables the start timeout for `Type=oneshot`, so the timer service
/// carries its own `TimeoutStartSec`. When that timeout fires, systemd sends
/// SIGTERM. Inside the binary swap window the script then rolls the update
/// back (`a_signal_inside_the_swap_window_rolls_the_update_back`), so the
/// release is not installed, and the rollback has only the service's stop
/// timeout to finish in. So the worst case of every curl call, added up, must
/// leave time for the rest of the run.
///
/// The rest of the run is read from the unit and the script, so raising
/// `TimeoutStopSec`, `TimeoutStartSec` or the health wait turns this red: a
/// restart and a rollback restart, each a stop and a start at the unit's
/// timeouts, the health wait between them, and a minute for the local steps
/// (the checksum, the unpack, the config check and the copies).
///
/// The worst case of one call is `--max-time` when it does not retry. With
/// `--retry` it is `--retry-max-time`, after which curl starts no retry, plus
/// the longest default backoff sleep before the last retry, plus `--max-time`
/// for that last attempt. A retrying call without `--retry-max-time` has no
/// bound: a server's Retry-After header could set the sleep.
///
/// Every logical line that runs `curl` as a command is read, continuation lines
/// joined, wherever its options are. [`runs_curl`] says what a command position
/// is; the one inside `location="$(curl` is one of them.
#[test]
fn every_network_call_and_the_timer_service_are_bounded() {
    let text = fs::read_to_string(repo_root().join("script/deploy.sh"))
        .expect("the deploy script must be readable");
    let joined = text.replace("\\\n", " ");

    let calls: Vec<&str> = joined
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && runs_curl(line))
        .collect();
    assert!(
        calls.len() >= 3,
        "script/deploy.sh makes at least three curl calls (the latest-release \
         request and two downloads), but the reader found {}: {calls:?}",
        calls.len()
    );

    let mut worst_case = 0;
    for call in &calls {
        assert!(
            call.contains("--connect-timeout"),
            "this curl call has no --connect-timeout: {call}"
        );
        let max_time = curl_seconds(call, "--max-time")
            .unwrap_or_else(|| panic!("this curl call has no --max-time: {call}"));
        worst_case += match curl_seconds(call, "--retry") {
            None | Some(0) => max_time,
            Some(retries) => {
                let retry_max_time = curl_seconds(call, "--retry-max-time").unwrap_or_else(|| {
                    panic!("this curl call retries with no --retry-max-time: {call}")
                });
                retry_max_time + (1 << (retries - 1)) + max_time
            }
        };
    }

    let service = text
        .find("[Service]")
        .expect("the timer service heredoc must carry a [Service] section");
    let heredoc = &text[service..];
    let end = heredoc
        .find("\nEOF")
        .expect("the timer service heredoc must be closed");
    let timeout = heredoc[..end]
        .lines()
        .find_map(|line| line.strip_prefix("TimeoutStartSec="))
        .unwrap_or_else(|| {
            panic!(
                "the timer service carries no TimeoutStartSec, so a stalled network \
                 path holds the daily run indefinitely: {}",
                &heredoc[..end]
            )
        });
    let timeout = systemd_seconds(timeout);

    let unit = fs::read_to_string(repo_root().join("script/masque.service"))
        .expect("the unit must be readable");
    let unit_seconds = |key: &str| {
        let value = unit
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("script/masque.service sets no {key}"));
        systemd_seconds(value)
    };
    let (stop, start) = (
        unit_seconds("TimeoutStopSec"),
        unit_seconds("TimeoutStartSec"),
    );
    let restart = text
        .find("systemctl restart \"$SERVICE_NAME\"\n")
        .expect("the update path restarts the service");
    let health_wait: u64 = text[restart..]
        .lines()
        .find_map(|line| line.trim().strip_prefix("sleep "))
        .expect("the update path waits before its health check")
        .parse()
        .expect("the health wait in whole seconds");
    let rest_of_the_run = 2 * (stop + start) + health_wait + 60;
    assert!(
        worst_case + rest_of_the_run <= timeout,
        "the curl calls can take {worst_case} s, which with {rest_of_the_run} s for \
         the rest of the run exceeds TimeoutStartSec ({timeout} s): systemd could \
         stop the run inside the binary swap window"
    );
}

/// A systemd time span in whole minutes (`15min`) or seconds (`15s`, `15`).
fn systemd_seconds(value: &str) -> u64 {
    match value.strip_suffix("min") {
        Some(minutes) => minutes.parse::<u64>().expect("whole minutes") * 60,
        None => value
            .trim_end_matches('s')
            .parse()
            .unwrap_or_else(|_| panic!("{value} is not whole minutes or seconds")),
    }
}

/// The bootstrap one-liner from the release notes: piped into `bash`, `$0` is
/// not a file. This once aborted the whole run; it must be a quiet no-op.
///
/// `$0` is then the word `bash`. With a file of that name in the working
/// directory, the script once installed that file as the copy the timer runs as
/// root (second review, 2026-11-13), so the run is made from a directory that
/// holds one.
#[test]
fn a_piped_run_installs_nothing_even_beside_a_file_named_bash() {
    let root = install_root("piped-bash");
    let elsewhere = scratch_tree("deploy", "piped-bash-cwd", &[]);
    write_executable(&elsewhere.join("bash"), "#!/bin/sh\necho planted\n");

    // The documented one-liner, `curl ... | bash -s --`, which leaves `$0` as
    // `bash` instead of a path.
    let script = fs::File::open(deploy_script()).expect("the deploy script must be readable");
    let output = run_within_deadline(
        deploy_shell(&root, &root.join("stubs"))
            .args(["-s", "--", "--dry-run", "--enable-timer", "--tag", "v0.2.4"])
            .current_dir(&elsewhere)
            .stdin(Stdio::from(script)),
    );

    assert!(
        output.status.success(),
        "a piped run must not abort: {}",
        stderr_of(&output)
    );
    assert!(
        !root.join("usr/local/sbin/volto-deploy").exists(),
        "a piped run has no file to copy from, and a file named `bash` in the \
         working directory was installed as the timer's script"
    );
    let stdout = stdout_of(&output);
    assert!(
        stdout.ends_with("dry-run: would enable timer\n"),
        "the run must reach the timer decision: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// The release signature
// ---------------------------------------------------------------------------

/// The sshsig namespace `script/deploy.sh` signs and verifies under.
const SIGN_NAMESPACE: &str = "volto-release";

/// Runs `ssh-keygen`, which the script itself requires on a host.
fn ssh_keygen(args: &[&str]) -> Output {
    Command::new("ssh-keygen")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("ssh-keygen must be runnable: script/deploy.sh verifies releases with it")
}

/// A fresh Ed25519 key pair in `dir`, returning the public key in the two-field
/// form the script carries (`ssh-ed25519 AAAA…`, no comment).
fn generate_key(dir: &Path, name: &str) -> String {
    let path = dir.join(name);
    let output = ssh_keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-C",
        "",
        "-f",
        path.to_str().expect("a UTF-8 scratch path"),
    ]);
    assert!(
        output.status.success(),
        "generating a test key failed: {}",
        stderr_of(&output)
    );
    let public = fs::read_to_string(path.with_extension("pub")).expect("the public key file");
    let fields: Vec<&str> = public.split_whitespace().take(2).collect();
    fields.join(" ")
}

/// Signs `file` with the private key `name` under `namespace`, leaving
/// `<file>.sig` beside it.
fn sign(dir: &Path, name: &str, namespace: &str, file: &Path) -> PathBuf {
    let output = ssh_keygen(&[
        "-Y",
        "sign",
        "-f",
        dir.join(name).to_str().expect("a UTF-8 scratch path"),
        "-n",
        namespace,
        file.to_str().expect("a UTF-8 scratch path"),
    ]);
    assert!(
        output.status.success(),
        "signing {} failed: {}",
        file.display(),
        stderr_of(&output)
    );
    let mut signature = file.as_os_str().to_owned();
    signature.push(".sig");
    PathBuf::from(signature)
}

/// Runs `--verify-signature` on `root`, with the trusted key replaced when one
/// is given.
fn verify_signature(root: &Path, signer: Option<&str>, sums: &Path, signature: &Path) -> Output {
    let mut command = deploy(root, &root.join("stubs"));
    command.arg("--verify-signature").arg(sums).arg(signature);
    if let Some(signer) = signer {
        command.env("VOLTO_DEPLOY_SIGNER", signer);
    }
    run_within_deadline(&mut command)
}

/// The key the script carries is the key that signs releases.
///
/// The fixture is a file signed on 2026-11-13 with the real release key, whose
/// private half no test can reach. Changing `RELEASE_SIGNER` to any other key
/// turns this red, which is the point: an edit to that line decides what every
/// host will install.
#[test]
fn the_embedded_key_accepts_a_signature_made_with_the_release_key() {
    let fixture = repo_root().join("tests/fixtures/release-signature");
    let output = verify_signature(
        &install_root("embedded-key"),
        None,
        &fixture.join("SHA256SUMS"),
        &fixture.join("SHA256SUMS.sig"),
    );

    assert!(
        output.status.success(),
        "the key in script/deploy.sh no longer verifies the fixture signed by \
         the release key: {}",
        stderr_of(&output)
    );
    assert!(stdout_of(&output).contains("signature verified"));
}

/// The four ways a signature can be wrong, each refused, beside the one way it
/// is right. Run through `--verify-signature`, which calls the function the
/// install path calls.
#[test]
fn a_signature_is_accepted_only_from_the_trusted_key_over_the_same_bytes() {
    let dir = scratch_tree("deploy", "signature", &[]);
    let trusted = generate_key(&dir, "trusted");
    generate_key(&dir, "stranger");

    let sums = dir.join("SHA256SUMS");
    fs::write(
        &sums,
        "0123abcd  volto-9.9.9-x86_64-unknown-linux-musl.tar.gz\n",
    )
    .unwrap();
    let signature = sign(&dir, "trusted", SIGN_NAMESPACE, &sums);

    let good = verify_signature(&dir, Some(&trusted), &sums, &signature);
    assert!(
        good.status.success(),
        "a signature by the trusted key over the same bytes must verify: {}",
        stderr_of(&good)
    );

    // The same signature over a list that names a different checksum.
    let tampered = dir.join("SHA256SUMS.tampered");
    fs::write(
        &tampered,
        "0123abce  volto-9.9.9-x86_64-unknown-linux-musl.tar.gz\n",
    )
    .unwrap();
    let output = verify_signature(&dir, Some(&trusted), &tampered, &signature);
    assert!(!output.status.success(), "a changed list must be refused");
    assert!(
        stderr_of(&output).contains("is not the release key's signature"),
        "the refusal must say what failed: {}",
        stderr_of(&output)
    );

    // A valid signature by a key the script does not trust.
    let by_stranger = dir.join("by-stranger");
    fs::copy(&sums, &by_stranger).unwrap();
    let stranger_signature = sign(&dir, "stranger", SIGN_NAMESPACE, &by_stranger);
    let output = verify_signature(&dir, Some(&trusted), &by_stranger, &stranger_signature);
    assert!(
        !output.status.success(),
        "a signature by another key must be refused"
    );

    // The trusted key's signature made for another purpose.
    let other_purpose = dir.join("other-purpose");
    fs::copy(&sums, &other_purpose).unwrap();
    let git_signature = sign(&dir, "trusted", "git", &other_purpose);
    let output = verify_signature(&dir, Some(&trusted), &other_purpose, &git_signature);
    assert!(
        !output.status.success(),
        "a signature under another namespace must be refused"
    );

    // No signature at all.
    let output = verify_signature(&dir, Some(&trusted), &sums, &dir.join("absent.sig"));
    assert!(
        !output.status.success(),
        "a missing signature must be refused"
    );

    // And the key the script carries does not accept the test key's signature,
    // so the override above is what made the first case pass.
    let output = verify_signature(&dir, None, &sums, &signature);
    assert!(
        !output.status.success(),
        "the embedded key accepted a signature made by a test key"
    );
}

/// A release directory as the download step leaves it, with the key that signs
/// it, for [`verify_release`].
struct Download {
    dir: Scratch,
    /// The public key the function under test is told to trust.
    trusted: String,
}

const ARCHIVE: &str = "volto-9.9.9-x86_64-unknown-linux-musl";

fn sha256_hex(path: &Path) -> String {
    let output = Command::new("shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
        .expect("shasum must be runnable");
    stdout_of(&output)
        .split_whitespace()
        .next()
        .expect("a digest")
        .to_owned()
}

/// Lays out an archive and a key pair. `sums` receives the archive's real
/// digest and returns the text of `SHA256SUMS`; `signer` names the key that
/// signs it, or `None` for a release without a signature.
fn download(name: &str, sums: impl Fn(&str) -> String, signer: Option<&str>) -> Download {
    let dir = scratch_tree("deploy", name, &["stubs"]);
    let trusted = generate_key(&dir, "trusted");
    generate_key(&dir, "stranger");

    let archive = dir.join(format!("{ARCHIVE}.tar.gz"));
    fs::write(&archive, b"the bytes of a release archive\n").unwrap();
    let list = dir.join("SHA256SUMS");
    fs::write(&list, sums(&sha256_hex(&archive))).unwrap();
    if let Some(signer) = signer {
        sign(&dir, signer, SIGN_NAMESPACE, &list);
    }

    // The script asks for `sha256sum`, which a macOS host does not always have.
    write_executable(
        &dir.join("stubs/sha256sum"),
        "#!/bin/sh\nexec shasum -a 256 \"$@\"\n",
    );
    Download { dir, trusted }
}

/// Runs the script's own `verify_release` over a [`Download`], with the
/// script's own `signature_is_valid` beside it. The last line of standard
/// output reports whether the function recorded a verified signature.
fn verify_release(download: &Download, allow_unsigned: bool) -> Output {
    let signature_is_valid = shell_function_body("script/deploy.sh", "signature_is_valid");
    let prelude = format!(
        "{signature_is_valid}\n}}\n\
         RELEASE_SIGNER='{}'\nSIGN_NAMESPACE={SIGN_NAMESPACE}\n\
         TMP='{}'\nNAME={ARCHIVE}\nTAG=v9.9.9\n\
         ALLOW_UNSIGNED={}\nRELEASE_IS_SIGNED=0\n\
         trap 'echo \"signed=$RELEASE_IS_SIGNED\"' EXIT",
        download.trusted,
        download.dir.display(),
        u8::from(allow_unsigned),
    );
    run_shell_function(
        "script/deploy.sh",
        "verify_release",
        &download.dir.join("stubs"),
        &prelude,
    )
}

/// The install path's verification, run as the script runs it: a signed list
/// that names the archive once, with the archive's digest, is accepted.
#[test]
fn a_signed_release_whose_archive_matches_its_list_is_accepted() {
    let download = download(
        "verify-good",
        |digest| {
            format!(
                "{digest}  {ARCHIVE}.tar.gz\n{}  volto-9.9.9-aarch64-unknown-linux-musl.tar.gz\n",
                "0".repeat(64)
            )
        },
        Some("trusted"),
    );
    let output = verify_release(&download, false);

    assert!(
        output.status.success(),
        "a correctly signed release must verify: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    assert!(stdout.contains("SHA256SUMS is signed by the release key"));
    assert!(stdout.contains("checksum verified against SHA256SUMS"));
    assert!(
        stdout.ends_with("signed=1\n"),
        "a verified signature must be recorded: {stdout}"
    );
}

/// A list signed by somebody else is refused, and so is a list with no
/// signature. With `--allow-unsigned` the unsigned one passes on its checksum
/// and is recorded as unsigned, which is what keeps the script from replacing
/// itself out of such a release.
#[test]
fn a_release_is_refused_without_the_release_keys_signature() {
    let honest = |digest: &str| format!("{digest}  {ARCHIVE}.tar.gz\n");

    let by_stranger = download("verify-stranger", honest, Some("stranger"));
    let output = verify_release(&by_stranger, false);
    assert!(
        !output.status.success(),
        "another key's signature must be refused"
    );
    assert!(
        stderr_of(&output).contains("is not signed by the release key"),
        "{}",
        stderr_of(&output)
    );
    // The flag covers a signature that is absent, never one that is wrong.
    let output = verify_release(&by_stranger, true);
    assert!(
        !output.status.success(),
        "--allow-unsigned must not excuse a signature that does not verify"
    );

    let unsigned = download("verify-unsigned", honest, None);
    let output = verify_release(&unsigned, false);
    assert!(
        !output.status.success(),
        "an unsigned release must be refused"
    );
    assert!(
        stderr_of(&output).contains("carries no SHA256SUMS.sig"),
        "{}",
        stderr_of(&output)
    );

    let output = verify_release(&unsigned, true);
    assert!(
        output.status.success(),
        "--allow-unsigned must let an unsigned release through on its checksum: {}",
        stderr_of(&output)
    );
    assert!(
        stdout_of(&output).ends_with("signed=0\n"),
        "an unsigned release must not be recorded as signed: {}",
        stdout_of(&output)
    );
}

/// The lists a checksum tool can be made to disagree about, each signed by the
/// release key and each refused.
///
/// Found by review on 2026-11-13: one `sha256sum` skips a line that starts with
/// a space or a backslash and reports success, while GNU's accepts it. A list
/// checked by the first when it was signed and read by the second on a host
/// could name an archive nobody checked. `verify_release` therefore reads the
/// list itself and refuses any line that is not exactly a digest, two spaces
/// and an archive name.
#[test]
fn a_signed_list_with_a_line_that_tools_read_differently_is_refused() {
    // `{D}` stands for the archive's real digest and `{A}` for its name.
    let cases = [
        ("leading-space", " {D}  {A}\n", "has a line that is not"),
        (
            "leading-backslash",
            "\\{D}  {A}\n",
            "has a line that is not",
        ),
        ("binary-marker", "{D} *{A}\n", "has a line that is not"),
        ("carriage-return", "{D}  {A}\r\n", "has a line that is not"),
        ("nul-byte", "{D}  {A}\n\0", "contains a NUL byte"),
        (
            "listed-twice",
            "{D}  {A}\nffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  {A}\n",
            "more than once",
        ),
        (
            "not-listed",
            "{D}  volto-9.9.9-other.tar.gz\n",
            "does not list",
        ),
    ];
    let archive = format!("{ARCHIVE}.tar.gz");

    for (name, template, refusal) in cases {
        let download = download(
            &format!("verify-{name}"),
            |digest| template.replace("{D}", digest).replace("{A}", &archive),
            Some("trusted"),
        );
        let output = verify_release(&download, false);
        assert!(
            !output.status.success(),
            "{name}: the list must be refused: {}",
            stdout_of(&output)
        );
        assert!(
            stderr_of(&output).contains(refusal),
            "{name}: the refusal must say `{refusal}`: {}",
            stderr_of(&output)
        );
    }
}

/// A signed list whose digest is not the archive's.
#[test]
fn an_archive_that_does_not_match_its_signed_digest_is_refused() {
    let download = download(
        "verify-mismatch",
        |_| format!("{}  {ARCHIVE}.tar.gz\n", "a".repeat(64)),
        Some("trusted"),
    );
    let output = verify_release(&download, false);

    assert!(!output.status.success(), "a wrong digest must be refused");
    assert!(
        stderr_of(&output).contains("checksum mismatch"),
        "{}",
        stderr_of(&output)
    );
}

/// The script sets the trusted key once, to a literal, and takes its own
/// replacement from a release only under a verified signature.
///
/// These are text checks because no run can reach them: a literal key is
/// tested only by a signature that the release key made, which a test cannot
/// make, and the replacement is taken only from a release signed by that key.
/// What a run can show is in
/// `the_install_path_trusts_only_its_own_key_and_verifies_before_it_unpacks`.
#[test]
fn the_trusted_key_is_a_literal_and_only_a_signed_release_replaces_the_script() {
    let text = fs::read_to_string(deploy_script()).expect("the deploy script must be readable");
    let code: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .collect();

    let assignments: Vec<&&str> = code
        .iter()
        .filter(|line| line.contains("RELEASE_SIGNER="))
        .collect();
    assert_eq!(
        assignments.len(),
        1,
        "RELEASE_SIGNER is assigned once: {assignments:?}"
    );
    assert!(
        assignments[0].starts_with("RELEASE_SIGNER='ssh-ed25519 ") && !assignments[0].contains('$'),
        "RELEASE_SIGNER is a literal key, not an expansion: {}",
        assignments[0]
    );

    // The installed copy of the script is replaced from the release in one
    // place, and only under a verified signature. A release from before signing
    // carries a script that verifies nothing.
    assert_eq!(
        code.iter()
            .filter(|line| line.contains("SELF_SOURCE="))
            .count(),
        2,
        "SELF_SOURCE is set in two places: from this script's own file, and from a signed release"
    );
    assert!(
        code.contains(&"SELF_SOURCE=\"${BASH_SOURCE[0]:-}\""),
        "the script's own file comes from BASH_SOURCE, which is empty on a piped run"
    );

    let takes: Vec<usize> = code
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == "SELF_SOURCE=\"$SRC/script/deploy.sh\"")
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        takes.len(),
        1,
        "the script takes its own replacement from the release in one place"
    );
    assert_eq!(
        code[takes[0] - 1],
        "if [ \"$RELEASE_IS_SIGNED\" -eq 1 ] && [ -f \"$SRC/script/deploy.sh\" ]; then",
        "the replacement must be conditional on a verified signature"
    );
}

/// `--allow-unsigned` is for the releases from before signing. Naming it for a
/// later one is refused before anything is downloaded, so removing a signature
/// from the release page does not turn a signed release into an installable
/// unsigned one.
#[test]
fn allowing_an_unsigned_release_is_refused_from_the_first_signed_version_on() {
    let root = install_root("allow-unsigned-range");

    let output = run_deploy(&root, &["--dry-run", "--tag", "v1.4.0", "--allow-unsigned"]);
    assert!(
        !output.status.success(),
        "--allow-unsigned must not apply to the first signed release"
    );
    assert!(
        stderr_of(&output).contains("--allow-unsigned applies to releases before 1.4.0"),
        "{}",
        stderr_of(&output)
    );

    // Fields compare as numbers, so 1.10.0 is not before 1.4.0.
    let output = run_deploy(
        &root,
        &["--dry-run", "--tag", "v1.10.0", "--allow-unsigned"],
    );
    assert!(
        !output.status.success(),
        "--allow-unsigned must not apply to 1.10.0"
    );

    let output = run_deploy(&root, &["--dry-run", "--tag", "v1.3.7", "--allow-unsigned"]);
    assert!(
        output.status.success(),
        "--allow-unsigned must apply to a release from before signing: {}",
        stderr_of(&output)
    );
}

/// Runs the script's `refuse_automatic_downgrade` with its own
/// `is_older_version`, for a run that did or did not look the release up.
fn automatic_downgrade(resolved: bool, release: &str, installed: &str) -> Output {
    let is_older_version = shell_function_body("script/deploy.sh", "is_older_version");
    let prelude = format!(
        "{is_older_version}\n}}\nTAG_WAS_RESOLVED={}\nTAG=v{release}\nVERSION={release}\nINSTALLED={installed}",
        u8::from(resolved)
    );
    run_shell_function(
        "script/deploy.sh",
        "refuse_automatic_downgrade",
        &scratch_tree("deploy", "downgrade-stubs", &[]),
        &prelude,
    )
}

/// The timer installs the release marked latest, and that mark can be moved to
/// an older release, which still carries a valid signature. A run that was not
/// told which release to install therefore never goes back; one that was told,
/// with `--tag`, does.
#[test]
fn a_run_that_looked_up_the_latest_release_never_goes_back() {
    let output = automatic_downgrade(true, "1.4.0", "1.4.1");
    assert!(
        !output.status.success(),
        "an older latest release must be refused"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("refusing to go back") && stderr.contains("--tag"),
        "the refusal must say how a rollback is done: {stderr}"
    );
    assert!(
        !stderr.contains("--tag v1.4.0"),
        "the refusal must not hand over the command for the release the page points at: {stderr}"
    );

    // Fields compare as numbers: 1.9.0 is older than 1.10.0.
    let output = automatic_downgrade(true, "1.9.0", "1.10.0");
    assert!(
        !output.status.success(),
        "1.10.0 to 1.9.0 is a downgrade and must be refused"
    );

    for (resolved, release, installed, what) in [
        (true, "1.4.1", "1.4.0", "an upgrade"),
        (
            true,
            "1.10.0",
            "1.9.0",
            "an upgrade across a two-digit field",
        ),
        (true, "1.4.0", "1.4.0", "the same version"),
        (true, "1.4.0", "", "a first install"),
        (false, "1.4.0", "1.4.1", "a rollback named with --tag"),
    ] {
        let output = automatic_downgrade(resolved, release, installed);
        assert!(
            output.status.success(),
            "{what} must not be refused: {}",
            stderr_of(&output)
        );
    }
}

/// `--verify-signature` is a mode of its own. An empty file name once fell
/// through to an ordinary run, which exited 0 having verified nothing.
#[test]
fn verifying_a_signature_with_an_empty_file_name_fails() {
    let output = run_deploy(
        &install_root("verify-empty-name"),
        &["--verify-signature", "", "x"],
    );

    assert!(
        !output.status.success(),
        "an empty file name must not be taken for no request: {}",
        stdout_of(&output)
    );
    assert!(stderr_of(&output).contains("no such file"));
}

/// The mode deploys nothing, so an option that asks for a deploy beside it is
/// refused instead of being dropped without a word.
#[test]
fn verifying_a_signature_takes_no_other_option() {
    let fixture = repo_root().join("tests/fixtures/release-signature");
    let sums = fixture.join("SHA256SUMS");
    let signature = fixture.join("SHA256SUMS.sig");
    let output = run_deploy(
        &install_root("verify-other-option"),
        &[
            "--verify-signature",
            sums.to_str().unwrap(),
            signature.to_str().unwrap(),
            "--tag",
            "v1.4.0",
        ],
    );

    assert!(
        !output.status.success(),
        "another option beside --verify-signature must be refused"
    );
    assert!(
        stderr_of(&output).contains("no other option"),
        "{}",
        stderr_of(&output)
    );
}

// ---------------------------------------------------------------------------
// The install path, end to end
// ---------------------------------------------------------------------------

/// The release the end-to-end runs install by name. It is from before signing,
/// so `--allow-unsigned` applies to it and no release key is needed.
const UNSIGNED_TAG: &str = "v1.3.7";

/// The version the planted install reports.
const INSTALLED_VERSION: &str = "1.3.6";

/// How the stand-in `systemctl` answers for the volto service.
#[derive(Clone, Copy)]
enum Service {
    /// `restart` succeeds and the service is active afterwards.
    ComesUp,
    /// `restart` fails, which ends the run inside the swap window.
    RestartFails,
    /// `restart` succeeds and the health check finds the service inactive.
    DiesAfterRestart,
    /// The first `daemon-reload` sends the named signal to the script, as a
    /// Ctrl-C, a dropped SSH session or a stop of the timer's service does,
    /// before the restart is issued. Everything else succeeds.
    InterruptedBeforeRestart(&'static str),
    /// Every `restart volto` sends the named signal to the script and then
    /// succeeds, as systemd finishes a restart job whose `systemctl` is gone.
    /// The rollback's own restart is signalled too.
    InterruptedDuringRestart(&'static str),
}

/// How the binary inside a published release answers `--check-config`.
///
/// Every candidate records the `RUST_LOG` its check ran with, or `<unset>`,
/// one line per check, in `logs/check-rust-log`.
#[derive(Clone, Copy)]
enum Candidate {
    LoadsTheConfig,
    RefusesTheConfig,
    /// Loads the config, and refuses `RUST_LOG=quinn=debug` with the real
    /// binary's message, as the real rule does (`it_cli` holds the real
    /// binary to that refusal).
    RefusesASilencingRustLog,
}

/// A host for a run of the real install path of `script/deploy.sh`.
///
/// `root` is `VOLTO_DEPLOY_ROOT`. `stubs` holds the commands that need root, a
/// Linux host, systemd or the network: `id` reports root, `uname` reports an
/// x86_64 Linux host, `sleep` returns at once, `sha256sum` runs `shasum`, and
/// `systemctl` and `curl` record their arguments in `logs`. `curl` serves the
/// files under `release/<tag>/` by the last two parts of the URL it is asked
/// for, and answers the latest-release lookup with the URL in `logs/latest`.
/// Everything else the script runs is the host's own: `install`, `tar`,
/// `mktemp`, `cmp`, `readlink`, `awk` and `bash`.
struct Host {
    /// Holds the tree the paths below are in.
    _base: Scratch,
    root: PathBuf,
    stubs: PathBuf,
    release: PathBuf,
    staging: PathBuf,
    logs: PathBuf,
    /// `TMPDIR` for the run, so a test can see what the run left behind.
    tmp: PathBuf,
}

impl Host {
    fn new(name: &str, service: Service) -> Host {
        let base = scratch_tree(
            "deploy",
            &format!("e2e-{name}"),
            &[
                "root/usr/local/bin",
                "root/usr/local/sbin",
                "root/etc/volto",
                "root/etc/systemd/system",
                "root/run",
                "stubs",
                "release",
                "staging",
                "logs",
                "tmp",
            ],
        );
        let host = Host {
            root: base.join("root"),
            stubs: base.join("stubs"),
            release: base.join("release"),
            staging: base.join("staging"),
            logs: base.join("logs"),
            tmp: base.join("tmp"),
            _base: base,
        };

        // `id -u volto` answers the uid in `logs/volto-uid`, or a uid no file
        // here belongs to, so the ownership migration finds nothing to move
        // unless a test asks for it.
        write_executable(
            &host.stubs.join("id"),
            &format!(
                "#!/bin/sh\n\
                 if [ \"$*\" = '-u volto' ]; then cat '{uid}' 2>/dev/null || echo 2147483646; exit 0; fi\n\
                 echo 0\n",
                uid = host.logs.join("volto-uid").display(),
            ),
        );
        write_executable(
            &host.stubs.join("chown"),
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n",
                host.logs.join("chown").display()
            ),
        );
        write_executable(
            &host.stubs.join("uname"),
            "#!/bin/sh\ncase \"$1\" in -m) echo x86_64 ;; *) echo Linux ;; esac\n",
        );
        write_executable(&host.stubs.join("sleep"), "#!/bin/sh\nexit 0\n");
        write_executable(
            &host.stubs.join("sha256sum"),
            "#!/bin/sh\nexec shasum -a 256 \"$@\"\n",
        );

        let (restart, active) = match service {
            Service::RestartFails => (1, 0),
            Service::DiesAfterRestart => (0, 1),
            Service::ComesUp
            | Service::InterruptedBeforeRestart(_)
            | Service::InterruptedDuringRestart(_) => (0, 0),
        };
        // The stand-in is run by the script's own shell, so `$PPID` is the
        // script.
        let interrupt = match service {
            Service::InterruptedBeforeRestart(signal) => format!(
                "[ \"$*\" = daemon-reload ] && [ ! -e '{marker}' ] && : > '{marker}' && kill -{signal} \"$PPID\"\n",
                marker = host.logs.join("interrupted").display(),
            ),
            Service::InterruptedDuringRestart(signal) => {
                format!("[ \"$*\" = 'restart volto' ] && kill -{signal} \"$PPID\"\n")
            }
            _ => String::new(),
        };
        // `show` is a query, recorded apart from the calls that act on the
        // service so that every sequence asserted below stays the sequence of
        // actions. It answers the unit's Environment= words from
        // `logs/unit-environment` and its EnvironmentFile= list from
        // `logs/unit-environment-files`, empty when the file is absent.
        write_executable(
            &host.stubs.join("systemctl"),
            &format!(
                "#!/bin/sh\n\
                 case \"$*\" in\n\
                 \x20 'show -p Environment --value volto') printf '%s\\n' \"$*\" >> '{shown}'; cat '{environment}' 2>/dev/null; exit 0 ;;\n\
                 \x20 'show -p EnvironmentFiles --value volto') printf '%s\\n' \"$*\" >> '{shown}'; cat '{files}' 2>/dev/null; exit 0 ;;\n\
                 esac\n\
                 printf '%s\\n' \"$*\" >> '{log}'\n\
                 {interrupt}\
                 case \"$*\" in\n\
                 \x20 'restart volto') exit {restart} ;;\n\
                 \x20 'is-active --quiet volto') exit {active} ;;\n\
                 \x20 'is-active volto') [ {active} -eq 0 ] && echo active || echo failed; exit {active} ;;\n\
                 esac\n\
                 exit 0\n",
                log = host.logs.join("systemctl").display(),
                shown = host.logs.join("systemctl-show").display(),
                environment = host.logs.join("unit-environment").display(),
                files = host.logs.join("unit-environment-files").display(),
            ),
        );
        write_executable(
            &host.stubs.join("curl"),
            &format!(
                "#!/bin/sh\n\
                 out= write= url=\n\
                 while [ $# -gt 0 ]; do\n\
                 \x20 case \"$1\" in\n\
                 \x20   -o) out=\"$2\"; shift 2 ;;\n\
                 \x20   -w) write=\"$2\"; shift 2 ;;\n\
                 \x20   --connect-timeout|--max-time|--retry|--retry-max-time) shift 2 ;;\n\
                 \x20   -*) shift ;;\n\
                 \x20   *) url=\"$1\"; shift ;;\n\
                 \x20 esac\n\
                 done\n\
                 printf '%s\\n' \"$url\" >> '{log}'\n\
                 if [ -n \"$write\" ]; then\n\
                 \x20 [ -f '{latest}' ] || exit 22\n\
                 \x20 cat '{latest}'\n\
                 \x20 exit 0\n\
                 fi\n\
                 tag=\"${{url%/*}}\"\n\
                 file='{release}'/\"${{tag##*/}}/${{url##*/}}\"\n\
                 [ -f \"$file\" ] || exit 22\n\
                 cp \"$file\" \"$out\"\n",
                log = host.logs.join("curl").display(),
                latest = host.logs.join("latest").display(),
                release = host.release.display(),
            ),
        );
        host
    }

    fn bin(&self) -> PathBuf {
        self.root.join("usr/local/bin/volto")
    }

    fn unit(&self) -> PathBuf {
        self.root.join("etc/systemd/system/volto.service")
    }

    fn installed_script(&self) -> PathBuf {
        self.root.join("usr/local/sbin/volto-deploy")
    }

    /// Plants an install of [`INSTALLED_VERSION`] with its config and unit.
    fn plant_install(&self) {
        plant_binary(&self.root, INSTALLED_VERSION);
        plant_config(&self.root);
        plant_unit(&self.root);
    }

    /// Publishes `tag` for x86_64 without a signature: the archive, with a
    /// binary that answers `--check-config` as `candidate` says, and the
    /// `SHA256SUMS` that lists it. Returns the binary's text.
    fn publish(&self, tag: &str, candidate: Candidate) -> String {
        self.publish_with_mode(tag, candidate, 0o755)
    }

    /// [`Host::publish`], with the binary in the archive at `mode`.
    fn publish_with_mode(&self, tag: &str, candidate: Candidate, mode: u32) -> String {
        let version = tag.trim_start_matches('v');
        let name = format!("volto-{version}-x86_64-unknown-linux-musl");
        let unpacked = self.staging.join(&name);
        fs::create_dir_all(unpacked.join("script")).expect("the staging tree must be creatable");

        let verdict = match candidate {
            Candidate::LoadsTheConfig => "echo \"$3 loads\"; exit 0".to_owned(),
            Candidate::RefusesTheConfig => {
                "echo \"error: failed to parse config file $3: unknown field\" >&2; exit 1"
                    .to_owned()
            }
            Candidate::RefusesASilencingRustLog => {
                "if [ \"${RUST_LOG-}\" = quinn=debug ]; then \
                 echo 'Error: RUST_LOG = \"quinn=debug\" turns off the log lines of this server' >&2; \
                 exit 1; fi; echo \"$3 loads\"; exit 0"
                    .to_owned()
            }
        };
        let verdict = format!(
            "printf '%s\\n' \"${{RUST_LOG-<unset>}}\" >> '{}'; {verdict}",
            self.logs.join("check-rust-log").display()
        );
        let binary = format!(
            "#!/bin/sh\n\
             # the binary inside the {tag} archive\n\
             case \"$1\" in\n\
             \x20 --version) echo \"volto {version}\" ;;\n\
             \x20 --help) echo '      --check-config  Load the configuration and exit' ;;\n\
             \x20 --check-config) {verdict} ;;\n\
             esac\n"
        );
        write_executable(&unpacked.join("volto"), &binary);
        fs::set_permissions(unpacked.join("volto"), fs::Permissions::from_mode(mode))
            .expect("the binary's mode must be settable");
        write_executable(
            &unpacked.join("script/deploy.sh"),
            "#!/bin/sh\n# the copy of deploy.sh inside the release archive\nexit 1\n",
        );
        fs::write(
            unpacked.join("script/masque.service"),
            "# the unit inside the release archive\n",
        )
        .expect("the unit must be writable");
        write_executable(
            &unpacked.join("script/install-selfsigned.sh"),
            &format!(
                "#!/bin/sh\nprintf 'VOLTO_INSTALL_ROOT=%s %s\\n' \"$VOLTO_INSTALL_ROOT\" \"$*\" >> '{}'\n\
                 printf '%s\\n' \"$PASSWORD\" >> '{}'\n",
                self.logs.join("installer").display(),
                self.logs.join("installer-password").display()
            ),
        );

        let published = self.release.join(tag);
        fs::create_dir_all(&published).expect("the release directory must be creatable");
        let archive = published.join(format!("{name}.tar.gz"));
        let tar = Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&self.staging)
            .arg(&name)
            // macOS tar would otherwise add AppleDouble entries for extended
            // attributes.
            .env("COPYFILE_DISABLE", "1")
            .output()
            .expect("tar must be runnable");
        assert!(tar.status.success(), "tar failed: {}", stderr_of(&tar));
        fs::write(
            published.join("SHA256SUMS"),
            format!("{}  {name}.tar.gz\n", sha256_hex(&archive)),
        )
        .expect("the checksum list must be writable");

        binary
    }

    /// Signs the published `SHA256SUMS` of `tag` with a key made for this host,
    /// and returns that key's public half.
    fn sign_release(&self, tag: &str) -> String {
        let signer = generate_key(&self.logs, "test-signer");
        sign(
            &self.logs,
            "test-signer",
            SIGN_NAMESPACE,
            &self.release.join(tag).join("SHA256SUMS"),
        );
        signer
    }

    /// Replaces `tar` with a stand-in that records its arguments in
    /// `logs/tar` and runs the host's own.
    fn record_tar(&self) {
        write_executable(
            &self.stubs.join("tar"),
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexec '{}' \"$@\"\n",
                self.logs.join("tar").display(),
                real_tool("tar").display()
            ),
        );
    }

    /// Makes the latest-release lookup answer `tag`.
    fn mark_latest(&self, tag: &str) {
        fs::write(
            self.logs.join("latest"),
            format!("https://github.com/example/volto/releases/tag/{tag}"),
        )
        .expect("the latest marker must be writable");
    }

    /// A run of `script/deploy.sh` on this host: [`deploy`] with the stubs,
    /// the release page's repository and the run's `TMPDIR`.
    fn command(&self) -> Command {
        let mut command = deploy(&self.root, &self.stubs);
        command
            .env("REPO", "example/volto")
            .env("TMPDIR", &self.tmp);
        command
    }

    /// Runs `script/deploy.sh` on this host with `args`.
    fn run(&self, args: &[&str]) -> Output {
        run_within_deadline(self.command().args(args))
    }

    /// Makes `systemctl show -p Environment --value volto` answer `words`.
    fn set_unit_environment(&self, words: &str) {
        fs::write(self.logs.join("unit-environment"), format!("{words}\n"))
            .expect("the unit's environment must be writable");
    }

    /// What one stub recorded, one call per line.
    fn calls(&self, stub: &str) -> String {
        fs::read_to_string(self.logs.join(stub)).unwrap_or_default()
    }

    /// Makes `id -u volto` answer `uid`.
    fn set_volto_uid(&self, uid: u32) {
        fs::write(self.logs.join("volto-uid"), format!("{uid}\n"))
            .expect("the uid answer must be writable");
    }
}

/// The permission bits of `path`, without following a final symbolic link.
fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .permissions()
        .mode()
        & 0o7777
}

/// A host on the layout releases before R8-M3 wrote moves to root ownership on
/// the next run of the script, and the run after that changes nothing.
///
/// In the old layout `/etc/volto` and its files belonged to the service user,
/// and root later wrote, renamed and chowned by name inside it, so a process
/// running as that user could point one of those names at a file of root's.
/// The run here is the no-op one (the installed version is the release), which
/// is what a timer run is on most days, so the migration cannot wait for an
/// update. The planted files belong to this test's own user, which `id -u
/// volto` is made to answer.
///
/// A symbolic link and a file with a second name elsewhere are left alone, and
/// the files they point at keep their mode: `chmod` follows a link. The
/// stand-in `chown` changes nothing on disk, so the second run makes `id -u
/// volto` answer another uid, which is what a real host looks like after the
/// first: nothing in the directory belongs to the service user any more.
#[test]
fn an_old_layout_moves_to_root_ownership_on_the_next_run_and_stays_there() {
    use std::os::unix::fs::MetadataExt as _;

    let host = Host::new("ownership", Service::ComesUp);
    host.plant_install();
    let dir = host.root.join("etc/volto");
    let outside = host.logs.join("outside");
    fs::create_dir_all(&outside).expect("the outside directory must be creatable");

    let files = [
        ("config.toml", 0o640),
        ("cert.pem", 0o644),
        ("key.pem", 0o640),
        ("ech.pem", 0o600),
    ];
    for (name, mode) in files {
        if name != "config.toml" {
            fs::write(dir.join(name), format!("{name}\n")).expect("plant the file");
        }
        fs::set_permissions(dir.join(name), fs::Permissions::from_mode(mode))
            .expect("set the old mode");
    }
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).expect("set the directory mode");

    let target = outside.join("shadow");
    fs::write(&target, "root's file\n").expect("plant the link target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
    std::os::unix::fs::symlink(&target, dir.join("evil.pem")).expect("plant the symbolic link");
    let linked = outside.join("linked");
    fs::write(&linked, "another name\n").expect("plant the hard link target");
    fs::set_permissions(&linked, fs::Permissions::from_mode(0o600)).expect("linked mode");
    fs::hard_link(&linked, dir.join("linked.pem")).expect("plant the hard link");

    host.set_volto_uid(fs::metadata(&dir).expect("the directory").uid());
    let output = host.run(&["--tag", "v1.3.6"]);

    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{}", stderr_of(&output));
    let mut calls: Vec<String> = host.calls("chown").lines().map(str::to_owned).collect();
    calls.sort();
    let mut expected: Vec<String> = files
        .iter()
        .map(|(name, _)| format!("-h root:volto {}", dir.join(name).display()))
        .chain([format!("root:volto {}", dir.display())])
        .collect();
    expected.sort();
    assert_eq!(
        calls, expected,
        "the directory and its four regular files move to root: {stdout}"
    );
    for (name, mode) in [
        ("config.toml", 0o640),
        ("cert.pem", 0o644),
        ("key.pem", 0o640),
        ("ech.pem", 0o640),
    ] {
        assert_eq!(
            mode_of(&dir.join(name)),
            mode,
            "{name}: the group must read it and nobody else write it"
        );
    }
    assert_eq!(mode_of(&dir), 0o750);
    assert_eq!(
        mode_of(&target),
        0o600,
        "a link's target must not be changed"
    );
    assert_eq!(
        mode_of(&linked),
        0o600,
        "a second name's file must not be changed"
    );
    assert_eq!(
        fs::read_to_string(dir.join("config.toml")).ok().as_deref(),
        Some("# planted\n"),
        "the configuration must be kept"
    );
    assert!(
        stdout.contains("moved") && stdout.contains("evil.pem") && stdout.contains("linked.pem"),
        "the run must say what it moved and name what it left: {stdout}"
    );

    host.set_volto_uid(2_147_483_646);
    let output = host.run(&["--tag", "v1.3.6"]);
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(
        host.calls("chown").lines().count(),
        expected.len(),
        "a second run must move nothing: {}",
        host.calls("chown")
    );
    assert!(
        !stdout_of(&output).contains("moved"),
        "{}",
        stdout_of(&output)
    );
}

/// The end-to-end harness reaches the end of an update, and an unsigned
/// release leaves the installed copy of this script as it was.
///
/// A release from before signing carries a copy of `deploy.sh` that verifies
/// nothing. Installing that copy as the one the timer runs would end signature
/// checking on this host for every later run. The decision rests on
/// `RELEASE_IS_SIGNED`, which only a verified signature sets, so its default
/// is what this run reads.
#[test]
fn an_unsigned_release_does_not_replace_the_installed_script() {
    let host = Host::new("unsigned", Service::ComesUp);
    host.plant_install();
    let candidate = host.publish(UNSIGNED_TAG, Candidate::LoadsTheConfig);
    let script = fs::read_to_string(deploy_script()).expect("the deploy script must be readable");
    fs::write(host.installed_script(), &script).expect("the installed copy must be writable");

    let output = host.run(&["--allow-unsigned", "--tag", UNSIGNED_TAG, "--enable-timer"]);

    assert!(
        output.status.success(),
        "an unsigned release named with --allow-unsigned must install: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    assert_eq!(
        fs::read_to_string(host.installed_script()).ok(),
        Some(script),
        "the installed copy of the script must stay the script under test, not \
         the copy inside the unsigned archive: {stdout}"
    );
    assert!(
        stdout.contains("keeping this script as it is"),
        "the run must say it kept its own copy: {stdout}"
    );

    // The rest of the update happened, so the run above went through the
    // download, the swap and the timer rather than stopping early.
    assert_eq!(
        fs::read_to_string(host.bin()).ok(),
        Some(candidate),
        "the release's binary must be installed: {stdout}"
    );
    assert_eq!(
        fs::read_to_string(host.unit()).ok().as_deref(),
        Some("# the unit inside the release archive\n"),
        "the release's unit must be installed: {stdout}"
    );
    let calls = host.calls("systemctl");
    assert!(
        calls.starts_with("daemon-reload\nrestart volto\nis-active --quiet volto\n")
            && calls.contains("enable --now volto-deploy.timer\n"),
        "systemctl must see the update and the timer: {calls}"
    );
}

/// The install path trusts the key the script carries, and verifies the
/// download before it unpacks it.
///
/// `VOLTO_DEPLOY_SIGNER` names the key that really signed this release, and the
/// run is refused all the same: the variable replaces the key for
/// `--verify-signature` alone. A release whose archive does not match its
/// listed digest is refused too. In neither run is the archive unpacked.
#[test]
fn the_install_path_trusts_only_its_own_key_and_verifies_before_it_unpacks() {
    let host = Host::new("environment-signer", Service::ComesUp);
    host.plant_install();
    host.publish("v1.4.0", Candidate::LoadsTheConfig);
    let signer = host.sign_release("v1.4.0");
    host.record_tar();

    let output = run_within_deadline(
        host.command()
            .args(["--tag", "v1.4.0"])
            .env("VOLTO_DEPLOY_SIGNER", &signer),
    );

    let stderr = stderr_of(&output);
    assert!(
        !output.status.success()
            && stderr.contains("SHA256SUMS in v1.4.0 is not signed by the release key"),
        "the install path must not trust the key in VOLTO_DEPLOY_SIGNER: {stderr}"
    );
    assert_eq!(host.calls("tar"), "", "nothing may be unpacked: {stderr}");

    let host = Host::new("wrong-digest", Service::ComesUp);
    host.plant_install();
    host.publish(UNSIGNED_TAG, Candidate::LoadsTheConfig);
    let sums = host.release.join(UNSIGNED_TAG).join("SHA256SUMS");
    let listed = fs::read_to_string(&sums).expect("the published list");
    fs::write(&sums, format!("{}{}", "0".repeat(64), &listed[64..])).expect("a wrong digest");
    host.record_tar();

    let output = host.run(&["--allow-unsigned", "--tag", UNSIGNED_TAG]);

    let stderr = stderr_of(&output);
    assert!(
        !output.status.success() && stderr.contains("checksum mismatch"),
        "an archive that does not match its digest must be refused: {stderr}"
    );
    assert_eq!(host.calls("tar"), "", "nothing may be unpacked: {stderr}");
    assert_eq!(
        fs::read_to_string(host.bin()).ok().as_deref(),
        Some("#!/bin/sh\necho \"volto 1.3.6\"\n")
    );
}

/// A failure inside the swap window puts the previous binary and unit back,
/// reloads systemd and starts the service.
///
/// `put_back start` is armed as an ERR trap once both `.prev` copies exist.
/// Here the restart fails after the new binary and unit are in place, which
/// leaves the old files as the only ones that can serve. Without the trap,
/// `set -e` ends the run with the new files installed and the service down.
///
/// `start` does nothing to an active unit and starts an inactive one, so after
/// a failure before the restart the old process keeps its tunnels, where a
/// `restart` would drop them. `daemon-reload` comes first, or systemd starts
/// the service under the unit it parsed last, the one being rolled back. The
/// files are read back, so a copy in the wrong direction is caught.
#[test]
fn a_failure_inside_the_swap_window_restores_both_files() {
    let host = Host::new("swap-window", Service::RestartFails);
    host.plant_install();
    host.publish(UNSIGNED_TAG, Candidate::LoadsTheConfig);
    let previous_binary =
        fs::read_to_string(host.bin()).expect("the planted binary must be readable");
    let previous_unit = fs::read_to_string(host.unit()).expect("the planted unit must be readable");

    let output = host.run(&["--allow-unsigned", "--tag", UNSIGNED_TAG]);

    let stderr = stderr_of(&output);
    assert!(
        !output.status.success(),
        "a failed restart must fail the run: {}",
        stdout_of(&output)
    );
    assert_eq!(
        fs::read_to_string(host.bin()).ok(),
        Some(previous_binary),
        "the previous binary must be back in place: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(host.unit()).ok(),
        Some(previous_unit),
        "the previous unit must be back in place: {stderr}"
    );
    assert_eq!(
        host.calls("systemctl"),
        "daemon-reload\nrestart volto\ndaemon-reload\nstart volto\n",
        "after the failed restart, systemd must be reloaded and the service \
         started, not restarted: {stderr}"
    );
    assert!(
        stderr.contains("installing volto 1.3.7 failed; restored the previous binary and unit"),
        "the run must say what it restored: {stderr}"
    );
}

/// A release that is not running three seconds after its restart is rolled
/// back: the previous binary and unit go back, systemd reloads, and the
/// service restarts on them.
///
/// This is the branch after the health check, where the ERR trap is not what
/// acts: `systemctl is-active` is the condition of an `if`, so its failure
/// fires no trap.
#[test]
fn a_release_that_does_not_stay_up_is_rolled_back() {
    let host = Host::new("health-check", Service::DiesAfterRestart);
    host.plant_install();
    host.publish(UNSIGNED_TAG, Candidate::LoadsTheConfig);
    let previous_binary =
        fs::read_to_string(host.bin()).expect("the planted binary must be readable");
    let previous_unit = fs::read_to_string(host.unit()).expect("the planted unit must be readable");

    let output = host.run(&["--allow-unsigned", "--tag", UNSIGNED_TAG]);

    let stderr = stderr_of(&output);
    assert!(
        !output.status.success(),
        "a release that does not stay up must fail the run: {}",
        stdout_of(&output)
    );
    assert_eq!(
        fs::read_to_string(host.bin()).ok(),
        Some(previous_binary),
        "the previous binary must be back in place: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(host.unit()).ok(),
        Some(previous_unit),
        "the previous unit must be back in place: {stderr}"
    );
    assert_eq!(
        host.calls("systemctl"),
        "daemon-reload\nrestart volto\nis-active --quiet volto\ndaemon-reload\nrestart volto\n",
        "the rollback must reload systemd before it restarts the service: {stderr}"
    );
    assert!(
        stderr.contains("volto 1.3.7 failed to start; rolled the binary and unit back to 1.3.6"),
        "the run must say what it rolled back and to which version: {stderr}"
    );
}

/// A signal inside the swap window rolls the update back as a failure there
/// does, and the run still ends through its cleanup (S9-M1).
///
/// A Ctrl-C under `sudo volto-deploy`, the SIGHUP that sudo relays when an SSH
/// session drops, and the SIGTERM that systemd sends when it stops the timer's
/// service all reach the script. With the rollback armed on ERR alone, a signal
/// after the binary was moved ended the run through the EXIT trap, which
/// restores nothing, and left the new release installed with no health check.
///
/// Before the restart is issued the old process still serves, so the rollback
/// starts the service, which leaves an active unit alone. Once the restart is
/// issued, systemd finishes it without the script, and the process it brings up
/// may be the new release, so the rollback restarts the service on the restored
/// files. The stand-in signals the rollback's own restart as well, and the
/// rollback must finish all the same. The exit status is the rollback's own,
/// not a death by the signal, and `TMPDIR` is empty afterwards, so the EXIT
/// trap ran.
#[test]
fn a_signal_inside_the_swap_window_rolls_the_update_back() {
    const BEFORE: &str = "daemon-reload\ndaemon-reload\nstart volto\n";
    const DURING: &str = "daemon-reload\nrestart volto\ndaemon-reload\nrestart volto\n";
    for (n, (service, expected)) in [
        (Service::InterruptedBeforeRestart("TERM"), BEFORE),
        (Service::InterruptedBeforeRestart("INT"), BEFORE),
        (Service::InterruptedDuringRestart("TERM"), DURING),
        (Service::InterruptedDuringRestart("INT"), DURING),
        (Service::InterruptedDuringRestart("HUP"), DURING),
    ]
    .into_iter()
    .enumerate()
    {
        let host = Host::new(&format!("interrupted-{n}"), service);
        host.plant_install();
        host.publish(UNSIGNED_TAG, Candidate::LoadsTheConfig);
        let previous_binary =
            fs::read_to_string(host.bin()).expect("the planted binary must be readable");
        let previous_unit =
            fs::read_to_string(host.unit()).expect("the planted unit must be readable");

        let output = host.run(&["--allow-unsigned", "--tag", UNSIGNED_TAG]);

        let stderr = stderr_of(&output);
        assert_eq!(
            output.status.code(),
            Some(1),
            "case {n}: the run must end through the rollback with status 1: {stderr}"
        );
        assert_eq!(
            fs::read_to_string(host.bin()).ok(),
            Some(previous_binary),
            "case {n}: the previous binary must be back in place: {stderr}"
        );
        assert_eq!(
            fs::read_to_string(host.unit()).ok(),
            Some(previous_unit),
            "case {n}: the previous unit must be back in place: {stderr}"
        );
        assert_eq!(
            host.calls("systemctl"),
            expected,
            "case {n}: the rollback must reload systemd and then start or restart: {stderr}"
        );
        assert!(
            stderr.contains(
                "the run was interrupted while installing volto 1.3.7; restored the previous binary and unit"
            ),
            "case {n}: the run must say it was interrupted and what it restored: {stderr}"
        );
        let left: Vec<_> = fs::read_dir(&host.tmp)
            .expect("the run's TMPDIR must be readable")
            .collect();
        assert!(
            left.is_empty(),
            "case {n}: the EXIT trap must remove the download directory: {left:?}"
        );
    }
}

/// The real update path asks the downloaded binary whether it can load this
/// host's config, and a "no" stops the run before anything on the host moves.
///
/// The dry-run tests above reach the same check through the dry run's own call
/// of `check_config_with`. This is the call the real path makes after the
/// archive is unpacked and before the `.prev` copies, which is the D93 guard
/// against a downgrade that cannot read the config it inherits.
#[test]
fn the_real_update_path_refuses_a_release_that_cannot_load_the_config() {
    let host = Host::new("config-check", Service::ComesUp);
    host.plant_install();
    host.publish(UNSIGNED_TAG, Candidate::RefusesTheConfig);
    let previous_binary =
        fs::read_to_string(host.bin()).expect("the planted binary must be readable");
    let previous_unit = fs::read_to_string(host.unit()).expect("the planted unit must be readable");

    let output = host.run(&["--allow-unsigned", "--tag", UNSIGNED_TAG]);

    let stderr = stderr_of(&output);
    assert!(
        !output.status.success(),
        "a release that cannot load the config must not be installed: {}",
        stdout_of(&output)
    );
    assert!(
        stderr.contains("refusing to install volto 1.3.7 over a config it cannot load")
            && stderr.contains("unknown field"),
        "the run must pass on the release's own refusal and say what it did: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(host.bin()).ok(),
        Some(previous_binary),
        "the installed binary must be untouched: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(host.unit()).ok(),
        Some(previous_unit),
        "the installed unit must be untouched: {stderr}"
    );
    assert!(
        !host.root.join("usr/local/bin/volto.prev").exists(),
        "the refusal must come before the previous binary is copied aside: {stderr}"
    );
    assert_eq!(
        host.calls("systemctl"),
        "",
        "the running service must be left alone: {stderr}"
    );
}

/// The update check runs with the `RUST_LOG` the service unit sets, so a value
/// the new release refuses at startup stops the update before the swap, with
/// the old binary still running (F3-M2).
///
/// Without it the check ran in the script's own environment, passed, and the
/// new binary was swapped in, refused to start, and was rolled back, on every
/// timer run. The unit's value reaches the check from `Environment=` and from
/// an `EnvironmentFile=`, whose assignment overrides `Environment=` as
/// systemd's does.
#[test]
fn a_unit_rust_log_the_release_refuses_stops_the_update_before_the_swap() {
    for (name, environment, file) in [
        (
            "rust-log-refused",
            "LANG=C.UTF-8 RUST_LOG=quinn=debug",
            None,
        ),
        (
            "rust-log-file-refused",
            "RUST_LOG=info",
            Some("# set for a QUIC investigation\nRUST_LOG=\"quinn=debug\"\n"),
        ),
    ] {
        let host = Host::new(name, Service::ComesUp);
        host.plant_install();
        host.publish(UNSIGNED_TAG, Candidate::RefusesASilencingRustLog);
        host.set_unit_environment(environment);
        if let Some(text) = file {
            let path = host.logs.join("volto.env");
            fs::write(&path, text).expect("the environment file must be writable");
            fs::write(
                host.logs.join("unit-environment-files"),
                format!("{} (ignore_errors=no)\n", path.display()),
            )
            .expect("the file list must be writable");
        }
        let previous_binary =
            fs::read_to_string(host.bin()).expect("the planted binary must be readable");
        let previous_unit =
            fs::read_to_string(host.unit()).expect("the planted unit must be readable");

        let output = host.run(&["--allow-unsigned", "--tag", UNSIGNED_TAG]);

        let stderr = stderr_of(&output);
        assert!(
            !output.status.success(),
            "{name}: a RUST_LOG the release refuses must stop the update: {}",
            stdout_of(&output)
        );
        assert!(
            stderr.contains("refusing to install volto 1.3.7 over a config it cannot load")
                && stderr.contains("RUST_LOG = \"quinn=debug\"")
                && stderr.contains("the volto unit's RUST_LOG=quinn=debug"),
            "{name}: the run must pass on the refusal and name the unit's value: {stderr}"
        );
        assert_eq!(
            host.calls("check-rust-log"),
            "quinn=debug\n",
            "{name}: the check must run with the unit's RUST_LOG"
        );
        assert_eq!(
            fs::read_to_string(host.bin()).ok(),
            Some(previous_binary),
            "{name}: the installed binary must be untouched: {stderr}"
        );
        assert_eq!(
            fs::read_to_string(host.unit()).ok(),
            Some(previous_unit),
            "{name}: the installed unit must be untouched: {stderr}"
        );
        assert!(
            !host.root.join("usr/local/bin/volto.prev").exists(),
            "{name}: the refusal must come before the previous binary is copied aside"
        );
        assert_eq!(
            host.calls("systemctl"),
            "",
            "{name}: the running service must be left alone: {stderr}"
        );
    }
}

/// A unit `RUST_LOG` the release accepts, or none, lets the update go on, and
/// the check sees the unit's value and never the script's own: the shell that
/// runs the script here sets the refused `RUST_LOG=quinn=debug`. A value
/// systemd had to quote is not read; the check then runs without it and the
/// run says so.
#[test]
fn a_unit_rust_log_the_release_accepts_or_none_lets_the_update_proceed() {
    for (name, environment, checked) in [
        (
            "rust-log-accepted",
            "RUST_LOG=info,quinn=debug",
            "info,quinn=debug",
        ),
        ("rust-log-absent", "", "<unset>"),
        ("rust-log-other", "LANG=C.UTF-8 TZ=UTC", "<unset>"),
        (
            "rust-log-quoted",
            "\"RUST_LOG=info quinn=debug\" LANG=C.UTF-8",
            "<unset>",
        ),
    ] {
        let host = Host::new(name, Service::ComesUp);
        host.plant_install();
        let candidate = host.publish(UNSIGNED_TAG, Candidate::RefusesASilencingRustLog);
        host.set_unit_environment(environment);

        // The script's own environment sets the value the release refuses, as
        // an operator's shell may.
        let output = run_within_deadline(
            host.command()
                .args(["--allow-unsigned", "--tag", UNSIGNED_TAG])
                .env("RUST_LOG", "quinn=debug"),
        );

        let stdout = stdout_of(&output);
        assert!(
            output.status.success(),
            "{name}: the update must go on: {stdout}{}",
            stderr_of(&output)
        );
        assert_eq!(
            host.calls("check-rust-log"),
            format!("{checked}\n"),
            "{name}: the check must run with the unit's RUST_LOG, not the script's"
        );
        assert_eq!(
            fs::read_to_string(host.bin()).ok(),
            Some(candidate),
            "{name}: the release's binary must be installed: {stdout}"
        );
        assert_eq!(
            stdout.contains("the volto unit's RUST_LOG was not checked"),
            name == "rust-log-quoted",
            "{name}: only a value that cannot be read is reported as not checked: {stdout}"
        );
    }
}

/// A host with no config takes the first-install path on the real run, even
/// with a binary in place: the config is what says an install exists. The
/// bundled installer is run with the release's binary, the relocated root and
/// the first-install arguments, and the update path's swap never happens.
#[test]
fn a_host_without_a_config_runs_the_bundled_installer() {
    let host = Host::new("first-install", Service::ComesUp);
    plant_binary(&host.root, INSTALLED_VERSION);
    plant_unit(&host.root);
    host.publish(UNSIGNED_TAG, Candidate::LoadsTheConfig);
    let previous_binary =
        fs::read_to_string(host.bin()).expect("the planted binary must be readable");

    let output = host.run(&[
        "--allow-unsigned",
        "--tag",
        UNSIGNED_TAG,
        "--sni",
        "volto.test",
    ]);

    let stderr = stderr_of(&output);
    assert!(
        output.status.success(),
        "a first install whose service comes up must succeed: {stderr}"
    );
    let installer = host.calls("installer");
    let expected_start = format!("VOLTO_INSTALL_ROOT={} --binary ", host.root.display());
    assert!(
        installer.starts_with(&expected_start)
            && installer
                .ends_with("/volto-1.3.7-x86_64-unknown-linux-musl/volto --sni volto.test\n")
            && installer.lines().count() == 1,
        "the bundled installer must run once, under the relocated root, with the \
         release's binary and the first-install arguments: {installer:?}\n{stderr}"
    );
    assert_eq!(
        fs::read_to_string(host.bin()).ok(),
        Some(previous_binary),
        "the update path's swap must not have run: {stderr}"
    );
    let calls = host.calls("systemctl");
    assert!(
        calls.starts_with("is-active --quiet volto\n") && !calls.contains("restart"),
        "the first install must check the service once and restart nothing: {calls}"
    );
}

/// A `.prev` left by an earlier update is never restored as if it were the
/// release this run replaced (R8-L5).
///
/// `.prev` was written only for a file that was there to copy, so on a host
/// with a deleted unit, or no executable binary, an older run's copy stayed and
/// both rollback paths restored it: the host went back past the release it was
/// running, and the run said it had rolled back to the previous release.
#[test]
fn a_stale_prev_from_an_earlier_update_is_never_restored() {
    // The unit was deleted; the ERR path restores the binary only.
    let host = Host::new("stale-unit-prev", Service::RestartFails);
    plant_binary(&host.root, INSTALLED_VERSION);
    plant_config(&host.root);
    fs::write(
        host.root.join("etc/systemd/system/volto.service.prev"),
        "a stale unit\n",
    )
    .expect("plant the stale unit");
    host.publish(UNSIGNED_TAG, Candidate::LoadsTheConfig);

    let output = host.run(&["--allow-unsigned", "--tag", UNSIGNED_TAG]);

    let stderr = stderr_of(&output);
    assert!(!output.status.success(), "{}", stdout_of(&output));
    assert_ne!(
        fs::read_to_string(host.unit()).ok().as_deref(),
        Some("a stale unit\n"),
        "the stale unit must not be restored: {stderr}"
    );
    assert!(
        stderr.contains("installing volto 1.3.7 failed; restored the previous binary --"),
        "the run must say it restored the binary alone: {stderr}"
    );

    // No executable binary; the health check finds nothing to roll back to.
    let host = Host::new("stale-binary-prev", Service::DiesAfterRestart);
    plant_config(&host.root);
    plant_unit(&host.root);
    write_executable(
        &host.root.join("usr/local/bin/volto.prev"),
        "#!/bin/sh\necho 'volto 1.0.0'\n",
    );
    let candidate = host.publish(UNSIGNED_TAG, Candidate::LoadsTheConfig);

    let output = host.run(&["--allow-unsigned", "--tag", UNSIGNED_TAG]);

    let stderr = stderr_of(&output);
    assert!(!output.status.success(), "{}", stdout_of(&output));
    assert_eq!(
        fs::read_to_string(host.bin()).ok(),
        Some(candidate),
        "the stale binary must not be restored: {stderr}"
    );
    assert!(
        stderr.contains(
            "volto 1.3.7 failed to start and there is no previous binary to roll back to"
        ),
        "{stderr}"
    );
}

/// The binary, the unit and the two timer units are replaced by a rename, on
/// the update and on the rollback, so no name ever holds a partial copy.
///
/// `install` writes under the name it is given. Over `/usr/local/bin/volto`
/// that would leave the name missing or partial until it finished, which a
/// restart under `Restart=on-failure` in that moment would execute. A unit
/// written straight to its name by a full `/etc` or a crash in mid-write would
/// be parsed truncated at `daemon-reload`. The stand-in `install` and `mv`
/// record their arguments and run the host's own.
#[test]
fn the_binary_the_unit_and_the_timer_units_are_replaced_by_a_rename() {
    let (real_install, real_mv) = (real_tool("install"), real_tool("mv"));

    for (name, service, args) in [
        (
            "atomic-units",
            Service::ComesUp,
            &["--allow-unsigned", "--tag", UNSIGNED_TAG, "--enable-timer"][..],
        ),
        (
            "atomic-unit-rollback",
            Service::DiesAfterRestart,
            &["--allow-unsigned", "--tag", UNSIGNED_TAG][..],
        ),
    ] {
        let host = Host::new(name, service);
        host.plant_install();
        let candidate = host.publish(UNSIGNED_TAG, Candidate::LoadsTheConfig);
        let previous_unit = fs::read_to_string(host.unit()).expect("the planted unit");
        for (tool, path) in [("install", &real_install), ("mv", &real_mv)] {
            write_executable(
                &host.stubs.join(tool),
                &format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexec '{}' \"$@\"\n",
                    host.logs.join(tool).display(),
                    path.display(),
                ),
            );
        }

        let output = host.run(args);

        let stderr = stderr_of(&output);
        let (installs, moves) = (host.calls("install"), host.calls("mv"));
        let (bin, unit) = (
            host.bin().display().to_string(),
            host.unit().display().to_string(),
        );
        for path in [&bin, &unit] {
            assert!(
                installs
                    .lines()
                    .all(|line| !line.ends_with(&format!(" {path}"))),
                "{name}: nothing may be installed straight over {path}: {installs}"
            );
        }
        // The rollback renames the binary and the unit a second time, back to
        // the previous ones.
        let rollback = name == "atomic-unit-rollback";
        let times = if rollback { 2 } else { 1 };
        let mut renamed = vec![(bin, times), (unit, times)];
        if !rollback {
            assert!(output.status.success(), "{name}: {stderr}");
            assert_eq!(fs::read_to_string(host.bin()).ok(), Some(candidate));
            assert_eq!(
                fs::read_to_string(host.unit()).ok().as_deref(),
                Some("# the unit inside the release archive\n"),
                "{name}: the release's unit must be installed: {stderr}"
            );
            for timer in ["volto-deploy.service", "volto-deploy.timer"] {
                let path = host.root.join("etc/systemd/system").join(timer);
                let text = fs::read_to_string(&path).unwrap_or_default();
                assert!(
                    text.starts_with("[Unit]\n") && mode_of(&path) == 0o644,
                    "{name}: {timer} must be written whole, mode 0644: {text}"
                );
                renamed.push((path.display().to_string(), 1));
            }
        } else {
            assert!(!output.status.success(), "{name}: {}", stdout_of(&output));
            assert_eq!(
                fs::read_to_string(host.unit()).ok(),
                Some(previous_unit),
                "{name}: the previous unit must be back in place: {stderr}"
            );
        }
        for (path, times) in renamed {
            let rename = format!("-f {path}.new {path}");
            assert_eq!(
                moves.lines().filter(|line| *line == rename).count(),
                times,
                "{name}: {path} must be written beside itself and renamed over: {moves}"
            );
        }
    }
}

/// A work directory on a `noexec` filesystem is named as the cause, before
/// anything is downloaded (R8-L4).
///
/// Linux reports a file on such a mount as not executable, so `[ -x ]` on the
/// unpacked binary failed and the run said the archive held no binary, every
/// day, on a host whose `/tmp` follows a common hardening benchmark. The
/// stand-in `findmnt` reports the mount the way util-linux prints it.
#[test]
fn a_noexec_work_directory_is_named_as_the_cause() {
    let host = Host::new("noexec", Service::ComesUp);
    host.plant_install();
    host.publish(UNSIGNED_TAG, Candidate::LoadsTheConfig);
    write_executable(
        &host.stubs.join("findmnt"),
        "#!/bin/sh
echo rw,nosuid,nodev,noexec,relatime
",
    );

    let output = host.run(&["--allow-unsigned", "--tag", UNSIGNED_TAG]);

    let stderr = stderr_of(&output);
    assert!(!output.status.success(), "{}", stdout_of(&output));
    assert!(
        stderr.contains("is on a filesystem mounted noexec") && stderr.contains("TMPDIR"),
        "the run must name the mount and the way out: {stderr}"
    );
    assert_eq!(host.calls("curl"), "", "nothing may be downloaded first");
    assert_eq!(
        host.calls("systemctl"),
        "",
        "the service must be left alone"
    );
}

/// A binary that is in the archive and cannot be executed is not reported as
/// missing (R8-L4).
#[test]
fn an_unexecutable_binary_is_not_reported_as_missing() {
    let host = Host::new("unexecutable", Service::ComesUp);
    host.plant_install();
    host.publish_with_mode(UNSIGNED_TAG, Candidate::LoadsTheConfig, 0o644);

    let output = host.run(&["--allow-unsigned", "--tag", UNSIGNED_TAG]);

    let stderr = stderr_of(&output);
    assert!(!output.status.success(), "{}", stdout_of(&output));
    assert!(
        !stderr.contains("did not contain a volto binary")
            && stderr.contains("cannot be executed where it was unpacked")
            && stderr.contains("noexec"),
        "the run must give both possible causes: {stderr}"
    );
    assert_eq!(
        host.calls("systemctl"),
        "",
        "the service must be left alone"
    );
}

/// A run that finds the lock held stops before it does anything (R8-L6).
///
/// systemd starts no second `volto-deploy.service`, but `sudo volto-deploy`
/// runs outside that service, and two runs inside the same few seconds copied
/// each other's new binary into `.prev`.
#[test]
fn a_run_stops_when_another_run_holds_the_lock() {
    let host = Host::new("lock-held", Service::ComesUp);
    host.plant_install();
    host.publish(UNSIGNED_TAG, Candidate::LoadsTheConfig);
    write_executable(&host.stubs.join("flock"), "#!/bin/sh\nexit 1\n");

    let output = host.run(&["--allow-unsigned", "--tag", UNSIGNED_TAG]);

    let stderr = stderr_of(&output);
    assert!(!output.status.success(), "{}", stdout_of(&output));
    assert!(
        stderr.contains("another run of this script holds"),
        "the refusal must say why: {stderr}"
    );
    assert_eq!(host.calls("curl"), "", "nothing may be downloaded");
    assert_eq!(
        host.calls("systemctl"),
        "",
        "the service must be left alone"
    );
    assert_eq!(
        fs::read_to_string(host.bin()).ok(),
        Some(format!("#!/bin/sh\necho \"volto {INSTALLED_VERSION}\"\n")),
        "the binary must be left alone"
    );

    // The same run with the lock free goes ahead.
    write_executable(&host.stubs.join("flock"), "#!/bin/sh\nexit 0\n");
    let output = host.run(&["--allow-unsigned", "--tag", UNSIGNED_TAG]);
    assert!(output.status.success(), "{}", stderr_of(&output));
}

/// Where `flock` is missing, a directory holding the pid of the run that made
/// it is the lock, and a directory whose run is gone is taken over.
///
/// The function runs with a `PATH` of its own that has no `flock`, which is the
/// only way to reach this branch on a host that has one.
#[test]
fn without_flock_a_directory_with_a_live_pid_is_the_lock() {
    let dir = scratch_tree("deploy", "lock-fallback", &["tools", "run"]);
    let tools = dir.join("tools");
    for tool in ["mkdir", "cat", "rm"] {
        std::os::unix::fs::symlink(real_tool(tool), tools.join(tool)).expect("link the tool");
    }
    let lock = dir.join("run/volto-deploy.lock");
    let held = dir.join("run/volto-deploy.lock.d");
    let acquire = |name: &str| {
        let output = run_shell_call(
            "script/deploy.sh",
            "acquire_lock",
            "&& echo \"took $LOCK_DIR\"",
            tools.as_os_str(),
            &format!("LOCK='{}'\nLOCK_DIR=", lock.display()),
        );
        (name.to_owned(), output)
    };

    // A free lock is taken, and the pid file names the run that took it.
    let (_, output) = acquire("free");
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert!(stdout_of(&output).contains(&format!("took {}", held.display())));
    assert!(
        fs::read_to_string(held.join("pid")).is_ok_and(|pid| !pid.trim().is_empty()),
        "the pid of the run must be recorded"
    );

    // Held by a live process: refused.
    fs::write(held.join("pid"), format!("{}\n", std::process::id())).expect("plant a live pid");
    let (_, output) = acquire("live");
    assert!(!output.status.success(), "a live holder must stop the run");
    assert!(stderr_of(&output).contains("another run of this script holds"));

    // An empty pid file: a run between mkdir and its pid write. Refused.
    fs::write(held.join("pid"), "").expect("empty the pid file");
    let (_, output) = acquire("empty");
    assert!(!output.status.success(), "an empty pid file counts as held");

    // Held by a process that has exited: taken over.
    let mut gone = Command::new("true").spawn().expect("spawn a process");
    let gone_pid = gone.id();
    gone.wait().expect("wait for it");
    fs::write(held.join("pid"), format!("{gone_pid}\n")).expect("plant a dead pid");
    let (_, output) = acquire("stale");
    assert!(
        output.status.success(),
        "a lock whose run is gone must be taken over: {}",
        stderr_of(&output)
    );
    assert_ne!(
        fs::read_to_string(held.join("pid")).ok(),
        Some(format!("{gone_pid}\n")),
        "the new run's pid must replace the old one"
    );
    let takeover = dir.join("run/volto-deploy.lock.takeover");
    assert!(!takeover.exists(), "a takeover releases its own lock");

    // A stale lock that another run is taking over: refused, and left to
    // that run (F3-L3). Two runs that found the same dead pid could both
    // remove and re-create the directory, and both go on.
    fs::write(held.join("pid"), format!("{gone_pid}\n")).expect("plant a dead pid");
    fs::create_dir(&takeover).expect("plant a takeover in progress");
    let (_, output) = acquire("takeover-held");
    assert!(
        !output.status.success(),
        "a takeover in progress must stop a second one: {}",
        stdout_of(&output)
    );
    assert!(
        stderr_of(&output).contains("is taking over"),
        "{}",
        stderr_of(&output)
    );
    assert_eq!(
        fs::read_to_string(held.join("pid")).ok(),
        Some(format!("{gone_pid}\n")),
        "the refused run must leave the lock to the run taking it over"
    );
}

/// The first-install password reaches the bundled installer in its
/// environment and not on its command line (R8-M1).
///
/// `deploy.sh` used to copy `-w PASS` into the installer's arguments, where it
/// sat in `/proc/<pid>/cmdline`, readable by every local user, for the whole
/// installer run.
#[test]
fn the_first_install_password_reaches_the_installer_outside_its_arguments() {
    const SECRET: &str = "argv-canary-d3p|&";
    let host = Host::new("first-install-password", Service::ComesUp);
    host.publish(UNSIGNED_TAG, Candidate::LoadsTheConfig);

    let output = host.run(&[
        "--allow-unsigned",
        "--tag",
        UNSIGNED_TAG,
        "--username",
        "alice",
        "--password",
        SECRET,
    ]);

    let stderr = stderr_of(&output);
    assert!(output.status.success(), "{stderr}");
    let installer = host.calls("installer");
    assert!(
        installer.ends_with("/volto --username alice\n") && !installer.contains(SECRET),
        "the installer's arguments must not carry the password: {installer:?}"
    );
    assert_eq!(
        host.calls("installer-password"),
        format!("{SECRET}\n"),
        "the installer must get the password in its environment"
    );
}

/// A run that looked the latest release up, the way the timer does, refuses a
/// release older than the installed one before it downloads anything.
///
/// The run is the real one: the stand-in `curl` answers the lookup with an
/// older tag, and the planted binary reports a newer version. Three more hosts
/// show what arms the refusal and what it can order. One whose latest release
/// is newer goes on to the download, so the refusal is what stopped the first.
/// One told `--tag v1.3.5` goes on to the download too, since a rollback named
/// at the host is not refused. One whose latest release is not three numbers
/// is refused before the download, since the refusal cannot order it.
#[test]
fn a_looked_up_release_older_than_the_install_is_refused_before_the_download() {
    let host = Host::new("latest-older", Service::ComesUp);
    host.plant_install();
    host.publish("v1.3.5", Candidate::LoadsTheConfig);
    host.mark_latest("v1.3.5");
    let previous_binary =
        fs::read_to_string(host.bin()).expect("the planted binary must be readable");

    let output = host.run(&[]);

    let stderr = stderr_of(&output);
    assert!(
        !output.status.success(),
        "an older latest release must be refused: {}",
        stdout_of(&output)
    );
    assert!(
        stderr.contains(
            "the latest release is v1.3.5 and this host runs 1.3.6 -- refusing to go back"
        ),
        "the refusal must name both versions: {stderr}"
    );
    assert_eq!(
        host.calls("curl"),
        "https://github.com/example/volto/releases/latest\n",
        "the lookup must be the only request: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(host.bin()).ok(),
        Some(previous_binary),
        "the installed binary must be untouched: {stderr}"
    );
    assert_eq!(
        host.calls("systemctl"),
        "",
        "the service must be left alone"
    );

    let newer = Host::new("latest-newer", Service::ComesUp);
    newer.plant_install();
    newer.publish(UNSIGNED_TAG, Candidate::LoadsTheConfig);
    newer.mark_latest(UNSIGNED_TAG);

    let output = newer.run(&[]);

    let stderr = stderr_of(&output);
    assert!(
        !stderr.contains("refusing to go back")
            && stderr
                .contains("carries no SHA256SUMS.sig -- refusing to install an unsigned release"),
        "a newer latest release must pass the refusal and reach the download, \
         where the missing signature stops it: {stderr}"
    );
    assert!(
        newer
            .calls("curl")
            .contains("/releases/download/v1.3.7/volto-1.3.7-x86_64-unknown-linux-musl.tar.gz\n"),
        "the run must have downloaded the release: {}",
        newer.calls("curl")
    );

    let named = Host::new("latest-named-rollback", Service::ComesUp);
    named.plant_install();
    named.publish("v1.3.5", Candidate::LoadsTheConfig);

    let output = named.run(&["--tag", "v1.3.5"]);

    let stderr = stderr_of(&output);
    assert!(
        !stderr.contains("refusing to go back")
            && stderr
                .contains("carries no SHA256SUMS.sig -- refusing to install an unsigned release"),
        "a rollback named with --tag must pass the refusal and reach the download: {stderr}"
    );
    assert!(
        named
            .calls("curl")
            .starts_with("https://github.com/example/volto/releases/download/v1.3.5/"),
        "the named rollback must be downloaded, with no lookup first: {}",
        named.calls("curl")
    );

    let unordered = Host::new("latest-prerelease", Service::ComesUp);
    unordered.plant_install();
    unordered.mark_latest("v1.3.8-rc1");

    let output = unordered.run(&[]);

    let stderr = stderr_of(&output);
    assert!(
        !output.status.success()
            && stderr.contains("the latest release is tagged v1.3.8-rc1, which is not vX.Y.Z"),
        "a latest release the refusal cannot order must not be installed: {stderr}"
    );
    assert_eq!(
        unordered.calls("curl"),
        "https://github.com/example/volto/releases/latest\n",
        "the lookup must be the only request: {stderr}"
    );
}
