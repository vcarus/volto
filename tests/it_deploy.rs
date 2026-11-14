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
//! therefore runs on its own, with a test key, as do `restore_previous` and
//! `refuse_automatic_downgrade`.

#[path = "common/scripts.rs"]
mod scripts;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use scripts::{
    loadable_config_text, path_with_stubs, plant_binary_without_the_flag,
    plant_placeholder_certificates, real_binary, repo_root, scratch_tree, stderr_of, stdout_of,
    write_executable,
};

fn deploy_script() -> PathBuf {
    repo_root().join("script/deploy.sh")
}

fn run_deploy(args: &[&str]) -> Output {
    run_deploy_under(None, args)
}

/// Runs the script as a file, optionally with its install paths relocated.
fn run_deploy_under(root: Option<&Path>, args: &[&str]) -> Output {
    let mut command = Command::new("bash");
    command
        .arg(deploy_script())
        .args(args)
        .current_dir(repo_root());
    if let Some(root) = root {
        command.env("VOLTO_DEPLOY_ROOT", root);
    }
    command
        .output()
        .expect("the deploy script must be runnable")
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
    Command::new("bash")
        .arg(deploy_script())
        .args(args)
        .current_dir(repo_root())
        .env("VOLTO_DEPLOY_ROOT", root)
        .env("VOLTO_DEPLOY_CANDIDATE", candidate)
        .output()
        .expect("the deploy script must be runnable")
}

/// Runs the script the way the documented one-liner does: `curl … | bash -s --`,
/// which leaves `$0` as `bash` instead of a path, from the directory `cwd`.
fn run_deploy_piped(root: &Path, cwd: &Path, args: &[&str]) -> Output {
    let script = fs::File::open(deploy_script()).expect("the deploy script must be readable");

    Command::new("bash")
        .arg("-s")
        .arg("--")
        .args(args)
        .current_dir(cwd)
        .env("VOLTO_DEPLOY_ROOT", root)
        .stdin(Stdio::from(script))
        .output()
        .expect("the deploy script must be runnable from stdin")
}

/// A stand-in for a host's filesystem: the directories a Linux host already has,
/// under a directory of this test's own.
fn install_root(name: &str) -> PathBuf {
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
    let output = run_deploy(&["-h"]);

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

/// Garbage flags must be rejected before anything privileged is attempted.
#[test]
fn unknown_options_are_rejected() {
    let output = run_deploy(&["--definitely-not-a-flag"]);

    assert!(!output.status.success(), "garbage flags must fail");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("unknown option: --definitely-not-a-flag"),
        "the error must name the offending flag: {stderr}"
    );
}

/// A tag that is not a tag must be caught before any download starts.
#[test]
fn a_malformed_tag_is_rejected_in_argument_form() {
    let output = run_deploy(&["--tag"]);

    assert!(!output.status.success(), "--tag without a value must fail");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("--tag needs a value"),
        "the error must say what is missing: {stderr}"
    );
}

/// The shape check on the tag itself. It sits after the preflight, so only the
/// dry run can reach it on a dev host.
#[test]
fn a_tag_without_its_leading_v_is_rejected() {
    let output = run_deploy(&["--dry-run", "--tag", "0.2.4"]);

    assert!(!output.status.success(), "a bare version must not be a tag");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("--tag expects the tag name as on the releases page"),
        "the error must show the expected shape: {stderr}"
    );
}

/// Resolving "latest" is a network call, which a dry run must never make.
#[test]
fn a_dry_run_without_a_tag_refuses_rather_than_resolving_one() {
    let output = run_deploy(&["--dry-run"]);

    assert!(!output.status.success(), "a dry run needs an explicit tag");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("--dry-run needs --tag"),
        "the error must say a tag is required: {stderr}"
    );
}

/// `--force` puts a named release's bytes on the host, so it has to be told
/// which release. The same reason `--dry-run` needs a tag, refused in the same
/// words.
#[test]
fn forcing_a_reinstall_without_a_tag_is_rejected() {
    let output = run_deploy(&["--force"]);

    assert!(
        !output.status.success(),
        "--force without a tag must not run"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("--force needs --tag"),
        "the error must say a tag is required: {stderr}"
    );
}

/// An unsigned release is installed by name. Without a tag the run would
/// resolve the latest release, which is the one path that must never accept a
/// release without a signature, because it is the path the timer takes.
#[test]
fn allowing_an_unsigned_release_without_a_tag_is_rejected() {
    let output = run_deploy(&["--allow-unsigned"]);

    assert!(
        !output.status.success(),
        "--allow-unsigned without a tag must not run"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("--allow-unsigned needs --tag"),
        "the error must say a tag is required: {stderr}"
    );
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

    let output = run_deploy_under(Some(&root), &["--dry-run", "--tag", "v0.2.4", "--force"]);

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

    let output = run_deploy_under(Some(&root), &["--dry-run", "--tag", "v0.2.4"]);

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

    let output = run_deploy_under(Some(&root), &["--dry-run", "--tag", "v0.2.4"]);

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

    let output = run_deploy_under(Some(&root), &["--dry-run", "--tag", "v0.2.4"]);

    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(
        stdout_of(&output),
        "dry-run: would update 0.2.4 -> v0.2.4 (missing: unit)\n"
    );
}

/// The everyday path of a timered host: a newer release exists.
#[test]
fn an_older_installed_version_becomes_an_update() {
    let root = install_root("older");
    plant_binary(&root, "0.2.3");
    plant_config(&root);
    plant_unit(&root);

    let output = run_deploy_under(Some(&root), &["--dry-run", "--tag", "v0.2.4"]);

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

    let output = run_deploy_under(Some(&root), &["--dry-run", "--tag", "v0.4.4"]);

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

/// The everyday direction must stay quiet: an upgrade has neither hazard, and a
/// warning printed on every timer tick is a warning nobody reads.
#[test]
fn an_upgrade_and_a_reinstall_say_nothing_about_downgrades() {
    for (name, installed, tag, decision) in [
        (
            "upgrade",
            "0.4.4",
            "v0.5.1",
            "dry-run: would update 0.4.4 -> v0.5.1\n",
        ),
        (
            "same-version",
            "0.5.1",
            "v0.5.1",
            "dry-run: already deployed and intact (v0.5.1)\n",
        ),
    ] {
        let root = install_root(name);
        plant_binary(&root, installed);
        plant_config(&root);
        plant_unit(&root);

        let output = run_deploy_under(Some(&root), &["--dry-run", "--tag", tag]);

        assert!(output.status.success(), "{}", stderr_of(&output));
        assert_eq!(
            stdout_of(&output),
            decision,
            "{name} must print only its decision"
        );
    }
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

    let first = run_deploy_under(
        Some(&root),
        &["--dry-run", "--enable-timer", "--tag", "v0.2.4"],
    );
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

    let second = run_deploy_under(
        Some(&root),
        &["--dry-run", "--enable-timer", "--tag", "v0.2.4"],
    );
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

    let output = Command::new("bash")
        .arg(deploy_script())
        .args(["--dry-run", "--enable-timer", "--tag", "v0.2.4"])
        .current_dir(repo_root())
        .env("PATH", path_with_stubs(&stubs))
        .output()
        .expect("the deploy script must be runnable");

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

/// The body of the shell function `name` in `script`, from its opening brace to
/// the closing brace at column zero.
///
/// The braces bound the function, so a test runs exactly that function and
/// none of the script around it.
fn shell_function_body(script: &str, name: &str) -> String {
    let text = fs::read_to_string(repo_root().join(script)).expect("the script must be readable");
    let start = text
        .find(&format!("\n{name}() {{"))
        .unwrap_or_else(|| panic!("{script} carries no `{name}()` function"));
    let rest = &text[start + 1..];
    let end = rest
        .find("\n}")
        .unwrap_or_else(|| panic!("`{name}()` in {script} is never closed"));
    rest[..end].to_owned()
}

/// Runs the shell function `name` from `script` on its own, with the stubs in
/// `stubs` first on `PATH` and `prelude` run before the call.
///
/// `die` is defined as a recorder that exits nonzero, so a test can read what
/// the function reported. The function runs under `set -eE`, as in the script.
fn run_shell_function(script: &str, name: &str, stubs: &Path, prelude: &str) -> Output {
    let body = shell_function_body(script, name);
    let program = format!(
        "set -eE\ndie() {{ printf 'die: %s\\n' \"$*\" >&2; exit 1; }}\nnote() {{ printf 'note: %s\\n' \"$*\"; }}\n{body}\n}}\n{prelude}\n{name}\n"
    );

    Command::new("bash")
        .args(["-c", &program])
        .env("PATH", path_with_stubs(stubs))
        .output()
        .expect("bash must be runnable")
}

/// The rollback puts the previous files back, reloads systemd, and starts the
/// service without restarting it.
///
/// `restore_previous` is the ERR trap of the swap window. A failure before the
/// restart, in the binary or unit `install` or in `daemon-reload`, leaves the
/// old process running and serving its tunnels. A failure of the restart itself
/// can leave the unit inactive. `systemctl start` covers both: it does nothing
/// to an active unit and starts an inactive one. A `restart` here would drop
/// every live tunnel for a failure that had cost nothing. `daemon-reload` comes
/// before the start, or systemd starts the service under the unit it parsed
/// last, which is the one being rolled back.
///
/// The real `install` runs, so the files are read back afterwards: a copy in
/// the wrong direction overwrites the only previous binary and still reports a
/// restore. The run that arms the trap over a whole update is
/// `a_failure_inside_the_swap_window_restores_both_files`.
#[test]
fn restoring_the_previous_files_starts_rather_than_restarts_the_service() {
    let dir = scratch_tree("deploy", "restore-previous", &["stubs", "bin", "unit"]);
    let stubs = dir.join("stubs");
    let log = dir.join("systemctl.log");

    write_executable(
        &stubs.join("systemctl"),
        &format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n", log.display()),
    );

    let bin = dir.join("bin/volto");
    let unit = dir.join("unit/volto.service");
    fs::write(&bin, "the failed binary\n").expect("plant the failed binary");
    fs::write(bin.with_extension("prev"), "the previous binary\n")
        .expect("plant the previous binary");
    fs::write(&unit, "the failed unit\n").expect("plant the failed unit");
    fs::write(unit.with_extension("service.prev"), "the previous unit\n")
        .expect("plant the previous unit");

    let prelude = format!(
        "BIN='{}'; UNIT='{}'; SERVICE_NAME=volto; VERSION=9.9.9",
        bin.display(),
        unit.display()
    );
    let output = run_shell_function("script/deploy.sh", "restore_previous", &stubs, &prelude);

    let stderr = stderr_of(&output);
    assert!(
        !output.status.success() && stderr.contains("restored the previous binary and unit"),
        "restore_previous must report what it restored and fail the run: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(&bin).ok().as_deref(),
        Some("the previous binary\n"),
        "restore_previous must copy the previous binary over the failed one: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(&unit).ok().as_deref(),
        Some("the previous unit\n"),
        "restore_previous must copy the previous unit over the failed one: {stderr}"
    );
    let calls = fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(
        calls, "daemon-reload\nstart volto\n",
        "restore_previous must reload systemd and then start the service, never \
         restart it: systemctl saw\n{calls}"
    );
}

/// Whether the shell line `line` runs `curl` as a command.
///
/// `curl` counts as a command word at the start of the line, after a `$(`, a
/// `(`, a backtick, a pipe, `&&`, `||`, `;` or `{`, after a keyword that
/// precedes a command (`if`, `then`, `else`, `elif`, `do`, `while`, `until`,
/// `!`, `exec`, `time`), and after a variable assignment. A `curl` in an
/// argument list, such as the preflight's `for tool in curl tar ...`, is not
/// a call.
fn runs_curl(line: &str) -> bool {
    const SEPARATORS: [&str; 7] = ["$(", "(", "`", "|", "&", ";", "{"];
    const KEYWORDS: [&str; 10] = [
        "if", "then", "else", "elif", "do", "while", "until", "!", "exec", "time",
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
/// SIGTERM, and the script traps only ERR and EXIT. A SIGTERM inside the binary
/// swap window would leave the new files in place with no health check and no
/// rollback. So the worst case of every curl call, added up, must leave time
/// for the rest of the run.
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
    let timeout: u64 = match timeout.strip_suffix("min") {
        Some(minutes) => minutes.parse::<u64>().expect("whole minutes") * 60,
        None => timeout
            .trim_end_matches('s')
            .parse()
            .expect("TimeoutStartSec in whole minutes or seconds"),
    };

    // The rest of the run: the checksum, the config check, the swap, the
    // restart and the three-second health wait.
    let rest_of_the_run = 120;
    assert!(
        worst_case + rest_of_the_run <= timeout,
        "the curl calls can take {worst_case} s, which with {rest_of_the_run} s for \
         the rest of the run exceeds TimeoutStartSec ({timeout} s): systemd could \
         stop the run inside the binary swap window"
    );
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

    let output = run_deploy_piped(
        &root,
        &elsewhere,
        &["--dry-run", "--enable-timer", "--tag", "v0.2.4"],
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

/// Runs `--verify-signature`, with the trusted key replaced when one is given.
fn verify_signature(signer: Option<&str>, sums: &Path, signature: &Path) -> Output {
    let mut command = Command::new("bash");
    command
        .arg(deploy_script())
        .arg("--verify-signature")
        .arg(sums)
        .arg(signature)
        .current_dir(repo_root());
    if let Some(signer) = signer {
        command.env("VOLTO_DEPLOY_SIGNER", signer);
    }
    command
        .output()
        .expect("the deploy script must be runnable")
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

    let good = verify_signature(Some(&trusted), &sums, &signature);
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
    let output = verify_signature(Some(&trusted), &tampered, &signature);
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
    let output = verify_signature(Some(&trusted), &by_stranger, &stranger_signature);
    assert!(
        !output.status.success(),
        "a signature by another key must be refused"
    );

    // The trusted key's signature made for another purpose.
    let other_purpose = dir.join("other-purpose");
    fs::copy(&sums, &other_purpose).unwrap();
    let git_signature = sign(&dir, "trusted", "git", &other_purpose);
    let output = verify_signature(Some(&trusted), &other_purpose, &git_signature);
    assert!(
        !output.status.success(),
        "a signature under another namespace must be refused"
    );

    // No signature at all.
    let output = verify_signature(Some(&trusted), &sums, &dir.join("absent.sig"));
    assert!(
        !output.status.success(),
        "a missing signature must be refused"
    );

    // And the key the script carries does not accept the test key's signature,
    // so the override above is what made the first case pass.
    let output = verify_signature(None, &sums, &signature);
    assert!(
        !output.status.success(),
        "the embedded key accepted a signature made by a test key"
    );
}

/// A release directory as the download step leaves it, with the key that signs
/// it, for [`verify_release`].
struct Download {
    dir: PathBuf,
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

/// The key the install path trusts comes from the script. `VOLTO_DEPLOY_SIGNER`
/// names the key that really signed this release, and the release is refused
/// all the same, because `verify_release` does not read the variable.
#[test]
fn the_install_path_ignores_a_key_named_in_the_environment() {
    let download = download(
        "verify-environment",
        |digest| format!("{digest}  {ARCHIVE}.tar.gz\n"),
        Some("stranger"),
    );
    let stranger = fs::read_to_string(download.dir.join("stranger.pub")).unwrap();
    let stranger: Vec<&str> = stranger.split_whitespace().take(2).collect();

    let signature_is_valid = shell_function_body("script/deploy.sh", "signature_is_valid");
    let prelude = format!(
        "{signature_is_valid}\n}}\n\
         export VOLTO_DEPLOY_SIGNER='{}'\n\
         RELEASE_SIGNER='{}'\nSIGN_NAMESPACE={SIGN_NAMESPACE}\n\
         TMP='{}'\nNAME={ARCHIVE}\nTAG=v9.9.9\nALLOW_UNSIGNED=0\nRELEASE_IS_SIGNED=0",
        stranger.join(" "),
        download.trusted,
        download.dir.display(),
    );
    let output = run_shell_function(
        "script/deploy.sh",
        "verify_release",
        &download.dir.join("stubs"),
        &prelude,
    );

    assert!(
        !output.status.success(),
        "the install path accepted a release signed by the key in VOLTO_DEPLOY_SIGNER"
    );
}

/// The script itself sets the trusted key once, to a literal, and reads the
/// override variable in the verify-only mode alone. The install path is one
/// call of `verify_release`, which the tests above run.
#[test]
fn the_trusted_key_is_a_literal_and_the_install_path_is_one_call() {
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

    let reads: Vec<&&str> = code
        .iter()
        .filter(|line| line.contains("VOLTO_DEPLOY_SIGNER"))
        .collect();
    assert_eq!(
        reads.len(),
        1,
        "VOLTO_DEPLOY_SIGNER is read in one place, the verify-only mode: {reads:?}"
    );
    assert!(
        reads[0].contains("\"$VERIFY_SUMS\""),
        "the one read of VOLTO_DEPLOY_SIGNER is the verify-only call: {}",
        reads[0]
    );

    assert_eq!(
        code.iter()
            .filter(|line| **line == "verify_release")
            .count(),
        1,
        "the install path verifies the download with one call of verify_release"
    );
    let call = text.find("\n    verify_release\n").expect("the call");
    let unpack = text.find("tar -xzf").expect("the unpack step");
    assert!(
        call < unpack,
        "verify_release must run before the archive is unpacked"
    );
    assert_eq!(
        text.matches("tar -xzf").count(),
        1,
        "the archive is unpacked in one place"
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

    let output = run_deploy_under(
        Some(&root),
        &["--dry-run", "--tag", "v1.4.0", "--allow-unsigned"],
    );
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
    let output = run_deploy_under(
        Some(&root),
        &["--dry-run", "--tag", "v1.10.0", "--allow-unsigned"],
    );
    assert!(
        !output.status.success(),
        "--allow-unsigned must not apply to 1.10.0"
    );

    let output = run_deploy_under(
        Some(&root),
        &["--dry-run", "--tag", "v1.3.7", "--allow-unsigned"],
    );
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

/// The refusal sits where the release has just been resolved and nothing has
/// been downloaded, the only assignment that arms it is the lookup of the
/// latest release, and no other line sets the flag. The run itself is
/// `a_looked_up_release_older_than_the_install_is_refused_before_the_download`.
#[test]
fn the_downgrade_refusal_runs_before_any_download_and_is_armed_by_the_lookup_alone() {
    let text = fs::read_to_string(deploy_script()).expect("the deploy script must be readable");

    let call = text
        .find("\nrefuse_automatic_downgrade\n")
        .expect("the script must call refuse_automatic_downgrade at top level");
    let download = text
        .find("--- download and verify ---")
        .expect("the download section");
    assert!(call < download, "the refusal must come before the download");

    // Every line of code that names the flag is one of three: the default, the
    // arming line after the lookup, and the read in the refusal. Anything else
    // is a second assignment, and a second assignment can disarm it.
    let named: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && line.contains("TAG_WAS_RESOLVED"))
        .collect();
    assert_eq!(
        named,
        [
            "TAG_WAS_RESOLVED=0",
            "[ \"$TAG_WAS_RESOLVED\" -eq 1 ] || return 0",
            "TAG_WAS_RESOLVED=1",
        ],
        "TAG_WAS_RESOLVED must be set once to its default, read once by the \
         refusal and armed once by the lookup, and named nowhere else"
    );
    assert!(
        text.contains("[[ \"$TAG\" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]] ||"),
        "a looked-up tag must be three numbers, or the refusal cannot order it"
    );
    let lookup = text.find("releases/latest").expect("the latest lookup");
    let arm = text.find("TAG_WAS_RESOLVED=1").expect("the arming line");
    assert!(
        lookup < arm && arm < call,
        "the refusal is armed right after the latest release is looked up"
    );
}

/// `--verify-signature` is a mode of its own. An empty file name once fell
/// through to an ordinary run, which exited 0 having verified nothing.
#[test]
fn verifying_a_signature_with_an_empty_file_name_fails() {
    let output = run_deploy(&["--verify-signature", "", "x"]);

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
    let output = run_deploy(&[
        "--verify-signature",
        sums.to_str().unwrap(),
        signature.to_str().unwrap(),
        "--tag",
        "v1.4.0",
    ]);

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
}

/// How the binary inside a published release answers `--check-config`.
#[derive(Clone, Copy)]
enum Candidate {
    LoadsTheConfig,
    RefusesTheConfig,
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
    root: PathBuf,
    stubs: PathBuf,
    release: PathBuf,
    staging: PathBuf,
    logs: PathBuf,
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
                "stubs",
                "release",
                "staging",
                "logs",
            ],
        );
        let host = Host {
            root: base.join("root"),
            stubs: base.join("stubs"),
            release: base.join("release"),
            staging: base.join("staging"),
            logs: base.join("logs"),
        };

        write_executable(&host.stubs.join("id"), "#!/bin/sh\necho 0\n");
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
            Service::ComesUp => (0, 0),
            Service::RestartFails => (1, 0),
            Service::DiesAfterRestart => (0, 1),
        };
        write_executable(
            &host.stubs.join("systemctl"),
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> '{log}'\n\
                 case \"$*\" in\n\
                 \x20 'restart volto') exit {restart} ;;\n\
                 \x20 'is-active --quiet volto') exit {active} ;;\n\
                 \x20 'is-active volto') [ {active} -eq 0 ] && echo active || echo failed; exit {active} ;;\n\
                 esac\n\
                 exit 0\n",
                log = host.logs.join("systemctl").display(),
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
        };
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
                "#!/bin/sh\nprintf 'VOLTO_INSTALL_ROOT=%s %s\\n' \"$VOLTO_INSTALL_ROOT\" \"$*\" >> '{}'\n",
                self.logs.join("installer").display()
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

    /// Makes the latest-release lookup answer `tag`.
    fn mark_latest(&self, tag: &str) {
        fs::write(
            self.logs.join("latest"),
            format!("https://github.com/example/volto/releases/tag/{tag}"),
        )
        .expect("the latest marker must be writable");
    }

    /// Runs `script/deploy.sh` with `args`, its paths under `root` and the stubs
    /// first on `PATH`.
    fn run(&self, args: &[&str]) -> Output {
        Command::new("bash")
            .arg(deploy_script())
            .args(args)
            .current_dir(repo_root())
            .env("PATH", path_with_stubs(&self.stubs))
            .env("VOLTO_DEPLOY_ROOT", &self.root)
            .env("REPO", "example/volto")
            .env_remove("TAG")
            .env_remove("VOLTO_DEPLOY_CANDIDATE")
            .env_remove("VOLTO_DEPLOY_SIGNER")
            .output()
            .expect("the deploy script must be runnable")
    }

    /// What one stub recorded, one call per line.
    fn calls(&self, stub: &str) -> String {
        fs::read_to_string(self.logs.join(stub)).unwrap_or_default()
    }
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

/// A failure inside the swap window puts the previous binary and unit back,
/// reloads systemd and starts the service.
///
/// `restore_previous` is armed as an ERR trap once both `.prev` copies exist.
/// Here the restart fails after the new binary and unit are in place, which
/// leaves the old files as the only ones that can serve. Without the trap,
/// `set -e` ends the run with the new files installed and the service down.
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

/// A run that looked the latest release up, the way the timer does, refuses a
/// release older than the installed one before it downloads anything.
///
/// The run is the real one: the stand-in `curl` answers the lookup with an
/// older tag, and the planted binary reports a newer version. A second host,
/// whose latest release is newer, shows the same run going on to the download,
/// so the refusal is what stopped the first one.
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
}
