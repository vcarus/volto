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
//! directory stands in for `/usr/local` and `/etc`. The privileged remainder
//! (download, checksum, rollback, systemd) is still covered by shellcheck plus
//! first-run review, the same deal as install-selfsigned.sh.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

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

/// Runs the script the way the documented one-liner does: `curl … | bash -s --`,
/// which leaves `$0` as `bash` instead of a path.
fn run_deploy_piped(root: &Path, args: &[&str]) -> Output {
    let script = fs::File::open(deploy_script()).expect("the deploy script must be readable");

    Command::new("bash")
        .arg("-s")
        .arg("--")
        .args(args)
        .current_dir(repo_root())
        .env("VOLTO_DEPLOY_ROOT", root)
        .stdin(Stdio::from(script))
        .output()
        .expect("the deploy script must be runnable from stdin")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A stand-in for a host's filesystem: the directories a Linux host already has,
/// under a directory of this test's own.
fn install_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("volto-deploy-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for dir in [
        "usr/local/bin",
        "usr/local/sbin",
        "etc/volto",
        "etc/systemd/system",
    ] {
        fs::create_dir_all(root.join(dir)).expect("the temporary install root must be creatable");
    }
    root
}

/// Plants an installed binary that answers `--version` like the real one.
fn plant_binary(root: &Path, version: &str) {
    let bin = root.join("usr/local/bin/volto");
    fs::write(&bin, format!("#!/bin/sh\necho \"volto {version}\"\n"))
        .expect("the stand-in binary must be writable");
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755))
        .expect("the stand-in binary must be executable");
}

fn plant_config(root: &Path) {
    fs::write(root.join("etc/volto/config.toml"), "# planted\n").expect("config must be writable");
}

fn plant_unit(root: &Path) {
    fs::write(root.join("etc/systemd/system/volto.service"), "# planted\n")
        .expect("the unit must be writable");
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

    let _ = fs::remove_dir_all(&root);
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

    let _ = fs::remove_dir_all(&root);
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

    let _ = fs::remove_dir_all(&root);
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

    let _ = fs::remove_dir_all(&root);
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
    assert!(!root
        .join("etc/systemd/system/volto-deploy.service")
        .exists());

    let _ = fs::remove_dir_all(&root);
}

/// The bootstrap one-liner from the release notes: piped into `bash`, `$0` is
/// not a file. This once aborted the whole run; it must be a quiet no-op.
#[test]
fn a_piped_bootstrap_has_nothing_to_copy_and_says_so_by_succeeding() {
    let root = install_root("piped");

    let output = run_deploy_piped(&root, &["--dry-run", "--enable-timer", "--tag", "v0.2.4"]);

    assert!(
        output.status.success(),
        "a piped run must not abort: {}",
        stderr_of(&output)
    );
    assert!(
        !root.join("usr/local/sbin/volto-deploy").exists(),
        "there is no file to copy from, so nothing may be installed"
    );
    let stdout = stdout_of(&output);
    assert!(
        stdout.ends_with("dry-run: would enable timer\n"),
        "the run must reach the timer decision: {stdout}"
    );

    let _ = fs::remove_dir_all(&root);
}
