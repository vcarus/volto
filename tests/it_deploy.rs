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

#[path = "common/scripts.rs"]
mod scripts;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use scripts::{
    loadable_config_text, plant_binary_without_the_flag, plant_placeholder_certificates,
    real_binary, repo_root, scratch_tree, stderr_of, stdout_of,
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
/// takes it from here instead. Everything after that — the capability probe and
/// the check itself — is the same code path either way.
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

/// Writes `text` to `path` with mode 0755.
fn write_executable(path: &Path, text: &str) {
    fs::write(path, text).expect("the stub must be writable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .expect("the stub must be executable");
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

    let path = std::env::var_os("PATH").expect("PATH must be set");
    let path =
        std::env::join_paths(std::iter::once(stubs.clone()).chain(std::env::split_paths(&path)))
            .expect("the stub directory must fit in PATH");

    let output = Command::new("bash")
        .arg(deploy_script())
        .args(["--dry-run", "--enable-timer", "--tag", "v0.2.4"])
        .current_dir(repo_root())
        .env("PATH", path)
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

    let path = std::env::var_os("PATH").expect("PATH must be set");
    let path = std::env::join_paths(
        std::iter::once(stubs.to_path_buf()).chain(std::env::split_paths(&path)),
    )
    .expect("the stub directory must fit in PATH");

    Command::new("bash")
        .args(["-c", &program])
        .env("PATH", path)
        .output()
        .expect("bash must be runnable")
}

/// The rollback starts the service and never restarts it.
///
/// `restore_previous` runs when any step of the swap window fails. A failure
/// before the restart, in the binary or unit `install` or in `daemon-reload`,
/// leaves the old process running and serving its tunnels. A failure of the
/// restart itself can leave the unit inactive. `systemctl start` covers both:
/// it does nothing to an active unit and starts an inactive one. A `restart`
/// here would drop every live tunnel for a failure that had cost nothing.
#[test]
fn restoring_the_previous_files_starts_rather_than_restarts_the_service() {
    let dir = scratch_tree("deploy", "restore-previous", &["stubs", "bin", "unit"]);
    let stubs = dir.join("stubs");
    let log = dir.join("systemctl.log");

    write_executable(
        &stubs.join("systemctl"),
        &format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n", log.display()),
    );
    write_executable(&stubs.join("install"), "#!/bin/sh\nexit 0\n");

    let bin = dir.join("bin/volto");
    let unit = dir.join("unit/volto.service");
    fs::write(bin.with_extension("prev"), "old binary").expect("plant the previous binary");
    fs::write(unit.with_extension("service.prev"), "old unit").expect("plant the previous unit");

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
    let calls = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        calls.lines().any(|line| line == "start volto"),
        "restore_previous must start the service: systemctl saw\n{calls}"
    );
    assert!(
        !calls.lines().any(|line| line.starts_with("restart")),
        "restore_previous must not restart a service that may still be serving: \
         systemctl saw\n{calls}"
    );
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
/// Every logical line that runs `curl -` is read, continuation lines joined,
/// including the one inside `location="$(curl`.
#[test]
fn every_network_call_and_the_timer_service_are_bounded() {
    let text = fs::read_to_string(repo_root().join("script/deploy.sh"))
        .expect("the deploy script must be readable");
    let joined = text.replace("\\\n", " ");

    let calls: Vec<&str> = joined
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && line.contains("curl -"))
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
        .filter(|line| line.starts_with("RELEASE_SIGNER="))
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

/// `--verify-signature` is a mode of its own. An empty file name once fell
/// through to an ordinary run, which exited 0 having verified nothing.
#[test]
fn verifying_a_signature_with_an_empty_file_name_fails() {
    let output = run_deploy(&[
        "--verify-signature",
        "",
        "x",
        "--dry-run",
        "--tag",
        "v1.0.0",
    ]);

    assert!(
        !output.status.success(),
        "an empty file name must not be taken for no request: {}",
        stdout_of(&output)
    );
    assert!(stderr_of(&output).contains("no such file"));
}
