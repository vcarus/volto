//! The self-signed installer must generate a configuration volto accepts.
//!
//! `script/install-selfsigned.sh` builds `/etc/volto/config.toml` by substituting
//! four values into the shipped example. That is exactly the kind of text munging
//! that rots silently: rename a key, reflow the example, and the script keeps
//! "working" while installing a config the server rejects — or, worse, one that
//! still carries the example's placeholder password.
//!
//! The script's `--print-config` flag exists for this test: it runs the real
//! generation path, touches nothing, and needs no root. The rest of the script
//! (users, certificates, systemd) cannot be exercised on the dev host and is
//! covered by shellcheck plus review.
//!
//! `--check-config` is the second seam, and it closes the other half of the same
//! hazard: parsing the generated text here proves this crate can read it, which
//! is not the same question as whether the binary about to be installed can.
//! That one is only answerable by running it, so the script runs it — `volto
//! --check-config`, the same flag `script/deploy.sh` puts to a release before it
//! swaps a binary (D93, D94). `VOLTO_INSTALL_ROOT` relocates the installer's
//! paths the way `VOLTO_DEPLOY_ROOT` does for `deploy.sh`, so a temporary
//! directory can hold the certificate and key the generated config names.

#[path = "common/scripts.rs"]
mod scripts;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use scripts::{
    plant_binary_without_the_flag, plant_placeholder_certificates, real_binary, repo_root,
    scratch_dir,
};
use volto::config::Config;

/// A stand-in for the host filesystem the installer writes into, carrying the
/// certificate and key the generated config names.
///
/// Nothing reads them: `Config::validate` insists both paths are files, which is
/// exactly the rule that makes `--check-config` unusable from a bare checkout and
/// the reason this seam exists at all.
fn install_root(name: &str) -> PathBuf {
    let root = scratch_dir("install", name);
    let conf_dir = root.join("etc/volto");
    fs::create_dir_all(&conf_dir).expect("the temporary install root must be creatable");
    plant_placeholder_certificates(&conf_dir);
    root
}

/// Copies the four sibling deployment assets into `root/script` and appends
/// `example_suffix` to the example config, returning the installer's new path.
///
/// They travel together because the installer resolves the unit and the example
/// through `SCRIPT_DIR`, which is wherever the copy of the script being run sits.
/// Copying all four rather than the two this reads is the point: a test that
/// silently worked with a broken sibling set would stop noticing when that
/// contract is what breaks.
fn plant_script_dir(root: &Path, example_suffix: &str) -> PathBuf {
    let dir = root.join("script");
    fs::create_dir_all(&dir).expect("the script directory must be creatable");

    for asset in [
        "install-selfsigned.sh",
        "deploy.sh",
        "config.example.toml",
        "masque.service",
    ] {
        fs::copy(repo_root().join("script").join(asset), dir.join(asset))
            .unwrap_or_else(|error| panic!("{asset} must be a sibling to copy: {error}"));
    }

    let example = dir.join("config.example.toml");
    let mut text = fs::read_to_string(&example).expect("the example must be readable");
    text.push_str(example_suffix);
    fs::write(&example, text).expect("the example copy must be writable");

    dir.join("install-selfsigned.sh")
}

/// Runs `--check-config` on the installer at `script`, with its install paths
/// relocated under `root` and `binary` as the volto being asked.
///
/// The credentials are fixed on purpose: what varies between the tests below is
/// the config the generator produces and the binary asked about it, and a value
/// that changes with neither would only be noise in the failure message.
fn run_check_config(root: &Path, script: &Path, binary: &Path) -> (bool, String, String) {
    let output = Command::new("bash")
        .arg(script)
        .args([
            "--check-config",
            "--binary",
            binary.to_str().expect("a UTF-8 path to the binary"),
            "-u",
            "alice",
            "-w",
            "correct-horse-battery",
        ])
        .current_dir(repo_root())
        .env("VOLTO_INSTALL_ROOT", root)
        .output()
        .expect("the installer script must be runnable");

    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Runs `--print-config` with the given arguments, returning its exit status,
/// standard output and standard error.
fn print_config(args: &[&str]) -> (bool, String, String) {
    let script = repo_root().join("script/install-selfsigned.sh");

    let output = Command::new("bash")
        .arg(&script)
        .arg("--print-config")
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("the installer script must be runnable");

    (
        output.status.success(),
        String::from_utf8(output.stdout).expect("the generated config must be UTF-8"),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Runs the installer's config generator with the given arguments.
fn generated_config(args: &[&str]) -> String {
    let (ok, stdout, stderr) = print_config(args);
    assert!(ok, "--print-config failed: {stderr}");
    stdout
}

#[test]
fn the_generated_configuration_is_valid() {
    let text = generated_config(&["-p", "4433", "-u", "alice", "-w", "correct-horse-battery"]);

    let config: Config = toml::from_str(&text).unwrap_or_else(|error| {
        panic!("the installer generated a config volto cannot parse: {error}\n{text}")
    });

    // Every substituted value must have landed.
    assert_eq!(config.server.listen.port(), 4433);
    assert_eq!(config.server.cert, PathBuf::from("/etc/volto/cert.pem"));
    assert_eq!(config.server.key, PathBuf::from("/etc/volto/key.pem"));
    assert_eq!(config.auth.users.len(), 1, "exactly one user is installed");
    assert_eq!(config.auth.users[0].username, "alice");
    assert_eq!(config.auth.users[0].password, "correct-horse-battery");

    // And the result must be a configuration volto would actually start on. The
    // certificate paths do not exist here, which is the only complaint allowed.
    let error = config
        .validate()
        .expect_err("the certificate does not exist in a checkout")
        .to_string();
    assert!(
        error.contains("server.cert"),
        "the generated config must be valid apart from its certificate paths: {error}"
    );
}

/// The failure that would matter most: shipping a live config that still carries
/// the example's placeholder password.
#[test]
fn the_placeholder_password_never_survives() {
    let text = generated_config(&[]);

    assert!(
        !text.contains("replace-me-with-something-long"),
        "the example placeholder password reached the generated config:\n{text}"
    );

    // With no password given, one is generated -- and it is not empty or trivial.
    let config: Config = toml::from_str(&text).expect("parses");
    assert_eq!(config.auth.users.len(), 1);
    let password = &config.auth.users[0].password;
    assert!(
        password.len() >= 16,
        "a generated password must not be trivial, got {} chars",
        password.len()
    );
    assert_eq!(config.auth.users[0].username, "surge", "the default user");
}

/// Two runs must not produce the same generated password.
#[test]
fn generated_passwords_differ_between_runs() {
    let first: Config = toml::from_str(&generated_config(&[])).expect("parses");
    let second: Config = toml::from_str(&generated_config(&[])).expect("parses");

    assert_ne!(
        first.auth.users[0].password, second.auth.users[0].password,
        "each install must get its own password"
    );
}

/// The commented-out second user in the example must stay commented out: the
/// substitution is anchored so it cannot turn a comment into a live credential.
#[test]
fn the_example_comment_does_not_become_a_user() {
    let text = generated_config(&["-u", "bob", "-w", "hunter2"]);
    let config: Config = toml::from_str(&text).expect("parses");

    assert_eq!(config.auth.users.len(), 1, "{text}");
    assert_eq!(config.auth.users[0].username, "bob");
    // The example's second user is still a comment, and still says user2.
    assert!(
        text.contains("# { username = \"user2\""),
        "the commented example user must survive as a comment:\n{text}"
    );
}

/// The shipped config seeds the handshake timers for a long-haul path.
///
/// Decision D43: an install derived from the example ships `initial_rtt_ms =
/// 150`, sized for the ~60-100 ms paths a fronted deployment typically serves,
/// while the compiled-in fallback stays RFC 9002's conservative 333. The pin is
/// here because the installer derives every install from the example file.
#[test]
fn the_shipped_config_seeds_a_long_haul_initial_rtt() {
    let config: Config = toml::from_str(&generated_config(&[])).expect("parses");
    assert_eq!(config.limits.initial_rtt_ms, 150);

    // The server-side default is deliberately not changed with it.
    assert_eq!(volto::config::DEFAULT_INITIAL_RTT_MS, 333);
}

/// A hand-picked password full of regular-expression metacharacters must reach
/// the config unchanged.
///
/// The generated default is base64, so only an operator who chooses their own
/// password ever exercises this — and every one of these characters is ordinary
/// in a password. `*` is the one that used to matter most: the config came out
/// perfectly correct, and then the script's own verification, a basic regular
/// expression, failed to find the line it had just written and aborted the
/// install with "failed to set the user in the config".
#[test]
fn a_password_full_of_metacharacters_survives_verbatim() {
    for password in ["Pa*ss.w0rd", "a+b.c*d", "^start$", "[brackets]"] {
        let text = generated_config(&["-u", "alice", "-w", password]);
        let config: Config = toml::from_str(&text).unwrap_or_else(|error| {
            panic!("{password} produced a config volto cannot parse: {error}\n{text}")
        });

        assert_eq!(config.auth.users.len(), 1, "{text}");
        assert_eq!(config.auth.users[0].username, "alice");
        assert_eq!(
            config.auth.users[0].password, password,
            "the password must reach the config verbatim:\n{text}"
        );
    }
}

/// The two characters the generator genuinely cannot carry must be refused, and
/// refused with a message that names them.
///
/// `|` is the delimiter of the substitutions that build the config, so it used
/// to end the `s` command early and abort the run with `sed: bad flag in
/// substitute command`. `&` expands to the whole matched line in a sed
/// replacement, so it used to write a mangled credential line. Both now stop at
/// the check, on `--print-config` as much as on a real install — that path used
/// to skip the character check entirely.
#[test]
fn credentials_with_a_pipe_or_an_ampersand_are_refused() {
    for argument in ["-w", "-u"] {
        for value in ["a|b", "p&ssword"] {
            let (ok, stdout, stderr) = print_config(&[argument, value]);

            assert!(!ok, "{argument} {value} must be refused, got:\n{stdout}");
            assert!(
                stderr.contains("must not contain a pipe or an ampersand"),
                "the refusal must name the characters, got: {stderr}"
            );
        }
    }
}

/// The question this crate cannot answer for itself: parsing the generated text
/// here proves *this* build reads it, and the host runs the binary the installer
/// was handed. So the script asks that binary, and this is the end-to-end shape
/// of the answer — the generator, the shipped example and a real volto agreeing
/// that what a first install writes is a file the service can start on.
#[test]
fn the_generated_configuration_is_one_the_binary_can_load() {
    let root = install_root("accepts");
    let script = repo_root().join("script/install-selfsigned.sh");

    let (ok, stdout, stderr) = run_check_config(&root, &script, &real_binary());

    assert!(ok, "the generated config must load: {stderr}");
    assert!(
        stdout.contains("loads on this volto"),
        "the run must say the config was checked: {stdout}"
    );

    let _ = fs::remove_dir_all(&root);
}

/// The drift this closes: the generated config is the shipped example with four
/// values substituted, every table in it is `deny_unknown_fields`, and one key
/// the binary does not know refuses the whole file rather than the key. Before
/// the check, that reached the host as a service looping under
/// `Restart=on-failure` with the answer only in the journal.
///
/// The example is corrupted in a copy of the whole `script/` directory, not in
/// the checkout: the installer resolves its siblings through `SCRIPT_DIR`, so
/// they have to move together.
#[test]
fn an_example_the_binary_cannot_load_is_refused_in_the_binarys_own_words() {
    let root = install_root("refuses");
    let script = plant_script_dir(&root, "\na_key_a_later_release_added = 2\n");

    let (ok, stdout, stderr) = run_check_config(&root, &script, &real_binary());

    assert!(
        !ok,
        "a config volto refuses must not be installed: {stdout}"
    );
    assert!(
        stderr.contains("unknown field"),
        "the binary's own account of the refusal must reach the operator: {stderr}"
    );
    assert!(
        stderr.contains("at line "),
        "including the position, which is the only thread back to the key: {stderr}"
    );
    assert!(
        stderr.contains("refusing to install a config volto cannot load"),
        "and the script must say what it did about it: {stderr}"
    );

    // The check happens before anything is written, so a refusal leaves nothing
    // for the "already exists, keeping it" branch to preserve on a later run.
    assert!(
        !root.join("etc/volto/config.toml").exists(),
        "a refused run must not leave a config behind"
    );

    let _ = fs::remove_dir_all(&root);
}

/// A binary that is not there must be refused with the flag that gets you out of
/// it, not only with the advice to build one.
///
/// The default `./target/release/volto` is a checkout's path. Run out of an
/// unpacked release tarball, where nothing has been built and the binary is
/// already sitting there, "build it first" was the whole message and it was the
/// wrong advice — the fix is `--binary ./volto`, which the message never named.
/// The same text guards the install path a few lines further down, which needs
/// root and so cannot be reached from here; this covers the wording for both.
#[test]
fn a_missing_binary_is_refused_with_the_flag_that_points_at_another_one() {
    let root = install_root("no-binary");
    let script = repo_root().join("script/install-selfsigned.sh");

    let (ok, stdout, stderr) = run_check_config(&root, &script, &root.join("nowhere/volto"));

    assert!(
        !ok,
        "a binary that is not on disk must stop the run: {stdout}"
    );
    assert!(
        stderr.contains("no volto binary at"),
        "the refusal must name the path it looked at: {stderr}"
    );
    assert!(
        stderr.contains("--binary"),
        "and the flag that points it somewhere else: {stderr}"
    );

    let _ = fs::remove_dir_all(&root);
}

/// The branch that decides whether the check may exist at all: a binary from
/// before the flag.
///
/// Such a volto answers `--check-config` with clap's usage error, and reading
/// that as "your configuration is broken" would turn every install with an older
/// binary into a failure — a new failure mode where there was none. So the flag
/// is looked for by name in the binary's own `--help` before it is used, and a
/// binary without it leaves the run exactly as it was before any of this existed.
///
/// The example carries the same unknown key as the test above, so a probe that
/// silently stopped working would show up here as a refusal rather than as a
/// quietly weaker check.
#[test]
fn a_binary_that_predates_the_flag_leaves_the_config_unchecked() {
    let root = install_root("too-old");
    let script = plant_script_dir(&root, "\na_key_a_later_release_added = 2\n");
    let binary = plant_binary_without_the_flag(&root, "volto-old");

    let (ok, stdout, stderr) = run_check_config(&root, &script, &binary);

    assert!(
        ok,
        "a binary that cannot be asked must not be treated as a refusal: {stderr}"
    );
    assert!(
        !stderr.contains("unexpected argument"),
        "the flag must never be tried on a binary whose help does not name it: {stderr}"
    );
    assert!(
        stdout.contains("predates --check-config"),
        "the run must say why the config went unchecked: {stdout}"
    );

    let _ = fs::remove_dir_all(&root);
}

/// Whether a user-id is short enough is volto's rule, not the installer's, and
/// the installer spells the number out anyway so the refusal arrives before a
/// certificate is generated. This is the only thing tying the two together.
///
/// `logfmt::MAX_TOKEN` is private to the crate, so the limit is asked of the
/// server through `Config::validate` rather than repeated a fourth time. If it
/// ever moves, the script keeps refusing at the old number and this fails,
/// naming the literal to change.
#[test]
fn the_username_limit_is_the_one_the_server_enforces() {
    let limit = longest_username_the_server_accepts();
    assert!(
        (1..256).contains(&limit),
        "the probe must have found a real limit, got {limit}"
    );

    // Exactly at the limit the installer must let the name through.
    let at_limit = "u".repeat(limit);
    let text = generated_config(&["-u", at_limit.as_str(), "-w", "hunter2"]);
    let config: Config = toml::from_str(&text).expect("parses");
    assert_eq!(config.auth.users[0].username.len(), limit);

    // One byte over, and it must refuse in the server's own number.
    let over_limit = "u".repeat(limit + 1);
    let (ok, stdout, stderr) = print_config(&["-u", over_limit.as_str(), "-w", "hunter2"]);
    assert!(!ok, "a user-id over the limit must be refused: {stdout}");
    assert!(
        stderr.contains(&format!("at most {limit} bytes")),
        "the refusal must carry the limit the server enforces: {stderr}"
    );
}

/// The longest user-id `Config::validate` accepts, asked of the server rather
/// than repeated from `logfmt::MAX_TOKEN`, which the test crate cannot see.
fn longest_username_the_server_accepts() -> usize {
    (1..256)
        .take_while(|length| server_accepts_username(&"u".repeat(*length)))
        .count()
}

/// Whether the server's user-id length rule lets `name` through.
///
/// The certificate paths deliberately do not exist, and that complaint comes
/// after the `[auth]` rules, so any error but the length one means the name got
/// past the rule being probed.
fn server_accepts_username(name: &str) -> bool {
    let text = format!(
        "[server]\n\
         listen = \"0.0.0.0:443\"\n\
         cert = \"/nonexistent/cert.pem\"\n\
         key = \"/nonexistent/key.pem\"\n\
         \n\
         [auth]\n\
         users = [{{ username = \"{name}\", password = \"placeholder\" }}]\n"
    );
    let config: Config = toml::from_str(&text).expect("the probe config must parse");

    match config.validate() {
        Ok(()) => true,
        Err(error) => !error.to_string().contains("byte limit"),
    }
}

/// `-h` must work and describe the safety-relevant flags.
#[test]
fn the_script_documents_itself() {
    let script = repo_root().join("script/install-selfsigned.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg("-h")
        .output()
        .expect("the script must run");

    assert!(output.status.success());
    let usage = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "--force",
        "--sni",
        "--username",
        "--print-config",
        "--check-config",
        "Re-running is safe",
    ] {
        assert!(
            usage.contains(expected),
            "usage must mention {expected}: {usage}"
        );
    }
}
