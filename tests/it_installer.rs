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
//! needs root, a Debian host and systemd. Six tests, starting with
//! `a_certificate_swap_that_fails_partway_puts_the_previous_pair_back`, run that
//! install path by putting stand-ins for those commands in front of `PATH`
//! (`plant_root_stubs`), with the real `install`, `mv` and `openssl`. What the
//! stand-ins replace, the user creation and the package install among them, is
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
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use scripts::{
    loadable_config_text, path_with_stubs, plant_binary_without_the_flag,
    plant_placeholder_certificates, real_binary, repo_root, scratch_tree, stderr_of, stdout_of,
    write_executable,
};
use volto::config::{Config, EXAMPLE_PLACEHOLDER_PASSWORD};

/// A stand-in for the host filesystem the installer writes into, carrying the
/// certificate and key the generated config names.
///
/// Nothing reads them: `Config::validate` insists both paths are files, which is
/// exactly the rule that makes `--check-config` unusable from a bare checkout and
/// the reason this seam exists at all.
fn install_root(name: &str) -> PathBuf {
    let root = scratch_tree("install", name, &["etc/volto"]);
    plant_placeholder_certificates(&root.join("etc/volto"));
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
        stdout_of(&output),
        stderr_of(&output),
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

    let ok = output.status.success();
    let stderr = stderr_of(&output);

    // Strict here, unlike `run_check_config`'s `stdout_of`: a generated
    // configuration that is not UTF-8 is the failure, and reading it lossily
    // would hide it behind whatever assertion looked at the text next. That
    // choice is why these two runners are two.
    let config = String::from_utf8(output.stdout).expect("the generated config must be UTF-8");

    (ok, config, stderr)
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
        !text.contains(EXAMPLE_PLACEHOLDER_PASSWORD),
        "the example placeholder password reached the generated config:\n{text}"
    );

    // The installer's second layer is its own `grep` for the placeholder, a
    // literal in the script; it is only a layer while it names the same string
    // the crate does.
    let script = fs::read_to_string(repo_root().join("script/install-selfsigned.sh"))
        .expect("the installer script must be readable");
    assert!(
        script.contains(&format!("'{EXAMPLE_PLACEHOLDER_PASSWORD}'")),
        "script/install-selfsigned.sh no longer greps for the crate's placeholder \
         password {EXAMPLE_PLACEHOLDER_PASSWORD:?}, so its refusal to install a file \
         that still carries it has drifted from the string the example ships"
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

/// `|` and `&` reach the config exactly as given, in the username and in the
/// password (R8-M1, R8-D2).
///
/// They were refused while the config was written by `sed`, where `|` was the
/// delimiter of the substitution and `&` expanded to the matched line. The
/// config is now written with `printf`, which takes a value as data, so both
/// are ordinary characters.
#[test]
fn credentials_with_a_pipe_or_an_ampersand_reach_the_config_verbatim() {
    for (username, password) in [
        ("a|b", "hunter2"),
        ("p&ul", "hunter2"),
        ("alice", "a|b|c"),
        ("alice", "p&ss&&word"),
        ("x|&y", "&|&"),
    ] {
        let text = generated_config(&["-u", username, "-w", password]);
        let config: Config = toml::from_str(&text).unwrap_or_else(|error| {
            panic!("{username:?} {password:?} produced a config volto cannot parse: {error}\n{text}")
        });

        assert_eq!(config.auth.users.len(), 1, "{text}");
        assert_eq!(config.auth.users[0].username, username, "{text}");
        assert_eq!(config.auth.users[0].password, password, "{text}");
    }
}

/// Writes, in `dir`, a wrapper for each of `tools` that records its arguments
/// in `dir/argv.log` and then runs the tool, and returns `dir` to put in front
/// of `PATH`.
///
/// A wrapper runs the stand-in of the same name in `stubs` when there is one,
/// and the host's tool otherwise. A tool the host does not have is skipped.
fn plant_argv_recorders(dir: &Path, stubs: Option<&Path>, tools: &[&str]) -> PathBuf {
    fs::create_dir_all(dir).expect("the recorder directory must be creatable");
    let log = dir.join("argv.log");
    for tool in tools {
        let target = match stubs.map(|stubs| stubs.join(tool)) {
            Some(stub) if stub.is_file() => stub,
            _ => match try_real_tool(tool) {
                Some(real) => real,
                None => continue,
            },
        };
        write_executable(
            &dir.join(tool),
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"{tool} $*\" >> '{}'\nexec '{}' \"$@\"\n",
                log.display(),
                target.display()
            ),
        );
    }
    dir.to_path_buf()
}

/// Every external command the installer runs, by name.
const INSTALLER_TOOLS: &[&str] = &[
    "sed", "grep", "awk", "head", "cut", "wc", "cat", "tr", "mktemp", "rm", "openssl", "install",
    "mv", "chown", "chgrp", "chmod", "date", "hostname", "id", "systemctl", "sleep", "useradd",
    "ufw", "dirname", "find", "cmp", "apt-get",
];

/// The password never appears on the argument vector of a program the
/// installer runs (R8-M1).
///
/// `/proc/<pid>/cmdline` is readable by every local user. The config used to
/// be written by `sed` with the password inside its script argument, and
/// checked by `grep -F` with the password as its pattern. Every external
/// command is wrapped here, on `--print-config` and on the full install path,
/// and none of them may have been handed the password.
#[test]
fn the_password_is_on_no_command_line_the_installer_runs() {
    const SECRET: &str = "argv-canary-4f1e9";
    let script = repo_root().join("script/install-selfsigned.sh");

    let print_root = scratch_tree("install", "argv-print", &[]);
    let recorders = plant_argv_recorders(&print_root.join("recorders"), None, INSTALLER_TOOLS);
    let output = Command::new("bash")
        .arg(&script)
        .args(["--print-config", "-u", "alice", "-w", SECRET])
        .current_dir(repo_root())
        .env("PATH", path_with_stubs(&recorders))
        .output()
        .expect("the installer script must be runnable");
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert!(
        stdout_of(&output).contains(SECRET),
        "the generated config must carry the password"
    );
    let log = fs::read_to_string(recorders.join("argv.log")).unwrap_or_default();
    assert!(
        log.lines().all(|line| !line.contains(SECRET)),
        "--print-config handed the password to another program:\n{log}"
    );

    let root = scratch_tree(
        "install",
        "argv-install",
        &["etc/volto", "usr/local/bin", "etc/systemd/system"],
    );
    let stubs = plant_root_stubs(&root, 0, "active");
    let recorders = plant_argv_recorders(&root.join("recorders"), Some(&stubs), INSTALLER_TOOLS);
    let output = Command::new("bash")
        .arg(&script)
        .args([
            "--binary",
            real_binary().to_str().expect("a UTF-8 path to the binary"),
            "-u",
            "alice",
        ])
        .current_dir(repo_root())
        .env("VOLTO_INSTALL_ROOT", &root)
        .env("PASSWORD", SECRET)
        .env("PATH", path_with_stubs(&recorders))
        .output()
        .expect("the installer script must be runnable");
    assert!(output.status.success(), "{}", stderr_of(&output));
    let config = fs::read_to_string(root.join("etc/volto/config.toml"))
        .expect("the install must have written a config");
    assert!(
        config.contains(&format!("password = \"{SECRET}\"")),
        "the installed config must carry the password from the environment:\n{config}"
    );
    let log = fs::read_to_string(recorders.join("argv.log")).unwrap_or_default();
    assert!(
        log.lines().any(|line| line.starts_with("openssl ")),
        "the recorders must have seen the install run: {log}"
    );
    assert!(
        log.lines().all(|line| !line.contains(SECRET)),
        "the install path handed the password to another program:\n{log}"
    );
}

/// The characters a double-quoted TOML string cannot carry as written, and the
/// usernames HTTP Basic cannot carry, must be refused by name.
///
/// A `"` or a `\` in either value would write a config line that is not valid
/// TOML, or one that means something else. A colon in a username cannot be told
/// apart from the separator in an RFC 7617 credential, and an empty username
/// names nobody. Each refusal must come from the check itself, on
/// `--print-config` as on a real install.
#[test]
fn credentials_toml_or_http_basic_cannot_carry_are_refused() {
    for (argument, value, refusal) in [
        ("-w", "pass\"word", "must not contain quotes or backslashes"),
        ("-u", "ali\"ce", "must not contain quotes or backslashes"),
        ("-w", "pass\\word", "must not contain quotes or backslashes"),
        ("-u", "ali\\ce", "must not contain quotes or backslashes"),
        ("-u", "ali:ce", "username must not contain a colon"),
        ("-u", "", "username must not be empty"),
        ("-w", "pass\u{1}word", "must not contain control characters"),
        ("-u", "ali\u{7f}ce", "must not contain control characters"),
    ] {
        let (ok, stdout, stderr) = print_config(&[argument, value]);

        assert!(!ok, "{argument} {value:?} must be refused, got:\n{stdout}");
        assert!(
            stderr.contains(refusal),
            "{argument} {value:?} must be refused with `{refusal}`, got: {stderr}"
        );
    }
}

/// The Surge policy line carries the pair as `username=..., password=...` on
/// one line, so a comma or any whitespace in either value cannot be expressed
/// there. A value the policy line cannot carry would install a proxy Surge
/// cannot reach with the credentials the installer just printed.
#[test]
fn credentials_the_surge_policy_line_cannot_carry_are_refused() {
    for (argument, value) in [
        ("-u", "a,b"),
        ("-u", "a b"),
        ("-w", "pass,word"),
        ("-w", " pass"),
    ] {
        let (ok, stdout, stderr) = print_config(&[argument, value]);

        assert!(!ok, "{argument} {value} must be refused, got:\n{stdout}");
        assert!(
            stderr.contains("must not contain a comma or whitespace"),
            "the refusal must name the characters, got: {stderr}"
        );
    }
}

/// A port the install path would refuse must be refused before the print and
/// check flags return, because those flags print or load the config that names
/// it. `--print-config --port 99999` used to print a configuration the install
/// path would then reject.
#[test]
fn an_unusable_port_is_refused_before_the_print_and_check_flags() {
    let (ok, stdout, stderr) = print_config(&["-p", "99999"]);
    assert!(
        !ok,
        "--print-config must refuse a port out of range, got:\n{stdout}"
    );
    assert!(
        stderr.contains("port out of range: 99999"),
        "the refusal must name the range: {stderr}"
    );

    let (ok, stdout, stderr) = print_config(&["-p", "abc"]);
    assert!(
        !ok,
        "--print-config must refuse a port that is not a number, got:\n{stdout}"
    );
    assert!(
        stderr.contains("port must be a number"),
        "the refusal must say what is wrong: {stderr}"
    );

    let (ok, _, stderr) = print_config(&["-p", "4433"]);
    assert!(ok, "a usable port must still print a config: {stderr}");
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

/// The first executable called `name` on the inherited `PATH`.
///
/// Resolved before the stubs below go in front of it, so a wrapper can hand its
/// arguments to the real tool by absolute path.
fn real_tool(name: &str) -> PathBuf {
    try_real_tool(name).unwrap_or_else(|| panic!("no {name} on PATH"))
}

/// [`real_tool`], or `None` when the host has no such tool.
fn try_real_tool(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").expect("PATH must be set");
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Writes stand-ins for the commands the install path needs root or a Debian
/// host for, and an `mv` that fails on its `fail_at`-th call. Returns the
/// directory to put in front of `PATH`.
///
/// `id -u` prints 0 and `id -u volto` succeeds, so the root check passes and no
/// user is created. `apt-get` is only looked up before the certificate step.
/// `systemctl` reports `service_status` for `is-active`: the `--quiet` form
/// exits 0 only when the status is `active`, the plain form prints the status
/// and exits 0, and every other invocation exits 0; every call is recorded in
/// `systemctl.log` beside it. `chown` changes nothing and records its arguments
/// in `chown.log`. `install` records its arguments in `install.log`, drops its
/// `-o` and `-g` arguments, which name a user this host does not have, and runs
/// the real `install`. `mv` counts its calls in `mv-calls` beside it.
fn plant_root_stubs(root: &Path, fail_at: usize, service_status: &str) -> PathBuf {
    let dir = root.join("stubs");
    fs::create_dir_all(&dir).expect("the stub directory must be creatable");

    write_executable(
        &dir.join("id"),
        "#!/bin/sh\nif [ \"$#\" -eq 1 ] && [ \"$1\" = -u ]; then echo 0; fi\nexit 0\n",
    );
    write_executable(
        &dir.join("systemctl"),
        &format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> '{log}'\n\
             if [ \"$1\" = is-active ]; then\n\
             \x20 if [ \"$2\" = --quiet ]; then\n\
             \x20   [ \"{service_status}\" = active ] || exit 1\n\
             \x20   exit 0\n\
             \x20 fi\n\
             \x20 echo \"{service_status}\"\n\
             \x20 exit 0\n\
             fi\n\
             exit 0\n",
            log = dir.join("systemctl.log").display(),
        ),
    );
    write_executable(&dir.join("apt-get"), "#!/bin/sh\nexit 0\n");
    write_executable(
        &dir.join("chown"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n",
            dir.join("chown.log").display()
        ),
    );
    write_executable(
        &dir.join("install"),
        &format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> '{log}'\n\
             skip=\n\
             for arg do\n\
             \x20 shift\n\
             \x20 if [ -n \"$skip\" ]; then skip=; continue; fi\n\
             \x20 case \"$arg\" in -o|-g) skip=1; continue ;; esac\n\
             \x20 set -- \"$@\" \"$arg\"\n\
             done\n\
             exec '{}' \"$@\"\n",
            real_tool("install").display(),
            log = dir.join("install.log").display(),
        ),
    );
    write_executable(
        &dir.join("mv"),
        &format!(
            "#!/bin/sh\n\
             count_file='{count}'\n\
             n=$(( $(cat \"$count_file\" 2>/dev/null || echo 0) + 1 ))\n\
             echo \"$n\" >\"$count_file\"\n\
             if [ \"$n\" -eq {fail_at} ]; then\n\
             \x20 echo \"mv stub: forced failure on call $n\" >&2\n\
             \x20 exit 1\n\
             fi\n\
             exec '{real}' \"$@\"\n",
            count = dir.join("mv-calls").display(),
            real = real_tool("mv").display(),
        ),
    );
    dir
}

/// A failed rename in the certificate swap must leave the configured paths
/// holding the pair they held before the run.
///
/// The swap is four renames: the old certificate and the old key to their
/// backups, then the new certificate and the new key into place. Each call of
/// the loop forces one of them to fail. Without the rollback, a failure at the
/// second leaves the old key with no certificate, and a failure at the third or
/// fourth leaves the new certificate or no certificate beside the old key's
/// backup. The service keeps the pair it loaded, so the next restart is the one
/// that fails.
///
/// The counter is asserted because a run that stopped before the swap would
/// leave the old pair in place too, and would pass for the wrong reason.
#[test]
fn a_certificate_swap_that_fails_partway_puts_the_previous_pair_back() {
    let script = repo_root().join("script/install-selfsigned.sh");

    for fail_at in 1..=4 {
        let root = scratch_tree(
            "install",
            &format!("swap-fails-at-{fail_at}"),
            &["etc/volto", "usr/local/bin"],
        );
        let conf_dir = root.join("etc/volto");
        let (cert, key) = plant_placeholder_certificates(&conf_dir);
        let old_cert = fs::read(&cert).expect("the old certificate must be readable");
        let old_key = fs::read(&key).expect("the old key must be readable");

        let binary = plant_binary_without_the_flag(&root, "volto-stub");
        let stubs = plant_root_stubs(&root, fail_at, "active");

        let output = Command::new("bash")
            .arg(&script)
            .args([
                "--force",
                "--sni",
                "volto.test",
                "--binary",
                binary.to_str().expect("a UTF-8 path to the binary"),
                "-u",
                "alice",
                "-w",
                "correct-horse-battery",
            ])
            .current_dir(repo_root())
            .env("VOLTO_INSTALL_ROOT", &root)
            .env("PATH", path_with_stubs(&stubs))
            .output()
            .expect("the installer script must be runnable");
        let stderr = stderr_of(&output);

        assert!(
            !output.status.success(),
            "rename {fail_at} failed, so the run must fail: {stderr}"
        );
        let calls: usize = fs::read_to_string(stubs.join("mv-calls"))
            .unwrap_or_else(|error| panic!("the run never reached the swap: {error}\n{stderr}"))
            .trim()
            .parse()
            .expect("the call count must be a number");
        assert!(
            calls >= fail_at
                && stderr.contains(&format!("mv stub: forced failure on call {fail_at}")),
            "the forced failure must be the one at rename {fail_at}: {stderr}"
        );

        assert_eq!(
            fs::read(&cert).ok(),
            Some(old_cert),
            "after a failure at rename {fail_at} the old certificate must be back at {}: {stderr}",
            cert.display()
        );
        assert_eq!(
            fs::read(&key).ok(),
            Some(old_key),
            "after a failure at rename {fail_at} the old key must be back at {}: {stderr}",
            key.display()
        );

        let mut leftovers: Vec<String> = fs::read_dir(&conf_dir)
            .expect("the configuration directory must be readable")
            .map(|entry| entry.expect("directory entry").file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".new") || name.ends_with(".bak"))
            .collect();
        leftovers.sort();
        assert!(
            leftovers.is_empty(),
            "after a failure at rename {fail_at} no new or backup file may stay behind, found {leftovers:?}: {stderr}"
        );
        assert!(
            stderr.contains("installing the new certificate failed"),
            "the run must say the swap failed: {stderr}"
        );
    }
}

/// A `chown` that fails when it is given the certificate pair, and succeeds on
/// the directory before it, so the run reaches the certificate transaction.
const CHOWN_FAILS_ON_THE_PAIR: &str =
    "#!/bin/sh\ncase \"$*\" in *cert.pem*) exit 1 ;; esac\nexit 0\n";

/// A failure at the ownership change must also put the previous pair back.
///
/// The ERR trap covered the four renames and was disarmed before `chown`. A
/// failure there ended the run with the new pair in place, owned by root with
/// the key at mode 0640, which the service user cannot read; the next restart
/// fails. The transaction now covers ownership and mode.
#[test]
fn a_failed_ownership_change_restores_the_previous_certificate_pair() {
    let root = scratch_tree(
        "install",
        "chown-fails",
        &["etc/volto", "usr/local/bin", "etc/systemd/system"],
    );
    let conf_dir = root.join("etc/volto");
    let (cert, key) = plant_placeholder_certificates(&conf_dir);
    let old_cert = fs::read(&cert).expect("the old certificate must be readable");
    let old_key = fs::read(&key).expect("the old key must be readable");

    let stubs = plant_root_stubs(&root, 0, "active");
    write_executable(&stubs.join("chown"), CHOWN_FAILS_ON_THE_PAIR);

    let output = run_full_install_with_stubs(&root, &stubs, &["--force"]);
    let stderr = stderr_of(&output);

    assert!(
        !output.status.success(),
        "a failed chown must fail the install: {stderr}"
    );
    assert!(
        stderr.contains("installing the new certificate failed"),
        "the run must say the certificate install failed: {stderr}"
    );
    assert_eq!(
        fs::read(&cert).ok(),
        Some(old_cert),
        "the old certificate must be back at {}: {stderr}",
        cert.display()
    );
    assert_eq!(
        fs::read(&key).ok(),
        Some(old_key),
        "the old key must be back at {}: {stderr}",
        key.display()
    );

    let mut leftovers: Vec<String> = fs::read_dir(&conf_dir)
        .expect("the configuration directory must be readable")
        .map(|entry| entry.expect("directory entry").file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".new") || name.ends_with(".bak"))
        .collect();
    leftovers.sort();
    assert!(
        leftovers.is_empty(),
        "after a failed chown no new or backup file may stay behind, found {leftovers:?}: {stderr}"
    );
}

/// A failed ownership change removes every new file it cannot replace with an
/// old one, and says only what it did.
///
/// On a first install there is no previous pair, so the rollback must remove
/// both the new certificate and the new key. On a host that had a certificate
/// but no key, the old certificate goes back and the new key must go, or the
/// old certificate is left beside a key that does not match it. In both cases
/// the message must name what was restored and what was removed.
#[test]
fn a_failed_ownership_change_removes_a_new_key_with_no_previous_one() {
    for (name, plant_cert) in [("chown-fails-first", false), ("chown-fails-no-key", true)] {
        let root = scratch_tree(
            "install",
            name,
            &["etc/volto", "usr/local/bin", "etc/systemd/system"],
        );
        let conf_dir = root.join("etc/volto");
        let cert = conf_dir.join("cert.pem");
        let key = conf_dir.join("key.pem");
        if plant_cert {
            fs::write(&cert, "the old certificate\n").expect("cert must be writable");
        }

        let stubs = plant_root_stubs(&root, 0, "active");
        write_executable(&stubs.join("chown"), CHOWN_FAILS_ON_THE_PAIR);

        let output = run_full_install_with_stubs(&root, &stubs, &[]);
        let stderr = stderr_of(&output);

        assert!(
            !output.status.success(),
            "{name}: a failed chown must fail the install: {stderr}"
        );
        assert!(
            !key.exists(),
            "{name}: the new key must be removed, it has no previous key to give way to: {stderr}"
        );
        if plant_cert {
            assert_eq!(
                fs::read_to_string(&cert).ok().as_deref(),
                Some("the old certificate\n"),
                "{name}: the old certificate must be back: {stderr}"
            );
            assert!(
                stderr.contains(&format!("restored the previous {}", cert.display()))
                    && stderr.contains(&format!("removed the new {}", key.display())),
                "{name}: the message must say the certificate was restored and the new key removed: {stderr}"
            );
        } else {
            assert!(
                !cert.exists(),
                "{name}: the new certificate must be removed on a first install: {stderr}"
            );
            assert!(
                stderr.contains(&format!(
                    "removed the new {} and {}",
                    cert.display(),
                    key.display()
                )) && !stderr.contains("restored"),
                "{name}: the message must say both new files were removed and nothing restored: {stderr}"
            );
        }
    }
}

/// Runs the full install path with the given service status, relocating every
/// install path under `root`.
///
/// The real binary is installed and asked whether it can load the generated
/// config, so this exercises the generator, the certificate, the unit install
/// and the service check as one run.
fn run_full_install(root: &Path, service_status: &str) -> std::process::Output {
    let stubs = plant_root_stubs(root, 0, service_status);
    run_full_install_with_stubs(root, &stubs, &[])
}

/// Runs the full install path with `stubs` in front of `PATH`, which a test uses
/// to replace one of the stand-ins the builder wrote.
fn run_full_install_with_stubs(
    root: &Path,
    stubs: &Path,
    extra_args: &[&str],
) -> std::process::Output {
    let script = repo_root().join("script/install-selfsigned.sh");

    Command::new("bash")
        .arg(&script)
        .args([
            "--binary",
            real_binary().to_str().expect("a UTF-8 path to the binary"),
            "-u",
            "alice",
            "-w",
            "correct-horse-battery",
        ])
        .args(extra_args)
        .current_dir(repo_root())
        .env("VOLTO_INSTALL_ROOT", root)
        .env("PATH", path_with_stubs(stubs))
        .output()
        .expect("the installer script must be runnable")
}

/// A service that failed to start must turn the install into a failure.
///
/// The installer read `systemctl is-active` with `|| true`, printed the status
/// and exited 0 even when the service failed to start. A port already bound
/// leaves the host without a proxy while the installer reports success. The
/// report and the security notes still print, so the operator has the
/// fingerprint and the policy line before the refusal.
#[test]
fn an_install_whose_service_failed_is_not_reported_as_success() {
    let root = scratch_tree(
        "install",
        "service-failed",
        &["etc/volto", "usr/local/bin", "etc/systemd/system"],
    );

    let output = run_full_install(&root, "failed");

    assert!(
        !output.status.success(),
        "an install that leaves the service not running must fail: {}",
        stdout_of(&output)
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("volto is failed after the install"),
        "the refusal must name the status: {stderr}"
    );
    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("==> done"),
        "the report must print before the refusal, so the fingerprint and the \
         policy line reach the operator: {stdout}"
    );
}

/// And a service that is active still succeeds, with the report printed.
#[test]
fn an_install_whose_service_is_active_reports_success() {
    let root = scratch_tree(
        "install",
        "service-active",
        &["etc/volto", "usr/local/bin", "etc/systemd/system"],
    );

    let output = run_full_install(&root, "active");

    assert!(output.status.success(), "{}", stderr_of(&output));
    assert!(
        stdout_of(&output).contains("==> done"),
        "the report must print: {}",
        stdout_of(&output)
    );
}

/// A configured host for the re-run tests: a config the real binary loads with
/// `body` appended, its certificate pair, an installed binary that reports an
/// old version, and an installed unit.
fn configured_root(name: &str, body: &str) -> PathBuf {
    let root = scratch_tree(
        "install",
        name,
        &["etc/volto", "usr/local/bin", "etc/systemd/system"],
    );
    let dir = root.join("etc/volto");
    let (cert, key) = plant_placeholder_certificates(&dir);
    fs::write(
        dir.join("config.toml"),
        loadable_config_text(&cert, &key, "127.0.0.1:4433", "planted", body),
    )
    .expect("config must be writable");
    write_executable(&root.join("usr/local/bin/volto"), OLD_BINARY);
    fs::write(root.join("etc/systemd/system/volto.service"), OLD_UNIT)
        .expect("the unit must be writable");
    root
}

/// The installed binary and unit [`configured_root`] plants.
const OLD_BINARY: &str = "#!/bin/sh\necho 'volto 0.0.1'\n";
const OLD_UNIT: &str = "# the installed unit\n";

/// What the stand-in `systemctl` was asked, one call per line.
fn systemctl_calls(stubs: &Path) -> String {
    fs::read_to_string(stubs.join("systemctl.log")).unwrap_or_default()
}

/// A re-run on a host that already has a config leaves the binary and the unit
/// alone and does not restart the service (R8-M2).
///
/// The installer used to install `--binary` over `/usr/local/bin/volto` and the
/// unit over the installed one on every run, with no config check and no
/// `.prev`, and then restart. A re-run to regenerate a certificate from a
/// checkout holding an older build downgraded the binary. With `--force` the
/// certificate is regenerated and the running service reloaded, which keeps
/// its tunnels.
#[test]
fn a_rerun_on_a_configured_host_keeps_the_binary_and_the_unit() {
    for (name, args) in [
        ("rerun-plain", &[][..]),
        ("rerun-force", &["--force"][..]),
    ] {
        let root = configured_root(name, "");
        let stubs = plant_root_stubs(&root, 0, "active");

        let output = run_full_install_with_stubs(&root, &stubs, args);

        let stderr = stderr_of(&output);
        assert!(output.status.success(), "{name}: {stderr}");
        assert_eq!(
            fs::read_to_string(root.join("usr/local/bin/volto")).ok().as_deref(),
            Some(OLD_BINARY),
            "{name}: the installed binary must be kept: {stderr}"
        );
        assert_eq!(
            fs::read_to_string(root.join("etc/systemd/system/volto.service"))
                .ok()
                .as_deref(),
            Some(OLD_UNIT),
            "{name}: the installed unit must be kept: {stderr}"
        );
        assert!(
            !root.join("usr/local/bin/volto.prev").exists(),
            "{name}: nothing was replaced, so nothing is kept as .prev"
        );
        let calls = systemctl_calls(&stubs);
        assert!(
            !calls.contains("restart")
                && !calls.contains("start volto")
                && !calls.contains("daemon-reload"),
            "{name}: the service must not be restarted: {calls}"
        );
        assert_eq!(
            calls.contains("reload volto"),
            name == "rerun-force",
            "{name}: only a regenerated certificate reloads the service: {calls}"
        );
        assert!(
            stdout_of(&output).contains("kept the installed binary and unit"),
            "{name}: the run must say what it kept: {}",
            stdout_of(&output)
        );
    }
}

/// `--replace-binary` asks the new binary about the existing config before
/// anything moves, and a refusal leaves the host as it was.
#[test]
fn replacing_the_binary_is_refused_when_it_cannot_load_the_existing_config() {
    let root = configured_root("replace-refused", "\n[limits]\na_key_a_later_release_added = 2\n");
    let stubs = plant_root_stubs(&root, 0, "active");
    let old_cert = fs::read(root.join("etc/volto/cert.pem")).expect("the certificate");

    let output = run_full_install_with_stubs(&root, &stubs, &["--replace-binary", "--force"]);

    let stderr = stderr_of(&output);
    assert!(!output.status.success(), "{}", stdout_of(&output));
    assert!(
        stderr.contains("unknown field") && stderr.contains("over a config it cannot load"),
        "the binary's own refusal must reach the operator: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(root.join("usr/local/bin/volto")).ok().as_deref(),
        Some(OLD_BINARY),
        "the installed binary must be untouched: {stderr}"
    );
    assert_eq!(
        fs::read(root.join("etc/volto/cert.pem")).ok(),
        Some(old_cert),
        "the refusal comes before the certificate step: {stderr}"
    );
    assert!(!root.join("usr/local/bin/volto.prev").exists());
    assert_eq!(systemctl_calls(&stubs), "", "the service must be left alone");
}

/// `--replace-binary` with a binary that loads the config keeps the previous
/// binary and unit as `.prev`, the way `deploy.sh` does, and restarts.
#[test]
fn replacing_the_binary_keeps_the_previous_one_and_restarts() {
    let root = configured_root("replace-accepted", "");
    let stubs = plant_root_stubs(&root, 0, "active");
    fs::write(root.join("usr/local/bin/volto.prev"), "a stale previous binary\n")
        .expect("the stale .prev must be writable");

    let output = run_full_install_with_stubs(&root, &stubs, &["--replace-binary"]);

    let stderr = stderr_of(&output);
    assert!(output.status.success(), "{stderr}");
    assert_eq!(
        fs::read(root.join("usr/local/bin/volto")).ok(),
        fs::read(real_binary()).ok(),
        "the new binary must be installed"
    );
    assert_eq!(
        fs::read_to_string(root.join("usr/local/bin/volto.prev")).ok().as_deref(),
        Some(OLD_BINARY),
        "the previous binary must be kept, not a stale .prev: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(root.join("etc/systemd/system/volto.service.prev"))
            .ok()
            .as_deref(),
        Some(OLD_UNIT),
        "the previous unit must be kept"
    );
    assert_eq!(
        fs::read(root.join("etc/systemd/system/volto.service")).ok(),
        fs::read(repo_root().join("script/masque.service")).ok(),
        "the shipped unit must be installed"
    );
    let calls = systemctl_calls(&stubs);
    assert!(
        calls.contains("daemon-reload\n") && calls.contains("restart volto\n"),
        "the service must be restarted on the new files: {calls}"
    );
}

/// A failed restart after `--replace-binary` puts the previous binary and unit
/// back and starts the service on them.
#[test]
fn a_replaced_binary_that_fails_to_restart_is_rolled_back() {
    let root = configured_root("replace-rollback", "");
    let stubs = plant_root_stubs(&root, 0, "active");
    write_executable(
        &stubs.join("systemctl"),
        &format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> '{}'\n\
             case \"$*\" in\n\
             \x20 'restart volto') exit 1 ;;\n\
             \x20 'is-active volto') echo active ;;\n\
             esac\n\
             exit 0\n",
            stubs.join("systemctl.log").display()
        ),
    );

    let output = run_full_install_with_stubs(&root, &stubs, &["--replace-binary"]);

    let stderr = stderr_of(&output);
    assert!(!output.status.success(), "{}", stdout_of(&output));
    assert!(
        stderr.contains("restored the previous binary and unit"),
        "the run must say what it restored: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(root.join("usr/local/bin/volto")).ok().as_deref(),
        Some(OLD_BINARY),
        "the previous binary must be back: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(root.join("etc/systemd/system/volto.service"))
            .ok()
            .as_deref(),
        Some(OLD_UNIT),
        "the previous unit must be back: {stderr}"
    );
    assert!(
        systemctl_calls(&stubs).ends_with("restart volto\ndaemon-reload\nstart volto\n"),
        "the rollback reloads systemd and starts the service: {}",
        systemctl_calls(&stubs)
    );
}

/// A first install writes the root-owned layout: `/etc/volto` root:volto 0750,
/// the config and the key root:volto 0640, the certificate root:volto 0644
/// (R8-M3).
///
/// The installer used to give the directory and every file in it to the
/// service user, and then wrote, renamed, chowned and chmodded by name inside
/// a directory that user could change. The stand-in `chown` and `install`
/// record what they were asked, since this host has no `volto` group.
#[test]
fn a_first_install_writes_the_root_owned_layout() {
    let root = scratch_tree(
        "install",
        "layout",
        &["etc/volto", "usr/local/bin", "etc/systemd/system"],
    );
    let stubs = plant_root_stubs(&root, 0, "active");

    let output = run_full_install_with_stubs(&root, &stubs, &["--sni", "volto.test"]);

    assert!(output.status.success(), "{}", stderr_of(&output));
    let dir = root.join("etc/volto");
    let chown = fs::read_to_string(stubs.join("chown.log")).unwrap_or_default();
    assert!(
        chown.contains(&format!("root:volto {}\n", dir.display()))
            && chown.contains(&format!(
                "root:volto {} {}\n",
                dir.join("cert.pem").display(),
                dir.join("key.pem").display()
            ))
            && !chown.contains("volto:volto"),
        "the directory and the pair must go to root:volto: {chown}"
    );
    let install = fs::read_to_string(stubs.join("install.log")).unwrap_or_default();
    assert!(
        install.lines().any(|line| line.starts_with("-o root -g volto -m 0640 ")
            && line.ends_with(&format!(" {}", dir.join("config.toml").display()))),
        "the config must be installed root:volto 0640: {install}"
    );
    assert!(!install.contains("-o volto"), "{install}");
    let mode = |name: &str| {
        fs::metadata(dir.join(name))
            .expect("installed file")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode("cert.pem"), 0o644);
    assert_eq!(mode("key.pem"), 0o640);
    assert_eq!(mode("config.toml"), 0o640);
    assert_eq!(
        fs::metadata(&dir).expect("the directory").permissions().mode() & 0o777,
        0o750
    );
}

/// A symbolic link where the key belongs is refused, and the file it points at
/// is not changed (R8-M3).
///
/// While the service user owned `/etc/volto` it could replace `key.pem` with a
/// link to a file of root's and delete `config.toml`; the next run took the
/// first-install path, kept the "existing" pair because `test -f` follows the
/// link, and its `chown` and `chmod` then acted on the link's target.
#[test]
fn a_symbolic_link_in_place_of_the_key_is_refused() {
    let root = scratch_tree(
        "install",
        "key-symlink",
        &["etc/volto", "usr/local/bin", "etc/systemd/system", "outside"],
    );
    let dir = root.join("etc/volto");
    fs::write(dir.join("cert.pem"), "not a certificate\n").expect("plant the certificate");
    let target = root.join("outside/shadow");
    fs::write(&target, "root's file\n").expect("plant the link target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
    std::os::unix::fs::symlink(&target, dir.join("key.pem")).expect("plant the link");
    let stubs = plant_root_stubs(&root, 0, "active");

    let output = run_full_install_with_stubs(&root, &stubs, &["--sni", "volto.test"]);

    let stderr = stderr_of(&output);
    assert!(!output.status.success(), "{}", stdout_of(&output));
    assert!(
        stderr.contains("is a symbolic link; refusing to use it"),
        "the refusal must say why: {stderr}"
    );
    assert_eq!(
        fs::metadata(&target).expect("the target").permissions().mode() & 0o777,
        0o600,
        "the link's target must keep its mode: {stderr}"
    );
    let chown = fs::read_to_string(stubs.join("chown.log")).unwrap_or_default();
    assert!(!chown.contains("key.pem"), "nothing may chown through the link: {chown}");
    assert!(!dir.join("config.toml").exists(), "no config may be written");
}

/// The certificate name must be a host name before it reaches openssl
/// (R8-L8).
///
/// `--sni 'a.example,IP:192.0.2.1'` put an IP address into the certificate's
/// subjectAltName, a `/` added subject fields to `-subj`, and either went into
/// the printed policy line as well.
#[test]
fn a_certificate_name_that_is_not_a_host_name_is_refused() {
    let long_label = format!("{}.example", "a".repeat(64));
    let too_long = vec!["abcdefghi"; 26].join(".");
    for name in [
        "a.example,IP:192.0.2.1",
        "a.example/O=Somebody",
        "-leading.example",
        "trailing-.example",
        "a..example",
        ".example",
        "example.",
        "192.0.2.1",
        "under_score.example",
        "spa ce.example",
        long_label.as_str(),
        too_long.as_str(),
    ] {
        let root = scratch_tree(
            "install",
            "bad-sni",
            &["etc/volto", "usr/local/bin", "etc/systemd/system"],
        );
        let stubs = plant_root_stubs(&root, 0, "active");
        let output = run_full_install_with_stubs(&root, &stubs, &["--sni", name]);

        let stderr = stderr_of(&output);
        assert!(!output.status.success(), "{name:?} must be refused: {}", stdout_of(&output));
        assert!(
            stderr.contains("the certificate name must be a host name"),
            "{name:?}: the refusal must say why: {stderr}"
        );
        assert!(
            !root.join("etc/volto/cert.pem").exists(),
            "{name:?}: no certificate may be generated"
        );
    }

    for name in ["volto.test", "a-b.example", "x", "A1.example.org"] {
        let root = scratch_tree(
            "install",
            "good-sni",
            &["etc/volto", "usr/local/bin", "etc/systemd/system"],
        );
        let stubs = plant_root_stubs(&root, 0, "active");
        let output = run_full_install_with_stubs(&root, &stubs, &["--sni", name]);
        assert!(output.status.success(), "{name:?}: {}", stderr_of(&output));
    }
}

/// The generated EC certificate asserts digitalSignature and not
/// keyEncipherment (R8-L9).
///
/// RFC 8446 section 4.4.2.2 asks that "the digitalSignature bit MUST be set if
/// the Key Usage extension is present". keyEncipherment is the RSA key
/// transport bit, which a P-256 key cannot perform.
#[test]
fn the_generated_certificate_asserts_only_digital_signature() {
    let root = scratch_tree(
        "install",
        "key-usage",
        &["etc/volto", "usr/local/bin", "etc/systemd/system"],
    );
    let stubs = plant_root_stubs(&root, 0, "active");
    let output = run_full_install_with_stubs(&root, &stubs, &["--sni", "volto.test"]);
    assert!(output.status.success(), "{}", stderr_of(&output));

    let text = Command::new("openssl")
        .args(["x509", "-noout", "-text", "-in"])
        .arg(root.join("etc/volto/cert.pem"))
        .output()
        .expect("openssl must be runnable");
    let text = stdout_of(&text);
    assert!(
        text.contains("Digital Signature"),
        "the certificate must assert digitalSignature:\n{text}"
    );
    assert!(
        !text.contains("Key Encipherment"),
        "an EC certificate must not assert keyEncipherment:\n{text}"
    );
}

/// The report must survive a certificate that openssl cannot read.
///
/// Under `set -euo pipefail` the plain assignments that read the fingerprint and
/// the expiry end the script when `openssl x509` fails. By that point the
/// certificate may have been regenerated and the service restarted, so the exit
/// is silent, prints no fingerprint, and lands exactly when every client's
/// pinned fingerprint has just gone stale. The report is the point of a re-run.
#[test]
fn an_unreadable_certificate_still_prints_the_report() {
    let root = scratch_tree(
        "install",
        "corrupt-certificate",
        &["etc/volto", "usr/local/bin", "etc/systemd/system"],
    );
    let conf_dir = root.join("etc/volto");
    fs::write(conf_dir.join("cert.pem"), "not a certificate\n").expect("cert must be writable");
    fs::write(conf_dir.join("key.pem"), "not a key\n").expect("key must be writable");

    let output = run_full_install(&root, "active");

    assert!(output.status.success(), "{}", stderr_of(&output));
    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("certificate: <unknown>"),
        "an unreadable certificate must print <unknown> rather than end the run: {stdout}"
    );
    assert!(
        stdout.contains("expires:     <unknown>"),
        "an unreadable expiry must print <unknown>: {stdout}"
    );
    assert!(
        stdout.contains("==> done"),
        "the report must print: {stdout}"
    );
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
    let usage = stdout_of(&output);
    for expected in [
        "--force",
        "--sni",
        "--username",
        "--print-config",
        "--check-config",
        "--replace-binary",
        "Re-running is safe",
    ] {
        assert!(
            usage.contains(expected),
            "usage must mention {expected}: {usage}"
        );
    }
}
