//! The self-signed installer must generate a configuration volto accepts.
//!
//! `script/install-selfsigned.sh` builds `/etc/volto/config.toml` by substituting
//! four values into the shipped example. A renamed key or a reflowed example
//! would let the script install a config the server rejects, or one that still
//! carries the example's placeholder password.
//!
//! The script's `--print-config` flag exists for this test: it runs the real
//! generation path, touches nothing, and needs no root. The rest of the script
//! needs root, a Debian host and systemd. The tests that run that install path
//! put stand-ins in front of `PATH` (`plant_root_stubs`): `id`, `apt-get`,
//! `systemctl` and `chown` answer for the host, and `install` and `mv` record
//! their calls, or fail on purpose, and run the host's own. `openssl` is the
//! host's. What the stand-ins replace, the user creation and the package
//! install among them, is covered by shellcheck plus review.
//!
//! `--check-config` is the second seam, and it closes the other half of the same
//! hazard: parsing the generated text here proves this crate can read it, which
//! is not the same question as whether the binary about to be installed can.
//! That one is only answerable by running it, so the script runs `volto
//! --check-config`, the same flag `script/deploy.sh` puts to a release before it
//! swaps a binary (D93, D94). `VOLTO_INSTALL_ROOT` relocates the installer's
//! paths the way `VOLTO_DEPLOY_ROOT` does for `deploy.sh`, so a temporary
//! directory can hold the certificate and key the generated config names.

#[path = "common/scripts.rs"]
mod scripts;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use scripts::{
    Scratch, loadable_config_text, path_with_stubs, plant_binary_without_the_flag,
    plant_placeholder_certificates, real_binary, real_tool, repo_root, run_within_deadline,
    scratch_tree, stderr_of, stdout_of, write_executable,
};
use volto::config::{Config, EXAMPLE_PLACEHOLDER_PASSWORD};

/// The installer in the checkout.
fn installer_script() -> PathBuf {
    repo_root().join("script/install-selfsigned.sh")
}

/// `bash script`, run from the checkout with a null stdin and without any
/// variable the installer reads from its environment.
///
/// The installer takes `BINARY`, `SNI`, `PORT`, `USERNAME`, `PASSWORD` and
/// `ECH_PUBLIC_NAME` from the environment, and `VOLTO_INSTALL_ROOT` relocates it, so a shell that
/// exports one of them would change every run. A caller sets what it means.
fn installer(script: &Path) -> Command {
    let mut command = Command::new(real_tool("bash"));
    command.arg(script);
    in_the_checkout_without_installer_variables(&mut command);
    command
}

/// Makes `command` run from the checkout with a null stdin and without the
/// variables [`installer`] names.
fn in_the_checkout_without_installer_variables(command: &mut Command) {
    command.current_dir(repo_root()).stdin(Stdio::null());
    for variable in [
        "BINARY",
        "SNI",
        "PORT",
        "USERNAME",
        "PASSWORD",
        "ECH_PUBLIC_NAME",
        "VOLTO_INSTALL_ROOT",
        "RUST_LOG",
        "JOURNAL_STREAM",
    ] {
        command.env_remove(variable);
    }
}

/// A stand-in for the host filesystem the installer writes into, carrying the
/// certificate and key the generated config names.
///
/// Nothing reads them: `Config::validate` insists both paths are files, which is
/// exactly the rule that makes `--check-config` unusable from a bare checkout and
/// the reason this seam exists at all.
fn install_root(name: &str) -> Scratch {
    let root = scratch_tree("install", name, &["etc/volto"]);
    plant_placeholder_certificates(&root.join("etc/volto"));
    root
}

/// A stand-in for a host before its first install: the directories the
/// installer writes into, under a scratch tree of this test's own.
fn host_root(name: &str) -> Scratch {
    scratch_tree(
        "install",
        name,
        &["etc/volto", "usr/local/bin", "etc/systemd/system"],
    )
}

/// Copies the installer, the example config and the unit into `root/script`
/// and appends `example_suffix` to the example config, returning the
/// installer's new path.
///
/// They travel together because the installer resolves the unit and the example
/// through `SCRIPT_DIR`, which is wherever the copy of the script being run sits.
fn plant_script_dir(root: &Path, example_suffix: &str) -> PathBuf {
    let dir = root.join("script");
    fs::create_dir_all(&dir).expect("the script directory must be creatable");

    for asset in [
        "install-selfsigned.sh",
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
    let output = run_within_deadline(
        installer(script)
            .args([
                "--check-config",
                "--binary",
                binary.to_str().expect("a UTF-8 path to the binary"),
                "-u",
                "alice",
                "-w",
                "correct-horse-battery",
            ])
            .env("VOLTO_INSTALL_ROOT", root),
    );

    (
        output.status.success(),
        stdout_of(&output),
        stderr_of(&output),
    )
}

/// Runs `--print-config` with the given arguments, returning its exit status,
/// standard output and standard error.
fn print_config(args: &[&str]) -> (bool, String, String) {
    let output = run_within_deadline(
        installer(&installer_script())
            .arg("--print-config")
            .args(args),
    );

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

    // The installer's own refusal is the second layer. An example that still
    // names the placeholder anywhere, a comment included, must be refused.
    let root = scratch_tree("install", "placeholder", &[]);
    let script = plant_script_dir(&root, &format!("\n# {EXAMPLE_PLACEHOLDER_PASSWORD}\n"));
    let output = run_within_deadline(installer(&script).args(["--print-config", "-w", "hunter2"]));
    assert!(
        !output.status.success()
            && stderr_of(&output).contains("the example placeholder password survived"),
        "an example that names the crate's placeholder password {EXAMPLE_PLACEHOLDER_PASSWORD:?} \
         must be refused: {}",
        stderr_of(&output)
    );

    // With no password given, one is generated, and it is not empty or trivial.
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

/// Credentials full of characters that mean something to a regular expression,
/// to `sed` or to a shell must reach the config unchanged.
///
/// The generated default is base64, so only an operator who chooses their own
/// credentials ever exercises this, and every one of these characters is
/// ordinary in a password. `generate_config` writes each value with `printf`
/// as data, and `verify_config` must then find the line it just wrote as text,
/// not as a pattern: `*` is the character that would break a pattern match.
#[test]
fn credentials_with_metacharacters_reach_the_config_verbatim() {
    for (username, password) in [
        ("alice", "Pa*ss.w0rd"),
        ("alice", "a+b.c*d"),
        ("alice", "^start$"),
        ("alice", "[brackets]"),
        ("a|b", "hunter2"),
        ("p&ul", "hunter2"),
        ("alice", "a|b|c"),
        ("alice", "p&ss&&word"),
        ("x|&y", "&|&"),
    ] {
        let text = generated_config(&["-u", username, "-w", password]);
        let config: Config = toml::from_str(&text).unwrap_or_else(|error| {
            panic!(
                "{username:?} {password:?} produced a config volto cannot parse: {error}\n{text}"
            )
        });

        assert_eq!(config.auth.users.len(), 1, "{text}");
        assert_eq!(config.auth.users[0].username, username, "{text}");
        assert_eq!(config.auth.users[0].password, password, "{text}");
    }
}

/// Writes, in `dir`, a recorder for each of `tools` that appends the tool's
/// name and arguments to `dir/argv.log` and then runs it: the stand-in of the
/// same name in `stubs` when there is one, the host's tool otherwise. Returns
/// `dir`, which a run then uses as its whole `PATH`.
fn plant_argv_recorders(dir: &Path, stubs: &Path, tools: &[&str]) -> PathBuf {
    fs::create_dir_all(dir).expect("the recorder directory must be creatable");
    let log = dir.join("argv.log");
    for tool in tools {
        let stub = stubs.join(tool);
        let target = if stub.is_file() {
            stub
        } else {
            real_tool(tool)
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

/// Every tool the installer runs on `--print-config` and on a first install,
/// and `cat`, which the stand-ins run as well. The list is what the runs of
/// [`the_password_is_on_no_command_line_the_installer_runs`] call, with
/// nothing else on `PATH`, and that test holds it to exactly that.
const INSTALLER_TOOLS: &[&str] = &[
    "awk",
    "cat",
    "chmod",
    "chown",
    "cut",
    "date",
    "dirname",
    "grep",
    "hostname",
    "id",
    "install",
    "mktemp",
    "mv",
    "openssl",
    "rm",
    "sleep",
    "systemctl",
    "ufw",
    "wc",
];

/// Looked up by the installer with `command -v` and never run.
const LOOKED_UP_ONLY: &[&str] = &["apt-get"];

/// Exports to the bash that `command` runs a `command_not_found_handle` that
/// appends the name of each command it could not find to `log`. bash 4 and
/// later run that function for every such command, one whose error output goes
/// to `/dev/null` included.
fn record_missing_commands<'a>(command: &'a mut Command, log: &Path) -> &'a mut Command {
    command.env(
        "BASH_FUNC_command_not_found_handle%%",
        format!(
            "() {{ printf '%s\\n' \"$1\" >> '{}'; return 127; }}",
            log.display()
        ),
    )
}

/// The password never appears on the argument vector of a program the
/// installer runs.
///
/// `/proc/<pid>/cmdline` is readable by every local user. Both runs here,
/// `--print-config` and a first install, have the recorders' directory as
/// their whole `PATH`, and every tool they run is recorded. A tool with no
/// recorder is not found and is named in `missing`, which fails the test, so
/// a new tool cannot take the password unseen. A tool called by its absolute
/// path is out of a recorder's reach; `the_installer_calls_no_tool_by_its_path`
/// holds the script to the calls that must be made that way.
#[test]
fn the_password_is_on_no_command_line_the_installer_runs() {
    const SECRET: &str = "argv-canary-4f1e9";
    let root = host_root("argv");
    let stubs = plant_root_stubs(&root, 0, "active");
    // An active firewall, so the run takes the branch that opens the port.
    write_executable(
        &stubs.join("ufw"),
        "#!/bin/sh\n[ \"$1\" = status ] && echo 'Status: active'\nexit 0\n",
    );
    let planted: Vec<&str> = INSTALLER_TOOLS
        .iter()
        .chain(LOOKED_UP_ONLY)
        .copied()
        .collect();
    let recorders = plant_argv_recorders(&root.join("recorders"), &stubs, &planted);
    let missing = root.join("missing");

    // A bash older than 4, such as the 3.2 macOS ships as /bin/bash, runs no
    // handle and records nothing. That fails here, naming the bash, rather
    // than letting the runs below pass with no tool recorded as missing.
    let bash = real_tool("bash");
    let probe = run_within_deadline(
        record_missing_commands(&mut Command::new(&bash), &missing)
            .args(["-c", "a-command-nobody-has 2>/dev/null; true"])
            .env("PATH", &recorders)
            .stdin(Stdio::null()),
    );
    assert!(probe.status.success(), "{}", stderr_of(&probe));
    assert_eq!(
        fs::read_to_string(&missing).ok().as_deref(),
        Some("a-command-nobody-has\n"),
        "this test needs a bash that runs command_not_found_handle (bash 4 or later), and \
         {}, the first bash on PATH, did not run it; put a newer bash ahead of it on PATH",
        bash.display()
    );
    fs::remove_file(&missing).expect("the probe's record must be removable");

    let output = run_within_deadline(
        record_missing_commands(&mut installer(&installer_script()), &missing)
            .args(["--print-config", "-u", "alice", "-w", SECRET])
            .env("PATH", &recorders),
    );
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert!(
        stdout_of(&output).contains(SECRET),
        "the generated config must carry the password"
    );

    let output = run_within_deadline(
        record_missing_commands(&mut installer(&installer_script()), &missing)
            .args([
                "--binary",
                real_binary().to_str().expect("a UTF-8 path to the binary"),
                "-u",
                "alice",
            ])
            .env("VOLTO_INSTALL_ROOT", &root)
            .env("PASSWORD", SECRET)
            .env("PATH", &recorders),
    );
    assert!(output.status.success(), "{}", stderr_of(&output));
    let config = fs::read_to_string(root.join("etc/volto/config.toml"))
        .expect("the install must have written a config");
    assert!(
        config.contains(&format!("password = \"{SECRET}\"")),
        "the installed config must carry the password from the environment:\n{config}"
    );

    assert_eq!(
        fs::read_to_string(&missing).unwrap_or_default(),
        "",
        "the installer ran a command that has no recorder; add it to INSTALLER_TOOLS"
    );
    let log = fs::read_to_string(recorders.join("argv.log")).unwrap_or_default();
    let ran: std::collections::BTreeSet<&str> = log
        .lines()
        .filter_map(|line| line.split(' ').next())
        .collect();
    let listed: std::collections::BTreeSet<&str> = INSTALLER_TOOLS.iter().copied().collect();
    assert_eq!(
        ran, listed,
        "INSTALLER_TOOLS must be the tools the two runs call, no more and no fewer"
    );
    assert!(
        log.lines().all(|line| !line.contains(SECRET)),
        "the installer handed the password to another program:\n{log}"
    );
}

/// The first word of each command in the shell line `line`: at its start,
/// after `$(`, `(`, a backtick, `|`, `&`, `;` or `{`, and past the words that
/// precede a command and any variable assignment.
fn command_words(line: &str) -> Vec<&str> {
    const KEYWORDS: [&str; 11] = [
        "if", "then", "else", "elif", "do", "while", "until", "!", "exec", "time", "command",
    ];
    line.split(['(', '`', '|', '&', ';', '{'])
        .filter_map(|segment| {
            segment.split_whitespace().find(|word| {
                !KEYWORDS.contains(word)
                    && !(word.contains('=') && !word.starts_with(['-', '"', '$', '[']))
            })
        })
        .collect()
}

/// The installer runs no tool by its absolute path, which a recorder on
/// `PATH` cannot see, except the three that must be: `"$BINARY"`, the volto it
/// was handed, asked for `--help` and `--check-config` and, with
/// `--ech-public-name`, for the ECH key (`ech-keygen`); `"$BIN"`, the
/// installed one, asked for `--version` and for the ECHConfigList of the key
/// the config names (`ech-config`); and `"$1"` in
/// `check_config_as_the_unit`, which is `$BINARY` again. None of the three is
/// given the password.
///
/// This one is a text check, because a run cannot show a call that bypasses
/// `PATH`: the call reaches the real tool, and nothing records it.
#[test]
fn the_installer_calls_no_tool_by_its_path() {
    let text = fs::read_to_string(installer_script()).expect("the installer must be readable");
    let mut heredoc: Option<String> = None;
    let mut by_path = std::collections::BTreeSet::new();
    for line in text.lines() {
        if let Some(end) = &heredoc {
            if line == end {
                heredoc = None;
            }
            continue;
        }
        if line.trim_start().starts_with('#') {
            continue;
        }
        if let Some((_, tag)) = line.split_once("<<").filter(|_| !line.contains("<<<")) {
            heredoc = Some(tag.trim().trim_matches('\'').to_owned());
        }
        for word in command_words(line) {
            let unquoted = word.trim_matches('"');
            let variable = unquoted.strip_prefix('$').is_some_and(|name| {
                !name.is_empty()
                    && name
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || "_{}".contains(ch))
            });
            if word.starts_with('/') || word.starts_with("./") || variable {
                by_path.insert(word.to_owned());
            }
        }
    }
    assert_eq!(
        by_path,
        ["\"$1\"", "\"$BIN\"", "\"$BINARY\""]
            .map(str::to_owned)
            .into(),
        "the installer calls a tool by its path, which the argv recorders cannot see"
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
/// it.
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
/// was handed. So the script asks that binary. This is the end-to-end shape of
/// the answer: the generator, the shipped example and a real volto agree that
/// what a first install writes is a file the service can start on.
#[test]
fn the_generated_configuration_is_one_the_binary_can_load() {
    let root = install_root("accepts");
    let script = installer_script();

    let (ok, stdout, stderr) = run_check_config(&root, &script, &real_binary());

    assert!(ok, "the generated config must load: {stderr}");
    assert!(
        stdout.contains("loads on this volto"),
        "the run must say the config was checked: {stdout}"
    );
}

/// The generated config is the shipped example with four values substituted,
/// every table in it is `deny_unknown_fields`, and one key the binary does not
/// know refuses the whole file rather than the key.
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
/// unpacked release tarball, the binary is `./volto` and the way out is
/// `--binary ./volto`, so the message must name the flag.
/// The same text guards the install path a few lines further down, which needs
/// root and so cannot be reached from here; this covers the wording for both.
#[test]
fn a_missing_binary_is_refused_with_the_flag_that_points_at_another_one() {
    let root = install_root("no-binary");
    let script = installer_script();

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
/// binary into a failure. So the flag is looked for by name in the binary's own
/// `--help` before it is used, and a binary without it leaves the config
/// unchecked.
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

/// Writes stand-ins for the commands the install path needs root or a Debian
/// host for, and an `mv` that fails on its `fail_at`-th call. Returns the
/// directory to put in front of `PATH`.
///
/// `id -u` prints 0 and `id -u volto` succeeds, so the root check passes and no
/// user is created. `apt-get` is only looked up before the certificate step.
/// `systemctl` reports `service_status` for `is-active`: the `--quiet` form
/// exits 0 only when the status is `active`, the plain form prints the status
/// and exits 0, and every other invocation exits 0; every call is recorded in
/// `systemctl.log` beside it, except `show`, a query, which goes to
/// `systemctl-show.log` and answers `show -p Environment` from
/// `unit-environment` beside it. `chown` changes nothing and records its arguments
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
             if [ \"$1\" = show ]; then\n\
             \x20 printf '%s\\n' \"$*\" >> '{shown}'\n\
             \x20 [ \"$3\" = Environment ] && cat '{environment}' 2>/dev/null\n\
             \x20 exit 0\n\
             fi\n\
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
            shown = dir.join("systemctl-show.log").display(),
            environment = dir.join("unit-environment").display(),
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
/// The stand-in's own failure line is asserted because a run that stopped
/// before the swap would leave the old pair in place too, and would pass for
/// the wrong reason.
#[test]
fn a_certificate_swap_that_fails_partway_puts_the_previous_pair_back() {
    let script = installer_script();

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

        let output = run_within_deadline(
            installer(&script)
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
                .env("VOLTO_INSTALL_ROOT", &root)
                .env("PATH", path_with_stubs(&stubs)),
        );
        let stderr = stderr_of(&output);

        assert!(
            !output.status.success(),
            "rename {fail_at} failed, so the run must fail: {stderr}"
        );
        fs::read_to_string(stubs.join("mv-calls"))
            .unwrap_or_else(|error| panic!("the run never reached the swap: {error}\n{stderr}"));
        assert!(
            stderr.contains(&format!("mv stub: forced failure on call {fail_at}")),
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

        let leftovers = backup_leftovers(&conf_dir);
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

/// The new and backup files of a certificate swap left in `dir`, sorted.
fn backup_leftovers(dir: &Path) -> Vec<String> {
    let mut leftovers: Vec<String> = fs::read_dir(dir)
        .expect("the configuration directory must be readable")
        .map(|entry| entry.expect("directory entry").file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".new") || name.ends_with(".bak"))
        .collect();
    leftovers.sort();
    leftovers
}

/// A signal during the certificate swap puts the previous pair back, as a
/// failed rename does.
///
/// The stand-in `mv` makes its rename and then sends the signal to the script,
/// on the call each case names. A Ctrl-C, the SIGHUP of a dropped session and a
/// SIGTERM would otherwise end the run there with the pair split. The
/// rollback's own renames come later and are not signalled. The
/// exit status is the rollback's, not a death by the signal.
#[test]
fn a_signal_during_the_certificate_swap_puts_the_previous_pair_back() {
    let script = installer_script();

    for (signal_at, signal) in [(1, "TERM"), (2, "HUP"), (3, "INT"), (4, "TERM")] {
        let root = scratch_tree(
            "install",
            &format!("swap-signal-at-{signal_at}"),
            &["etc/volto", "usr/local/bin"],
        );
        let conf_dir = root.join("etc/volto");
        let (cert, key) = plant_placeholder_certificates(&conf_dir);
        let old_cert = fs::read(&cert).expect("the old certificate must be readable");
        let old_key = fs::read(&key).expect("the old key must be readable");

        let binary = plant_binary_without_the_flag(&root, "volto-stub");
        let stubs = plant_root_stubs(&root, 0, "active");
        write_executable(
            &stubs.join("mv"),
            &format!(
                "#!/bin/sh\n\
                 count_file='{count}'\n\
                 n=$(( $(cat \"$count_file\" 2>/dev/null || echo 0) + 1 ))\n\
                 echo \"$n\" >\"$count_file\"\n\
                 '{real}' \"$@\"\n\
                 status=$?\n\
                 [ \"$n\" -ne {signal_at} ] || kill -{signal} \"$PPID\"\n\
                 exit \"$status\"\n",
                count = stubs.join("mv-calls").display(),
                real = real_tool("mv").display(),
            ),
        );

        let output = run_within_deadline(
            installer(&script)
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
                .env("VOLTO_INSTALL_ROOT", &root)
                .env("PATH", path_with_stubs(&stubs)),
        );
        let stderr = stderr_of(&output);

        assert_eq!(
            output.status.code(),
            Some(1),
            "SIG{signal} after rename {signal_at} must end the run through the rollback: {stderr}"
        );
        assert_eq!(
            fs::read(&cert).ok(),
            Some(old_cert),
            "after SIG{signal} at rename {signal_at} the old certificate must be back: {stderr}"
        );
        assert_eq!(
            fs::read(&key).ok(),
            Some(old_key),
            "after SIG{signal} at rename {signal_at} the old key must be back: {stderr}"
        );
        let leftovers = backup_leftovers(&conf_dir);
        assert!(
            leftovers.is_empty(),
            "after SIG{signal} at rename {signal_at} no new or backup file may stay, found {leftovers:?}: {stderr}"
        );
        assert!(
            stderr
                .contains("installing the new certificate was interrupted; restored the previous"),
            "the run must say the swap was interrupted: {stderr}"
        );
    }
}

/// A `chown` that fails when it is given the certificate pair, and succeeds on
/// the directory before it, so the run reaches the certificate transaction.
const CHOWN_FAILS_ON_THE_PAIR: &str =
    "#!/bin/sh\ncase \"$*\" in *cert.pem*) exit 1 ;; esac\nexit 0\n";

/// A failure at the ownership change must also put the previous pair back.
///
/// A failure at `chown` or `chmod` would otherwise leave the new pair in place
/// with the key still root's at mode 0600, which the service user cannot read,
/// so the next restart fails.
#[test]
fn a_failed_ownership_change_restores_the_previous_certificate_pair() {
    let root = host_root("chown-fails");
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

    let leftovers = backup_leftovers(&conf_dir);
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
        let root = host_root(name);
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
fn run_full_install(root: &Path, service_status: &str) -> Output {
    let stubs = plant_root_stubs(root, 0, service_status);
    run_full_install_with_stubs(root, &stubs, &[])
}

/// Runs the full install path with `stubs` in front of `PATH`, which a test uses
/// to replace one of the stand-ins the builder wrote.
fn run_full_install_with_stubs(root: &Path, stubs: &Path, extra_args: &[&str]) -> Output {
    run_within_deadline(
        installer(&installer_script())
            .args([
                "--binary",
                real_binary().to_str().expect("a UTF-8 path to the binary"),
                "-u",
                "alice",
                "-w",
                "correct-horse-battery",
            ])
            .args(extra_args)
            .env("VOLTO_INSTALL_ROOT", root)
            .env("PATH", path_with_stubs(stubs)),
    )
}

/// A service that failed to start must turn the install into a failure.
///
/// A port already bound
/// leaves the host without a proxy while the installer reports success. The
/// report and the security notes still print, so the operator has the
/// fingerprint and the policy line before the refusal.
#[test]
fn an_install_whose_service_failed_is_not_reported_as_success() {
    let root = host_root("service-failed");

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

/// A first install whose `systemctl start` fails still prints the report
/// before it fails.
///
/// Under `Type=notify` the start fails at once when the binary cannot be
/// executed, and after `TimeoutStartSec=` when the server never reports ready.
/// Without a guard on that call `set -e` would end the run there, and the
/// operator would get neither the fingerprint nor the policy line.
#[test]
fn a_first_install_whose_start_fails_still_prints_the_report() {
    let root = host_root("start-fails");
    let stubs = plant_root_stubs(&root, 0, "failed");
    write_executable(
        &stubs.join("systemctl"),
        &format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> '{}'\n\
             case \"$*\" in\n\
             \x20 'start volto') exit 1 ;;\n\
             \x20 'is-active --quiet volto') exit 3 ;;\n\
             \x20 'is-active volto') echo failed; exit 3 ;;\n\
             esac\n\
             exit 0\n",
            stubs.join("systemctl.log").display()
        ),
    );

    let output = run_full_install_with_stubs(&root, &stubs, &[]);

    let stdout = stdout_of(&output);
    assert!(!output.status.success(), "{stdout}");
    assert!(
        stdout.contains("systemctl start volto failed")
            && stdout.contains("certificate: ")
            && stdout.contains("server-cert-fingerprint-sha256="),
        "the fingerprint and the policy line must print before the failure: {stdout}"
    );
    assert!(
        stderr_of(&output).contains("volto is failed after the install"),
        "{}",
        stderr_of(&output)
    );
}

/// And a service that is active still succeeds, with the report printed, the
/// binary and the unit installed and the service enabled before it starts.
#[test]
fn an_install_whose_service_is_active_reports_success() {
    let root = host_root("service-active");
    let stubs = plant_root_stubs(&root, 0, "active");

    let output = run_full_install_with_stubs(&root, &stubs, &[]);

    assert!(output.status.success(), "{}", stderr_of(&output));
    assert!(
        stdout_of(&output).contains("==> done"),
        "the report must print: {}",
        stdout_of(&output)
    );
    assert_eq!(
        fs::read(root.join("usr/local/bin/volto")).ok(),
        fs::read(real_binary()).ok(),
        "the binary must be installed"
    );
    assert_eq!(
        fs::read(root.join("etc/systemd/system/volto.service")).ok(),
        fs::read(repo_root().join("script/masque.service")).ok(),
        "the shipped unit must be installed"
    );
    let calls = systemctl_calls(&stubs);
    assert!(
        calls.starts_with("daemon-reload\nenable volto\n"),
        "systemd must read the unit and enable the service, so it comes back after a reboot: {calls}"
    );
}

/// A configured host for the re-run tests: a config the real binary loads with
/// `body` appended, its certificate pair, an installed binary that reports an
/// old version, and an installed unit.
fn configured_root(name: &str, body: &str) -> Scratch {
    let root = host_root(name);
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
/// alone and does not restart the service, so a re-run to regenerate a
/// certificate from a checkout holding an older build cannot downgrade the
/// binary. With `--force` the
/// certificate is regenerated and the running service reloaded, which keeps
/// its tunnels.
#[test]
fn a_rerun_on_a_configured_host_keeps_the_binary_and_the_unit() {
    for (name, args) in [("rerun-plain", &[][..]), ("rerun-force", &["--force"][..])] {
        let root = configured_root(name, "");
        let stubs = plant_root_stubs(&root, 0, "active");

        let output = run_full_install_with_stubs(&root, &stubs, args);

        let stderr = stderr_of(&output);
        assert!(output.status.success(), "{name}: {stderr}");
        assert_eq!(
            fs::read_to_string(root.join("usr/local/bin/volto"))
                .ok()
                .as_deref(),
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
    let root = configured_root(
        "replace-refused",
        "\n[limits]\na_key_a_later_release_added = 2\n",
    );
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
        fs::read_to_string(root.join("usr/local/bin/volto"))
            .ok()
            .as_deref(),
        Some(OLD_BINARY),
        "the installed binary must be untouched: {stderr}"
    );
    assert_eq!(
        fs::read(root.join("etc/volto/cert.pem")).ok(),
        Some(old_cert),
        "the refusal comes before the certificate step: {stderr}"
    );
    assert!(!root.join("usr/local/bin/volto.prev").exists());
    assert_eq!(
        systemctl_calls(&stubs),
        "",
        "the service must be left alone"
    );
}

/// `--replace-binary` asks the new binary with the `RUST_LOG` the installed
/// unit sets, as `deploy.sh` does, so a value the binary refuses at startup
/// stops the run before anything moves, and one it accepts does not.
/// The binary is the real one, so its own rule judges the value.
#[test]
fn replacing_the_binary_is_checked_with_the_units_rust_log() {
    for (name, environment, refused) in [
        ("replace-rust-log-refused", "RUST_LOG=quinn=debug", true),
        (
            "replace-rust-log-accepted",
            "RUST_LOG=info,quinn=debug",
            false,
        ),
    ] {
        let root = configured_root(name, "");
        let stubs = plant_root_stubs(&root, 0, "active");
        fs::write(stubs.join("unit-environment"), format!("{environment}\n"))
            .expect("the unit's environment must be writable");

        let output = run_full_install_with_stubs(&root, &stubs, &["--replace-binary"]);

        let stderr = stderr_of(&output);
        let installed = fs::read_to_string(root.join("usr/local/bin/volto")).ok();
        if refused {
            assert!(!output.status.success(), "{name}: {}", stdout_of(&output));
            assert!(
                stderr.contains("RUST_LOG = \"quinn=debug\" turns off")
                    && stderr.contains("over a config it cannot load")
                    && stderr.contains("the volto unit's RUST_LOG=quinn=debug"),
                "{name}: the binary's own refusal must reach the operator: {stderr}"
            );
            assert_eq!(
                installed.as_deref(),
                Some(OLD_BINARY),
                "{name}: the installed binary must be untouched: {stderr}"
            );
            assert!(!root.join("usr/local/bin/volto.prev").exists(), "{name}");
            assert_eq!(
                systemctl_calls(&stubs),
                "",
                "{name}: the service must be left alone"
            );
        } else {
            assert!(output.status.success(), "{name}: {stderr}");
            assert_eq!(
                fs::read(root.join("usr/local/bin/volto")).ok(),
                fs::read(real_binary()).ok(),
                "{name}: the new binary must be installed"
            );
        }
    }
}

/// `--replace-binary` with a binary that loads the config keeps the previous
/// binary and unit as `.prev`, the way `deploy.sh` does, and restarts.
#[test]
fn replacing_the_binary_keeps_the_previous_one_and_restarts() {
    let root = configured_root("replace-accepted", "");
    let stubs = plant_root_stubs(&root, 0, "active");
    fs::write(
        root.join("usr/local/bin/volto.prev"),
        "a stale previous binary\n",
    )
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
        fs::read_to_string(root.join("usr/local/bin/volto.prev"))
            .ok()
            .as_deref(),
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
        calls.starts_with("daemon-reload\nenable volto\nis-active --quiet volto\nrestart volto\n"),
        "systemd must read the new unit before the service restarts on it: {calls}"
    );
}

/// Replaces the stand-in `systemctl` in `stubs` with one whose `restart volto`
/// fails and whose `is-active volto` prints `active`. It records every call in
/// `systemctl.log`, `show` included, and succeeds otherwise.
fn restart_fails(stubs: &Path) {
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
}

/// A failed restart after `--replace-binary` puts the previous binary and unit
/// back and starts the service on them.
#[test]
fn a_replaced_binary_that_fails_to_restart_is_rolled_back() {
    let root = configured_root("replace-rollback", "");
    let stubs = plant_root_stubs(&root, 0, "active");
    restart_fails(&stubs);

    let output = run_full_install_with_stubs(&root, &stubs, &["--replace-binary"]);

    let stderr = stderr_of(&output);
    assert!(!output.status.success(), "{}", stdout_of(&output));
    assert!(
        stderr.contains("restored the previous binary and unit"),
        "the run must say what it restored: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(root.join("usr/local/bin/volto"))
            .ok()
            .as_deref(),
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

/// The unit is written beside its target and renamed over it, on a first
/// install, on `--replace-binary` and on its rollback.
///
/// Written straight to its name, a full `/etc` or a crash in mid-write would
/// leave a truncated unit that systemd then parses at `daemon-reload`. The stand-in
/// `install` records its arguments already; the stand-in `mv` here records its
/// own and runs the host's.
#[test]
fn the_unit_is_replaced_by_a_rename() {
    for (name, rollback) in [("unit-rename-first", false), ("unit-rename-rollback", true)] {
        let root = if rollback {
            configured_root(name, "")
        } else {
            host_root(name)
        };
        let stubs = plant_root_stubs(&root, 0, "active");
        write_executable(
            &stubs.join("mv"),
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexec '{}' \"$@\"\n",
                stubs.join("mv.log").display(),
                real_tool("mv").display(),
            ),
        );
        if rollback {
            write_executable(
                &stubs.join("systemctl"),
                &format!(
                    "#!/bin/sh\n\
                     [ \"$1\" = show ] && exit 0\n\
                     printf '%s\\n' \"$*\" >> '{}'\n\
                     [ \"$*\" = 'restart volto' ] && exit 1\n\
                     exit 0\n",
                    stubs.join("systemctl.log").display()
                ),
            );
        }

        let args: &[&str] = if rollback { &["--replace-binary"] } else { &[] };
        let output = run_full_install_with_stubs(&root, &stubs, args);

        let stderr = stderr_of(&output);
        let unit = root.join("etc/systemd/system/volto.service");
        let expected = if rollback {
            assert!(!output.status.success(), "{name}: {}", stdout_of(&output));
            OLD_UNIT.to_owned()
        } else {
            assert!(output.status.success(), "{name}: {stderr}");
            fs::read_to_string(repo_root().join("script/masque.service"))
                .expect("the shipped unit must be readable")
        };
        assert_eq!(
            fs::read_to_string(&unit).ok(),
            Some(expected),
            "{name}: the unit must be the one this run leaves in place: {stderr}"
        );
        let installs = fs::read_to_string(stubs.join("install.log")).unwrap_or_default();
        let unit = unit.display().to_string();
        assert!(
            installs
                .lines()
                .all(|line| !line.ends_with(&format!(" {unit}"))),
            "{name}: nothing may be installed straight over {unit}: {installs}"
        );
        let moves = fs::read_to_string(stubs.join("mv.log")).unwrap_or_default();
        let rename = format!("-f {unit}.new {unit}");
        assert_eq!(
            moves.lines().filter(|line| *line == rename).count(),
            if rollback { 2 } else { 1 },
            "{name}: the unit must be written beside itself and renamed over: {moves}"
        );
    }
}

/// A signal while `--replace-binary` swaps the binary and unit rolls them back
/// as a failure there does.
///
/// The stand-in `systemctl` sends the signal to the script on the first
/// `daemon-reload`, before the restart is issued, or on every `restart volto`,
/// the rollback's own included. Before the restart the rollback starts the
/// service, which leaves the old process serving; after it the rollback
/// restarts the service on the restored files, because systemd finishes the
/// restart job without the script.
#[test]
fn a_signal_while_replacing_the_binary_rolls_it_back() {
    for (n, (trigger, signal, expected)) in [
        (
            "daemon-reload",
            "TERM",
            "daemon-reload\ndaemon-reload\nstart volto\n",
        ),
        (
            "restart volto",
            "HUP",
            "daemon-reload\nenable volto\nis-active --quiet volto\nrestart volto\n\
             daemon-reload\nrestart volto\n",
        ),
        (
            "restart volto",
            "INT",
            "daemon-reload\nenable volto\nis-active --quiet volto\nrestart volto\n\
             daemon-reload\nrestart volto\n",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let root = configured_root(&format!("replace-signal-{n}"), "");
        let stubs = plant_root_stubs(&root, 0, "active");
        let marker = stubs.join("signalled");
        // `restart volto` is signalled every time, `daemon-reload` once.
        let once = if trigger == "daemon-reload" {
            format!("[ ! -e '{m}' ] && : > '{m}' && ", m = marker.display())
        } else {
            String::new()
        };
        write_executable(
            &stubs.join("systemctl"),
            &format!(
                "#!/bin/sh\n\
                 [ \"$1\" = show ] && exit 0\n\
                 printf '%s\\n' \"$*\" >> '{log}'\n\
                 [ \"$*\" = '{trigger}' ] && {once}kill -{signal} \"$PPID\"\n\
                 case \"$*\" in\n\
                 \x20 'is-active volto') echo active ;;\n\
                 esac\n\
                 exit 0\n",
                log = stubs.join("systemctl.log").display()
            ),
        );

        let output = run_full_install_with_stubs(&root, &stubs, &["--replace-binary"]);

        let stderr = stderr_of(&output);
        assert_eq!(
            output.status.code(),
            Some(1),
            "case {n}: the run must end through the rollback: {stderr}"
        );
        assert!(
            stderr.contains(
                "replacing the binary and unit was interrupted; restored the previous binary and unit"
            ),
            "case {n}: the run must say it was interrupted and what it restored: {stderr}"
        );
        assert_eq!(
            fs::read_to_string(root.join("usr/local/bin/volto"))
                .ok()
                .as_deref(),
            Some(OLD_BINARY),
            "case {n}: the previous binary must be back: {stderr}"
        );
        assert_eq!(
            fs::read_to_string(root.join("etc/systemd/system/volto.service"))
                .ok()
                .as_deref(),
            Some(OLD_UNIT),
            "case {n}: the previous unit must be back: {stderr}"
        );
        assert_eq!(
            systemctl_calls(&stubs),
            expected,
            "case {n}: the rollback must reload systemd and then start or restart: {stderr}"
        );
    }
}

/// A rollback after `--replace-binary` puts the unit back only together with
/// the binary, as `deploy.sh` does.
///
/// The installed binary here is not executable, so no `volto.prev` is made,
/// while `volto.service.prev` is. Restoring that unit alone would put the new
/// binary under the old unit and report a rollback.
#[test]
fn a_rollback_without_a_previous_binary_leaves_the_new_pair() {
    let root = configured_root("replace-no-prev-binary", "");
    fs::set_permissions(
        root.join("usr/local/bin/volto"),
        fs::Permissions::from_mode(0o644),
    )
    .expect("the installed binary's mode must be settable");
    let stubs = plant_root_stubs(&root, 0, "active");
    restart_fails(&stubs);

    let output = run_full_install_with_stubs(&root, &stubs, &["--replace-binary"]);

    let stderr = stderr_of(&output);
    assert!(!output.status.success(), "{}", stdout_of(&output));
    assert!(
        root.join("etc/systemd/system/volto.service.prev").exists()
            && !root.join("usr/local/bin/volto.prev").exists(),
        "the case under test: a unit .prev and no binary .prev"
    );
    assert!(
        stderr.contains("there was nothing to restore"),
        "a unit alone is not a rollback: {stderr}"
    );
    assert_eq!(
        fs::read(root.join("usr/local/bin/volto")).ok(),
        fs::read(real_binary()).ok(),
        "the new binary stays: {stderr}"
    );
    assert_eq!(
        fs::read(root.join("etc/systemd/system/volto.service")).ok(),
        fs::read(repo_root().join("script/masque.service")).ok(),
        "the new unit stays with it: {stderr}"
    );
}

/// A first install writes the root-owned layout: `/etc/volto` root:volto 0750,
/// the config and the key root:volto 0640, the certificate root:volto 0644.
///
/// Root writes, renames, chowns and chmods by name inside the directory, which
/// is safe only while the service user cannot change it. The stand-in `chown` and `install`
/// record what they were asked, since this host has no `volto` group.
#[test]
fn a_first_install_writes_the_root_owned_layout() {
    let root = host_root("layout");
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
        install
            .lines()
            .any(|line| line.starts_with("-o root -g volto -m 0640 ")
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
        fs::metadata(&dir)
            .expect("the directory")
            .permissions()
            .mode()
            & 0o777,
        0o750
    );
}

/// The public name the ECH tests give the installer.
const ECH_PUBLIC_NAME: &str = "public.example";

/// What is in `root`'s `/etc/volto`, by file name.
fn conf_dir_entries(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(root.join("etc/volto"))
        .expect("the config directory must be readable")
        .map(|entry| {
            entry
                .expect("a directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// The ECHConfigList the real binary prints for the key file `key`.
fn ech_config_list(key: &Path) -> String {
    let output = run_within_deadline(Command::new(real_binary()).arg("ech-config").arg(key));
    assert!(
        output.status.success(),
        "volto ech-config must read the key the installer wrote: {}",
        stderr_of(&output)
    );
    stdout_of(&output).trim().to_owned()
}

/// `--ech-public-name` turns the example's commented `ech_key` line into one
/// that names the key file the install writes. Without the option the line
/// stays a comment and the config sets no key.
#[test]
fn the_ech_option_points_the_generated_config_at_the_key_file() {
    let with = generated_config(&["--ech-public-name", ECH_PUBLIC_NAME]);
    let config: Config = toml::from_str(&with).expect("the generated config must parse");
    assert_eq!(
        config.server.ech_key.as_deref(),
        Some(Path::new("/etc/volto/ech.pem")),
        "the config must name the key file: {with}"
    );

    let without = generated_config(&[]);
    let config: Config = toml::from_str(&without).expect("the generated config must parse");
    assert_eq!(config.server.ech_key, None);
    assert!(
        without
            .lines()
            .any(|line| line == "#ech_key = \"/etc/volto/ech.pem\""),
        "without the option the example's line must stay a comment: {without}"
    );
}

/// A first install with `--ech-public-name` sets ECH up in one run: the key
/// file beside the certificate, a config that names it and that the binary
/// loads, and `ech-config` on the policy line. A later run without the option
/// reads the key out of the config and prints the line with it again.
///
/// Without a terminal the list is not printed, for the reason the password is
/// not: it is what lets a client in. The line then names the command that
/// prints it.
#[test]
fn a_first_install_with_the_ech_option_sets_up_ech_in_one_run() {
    let root = host_root("ech-first");
    let stubs = plant_root_stubs(&root, 0, "active");
    let key = root.join("etc/volto/ech.pem");
    let config_path = root.join("etc/volto/config.toml");

    let output = run_full_install_with_stubs(
        &root,
        &stubs,
        &["--sni", "volto.test", "--ech-public-name", ECH_PUBLIC_NAME],
    );

    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(
        fs::metadata(&key)
            .expect("the ECH key file must exist")
            .permissions()
            .mode()
            & 0o777,
        0o640,
        "the service reads the key through its group"
    );
    let chown = fs::read_to_string(stubs.join("chown.log")).unwrap_or_default();
    assert!(
        chown.contains(&format!("root:volto {}\n", key.display())),
        "the key must go to root:volto: {chown}"
    );
    let config: Config =
        toml::from_str(&fs::read_to_string(&config_path).expect("the installed config"))
            .expect("the installed config parses");
    assert_eq!(config.server.ech_key.as_deref(), Some(key.as_path()));
    let check = run_within_deadline(
        Command::new(real_binary())
            .arg("--check-config")
            .arg("--config")
            .arg(&config_path)
            .env_remove("RUST_LOG"),
    );
    assert!(
        check.status.success(),
        "the binary must load the installed config with its ECH key: {}",
        stderr_of(&check)
    );
    let list = ech_config_list(&key);
    assert!(list.len() > 40, "an ECHConfigList in base64: {list:?}");
    let placeholder = format!(
        "ech-config=<run: volto ech-config {}>, username=",
        key.display()
    );
    assert!(
        stdout.contains(&placeholder),
        "the policy line must carry ech-config and say where the list comes from: {stdout}"
    );
    assert!(
        !stdout.contains(&list),
        "the list reached a stdout that is not a terminal:\n{stdout}"
    );

    let again = run_full_install_with_stubs(&root, &stubs, &["--sni", "volto.test"]);

    assert!(again.status.success(), "{}", stderr_of(&again));
    assert!(
        stdout_of(&again).contains(&placeholder),
        "a re-run must read the key out of the config: {}",
        stdout_of(&again)
    );
    assert_eq!(ech_config_list(&key), list, "a re-run must keep the key");
}

/// On a terminal the policy line carries the ECHConfigList itself, and the
/// password, ready to paste.
///
/// Every other test here runs the installer on a pipe, where both print as a
/// pointer to where they are. Python's `pty.spawn` gives this run a terminal
/// and copies what it prints. The test is skipped, with the reason printed,
/// only when no `python3` is on `PATH`.
#[test]
fn on_a_terminal_the_policy_line_carries_the_ech_config_list() {
    match Command::new("python3").arg("--version").output() {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipped: no python3 on PATH to give the installer a terminal");
            return;
        }
        Err(error) => panic!("python3 must be runnable: {error}"),
    }
    let root = host_root("ech-terminal");
    let stubs = plant_root_stubs(&root, 0, "active");
    let mut command = Command::new("python3");
    command
        .args([
            "-c",
            "import os, pty, sys\n\
             sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))",
        ])
        .arg(real_tool("bash"))
        .arg(installer_script())
        .args([
            "--binary",
            real_binary().to_str().expect("a UTF-8 path to the binary"),
            "-u",
            "alice",
            "-w",
            "correct-horse-battery",
            "--sni",
            "volto.test",
            "--ech-public-name",
            ECH_PUBLIC_NAME,
        ]);
    in_the_checkout_without_installer_variables(&mut command);
    command
        .env("VOLTO_INSTALL_ROOT", &*root)
        .env("PATH", path_with_stubs(&stubs));

    let output = run_within_deadline(&mut command);

    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{stdout}\n{}", stderr_of(&output));
    let list = ech_config_list(&root.join("etc/volto/ech.pem"));
    let expected = format!("ech-config={list}, username=alice, password=correct-horse-battery");
    assert!(
        stdout.contains(&expected),
        "a terminal must get the line with the list and the password in it: {stdout}"
    );
}

/// A config regenerated on a host that has an ECH key, without the option,
/// does not name the key, and the run says so: clients that send ECH would
/// otherwise stop connecting with nothing printed about it.
#[test]
fn a_regenerated_config_that_leaves_an_ech_key_unused_is_pointed_out() {
    let root = host_root("ech-unused");
    let stubs = plant_root_stubs(&root, 0, "active");
    let key = root.join("etc/volto/ech.pem");
    fs::write(&key, "a key file from an earlier install\n").expect("the key must be writable");

    let output = run_full_install_with_stubs(&root, &stubs, &["--sni", "volto.test"]);

    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert!(
        stdout.contains(&format!(
            "{} exists and the new config will not name it",
            key.display()
        )) && stdout.contains("--ech-public-name"),
        "the run must say that the key is left unused and how to keep it: {stdout}"
    );
    assert!(!stdout.contains("ech-config="), "{stdout}");
}

/// On a host that already has a config, `--ech-public-name` writes nothing:
/// the config is the operator's, and the run says how to add ECH to it.
#[test]
fn the_ech_option_on_a_configured_host_writes_nothing_and_says_what_to_do() {
    let root = configured_root("ech-configured", "");
    let stubs = plant_root_stubs(&root, 0, "active");
    let config_path = root.join("etc/volto/config.toml");
    let before = fs::read(&config_path).expect("the planted config");
    let entries = conf_dir_entries(&root);

    let output =
        run_full_install_with_stubs(&root, &stubs, &["--ech-public-name", ECH_PUBLIC_NAME]);

    let stdout = stdout_of(&output);
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(fs::read(&config_path).ok(), Some(before));
    assert_eq!(conf_dir_entries(&root), entries, "no key file may appear");
    assert!(
        stdout.contains(&format!(
            "ech-keygen --public-name {ECH_PUBLIC_NAME} --out "
        )),
        "the run must give the command that makes the key: {stdout}"
    );
    assert!(
        !stdout.contains("ech-config="),
        "a config without an ECH key gives a policy line without ech-config: {stdout}"
    );
}

/// A public name that is not a host name is refused before anything is
/// generated, by the flags that stop early as well.
#[test]
fn a_public_name_that_is_not_a_host_name_is_refused_before_anything_is_written() {
    for name in ["two words", "a..b", "-a.example", "192.0.2.1", ""] {
        let (ok, config, stderr) = print_config(&["--ech-public-name", name]);
        assert!(
            !ok && config.is_empty() && stderr.contains("ECH public name"),
            "{name:?} must be refused by name, with no config printed: {stderr}"
        );
    }

    let root = host_root("ech-bad-name");
    let stubs = plant_root_stubs(&root, 0, "active");

    let output = run_full_install_with_stubs(&root, &stubs, &["--ech-public-name", "a..b"]);

    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("ECH public name"),
        "{}",
        stderr_of(&output)
    );
    assert_eq!(conf_dir_entries(&root), Vec::<String>::new());
}

/// A volto without `ech-keygen` cannot make the key, so the run stops before
/// it writes anything, the certificate included.
#[test]
fn a_binary_without_ech_keygen_is_refused_before_anything_is_written() {
    let root = host_root("ech-old-binary");
    let stubs = plant_root_stubs(&root, 0, "active");
    let old = plant_binary_without_the_flag(&root, "volto-old");

    let output = run_within_deadline(
        installer(&installer_script())
            .args([
                "--binary",
                old.to_str().expect("a UTF-8 path to the binary"),
                "-u",
                "alice",
                "-w",
                "correct-horse-battery",
                "--ech-public-name",
                ECH_PUBLIC_NAME,
            ])
            .env("VOLTO_INSTALL_ROOT", &*root)
            .env("PATH", path_with_stubs(&stubs)),
    );

    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("ech-keygen"),
        "the refusal must name what the binary lacks: {}",
        stderr_of(&output)
    );
    assert_eq!(conf_dir_entries(&root), Vec::<String>::new());
}

/// A symbolic link where the key belongs is refused, and the file it points at
/// is not changed.
///
/// A host on the old layout, where the service user owned `/etc/volto`, may
/// hold such a link to a file of root's. `test -f` follows the link, and the
/// run's `chown` and `chmod` would then act on the link's target.
#[test]
fn a_symbolic_link_in_place_of_the_key_is_refused() {
    let root = scratch_tree(
        "install",
        "key-symlink",
        &[
            "etc/volto",
            "usr/local/bin",
            "etc/systemd/system",
            "outside",
        ],
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
        fs::metadata(&target)
            .expect("the target")
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "the link's target must keep its mode: {stderr}"
    );
    let chown = fs::read_to_string(stubs.join("chown.log")).unwrap_or_default();
    assert!(
        !chown.contains("key.pem"),
        "nothing may chown through the link: {chown}"
    );
    assert!(
        !dir.join("config.toml").exists(),
        "no config may be written"
    );
}

/// The certificate name must be a host name before it reaches openssl.
///
/// `--sni 'a.example,IP:192.0.2.1'` would put an IP address into the
/// certificate's subjectAltName, a `/` would add subject fields to `-subj`, and
/// either would go into the printed policy line as well.
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
        let root = host_root("bad-sni");
        let stubs = plant_root_stubs(&root, 0, "active");
        let output = run_full_install_with_stubs(&root, &stubs, &["--sni", name]);

        let stderr = stderr_of(&output);
        assert!(
            !output.status.success(),
            "{name:?} must be refused: {}",
            stdout_of(&output)
        );
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
        let root = host_root("good-sni");
        let stubs = plant_root_stubs(&root, 0, "active");
        let output = run_full_install_with_stubs(&root, &stubs, &["--sni", name]);
        assert!(output.status.success(), "{name:?}: {}", stderr_of(&output));
    }
}

/// The generated EC certificate asserts digitalSignature and not
/// keyEncipherment.
///
/// RFC 8446 section 4.4.2.2 asks that "the digitalSignature bit MUST be set if
/// the Key Usage extension is present". keyEncipherment is the RSA key
/// transport bit, which a P-256 key cannot perform.
#[test]
fn the_generated_certificate_asserts_only_digital_signature() {
    let root = host_root("key-usage");
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

/// Runs the full install path with no password given, so the installer
/// generates one, with stdout a pipe as under the update timer.
fn run_install_generating_the_password(root: &Path, stubs: &Path) -> Output {
    run_within_deadline(
        installer(&installer_script())
            .args([
                "--binary",
                real_binary().to_str().expect("a UTF-8 path to the binary"),
                "--sni",
                "volto.test",
            ])
            .env("VOLTO_INSTALL_ROOT", root)
            .env("PATH", path_with_stubs(stubs)),
    )
}

/// A generated password is not printed when stdout is not a terminal.
///
/// The update timer runs a first install when the config is missing, and its
/// output goes to the journal of `volto-deploy.service`, which the `adm` and
/// `systemd-journal` groups read. The policy line then names the config file
/// in place of the password.
#[test]
fn a_generated_password_is_not_printed_without_a_terminal() {
    let root = host_root("password-pipe");
    let stubs = plant_root_stubs(&root, 0, "active");

    let output = run_install_generating_the_password(&root, &stubs);

    assert!(output.status.success(), "{}", stderr_of(&output));
    let config: Config = toml::from_str(
        &fs::read_to_string(root.join("etc/volto/config.toml")).expect("the installed config"),
    )
    .expect("the installed config parses");
    let password = &config.auth.users[0].password;
    let stdout = stdout_of(&output);
    assert!(
        !stdout.contains(password.as_str()),
        "the generated password reached a stdout that is not a terminal:\n{stdout}"
    );
    assert!(
        stdout.contains("password=<as in "),
        "the policy line must say where the password is: {stdout}"
    );
}

/// A run without a terminal does not replace the password of a host that
/// already has an install.
///
/// Deleting `config.toml` and re-running regenerates the config. When the
/// re-run is the timer's, a generated password would replace every client's
/// credential and be printed only to the journal, so such a run stops before
/// anything changes; with the password given it goes ahead.
#[test]
fn a_run_without_a_terminal_does_not_replace_the_password_silently() {
    let root = host_root("password-silent");
    write_executable(&root.join("usr/local/bin/volto"), OLD_BINARY);
    let stubs = plant_root_stubs(&root, 0, "active");

    let output = run_install_generating_the_password(&root, &stubs);

    let stderr = stderr_of(&output);
    assert!(!output.status.success(), "{}", stdout_of(&output));
    assert!(
        stderr.contains("would replace the one the clients use"),
        "the refusal must say why: {stderr}"
    );
    assert!(
        !root.join("etc/volto/config.toml").exists(),
        "no config may be written"
    );
    assert!(
        !root.join("etc/volto/cert.pem").exists(),
        "no certificate may be written"
    );
    assert_eq!(
        fs::read_to_string(root.join("usr/local/bin/volto"))
            .ok()
            .as_deref(),
        Some(OLD_BINARY),
        "the binary must be left alone"
    );

    let output = run_full_install_with_stubs(&root, &stubs, &["--sni", "volto.test"]);
    assert!(
        output.status.success(),
        "with the password given the run goes ahead: {}",
        stderr_of(&output)
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
    let root = host_root("corrupt-certificate");
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

/// A run that does not end is killed at its deadline and fails the test,
/// rather than holding the test binary. Every runner here goes through
/// [`run_within_deadline`], which is this with a longer limit.
#[test]
fn a_run_that_does_not_end_is_killed_at_its_deadline() {
    let started = std::time::Instant::now();
    let outcome = std::panic::catch_unwind(|| {
        scripts::run_within(
            Command::new("bash")
                .args(["-c", "while :; do :; done"])
                .stdin(Stdio::null()),
            std::time::Duration::from_secs(1),
        )
    });
    let message = outcome
        .expect_err("a run past its deadline must panic")
        .downcast::<String>()
        .map(|message| *message)
        .unwrap_or_default();
    assert!(message.contains("was still running after 1s"), "{message}");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

/// A run whose command exits while a process it started in the background
/// still holds its standard output is killed at the same deadline, and the
/// background process goes with it.
#[test]
fn a_background_process_holding_the_output_is_killed_at_the_deadline() {
    let root = scratch_tree("install", "held-output", &[]);
    let pid_file = root.join("pid");
    let started = std::time::Instant::now();
    let outcome = std::panic::catch_unwind(|| {
        scripts::run_within(
            Command::new("sh")
                .args(["-c", "sleep 600 & echo $! > \"$1\"", "sh"])
                .arg(&pid_file)
                .stdin(Stdio::null()),
            std::time::Duration::from_secs(1),
        )
    });
    let message = outcome
        .expect_err("a run whose output is still held past its deadline must panic")
        .downcast::<String>()
        .map(|message| *message)
        .unwrap_or_default();
    assert!(message.contains("was still running after 1s"), "{message}");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));

    let pid: i32 = fs::read_to_string(&pid_file)
        .expect("the script must have written the background pid")
        .trim()
        .parse()
        .expect("a pid");
    let pid = rustix::process::Pid::from_raw(pid).expect("a positive pid");
    let gone_by = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while rustix::process::test_kill_process(pid).is_ok() {
        assert!(
            std::time::Instant::now() < gone_by,
            "the background process {pid} outlived the deadline's kill"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// `-h` must work and describe the safety-relevant flags.
#[test]
fn the_script_documents_itself() {
    let output = run_within_deadline(installer(&installer_script()).arg("-h"));

    assert!(output.status.success());
    let usage = stdout_of(&output);
    for expected in [
        "--force",
        "--sni",
        "--username",
        "--print-config",
        "--check-config",
        "--replace-binary",
        "--ech-public-name",
        "Re-running is safe",
    ] {
        assert!(
            usage.contains(expected),
            "usage must mention {expected}: {usage}"
        );
    }
}

/// On a host that has a key and no certificate, the rollback of a swap puts
/// the old key back and removes nothing that was there before the run.
///
/// The key is backed up whenever it exists, not only beside a certificate.
/// Without that backup, a failed rename of the new key into place, or a signal
/// after the rename, left the rollback a file at the key path with no backup
/// to restore. It removed that file and reported it as the new key, which on
/// a failed rename was the operator's old one. The stand-in `mv` acts on the
/// rename of the new key alone, whatever its position among the renames.
#[test]
fn a_rollback_on_a_host_with_a_key_and_no_certificate_puts_the_old_key_back() {
    let script = installer_script();

    for (name, action) in [
        ("key-only-mv-fails", "exit 1"),
        (
            "key-only-signal",
            "'{real}' \"$@\"; kill -TERM \"$PPID\"; exit 0",
        ),
    ] {
        let root = scratch_tree("install", name, &["etc/volto", "usr/local/bin"]);
        let conf_dir = root.join("etc/volto");
        let cert = conf_dir.join("cert.pem");
        let key = conf_dir.join("key.pem");
        fs::write(&key, "the old key\n").expect("the key must be writable");

        let binary = plant_binary_without_the_flag(&root, "volto-stub");
        let stubs = plant_root_stubs(&root, 0, "active");
        let real = real_tool("mv");
        write_executable(
            &stubs.join("mv"),
            &format!(
                "#!/bin/sh\n\
                 case \"$1\" in *key.pem.new) {action} ;; esac\n\
                 exec '{real}' \"$@\"\n",
                action = action.replace("{real}", &real.display().to_string()),
                real = real.display(),
            ),
        );

        let output = run_within_deadline(
            installer(&script)
                .args([
                    "--sni",
                    "volto.test",
                    "--binary",
                    binary.to_str().expect("a UTF-8 path to the binary"),
                    "-u",
                    "alice",
                    "-w",
                    "correct-horse-battery",
                ])
                .env("VOLTO_INSTALL_ROOT", &root)
                .env("PATH", path_with_stubs(&stubs)),
        );
        let stderr = stderr_of(&output);

        assert_eq!(output.status.code(), Some(1), "{name}: {stderr}");
        assert_eq!(
            fs::read_to_string(&key).ok().as_deref(),
            Some("the old key\n"),
            "{name}: the old key must be back at {}: {stderr}",
            key.display()
        );
        assert!(
            !cert.exists(),
            "{name}: the new certificate must be removed, it has no previous one: {stderr}"
        );
        assert!(
            stderr.contains(&format!("restored the previous {}", key.display()))
                && stderr.contains(&format!("removed the new {}", cert.display()))
                && !stderr.contains(&format!("removed the new {} and", cert.display())),
            "{name}: the message must say the key was restored and only the new certificate removed: {stderr}"
        );
        let leftovers = backup_leftovers(&conf_dir);
        assert!(
            leftovers.is_empty(),
            "{name}: no new or backup file may stay behind, found {leftovers:?}: {stderr}"
        );
    }
}
