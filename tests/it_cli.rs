//! The command line, exercised as a process rather than as a library call.
//!
//! Everything else in this tree tests volto from inside: `tests/common` builds a
//! `Config` and a `Server` in the test process, which is the right level for
//! protocol behaviour and useless for the two questions this file asks. Both are
//! about the binary as `script/deploy.sh` meets it — a file on disk, run with
//! arguments, judged by its exit status and its two output streams.
//!
//! `--check-config` is the flag that answers "can *this* binary read *that*
//! file", which is the question a rollback turns on (D93): a configuration file
//! is forward-only, because every table is `deny_unknown_fields`, so a host
//! installed at a later release carries keys an earlier binary refuses — and it
//! refuses the whole file, so the service does not start at all. Answering that
//! before the binary is swapped is what turns a doomed downgrade from something
//! discovered at three in the morning into something refused at the door.
//!
//! What the tests below pin, therefore, is not only that the flag works but the
//! exact shape `deploy.sh` reads it by: the flag is named in `--help` (the
//! capability probe), a refusal exits 1 with the reason on stderr, and an
//! unknown *argument* fails a different way than an unknown *key* — the
//! misreading that would turn "your volto is too old to check" into "your config
//! is broken".

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The binary under test, built by cargo for this integration test.
fn volto() -> &'static str {
    env!("CARGO_BIN_EXE_volto")
}

/// A directory of this test's own, standing in for `/etc/volto`.
fn config_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("volto-cli-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("the temporary config directory must be creatable");
    // `Config::validate` insists both exist and are files; nothing here parses
    // them, because the certificate is not what any of this is about.
    fs::write(dir.join("cert.pem"), "not a certificate\n").expect("cert must be writable");
    fs::write(dir.join("key.pem"), "not a key\n").expect("key must be writable");
    dir
}

/// Writes a configuration file naming the certificate pair planted above.
///
/// `listen` is a parameter because one test needs a port it has already taken
/// for itself; `body` is appended verbatim, tables and all.
fn write_config(dir: &Path, listen: &str, body: &str) -> PathBuf {
    let path = dir.join("config.toml");
    let text = format!(
        "[server]\n\
         listen = \"{listen}\"\n\
         cert = \"{}\"\n\
         key = \"{}\"\n\
         \n\
         [auth]\n\
         users = [{{ username = \"user1\", password = \"{SECRET}\" }}]\n\
         {body}",
        dir.join("cert.pem").display(),
        dir.join("key.pem").display(),
    );
    fs::write(&path, text).expect("the config must be writable");
    path
}

/// A password distinctive enough that finding it in any output is proof.
const SECRET: &str = "hunter2-TAILSECRET";

fn run(args: &[&str]) -> Output {
    Command::new(volto())
        .args(args)
        .output()
        .expect("the volto binary must be runnable")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The capability probe `script/deploy.sh` uses to tell a binary that can check
/// a configuration from one that predates the flag.
///
/// It reads `--help` rather than trying the flag and interpreting the failure,
/// so this string is a contract between the two files: rename the flag and the
/// deploy script silently falls back to the advisory it had before, on every
/// host, without a test failing anywhere else.
#[test]
fn the_help_advertises_the_flag_the_deploy_script_probes_for() {
    let output = run(&["--help"]);

    assert!(output.status.success(), "{}", stderr_of(&output));
    let usage = stdout_of(&output);
    assert!(
        usage.contains("--check-config"),
        "deploy.sh detects the flag by name in --help: {usage}"
    );
}

/// The everyday answer: the file loads, one line says so, nothing is started.
///
/// The port in the file is one this test is already holding, which is what
/// makes "nothing is started" an assertion rather than a claim — a run that
/// bound the listener would fail with the address in use. The directory is
/// checked afterwards for good measure: a check that writes is not a check.
#[test]
fn a_configuration_that_loads_is_reported_without_binding_anything() {
    let dir = config_dir("valid");

    // Held for the duration of the run, so the address really is taken.
    let taken = std::net::UdpSocket::bind("127.0.0.1:0").expect("an ephemeral port must be free");
    let listen = taken
        .local_addr()
        .expect("the bound address must be readable");

    let path = write_config(&dir, &listen.to_string(), "");
    let output = run(&["--check-config", "--config", path.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "a valid configuration must be accepted: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    assert!(
        stdout.contains(&format!("{}", path.display())),
        "the confirmation must name the file it read: {stdout}"
    );
    assert_eq!(
        stdout.lines().count(),
        1,
        "success is one line, not a report: {stdout}"
    );

    let mut left_behind: Vec<String> = fs::read_dir(&dir)
        .expect("the directory must still be readable")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    left_behind.sort();
    assert_eq!(
        left_behind,
        ["cert.pem", "config.toml", "key.pem"],
        "the check must not write anything"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// The rollback case, which is the reason the flag exists.
///
/// A key from a later release is refused whole, and the refusal has to carry the
/// one thing the operator can act on — the position — without carrying the one
/// thing it must never carry, which lives two lines above it in the same file.
#[test]
fn a_key_from_the_future_is_refused_with_its_position_and_no_secret() {
    let dir = config_dir("future-key");
    let path = write_config(
        &dir,
        "127.0.0.1:4433",
        "\n[limits]\na_key_a_later_release_added = 2\n",
    );

    let output = run(&["--check-config", "--config", path.to_str().unwrap()]);

    assert_eq!(
        output.status.code(),
        Some(1),
        "a configuration this binary cannot load must exit 1, and only clap's own \
         usage errors may exit 2: {}",
        stderr_of(&output)
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("unknown field"),
        "the refusal must say what kind of mistake it is: {stderr}"
    );
    // Computed from the file rather than written down, so the assertion stays
    // exact when the fixture above grows a line.
    let offending = fs::read_to_string(&path)
        .expect("the config must be readable")
        .lines()
        .position(|line| line.starts_with("a_key_a_later_release_added"))
        .expect("the fixture must contain the offending key")
        + 1;
    assert!(
        stderr.contains(&format!("at line {offending},")),
        "the position is the operator's only thread back to the key, since the \
         name itself is redacted: {stderr}"
    );
    assert!(
        !stderr.contains(SECRET) && !stdout_of(&output).contains(SECRET),
        "a configuration error must never echo a credential: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// The check has to be the same judgement the service makes, or it is worth
/// nothing: a file it accepts must start, and a file it refuses must not.
///
/// The refusal direction is the one a test can take all the way, since it costs
/// no socket — the configuration is loaded before anything is bound, so the
/// process is gone by the time a listener would exist. The acceptance direction
/// is covered by every other integration test in this tree, which builds its
/// server through the same `Config::load`.
#[test]
fn the_check_refuses_exactly_what_the_server_refuses_to_start_on() {
    let dir = config_dir("agreement");
    let path = write_config(
        &dir,
        "127.0.0.1:4433",
        "\n[limits]\na_key_a_later_release_added = 2\n",
    );
    let path = path.to_str().unwrap();

    let checked = run(&["--check-config", "--config", path]);
    let started = run(&["--config", path]);

    assert_eq!(
        checked.status.code(),
        started.status.code(),
        "the check and the startup must agree on the verdict"
    );
    assert_eq!(
        stderr_of(&checked),
        stderr_of(&started),
        "and on the reason, word for word"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Validation, not only parsing: a key this binary knows can still hold a value
/// it refuses, and that failure is a startup failure like any other.
#[test]
fn a_value_out_of_range_is_refused_by_the_name_of_its_key() {
    let dir = config_dir("out-of-range");
    let path = write_config(&dir, "127.0.0.1:4433", "\n[limits]\nmax_streams_bidi = 0\n");

    let output = run(&["--check-config", "--config", path.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(1), "{}", stdout_of(&output));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("limits.max_streams_bidi"),
        "a range failure must name the key: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// A file that is not there is a failure of the same kind, not a panic.
#[test]
fn a_missing_file_is_refused_by_name() {
    let dir = config_dir("missing");
    let path = dir.join("nowhere.toml");

    let output = run(&["--check-config", "--config", path.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr_of(&output).contains("failed to read config file"),
        "{}",
        stderr_of(&output)
    );

    let _ = fs::remove_dir_all(&dir);
}

/// A legal configuration that deserves a word still passes.
///
/// The warnings are the ones `Config::warnings` already produces at startup;
/// what this pins is that they go to stderr and leave the exit status alone. A
/// check that failed on "authentication is off" would refuse to deploy a
/// configuration the service runs quite happily, and one that swallowed the
/// warning would be a quieter place to hide it than the journal.
#[test]
fn a_warning_is_reported_without_failing_the_check() {
    let dir = config_dir("warned");
    let path = dir.join("config.toml");
    fs::write(
        &path,
        format!(
            "[server]\nlisten = \"127.0.0.1:4433\"\ncert = \"{}\"\nkey = \"{}\"\n",
            dir.join("cert.pem").display(),
            dir.join("key.pem").display(),
        ),
    )
    .expect("the config must be writable");

    let output = run(&["--check-config", "--config", path.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "a warning is not a failure: {}",
        stderr_of(&output)
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("authentication is DISABLED"),
        "an empty user list must still be said out loud: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// The distinction `script/deploy.sh` must never blur.
///
/// An argument the binary does not know is clap's failure, reported in clap's
/// words and with clap's exit status; a key the binary does not know is ours,
/// reported in the parser's words with exit 1. An older volto meeting
/// `--check-config` produces the first, and reading it as the second would
/// abandon a perfectly good rollback for a configuration error that does not
/// exist.
#[test]
fn an_unknown_argument_fails_differently_from_an_unknown_key() {
    let dir = config_dir("unknown-argument");
    let path = write_config(&dir, "127.0.0.1:4433", "");

    let output = run(&[
        "--config",
        path.to_str().unwrap(),
        "--definitely-not-a-flag",
    ]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "clap reports a usage error with its own status: {}",
        stderr_of(&output)
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("unexpected argument"),
        "and in its own words: {stderr}"
    );
    assert!(
        !stderr.contains("config file"),
        "which must not read like a configuration failure: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}
