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

#[path = "common/scripts.rs"]
mod scripts;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use scripts::{
    loadable_config_text, plant_placeholder_certificates, real_binary, scratch_tree, stderr_of,
    stdout_of,
};

/// A directory of this test's own, standing in for `/etc/volto`.
fn config_dir(name: &str) -> PathBuf {
    let dir = scratch_tree("cli", name, &[]);
    plant_placeholder_certificates(&dir);
    dir
}

/// Writes a configuration file naming the certificate pair planted above.
///
/// `listen` is a parameter because one test needs a port it has already taken
/// for itself; `body` is appended verbatim, tables and all.
fn write_config(dir: &Path, listen: &str, body: &str) -> PathBuf {
    let path = dir.join("config.toml");
    let text = loadable_config_text(
        &dir.join("cert.pem"),
        &dir.join("key.pem"),
        listen,
        SECRET,
        body,
    );
    fs::write(&path, text).expect("the config must be writable");
    path
}

/// A password distinctive enough that finding it in any output is proof.
const SECRET: &str = "hunter2-TAILSECRET";

/// Runs the binary to its end with `JOURNAL_STREAM` removed, so the text on
/// stderr does not depend on whether the test runner itself runs under systemd.
fn run(args: &[&str]) -> Output {
    Command::new(real_binary())
        .env_remove("JOURNAL_STREAM")
        .args(args)
        .output()
        .expect("the volto binary must be runnable")
}

/// [`run`] for a command line that would start the server if it accepted the
/// file: the process is killed, and the test fails, if it is still running
/// after `limit`.
#[track_caller]
fn run_expecting_exit(args: &[&str], limit: Duration) -> Output {
    run_expecting_exit_with(args, None, limit)
}

/// [`run_expecting_exit`] with `JOURNAL_STREAM` set to `journal_stream`, or
/// removed when it is `None`, so the result does not depend on whether the test
/// runner itself runs under systemd.
#[track_caller]
fn run_expecting_exit_with(args: &[&str], journal_stream: Option<&str>, limit: Duration) -> Output {
    let mut command = Command::new(real_binary());
    match journal_stream {
        Some(value) => command.env("JOURNAL_STREAM", value),
        None => command.env_remove("JOURNAL_STREAM"),
    };
    let mut child = command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the volto binary must be runnable");
    let started = Instant::now();
    while child
        .try_wait()
        .expect("the child must be waitable")
        .is_none()
    {
        if started.elapsed() > limit {
            let _ = child.kill();
            let output = child
                .wait_with_output()
                .expect("the killed child must be reaped");
            panic!(
                "volto {args:?} was still running after {limit:?}, so it started on a \
                 file the check refuses: {}",
                stderr_of(&output)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child
        .wait_with_output()
        .expect("the child's output must be readable")
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
}

/// The rollback case, which is the reason the flag exists.
///
/// A key from a later release is refused whole, and the refusal has to carry the
/// one thing the operator can act on, the position.
///
/// The password sits three lines above the offending key, and the parser's
/// message names neither line's contents, so the assertion on the secret here
/// cannot fail on its own. The redaction is tested where the error is on the
/// credential line itself, by
/// `a_malformed_credential_line_is_refused_without_the_secret`.
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
}

/// A parse error on the line that holds the password is reported without the
/// password.
///
/// The `users` entry is a string where a table belongs, so the error is on the
/// credential line. The `toml` crate's own rendering of that error prints the
/// line, and serde's message quotes the value it refused, so either route would
/// put [`SECRET`] on stderr and into the journal on every restart.
#[test]
fn a_malformed_credential_line_is_refused_without_the_secret() {
    let dir = config_dir("malformed-credential");
    let path = dir.join("config.toml");
    fs::write(
        &path,
        format!(
            "[server]\nlisten = \"127.0.0.1:4433\"\ncert = \"{}\"\nkey = \"{}\"\n\n\
             [auth]\nusers = [\"user1:{SECRET}\"]\n",
            dir.join("cert.pem").display(),
            dir.join("key.pem").display(),
        ),
    )
    .expect("the config must be writable");

    let output = run(&["--check-config", "--config", path.to_str().unwrap()]);

    let stderr = stderr_of(&output);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    let credential_line = fs::read_to_string(&path)
        .expect("the config must be readable")
        .lines()
        .position(|line| line.starts_with("users = "))
        .expect("the fixture must contain the users line")
        + 1;
    assert!(
        stderr.contains(&format!("at line {credential_line},")),
        "the error must be the one on the credential line: {stderr}"
    );
    assert!(
        !stderr.contains(SECRET) && !stdout_of(&output).contains(SECRET),
        "a configuration error must never echo a credential: {stderr}"
    );
}

/// The check has to be the same judgement the service makes, or it is worth
/// nothing: a file it accepts must start, and a file it refuses must not.
///
/// The refusal direction is the one a test can take all the way, since it costs
/// no socket: the configuration is loaded before anything is bound, so the
/// process is gone by the time a listener would exist. The acceptance direction
/// is covered by every other integration test in this tree, which builds its
/// server through the same `Config::load`.
///
/// If startup ever accepted the file, the server would run until killed, so the
/// start is bounded by a timeout. The file listens on a port this test holds, so
/// such a server fails to bind and says something other than the check.
#[test]
fn the_check_refuses_exactly_what_the_server_refuses_to_start_on() {
    let dir = config_dir("agreement");

    // Held for the duration of the run, so a server that got as far as binding
    // could not.
    let taken = std::net::UdpSocket::bind("127.0.0.1:0").expect("an ephemeral port must be free");
    let listen = taken
        .local_addr()
        .expect("the bound address must be readable");

    let path = write_config(
        &dir,
        &listen.to_string(),
        "\n[limits]\na_key_a_later_release_added = 2\n",
    );
    let path = path.to_str().unwrap();

    let checked = run(&["--check-config", "--config", path]);
    let started = run_expecting_exit(&["--config", path], Duration::from_secs(20));

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
}

/// A file that is not there is a failure of the same kind, not a panic.
#[test]
fn a_missing_file_is_refused_by_name() {
    let dir = config_dir("missing");
    let path = dir.join("nowhere.toml");

    let output = run(&["--check-config", "--config", path.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains(&format!("failed to read config file {}", path.display())),
        "the refusal must name the file it could not read: {stderr}"
    );
}

/// The reason a start failed reaches the journal at priority err.
///
/// journald files a line without a `<N>` prefix at the unit's `SyslogLevel=`,
/// which is info, so `journalctl -p warning` would show systemd's exit lines and
/// not the cause. Two failures are run: a missing file, which fails before any
/// subscriber exists, and a certificate that does not parse, which fails in
/// `Server::bind` after the subscriber is installed. Outside the journal the
/// output is what the standard library prints for an error returned from `main`.
#[test]
fn a_failed_start_is_filed_as_an_error_in_the_journal() {
    let dir = config_dir("journal-priority");
    // The planted certificate is not one, so this file loads and fails to bind.
    let unparseable = write_config(&dir, "127.0.0.1:0", "");
    let missing = dir.join("nowhere.toml");

    for (case, path) in [
        ("missing file", &missing),
        ("certificate that does not parse", &unparseable),
    ] {
        let args = ["--config", path.to_str().unwrap()];

        let journal = run_expecting_exit_with(&args, Some("8:12345"), Duration::from_secs(20));
        let stderr = stderr_of(&journal);
        assert_eq!(journal.status.code(), Some(1), "{case}: {stderr}");
        assert!(
            stderr.contains("Error: "),
            "{case}: the reason must still be there: {stderr}"
        );
        for line in stderr.lines() {
            assert!(
                line.starts_with("<3>"),
                "{case}: every line of the reason must be filed at err, or \
                 `journalctl -p warning` does not show it: {line:?} in\n{stderr}"
            );
        }

        let plain = run_expecting_exit_with(&args, None, Duration::from_secs(20));
        let stderr = stderr_of(&plain);
        assert_eq!(plain.status.code(), Some(1), "{case}: {stderr}");
        assert!(
            stderr.starts_with("Error: ") && !stderr.lines().any(|line| line.starts_with('<')),
            "{case}: a terminal must see no priority prefix: {stderr}"
        );
    }
}

/// A `SIGHUP` that arrives while the server is still starting is a reload, not
/// the end of the process.
///
/// `systemctl reload` sends the signal as soon as the unit is active, which for
/// `Type=simple` is as soon as the process exists. Until a handler is installed
/// the signal's default action ends the process, and systemd does not restart a
/// service that died by `SIGHUP` unless the unit says so. The first stdout line
/// is the startup warning about authentication, written before `Server::bind`.
/// The handler has to exist by then, so the signal sent at that line must come
/// back as a reload, and the process must still stop cleanly on `SIGTERM`.
///
/// What this catches is a handler created after `Server::bind`, which reads
/// and parses the certificate. It does not catch one created between the
/// warning line and `Server::bind`: that window is microseconds, and the
/// signal sent here reaches the process only after the line has crossed a
/// pipe, a reader thread and a channel. Catching that would need the binary
/// to pause at the warning line on request, which it has no hook for.
#[test]
fn a_sighup_during_startup_is_taken_as_a_reload() {
    use std::io::{BufRead, BufReader};
    use std::sync::mpsc;

    use rustix::process::{Pid, Signal, kill_process};

    let dir = scratch_tree("cli", "early-sighup", &[]);
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("a self-signed certificate must be generated");
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    fs::write(&cert, issued.cert.pem()).expect("the cert must be writable");
    fs::write(&key, issued.signing_key.serialize_pem()).expect("the key must be writable");
    // No `[auth]`, so the startup warning about it is the first line written.
    let path = dir.join("config.toml");
    fs::write(
        &path,
        format!(
            "[server]\nlisten = \"127.0.0.1:0\"\ncert = \"{}\"\nkey = \"{}\"\n",
            cert.display(),
            key.display(),
        ),
    )
    .expect("the config must be writable");

    let mut child = Command::new(real_binary())
        .args(["--config", path.to_str().unwrap()])
        .env_remove("JOURNAL_STREAM")
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the volto binary must be runnable");
    let pid = Pid::from_child(&child);

    let (lines, received) = mpsc::channel();
    let stdout = child.stdout.take().expect("stdout is piped");
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if lines.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut seen = Vec::new();
    let mut wait_for = |needle: &str, child: &mut std::process::Child| loop {
        if let Some(status) = child.try_wait().expect("the child must be waitable") {
            panic!(
                "volto exited with {status} while waiting for {needle:?}; stdout so far:\n{}",
                seen.join("\n")
            );
        }
        match received.recv_timeout(Duration::from_millis(20)) {
            Ok(line) => {
                let found = line.contains(needle);
                seen.push(line);
                if found {
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::sleep(Duration::from_millis(20))
            }
        }
        assert!(
            Instant::now() < deadline,
            "no {needle:?} within 20 s; stdout so far:\n{}",
            seen.join("\n")
        );
    };

    wait_for("authentication is DISABLED", &mut child);
    kill_process(pid, Signal::HUP).expect("SIGHUP must be deliverable");
    wait_for("received SIGHUP", &mut child);

    kill_process(pid, Signal::TERM).expect("SIGTERM must be deliverable");
    let output = child
        .wait_with_output()
        .expect("the child's output must be readable");
    assert!(
        output.status.success(),
        "volto must stop cleanly on SIGTERM after the reload: {} {}",
        output.status,
        stderr_of(&output)
    );
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
}

/// The support bundle prints what an issue needs and not what it must not carry.
///
/// The password is the assertion that matters. `--diagnostics` prints the whole
/// parsed configuration, which is exactly the shape that leaks a secret if the
/// redaction is not reached, and the operator this flag is written for is being
/// asked to paste the output somewhere public. [`SECRET`] is distinctive enough
/// that finding it anywhere in either stream is proof, and the run is over a
/// port this test already holds, so a bundle that bound the listener would fail
/// with the address in use rather than pass quietly.
#[test]
fn the_support_bundle_names_the_version_and_redacts_the_password() {
    let dir = config_dir("diagnostics");

    // Held for the duration of the run: nothing here may bind anything.
    let taken = std::net::UdpSocket::bind("127.0.0.1:0").expect("an ephemeral port must be free");
    let listen = taken
        .local_addr()
        .expect("the bound address must be readable");

    let path = write_config(&dir, &listen.to_string(), "");
    let output = run(&["--diagnostics", "--config", path.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "a support bundle over a loadable file must exit 0: {}",
        stderr_of(&output)
    );

    let stdout = stdout_of(&output);
    assert!(
        !stdout.contains(SECRET),
        "the password must not reach the bundle an operator pastes into an \
         issue: {stdout}"
    );
    assert!(
        !stderr_of(&output).contains(SECRET),
        "nor the other stream: {}",
        stderr_of(&output)
    );
    assert!(
        stdout.contains("<redacted>"),
        "and the field has to still be there, so a reader can see there was one: \
         {stdout}"
    );

    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "a bundle that does not say which binary produced it answers nothing: \
         {stdout}"
    );
    assert!(
        stdout.contains(&format!("{}", path.display())),
        "nor one that does not name the file it read: {stdout}"
    );
    for section in [
        "[limits]",
        "[security]",
        "[warnings]",
        "[file descriptors]",
        "[udp socket buffers]",
        "[operating system]",
    ] {
        assert!(
            stdout.contains(section),
            "the bundle must carry the {section} section: {stdout}"
        );
    }

    // The descriptor limits are read with `getrlimit` on the process running
    // the command, which from an SSH shell is that shell and not the service.
    // Two hosts were reported with the shell's figures because the bundle did
    // not say so, so the line that says so is part of the bundle.
    assert!(
        stdout.contains("not the service's"),
        "the bundle must say whose descriptor limits those two lines are: {stdout}"
    );
    assert!(
        stdout.contains("/proc/<MainPID>/limits"),
        "and name where the service's own figures are: {stdout}"
    );
}

/// The two flags answer different questions, so a command line naming both is
/// refused rather than resolved by a precedence nobody would remember.
#[test]
fn the_two_reporting_flags_refuse_to_be_combined() {
    let dir = config_dir("both-flags");
    let path = write_config(&dir, "127.0.0.1:4433", "");

    let output = run(&[
        "--check-config",
        "--diagnostics",
        "--config",
        path.to_str().unwrap(),
    ]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "clap reports a usage error with its own status: {}",
        stderr_of(&output)
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("--check-config") && stderr.contains("--diagnostics"),
        "and it has to name both flags, so the operator knows which to drop: \
         {stderr}"
    );
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
}

/// `ech-keygen` with the public name `public.example`, writing its key to
/// `out`.
fn keygen(out: &Path) -> Output {
    run(&[
        "ech-keygen",
        "--public-name",
        "public.example",
        "--out",
        out.to_str().unwrap(),
    ])
}

/// Adds `server.ech_key = key` to the configuration file at `config`, which
/// [`write_config`] wrote.
fn add_ech_key(config: &Path, key: &Path) {
    let text = fs::read_to_string(config).expect("the config");
    let text = text.replacen(
        "\n\n[auth]",
        &format!("\nech_key = \"{}\"\n\n[auth]", key.display()),
        1,
    );
    assert_ne!(
        fs::read_to_string(config).expect("the config"),
        text,
        "the config has an [auth] table to put the key ahead of"
    );
    fs::write(config, text).expect("rewrite the config");
}

/// Standard padded base64 (RFC 4648 §4), decoded by hand: this binary links
/// the standard library and nothing of volto's.
fn base64_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bytes = Vec::new();
    let (mut bits, mut held) = (0u32, 0u32);
    for character in text.bytes().filter(|character| *character != b'=') {
        let value = ALPHABET
            .iter()
            .position(|letter| *letter == character)
            .expect("a base64 character");
        bits = (bits << 6) | u32::try_from(value).expect("six bits");
        held += 6;
        if held >= 8 {
            held -= 8;
            bytes.push(u8::try_from(bits >> held).expect("one byte"));
            bits &= (1 << held) - 1;
        }
    }
    bytes
}

/// Asserts that `list` is an ECHConfigList holding one ECHConfig of version
/// 0xfe0d with `config_id` and `public_name`, read field by field from the
/// structures of RFC 9849 §4: `ECHConfig ECHConfigList<4..2^16-1>`, then
/// `uint16 version; uint16 length;` and the contents, whose `HpkeKeyConfig`
/// is `uint8 config_id; HpkeKemId kem_id; HpkePublicKey public_key;
/// HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;`, followed by
/// `uint8 maximum_name_length; opaque public_name<1..255>;`.
#[track_caller]
fn assert_echconfig_list(list: &[u8], config_id: u8, public_name: &str) {
    let u16_at = |at: usize| usize::from(u16::from_be_bytes([list[at], list[at + 1]]));
    assert_eq!(u16_at(0), list.len() - 2, "the list's length: {list:02x?}");
    assert_eq!(list[2..4], [0xfe, 0x0d], "the version: {list:02x?}");
    assert_eq!(u16_at(4), list.len() - 6, "one ECHConfig: {list:02x?}");
    assert_eq!(list[6], config_id, "the config_id: {list:02x?}");
    // config_id (1), kem_id (2), then the public key's own length.
    let suites = 9 + 2 + u16_at(9);
    let name = suites + 2 + u16_at(suites) + 1;
    let length = usize::from(list[name]);
    assert_eq!(
        &list[name + 1..name + 1 + length],
        public_name.as_bytes(),
        "the public name: {list:02x?}"
    );
}

/// `ech-keygen` writes a key file and prints its ECHConfigList, `ech-config`
/// prints the same list from the file, and an existing file is not replaced.
#[test]
fn the_ech_subcommands_write_a_key_and_print_its_list_again() {
    let dir = config_dir("ech-keygen");
    let key = dir.join("ech.pem");
    let key_arg = key.to_str().unwrap();

    let written = run(&[
        "ech-keygen",
        "--public-name",
        "public.example",
        "--config-id",
        "5",
        "--out",
        key_arg,
    ]);
    assert_eq!(written.status.code(), Some(0), "{}", stderr_of(&written));
    let list = stdout_of(&written);
    let list = list.trim();
    assert!(
        list.len() > 60
            && list
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)),
        "stdout is one base64 ECHConfigList: {list:?}"
    );
    assert_echconfig_list(&base64_decode(list), 5, "public.example");
    let text = fs::read_to_string(&key).expect("the key file was written");
    assert!(text.starts_with("-----BEGIN PRIVATE KEY-----\n"), "{text}");
    assert!(text.contains("-----BEGIN ECHCONFIG-----\n"));
    assert!(!list.is_empty() && !stderr_of(&written).contains(text.lines().nth(1).unwrap()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(&key).expect("metadata").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the key file is readable by its owner only"
        );
    }

    let printed = run(&["ech-config", key_arg]);
    assert_eq!(printed.status.code(), Some(0), "{}", stderr_of(&printed));
    assert_eq!(stdout_of(&printed).trim(), list);

    let again = keygen(&key);
    assert_eq!(again.status.code(), Some(1));
    assert!(
        stderr_of(&again).contains("never replaced"),
        "{}",
        stderr_of(&again)
    );
    assert_eq!(fs::read_to_string(&key).expect("the key file"), text);

    let refused = run(&[
        "ech-keygen",
        "--public-name",
        "192.0.2.1",
        "--out",
        dir.join("other.pem").to_str().unwrap(),
    ]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        stderr_of(&refused).contains("numeric label"),
        "{}",
        stderr_of(&refused)
    );
    assert!(
        !dir.join("other.pem").exists(),
        "nothing is written for a refused name"
    );
}

/// `--check-config` reads the ECH key file whole, and refuses one the server
/// would refuse at startup, by the key's name.
#[test]
fn the_check_refuses_a_bad_ech_key_file_by_the_name_of_its_key() {
    let dir = config_dir("ech-check");
    let key = dir.join("ech.pem");
    let written = keygen(&key);
    assert_eq!(written.status.code(), Some(0), "{}", stderr_of(&written));

    let path = write_config(&dir, "127.0.0.1:4433", "");
    add_ech_key(&path, &key);
    let checked = run(&["--check-config", "--config", path.to_str().unwrap()]);
    assert_eq!(checked.status.code(), Some(0), "{}", stderr_of(&checked));

    // The private key of one file with the ECHConfig of another.
    let other = dir.join("other.pem");
    let generated = keygen(&other);
    assert_eq!(generated.status.code(), Some(0));
    let mine = fs::read_to_string(&key).expect("key");
    let theirs = fs::read_to_string(&other).expect("other");
    let private: String = mine
        .split_inclusive('\n')
        .take_while(|l| !l.starts_with("-----BEGIN ECHCONFIG"))
        .collect();
    let config: String = theirs
        .split_inclusive('\n')
        .skip_while(|l| !l.starts_with("-----BEGIN ECHCONFIG"))
        .collect();
    let mixed = dir.join("mixed.pem");
    fs::write(&mixed, format!("{private}{config}")).expect("write the mixed file");

    let path = write_config(&dir, "127.0.0.1:4433", "");
    add_ech_key(&path, &mixed);
    let refused = run(&["--check-config", "--config", path.to_str().unwrap()]);
    assert_eq!(refused.status.code(), Some(1), "{}", stdout_of(&refused));
    let stderr = stderr_of(&refused);
    assert!(
        stderr.contains("server.ech_key"),
        "the refusal names the key: {stderr}"
    );
    assert!(stderr.contains("do not form a usable ECH key"), "{stderr}");
}

/// An X.509 version 1 certificate for `localhost` and its key, the same pair
/// as `V1_CERT` and `V1_KEY` in `src/tls/awslc/tests.rs`, where the comment
/// says how it was made. webpki refuses a version 1 certificate.
const V1_CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIIBGjCBwAIJALKFNYcyBwe7MAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCWxvY2Fs
aG9zdDAgFw0yNjExMjAwODM5NDJaGA8yMTI2MTAyNzA4Mzk0MlowFDESMBAGA1UE
AwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd7BPf1SU7GG7
dAQRZRjFZsj/C///uZeAv/6dllF2WSOg0jx3a541t309Kry8QDHHGyjrPD5rYAMI
z29KVavRaDAKBggqhkjOPQQDAgNJADBGAiEApJ4xsVnqSsULDQU0wPoviHYfBitq
6gQhlG7+L/OETTICIQDgqTmvSvGJzQnKePJ8SYZzY3x0uWrIqAE2NcuIKjbeeQ==
-----END CERTIFICATE-----
";
const V1_KEY: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7FpxDT+FSsvFUCih
yShn4Z4G7F1ocW9wTR/1r9ZRugOhRANCAAR3sE9/VJTsYbt0BBFlGMVmyP8L//+5
l4C//p2WUXZZI6DSPHdrnjW3fT0qvLxAMccbKOs8PmtgAwjPb0pVq9Fo
-----END PRIVATE KEY-----
";

/// `--check-config` refuses a leaf certificate webpki cannot parse, in the
/// words the server refuses it with at startup, because the server's TLS
/// would bind it and the `expected_sni` coverage warning cannot read it.
#[test]
fn the_check_refuses_a_leaf_webpki_cannot_parse() {
    let dir = config_dir("v1-leaf");
    fs::write(dir.join("cert.pem"), V1_CERT).expect("write the certificate");
    fs::write(dir.join("key.pem"), V1_KEY).expect("write the key");
    let path = write_config(&dir, "127.0.0.1:4433", "");
    let refused = run(&["--check-config", "--config", path.to_str().unwrap()]);
    assert_eq!(refused.status.code(), Some(1), "{}", stdout_of(&refused));
    let stderr = stderr_of(&refused);
    assert!(
        stderr.contains("server.cert and server.key do not form a usable certificate/key pair"),
        "{stderr}"
    );
}

/// `--check-config` refuses `security.require_ech` without `server.ech_key`,
/// naming both keys, because no client could reach such a server; with a key
/// it accepts it.
#[test]
fn the_check_refuses_require_ech_without_an_ech_key() {
    let dir = config_dir("require-ech-check");
    let path = write_config(&dir, "127.0.0.1:4433", "\n[security]\nrequire_ech = true\n");
    let refused = run(&["--check-config", "--config", path.to_str().unwrap()]);
    assert_eq!(refused.status.code(), Some(1), "{}", stdout_of(&refused));
    let stderr = stderr_of(&refused);
    assert!(
        stderr.contains("security.require_ech") && stderr.contains("server.ech_key"),
        "the refusal names both keys: {stderr}"
    );

    let key = dir.join("ech.pem");
    let written = keygen(&key);
    assert_eq!(written.status.code(), Some(0), "{}", stderr_of(&written));
    add_ech_key(&path, &key);
    let checked = run(&["--check-config", "--config", path.to_str().unwrap()]);
    assert_eq!(checked.status.code(), Some(0), "{}", stderr_of(&checked));
}
