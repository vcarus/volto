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

// For the QUIC client that shows a server started under a notification socket
// nobody listens on still serves.
mod common;
#[path = "common/scripts.rs"]
mod scripts;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use scripts::{
    Scratch, loadable_config_text, plant_placeholder_certificates, real_binary, scratch_tree,
    server_section, stderr_of, stdout_of, write_private,
};

/// A directory of this test's own, standing in for `/etc/volto`.
fn config_dir(name: &str) -> Scratch {
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
    write_private(&path, &text);
    path
}

/// A password distinctive enough that finding it in any output is proof.
const SECRET: &str = "hunter2-TAILSECRET";

/// Runs the binary to its end with `JOURNAL_STREAM` and `RUST_LOG` removed, so
/// the text on stderr does not depend on whether the test runner itself runs
/// under systemd, and `--check-config`, which judges `RUST_LOG`, does not
/// depend on the runner's own value.
fn run(args: &[&str]) -> Output {
    run_in(args, &[])
}

/// [`run`] with `env` set after the two variables are removed.
fn run_in(args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(real_binary())
        .env_remove("JOURNAL_STREAM")
        .env_remove("RUST_LOG")
        .envs(env.iter().copied())
        .args(args)
        .output()
        .expect("the volto binary must be runnable")
}

/// [`run_in`] for a command line that would start the server if it accepted
/// the file: the process is killed, and the test fails, if it is still running
/// after `limit`. `JOURNAL_STREAM` and `RUST_LOG` are removed from the
/// environment, then `env` set, so the result depends on neither variable of
/// the test runner's own.
#[track_caller]
fn run_expecting_exit_in(args: &[&str], env: &[(&str, &str)], limit: Duration) -> Output {
    let mut command = Command::new(real_binary());
    command.env_remove("JOURNAL_STREAM").env_remove("RUST_LOG");
    command.envs(env.iter().copied());
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
                "volto {args:?} was still running after {limit:?}, so it did not stop \
                 on its own: {}",
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

/// `--help` is written for an operator: a doc comment's later paragraphs are
/// part of the long help clap prints, so none of them may be about clap.
#[test]
fn the_help_says_nothing_about_how_it_is_built() {
    let output = run(&["--help"]);

    assert!(output.status.success(), "{}", stderr_of(&output));
    let usage = stdout_of(&output);
    for word in ["clap", "conflicts_with"] {
        assert!(!usage.contains(word), "--help names {word}: {usage}");
    }
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
    write_private(
        &path,
        &format!(
            "{}\n[auth]\nusers = [\"user1:{SECRET}\"]\n",
            server_section(
                &dir.join("cert.pem"),
                &dir.join("key.pem"),
                "127.0.0.1:4433"
            ),
        ),
    );

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
    let started = run_expecting_exit_in(&["--config", path], &[], Duration::from_secs(20));

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

        let journal = run_expecting_exit_in(
            &args,
            &[("JOURNAL_STREAM", "8:12345")],
            Duration::from_secs(20),
        );
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

        let plain = run_expecting_exit_in(&args, &[], Duration::from_secs(20));
        let stderr = stderr_of(&plain);
        assert_eq!(plain.status.code(), Some(1), "{case}: {stderr}");
        assert!(
            stderr.starts_with("Error: ") && !stderr.lines().any(|line| line.starts_with('<')),
            "{case}: a terminal must see no priority prefix: {stderr}"
        );
    }
}

/// A log filter that would turn this server's own lines off stops the start,
/// from the environment as from the file, so the startup warnings (the
/// open-proxy warning among them) cannot be switched off without an error.
///
/// The planted certificate does not parse, so a start that gets past the log
/// filter fails later, in `Server::bind`, for a reason that does not name
/// `RUST_LOG`. That is what tells the refusal from a start that went on.
#[test]
fn a_log_filter_that_silences_the_server_stops_the_start() {
    let dir = config_dir("silenced-log");
    let path = write_config(&dir, "127.0.0.1:0", "");
    let args = ["--config", path.to_str().unwrap()];
    let limit = Duration::from_secs(20);

    for value in ["off", "OFF", "0", "volto=off", "quinn=off"] {
        let journal = [("RUST_LOG", value), ("JOURNAL_STREAM", "8:12345")];
        let output = run_expecting_exit_in(&args, &journal, limit);
        let stderr = stderr_of(&output);
        assert_eq!(output.status.code(), Some(1), "RUST_LOG={value}: {stderr}");
        for needle in ["RUST_LOG", &format!("{value:?}"), "\"info\""] {
            assert!(
                stderr.contains(needle),
                "RUST_LOG={value}: the refusal must name the variable, the value and \
                 the accepted values ({needle}): {stderr}"
            );
        }
        assert!(
            stderr.lines().all(|line| line.starts_with("<3>")),
            "RUST_LOG={value}: the refusal is a start failure, filed at err: {stderr}"
        );
    }

    // Another crate turned off beside a level is legal: the start goes on and
    // fails at the certificate.
    let output = run_expecting_exit_in(&args, &[("RUST_LOG", "info,quinn=off")], limit);
    let stderr = stderr_of(&output);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        !stderr.contains("RUST_LOG"),
        "info,quinn=off must be applied, not refused: {stderr}"
    );

    // The same rule for the key, which `--check-config` reports.
    let dir = config_dir("silenced-level");
    let path = write_config(&dir, "127.0.0.1:0", "\n[log]\nlevel = \"volto=off\"\n");
    let output = run(&["--check-config", "--config", path.to_str().unwrap()]);
    let stderr = stderr_of(&output);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    for needle in ["log.level", "\"volto=off\"", "\"info\""] {
        assert!(stderr.contains(needle), "{needle}: {stderr}");
    }
}

/// `--check-config` judges `RUST_LOG` when it is set, by the function startup
/// installs the filter with, so a value that would stop the start fails the
/// check with startup's message (F3-M2). `script/deploy.sh` runs the check with
/// the service unit's `RUST_LOG` to see exactly this.
///
/// A value startup would ignore in favour of `log.level` is a warning and
/// leaves the status alone, as it leaves the start alone.
#[test]
fn the_check_judges_rust_log_by_the_rule_startup_applies() {
    let dir = config_dir("check-rust-log");
    let path = write_config(&dir, "127.0.0.1:0", "");
    let args = ["--check-config", "--config", path.to_str().unwrap()];

    for value in ["quinn=debug", "off", " volto=off"] {
        let output = run_in(&args, &[("RUST_LOG", value)]);
        let stderr = stderr_of(&output);
        assert_eq!(
            output.status.code(),
            Some(1),
            "RUST_LOG={value:?}: {stderr}"
        );
        for needle in ["RUST_LOG", &format!("{:?}", value.trim()), "\"info\""] {
            assert!(
                stderr.contains(needle),
                "RUST_LOG={value:?}: the refusal must be startup's ({needle}): {stderr}"
            );
        }
        assert!(
            stdout_of(&output).is_empty(),
            "RUST_LOG={value:?}: a refused check reports no success"
        );
    }

    for value in ["info,quinn=debug", "volto=debug", " info"] {
        let output = run_in(&args, &[("RUST_LOG", value)]);
        assert!(
            output.status.success(),
            "RUST_LOG={value:?} must pass the check: {}",
            stderr_of(&output)
        );
        assert!(
            !stderr_of(&output).contains("RUST_LOG"),
            "RUST_LOG={value:?} applies, so nothing is said about it: {}",
            stderr_of(&output)
        );
    }

    let output = run_in(&args, &[("RUST_LOG", "warning")]);
    let stderr = stderr_of(&output);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("warning: RUST_LOG would be ignored at startup"),
        "a RUST_LOG startup ignores is reported as a warning: {stderr}"
    );
}

/// A `SIGHUP` that arrives while the server is still starting is a reload, not
/// the end of the process.
///
/// Under `Type=notify` the unit is active only once the server has sent
/// `READY=1`, which is after the handler exists. A `SIGHUP` sent by other means,
/// such as `kill` or a renewal hook that does not go through systemd, can still
/// arrive earlier. Until a handler is installed
/// the signal's default action ends the process, and systemd does not restart a
/// service that died by `SIGHUP` unless the unit says so. The startup warnings
/// are written before `Server::bind`. The handler has to exist by then, so the
/// signal sent at a warning line must come back as a reload, and the process
/// must still stop cleanly on `SIGTERM`.
///
/// Without help the window between the warning line and `Server::bind` lasts
/// microseconds, and the signal sent here reaches the process only after the
/// line has crossed a pipe, a reader thread and a channel; a handler created
/// inside that window would pass. So a debug build run with
/// `VOLTO_DEBUG_PAUSE_AFTER_THE_WARNINGS` waits for a line on stdin after the
/// warnings, the signal is sent during that wait, and the line is written
/// after it. A release build has no such wait (`cfg(debug_assertions)` in
/// `src/main.rs`), so under `cargo test --release` this catches only a handler
/// created after `Server::bind`.
#[test]
fn a_sighup_during_startup_is_taken_as_a_reload() {
    use std::io::Write;

    use rustix::process::{Pid, Signal, kill_process};

    let dir = scratch_tree("cli", "early-sighup", &[]);
    // A keep-alive of 0 draws a startup warning, so there is a line to send
    // the signal at.
    let mut serving = Serving::start(
        &dir,
        "\n[limits]\nkeep_alive_interval = 0\n",
        &[(
            "VOLTO_DEBUG_PAUSE_AFTER_THE_WARNINGS",
            std::ffi::OsStr::new("1"),
        )],
    );
    let pid = Pid::from_child(&serving.child.0);
    let mut stdin = serving.child.0.stdin.take().expect("stdin is piped");

    serving.wait_for("limits.keep_alive_interval = 0");
    // The process is now waiting for this line, before `Server::bind`. A
    // signal whose action is still the default ends it at once, before the
    // line can be read.
    kill_process(pid, Signal::HUP).expect("SIGHUP must be deliverable");
    writeln!(stdin, "go").expect("the paused process must read its stdin");
    serving.wait_for("received SIGHUP");

    let (status, _, stderr) = serving.stop();
    assert!(
        status.success(),
        "volto must stop cleanly on SIGTERM after the reload: {status} {stderr}"
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
    write_private(
        &path,
        &server_section(
            &dir.join("cert.pem"),
            &dir.join("key.pem"),
            "127.0.0.1:4433",
        ),
    );

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

/// A configuration file every local user can read is reported by the check,
/// without failing it; the group-readable mode an install gives it is not.
#[test]
fn a_file_readable_by_others_is_reported_by_the_check() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = config_dir("world-readable");
    let path = write_config(&dir, "127.0.0.1:4433", "");
    for (mode, warns) in [(0o644, true), (0o640, false)] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("set the mode");
        let output = run(&["--check-config", "--config", path.to_str().unwrap()]);
        let stderr = stderr_of(&output);
        assert!(output.status.success(), "{mode:o}: {stderr}");
        assert_eq!(
            stderr.contains(&format!("chmod o-r {}", path.display())),
            warns,
            "{mode:o}: {stderr}"
        );
    }
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
    assert!(
        stdout.contains("not the service's"),
        "the bundle must say whose descriptor limits those two lines are: {stdout}"
    );
    assert!(
        stdout.contains("/proc/<MainPID>/limits"),
        "and name where the service's own figures are: {stdout}"
    );
}

/// The bundle's operating system line is the three words `uname -srm` prints,
/// read without a `uname` program: a minimal container has none on its `PATH`,
/// and the run below has an empty one.
#[test]
fn the_support_bundle_reads_the_kernel_without_a_uname_program() {
    let dir = config_dir("diagnostics-uname");
    let path = write_config(&dir, "127.0.0.1:4433", "");
    let output = Command::new(real_binary())
        .env_remove("JOURNAL_STREAM")
        .env("PATH", "")
        .args(["--diagnostics", "--config", path.to_str().unwrap()])
        .output()
        .expect("the volto binary must be runnable");
    assert!(output.status.success(), "{}", stderr_of(&output));

    let stdout = stdout_of(&output);
    let line = stdout
        .lines()
        .skip_while(|line| *line != "[operating system]")
        .nth(1)
        .unwrap_or_else(|| panic!("no operating system line: {stdout}"));
    let uname = Command::new("uname")
        .args(["-s", "-r", "-m"])
        .output()
        .expect("the test host has uname");
    assert_eq!(line, String::from_utf8_lossy(&uname.stdout).trim());
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

/// Standard padded base64 (RFC 4648 §4), decoded by hand rather than by
/// volto's decoder, so the two cannot agree by sharing a defect.
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
/// `uint8 maximum_name_length; opaque public_name<1..255>;`. Returns the
/// `maximum_name_length`.
#[track_caller]
fn assert_echconfig_list(list: &[u8], config_id: u8, public_name: &str) -> u8 {
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
    list[name - 1]
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
    assert!(!stderr_of(&written).contains(text.lines().nth(1).unwrap()));
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(&key).expect("metadata").permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "the key file is readable by its owner only"
    );

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

/// Adds `server.ech_previous_key = key` to a configuration file that
/// [`add_ech_key`] already gave an `ech_key`.
fn add_ech_previous_key(config: &Path, key: &Path) {
    let text = fs::read_to_string(config).expect("the config");
    let with = text.replacen(
        "\nech_key = ",
        &format!("\nech_previous_key = \"{}\"\nech_key = ", key.display()),
        1,
    );
    assert_ne!(
        text, with,
        "the config has an ech_key to put the key beside"
    );
    fs::write(config, with).expect("rewrite the config");
}

/// `ech-keygen --replaces` gives the new key a config_id other than the
/// replaced key's and, without `--public-name` and `--max-name-length`, that
/// key's public name and `maximum_name_length`. An
/// explicit `--config-id` equal to the replaced key's is refused and writes
/// nothing.
///
/// A random config_id equals the replaced key's once in 256 runs without the
/// rule, so the inherited case below cannot be relied on to fail when the rule
/// is removed. The explicit `--config-id` case fails every time.
#[test]
fn a_replacing_ech_key_takes_another_config_id_and_the_same_public_name() {
    let dir = config_dir("ech-replaces");
    let current = dir.join("ech.pem");
    let written = run(&[
        "ech-keygen",
        "--public-name",
        "front.example",
        "--config-id",
        "200",
        "--max-name-length",
        "64",
        "--out",
        current.to_str().unwrap(),
    ]);
    assert_eq!(written.status.code(), Some(0), "{}", stderr_of(&written));
    let before = fs::read_to_string(&current).expect("the current key");

    let inherited = dir.join("inherited.pem");
    let made = run(&[
        "ech-keygen",
        "--replaces",
        current.to_str().unwrap(),
        "--out",
        inherited.to_str().unwrap(),
    ]);
    assert_eq!(made.status.code(), Some(0), "{}", stderr_of(&made));
    let list = base64_decode(stdout_of(&made).trim());
    assert_ne!(list[6], 200, "the replaced key's config_id");
    assert_eq!(
        assert_echconfig_list(&list, list[6], "front.example"),
        64,
        "the replaced key's maximum_name_length"
    );

    let named = dir.join("named.pem");
    let made = run(&[
        "ech-keygen",
        "--replaces",
        current.to_str().unwrap(),
        "--public-name",
        "other.example",
        "--config-id",
        "201",
        "--max-name-length",
        "7",
        "--out",
        named.to_str().unwrap(),
    ]);
    assert_eq!(made.status.code(), Some(0), "{}", stderr_of(&made));
    let list = base64_decode(stdout_of(&made).trim());
    assert_eq!(
        assert_echconfig_list(&list, 201, "other.example"),
        7,
        "the value the flag gave"
    );

    let same = dir.join("same.pem");
    let refused = run(&[
        "ech-keygen",
        "--replaces",
        current.to_str().unwrap(),
        "--config-id",
        "200",
        "--out",
        same.to_str().unwrap(),
    ]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        stderr_of(&refused).contains("--config-id 200 is the config_id of the key --replaces"),
        "{}",
        stderr_of(&refused)
    );
    assert!(!same.exists(), "nothing is written for a refused config_id");

    let missing = run(&[
        "ech-keygen",
        "--replaces",
        dir.join("absent.pem").to_str().unwrap(),
        "--out",
        same.to_str().unwrap(),
    ]);
    assert_eq!(missing.status.code(), Some(1));
    let stderr = stderr_of(&missing);
    assert!(
        stderr.contains("failed to read --replaces = ") && !stderr.contains("server.ech_key"),
        "the file is named by the flag that named it: {stderr}"
    );
    assert!(
        !same.exists(),
        "nothing is written when the replaced key does not read"
    );

    let neither = run(&["ech-keygen", "--out", same.to_str().unwrap()]);
    assert_eq!(neither.status.code(), Some(2), "{}", stderr_of(&neither));
    assert!(
        stderr_of(&neither).contains("--public-name"),
        "{}",
        stderr_of(&neither)
    );
    assert_eq!(
        fs::read_to_string(&current).expect("the current key"),
        before,
        "the replaced key is only read"
    );
}

/// `--check-config` reads `server.ech_previous_key` and holds it to the rules
/// startup holds it to: a second key with another config_id passes, one with
/// the current key's config_id is refused by both keys' names, a file that is
/// not there is refused by its path, and so is the key without `ech_key`.
#[test]
fn the_check_holds_the_previous_ech_key_to_the_rules_of_startup() {
    let dir = config_dir("ech-previous-check");
    let current = dir.join("ech.pem");
    let written = keygen(&current);
    assert_eq!(written.status.code(), Some(0), "{}", stderr_of(&written));
    // The config_id, read from the list `ech-keygen` printed.
    let id = base64_decode(stdout_of(&written).trim())[6];
    let check = |path: &Path| run(&["--check-config", "--config", path.to_str().unwrap()]);

    let previous = dir.join("ech-old.pem");
    let made = run(&[
        "ech-keygen",
        "--replaces",
        current.to_str().unwrap(),
        "--out",
        previous.to_str().unwrap(),
    ]);
    assert_eq!(made.status.code(), Some(0), "{}", stderr_of(&made));
    let path = write_config(&dir, "127.0.0.1:4433", "");
    add_ech_key(&path, &current);
    add_ech_previous_key(&path, &previous);
    let checked = check(&path);
    assert_eq!(checked.status.code(), Some(0), "{}", stderr_of(&checked));

    let twin = dir.join("ech-twin.pem");
    let made = run(&[
        "ech-keygen",
        "--public-name",
        "public.example",
        "--config-id",
        &id.to_string(),
        "--out",
        twin.to_str().unwrap(),
    ]);
    assert_eq!(made.status.code(), Some(0), "{}", stderr_of(&made));
    let path = write_config(&dir, "127.0.0.1:4433", "");
    add_ech_key(&path, &current);
    add_ech_previous_key(&path, &twin);
    let refused = check(&path);
    assert_eq!(refused.status.code(), Some(1));
    let stderr = stderr_of(&refused);
    assert!(
        stderr.contains(&format!(
            "server.ech_key and server.ech_previous_key both have config_id {id}"
        )),
        "{stderr}"
    );

    let path = write_config(&dir, "127.0.0.1:4433", "");
    add_ech_key(&path, &current);
    add_ech_previous_key(&path, &dir.join("absent.pem"));
    let refused = check(&path);
    assert_eq!(refused.status.code(), Some(1));
    let stderr = stderr_of(&refused);
    assert!(
        stderr.contains("ech_previous_key") && stderr.contains("absent.pem"),
        "{stderr}"
    );

    let path = write_config(&dir, "127.0.0.1:4433", "");
    let text = fs::read_to_string(&path).expect("the config");
    let with = text.replacen(
        "\n\n[auth]",
        &format!("\nech_previous_key = \"{}\"\n\n[auth]", previous.display()),
        1,
    );
    assert_ne!(text, with);
    fs::write(&path, with).expect("rewrite the config");
    let refused = check(&path);
    assert_eq!(refused.status.code(), Some(1));
    let stderr = stderr_of(&refused);
    assert!(
        stderr.contains("ech_previous_key") && stderr.contains("ech_key"),
        "{stderr}"
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

/// A volto serving a real certificate on a loopback port of its own, with
/// its stdout read line by line.
///
/// `JOURNAL_STREAM`, `RUST_LOG` and the three variables of the notification
/// protocol are removed before `env` is set, so the run depends on none of
/// the test runner's own.
struct Serving {
    child: Reaped,
    lines: std::sync::mpsc::Receiver<String>,
    seen: Vec<String>,
    addr: std::net::SocketAddr,
    ca: rustls::pki_types::CertificateDer<'static>,
}

impl Serving {
    /// Starts the binary on a configuration written into `dir`, with `body`
    /// appended to it and stdin and both output streams piped and nothing
    /// reading or writing them yet. Returns the child, the address it listens
    /// on and its certificate.
    fn spawn(
        dir: &Path,
        body: &str,
        env: &[(&str, &std::ffi::OsStr)],
    ) -> (
        Reaped,
        std::net::SocketAddr,
        rustls::pki_types::CertificateDer<'static>,
    ) {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("a self-signed certificate must be generated");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        fs::write(&cert, issued.cert.pem()).expect("the cert must be writable");
        fs::write(&key, issued.signing_key.serialize_pem()).expect("the key must be writable");

        // A port the kernel just handed out and this test let go of, so that
        // the test knows which port to ask about afterwards.
        let addr = std::net::UdpSocket::bind("127.0.0.1:0")
            .and_then(|socket| socket.local_addr())
            .expect("an ephemeral port must be free");
        let path = dir.join("config.toml");
        write_private(
            &path,
            &loadable_config_text(&cert, &key, &addr.to_string(), SECRET, body),
        );

        let child = Command::new(real_binary())
            .args(["--config", path.to_str().unwrap()])
            .env_remove("JOURNAL_STREAM")
            .env_remove("RUST_LOG")
            .env_remove("NOTIFY_SOCKET")
            .env_remove("WATCHDOG_USEC")
            .env_remove("WATCHDOG_PID")
            // Plain text, so a line can be matched on its fields.
            .env("NO_COLOR", "1")
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the volto binary must be runnable");
        (Reaped(child), addr, issued.cert.der().clone())
    }

    /// Starts the binary as [`Self::spawn`] does and reads its stdout.
    fn start(dir: &Path, body: &str, env: &[(&str, &std::ffi::OsStr)]) -> Self {
        use std::io::{BufRead, BufReader};

        let (mut child, addr, ca) = Self::spawn(dir, body, env);
        let (sender, lines) = std::sync::mpsc::channel();
        let stdout = child.0.stdout.take().expect("stdout is piped");
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });

        Self {
            child,
            lines,
            seen: Vec::new(),
            addr,
            ca,
        }
    }

    /// Reads stdout until a line contains `needle`, failing on an exit or
    /// after 20 s.
    #[track_caller]
    fn wait_for(&mut self, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.0.try_wait().expect("the child must be waitable") {
                panic!(
                    "volto exited with {status} while waiting for {needle:?}; stdout so far:\n{}",
                    self.seen.join("\n")
                );
            }
            if let Ok(line) = self.lines.recv_timeout(Duration::from_millis(20)) {
                let found = line.contains(needle);
                self.seen.push(line);
                if found {
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "no {needle:?} within 20 s; stdout so far:\n{}",
                self.seen.join("\n")
            );
        }
    }

    /// Stops the server with `SIGTERM` and returns its exit status with
    /// every stdout line it wrote.
    fn stop(mut self) -> (std::process::ExitStatus, Vec<String>, String) {
        use rustix::process::{Pid, Signal, kill_process};

        kill_process(Pid::from_child(&self.child.0), Signal::TERM)
            .expect("SIGTERM must be deliverable");
        // Read to the pipe's end, which the exit closes, before the wait, so
        // that a child with a full pipe is not waited for while it waits.
        let mut stderr = Vec::new();
        if let Some(mut pipe) = self.child.0.stderr.take() {
            use std::io::Read as _;
            pipe.read_to_end(&mut stderr)
                .expect("the child's stderr must be readable");
        }
        let status = self.child.0.wait().expect("the child must be waitable");
        // The reader thread ends at the pipe's end, which the exit closes.
        self.seen.extend(self.lines.iter());
        (
            status,
            self.seen,
            String::from_utf8_lossy(&stderr).into_owned(),
        )
    }
}

/// A child that is killed and reaped when this is dropped, so that a test
/// which fails before it stops its server leaves no process behind.
struct Reaped(std::process::Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A server that can write neither its log nor a complaint about it still
/// starts, and still stops on `SIGTERM`.
///
/// The test closes the reading ends of the server's stdout and stderr, so every
/// write to either fails with a broken pipe. tracing-subscriber's default is to
/// report a log line it could not write with `eprintln!`, and `eprintln!`
/// panics when stderr cannot be written. The server turns that report off
/// (`log_internal_errors(false)`), so a broken pipe costs the line and nothing
/// else. `READY=1` on a notification socket is how the test knows the server is
/// up without reading its output.
#[test]
fn a_server_that_cannot_write_its_log_still_starts_and_stops() {
    use std::os::unix::net::UnixDatagram;

    use rustix::process::{Pid, Signal, kill_process};

    let dir = scratch_tree("cli", "log-closed", &[]);
    let socket = dir.join("notify");
    let receiver = UnixDatagram::bind(&socket).expect("the notification socket must bind");
    receiver
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("a read timeout");
    let (mut child, _addr, _ca) =
        Serving::spawn(&dir, "", &[("NOTIFY_SOCKET", socket.as_os_str())]);
    drop(child.0.stdout.take());
    drop(child.0.stderr.take());

    let mut buf = [0u8; 64];
    let len = receiver
        .recv(&mut buf)
        .expect("READY=1 must arrive within 20 s from a server that cannot write its log");
    assert_eq!(&buf[..len], b"READY=1");
    // Long enough for the accept loop to have written its startup line, which
    // is the first write after `READY=1` that has to fail without a panic.
    std::thread::sleep(Duration::from_millis(300));

    kill_process(Pid::from_child(&child.0), Signal::TERM).expect("SIGTERM must be deliverable");
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("the child must be waitable") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the server was still running 20 s after SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        status.success(),
        "the server must stop cleanly on SIGTERM: {status}"
    );
}

/// Under `Type=notify` the server says `READY=1` once its listener is bound,
/// and not before, and under `WatchdogSec=` keep-alives follow.
///
/// The test owns the notification socket, as systemd does. When the message
/// arrives the test tries to bind the server's port itself, and that bind has
/// to fail: the server's socket already holds it. `WATCHDOG_USEC` is 200 ms, so
/// a keep-alive is due every 100 ms, and at least two have to arrive.
#[test]
fn readiness_is_sent_once_the_listener_is_bound_and_keep_alives_follow() {
    use std::os::unix::net::UnixDatagram;

    let dir = scratch_tree("cli", "ready", &[]);
    let socket = dir.join("notify");
    let receiver = UnixDatagram::bind(&socket).expect("the notification socket must bind");
    receiver
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("a read timeout");
    let serving = Serving::start(
        &dir,
        "",
        &[
            ("NOTIFY_SOCKET", socket.as_os_str()),
            ("WATCHDOG_USEC", std::ffi::OsStr::new("200000")),
        ],
    );

    let mut buf = [0u8; 256];
    let len = receiver
        .recv(&mut buf)
        .expect("READY=1 must arrive within 20 s");
    assert_eq!(&buf[..len], b"READY=1");
    let probe = std::net::UdpSocket::bind(serving.addr);
    assert_eq!(
        probe.as_ref().map_err(std::io::Error::kind).err(),
        Some(std::io::ErrorKind::AddrInUse),
        "the listener must be bound by the time READY=1 arrives: {probe:?}"
    );
    for keep_alive in 1..=2 {
        let len = receiver
            .recv(&mut buf)
            .unwrap_or_else(|error| panic!("keep-alive {keep_alive} must arrive: {error}"));
        assert_eq!(&buf[..len], b"WATCHDOG=1", "keep-alive {keep_alive}");
    }

    let (status, lines, stderr) = serving.stop();
    assert!(
        status.success(),
        "volto must stop cleanly on SIGTERM: {status} {stderr}\n{}",
        lines.join("\n")
    );
}

/// A notification socket nobody listens on is one WARN line, and the server
/// starts and serves without notifications.
#[test]
fn a_notification_socket_nobody_listens_on_is_one_warning_and_no_outage() {
    let dir = scratch_tree("cli", "notify-absent", &[]);
    let socket = dir.join("nobody");
    let mut serving = Serving::start(
        &dir,
        "",
        &[
            ("NOTIFY_SOCKET", socket.as_os_str()),
            ("WATCHDOG_USEC", std::ffi::OsStr::new("200000")),
        ],
    );
    serving.wait_for("accepting QUIC connections");

    let runtime = tokio::runtime::Runtime::new().expect("a runtime for the client");
    runtime.block_on(async {
        let endpoint = common::client_endpoint(&serving.ca, &["h3"]);
        let connection = common::finish_connect(&endpoint, serving.addr)
            .await
            .expect("the server must complete a QUIC handshake");
        connection.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
    });

    let (status, lines, stderr) = serving.stop();
    assert!(status.success(), "{status} {stderr}\n{}", lines.join("\n"));
    // Only the lines of `volto::systemd` are counted. Startup has WARN lines of
    // its own that depend on the host, such as a socket buffer the kernel
    // capped, which a Linux runner at its default `rmem_max` writes.
    const NOTIFICATION_LINES: [&str; 5] = [
        "log_id=\"wkj009dk\"",
        "log_id=\"h6ro04gv\"",
        "log_id=\"kyd7134y\"",
        "log_id=\"4s9p4dd7\"",
        "log_id=\"30nndon9\"",
    ];
    let warnings: Vec<&String> = lines
        .iter()
        .filter(|line| NOTIFICATION_LINES.iter().any(|id| line.contains(id)))
        .collect();
    assert_eq!(
        warnings.len(),
        1,
        "exactly one line about notifications: {warnings:#?}\n{}",
        lines.join("\n")
    );
    assert!(
        warnings[0].contains("WARN") && warnings[0].contains("log_id=\"h6ro04gv\""),
        "the line is the WARN for a socket that cannot be reached: {}",
        warnings[0]
    );
}

/// A filter that hides WARN for this server still lets the configuration
/// warnings reach the operator: they are written to stderr as well, once each.
///
/// `log.level = "error"` is an accepted value, and the configuration warnings
/// are WARN lines, so without the copy a server whose file switches
/// authentication off would start with no line about it. The copy carries the
/// warning priority when journald reads stderr. Where the filter shows WARN,
/// stderr stays empty and the warning is the log line alone. `READY=1` comes
/// after the warnings, so the server is stopped only once they are written.
#[test]
fn a_filter_that_hides_warnings_does_not_hide_the_configuration_warnings() {
    use std::os::unix::net::UnixDatagram;

    const WARNING: &str = "security.allow_private_networks is on";

    for (name, level, journal, copy) in [
        ("error", "error", None, Some("warning: ")),
        (
            "error-journal",
            "warn,volto=error",
            Some("8:12345"),
            Some("<4>warning: "),
        ),
        ("info", "info", None, None),
    ] {
        let dir = scratch_tree("cli", &format!("hidden-warnings-{name}"), &[]);
        let socket = dir.join("notify");
        let receiver = UnixDatagram::bind(&socket).expect("the notification socket must bind");
        receiver
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("a read timeout");
        let mut env = vec![("NOTIFY_SOCKET", socket.as_os_str())];
        if let Some(value) = journal {
            env.push(("JOURNAL_STREAM", std::ffi::OsStr::new(value)));
        }
        let serving = Serving::start(
            &dir,
            &format!("[security]\nallow_private_networks = true\n[log]\nlevel = \"{level}\"\n"),
            &env,
        );

        let mut buf = [0u8; 64];
        let len = receiver
            .recv(&mut buf)
            .unwrap_or_else(|error| panic!("{name}: READY=1 must arrive within 20 s: {error}"));
        assert_eq!(&buf[..len], b"READY=1", "{name}");

        let (status, lines, stderr) = serving.stop();
        assert!(status.success(), "{name}: {status} {stderr}");
        let copies: Vec<&str> = stderr.lines().filter(|l| l.contains(WARNING)).collect();
        let logged = lines.iter().filter(|l| l.contains(WARNING)).count();
        match copy {
            Some(prefix) => {
                assert_eq!(copies.len(), 1, "{name}: one copy on stderr:\n{stderr}");
                assert!(
                    copies[0].starts_with(&format!("{prefix}{WARNING}")),
                    "{name}: the copy starts with {prefix:?}: {:?}",
                    copies[0]
                );
                assert_eq!(logged, 0, "{name}: the filter hides the log line");
            }
            None => {
                assert!(copies.is_empty(), "{name}: no copy on stderr:\n{stderr}");
                assert_eq!(logged, 1, "{name}: the log line:\n{}", lines.join("\n"));
            }
        }
    }
}
