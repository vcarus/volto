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

use std::path::PathBuf;
use std::process::Command;

use volto::config::Config;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Runs the installer's config generator with the given arguments.
fn generated_config(args: &[&str]) -> String {
    let script = repo_root().join("script/install-selfsigned.sh");

    let output = Command::new("bash")
        .arg(&script)
        .arg("--print-config")
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("the installer script must be runnable");

    assert!(
        output.status.success(),
        "--print-config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("the generated config must be UTF-8")
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
    for expected in ["--force", "--sni", "--username", "Re-running is safe"] {
        assert!(
            usage.contains(expected),
            "usage must mention {expected}: {usage}"
        );
    }
}
