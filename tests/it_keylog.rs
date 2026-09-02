//! M6: the `SSLKEYLOGFILE` switch (spec §0, decision D8).
//!
//! Debugging sovereignty sits on the server: Surge cannot export its TLS secrets,
//! so the only way to read a real session's frames is for the server to write the
//! secrets itself. This test proves the switch actually produces a usable file
//! rather than silently doing nothing — the failure mode that would only be
//! discovered while trying to debug something else.
//!
//! Its own test binary because it sets a process-wide environment variable, which
//! must happen before the server's TLS configuration is built and must not race
//! other tests. The two tests here serialize against each other explicitly, so
//! the guarantee does not depend on how the runner is invoked.

// An argued exception to the package's `unsafe_code = "deny"`: the two
// `set_var` calls are the process-wide write edition 2024 makes explicit, and
// the `ENV` mutex below is the argument for why they are sound here.
#![allow(unsafe_code)]

mod common;

use std::sync::LazyLock;

use common::{ALLOW_PRIVATE, H3Client, TempDir, TestServer, open_tcp_tunnel, spawn_echo_target};
use tokio::sync::Mutex;

/// Serializes the two tests: `SSLKEYLOGFILE` is process-wide, and rustls reads it
/// when a server's TLS configuration is built, so a concurrent test would see the
/// other's value.
///
/// An async mutex because the guard is deliberately held across awaits — the whole
/// test, from setting the variable to reading the file, is the critical section.
static ENV: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[tokio::test]
async fn enabling_keylog_writes_the_tls_secrets() {
    let _guard = ENV.lock().await;

    let dir = TempDir::new("keylog");
    let keylog = dir.path().join("keys.log");

    // `KeyLogFile` reads this once, when the rustls configuration is built, so it
    // has to be set before the server starts. Safe here: single test, single
    // thread, nothing else in this binary depends on the environment.
    unsafe { std::env::set_var("SSLKEYLOGFILE", &keylog) };

    let server = TestServer::start_with_log(ALLOW_PRIVATE, "keylog = true\n").await;

    // A complete handshake plus one successful request, so the secrets for both
    // the handshake and the application data have been derived.
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;
    let _stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    let contents = std::fs::read_to_string(&keylog).expect("the keylog file must exist");
    assert!(
        !contents.is_empty(),
        "the keylog file must not be empty once a session has been negotiated"
    );

    // The NSS key log format Wireshark expects: `<LABEL> <client_random> <secret>`.
    // Asserting the shape, not just the size, is what makes this a test of
    // usability rather than of file creation.
    let labels: Vec<&str> = contents
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert!(
        labels.iter().any(|label| label.contains("TRAFFIC_SECRET")),
        "expected TLS 1.3 traffic secrets, got labels {labels:?}"
    );
    for line in contents.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 3, "malformed keylog line: {line:?}");
        // The client random and the secret are lowercase hex.
        for field in &fields[1..] {
            assert!(
                field.chars().all(|c| c.is_ascii_hexdigit()),
                "expected hex in {line:?}"
            );
        }
    }
}

/// With the switch off — the default — nothing is written even though the
/// environment variable is set.
#[tokio::test]
async fn keylog_is_off_unless_asked_for() {
    let _guard = ENV.lock().await;

    let dir = TempDir::new("keylog-off");
    let keylog = dir.path().join("must-not-appear.log");
    // Safe for the same reason as above: serialized by `ENV`, set before the
    // server builds its TLS configuration.
    unsafe { std::env::set_var("SSLKEYLOGFILE", &keylog) };

    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;
    // A fully negotiated session, which is what would have produced secrets.
    let _stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    assert!(
        !keylog.exists(),
        "secrets must not be written unless log.keylog is on"
    );
}
