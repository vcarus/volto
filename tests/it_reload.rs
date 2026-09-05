//! M6: `SIGHUP` configuration reload (spec §6).
//!
//! The two properties that matter operationally:
//!
//! * a **good** reload takes effect for new connections — new credentials work,
//!   withdrawn ones stop working, without dropping anyone who is connected;
//! * a **bad** reload changes nothing at all. The usual sender of this signal is
//!   `certbot --deploy-hook` at three in the morning, so "config file is broken"
//!   must mean "carry on as before", never "exit".
//!
//! The signal itself is not delivered here: these tests call the same
//! `ReloadHandle::reload` that `main`'s `SIGHUP` handler calls, which is where all
//! the behaviour lives. The handler around it is a `while signal.recv()` loop.

// The package-wide default is `deny` (`Cargo.toml`); this file argues for its
// allow: the configuration numbers are ones this file writes out itself.
#![allow(clippy::as_conversions)]

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::Response;
use common::rawstream::{connect_headers_frame, read_frame, status_of};
use common::{
    ALLOW_PRIVATE, GATE_LOCALHOST, H3Client, STOP_TIMEOUT, SharedBuffer, TIMEOUT, TestServer,
    auth_section, authorized_connect, close_and_drain, connect_request, echoes, open_tcp_tunnel,
    open_udp_session, read_at_least, respond_to, send_and_respond, spawn_echo_target,
    spawn_end_reporting_target, spawn_udp_echo_target, udp_round_trip,
};
use volto::h3api::{FieldValue, Status};

/// Reloads the server with a subscriber of this test's own, and returns
/// everything it logged.
///
/// Scoped rather than process-wide (`SharedBuffer::install`) because this file
/// is many `#[tokio::test]`s and `tracing_subscriber::fmt().init()` may run only
/// once per process. `ReloadHandle::reload` is synchronous and runs on the
/// caller's own thread, which is exactly what a thread-local default subscriber
/// covers -- so this captures the reload's lines and nothing else's.
fn reload_capturing_logs(server: &TestServer) -> (anyhow::Result<()>, String) {
    let logs = SharedBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("volto=info")
        .with_writer(logs.clone())
        .with_ansi(false)
        .finish();

    let result = tracing::subscriber::with_default(subscriber, || server.reload());
    (result, logs.contents())
}

/// Sends a CONNECT with credentials and returns the response.
async fn connect_as(
    client: &mut H3Client,
    authority: &str,
    username: &str,
    password: &str,
) -> Response {
    respond_to(client, authorized_connect(authority, username, password)).await
}

/// The headline case: rotate the credentials, reload, and the change is in force
/// for new connections — old password out, new password in.
#[tokio::test]
async fn reloading_replaces_the_accepted_credentials() {
    let server = TestServer::start_with(&format!(
        "{}{ALLOW_PRIVATE}",
        auth_section(&[("user1", "old-password")])
    ))
    .await;
    let target = spawn_echo_target().await;

    // Before: the old password works, the new one does not exist yet.
    let mut client = H3Client::connect(&server).await;
    assert_eq!(
        connect_as(&mut client, &target.to_string(), "user1", "old-password")
            .await
            .status,
        Status::OK
    );
    assert_eq!(
        connect_as(&mut client, &target.to_string(), "user1", "new-password")
            .await
            .status,
        Status::PROXY_AUTHENTICATION_REQUIRED
    );

    server.rewrite_config(&format!(
        "{}{ALLOW_PRIVATE}",
        auth_section(&[("user1", "new-password")])
    ));
    server.reload().expect("a valid configuration must apply");

    // After, on a new connection: exactly the other way round.
    let mut fresh = H3Client::connect(&server).await;
    assert_eq!(
        connect_as(&mut fresh, &target.to_string(), "user1", "new-password")
            .await
            .status,
        Status::OK,
        "the new password must be accepted after a reload"
    );
    assert_eq!(
        connect_as(&mut fresh, &target.to_string(), "user1", "old-password")
            .await
            .status,
        Status::PROXY_AUTHENTICATION_REQUIRED,
        "the withdrawn password must stop working after a reload"
    );
}

/// A connection that predates the reload keeps the configuration it was accepted
/// with. Documented behaviour rather than an accident: the alternative is a
/// tunnel's rules changing under it mid-transfer.
#[tokio::test]
async fn existing_connections_keep_the_configuration_they_started_with() {
    let server = TestServer::start_with(&format!(
        "{}{ALLOW_PRIVATE}",
        auth_section(&[("user1", "old-password")])
    ))
    .await;
    let target = spawn_echo_target().await;

    let mut client = H3Client::connect(&server).await;
    let request = authorized_connect(&target.to_string(), "user1", "old-password");
    let (response, mut held) = send_and_respond(&mut client, request).await;
    assert_eq!(response.status, Status::OK);

    server.rewrite_config(&format!(
        "{}{ALLOW_PRIVATE}",
        auth_section(&[("user1", "new-password")])
    ));
    server.reload().expect("reload");

    // The tunnel opened before the reload is untouched.
    echoes(&mut held, b"still mine").await;

    // And so is the credential this connection was accepted with.
    assert_eq!(
        connect_as(&mut client, &target.to_string(), "user1", "old-password")
            .await
            .status,
        Status::OK,
        "an existing connection keeps its original configuration"
    );
}

/// Attempts a bare QUIC connection, reporting whether the server took it.
///
/// A connection past the cap is refused during the handshake, so the attempt
/// fails rather than producing a connection that is then unusable.
async fn connect_attempt(server: &TestServer) -> bool {
    let endpoint = common::client_endpoint(&server.ca, &["h3"]);
    common::finish_connect(&endpoint, server.addr).await.is_ok()
}

/// `max_connections` is read per accepted connection, so a reload moves it.
///
/// This is the knob an operator turns during an incident, and
/// `docs/deployment.md#reloading` promises it applies to connections accepted
/// from then on. It used to be copied into a local once, before the accept loop,
/// so neither raising nor lowering it did anything until a restart.
#[tokio::test]
async fn reloading_replaces_the_connection_cap() {
    let server =
        TestServer::start_with(&format!("[limits]\nmax_connections = 1\n{ALLOW_PRIVATE}")).await;
    let target = spawn_echo_target().await;

    // One connection fits, and is kept for the rest of the test so the cap keeps
    // biting.
    let mut first = H3Client::connect(&server).await;
    assert_eq!(
        respond_to(&mut first, connect_request(&target.to_string()))
            .await
            .status,
        Status::OK
    );
    assert!(
        !connect_attempt(&server).await,
        "a second connection must be refused while the cap is 1"
    );

    // Raised: the second connection now fits.
    server.rewrite_config(&format!("[limits]\nmax_connections = 2\n{ALLOW_PRIVATE}"));
    server.reload().expect("a valid configuration must apply");

    let mut second = H3Client::connect(&server).await;
    assert_eq!(
        respond_to(&mut second, connect_request(&target.to_string()))
            .await
            .status,
        Status::OK,
        "the raised cap must apply to connections accepted after the reload"
    );

    // Lowered again, below what is already open: the connections that exist are
    // left alone, and the next one is refused.
    server.rewrite_config(&format!("[limits]\nmax_connections = 1\n{ALLOW_PRIVATE}"));
    server.reload().expect("a valid configuration must apply");

    assert!(
        !connect_attempt(&server).await,
        "the lowered cap must apply to connections accepted after the reload"
    );
    assert_eq!(
        respond_to(&mut first, connect_request(&target.to_string()))
            .await
            .status,
        Status::OK,
        "connections already open must survive a lowered cap"
    );
}

/// A reload can also tighten the destination policy.
#[tokio::test]
async fn reloading_replaces_the_destination_policy() {
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let target = spawn_echo_target().await;

    let mut client = H3Client::connect(&server).await;
    assert_eq!(
        respond_to(&mut client, connect_request(&target.to_string()))
            .await
            .status,
        Status::OK
    );

    // Withdraw access to private address space.
    server.rewrite_config("[security]\nallow_private_networks = false\n");
    server.reload().expect("reload");

    let mut fresh = H3Client::connect(&server).await;
    let refused = respond_to(&mut fresh, connect_request(&target.to_string())).await;
    assert_eq!(refused.status, Status::FORBIDDEN);
    assert_eq!(
        refused
            .fields
            .get("proxy-status")
            .and_then(FieldValue::to_str),
        Some("volto; error=destination_ip_prohibited")
    );
}

/// A broken configuration file must be rejected whole, leaving the running one in
/// force — and the server must keep serving throughout.
#[tokio::test]
async fn a_broken_configuration_changes_nothing() {
    let server = TestServer::start_with(&format!(
        "{}{ALLOW_PRIVATE}",
        auth_section(&[("user1", "s3cret")])
    ))
    .await;
    let target = spawn_echo_target().await;

    let cases: Vec<(&str, String)> = vec![
        // Not TOML at all.
        ("malformed TOML", "[server\nlisten = oops".to_owned()),
        // Valid TOML, unknown key.
        (
            "unknown key",
            format!(
                "[server]\nlisten = \"127.0.0.1:0\"\ncert = \"{}\"\nkey = \"{}\"\nlisen = 1\n",
                server.dir().join("cert.pem").display(),
                server.dir().join("key.pem").display()
            ),
        ),
        // Valid TOML, fails validation: a username with a colon in it.
        (
            "invalid user",
            format!(
                "[server]\nlisten = \"127.0.0.1:0\"\ncert = \"{}\"\nkey = \"{}\"\n\
                 [auth]\nusers = [{{ username = \"a:b\", password = \"p\" }}]\n",
                server.dir().join("cert.pem").display(),
                server.dir().join("key.pem").display()
            ),
        ),
        // Valid TOML whose integers are out of range. TOML deserializes across
        // the whole of the target type, so `u64::MAX` is something a typo can
        // put in the file, and validation used to have no answer for either of
        // these: the keep-alive check panicked on the arithmetic it did (which
        // on this path is a panic *while a server is running*), and the grace
        // period was accepted and quietly stopped bounding the drain (D86).
        (
            "keep-alive past what its own check could double",
            format!(
                "[server]\nlisten = \"127.0.0.1:0\"\ncert = \"{}\"\nkey = \"{}\"\n\
                 [limits]\nkeep_alive_interval = 18446744073709551615\n",
                server.dir().join("cert.pem").display(),
                server.dir().join("key.pem").display()
            ),
        ),
        (
            "unbounded shutdown grace",
            format!(
                "[server]\nlisten = \"127.0.0.1:0\"\ncert = \"{}\"\nkey = \"{}\"\n\
                 shutdown_grace = 18446744073709551615\n",
                server.dir().join("cert.pem").display(),
                server.dir().join("key.pem").display()
            ),
        ),
        // Valid and internally consistent, but the certificate is missing.
        (
            "missing certificate",
            "[server]\nlisten = \"127.0.0.1:0\"\ncert = \"/nonexistent/volto/fullchain.pem\"\n\
             key = \"/nonexistent/volto/privkey.pem\"\n"
                .to_owned(),
        ),
        // The half-written-renewal case, and the one that only the *second* stage
        // of the reload can catch: the files exist and pass validation, but their
        // contents are not a usable certificate yet.
        ("truncated certificate", {
            let truncated = server.dir().join("truncated.pem");
            std::fs::write(&truncated, "-----BEGIN CERTIFICATE-----\nnot base64 yet")
                .expect("write truncated cert");
            format!(
                "[server]\nlisten = \"127.0.0.1:0\"\ncert = \"{}\"\nkey = \"{}\"\n",
                truncated.display(),
                server.dir().join("key.pem").display()
            )
        }),
        // A certificate and a key that are individually fine but do not match --
        // what a deploy hook that copies one file and not the other produces.
        ("mismatched key", {
            let other = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                .expect("generate an unrelated key");
            let stray = server.dir().join("stray-key.pem");
            std::fs::write(&stray, other.signing_key.serialize_pem()).expect("write stray key");
            format!(
                "[server]\nlisten = \"127.0.0.1:0\"\ncert = \"{}\"\nkey = \"{}\"\n",
                server.dir().join("cert.pem").display(),
                stray.display()
            )
        }),
    ];

    for (label, text) in &cases {
        server.write_invalid_config(text);
        let error = server
            .reload()
            .expect_err(&format!("{label} must be rejected"));
        // The error has to name what is wrong, since it is all the operator gets.
        assert!(
            !format!("{error:#}").is_empty(),
            "{label} produced an empty error"
        );

        // The original credentials still work, on a brand new connection, after
        // every failed reload.
        let mut client = H3Client::connect(&server).await;
        assert_eq!(
            connect_as(&mut client, &target.to_string(), "user1", "s3cret")
                .await
                .status,
            Status::OK,
            "after a failed reload ({label}), the running configuration must survive"
        );
    }

    // A good reload still works after all those failures.
    server.rewrite_config(&format!(
        "{}{ALLOW_PRIVATE}",
        auth_section(&[("user2", "another")])
    ));
    server
        .reload()
        .expect("a valid configuration must still apply");

    let mut client = H3Client::connect(&server).await;
    assert_eq!(
        connect_as(&mut client, &target.to_string(), "user2", "another")
            .await
            .status,
        Status::OK
    );
}

/// Reloading a certificate must keep the endpoint serving.
///
/// The new certificate here is a *different* self-signed one, so a client that
/// trusts only the original CA must now fail to handshake — which proves the swap
/// reached the endpoint rather than being accepted and dropped.
#[tokio::test]
async fn reloading_swaps_the_certificate() {
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let target = spawn_echo_target().await;

    let mut client = H3Client::connect(&server).await;
    assert_eq!(
        respond_to(&mut client, connect_request(&target.to_string()))
            .await
            .status,
        Status::OK
    );

    // Issue a fresh certificate for the same name and point the config at it.
    let reissued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate a second self-signed certificate");
    let cert = server.dir().join("cert2.pem");
    let key = server.dir().join("key2.pem");
    std::fs::write(&cert, reissued.cert.pem()).expect("write cert");
    std::fs::write(&key, reissued.signing_key.serialize_pem()).expect("write key");

    server.write_invalid_config(&format!(
        "[server]\nlisten = \"127.0.0.1:0\"\ncert = \"{}\"\nkey = \"{}\"\n\
         [security]\nallow_private_networks = true\n[log]\nlevel = \"debug\"\n",
        cert.display(),
        key.display()
    ));
    server
        .reload()
        .expect("the reissued certificate must apply");

    // A client trusting only the old CA can no longer complete the handshake.
    let endpoint = common::client_endpoint(&server.ca, &["h3"]);
    let result = common::finish_connect(&endpoint, server.addr).await;
    assert!(
        result.is_err(),
        "after the swap, the old CA must no longer validate the server"
    );

    // While a client trusting the new one connects and tunnels normally.
    let mut trusting = H3Client::connect_with_ca(&server, reissued.cert.der().clone()).await;
    assert_eq!(
        respond_to(&mut trusting, connect_request(&target.to_string()))
            .await
            .status,
        Status::OK,
        "the endpoint must serve the reloaded certificate"
    );
}

// ---------------------------------------------------------------------------
// Storms: many reloads in quick succession, with traffic in flight.
//
// Everything above is a single reload in a quiet moment. What an operator
// actually produces is a stream of them -- a config-management run that reloads
// on every convergence pass, a renewal hook that fires per certificate -- and
// they land while tunnels are carrying data. These pin that shape: the reload
// path and the teardown paths share the endpoint, the live configuration and
// the per-connection quota, and none of them may disturb the others.
// ---------------------------------------------------------------------------

/// How many reloads a storm fires. Even rounds re-apply the text already in
/// force, odd ones move a live-reloadable transport parameter.
const STORM_ROUNDS: u32 = 24;

/// A burst of reloads while both tunnel types are carrying data.
///
/// Half of these re-apply the very text already in force, which is what an
/// unattended `systemctl reload` loop mostly does, and half move
/// `max_streams_bidi`. Between each pair a TCP tunnel and a UDP session opened
/// before the storm both make a round trip: a reload swaps the endpoint's
/// server configuration and the live `Config` behind an `Arc`, and neither is
/// allowed to reach a connection that is already running.
#[tokio::test]
async fn a_storm_of_reloads_leaves_live_tunnels_untouched() {
    let server = TestServer::start().await;
    let tcp = spawn_echo_target().await;
    let udp = spawn_udp_echo_target().await;

    let mut client = H3Client::connect(&server).await;
    let mut tunnel = open_tcp_tunnel(&mut client, &tcp.to_string()).await;
    let (qsid, _session) = open_udp_session(&mut client, &server, udp).await;

    for round in 0..STORM_ROUNDS {
        // Applied in pairs, so every second reload is a genuine no-op re-apply
        // of a file that has not changed.
        let streams = 8 + (round / 2) % 2;
        server.rewrite_config(&format!(
            "[limits]\nmax_streams_bidi = {streams}\n{ALLOW_PRIVATE}"
        ));
        server
            .reload()
            .unwrap_or_else(|error| panic!("round {round} of the storm was refused: {error:#}"));

        // Both directions of both tunnel types, every round: a reload that
        // disturbed a live tunnel would show up here rather than at the end.
        let payload = Bytes::from(format!("round-{round:02}"));
        tunnel
            .send_data(payload.clone())
            .await
            .unwrap_or_else(|error| panic!("round {round}: the TCP tunnel broke: {error}"));
        assert_eq!(
            read_at_least(&mut tunnel, payload.len()).await,
            &payload[..],
            "round {round}: the TCP tunnel echoed the wrong bytes"
        );
        assert_eq!(
            &udp_round_trip(&client, qsid, &payload).await[..],
            &payload[..],
            "round {round}: the UDP session echoed the wrong bytes"
        );
    }

    // The last configuration of the storm is the one in force, and it is in
    // force on the wire: a connection accepted now may hold one request stream
    // and no more, so the second cannot even be opened.
    server.rewrite_config(&format!("[limits]\nmax_streams_bidi = 1\n{ALLOW_PRIVATE}"));
    server
        .reload()
        .expect("the last reload of the storm applies");

    let fresh = H3Client::connect(&server).await;
    let (mut send, mut recv) = fresh
        .quic
        .open_bi()
        .await
        .expect("the first request stream fits inside a limit of one");
    send.write_all(&connect_headers_frame(&tcp.to_string()))
        .await
        .expect("send the CONNECT request");
    let (_, block) = read_frame(&mut recv).await;
    assert_eq!(status_of(&block), "200");

    assert!(
        tokio::time::timeout(Duration::from_millis(500), fresh.quic.open_bi())
            .await
            .is_err(),
        "a connection accepted after the storm must be held to the reloaded stream limit"
    );

    // While the connection that predates the storm keeps what it negotiated: it
    // already holds two request streams, and a third still opens.
    let _third = open_tcp_tunnel(&mut client, &tcp.to_string()).await;
}

/// The same storm with the failures interleaved.
///
/// A reload that cannot be applied has to be a no-op *and* leave the machinery
/// intact for the next one, and the interesting moment is when it happens with
/// tunnels running: the failure is discovered at three different depths -- the
/// TOML parse, `Config::validate`, and loading the certificate -- and the last
/// of those is past the point where a careless implementation would already
/// have swapped something.
#[tokio::test]
async fn a_storm_of_failed_reloads_changes_nothing_and_leaves_the_next_one_working() {
    let server = TestServer::start().await;
    let tcp = spawn_echo_target().await;
    let udp = spawn_udp_echo_target().await;

    let mut client = H3Client::connect(&server).await;
    let mut tunnel = open_tcp_tunnel(&mut client, &tcp.to_string()).await;
    let (qsid, _session) = open_udp_session(&mut client, &server, udp).await;

    let cert = server.dir().join("cert.pem");
    let key = server.dir().join("key.pem");
    let broken: Vec<(&str, String)> = vec![
        ("malformed TOML", "[limits\nmax_streams_bidi = ".to_owned()),
        (
            // Rejected by `Config::validate`, not by the parser: the keep-alive
            // has to be strictly under half the idle timeout.
            "a keep-alive longer than the idle timeout allows",
            format!(
                "[server]\nlisten = \"127.0.0.1:0\"\ncert = \"{}\"\nkey = \"{}\"\n\
                 [limits]\nmax_idle_timeout = 10\nkeep_alive_interval = 9\n",
                cert.display(),
                key.display()
            ),
        ),
        (
            // Valid and consistent; the failure is in the certificate load,
            // which happens after validation and before anything is swapped.
            "a certificate that is not there",
            "[server]\nlisten = \"127.0.0.1:0\"\ncert = \"/nonexistent/volto/fullchain.pem\"\n\
             key = \"/nonexistent/volto/privkey.pem\"\n"
                .to_owned(),
        ),
    ];

    for round in 0..STORM_ROUNDS {
        let (label, text) = &broken[round as usize % broken.len()];

        if round % 2 == 0 {
            server.write_invalid_config(text);
            let error = server
                .reload()
                .expect_err(&format!("round {round} ({label}) must be refused"));
            assert!(
                !format!("{error:#}").is_empty(),
                "round {round} ({label}) produced an empty error"
            );
        } else {
            // A good one in between, so the failures are not merely being
            // ignored by a reload path that stopped working altogether.
            server.rewrite_config(&format!("[limits]\nmax_streams_bidi = 16\n{ALLOW_PRIVATE}"));
            server
                .reload()
                .unwrap_or_else(|error| panic!("round {round} must apply: {error:#}"));
        }

        let payload = Bytes::from(format!("round-{round:02}"));
        tunnel
            .send_data(payload.clone())
            .await
            .unwrap_or_else(|error| panic!("round {round} ({label}): the tunnel broke: {error}"));
        assert_eq!(
            read_at_least(&mut tunnel, payload.len()).await,
            &payload[..],
            "round {round} ({label}): the TCP tunnel echoed the wrong bytes"
        );
        assert_eq!(
            &udp_round_trip(&client, qsid, &payload).await[..],
            &payload[..],
            "round {round} ({label}): the UDP session echoed the wrong bytes"
        );
    }

    // The failures cost the next reload nothing: this one is observable on a
    // fresh connection.
    server.rewrite_config("[security]\nallow_private_networks = false\n");
    server
        .reload()
        .expect("a valid configuration must still apply after the storm");

    let mut afterwards = H3Client::connect(&server).await;
    let refused = respond_to(&mut afterwards, connect_request(&tcp.to_string())).await;
    assert_eq!(refused.status, Status::FORBIDDEN);
    assert_eq!(
        refused
            .fields
            .get("proxy-status")
            .and_then(FieldValue::to_str),
        Some("volto; error=destination_ip_prohibited")
    );
}

/// `[server] listen` and the socket buffers are startup keys: a reload carrying
/// new values for them is accepted and moves nothing -- and says so.
///
/// `docs/configuration.md` and `docs/deployment.md` both promise the no-op: the
/// usual sender of `SIGHUP` is a renewal hook that re-writes the whole file, and
/// a reload that refused it -- or worse, tried to rebind -- would take the proxy
/// off the air over a key the operator did not mean to change. So the rest of
/// the same file still applies, which is what separates "this key is a no-op"
/// from "the reload failed".
///
/// The silence, though, was never the point. An operator who *did* mean to move
/// the socket had nothing to read: the reload succeeded, the line said so, and
/// the one key that did not apply was the one nothing mentioned. So the no-op
/// carries a `warn!` naming both addresses, and this test pins it -- the
/// promise is "does not rebind", not "does not tell you".
#[tokio::test]
async fn a_reload_cannot_move_the_listening_socket() {
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let target = spawn_echo_target().await;
    let elsewhere = common::closed_udp_address().await;

    server.write_invalid_config(&format!(
        "[server]\nlisten = \"{elsewhere}\"\ncert = \"{}\"\nkey = \"{}\"\n\
         [limits]\nsocket_recv_buffer = 1048576\nsocket_send_buffer = 1048576\n\
         [security]\nallow_private_networks = false\n",
        server.dir().join("cert.pem").display(),
        server.dir().join("key.pem").display(),
    ));
    let (reloaded, logs) = reload_capturing_logs(&server);
    reloaded.expect("a startup-only key is not a reason to refuse a whole reload");

    // Named, both halves: what the socket is on and what the file asked for.
    let warning = logs
        .lines()
        .find(|line| line.contains("a reload cannot move the listening socket"))
        .unwrap_or_else(|| panic!("the ignored key must be reported; log was:\n{logs}"));
    assert!(
        warning.contains("WARN"),
        "a key that silently did not apply is a warning, not an aside: {warning}"
    );
    assert!(
        warning.contains(&format!("configured={elsewhere}")),
        "the warning must name the address the file asked for: {warning}"
    );
    assert!(
        warning.contains("bound=127.0.0.1:0"),
        "the warning must name the address it was configured with at startup: {warning}"
    );

    // Still answering where it was bound, and the reloadable key from the same
    // file did take effect.
    let mut client = H3Client::connect(&server).await;
    assert_eq!(
        respond_to(&mut client, connect_request(&target.to_string()))
            .await
            .status,
        Status::FORBIDDEN,
        "the reloadable half of that file must have applied"
    );

    // And nothing came up on the address it named.
    let endpoint = common::client_endpoint(&server.ca, &["h3"]);
    let connecting = endpoint
        .connect(elsewhere, "localhost")
        .expect("start connecting");
    assert!(
        !matches!(
            tokio::time::timeout(Duration::from_secs(2), connecting).await,
            Ok(Ok(_))
        ),
        "a reload must not bind the address it was handed"
    );
}

/// A `SIGHUP` that lands after `SIGTERM` must not reopen the door.
///
/// The drain closes the listener with `set_server_config(None)`; a reload that
/// went on to install a new one would put the endpoint back to accepting
/// handshakes it is seconds from closing. So a reload during the drain is
/// refused outright -- and refusing it must cost the drain nothing, which is
/// the other half of what is asserted here.
#[tokio::test]
async fn a_reload_during_the_shutdown_drain_is_refused() {
    let mut server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // Something to drain, so the shutdown is genuinely still in progress.
    let mut tunnel = open_tcp_tunnel(&mut client, &target.to_string()).await;

    server.shutdown();
    client.await_goaway().await;

    server.rewrite_config(&format!("[limits]\nmax_streams_bidi = 4\n{ALLOW_PRIVATE}"));
    let error = server
        .reload()
        .expect_err("a reload during the drain must be refused");
    assert!(
        format!("{error:#}").contains("shutting down"),
        "the refusal must say why: {error:#}"
    );

    // The tunnel being drained is untouched by the refusal, and the drain still
    // ends on its own terms.
    echoes(&mut tunnel, b"draining").await;

    close_and_drain(&mut tunnel).await;
    server.wait_until_stopped(STOP_TIMEOUT).await;
}

/// Reloads landing throughout a UDP session's idle timeout must not disturb it.
///
/// The session holds the configuration its connection was accepted with, so
/// moving `udp_session_timeout` under it changes nothing -- and the invariant on
/// the far side is RFC 9298 §3.1's: reclaiming the socket has to close the
/// request stream, or the client is left believing the session still exists.
/// The two paths meet on the live `Config` and on the connection's tunnel
/// quota, which is what this hammers.
#[tokio::test]
async fn reloads_during_a_session_timeout_still_close_the_request_stream() {
    let server = TestServer::start_with(&format!(
        "[limits]\nudp_session_timeout = 1\n{ALLOW_PRIVATE}"
    ))
    .await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, mut stream) = open_udp_session(&mut client, &server, target).await;
    assert_eq!(&udp_round_trip(&client, qsid, b"alive").await[..], b"alive");

    // From here nothing crosses the proxy, so the session's one-second clock is
    // running. Flip the very key it is counting down on, throughout.
    let storm = async {
        for round in 0..STORM_ROUNDS {
            let timeout = if round % 2 == 0 { 30 } else { 1 };
            server.rewrite_config(&format!(
                "[limits]\nudp_session_timeout = {timeout}\n{ALLOW_PRIVATE}"
            ));
            server
                .reload()
                .unwrap_or_else(|error| panic!("round {round} was refused: {error:#}"));
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // The storm ends -- well inside the one second this session has left --
        // on a value that would keep it alive for another half minute if the
        // timeout were read live rather than snapshotted when the connection was
        // accepted. That is what makes the assertion below say something.
        server.rewrite_config(&format!(
            "[limits]\nudp_session_timeout = 30\n{ALLOW_PRIVATE}"
        ));
        server
            .reload()
            .expect("the last reload of the storm applies");
    };

    let closed = async {
        tokio::time::timeout(TIMEOUT, async {
            loop {
                match stream.recv_data().await {
                    Ok(Some(_)) => continue,
                    ended => return ended,
                }
            }
        })
        .await
        .expect("the server must close the idled-out session")
    };

    let (_, ended) = tokio::join!(storm, closed);
    assert!(
        matches!(ended, Ok(None)),
        "an idled-out session must end its request stream cleanly, got {ended:?}"
    );
}

/// A client that vanishes mid-transfer is reaped even while reloads are landing.
///
/// The connection goes away without finishing its stream and without a GOAWAY --
/// the everyday shape of a phone changing networks -- and the target socket has
/// to go with it (RFC 9114 §4.4: a proxy that detects an error on the QUIC
/// connection MUST close the TCP connection). *How* the target learns is a
/// property of the host's TCP stack rather than of this server, so what is
/// asserted is that it learns at all: nothing arrives on the channel if the
/// socket is leaked.
#[tokio::test]
async fn a_tunnel_abandoned_during_a_reload_storm_still_closes_its_target() {
    let server = TestServer::start().await;
    let (target, mut ended) = spawn_end_reporting_target().await;
    let mut client = H3Client::connect(&server).await;

    // This target only reads and reports how its connection ended, so the write
    // below is one-way: it exists to make the tunnel a live transfer rather
    // than a freshly opened one.
    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;
    stream
        .send_data(Bytes::from_static(b"in flight"))
        .await
        .expect("send through the tunnel");

    // The connection disappears with the tunnel still open, in the middle of a
    // run of reloads.
    server.rewrite_config(&format!("[limits]\nmax_streams_bidi = 32\n{ALLOW_PRIVATE}"));
    server.reload().expect("the reload before the abandonment");
    drop(stream);
    drop(client);
    for round in 0..STORM_ROUNDS {
        server
            .reload()
            .unwrap_or_else(|error| panic!("round {round} after the abandonment: {error:#}"));
    }

    tokio::time::timeout(TIMEOUT, ended.recv())
        .await
        .expect("the abandoned target socket must be closed, not leaked")
        .expect("close notification");

    // And the server is still serving, on the configuration the storm left.
    let mut afterwards = H3Client::connect(&server).await;
    assert_eq!(
        respond_to(&mut afterwards, connect_request(&target.to_string()))
            .await
            .status,
        Status::OK,
        "the server must still serve after an abandonment crossed with a reload storm"
    );
}

/// A gate name with an empty label is refused at reload, not held unmatchably.
///
/// `expected_sni = ["local..host"]` used to pass validation, because the
/// character class allows `.` and only one trailing dot was ever stripped. The
/// gate then held a name no ClientHello can carry, so every client was dropped
/// in silence, and the D106 warning that exists for that failure did not fire
/// either: `tls::names_not_covered` stripped every trailing dot and found the
/// name covered. The two spellings are now one helper, `gate::root_relative`,
/// and an empty label is refused where a misconfiguration can still be reported.
#[tokio::test]
async fn a_reloaded_gate_name_with_an_empty_label_is_refused() {
    let mut server = TestServer::start_with(GATE_LOCALHOST).await;

    server.rewrite_config(
        "[security]\nallow_private_networks = true\nexpected_sni = [\"local..host\"]\n",
    );
    let error = server
        .reload()
        .expect_err("a name with an empty label must be refused");
    let message = format!("{error:#}");
    assert!(
        message.contains("security.expected_sni[0]") && message.contains("empty label"),
        "the refusal must name the entry and say what is wrong with it: {message}"
    );

    // The refusal left the gate where it was, so the name the certificate covers
    // still opens a connection. A reload that had applied would have made this
    // time out with nothing on the wire, which is the failure being prevented.
    let client = H3Client::connect(&server).await;
    drop(client);

    server.shutdown();
    server.wait_until_stopped(STOP_TIMEOUT).await;
}

/// A reloaded name the certificate cannot prove draws the D106 warning.
///
/// One name the certificate covers and one it does not, both spelled with the
/// trailing root dot a client may or may not send. The uncovered one has to be
/// reported, because a gate that admits a name no certificate covers refuses the
/// handshake at TLS and the operator has nothing else to go on; the covered one
/// must be silent, or a configuration written the absolute way draws a warning
/// it does not deserve. The warning had unit coverage in `src/config.rs` and
/// none through `reload`, which is where an operator meets it.
///
/// Not a red proof of the trailing-dot helper. `rustls::pki_types::ServerName`
/// parses `localhost.` and matches it against the certificate itself, so for
/// every name that passes validation the coverage check reads the same either
/// way; what the helper closes is the two-dot form, and that is refused at
/// validation now.
#[tokio::test]
async fn a_reloaded_name_the_certificate_cannot_prove_draws_the_warning() {
    let mut server = TestServer::start_with(GATE_LOCALHOST).await;

    server.rewrite_config(
        "[security]\nallow_private_networks = true\n\
         expected_sni = [\"localhost.\", \"porxy.example.\"]\n",
    );
    let (result, logs) = reload_capturing_logs(&server);
    result.expect("the reload itself is valid; the names are only warned about");

    assert_eq!(
        logs.matches("does not cover").count(),
        1,
        "exactly one of the two names is uncovered; log was:\n{logs}"
    );
    assert!(
        logs.contains("porxy.example."),
        "the warning must name the entry as the operator wrote it; log was:\n{logs}"
    );

    server.shutdown();
    server.wait_until_stopped(STOP_TIMEOUT).await;
}
