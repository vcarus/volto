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

mod common;

use bytes::Bytes;
use common::Response;
use common::{
    auth_section, authorized_connect, connect_request, read_at_least, respond_to, send_and_respond,
    spawn_echo_target, H3Client, TestServer, ALLOW_PRIVATE,
};
use volto::h3api::{FieldValue, Status};

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
    held.send_data(Bytes::from_static(b"still mine"))
        .await
        .expect("the established tunnel still works");
    assert_eq!(&read_at_least(&mut held, 10).await, b"still mine");

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
