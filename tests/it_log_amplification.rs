//! How many log lines one peer can make this server write, and what may ride in
//! them.
//!
//! The log is an attack surface of its own. `journalctl` rate limiting counts
//! *lines*, not bytes, and it is per unit: a peer that can drive one line per
//! request at a level that survives to production does not merely fill a disk,
//! it knocks this service's genuine lines out of the journal for the rest of the
//! window. So the interesting question about a peer-reachable log statement is
//! not whether it is useful but how many of it one connection can buy, and with
//! how few bytes.
//!
//! Everything here runs at `volto=info`, which is the shipped default
//! (`script/config.example.toml`, `docs/configuration.md`): DEBUG is invisible in
//! production, so a line only counts if it reaches this filter.
//!
//! One target is raised past it. Volume is a level question and escaping is not:
//! the rule that peer bytes are bounded and escaped where they enter a value
//! holds at every level, and the operator who turned DEBUG on is the one moment
//! a flood of forged entries costs the most. The only such line a peer can reach
//! before it has done anything at all is `volto::quic`'s handshake failure, so
//! that module alone is watched at DEBUG here.
//!
//! Its own binary because a capturing subscriber is process-wide and
//! `tracing_subscriber::fmt().init()` may run once, which is why every scenario
//! lives inside the one `#[tokio::test]` and takes a mark into the shared buffer
//! rather than starting from an empty one.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    auth_section, authorize, authorized_connect, basic_credentials, closed_udp_address,
    connect_request, connect_udp_request, open_tcp_tunnel, respond_to, spawn_echo_target, H3Client,
    SharedBuffer, TestServer, ALLOW_PRIVATE,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use volto::h3api::Status;

/// Loopback, which the default policy refuses: what an SSRF probe looks like
/// from here, and the cheapest production-level warning a peer can buy.
const PROHIBITED: &str = "127.0.0.1:443";

/// Requests per storm.
///
/// Small enough to stay a second of test time and large enough that a 1:1 line
/// rate is unmistakable next to any bound: nothing that samples could produce
/// this many lines by accident. A power of two so that the last request of a
/// storm is one the doubling sampler reports, which is what lets the running
/// total be asserted rather than inferred.
const STORM: usize = 64;

/// The credentials the authenticating servers below are configured with.
const USER: &str = "user1";
const PASSWORD: &str = "s3cret-pa55word";

#[tokio::test]
async fn one_peer_cannot_buy_an_unbounded_number_of_production_log_lines() {
    let buffer = SharedBuffer::install("volto=info,volto::quic=debug");

    a_policy_refusal_storm_is_sampled(&buffer).await;
    a_tunnel_limit_storm_is_sampled(&buffer).await;
    an_authentication_storm_is_bounded_by_the_failure_budget(&buffer).await;
    a_peer_close_reason_never_reaches_the_journal(&buffer).await;
    a_handshake_close_reason_never_forges_a_line(&buffer).await;
    a_udp_session_costs_exactly_one_line(&buffer).await;
}

/// The SSRF warning must stay loud without being one line per request.
///
/// `admit_target`'s refusal is the cheapest production-level line in the server:
/// an IP literal takes no resolver slot and holds no socket, so the whole cost to
/// a peer is one HEADERS frame — under a hundred bytes for a `WARN` that reaches
/// the journal. A port scan through the proxy is 65535 of them.
///
/// D44 settled that this line stays at WARN, and it must: it is the evidence an
/// operator is left with when somebody probes the private side of the host. What
/// is bounded here is the *volume*, not the loudness — the first refusal warns
/// exactly as before, and later ones warn again as the running count doubles, so
/// a scan still announces itself and now says how large it was.
async fn a_policy_refusal_storm_is_sampled(buffer: &SharedBuffer) {
    let server = TestServer::start_with("").await;
    let mut client = H3Client::connect(&server).await;
    let mark = buffer.mark();

    for _ in 0..STORM {
        let response = respond_to(&mut client, connect_request(PROHIBITED)).await;
        assert_eq!(response.status, Status::FORBIDDEN);
    }

    let warnings = buffer.lines_since(
        mark,
        &[
            " WARN ",
            "every address of the target is prohibited by policy",
        ],
    );
    assert!(
        !warnings.is_empty(),
        "the SSRF-shaped refusal must still be audible at WARN"
    );
    assert!(
        warnings.len() < STORM,
        "{STORM} refusals bought {} production warnings; one per request means a peer \
         decides how much of this journal is left for anybody else:\n{}",
        warnings.len(),
        warnings.join("\n")
    );
    assert!(
        warnings
            .last()
            .expect("a warning")
            .contains(&format!("refusals={STORM}")),
        "the last warning must carry the running total, or bounding the volume \
         throws away the size of the scan:\n{}",
        warnings.join("\n")
    );

    // Nothing was silenced: every refusal the peer made is still answered, and
    // the ones that did not warn are on the debug channel an operator can turn
    // on. What the sampler removes is repetition, not the record.
    let refused = buffer.lines_since(mark, &["every address of the target is prohibited"]);
    assert_eq!(
        refused.len(),
        warnings.len(),
        "at `info` only the sampled lines may appear at all"
    );
}

/// The same treatment for the other refusal a peer can repeat at will.
///
/// Reaching the tunnel limit costs a peer `max_targets_per_conn` live tunnels,
/// which is real resource commitment — but once it is there, *every* further
/// request is a warning, for ever, at one HEADERS frame apiece. The limit is set
/// to one here so the storm is the point rather than the setup.
async fn a_tunnel_limit_storm_is_sampled(buffer: &SharedBuffer) {
    let target = spawn_echo_target().await;
    let server = TestServer::start_with(&format!(
        "[limits]\nmax_targets_per_conn = 1\n{ALLOW_PRIVATE}"
    ))
    .await;
    let mut client = H3Client::connect(&server).await;

    // Held for the rest of this scenario: it is the one tunnel the quota allows,
    // so every request below is refused.
    let _held = open_tcp_tunnel(&mut client, &target.to_string()).await;
    let mark = buffer.mark();

    for _ in 0..STORM {
        let response = respond_to(&mut client, connect_request(&target.to_string())).await;
        assert_eq!(response.status, Status::SERVICE_UNAVAILABLE);
    }

    let warnings = buffer.lines_since(mark, &[" WARN ", "connection is at its tunnel limit"]);
    assert!(
        !warnings.is_empty(),
        "a connection sitting on its limit is still worth telling an operator about"
    );
    assert!(
        warnings.len() < STORM,
        "{STORM} refused requests bought {} production warnings:\n{}",
        warnings.len(),
        warnings.join("\n")
    );
}

/// The 407 path already has a bound, and this is what proves it is the *log*
/// that is bounded and not just the connection.
///
/// `security.max_auth_failures` exists to make guessing cost a handshake, and the
/// warning per failure is deliberate — it is what a fail2ban rule reads. The
/// property that keeps it from being a flood is that the budget is charged per
/// connection and the connection is closed when it runs out, so the line count
/// per handshake is bounded by a configured number rather than by how many
/// streams the peer feels like opening.
async fn an_authentication_storm_is_bounded_by_the_failure_budget(buffer: &SharedBuffer) {
    const BUDGET: usize = 3;

    let server = TestServer::start_with(&format!(
        "{}\n[security]\nmax_auth_failures = {BUDGET}\n",
        auth_section(&[(USER, PASSWORD)])
    ))
    .await;
    let mut client = H3Client::connect(&server).await;
    let mark = buffer.mark();

    // Every one of these is a wrong guess; the connection is closed part-way
    // through, so the later ones fail to send rather than being answered.
    for _ in 0..STORM {
        let request = authorized_connect(PROHIBITED, USER, "wrong-password");
        if client.send.send_request(request).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let failures = buffer.lines_since(mark, &[" WARN ", "authentication failed"]);
    assert!(
        failures.len() <= BUDGET,
        "the failure budget is {BUDGET}, so a connection may not write more than \
         {BUDGET} warnings about it; got {}:\n{}",
        failures.len(),
        failures.join("\n")
    );

    // The password may not appear anywhere, at any level, however the attempt
    // was graded -- and neither may the real one, which nothing here ever sends.
    let contents = buffer.since(mark);
    assert!(
        !contents.contains("wrong-password") && !contents.contains(PASSWORD),
        "a credential reached the log:\n{contents}"
    );
}

/// The closing line records its error with `Display`, which escapes nothing — so
/// nothing peer-chosen may be inside it.
///
/// A peer closing a QUIC connection chooses both the error code and a reason
/// phrase, and the reason phrase is arbitrary bytes of its choosing. `%error` on
/// a `WARN` would put them in the journal unescaped: `systemd` splits a service's
/// stdout on `\n`, so a newline in there is a forged journal entry, attributed to
/// this server, from an unauthenticated peer that has done nothing but complete a
/// handshake.
///
/// What keeps that out is `ConnectionError`'s conversion, which keeps the code
/// and drops the peer's prose. Nothing else pins it, and the conversion reads as
/// a tidying-up rather than as a defence, so this is the test that says it is
/// load-bearing.
///
/// This drives the *application* close, which is the one a peer can send through
/// quinn's public API and so the one a test can reach. The transport close —
/// frame type 0x1c, whose reason phrase is kept rather than dropped, bounded and
/// escaped instead — needs a hostile QUIC stack to send, so it is pinned in
/// `volto::h3::error`'s own tests against the same conversion.
async fn a_peer_close_reason_never_reaches_the_journal(buffer: &SharedBuffer) {
    /// The bytes a peer would like the journal to carry. The newline is the
    /// attack; the rest is what it would forge.
    const FORGED: &str = "goodbye\nINFO volto: authentication succeeded for admin";

    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let client = H3Client::connect(&server).await;
    let mark = buffer.mark();

    // A code that is not a clean goodbye, so the connection is graded as an
    // error and the line is a WARN rather than the INFO a benign close gets.
    client
        .quic
        .close(quinn::VarInt::from_u32(0x1234), FORGED.as_bytes());

    let line = buffer
        .wait_for_line(mark, &[" WARN ", "connection closed with error"])
        .await;
    assert!(
        !line.contains("goodbye"),
        "the peer's reason phrase reached the journal: {line}"
    );

    let contents = buffer.since(mark);
    assert!(
        !contents.contains("authentication succeeded"),
        "a peer forged a log line through a close reason:\n{contents}"
    );
}

/// The same rule at the other door: a close that lands *during* the handshake.
///
/// The conversion the scenario above pins is reached only by a connection this
/// server already has. A peer that closes before the handshake completes never
/// gets there: `quinn`'s error goes straight onto `volto::quic`'s failure line,
/// and its `Display` prints the reason phrase the peer wrote, unbounded and
/// unescaped.
///
/// A TLS alert is how a test reaches that door without a hostile QUIC stack: the
/// client below refuses the server's certificate with an error of its own
/// choosing, `rustls` sends the alert while the server is still handshaking, and
/// the alert's description travels in the CONNECTION_CLOSE reason phrase. So the
/// bytes asserted on here are the client's, sent before it has proved anything
/// at all -- which is exactly the peer this bound exists for.
///
/// Unlike the application close above, the phrase is *kept* rather than dropped:
/// what a peer's QUIC stack says about a failed handshake is worth reading. What
/// it may not do is arrive whole, or with a newline still in it.
async fn a_handshake_close_reason_never_forges_a_line(buffer: &SharedBuffer) {
    /// The bytes a peer would like the journal to carry. The newline is the
    /// attack; `for admin` is the tail that a bounded field can never reach.
    const FORGED: &str = "goodbye\nINFO volto: authentication succeeded for admin";

    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let mark = buffer.mark();

    let endpoint = endpoint_refusing_the_certificate(FORGED);
    common::finish_connect(&endpoint, server.addr)
        .await
        .expect_err("a client that refuses the certificate cannot complete the handshake");

    let line = buffer
        .wait_for_line(mark, &[" DEBUG ", "QUIC handshake failed"])
        .await;
    assert!(
        line.contains("goodbye"),
        "the phrase a peer's stack sent is what makes a failed handshake \
         diagnosable, so it must survive: {line}"
    );

    let contents = buffer.since(mark);
    assert!(
        buffer
            .lines_since(mark, &["authentication succeeded"])
            .is_empty(),
        "a peer forged a journal entry through a handshake close reason:\n{contents}"
    );
    assert!(
        !contents.contains("for admin"),
        "the whole of the peer's prose reached the journal; only a bounded head \
         of it may:\n{contents}"
    );
}

/// A client endpoint that refuses every certificate, with `detail` as its reason.
///
/// The reason is what makes this a probe rather than a connectivity test:
/// `rustls` puts its error text into the alert it sends, `quinn` puts the alert
/// description into the CONNECTION_CLOSE reason phrase, and the server reads
/// `detail` off the wire without having accepted anything.
fn endpoint_refusing_the_certificate(detail: &'static str) -> quinn::Endpoint {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = RefuseWith {
        detail,
        schemes: provider
            .signature_verification_algorithms
            .supported_schemes(),
    };

    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("bind address")).expect("client");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic tls"),
    )));
    endpoint
}

/// The verifier behind [`endpoint_refusing_the_certificate`].
///
/// The signature schemes are the provider's own: an empty list would be refused
/// by the *server* while choosing one, which is a different failure than the one
/// under test.
#[derive(Debug)]
struct RefuseWith {
    detail: &'static str,
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for RefuseWith {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Err(rustls::Error::General(self.detail.to_owned()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.3 only, and the certificate is refused before any signature is
        // reached either way.
        Err(rustls::Error::General(self.detail.to_owned()))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(self.detail.to_owned()))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// The baseline every bound above is measured against: a tunnel is worth one
/// line, and a peer that opens tunnels is *meant* to be able to write one line
/// each.
///
/// A CONNECT-UDP session is the cheapest of them — the target is never contacted,
/// only bound and connected — so this is the floor on what an authorised client
/// costs the journal. It is deliberately not bounded: an access log that drops
/// records is not an access log. Pinned so that the number is a decision somebody
/// made rather than an accident, and so a second line per session cannot be added
/// without this saying so.
async fn a_udp_session_costs_exactly_one_line(buffer: &SharedBuffer) {
    const SESSIONS: usize = 8;

    let server = TestServer::start_with(&format!(
        "{}\n{ALLOW_PRIVATE}",
        auth_section(&[(USER, PASSWORD)])
    ))
    .await;
    let closed = closed_udp_address().await;
    let mut client = H3Client::connect(&server).await;
    let mark = buffer.mark();

    for _ in 0..SESSIONS {
        let mut request = connect_udp_request(server.addr, &closed.ip().to_string(), closed.port());
        authorize(&mut request, &basic_credentials(USER, PASSWORD));
        let (response, mut stream) = common::send_and_respond(&mut client, request).await;
        assert_eq!(response.status, Status::OK);
        stream.finish().expect("finish the session");
    }

    let established = buffer.lines_since(mark, &[" INFO ", "udp session established"]);
    assert_eq!(
        established.len(),
        SESSIONS,
        "one line per session is the access log; more than one is amplification"
    );
}
