//! The operating system as the adversary: the moments it says no.
//!
//! Every other adversarial binary in this suite puts the *peer* or the
//! *configuration* in the hostile role. This one puts the host there: the
//! process runs out of file descriptors mid-flight, so every `socket()` a new
//! tunnel needs fails with `EMFILE` until it does not any more.
//!
//! # How the fault is injected
//!
//! `setrlimit(RLIMIT_NOFILE)` down to the lowest descriptor number that is
//! currently free, which makes every *new* allocation fail while leaving every
//! descriptor already open untouched — see [`FdClamp`]. That is process-wide, so
//! this binary holds exactly one test function and the clamp is released by a
//! guard rather than by a line at the end of it.
//!
//! # What is pinned
//!
//! * **A refused descriptor is one request's problem.** The client is answered,
//!   the connection lives, no GOAWAY is sent, and every tunnel already running
//!   keeps relaying in both directions.
//! * **The answer says whose fault it was.** A local exhaustion is
//!   `proxy_internal_error` (RFC 9209 §2.3.30, "an internal error unrelated to
//!   the origin") and names no `next-hop`, rather than telling the client a
//!   healthy destination is down and echoing its address — D89.
//! * **RFC 9298 §3.1's order does not bend under it.** A CONNECT-UDP session
//!   whose socket cannot be opened is refused before any 2xx, not accepted and
//!   then silently black-holed.
//! * **A refused tunnel gives its slot back.** `max_targets_per_conn` is set far
//!   below the number of refusals the run drives, so a slot leaked per failure
//!   would turn the later refusals into `503 connection_limit_reached` — a
//!   different `Proxy-Status` on the wire, which is what the assertion reads.
//! * **And its Quarter Stream ID.** A CONNECT-UDP session claims one before the
//!   resolver is asked anything, so a refusal has to give the routing entry
//!   back; a datagram named for a refused session is counted as dropped on the
//!   closing line rather than delivered into a queue nobody reads.
//! * **Exhaustion is quiet.** Nothing spins: with no client traffic at all the
//!   server writes essentially nothing to its log, which a `socket()` retry loop
//!   could not manage, and every refusal arrives inside [`REFUSAL_BOUND`].
//! * **A reload during the fault changes nothing.** `SIGHUP` cannot read the
//!   configuration file without a descriptor, and the reload has to fail whole
//!   rather than half-apply — the case `certbot --deploy-hook` walks into.
//! * **The recovery is complete.** The budget comes back and the very next
//!   request opens a working tunnel, a new CONNECT-UDP session still routes
//!   datagrams by Quarter Stream ID, a reload succeeds again, and the process
//!   holds no more descriptors than it did before the fault.
//! * **A storm of unresolvable targets is per-request too**, and does not touch
//!   the healthy tunnel running beside it.

// The package-wide default is `deny` (`Cargo.toml`); this file argues for its
// allow: the fault parameters are ones this file writes out itself.
#![allow(clippy::as_conversions)]

mod common;

#[path = "common/fds.rs"]
mod fds;

use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use common::{
    ALLOW_PRIVATE, ClientStream, H3Client, Response, SharedBuffer, TestServer, connect_request,
    connect_udp_request, echoes, numeric_field, open_tcp_tunnel, open_udp_session, proxy_status,
    respond_to, send_and_respond, send_udp_payload, spawn_echo_target, spawn_udp_echo_target,
    udp_round_trip,
};
use fds::settled_fds;
use rustix::process::{Resource, Rlimit};
use volto::datagram;
use volto::h3api::Status;

/// Tunnel slots the connection under test is given.
///
/// Two of them are held for the whole run by the tunnels opened before the
/// fault, so the refusals draw on the other four, far below [`REFUSALS`],
/// which is the point.
const SLOTS: u32 = 6;

/// Refusals driven one at a time while the descriptor budget is exhausted.
///
/// Four times the free slots, so a slot that a refused tunnel failed to give
/// back fails the run at the fifth refusal rather than at some unreachable
/// scale.
const REFUSALS: usize = 16;

/// Unresolvable targets driven at the connection in the DNS storm.
const DNS_STORM: usize = 12;

/// Upper bound on how long one refusal may take to arrive.
///
/// Generous by three orders of magnitude against what it costs — a `socket()`
/// that fails is one syscall — so only a refusal that waits on something can
/// fail it.
const REFUSAL_BOUND: Duration = Duration::from_secs(2);

/// Lines the server may write while the fault lasts and no client says anything.
///
/// A loop retrying the allocation would write one line per attempt and reach
/// thousands in the window below; the observed figure is zero, and one refused
/// request costs three lines. So the bound is set under that: a window that
/// caught even a single refusal's worth of work would already fail. The slack
/// that is left is for a timer that happens to fire, not for a retry.
const QUIET_LINES: usize = 2;

/// How much the descriptor count may drift across the whole run.
///
/// The same reasoning `it_soak` gives for its own slack: the runtime opens and
/// closes descriptors of its own, and a sample is a directory listing rather
/// than a barrier.
///
/// The comparison says nothing about the refusals themselves. Under the clamp
/// no descriptor can be allocated, so a refused request has nothing to leak;
/// what pins the refusals is the slot accounting and the quiet window. What
/// the comparison sees is a leak after the clamp is lifted: in the recovery
/// tunnels and in the reload.
const FD_SLACK: usize = 8;

/// The process's descriptor budget, clamped for the length of a scope.
///
/// The soft limit goes down to the lowest descriptor number that is free now,
/// which is the whole trick: the kernel refuses an allocation whose descriptor
/// number would reach the limit, and a descriptor already open is never
/// re-checked against it. So the server's live tunnels are untouched and its
/// next `socket()` fails.
///
/// Restored by `Drop` rather than by a line at the end of the test: a panic
/// inside the clamped section would otherwise leave the whole process unable to
/// open a descriptor, and the failure would be reported as whatever unrelated
/// thing broke next.
struct FdClamp {
    saved: Rlimit,
}

impl FdClamp {
    /// Clamps the budget, proving on the way out that it took effect.
    fn tighten() -> Self {
        // `getrlimit` cannot fail for a resource the kernel always knows about,
        // which is why rustix hands back the limits rather than a `Result`.
        let saved = rustix::process::getrlimit(Resource::Nofile);

        // Binding and dropping a socket names a descriptor number that is free:
        // the lowest one, since that is what the kernel hands out.
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("a probe socket");
        let free = socket.as_raw_fd();
        drop(socket);

        // The hard limit is carried across as the `Option` it arrived as rather
        // than reconstructed: `None` is `RLIM_INFINITY` on both sides of the
        // call, so round-tripping it is what leaves an unlimited ceiling
        // unlimited.
        let clamped = Rlimit {
            current: Some(u64::try_from(free).expect("a descriptor number is not negative")),
            maximum: saved.maximum,
        };
        rustix::process::setrlimit(Resource::Nofile, clamped).expect("clamp RLIMIT_NOFILE");

        let clamp = Self { saved };

        // The self-check that makes every assertion below mean something: a
        // clamp that did not take would leave the server serving every request
        // happily, and the run would pass while testing nothing at all.
        let error = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect_err("the clamp must make a new socket impossible");
        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::MFILE.raw_os_error()),
            "the clamp produced {error} rather than EMFILE"
        );

        clamp
    }
}

impl Drop for FdClamp {
    fn drop(&mut self) {
        // What is restored is exactly what this guard read.
        rustix::process::setrlimit(Resource::Nofile, self.saved).expect("restore RLIMIT_NOFILE");
    }
}

/// How long to leave between the descriptor samples [`fds::settled_fds`] takes.
///
/// A refused request holds nothing but the stream it was answered on, so what
/// has to drain here is a scheduling turn rather than a socket close: the
/// shorter of the two intervals this suite uses.
const FD_SAMPLE_INTERVAL: Duration = Duration::from_millis(25);

/// The `Proxy-Status` field of a response, or `"<none>"`.
///
/// The `String` form the assertions here interpolate, over
/// [`common::proxy_status`].
fn reported_status(response: &Response) -> String {
    proxy_status(response).unwrap_or("<none>").to_owned()
}

/// Asserts that a response is the answer a local resource exhaustion gets.
///
/// Three things at once, because they are one verdict: the status RFC 9209
/// §2.3.30 recommends for `proxy_internal_error`, that error type rather than
/// one that blames the target, and no `next-hop` — the proxy never contacted
/// one, so there is none to name (D89).
#[track_caller]
fn assert_local_failure(response: &Response, what: &str) {
    let status = reported_status(response);
    assert_eq!(
        response.status,
        Status::INTERNAL_SERVER_ERROR,
        "{what}: proxy-status={status}"
    );
    assert_eq!(
        status, "volto; error=proxy_internal_error",
        "{what}: a descriptor this host could not spare is not a verdict on the target"
    );
    assert!(
        !status.contains("next-hop"),
        "{what}: no hop was contacted, so none may be named: {status}"
    );
}

/// The one test of this binary, in phases.
///
/// Each phase is a function of its own so that a failure names the phase, and
/// the order and the clamp's scope stay visible here.
#[tokio::test]
async fn the_operating_system_refusing_a_descriptor_costs_one_request() {
    let mut run = Run::start().await;

    let fds_before = settled_fds(FD_SAMPLE_INTERVAL)
        .await
        .expect("both CI platforms list this process's descriptors");

    let clamp = FdClamp::tighten();
    let refused = refusals_under_the_clamp(&mut run).await;
    nothing_spins_under_the_clamp(&run).await;
    a_reload_under_the_clamp_changes_nothing(&mut run).await;
    drop(clamp);

    recovery(&mut run, fds_before).await;
    a_dns_storm_beside_the_live_tunnels(&mut run).await;
    the_refused_session_routes_nowhere(run, refused).await;
}

/// What every phase works on: the server, its log, the client, and the two
/// tunnels established before the fault, which live for the whole run.
struct Run {
    log: SharedBuffer,
    server: TestServer,
    echo_authority: String,
    udp_echo: SocketAddr,
    client: H3Client,
    live_tcp: ClientStream,
    live_qsid: u64,
    /// Held so the session stays open; only its Quarter Stream ID is used.
    _live_udp: ClientStream,
    /// The tunnel and the session opened after the fault, held to the end of
    /// the run so that their closing cannot reach the closing line early.
    _recovered: Vec<ClientStream>,
}

/// The CONNECT-UDP session refused under the clamp.
///
/// The stream is kept rather than dropped, because its Quarter Stream ID is
/// the third thing a refused session has to give back: the claim on the
/// connection's datagram routing table, taken before the resolver is asked
/// anything so that optimistically sent packets are not lost. What happens to
/// a datagram named for it is asserted in the last phase.
struct Refused {
    qsid: u64,
    _stream: ClientStream,
}

impl Run {
    /// Two tunnels established before the fault, and working.
    async fn start() -> Self {
        let log = SharedBuffer::shared("volto=debug");

        let server = TestServer::start_with(&format!(
            "[limits]\nmax_targets_per_conn = {SLOTS}\n{ALLOW_PRIVATE}"
        ))
        .await;

        let echo_authority = spawn_echo_target().await.to_string();
        let udp_echo = spawn_udp_echo_target().await;

        let mut client = H3Client::connect(&server).await;

        let mut live_tcp = open_tcp_tunnel(&mut client, &echo_authority).await;
        let (live_qsid, live_udp) = open_udp_session(&mut client, &server, udp_echo).await;

        echoes(&mut live_tcp, b"before").await;
        assert_eq!(
            udp_round_trip(&client, live_qsid, b"before").await.as_ref(),
            b"before"
        );

        Self {
            log,
            server,
            echo_authority,
            udp_echo,
            client,
            live_tcp,
            live_qsid,
            _live_udp: live_udp,
            _recovered: Vec::new(),
        }
    }
}

/// Every refusal under the clamp, the tunnels already running untouched, and
/// slot conservation one refusal at a time.
async fn refusals_under_the_clamp(run: &mut Run) -> Refused {
    // A CONNECT whose target socket cannot be opened.
    let started = Instant::now();
    let tcp_refusal = respond_to(&mut run.client, connect_request(&run.echo_authority)).await;
    let elapsed = started.elapsed();
    assert_local_failure(&tcp_refusal, "CONNECT under EMFILE");
    assert!(elapsed < REFUSAL_BOUND, "the refusal took {elapsed:?}");

    // And a CONNECT-UDP one, which RFC 9298 §3.1 makes the sharper case: the
    // socket is opened before the 2xx precisely so that a session that cannot
    // carry anything is refused instead of accepted and black-holed.
    let started = Instant::now();
    let (udp_refusal, refused_udp) = send_and_respond(
        &mut run.client,
        connect_udp_request(
            run.server.addr,
            &run.udp_echo.ip().to_string(),
            run.udp_echo.port(),
        ),
    )
    .await;
    let elapsed = started.elapsed();
    let refused = Refused {
        qsid: datagram::quarter_stream_id(refused_udp.id()),
        _stream: refused_udp,
    };
    assert_local_failure(&udp_refusal, "CONNECT-UDP under EMFILE");
    assert!(elapsed < REFUSAL_BOUND, "the refusal took {elapsed:?}");

    // The tunnels already running are untouched, in both directions.
    echoes(&mut run.live_tcp, b"during").await;
    assert_eq!(
        udp_round_trip(&run.client, run.live_qsid, b"during")
            .await
            .as_ref(),
        b"during"
    );
    assert_eq!(
        run.client.goaway(),
        None,
        "a refused descriptor must not end the connection"
    );

    // Slot conservation, one refusal at a time.
    for refusal in 0..REFUSALS {
        let started = Instant::now();
        let response = respond_to(&mut run.client, connect_request(&run.echo_authority)).await;
        let elapsed = started.elapsed();
        assert_local_failure(&response, &format!("refusal {refusal} of {REFUSALS}"));
        assert!(
            elapsed < REFUSAL_BOUND,
            "refusal {refusal} took {elapsed:?}"
        );
    }

    refused
}

/// Nothing spins while the fault lasts.
async fn nothing_spins_under_the_clamp(run: &Run) {
    let quiet = run.log.mark();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let lines = run.log.since(quiet).lines().count();
    assert!(
        lines <= QUIET_LINES,
        "the server wrote {lines} lines in half a second of silence under EMFILE:\n{}",
        run.log.since(quiet)
    );
}

/// A reload cannot read the configuration file, and changes nothing.
async fn a_reload_under_the_clamp_changes_nothing(run: &mut Run) {
    let failed = run
        .server
        .reload()
        .expect_err("a reload with no descriptor to open the file with must fail");
    // It has to say why: the file it could not read, and the operating
    // system's own words for the cause.
    let emfile = std::io::Error::from_raw_os_error(rustix::io::Errno::MFILE.raw_os_error());
    let said = format!("{failed:#}");
    assert!(
        said.contains("failed to read config file") && said.contains(&emfile.to_string()),
        "a failed reload must say that the file could not be read and why: {said}"
    );
    echoes(&mut run.live_tcp, b"reload").await;
}

/// With the clamp lifted: a working tunnel, a routed session, a reload, and
/// no more descriptors than before the fault.
async fn recovery(run: &mut Run, fds_before: usize) {
    let mut recovered = open_tcp_tunnel(&mut run.client, &run.echo_authority).await;
    echoes(&mut recovered, b"healed").await;

    // The datagram router is the part of the recovery a status code cannot
    // show: a session opened after the fault has to claim its Quarter Stream ID
    // and have packets routed to it, which is the state a refused session must
    // not have left behind.
    let (recovered_qsid, recovered_udp) =
        open_udp_session(&mut run.client, &run.server, run.udp_echo).await;
    assert_ne!(recovered_qsid, run.live_qsid);
    assert_eq!(
        udp_round_trip(&run.client, recovered_qsid, b"healed")
            .await
            .as_ref(),
        b"healed"
    );
    assert_eq!(
        udp_round_trip(&run.client, run.live_qsid, b"healed")
            .await
            .as_ref(),
        b"healed",
        "the session that lived through the fault still routes"
    );
    run._recovered.extend([recovered, recovered_udp]);

    run.server
        .reload()
        .expect("with descriptors back, a reload works again");

    let fds_after = settled_fds(FD_SAMPLE_INTERVAL)
        .await
        .expect("descriptor listing");
    assert!(
        fds_after <= fds_before + FD_SLACK,
        "descriptors grew across the fault: {fds_before} before, {fds_after} after"
    );
}

/// A storm of unresolvable targets is per-request too, beside the tunnels that
/// lived through the fault.
async fn a_dns_storm_beside_the_live_tunnels(run: &mut Run) {
    let host = common::unresolvable_host();
    for attempt in 0..DNS_STORM {
        let response = respond_to(&mut run.client, connect_request(&format!("{host}:443"))).await;
        assert_eq!(
            response.status,
            Status::BAD_GATEWAY,
            "storm request {attempt}: proxy-status={}",
            reported_status(&response)
        );
        assert_eq!(
            proxy_status(&response),
            Some("volto; error=dns_error"),
            "storm request {attempt}"
        );
    }

    echoes(&mut run.live_tcp, b"after!").await;
    assert_eq!(
        udp_round_trip(&run.client, run.live_qsid, b"after!")
            .await
            .as_ref(),
        b"after!"
    );
    assert_eq!(
        run.client.goaway(),
        None,
        "the connection outlived every fault"
    );
}

/// The third thing a refused session held: its Quarter Stream ID.
///
/// A session claims one before the resolver is asked anything, so a refusal has
/// to give it back, and the only production-visible trace of that is the drop
/// counter on the closing line (RFC 9298 §5 and RFC 9297 §2.1 both ask the
/// router to drop such a datagram silently). A routing entry that outlived its
/// refused session would deliver this into a queue nobody reads and count
/// nothing.
///
/// One datagram, and the run sends no other droppable one, so the closing line
/// has to say exactly one. Takes the run, because it ends the connection.
async fn the_refused_session_routes_nowhere(run: Run, refused: Refused) {
    let orphan = run.log.mark();
    send_udp_payload(&run.client.quic, refused.qsid, b"orphan");
    // A fence: the round trip crosses the router after the datagram above, so
    // the drop has been counted by the time the connection closes.
    assert_eq!(
        udp_round_trip(&run.client, run.live_qsid, b"fence")
            .await
            .as_ref(),
        b"fence"
    );
    // The count alone cannot say why the datagram was dropped. An entry left
    // behind by the refused session, whose receiver is gone, fails its send and
    // is counted as a full queue, so the closing line would say one either way.
    // This DEBUG line is written only for a Quarter Stream ID that has no entry
    // at all.
    run.log
        .wait_for_line(
            orphan,
            &[
                "dropping datagrams for sessions that do not exist",
                &format!("quarter_stream_id={} ", refused.qsid),
            ],
        )
        .await;

    let mark = run.log.mark();
    run.client.quic.close(quinn::VarInt::from_u32(0), b"");

    let line = run
        .log
        .wait_for_line(
            mark,
            &[" INFO ", "connection closed", "reason=\"peer_close\""],
        )
        .await;
    assert_eq!(
        numeric_field(&line, "dropped_datagrams"),
        1,
        "the Quarter Stream ID of a refused session must route nowhere; line was:\n{line}"
    );
}
