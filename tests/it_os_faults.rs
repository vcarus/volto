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
//!   Driven sequentially and then as a concurrent burst, because the two take
//!   different paths through the quota.
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

mod common;

use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{
    connect_request, connect_udp_request, open_tcp_tunnel, open_udp_session, read_at_least,
    respond_to, spawn_echo_target, spawn_udp_echo_target, udp_round_trip, ClientStream, H3Client,
    Response, SharedBuffer, TestServer, ALLOW_PRIVATE, TIMEOUT,
};
use volto::h3api::{FieldValue, Status};

/// Tunnel slots the connection under test is given.
///
/// Two of them are held for the whole run by the tunnels opened before the
/// fault, so [`FREE_SLOTS`] is what the refusals actually draw on — and it is
/// far below [`REFUSALS`], which is the point.
const SLOTS: u32 = 6;

/// Slots left over once the two long-lived tunnels have theirs.
const FREE_SLOTS: usize = SLOTS as usize - 2;

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
/// caught even a single refusal's worth of work would already fail, which is
/// what the injected-regression check was run against. The slack that is left
/// is for a timer that happens to fire, not for a retry.
const QUIET_LINES: usize = 2;

/// How much the descriptor count may drift across the whole run.
///
/// The same reasoning `it_soak` gives for its own slack: the runtime opens and
/// closes descriptors of its own, and a sample is a directory listing rather
/// than a barrier. A descriptor leaked per refusal would come to [`REFUSALS`]
/// plus the burst, well clear of this.
const FD_SLACK: usize = 8;

/// The process's descriptor budget, clamped for the length of a scope.
///
/// `rlim_cur` goes down to the lowest descriptor number that is free right now,
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
    saved: libc::rlimit,
}

impl FdClamp {
    /// Clamps the budget, proving on the way out that it took effect.
    fn tighten() -> Self {
        let saved = read_limit();

        // Binding and dropping a socket names a descriptor number that is free:
        // the lowest one, since that is what the kernel hands out.
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("a probe socket");
        let free = socket.as_raw_fd();
        drop(socket);

        let clamped = libc::rlimit {
            rlim_cur: free as libc::rlim_t,
            rlim_max: saved.rlim_max,
        };
        // SAFETY: `setrlimit` reads the struct and writes nothing.
        let result = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &clamped) };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());

        let clamp = Self { saved };

        // The self-check that makes every assertion below mean something: a
        // clamp that did not take would leave the server serving every request
        // happily, and the run would pass while testing nothing at all.
        let error = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect_err("the clamp must make a new socket impossible");
        assert_eq!(
            error.raw_os_error(),
            Some(libc::EMFILE),
            "the clamp produced {error} rather than EMFILE"
        );

        clamp
    }
}

impl Drop for FdClamp {
    fn drop(&mut self) {
        // SAFETY: as above; what is restored is what this guard read.
        let result = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.saved) };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    }
}

/// The process's current `RLIMIT_NOFILE`.
fn read_limit() -> libc::rlimit {
    // SAFETY: `getrlimit` fills the struct and reads nothing else.
    let mut limit = unsafe { std::mem::zeroed::<libc::rlimit>() };
    let result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    limit
}

/// The descriptors this process holds, if the platform will say.
///
/// `/dev/fd` on macOS and `/proc/self/fd` on Linux are the same directory under
/// two names, and both CI platforms have one. Reading it needs a descriptor of
/// its own, so it is only ever called with the budget intact.
fn open_fds() -> Option<usize> {
    let listing = if cfg!(target_os = "macos") {
        "/dev/fd"
    } else {
        "/proc/self/fd"
    };

    std::fs::read_dir(listing)
        .ok()
        .map(std::iter::Iterator::count)
}

/// [`open_fds`] once the descriptors a just-finished request owned are gone.
///
/// A request is over from the client's point of view as soon as it has read the
/// response; the server task that owned anything is finished a scheduling turn
/// or two later. The lowest of several samples is the steady state.
async fn settled_fds() -> Option<usize> {
    let mut lowest = open_fds()?;

    for _ in 0..8 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        lowest = lowest.min(open_fds()?);
    }

    Some(lowest)
}

/// The `Proxy-Status` field of a response, or `"<none>"`.
fn proxy_status(response: &Response) -> String {
    response
        .fields
        .get("proxy-status")
        .and_then(FieldValue::to_str)
        .unwrap_or("<none>")
        .to_owned()
}

/// Asserts that a response is the answer a local resource exhaustion gets.
///
/// Three things at once, because they are one verdict: the status RFC 9209
/// §2.3.30 recommends for `proxy_internal_error`, that error type rather than
/// one that blames the target, and no `next-hop` — the proxy never contacted
/// one, so there is none to name (D89).
#[track_caller]
fn assert_local_failure(response: &Response, what: &str) {
    let status = proxy_status(response);
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

/// A hostname no resolver anywhere can answer for.
///
/// Longer than the 255 octets DNS allows, so the stub resolver refuses it
/// before a query leaves the host — the trick `crate::net`'s own unit test
/// uses, and the only way to get a deterministic resolution failure without a
/// network.
fn unresolvable() -> String {
    let label = "a".repeat(60);
    vec![label; 5].join(".") + ".invalid"
}

/// Sends `count` CONNECT requests before reading any of their answers.
///
/// The concurrent shape of the quota: `count` request tasks are live on the
/// server at once, each asking [`volto`]'s tunnel quota for a slot, where the
/// sequential loop asks for one at a time.
async fn burst(client: &mut H3Client, authority: &str, count: usize) -> Vec<Response> {
    let mut streams: Vec<ClientStream> = Vec::with_capacity(count);
    for _ in 0..count {
        streams.push(
            client
                .send
                .send_request(connect_request(authority))
                .await
                .expect("send request"),
        );
    }

    let mut responses = Vec::with_capacity(count);
    for stream in &mut streams {
        responses.push(
            tokio::time::timeout(TIMEOUT, stream.recv_response())
                .await
                .expect("a burst response arrived")
                .expect("response"),
        );
    }

    responses
}

#[tokio::test]
async fn the_operating_system_refusing_a_descriptor_costs_one_request() {
    let log = SharedBuffer::install("volto=debug");

    let server = TestServer::start_with(&format!(
        "[limits]\nmax_targets_per_conn = {SLOTS}\n{ALLOW_PRIVATE}"
    ))
    .await;

    let echo = spawn_echo_target().await;
    let echo_authority = echo.to_string();
    let udp_echo = spawn_udp_echo_target().await;

    let mut client = H3Client::connect(&server).await;

    // --- Two tunnels established before the fault, and working. ---
    let mut live_tcp = open_tcp_tunnel(&mut client, &echo_authority).await;
    let (live_qsid, _live_udp) = open_udp_session(&mut client, &server, udp_echo).await;

    live_tcp
        .send_data(Bytes::from_static(b"before"))
        .await
        .expect("write into the live tunnel");
    assert_eq!(read_at_least(&mut live_tcp, 6).await, b"before");
    assert_eq!(
        udp_round_trip(&client, live_qsid, b"before").await.as_ref(),
        b"before"
    );

    let fds_before = settled_fds()
        .await
        .expect("both CI platforms list this process's descriptors");

    // --- The fault. ---
    let clamp = FdClamp::tighten();

    // A CONNECT whose target socket cannot be opened.
    let started = Instant::now();
    let tcp_refusal = respond_to(&mut client, connect_request(&echo_authority)).await;
    let elapsed = started.elapsed();
    assert_local_failure(&tcp_refusal, "CONNECT under EMFILE");
    assert!(elapsed < REFUSAL_BOUND, "the refusal took {elapsed:?}");

    // And a CONNECT-UDP one, which RFC 9298 §3.1 makes the sharper case: the
    // socket is opened before the 2xx precisely so that a session that cannot
    // carry anything is refused instead of accepted and black-holed.
    let started = Instant::now();
    let udp_refusal = respond_to(
        &mut client,
        connect_udp_request(server.addr, &udp_echo.ip().to_string(), udp_echo.port()),
    )
    .await;
    let elapsed = started.elapsed();
    assert_local_failure(&udp_refusal, "CONNECT-UDP under EMFILE");
    assert!(elapsed < REFUSAL_BOUND, "the refusal took {elapsed:?}");

    // --- The tunnels already running are untouched, in both directions. ---
    live_tcp
        .send_data(Bytes::from_static(b"during"))
        .await
        .expect("the live tunnel still takes bytes");
    assert_eq!(read_at_least(&mut live_tcp, 6).await, b"during");
    assert_eq!(
        udp_round_trip(&client, live_qsid, b"during").await.as_ref(),
        b"during"
    );
    assert_eq!(
        client.goaway(),
        None,
        "a refused descriptor must not end the connection"
    );

    // --- Slot conservation, one refusal at a time. ---
    for refusal in 0..REFUSALS {
        let started = Instant::now();
        let response = respond_to(&mut client, connect_request(&echo_authority)).await;
        let elapsed = started.elapsed();
        assert_local_failure(&response, &format!("refusal {refusal} of {REFUSALS}"));
        assert!(
            elapsed < REFUSAL_BOUND,
            "refusal {refusal} took {elapsed:?}"
        );
    }

    // --- And as a burst, which asks the quota for every slot at once. ---
    //
    // The settle is for the server-side release that trails the client's view of
    // an answered request by a scheduling turn: the same lag `it_stress` leaves
    // headroom for, and here the burst is sized to the free slots exactly.
    tokio::time::sleep(Duration::from_millis(100)).await;
    for (index, response) in burst(&mut client, &echo_authority, FREE_SLOTS)
        .await
        .iter()
        .enumerate()
    {
        assert_local_failure(response, &format!("burst refusal {index}"));
    }

    // --- Nothing spins while the fault lasts. ---
    let quiet = log.mark();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let lines = log.since(quiet).lines().count();
    assert!(
        lines <= QUIET_LINES,
        "the server wrote {lines} lines in half a second of silence under EMFILE:\n{}",
        log.since(quiet)
    );

    // --- A reload cannot read the configuration file, and changes nothing. ---
    let failed = server
        .reload()
        .expect_err("a reload with no descriptor to open the file with must fail");
    assert!(
        !failed.to_string().is_empty(),
        "a failed reload must say why"
    );
    live_tcp
        .send_data(Bytes::from_static(b"reload"))
        .await
        .expect("a failed reload leaves the live tunnel alone");
    assert_eq!(read_at_least(&mut live_tcp, 6).await, b"reload");

    // --- Recovery. ---
    drop(clamp);

    let mut recovered = open_tcp_tunnel(&mut client, &echo_authority).await;
    recovered
        .send_data(Bytes::from_static(b"healed"))
        .await
        .expect("the recovered tunnel takes bytes");
    assert_eq!(read_at_least(&mut recovered, 6).await, b"healed");

    // The datagram router is the part of the recovery a status code cannot
    // show: a session opened after the fault has to claim its Quarter Stream ID
    // and have packets routed to it, which is the state a refused session must
    // not have left behind.
    let (recovered_qsid, _recovered_udp) = open_udp_session(&mut client, &server, udp_echo).await;
    assert_ne!(recovered_qsid, live_qsid);
    assert_eq!(
        udp_round_trip(&client, recovered_qsid, b"healed")
            .await
            .as_ref(),
        b"healed"
    );
    assert_eq!(
        udp_round_trip(&client, live_qsid, b"healed").await.as_ref(),
        b"healed",
        "the session that lived through the fault still routes"
    );

    server
        .reload()
        .expect("with descriptors back, a reload works again");

    let fds_after = settled_fds().await.expect("descriptor listing");
    assert!(
        fds_after <= fds_before + FD_SLACK,
        "descriptors grew across the fault: {fds_before} before, {fds_after} after"
    );

    // --- A storm of unresolvable targets, beside a healthy tunnel. ---
    let host = unresolvable();
    for attempt in 0..DNS_STORM {
        let response = respond_to(&mut client, connect_request(&format!("{host}:443"))).await;
        assert_eq!(
            response.status,
            Status::BAD_GATEWAY,
            "storm request {attempt}: proxy-status={}",
            proxy_status(&response)
        );
        assert_eq!(
            proxy_status(&response),
            "volto; error=dns_error",
            "storm request {attempt}"
        );
    }

    live_tcp
        .send_data(Bytes::from_static(b"after!"))
        .await
        .expect("the live tunnel survives the storm");
    assert_eq!(read_at_least(&mut live_tcp, 6).await, b"after!");
    assert_eq!(
        udp_round_trip(&client, live_qsid, b"after!").await.as_ref(),
        b"after!"
    );
    assert_eq!(client.goaway(), None, "the connection outlived every fault");
}
