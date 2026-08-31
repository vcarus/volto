//! What one peer can make this process *hold*, weighed rather than reasoned
//! about.
//!
//! Every other bound in this suite is asserted on the wire: a refusal arrives, a
//! stream is reset, a packet is dropped. The bounds here leave no such trace.
//! They are bytes on the heap, and the only way to state one is to weigh it, so
//! this binary carries a `#[global_allocator]` that tallies live bytes -- every
//! allocation minus every free -- while a measurement is armed, in the same
//! spirit as `it_relay_memory`, which counts blocks rather than bytes.
//!
//! What the tally counts is *requested* bytes, not resident ones: a one-byte
//! `Box<str>` is counted as one byte where the system allocator really hands out
//! a bucket several times that. Every figure below is therefore a lower bound on
//! what the host actually pays, which is the safe direction for a ceiling to be
//! wrong in.
//!
//! Each input here is one a *conformant* peer may send, so none of them can be
//! answered by refusing it: what bounds them is arithmetic, and this is where
//! that arithmetic is pinned. `docs/configuration.md` quotes the same numbers
//! for an operator sizing a host, which is the other reason they belong in a
//! test rather than in a comment.

mod common;

#[path = "common/alloc.rs"]
mod alloc;

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use common::{
    connect_request, open_tcp_tunnel, open_udp_session, send_and_respond, spawn_echo_target,
    spawn_udp_echo_target, udp_round_trip, ClientStream, H3Client, TestServer, TIMEOUT,
};
use volto::datagram::put_varint;
use volto::h3api::{FieldValue, Request, Status};

// ---------------------------------------------------------------------------
// The scales
// ---------------------------------------------------------------------------

/// A pass-through allocator that tallies live bytes while armed.
///
/// Armed rather than always counting, because the process this runs in starts a
/// QUIC server, QUIC clients and targets, and none of that setup is what a
/// measurement is about. A free of memory allocated *before* the arming makes
/// the tally negative, which is why it is signed: every figure below is a
/// difference across an armed window, and an unmatched free only ever
/// understates the growth being measured.
struct Tallying;

static ARMED: AtomicBool = AtomicBool::new(false);
static LIVE: AtomicI64 = AtomicI64::new(0);

/// Records a change in live bytes, if counting is on.
fn record(delta: i64) {
    if ARMED.load(Ordering::Relaxed) {
        LIVE.fetch_add(delta, Ordering::Relaxed);
    }
}

impl alloc::Record for Tallying {
    fn allocated(size: usize) {
        record(size as i64);
    }

    fn reallocated(old: usize, new: usize) {
        record(new as i64 - old as i64);
    }

    fn freed(size: usize) {
        record(-(size as i64));
    }
}

#[global_allocator]
static GLOBAL: alloc::PassThrough<Tallying> = alloc::PassThrough::new();

/// Serialises the measured windows.
///
/// The tally is one counter for the whole process, so two measurements running
/// at once would weigh each other. `cargo test` runs the tests of a binary
/// concurrently, so this is the only thing keeping them apart. `tokio`'s mutex
/// rather than the standard library's, because it is held across the awaits the
/// measurement is made of.
static SCALES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Runs `body` with the tally armed and reports what was still live at its end.
///
/// The value `body` produces is read *after* the reading is taken, which is the
/// whole arrangement: whatever must still be alive to be weighed -- open
/// tunnels, live sessions -- is returned from the body and so is not dropped
/// before the counter is read.
async fn while_holding<F: Future>(body: F) -> (F::Output, i64) {
    LIVE.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let out = body.await;
    let held = LIVE.load(Ordering::Relaxed);
    ARMED.store(false, Ordering::Relaxed);
    (out, held)
}

/// The live tally right now, for the waits that have to watch it move.
fn live_now() -> i64 {
    LIVE.load(Ordering::Relaxed)
}

/// Waits until the tally satisfies `settled`, or [`TIMEOUT`] passes.
///
/// The server side of every measurement here finishes without saying so on the
/// wire -- an unfinished capsule draws no answer, and a session that has closed
/// drops its buffers a few instructions after the FIN the client sees. So the
/// tally is its own signal, and each caller states what it is waiting for and
/// asserts the outcome itself. Bounded and self-terminating either way.
async fn settle(settled: impl Fn(i64) -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while !settled(live_now()) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------------
// A request's field section, held for the whole life of its tunnel
// ---------------------------------------------------------------------------

/// Field lines in the widest request a conformant client may send.
///
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` is 64 KiB and RFC 9114 §4.2.2 sizes a
/// section as name plus value plus 32 bytes for each field, so a one-byte name
/// with an empty value costs 33 of those bytes and about 1985 of them fill the
/// budget. 1900 leaves room for the CONNECT pseudo-headers, and the suite's
/// client enforces the advertised limit itself -- so a request this builds and
/// the client agrees to send is one the server is obliged to accept.
const PADDING_FIELDS: usize = 1900;

/// Tunnels opened per phase: enough that the per-tunnel figure is not noise,
/// few enough that the phase is quick.
const TUNNELS: usize = 64;

/// Live bytes one tunnel's held request may cost, at the widest field section
/// this server accepts.
///
/// The measured figure on the dev host is about 77 KiB: `Fields` is a vector of
/// 32-byte entries that doubles its way to 2048 of them, plus one allocation per
/// field name. That is roughly the advertised 64 KiB section size over again,
/// which is no accident -- RFC 9114 §4.2.2's 32-byte-per-field charge exists to
/// model exactly this per-field cost.
///
/// The ceiling is 128 KiB: well above the measurement, so an allocator or a
/// container that pads differently does not make this flap, and low enough that
/// a field section held in some *third* form as well -- the decoded
/// `Vec<Field>` kept alongside the `Fields` it was moved into, say -- fails it.
const HELD_PER_TUNNEL_CEILING: i64 = 128 * 1024;

/// A CONNECT request as wide as the advertised field-section limit allows.
fn padded_connect_request(authority: &str) -> Request {
    let mut request = connect_request(authority);
    let empty = FieldValue::parse(b"").expect("the empty string is a field value");
    for _ in 0..PADDING_FIELDS {
        request.fields.append("a", empty.clone());
    }
    request
}

/// A tunnel holds its request's decoded field section for as long as it lives.
///
/// The ledger entry this pins, and the reason it is worth pinning: a decoded
/// request is not released once the request has been routed.
/// `conn::handle_request` keeps it for the whole life of the tunnel it opened,
/// so what a field section costs is multiplied not by how many requests are
/// being *parsed* -- which is what the D77 buffering budget bounds, and it
/// bounds the *encoded* bytes at 1 MiB per connection -- but by
/// `max_targets_per_conn` tunnels times `max_connections` connections, for as
/// long as those tunnels carry traffic.
///
/// Two phases against one server, so everything but the field section cancels:
/// the same number of tunnels to the same target over an equivalent connection,
/// once with a bare CONNECT and once with the widest one the advertised limit
/// allows. The first phase's tunnels stay open across the second, so nothing
/// they allocated is freed inside the second's window.
///
/// # Measured
///
/// On the dev host (macOS, debug build), 64 tunnels per phase:
///
/// | phase | live bytes with the tunnels open |
/// |---|---|
/// | bare CONNECT | 1.82 MiB |
/// | 1900 field lines | 6.64 MiB |
///
/// which is about 77 KiB per tunnel for the field section alone, from a request
/// that is under 6 KiB on the wire.
#[tokio::test(flavor = "multi_thread")]
async fn a_tunnel_holds_its_requests_field_section_for_its_whole_life() {
    let _scales = SCALES.lock().await;

    let server = TestServer::start().await;
    let target = spawn_echo_target().await.to_string();

    let mut plain_client = H3Client::connect(&server).await;
    let (_plain_tunnels, plain_held) = while_holding(async {
        let mut tunnels = Vec::with_capacity(TUNNELS);
        for _ in 0..TUNNELS {
            tunnels.push(open_tcp_tunnel(&mut plain_client, &target).await);
        }
        tunnels
    })
    .await;

    let mut padded_client = H3Client::connect(&server).await;
    let (_padded_tunnels, padded_held) = while_holding(async {
        let mut tunnels = Vec::with_capacity(TUNNELS);
        for index in 0..TUNNELS {
            let (response, stream) =
                send_and_respond(&mut padded_client, padded_connect_request(&target)).await;
            assert_eq!(
                response.status,
                Status::OK,
                "tunnel {index} of the padded phase was refused"
            );
            tunnels.push(stream);
        }
        tunnels
    })
    .await;

    let per_tunnel = (padded_held - plain_held) / TUNNELS as i64;

    // The floor is what keeps this about anything at all: a server that did not
    // keep the section would pass the ceiling trivially, and so would a phase
    // that failed to open its tunnels. A quarter of the arithmetic -- 1900
    // entries of 32 bytes is 59 KiB before a single name is allocated -- is
    // clear of any noise between two otherwise identical phases.
    assert!(
        per_tunnel > 16 * 1024,
        "padded tunnels held only {per_tunnel} bytes more each than bare ones \
         ({padded_held} against {plain_held} for {TUNNELS} tunnels): the field \
         section is not reaching the tunnel at all, so this measures nothing"
    );

    assert!(
        per_tunnel < HELD_PER_TUNNEL_CEILING,
        "each tunnel holds {per_tunnel} bytes of decoded request for its whole \
         life, past the {HELD_PER_TUNNEL_CEILING} this server accounts for \
         ({padded_held} against {plain_held} for {TUNNELS} tunnels)"
    );
}

// ---------------------------------------------------------------------------
// A CONNECT-UDP session's third buffer
// ---------------------------------------------------------------------------

/// Sessions opened for the capsule measurement.
const SESSIONS: usize = 16;

/// The largest DATAGRAM capsule value `capsule::MAX_DATAGRAM_CAPSULE_VALUE`
/// admits: a Context ID varint of up to 8 bytes, plus a whole UDP payload.
const MAX_CAPSULE_VALUE: u64 = 8 + 65527;

/// Live bytes one session's capsule decoder may hold.
///
/// The decoder buffers a DATAGRAM capsule's value until all of it has arrived,
/// because a UDP payload cannot be forwarded piecewise. A peer that declares the
/// largest value the decoder admits and then stops one byte short leaves that
/// much buffered until the session's idle timeout -- which is a *third*
/// per-session buffer, beside the 64 KiB target-socket buffer and the ~92 KiB
/// inbound datagram queue.
///
/// The ceiling is four times the value itself: room for `BytesMut` to have
/// doubled its way there and for the reads that carried it, and a refusal of any
/// decoder that started accumulating across capsules rather than within one.
const HELD_PER_SESSION_CEILING: i64 = 4 * (MAX_CAPSULE_VALUE as i64);

/// A DATAGRAM capsule header (RFC 9297 §3.5) declaring `length` bytes of value.
fn datagram_capsule_header(length: u64) -> Bytes {
    let mut out = BytesMut::new();
    put_varint(&mut out, 0x00);
    put_varint(&mut out, length);
    out.freeze()
}

/// A session holds one unfinished capsule, and no more than one.
///
/// The input is conformant: RFC 9297 §3.2 lets a capsule be as long as its
/// length says and arrive across as many stream reads as the sender likes, so a
/// peer that sends a maximal DATAGRAM capsule and withholds its last byte is
/// doing nothing this server may refuse. What that costs is what this weighs,
/// and the ceiling is the claim that it is one capsule's worth rather than
/// however much the peer chooses to send.
///
/// The window is armed only for the *stall*: the sessions are open and their two
/// documented buffers already allocated before it opens, so what grows inside it
/// is the capsule decoder and nothing else.
///
/// # Measured
///
/// On the dev host (macOS, debug build), 16 sessions: 1.22 MiB of growth, about
/// 78 KiB apiece -- a 64 KiB value inside a `BytesMut` that doubled its way
/// there.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_holds_one_unfinished_capsule_and_no_more() {
    let _scales = SCALES.lock().await;

    let server = TestServer::start().await;
    let echo = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut sessions = Vec::with_capacity(SESSIONS);
    for _ in 0..SESSIONS {
        let (_quarter, stream) = open_udp_session(&mut client, &server, echo).await;
        sessions.push(stream);
    }

    // One byte short of the whole value, on every session.
    let stall: Bytes = {
        let mut out = BytesMut::new();
        out.put_slice(&datagram_capsule_header(MAX_CAPSULE_VALUE));
        out.put_bytes(0x5a, MAX_CAPSULE_VALUE as usize - 1);
        out.freeze()
    };
    let sent = SESSIONS as i64 * (MAX_CAPSULE_VALUE as i64 - 1);

    let (sessions, held) = while_holding(async {
        for (index, session) in sessions.iter_mut().enumerate() {
            session
                .send_data(stall.clone())
                .await
                .unwrap_or_else(|error| {
                    panic!("session {index} would not take the stall: {error}")
                });
        }

        // `send_data` returns once quinn has the bytes, not once the server has
        // read them, and an unfinished capsule produces no answer to wait for --
        // that being the point of it. So the tally is the signal.
        settle(|live| live >= sent).await;
        sessions
    })
    .await;

    let per_session = held / SESSIONS as i64;

    assert!(
        held >= sent,
        "the sessions took only {held} bytes of the {sent} they were sent: the \
         capsule stream is not being read, so this measures nothing"
    );

    assert!(
        per_session < HELD_PER_SESSION_CEILING,
        "each session holds {per_session} bytes of unfinished capsule, past the \
         {HELD_PER_SESSION_CEILING} that one maximal capsule can account for"
    );

    // Held to here, so the reading above was taken with every session alive.
    drop(sessions);
}

// ---------------------------------------------------------------------------
// What a closed session gives back
// ---------------------------------------------------------------------------

/// Sessions opened and closed one after another.
///
/// Four times `INBOUND_QUEUE_DEPTH` and a quarter of the default
/// `max_targets_per_conn`, so a session's worth of anything left behind is
/// several megabytes by the end and impossible to mistake for noise.
const CHURNED_SESSIONS: usize = 64;

/// Live bytes one connection may keep per session it has already closed.
///
/// Nothing keeps a *session's* memory: the tunnel slot, the Quarter Stream ID
/// registration, the inbound queue, the target socket, the 64 KiB packet buffer,
/// the capsule decoder and the decoded request are all owned by things that end
/// with it. What a connection does keep is quinn's own per-stream bookkeeping,
/// which is why this is not zero.
///
/// 8 KiB apiece is two orders of magnitude under the ~156 KiB a live session
/// costs, so a release path that stopped firing cannot pass this.
const KEPT_PER_CLOSED_SESSION: i64 = 8 * 1024;

/// Closes a CONNECT-UDP session and waits for the server to close its half.
///
/// RFC 9298 §3.1 pairs the two ends: the client finishing its side ends the
/// session, and the session ending finishes the server's. So the FIN that comes
/// back is the signal that the session loop has returned -- which is where
/// everything it held goes.
async fn close_session(session: &mut ClientStream) {
    session.finish().expect("finish the request stream");

    let ended = tokio::time::timeout(TIMEOUT, async {
        while session
            .recv_data()
            .await
            .expect("read the capsule stream")
            .is_some()
        {}
    })
    .await;
    ended.expect("the server must close its half of a session the client ended");
}

/// A connection that has opened and closed sessions holds nothing for them.
///
/// The composition question behind half the release paths in this server: a
/// session's memory is held by no counter and freed by no explicit call -- the
/// tunnel slot, the Quarter Stream ID claim, the inbound queue, the target
/// socket and the decoded request are all released by *dropping* the things that
/// own them, on whichever of the half-dozen paths a session ends by. Each of
/// those drops is unit-tested where it lives; that they all actually run when a
/// real session closes is only visible from here.
///
/// Every session is genuinely live before it is closed -- a datagram goes to the
/// target and its answer comes back -- so a run that closed nothing because it
/// opened nothing cannot pass.
///
/// # Measured
///
/// On the dev host (macOS, debug build), 64 sessions opened, exercised and
/// closed one after another leave about 39 KiB behind in total: roughly 630
/// bytes a session, against the ~156 KiB each of them held while it was live.
/// Left open instead of closed, the same run leaves 4.5 MiB behind, so the
/// allowance below is thirteen times the measurement and a ninth of a leak.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_keeps_nothing_for_the_sessions_it_has_closed() {
    let _scales = SCALES.lock().await;

    let server = TestServer::start().await;
    let echo = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // One session before the window, so what the window weighs is the churn
    // rather than whatever a connection allocates for its first session.
    let (quarter, mut first) = open_udp_session(&mut client, &server, echo).await;
    udp_round_trip(&client, quarter, b"warm-up").await;
    close_session(&mut first).await;
    drop(first);

    let allowed = CHURNED_SESSIONS as i64 * KEPT_PER_CLOSED_SESSION;

    let ((), kept) = while_holding(async {
        for index in 0..CHURNED_SESSIONS {
            let (quarter, mut session) = open_udp_session(&mut client, &server, echo).await;
            let answer = udp_round_trip(&client, quarter, b"round trip").await;
            assert_eq!(
                &answer[..],
                b"round trip",
                "session {index} did not reach its target"
            );
            close_session(&mut session).await;
        }

        // The last session's FIN reaches the client a few instructions before
        // the drops that follow it, so the tally is given a moment to catch up
        // rather than being read on the heels of the loop.
        settle(|live| live < allowed).await;
    })
    .await;

    assert!(
        kept < allowed,
        "{CHURNED_SESSIONS} sessions opened and closed left {kept} bytes behind, \
         past the {allowed} a connection is allowed to keep for them: something \
         a session held is outliving it"
    );
}
