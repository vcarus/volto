//! The hostile-peer matrix: what a peer that has proved nothing can make this
//! server do, and which bound answers each attempt.
//!
//! Every other binary in this suite is organised around a feature -- tunnels,
//! settings, the policy. This one is organised around the attacker, so that the
//! next reviewer reads the threat model once instead of deriving it again from
//! nine files. Most rows below are already pinned elsewhere and are *referenced*
//! rather than copied; the tests in this file are the rows that had no pin.
//!
//! # The matrix
//!
//! "Bound" names the constant or configuration key that answers the attempt and
//! the source it lives in; "on the wire" is what the peer actually observes,
//! since that is all these tests may assert.
//!
//! | # | What the peer does | Bound | On the wire | Pinned by |
//! |---|---|---|---|---|
//! | a | Starts a QUIC handshake and abandons it, retransmitting Initials so the transport never sees it as idle | `max_idle_timeout` around `incoming.await`, plus the `max_connections` slot the accept loop takes before it (`src/quic.rs`) | Nothing -- the `Connecting` is dropped, which refuses the connection at the QUIC layer; the slot comes back | `it_handshake::a_quic_handshake_that_never_completes_gives_its_slot_back` |
//! | a2 | Completes the QUIC handshake but permits no unidirectional streams, so the HTTP/3 handshake cannot finish | `max_idle_timeout` on `h3api::Connection::handshake` (`src/h3/connection.rs`) | CONNECTION_CLOSE H3_STREAM_CREATION_ERROR (0x103) | `it_handshake::a_peer_that_permits_no_unidirectional_streams_is_hung_up_on` |
//! | b | Completes both handshakes and then says nothing, answering keep-alives | `SILENCE_FACTOR * max_idle_timeout` from the handshake, never re-armed (`src/conn.rs`, D76) | CONNECTION_CLOSE H3_NO_ERROR (0x100); the `max_connections` slot comes back | `it_handshake::a_peer_that_never_sends_a_request_gives_its_slot_back`; shipped numbers in [`the_shipped_bound_closes_a_silent_peer`] |
//! | c | Opens one request stream per idle period, a byte on each, never a whole request (review C1') | The same deadline: it is absolute, so opening streams buys no time (`src/conn.rs`) | CONNECTION_CLOSE H3_NO_ERROR two idle timeouts after the *handshake* | `it_handshake::opening_request_streams_does_not_extend_the_bound`; shipped numbers in [`the_shipped_bound_is_not_extended_by_new_streams`] |
//! | c2 | Authenticates once and then idles for ever | None -- the bound is lifted for the life of the connection (`Context.authenticated`) | Nothing; the connection stays usable | `it_handshake::an_authenticated_connection_is_not_bounded` |
//! | d | Opens a request stream and stalls before its HEADERS arrive | One `max_idle_timeout` per stream, in `Resolver::resolve` (`src/h3/stream.rs`, D76 M2) | RESET_STREAM + STOP_SENDING H3_REQUEST_INCOMPLETE (0x10d); the connection carries on | `it_handshake::a_request_that_stalls_before_its_headers_is_reset` |
//! | d2 | Opens a unidirectional stream and never completes its type varint | One `max_idle_timeout` on `read_stream_type` (`src/h3/connection.rs`, review L3) | STOP_SENDING H3_STREAM_CREATION_ERROR; the connection carries on | `it_hardening::a_unidirectional_stream_that_never_names_its_type_is_abandoned` |
//! | e | Announces a HEADERS frame larger than one frame may be | `MAX_BUFFERED_FRAME` = `MAX_FIELD_SECTION_SIZE` = 64 KiB (`src/h3/frame.rs`) | 431 then STOP_SENDING H3_EXCESSIVE_LOAD (0x107); the connection carries on | `it_settings::an_oversized_header_section_is_refused` |
//! | e2 | Announces full-sized HEADERS on stream after stream and finishes none | `HEADERS_BUFFER_BUDGET` = 1 MiB per connection (`src/h3/mod.rs`, D77) | 431 + H3_EXCESSIVE_LOAD on the request past the budget only; sixteen at once are all served | `it_hardening::headers_buffered_across_a_connection_are_bounded`, `it_hardening::a_request_past_the_buffering_budget_costs_only_that_request` |
//! | e3 | Fills that budget with request streams, then sends its own well-formed control frames | The control stream has an unshared budget (`BufferBudget::unshared`), so its frames cannot be the ones refused -- a refusal there could only be a connection error | Nothing: the control frames are accepted and the connection lives | [`the_control_stream_does_not_share_the_request_buffering_budget`] |
//! | f | Grants no flow-control window, so it never reads its 407/403/431/501 | One `max_idle_timeout` per refusal write, in `Stream::respond_within` (`src/h3/stream.rs`, review H1) | RESET_STREAM H3_REQUEST_CANCELLED (0x10c); the connection carries on | `it_hardening::a_refusal_the_peer_will_not_take_is_reset`, `it_hardening::a_431_the_peer_will_not_take_is_reset`; shipped numbers in [`the_shipped_write_deadline_ends_an_unread_refusal`] |
//! | g | Guesses credentials down one connection | `[security] max_auth_failures` (0 disables), counted *before* the 407 is written (`src/conn.rs`, review H1) | CONNECTION_CLOSE 0x10b (`h3api::AUTH_FAILURE_LIMIT_CODE`), at once rather than after the bounded write | `it_hardening::repeated_authentication_failures_close_the_connection`, `it_hardening::a_peer_that_never_reads_its_407_still_spends_its_budget`, `it_hardening::a_zero_budget_disables_the_cap` |
//! | h | Opens more than sixteen unidirectional streams | `MAX_PEER_UNI_STREAMS` = 16, a transport parameter (`src/quic.rs`) | The seventeenth is never granted: no credit, so no stream and nothing to refuse | [`sixteen_is_all_the_unidirectional_streams_a_peer_gets`] |
//! | i | Opens a unidirectional stream of an unknown type | RFC 9114 §6.2: unknown types are aborted, never a connection error (`src/h3/connection.rs`) | STOP_SENDING H3_STREAM_CREATION_ERROR; the connection carries on | [`a_unidirectional_stream_of_an_unknown_type_costs_one_stream`] |
//! | i2 | Opens a second control stream, a client-initiated push stream, or closes its control stream cleanly | RFC 9114 §6.2.1/§6.2.2 (`src/h3/connection.rs`) | CONNECTION_CLOSE H3_STREAM_CREATION_ERROR for the first two, H3_CLOSED_CRITICAL_STREAM (0x104) for the third | [`unidirectional_streams_that_break_a_critical_stream_rule_end_the_connection`] |
//! | j | Sends a frame type reserved for HTTP/2 (0x02, 0x06, 0x08, 0x09) | `RESERVED_HTTP2_TYPES` (`src/h3/frame.rs`) | CONNECTION_CLOSE H3_FRAME_UNEXPECTED (0x105), whatever stream it arrives on | [`frame_types_reserved_for_http2_end_the_connection`] |
//! | j2 | Puts an unknown or empty frame before SETTINGS on the control stream | RFC 9114 §6.2.1 first-frame rule (`Control::accept`) | CONNECTION_CLOSE H3_MISSING_SETTINGS (0x10a) | `it_settings::a_frame_before_settings_ends_the_connection` |
//! | j5 | Sends a frame that belongs on the control stream -- SETTINGS, GOAWAY, CANCEL_PUSH, MAX_PUSH_ID, PUSH_PROMISE -- on a request stream, declaring a length past what one frame may be | RFC 9114 §7.2.3-§7.2.7 and §4.1, applied to the frame *type* before its length (`frame::misplaced`) | CONNECTION_CLOSE H3_FRAME_UNEXPECTED (0x105), never a 431, and nothing charged to the buffering budget on the way | [`control_stream_frames_on_a_request_stream_end_the_connection`], [`a_frame_refused_for_its_type_is_never_charged_for`] |
//! | j6 | Announces a HEADERS frame on a tunnel whose CONNECT has been answered, and never finishes it | RFC 9114 §4.4, decided from the frame header rather than after the payload (`frame::misplaced`) | CONNECTION_CLOSE H3_FRAME_UNEXPECTED (0x105); the announcement never reaches the budget, so tunnels cannot pin it between them | [`a_field_section_on_an_established_tunnel_ends_the_connection`] |
//! | j3 | Sends a second SETTINGS, or HEADERS/DATA/PUSH_PROMISE, on the control stream after SETTINGS | `Control::accept` (`src/h3/connection.rs`) | CONNECTION_CLOSE H3_FRAME_UNEXPECTED | [`frames_the_control_stream_may_not_carry_end_the_connection`] |
//! | j4 | Sends CANCEL_PUSH, or a MAX_PUSH_ID that shrinks | RFC 9114 §7.2.3/§7.2.7 (`Control::accept`) | CONNECTION_CLOSE H3_ID_ERROR (0x108) | `it_critical_streams::a_cancel_push_is_an_id_error`, `it_critical_streams::a_shrinking_max_push_id_is_an_id_error` |
//! | k | References the QPACK dynamic table in a field section | `QPACK_MAX_TABLE_CAPACITY = 0` is advertised, so there is no entry to name (`src/h3/qpack.rs`) | CONNECTION_CLOSE QPACK_DECOMPRESSION_FAILED (0x200) | `it_extended_connect::a_dynamic_table_reference_closes_the_connection` |
//! | k2 | Sends encoder or decoder instructions for that table | RFC 9204 §6 (`serve_qpack`) | CONNECTION_CLOSE QPACK_ENCODER_STREAM_ERROR (0x201) / QPACK_DECODER_STREAM_ERROR (0x202) | `it_critical_streams::encoder_instructions_beyond_a_zero_table_are_refused`, `it_critical_streams::decoder_instructions_for_a_table_never_used_are_refused` |
//! | l | Sends a datagram whose Quarter Stream ID is unparseable or above 2^60-1 | RFC 9297 §2.1's two MUST-close cases (`src/datagram.rs`, `route_datagram`) | CONNECTION_CLOSE H3_DATAGRAM_ERROR (0x33) | `it_udp::an_out_of_range_quarter_stream_id_closes_the_connection`, `it_udp::a_datagram_without_a_quarter_stream_id_closes_the_connection` |
//! | l2 | Sends a datagram for a session that does not exist, or with an unknown or truncated context ID | Dropped, never a connection error (`route_datagram`, `Shared::deliver`) | Nothing at all; the connection and every session on it carry on | `it_udp::datagrams_for_unknown_sessions_are_dropped`, `it_udp::unknown_context_ids_are_dropped_without_ending_the_session`, `it_udp::a_truncated_context_id_is_dropped_without_closing_the_connection` |
//! | l3 | Sends a datagram before it has sent SETTINGS, or one addressed to a live *TCP* tunnel | The same drop: the routing table is claimed by CONNECT-UDP sessions only, and receipt is not gated on the peer's SETTINGS | Nothing; the tunnel is unaffected | [`datagrams_no_session_can_own_are_dropped`] |
//! | m | Sends a truncated, oversized or unknown capsule on a session's request stream | RFC 9297 §3 incremental decoder, `MAX_DATAGRAM_CAPSULE_VALUE` per capsule (`src/capsule.rs`) | RESET_STREAM H3_MESSAGE_ERROR (0x10e) for a capsule that merely stopped early, H3_DATAGRAM_ERROR (0x33) for one that could never parse, nothing at all for an unknown type; the connection carries on | `it_udp::a_truncated_capsule_is_rejected`, `it_udp::an_oversized_datagram_capsule_is_reset_as_a_parse_error`, `it_udp::unknown_capsule_types_are_skipped` |
//! | n | Opens more request streams than it is allowed at once | `[limits] max_streams_bidi` (`src/quic.rs`) | The next one is never granted; the streams already open are untouched | [`the_bidirectional_stream_limit_caps_what_one_peer_can_open`] |
//! | n2 | Opens more tunnels than one connection may hold | `[limits] max_targets_per_conn`, taken before any socket is (`src/conn.rs`) | 503 with `Proxy-Status: connection_limit_reached`; other connections have their own budget | `it_policy::the_tunnel_quota_is_enforced_per_connection`, `it_policy::tcp_and_udp_tunnels_share_the_quota` |
//! | o | Opens its control stream with an unknown frame whose declared length never ends, then authenticates | **None.** The MISSING_SETTINGS verdict is suspended for as long as the frame runs, and an authenticated connection is not bounded | Nothing: the connection serves requests for ever. **Recorded residual** (review L1, "recorded, not fixed"): the cost to this server is zero -- the payload is discarded as it arrives, never buffered -- and it needs credentials, so it buys an authenticated peer nothing it does not already have | [`an_unfinished_unknown_frame_suspends_the_settings_verdict`] pins today's behaviour so a change is noticed |
//! | p | Opens and resets request streams in a storm, each announcing a full-sized field section | No rate limit; what has to hold is that every charge is released when the frame dies with its stream (`FrameDecoder`'s guard, D77) | Nothing; the budget is exactly where it was afterwards | [`a_storm_of_reset_requests_leaves_the_budget_where_it_was`] |
//! | q | Asks for a target in private address space, or on a denied port | `[security] allow_private_networks`, `denied_ports` (`src/policy.rs`) | 403 with `Proxy-Status: destination_ip_prohibited` / `http_request_denied` | `it_policy::loopback_is_prohibited_by_default`, `it_policy::special_purpose_and_transition_addresses_are_prohibited_by_default`, `it_policy::a_denied_port_is_refused_on_both_paths` |
//! | q2 | Asks for a name the exit resolver blackholed | D49: not this proxy's refusal to make | 200, then the stream is closed at once -- indistinguishable from a target that hung up | `it_policy::a_blackholed_tcp_target_is_accepted_then_closed`, `it_policy::a_blackholed_udp_target_is_accepted_then_closed` |
//! | q3 | Points a CONNECT-UDP session at a target that never answers, and floods it | `[security] unanswered_packet_budget` (`src/tunnel/udp.rs`) | Packets past the budget are dropped; the budget is lifted once the target answers | `it_policy::packets_to_a_silent_target_are_capped`, `it_policy::the_cap_is_lifted_once_the_target_answers` |
//! | q4 | Guesses with a user-id carrying a newline, a terminal escape, or 48 KB of text | `logfmt::bounded` cuts the peer's bytes to 32 and tracing escapes them, in a line that puts `remote=` first (`src/conn.rs`, `src/logfmt.rs`, review H3/M5) | A quoted, escaped, truncated `username=` field: no forged journal line, and no log amplification -- and never the attempted password | `it_log_fields::operator_facing_fields_print_values_not_options`, `it_auth_log::a_rejected_password_is_never_logged` |
//! | r | Sends GOAWAY | RFC 9114 §5.2: a client's GOAWAY does not end the connection here; only an identifier that grows is an error | Nothing, and requests are still served; a growing identifier is CONNECTION_CLOSE H3_ID_ERROR | [`a_goaway_from_the_peer_does_not_end_the_connection`] |
//! | r2 | Completes the QUIC handshake and closes at once, never a stream and never a byte of HTTP/3 | Nothing to bound: the connection task ends with the connection | Nothing; the `max_connections` slot comes back | [`a_peer_that_closes_before_it_says_anything_frees_its_slot`] |
//!
//! # Reading the tests
//!
//! Every test here drives raw QUIC streams or the shared client and asserts what
//! the peer observes -- a status, a reset code, a close code, or nothing at all.
//! None of them reads a counter out of the server, and none asserts that a
//! stream allowance came back: a peer cannot see that, and the reset code is
//! what it can.
//!
//! The three `#[ignore]`d tests are the same rows with the shipped defaults
//! (`max_idle_timeout` = 60s) instead of a tightened configuration, so an
//! operator can prove the production numbers once:
//!
//! ```text
//! cargo test --test it_hostile -- --ignored
//! ```

mod common;

use std::future::Future;
use std::panic::Location;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use common::rawstream::{
    application_close, assert_closed_with, authenticated_connect_headers_frame,
    connect_headers_frame, frame, read_frame, status_of,
};
use common::{
    auth_section, basic_credentials, client_endpoint, client_endpoint_with_transport, connect_quic,
    finish_connect, open_tcp_tunnel, read_at_least, spawn_echo_target, H3Client, TestServer,
    ALLOW_PRIVATE, IMPATIENT, TIMEOUT,
};
use volto::datagram;

// ---------------------------------------------------------------------------
// The vocabulary, spelled out rather than imported
// ---------------------------------------------------------------------------
//
// These are the bytes the server is asked to parse and the codes it is asked to
// answer with. A test that took them from the server's own constants would agree
// with it whatever it held.

/// DATA frame type (RFC 9114 §7.2.1).
const FRAME_DATA: u64 = 0x00;
/// HEADERS frame type (RFC 9114 §7.2.2).
const FRAME_HEADERS: u64 = 0x01;
/// CANCEL_PUSH frame type (RFC 9114 §7.2.3).
const FRAME_CANCEL_PUSH: u64 = 0x03;
/// SETTINGS frame type (RFC 9114 §7.2.4).
const FRAME_SETTINGS: u64 = 0x04;
/// PUSH_PROMISE frame type (RFC 9114 §7.2.5).
const FRAME_PUSH_PROMISE: u64 = 0x05;
/// GOAWAY frame type (RFC 9114 §7.2.6).
const FRAME_GOAWAY: u64 = 0x07;
/// MAX_PUSH_ID frame type (RFC 9114 §7.2.7).
const FRAME_MAX_PUSH_ID: u64 = 0x0d;

/// Control stream type (RFC 9114 §6.2.1).
const STREAM_CONTROL: u64 = 0x00;
/// Push stream type (RFC 9114 §6.2.2), which only a server may open.
const STREAM_PUSH: u64 = 0x01;

/// A reserved stream or frame type of the form 0x1f * N + 0x21 (RFC 9114 §9).
///
/// N is arbitrary: every value of it names something an endpoint must ignore or
/// abort rather than fault on.
const GREASE: u64 = 0x1f * 7 + 0x21;

/// H3_NO_ERROR (RFC 9114 §8.1): a close with nothing to report.
const H3_NO_ERROR: u64 = 0x100;
/// H3_STREAM_CREATION_ERROR (RFC 9114 §8.1).
const H3_STREAM_CREATION_ERROR: u64 = 0x103;
/// H3_CLOSED_CRITICAL_STREAM (RFC 9114 §8.1).
const H3_CLOSED_CRITICAL_STREAM: u64 = 0x104;
/// H3_FRAME_UNEXPECTED (RFC 9114 §8.1).
const H3_FRAME_UNEXPECTED: u64 = 0x105;
/// H3_ID_ERROR (RFC 9114 §8.1).
const H3_ID_ERROR: u64 = 0x108;
/// H3_REQUEST_CANCELLED (RFC 9114 §8.1).
///
/// A `u32` because this one is also *sent* by the tests below, and that is what
/// [`quinn::VarInt::from_u32`] takes without a fallible conversion.
const H3_REQUEST_CANCELLED: u32 = 0x10c;

/// The most unidirectional streams this server lets a peer have at once.
///
/// `MAX_PEER_UNI_STREAMS` in `src/quic.rs`, written out here because it is a
/// transport parameter: what it means is what the peer is granted, and that is
/// what the test measures.
const PEER_UNI_STREAMS: usize = 16;

/// Field sections of the largest advertised size one connection may hold
/// half-received at once: `HEADERS_BUFFER_BUDGET / MAX_FIELD_SECTION_SIZE`.
const FULL_SIZED_FRAMES_THAT_FIT: usize = 16;

/// A target the destination policy refuses before the resolver is asked.
///
/// Port 25 is on the default deny list and the port rule is checked first, so a
/// request for it is answered without touching the network.
const DENIED_TARGET: &str = "192.0.2.1:25";

/// The credentials the tests that configure authentication use.
const USER: (&str, &str) = ("user1", "s3cret");

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

/// A SETTINGS frame carrying one harmless setting.
///
/// Non-empty on purpose: a zero-length frame is charged nothing, and one of the
/// tests below is about what a control frame is charged.
fn settings_frame() -> Vec<u8> {
    let mut payload = BytesMut::new();
    // SETTINGS_MAX_FIELD_SECTION_SIZE (RFC 9114 §7.2.4.1), which is what a
    // client tells a server about its own willingness to receive.
    datagram::put_varint(&mut payload, 0x06);
    datagram::put_varint(&mut payload, volto::h3::MAX_FIELD_SECTION_SIZE);
    frame(FRAME_SETTINGS, &payload)
}

/// A frame whose whole payload is one varint: GOAWAY or MAX_PUSH_ID.
fn varint_frame(kind: u64, value: u64) -> Vec<u8> {
    let mut payload = BytesMut::new();
    datagram::put_varint(&mut payload, value);
    frame(kind, &payload)
}

/// Opens a unidirectional stream of `stream_type` and writes `bytes` after it.
async fn open_uni_stream(
    connection: &quinn::Connection,
    stream_type: u64,
    bytes: &[u8],
) -> quinn::SendStream {
    let mut stream = connection
        .open_uni()
        .await
        .expect("open a unidirectional stream");

    let mut wire = BytesMut::new();
    datagram::put_varint(&mut wire, stream_type);
    wire.extend_from_slice(bytes);
    stream.write_all(&wire).await.expect("send the stream");

    stream
}

/// Opens a request stream, announces a full-sized HEADERS frame and sends one
/// byte of it.
///
/// One byte rather than none so the stream is genuinely mid-frame, and both
/// halves are handed back rather than dropped: dropping a [`quinn::SendStream`]
/// finishes it, which would tell the server the frame will never be completed.
async fn announce_full_sized_headers(
    connection: &quinn::Connection,
) -> (quinn::SendStream, quinn::RecvStream) {
    let (mut send, recv) = connection.open_bi().await.expect("open a request stream");

    let mut announcement = BytesMut::new();
    datagram::put_varint(&mut announcement, FRAME_HEADERS);
    datagram::put_varint(&mut announcement, volto::h3::MAX_FIELD_SECTION_SIZE);
    announcement.extend_from_slice(b"\x00");
    send.write_all(&announcement)
        .await
        .expect("announce a full-sized field section");

    (send, recv)
}

/// Opens a request stream and writes a frame header for `kind` declaring
/// `length` bytes, without a byte of the payload behind it.
///
/// The header alone is the whole of the case for the tests below: a verdict that
/// waited for the payload would never be reached, so one that arrives proves the
/// frame was judged from its type and its declared length alone.
async fn announce_frame(
    connection: &quinn::Connection,
    kind: u64,
    length: u64,
) -> (quinn::SendStream, quinn::RecvStream) {
    let (mut send, recv) = connection.open_bi().await.expect("open a request stream");

    let mut announcement = BytesMut::new();
    datagram::put_varint(&mut announcement, kind);
    datagram::put_varint(&mut announcement, length);
    // A write that fails is the connection already gone, which is one of the
    // answers these tests wait for rather than a failure of the test.
    let _ = send.write_all(&announcement).await;

    (send, recv)
}

/// Opens a request stream and asserts the server answers it.
///
/// The answer is a 403 rather than a 200 because the target is [`DENIED_TARGET`]:
/// nothing has to be listening, and the answer still proves the connection is
/// serving rather than merely unclosed -- which is the difference most cases here
/// turn on.
///
/// Written as a synchronous function returning a future so `#[track_caller]`
/// survives to the poll that panics (D66).
#[track_caller]
fn still_serving(connection: &quinn::Connection) -> impl Future<Output = ()> + '_ {
    let caller = Location::caller();
    async move {
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .unwrap_or_else(|error| panic!("the connection at {caller} is gone: {error}"));
        send.write_all(&connect_headers_frame(DENIED_TARGET))
            .await
            .unwrap_or_else(|error| {
                panic!("the request sent at {caller} could not be written: {error}")
            });

        let (frame_type, payload) = read_frame(&mut recv).await;
        assert_eq!(
            frame_type, FRAME_HEADERS,
            "at {caller}: a response begins with HEADERS"
        );
        assert_eq!(
            status_of(&payload),
            "403",
            "at {caller}: the connection must still be serving requests"
        );
    }
}

/// Asserts that `connection` is still open after `within`.
///
/// The negative half of most of these cases: what the peer observes is that
/// nothing happened to it.
#[track_caller]
fn stays_open(connection: &quinn::Connection, within: Duration) -> impl Future<Output = ()> + '_ {
    let caller = Location::caller();
    async move {
        if let Ok(error) = tokio::time::timeout(within, connection.closed()).await {
            panic!("the connection at {caller} was closed within {within:?}: {error}");
        }
    }
}

/// Transport parameters for a peer with no room for an answer at all.
///
/// A short response fits in any per-stream window big enough for the server's
/// own 19-byte SETTINGS frame, so what has to be exhausted is the *connection*
/// window: nothing here reads the server's control stream, so those 19 bytes
/// stay charged to that window and leave less than a response behind them. The
/// keep-alive is what makes a test about the application's deadlines -- with it,
/// the transport's own idle timeout can never be the thing that ends anything.
fn windowless_transport() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.receive_window(24u32.into());
    transport.stream_receive_window(24u32.into());
    transport.keep_alive_interval(Some(Duration::from_millis(100)));
    transport
}

/// A QUIC connection that keeps itself alive and has said nothing.
///
/// Same shape as `it_handshake`'s peer, and for the same reason: with the
/// keep-alive, every ACK restarts the server's idle timer, so the transport can
/// never be the thing that closes the connection and only an application bound
/// can be.
async fn silent_peer(server: &TestServer) -> (quinn::Endpoint, quinn::Connection) {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_millis(100)));

    let endpoint = client_endpoint_with_transport(&server.ca, &["h3"], transport);
    let connection = finish_connect(&endpoint, server.addr)
        .await
        .expect("the QUIC handshake must succeed");

    (endpoint, connection)
}

// ---------------------------------------------------------------------------
// h: the peer's unidirectional stream allowance
// ---------------------------------------------------------------------------

/// HTTP/3 needs three unidirectional streams from a client and this server
/// grants sixteen, so the seventeenth is not refused -- it is never granted.
///
/// The allowance is a transport parameter, which means the peer's own stack
/// enforces it and nothing reaches the server at all: there is no stream to
/// abort, no task to park, and nothing to log. That is the whole point of
/// bounding it there (review L3), and it is why this test asserts on a stream
/// that does not open rather than on a code.
///
/// The second half is what makes it a limit on what a peer holds at once rather
/// than on what it may ever open: once the streams end, the allowance is back.
#[tokio::test]
async fn sixteen_is_all_the_unidirectional_streams_a_peer_gets() {
    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    // Not written to: an unwritten stream is one the server has not seen, so
    // nothing here can hand the credit back early.
    let mut open = Vec::new();
    for index in 0..PEER_UNI_STREAMS {
        let stream = tokio::time::timeout(TIMEOUT, connection.open_uni())
            .await
            .unwrap_or_else(|_| panic!("stream {index} of {PEER_UNI_STREAMS} was not granted"))
            .expect("open a unidirectional stream");
        open.push(stream);
    }

    assert!(
        tokio::time::timeout(Duration::from_millis(500), connection.open_uni())
            .await
            .is_err(),
        "a {}th unidirectional stream must not be granted",
        PEER_UNI_STREAMS + 1
    );
    assert!(
        connection.close_reason().is_none(),
        "asking for one stream too many is not a protocol violation"
    );

    // Ending them is what returns the allowance -- it caps what a peer may hold
    // at once, not how many it may ever open. All sixteen go rather than one,
    // because how a peer's stack meters a partial return is quinn's business
    // and not this server's: what the server owes is the allowance back once
    // the streams are gone.
    for stream in &mut open {
        stream.finish().expect("finish a stream");
    }
    let granted = tokio::time::timeout(TIMEOUT, connection.open_uni())
        .await
        .expect("the allowance must come back once the streams end")
        .expect("open a unidirectional stream");
    drop(granted);
}

// ---------------------------------------------------------------------------
// i: unidirectional streams the server will not serve
// ---------------------------------------------------------------------------

/// A unidirectional stream of a type this server does not know costs that
/// stream and nothing else.
///
/// The rule is RFC 9114 §6.2's: unknown stream types are aborted or discarded
/// and MUST NOT be a connection error of any kind. A greasing client is exactly
/// the peer testing this, and it is a well-behaved one.
#[tokio::test]
async fn a_unidirectional_stream_of_an_unknown_type_costs_one_stream() {
    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    let greased = open_uni_stream(&connection, GREASE, b"nothing here means anything").await;

    let stopped = tokio::time::timeout(TIMEOUT, greased.stopped())
        .await
        .expect("the server must not read an unknown stream indefinitely")
        .expect("the stream must be stopped, not broken");
    assert_eq!(
        stopped.map(quinn::VarInt::into_inner),
        Some(H3_STREAM_CREATION_ERROR),
        "an unknown stream type is aborted, and the peer is told which code with"
    );

    assert!(
        connection.close_reason().is_none(),
        "an unknown stream type must not be a connection error of any kind"
    );
    still_serving(&connection).await;
}

/// The three ways a peer can break a critical-stream rule with a stream rather
/// than a frame.
///
/// All three are connection errors, and the code is the assertion: a second
/// control stream and a client-initiated push stream are both
/// H3_STREAM_CREATION_ERROR, while a control stream the peer finishes -- however
/// politely -- is H3_CLOSED_CRITICAL_STREAM. A test client that got these wrong
/// would take the connection down mid-tunnel, so what each one is answered with
/// is worth pinning separately.
#[tokio::test]
async fn unidirectional_streams_that_break_a_critical_stream_rule_end_the_connection() {
    for (name, code, second_stream, finish_control) in [
        (
            "a client-initiated push stream",
            H3_STREAM_CREATION_ERROR,
            Some(STREAM_PUSH),
            false,
        ),
        (
            "a second control stream",
            H3_STREAM_CREATION_ERROR,
            Some(STREAM_CONTROL),
            false,
        ),
        (
            "a control stream the peer closed",
            H3_CLOSED_CRITICAL_STREAM,
            None,
            true,
        ),
    ] {
        let server = TestServer::start().await;
        let (_endpoint, connection) = connect_quic(&server).await;

        // The legitimate control stream first, in every case: two of the
        // offences are about a *second* stream, and the third is about this one
        // ending.
        let mut control = open_uni_stream(&connection, STREAM_CONTROL, &settings_frame()).await;

        if let Some(stream_type) = second_stream {
            let _second = open_uni_stream(&connection, stream_type, &[]).await;
        }
        if finish_control {
            control.finish().expect("finish the control stream");
        }

        let (closed_with, reason) = application_close(&connection, TIMEOUT).await;
        assert_eq!(
            closed_with, code,
            "{name}: wrong close code; the reason was {reason:?}"
        );
        assert!(
            !reason.is_empty(),
            "{name}: the peer must be told what it did"
        );
    }
}

// ---------------------------------------------------------------------------
// j: frames that end the connection
// ---------------------------------------------------------------------------

/// The frame types HTTP/2 used and HTTP/3 does not are a connection error
/// wherever they arrive.
///
/// A peer sending one has mistaken this connection for an HTTP/2 one, and the
/// rule is not about which stream it made the mistake on -- so this drives them
/// onto a *request* stream, where the rest of the suite never looks, and where a
/// decoder that classified them per stream would answer with a reset instead.
#[tokio::test]
async fn frame_types_reserved_for_http2_end_the_connection() {
    for kind in [0x02u64, 0x06, 0x08, 0x09] {
        let server = TestServer::start().await;
        let (_endpoint, connection) = connect_quic(&server).await;

        let (mut send, _recv) = connection.open_bi().await.expect("open a request stream");
        send.write_all(&frame(kind, b"as HTTP/2 would have it"))
            .await
            .expect("send a reserved frame");

        let (closed_with, reason) = application_close(&connection, TIMEOUT).await;
        assert_eq!(
            closed_with, H3_FRAME_UNEXPECTED,
            "frame type {kind:#x} is reserved for HTTP/2; the reason was {reason:?}"
        );
    }
}

/// What the control stream may not carry once SETTINGS has been seen.
///
/// The first-frame rule has its own test in `it_settings`; this is the other
/// half -- the frames that are wrong on this stream whenever they arrive. Each
/// case sends a perfectly good SETTINGS first, so a server that tripped over
/// that instead would fail here with a different code.
#[tokio::test]
async fn frames_the_control_stream_may_not_carry_end_the_connection() {
    for (name, offence) in [
        ("a second SETTINGS frame", settings_frame()),
        (
            "a HEADERS frame",
            frame(FRAME_HEADERS, b"not on this stream"),
        ),
        ("a DATA frame", frame(FRAME_DATA, b"nor this one")),
        ("a PUSH_PROMISE frame", frame(FRAME_PUSH_PROMISE, b"\x00")),
    ] {
        let server = TestServer::start().await;
        let (_endpoint, connection) = connect_quic(&server).await;

        let mut control = settings_frame();
        control.extend_from_slice(&offence);
        let _control = open_uni_stream(&connection, STREAM_CONTROL, &control).await;

        let (closed_with, reason) = application_close(&connection, TIMEOUT).await;
        assert_eq!(
            closed_with, H3_FRAME_UNEXPECTED,
            "{name} on the control stream; the reason was {reason:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// j5, j6: a frame's type is judged before its length
// ---------------------------------------------------------------------------

/// The frames that belong on the control stream are a connection error on a
/// request stream, whatever length they declare.
///
/// The declared length is the point. 100000 bytes is past `MAX_BUFFERED_FRAME`,
/// so a decoder that checked the length first would answer with the 431 and the
/// stream reset a field section too large to hold gets -- a nonsensical reply to
/// a frame that is not a field section at all, and one that leaves the
/// connection running after a MUST-close. Not a byte of payload is sent, so the
/// verdict cannot have waited for one.
#[tokio::test]
async fn control_stream_frames_on_a_request_stream_end_the_connection() {
    /// Past the largest frame this server will buffer, so the per-frame cap
    /// would have something to say about it.
    const PAST_ONE_FRAME: u64 = 100_000;

    for (name, kind, length) in [
        ("SETTINGS", FRAME_SETTINGS, PAST_ONE_FRAME),
        ("GOAWAY", FRAME_GOAWAY, PAST_ONE_FRAME),
        ("CANCEL_PUSH", FRAME_CANCEL_PUSH, PAST_ONE_FRAME),
        ("MAX_PUSH_ID", FRAME_MAX_PUSH_ID, PAST_ONE_FRAME),
        ("PUSH_PROMISE", FRAME_PUSH_PROMISE, PAST_ONE_FRAME),
        // The same verdict at a length the cap allows: what is judged is the
        // type, and it is judged the same way on either side of the bound.
        ("SETTINGS", FRAME_SETTINGS, 0),
    ] {
        let server = TestServer::start().await;
        let (_endpoint, connection) = connect_quic(&server).await;

        // Held rather than dropped: dropping the sending half finishes the
        // stream, and a stream that ends mid-frame has a verdict of its own
        // (H3_FRAME_ERROR) that would race this one.
        let (_held, mut recv) = announce_frame(&connection, kind, length).await;
        let answered = tokio::spawn(async move { recv.read_to_end(4096).await });

        let (closed_with, reason) = application_close(&connection, TIMEOUT).await;
        assert_eq!(
            closed_with, H3_FRAME_UNEXPECTED,
            "{name} declaring {length} bytes on a request stream; the reason was {reason:?}"
        );

        let answered = answered.await.expect("the response reader");
        assert!(
            answered.as_deref().unwrap_or(&[]).is_empty(),
            "{name}: a frame that is not a field section must not be answered like one, \
             got {answered:?}"
        );
    }
}

/// A frame refused for its type is refused before the connection is charged for
/// it.
///
/// Seventeen full-sized announcements is one past the connection's whole HEADERS
/// budget (D77), so a decoder that charged a PUSH_PROMISE the way it charges a
/// HEADERS would answer the last of them with a 431 and carry on. None of them
/// is charged: the first is a connection error the moment its header lands, and
/// no answer of any kind reaches the peer.
#[tokio::test(flavor = "multi_thread")]
async fn a_frame_refused_for_its_type_is_never_charged_for() {
    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    // Every stream is opened before any of them says anything: the first
    // announcement ends the connection, and `open_bi` with it.
    let mut streams = Vec::new();
    for _ in 0..=FULL_SIZED_FRAMES_THAT_FIT {
        streams.push(connection.open_bi().await.expect("open a request stream"));
    }

    let mut announcement = BytesMut::new();
    datagram::put_varint(&mut announcement, FRAME_PUSH_PROMISE);
    datagram::put_varint(&mut announcement, volto::h3::MAX_FIELD_SECTION_SIZE);

    let (answers, mut answered) = tokio::sync::mpsc::channel(FULL_SIZED_FRAMES_THAT_FIT + 1);
    let mut held = Vec::new();
    for (mut send, mut recv) in streams {
        // A write that fails is the connection already ended, which is the
        // answer this test is waiting for.
        let _ = send.write_all(&announcement).await;
        held.push(send);

        let answers = answers.clone();
        tokio::spawn(async move {
            if let Ok(response) = recv.read_to_end(4096).await {
                let _ = answers.send(response).await;
            }
        });
    }
    drop(answers);

    let (closed_with, reason) = application_close(&connection, TIMEOUT).await;
    assert_eq!(
        closed_with, H3_FRAME_UNEXPECTED,
        "a PUSH_PROMISE on a request stream; the reason was {reason:?}"
    );

    while let Some(response) = answered.recv().await {
        assert!(
            response.is_empty(),
            "a frame refused for its type must not be charged for: one announcement was \
             answered {}",
            status_of_response(&response)
        );
    }
}

/// A field section announced on an established tunnel is a connection error
/// decided from the frame header, not after payload that never comes.
///
/// RFC 9114 §4.4 permits only DATA once the CONNECT method has completed, and
/// the length here is exactly the largest frame this server will buffer -- inside
/// the per-frame cap, so a decoder that reached the length check would accept the
/// announcement, charge the connection's budget for it and wait. Sixteen tunnels
/// doing that pin the whole budget with five bytes apiece.
#[tokio::test]
async fn a_field_section_on_an_established_tunnel_ends_the_connection() {
    let server = TestServer::start().await;
    let echo = spawn_echo_target().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
    send.write_all(&connect_headers_frame(&echo.to_string()))
        .await
        .expect("send a CONNECT request");

    let (frame_type, payload) = read_frame(&mut recv).await;
    assert_eq!(frame_type, FRAME_HEADERS);
    assert_eq!(
        status_of(&payload),
        "200",
        "the tunnel must be established before the frame arrives"
    );

    let mut announcement = BytesMut::new();
    datagram::put_varint(&mut announcement, FRAME_HEADERS);
    datagram::put_varint(&mut announcement, volto::h3::MAX_FIELD_SECTION_SIZE);
    send.write_all(&announcement)
        .await
        .expect("announce a field section on the tunnel");

    let (closed_with, reason) = application_close(&connection, TIMEOUT).await;
    assert_eq!(
        closed_with, H3_FRAME_UNEXPECTED,
        "a HEADERS frame once the CONNECT had completed; the reason was {reason:?}"
    );
}

// ---------------------------------------------------------------------------
// e3: the control stream's own buffering budget
// ---------------------------------------------------------------------------

/// A peer that has filled the connection's HEADERS budget with request streams
/// must still be able to send its own control frames.
///
/// The budget hands out a *stream* error (D77, review M1), and there is no such
/// thing on the control stream: RFC 9114 §6.2.1 makes anything that ends it a
/// connection error. So a shared budget would mean a peer could be disconnected
/// for its own well-formed SETTINGS -- which is why the control stream is given
/// a budget of its own (`BufferBudget::unshared`).
///
/// The refusal is what proves the budget really is full at the moment the
/// control frames arrive; which stream is refused is up to the order the
/// server's tasks reach them in, so it is looked for rather than expected on a
/// particular one.
#[tokio::test(flavor = "multi_thread")]
async fn the_control_stream_does_not_share_the_request_buffering_budget() {
    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    let mut held = Vec::new();
    let (refusals, mut refused) = tokio::sync::mpsc::channel(FULL_SIZED_FRAMES_THAT_FIT + 1);
    for _ in 0..=FULL_SIZED_FRAMES_THAT_FIT {
        let (send, mut recv) = announce_full_sized_headers(&connection).await;
        // Parked rather than dropped: dropping the sending half finishes the
        // stream, which would tell the server the frame will never be completed
        // and give its share of the budget back.
        held.push(send);

        let refusals = refusals.clone();
        tokio::spawn(async move {
            if let Ok(response) = recv.read_to_end(4096).await {
                let _ = refusals.send(response).await;
            }
        });
    }
    drop(refusals);

    let response = tokio::time::timeout(TIMEOUT, refused.recv())
        .await
        .expect("one request past the budget must be refused")
        .expect("the refusal arrives on a live stream");
    assert_eq!(
        status_of_response(&response),
        "431",
        "the budget is full, which is the state the control stream is judged in"
    );

    // Two frames the control stream is entitled to send, both of them carrying a
    // payload: a zero-length frame would be charged nothing and would prove
    // nothing about whose budget it came out of.
    let mut control = settings_frame();
    control.extend_from_slice(&varint_frame(FRAME_MAX_PUSH_ID, 8));
    let _control = open_uni_stream(&connection, STREAM_CONTROL, &control).await;

    stays_open(&connection, Duration::from_millis(500)).await;
}

/// The `:status` of a response read whole from a raw request stream.
fn status_of_response(response: &[u8]) -> String {
    let (frame_type, used) = datagram::peek_varint(response).expect("a frame type");
    assert_eq!(frame_type, FRAME_HEADERS, "a response begins with HEADERS");
    let (length, more) = datagram::peek_varint(&response[used..]).expect("a frame length");

    let payload = &response[used + more..];
    assert_eq!(
        payload.len() as u64,
        length,
        "the response is the whole of what the stream carried"
    );
    status_of(payload)
}

// ---------------------------------------------------------------------------
// l3: datagrams nobody can own
// ---------------------------------------------------------------------------

/// Two datagrams no session could ever claim, and the answer to both is silence.
///
/// The first arrives before the peer has sent SETTINGS at all -- this server does
/// not gate *receipt* on the peer's settings, so what saves it is the routing
/// table being empty rather than any check. The second names a live TCP tunnel:
/// only a CONNECT-UDP session claims a Quarter Stream ID (D79), so a tunnel can
/// never be fed datagrams however precisely they are addressed.
///
/// Dropping is the whole behaviour. What would be wrong is a connection error --
/// RFC 9297 §2.1 keeps those for a Quarter Stream ID that cannot name a stream at
/// all, which `it_udp` pins -- or a datagram coming back.
#[tokio::test]
async fn datagrams_no_session_can_own_are_dropped() {
    let server = TestServer::start().await;

    // Before SETTINGS: a raw QUIC connection with no control stream on it yet.
    let (_endpoint, connection) = connect_quic(&server).await;
    connection
        .send_datagram(datagram::encode_udp_payload(4321, b"for nobody"))
        .expect("the server advertises max_datagram_frame_size");
    still_serving(&connection).await;
    assert!(
        connection.close_reason().is_none(),
        "a datagram for no session is dropped, not answered with a close"
    );

    // Addressed to a TCP tunnel, which never enters the routing table.
    let echo = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;
    let mut tunnel = open_tcp_tunnel(&mut client, &echo.to_string()).await;

    let quarter_stream_id = datagram::quarter_stream_id(tunnel.id());
    client
        .quic
        .send_datagram(datagram::encode_udp_payload(
            quarter_stream_id,
            b"not a UDP session",
        ))
        .expect("send a datagram for a TCP tunnel");

    assert!(
        tokio::time::timeout(Duration::from_millis(300), client.quic.read_datagram())
            .await
            .is_err(),
        "a datagram for a TCP tunnel must not be answered"
    );

    // And the tunnel itself never noticed.
    tunnel
        .send_data(Bytes::from_static(b"payload"))
        .await
        .expect("send payload");
    assert_eq!(read_at_least(&mut tunnel, 7).await, b"payload");
}

// ---------------------------------------------------------------------------
// n: the request-stream allowance
// ---------------------------------------------------------------------------

/// `max_streams_bidi` is what stops a peer from opening request streams without
/// end, and like the unidirectional allowance it is enforced by the peer's own
/// stack.
///
/// Two is enough to show the shape. What matters is the second half: the streams
/// already open are not disturbed by the peer asking for one too many, so a
/// client that runs into its own allowance loses nothing it already had.
#[tokio::test]
async fn the_bidirectional_stream_limit_caps_what_one_peer_can_open() {
    let server =
        TestServer::start_with(&format!("[limits]\nmax_streams_bidi = 2\n{ALLOW_PRIVATE}")).await;
    let echo = spawn_echo_target().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    let mut tunnels = Vec::new();
    for _ in 0..2 {
        let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
        send.write_all(&connect_headers_frame(&echo.to_string()))
            .await
            .expect("send a CONNECT request");

        let (frame_type, payload) = read_frame(&mut recv).await;
        assert_eq!(frame_type, FRAME_HEADERS);
        assert_eq!(status_of(&payload), "200", "the tunnel must be opened");
        tunnels.push((send, recv));
    }

    assert!(
        tokio::time::timeout(Duration::from_millis(500), connection.open_bi())
            .await
            .is_err(),
        "a third request stream must not be granted"
    );
    assert!(
        connection.close_reason().is_none(),
        "asking for one stream too many is not a protocol violation"
    );

    // The tunnels that were admitted still carry traffic.
    let (send, recv) = &mut tunnels[0];
    send.write_all(&frame(FRAME_DATA, b"payload"))
        .await
        .expect("send payload through the tunnel");
    let (frame_type, payload) = read_frame(recv).await;
    assert_eq!(frame_type, FRAME_DATA);
    assert_eq!(payload, b"payload");
}

// ---------------------------------------------------------------------------
// p: a storm of resets
// ---------------------------------------------------------------------------

/// Nothing rate-limits how fast a peer may open and reset request streams, and
/// nothing has to: what a stream costs while it lives is bounded, and this is
/// the proof that it costs nothing once it is gone.
///
/// Each round of the storm fills the budget exactly -- sixteen announcements of
/// the largest field section the server will buffer -- and then resets every
/// one of them, so the connection's whole budget passes through the charge path
/// a dozen times. If a single charge were left behind, the sixteen full-sized
/// announcements afterwards could not all fit -- which is exactly what the last
/// block measures.
///
/// A round does not reset until the server has been seen to refuse a
/// seventeenth announcement: that refusal is the only on-wire proof that the
/// sixteen were read and charged before they died. Without it the resets win
/// the race every time -- a `RESET_STREAM` that overtakes three bytes of
/// announcement is read by nobody -- and the storm would pass through the
/// charge path not once (mutation check, 2026-08-23).
#[tokio::test(flavor = "multi_thread")]
async fn a_storm_of_reset_requests_leaves_the_budget_where_it_was() {
    /// One leaked charge in any of these is enough to be caught below; the
    /// repetitions are for the leak that only happens on an unlucky
    /// interleaving.
    const ROUNDS: usize = 12;

    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    for _ in 0..ROUNDS {
        let (refusals, mut refused) = tokio::sync::mpsc::channel(FULL_SIZED_FRAMES_THAT_FIT + 1);
        let mut senders = Vec::new();
        for _ in 0..=FULL_SIZED_FRAMES_THAT_FIT {
            let (send, mut recv) = announce_full_sized_headers(&connection).await;
            senders.push(send);

            let refusals = refusals.clone();
            tokio::spawn(async move {
                if let Ok(response) = recv.read_to_end(4096).await {
                    let _ = refusals.send(response).await;
                }
            });
        }
        drop(refusals);

        let response = tokio::time::timeout(TIMEOUT, refused.recv())
            .await
            .expect("one announcement past the budget must be refused")
            .expect("the refusal arrives on a live stream");
        assert_eq!(
            status_of_response(&response),
            "431",
            "the budget is full, so every other announcement of this round is charged"
        );

        for mut send in senders {
            let _ = send.reset(quinn::VarInt::from_u32(H3_REQUEST_CANCELLED));
        }
    }

    stays_open(&connection, Duration::from_millis(200)).await;

    // Exactly the budget, announced all at once: not one of these may be
    // refused, and a leaked charge is what would refuse one.
    let mut held = Vec::new();
    let (refusals, mut refused) = tokio::sync::mpsc::channel(FULL_SIZED_FRAMES_THAT_FIT);
    for _ in 0..FULL_SIZED_FRAMES_THAT_FIT {
        let (send, mut recv) = announce_full_sized_headers(&connection).await;
        held.push(send);

        let refusals = refusals.clone();
        tokio::spawn(async move {
            if let Ok(response) = recv.read_to_end(4096).await {
                let _ = refusals.send(response).await;
            }
        });
    }
    drop(refusals);

    if let Ok(Some(response)) = tokio::time::timeout(Duration::from_secs(1), refused.recv()).await {
        panic!(
            "the budget did not survive the storm: a full-sized request was answered {}",
            status_of_response(&response)
        );
    }
    stays_open(&connection, Duration::from_millis(200)).await;
}

// ---------------------------------------------------------------------------
// o: the recorded residual
// ---------------------------------------------------------------------------

/// An unknown frame whose declared length never ends suspends the SETTINGS
/// verdict for as long as the peer cares to keep it running.
///
/// **This is a recorded residual, not a bound** (review L1, decided "recorded,
/// not fixed"). RFC 9114 §9 says unknown frame types are ignored, so the decoder
/// discards the payload as it arrives -- which means the frame is never
/// *completed*, and the rule that the control stream must open with SETTINGS is
/// never reached. The cost to this server is zero: nothing is buffered, and the
/// stream is one the peer was entitled to open anyway.
///
/// What keeps it harmless is the first half of this test: while the connection
/// has never authenticated, D76's absolute deadline closes it regardless of what
/// its control stream is doing. Past that door the suspension is unlimited, which
/// is the second half -- pinned so that a change to either half is noticed here
/// rather than in production.
#[tokio::test]
async fn an_unfinished_unknown_frame_suspends_the_settings_verdict() {
    /// An unknown frame declaring the largest length a varint can carry
    /// (2^62-1), of which one byte is sent.
    fn endless_unknown_frame() -> Vec<u8> {
        let mut wire = BytesMut::new();
        datagram::put_varint(&mut wire, GREASE);
        datagram::put_varint(&mut wire, (1u64 << 62) - 1);
        wire.extend_from_slice(b"\x00");
        wire.to_vec()
    }

    let server = TestServer::start_with(&format!("{IMPATIENT}{}", auth_section(&[USER]))).await;

    // Unauthenticated: the verdict is suspended, and the connection goes anyway.
    // H3_NO_ERROR rather than H3_MISSING_SETTINGS is the point -- what ended it
    // was the deadline, not the rule the frame is standing on.
    let (_endpoint, unauthenticated) = silent_peer(&server).await;
    let _control =
        open_uni_stream(&unauthenticated, STREAM_CONTROL, &endless_unknown_frame()).await;
    assert_closed_with(&unauthenticated, H3_NO_ERROR, Duration::from_secs(6)).await;

    // Authenticated: nothing bounds it any more.
    let (_endpoint, authenticated) = silent_peer(&server).await;
    let _control = open_uni_stream(&authenticated, STREAM_CONTROL, &endless_unknown_frame()).await;

    let (mut send, mut recv) = authenticated
        .open_bi()
        .await
        .expect("open a request stream");
    send.write_all(&authenticated_connect_headers_frame(
        DENIED_TARGET,
        &basic_credentials(USER.0, USER.1),
    ))
    .await
    .expect("send an authenticated CONNECT request");
    let (frame_type, payload) = read_frame(&mut recv).await;
    assert_eq!(frame_type, FRAME_HEADERS);
    assert_eq!(
        status_of(&payload),
        "403",
        "the credentials must be accepted, which is what lifts the D76 bound"
    );

    // Well past the bound the first half of this test measured.
    stays_open(&authenticated, Duration::from_secs(4)).await;
    assert!(
        authenticated.close_reason().is_none(),
        "an authenticated connection whose SETTINGS never arrived is not closed for it"
    );
}

// ---------------------------------------------------------------------------
// r: goodbyes
// ---------------------------------------------------------------------------

/// A client's GOAWAY is a statement about what it will send, not a request to
/// hang up, and this server treats it as one.
///
/// The second half is the rule that does bite: an identifier that grows is
/// H3_ID_ERROR, because it would be taking back a promise about which requests
/// the peer has already abandoned.
#[tokio::test]
async fn a_goaway_from_the_peer_does_not_end_the_connection() {
    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    let mut control = settings_frame();
    control.extend_from_slice(&varint_frame(FRAME_GOAWAY, 8));
    // Repeating it with an identifier that has not grown is legal and says the
    // peer has abandoned more, not fewer, of its own requests.
    control.extend_from_slice(&varint_frame(FRAME_GOAWAY, 4));
    let mut stream = open_uni_stream(&connection, STREAM_CONTROL, &control).await;

    still_serving(&connection).await;
    stays_open(&connection, Duration::from_millis(300)).await;

    stream
        .write_all(&varint_frame(FRAME_GOAWAY, 12))
        .await
        .expect("send a GOAWAY that grows");
    let (closed_with, reason) = application_close(&connection, TIMEOUT).await;
    assert_eq!(
        closed_with, H3_ID_ERROR,
        "a GOAWAY identifier that grows is an ID error; the reason was {reason:?}"
    );
}

/// A peer that closes the moment its QUIC handshake is done -- never a stream,
/// never a byte of HTTP/3 -- must not take its connection slot with it.
///
/// The slot is taken by the accept loop before either handshake, and the
/// connection task is what gives it back, so the case worth pinning is the one
/// where that task ends without ever having served anything.
/// `max_connections = 1` is what makes the answer visible from outside.
#[tokio::test]
async fn a_peer_that_closes_before_it_says_anything_frees_its_slot() {
    let server = TestServer::start_with("[limits]\nmax_connections = 1\n").await;

    let (endpoint, connection) = connect_quic(&server).await;
    connection.close(0u32.into(), b"nothing further");
    // Delivers the CONNECTION_CLOSE rather than leaving it to a timeout, so what
    // is measured below is the server reaping the task.
    endpoint.wait_idle().await;
    drop(endpoint);

    // Retried because the reap happens a moment after the peer goes away, and
    // driven through `finish_connect` rather than a client that asserts: a
    // refusal here is a result to retry on, not a failure.
    for attempt in 0..40 {
        let admitted = client_endpoint(&server.ca, &["h3"]);
        match finish_connect(&admitted, server.addr).await {
            Ok(connection) => {
                still_serving(&connection).await;
                return;
            }
            Err(error) => {
                assert!(attempt < 39, "the slot was never returned: {error}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The shipped numbers
// ---------------------------------------------------------------------------
//
// Everything above tightens `max_idle_timeout` so a deadline can be waited out
// in a test run. These three are the same rows on the configuration production
// actually ships -- 60s idle, 20s keep-alive -- so an operator can prove the real
// numbers once. They take about two minutes each and are `#[ignore]`d for it:
//
//     cargo test --test it_hostile -- --ignored

/// The shipped bound on a silent, unauthenticated peer: two 60s idle timeouts.
///
/// Both edges are asserted. That it fires at all is what row (b) is about; that
/// it does not fire *early* is what keeps a client which merely took its time
/// over the first request from being hung up on.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "shipped config: waits out 2 x 60s"]
async fn the_shipped_bound_closes_a_silent_peer() {
    let server = TestServer::start_with("").await;
    let (_endpoint, connection) = silent_peer(&server).await;

    let started = Instant::now();
    assert_closed_with(&connection, H3_NO_ERROR, Duration::from_secs(150)).await;

    let elapsed = started.elapsed();
    assert!(
        elapsed > Duration::from_secs(100) && elapsed < Duration::from_secs(140),
        "the shipped bound is two 60s idle timeouts, and this took {elapsed:?}"
    );
}

/// The shipped bound is absolute: streams opened while it runs do not move it.
///
/// Half an idle timeout apart, which is well inside the window a rearmed timer
/// would keep resetting. The connection still goes at two idle timeouts from the
/// handshake (review C1').
#[tokio::test(flavor = "multi_thread")]
#[ignore = "shipped config: waits out 2 x 60s"]
async fn the_shipped_bound_is_not_extended_by_new_streams() {
    let server = TestServer::start_with("").await;
    let (_endpoint, connection) = silent_peer(&server).await;

    let poking = tokio::spawn({
        let connection = connection.clone();
        async move {
            // Held open on purpose: a finished stream is a request that ended,
            // and what is under test is one that merely started.
            let mut open = Vec::new();
            while let Ok((mut send, recv)) = connection.open_bi().await {
                if send.write_all(&[0x01]).await.is_err() {
                    break;
                }
                open.push((send, recv));
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    });

    let started = Instant::now();
    assert_closed_with(&connection, H3_NO_ERROR, Duration::from_secs(150)).await;
    poking.abort();

    let elapsed = started.elapsed();
    assert!(
        elapsed > Duration::from_secs(100) && elapsed < Duration::from_secs(140),
        "opening streams must not extend the bound, and this took {elapsed:?}"
    );
}

/// The shipped deadline on a refusal the peer will not read: one 60s idle
/// timeout, then the request stream is reset.
///
/// No `[auth]` section, so the first request authenticates and the connection
/// bound is out of the way: what is measured is the write deadline alone.
///
/// Not a byte is read, and the reset is watched for with `received_reset`
/// rather than by trying to read the answer: reading is what would grow the
/// window and let the answer through, which is the whole condition being
/// reproduced. Both edges are asserted -- a deadline that fired at once would
/// cut off a client that was merely slow, and one that never fired is the
/// finding this row exists for.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "shipped config: waits out 60s"]
async fn the_shipped_write_deadline_ends_an_unread_refusal() {
    let server = TestServer::start_with("").await;
    let endpoint = client_endpoint_with_transport(&server.ca, &["h3"], windowless_transport());
    let connection = finish_connect(&endpoint, server.addr)
        .await
        .expect("handshake");

    let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
    let started = Instant::now();
    send.write_all(&connect_headers_frame(DENIED_TARGET))
        .await
        .expect("send a request that will be refused");

    let reset = tokio::time::timeout(Duration::from_secs(120), recv.received_reset())
        .await
        .expect("the server must not wait for a window that is not coming")
        .expect("the request stream must be reset, not broken");
    assert_eq!(
        reset.map(quinn::VarInt::into_inner),
        Some(u64::from(H3_REQUEST_CANCELLED)),
        "an abandoned answer is a cancelled request"
    );

    let elapsed = started.elapsed();
    assert!(
        elapsed > Duration::from_secs(45) && elapsed < Duration::from_secs(90),
        "the shipped write deadline is one 60s idle timeout, and this took {elapsed:?}"
    );
    assert!(
        connection.close_reason().is_none(),
        "one abandoned answer must not cost the connection"
    );
}
