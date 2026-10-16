//! The QUIC transport parameters, the stream allowance a connection is granted
//! and the gate that records its authentication.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use quinn::{IdleTimeout, VarInt};

use crate::config::CongestionControl;

#[cfg(doc)]
use super::reload::server_config;

/// The QUIC transport parameters, from `[limits]` plus the memory bounds.
///
/// Split out from [`server_config`] so it can be asserted on without a
/// certificate: these are the numbers that decide both what a legitimate client
/// gets and what an attacker can make this process hold.
pub(super) fn transport_config(limits: &crate::config::Limits) -> Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();

    // Deliberately *not* `limits.max_streams_bidi`: that is what an
    // authenticated connection gets, and it is granted in one step by
    // [`admit_configured_streams`] the first time a request on the connection
    // passes the credentials check. What goes into the transport parameters is
    // the small allowance a peer that has proved nothing starts on; see
    // [`INITIAL_BIDI_STREAMS`].
    transport.max_concurrent_bidi_streams(VarInt::from_u32(initial_bidi_streams(limits)));

    // Stated rather than inherited: HTTP/3 needs three of these and quinn's
    // default allows a hundred; see [`MAX_PEER_UNI_STREAMS`].
    transport.max_concurrent_uni_streams(VarInt::from_u32(MAX_PEER_UNI_STREAMS));

    // The bound on what an unauthenticated peer can make this process hold,
    // where quinn's default is no aggregate bound at all; the arithmetic is in
    // [`CONNECTION_RECEIVE_WINDOW`].
    transport.receive_window(CONNECTION_RECEIVE_WINDOW);

    // A deliberate raise above quinn's own default, sized against the production
    // path's bandwidth-delay product; the case for the number, and why it is not
    // a memory decision, is in [`STREAM_RECEIVE_WINDOW`].
    transport.stream_receive_window(STREAM_RECEIVE_WINDOW);

    // Exactly what quinn already defaults to, set here rather than inherited so
    // the arithmetic quoted against it cannot go stale; see [`SEND_WINDOW`].
    transport.send_window(SEND_WINDOW);

    // The other two buffers an unauthenticated peer can fill, pinned at quinn's
    // own values for the same reason as the window above them; see
    // [`DATAGRAM_RECEIVE_BUFFER`] and [`CRYPTO_BUFFER_SIZE`].
    transport.datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER));
    transport.crypto_buffer_size(CRYPTO_BUFFER_SIZE);

    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(limits.max_idle_timeout())
            .context("limits.max_idle_timeout is out of range for QUIC")?,
    ));
    // `None` when the operator set 0, which switches keep-alives off entirely.
    transport.keep_alive_interval(limits.keep_alive_interval());

    // Seeds the loss-recovery timers until the first RTT sample arrives. At
    // quinn's 333 ms default a handshake packet lost on the way waits about a
    // second to be resent; an operator who has read `rtt_ms` off the connection
    // logs can cut that to the path's scale instead.
    transport.initial_rtt(limits.initial_rtt());

    // quinn clamps this up to 1200 silently; `Config::validate` rejects anything
    // below instead, so a typo is reported rather than quietly corrected.
    transport.initial_mtu(limits.initial_mtu);
    if limits.mtu_discovery {
        // Everything except the search ceiling stays at quinn's defaults. A
        // size is only ever adopted by probing it, and a lost probe is not a
        // congestion signal. A path that delivers single probes at a size it
        // cannot carry under load is the exception, and it is why the default
        // ceiling sits below quinn's (`DEFAULT_MTU_UPPER_BOUND`, D81).
        // `Config::validate` already rejected a written ceiling above the 1472
        // bytes IPv4 leaves of an Ethernet frame; the accessor resolves an
        // absent one.
        let mut mtud = quinn::MtuDiscoveryConfig::default();
        mtud.upper_bound(limits.mtu_upper_bound());
        transport.mtu_discovery_config(Some(mtud));
    } else {
        // Stops the upward search, so packets start at `initial_mtu` and are
        // never probed larger: spec §5.4's conservative setting for a path that
        // black-holes large packets, where a stable small MTU beats an
        // optimistic large one. Not a hard pin — quinn's black-hole detector
        // keeps running with discovery off, and if it fires the packet size
        // drops to the 1200-byte floor for the rest of the connection, since
        // nothing is left to probe it back up.
        transport.mtu_discovery_config(None);
    }

    // QUIC datagram support stays at quinn's default (enabled), which is
    // what makes `max_datagram_frame_size` appear in our transport
    // parameters. What a session does with the datagrams once they are
    // received is CONNECT-UDP's own bound, `INBOUND_QUEUE_DEPTH`; what the
    // transport holds before that is [`DATAGRAM_RECEIVE_BUFFER`] above.

    transport.congestion_controller_factory(congestion_factory(limits.congestion_control));

    Ok(transport)
}

/// The bidirectional stream allowance a connection is accepted with.
///
/// A `min` rather than a flat constant, so that an operator who configures fewer
/// than [`INITIAL_BIDI_STREAMS`] gets what they configured and not more —
/// before authentication as well as after it. Nothing here can raise the
/// configured value; the clamp only ever lowers it.
fn initial_bidi_streams(limits: &crate::config::Limits) -> u32 {
    limits.max_streams_bidi.min(INITIAL_BIDI_STREAMS)
}

/// Grants a connection the configured bidirectional stream allowance.
///
/// The other half of [`INITIAL_BIDI_STREAMS`], called once per connection by
/// [`crate::tunnel::Context::mark_authenticated`] — the one place both ways of
/// getting past the door meet. It lives here rather than there so that the two
/// values a connection's stream allowance can take are stated in the same file
/// as each other, next to the reasoning that pairs them.
///
/// quinn spells the two directions differently — `max_concurrent_bidi_streams`
/// on `TransportConfig`, `set_max_concurrent_bi_streams` on `Connection` — and
/// they are the same parameter. Raising it allocates the new stream slots and
/// queues a MAX_STREAMS frame, which reaches the peer on the next packet this
/// connection sends: in practice the one carrying the response to the request
/// that just authenticated.
pub(crate) fn admit_configured_streams(quic: &quinn::Connection, max_streams_bidi: u32) {
    quic.set_max_concurrent_bi_streams(VarInt::from_u32(max_streams_bidi));
}

/// Whether a connection has got past the door, shared by everything that asks.
///
/// One flag with three readers in three modules — the accept loop's eviction
/// candidacy (D80), the bound on how long a connection may say nothing (D76),
/// and the stream allowance above (D98) — and one of those is not a read at all
/// but a transition: the raise happens on the false-to-true edge and must
/// happen exactly once, however many requests authenticate at the same moment.
///
/// A newtype rather than the `Arc<AtomicBool>` it wraps, because that invariant
/// cannot survive as a convention across three modules: a plain `store(true)`
/// written anywhere in them compiles and silently skips the raise. There is no
/// way to open this gate without being told whether you were the one who opened
/// it.
#[derive(Clone, Debug, Default)]
pub struct AuthGate(Arc<AtomicBool>);

impl AuthGate {
    /// A gate nothing has passed yet.
    pub fn closed() -> Self {
        Self::default()
    }

    /// Records that a request got past the door; `true` if it was the first.
    ///
    /// `Relaxed` for the same reason the reads are: what is ordered against is
    /// the flag itself, and a `swap` names exactly one caller the first however
    /// many race.
    pub fn mark(&self) -> bool {
        !self.0.swap(true, Ordering::Relaxed)
    }

    /// Whether anything has.
    pub fn is_open(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// The quinn congestion controller factory named by `[limits] congestion_control`.
///
/// `TransportConfig` has no getter for the factory and its `Debug` skips it, so
/// the mapping is invisible to the assertions on [`transport_config`]: a
/// `Bbr => CubicConfig` slip passes every one of them. The failure it would
/// cause is not subtle in production (the download direction of a long
/// international path collapsed to near-zero on 2026-08-13, and it took a day to
/// localise) but it is silent there, so the unit tests open a connection with
/// the transport parameters and downcast the controller it runs.
///
/// BBR by default. A loss-based controller (CUBIC, NewReno) reads the
/// non-congestive packet loss of a long international path as congestion and
/// collapses the window — the download direction stalls to near-zero while a
/// co-located Shadowsocks server on the same box sails through, because the Linux
/// kernel runs BBR for TCP. BBR models bandwidth and RTT instead, holding
/// throughput on exactly these paths. See `config::CongestionControl` for why this
/// is the default and stays configurable.
///
/// Since 1.2.0 `bbr` builds the capped controller of [`crate::congestion`]
/// (D108), and `bbr-uncapped` builds quinn's BBR as it ships.
fn congestion_factory(
    cc: CongestionControl,
) -> Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> {
    match cc {
        CongestionControl::Bbr => Arc::new(crate::congestion::BbrCappedConfig::default()),
        CongestionControl::BbrUncapped => Arc::new(quinn::congestion::BbrConfig::default()),
        CongestionControl::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
        CongestionControl::NewReno => Arc::new(quinn::congestion::NewRenoConfig::default()),
    }
}

/// Aggregate flow-control window for one connection, in bytes.
///
/// The bound on what an *unauthenticated* peer can make this process hold.
/// quinn's own default is `VarInt::MAX` — no aggregate limit at all — and with
/// this server's raised stream limit that is 1024 x the 2 MiB
/// [`STREAM_RECEIVE_WINDOW`], so a single connection could pin 2 GiB of receive
/// buffer before we ever see a request to authenticate: open the streams, fill
/// each window, stop. On a 1 GB VPS one connection is enough to end the process.
///
/// The cap only constrains data that has arrived and not yet been read, and both
/// tunnel pumps read continuously, so it binds exactly when the target is slower
/// than the client — which is the case that should be bounded.
///
/// 16 MiB against the 2 MiB per-stream window: eight simultaneously saturated
/// tunnels still get their full stream windows, while the worst case stops being
/// a function of `max_streams_bidi`.
pub const CONNECTION_RECEIVE_WINDOW: VarInt = VarInt::from_u32(16 * 1024 * 1024);

/// Per-stream flow-control window, in bytes.
///
/// A deliberate raise above quinn's own default of 1,250,000, not inherited from
/// it and not a pin at it. No RFC constrains the value — RFC 9000 §4.2 leaves the
/// amount of credit to implementations outright, and §4.3 only observes the
/// consequence of getting it wrong: an endpoint that "cannot ensure that its peer
/// always has available flow control credit that is greater than the peer's
/// bandwidth-delay product" finds "its receive throughput will be limited by flow
/// control". That is advice, not a requirement, and it is the whole of the case.
/// The production path's BDP — a 100 Mbps client uplink over a 95 ms RTT — is
/// about 1.19 MB, so quinn's default sat at roughly 1.05x it: exactly one BDP,
/// with no margin for a window update still in flight. 2 MiB is about 1.75x.
/// Measured corroboration: the peer we interoperate with sizes its own side far
/// higher still, Surge's ClientHello advertising
/// `initial_max_stream_data_bidi_local` = 12 MiB per stream.
///
/// Not a memory decision. [`CONNECTION_RECEIVE_WINDOW`] is the real bound — the
/// invariant is that (the sum of the highest offsets received) minus (the bytes
/// read) stays within it — so a larger per-stream window cannot raise the
/// per-connection worst case, which is unchanged at 16 MiB. What this value
/// actually decides is how few simultaneously saturated tunnels it takes to spend
/// the whole connection's credit — 16 MiB / 2 MiB = 8 — which is a fairness
/// property rather than a memory one, and 8:1 is still far more conservative than
/// the 1.33:1 the peer itself runs (16 MiB of `initial_max_data` against 12 MiB
/// per stream). The per-tunnel ceiling in the download direction is whatever the
/// client advertises to us and is not settable here.
pub const STREAM_RECEIVE_WINDOW: VarInt = VarInt::from_u32(2 * 1024 * 1024);

/// quinn's own default per-stream receive window, in bytes.
///
/// Not a value this server uses — [`STREAM_RECEIVE_WINDOW`] is what reaches the
/// wire — but the number the reasoning there is written against, so it is stated
/// once and checked by `quinn_has_not_moved_the_defaults_we_quote` rather than
/// left as a claim in prose that a dependency bump could quietly falsify.
#[cfg(test)]
const QUINN_DEFAULT_STREAM_RECEIVE_WINDOW: u64 = 1_250_000;

/// Aggregate outbound stream data retained per connection, in bytes.
///
/// The mirror image of [`CONNECTION_RECEIVE_WINDOW`], and the only bound on what
/// this process buffers for a client that has stopped reading. quinn-proto
/// 0.11.x counts bytes retained from application writes rather than bytes still
/// unacknowledged: acknowledged data goes on counting until the storage holding
/// it is released, which is what makes this a bound on memory rather than only on
/// data in flight. What it counts is bytes accepted from the buffers this process
/// hands over, so a slice of a larger allocation can retain more than the limit
/// accounts for. That is the amplification the 64 KiB relay block in
/// `tunnel/tcp.rs` is shaped to hold at 1.33x; see D47's 2026-08-23 addendum.
/// 10 MB over the ~90 ms path RTT is about 889 Mbps against a measured peak of
/// 177 Mbps, so it is nowhere near a throughput constraint.
///
/// Set to exactly what quinn already defaults to, so it changes not a byte on the
/// wire today. It is pinned rather than inherited because upstream derives that
/// default from `STREAM_RWND`, a private constant inside quinn's
/// `TransportConfig::default` with no stability guarantee, while the arithmetic
/// above is quoted against it. Dependabot proposes cargo bumps weekly; a patch
/// release that moved that constant would leave the documented numbers quietly
/// false. Setting the value here makes them true by construction instead of by
/// inheritance.
///
/// Note the asymmetry it leaves: 16 MiB of inbound credit granted against a
/// 10 MB outbound cap, on a proxy whose traffic is mostly outbound. That is an
/// accepted decision, not an oversight — lifting the outbound cap to match would
/// add roughly 1.6 GiB of theoretical worst case across `max_connections` (256 by
/// default) in exchange for throughput we cannot measure a need for.
pub const SEND_WINDOW: u64 = 10_000_000;

// D47's invariants and its validation rules, as arithmetic. Those rules were
// written for the day these three might become configuration keys, and they are
// the relationships between the values whether or not that day comes: the
// stream window is at least 64 KiB, at most an eighth of the connection window,
// and below 4 MiB, where the fairness crossover falls to four saturated
// tunnels and which that ADR says is not to be tried; the send window is never
// below the stream window it feeds.
const _: () = assert!(STREAM_RECEIVE_WINDOW.into_inner() >= 64 * 1024);
const _: () =
    assert!(STREAM_RECEIVE_WINDOW.into_inner() <= CONNECTION_RECEIVE_WINDOW.into_inner() / 8);
const _: () = assert!(STREAM_RECEIVE_WINDOW.into_inner() < 4 * 1024 * 1024);
const _: () = assert!(SEND_WINDOW >= STREAM_RECEIVE_WINDOW.into_inner());

/// Inbound QUIC DATAGRAM bytes the transport buffers per connection.
///
/// Exactly what quinn already defaults to, and stated here for the reason D47
/// gives for [`SEND_WINDOW`]: upstream derives it from `STREAM_RWND`, a private
/// constant inside `TransportConfig::default` with no stability promise, and
/// Dependabot proposes cargo bumps weekly. A patch release that moved that
/// constant would move this buffer with it and change what an unauthenticated
/// peer can make this process hold, silently and without a line of this tree
/// changing.
///
/// It is 1.25 MB per connection, 320 MB across the default `max_connections`,
/// and every byte of it is reachable before a credential has been seen: quinn
/// buffers whatever the peer sends, `serve_peer` drains the queue, and before
/// authentication every datagram in it is routed to the `Unroutable` drop
/// because the session table is empty. Small next to the 16 MiB of
/// [`CONNECTION_RECEIVE_WINDOW`] beside it, which is why the value is kept
/// rather than lowered; what was missing was the pin, not a different number.
///
/// Not `None`, which would disable inbound datagrams altogether and with them
/// CONNECT-UDP, and not a `[limits]` key, for D47's reason: three coupled
/// numbers that operations can diagnose neither failure mode of.
const DATAGRAM_RECEIVE_BUFFER: usize = 1_250_000;

/// Out-of-order CRYPTO frame bytes the transport buffers per connection.
///
/// Pinned at quinn's own 16 KiB, on the same argument as
/// [`DATAGRAM_RECEIVE_BUFFER`]: it is held by a peer that has authenticated
/// nothing, so it belongs in the inventory of what an unauthenticated
/// connection costs, and an inventory that reads a dependency's private default
/// is not an inventory. 16 KiB is ample for the one client flight this server
/// ever reassembles, a ClientHello, which is 1.2 KB and up with a
/// post-quantum key share.
const CRYPTO_BUFFER_SIZE: usize = 16 * 1024;

/// Unidirectional streams a peer may have open on one connection at a time.
///
/// HTTP/3 gives a client exactly three of them — the control stream and the
/// QPACK encoder/decoder pair (RFC 9114 §6.2, RFC 9204 §4.2) — and Surge opens
/// those three and nothing else. Everything past them is either an unknown type,
/// which RFC 9114 §6.2 has this server abort rather than reject, or a second
/// stream of a kind that may only be opened once, which is a connection error.
/// So no client that behaves needs a fourth, and a peer that opens them anyway
/// costs a task each while it says nothing.
///
/// Sixteen rather than three: this is a transport parameter, so exceeding it is
/// a QUIC-level failure with no application-level explanation attached, and the
/// margin means an ordinary client can only meet it by doing something the
/// HTTP/3 layer would refuse anyway. The number this replaces is quinn's own
/// default of 100, which this server had never taken a position on — the bidi
/// limit beside it has been a configuration key all along (review L3).
pub const MAX_PEER_UNI_STREAMS: u32 = 16;

/// Bidirectional streams a peer may have open before it has authenticated.
///
/// `[limits] max_streams_bidi` is what an authenticated connection is worth —
/// one stream per tunnel, 1024 of them by default — and it used to be what the
/// transport parameters advertised at the handshake, which handed it to every
/// peer that could complete one. So a client that had proved nothing could open
/// 1024 request streams at once and draw a 407 on each: 1024 parked request
/// tasks and 1024 refusals written for a peer with no credentials. Neither
/// bound that already applied there is a bound on *concurrency* — D77's 1 MiB
/// HEADERS budget bounds bytes buffered, D76's absolute deadline bounds time —
/// so nothing measured the one quantity that was free.
///
/// It is also work this process pays for at the wrong moment. quinn reserves a
/// stream slot for every unit of the allowance when the connection is
/// *created*, not when a stream is opened (see `docs/configuration.md`), so the
/// configured value was a per-handshake cost that a peer never had to
/// authenticate to impose. Clamping moves it to the first request that gets
/// past the door.
///
/// Sixteen, the same number as [`MAX_PEER_UNI_STREAMS`] and for the same kind
/// of reason: margin over what the protocol needs rather than the minimum,
/// because running into a transport parameter is a QUIC-level stall with no
/// application-level explanation attached. It happens to be exactly D77's
/// budget as well — sixteen field sections at the 64 KiB per-frame cap is the
/// 1 MiB a connection may buffer — so what an unauthenticated peer can hold in
/// HEADERS is now bounded twice over by the same number.
///
/// # Why it cannot stall a client that bursts
///
/// A client may fire several CONNECTs the moment the handshake completes,
/// before the first 200 comes back, and more than sixteen of them would find
/// the seventeenth blocked rather than refused — STREAMS_BLOCKED, which is
/// backpressure and not an error. What unblocks it is the first of the sixteen
/// to authenticate, and that is decided before any name is resolved and any
/// socket is opened (`conn::handle_request`), so the raise happens in the same
/// task that read the first HEADERS and its MAX_STREAMS rides the packet
/// carrying that request's response. The seventeenth tunnel therefore waits the
/// round trip the client was already waiting for its first answer, once per
/// connection, and only on a connection that opens more than sixteen tunnels
/// before any of them is answered. Below that this is never reached at all.
///
/// Closing streams returns credit before authentication too, which is what
/// keeps a well-behaved unauthenticated peer moving at all — RFC 9000 §4.6
/// leaves that to the receiver ("this document leaves implementations to decide
/// when and how many streams should be advertised to a peer via MAX_STREAMS.
/// Implementations might choose to increase limits as streams are closed"), and
/// quinn announces one only once an eighth of the window has come back, so three
/// closes rather than one. That is why the raise is what a burst waits on and
/// not the churn.
///
/// Which is also why the raise is not conditioned on hearing from the peer. The
/// same section: "An endpoint MUST NOT wait to receive this signal before
/// advertising additional credit, since doing so will mean that the peer will be
/// blocked for at least an entire round trip, and potentially indefinitely if
/// the peer chooses not to send STREAMS_BLOCKED frames."
pub const INITIAL_BIDI_STREAMS: u32 = 16;

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    use crate::quic::tests::loopback_pair;

    /// Renders the built transport parameters for inspection.
    ///
    /// `TransportConfig` has no getters, but its `Debug` prints every field, and
    /// asserting on that is enough to pin the values that matter.
    fn transport_debug(limits: &crate::config::Limits) -> String {
        format!("{:?}", transport_config(limits).expect("valid limits"))
    }

    /// The bound that stops one unauthenticated connection from exhausting the
    /// host's memory (audit 2026-08, finding 1.1a).
    ///
    /// quinn's default is `receive_window: VarInt::MAX` — no aggregate limit —
    /// which with 1024 streams of 2 MiB each is 2 GiB per connection, reachable
    /// before any request is authenticated.
    #[test]
    fn the_connection_receive_window_is_bounded() {
        let rendered = transport_debug(&crate::config::Limits::default());

        // Anchored on the separator: `stream_receive_window` ends in the same
        // characters, so the bare substring could pass on the wrong field should
        // the two ever hold the same value.
        assert!(
            rendered.contains(", receive_window: 16777216"),
            "the aggregate receive window must be capped at 16 MiB: {rendered}"
        );
        assert!(
            !rendered.contains(&format!("receive_window: {}", u64::from(VarInt::MAX))),
            "the unbounded quinn default must not survive: {rendered}"
        );
    }

    /// Both windows really reach the transport parameters, so an edit here cannot
    /// silently drop them.
    #[test]
    fn the_stream_and_send_windows_are_set() {
        let rendered = transport_debug(&crate::config::Limits::default());

        assert!(
            rendered.contains("stream_receive_window: 2097152"),
            "the per-stream receive window must stay at 2 MiB, the value the BDP and \
             fairness arithmetic in this module is quoted against: {rendered}"
        );
        assert!(
            rendered.contains("send_window: 10000000"),
            "the outbound send window must stay at 10 MB, the only bound on what we \
             buffer for a client that stops reading: {rendered}"
        );
    }

    /// The two buffers that used to be inherited really reach the wire.
    ///
    /// Both are held by a peer that has authenticated nothing, so what they are
    /// set to is part of what an unauthenticated connection costs; see
    /// [`DATAGRAM_RECEIVE_BUFFER`] and [`CRYPTO_BUFFER_SIZE`].
    #[test]
    fn the_datagram_and_crypto_buffers_are_stated_rather_than_inherited() {
        let rendered = transport_debug(&crate::config::Limits::default());

        assert!(
            rendered.contains(&format!(
                "datagram_receive_buffer_size: Some({DATAGRAM_RECEIVE_BUFFER})"
            )),
            "the inbound datagram buffer must be the pinned 1.25 MB: {rendered}"
        );
        assert!(
            rendered.contains(&format!("crypto_buffer_size: {CRYPTO_BUFFER_SIZE}")),
            "the out-of-order CRYPTO buffer must be the pinned 16 KiB: {rendered}"
        );
    }

    /// quinn's own defaults still agree with what this module says about them.
    ///
    /// The drift alarm covers two different claims, neither of which can change
    /// behaviour any more — both values reaching the wire are set explicitly —
    /// but either of which a cargo bump could turn into a false comment, and
    /// Dependabot proposes those weekly. [`SEND_WINDOW`] is genuinely pinned at
    /// quinn's default, so a moved default would invalidate the pin's own
    /// justification. [`STREAM_RECEIVE_WINDOW`] is no longer a pin — it is a
    /// deliberate raise — so quinn's value is not asserted against *ours*; what is
    /// asserted is [`QUINN_DEFAULT_STREAM_RECEIVE_WINDOW`], the number the BDP
    /// arithmetic there compares 2 MiB to.
    #[test]
    fn quinn_has_not_moved_the_defaults_we_quote() {
        let rendered = format!("{:?}", quinn::TransportConfig::default());

        assert!(
            rendered.contains(&format!("send_window: {SEND_WINDOW}")),
            "a quinn bump changed the default send window: our pin is unaffected, but \
             the comments in this module that call it quinn's default need \
             re-checking: {rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "stream_receive_window: {QUINN_DEFAULT_STREAM_RECEIVE_WINDOW}"
            )),
            "a quinn bump changed the default per-stream receive window: we no longer \
             use it, but STREAM_RECEIVE_WINDOW is justified as a raise above it, so \
             that arithmetic needs re-checking: {rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "datagram_receive_buffer_size: Some({DATAGRAM_RECEIVE_BUFFER})"
            )),
            "a quinn bump changed the default inbound datagram buffer: our pin is \
             unaffected, but it was chosen as a pin at that default, so the choice \
             needs re-making rather than inheriting silently: {rendered}"
        );
        assert!(
            rendered.contains(&format!("crypto_buffer_size: {CRYPTO_BUFFER_SIZE}")),
            "a quinn bump changed the default CRYPTO reassembly buffer: as above, \
             our pin holds and the reason for the number needs re-checking: {rendered}"
        );
    }

    /// What the handshake advertises is the clamp, not `max_streams_bidi`.
    ///
    /// The shipped default is 1024, and finding it here would mean every peer
    /// that can complete a handshake is handed a thousand request streams
    /// before it has proved anything; see [`INITIAL_BIDI_STREAMS`]. Asserted on
    /// the default limits rather than on a contrived pair, because the default
    /// is the configuration that ships.
    #[test]
    fn the_handshake_advertises_the_initial_stream_allowance() {
        let limits = crate::config::Limits::default();
        assert!(
            limits.max_streams_bidi > INITIAL_BIDI_STREAMS,
            "the default must be above the clamp for this to be measuring anything: {}",
            limits.max_streams_bidi
        );

        let rendered = transport_debug(&limits);
        assert!(
            rendered.contains(&format!(
                "max_concurrent_bidi_streams: {INITIAL_BIDI_STREAMS}"
            )),
            "an unauthenticated peer must be advertised the clamp: {rendered}"
        );
    }

    /// The clamp only ever lowers: an operator who wants fewer gets fewer.
    ///
    /// `min` rather than a flat constant, so a configuration below the clamp is
    /// honoured from the handshake onwards rather than being quietly raised to
    /// sixteen for as long as the connection went unauthenticated.
    #[test]
    fn a_configured_allowance_below_the_clamp_is_not_raised_to_it() {
        for configured in [1, 7, INITIAL_BIDI_STREAMS] {
            let limits = crate::config::Limits {
                max_streams_bidi: configured,
                ..Default::default()
            };
            assert_eq!(
                initial_bidi_streams(&limits),
                configured,
                "a configured allowance of {configured} must reach the wire as itself"
            );
        }

        assert_eq!(
            initial_bidi_streams(&crate::config::Limits {
                max_streams_bidi: INITIAL_BIDI_STREAMS + 1,
                ..Default::default()
            }),
            INITIAL_BIDI_STREAMS,
            "and one above it must not"
        );
    }

    /// The configured limits really reach the transport parameters.
    ///
    /// `max_streams_bidi` is the one that does not reach them as itself: 7 is
    /// below [`INITIAL_BIDI_STREAMS`], so it is what an unauthenticated peer is
    /// advertised, and the clamp's own two tests are above.
    #[test]
    fn configured_limits_reach_the_transport_config() {
        let limits = crate::config::Limits {
            max_streams_bidi: 7,
            initial_mtu: 1350,
            mtu_upper_bound: Some(1464),
            initial_rtt_ms: 150,
            ..Default::default()
        };

        let rendered = transport_debug(&limits);
        assert!(
            rendered.contains("max_concurrent_bidi_streams: 7"),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "max_concurrent_uni_streams: {MAX_PEER_UNI_STREAMS}"
            )),
            "the peer's unidirectional stream limit is ours to state, not quinn's \
             to default (review L3): {rendered}"
        );
        assert!(
            rendered.contains("1350"),
            "the initial MTU must apply: {rendered}"
        );
        assert!(
            rendered.contains("upper_bound: 1464"),
            "the discovery ceiling must apply: {rendered}"
        );
        assert!(
            rendered.contains("initial_rtt: 150ms"),
            "the initial RTT must apply: {rendered}"
        );
    }

    proptest::proptest! {
        /// Property 2: whatever validation accepts, this can be built from (D86).
        ///
        /// The other half of the invariant `crate::config`'s properties state:
        /// a value that passes validation must not be able to fail — or panic —
        /// on its way into a `quinn::TransportConfig`, which is where every
        /// `[limits]` key that reaches the transport ends up. The generator
        /// clamps into the accepted space rather than filtering, so it stacks
        /// cases on the boundaries; that its output really is accepted is
        /// asserted here rather than assumed, so the two statements of the
        /// ranges cannot drift apart silently. Run in a debug build, where
        /// arithmetic overflow is a panic rather than a wrap.
        #[test]
        fn every_accepted_limits_builds_a_transport_config(
            limits in crate::config::tests::valid_limits()
        ) {
            let config = crate::config::tests::config_with(limits.clone());
            prop_assert!(
                crate::config::tests::valid_apart_from_certs(&config),
                "the generator produced limits validation rejects: {:?}",
                config.validate().err()
            );

            prop_assert!(transport_config(&limits).is_ok());
        }
    }

    /// The controller a connection accepted with `transport_config(limits)`
    /// runs, named by its concrete type with the `congestion_control` value
    /// that selects it.
    ///
    /// `TransportConfig` keeps the factory in a private field that its `Debug`
    /// does not print, so [`transport_debug`], which pins every other transport
    /// parameter, cannot see it. The controller is read back from the server
    /// side of a real connection instead, through `Connection::congestion_state`,
    /// and `Controller::into_any` exists for this downcast.
    async fn controller_type_of(limits: &crate::config::Limits) -> &'static str {
        let transport = transport_config(limits).expect("the limits build a transport config");
        let (_client, server) = loopback_pair(transport).await;
        let any = server.congestion_state().into_any();

        if any.is::<crate::congestion::BbrCapped>() {
            "bbr"
        } else if any.is::<quinn::congestion::Bbr>() {
            "bbr-uncapped"
        } else if any.is::<quinn::congestion::Cubic>() {
            "cubic"
        } else if any.is::<quinn::congestion::NewReno>() {
            "newreno"
        } else {
            "unknown"
        }
    }

    /// Every `congestion_control` value selects the controller it names, on a
    /// connection accepted with the transport parameters `transport_config`
    /// builds.
    #[tokio::test]
    async fn each_congestion_control_value_selects_its_controller() {
        use crate::config::CongestionControl;

        for (value, expected) in [
            (CongestionControl::Bbr, "bbr"),
            (CongestionControl::BbrUncapped, "bbr-uncapped"),
            (CongestionControl::Cubic, "cubic"),
            (CongestionControl::NewReno, "newreno"),
        ] {
            let limits = crate::config::Limits {
                congestion_control: value,
                ..crate::config::Limits::default()
            };
            assert_eq!(controller_type_of(&limits).await, expected, "{value:?}");
        }
    }

    /// `bbr-uncapped` selects quinn's own BBR, the controller
    /// `quinn::congestion::BbrConfig` builds, with no cap around it (D108).
    /// It is the comparison against the default and the way back to quinn's
    /// controller without a rebuild.
    #[tokio::test]
    async fn bbr_uncapped_selects_quinns_own_bbr() {
        use serde::Deserialize as _;
        use serde::de::IntoDeserializer as _;

        let value =
            crate::config::CongestionControl::deserialize("bbr-uncapped".into_deserializer())
                .map_err(|e: serde::de::value::Error| e.to_string())
                .expect("bbr-uncapped is a congestion_control value");
        let limits = crate::config::Limits {
            congestion_control: value,
            ..crate::config::Limits::default()
        };

        assert_eq!(controller_type_of(&limits).await, "bbr-uncapped");
    }

    /// The default really is BBR, all the way to the controller a connection
    /// runs. Since 1.2.0 that is the capped controller (D108), the type
    /// [`controller_type_of`] names `bbr`.
    ///
    /// The one assertion in this module with a production incident behind it.
    /// quinn defaults to CUBIC, so losing this mapping (a mis-edited match arm,
    /// a default that stops being BBR, or `transport_config` no longer
    /// installing the factory) lands on a loss-based controller, and a
    /// loss-based controller collapses the download direction of the production
    /// path to near-zero while leaving upload, CPU and every log line looking
    /// normal. Nothing else in the suite can tell the two apart.
    #[tokio::test]
    async fn the_default_congestion_controller_is_bbr() {
        let limits = crate::config::Limits::default();

        assert_eq!(
            limits.congestion_control,
            crate::config::CongestionControl::Bbr,
            "the default must stay BBR"
        );
        assert_eq!(
            controller_type_of(&limits).await,
            "bbr",
            "the default limits must build the capped BBR controller, not quinn's CUBIC"
        );
    }
}
