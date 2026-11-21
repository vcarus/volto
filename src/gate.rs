//! The SNI gate: which handshakes are allowed to reach quinn at all.
//!
//! A UDP port that answers anything is a port a scan finds. quinn's endpoint is
//! conservative but not silent: a long-header packet naming a version it does
//! not speak draws a Version Negotiation packet, an Initial whose Destination
//! Connection ID is shorter than the eight bytes RFC 9000 §7.2 requires draws a
//! CONNECTION_CLOSE, and a short-header packet for no live connection can draw a
//! Stateless Reset. Each of those is a correct answer to a QUIC peer and an
//! answer to a scanner as well. The third is not this module's: the endpoint
//! is built with a connection ID generator that makes quinn drop such a packet
//! instead (`quic::cid`), with the gate on or off.
//!
//! This module puts a filter *under* quinn, at the socket, so that a datagram
//! quinn would answer never reaches it. It is off unless `[security]
//! expected_sni` names at least one host or `[server] ech_key` names an ECH
//! key: with neither, which is the shipped default, every datagram passes
//! through untouched. Without a key the gate keeps no state and judges each
//! datagram on its own, as the next four sections describe. A key adds the
//! hold of the section after them.
//!
//! # What passes
//!
//! With the gate open, a received datagram is judged by its first QUIC packet.
//! One packet is enough to judge the whole datagram because RFC 9000 §12.2 says
//! "Receivers MAY route based on the information in the first packet contained
//! in a UDP datagram" and, in the same paragraph, "Senders MUST NOT coalesce
//! QUIC packets with different connection IDs into a single UDP datagram":
//!
//! * **Short header**: passes. It belongs to a connection this endpoint may
//!   already hold, and the gate keeps no connection state to judge it with; see
//!   *Short headers* below.
//! * **Long header, version not 1**: refused, whatever the version is. What
//!   that removes depends on the version. quinn's default `EndpointConfig`,
//!   which [`crate::quic::Server::bind`] takes with only its connection ID
//!   generator replaced (`quic::cid`), supports seven:
//!   version 1 and the six draft numbers `0xff00001d` to `0xff000022`
//!   (quinn-proto 0.11.x `src/lib.rs`, `DEFAULT_SUPPORTED_VERSIONS`). For a
//!   version outside that list quinn would send a Version Negotiation packet,
//!   and refusing removes the reply. For one of the six drafts quinn would
//!   open a connection, and refusing removes the service. Nothing this server
//!   interoperates with is affected, because Surge speaks version 1.
//! * **Long header, not an Initial**: passes. quinn drops a Handshake or 0-RTT
//!   packet for an unknown connection without a word.
//! * **An Initial in a datagram below 1200 bytes**: passes, because RFC 9000
//!   §14.1 has the server discard it and quinn does exactly that, silently.
//! * **An Initial whose Destination Connection ID is shorter than eight
//!   bytes**: refused, on the header alone and whether or not the packet
//!   authenticates. Nothing legitimate is this shape (RFC 9000 §7.2, quoted at
//!   `MIN_CLIENT_CONNECTION_ID`), and quinn answers it with the
//!   CONNECTION_CLOSE named above before it reads a frame.
//! * **An Initial this server cannot open**: passes. Only a client's *first*
//!   Initial packets are keyed by their own Destination Connection ID: once the
//!   server has answered, the client addresses it by the connection ID the
//!   server chose (RFC 9000 §7.2) while the Initial keys stay the ones derived
//!   from the first packet (RFC 9001 §5.2), so the acknowledgements and later
//!   fragments of a handshake already admitted here cannot be opened without
//!   its state. They belong to a flight that was judged when it started; a
//!   forgery that is not one of them fails quinn's own decryption and is
//!   dropped there without a reply.
//! * **An Initial with no CRYPTO frame at offset 0**: passes. It is an
//!   acknowledgement or a later fragment of a handshake already in progress, and
//!   the flight it belongs to was judged when it started. Without a key the gate
//!   reads the first packet of a datagram only (D115), so a first packet of PING
//!   and PADDING with a whole ClientHello in an Initial coalesced behind it
//!   passes too, and its name is judged by the second gate.
//! * **An Initial whose ClientHello is cut short before its extensions**:
//!   passes. A ClientHello may span several Initial packets, and a gate that
//!   guessed here would refuse a legitimate client whose first flight is large;
//!   the ClientHello callback in [`crate::tls`] is the second gate that catches
//!   what this one lets through.
//! * **An Initial carrying a complete ClientHello**: refused unless its
//!   `server_name` extension (RFC 6066 §3) names a host in the configured list.
//!
//! # How a datagram is refused
//!
//! Not by removing it from the batch. A single `recvmmsg` buffer can hold a
//! whole GRO run of datagrams described by one stride, and cutting one out of
//! the middle would mean rewriting the run. Instead the refused datagram is left
//! in place with its Destination Connection ID *length* byte overwritten by a
//! value no connection ID may have (RFC 9000 §17.2 caps it at 20 bytes), which
//! is a header quinn's own decoder rejects before it acts on the version, the
//! type or anything else. The decoder reads the four version bytes first and
//! the connection IDs next, so the rejection needs only the first six bytes to
//! be there. It rejects it by returning, not by answering.
//!
//! The obvious alternative, clearing the fixed bit, does not work here: quinn
//! accepts either value for it unless `EndpointConfig::grease_quic_bit` is
//! turned off, and it defaults to on.
//!
//! # What is left uncovered
//!
//! An Initial the gate passes because it can read no name out of it still
//! reaches quinn, and quinn acknowledges it if anything in it is ack-eliciting:
//! a PING and nothing else, a ClientHello cut short before its extensions, a
//! lone CRYPTO frame at a non-zero offset. Each draws an acknowledgement with
//! no name anywhere in it. The second and the third are the fail-open branch
//! above, and refusing them is refusing the large first flight this module
//! deliberately lets through; the first could be refused on its own, and doing
//! so would leave the other two answering, so it would change nothing about
//! what somebody able to build an Initial packet can learn here. All three cost
//! that somebody a QUIC v1 Initial keyed the way RFC 9001 §5.2 says, which is a
//! probe aimed at this server rather than the scan of an address the gate is
//! for.
//!
//! A ClientHello that reaches libssl past this gate (cut short and completed in
//! the next datagram, or in an Initial coalesced behind a first packet without
//! one) and names a host off the list draws more than an acknowledgement: the
//! second gate refuses it with an `unrecognized_name(112)` alert in a
//! CONNECTION_CLOSE (D106).
//!
//! Nor is any of this traffic obfuscation. The gate hides that a *service* is
//! here from somebody who does not know the name to ask for; it does nothing
//! about what a connection looks like once one is open.
//!
//! # Short headers
//!
//! The gate passes every short-header packet. Telling a live connection's
//! packets from a stranger's needs the set of live connection IDs, which lives
//! inside quinn, and filtering on the four-tuple instead would break the
//! connection migration a mobile client behind a relay's NAT depends on.
//!
//! # The hold, with an ECH key
//!
//! The server never publishes its ECHConfigList; an operator hands it to each
//! client. So an ECH extension that opens under the key is a credential, and it
//! can be checked before the server sends a single packet (D115). It cannot be
//! checked from one Initial packet: the HPKE associated data is the whole outer
//! ClientHello (RFC 9849 §5.2, quoted at `EchKey::opens`), and a ClientHello
//! with a post-quantum key share does not fit one packet. So with a key
//! configured the gate keeps state.
//!
//! Every datagram is still judged by its first packet, and every rule of *What
//! passes* that is decided before the packet is opened stays as it is: a
//! version other than 1 and a Destination Connection ID under eight bytes are
//! refused, and a short header, a long header that is not an Initial, an
//! Initial in a datagram under 1200 bytes and an Initial that does not open
//! under its own connection ID's keys pass. An Initial that does open is the
//! first flight of a new handshake, and it is *held*: copied out of the
//! batch, under the key of its Destination Connection ID and source address,
//! together with the CRYPTO bytes its frames carry. The datagram in the batch
//! is blinded, so quinn never sees it there. When the CRYPTO stream of a flight
//! holds a whole ClientHello, the flight is judged, and either every datagram
//! it held is released to quinn in the order they arrived, or all of them are
//! dropped and nothing is sent. The judgement is `hold::judge`, whose rule
//! table admits an ECH extension the key opens unless it is a replay, drops
//! one the key does not open whatever `[security] require_ech` says (our own
//! rule, a deviation from RFC 9849 §7.1), and judges a ClientHello without ECH
//! by `require_ech` and by its name, against the whole ClientHello rather than
//! one packet.
//!
//! An Initial that carries no ClientHello (a PING, a lone CRYPTO frame past
//! offset 0, a ClientHello cut short) is held like any other and, when nothing
//! completes it, dropped. So the acknowledgements of *What is left uncovered*
//! are not sent while a key is configured.
//!
//! **Bounds.** Everything held came from a peer that has not authenticated,
//! so the hold is bounded in time, in number and in bytes at once, each by a
//! constant in `hold` with its reason (`HOLD_LIFETIME`, `HOLD_FLIGHTS`,
//! `HOLD_FLIGHT_BYTES`, `HOLD_HELLO_BYTES`, `HOLD_TOTAL_BYTES`). A full table,
//! or a hold out of bytes, evicts its oldest flight. No timer runs: a flight
//! past its lifetime is never released, and it is freed by the next first
//! Initial that reaches the hold, which is when its room could be wanted.
//!
//! **Release.** A released datagram has to come back in a later receive call,
//! since the batch it arrived in has already been handed over with it blinded.
//! `poll_recv` therefore hands out released datagrams first, one to a buffer
//! with a stride of its own length, before it reads the socket again, and
//! with no waker of its own (`poll_recv` says why).
//!
//! **The replay record** keeps every `enc` the key opened, with its address,
//! for the life of the process up to `REPLAY_ENTRIES`, and does not expire by
//! time. Only a flight the key opened adds to it, so a peer without the key
//! cannot grow it. A reload that changes the key empties it, and it is not kept
//! across a restart.
//!
//! **Limits.** Two are known and not handled. First, the replay record admits
//! whichever copy of a flight completes first. A copy that reaches the server
//! from another address before the client's own last packet is admitted, and
//! the client's flight is then dropped as the replay. The two cannot be told
//! apart without a freshness field, which a first flight does not carry, and
//! the copy has to come from a position on the path that can get ahead of the
//! original. Second, a flight is keyed by its source address, so a client
//! whose source port changes between two packets of one first flight leaves
//! two halves that never complete; the flight completes when the client sends
//! it again from the new port. A port change between an admitted flight and
//! its retransmission makes the retransmission look like a replay, and it is
//! dropped until the client makes a new attempt, which carries a new `enc`.
//! Both end in silence rather than in an error.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::BytesMut;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, ConnectionId, UdpPoller};
use tracing::debug;

use crate::logfmt::escaped_bytes;
pub use crate::names::Names;
use crate::tls::EchKey;

mod hold;
mod initial;
mod seam;

#[doc(hidden)]
pub use hold::Dropped;
use hold::{Arrival, Memory};
use initial::{
    DCID_LENGTH_OFFSET, INITIAL_PACKET_TYPE, InitialHeader, LONG_HEADER_FORM, LONG_PACKET_TYPE,
    QUIC_V1, coalesced_frames, crypto_frames, crypto_stream_prefix, decrypt,
};
#[doc(hidden)]
pub use seam::{
    FirstFlight, HOLD_FLIGHT_BYTES, HOLD_FLIGHTS, HOLD_HELLO_BYTES, HOLD_LIFETIME,
    HOLD_TOTAL_BYTES, HoldInput, HoldRecord, REPLAY_ENTRIES, SEALED_FRAMES_MAX, Screening,
    first_flight, held_fragments, hold_input_key, judgement, sealed_initial,
};

/// The longest connection ID QUIC version 1 allows, in bytes.
///
/// The second sentence is what [`blind`] rests on: a length above this is not
/// merely unusual, it is a packet every version-1 endpoint is required to throw
/// away.
///
//= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
//# In QUIC version 1, this value MUST NOT exceed
//# 20 bytes.  Endpoints that receive a version 1 long header with a
//# value larger than 20 MUST drop the packet.
const MAX_CONNECTION_ID: usize = 20;

/// The smallest UDP payload that may carry an Initial packet, in bytes.
///
/// Anything below it is discarded by the server without a reply, so the gate has
/// nothing to protect there and skips the key derivation such a packet would
/// otherwise cost it.
///
//= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
//# A server MUST discard an Initial packet that is carried in a UDP
//# datagram with a payload that is smaller than the smallest allowed
//# maximum datagram size of 1200 bytes.
const MIN_INITIAL_DATAGRAM: usize = 1200;

/// The shortest Destination Connection ID a client's first Initial may carry.
///
/// Applied to every Initial the gate parses, ahead of decryption;
/// [`classify`] says why.
///
//= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
//# When an Initial packet is sent by a client that has not previously
//# received an Initial or Retry packet from the server, the client
//# populates the Destination Connection ID field with an unpredictable
//# value.  This Destination Connection ID MUST be at least 8 bytes in
//# length.
const MIN_CLIENT_CONNECTION_ID: usize = 8;

/// The value written over a refused datagram's Destination Connection ID length.
///
/// Any number above [`MAX_CONNECTION_ID`] would do; the largest a byte can hold
/// is chosen so that the intent reads as "not a length any version could accept"
/// rather than as an off-by-one against one version's ceiling.
const IMPOSSIBLE_CID_LENGTH: u8 = 0xff;

/// What the gate enforces: the names a ClientHello may carry, the ECH key,
/// and whether ECH is required.
///
/// Built from `[security] expected_sni`, `[security] require_ech` and the key
/// `server.ech_key` names, at bind and on every reload. The gate is on when the
/// list holds a name or there is a key; with neither, every datagram passes
/// untouched. A key turns on the hold the module documentation describes.
#[derive(Debug)]
pub struct Policy {
    names: Names,
    ech: Option<Arc<EchKey>>,
    require_ech: bool,
}

impl Policy {
    /// The policy of `names`, the ECH key `ech` and `require_ech`.
    ///
    /// `require_ech` is read only where there is a key: the configuration
    /// refuses it without one at startup, by `--check-config` and on reload,
    /// so no running server holds that pair.
    pub fn new(names: Names, ech: Option<Arc<EchKey>>, require_ech: bool) -> Self {
        Self {
            names,
            ech,
            require_ech,
        }
    }

    /// Whether the gate judges anything at all.
    pub fn is_on(&self) -> bool {
        !self.names.is_empty() || self.ech.is_some()
    }

    /// The names a ClientHello without ECH has to carry, or an empty list for
    /// any name.
    pub fn names(&self) -> &Names {
        &self.names
    }
}

/// A policy of names alone: no ECH key, so no hold.
impl From<Names> for Policy {
    fn from(names: Names) -> Self {
        Self::new(names, None, false)
    }
}

/// Whether `a` and `b` are the same ECH key.
///
/// Compared by the ECHConfigList each one prints, which holds the public key,
/// so two files with the same list hold the same key. A reload re-reads the
/// file every time, so the two are never the same allocation even when the
/// key did not change.
fn same_key(a: Option<&EchKey>, b: Option<&EchKey>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.config_list() == b.config_list(),
        _ => false,
    }
}

/// Puts `new` in force, with what the change does to the hold and the replay
/// record: a new ECH key empties the record, and no key empties the hold.
/// [`Expected::set`] says why.
fn follow(memory: &mut Memory, new: Arc<Policy>) {
    if !same_key(memory.policy.ech.as_deref(), new.ech.as_deref()) {
        memory.replay.clear();
    }
    if new.ech.is_none() {
        memory.hold.clear();
    }
    memory.policy = new;
}

/// The policy the gate is enforcing right now, and the state it keeps.
///
/// A `SIGHUP` replaces the policy, so the handle is shared rather than copied:
/// the socket wrapper is built once at bind time and has to see a reload
/// without being rebuilt, since rebuilding it would mean rebinding the port.
///
/// The policy sits under one lock with the hold and the replay record, which
/// live here rather than in [`Gate`] because a reload has to reach them: a new
/// ECH key clears the replay record, and a policy without a key clears the
/// hold. A receive batch takes the lock once and reads the policy under it.
///
/// The flag beside it answers "is the gate on at all" without taking the lock,
/// because a gate that is off is the shipped default. A gate that is off then
/// costs a receive batch one atomic load.
#[derive(Clone)]
pub struct Expected(Arc<Held>);

/// The policy with the hold, and the flag that says whether it is on.
struct Held {
    /// The policy, the hold and the replay record, which only a policy with a
    /// key uses.
    memory: Mutex<Memory>,
    /// Whether the policy is on. Written after it, read before it.
    any: AtomicBool,
    /// Whether `memory` has released datagrams waiting for the next receive
    /// call. Written under the `memory` lock.
    releasing: AtomicBool,
    /// Whether the server has stopped taking new connections. Set once, by
    /// [`Expected::close`], and never cleared.
    closed: AtomicBool,
}

impl fmt::Debug for Expected {
    /// Hand-written because the hold is not `Debug`: it is datagrams.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Expected").field(&self.current()).finish()
    }
}

impl Expected {
    /// A handle starting on `policy`, with an empty hold.
    pub fn new(policy: impl Into<Policy>) -> Self {
        let policy = policy.into();
        let any = AtomicBool::new(policy.is_on());
        Self(Arc::new(Held {
            memory: Mutex::new(Memory::new(Arc::new(policy))),
            any,
            releasing: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }))
    }

    /// Replaces the policy, for every datagram received from now on.
    ///
    /// The policy is written first and the flag second, with a `Release` store
    /// against the `Acquire` load in [`Expected::any`], so a reader that sees
    /// the flag set also sees the policy the flag is about.
    ///
    /// The order matters in one direction only. A reader that has already
    /// loaded the flag while it still said "off" judges its batch against the
    /// policy that was in force a moment earlier, which is what a reload means
    /// for every datagram that arrived just before it and is why the gate can
    /// be reloaded at all. Storing the flag first would allow the opposite: a
    /// reader seeing "the gate is on" and then reading a policy that is not yet
    /// the new one, which is a judgement made against a policy no
    /// configuration ever asked for.
    ///
    /// A new ECH key empties the replay record, because the record is the
    /// `enc` values one key opened. A policy without a key empties the hold,
    /// because nothing would judge what it holds; the clients of those
    /// flights send them again and the gate passes them as it now does. Both
    /// happen under the lock the policy itself sits under, and a receive batch
    /// reads the policy only under that lock. So no flight is held, judged or
    /// recorded under a policy that is no longer in force, however a receive
    /// call and a reload interleave (D115): a flight held just before the
    /// reload is in the hold the reload clears, and one that arrives just
    /// after is judged by the new policy.
    pub fn set(&self, policy: impl Into<Policy>) {
        let policy = Arc::new(policy.into());
        let any = policy.is_on();
        follow(&mut self.memory(), policy);
        self.0.any.store(any, Ordering::Release);
    }

    /// Stops every new handshake at the socket, for the rest of the process:
    /// from the next receive call on, [`Gate`] drops every datagram that
    /// starts with an Initial packet, whatever the policy says and whether it
    /// is on or off, and delivers nothing more out of the hold.
    ///
    /// `Server::drain` calls this just before it removes the endpoint's server
    /// configuration. Without it the shutdown grace is the one time the
    /// endpoint answers a stranger: quinn-proto 0.11.19
    /// `Endpoint::handle_first_packet` answers an Initial it cannot route with
    /// a Stateless Reset when the endpoint has no server configuration, which
    /// is the case from the drain's first step until the process ends.
    ///
    /// The rule is on the packet type alone because the gate cannot know which
    /// connections the endpoint still holds. So it also drops the later
    /// Initial packets of a handshake that was in flight when the drain began,
    /// and that handshake ends at the client's timeout. Nothing is lost by
    /// that: such a connection would be born under a GOAWAY and could carry no
    /// request. An established connection sends no Initial packet, so its
    /// traffic is untouched.
    ///
    /// The order against the server configuration is what makes this exact.
    /// quinn's endpoint driver holds the endpoint's mutex from `poll_recv`
    /// through the handling of the batch it returned (quinn 0.11.12
    /// `EndpointDriver::poll`), and `Endpoint::set_server_config` takes the
    /// same mutex. A batch received before this store is therefore handled
    /// whole while the server configuration is still present, and every batch
    /// received after the configuration is gone was screened with the flag
    /// set, as long as the caller stores first and removes second.
    ///
    /// The hold is left as it is: nothing delivers from it again, it is
    /// bounded, and the process is ending.
    pub fn close(&self) {
        self.0.closed.store(true, Ordering::Release);
    }

    /// Whether [`Expected::close`] was called.
    pub fn closed(&self) -> bool {
        self.0.closed.load(Ordering::Acquire)
    }

    /// Whether the policy in force judges anything, without taking the lock.
    pub fn any(&self) -> bool {
        self.0.any.load(Ordering::Acquire)
    }

    /// The policy in force.
    pub fn current(&self) -> Arc<Policy> {
        Arc::clone(&self.memory().policy)
    }

    /// The policy, the hold and the replay record.
    ///
    /// Nothing that runs under this lock may panic on any input, because a
    /// panic under `poll_recv` is not recovered anywhere. `poll_recv` runs
    /// inside quinn's endpoint driver, which holds the endpoint's own mutex
    /// across it (quinn 0.11.12 `src/endpoint.rs`, `EndpointDriver::poll`).
    /// The panic unwinds out of that function and poisons that mutex. tokio
    /// drops the driver while it unwinds, and quinn's `Drop for EndpointDriver`
    /// calls `lock().unwrap()` on the poisoned mutex. A panic in a destructor
    /// during unwinding aborts the process, so every connection ends with it.
    /// Taking over a poisoned guard here therefore matters only for a
    /// panic on the reload side, in [`Expected::set`], which would leave the
    /// next datagram judged against whatever the hold then holds, and that is
    /// bounded either way.
    fn memory(&self) -> MutexGuard<'_, Memory> {
        self.0.memory.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A UDP socket that hands quinn only the datagrams the gate admits.
///
/// Everything except [`AsyncUdpSocket::poll_recv`] is passed straight through,
/// including the capability answers. `max_receive_segments` controls whether
/// GRO is used at all and `may_fragment` controls whether MTU discovery runs,
/// so a wrapper that answered them itself would quietly change the transport.
#[derive(Debug)]
pub struct Gate {
    inner: Arc<dyn AsyncUdpSocket>,
    expected: Expected,
}

impl Gate {
    /// Wraps `inner`, judging against `expected`.
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, expected: Expected) -> Self {
        Self { inner, expected }
    }

    /// Judges one datagram under the policy in force, with the hold when the
    /// policy has an ECH key, and blinds it unless it passes.
    ///
    /// `held` is the lock on the policy and the hold, taken at the first
    /// datagram of a batch and kept for the rest of it, so the batch reads the
    /// policy only under the lock a reload swaps it under ([`Expected::set`]
    /// says why). A policy that is off passes the datagram untouched.
    ///
    /// Under a key, a first Initial is copied into the hold before it is
    /// blinded in the batch, so quinn never sees it there; if its flight is
    /// admitted, the copy is what quinn receives, from the next receive call.
    /// The clock is read the first time a batch has a first Initial in it.
    fn screen_holding<'a>(
        &'a self,
        meta: &RecvMeta,
        datagram: &mut [u8],
        held: &mut Option<MutexGuard<'a, Memory>>,
        now: &mut Option<Instant>,
    ) {
        let memory = held.get_or_insert_with(|| self.expected.memory());
        if !memory.policy.is_on() {
            return;
        }
        match screen_one(memory, meta, datagram, now, &mut log_drop) {
            Screened::Passed => {}
            Screened::Refused(refusal) => {
                log_refusal(meta.addr, &refusal);
                blind(datagram);
            }
            Screened::Released => {
                self.expected.0.releasing.store(true, Ordering::Release);
                blind(datagram);
            }
            Screened::Held | Screened::Dropped => blind(datagram),
        }
    }

    /// Hands quinn the datagrams of admitted flights, one per buffer, and says
    /// how many.
    ///
    /// Each goes into a buffer of its own with `stride` equal to its length, so
    /// quinn reads it as one datagram whatever GRO did to the batch it first
    /// arrived in. quinn's receive buffers each hold the largest datagram it
    /// accepts (`RecvState::new` sizes them at the maximum UDP payload times
    /// the GRO segment count), and one that would not fit is dropped rather
    /// than cut, which a datagram quinn itself received never needs.
    fn deliver(&self, bufs: &mut [IoSliceMut<'_>], metas: &mut [RecvMeta]) -> usize {
        let mut memory = self.expected.memory();
        let room = bufs.len().min(metas.len());
        let mut delivered = 0;
        while delivered < room {
            let Some(held) = memory.hold.pop_released() else {
                break;
            };
            let length = held.bytes.len();
            let Some(slot) = bufs[delivered].get_mut(..length) else {
                continue;
            };
            slot.copy_from_slice(&held.bytes);
            let mut meta = held.meta;
            meta.len = length;
            meta.stride = length;
            metas[delivered] = meta;
            delivered += 1;
        }
        self.expected
            .0
            .releasing
            .store(!memory.hold.released.is_empty(), Ordering::Release);
        delivered
    }
}

/// Logs one refused datagram.
///
/// DEBUG rather than a production level: this fires once per refused datagram,
/// which is once per packet of a scan, and D97's rule is that a line a peer can
/// repeat at will is either sampled or expensive. The per-packet debug lines
/// elsewhere in this server are deliberately neither, and this is one of them.
fn log_refusal(remote: SocketAddr, refusal: &Refusal) {
    match refusal {
        Refusal::Version(version) => debug!(
            %remote,
            version = format_args!("{version:#010x}"),
            "dropping a QUIC packet: the SNI gate answers no version but 1"
        ),
        Refusal::ShortConnectionId(length) => debug!(
            %remote,
            connection_id_length = length,
            "dropping an Initial packet: its destination connection ID is shorter than \
             eight bytes"
        ),
        Refusal::NotClientHello => debug!(
            %remote,
            "dropping an Initial packet: its first handshake message is not a ClientHello"
        ),
        Refusal::Anonymous => debug!(
            %remote,
            "dropping a handshake: its ClientHello carries no server_name"
        ),
        Refusal::OtherName(name) => debug!(
            %remote,
            server_name = %escaped_bytes(name),
            "dropping a handshake: its server_name is not one this server answers to"
        ),
    }
}

/// Logs one first flight the hold dropped.
///
/// One line per flight, however many datagrams it had (D97), at DEBUG for the
/// reason [`log_refusal`] gives.
fn log_drop(remote: SocketAddr, dropped: Dropped) {
    let why = match &dropped {
        Dropped::NotClientHello => "its first handshake message is not a ClientHello",
        Dropped::UnreadableExtensions => "its ClientHello's extension block does not parse",
        Dropped::TooLong => "its ClientHello is longer than libssl reads",
        Dropped::Conflict => "two of its packets carry different bytes at one offset",
        Dropped::Frames => "a packet of it carries frames an Initial packet may not",
        Dropped::EchNotOpened => "its ECH extension does not open under this server's key",
        Dropped::Replayed => "its ECH was already admitted from another address",
        Dropped::EchRequired => "it carries no ECH extension and security.require_ech is on",
        Dropped::Anonymous => "its ClientHello carries no server_name",
        Dropped::OtherName(_) => "its server_name is not one this server answers to",
        Dropped::Expired => "its ClientHello did not complete in time",
        Dropped::Evicted => "the hold was full and this was its oldest flight",
        Dropped::TooBig => "it outgrew the bytes one held flight may take",
    };
    match dropped {
        Dropped::OtherName(name) => debug!(
            %remote,
            server_name = %escaped_bytes(&name),
            "dropping a first flight: {why}"
        ),
        _ => debug!(%remote, "dropping a first flight: {why}"),
    }
}

/// What the gate makes of one datagram under `memory`'s policy, which is on:
/// without an ECH key the stateless judgement, with one the hold.
///
/// The one screening function, called by the socket path and by
/// [`Screening`]. `now` is the arrival time, read from the clock the first
/// time it is needed when it is `None`. Every flight the hold drops is
/// reported once through `report`.
fn screen_one(
    memory: &mut Memory,
    meta: &RecvMeta,
    datagram: &[u8],
    now: &mut Option<Instant>,
    report: &mut dyn FnMut(SocketAddr, Dropped),
) -> Screened {
    if memory.policy.ech.is_none() {
        return match judge(datagram, &memory.policy.names) {
            Verdict::Pass => Screened::Passed,
            Verdict::Refuse(refusal) => Screened::Refused(refusal),
        };
    }
    match classify(datagram, true) {
        Classified::Pass => Screened::Passed,
        Classified::Refuse(refusal) => Screened::Refused(refusal),
        Classified::Opened { dcid, frames, more } => {
            let arrival = Arrival {
                now: *now.get_or_insert_with(Instant::now),
                meta: *meta,
                datagram,
                dcid,
            };
            let fragments = flight_fragments(&frames, &more);
            memory.take(&arrival, fragments.as_deref(), report)
        }
    }
}

/// The CRYPTO frames the hold reads from one datagram: those of its first
/// packet, `frames`, and those of the Initial packets of the same flight
/// coalesced behind it, `more`, in that order.
///
/// `None` when a packet's frames do not parse, or carry a type no Initial
/// packet may, which makes the whole flight one the hold drops: quinn would
/// close the connection over it, which is a reply.
fn flight_fragments<'a>(frames: &'a [u8], more: &'a [BytesMut]) -> Option<Vec<(u64, &'a [u8])>> {
    let mut fragments = Vec::new();
    for payload in std::iter::once(frames).chain(more.iter().map(|m| &m[..])) {
        let walk = crypto_frames(payload)?;
        if !walk.whole {
            return None;
        }
        fragments.extend(walk.fragments);
    }
    Some(fragments)
}

/// What [`classify`] made of a datagram.
enum Classified {
    /// Hand it to quinn unchanged.
    Pass,
    /// Make quinn's decoder throw it away.
    Refuse(Refusal),
    /// A first Initial that opened under the keys its own Destination
    /// Connection ID derives: that connection ID, and the packet's frames.
    Opened {
        dcid: ConnectionId,
        frames: BytesMut,
        /// The frames of the Initial packets of the same flight coalesced
        /// behind it, when [`classify`] was asked for them.
        more: Vec<BytesMut>,
    },
}

/// What should happen to one datagram, as far as it can be said without
/// reading its ClientHello: passed, refused, or opened as a first Initial.
///
/// A function of the datagram's bytes alone, with no socket: the [`judgement`]
/// and [`Screening`] seams reach it without a bound port, and the receive path
/// is the only code that knows about batches, strides and blinding.
///
/// `coalesced` asks for the Initial packets of the same flight behind the
/// first as well ([`coalesced_frames`]), which only the hold reads.
fn classify(datagram: &[u8], coalesced: bool) -> Classified {
    let Some(&first) = datagram.first() else {
        return Classified::Pass;
    };

    // A short header names a connection by its ID, which is state this
    // module does not have; see the module documentation. It is also, by
    // RFC 9000 §12.2, only ever the last packet in a datagram, so a
    // handshake can never be hiding behind one.
    //
    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.2
    //# A packet with a short header does not include a
    //# length, so it can only be the last packet included in a UDP datagram.
    if first & LONG_HEADER_FORM == 0 {
        return Classified::Pass;
    }

    let Some(version) = datagram.get(1..5) else {
        // Too short for quinn to read a version out of, so too short for it
        // to answer with a Version Negotiation packet.
        return Classified::Pass;
    };
    let version = u32::from_be_bytes([version[0], version[1], version[2], version[3]]);

    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
    //# If a server receives a packet that indicates an unsupported version
    //# and if the packet is large enough to initiate a new connection for
    //# any supported version, the server SHOULD send a Version Negotiation
    //# packet as described in Section 6.1.
    //
    // A deliberate departure from that SHOULD, and the reason the gate
    // exists: a Version Negotiation packet is a reply, and a reply is what a
    // scan is looking for. D106. The module documentation says what refusing
    // does to the six draft versions quinn also supports.
    if version != QUIC_V1 {
        return Classified::Refuse(Refusal::Version(version));
    }

    // Handshake, 0-RTT and Retry packets for a connection this endpoint does
    // not hold are dropped by quinn without a reply, and for one it does
    // hold they belong to a handshake that already passed this gate.
    if first & LONG_PACKET_TYPE != INITIAL_PACKET_TYPE {
        return Classified::Pass;
    }

    if datagram.len() < MIN_INITIAL_DATAGRAM {
        return Classified::Pass;
    }

    let Some(header) = InitialHeader::parse(datagram) else {
        // Not a packet quinn could decode either (a header that runs off
        // the end of the datagram, a length field that claims more than
        // arrived), and one it drops without a reply.
        return Classified::Pass;
    };

    // Judged on the header alone, ahead of the decryption, because quinn
    // judges it ahead of its own decryption. `Endpoint::early_validate_first_packet`
    // runs before `first_decode.finish` and answers a Destination
    // Connection ID under eight bytes with a CONNECTION_CLOSE carrying
    // PROTOCOL_VIOLATION, without opening the packet. Its one exemption is
    // a packet carrying a token whose Destination Connection ID is exactly
    // the length this endpoint's own generator uses, which is eight, so
    // nothing under eight bytes is exempt. RFC 9000 §7.2 gives a client's
    // first Initial a floor of eight bytes, quoted at
    // `MIN_CLIENT_CONNECTION_ID`, and every later Initial of an admitted
    // handshake is addressed by the eight bytes this endpoint's own
    // generator chose, as is the one a Retry supplies. So nothing
    // legitimate is ever this shape, and the reply quinn would send is one
    // of the three this gate exists to take away.
    //
    // Placed after the decryption, this check would let the shape that costs an
    // attacker no cryptography at all (a 1200-byte Initial with a four-byte
    // connection ID and a payload nobody sealed) pass through to that
    // reply, because a packet that fails decryption is passed.
    if header.dcid.len() < MIN_CLIENT_CONNECTION_ID {
        return Classified::Refuse(Refusal::ShortConnectionId(header.dcid.len()));
    }

    let Some((keys, frames)) = decrypt(datagram, &header) else {
        // A later Initial of a flight this gate already judged, as the
        // module documentation says, or a forgery quinn drops without a
        // reply. Passed rather than dropped, because the Handshake packet
        // that carries the client's Finished is often coalesced behind it,
        // and dropping the datagram would cost every admitted handshake a
        // probe timeout.
        //
        //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
        //# Upon first receiving an Initial or Retry packet from the server, the
        //# client uses the Source Connection ID supplied by the server as the
        //# Destination Connection ID for subsequent packets, including any 0-RTT
        //# packets.
        return Classified::Pass;
    };

    let more = if coalesced {
        coalesced_frames(&keys, datagram, &header)
    } else {
        Vec::new()
    };
    Classified::Opened {
        dcid: ConnectionId::new(&datagram[header.dcid]),
        frames,
        more,
    }
}

/// What should happen to one datagram without the hold: its ClientHello is
/// judged by its name, from what its first packet holds.
fn judge(datagram: &[u8], expected: &Names) -> Verdict {
    let frames = match classify(datagram, false) {
        Classified::Pass => return Verdict::Pass,
        Classified::Refuse(refusal) => return Verdict::Refuse(refusal),
        Classified::Opened { frames, .. } => frames,
    };

    let Some(crypto) = crypto_stream_prefix(&frames) else {
        // No CRYPTO frame at offset 0: an acknowledgement, or a later
        // fragment of a first flight whose beginning was already judged.
        return Verdict::Pass;
    };

    match first_flight(&crypto) {
        // A ClientHello that does not fit in this packet is judged by the
        // second gate in the TLS layer instead; see the module
        // documentation.
        FirstFlight::Truncated => Verdict::Pass,
        FirstFlight::NotAClientHello => Verdict::Refuse(Refusal::NotClientHello),
        FirstFlight::Anonymous => Verdict::Refuse(Refusal::Anonymous),
        FirstFlight::Named(name) if expected.accepts_bytes(name) => Verdict::Pass,
        // The name is borrowed from the frames this function decrypted and
        // drops on return, so the refusal takes the copy the pass path
        // does not need.
        FirstFlight::Named(name) => Verdict::Refuse(Refusal::OtherName(name.to_vec())),
    }
}

impl AsyncUdpSocket for Gate {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        metas: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // A closed gate admits no Initial and delivers nothing from the hold;
        // `Expected::close` says why. One atomic load per batch otherwise.
        if self.expected.closed() {
            let count = match self.inner.poll_recv(cx, bufs, metas) {
                Poll::Ready(Ok(count)) => count,
                other => return other,
            };
            for (meta, buf) in metas.iter().zip(bufs.iter_mut()).take(count) {
                each_datagram(meta, buf, |datagram| {
                    if starts_with_an_initial(datagram) {
                        blind(datagram);
                    }
                });
            }
            return Poll::Ready(Ok(count));
        }

        // The datagrams of flights the hold admitted go first, ahead of the
        // socket. They were released inside an earlier call of this function,
        // which returned `Ready`, and quinn's endpoint driver calls again after
        // every `Ready`: `RecvState::poll_socket` loops until the socket is
        // `Pending`, and when its work limiter stops the loop first it reports
        // `keep_going` and the driver wakes itself. So a release needs no
        // waker of its own and waits for no timer.
        if self.expected.0.releasing.load(Ordering::Acquire) {
            let delivered = self.deliver(bufs, metas);
            if delivered > 0 {
                return Poll::Ready(Ok(delivered));
            }
        }

        let count = match self.inner.poll_recv(cx, bufs, metas) {
            Poll::Ready(Ok(count)) => count,
            other => return other,
        };

        // The flag first, so a gate that is off pays one atomic load per batch
        // and takes no lock.
        if !self.expected.any() {
            return Poll::Ready(Ok(count));
        }

        let mut held = None;
        let mut now = None;
        for (meta, buf) in metas.iter().zip(bufs.iter_mut()).take(count) {
            each_datagram(meta, buf, |datagram| {
                self.screen_holding(meta, datagram, &mut held, &mut now);
            });
        }

        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// The gate's verdict on one datagram.
///
/// Public, and hidden, for the callers outside this module: the fuzz target and
/// the tests behind [`judgement`] have to be able to say which verdict they got.
/// Nothing in this crate names it.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Hand it to quinn unchanged.
    Pass,
    /// Make quinn's decoder throw it away.
    Refuse(Refusal),
}

/// Why a datagram was refused, and what the refusal was about.
///
/// The values are the parser's own, not the logger's: a peer-chosen name is
/// carried raw and is bounded and escaped in [`log_refusal`], inside the
/// `debug!` that prints it. Nothing is rendered for a build that is not logging
/// at DEBUG, which a flood of refused handshakes is the reason to care about.
///
/// Hidden, and public for the same reason [`Verdict`] is.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A long header naming a QUIC version this server does not speak.
    Version(u32),
    /// An Initial whose Destination Connection ID is under
    /// [`MIN_CLIENT_CONNECTION_ID`] bytes, carrying the length it had.
    ShortConnectionId(usize),
    /// A first flight that does not begin with a ClientHello.
    NotClientHello,
    /// A complete ClientHello with no `server_name` extension.
    Anonymous,
    /// A ClientHello naming somebody else, carrying the name it gave.
    ///
    /// Peer-chosen bytes, exactly as the extension spelled them: whatever reads
    /// them owes them [`crate::logfmt::escaped_bytes`] before they reach a log.
    OtherName(Vec<u8>),
}

/// Calls `screen` on each datagram of one received buffer.
///
/// Exactly how quinn's own receive loop walks a GRO run: `len` bytes of buffer
/// holding datagrams `stride` bytes apart, the last one possibly shorter. A
/// datagram the gate holds or refuses is blinded where it lies rather than cut
/// out, so the strides stay as they were; see the module documentation.
fn each_datagram(meta: &RecvMeta, buf: &mut [u8], screen: impl FnMut(&mut [u8])) {
    // `len` is at most the buffer's length, so the slice is in range, and a
    // zero stride, which `chunks_mut` would panic on, is read as one.
    let len = meta.len.min(buf.len());
    buf[..len].chunks_mut(meta.stride.max(1)).for_each(screen);
}

/// Whether the first packet of `datagram` is an Initial, read off its first
/// byte alone: the long header form with packet type 0, which is the Initial
/// type in every version quinn's endpoint accepts (QUIC v1 and the drafts 29
/// to 34). The version is not read, so a long header of any other version with
/// these bits counts too, and dropping that one changes nothing a closed
/// endpoint would have done with it.
fn starts_with_an_initial(datagram: &[u8]) -> bool {
    datagram.first().is_some_and(|first| {
        first & LONG_HEADER_FORM != 0 && first & LONG_PACKET_TYPE == INITIAL_PACKET_TYPE
    })
}

/// Makes quinn's packet decoder reject a datagram before it can answer it.
///
/// Overwrites the Destination Connection ID Length field with a value RFC 9000
/// §17.2 obliges every version-1 endpoint to drop the packet over (quoted at
/// [`MAX_CONNECTION_ID`]). quinn's decoder reads that field right after the
/// four version bytes, and rejects it before it acts on the version or reads
/// the packet type, the token or the payload, so the rejection does not depend
/// on anything else in the packet being well formed, and the decoder answers
/// it by returning rather than by replying. A datagram too short to hold that
/// byte is one quinn already drops without a reply.
fn blind(datagram: &mut [u8]) {
    if let Some(length) = datagram.get_mut(DCID_LENGTH_OFFSET) {
        *length = IMPOSSIBLE_CID_LENGTH;
    }
}

/// What the gate with the hold did with one datagram.
///
/// Hidden, and public for [`Screening`]'s callers.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screened {
    /// Handed to quinn unchanged.
    Passed,
    /// Refused without the hold, as the stateless gate refuses it.
    Refused(Refusal),
    /// Held: quinn does not see it unless its flight is admitted.
    Held,
    /// It completed its flight, which was admitted: every datagram of the
    /// flight is waiting for [`Screening::released`].
    Released,
    /// Its flight was dropped, and with it every datagram the flight held.
    Dropped,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_replaced_list_is_what_the_next_datagram_is_judged_against() {
        let expected = Expected::new(Names::new(&["old.example".to_owned()]));
        assert!(expected.current().names().accepts("old.example"));

        expected.set(Names::new(&["new.example".to_owned()]));
        assert!(!expected.current().names().accepts("old.example"));
        assert!(expected.current().names().accepts("new.example"));
    }

    /// The flag is what `poll_recv` reads before it takes the lock, so it has
    /// to follow `set` in both directions or a reload would either be ignored
    /// or turn the gate off.
    #[test]
    fn the_flag_beside_the_list_follows_every_replacement() {
        let expected = Expected::new(Names::new(&[]));
        assert!(!expected.any(), "an empty list is the gate being off");

        expected.set(Names::new(&["proxy.example".to_owned()]));
        assert!(expected.any(), "a name was added, so the gate is on");

        expected.set(Names::new(&[]));
        assert!(!expected.any(), "the list was emptied, so the gate is off");

        assert!(
            Expected::new(Names::new(&["proxy.example".to_owned()])).any(),
            "a handle built on a non-empty list starts open"
        );
    }

    /// Under an ECH key the header rules still refuse a datagram before the
    /// hold sees it, as they do without one.
    #[test]
    fn the_header_rules_refuse_under_a_key_too() {
        let key = Arc::new(EchKey::generate("public.example", 7, 0).expect("a key"));
        let mut screening = Screening::new(Policy::new(Names::new(&[]), Some(key), false));
        let mut datagram = sealed_initial(&[0x51; 8], 0, &[0x01]);
        datagram[1..5].copy_from_slice(&2u32.to_be_bytes());
        let from = SocketAddr::from(([127, 0, 0, 1], 4433));
        let (screened, drops) = screening.receive(Duration::ZERO, from, &datagram);
        assert_eq!(screened, Screened::Refused(Refusal::Version(2)));
        assert!(drops.is_empty() && screening.flights() == 0);
    }

    /// A reload that removes the key leaves no flight held, on the socket
    /// path: a flight the receive path put in the hold under the key is gone
    /// once [`Expected::set`] installs a policy without one, and the next
    /// datagram is judged under the new policy, which with no names either is
    /// the gate switched off, so quinn gets it untouched.
    ///
    /// The receive path reads the policy only under the lock `set` swaps it
    /// under, so no receive call can screen under a key the reload has
    /// already removed. What can strand a flight is a `set` that swaps the
    /// policy and leaves the hold as it was, which this drives.
    #[tokio::test]
    async fn a_reload_that_removes_the_key_leaves_no_flight_held() {
        let key = Arc::new(EchKey::generate("public.example", 7, 0).expect("a key"));
        let expected = Expected::new(Policy::new(Names::new(&[]), Some(key), false));
        let runtime = quinn::default_runtime().expect("a tokio runtime");
        let socket = runtime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").expect("bind"))
            .expect("wrap");
        let gate = Gate::new(socket, expected.clone());
        let meta = |datagram: &[u8]| RecvMeta {
            addr: SocketAddr::from(([127, 0, 0, 1], 4433)),
            len: datagram.len(),
            stride: datagram.len(),
            ..RecvMeta::default()
        };

        // The first four bytes of a ClientHello that declares 256: a flight
        // the hold keeps until the rest arrives.
        let first = sealed_initial(&[0x51; 8], 0, &[0x06, 0x00, 0x04, 0x01, 0x00, 0x01, 0x00]);
        let mut datagram = first.clone();
        let (mut held, mut now) = (None, None);
        gate.screen_holding(&meta(&first), &mut datagram, &mut held, &mut now);
        drop(held);
        assert_eq!(expected.memory().hold.flights(), 1, "the flight is held");
        assert_ne!(datagram, first, "a held datagram is blinded in the batch");

        expected.set(Names::new(&[]));
        assert_eq!(expected.memory().hold.flights(), 0, "a flight was stranded");

        let next = sealed_initial(&[0x52; 8], 0, &[0x06, 0x00, 0x04, 0x01, 0x00, 0x01, 0x00]);
        let mut datagram = next.clone();
        let (mut held, mut now) = (None, None);
        gate.screen_holding(&meta(&next), &mut datagram, &mut held, &mut now);
        drop(held);
        assert_eq!(datagram, next, "the gate is off, so quinn gets it as sent");
        assert_eq!(expected.memory().hold.flights(), 0);
    }

    /// The closed gate's rule reads the header form and the packet type and
    /// nothing else: an Initial with or without the fixed bit, and not a
    /// 0-RTT, Handshake, Retry or short-header packet, nor an empty datagram.
    #[test]
    fn only_a_long_header_of_type_zero_starts_with_an_initial() {
        for first in [0xc0u8, 0x80, 0xcf, 0x8f] {
            assert!(starts_with_an_initial(&[first, 0, 0, 0, 1]), "{first:#x}");
        }
        for first in [0xd0u8, 0xe0, 0xf0, 0x40, 0x00, 0x7f] {
            assert!(!starts_with_an_initial(&[first, 0, 0, 0, 1]), "{first:#x}");
        }
        assert!(!starts_with_an_initial(&[]));
    }

    #[test]
    fn blinding_writes_a_connection_id_length_no_version_allows() {
        let mut datagram = vec![0xc0, 0x00, 0x00, 0x00, 0x01, 0x08];
        blind(&mut datagram);

        assert_eq!(datagram[DCID_LENGTH_OFFSET], IMPOSSIBLE_CID_LENGTH);
        assert!(usize::from(datagram[DCID_LENGTH_OFFSET]) > MAX_CONNECTION_ID);
        // Nothing else moved: the datagram keeps its length and its first bytes,
        // so a GRO run's strides still line up.
        assert_eq!(
            &datagram[..DCID_LENGTH_OFFSET],
            &[0xc0, 0x00, 0x00, 0x00, 0x01]
        );
    }

    /// Total on any input, including one with no room for the byte it writes.
    #[test]
    fn blinding_a_datagram_too_short_to_carry_a_header_changes_nothing() {
        for length in 0..DCID_LENGTH_OFFSET {
            let mut datagram = vec![0xc0; length];
            blind(&mut datagram);
            assert_eq!(datagram, vec![0xc0; length]);
        }
    }
}
