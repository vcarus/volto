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
//!   which [`crate::quic::Server::bind`] takes unchanged, supports seven:
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
//!   authenticates. RFC 9000 §7.2 gives a client's first Initial a floor of
//!   eight bytes. Every later Initial of an admitted handshake is addressed by
//!   the eight bytes this endpoint chose, and so is the one a Retry supplies,
//!   so nothing legitimate is this shape. quinn's own rule is ahead of its
//!   decryption as well, in `early_validate_first_packet`, and it answers this
//!   shape with the CONNECTION_CLOSE named above before it reads a frame.
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
//!   the flight it belongs to was judged when it started.
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
//! is a header quinn's own decoder rejects before it looks at the version, the
//! type or anything else. It rejects it by returning, not by answering.
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
//! Nor is any of this traffic obfuscation. The gate hides that a *service* is
//! here from somebody who does not know the name to ask for; it does nothing
//! about what a connection looks like once one is open.
//!
//! # Short headers
//!
//! The gate passes every short-header packet. Telling a live connection's
//! packets from a stranger's needs the set of live connection IDs, which lives
//! inside quinn, and filtering on the four-tuple instead would break the
//! connection migration a mobile client behind a relay's NAT depends on. A
//! short-header packet for a connection the endpoint does not hold draws no
//! Stateless Reset (RFC 9000 §10.3) all the same, because the connection ID
//! generator in `quic::cid` makes quinn drop it without a reply; that module
//! says how, and what it costs a client.
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
//! dropped and nothing is sent. The judgement is `hold::judge`:
//!
//! * an ECH extension the key opens is admitted, unless the same HPKE `enc`
//!   was admitted before from another address, which is a copy of somebody
//!   else's flight. The name in the clear is not looked at;
//! * an ECH extension the key does not open is dropped, whatever
//!   `[security] require_ech` says. This is our own rule and a deviation from
//!   RFC 9849 §7.1, which has a server go on with the outer ClientHello and so
//!   send the ECHConfigList back as `retry_configs`;
//! * no ECH extension is dropped under `require_ech`, and otherwise judged by
//!   its name as above, against the whole ClientHello rather than one packet.
//!
//! An Initial that carries no ClientHello (a PING, a lone CRYPTO frame past
//! offset 0, a ClientHello cut short) is held like any other and, when nothing
//! completes it, dropped. So the acknowledgements of *What is left uncovered*
//! are not sent while a key is configured.
//!
//! **Bounds.** Everything held came from a peer that has not authenticated,
//! so the hold is bounded in time, in number and in bytes at once, each by a
//! constant in `hold` with its reason: a flight is held for at most
//! `HOLD_LIFETIME`, at most `HOLD_FLIGHTS` flights are held at once, one
//! flight holds at most `HOLD_FLIGHT_BYTES` and reassembles at most
//! `HOLD_HELLO_BYTES` of CRYPTO stream, and the hold as a whole, released
//! datagrams included, at most `HOLD_TOTAL_BYTES`. A full table, or a hold out
//! of bytes, evicts its oldest flight. No timer runs: a flight past its
//! lifetime is never released, and it is freed by the next first Initial that
//! reaches the hold, which is when its room could be wanted.
//!
//! **Release.** A released datagram has to come back in a later receive call,
//! since the batch it arrived in has already been handed over with it blinded.
//! `poll_recv` therefore hands out released datagrams first, one to a buffer
//! with a stride of its own length, before it reads the socket again. A
//! release only ever happens inside a call that returns `Ready`, and quinn
//! calls again after every `Ready`, so a release needs no waker.
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

use std::borrow::Cow;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, ConnectionId, UdpPoller};
use tracing::debug;

use crate::datagram::peek_varint;
use crate::logfmt::escaped_bytes;
use crate::tls::EchKey;

mod hold;

#[doc(hidden)]
pub use hold::Dropped;
use hold::{Arrival, Memory, Taken};

/// The QUIC version this server speaks, as it appears in a long header.
const QUIC_V1: u32 = 0x0000_0001;

/// Header Form bit: set on a long header, clear on a short one (RFC 9000 §17).
const LONG_HEADER_FORM: u8 = 0x80;

/// Long Packet Type bits of the first byte (RFC 9000 §17.2).
const LONG_PACKET_TYPE: u8 = 0x30;

/// The Long Packet Type of an Initial packet in QUIC v1 (RFC 9000 §17.2.2).
const INITIAL_PACKET_TYPE: u8 = 0x00;

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
/// The floor is applied to every Initial the gate parses rather than only to one
/// it can open, because quinn applies its own the same way: its
/// `early_validate_first_packet` refuses a shorter one before any decryption.
/// Nothing legitimate arrives under it, because every Initial after a client's
/// first is addressed by the eight bytes this endpoint's own generator chose.
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

/// Offset of the Destination Connection ID Length field in a long header.
///
/// One byte of flags plus four of version (RFC 9000 §17.2).
const DCID_LENGTH_OFFSET: usize = 5;

/// The QUIC frame types an Initial packet may carry (RFC 9000 §17.2.2).
const FRAME_PADDING: u64 = 0x00;
const FRAME_PING: u64 = 0x01;
const FRAME_ACK: u64 = 0x02;
const FRAME_ACK_ECN: u64 = 0x03;
const FRAME_CRYPTO: u64 = 0x06;
const FRAME_CONNECTION_CLOSE: u64 = 0x1c;

/// The hosts a handshake may name, compared the way a name is compared.
///
/// Held as normalised strings (lowercased, with a trailing root dot removed),
/// so that the normalisation happens once at load rather than once per
/// Initial packet, and so that both gates can only ever agree: this one, and
/// the ClientHello callback of the server's TLS (`tls::awslc`), which calls
/// [`Names::accepts`] too.
#[derive(Debug)]
pub struct Names {
    names: Vec<String>,
}

impl Names {
    /// Normalises what the configuration file said.
    pub fn new(configured: &[String]) -> Self {
        Self {
            names: configured.iter().map(|name| normalise(name)).collect(),
        }
    }

    /// Whether the gate is off, which an empty list is.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Whether `name` is one of them.
    ///
    /// DNS names are case-insensitive and a trailing dot is the same name
    /// spelled absolutely, so both are normalised away on each side: the held
    /// side at load, this side without an allocation, since the held names are
    /// already lowercase. Nothing else is: no wildcards, no suffix matching. A
    /// name that is not on the list is not this server's.
    pub fn accepts(&self, name: &str) -> bool {
        let name = root_relative(name);
        self.names
            .iter()
            .any(|held| held.eq_ignore_ascii_case(name))
    }
}

/// `name` without its trailing root dot, which is the same name spelled
/// relative to the root.
///
/// The whole of the rule "a configured host name may end in a root dot", in one
/// place, because its four callers have to agree. If one of them removed
/// *every* trailing dot where the others remove one, `expected_sni =
/// ["host.tw.."]` would be held by the gate as `host.tw.`, a form no
/// ClientHello can carry, because RFC 6066 §3 has the name represented "without
/// a trailing dot". It would then be judged covered by the certificate as
/// `host.tw`, so the D106 warning that exists for exactly this silent typo
/// would not fire.
///
/// One dot and no more, because a second dot is an empty label rather than a
/// spelling of the root. `Config::validate` refuses those outright, so the four
/// callers agree on every name that can reach them.
pub(crate) fn root_relative(name: &str) -> &str {
    name.trim_suffix('.')
}

/// Lowercased, with one trailing root dot removed.
fn normalise(name: &str) -> String {
    root_relative(name).to_ascii_lowercase()
}

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

/// What a change of policy from `old` to `new` does to the hold and the
/// replay record: a new ECH key empties the record, and no key empties the
/// hold. [`Expected::set`] says why.
fn follow(memory: &mut Memory, old: &Policy, new: &Policy) {
    if !same_key(old.ech.as_deref(), new.ech.as_deref()) {
        memory.replay.clear();
    }
    if new.ech.is_none() {
        memory.hold.clear();
    }
}

/// The policy the gate is enforcing right now, and the state it keeps.
///
/// A `SIGHUP` replaces the policy, so the handle is shared rather than copied:
/// the socket wrapper is built once at bind time and has to see a reload
/// without being rebuilt, since rebuilding it would mean rebinding the port.
///
/// Read once per receive batch rather than once per datagram, and written once
/// per reload, so a plain `RwLock` around an `Arc` is all the sharing this needs.
///
/// The flag beside it answers "is the gate on at all" without taking the lock,
/// because a gate that is off is the shipped default. A gate that is off then
/// costs a receive batch one atomic load rather than a read guard, an `Arc`
/// clone and its drop.
///
/// The hold and the replay record live here too, rather than in [`Gate`],
/// because a reload has to reach them: a new ECH key clears the replay record,
/// and a policy without a key clears the hold.
#[derive(Clone)]
pub struct Expected(Arc<Held>);

/// The policy, the flag that says whether it is on, and the hold.
struct Held {
    policy: RwLock<Arc<Policy>>,
    /// Whether `policy` is on. Written after `policy`, read before it.
    any: AtomicBool,
    /// The hold and the replay record, which only a policy with a key uses.
    memory: Mutex<Memory>,
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
            policy: RwLock::new(Arc::new(policy)),
            any,
            memory: Mutex::new(Memory::new()),
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
    /// happen under the hold's lock, with the policy swapped inside it, and
    /// `Gate::screen_holding` reads the policy again once it holds that lock.
    /// So no flight is held, judged or recorded under a policy that is no
    /// longer in force, however a receive call and a reload interleave: a
    /// flight held just before the reload is in the hold the reload clears,
    /// and one that arrives just after is judged by the new policy. Without
    /// that second read, a receive call that had read the old policy before a
    /// reload removed the key could hold flights after the reload had cleared
    /// the hold, and with no key nothing would ever expire them.
    pub fn set(&self, policy: impl Into<Policy>) {
        let policy = Arc::new(policy.into());
        let any = policy.is_on();
        {
            let mut memory = self.memory();
            follow(&mut memory, &self.current(), &policy);
            *self
                .0
                .policy
                .write()
                .unwrap_or_else(PoisonError::into_inner) = policy;
        }
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
    ///
    /// Poisoning would mean a panic while swapping an `Arc`; the value itself is
    /// immutable, so there is nothing to observe half-written.
    pub fn current(&self) -> Arc<Policy> {
        self.0
            .policy
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The hold and the replay record.
    ///
    /// Nothing that runs under this lock may panic on any input, because a
    /// panic under `poll_recv` is not recovered anywhere. `poll_recv` runs
    /// inside quinn's endpoint driver, which holds the endpoint's own mutex
    /// across it (quinn 0.11.12 `src/endpoint.rs`, `EndpointDriver::poll`).
    /// The panic unwinds out of that function and poisons that mutex. tokio
    /// drops the driver while it unwinds, and quinn's `Drop for EndpointDriver`
    /// calls `lock().unwrap()` on the poisoned mutex. A panic in a destructor
    /// during unwinding aborts the process, so every connection ends with it.
    /// This was observed on 2026-11-20 with an underflow in the hold's byte
    /// count. Taking over a poisoned guard here therefore matters only for a
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
pub struct Gate {
    inner: Arc<dyn AsyncUdpSocket>,
    expected: Expected,
    /// The judging half, which is everything that is not the socket.
    judge: Judge,
}

impl Gate {
    /// Wraps `inner`, judging against `expected`.
    pub fn new(
        inner: Arc<dyn AsyncUdpSocket>,
        expected: Expected,
        crypto: Arc<dyn quinn::crypto::ServerConfig>,
    ) -> Self {
        Self {
            inner,
            expected,
            judge: Judge { crypto },
        }
    }

    /// Judges one datagram without the hold and blinds it if it is refused.
    fn screen(&self, remote: SocketAddr, datagram: &mut [u8], expected: &Names) {
        let Verdict::Refuse(refusal) = self.judge.judge(datagram, expected) else {
            return;
        };
        log_refusal(remote, &refusal);
        blind(datagram);
    }

    /// Judges one datagram with the hold, which an ECH key turns on, and blinds
    /// it unless it passes.
    ///
    /// A first Initial is copied into the hold before it is blinded in the
    /// batch, so quinn never sees it there; if its flight is admitted, the copy
    /// is what quinn receives, from the next receive call. The hold's lock and
    /// the clock are taken the first time a batch has a first Initial in it,
    /// and not at all for a batch of short headers, which is the data path.
    ///
    /// The policy the hold judges by is read again once the lock is held,
    /// rather than taken from the batch: [`Expected::set`] says why. When the
    /// policy read then has no key, a reload removed it after this batch began,
    /// and the datagram is judged as the stateless gate judges it.
    fn screen_holding<'a>(
        &'a self,
        meta: &RecvMeta,
        datagram: &mut [u8],
        held: &mut Option<(MutexGuard<'a, Memory>, Arc<Policy>)>,
        now: &mut Option<Instant>,
    ) {
        let (dcid, frames) = match self.judge.classify(datagram, true) {
            Classified::Pass => return,
            Classified::Refuse(refusal) => {
                log_refusal(meta.addr, &refusal);
                blind(datagram);
                return;
            }
            Classified::Opened { dcid, frames, more } => (dcid, (frames, more)),
        };
        let (memory, policy) = held.get_or_insert_with(|| {
            let memory = self.expected.memory();
            (memory, self.expected.current())
        });
        if policy.ech.is_none() {
            if policy.is_on() {
                self.screen(meta.addr, datagram, &policy.names);
            }
            return;
        }
        let now = *now.get_or_insert_with(Instant::now);
        let arrival = Arrival {
            now,
            meta: *meta,
            datagram,
            dcid,
        };
        if hold_opened(memory, arrival, &frames.0, &frames.1, policy, &mut log_drop)
            == Screened::Released
        {
            self.expected.0.releasing.store(true, Ordering::Release);
        }
        blind(datagram);
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

/// What the hold made of one opened first Initial, shared by the socket path
/// and [`Screening`].
///
/// `frames` are those of the datagram's first packet and `more` those of the
/// Initial packets of the same flight coalesced behind it. A packet whose
/// frames do not parse, or carry a type no Initial packet may, makes the whole
/// flight one the hold drops: quinn would close the connection over it, which
/// is a reply.
fn hold_opened(
    memory: &mut Memory,
    arrival: Arrival<'_>,
    frames: &[u8],
    more: &[BytesMut],
    policy: &Policy,
    report: &mut dyn FnMut(SocketAddr, Dropped),
) -> Screened {
    let mut fragments = Vec::new();
    let mut whole = true;
    for payload in std::iter::once(frames).chain(more.iter().map(|m| &m[..])) {
        match crypto_frames(payload) {
            Some(walk) if walk.whole => fragments.extend(walk.fragments),
            _ => whole = false,
        }
    }
    let fragments = whole.then_some(fragments.as_slice());
    match memory.take(arrival, fragments, policy, report) {
        Some(Taken::Held) => Screened::Held,
        Some(Taken::Released) => Screened::Released,
        None => Screened::Dropped,
    }
}

/// The half of the gate that judges datagrams, held by [`Gate`] and needing no
/// socket.
///
/// Separate from the socket because none of it reads one: a verdict is a
/// function of the datagram's bytes, the list in force and the Initial keys.
/// So judging is reachable without a bound port (through the [`judgement`]
/// seam, by a fuzz target and by the tests that spell packets), and the receive
/// path is left as the only thing that has to know about batches, strides and
/// blinding.
struct Judge {
    /// The source of Initial keys.
    ///
    /// Held from bind time and never reloaded, because the initial secrets do
    /// not depend on the certificate: RFC 9001 §5.2 derives them from the
    /// Destination Connection ID in the client's own packet and a salt fixed by
    /// the version. What a `SIGHUP` can change (the certificate, the key) is not
    /// an input to any of it.
    crypto: Arc<dyn quinn::crypto::ServerConfig>,
}

/// What [`Judge::classify`] made of a datagram.
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
        /// behind it, when [`Judge::classify`] was asked for them.
        more: Vec<BytesMut>,
    },
}

impl Judge {
    /// What should happen to one datagram, as far as it can be said without
    /// reading its ClientHello: passed, refused, or opened as a first Initial.
    ///
    /// `coalesced` asks for the Initial packets of the same flight behind the
    /// first as well ([`coalesced_frames`]), which only the hold reads.
    fn classify(&self, datagram: &[u8], coalesced: bool) -> Classified {
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
        // scan is looking for. D106. For the six draft versions quinn's default
        // `EndpointConfig` also supports, refusing removes the connection rather
        // than the reply; the module documentation says so in full.
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

        let Some((keys, frames)) = self.decrypt(datagram, &header) else {
            // Authentication failed under the keys this packet's own
            // Destination Connection ID derives. That is every client Initial
            // after the server has answered: the client has switched to the
            // server's connection ID while its Initial keys stay those of its
            // first packet, so such a packet is an acknowledgement or a later
            // fragment of a first flight this gate already judged. The
            // Handshake packet that carries the client's Finished is often
            // coalesced behind it, so dropping the datagram would cost every
            // admitted handshake a probe timeout. A packet that is none of that
            // fails quinn's own decryption and is dropped there without a reply.
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
            dcid: ConnectionId::new(&datagram[header.dcid.clone()]),
            frames,
            more,
        }
    }

    /// What should happen to one datagram without the hold: its ClientHello is
    /// judged by its name, from what its first packet holds.
    fn judge(&self, datagram: &[u8], expected: &Names) -> Verdict {
        let frames = match self.classify(datagram, false) {
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
            FirstFlight::Named(name) => match std::str::from_utf8(name) {
                Ok(text) if expected.accepts(text) => Verdict::Pass,
                // The verdict outlives the datagram it was judged from, so the
                // refusal takes the copy the pass path does not need.
                _ => Verdict::Refuse(Refusal::OtherName(name.to_vec())),
            },
        }
    }

    /// Removes header protection and packet protection from an Initial packet,
    /// returning the Initial keys it opened under and its frames.
    ///
    /// `None` is either a packet too short for the keys to be applied (one
    /// quinn could not read either) or an authentication failure under the
    /// keys this packet's own Destination Connection ID derives: a later
    /// Initial of a handshake in progress, keyed by the client's first packet
    /// instead, or a packet that only says it is a QUIC v1 Initial. The caller
    /// passes both through, because quinn tells them apart with the state this
    /// gate lacks and drops the second kind without a reply.
    fn decrypt(
        &self,
        datagram: &[u8],
        header: &InitialHeader,
    ) -> Option<(quinn::crypto::Keys, BytesMut)> {
        // quinn's header key takes the whole packet and reads its sample from
        // four bytes past the packet number, so a packet too short for that
        // would panic rather than fail. RFC 9001 §5.4.2 puts the sample there.
        //
        // The half of that test which does not need a cipher is asked first,
        // above the key derivation, because deriving Initial secrets is nearly
        // the whole cost of judging a packet and a packet with no room for the
        // four bytes is refused under every cipher there is. No packet changes
        // verdict: a sample end past the packet end follows from this one.
        let number_end_limit = header.packet_number_offset.checked_add(4)?;
        if number_end_limit > header.packet_end {
            return None;
        }

        // The keys are a function of the Destination Connection ID and the
        // version alone, which is what makes this possible at all without any
        // connection state.
        //
        //= https://www.rfc-editor.org/rfc/rfc9001#section-5.2
        //# Initial packets apply the packet protection process, but use a secret
        //# derived from the Destination Connection ID field from the client's
        //# first Initial packet.
        let keys = self
            .crypto
            .initial_keys(QUIC_V1, &ConnectionId::new(&datagram[header.dcid.clone()]))
            .ok()?;
        let frames = open_with(&keys, datagram, header)?;
        Some((keys, frames))
    }
}

/// The frames of every Initial packet coalesced behind the first one of
/// `datagram`, whose header is `first` and which opened under `keys`, that
/// belongs to the same flight.
///
/// Only the hold asks for these, because only the hold reads a flight rather
/// than a packet: a client may put two Initial packets of one first flight
/// into one datagram, and the ClientHello is then not whole without the
/// second. A packet behind the first belongs to the flight when it is a
/// version 1 Initial with the same Destination Connection ID, and then it
/// opens under the same keys, which RFC 9001 §5.2 derives from that connection
/// ID, so the keys the first packet opened under are used again rather than
/// derived a second time. One that does not open is skipped, as quinn skips
/// it. The walk stops at the first packet that is anything else, because RFC
/// 9000 §12.2 lets a receiver route on the first packet alone and a short
/// header can only be last. A datagram with nothing behind its first packet,
/// which is every first flight quinn and Surge send, costs nothing here.
fn coalesced_frames(
    keys: &quinn::crypto::Keys,
    datagram: &[u8],
    first: &InitialHeader,
) -> Vec<BytesMut> {
    let mut frames = Vec::new();
    if first.packet_end >= datagram.len() {
        return frames;
    }
    let dcid = &datagram[first.dcid.clone()];
    let mut at = first.packet_end;
    while let Some(packet) = datagram.get(at..).filter(|rest| !rest.is_empty()) {
        let Some(&byte) = packet.first() else { break };
        if byte & LONG_HEADER_FORM == 0
            || byte & LONG_PACKET_TYPE != INITIAL_PACKET_TYPE
            || packet.get(1..5) != Some(&QUIC_V1.to_be_bytes()[..])
        {
            break;
        }
        let Some(header) = InitialHeader::parse(packet) else {
            break;
        };
        if packet.get(header.dcid.clone()) != Some(dcid) {
            break;
        }
        if let Some(opened) = open_with(keys, packet, &header) {
            frames.push(opened);
        }
        at += header.packet_end;
    }
    frames
}

/// Removes header protection and packet protection from the Initial packet at
/// the start of `datagram`, whose header is `header`, under `keys`.
///
/// `None` for a packet too short for the keys to be applied or one that does
/// not authenticate; [`Judge::decrypt`] says what each means.
fn open_with(
    keys: &quinn::crypto::Keys,
    datagram: &[u8],
    header: &InitialHeader,
) -> Option<BytesMut> {
    let number_end_limit = header.packet_number_offset.checked_add(4)?;

    // The other half, which the cipher's sample size decides.
    let sample_end = number_end_limit.checked_add(keys.header.remote.sample_size())?;
    if sample_end > header.packet_end {
        return None;
    }

    // Only the header and the sample it is unmasked with are copied. Header
    // protection reads up to `sample_end` and writes five bytes inside it,
    // the first byte and the packet number, so the rest of the packet has
    // no reason to be moved: the payload below is taken from the datagram
    // where it already is, and the associated data the AEAD needs is inside
    // this copy.
    let mut head = datagram[..sample_end].to_vec();
    keys.header
        .remote
        .decrypt(header.packet_number_offset, &mut head);

    // The two bits the header protection was hiding.
    let number_length = usize::from(head[0] & 0x03) + 1;
    let number_end = header.packet_number_offset.checked_add(number_length)?;
    if number_end > header.packet_end {
        return None;
    }

    // The truncated packet number, used as the full one. A client's Initial
    // packet numbers start at zero and are still single digits by the time
    // its first flight is complete, so the encoded bits are the whole number.
    // RFC 9000 §17.1 makes the sender include enough of them for a peer
    // that has acknowledged nothing to reconstruct it, and there is nothing
    // to acknowledge yet.
    let mut number = 0u64;
    for byte in &head[header.packet_number_offset..number_end] {
        number = (number << 8) | u64::from(*byte);
    }

    // The AEAD tag is the tail of the payload; a "packet" too short to hold
    // one is not one, and the check is here rather than left to the cipher
    // so that this function is total on its own terms.
    if header.packet_end - number_end < keys.packet.remote.tag_len() {
        return None;
    }

    let mut frames = BytesMut::from(&datagram[number_end..header.packet_end]);
    keys.packet
        .remote
        .decrypt(number, &head[..number_end], &mut frames)
        .ok()?;
    Some(frames)
}

impl fmt::Debug for Gate {
    /// Hand-written because neither the crypto configuration the judge holds
    /// nor the trait object holding it is `Debug`, and `AsyncUdpSocket` requires
    /// one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gate")
            .field("inner", &self.inner)
            .field("expected", &self.expected)
            .finish_non_exhaustive()
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
        // and takes neither the lock nor a clone of the policy.
        if !self.expected.any() {
            return Poll::Ready(Ok(count));
        }

        let policy = self.expected.current();
        if !policy.is_on() {
            return Poll::Ready(Ok(count));
        }

        let mut held = None;
        let mut now = None;
        for (meta, buf) in metas.iter().zip(bufs.iter_mut()).take(count) {
            each_datagram(meta, buf, |datagram| {
                if policy.ech.is_some() {
                    self.screen_holding(meta, datagram, &mut held, &mut now);
                } else {
                    self.screen(meta.addr, datagram, &policy.names);
                }
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
fn each_datagram(meta: &RecvMeta, buf: &mut [u8], mut screen: impl FnMut(&mut [u8])) {
    let len = meta.len.min(buf.len());
    let stride = meta.stride.max(1);
    let mut at = 0;
    while at < len {
        let end = at.saturating_add(stride).min(len);
        screen(&mut buf[at..end]);
        at = end;
    }
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
/// [`MAX_CONNECTION_ID`]). That field is read before the version, the packet
/// type, the token or the payload, so the rejection does not depend on anything
/// else in the packet being well formed, and quinn's own decoder answers it by
/// returning rather than by replying. A datagram too short to hold that byte is
/// one quinn already drops without a reply.
fn blind(datagram: &mut [u8]) {
    if let Some(length) = datagram.get_mut(DCID_LENGTH_OFFSET) {
        *length = IMPOSSIBLE_CID_LENGTH;
    }
}

/// Where the interesting parts of a long header are.
struct InitialHeader {
    /// The Destination Connection ID, as a range into the datagram.
    dcid: std::ops::Range<usize>,
    /// Where the Packet Number field starts.
    packet_number_offset: usize,
    /// One past the last byte of this packet, which may be followed by more.
    packet_end: usize,
}

impl InitialHeader {
    /// Reads an Initial header, or `None` if it does not fit what arrived.
    ///
    /// Every field is bounds-checked against the datagram rather than trusted,
    /// because all of it is attacker-chosen and none of it is authenticated yet.
    fn parse(datagram: &[u8]) -> Option<Self> {
        let mut at = DCID_LENGTH_OFFSET;

        let dcid_length = usize::from(*datagram.get(at)?);
        at += 1;
        if dcid_length > MAX_CONNECTION_ID {
            return None;
        }
        let dcid = at..at.checked_add(dcid_length)?;
        datagram.get(dcid.clone())?;
        at = dcid.end;

        let scid_length = usize::from(*datagram.get(at)?);
        at += 1;
        if scid_length > MAX_CONNECTION_ID {
            return None;
        }
        at = at.checked_add(scid_length)?;
        if at > datagram.len() {
            return None;
        }

        // The Token Length and Length fields are QUIC varints, the same encoding
        // `crate::datagram` reads for HTTP Datagrams (RFC 9000 §16).
        let (token_length, read) = peek_varint(datagram.get(at..)?)?;
        at = at.checked_add(read)?;
        at = at.checked_add(usize::try_from(token_length).ok()?)?;
        if at > datagram.len() {
            return None;
        }

        let (length, read) = peek_varint(datagram.get(at..)?)?;
        let packet_number_offset = at.checked_add(read)?;
        let packet_end = packet_number_offset.checked_add(usize::try_from(length).ok()?)?;
        if packet_end > datagram.len() {
            return None;
        }

        Some(Self {
            dcid,
            packet_number_offset,
            packet_end,
        })
    }
}

/// The CRYPTO frames of an Initial packet's payload, in the order they came.
struct Frames<'a> {
    /// Each frame's offset and data.
    fragments: Vec<(u64, &'a [u8])>,
    /// Whether the walk reached the end of the payload, rather than stopping
    /// at a frame type RFC 9000 §17.2.2 does not allow in an Initial packet.
    whole: bool,
}

/// Walks an Initial packet's frames and collects its CRYPTO frames.
///
/// `None` is a frame whose fields do not fit the payload. Frames are walked
/// rather than searched for, because a frame's length is implied by its type
/// and skipping one wrongly would find CRYPTO data that is not there. Only the
/// frame types RFC 9000 §17.2.2 allows in an Initial packet are understood;
/// anything else ends the walk with whatever was found so far, and says so.
fn crypto_frames(payload: &[u8]) -> Option<Frames<'_>> {
    let mut fragments: Vec<(u64, &[u8])> = Vec::new();
    let mut at = 0usize;

    while at < payload.len() {
        let (frame, read) = peek_varint(&payload[at..])?;
        at += read;

        match frame {
            FRAME_PADDING | FRAME_PING => {}
            FRAME_ACK | FRAME_ACK_ECN => {
                // Largest Acknowledged, ACK Delay, ACK Range Count, First ACK
                // Range, then two varints per additional range, then three more
                // for the ECN counts (RFC 9000 §19.3).
                at = skip_varints(payload, at, 2)?;
                let (ranges, read) = peek_varint(payload.get(at..)?)?;
                at += read;
                at = skip_varints(payload, at, 1)?;
                let ranges = usize::try_from(ranges).ok()?.checked_mul(2)?;
                at = skip_varints(payload, at, ranges)?;
                if frame == FRAME_ACK_ECN {
                    at = skip_varints(payload, at, 3)?;
                }
            }
            FRAME_CRYPTO => {
                let (offset, read) = peek_varint(payload.get(at..)?)?;
                at += read;
                let (length, read) = peek_varint(payload.get(at..)?)?;
                at += read;
                let end = at.checked_add(usize::try_from(length).ok()?)?;
                fragments.push((offset, payload.get(at..end)?));
                at = end;
            }
            FRAME_CONNECTION_CLOSE => {
                // Error Code, Frame Type, Reason Phrase Length, Reason Phrase.
                at = skip_varints(payload, at, 2)?;
                let (reason, read) = peek_varint(payload.get(at..)?)?;
                at += read;
                at = at.checked_add(usize::try_from(reason).ok()?)?;
                if at > payload.len() {
                    return None;
                }
            }
            // Not a frame type an Initial packet may carry. Stop reading rather
            // than guess: what follows is not frames as we understand them.
            _ => {
                return Some(Frames {
                    fragments,
                    whole: false,
                });
            }
        }
    }

    Some(Frames {
        fragments,
        whole: true,
    })
}

/// The CRYPTO stream bytes an Initial packet carries from offset 0 onwards.
///
/// `None` means the packet has no CRYPTO frame starting at offset 0 (an
/// acknowledgement, or a retransmitted middle of a first flight), which is the
/// case the stateless gate passes through rather than judging. The frames are
/// those [`crypto_frames`] finds.
fn crypto_stream_prefix(payload: &[u8]) -> Option<Cow<'_, [u8]>> {
    let mut fragments = crypto_frames(payload)?.fragments;

    // Sorted and appended while contiguous, so a first flight split across
    // several CRYPTO frames in one packet reads as one stream.
    fragments.sort_by_key(|(offset, _)| *offset);

    // In practice there is exactly one frame and it starts at offset 0, which
    // is a first flight that fits in one packet, so that case is borrowed out
    // of the decrypted frames rather than copied into a second buffer.
    if let [(0, data)] = fragments.as_slice() {
        return (!data.is_empty()).then_some(Cow::Borrowed(*data));
    }

    let mut stream: Vec<u8> = Vec::new();
    for (offset, data) in fragments {
        let offset = usize::try_from(offset).ok()?;
        if offset > stream.len() {
            break;
        }
        // A retransmission may overlap what is already here.
        let skip = stream.len() - offset;
        if let Some(fresh) = data.get(skip..) {
            stream.extend_from_slice(fresh);
        }
    }

    (!stream.is_empty()).then_some(Cow::Owned(stream))
}

/// Advances past `count` varints, or `None` if they do not all fit.
fn skip_varints(payload: &[u8], mut at: usize, count: usize) -> Option<usize> {
    for _ in 0..count {
        let (_, read) = peek_varint(payload.get(at..)?)?;
        at = at.checked_add(read)?;
    }
    Some(at)
}

/// What a first flight's CRYPTO bytes said, and the reader that says it.
///
/// Both live in [`crate::hello`], the one ClientHello parser the gate, the TLS
/// provider and the tests share. They are re-exported here, hidden and public,
/// for the callers that reached them through this module before: the fuzz
/// target and `tests/it_gate_shapes.rs` hand CRYPTO bytes to the reader
/// directly, because the only other way to reach it is to spell a whole
/// Initial packet that authenticates, which a fuzzer cannot do by luck.
#[doc(hidden)]
pub use crate::hello::{FirstFlight, first_flight};

// The seams `fuzz/fuzz_targets/gate.rs`, `fuzz/fuzz_targets/hold.rs` and
// `tests/it_gate_shapes.rs` reach this module through (D83): [`judgement`] and
// [`Screening`], [`first_flight`] above, and [`nameless_crypto`] for building
// the packets they judge.
//
// Everything above judges bytes an internet scanner chose, before any peer has
// authenticated and before quinn has seen them, which is exactly the shape a
// coverage-guided fuzzer is for. No judging seam is an entry point of its own:
// each calls the functions the socket path calls, so a finding here is a
// finding in what the server runs.

/// The hold's bounds, for the fuzz target and the tests that assert them.
#[doc(hidden)]
pub use hold::{
    HOLD_FLIGHT_BYTES, HOLD_FLIGHTS, HOLD_HELLO_BYTES, HOLD_LIFETIME, HOLD_TOTAL_BYTES,
    REPLAY_ENTRIES,
};

/// The judge every seam shares, built once per process.
fn seam_judge() -> &'static Judge {
    static JUDGE: OnceLock<Judge> = OnceLock::new();
    JUDGE.get_or_init(|| Judge {
        crypto: nameless_crypto(),
    })
}

/// The gate's verdict on one datagram, for the fuzz target and the tests.
///
/// This is `Gate::screen`'s own `Judge::judge`, over a judge built once per
/// process, so the judgement a fuzzer explores is the judgement a received
/// datagram gets. The socket, the batch walk and the blinding are the only
/// parts left out, and none of them is a parser.
///
/// Hidden rather than API: nothing outside `fuzz/` and `tests/` has any reason
/// to call it, and nothing in this crate does.
#[doc(hidden)]
pub fn judgement(datagram: &[u8], expected: &Names) -> Verdict {
    seam_judge().judge(datagram, expected)
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

/// The gate with the hold, driven one datagram at a time, for the fuzz target
/// and the tests.
///
/// It runs the receive path's own code: [`Judge::classify`], then the hold
/// through the function `Gate::screen_holding` calls, under a policy the
/// caller gives and a clock the caller moves. The socket, the batch walk, the
/// blinding and the delivery into quinn's buffers are what is left out.
#[doc(hidden)]
pub struct Screening {
    policy: Policy,
    memory: Memory,
    epoch: Instant,
}

impl Screening {
    /// A gate under `policy` with an empty hold.
    pub fn new(policy: impl Into<Policy>) -> Self {
        Self {
            policy: policy.into(),
            memory: Memory::new(),
            epoch: Instant::now(),
        }
    }

    /// Screens `datagram` from `from`, received `after` the screening began.
    ///
    /// Returns what became of it and every flight the hold dropped on the
    /// way, with the address it came from. A policy without an ECH key is the
    /// stateless gate, as on the socket path.
    pub fn receive(
        &mut self,
        after: Duration,
        from: SocketAddr,
        datagram: &[u8],
    ) -> (Screened, Vec<(SocketAddr, Dropped)>) {
        let mut drops = Vec::new();
        let judge = seam_judge();
        if self.policy.ech.is_none() {
            let screened = match judge.judge(datagram, &self.policy.names) {
                Verdict::Pass => Screened::Passed,
                Verdict::Refuse(refusal) => Screened::Refused(refusal),
            };
            return (screened, drops);
        }
        let screened = match judge.classify(datagram, true) {
            Classified::Pass => Screened::Passed,
            Classified::Refuse(refusal) => Screened::Refused(refusal),
            Classified::Opened { dcid, frames, more } => {
                let meta = RecvMeta {
                    addr: from,
                    len: datagram.len(),
                    stride: datagram.len(),
                    ..RecvMeta::default()
                };
                let arrival = Arrival {
                    now: self.epoch + after,
                    meta,
                    datagram,
                    dcid,
                };
                hold_opened(
                    &mut self.memory,
                    arrival,
                    &frames,
                    &more,
                    &self.policy,
                    &mut |from, why| drops.push((from, why)),
                )
            }
        };
        (screened, drops)
    }

    /// Takes the datagrams of admitted flights, in the order quinn would get
    /// them, with the address each came from.
    pub fn released(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        std::iter::from_fn(|| self.memory.hold.pop_released())
            .map(|held| (held.meta.addr, held.bytes))
            .collect()
    }

    /// How many flights are held.
    pub fn flights(&self) -> usize {
        self.memory.hold.flights()
    }

    /// Every byte the hold occupies, as its byte bound counts.
    pub fn held_bytes(&self) -> usize {
        self.memory.hold.bytes()
    }

    /// Every byte the hold occupies, summed from what it holds. Equal to
    /// [`Screening::held_bytes`] after every datagram, or the count has
    /// drifted.
    pub fn recounted_bytes(&self) -> usize {
        self.memory.hold.recount()
    }

    /// How many `enc` values the replay record holds.
    pub fn replay_entries(&self) -> usize {
        self.memory.replay.len()
    }

    /// Replaces the policy as a reload does, with the same effect on the
    /// replay record and the hold as [`Expected::set`].
    pub fn set(&mut self, policy: impl Into<Policy>) {
        let policy = policy.into();
        follow(&mut self.memory, &self.policy, &policy);
        self.policy = policy;
    }
}

/// A TLS configuration with no identity at all, as a source of Initial keys.
///
/// Initial keys come from the client's Destination Connection ID and a salt
/// fixed by the version (RFC 9001 §5.2, quoted at `Judge::decrypt`), never
/// from the server's certificate, which is what `Judge::crypto` already relies
/// on for `SIGHUP`. So a configuration carrying no certificate derives exactly
/// the keys the running server derives, and [`judgement`], the fuzz target and
/// the tests that spell Initial packets need no key material, no file and no
/// clock to open or to build the packets the real gate opens. The resolver is
/// never asked for anything: nothing here starts a TLS session.
///
/// The two `expect`s cannot fail: rustls's aws-lc-rs provider supports TLS
/// 1.3, and a TLS 1.3 configuration carries the initial cipher suite quinn
/// asks for.
#[doc(hidden)]
pub fn nameless_crypto() -> Arc<dyn quinn::crypto::ServerConfig> {
    /// A resolver with nothing to present.
    #[derive(Debug)]
    struct NoIdentity;

    impl rustls::server::ResolvesServerCert for NoIdentity {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("the aws-lc-rs crypto provider supports TLS 1.3")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(NoIdentity));

    Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
            .expect("a TLS 1.3 configuration carries an initial cipher suite"),
    )
}

/// The most frame bytes [`sealed_initial`] carries: what a two-byte Length
/// field leaves after the one-byte packet number and the AEAD tag.
#[doc(hidden)]
pub const SEALED_FRAMES_MAX: usize = 0x3fff - 1 - 16;

/// A first Initial carrying `frames`, sealed under the keys its own
/// Destination Connection ID `dcid` derives, for the fuzz target `hold` and
/// the test that writes its seeds.
///
/// The fuzz target cannot spell a packet that authenticates, so without this
/// it could change a held packet's bytes only by breaking its AEAD, and the
/// hold would never see frames the fuzzer chose. With it, the fuzzer chooses
/// the frames and this function seals them, with [`nameless_crypto`]'s keys,
/// which are the keys the gate opens the packet with.
///
/// The header is the plainest a client sends: QUIC v1, no Source Connection
/// ID, no token, a two-byte Length field and a one-byte packet number
/// `number`. The frames are followed by PADDING up to a 1200-byte datagram,
/// and cut at [`SEALED_FRAMES_MAX`] bytes.
#[doc(hidden)]
pub fn sealed_initial(dcid: &[u8; 8], number: u8, frames: &[u8]) -> Vec<u8> {
    let keys = seam_judge()
        .crypto
        .initial_keys(QUIC_V1, &ConnectionId::new(dcid))
        .expect("Initial keys for QUIC v1");
    let tag = keys.packet.remote.tag_len();
    let frames = &frames[..frames.len().min(SEALED_FRAMES_MAX)];

    let mut packet = vec![LONG_HEADER_FORM | 0x40 | INITIAL_PACKET_TYPE];
    packet.extend_from_slice(&QUIC_V1.to_be_bytes());
    packet.push(8);
    packet.extend_from_slice(dcid);
    packet.push(0); // no Source Connection ID
    packet.push(0); // no token
    let number_offset = packet.len() + 2;
    let payload = frames
        .len()
        .max(MIN_INITIAL_DATAGRAM - number_offset - 1 - tag);
    let length = u16::try_from(1 + payload + tag).expect("at most SEALED_FRAMES_MAX frame bytes");
    packet.extend_from_slice(&(0x4000 | length).to_be_bytes());
    packet.push(number);
    packet.extend_from_slice(frames);
    packet.resize(number_offset + 1 + payload, 0); // PADDING
    packet.resize(number_offset + 1 + payload + tag, 0); // room for the tag
    keys.packet
        .remote
        .encrypt(u64::from(number), &mut packet, number_offset + 1);
    keys.header.remote.encrypt(number_offset, &mut packet);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn a_name_is_matched_case_insensitively_and_without_its_root_dot() {
        let names = Names::new(&["Example.COM.".to_owned()]);

        assert!(names.accepts("example.com"));
        assert!(names.accepts("EXAMPLE.com"));
        assert!(names.accepts("example.com."));
        assert!(!names.accepts("www.example.com"));
        assert!(!names.accepts("example.co"));
        assert!(!names.accepts(""));
    }

    /// One dot and no more, which is what makes the four callers agree.
    ///
    /// `trim_end_matches('.')`, which this replaced in `tls::names_not_covered`,
    /// answers `host.tw` for the last two of these; the gate and the validator
    /// answered `host.tw.` and `host.tw..`, so a certificate check and a
    /// ClientHello match were run on different strings.
    #[test]
    fn only_one_trailing_dot_is_the_root() {
        assert_eq!(root_relative("host.tw"), "host.tw");
        assert_eq!(root_relative("host.tw."), "host.tw");
        assert_eq!(root_relative("host.tw.."), "host.tw.");
        assert_eq!(root_relative("host.tw..."), "host.tw..");
        assert_eq!(root_relative("."), "");
        assert_eq!(root_relative(""), "");
        // Nothing else about the name is touched: not the case, not a leading
        // dot, not an inner one.
        assert_eq!(root_relative(".Host.TW"), ".Host.TW");
    }

    #[test]
    fn an_empty_list_is_the_gate_being_off() {
        assert!(Names::new(&[]).is_empty());
        assert!(!Names::new(&["a".to_owned()]).is_empty());

        let two = Names::new(&["a".to_owned(), "b".to_owned()]);
        assert!(two.accepts("a") && two.accepts("b") && !two.accepts("c"));
    }

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

    #[test]
    fn a_crypto_frame_at_offset_zero_is_the_one_that_is_read() {
        // CRYPTO, offset 0, length 3.
        let payload = [0x06, 0x00, 0x03, b'a', b'b', b'c'];
        // One fragment at offset 0, which is every first flight that fits in one
        // packet, is borrowed out of the frames rather than copied.
        assert_matches!(crypto_stream_prefix(&payload), Some(Cow::Borrowed(b"abc")));
        assert_eq!(crypto_stream_prefix(&payload).as_deref(), Some(&b"abc"[..]));

        // The same frame at offset 1 carries no beginning to judge.
        let payload = [0x06, 0x01, 0x03, b'a', b'b', b'c'];
        assert_eq!(crypto_stream_prefix(&payload), None);
    }

    #[test]
    fn padding_and_ping_do_not_hide_the_crypto_frame() {
        let mut payload = vec![0x00; 16]; // PADDING
        payload.push(0x01); // PING
        payload.extend_from_slice(&[0x06, 0x00, 0x02, b'h', b'i']);
        payload.extend_from_slice(&[0x00; 8]); // trailing PADDING

        assert_eq!(crypto_stream_prefix(&payload).as_deref(), Some(&b"hi"[..]));
    }

    #[test]
    fn an_ack_frame_is_skipped_by_its_own_shape() {
        // ACK: largest 1, delay 0, range count 1, first range 0, then one range
        // pair (gap 0, length 0); followed by the CRYPTO frame that matters.
        let mut payload = vec![0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00];
        payload.extend_from_slice(&[0x06, 0x00, 0x01, b'x']);

        assert_eq!(crypto_stream_prefix(&payload).as_deref(), Some(&b"x"[..]));
    }

    #[test]
    fn two_crypto_frames_are_joined_in_offset_order() {
        let mut payload = vec![0x06, 0x02, 0x02, b'c', b'd']; // offset 2
        payload.extend_from_slice(&[0x06, 0x00, 0x02, b'a', b'b']); // offset 0

        assert_eq!(
            crypto_stream_prefix(&payload).as_deref(),
            Some(&b"abcd"[..])
        );
    }

    /// A gap is not filled in: what is returned is the contiguous prefix, and a
    /// ClientHello read out of a stream with a hole in it would be nonsense.
    #[test]
    fn a_gap_ends_the_assembled_prefix() {
        let mut payload = vec![0x06, 0x00, 0x02, b'a', b'b']; // offset 0
        payload.extend_from_slice(&[0x06, 0x09, 0x02, b'y', b'z']); // offset 9

        assert_eq!(crypto_stream_prefix(&payload).as_deref(), Some(&b"ab"[..]));
    }

    /// A receive call that read a policy with a key, interleaved with a reload
    /// that removes the key before the call takes the hold's lock, holds
    /// nothing: the hold that reload cleared stays empty, so nothing is left
    /// that no key would ever expire. With no names either, the new policy is
    /// the gate switched off, and the datagram goes to quinn untouched.
    #[tokio::test]
    async fn a_reload_that_removes_the_key_leaves_no_flight_held() {
        let key = Arc::new(EchKey::generate("public.example", 7, 0).expect("a key"));
        let expected = Expected::new(Policy::new(Names::new(&[]), Some(key), false));
        // What the receive call read before the reload.
        let stale = expected.current();
        assert!(stale.ech.is_some());
        expected.set(Names::new(&[]));

        let runtime = quinn::default_runtime().expect("a tokio runtime");
        let socket = runtime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").expect("bind"))
            .expect("wrap");
        let gate = Gate::new(socket, expected.clone(), nameless_crypto());
        let sent = sealed_initial(&[0x51; 8], 0, &[0x01]);
        let mut datagram = sent.clone();
        let meta = RecvMeta {
            addr: SocketAddr::from(([127, 0, 0, 1], 4433)),
            len: datagram.len(),
            stride: datagram.len(),
            ..RecvMeta::default()
        };
        // The batch's branch, taken on the policy read before the reload.
        if stale.ech.is_some() {
            let (mut held, mut now) = (None, None);
            gate.screen_holding(&meta, &mut datagram, &mut held, &mut now);
        }

        assert_eq!(expected.memory().hold.flights(), 0, "a flight was stranded");
        assert_eq!(datagram, sent, "the gate is off, so quinn gets it as sent");
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

    /// The header reader is total: no input makes it panic, and none of the
    /// lengths in it can be trusted into an overflow.
    #[test]
    fn the_initial_header_reader_is_total() {
        for byte in 0u16..=255 {
            let datagram = vec![u8::try_from(byte).unwrap(); 64];
            let _ = InitialHeader::parse(&datagram);
        }

        // A token length that claims the whole varint space.
        let mut datagram = vec![0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
        datagram.extend_from_slice(&[0xff; 8]); // token length varint, huge
        datagram.extend_from_slice(&[0x00; 32]);
        assert!(InitialHeader::parse(&datagram).is_none());
    }

    #[test]
    fn a_frame_walk_is_total_over_arbitrary_bytes() {
        for seed in 0u16..=255 {
            let payload: Vec<u8> = (0..64u16)
                .map(|i| u8::try_from((i.wrapping_mul(31).wrapping_add(seed)) & 0xff).unwrap())
                .collect();
            let _ = crypto_stream_prefix(&payload);
        }
    }
}
