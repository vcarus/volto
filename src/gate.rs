//! The SNI gate: which handshakes are allowed to reach quinn at all.
//!
//! A UDP port that answers anything is a port a scan finds. quinn's endpoint is
//! conservative but not silent: a long-header packet naming a version it does
//! not speak draws a Version Negotiation packet, an Initial whose Destination
//! Connection ID is shorter than the eight bytes RFC 9000 §7.2 requires draws a
//! CONNECTION_CLOSE, and a short-header packet for no live connection can draw a
//! Stateless Reset. Each of those is a correct answer to a QUIC peer and an
//! answer to a scanner as well.
//!
//! This module puts a filter *under* quinn, at the socket, so that a datagram
//! quinn would answer never reaches it. It is off unless `[security]
//! expected_sni` names at least one host: an empty list is the shipped default
//! and every datagram passes through untouched.
//!
//! # What passes
//!
//! With the gate open, a received datagram is judged by its first QUIC packet.
//! One packet is enough to judge the whole datagram because RFC 9000 §12.2 says
//! "Receivers MAY route based on the information in the first packet contained
//! in a UDP datagram" and, in the same paragraph, "Senders MUST NOT coalesce
//! QUIC packets with different connection IDs into a single UDP datagram":
//!
//! * **Short header** — passes. It belongs to a connection this endpoint may
//!   already hold, and the gate keeps no connection state to judge it with; see
//!   *What is left uncovered* below.
//! * **Long header, version not 1** — refused. quinn would answer it with a
//!   Version Negotiation packet.
//! * **Long header, not an Initial** — passes. quinn drops a Handshake or 0-RTT
//!   packet for an unknown connection without a word.
//! * **An Initial in a datagram below 1200 bytes** — passes, because RFC 9000
//!   §14.1 has the server discard it and quinn does exactly that, silently.
//! * **An Initial this server cannot open** — passes. Only a client's *first*
//!   Initial packets are keyed by their own Destination Connection ID: once the
//!   server has answered, the client addresses it by the connection ID the
//!   server chose (RFC 9000 §7.2) while the Initial keys stay the ones derived
//!   from the first packet (RFC 9001 §5.2), so the acknowledgements and later
//!   fragments of a handshake already admitted here cannot be opened without
//!   its state. They belong to a flight that was judged when it started; a
//!   forgery that is not one of them fails quinn's own decryption and is
//!   dropped there without a reply.
//! * **An Initial this server can open whose Destination Connection ID is
//!   shorter than eight bytes** — refused. Opening it is what says its keys
//!   came from the connection ID written in it, and that is a client's first
//!   Initial, which RFC 9000 §7.2 gives a floor of eight bytes. Every later
//!   Initial of an admitted handshake is addressed by the eight bytes this
//!   endpoint chose, and so is the one a Retry supplies, so nothing legitimate
//!   is this shape — and quinn answers it with the CONNECTION_CLOSE named
//!   above before it reads a frame.
//! * **An Initial with no CRYPTO frame at offset 0** — passes. It is an
//!   acknowledgement or a later fragment of a handshake already in progress, and
//!   the flight it belongs to was judged when it started.
//! * **An Initial whose ClientHello is cut short before its extensions** —
//!   passes. A ClientHello may span several Initial packets, and a gate that
//!   guessed here would refuse a legitimate client whose first flight is large;
//!   the certificate resolver in [`crate::tls`] is the second gate that catches
//!   what this one lets through.
//! * **An Initial carrying a complete ClientHello** — refused unless its
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
//! type or anything else — and rejects by returning, not by answering.
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
//! A short-header packet for a connection this endpoint does not hold can still
//! draw a Stateless Reset (RFC 9000 §10.3), and this module deliberately does
//! not try to stop it: telling a live connection's packets from a stranger's
//! needs the set of live connection IDs, which lives inside quinn, and filtering
//! on the four-tuple instead would break the connection migration a mobile
//! client behind a relay's NAT depends on. What it costs is small enough to
//! state exactly: quinn answers only a packet of at least 22 bytes whose first
//! two bits are `01`, and only when the eight bytes after them pass the
//! endpoint's own keyed connection-ID check, which random payload does with
//! probability 2^-40. A scanner's empty or fixed probe gets nothing.
//!
//! Nor is any of this traffic obfuscation. The gate hides that a *service* is
//! here from somebody who does not know the name to ask for; it does nothing
//! about what a connection looks like once one is open.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock, PoisonError, RwLock};
use std::task::{Context, Poll};

use bytes::BytesMut;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, ConnectionId, UdpPoller};
use tracing::debug;

use crate::datagram::peek_varint;
use crate::logfmt::escaped_bytes;

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
/// A packet the gate can open is keyed by the connection ID written in it, and
/// only a first Initial is (RFC 9001 §5.2, quoted at [`Judge::decrypt`]), so the
/// sentence below applies to every packet that gets that far.
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

/// The TLS `client_hello` handshake message type (RFC 8446 §4).
const CLIENT_HELLO: u8 = 1;

/// The TLS `server_name` extension type (RFC 6066 §3).
const SERVER_NAME_EXTENSION: u16 = 0;

/// The `host_name` NameType of a `server_name` entry (RFC 6066 §3).
const HOST_NAME: u8 = 0;

/// The QUIC frame types an Initial packet may carry (RFC 9000 §17.2.2).
const FRAME_PADDING: u64 = 0x00;
const FRAME_PING: u64 = 0x01;
const FRAME_ACK: u64 = 0x02;
const FRAME_ACK_ECN: u64 = 0x03;
const FRAME_CRYPTO: u64 = 0x06;
const FRAME_CONNECTION_CLOSE: u64 = 0x1c;

/// The hosts a handshake may name, compared the way a name is compared.
///
/// Held as normalised strings — lowercased and with a trailing root dot removed
/// — so that the normalisation happens once at load rather than once per
/// Initial packet, and so that both gates ([`Names::accepts`] here and the
/// certificate resolver in [`crate::tls`]) can only ever agree.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
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
    /// spelled absolutely, so both are normalised away on each side. Nothing
    /// else is: no wildcards, no suffix matching. A name that is not on the list
    /// is not this server's.
    pub fn accepts(&self, name: &str) -> bool {
        let name = normalise(name);
        self.names.contains(&name)
    }
}

/// Lowercased, with one trailing root dot removed.
fn normalise(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

/// The list the gate is enforcing right now.
///
/// A `SIGHUP` replaces it, so the handle is shared rather than copied: the
/// socket wrapper is built once at bind time and has to see a reload without
/// being rebuilt, since rebuilding it would mean rebinding the port.
///
/// Read once per receive batch rather than once per datagram, and written once
/// per reload, so a plain `RwLock` around an `Arc` is all the sharing this needs.
#[derive(Clone, Debug, Default)]
pub struct Expected(Arc<RwLock<Arc<Names>>>);

impl Expected {
    /// A handle starting on `names`.
    pub fn new(names: Names) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(names))))
    }

    /// Replaces the list, for every datagram received from now on.
    pub fn set(&self, names: Names) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(names);
    }

    /// The list in force.
    ///
    /// Poisoning would mean a panic while swapping an `Arc`; the value itself is
    /// immutable, so there is nothing to observe half-written.
    pub fn current(&self) -> Arc<Names> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// A UDP socket that hands quinn only the datagrams the gate admits.
///
/// Everything except [`AsyncUdpSocket::poll_recv`] is passed straight through,
/// including the capability answers — `max_receive_segments` decides whether GRO
/// is used at all and `may_fragment` decides whether MTU discovery runs, so a
/// wrapper that answered them itself would quietly change the transport.
pub struct Gate {
    inner: Arc<dyn AsyncUdpSocket>,
    expected: Expected,
    /// Everything that decides, which is everything that is not the socket.
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

    /// Judges one datagram and blinds it if it is refused.
    fn screen(&self, remote: SocketAddr, datagram: &mut [u8], expected: &Names) {
        let Verdict::Refuse(refusal) = self.judge.judge(datagram, expected) else {
            return;
        };

        // DEBUG rather than a production level: this fires once per refused
        // datagram, which is once per packet of a scan, and D97's rule is that a
        // line a peer can repeat at will is either sampled or expensive. The
        // per-packet debug lines elsewhere in this server are deliberately
        // neither, and this is one of them.
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
                server_name = %name,
                "dropping a handshake: its server_name is not one this server answers to"
            ),
        }

        blind(datagram);
    }
}

/// The half of the gate that decides, held by [`Gate`] and needing no socket.
///
/// Separate from the socket because none of it reads one: a verdict is a
/// function of the datagram's bytes, the list in force and the Initial keys.
/// So judging is reachable without a bound port — by a unit test, and through
/// the [`judgement`] seam by a fuzz target — and the receive path is left as the
/// only thing that has to know about batches, strides and blinding.
struct Judge {
    /// The source of Initial keys.
    ///
    /// Held from bind time and never reloaded, because the initial secrets do
    /// not depend on the certificate: RFC 9001 §5.2 derives them from the
    /// Destination Connection ID in the client's own packet and a salt fixed by
    /// the version. What a `SIGHUP` can change — the certificate, the key — is
    /// not an input to any of it.
    crypto: Arc<dyn quinn::crypto::ServerConfig>,
}

impl Judge {
    /// What should happen to one datagram.
    fn judge(&self, datagram: &[u8], expected: &Names) -> Verdict {
        let Some(&first) = datagram.first() else {
            return Verdict::Pass;
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
            return Verdict::Pass;
        }

        let Some(version) = datagram.get(1..5) else {
            // Too short for quinn to read a version out of, so too short for it
            // to answer with a Version Negotiation packet.
            return Verdict::Pass;
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
        // scan is looking for. D106.
        if version != QUIC_V1 {
            return Verdict::Refuse(Refusal::Version(version));
        }

        // Handshake, 0-RTT and Retry packets for a connection this endpoint does
        // not hold are dropped by quinn without a reply, and for one it does
        // hold they belong to a handshake that already passed this gate.
        if first & LONG_PACKET_TYPE != INITIAL_PACKET_TYPE {
            return Verdict::Pass;
        }

        if datagram.len() < MIN_INITIAL_DATAGRAM {
            return Verdict::Pass;
        }

        let payload = match self.open(datagram) {
            Opened::Unreadable => return Verdict::Pass,
            // Keyed by a connection ID this packet does not carry: the client
            // has heard back and switched to the server's connection ID,
            // while its Initial keys stay those of its first packet. Such a
            // packet is an acknowledgement or a later fragment of a first
            // flight this gate already judged — and the Handshake packet that
            // carries the client's Finished is often coalesced behind it, so
            // dropping the datagram would cost every admitted handshake a
            // probe timeout. A packet that is none of that fails quinn's own
            // decryption and is dropped there without a reply.
            //
            //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
            //# Upon first receiving an Initial or Retry packet from the server, the
            //# client uses the Source Connection ID supplied by the server as the
            //# Destination Connection ID for subsequent packets, including any 0-RTT
            //# packets.
            Opened::Failed => return Verdict::Pass,
            Opened::Payload {
                dcid_length,
                frames,
            } => {
                // It opened, so its keys came from the Destination Connection ID
                // written in it, and only a client's first Initial is keyed that
                // way — which is a packet RFC 9000 §7.2 gives a floor of eight
                // bytes to (quoted at `MIN_CLIENT_CONNECTION_ID`). Every later
                // Initial of an admitted handshake is addressed by the eight
                // bytes this endpoint's own generator chose, and so is the one a
                // Retry supplies, so nothing legitimate is ever this shape.
                // quinn answers what is with a CONNECTION_CLOSE carrying
                // PROTOCOL_VIOLATION before it reads a single frame, which is
                // one of the three replies this gate exists to take away.
                if dcid_length < MIN_CLIENT_CONNECTION_ID {
                    return Verdict::Refuse(Refusal::ShortConnectionId(dcid_length));
                }
                frames
            }
        };

        let Some(crypto) = crypto_stream_prefix(&payload) else {
            // No CRYPTO frame at offset 0: an acknowledgement, or a later
            // fragment of a first flight whose beginning was already judged.
            return Verdict::Pass;
        };

        match client_hello_name(&crypto) {
            // A ClientHello that does not fit in this packet is judged by the
            // certificate resolver instead; see the module documentation.
            FirstFlight::Truncated => Verdict::Pass,
            FirstFlight::NotAClientHello => Verdict::Refuse(Refusal::NotClientHello),
            FirstFlight::Anonymous => Verdict::Refuse(Refusal::Anonymous),
            FirstFlight::Named(name) => match std::str::from_utf8(&name) {
                Ok(text) if expected.accepts(text) => Verdict::Pass,
                _ => Verdict::Refuse(Refusal::OtherName(escaped_bytes(&name))),
            },
        }
    }

    /// Removes header protection and packet protection from an Initial packet.
    ///
    /// [`Opened::Unreadable`] means the packet is not one quinn could read
    /// either — a header that runs off the end of the datagram, a length field
    /// that claims more than arrived — and the caller passes those through
    /// rather than judging them, because quinn drops them without a reply.
    /// [`Opened::Failed`] is an authentication failure under the keys this
    /// packet's own Destination Connection ID derives: a later Initial of a
    /// handshake in progress, keyed by the client's first packet instead, or a
    /// packet that only says it is a QUIC v1 Initial. The caller passes both
    /// through, because quinn tells them apart with the state this gate lacks
    /// and drops the second kind without a reply.
    fn open(&self, datagram: &[u8]) -> Opened {
        let Some(opened) = self.decrypt(datagram) else {
            return Opened::Unreadable;
        };
        opened
    }

    /// The body of [`Self::open`], written with `?` over the bounds checks.
    fn decrypt(&self, datagram: &[u8]) -> Option<Opened> {
        let header = InitialHeader::parse(datagram)?;

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

        // quinn's header key takes the whole packet and reads its sample from
        // four bytes past the packet number, so a packet too short for that
        // would panic rather than fail. RFC 9001 §5.4.2 puts the sample there.
        let sample_end = header
            .packet_number_offset
            .checked_add(4)?
            .checked_add(keys.header.remote.sample_size())?;
        if sample_end > header.packet_end {
            return None;
        }

        let mut packet = datagram[..header.packet_end].to_vec();
        keys.header
            .remote
            .decrypt(header.packet_number_offset, &mut packet);

        // The two bits the header protection was hiding.
        let number_length = usize::from(packet[0] & 0x03) + 1;
        let number_end = header.packet_number_offset.checked_add(number_length)?;
        if number_end > header.packet_end {
            return None;
        }

        // The truncated packet number, used as the full one. A client's Initial
        // packet numbers start at zero and are still single digits by the time
        // its first flight is complete, so the encoded bits are the whole number
        // — RFC 9000 §17.1 makes the sender include enough of them for a peer
        // that has acknowledged nothing to reconstruct it, and there is nothing
        // to acknowledge yet.
        let mut number = 0u64;
        for byte in &packet[header.packet_number_offset..number_end] {
            number = (number << 8) | u64::from(*byte);
        }

        // The AEAD tag is the tail of the payload; a "packet" too short to hold
        // one is not one, and the check is here rather than left to the cipher
        // so that this function is total on its own terms.
        if header.packet_end - number_end < keys.packet.remote.tag_len() {
            return None;
        }

        let associated = packet[..number_end].to_vec();
        let mut protected = BytesMut::from(&packet[number_end..]);

        match keys
            .packet
            .remote
            .decrypt(number, &associated, &mut protected)
        {
            Ok(()) => Some(Opened::Payload {
                dcid_length: header.dcid.len(),
                frames: protected.to_vec(),
            }),
            Err(_) => Some(Opened::Failed),
        }
    }
}

/// What came of trying to open an Initial packet.
enum Opened {
    /// Not a packet quinn could decode either; the gate does not judge it.
    Unreadable,
    /// A QUIC v1 Initial that failed authentication under the keys its own
    /// Destination Connection ID derives.
    Failed,
    /// The decrypted frames, and how long the Destination Connection ID that
    /// keyed them was — which the caller judges, so it is carried here rather
    /// than read off the datagram a second time.
    Payload { dcid_length: usize, frames: Vec<u8> },
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
        let count = match self.inner.poll_recv(cx, bufs, metas) {
            Poll::Ready(Ok(count)) => count,
            other => return other,
        };

        let expected = self.expected.current();
        if expected.is_empty() {
            return Poll::Ready(Ok(count));
        }

        for (meta, buf) in metas.iter().zip(bufs.iter_mut()).take(count) {
            // Exactly how quinn's own receive loop walks a GRO run: `len` bytes
            // of buffer holding datagrams `stride` bytes apart, the last one
            // possibly shorter.
            let len = meta.len.min(buf.len());
            let stride = meta.stride.max(1);
            let mut at = 0;
            while at < len {
                let end = at.saturating_add(stride).min(len);
                self.screen(meta.addr, &mut buf[at..end], &expected);
                at = end;
            }
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

/// What the gate decided about one datagram.
///
/// Public, and hidden, for the one caller outside this module: the fuzz target
/// behind [`judgement`] has to be able to say which verdict it got. Nothing in
/// this crate names it.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Hand it to quinn unchanged.
    Pass,
    /// Make quinn's decoder throw it away.
    Refuse(Refusal),
}

/// Why a datagram was refused, in the words its log line uses.
///
/// Hidden, and public for the same reason [`Verdict`] is.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A long header naming a QUIC version this server does not speak.
    Version(u32),
    /// A first Initial whose Destination Connection ID is under
    /// [`MIN_CLIENT_CONNECTION_ID`] bytes, carrying the length it had.
    ShortConnectionId(usize),
    /// A first flight that does not begin with a ClientHello.
    NotClientHello,
    /// A complete ClientHello with no `server_name` extension.
    Anonymous,
    /// A ClientHello naming somebody else. Already bounded and escaped.
    OtherName(String),
}

/// Makes quinn's packet decoder reject a datagram before it can answer it.
///
/// Overwrites the Destination Connection ID Length field with a value RFC 9000
/// §17.2 obliges every version-1 endpoint to drop the packet over (quoted at
/// [`MAX_CONNECTION_ID`]). That field is read before the version, the packet
/// type, the token or the payload, so the rejection does not depend on anything
/// else in the packet being well formed — and quinn's own decoder answers it by
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

/// The CRYPTO stream bytes an Initial packet carries from offset 0 onwards.
///
/// `None` means the packet has no CRYPTO frame starting at offset 0 — an
/// acknowledgement, or a retransmitted middle of a first flight — which is the
/// case the gate passes through rather than judging.
///
/// Frames are walked rather than searched for, because a frame's length is
/// implied by its type and skipping one wrongly would find CRYPTO data that is
/// not there. Only the frame types RFC 9000 §17.2.2 allows in an Initial packet
/// are understood; anything else ends the walk with whatever was found so far.
fn crypto_stream_prefix(payload: &[u8]) -> Option<Vec<u8>> {
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
            _ => break,
        }
    }

    // Sorted and appended while contiguous, so a first flight split across
    // several CRYPTO frames in one packet reads as one stream. In practice there
    // is exactly one frame and this is a copy.
    fragments.sort_by_key(|(offset, _)| *offset);
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

    (!stream.is_empty()).then_some(stream)
}

/// Advances past `count` varints, or `None` if they do not all fit.
fn skip_varints(payload: &[u8], mut at: usize, count: usize) -> Option<usize> {
    for _ in 0..count {
        let (_, read) = peek_varint(payload.get(at..)?)?;
        at = at.checked_add(read)?;
    }
    Some(at)
}

/// What a first flight's CRYPTO bytes said about the name being asked for.
///
/// Hidden, and public for the same reason [`Verdict`] is: [`first_flight`] hands
/// it to a fuzz target.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
pub enum FirstFlight {
    /// The ClientHello is not all here yet.
    Truncated,
    /// The first handshake message is something other than a ClientHello.
    NotAClientHello,
    /// A whole ClientHello with no `server_name` extension.
    Anonymous,
    /// The host name it asked for, as it arrived.
    Named(Vec<u8>),
}

/// Reads the `server_name` a ClientHello carries.
///
/// The one judgement that has to be made carefully is between "no name" and "not
/// all here": a ClientHello may be spread over several Initial packets, and
/// refusing one because its extensions had not arrived would turn a large first
/// flight into an unreachable server. So every read that runs off the end of the
/// message *length* is [`FirstFlight::Truncated`], and only a message whose declared
/// length is entirely present can be [`FirstFlight::Anonymous`].
fn client_hello_name(crypto: &[u8]) -> FirstFlight {
    let mut reader = Reader::new(crypto);

    let Some(kind) = reader.byte() else {
        return FirstFlight::Truncated;
    };
    if kind != CLIENT_HELLO {
        return FirstFlight::NotAClientHello;
    }
    let Some(length) = reader.u24() else {
        return FirstFlight::Truncated;
    };
    let Some(body) = reader.take(length) else {
        return FirstFlight::Truncated;
    };

    // From here the whole message is present, so anything that does not parse is
    // a malformed ClientHello rather than an unfinished one, and a malformed one
    // names nobody.
    match server_name(body) {
        Some(name) => FirstFlight::Named(name.to_vec()),
        None => FirstFlight::Anonymous,
    }
}

/// The `host_name` of a complete ClientHello body, if it has one.
fn server_name(body: &[u8]) -> Option<&[u8]> {
    let mut reader = Reader::new(body);

    reader.take(2)?; // legacy_version
    reader.take(32)?; // random
    reader.vector8()?; // legacy_session_id
    reader.vector16()?; // cipher_suites
    reader.vector8()?; // legacy_compression_methods
    let extensions = reader.vector16()?;

    let mut reader = Reader::new(extensions);
    while !reader.is_empty() {
        let kind = reader.u16()?;
        let data = reader.vector16()?;
        if kind == SERVER_NAME_EXTENSION {
            return host_name(data);
        }
    }

    None
}

/// The first `host_name` entry of a `server_name` extension body.
///
//= https://www.rfc-editor.org/rfc/rfc6066#section-3
//# The ServerNameList MUST NOT contain more than one name of the same
//# name_type.
fn host_name(extension: &[u8]) -> Option<&[u8]> {
    let mut reader = Reader::new(extension);
    let list = reader.vector16()?;

    let mut reader = Reader::new(list);
    while !reader.is_empty() {
        let kind = reader.byte()?;
        let name = reader.vector16()?;
        if kind == HOST_NAME {
            return Some(name);
        }
    }

    None
}

/// A cursor over bytes that never panics and never wraps.
///
/// TLS structures are length-prefixed all the way down and every one of those
/// lengths is peer-chosen, so each read is an `Option` and a `None` propagates.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.bytes.split_at_checked(count)?;
        self.bytes = rest;
        Some(head)
    }

    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        let bytes = self.take(3)?;
        Some((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
    }

    /// A vector with a one-byte length prefix.
    fn vector8(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.byte()?);
        self.take(length)
    }

    /// A vector with a two-byte length prefix.
    fn vector16(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }
}

// The two seams `fuzz/fuzz_targets/gate.rs` reaches this module through (D83).
//
// Everything above judges bytes an internet scanner chose, before any peer has
// authenticated and before quinn has seen them, which is exactly the shape a
// coverage-guided fuzzer is for. Neither seam is an entry point of its own:
// each calls the function the socket path calls, so a finding here is a finding
// in what the server runs.

/// The gate's verdict on one datagram, for the fuzz target.
///
/// This is `Gate::screen`'s own `Judge::judge`, over a judge built once per
/// process, so the judgement a fuzzer explores is the judgement a received
/// datagram gets — the socket, the batch walk and the blinding are the only
/// parts left out, and none of them is a parser.
///
/// Hidden rather than API: nothing outside `fuzz/` has any reason to call it,
/// and nothing in this crate does.
#[doc(hidden)]
pub fn judgement(datagram: &[u8], expected: &Names) -> Verdict {
    static JUDGE: OnceLock<Judge> = OnceLock::new();
    JUDGE.get_or_init(nameless_judge).judge(datagram, expected)
}

/// What a first flight's CRYPTO bytes name, for the fuzz target.
///
/// The ClientHello reader (`client_hello_name` and the `Reader` under it) is
/// the hand-written TLS parsing in this module, and the only way to reach it
/// through [`judgement`] is to spell a whole Initial packet that authenticates
/// — which a fuzzer cannot do by luck. So it is also offered on its own, with
/// the CRYPTO bytes handed over directly.
#[doc(hidden)]
pub fn first_flight(crypto: &[u8]) -> FirstFlight {
    client_hello_name(crypto)
}

/// A judge over a TLS configuration with no identity at all.
///
/// Initial keys come from the client's Destination Connection ID and a salt
/// fixed by the version (RFC 9001 §5.2, quoted at `Judge::decrypt`), never
/// from the server's certificate — which is what `Judge::crypto` already rests
/// on for `SIGHUP`. So a configuration carrying no certificate derives exactly
/// the keys the running server derives, and the fuzz target needs no key
/// material, no file and no clock to open the packets the real gate opens. The
/// resolver is never asked for anything: nothing here starts a TLS session.
///
/// The panics are unreachable in the only build that calls this, and would be a
/// crypto provider without TLS 1.3 — the same condition [`crate::tls`] turns
/// into a startup error.
fn nameless_judge() -> Judge {
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

    Judge {
        crypto: Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
                .expect("a TLS 1.3 configuration carries an initial cipher suite"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello body with the given extensions block appended.
    fn client_hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0x00; 32]); // random
        body.push(0); // legacy_session_id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        body.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend_from_slice(extensions);

        let mut message = vec![CLIENT_HELLO];
        let length = body.len();
        message.extend_from_slice(&[
            u8::try_from(length >> 16).unwrap(),
            u8::try_from((length >> 8) & 0xff).unwrap(),
            u8::try_from(length & 0xff).unwrap(),
        ]);
        message.extend_from_slice(&body);
        message
    }

    /// A `server_name` extension naming `host`.
    fn sni_extension(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let mut entry = vec![HOST_NAME];
        entry.extend_from_slice(&u16::try_from(host.len()).unwrap().to_be_bytes());
        entry.extend_from_slice(host);

        let mut list = u16::try_from(entry.len()).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&entry);

        let mut extension = SERVER_NAME_EXTENSION.to_be_bytes().to_vec();
        extension.extend_from_slice(&u16::try_from(list.len()).unwrap().to_be_bytes());
        extension.extend_from_slice(&list);
        extension
    }

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
        assert!(expected.current().accepts("old.example"));

        expected.set(Names::new(&["new.example".to_owned()]));
        assert!(!expected.current().accepts("old.example"));
        assert!(expected.current().accepts("new.example"));
    }

    #[test]
    fn a_client_hello_naming_a_host_is_read_back() {
        let hello = client_hello(&sni_extension("proxy.example"));
        assert_eq!(
            client_hello_name(&hello),
            FirstFlight::Named(b"proxy.example".to_vec())
        );
    }

    /// The extension is found even when it is not the first one.
    #[test]
    fn extensions_are_walked_rather_than_assumed_to_be_in_any_order() {
        let mut extensions = vec![0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]; // supported_versions
        extensions.extend_from_slice(&sni_extension("proxy.example"));
        let hello = client_hello(&extensions);

        assert_eq!(
            client_hello_name(&hello),
            FirstFlight::Named(b"proxy.example".to_vec())
        );
    }

    #[test]
    fn a_complete_client_hello_without_the_extension_names_nobody() {
        let hello = client_hello(&[]);
        assert_eq!(client_hello_name(&hello), FirstFlight::Anonymous);
    }

    /// The fail-open branch: a first flight larger than one Initial packet.
    ///
    /// Every prefix that stops before the message is complete has to read as
    /// truncated, whichever field the cut lands in — that is what stops a large
    /// ClientHello from being refused for a name it had not got to yet.
    #[test]
    fn a_client_hello_cut_short_is_truncated_not_anonymous() {
        let hello = client_hello(&sni_extension("proxy.example"));

        for cut in 0..hello.len() {
            assert_eq!(
                client_hello_name(&hello[..cut]),
                FirstFlight::Truncated,
                "a ClientHello cut at {cut} of {} bytes must fail open",
                hello.len()
            );
        }

        assert_eq!(
            client_hello_name(&hello),
            FirstFlight::Named(b"proxy.example".to_vec())
        );
    }

    /// A cut inside the *extensions* is the case the design argument is about,
    /// and it is only truncated because the message length said so.
    #[test]
    fn extensions_cut_before_the_server_name_fail_open() {
        let mut extensions = vec![0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
        extensions.extend_from_slice(&sni_extension("proxy.example"));
        let hello = client_hello(&extensions);

        // Anywhere inside the extensions block, which is the tail of the message.
        let inside = hello.len() - 4;
        assert_eq!(client_hello_name(&hello[..inside]), FirstFlight::Truncated);
    }

    #[test]
    fn a_first_message_that_is_not_a_client_hello_is_refused() {
        // A ServerHello (2) is not something a client's first flight opens with.
        assert_eq!(
            client_hello_name(&[0x02, 0, 0, 0]),
            FirstFlight::NotAClientHello
        );
    }

    /// A `server_name` list whose declared lengths do not fit its own extension
    /// is malformed rather than truncated: the message length already said the
    /// whole ClientHello was here.
    #[test]
    fn a_malformed_server_name_extension_names_nobody() {
        let mut extension = SERVER_NAME_EXTENSION.to_be_bytes().to_vec();
        extension.extend_from_slice(&[0x00, 0x04]); // extension length
        extension.extend_from_slice(&[0xff, 0xff, 0x00, 0x00]); // list length lies
        let hello = client_hello(&extension);

        assert_eq!(client_hello_name(&hello), FirstFlight::Anonymous);
    }

    #[test]
    fn a_crypto_frame_at_offset_zero_is_the_one_that_is_read() {
        // CRYPTO, offset 0, length 3.
        let payload = [0x06, 0x00, 0x03, b'a', b'b', b'c'];
        assert_eq!(crypto_stream_prefix(&payload), Some(b"abc".to_vec()));

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

        assert_eq!(crypto_stream_prefix(&payload), Some(b"hi".to_vec()));
    }

    #[test]
    fn an_ack_frame_is_skipped_by_its_own_shape() {
        // ACK: largest 1, delay 0, range count 1, first range 0, then one range
        // pair (gap 0, length 0); followed by the CRYPTO frame that matters.
        let mut payload = vec![0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00];
        payload.extend_from_slice(&[0x06, 0x00, 0x01, b'x']);

        assert_eq!(crypto_stream_prefix(&payload), Some(b"x".to_vec()));
    }

    #[test]
    fn two_crypto_frames_are_joined_in_offset_order() {
        let mut payload = vec![0x06, 0x02, 0x02, b'c', b'd']; // offset 2
        payload.extend_from_slice(&[0x06, 0x00, 0x02, b'a', b'b']); // offset 0

        assert_eq!(crypto_stream_prefix(&payload), Some(b"abcd".to_vec()));
    }

    /// A gap is not filled in: what is returned is the contiguous prefix, and a
    /// ClientHello read out of a stream with a hole in it would be nonsense.
    #[test]
    fn a_gap_ends_the_assembled_prefix() {
        let mut payload = vec![0x06, 0x00, 0x02, b'a', b'b']; // offset 0
        payload.extend_from_slice(&[0x06, 0x09, 0x02, b'y', b'z']); // offset 9

        assert_eq!(crypto_stream_prefix(&payload), Some(b"ab".to_vec()));
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

    /// A quinn crypto configuration around a throwaway certificate: the source
    /// of Initial keys, which do not depend on the certificate at all.
    fn throwaway_crypto() -> Arc<dyn quinn::crypto::ServerConfig> {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("a self-signed certificate");
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(issued.signing_key.serialize_der().into());
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let crypto = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_no_client_auth()
            .with_single_cert(vec![issued.cert.der().clone()], key)
            .expect("a usable certificate/key pair");
        Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
                .expect("a QUIC-capable configuration"),
        )
    }

    /// A CRYPTO frame at offset 0 carrying `data`.
    fn crypto_frame(data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x06, 0x00];
        let length = u16::try_from(data.len()).expect("a short handshake message");
        frame.extend_from_slice(&(0x4000 | length).to_be_bytes());
        frame.extend_from_slice(data);
        frame
    }

    /// A 1200-byte QUIC v1 Initial addressed to `dcid` and carrying `frames`,
    /// protected with the keys `keyed_by` derives.
    ///
    /// With `keyed_by == dcid` this is a client's first packet. With the two
    /// different it is the shape of every client Initial after the server has
    /// answered: the Destination Connection ID is now the server's, while the
    /// keys stay those of the first packet (RFC 9000 §7.2, RFC 9001 §5.2).
    fn initial(
        crypto: &dyn quinn::crypto::ServerConfig,
        dcid: &[u8],
        keyed_by: &[u8],
        frames: &[u8],
    ) -> Vec<u8> {
        let keys = crypto
            .initial_keys(QUIC_V1, &ConnectionId::new(keyed_by))
            .expect("Initial keys for QUIC v1");
        let tag_len = keys.packet.remote.tag_len();

        let mut datagram = vec![0xc0]; // long header, Initial, one-byte packet number
        datagram.extend_from_slice(&QUIC_V1.to_be_bytes());
        datagram.push(u8::try_from(dcid.len()).unwrap());
        datagram.extend_from_slice(dcid);
        datagram.push(8);
        datagram.extend_from_slice(&[0xcc; 8]);
        datagram.push(0); // no token
        // What follows the Length field: packet number, frames, PADDING to
        // 1200 bytes, tag.
        let header_len = datagram.len() + 2 + 1;
        let payload_len = MIN_INITIAL_DATAGRAM - header_len - tag_len;
        assert!(frames.len() <= payload_len, "frames do not fit one Initial");
        let length = u16::try_from(1 + payload_len + tag_len).unwrap();
        datagram.extend_from_slice(&(0x4000 | length).to_be_bytes());
        let packet_number_offset = datagram.len();
        datagram.push(0); // packet number 0
        datagram.extend_from_slice(frames);
        datagram.resize(packet_number_offset + 1 + payload_len, 0);
        datagram.resize(MIN_INITIAL_DATAGRAM, 0);

        keys.packet
            .remote
            .encrypt(0, &mut datagram, packet_number_offset + 1);
        keys.header
            .remote
            .encrypt(packet_number_offset, &mut datagram);
        datagram
    }

    const CLIENT_CID: [u8; 8] = [0xaa; 8];
    const SERVER_CID: [u8; 8] = [0xbb; 8];

    /// The control: a first packet, keyed by its own Destination Connection
    /// ID, is opened and judged by the name it carries.
    #[test]
    fn a_first_initial_is_opened_under_its_own_keys() {
        let crypto = throwaway_crypto();
        let judge = Judge {
            crypto: crypto.clone(),
        };
        let names = Names::new(&["localhost".to_owned()]);

        let hello = client_hello(&sni_extension("other.example"));
        let stranger = initial(&*crypto, &CLIENT_CID, &CLIENT_CID, &crypto_frame(&hello));
        assert_eq!(
            judge.judge(&stranger, &names),
            Verdict::Refuse(Refusal::OtherName("\"other.example\"".to_owned()))
        );

        let hello = client_hello(&sni_extension("localhost"));
        let ours = initial(&*crypto, &CLIENT_CID, &CLIENT_CID, &crypto_frame(&hello));
        assert_eq!(judge.judge(&ours, &names), Verdict::Pass);
    }

    /// A later Initial of an admitted handshake cannot be opened here, and
    /// must not be refused for it: the Handshake packet carrying the client's
    /// Finished rides in the same datagram, and blinding it costs the
    /// handshake a probe timeout. Seen on a production host on 2026-09-03 as
    /// every handshake's RTT stuck at the configured initial estimate.
    #[test]
    fn a_later_initial_keyed_by_the_first_packet_is_not_a_stranger() {
        let crypto = throwaway_crypto();
        let judge = Judge {
            crypto: crypto.clone(),
        };
        let names = Names::new(&["localhost".to_owned()]);

        // An acknowledgement of the server's Initial: ACK frame for packet 0.
        let ack = [0x02, 0x00, 0x00, 0x00, 0x00];
        let later = initial(&*crypto, &SERVER_CID, &CLIENT_CID, &ack);
        assert_eq!(judge.judge(&later, &names), Verdict::Pass);

        // Even one that looks like a stranger's ClientHello once opened under
        // the wrong keys cannot be told from an acknowledgement without the
        // connection's state; quinn, which has it, is the one to judge.
        let hello = client_hello(&sni_extension("other.example"));
        let later = initial(&*crypto, &SERVER_CID, &CLIENT_CID, &crypto_frame(&hello));
        assert_eq!(judge.judge(&later, &names), Verdict::Pass);
    }

    /// A first Initial whose Destination Connection ID is under eight bytes.
    ///
    /// That it opens at all is what makes it a first Initial rather than a
    /// later packet of a flight already admitted, and a first Initial has a
    /// floor of eight bytes (RFC 9000 §7.2, quoted at
    /// [`MIN_CLIENT_CONNECTION_ID`]). quinn answers this one with
    /// CONNECTION_CLOSE(PROTOCOL_VIOLATION) before it reads a frame, which is
    /// one of the three replies this gate exists to take away — so the header
    /// is judged ahead of anything the packet carries, and the two witnesses
    /// here carry nothing and carry a name on the list.
    #[test]
    fn a_first_initial_with_a_short_connection_id_is_refused() {
        let crypto = throwaway_crypto();
        let judge = Judge {
            crypto: crypto.clone(),
        };
        let names = Names::new(&["localhost".to_owned()]);

        let short = [0x11; 4];
        let padding_only = initial(&*crypto, &short, &short, &[]);
        assert_eq!(padding_only.len(), MIN_INITIAL_DATAGRAM);
        assert_eq!(
            judge.judge(&padding_only, &names),
            Verdict::Refuse(Refusal::ShortConnectionId(short.len())),
            "a PADDING-only Initial behind a four-byte connection ID"
        );

        let hello = client_hello(&sni_extension("localhost"));
        let named = initial(&*crypto, &short, &short, &crypto_frame(&hello));
        assert_eq!(
            judge.judge(&named, &names),
            Verdict::Refuse(Refusal::ShortConnectionId(short.len())),
            "a name on the list does not buy a connection ID no client may choose"
        );
    }

    /// The same packet behind a connection ID a client may actually choose.
    ///
    /// The sibling of the test above and the half that says the rule is about
    /// the length rather than about the shape: eight bytes is the floor, and a
    /// datagram carrying nothing to judge is passed through as it always was.
    #[test]
    fn a_first_initial_with_a_full_connection_id_is_not_refused_for_its_length() {
        let crypto = throwaway_crypto();
        let judge = Judge {
            crypto: crypto.clone(),
        };
        let names = Names::new(&["localhost".to_owned()]);

        assert_eq!(CLIENT_CID.len(), MIN_CLIENT_CONNECTION_ID);
        let padding_only = initial(&*crypto, &CLIENT_CID, &CLIENT_CID, &[]);
        assert_eq!(
            judge.judge(&padding_only, &names),
            Verdict::Pass,
            "an eight-byte connection ID is the shortest one a client may choose"
        );
    }

    /// Writes the seed corpus for `fuzz/fuzz_targets/gate.rs`, and pins it.
    ///
    /// A fuzzer cannot spell an Initial packet that authenticates, so without
    /// seeds the target would explore the header parser and nothing behind it.
    /// These are five datagrams — one per branch the judgement can end on — and
    /// two bare ClientHellos, written where `cargo fuzz run gate` looks for
    /// them. `fuzz/corpus/` is machine-local and gitignored (D83), so this runs
    /// with every `cargo test` rather than leaving the corpus to a step
    /// somebody has to remember; each file carries the target's mode byte in
    /// front of the bytes under test.
    ///
    /// The assertions are the other half of it. They pin what each seed is a
    /// seed *for*, so a verdict that moves is a red test rather than a corpus
    /// that quietly stops covering anything — and they pin the claim
    /// [`nameless_judge`] rests on, since these packets are built under a real
    /// self-signed certificate and opened here by a configuration that has
    /// none. Initial keys do not depend on the certificate; if they ever did,
    /// both of the refusals below would fall through to [`Verdict::Pass`].
    #[test]
    fn the_fuzz_seed_corpus_is_written_with_the_verdicts_it_was_built_for() {
        /// The target's mode byte for a whole datagram.
        const AS_A_DATAGRAM: u8 = 0x00;
        /// The target's mode byte for bare CRYPTO bytes.
        const AS_CRYPTO_BYTES: u8 = 0x01;

        let crypto = throwaway_crypto();
        // The list the target configures for mode byte `AS_A_DATAGRAM`.
        let names = Names::new(&["localhost".to_owned()]);

        let ours = client_hello(&sni_extension("localhost"));
        let stranger = client_hello(&sni_extension("other.example"));
        let anonymous = client_hello(&[]);
        let cut = ours[..ours.len() - 4].to_vec();
        // An acknowledgement of the server's Initial, keyed by the client's
        // first packet: the shape v0.9.1 stopped refusing.
        let ack = [0x02, 0x00, 0x00, 0x00, 0x00];

        let datagrams = [
            (
                "a-name-we-answer-to",
                initial(&*crypto, &CLIENT_CID, &CLIENT_CID, &crypto_frame(&ours)),
                Verdict::Pass,
            ),
            (
                "a-name-we-do-not",
                initial(&*crypto, &CLIENT_CID, &CLIENT_CID, &crypto_frame(&stranger)),
                Verdict::Refuse(Refusal::OtherName("\"other.example\"".to_owned())),
            ),
            (
                "no-server-name",
                initial(
                    &*crypto,
                    &CLIENT_CID,
                    &CLIENT_CID,
                    &crypto_frame(&anonymous),
                ),
                Verdict::Refuse(Refusal::Anonymous),
            ),
            (
                "a-client-hello-cut-short",
                initial(&*crypto, &CLIENT_CID, &CLIENT_CID, &crypto_frame(&cut)),
                Verdict::Pass,
            ),
            (
                "a-second-flight-initial",
                initial(&*crypto, &SERVER_CID, &CLIENT_CID, &ack),
                Verdict::Pass,
            ),
        ];

        let crypto_bytes = [
            (
                "crypto-a-whole-client-hello",
                ours.clone(),
                FirstFlight::Named(b"localhost".to_vec()),
            ),
            (
                "crypto-a-client-hello-cut-short",
                cut.clone(),
                FirstFlight::Truncated,
            ),
        ];

        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/gate");
        std::fs::create_dir_all(&directory).expect("a corpus directory to write seeds into");
        let seed = |name: &str, mode: u8, body: &[u8]| {
            let mut file = Vec::with_capacity(1 + body.len());
            file.push(mode);
            file.extend_from_slice(body);
            std::fs::write(directory.join(name), file).expect("a seed file");
        };

        for (name, datagram, verdict) in datagrams {
            assert_eq!(judgement(&datagram, &names), verdict, "the seed {name}");
            seed(name, AS_A_DATAGRAM, &datagram);
        }
        for (name, bytes, flight) in crypto_bytes {
            assert_eq!(first_flight(&bytes), flight, "the seed {name}");
            seed(name, AS_CRYPTO_BYTES, &bytes);
        }
    }

    // -----------------------------------------------------------------------
    // Shape metamorphism: an unusual but legal first flight is judged by its
    // name and by nothing else
    // -----------------------------------------------------------------------
    //
    // Everything below is one property with many witnesses. A first flight has
    // a great deal of freedom in how it is laid out -- how many CRYPTO frames
    // carry it and in what order, what else rides in front of them, how long
    // the connection IDs and the packet number are, whether a token is there,
    // whether a second packet is coalesced behind it, and how the ClientHello
    // itself is spelled -- and none of that freedom may move the verdict. So
    // each shape is built twice, once naming a host on the list and once naming
    // a host that is not, and both halves are asserted: a shape that turns a
    // listed name into a refusal is a client this server has become unreachable
    // to, and a shape that turns an unlisted name into a pass is the gate gone
    // blind. A parser that gives up reads as the second.

    /// How a first flight's bytes are spread over the frames of one payload.
    type Layout = fn(&[u8]) -> Vec<u8>;

    /// How a ClientHello naming a host is written out.
    type Spelling = fn(&str) -> Vec<u8>;

    /// A name the list holds, and one it does not.
    const LISTED: &str = "listed.example";
    const UNLISTED: &str = "other.example";

    /// A QUIC variable-length integer, in the shortest encoding that holds it.
    fn varint(value: usize) -> Vec<u8> {
        match u64::try_from(value).expect("a length that fits a varint") {
            small @ 0..=63 => vec![u8::try_from(small).expect("six bits")],
            medium @ 64..=16383 => (0x4000 | u16::try_from(medium).expect("fourteen bits"))
                .to_be_bytes()
                .to_vec(),
            large => (0x8000_0000 | u32::try_from(large).expect("thirty bits"))
                .to_be_bytes()
                .to_vec(),
        }
    }

    /// A CRYPTO frame carrying `data` at `offset` in the handshake stream.
    fn crypto_frame_at(offset: usize, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x06];
        frame.extend_from_slice(&varint(offset));
        frame.extend_from_slice(&varint(data.len()));
        frame.extend_from_slice(data);
        frame
    }

    /// A TLS extension of `kind` carrying `body`.
    fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = kind.to_be_bytes().to_vec();
        bytes.extend_from_slice(
            &u16::try_from(body.len())
                .expect("a short extension")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(body);
        bytes
    }

    /// [`client_hello`] with the fields a real client varies ahead of its
    /// extensions: the middlebox-compatibility `legacy_session_id` Chrome sends
    /// 32 bytes of (RFC 8446 §4.1.2), and the cipher suites it offers.
    fn client_hello_with(session_id: usize, ciphers: &[u16], extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0x00; 32]); // random
        body.push(u8::try_from(session_id).expect("a session id of at most 255 bytes"));
        body.extend_from_slice(&vec![0x5a; session_id]);
        let suites: Vec<u8> = ciphers.iter().flat_map(|c| c.to_be_bytes()).collect();
        body.extend_from_slice(
            &u16::try_from(suites.len())
                .expect("a short suite list")
                .to_be_bytes(),
        );
        body.extend_from_slice(&suites);
        body.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods
        body.extend_from_slice(
            &u16::try_from(extensions.len())
                .expect("short extensions")
                .to_be_bytes(),
        );
        body.extend_from_slice(extensions);

        let mut message = vec![CLIENT_HELLO];
        let length = body.len();
        message.extend_from_slice(&[
            u8::try_from(length >> 16).expect("a short message"),
            u8::try_from((length >> 8) & 0xff).expect("a byte"),
            u8::try_from(length & 0xff).expect("a byte"),
        ]);
        message.extend_from_slice(&body);
        message
    }

    /// The parts of an Initial header a legitimate client chooses for itself.
    #[derive(Clone)]
    struct Shape {
        /// The Destination Connection ID, which is also what keys the packet.
        dcid: Vec<u8>,
        /// The Source Connection ID, which may be empty.
        scid: Vec<u8>,
        /// A `NEW_TOKEN` or Retry token, or nothing.
        token: Vec<u8>,
        /// How many bytes the Packet Number field takes, one to four.
        number_length: usize,
        /// How long the Initial packet itself is, before anything coalesced.
        packet_length: usize,
    }

    impl Default for Shape {
        fn default() -> Self {
            Self {
                dcid: CLIENT_CID.to_vec(),
                scid: vec![0xcc; 8],
                token: Vec::new(),
                number_length: 1,
                packet_length: MIN_INITIAL_DATAGRAM,
            }
        }
    }

    /// [`initial`] with every header field the caller's to choose.
    ///
    /// Keyed by its own Destination Connection ID, which is what a client's
    /// first packet is (RFC 9001 §5.2) — and still is after a Retry, since the
    /// keys are recomputed from the connection ID the Retry supplied.
    fn shaped_initial(
        crypto: &dyn quinn::crypto::ServerConfig,
        shape: &Shape,
        frames: &[u8],
    ) -> Vec<u8> {
        let keys = crypto
            .initial_keys(QUIC_V1, &ConnectionId::new(&shape.dcid))
            .expect("Initial keys for QUIC v1");
        let tag_len = keys.packet.remote.tag_len();
        assert!(
            (1..=4).contains(&shape.number_length),
            "a packet number is one to four bytes"
        );

        let mut packet =
            vec![0xc0 | u8::try_from(shape.number_length - 1).expect("two bits of length")];
        packet.extend_from_slice(&QUIC_V1.to_be_bytes());
        packet.push(u8::try_from(shape.dcid.len()).expect("a legal connection id"));
        packet.extend_from_slice(&shape.dcid);
        packet.push(u8::try_from(shape.scid.len()).expect("a legal connection id"));
        packet.extend_from_slice(&shape.scid);
        packet.extend_from_slice(&varint(shape.token.len()));
        packet.extend_from_slice(&shape.token);

        // A two-byte Length field, which is what every real Initial uses.
        let number_offset = packet.len() + 2;
        let payload_len = shape
            .packet_length
            .checked_sub(number_offset + shape.number_length + tag_len)
            .expect("a packet long enough to hold its own header");
        assert!(frames.len() <= payload_len, "frames do not fit one Initial");
        let length = u16::try_from(shape.number_length + payload_len + tag_len)
            .expect("a length that fits two bytes");
        packet.extend_from_slice(&(0x4000 | length).to_be_bytes());

        packet.resize(number_offset + shape.number_length, 0); // packet number 0
        packet.extend_from_slice(frames);
        packet.resize(number_offset + shape.number_length + payload_len, 0); // PADDING
        packet.resize(shape.packet_length, 0); // room for the tag

        keys.packet
            .remote
            .encrypt(0, &mut packet, number_offset + shape.number_length);
        keys.header.remote.encrypt(number_offset, &mut packet);
        packet
    }

    /// Asserts that a datagram laid out by `build` is judged by its name alone.
    ///
    /// Written as a plain function taking a builder rather than two datagrams so
    /// that the listed and the unlisted half can never drift apart: they are the
    /// same shape twice.
    #[track_caller]
    fn judged_by_its_name_alone(shape: &str, build: impl Fn(&str) -> Vec<u8>) {
        let names = Names::new(&[LISTED.to_owned()]);

        assert_eq!(
            judgement(&build(LISTED), &names),
            Verdict::Pass,
            "{shape}: a first flight naming {LISTED} must reach quinn"
        );
        let refusal = judgement(&build(UNLISTED), &names);
        assert!(
            matches!(refusal, Verdict::Refuse(Refusal::OtherName(_))),
            "{shape}: a first flight naming {UNLISTED} must be refused for its name, not {refusal:?}"
        );
    }

    /// How a first flight's bytes are distributed over the frames of one packet.
    ///
    /// Every one of these is a legal Initial payload that a client is free to
    /// send, and RFC 9000 §19.6 puts no order on CRYPTO frames within a packet.
    #[test]
    fn the_frames_a_first_flight_is_laid_out_in_do_not_change_the_verdict() {
        let crypto = throwaway_crypto();

        let layouts: Vec<(&str, Layout)> = vec![
            ("one CRYPTO frame", |hello| crypto_frame_at(0, hello)),
            ("two CRYPTO frames in order", |hello| {
                let (head, tail) = hello.split_at(hello.len() / 2);
                let mut frames = crypto_frame_at(0, head);
                frames.extend_from_slice(&crypto_frame_at(head.len(), tail));
                frames
            }),
            ("two CRYPTO frames in reverse order", |hello| {
                let (head, tail) = hello.split_at(hello.len() / 2);
                let mut frames = crypto_frame_at(head.len(), tail);
                frames.extend_from_slice(&crypto_frame_at(0, head));
                frames
            }),
            ("three CRYPTO frames, middle one first", |hello| {
                let third = hello.len() / 3;
                let mut frames = crypto_frame_at(third, &hello[third..third * 2]);
                frames.extend_from_slice(&crypto_frame_at(third * 2, &hello[third * 2..]));
                frames.extend_from_slice(&crypto_frame_at(0, &hello[..third]));
                frames
            }),
            ("PADDING before the CRYPTO frame", |hello| {
                let mut frames = vec![0x00; 32];
                frames.extend_from_slice(&crypto_frame_at(0, hello));
                frames
            }),
            ("PING before the CRYPTO frame", |hello| {
                let mut frames = vec![0x01];
                frames.extend_from_slice(&crypto_frame_at(0, hello));
                frames
            }),
            ("an ACK frame before the CRYPTO frame", |hello| {
                // Largest Acknowledged 10, delay 27, no further ranges, first
                // range 3. Every field is distinct and non-zero on purpose: an
                // ACK of zeroes is indistinguishable from PADDING, so a walk
                // that lands one varint out still finds the CRYPTO frame and
                // the shape proves nothing.
                let mut frames = vec![0x02, 0x0a, 0x1b, 0x00, 0x03];
                frames.extend_from_slice(&crypto_frame_at(0, hello));
                frames
            }),
            ("a two-range ACK frame before the CRYPTO frame", |hello| {
                // Largest 10, delay 27, two further ranges, first range 1, then
                // the gap and length of each of them.
                let mut frames = vec![0x02, 0x0a, 0x1b, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05];
                frames.extend_from_slice(&crypto_frame_at(0, hello));
                frames
            }),
            ("an ACK_ECN frame before the CRYPTO frame", |hello| {
                // The same, with the three ECN counts an ACK_ECN carries.
                let mut frames = vec![0x03, 0x0a, 0x1b, 0x00, 0x03, 0x11, 0x12, 0x13];
                frames.extend_from_slice(&crypto_frame_at(0, hello));
                frames
            }),
            ("PADDING, PING and ACK around two CRYPTO frames", |hello| {
                let (head, tail) = hello.split_at(hello.len() / 2);
                let mut frames = vec![0x00; 8];
                frames.push(0x01);
                frames.extend_from_slice(&[0x02, 0x0a, 0x1b, 0x00, 0x03]);
                frames.extend_from_slice(&crypto_frame_at(head.len(), tail));
                frames.push(0x01);
                frames.extend_from_slice(&crypto_frame_at(0, head));
                frames.extend_from_slice(&[0x00; 8]);
                frames
            }),
        ];

        for (shape, lay_out) in layouts {
            judged_by_its_name_alone(shape, |name| {
                let hello = client_hello(&sni_extension(name));
                shaped_initial(&*crypto, &Shape::default(), &lay_out(&hello))
            });
        }
    }

    /// The header fields a client picks, none of which the name depends on.
    #[test]
    fn the_header_a_first_flight_wears_does_not_change_the_verdict() {
        let crypto = throwaway_crypto();

        let mut shapes = vec![
            ("the baseline header".to_owned(), Shape::default()),
            (
                "a 20-byte Destination Connection ID".to_owned(),
                Shape {
                    dcid: vec![0xa1; MAX_CONNECTION_ID],
                    ..Shape::default()
                },
            ),
            (
                "an empty Source Connection ID".to_owned(),
                Shape {
                    scid: Vec::new(),
                    ..Shape::default()
                },
            ),
            (
                "a 20-byte Source Connection ID".to_owned(),
                Shape {
                    scid: vec![0xc5; MAX_CONNECTION_ID],
                    ..Shape::default()
                },
            ),
            (
                "a token, as a client returning a NEW_TOKEN sends".to_owned(),
                Shape {
                    token: vec![0x7e; 64],
                    ..Shape::default()
                },
            ),
            (
                "a token, the longest connection IDs and a four-byte number".to_owned(),
                Shape {
                    dcid: vec![0xa1; MAX_CONNECTION_ID],
                    scid: vec![0xc5; MAX_CONNECTION_ID],
                    token: vec![0x7e; 200],
                    number_length: 4,
                    ..Shape::default()
                },
            ),
            (
                "a datagram larger than the minimum".to_owned(),
                Shape {
                    packet_length: 1500,
                    ..Shape::default()
                },
            ),
        ];
        shapes.extend((1..=4).map(|number_length| {
            (
                format!("a {number_length}-byte packet number"),
                Shape {
                    number_length,
                    ..Shape::default()
                },
            )
        }));

        for (shape, header) in shapes {
            judged_by_its_name_alone(&shape, |name| {
                let hello = client_hello(&sni_extension(name));
                shaped_initial(&*crypto, &header, &crypto_frame_at(0, &hello))
            });
        }
    }

    /// A packet coalesced behind the Initial is not what the gate judges.
    ///
    /// RFC 9000 §12.2 lets a receiver route on the first packet of a datagram
    /// alone, and this gate does. The witness is a second packet that names the
    /// *other* host: if any of it were read, both halves of the property would
    /// come out inverted rather than merely wrong.
    #[test]
    fn a_packet_coalesced_behind_the_initial_is_not_what_is_judged() {
        let crypto = throwaway_crypto();
        let head = Shape {
            packet_length: 700,
            ..Shape::default()
        };

        // A long header of each type a client may coalesce behind an Initial,
        // and a short header, which RFC 9000 §12.2 allows only last.
        let followers: [(&str, u8); 3] = [
            ("a 0-RTT packet", 0xd0),
            ("a Handshake packet", 0xe0),
            ("a short-header packet", 0x40),
        ];

        for (shape, first_byte) in followers {
            judged_by_its_name_alone(shape, |name| {
                let ours = client_hello(&sni_extension(name));
                let mut datagram = shaped_initial(&*crypto, &head, &crypto_frame_at(0, &ours));

                // The bait: everything the judge would find if it read on.
                let theirs = client_hello(&sni_extension(if name == LISTED {
                    UNLISTED
                } else {
                    LISTED
                }));
                let mut follower = vec![first_byte];
                if first_byte & LONG_HEADER_FORM != 0 {
                    follower.extend_from_slice(&QUIC_V1.to_be_bytes());
                    follower.push(u8::try_from(head.dcid.len()).expect("a legal length"));
                    follower.extend_from_slice(&head.dcid);
                    follower.push(0); // Source Connection ID
                    follower.extend_from_slice(&varint(400)); // Length
                    follower.push(0); // packet number
                }
                follower.extend_from_slice(&crypto_frame_at(0, &theirs));
                follower.resize(500, 0);
                datagram.extend_from_slice(&follower);
                datagram
            });
        }
    }

    /// How the ClientHello itself is spelled, which is where a real stack's
    /// idiosyncrasies live: Chrome's 32-byte session id, the GREASE values
    /// RFC 8701 has clients scatter through it, and where in the extension list
    /// `server_name` happens to fall.
    #[test]
    fn the_way_a_client_hello_is_spelled_does_not_change_the_verdict() {
        let crypto = throwaway_crypto();

        /// A GREASE extension, which carries nothing and means nothing.
        fn grease(kind: u16) -> Vec<u8> {
            extension(kind, &[])
        }

        /// `supported_versions`, offering TLS 1.3.
        fn supported_versions() -> Vec<u8> {
            extension(0x002b, &[0x02, 0x03, 0x04])
        }

        let spellings: Vec<(&str, Spelling)> = vec![
            ("server_name as the only extension", |name| {
                client_hello(&sni_extension(name))
            }),
            ("server_name first of three", |name| {
                let mut extensions = sni_extension(name);
                extensions.extend_from_slice(&supported_versions());
                extensions.extend_from_slice(&grease(0x1a1a));
                client_hello(&extensions)
            }),
            ("server_name last of three", |name| {
                let mut extensions = grease(0x0a0a);
                extensions.extend_from_slice(&supported_versions());
                extensions.extend_from_slice(&sni_extension(name));
                client_hello(&extensions)
            }),
            ("a 32-byte legacy_session_id", |name| {
                client_hello_with(32, &[0x1301], &sni_extension(name))
            }),
            ("GREASE cipher suites around the real one", |name| {
                client_hello_with(32, &[0x0a0a, 0x1301, 0x1302, 0x5a5a], &sni_extension(name))
            }),
            ("GREASE extensions on both sides of server_name", |name| {
                let mut extensions = grease(0x0a0a);
                extensions.extend_from_slice(&sni_extension(name));
                extensions.extend_from_slice(&grease(0x3a3a));
                client_hello_with(32, &[0x0a0a, 0x1301], &extensions)
            }),
            ("an unknown name_type ahead of the host_name", |name| {
                let host = name.as_bytes();
                // An entry of some other NameType, then the host_name.
                let mut list = vec![0x42, 0x00, 0x03, b'x', b'y', b'z'];
                list.push(HOST_NAME);
                list.extend_from_slice(
                    &u16::try_from(host.len())
                        .expect("a short name")
                        .to_be_bytes(),
                );
                list.extend_from_slice(host);
                let mut body = u16::try_from(list.len())
                    .expect("a short list")
                    .to_be_bytes()
                    .to_vec();
                body.extend_from_slice(&list);
                client_hello(&extension(SERVER_NAME_EXTENSION, &body))
            }),
            ("the name in upper case", |name| {
                client_hello(&sni_extension(&name.to_ascii_uppercase()))
            }),
            ("the name with its root dot", |name| {
                client_hello(&sni_extension(&format!("{name}.")))
            }),
            ("everything a Chrome-shaped hello does at once", |name| {
                let mut extensions = grease(0x0a0a);
                extensions.extend_from_slice(&supported_versions());
                extensions.extend_from_slice(&sni_extension(&name.to_ascii_uppercase()));
                extensions.extend_from_slice(&extension(0x0010, &[0x00, 0x03, 0x02, b'h', b'3']));
                extensions.extend_from_slice(&grease(0x5a5a));
                client_hello_with(32, &[0x0a0a, 0x1301, 0x1302, 0x1303], &extensions)
            }),
        ];

        for (shape, spell) in spellings {
            judged_by_its_name_alone(shape, |name| {
                shaped_initial(
                    &*crypto,
                    &Shape::default(),
                    &crypto_frame_at(0, &spell(name)),
                )
            });
        }
    }
}
