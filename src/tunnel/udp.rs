//! CONNECT-UDP tunnels (RFC 9298) over HTTP Datagrams (RFC 9297).
//!
//! # Shape of a session
//!
//! A CONNECT-UDP request opens a *session*: one request stream plus one
//! connected UDP socket. Unlike a TCP tunnel, the payload does not travel on the
//! request stream — it travels in QUIC DATAGRAM frames shared by every session
//! on the connection, each tagged with the Quarter Stream ID of its request
//! stream. So a session needs three things pumped at once:
//!
//! * inbound datagrams, delivered by the connection-wide router via a channel;
//! * outbound packets read from the UDP socket;
//! * the request stream itself, which carries capsules and the close signal.
//!
//! # Deliberate asymmetries
//!
//! * The 2xx is sent **immediately** after the socket is ready (RFC 9298 §3.1):
//!   UDP has no handshake, so waiting for the target to answer would hang.
//! * Name resolution happens **before** the 2xx, so an unresolvable target is
//!   refused rather than becoming a silent black hole.
//! * The session is registered for datagram delivery **before** that resolution,
//!   so the packets a client is allowed to send optimistically (RFC 9298 §5) are
//!   buffered instead of dropped, and discarded with the session if the request
//!   is refused.
//! * An oversized outbound packet is **dropped**, never downgraded to a capsule
//!   (RFC 9298 §6.1).
//! * Closing the socket also closes the request stream, and vice versa
//!   (RFC 9298 §3.1) — a half-open UDP session has no meaning.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{header, HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use percent_encoding::percent_decode_str;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::capsule::{self, Capsule, CapsuleDecoder};
use crate::datagram::{self, MAX_UDP_PAYLOAD};
use crate::h3api::{self, Reader, Stream, Writer};
use crate::tunnel::{Context, ProxyError, Unreachable};
use crate::{net, policy, tunnel};

/// Path prefix of the RFC 9298 §2 default URI template.
pub const WELL_KNOWN_PREFIX: &str = "/.well-known/masque/udp/";

/// Inbound datagrams buffered per session before packets start being dropped.
///
/// Bounded on purpose: UDP allows loss, whereas an unbounded queue would let a
/// slow target turn into unbounded memory growth. The same queue serves both
/// phases of a session — the one before the target socket exists, where it holds
/// what RFC 9298 §5 calls optimistically sent packets, and the running one — so
/// this constant is the whole per-session bound rather than one of two.
///
/// # What this costs at the configured limits
///
/// Worst case is `depth x payload x max_targets_per_conn x max_connections`.
/// Only the payload needs care: a QUIC DATAGRAM frame cannot be fragmented, so a
/// datagram never exceeds the `max_udp_payload_size` this server advertises
/// (quinn's default, 1472 bytes) even though RFC 9298 §5 permits a 65527-byte UDP
/// payload in principle. With the shipped defaults (`INBOUND_QUEUE_DEPTH` = 64,
/// `max_targets_per_conn` = 256, `max_connections` = 256) that is ~92 KiB per
/// session, ~23 MiB per connection and ~5.8 GiB across a server saturated at both
/// limits — an operator lowering either limit lowers it proportionally.
///
/// Registering a session before its target socket exists does **not** raise that
/// ceiling: the queue is the same size in both phases, sessions are still capped
/// by the per-connection tunnel quota, and a full queue is already reachable on a
/// running session whenever a client sends faster than the proxy forwards. What
/// it changes is how long a full queue can sit undrained — no longer than name
/// resolution takes, after which the session either starts draining or is refused
/// and the queue is discarded with it.
const INBOUND_QUEUE_DEPTH: usize = 64;

/// Routes inbound HTTP datagrams to the session that owns them.
///
/// Keyed by Quarter Stream ID, which is how RFC 9297 §2.1 names a session on the
/// wire. Owned by the connection and shared with every session on it.
#[derive(Default)]
pub struct SessionRegistry {
    sessions: Mutex<HashMap<u64, mpsc::Sender<Bytes>>>,
}

impl SessionRegistry {
    /// Registers a session, returning a guard that deregisters it on drop.
    ///
    /// The guard is what keeps the table from leaking entries: a session can end
    /// through any of half a dozen paths, and all of them drop it.
    fn register(
        self: &Arc<Self>,
        quarter_stream_id: u64,
        inbound: mpsc::Sender<Bytes>,
    ) -> SessionGuard {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(quarter_stream_id, inbound);

        SessionGuard {
            registry: Arc::clone(self),
            quarter_stream_id,
        }
    }

    /// The inbound sink for a Quarter Stream ID, if a session owns it.
    fn get(&self, quarter_stream_id: u64) -> Option<mpsc::Sender<Bytes>> {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&quarter_stream_id)
            .cloned()
    }

    /// Number of live sessions. Used by tests and future accounting.
    pub fn len(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Whether any session is live.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Deregisters a session when dropped.
struct SessionGuard {
    registry: Arc<SessionRegistry>,
    quarter_stream_id: u64,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.registry
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.quarter_stream_id);
    }
}

/// Delivers inbound QUIC datagrams to their sessions until the connection ends.
///
/// One task per connection. What happens to a datagram that cannot be delivered
/// depends on *why*, and RFC 9297 §2.1 draws the lines:
///
/// * a Quarter Stream ID that cannot be parsed, or one above 2^60-1, is a
///   **connection error** of type H3_DATAGRAM_ERROR — neither can name a QUIC
///   stream, so there is nothing to drop it *for*;
/// * a Quarter Stream ID with no live session is **dropped**. The RFC permits
///   discarding a datagram whose request stream does not exist, which happens
///   routinely when a session closes with packets still in flight;
/// * a datagram whose Context ID is truncated or unknown is likewise dropped.
///
/// One SHOULD is deliberately not implemented: a Quarter Stream ID naming a
/// stream "that cannot be created due to the peer's stream limits" SHOULD draw
/// H3_ID_ERROR. RFC 9297 §2.1 grants the exemption this router relies on —
/// "Generating an error is not mandatory because the QUIC stream limit might be
/// unknown to the HTTP/3 layer" — and this router sits outside the HTTP/3 layer
/// altogether, so it cannot tell that case apart from a session that has already
/// closed.
pub async fn route_datagrams(quic: quinn::Connection, sessions: Arc<SessionRegistry>) {
    loop {
        let datagram = match quic.read_datagram().await {
            Ok(datagram) => datagram,
            // The connection is gone; so is every session on it.
            Err(error) => {
                debug!(%error, "stopped reading QUIC datagrams");
                return;
            }
        };

        let decoded = match datagram::decode(datagram) {
            Ok(decoded) => decoded,
            // The two conditions RFC 9297 §2.1 states as MUST-close.
            Err(error) if error.is_connection_error() => {
                warn!(%error, "closing the connection after an unusable HTTP datagram");
                quic.close(h3api::DATAGRAM_ERROR_CLOSE, b"invalid HTTP datagram");
                return;
            }
            Err(error) => {
                debug!(%error, "malformed HTTP datagram");
                continue;
            }
        };

        if decoded.context_id != datagram::CONTEXT_ID_UDP_PAYLOAD {
            // RFC 9298 §5: an unknown context must be dropped silently, never
            // treated as an error.
            debug!(
                quarter_stream_id = decoded.quarter_stream_id,
                context_id = decoded.context_id,
                "dropping datagram with an unknown context id"
            );
            continue;
        }

        let Some(inbound) = sessions.get(decoded.quarter_stream_id) else {
            debug!(
                quarter_stream_id = decoded.quarter_stream_id,
                "dropping datagram for an unknown session"
            );
            continue;
        };

        // Never block the router on one slow session: dropping a UDP packet is
        // legitimate, stalling every other session is not.
        if inbound.try_send(decoded.payload).is_err() {
            debug!(
                quarter_stream_id = decoded.quarter_stream_id,
                "inbound queue full or closed, dropping datagram"
            );
        }
    }
}

/// Establishes a UDP tunnel for a `connect-udp` request and runs it.
pub async fn run(req: &Request<()>, mut stream: Stream, stream_id: u64, ctx: Context) {
    if let Err(reason) = validate(req) {
        debug!(stream_id, reason, "malformed connect-udp request");
        tunnel::refuse(&mut stream, StatusCode::BAD_REQUEST, stream_id).await;
        return;
    }

    let (host, port) = match parse_target(req.uri().path(), req.uri().query()) {
        Ok(target) => target,
        Err(reason) => {
            debug!(stream_id, path = %req.uri().path(), reason, "malformed connect-udp request");
            tunnel::refuse(&mut stream, StatusCode::BAD_REQUEST, stream_id).await;
            return;
        }
    };

    // The Quarter Stream ID follows from the stream id alone, so the session can
    // start collecting datagrams as soon as the request is known to be a
    // well-formed CONNECT-UDP one — before the resolver is asked anything.
    //
    // RFC 9298 §5: "A client MAY optimistically start sending UDP packets in
    // HTTP Datagrams before receiving the response to its UDP proxying request",
    // and a proxy receiving them early "SHALL either drop that HTTP Datagram
    // silently or buffer it temporarily (on the order of a round trip)".
    // Registering here takes the second option: the packets land in the queue the
    // session is about to read from, so a client that opens a tunnel and sends
    // immediately does not lose its first packets to name resolution.
    //
    // Every refusal below returns, dropping the guard and with it the queue —
    // which is the discard the same paragraph calls for when the request the
    // datagrams were waiting on never succeeds. [`INBOUND_QUEUE_DEPTH`] carries
    // what that buffer costs.
    let quarter_stream_id = datagram::quarter_stream_id(stream_id);
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE_DEPTH);
    let _guard = ctx.sessions.register(quarter_stream_id, inbound_tx);

    // Cheapest check first, and one that needs no resolver.
    if !ctx.policy.allows_port(port) {
        debug!(stream_id, host, port, "target port denied by policy");
        tunnel::refuse_because(
            &mut stream,
            StatusCode::FORBIDDEN,
            ProxyError::HttpRequestDenied,
            stream_id,
        )
        .await;
        return;
    }

    // RFC 9298 §3.1: resolution must complete before the 2xx, so a bad name is
    // refused instead of silently swallowing every packet.
    //
    // Decision D9: a resolver failure is a 502, not a 400. A transient DNS
    // failure is not something the client did wrong, and the RFC 9209 reason
    // tells it which of the two happened.
    let addresses = match net::resolve(&host, port).await {
        Ok(addresses) => addresses,
        Err(error) => {
            debug!(stream_id, host, port, %error, "failed to resolve connect-udp target");
            tunnel::refuse_because(
                &mut stream,
                StatusCode::BAD_GATEWAY,
                ProxyError::DnsError,
                stream_id,
            )
            .await;
            return;
        }
    };

    let allowed = ctx.policy.allowed_addresses(&addresses);
    if allowed.is_empty() {
        // As on the TCP path: a resolver that answers only the unspecified
        // address has filtered the name, which is routine. Anything else — a
        // private address among the answers above all — stays a warning.
        if policy::is_dns_blackhole(&addresses) {
            info!(
                stream_id,
                host,
                port,
                ?addresses,
                "every address of the target is a DNS blackhole"
            );
        } else {
            warn!(
                stream_id,
                host,
                port,
                ?addresses,
                "every address of the target is prohibited by policy"
            );
        }
        tunnel::refuse_because(
            &mut stream,
            StatusCode::FORBIDDEN,
            ProxyError::DestinationIpProhibited,
            stream_id,
        )
        .await;
        return;
    }

    let socket = match bind_any(&allowed).await {
        Ok(socket) => socket,
        Err(failure) => {
            // As on the TCP path, the status follows from the RFC 9209 type
            // rather than collapsing every failure into one 502, and the answer
            // names the address that failed.
            debug!(
                stream_id,
                ?allowed,
                error = %failure.error,
                "failed to open target UDP socket"
            );
            tunnel::refuse_unreachable(&mut stream, &failure, stream_id).await;
            return;
        }
    };

    if let Err(error) = stream.respond_with(StatusCode::OK, capsule_headers()).await {
        debug!(stream_id, %error, "failed to send 200 for connect-udp");
        return;
    }

    let target = socket.peer_addr().ok();
    info!(
        stream_id,
        quarter_stream_id,
        host,
        port,
        ?target,
        datagrams = ctx.datagrams_allowed(),
        "udp session established"
    );

    let (writer, reader) = stream.split();
    let mut session = Session {
        quarter_stream_id,
        socket,
        inbound: inbound_rx,
        reader,
        writer,
        decoder: CapsuleDecoder::new(),
        // Zero is the operator's way of switching the mitigation off, so it means
        // "uncapped" rather than "nothing may be sent".
        unanswered_budget: match ctx.unanswered_packet_budget {
            0 => None,
            budget => Some(budget),
        },
        oversize_reported: false,
        ctx,
    };

    session.run(stream_id).await;

    debug!(stream_id, quarter_stream_id, "udp session closed");
}

/// A running UDP session.
struct Session {
    quarter_stream_id: u64,
    socket: UdpSocket,
    /// Payloads the connection router decoded for this session.
    inbound: mpsc::Receiver<Bytes>,
    reader: Reader,
    writer: Writer,
    /// The request stream body is a capsule sequence (RFC 9297 §3.2).
    decoder: CapsuleDecoder,
    /// Packets still allowed towards a target that has never answered.
    ///
    /// RFC 9298 §7: until the target says something, this session might be an
    /// attempt to use the proxy as a reflector or a port scanner, so what it can
    /// emit is capped. `None` means uncapped — either the target has answered,
    /// which lifts the cap for good because the target has consented to the
    /// conversation, or the operator disabled the mitigation.
    unanswered_budget: Option<u32>,
    /// Whether this session has already reported an oversized drop.
    ///
    /// The drops themselves are per packet and can arrive at line rate, so only
    /// the first is worth an operator's attention; see [`oversize_verdict`]. A
    /// plain `bool` because the session loop is the only thing that touches it,
    /// one step at a time.
    oversize_reported: bool,
    ctx: Context,
}

/// What a single step of the session loop decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Keep going, and treat this as activity for the idle timer.
    Continue,
    /// The session is over; close the request stream tidily.
    Stop,
    /// The session is over and the request stream has **already been reset**.
    ///
    /// Distinct from [`Step::Stop`] because the tidy close would contradict the
    /// reset: telling the peer "no error" on a stream we just aborted leaves it
    /// to guess which signal to believe.
    Aborted,
}

impl Session {
    /// Pumps the session until it closes, one direction at a time.
    async fn run(&mut self, stream_id: u64) {
        // A UDP datagram can be at most this big, so one buffer serves forever.
        let mut packet = vec![0u8; MAX_UDP_PAYLOAD];

        loop {
            // Wrapping the whole step measures idleness directly: any branch
            // firing resets the clock. Every branch below is cancel-safe.
            let step = tokio::time::timeout(self.ctx.idle_timeout, async {
                tokio::select! {
                    payload = self.inbound.recv() => match payload {
                        Some(payload) => self.forward_to_target(payload).await,
                        // Only happens if the registry dropped our sender.
                        None => Step::Stop,
                    },
                    received = self.socket.recv(&mut packet) => match received {
                        Ok(length) => self.forward_to_client(&packet[..length]).await,
                        Err(error) => {
                            // ICMP errors surface here on a connected socket.
                            // RFC 9298 §3.1: the request stream must be closed.
                            debug!(stream_id, %error, "target socket failed");
                            Step::Stop
                        }
                    },
                    chunk = self.reader.recv_data() => {
                        self.handle_stream_chunk(stream_id, chunk).await
                    }
                }
            })
            .await;

            match step {
                Ok(Step::Continue) => {}
                Ok(Step::Stop) => break,
                // The stream carries its own error signal already; anything
                // added here would only muddy it. The socket still closes, with
                // `self`.
                Ok(Step::Aborted) => return,
                Err(_elapsed) => {
                    debug!(
                        stream_id,
                        timeout_secs = self.ctx.idle_timeout.as_secs(),
                        "udp session idle timeout"
                    );
                    break;
                }
            }
        }

        // RFC 9298 §3.1: closing the UDP socket and closing the request stream
        // go together. The socket closes when `self` drops; the stream needs
        // saying explicitly.
        self.reader.stop_receiving(h3api::NO_ERROR);
        if let Err(error) = self.writer.finish().await {
            debug!(stream_id, %error, "failed to finish the connect-udp stream");
        }
    }

    /// Forwards a payload received from the client to the target.
    async fn forward_to_target(&mut self, payload: Bytes) -> Step {
        // RFC 9298 §5: a context-0 payload larger than this cannot be a UDP
        // datagram, so the stream is aborted rather than truncating it.
        if payload.len() > MAX_UDP_PAYLOAD {
            warn!(
                quarter_stream_id = self.quarter_stream_id,
                length = payload.len(),
                "client sent an oversized UDP payload, aborting the session"
            );
            self.writer.reset(h3api::DATAGRAM_ERROR);
            return Step::Aborted;
        }

        // RFC 9298 §7. The packet is dropped rather than the session closed: a
        // legitimate flow whose target is merely slow to answer must be able to
        // recover once a reply arrives, and UDP loss is not an error condition.
        if let Some(remaining) = self.unanswered_budget.as_mut() {
            if *remaining == 0 {
                debug!(
                    quarter_stream_id = self.quarter_stream_id,
                    "unanswered packet budget exhausted, dropping outbound packet"
                );
                return Step::Continue;
            }
            *remaining -= 1;
        }

        match self.socket.send(&payload).await {
            Ok(_) => Step::Continue,
            Err(error) if is_per_packet_send_error(&error) => {
                debug!(
                    quarter_stream_id = self.quarter_stream_id,
                    length = payload.len(),
                    %error,
                    "target socket refused this packet, dropping it"
                );
                Step::Continue
            }
            Err(error) => {
                // The target is unreachable (ICMP) or the socket is broken.
                debug!(%error, "failed to send to the target");
                Step::Stop
            }
        }
    }

    /// Forwards a packet received from the target to the client.
    async fn forward_to_client(&mut self, packet: &[u8]) -> Step {
        // The socket is connected, so anything arriving here really is from the
        // target: the conversation is two-way and the amplification cap is done.
        self.unanswered_budget = None;

        let encoded_len = datagram::encoded_len(
            self.quarter_stream_id,
            datagram::CONTEXT_ID_UDP_PAYLOAD,
            packet.len(),
        );

        if self.ctx.datagrams_allowed() {
            // The QUIC datagram path. If the packet does not fit, it is dropped:
            // RFC 9298 §6.1 says SHOULD NOT fall back to a capsule, because
            // doing so silently converts a lossy flow into a head-of-line
            // blocked one.
            let limit = self.ctx.datagrams.max_datagram_size().unwrap_or(0);
            match oversize_verdict(encoded_len, limit, &mut self.oversize_reported) {
                Oversize::Fits => {}
                Oversize::DropAndReport => {
                    info!(
                        quarter_stream_id = self.quarter_stream_id,
                        encoded_len,
                        limit,
                        "target packet too large for a QUIC datagram, dropping; further \
                         drops on this session are logged at debug level"
                    );
                    return Step::Continue;
                }
                Oversize::DropQuietly => {
                    debug!(
                        quarter_stream_id = self.quarter_stream_id,
                        encoded_len, limit, "target packet too large for a QUIC datagram, dropping"
                    );
                    return Step::Continue;
                }
            }

            let encoded = datagram::encode_udp_payload(self.quarter_stream_id, packet);
            if let Err(error) = self.ctx.datagrams.send_datagram(encoded) {
                debug!(%error, "failed to send a QUIC datagram");
            }
            return Step::Continue;
        }

        // The peer never advertised SETTINGS_H3_DATAGRAM, so RFC 9297 §2.1.1
        // forbids the datagram path entirely and the request stream is the only
        // way out. This is not the same situation as the oversize case above:
        // there a datagram path exists and RFC 9298 §6.1 says not to bypass it,
        // whereas here there is none, so capsules are the correct channel.
        let encoded = capsule::encode_datagram(datagram::CONTEXT_ID_UDP_PAYLOAD, packet);
        if let Err(error) = self.writer.send_data(encoded).await {
            debug!(%error, "failed to send a DATAGRAM capsule");
            return Step::Stop;
        }

        Step::Continue
    }

    /// Handles bytes, EOF or an error on the request stream.
    ///
    /// The body is a capsule sequence. A DATAGRAM capsule carries a UDP payload
    /// the client chose to send reliably instead of in a QUIC datagram, and is
    /// forwarded exactly the same way.
    async fn handle_stream_chunk(
        &mut self,
        stream_id: u64,
        chunk: Result<Option<Bytes>, h3api::StreamError>,
    ) -> Step {
        match chunk {
            Ok(Some(data)) => {
                self.decoder.push(data);

                loop {
                    match self.decoder.next_capsule() {
                        Ok(Some(Capsule::Datagram {
                            context_id,
                            payload,
                        })) => {
                            if context_id != datagram::CONTEXT_ID_UDP_PAYLOAD {
                                // RFC 9298 §5, as for datagrams: drop silently.
                                debug!(
                                    stream_id,
                                    context_id, "dropping capsule with an unknown context id"
                                );
                                continue;
                            }
                            match self.forward_to_target(payload).await {
                                Step::Continue => {}
                                over => return over,
                            }
                        }
                        // More bytes needed.
                        Ok(None) => return Step::Continue,
                        Err(error) => {
                            // RFC 9297 §5.2 registers 0x33 as exactly this: a
                            // "Datagram or Capsule Protocol parse error".
                            debug!(stream_id, %error, "malformed capsule");
                            self.writer.reset(h3api::DATAGRAM_ERROR);
                            return Step::Aborted;
                        }
                    }
                }
            }
            // RFC 9298 §3.1: the client closing the stream ends the session.
            Ok(None) => {
                if self.decoder.at_capsule_boundary() {
                    debug!(stream_id, "client closed the connect-udp stream");
                    Step::Stop
                } else {
                    // RFC 9297 §3.3: a stream carrying capsules that "is
                    // terminated cleanly [...] and the last Capsule on the
                    // stream was truncated [...] MUST be treated as if it were a
                    // malformed or incomplete message", and the same section
                    // sends HTTP/3 to RFC 9114 §4.1.2, where a malformed message
                    // "MUST be treated as a stream error of type
                    // H3_MESSAGE_ERROR".
                    //
                    // Deliberately *not* the 0x33 used for the parse failures
                    // above, even though both arrive through the capsule
                    // decoder. 0x33 is registered as a "Datagram or Capsule
                    // Protocol parse error", and nothing failed to parse here:
                    // every capsule received was well formed, and the message
                    // simply ended somewhere other than a capsule boundary. The
                    // two codes cover different faults and this one is the
                    // message's, so the code the RFC names for a malformed
                    // message is the right one to send.
                    debug!(
                        stream_id,
                        error = %capsule::Error::Truncated,
                        "connect-udp stream ended mid-capsule"
                    );
                    self.writer.reset(h3api::MESSAGE_ERROR);
                    Step::Aborted
                }
            }
            Err(error) => {
                match h3api::peer_reset_code(&error) {
                    Some(code) => debug!(stream_id, code, "client reset the connect-udp stream"),
                    None => debug!(stream_id, %error, "connect-udp stream failed"),
                }
                Step::Stop
            }
        }
    }
}

/// What to do with a packet the target sent, on the QUIC datagram path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Oversize {
    /// Within the negotiated datagram size; send it unchanged.
    Fits,
    /// Too large, and the first such drop on this session: worth an `info!`.
    DropAndReport,
    /// Too large, and not the first: `debug!` only.
    DropQuietly,
}

/// Decides whether an outbound packet fits, and whether a drop is worth reporting.
///
/// The drop itself is not negotiable — RFC 9298 §6.1 rules out falling back to a
/// capsule, so an oversized packet is lost the way a UDP packet on a too-small
/// link would be. What is negotiable is how loudly it is said. At `debug!` it was
/// invisible in production, and the condition is not hypothetical: Surge
/// advertises `max_datagram_frame_size = 1300`, which a large EDNS0 or DNSSEC
/// answer and any QUIC-in-QUIC flow through the tunnel clear routinely. So the
/// first drop of a session is raised to `info!` — one line naming the length and
/// the limit, enough for an operator to recognise what is happening — and the
/// rest stay at `debug!`, because these arrive per packet and a flood of one
/// benign message is what buries the warnings that matter.
///
/// `reported` is the session's flag and is flipped here, which is the whole state
/// this costs: no allocation, no lock, one branch on the forwarding path. A
/// packet that fits leaves it untouched, so the first *real* drop is always the
/// one that gets reported.
fn oversize_verdict(encoded_len: usize, limit: usize, reported: &mut bool) -> Oversize {
    if encoded_len <= limit {
        return Oversize::Fits;
    }

    if std::mem::replace(reported, true) {
        Oversize::DropQuietly
    } else {
        Oversize::DropAndReport
    }
}

/// Whether a target-socket `send` failure affects only this packet.
///
/// RFC 9298 draws the line in two places. §3.1 requires the request stream to be
/// closed when "a UDP proxy is notified by its operating system that its socket
/// is no longer usable" — ECONNREFUSED from an ICMP port-unreachable is that
/// case. §5, on the other hand, says a proxy that "can only send out UDP packets
/// of a certain length due to its underlying link MTU [...] has no choice but to
/// discard incoming HTTP Datagrams" longer than that. Discard means discard: the
/// session survives.
///
/// The errors below are per-packet verdicts, not verdicts on the socket:
///
/// * `EMSGSIZE` — the direct consequence of the DF bit [`crate::net`] sets on
///   Linux (`IP_PMTUDISC_DO`), raised for every payload above the path MTU. This
///   is the one that matters in production: a client is entitled to send a 4 KiB
///   UDP packet, and tearing its tunnel down for it would be a bug the dev host
///   cannot reproduce, since macOS has no equivalent socket option.
/// * `EPERM` / `EACCES` — a local firewall rejecting individual packets.
///
/// Kept as a plain function over the OS error number because `std` maps none of
/// these onto a stable `ErrorKind`.
fn is_per_packet_send_error(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EMSGSIZE) | Some(libc::EPERM) | Some(libc::EACCES)
    )
}

/// The response headers of a CONNECT-UDP 2xx.
///
/// RFC 9297 §3.4 says a response that uses the Capsule Protocol SHOULD carry
/// `Capsule-Protocol: ?1`, and §3.2 forbids Content-Length, Content-Type and
/// Transfer-Encoding on it, since the body is a capsule sequence rather than a
/// representation. Sending only the one field satisfies both.
fn capsule_headers() -> HeaderMap {
    let mut headers = HeaderMap::with_capacity(1);
    headers.insert(
        HeaderName::from_static("capsule-protocol"),
        HeaderValue::from_static("?1"),
    );
    headers
}

/// Opens a connected UDP socket to the first address that works.
///
/// As on the TCP path, the address of the last attempt travels with the error:
/// it is the hop an RFC 9209 `next-hop` parameter names.
async fn bind_any(addresses: &[std::net::SocketAddr]) -> Result<UdpSocket, Unreachable> {
    let mut last = None;

    for address in addresses {
        match net::connected_udp_socket(*address).await {
            Ok(socket) => return Ok(socket),
            Err(error) => {
                debug!(%address, %error, "could not open a socket to the target");
                last = Some(Unreachable {
                    next_hop: Some(*address),
                    error,
                });
            }
        }
    }

    Err(last.unwrap_or_else(|| Unreachable {
        next_hop: None,
        error: std::io::Error::new(std::io::ErrorKind::InvalidInput, "no addresses to bind to"),
    }))
}

/// Checks a CONNECT-UDP request against the rules that are about the message
/// rather than the target.
///
/// Two of them, both stated as requirements on the receiver:
///
/// * RFC 9298 §3.4 — "The :path and :scheme pseudo-header fields SHALL NOT be
///   empty", and "a UDP proxying request that does not conform to these
///   restrictions is malformed". RFC 9220 says the same in the other direction:
///   an extended CONNECT request must carry both. `:path` needs no check here
///   because [`parse_target`] already refuses anything that is not the template.
/// * RFC 9297 §3.2 — "The Capsule Protocol MUST NOT be used with messages that
///   contain Content-Length, Content-Type, or Transfer-Encoding header fields
///   [...] A receiver that observes a violation of these requirements MUST treat
///   the HTTP message as malformed." The body of this request stream is a
///   capsule sequence, so all three describe a framing that cannot exist here.
///
/// Two rules deliberately *not* enforced, both of which some proxies do enforce:
///
/// * the `:scheme` value is not required to be `https`. RFC 9298 derives it from
///   whatever URI template the client was configured with rather than fixing it,
///   and this server only ever listens under TLS, so the value decides nothing.
///   Rejecting `http` would be stricter than the specification for no gain.
/// * `Capsule-Protocol: ?0`, or a value that is not a Boolean, is not rejected.
///   RFC 9297 §3.4 says a non-Boolean value "MUST be handled as if the field
///   were not present" and that a false value "has the same semantics as when
///   the header is not present" — so the conformant reaction to both is to
///   ignore the field, which is what this server does by never reading it. The
///   field tells an *intermediary* that capsules are in flight; an endpoint that
///   knows the `connect-udp` upgrade token knows it already (RFC 9297 §3).
///
/// A violation is answered with 400 and a clean stream close rather than a
/// RESET_STREAM. RFC 9114 §4.1.2 allows a server to send a response before
/// closing the stream, and resetting instead would discard the buffered
/// response, leaving the client to guess why its tunnel was refused.
fn validate(req: &Request<()>) -> Result<(), &'static str> {
    if req.uri().scheme_str().is_none_or(str::is_empty) {
        return Err("connect-udp requires a non-empty :scheme");
    }

    // Named one at a time so the log says which field was the problem.
    if req.headers().contains_key(header::CONTENT_LENGTH) {
        return Err("content-length is forbidden on a capsule stream");
    }
    if req.headers().contains_key(header::CONTENT_TYPE) {
        return Err("content-type is forbidden on a capsule stream");
    }
    if req.headers().contains_key(header::TRANSFER_ENCODING) {
        return Err("transfer-encoding is forbidden on a capsule stream");
    }

    Ok(())
}

/// Parses the RFC 9298 §2 default URI template.
///
/// ```text
/// /.well-known/masque/udp/{target_host}/{target_port}/
/// ```
///
/// Parsing is deliberately lenient about the things clients disagree on — the
/// trailing slash is optional, and an IPv6 literal is accepted both in the
/// RFC 9298 §3.1 form (bare, only the colons escaped) and bracketed — while
/// staying strict about anything ambiguous.
pub fn parse_target(path: &str, query: Option<&str>) -> Result<(String, u16), &'static str> {
    // A query string would make the URI something other than the template.
    if query.is_some_and(|query| !query.is_empty()) {
        return Err("the connect-udp template accepts no query");
    }

    let rest = path
        .strip_prefix(WELL_KNOWN_PREFIX)
        .ok_or("path is not the connect-udp template")?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);

    // Split before decoding: a percent-encoded slash inside a segment must not
    // create a segment boundary.
    let mut segments = rest.split('/');
    let host = segments.next().unwrap_or_default();
    let port = segments.next().ok_or("missing target_port")?;
    if segments.next().is_some() {
        return Err("too many path segments for the connect-udp template");
    }

    let host = percent_decode_str(host)
        .decode_utf8()
        .map_err(|_| "target_host is not valid UTF-8")?;
    if host.is_empty() {
        return Err("empty target_host");
    }

    let port = percent_decode_str(port)
        .decode_utf8()
        .map_err(|_| "target_port is not valid UTF-8")?;
    let port: u16 = port.parse().map_err(|_| "invalid target_port")?;
    if port == 0 {
        return Err("target_port must not be zero");
    }

    Ok((host.into_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(path: &str) -> Result<(String, u16), &'static str> {
        parse_target(path, None)
    }

    #[test]
    fn parses_the_default_template() {
        assert_eq!(
            parse("/.well-known/masque/udp/192.0.2.1/53/"),
            Ok(("192.0.2.1".to_owned(), 53))
        );
    }

    #[test]
    fn the_trailing_slash_is_optional() {
        assert_eq!(
            parse("/.well-known/masque/udp/example.com/443"),
            Ok(("example.com".to_owned(), 443))
        );
        assert_eq!(
            parse("/.well-known/masque/udp/example.com/443/"),
            Ok(("example.com".to_owned(), 443))
        );
    }

    #[test]
    fn percent_encoded_hosts_are_decoded() {
        assert_eq!(
            parse("/.well-known/masque/udp/dns.example%2Ecom/53"),
            Ok(("dns.example.com".to_owned(), 53))
        );
    }

    /// RFC 9298 §3.1: an IPv6 literal appears with its colons escaped and no
    /// brackets.
    #[test]
    fn parses_bare_ipv6_literals() {
        assert_eq!(
            parse("/.well-known/masque/udp/2001%3Adb8%3A%3A1/53/"),
            Ok(("2001:db8::1".to_owned(), 53))
        );
    }

    /// Not the standard form, but cheap to accept and some clients send it.
    #[test]
    fn tolerates_bracketed_ipv6_literals() {
        assert_eq!(
            parse("/.well-known/masque/udp/%5B2001%3Adb8%3A%3A1%5D/53/"),
            Ok(("[2001:db8::1]".to_owned(), 53))
        );
    }

    #[test]
    fn rejects_a_foreign_path() {
        assert!(parse("/").is_err());
        assert!(parse("/.well-known/masque/ip/192.0.2.1/53/").is_err());
        assert!(parse("/masque/udp/192.0.2.1/53/").is_err());
    }

    #[test]
    fn rejects_a_missing_or_invalid_port() {
        assert!(parse("/.well-known/masque/udp/192.0.2.1").is_err());
        assert!(parse("/.well-known/masque/udp/192.0.2.1/").is_err());
        assert!(parse("/.well-known/masque/udp/192.0.2.1/0").is_err());
        assert!(parse("/.well-known/masque/udp/192.0.2.1/65536").is_err());
        assert!(parse("/.well-known/masque/udp/192.0.2.1/domain").is_err());
    }

    #[test]
    fn rejects_an_empty_host() {
        assert!(parse("/.well-known/masque/udp//53").is_err());
    }

    #[test]
    fn rejects_extra_segments() {
        assert!(parse("/.well-known/masque/udp/192.0.2.1/53/extra").is_err());
    }

    #[test]
    fn rejects_a_query_string() {
        assert!(parse_target("/.well-known/masque/udp/192.0.2.1/53/", Some("x=1")).is_err());
        // An empty query is indistinguishable from none.
        assert!(parse_target("/.well-known/masque/udp/192.0.2.1/53/", Some("")).is_ok());
    }

    /// A percent-encoded slash must stay inside its segment.
    #[test]
    fn an_encoded_slash_does_not_split_segments() {
        assert_eq!(
            parse("/.well-known/masque/udp/a%2Fb/53"),
            Ok(("a/b".to_owned(), 53))
        );
    }

    /// Builds a well-formed CONNECT-UDP request, which the caller then spoils.
    fn connect_udp_request() -> Request<()> {
        Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://proxy.example/.well-known/masque/udp/192.0.2.1/53/")
            .body(())
            .expect("request")
    }

    #[test]
    fn accepts_a_well_formed_request() {
        assert_eq!(validate(&connect_udp_request()), Ok(()));
    }

    /// RFC 9298 §3.4: `:scheme` must be there and must not be empty. Only a
    /// hand-rolled client can get this wrong — `h3` fills the field in — which
    /// is exactly why the server cannot assume it.
    #[test]
    fn rejects_a_request_without_a_scheme() {
        let mut request = connect_udp_request();
        *request.uri_mut() = "/.well-known/masque/udp/192.0.2.1/53/"
            .parse()
            .expect("origin-form uri");

        assert!(validate(&request).is_err());
    }

    /// RFC 9298 §3.4 does not fix the scheme to `https`, so neither does this.
    #[test]
    fn accepts_any_non_empty_scheme() {
        let mut request = connect_udp_request();
        *request.uri_mut() = "http://proxy.example/.well-known/masque/udp/192.0.2.1/53/"
            .parse()
            .expect("uri");

        assert_eq!(validate(&request), Ok(()));
    }

    /// RFC 9297 §3.2: none of these can describe the body of a capsule stream,
    /// and a receiver that sees one must treat the message as malformed.
    #[test]
    fn rejects_content_framing_headers() {
        for (name, value) in [
            ("content-length", "0"),
            ("content-length", "42"),
            ("content-type", "application/octet-stream"),
            ("transfer-encoding", "chunked"),
        ] {
            let mut request = connect_udp_request();
            request.headers_mut().insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );

            assert!(
                validate(&request).is_err(),
                "{name}: {value} must be refused"
            );
        }
    }

    /// The capsule protocol is in use because the upgrade token says so, so the
    /// header is advisory and none of its values change what happens here.
    #[test]
    fn the_capsule_protocol_header_is_never_a_reason_to_refuse() {
        for value in ["?1", "?0", "1", "not-a-boolean", ""] {
            let mut request = connect_udp_request();
            request.headers_mut().insert(
                HeaderName::from_static("capsule-protocol"),
                HeaderValue::from_str(value).expect("header value"),
            );

            assert_eq!(validate(&request), Ok(()), "capsule-protocol: {value:?}");
        }

        // Absent entirely: only a SHOULD in RFC 9297 §3.4.
        assert_eq!(validate(&connect_udp_request()), Ok(()));
    }

    /// RFC 9298 §5: a payload the link cannot carry is discarded, not a reason
    /// to end the session.
    ///
    /// Tested as a pure function because the condition cannot be produced on
    /// loopback: `EMSGSIZE` needs the DF bit, which is a no-op on macOS, and a
    /// Linux loopback MTU is far larger than anything a test would send. The
    /// three codes below are POSIX and present in `libc` on both hosts.
    #[test]
    fn per_packet_send_errors_do_not_end_the_session() {
        for code in [libc::EMSGSIZE, libc::EPERM, libc::EACCES] {
            let error = std::io::Error::from_raw_os_error(code);
            assert!(
                is_per_packet_send_error(&error),
                "errno {code} ({error}) must only cost one packet"
            );
        }
    }

    /// The other half of the rule: RFC 9298 §3.1 requires the request stream to
    /// be closed when the socket itself is reported unusable, which is what
    /// `ECONNREFUSED` from an ICMP port-unreachable means.
    #[test]
    fn socket_failures_still_end_the_session() {
        for code in [libc::ECONNREFUSED, libc::ENETUNREACH, libc::EHOSTUNREACH] {
            let error = std::io::Error::from_raw_os_error(code);
            assert!(
                !is_per_packet_send_error(&error),
                "errno {code} ({error}) must end the session"
            );
        }

        // An error with no OS number at all is not a per-packet verdict either.
        assert!(!is_per_packet_send_error(&std::io::Error::other(
            "synthetic"
        )));
    }

    /// What Surge advertises as `max_datagram_frame_size`, and therefore the
    /// limit the oversize path actually meets in production.
    const SURGE_MAX_DATAGRAM_FRAME_SIZE: usize = 1300;

    /// One `info!` per session, then silence.
    ///
    /// RFC 9298 §6.1 fixes the behaviour — the packet is dropped, never downgraded
    /// to a capsule — so only its visibility is in question here. At `debug!`
    /// alone the condition could not be seen at all in production, and a line per
    /// dropped packet would be the flood D44 removed elsewhere.
    ///
    /// A pure function for the same reason as the errno rule above: a live session
    /// needs a real QUIC connection, while the decision being asserted lives
    /// entirely in the arithmetic and the flag.
    #[test]
    fn only_the_first_oversize_drop_of_a_session_is_reported() {
        // A 4 KiB answer — an EDNS0/DNSSEC response is routinely this size.
        let oversize = datagram::encoded_len(9, datagram::CONTEXT_ID_UDP_PAYLOAD, 4096);
        assert!(oversize > SURGE_MAX_DATAGRAM_FRAME_SIZE);

        let mut reported = false;
        assert_eq!(
            oversize_verdict(oversize, SURGE_MAX_DATAGRAM_FRAME_SIZE, &mut reported),
            Oversize::DropAndReport,
            "an operator must be told once that this is happening"
        );

        for _ in 0..3 {
            assert_eq!(
                oversize_verdict(oversize, SURGE_MAX_DATAGRAM_FRAME_SIZE, &mut reported),
                Oversize::DropQuietly,
                "every later drop in the same session stays at debug level"
            );
        }
    }

    /// The other half: an ordinary packet is sent untouched and does not spend the
    /// one report a session gets.
    #[test]
    fn a_packet_within_the_limit_is_sent_and_costs_no_report() {
        let fits = datagram::encoded_len(9, datagram::CONTEXT_ID_UDP_PAYLOAD, 512);
        assert!(fits <= SURGE_MAX_DATAGRAM_FRAME_SIZE);

        let mut reported = false;
        for _ in 0..3 {
            assert_eq!(
                oversize_verdict(fits, SURGE_MAX_DATAGRAM_FRAME_SIZE, &mut reported),
                Oversize::Fits
            );
        }
        assert!(!reported, "a packet that fits is not a drop");

        // Exactly the limit still fits; one byte past it does not, and that is the
        // drop the session reports.
        assert_eq!(
            oversize_verdict(
                SURGE_MAX_DATAGRAM_FRAME_SIZE,
                SURGE_MAX_DATAGRAM_FRAME_SIZE,
                &mut reported
            ),
            Oversize::Fits
        );
        assert_eq!(
            oversize_verdict(
                SURGE_MAX_DATAGRAM_FRAME_SIZE + 1,
                SURGE_MAX_DATAGRAM_FRAME_SIZE,
                &mut reported
            ),
            Oversize::DropAndReport
        );
    }

    /// RFC 9298 §5 lets a client send UDP payloads before the response arrives,
    /// and lets the proxy buffer them. Registering the session before the target
    /// socket exists is what turns that permission into behaviour: a datagram the
    /// router delivers while the session loop has not started yet must still be
    /// there when it does — once, in order, and without a consumer running.
    ///
    /// Deterministic on purpose: forcing that ordering through a live server
    /// would mean racing the resolver, so the guarantee is asserted where it
    /// actually lives, on the registry and its queue.
    #[tokio::test]
    async fn datagrams_delivered_before_the_session_starts_are_kept() {
        let registry = Arc::new(SessionRegistry::default());
        let (inbound_tx, mut inbound) = mpsc::channel(INBOUND_QUEUE_DEPTH);
        let _guard = registry.register(9, inbound_tx);

        // Exactly what `route_datagrams` does, with nothing reading the far end.
        for payload in [b"first".as_slice(), b"second".as_slice()] {
            let sink = registry.get(9).expect("the session is registered");
            sink.try_send(Bytes::copy_from_slice(payload))
                .expect("an early datagram must be buffered, not refused");
        }

        // The session loop starts only now.
        assert_eq!(inbound.recv().await.as_deref(), Some(b"first".as_slice()));
        assert_eq!(inbound.recv().await.as_deref(), Some(b"second".as_slice()));
        assert!(
            inbound.try_recv().is_err(),
            "a buffered datagram must be delivered once, not replayed"
        );
    }

    /// The other half of the same design: the buffer is bounded by
    /// [`INBOUND_QUEUE_DEPTH`], and a request that never reaches its target
    /// discards whatever it had accumulated.
    #[tokio::test]
    async fn the_early_buffer_is_bounded_and_dies_with_the_session() {
        let registry = Arc::new(SessionRegistry::default());
        let (inbound_tx, inbound) = mpsc::channel(INBOUND_QUEUE_DEPTH);
        let guard = registry.register(9, inbound_tx);

        let sink = registry.get(9).expect("the session is registered");
        for _ in 0..INBOUND_QUEUE_DEPTH {
            sink.try_send(Bytes::from_static(b"x"))
                .expect("within the queue depth");
        }
        assert!(
            sink.try_send(Bytes::from_static(b"x")).is_err(),
            "the queue must stop accepting at its depth rather than grow"
        );

        // A refusal path returns before the session runs: the guard drops, the
        // Quarter Stream ID stops routing, and the buffer goes with the receiver.
        drop(guard);
        drop(inbound);
        assert!(registry.get(9).is_none());
        assert!(
            sink.try_send(Bytes::from_static(b"x")).is_err(),
            "nothing may be handed to a session that was refused"
        );
    }

    #[test]
    fn registry_routes_by_quarter_stream_id() {
        let registry = Arc::new(SessionRegistry::default());
        let (tx_a, _rx_a) = mpsc::channel(1);
        let (tx_b, _rx_b) = mpsc::channel(1);

        let guard_a = registry.register(1, tx_a);
        let guard_b = registry.register(2, tx_b);
        assert_eq!(registry.len(), 2);
        assert!(registry.get(1).is_some());
        assert!(registry.get(2).is_some());
        assert!(registry.get(3).is_none());

        drop(guard_a);
        assert_eq!(registry.len(), 1);
        assert!(registry.get(1).is_none(), "the guard must deregister");

        drop(guard_b);
        assert!(registry.is_empty());
    }
}
