//! TCP CONNECT tunnels (RFC 9114 §4.4).
//!
//! # Close semantics
//!
//! A CONNECT tunnel is two independent byte streams, and getting their
//! termination right is what makes protocols that half-close (notably older
//! HTTP and some database clients) work through the proxy:
//!
//! | event | reaction |
//! |---|---|
//! | client finishes its sending side (FIN) | shut down **only** the write side of the TCP socket, keep reading from the target |
//! | target reaches EOF | finish our sending side, keep reading from the client |
//! | target resets or errors | reset the request stream with `H3_CONNECT_ERROR`, whichever direction noticed |
//! | client resets the request stream, or stops reading it | close the TCP connection with a reset, and cancel the direction the client left alone with `H3_REQUEST_CANCELLED` |
//!
//! The two directions therefore run as independent pumps that are joined, plus a
//! sticky teardown signal for the abnormal cases where one direction failing
//! must stop the other. The signal carries *why* the tunnel is being torn down —
//! see `Teardown` below — because the code the pump that did not see the failure
//! has to put on its own half follows from the reason: `H3_CONNECT_ERROR` when
//! the target failed, `H3_REQUEST_CANCELLED` when the client cancelled.
//!
//! Only the last row aborts the TCP connection; see `abort_target` for why the
//! other three keep their FIN semantics.
//!
//! # What bounds the waits
//!
//! While both directions are live nothing here is on a timer, and nothing needs
//! to be: each pump is the other's watchdog. A client that abandons the request
//! stream is met by the read pump, or -- when that pump is parked in a write --
//! by the `Reader::reset_by_peer` arm beside it; a target that fails is met by
//! whichever pump touches the socket next. Every one of those raises a teardown,
//! and a teardown is what ends the other pump's wait.
//!
//! The first two rows of the table above take that watchdog away, because they
//! are the two endings that end a direction *without* a teardown: the pump
//! returns, and the surviving direction is left with nobody watching it. A
//! client that finishes its sending side and then stops granting flow-control
//! credit, or a target that reaches EOF and then stops reading, would hold the
//! target socket, its file descriptor and the tunnel slot for as long as the
//! QUIC connection lasts -- which keep-alives can make indefinite.
//!
//! So from the moment one direction has ended cleanly, each write in the
//! surviving direction is bounded by `[limits] udp_session_timeout`, the same
//! knob a CONNECT-UDP session's idle bound comes from. Each write gets its own
//! budget, so a client that keeps reading may take hours to drain a download
//! after its FIN. What the budget bounds is the *completion* of one write
//! rather than progress on it, though: a peer that takes a few bytes every so
//! often, and never enough to finish the write it woke, is cut once that one
//! write has been outstanding for a whole budget. So there is a floor under how
//! slowly a half-closed tunnel may be drained -- one relay chunk, up to
//! `RELAY_BLOCK_SIZE`, per budget on the target -> client side and one of
//! quinn's ~1.4 KB pieces per budget on the other -- which at the default 180 s
//! is orders of magnitude under any real client. A tunnel whose two directions
//! are both still open is untouched however long a write parks, because there
//! the other pump is still the watchdog.
//!
//! What nothing bounds is the surviving direction parked in a *read*. A target
//! that has taken the client's FIN may legitimately take minutes to answer, and
//! a bound there would cut the very half-closes this proxy exists to carry, so a
//! half-closed tunnel with no traffic at all on it is deliberately left to run.
//! What limits that is capacity rather than time: `max_connections` x
//! `max_targets_per_conn` sockets, the product the fd budget is sized from.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, info};

use crate::h3api::{
    self, Buffer, Fields, Reader, RespondError, Status, Stream, StreamError, Writer,
};
use crate::tunnel;
use crate::tunnel::{Context, Unreachable};

/// Smallest window `read_buf` is ever offered on the target → client relay.
///
/// The threshold half of the pair below: a block is kept in use until fewer
/// than this many bytes are left in it, so every read still has at least 16 KiB
/// of room. It is also the size of the *first* allocation a tunnel makes, so a
/// tunnel that never carries a byte costs 16 KiB rather than a whole block.
const RELAY_BUF_SIZE: usize = 16 * 1024;

/// The block reads are cut from once the initial 16 KiB is used up.
///
/// # Why a block rather than a buffer
///
/// `BytesMut::split` hands the filled bytes on without copying them, which is
/// what keeps the relay allocation-light — but the piece handed on and the
/// piece kept share one heap block, and quinn holds its piece until the segment
/// carrying it has been acknowledged. So the memory a tunnel occupies is
/// *blocks* × block size, while the only thing bounding it — quinn's
/// `send_window`, 10 MB per connection — counts bytes. Reserving a fresh
/// [`RELAY_BUF_SIZE`] block per read made every read, however small, pin 16 KiB:
/// 11.7x amplification for MTU-sized reads and 238x for 64-byte ones.
///
/// # The arithmetic
///
/// A block is abandoned only once its remaining capacity falls below
/// [`RELAY_BUF_SIZE`], so at least `RELAY_BLOCK_SIZE - RELAY_BUF_SIZE` = 48 KiB
/// of it has been handed to the client by then. Worst-case amplification is
/// therefore 64 / 48 = 1.33x whatever the read sizes are, against a factor that
/// grew without bound as reads got smaller.
///
/// # What it costs at rest
///
/// The trade is paid in resting size: a tunnel that has relayed a single byte
/// holds one whole block across every wait from then on, so an idle tunnel
/// costs 64 KiB rather than the 16 KiB it started with. Saturated at the
/// default limits -- `max_connections` x `max_targets_per_conn` -- that is
/// 4 GiB, and at the ~20 live tunnels per connection seen in production about
/// 1.3 MB per connection. The amplification is what produces the memory peaks
/// worth avoiding, and 1.33x beats 2x there; `docs/configuration.md` says the
/// same to operators.
const RELAY_BLOCK_SIZE: usize = 64 * 1024;

/// Why the tunnel is being torn down, carried on the teardown channel.
///
/// A bare "stop now" flag is not enough, because neither pump can tell from a
/// flag alone how to close its own half — and simply returning gets it wrong in
/// one direction each time. `quinn::SendStream::drop` finishes the stream, so a
/// writer dropped on a target error puts a clean FIN on the wire and a truncated
/// response reads to the client as a complete one; `quinn::RecvStream::drop`
/// stops the peer with code 0, so a reader dropped on the same target error
/// contradicts the `H3_CONNECT_ERROR` the other half just sent.
///
/// With the reason attached, a target error reaches the client as
/// `H3_CONNECT_ERROR` whichever pump noticed it (RFC 9114 §4.4), and a client
/// abort cancels the direction the client left alone. §4.4 asks for that
/// second one in as many words: "If the stream is reset or reading is aborted
/// by the client, a proxy SHOULD perform the same operation on the other
/// direction in order to ensure that both directions of the stream are
/// cancelled." Leaving it alone was the older reading, and it left a client
/// that reset only its sending side reading a truncated response as a complete
/// one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Teardown {
    /// Nothing has gone wrong; both directions are still relaying.
    Running,
    /// The client reset the request stream or stopped reading it.
    ClientAbort,
    /// The connection to the target failed, in either direction.
    TargetError,
}

/// One direction's clean ending, and the bound it puts on the other's writes.
///
/// Deliberately *not* a [`Teardown`] variant. A clean FIN is not an abnormal
/// end and must not reach the other pump as one: the teardown channel's whole
/// job is to say which party failed, and a sticky "the client finished" on it
/// would have every exit arm asking whether this teardown is really a teardown.
/// A separate flag says only what it says, and only the two `select!` arms that
/// need it ever look.
struct HalfClose {
    /// Raised when *this* direction reaches the ending that raises no teardown:
    /// the client's FIN in one pump, the target's EOF in the other.
    ///
    /// The receiver keeps the value after this sender is dropped, which is what
    /// lets the pump that raises it return immediately afterwards.
    mine: watch::Sender<bool>,
    /// The other direction's flag.
    other: watch::Receiver<bool>,
    /// How long a write has to complete in, once `other` is set.
    budget: Duration,
}

impl HalfClose {
    /// Records that this direction has ended cleanly.
    fn ended(&self) {
        // Fails only if the other pump has already dropped its receiver, which
        // means it has ended too and there is nothing left to bound.
        let _ = self.mine.send(true);
    }

    /// Resolves once the other direction has ended cleanly and a whole budget
    /// has then passed without this direction's write completing.
    ///
    /// A write that is progressing but not finishing is cut like any other: the
    /// budget is per write and starts when the write does, so what it measures
    /// is how long that one write has been outstanding, not how long the peer
    /// has been silent.
    ///
    /// Cancel-safe by construction rather than by care: the caller builds a
    /// fresh one of these per write, so the sleep it ends with is the budget
    /// for *that* write and the previous write having completed has already
    /// reset it. Awaiting the flag before the sleep is what also catches a FIN
    /// that lands while a write is already parked -- the arm is armed at the
    /// write's first poll, whether or not the other direction has ended by
    /// then.
    async fn stalled(&mut self) {
        while !*self.other.borrow_and_update() {
            if self.other.changed().await.is_err() {
                // The other pump dropped its sender without ever ending
                // cleanly, so it ended some other way -- and every other way
                // raises a teardown, which is the arm that acts on it. Nothing
                // for this one to do but stay out of the way.
                return std::future::pending().await;
            }
        }

        tokio::time::sleep(self.budget).await;
    }
}

/// Establishes a TCP tunnel to `authority` and relays until both directions end.
pub async fn run(authority: &str, mut stream: Stream, stream_id: u64, ctx: &Context) {
    let (host, port) = match split_authority(authority) {
        Ok(target) => target,
        Err(reason) => {
            debug!(stream_id, authority, reason, "malformed CONNECT authority");
            tunnel::refuse(&mut stream, Status::BAD_REQUEST, stream_id).await;
            return;
        }
    };

    // Port policy, resolution and destination policy, in that order and with
    // every refusal already answered by the time this returns — see
    // [`tunnel::admit_target`]. An accepted TCP tunnel carries no response
    // fields of its own, so the 200-then-close path is handed an empty list.
    let Some(allowed) =
        tunnel::admit_target(&host, port, ctx, &mut stream, stream_id, Fields::new).await
    else {
        return;
    };

    let tcp = match connect_any(&allowed, ctx.connect_timeout).await {
        Ok(tcp) => tcp,
        Err(failure) => {
            // RFC 9114 §4.4: a proxy that cannot establish the connection
            // answers with a non-2xx status rather than resetting the stream.
            // Which non-2xx follows from the RFC 9209 type, so a timeout is a
            // 504 and an unreachable target a 503 rather than all of them 502,
            // and the answer names the address that failed.
            debug!(
                stream_id,
                authority,
                ?allowed,
                error = %failure.error,
                "failed to connect to target"
            );
            tunnel::refuse_unreachable(&mut stream, &failure, stream_id).await;
            return;
        }
    };

    // A proxy should not add Nagle delay on top of whatever the endpoints do.
    if let Err(error) = tcp.set_nodelay(true) {
        debug!(stream_id, %error, "failed to set TCP_NODELAY on the target socket");
    }

    let target = tcp.peer_addr().ok();

    // Bounded exactly as every refusal is, and for the same reason
    // ([`h3api::Stream::respond_within`]): a peer that grants no flow-control
    // credit never takes even the few bytes of a 200, and nothing else would
    // ever end the wait -- the pumps below do not exist until this write
    // returns. On expiry the stream has already been reset with
    // H3_REQUEST_CANCELLED, and returning here drops `tcp`, closing the target
    // connection that will now carry nothing.
    match stream.respond_within(Status::OK, Fields::new()).await {
        Ok(()) => {}
        Err(RespondError::Failed(error)) => {
            debug!(stream_id, %error, "failed to send 200 for CONNECT");
            return;
        }
        Err(RespondError::Expired) => {
            debug!(
                stream_id,
                authority, "gave up on a 200 for CONNECT the peer would not take"
            );
            // The stream has already been reset with H3_REQUEST_CANCELLED, which
            // is the client-abort half of RFC 9114 §4.4: "If the proxy detects
            // that the client has reset the stream or aborted reading from the
            // stream, it MUST close the TCP connection", and "In all these
            // cases, if the underlying TCP implementation permits it, the proxy
            // SHOULD send a TCP segment with the RST bit set." Returning drops
            // `tcp` and closes it either way; arming the reset first is what
            // makes it the abortive close the SHOULD asks for, so a target that
            // has already accepted the connection is not left believing it was
            // finished politely.
            abort_target(&tcp);
            return;
        }
    }

    info!(
        stream_id,
        authority,
        target = %crate::logfmt::or_dash(target),
        "tcp tunnel established"
    );

    let (writer, reader) = stream.split();
    let (tcp_read, tcp_write) = tcp.into_split();

    // Sticky so a teardown cannot be missed by a pump that is not yet waiting.
    // The sender lives here, outliving both pumps.
    let (teardown, teardown_rx) = watch::channel(Teardown::Running);

    // The two clean endings, each watched by the direction it leaves alone.
    let (client_finished, client_finished_rx) = watch::channel(false);
    let (target_eof, target_eof_rx) = watch::channel(false);

    tokio::join!(
        client_to_target(
            reader,
            tcp_write,
            &teardown,
            teardown_rx.clone(),
            HalfClose {
                mine: client_finished,
                other: target_eof_rx,
                budget: ctx.idle_timeout,
            },
        ),
        target_to_client(
            writer,
            tcp_read,
            &teardown,
            teardown_rx,
            HalfClose {
                mine: target_eof,
                other: client_finished_rx,
                budget: ctx.idle_timeout,
            },
        ),
    );

    debug!(stream_id, authority, "tcp tunnel closed");
}

/// Connects to the first address that accepts, reporting the last failure.
///
/// Trying every address matters for dual-stack targets, where the AAAA record
/// may be unreachable while the A record works. The address of the last attempt
/// travels with the error, since that is the hop the client is told about.
///
/// `budget` bounds the **whole** loop rather than each address, so a name with
/// several unreachable addresses cannot multiply the wait by their number. Why
/// it is bounded at all: the tunnel slot and the file descriptor behind it are
/// held for the length of this call, and a target that silently drops SYNs
/// otherwise holds them for as long as the operating system retries — around two
/// minutes on Linux. No attacker is needed for that; a handful of black-holed
/// addresses during ordinary browsing is enough to spend a connection's whole
/// `max_targets_per_conn` on tunnels that will never open.
///
/// One thing this deliberately does not do is notice the client giving up: a
/// request stream reset mid-connect leaves the attempt running until it finishes
/// or the budget expires. Bounding it is what makes that acceptable.
async fn connect_any(
    addresses: &[SocketAddr],
    budget: Option<Duration>,
) -> Result<TcpStream, Unreachable> {
    connect_any_with(addresses, budget, TcpStream::connect).await
}

/// [`connect_any`] with the per-address connect step supplied by the caller.
///
/// Split out only so the budget can be tested against a connect that never
/// completes; production always passes [`TcpStream::connect`].
async fn connect_any_with<C, F>(
    addresses: &[SocketAddr],
    budget: Option<Duration>,
    connect: C,
) -> Result<TcpStream, Unreachable>
where
    C: Fn(SocketAddr) -> F,
    F: std::future::Future<Output = io::Result<TcpStream>>,
{
    // Taken once, before the first attempt: every address draws on the same
    // budget.
    let deadline = budget.map(|budget| tokio::time::Instant::now() + budget);
    let mut last = None;

    for address in addresses {
        let attempt = connect(*address);

        let result = match deadline {
            Some(deadline) => match tokio::time::timeout_at(deadline, attempt).await {
                Ok(result) => result,
                // Reported as the hop that was still in flight, which is the one
                // the client is waiting on.
                Err(_) => {
                    return Err(Unreachable {
                        next_hop: Some(*address),
                        error: io::Error::new(
                            io::ErrorKind::TimedOut,
                            "the connect budget expired before the target answered",
                        ),
                    })
                }
            },
            None => attempt.await,
        };

        match result {
            Ok(tcp) => return Ok(tcp),
            Err(error) => {
                debug!(%address, %error, "target address unreachable, trying the next");
                last = Some(Unreachable {
                    next_hop: Some(*address),
                    error,
                });
            }
        }
    }

    Err(last.unwrap_or_else(Unreachable::no_addresses))
}

/// Pumps client → target.
async fn client_to_target(
    mut reader: Reader,
    mut tcp_write: OwnedWriteHalf,
    teardown: &watch::Sender<Teardown>,
    mut teardown_rx: watch::Receiver<Teardown>,
    mut half: HalfClose,
) {
    let budget = half.budget;

    // The two places that can notice a teardown — the wait for the client's
    // next chunk and the write of the one already in hand — end this direction
    // identically, and `OwnedWriteHalf::forget` consumes the half, so the
    // reason is carried out of the loop and acted on once below.
    let reason = loop {
        let chunk = tokio::select! {
            biased;
            reason = torn_down(&mut teardown_rx) => break reason,
            chunk = reader.recv_data() => chunk,
        };

        match chunk {
            Ok(Some(data)) => {
                // The write is under the same signal as the read, because it is
                // the half that can park indefinitely: a target that has stopped
                // reading fills every buffer between here and it, and a teardown
                // raised by the other pump would otherwise wait for that write
                // to finish before the socket could be closed at all —
                // RFC 9114 §4.4's "if a proxy detects an error with the stream
                // or the QUIC connection, it MUST close the TCP connection"
                // delayed for as long as a target chooses to stall.
                //
                // Abandoning `write_all` part-way is acceptable here and only
                // here. Every path that raises a teardown ends with the target
                // socket reset or dropped, so the target never sees a truncated
                // chunk followed by more of the tunnel: it sees the end of the
                // connection. Resource bounds are unchanged — `data` is dropped
                // with this arm either way.
                //
                // The client's own RESET_STREAM is the third thing that can
                // end the wait, and it needs a branch of its own: the read
                // that would have met it as an error is not running while this
                // write is, and a target that has stopped reading never ends
                // the write. Without it, RFC 9114 §4.4's "If the proxy detects
                // that the client has reset the stream or aborted reading from
                // the stream, it MUST close the TCP connection" went unmet for
                // the life of the QUIC connection -- the target socket, its
                // file descriptor and the tunnel slot all held by a request the
                // client had already abandoned.
                //
                // That branch goes *last*, which is the one thing the ordering
                // here decides. `biased` polls in order and stops at the first
                // arm that is ready, so a write that completes on its first
                // poll -- the ordinary case, a target keeping up -- never polls
                // the watcher at all, and never arms the timer
                // `Reader::reset_by_peer` falls back on while the client's next
                // chunks are already buffered. The watcher only starts costing
                // anything once the write is genuinely parked, which is the
                // only state it is there for.
                let written = tokio::select! {
                    biased;
                    reason = torn_down(&mut teardown_rx) => break reason,
                    written = tcp_write.write_all(&data) => written,
                    error = reader.reset_by_peer() => {
                        client_aborted(&error, tcp_write, teardown);
                        return;
                    }
                    // The mirror of the arm in `target_to_client`, and the same
                    // argument in the other direction: once the target has sent
                    // its EOF, the pump that would have noticed it stall is
                    // gone, and a target that stops *reading* parks this write
                    // for the life of the QUIC connection. It arms only after
                    // that EOF, and it goes last for the reason the watcher
                    // above does.
                    () = half.stalled() => {
                        debug!(
                            timeout_secs = budget.as_secs(),
                            "target stopped reading after its own EOF, cutting the tunnel"
                        );
                        // The target is the party at fault, which is what the
                        // write-error arm below reports too. This one adds the
                        // abortive close, because unlike there the socket is
                        // still open: the target must not read a polite FIN off
                        // a tunnel this server cut.
                        reader.stop_receiving(h3api::CONNECT_ERROR);
                        abort_target(tcp_write.as_ref());
                        tcp_write.forget();
                        let _ = teardown.send(Teardown::TargetError);
                        return;
                    }
                };

                if let Err(error) = written {
                    // The target is gone (RST, EPIPE): the tunnel is broken.
                    debug!(%error, "write to target failed");
                    reader.stop_receiving(h3api::CONNECT_ERROR);
                    let _ = teardown.send(Teardown::TargetError);
                    return;
                }
            }
            // The client finished its sending side. Propagate it as a TCP FIN
            // and leave the other direction running, so anything the target
            // still has to say reaches the client.
            Ok(None) => {
                // Raised before the shutdown rather than after it, because this
                // is the moment the other direction loses its watchdog: from
                // here nothing but its own bound is left to notice a client
                // that stops reading what it asked for.
                half.ended();
                if let Err(error) = tcp_write.shutdown().await {
                    debug!(%error, "failed to shut down the target write side");
                }
                return;
            }
            Err(error) => {
                client_aborted(&error, tcp_write, teardown);
                return;
            }
        }
    };

    // The other direction ended the tunnel abnormally. Whatever ended it is
    // spelled out on this half too, rather than left to the `Reader` drop to
    // stop the client with code 0 — which would leave the two halves carrying
    // different verdicts on the same event.
    //
    // A target error is `H3_CONNECT_ERROR`, the code the other pump put on the
    // response direction (RFC 9114 §4.4). A client abort is
    // `H3_REQUEST_CANCELLED`: §4.4 asks a proxy to "perform the same operation
    // on the other direction in order to ensure that both directions of the
    // stream are cancelled", and §8.1 gives that code for "the request or its
    // response (including pushed response) is cancelled".
    //
    // The ask reaches the wire here and not later: `stop_receiving` is
    // `quinn::RecvStream::stop`, which queues STOP_SENDING at the point of call.
    // On the half a client has already closed it is a no-op — quinn answers
    // `ClosedStream`, which `FrameReader::stop` discards, because a stream that
    // is already over has nothing left to stop.
    reader.stop_receiving(match reason {
        Teardown::TargetError => h3api::CONNECT_ERROR,
        _ => h3api::REQUEST_CANCELLED,
    });

    // Forgotten rather than dropped: shutting the write side down on the way out
    // would put a FIN on the wire, which is the wrong signal for every path that
    // gets here — and would overtake the reset when the other pump armed one.
    tcp_write.forget();
}

/// Ends the client → target direction after the client abandoned the stream.
///
/// Shared by the two places that can notice it, because RFC 9114 §4.4 gives
/// both the same answer: the read that fails with a reset, and the write that
/// was parked when the RESET_STREAM landed. The two differ only in where the
/// news came from.
fn client_aborted(
    error: &StreamError,
    tcp_write: OwnedWriteHalf,
    teardown: &watch::Sender<Teardown>,
) {
    match h3api::peer_reset_code(error) {
        Some(code) => debug!(code, "client reset the tunnel"),
        None => debug!(%error, "reading from the client failed"),
    }
    // The request stream is unusable: close the TCP connection by stopping the
    // other pump, which drops the read half. The client aborted the tunnel, so
    // that close is a reset (RFC 9114 §4.4) rather than the FIN a natural drop
    // would produce.
    abort_target(tcp_write.as_ref());
    tcp_write.forget();
    let _ = teardown.send(Teardown::ClientAbort);
}

/// Pumps target → client.
async fn target_to_client(
    mut writer: Writer,
    mut tcp_read: OwnedReadHalf,
    teardown: &watch::Sender<Teardown>,
    mut teardown_rx: watch::Receiver<Teardown>,
    mut half: HalfClose,
) {
    let budget = half.budget;
    let mut buf = BytesMut::with_capacity(RELAY_BUF_SIZE);

    // Both places that can notice a teardown -- the wait for the target's next
    // read and the write of the bytes already in hand -- end this direction
    // identically, so the reason is carried out of the loop and acted on once
    // below, exactly as `client_to_target` does it.
    let reason = loop {
        ensure_window(&mut buf);

        let read = tokio::select! {
            biased;
            reason = torn_down(&mut teardown_rx) => break reason,
            read = tcp_read.read_buf(&mut buf) => read,
        };

        match read {
            // Target EOF: finish our sending side only. The client may still
            // have data for the target.
            Ok(0) => {
                // As in the opposite pump: raised first, because this is the
                // moment the client -> target direction is left with no
                // watchdog but its own bound.
                half.ended();
                if let Err(error) = writer.finish() {
                    debug!(%error, "failed to finish the response stream");
                }
                return;
            }
            Ok(_) => {
                // `split` hands the filled bytes over without copying them.
                let data: Buffer = buf.split().freeze();

                // The write is under the same signal as the read, for the
                // reason its opposite number in `client_to_target` is: a client
                // that has stopped reading grants no more flow-control credit,
                // so this write parks until the connection ends, and a teardown
                // raised by the other pump would wait behind it -- the target
                // socket held open for as long as the client cares to stall.
                //
                // Abandoning `send_data` part-way can leave a truncated DATA
                // frame on the stream. That is harmless only because the
                // teardown arm below resets the writer before anything else can
                // be written: the peer that reads the partial frame reads a
                // RESET_STREAM behind it, which ends the stream as failed, so
                // the truncation can never be mistaken for a complete response.
                // RFC 9114 §7.1 says as much of the reader's side: "When a
                // stream terminates cleanly, if the last frame on the stream was
                // truncated, this MUST be treated as a connection error of type
                // H3_FRAME_ERROR. Streams that terminate abruptly may be reset
                // at any point in a frame." So the reset is not a way of tidying
                // the truncation up after the fact -- it is what makes the
                // truncation legal, and a FIN in its place would be the
                // connection error that sentence names.
                let sent = tokio::select! {
                    biased;
                    reason = torn_down(&mut teardown_rx) => break reason,
                    sent = writer.send_data(data) => sent,
                    // Once the client has finished its sending side, the pump
                    // that would have noticed it stop reading is gone -- its
                    // `Ok(None)` arm raises no teardown, by design -- so this
                    // write is all that is left to notice, and it would
                    // otherwise park until the connection ends. Last in the
                    // order for the reason the watcher in `client_to_target`
                    // is: a write that completes on its first poll never arms
                    // the timer at all.
                    () = half.stalled() => {
                        debug!(
                            timeout_secs = budget.as_secs(),
                            "client stopped reading after its own FIN, cutting the tunnel"
                        );
                        // Reset rather than left to a FIN, and for the reason
                        // the teardown arm below is: this write was abandoned
                        // part-way, so the DATA frame on the wire is truncated
                        // and only a RESET_STREAM behind it stops that
                        // truncation reading as a complete response. The same
                        // argument, with RFC 9114 §7.1 quoted, is above.
                        writer.reset(h3api::REQUEST_CANCELLED);
                        abort_target(tcp_read.as_ref());
                        // Nobody is listening -- the other pump returned when
                        // the client finished -- but every other exit from this
                        // loop says why it left, and an exit that quietly did
                        // not would be the one to misread later.
                        let _ = teardown.send(Teardown::ClientAbort);
                        return;
                    }
                };

                if let Err(error) = sent {
                    match h3api::peer_reset_code(&error) {
                        Some(code) => debug!(code, "client reset the tunnel"),
                        None => debug!(%error, "sending to the client failed"),
                    }
                    // RFC 9114 §4.4's other client-side abort: the client has
                    // stopped reading the tunnel, so what is left of the target
                    // connection is closed with a reset. The other pump does the
                    // dropping; this only decides how the socket closes.
                    abort_target(tcp_read.as_ref());
                    let _ = teardown.send(Teardown::ClientAbort);
                    return;
                }
            }
            Err(error) => {
                // The target reset the connection. RFC 9114 §4.4 maps this onto
                // a stream reset with H3_CONNECT_ERROR.
                debug!(%error, "read from target failed");
                writer.reset(h3api::CONNECT_ERROR);
                let _ = teardown.send(Teardown::TargetError);
                return;
            }
        }
    };

    // Returning without saying anything would drop the `Writer` — and a dropped
    // `quinn::SendStream` finishes rather than resets, so whatever of the
    // target's answer had not been sent would reach the client as a complete
    // response. Both reasons are therefore spelled out here; only the code
    // differs.
    //
    // The write pump finding the target broken is a stream error of type
    // H3_CONNECT_ERROR (RFC 9114 §4.4). A client abort is H3_REQUEST_CANCELLED,
    // because §4.4 asks that "if the stream is reset or reading is aborted by
    // the client, a proxy SHOULD perform the same operation on the other
    // direction in order to ensure that both directions of the stream are
    // cancelled" — and §8.1 defines that code as "the request or its response
    // (including pushed response) is cancelled". A client that reset only its
    // sending side is exactly the case that used to be told its truncated
    // response was complete.
    writer.reset(match reason {
        Teardown::TargetError => h3api::CONNECT_ERROR,
        _ => h3api::REQUEST_CANCELLED,
    });
}

/// Offers `buf` a full-sized window to read into, allocating a block at a time.
///
/// Without this, `read_buf` reserves only 64 bytes at a time once the initial
/// capacity is used up.
///
/// Reserved a block at a time rather than a window at a time: after the `split`
/// that hands filled bytes on, what is left of the block is shared with the
/// `Bytes` quinn is holding, so a `reserve` that cannot be satisfied from it
/// allocates a whole new one. Asking only when fewer than a window remains is
/// what lets consecutive reads come out of the same block -- see
/// [`RELAY_BLOCK_SIZE`] for the arithmetic, and the tests below for the two
/// halves of it that are pinned: every read is offered [`RELAY_BUF_SIZE`], and
/// a block carries at least `RELAY_BLOCK_SIZE - RELAY_BUF_SIZE` before it is
/// replaced.
fn ensure_window(buf: &mut BytesMut) {
    if buf.capacity() < RELAY_BUF_SIZE {
        buf.reserve(RELAY_BLOCK_SIZE);
    }
}

/// Arms an abortive close on the target connection (RFC 9114 §4.4).
///
/// §4.4 requires the TCP connection to be closed when the proxy "detects that
/// the client has reset the stream or aborted reading from the stream", and adds
/// that "in all these cases, if the underlying TCP implementation permits it,
/// the proxy SHOULD send a TCP segment with the RST bit set". `SO_LINGER` at
/// zero is how that is asked for: the next close of the socket aborts instead of
/// draining, so the target learns the tunnel was cut rather than politely
/// finished, and stops holding a half-open connection until its own timeout.
///
/// Setting the option has no effect until the socket is closed, so arming it on
/// the way out cannot disturb anything still in flight.
///
/// **This is only ever called on a path that cuts a live tunnel short**: the two
/// client aborts, and the two bounds that fire when a half-closed tunnel's
/// surviving direction stalls. A clean client FIN, a target EOF, and a target
/// that resets or errors all keep their existing FIN semantics — the half-close
/// table at the top of this module is the behaviour this proxy exists to get
/// right, and a reset is not a substitute for any of it. The bounds are on the
/// abortive side of that line because they leave a transfer unfinished: a FIN
/// would tell the target the tunnel was seen through.
///
/// `set_linger` is deprecated in tokio because `SO_LINGER` can make a close block
/// the thread while the send buffer drains. That is the *non-zero* timeout; at
/// zero the close is by definition immediate, which is exactly why this is the
/// one safe use of it.
fn abort_target(tcp: &TcpStream) {
    #[allow(deprecated)]
    if let Err(error) = tcp.set_linger(Some(Duration::ZERO)) {
        // The connection still closes, just with a FIN: a SHOULD unmet, not a
        // tunnel broken.
        debug!(%error, "failed to arm a TCP reset on the target socket");
    }
}

/// Resolves once either direction has asked for the tunnel to be torn down,
/// with the reason it gave.
async fn torn_down(teardown_rx: &mut watch::Receiver<Teardown>) -> Teardown {
    loop {
        let reason = *teardown_rx.borrow_and_update();
        if reason != Teardown::Running {
            return reason;
        }
        // The sender outlives both pumps, so this cannot actually fail; treat a
        // closed channel as a teardown anyway. Reported as a client abort,
        // which is the reason that blames nothing: no pump saw the target fail,
        // so the waking half is cancelled rather than told there was an error
        // upstream.
        if teardown_rx.changed().await.is_err() {
            return Teardown::ClientAbort;
        }
    }
}

/// Splits a CONNECT `:authority` into host and port.
///
/// RFC 9114 §4.4 requires authority-form (`host:port`), with IPv6 literals in
/// brackets as per RFC 3986.
fn split_authority(authority: &str) -> Result<(String, u16), &'static str> {
    if authority.contains('@') {
        return Err("userinfo is not allowed in a CONNECT authority");
    }

    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => {
            let (host, rest) = rest.split_once(']').ok_or("unterminated IPv6 literal")?;
            if host.is_empty() {
                return Err("empty host");
            }
            if host.contains(['[', ']']) {
                // The same rule as the unbracketed arm below, and refused here
                // for the same reason: RFC 3986 §3.2.2 gives "[" and "]" to the
                // IP-literal form alone, so a bracket *inside* one is not part
                // of the address it delimits. `[a[b]:443` must not be dialled
                // as `a[b`. Written as the same two-character predicate rather
                // than as a check for "[" only, so the two arms cannot drift:
                // `]` cannot appear here, since the split above takes the first
                // one, and asking about it costs nothing.
                return Err("stray bracket in host");
            }
            let port = rest
                .strip_prefix(':')
                .ok_or("missing port after IPv6 literal")?;
            (host.to_owned(), port)
        }
        None => {
            let (host, port) = authority.rsplit_once(':').ok_or("missing port")?;
            if host.is_empty() {
                return Err("empty host");
            }
            if host.contains(':') {
                // Ambiguous with host:port; brackets are mandatory.
                return Err("unbracketed IPv6 literal");
            }
            if host.contains(['[', ']']) {
                // A bracket that did not open the authority is not part of any
                // host: RFC 3986 §3.2.2 gives them to the IP-literal form alone,
                // which the arm above is. Refused rather than tolerated because
                // the host is what gets dialled and what gets logged, and
                // `example.com]` must not quietly become `example.com`.
                return Err("stray bracket in host");
            }
            (host.to_owned(), port)
        }
    };

    let port: u16 = port.parse().map_err(|_| "invalid port")?;
    if port == 0 {
        return Err("port must not be zero");
    }

    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::{
        connect_any_with, ensure_window, split_authority, RELAY_BLOCK_SIZE, RELAY_BUF_SIZE,
    };
    use bytes::BytesMut;
    use std::io;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::net::TcpStream;

    fn address(literal: &str) -> SocketAddr {
        literal.parse().expect("socket address")
    }

    /// A target that black-holes SYNs is the case the budget exists for: the
    /// operating system would keep retrying for around two minutes, and the
    /// tunnel slot and file descriptor are held for all of it.
    ///
    /// Real time with a small budget rather than a paused clock, because tokio's
    /// `test-util` feature is not enabled in this tree. The upper bound is two
    /// orders of magnitude above the budget, so only an unbounded wait fails it.
    #[tokio::test]
    async fn the_connect_budget_bounds_a_target_that_never_answers() {
        let addresses = [address("192.0.2.1:443"), address("192.0.2.2:443")];
        let budget = Duration::from_millis(50);
        let started = std::time::Instant::now();

        // The outer timeout is what turns a regression here into a failure
        // rather than a hung test run.
        let failure = tokio::time::timeout(
            Duration::from_secs(5),
            connect_any_with(&addresses, Some(budget), |_| {
                std::future::pending::<io::Result<TcpStream>>()
            }),
        )
        .await
        .expect("the budget must bound the wait")
        .expect_err("a connect that never answers must not succeed");
        let elapsed = started.elapsed();

        assert_eq!(failure.error.kind(), io::ErrorKind::TimedOut);
        // The hop named is the one still in flight, which is the one the client
        // is waiting on.
        assert_eq!(failure.next_hop, Some(addresses[0]));
        assert!(elapsed >= budget, "returned early, after {elapsed:?}");
    }

    /// One budget for the whole list, not one per address: several unreachable
    /// addresses must not multiply the wait by their number.
    ///
    /// The first address spends three quarters of the budget and fails, the
    /// second never answers. Shared, that ends at the budget; one budget each
    /// would end at 1.75 times it, which the upper bound below excludes.
    #[tokio::test]
    async fn every_address_draws_on_the_same_budget() {
        let addresses = [address("192.0.2.1:443"), address("192.0.2.2:443")];
        let budget = Duration::from_millis(400);
        let started = std::time::Instant::now();

        let failure = tokio::time::timeout(
            Duration::from_secs(5),
            connect_any_with(&addresses, Some(budget), |address| async move {
                if address == addresses[0] {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                }
                std::future::pending().await
            }),
        )
        .await
        .expect("the budget must bound the wait")
        .expect_err("the budget must expire");
        let elapsed = started.elapsed();

        assert_eq!(failure.error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(failure.next_hop, Some(addresses[1]));
        assert!(
            elapsed < Duration::from_millis(600),
            "the second address got a budget of its own: {elapsed:?}"
        );
    }

    /// With the budget disabled the loop behaves exactly as it did before it
    /// existed: every address is tried, and the last failure is what travels out.
    #[tokio::test]
    async fn a_disabled_budget_tries_every_address() {
        let addresses = [address("192.0.2.1:443"), address("192.0.2.2:443")];
        let attempted = std::cell::RefCell::new(Vec::new());

        let failure = connect_any_with(&addresses, None, |address| {
            attempted.borrow_mut().push(address);
            async move { Err(io::Error::from(io::ErrorKind::ConnectionRefused)) }
        })
        .await
        .expect_err("every address refuses");

        assert_eq!(attempted.into_inner(), addresses);
        assert_eq!(failure.error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(failure.next_hop, Some(addresses[1]));
    }

    /// An empty list has no hop to name, and must not be reported as a timeout.
    #[tokio::test]
    async fn an_empty_address_list_names_no_hop() {
        let failure = tokio::time::timeout(
            Duration::from_secs(5),
            connect_any_with(&[], Some(Duration::from_secs(10)), |_| {
                std::future::pending::<io::Result<TcpStream>>()
            }),
        )
        .await
        .expect("an empty list needs no waiting at all")
        .expect_err("there is nothing to connect to");

        assert_eq!(failure.error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(failure.next_hop, None);
    }

    #[test]
    fn accepts_host_and_port() {
        assert_eq!(
            split_authority("example.com:443"),
            Ok(("example.com".to_owned(), 443))
        );
        assert_eq!(
            split_authority("192.0.2.1:8080"),
            Ok(("192.0.2.1".to_owned(), 8080))
        );
    }

    #[test]
    fn accepts_bracketed_ipv6() {
        assert_eq!(
            split_authority("[2001:db8::1]:443"),
            Ok(("2001:db8::1".to_owned(), 443))
        );
        assert_eq!(split_authority("[::1]:53"), Ok(("::1".to_owned(), 53)));
    }

    #[test]
    fn rejects_missing_or_bad_port() {
        assert!(split_authority("example.com").is_err());
        assert!(split_authority("example.com:").is_err());
        assert!(split_authority("example.com:0").is_err());
        assert!(split_authority("example.com:99999").is_err());
        assert!(split_authority("example.com:http").is_err());
        assert!(split_authority("[2001:db8::1]").is_err());
        assert!(split_authority("[2001:db8::1]443").is_err());
    }

    #[test]
    fn rejects_ambiguous_and_malformed_hosts() {
        assert!(split_authority(":443").is_err());
        assert!(split_authority("2001:db8::1:443").is_err());
        assert!(split_authority("[2001:db8::1:443").is_err());
        assert!(split_authority("user:pass@example.com:443").is_err());
    }

    /// A bracket anywhere but around the whole host is not part of a host.
    ///
    /// `uri_authority` passes them through wherever RFC 3986 allows the
    /// character, so this is where the shape is judged -- and `example.com]`
    /// must not become `example.com` on the way to the resolver (review M3).
    #[test]
    fn rejects_a_stray_bracket_in_a_host() {
        assert!(split_authority("example.com]:443").is_err());
        assert!(split_authority("example.com[:443").is_err());
        assert!(split_authority("[example.com:443").is_err());
        assert!(split_authority("exa]mple.com:443").is_err());
    }

    /// The bracketed arm judges the same shape, which it used to wave through:
    /// `[a[b]:443` opened a tunnel to the host `a[b` and came back a 502 from
    /// the resolver rather than the 400 the unbracketed arm gives.
    #[test]
    fn rejects_a_stray_bracket_inside_an_ip_literal() {
        assert!(split_authority("[a[b]:443").is_err());
        assert!(split_authority("[2001:db8[::1]:443").is_err());
        assert!(split_authority("[[2001:db8::1]:443").is_err());
    }

    /// Every read is offered a full-sized window, whatever the reads before it
    /// took out of the block.
    ///
    /// The sizes are the ones a relay meets: a one-byte push, a small record, an
    /// MTU-sized segment, and a read that fills the window exactly. The frozen
    /// pieces are held for the whole run because that is what a tunnel does --
    /// quinn keeps each until the segment carrying it is acknowledged -- and
    /// holding them is what stops `reserve` from quietly reusing the block they
    /// came out of.
    #[test]
    fn every_read_is_offered_a_full_window() {
        let mut buf = BytesMut::with_capacity(RELAY_BUF_SIZE);
        let mut held = Vec::new();

        for size in [1usize, 64, 100, 1460, RELAY_BUF_SIZE]
            .into_iter()
            .cycle()
            .take(100)
        {
            ensure_window(&mut buf);
            assert!(
                buf.capacity() >= RELAY_BUF_SIZE,
                "a read was offered {} bytes, under the {RELAY_BUF_SIZE}-byte window",
                buf.capacity()
            );

            // Stands in for a read that filled `size` bytes of that window.
            buf.resize(size, 0);
            held.push(buf.split().freeze());
        }
    }

    /// Consecutive reads come out of one block, so what a tunnel pins is bounded
    /// by the bytes in flight rather than by how small its reads are.
    ///
    /// A hundred bytes a read is the shape that cost 238x before
    /// [`RELAY_BLOCK_SIZE`] existed. Counting blocks by the pointer `reserve`
    /// hands back is what catches a block replaced early, whichever of the two
    /// constants moved to cause it.
    #[test]
    fn consecutive_reads_come_out_of_one_block() {
        const READ: usize = 100;
        const RELAYED: usize = 1024 * 1024;
        /// What a block must carry before it may be replaced.
        ///
        /// Spelled out rather than taken from the constants on purpose: a bound
        /// derived from `RELAY_BLOCK_SIZE` holds whatever that constant is set
        /// to, and the size is half of what is being pinned here.
        /// `it_relay_memory` counts allocations end to end and is content with a
        /// 20 KiB block, which is the hole this closes.
        const CARRIED: usize = 48 * 1024;

        let mut buf = BytesMut::with_capacity(RELAY_BUF_SIZE);
        let mut held = Vec::new();
        let mut base = buf.as_ptr();
        let mut blocks = 1usize;
        let mut relayed = 0usize;

        while relayed < RELAYED {
            ensure_window(&mut buf);
            if !std::ptr::eq(buf.as_ptr(), base) {
                blocks += 1;
            }

            buf.resize(READ, 0);
            held.push(buf.split().freeze());
            // Where the next read will land: still inside this block until
            // `ensure_window` has to go and find another one.
            base = buf.as_ptr();
            relayed += READ;
        }

        assert_eq!(
            RELAY_BLOCK_SIZE - RELAY_BUF_SIZE,
            CARRIED,
            "a block no longer carries what the count below is measured against"
        );

        // Two blocks over the arithmetic: the 16 KiB one a tunnel starts with,
        // and however far into the last one the run happened to stop.
        let ceiling = RELAYED / CARRIED + 2;
        assert!(
            blocks <= ceiling,
            "{RELAYED} bytes of {READ}-byte reads pinned {blocks} blocks, over the {ceiling} \
             that carrying {CARRIED} bytes of each allows"
        );
    }
}
