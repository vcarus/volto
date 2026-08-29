//! M1: TCP CONNECT tunnels (RFC 9114 §4.4) and request dispatch.

mod common;

use std::future::Future;
use std::net::SocketAddr;
use std::panic::Location;
use std::time::Duration;

use bytes::Bytes;
use common::rawstream::{assert_closed_with, connect_headers_frame, frame, read_frame, status_of};
use common::{
    assert_peer_reset, client_endpoint_with_transport, closed_address, connect_request,
    finish_connect, open_tcp_tunnel, read_at_least, read_to_end, respond_to, send_and_respond,
    spawn_drain_then_reply_target, spawn_echo_target, spawn_end_reporting_target,
    spawn_flood_then_reset_target, spawn_reset_after_read_target, ConnectionEnd, H3Client,
    TestServer, ALLOW_PRIVATE, TIMEOUT,
};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use volto::h3api::{FieldValue, Method, Request, Status};

/// H3_CONNECT_ERROR (RFC 9114 §8.1).
const H3_CONNECT_ERROR: u64 = 0x010f;

/// H3_MESSAGE_ERROR (RFC 9114 §8.1), the answer to a malformed request.
const H3_MESSAGE_ERROR: u64 = 0x010e;

/// H3_FRAME_UNEXPECTED (RFC 9114 §8.1), the answer to a frame out of place.
const H3_FRAME_UNEXPECTED: u64 = 0x0105;

/// H3_REQUEST_CANCELLED (RFC 9114 §8.1): "The request or its response
/// (including pushed response) is cancelled."
const H3_REQUEST_CANCELLED: u64 = 0x010c;

/// DATA frame type (RFC 9114 §7.2.1).
const FRAME_DATA: u64 = 0x00;

/// HEADERS frame type (RFC 9114 §7.2.2).
const FRAME_HEADERS: u64 = 0x01;

/// A 2s idle timeout, which is also how long any one response may take.
///
/// Long enough that a deadline lapsing is a deliberate act rather than a slow
/// machine, and short enough for a test to wait out.
const DELIBERATE: &str = "[limits]\nmax_idle_timeout = 2\nkeep_alive_interval = 0\n";

/// Transport parameters for a peer that leaves no room for an answer.
///
/// 24 bytes of connection-level allowance is over the 19-byte SETTINGS frame
/// the handshake needs and under what the handshake plus any response costs;
/// nothing reads the server's control stream here, so the allowance is spent by
/// the handshake and never returned. The keep-alive is what makes the test
/// about the application's deadline: with it, the transport's own idle timeout
/// can never be the thing that ends anything.
fn windowless_transport() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.receive_window(24u32.into());
    transport.stream_receive_window(24u32.into());
    transport.keep_alive_interval(Some(Duration::from_millis(100)));
    transport
}

#[tokio::test]
async fn tunnels_bytes_to_an_echo_target() {
    let server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    stream
        .send_data(Bytes::from_static(b"hello volto"))
        .await
        .expect("send payload");

    let echoed = read_at_least(&mut stream, b"hello volto".len()).await;
    assert_eq!(&echoed, b"hello volto");

    // The tunnel stays usable for a second exchange on the same stream.
    stream
        .send_data(Bytes::from_static(b"again"))
        .await
        .expect("send again");
    let echoed = read_at_least(&mut stream, b"again".len()).await;
    assert_eq!(&echoed, b"again");
}

/// The half-close case: the client finishes its sending side first and must
/// still receive everything the target sends afterwards.
///
/// The target deliberately replies only after it has seen EOF, so it can answer
/// at all only if the client's stream FIN was translated into a shutdown of the
/// *write* side of the target socket rather than a full close.
#[tokio::test]
async fn client_half_close_still_receives_remaining_target_data() {
    let server = TestServer::start().await;
    let target = spawn_drain_then_reply_target("+TAIL").await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    stream
        .send_data(Bytes::from_static(b"ping"))
        .await
        .expect("send payload");

    // Client FIN. The target must see EOF, not a reset.
    stream.finish().expect("finish the sending side");

    // The target's remaining data must arrive, followed by a clean stream end
    // once the target closes (target EOF -> we finish our sending side).
    let received = read_to_end(&mut stream).await;
    assert_eq!(
        &received, b"ping+TAIL",
        "expected the target's post-EOF reply to survive the client's half-close"
    );
}

/// A TCP target that reads slowly and reports the total once it sees EOF.
///
/// The pause on every read is what keeps the proxy's client -> target pump
/// parked in its write while the rest of the client's burst piles up behind it
/// in quinn's receive buffers. That is the state the watcher on the request
/// stream is polled in, and the state a burst-then-FIN client leaves the pump in
/// for many iterations in a row.
///
/// Answering only after EOF makes the whole exchange observable from the client:
/// a byte count that comes back short, or does not come back at all, is a tunnel
/// whose task stopped running part-way.
async fn spawn_slow_counting_target() -> SocketAddr {
    /// Read nothing at all for this long after accepting, so the proxy's write
    /// to this socket fills the kernel buffer and parks. That is what leaves
    /// the whole burst -- and the FIN behind it -- sitting in the server's QUIC
    /// receive buffers with the pump unable to drain them.
    const BEFORE_FIRST_READ: Duration = Duration::from_millis(400);
    /// Then drain slowly, so the pump stays behind for many iterations rather
    /// than catching up in one.
    const PER_READ: Duration = Duration::from_millis(20);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target address");

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let mut counted = 0usize;
                tokio::time::sleep(BEFORE_FIRST_READ).await;
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            counted += n;
                            tokio::time::sleep(PER_READ).await;
                        }
                        Err(_) => return,
                    }
                }
                let _ = socket.write_all(counted.to_string().as_bytes()).await;
            });
        }
    });

    addr
}

/// An upload that arrives faster than the target drains it must still end in a
/// clean half-close.
///
/// The shape is an ordinary one -- a client uploading on a fast link to a slower
/// target, then finishing its sending side -- and it is what puts the request
/// stream into the state the reset watcher has to survive: chunk after chunk
/// already buffered while the pump is parked writing the one before it, then the
/// FIN arriving with the last of them rather than after a pause.
///
/// It is a regression test for the watcher and not for the relay. A watcher that
/// borrows quinn's per-stream reader slot leaves a waker in it that no later
/// read takes out again, and the clean FIN at the end of this burst is what
/// makes quinn notice: `RecvStream::drop` asserts the slot is empty once a
/// stream has been read to its end, so the pump's task dies on the way out and
/// the target's post-EOF reply never reaches the client.
#[tokio::test]
async fn a_burst_upload_that_outruns_the_target_still_half_closes_cleanly() {
    /// Enough chunks that the pump is parked with more already buffered many
    /// times over, which is what a single-chunk upload never does.
    const FRAMES: usize = 64;
    const FRAME: usize = 16 * 1024;

    let server = TestServer::start().await;
    let target = spawn_slow_counting_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    // A burst, with nothing read back in between: the point is for the frames to
    // pile up in the server's receive buffers ahead of the pump.
    let payload = Bytes::from(vec![0x7eu8; FRAME]);
    for _ in 0..FRAMES {
        stream
            .send_data(payload.clone())
            .await
            .expect("send a chunk of the burst");
    }

    // The FIN travels with the bytes already queued, so it lands behind the last
    // chunk rather than after a pause the pump could drain in.
    stream.finish().expect("finish the sending side");

    let reply = tokio::time::timeout(TIMEOUT, read_to_end(&mut stream))
        .await
        .expect("the target's answer must arrive within the bound");
    assert_eq!(
        String::from_utf8_lossy(&reply),
        (FRAMES * FRAME).to_string(),
        "the target must see every byte of the burst and a clean EOF, and its \
         answer must reach the client"
    );
}

/// A TCP target that stops reading until the whole upload has arrived, then
/// drains it a sip at a time and answers with the byte count.
///
/// Both halves are aimed at one state of the relay: parked in a write to this
/// socket with nothing left on the QUIC stream to read -- the client's last
/// bytes and its FIN already taken off it.
///
/// * The freeze is what gets the upload and the FIN drained: the relay pulls
///   what it can, fills every buffer between here and it, and parks with the
///   rest waiting in quinn's receive buffer.
/// * The sips are what keep it parked afterwards. A read frees room for the
///   relay to write into, and reading less than the ~1.4 KB pieces quinn hands
///   it means the room a read frees is never enough to finish the write it woke.
///   The receive buffer is asked to be small for the same reason, since a
///   kernel that honours the request opens its window a sip at a time rather
///   than in one jump: Linux does, macOS clamps the value and widens the window
///   in far larger steps, which leaves the relay free to finish the last piece.
async fn spawn_stalling_counting_target() -> SocketAddr {
    /// Read nothing at all for this long, so the whole upload lands and every
    /// buffer between the proxy and here is full before the first read.
    const FREEZE: Duration = Duration::from_millis(300);
    /// A sip, under the size of a piece.
    const READ: usize = 1024;

    let socket = TcpSocket::new_v4().expect("target socket");
    // Best-effort: what a kernel does with it is the kernel's business, and the
    // test asserts nothing about the size it ends up with.
    let _ = socket.set_recv_buffer_size(4 * 1024);
    socket
        .bind("127.0.0.1:0".parse().expect("bind address"))
        .expect("bind target");
    let listener = socket.listen(16).expect("listen");
    let addr = listener.local_addr().expect("target address");

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; READ];
                let mut counted = 0usize;
                tokio::time::sleep(FREEZE).await;
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => counted += n,
                        Err(_) => return,
                    }
                }
                let _ = socket.write_all(counted.to_string().as_bytes()).await;
            });
        }
    });

    addr
}

/// A client FIN that arrives mid-upload is not an abort, and the tunnel must
/// finish the upload it is still carrying.
///
/// The sequence is the one a stalled upload produces: the client's body and its
/// FIN are all inside quinn on the server, the relay is parked in a write to a
/// target that is draining a sip at a time, and the watcher beside that write
/// (`Reader::reset_by_peer`) is polled over and over while the reading half is
/// nowhere near the end of the stream. A watcher that reported any of that as a
/// reset would tear the tunnel down as a client abort, and the target would be
/// cut off part-way through the upload rather than seeing it out and answering.
///
/// What it does *not* reliably reach is the watcher's drained arm -- the one for
/// a stream whose bytes are all read and whose FIN is in. Whether the relay is
/// ever left in that exact state depends on how finely the kernel opens a
/// receive window (see [`spawn_stalling_counting_target`]), and on the hosts
/// this suite runs on it never is: the last piece always completes. That arm is
/// pinned directly instead, over a bare stream pair, by
/// [`a_drained_stream_is_not_a_reset_to_the_watcher`].
///
/// The target's stall is two orders of magnitude under the tunnel's idle bound,
/// so what this pins is the watcher and not that bound.
#[tokio::test(flavor = "multi_thread")]
async fn a_drained_client_fin_is_not_a_reset() {
    /// Past what the buffers between the proxy and the target hold, so the
    /// relay is parked in a write rather than done by the time the freeze ends.
    const FRAMES: usize = 64;
    const FRAME: usize = 16 * 1024;

    let server = TestServer::start().await;
    let target = spawn_stalling_counting_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    let payload = Bytes::from(vec![0x7eu8; FRAME]);
    for _ in 0..FRAMES {
        stream
            .send_data(payload.clone())
            .await
            .expect("send a chunk of the burst");
    }
    // Travels with the bytes already queued, so it is drained along with them
    // rather than after a pause the relay could notice separately.
    stream.finish().expect("finish the sending side");

    let reply = tokio::time::timeout(TIMEOUT, read_to_end(&mut stream))
        .await
        .expect("the target's answer must arrive within the bound");
    assert_eq!(
        String::from_utf8_lossy(&reply),
        (FRAMES * FRAME).to_string(),
        "the target must see every byte of the upload and a clean EOF, and its \
         answer must reach the client"
    );
}

/// A bare QUIC server endpoint with a self-signed certificate.
///
/// [`TestServer`] is the whole proxy and hands nothing of its HTTP/3 connection
/// back; the test below needs the *server* side of one in its own hands, so it
/// builds the endpoint itself. Everything else about it -- TLS 1.3, the `h3`
/// ALPN, a loopback port -- is what `volto::tls` and `volto::quic` would have
/// produced.
fn h3_server_endpoint() -> (quinn::Endpoint, CertificateDer<'static>) {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate a self-signed certificate");
    let certificate = issued.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(issued.signing_key.serialize_der().into());

    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .expect("a usable certificate and key");
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).expect("quic tls"),
    ));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().expect("bind address"))
        .expect("bind the server endpoint");

    (endpoint, certificate)
}

/// The watcher's drained arm: a stream the peer finished and this end has read
/// out is not a reset, and never becomes one.
///
/// `Reader::reset_by_peer` is what a parked write selects on, and it must
/// resolve for exactly one thing -- a RESET_STREAM from the peer. It watches by
/// asking for a zero-length read, which parks while the stream has nothing to
/// give; the case that needs deciding is the one where the stream *is* over,
/// every byte read and the FIN taken, because there the read returns at once
/// and there is nothing left to be woken by. The answer is that the wait simply
/// never ends: the ending belongs to the reading half, and resolving here would
/// turn a clean FIN into a client abort and cut a tunnel that was still working.
///
/// Pinned over a bare stream pair rather than through the relay because the
/// relay cannot be steered into that state from outside: whether it is ever left
/// parked with its request stream drained is a race between a kernel receive
/// window and its own write, and on the hosts this suite runs on the last piece
/// always completes. [`a_drained_client_fin_is_not_a_reset`] pins the sequence
/// around it; this pins the arm.
#[tokio::test(flavor = "multi_thread")]
async fn a_drained_stream_is_not_a_reset_to_the_watcher() {
    /// The body, sent up front so it and the FIN are inside quinn before the
    /// server-side reader looks at either.
    const BODY: &[u8] = b"the whole of the upload, and then the end of it";
    /// How long the watcher has to stay parked. Twice the interval the watcher
    /// re-checks on when a stream still has buffered bytes, so an arm that
    /// merely takes its time would have resolved by now.
    const PARKED_FOR: Duration = Duration::from_millis(500);

    let (endpoint, ca) = h3_server_endpoint();
    let addr = endpoint.local_addr().expect("server address");

    let client = tokio::spawn(async move {
        let endpoint = common::client_endpoint(&ca, &["h3"]);
        let connection = finish_connect(&endpoint, addr)
            .await
            .expect("the QUIC handshake");
        let (mut send, recv) = connection.open_bi().await.expect("open a request stream");
        send.write_all(&connect_headers_frame("192.0.2.1:443"))
            .await
            .expect("send the CONNECT request");
        send.write_all(&frame(FRAME_DATA, BODY))
            .await
            .expect("send the body");
        // The FIN. Nothing can follow it, which is the whole point: a stream
        // that ended cleanly can never afterwards be reset.
        send.finish().expect("finish the sending side");

        // Handed back rather than dropped: a client that went away would end
        // the wait below as a lost connection instead of leaving it parked.
        (endpoint, connection, send, recv)
    });

    let quic = endpoint
        .accept()
        .await
        .expect("an incoming connection")
        .await
        .expect("the QUIC handshake");
    let mut connection = volto::h3api::Connection::handshake(quic, TIMEOUT, Default::default())
        .await
        .expect("the HTTP/3 handshake");
    let (_request, stream) = connection
        .accept()
        .await
        .expect("accept a request stream")
        .expect("this server never reports the end of a connection as Ok(None)")
        .resolve()
        .await
        .expect("the request must be well formed");
    // Splitting is what puts the reader in the mode a live tunnel reads in.
    let (_writer, mut reader) = stream.split();

    let _client = client.await.expect("the client task");

    // Drain to the end of the stream, which is the state under test: the FIN is
    // taken, and quinn has nothing left to hand out.
    let mut received = Vec::new();
    while let Some(chunk) = reader
        .recv_data()
        .await
        .expect("the body must arrive without error")
    {
        received.extend_from_slice(&chunk);
    }
    assert_eq!(received, BODY, "the whole body must be read first");

    assert!(
        tokio::time::timeout(PARKED_FOR, reader.reset_by_peer())
            .await
            .is_err(),
        "a stream the peer finished and this end has drained must leave the watcher parked: \
         resolving it would report a clean FIN as a client abort"
    );
}

/// A target that resets after the tunnel is up must surface as a stream reset
/// with H3_CONNECT_ERROR, not as a clean end of stream.
///
/// This is the case the *read* pump notices, because the client is not uploading
/// and the write pump is parked reading from it. Its sibling below covers the
/// other order, where the write pump is the one that finds the target gone.
#[tokio::test]
async fn target_reset_becomes_h3_connect_error() {
    let server = TestServer::start().await;
    let target = spawn_reset_after_read_target().await;
    let mut client = H3Client::connect(&server).await;

    // The 200 goes out as soon as the TCP connection is established. The target
    // resets only after it has read, so this cannot be overtaken by the reset.
    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    // Triggers the target's reset.
    stream
        .send_data(Bytes::from_static(b"go"))
        .await
        .expect("send payload");

    // Matched rather than `expect_err`ed: the point is to name what a success
    // would have meant, which a panic message from `expect_err` cannot.
    let error = match tokio::time::timeout(TIMEOUT, stream.recv_data())
        .await
        .expect("the reset arrived")
    {
        Ok(_) => panic!("a target reset must not look like a clean end of stream"),
        Err(error) => error,
    };

    assert_peer_reset(&error, H3_CONNECT_ERROR);
}

/// The same target reset, noticed by the *write* pump instead.
///
/// The client keeps uploading and does not read the tunnel while it does, which
/// parks the write pump in `write_all` and the read pump in `send_data` — so
/// when the RST lands only the write pump is in a position to see it. It used to
/// stop the client's sending side and then simply return, dropping the writer,
/// and a dropped `quinn::SendStream` finishes rather than resets: the response
/// direction ended in a clean FIN. That is the truncation shape, and what an
/// upload-shaped protocol through the tunnel would read as a complete response.
/// RFC 9114 §4.4 rules it out — any error on the TCP connection, a received RST
/// included, is a stream error of type H3_CONNECT_ERROR.
#[tokio::test]
async fn target_reset_during_a_client_upload_becomes_h3_connect_error() {
    let server = TestServer::start().await;
    // Comfortably past the client's 1.25 MB stream flow-control window, so the
    // proxy still has unsent target data when the reset arrives.
    let target = spawn_flood_then_reset_target(8 * 1024 * 1024).await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    // Pushed from a task so the stream comes back afterwards for the response
    // direction, and deliberately without reading it in the meantime. The byte
    // bound is only a backstop: the upload parks on flow control long before it,
    // because the proxy has stopped reading the stream.
    let payload = Bytes::from(vec![0xa5u8; 64 * 1024]);
    let upload = tokio::spawn(async move {
        let mut sent = 0usize;
        loop {
            if let Err(error) = stream.send_data(payload.clone()).await {
                return (Some(error), stream);
            }
            sent += payload.len();
            if sent > 64 * 1024 * 1024 {
                return (None, stream);
            }
        }
    });

    let (send_error, mut stream) = tokio::time::timeout(TIMEOUT, upload)
        .await
        .expect("the upload must end")
        .expect("the upload task");

    let send_error = send_error.expect("the client's upload must be stopped by the target's reset");
    assert_peer_reset(&send_error, H3_CONNECT_ERROR);

    // Drain what the target managed to send before the reset; the flood is there
    // to pin the read pump, not to be checked. What matters is how it ends.
    let error = tokio::time::timeout(TIMEOUT, async {
        loop {
            match stream.recv_data().await {
                Ok(Some(_)) => continue,
                Ok(None) => panic!(
                    "a target reset reached the client as a clean end of stream: a truncated \
                     response is indistinguishable from a complete one"
                ),
                Err(error) => return error,
            }
        }
    })
    .await
    .expect("the reset arrived");

    assert_peer_reset(&error, H3_CONNECT_ERROR);
}

/// The same target reset again, read off the *request* direction.
///
/// [`target_reset_becomes_h3_connect_error`] pins the response direction, where
/// the pump that met the reset puts the code on its own writer. The other pump
/// is somewhere else entirely — waiting for the client's next chunk — and learns
/// of the teardown only through the reason the first one raised. What it makes
/// of that reason is the client's STOP_SENDING, and the two directions have to
/// carry the same verdict: a cancellation in its place tells the client the
/// proxy gave up on the request, where what happened is that the target
/// connection failed.
///
/// The client sends once and no more, which is what puts the pumps in those
/// positions: the write to the target has completed by the time the RST lands,
/// so the request pump is back to waiting and only the read pump can notice.
#[tokio::test]
async fn a_target_reset_stops_the_request_direction_with_h3_connect_error() {
    let server = TestServer::start().await;
    let target = spawn_reset_after_read_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;
    // Taken before the reset can arrive: the future borrows nothing, so waiting
    // on it cannot miss a STOP_SENDING that overtakes this line.
    let stopped = stream.stopped();

    // Triggers the target's reset.
    stream
        .send_data(Bytes::from_static(b"go"))
        .await
        .expect("send payload");

    let code = tokio::time::timeout(TIMEOUT, stopped)
        .await
        .expect("a failed target must stop the client's sending side")
        .expect("the stream must still be open to be stopped");
    assert_eq!(
        code.map(quinn::VarInt::into_inner),
        Some(H3_CONNECT_ERROR),
        "the request direction must carry the target's failure, not a cancelled request"
    );
}

/// RFC 9114 §4.4: "if the underlying TCP implementation permits it, the proxy
/// SHOULD send a TCP segment with the RST bit set" when the client resets the
/// tunnel. Observable at the target as `ECONNRESET` on a read that would have
/// returned a clean EOF had the proxy closed with a FIN.
#[tokio::test]
async fn client_reset_aborts_the_target_connection() {
    let server = TestServer::start().await;
    let (target, mut ended) = spawn_end_reporting_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    // Abruptly reset the request stream instead of finishing it.
    stream.stop_stream(volto::h3api::Code::H3_REQUEST_CANCELLED);
    drop(stream);

    let end = tokio::time::timeout(TIMEOUT, ended.recv())
        .await
        .expect("the target connection must be closed after a client reset")
        .expect("close notification");

    assert_eq!(
        end,
        ConnectionEnd::Failed(std::io::ErrorKind::ConnectionReset),
        "an aborted tunnel must reach the target as a reset, not as a clean EOF"
    );
}

/// RFC 9114 §4.4: "If the stream is reset or reading is aborted by the client,
/// a proxy SHOULD perform the same operation on the other direction in order to
/// ensure that both directions of the stream are cancelled."
///
/// A client that resets only its *sending* side used to have the response
/// direction finished with a clean FIN, because a dropped `quinn::SendStream`
/// finishes rather than resets — so whatever the target had still to say read to
/// the client as a complete response rather than as a cancelled one. It is now
/// reset with H3_REQUEST_CANCELLED, RFC 9114 §8.1's "the request or its response
/// (including pushed response) is cancelled", and the target still sees the RST
/// the same paragraph of §4.4 asks for.
#[tokio::test]
async fn a_client_reset_cancels_the_response_direction_too() {
    let server = TestServer::start().await;
    let (target, mut ended) = spawn_end_reporting_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    // Only the sending side, and the stream is kept rather than dropped: the
    // response direction stays open, which is the half under test.
    stream.stop_stream(volto::h3api::Code::H3_REQUEST_CANCELLED);

    let error = match tokio::time::timeout(TIMEOUT, stream.recv_data())
        .await
        .expect("the server must end the response direction promptly")
    {
        Ok(Some(_)) => panic!("this target never writes, so there is nothing to read"),
        Ok(None) => panic!(
            "a cancelled request reached the client as a clean end of stream: a truncated \
             response is indistinguishable from a complete one"
        ),
        Err(error) => error,
    };
    assert_peer_reset(&error, H3_REQUEST_CANCELLED);

    // And the other operation §4.4 asks for on a client abort is unchanged.
    let end = tokio::time::timeout(TIMEOUT, ended.recv())
        .await
        .expect("the target connection must be closed after a client reset")
        .expect("close notification");
    assert_eq!(
        end,
        ConnectionEnd::Failed(std::io::ErrorKind::ConnectionReset),
        "an aborted tunnel must still reach the target as a reset"
    );
}

/// The other half of the same sentence: a client that aborts *reading* must have
/// its own sending direction cancelled with an HTTP/3 code.
///
/// Left to the `Reader` being dropped, quinn stops the peer with code 0 — so the
/// two halves of one cancelled request ended under two different verdicts. The
/// server notices the client's STOP_SENDING when it next writes to the response
/// direction, which is what the echoed byte below arranges.
///
/// Driven on a raw QUIC stream because the shared client has no way to abort
/// reading while keeping its sending side open, which is precisely the shape
/// under test.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_stop_sending_cancels_the_request_direction_too() {
    let server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let client = H3Client::connect(&server).await;

    let (mut send, mut recv) = client.quic.open_bi().await.expect("open a request stream");
    send.write_all(&connect_headers_frame(&target.to_string()))
        .await
        .expect("send the CONNECT request");

    let (kind, payload) = read_frame(&mut recv).await;
    assert_eq!(kind, FRAME_HEADERS, "the tunnel must open with a response");
    assert_eq!(status_of(&payload), "200", "the tunnel must be accepted");

    // Abort reading the response direction. The code a client picks is its own
    // business; what is under test is the code the server answers with.
    recv.stop(quinn::VarInt::from_u32(0))
        .expect("stop reading the response direction");

    // The echo comes back on a direction nobody is reading, which is where the
    // server meets the STOP_SENDING.
    send.write_all(&frame(FRAME_DATA, b"echo me"))
        .await
        .expect("send payload");

    let stopped = tokio::time::timeout(TIMEOUT, send.stopped())
        .await
        .expect("the server must cancel the request direction")
        .expect("stop code");
    assert_eq!(
        stopped.map(quinn::VarInt::into_inner),
        Some(H3_REQUEST_CANCELLED),
        "both directions of a cancelled request must carry the same verdict"
    );
}

/// A TCP target that never reads and writes until it cannot, reporting how its
/// connection ended.
///
/// The shape needed to park *both* of the proxy's pumps at once. Never reading
/// fills every buffer between the client and the target, so the proxy's
/// client → target pump ends up inside `write_all`; writing without ever being
/// read — the client under test does not read the tunnel either — fills the
/// other direction, so the target → client pump ends up inside `send_data`,
/// which is the only place it can notice a client's STOP_SENDING.
///
/// The end is reported from the blocked write rather than from a read, because
/// reading is exactly what this target must not do: an abortive close makes a
/// blocked write fail with `ConnectionReset` or `BrokenPipe`, and a proxy that
/// never closed the socket leaves it blocked for ever, which is the failure this
/// reports by silence.
async fn spawn_deaf_flooding_target(
) -> (SocketAddr, tokio::sync::mpsc::Receiver<std::io::ErrorKind>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target address");
    let (tx, rx) = tokio::sync::mpsc::channel(1);

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let payload = vec![0x5au8; 64 * 1024];
                loop {
                    if let Err(error) = socket.write_all(&payload).await {
                        let _ = tx.send(error.kind()).await;
                        return;
                    }
                }
            });
        }
    });

    (addr, rx)
}

/// How long a target close may take once the client has aborted.
///
/// Two orders of magnitude under the wait a stalled `write_all` or `send_data`
/// would impose, which is unbounded.
const CLOSE_WITHIN: Duration = Duration::from_secs(2);

/// Opens a tunnel to a deaf, flooding target and uploads into it until the
/// client's own writes stall, which is when both of the proxy's pumps are
/// parked.
///
/// The client → target pump ends up inside `write_all`, because the target
/// never reads and every buffer between here and it is full; the target →
/// client pump ends up inside `send_data`, because nothing here reads the
/// response direction and its flow-control window is spent. Neither is reading
/// the request stream in that state, which is what the two tests below start
/// from — they differ only in how the client then abandons it.
///
/// One later caller has only one pump to park, its target having ended its own
/// sending side before the upload begins. The upload loop is the same either
/// way: what it needs of a target is that it does not read.
///
/// The two halves of the raw request stream come back still open.
#[track_caller]
fn park_both_pumps(
    connection: &quinn::Connection,
    target: SocketAddr,
) -> impl Future<Output = (quinn::SendStream, quinn::RecvStream)> + '_ {
    let caller = Location::caller();
    let request = connect_headers_frame(&target.to_string());

    async move {
        let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
        send.write_all(&request)
            .await
            .expect("send the CONNECT request");

        let (kind, payload) = read_frame(&mut recv).await;
        assert_eq!(
            kind, FRAME_HEADERS,
            "at {caller}: the tunnel must open with a response"
        );
        assert_eq!(
            status_of(&payload),
            "200",
            "at {caller}: the tunnel must be accepted"
        );

        // Upload until a write no longer completes. Loopback buffers on macOS
        // are large and the server's own stream window is 2 MB, so the stall is
        // found by writing rather than by predicting how much it takes.
        let chunk = vec![0xa5u8; 64 * 1024];
        let mut stalled = false;
        for _ in 0..512 {
            match tokio::time::timeout(
                Duration::from_millis(200),
                send.write_all(&frame(FRAME_DATA, &chunk)),
            )
            .await
            {
                Ok(result) => result.expect("the upload must not fail before it stalls"),
                Err(_) => {
                    stalled = true;
                    break;
                }
            }
        }
        assert!(
            stalled,
            "at {caller}: the upload never stalled, so the proxy was never parked in its write"
        );

        (send, recv)
    }
}

/// A teardown must not wait behind a write to a target that stopped reading.
///
/// RFC 9114 §4.4: "if a proxy detects an error with the stream or the QUIC
/// connection, it MUST close the TCP connection." With the write outside the
/// pump's `select!`, that close waited for `write_all` to finish — which, on a
/// target that never reads, is never: the client's STOP_SENDING was noticed by
/// the other pump, the teardown was raised, and nothing acted on it, so the
/// target socket stayed open for the life of the process.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_abort_closes_a_target_that_stopped_reading() {
    let server = TestServer::start().await;
    let (target, mut ended) = spawn_deaf_flooding_target().await;
    let client = H3Client::connect(&server).await;

    let (_send, mut recv) = park_both_pumps(&client.quic, target).await;

    // Abort reading the response direction: the other pump meets this inside
    // `send_data` and raises the teardown the write pump has to act on.
    recv.stop(quinn::VarInt::from_u32(0))
        .expect("stop reading the response direction");

    let end = tokio::time::timeout(CLOSE_WITHIN, ended.recv())
        .await
        .expect("the target socket must be closed once the client aborts")
        .expect("close notification");
    assert!(
        matches!(
            end,
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
        ),
        "the target must see the connection go away, got {end:?}"
    );
}

/// The other way a client abandons a stalled tunnel: RESET_STREAM rather than
/// STOP_SENDING.
///
/// RFC 9114 §4.4 names both in one sentence — "If the proxy detects that the
/// client has reset the stream or aborted reading from the stream, it MUST
/// close the TCP connection" — and only the second half was detected. A reset
/// reaches the proxy as an error on a *read* of the request stream, and with
/// both pumps parked in writes nobody was reading: the client → target pump sat
/// in `write_all` on a target that never reads, the target → client pump sat in
/// `send_data` on a client that never reads, and neither ever looked again. The
/// target socket, its file descriptor and the tunnel slot were held for the
/// life of the QUIC connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_reset_closes_a_target_that_stopped_reading() {
    let server = TestServer::start().await;
    let (target, mut ended) = spawn_deaf_flooding_target().await;
    let client = H3Client::connect(&server).await;

    let (mut send, _recv) = park_both_pumps(&client.quic, target).await;

    // The sending direction only, and the response direction is left open and
    // unread: the client says "I will send no more" and nothing else. Reading
    // the response would let `send_data` make progress and hand the other pump
    // a chance to notice something, which is the case already covered above.
    send.reset(quinn::VarInt::from_u64(H3_REQUEST_CANCELLED).expect("a valid code"))
        .expect("reset the request direction");

    let end = tokio::time::timeout(CLOSE_WITHIN, ended.recv())
        .await
        .expect("the target socket must be closed once the client resets the stream")
        .expect("close notification");
    assert!(
        matches!(
            end,
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
        ),
        "the target must see the connection go away, got {end:?}"
    );
}

/// The counterpart, and the regression that stops the reset above from leaking
/// into the normal path: a client that finishes its sending side cleanly must
/// still reach the target as a FIN, i.e. as a clean EOF.
#[tokio::test]
async fn a_clean_client_close_still_reaches_the_target_as_eof() {
    let server = TestServer::start().await;
    let (target, mut ended) = spawn_end_reporting_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    stream
        .send_data(Bytes::from_static(b"hello"))
        .await
        .expect("send payload");
    stream.finish().expect("finish the sending side");

    let end = tokio::time::timeout(TIMEOUT, ended.recv())
        .await
        .expect("the target must see the client's FIN")
        .expect("close notification");

    assert_eq!(
        end,
        ConnectionEnd::Eof,
        "a clean half-close must stay a FIN: RFC 9114 §4.4 half-close semantics \
         depend on the target seeing an ordinary end of stream"
    );
}

/// A one-second bound on a stalled write in a half-closed tunnel.
///
/// It is `[limits] udp_session_timeout`, which a CONNECT-UDP session's idle
/// bound also comes from; one second is the smallest the config layer accepts.
const HALF_CLOSED_TIMEOUT: &str = "[limits]\nudp_session_timeout = 1\n";

/// The same number as a duration, for the tests that have to out-wait it.
const HALF_CLOSED_BUDGET: Duration = Duration::from_secs(1);

/// How long the tests below give a bound of one second to fire.
///
/// Five times the bound, so only a tunnel that is never cut at all fails —
/// never a slow machine.
const CUT_WITHIN: Duration = Duration::from_secs(5);

/// A per-stream receive window too small to take one relay chunk.
///
/// What it buys the test below is a proxy parked in `send_data` after a *short*
/// burst from the target, rather than after the megabytes it would take to fill
/// quinn's default 1.25 MB window. Short matters there: the bytes the proxy has
/// not read off the target socket yet are what decide how its close looks on the
/// wire.
const CHUNKLESS_WINDOW: u32 = 4 * 1024;

/// A TCP target that writes one short burst, says nothing more, and reports the
/// first error a read of the socket gives it.
///
/// The shape [`spawn_deaf_flooding_target`] cannot have: it never stops writing,
/// so the proxy's receive queue always holds bytes it has not read, and closing
/// a socket with unread data in that queue sends an RST whether or not anything
/// asked for one (RFC 1122 §4.2.2.13). A test built on it therefore cannot tell
/// the abortive close this server arms from the ordinary close it would fall
/// back to. One burst, sized so the proxy reads all of it and then parks in the
/// write, leaves that queue empty and the close saying only what the proxy meant
/// it to say.
///
/// Reads are polled rather than awaited once, because the half-close under test
/// has already put a FIN on this socket: the first read returns a clean EOF that
/// says nothing about the ending, and what the test is waiting for is the error
/// a later one fails with. A tunnel closed politely never produces that error,
/// and a test hunting an abortive close ends in the timeout it was given. That
/// FIN also decides where the error can arrive at all: it leaves the proxy's
/// socket in FIN_WAIT_2, and only a stack that resets from there (macOS) sends
/// the RST this reports — on Linux the report never comes, and the caller must
/// not wait for it.
async fn spawn_quiet_burst_target(
    burst: usize,
) -> (SocketAddr, tokio::sync::mpsc::Receiver<std::io::ErrorKind>) {
    /// Between two polls of a socket that is only ever going to say `Ok(0)`.
    const POLL: Duration = Duration::from_millis(20);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target address");
    let (tx, rx) = tokio::sync::mpsc::channel(1);

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                // One write, so it reaches the proxy as one segment and one
                // read. Nothing follows it: another burst would refill the
                // receive queue this test needs empty.
                if socket.write_all(&vec![0x5au8; burst]).await.is_err() {
                    return;
                }

                let mut buf = [0u8; 1024];
                loop {
                    match socket.read(&mut buf).await {
                        // The client's own half-close, arriving as it should.
                        Ok(_) => tokio::time::sleep(POLL).await,
                        Err(error) => {
                            let _ = tx.send(error.kind()).await;
                            return;
                        }
                    }
                }
            });
        }
    });

    (addr, rx)
}

/// A client that finishes its sending side and then stops reading must not hold
/// the tunnel open for the life of the connection.
///
/// The clean FIN ends the client → target pump through the one arm that raises
/// no teardown, which is what leaves the surviving direction unwatched: it parks
/// in `send_data` as soon as the client's flow-control window is spent, and
/// nothing is left to raise a teardown that would end that wait. The target
/// socket, its file descriptor and the tunnel slot were held until the QUIC
/// connection ended — which this server's own keep-alives can postpone
/// indefinitely.
///
/// Both halves of the cut are asserted where they are observable: the client
/// sees its response direction cancelled rather than finished everywhere, so
/// the download it abandoned cannot read back as a complete one, and on a stack
/// that sends a reset from FIN_WAIT_2 (macOS) the target sees the connection go
/// away *abortively*, the way the mirror test below asserts it. The reset is
/// the half that needs arranging — see [`spawn_quiet_burst_target`] for why a
/// flooding target produces one by accident and so pins nothing, and the
/// comment at the assertion for why Linux never delivers it on this path.
#[tokio::test(flavor = "multi_thread")]
async fn a_half_closed_tunnel_whose_client_stops_reading_is_cut() {
    /// Over [`CHUNKLESS_WINDOW`] so the write parks, inside one loopback
    /// segment and one relay read so nothing of it is left unread.
    const BURST: usize = 8 * 1024;

    let server = TestServer::start_with(&format!("{HALF_CLOSED_TIMEOUT}{ALLOW_PRIVATE}")).await;
    let (target, mut ended) = spawn_quiet_burst_target(BURST).await;
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(CHUNKLESS_WINDOW.into());
    let mut client = H3Client::connect_with_transport(&server, transport).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    // The half-close, and then nothing: the target's burst is more than the
    // window allows, so the proxy is parked in `send_data`. Reading here is what
    // must not happen — a read would grant credit, the write would complete, and
    // the next one would start on a budget of its own.
    stream.finish().expect("finish the sending side");

    // What the cut looks like from the target depends on the kernel. The
    // proxy's clean FIN went out the moment the client half-closed — that is
    // the RFC 9114 §4.4 behaviour — so by cut time its socket is in FIN_WAIT_2,
    // and the armed reset can only chase a FIN the target already has. macOS
    // sends that trailing RST; Linux's `tcp_need_reset()` does not include
    // FIN_WAIT_2, so the close there is silent and the target keeps reading a
    // clean EOF. The proof the cut happened is therefore split: the target-side
    // reset is asserted where the stack can express it, and the client-side
    // reset below is asserted everywhere.
    // Waiting here is load-bearing either way: the client must still not be
    // reading when the bound fires, because a read grants credit, the parked
    // write completes, and the tunnel is legitimately rescued.
    if cfg!(target_os = "macos") {
        let end = tokio::time::timeout(CUT_WITHIN, ended.recv())
            .await
            .expect(
                "a half-closed tunnel whose client stopped reading must be cut, and cut abortively",
            )
            .expect("close notification");
        assert_eq!(
            end,
            std::io::ErrorKind::ConnectionReset,
            "a tunnel cut short must reach the target as a reset, not as a clean end of stream"
        );
    } else {
        // No report to wait for on this kernel, so the deafness is held for
        // three budgets instead — the cut lands after one — and the reset
        // asserted below is the whole proof.
        tokio::time::sleep(HALF_CLOSED_BUDGET * 3).await;
    }

    // And the client's own half is cancelled rather than left to a FIN, which a
    // truncated response would otherwise be indistinguishable from.
    let error = tokio::time::timeout(TIMEOUT, async {
        loop {
            match stream.recv_data().await {
                Ok(Some(_)) => continue,
                Ok(None) => panic!(
                    "an abandoned download reached the client as a clean end of stream: a \
                     truncated response is indistinguishable from a complete one"
                ),
                Err(error) => return error,
            }
        }
    })
    .await
    .expect("the reset arrived");
    assert_peer_reset(&error, H3_REQUEST_CANCELLED);
}

/// A TCP target that writes `total` bytes, ends its sending side, and then
/// drains whatever the client sends.
///
/// `total` is meant to be past the client's stream flow-control window, so the
/// proxy is parked in `send_data` for as long as the client declines to read.
/// Ending its own sending side afterwards is what lets the client tell a tunnel
/// that survived from one that was cut: the bytes all arrive and the stream then
/// ends cleanly.
async fn spawn_bounded_flood_target(total: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target address");

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let payload = vec![0x5au8; 64 * 1024];
                let mut written = 0usize;
                while written < total {
                    let take = payload.len().min(total - written);
                    if socket.write_all(&payload[..take]).await.is_err() {
                        return;
                    }
                    written += take;
                }
                // EOF on this side only; the read side stays open so the
                // half-close under test is the client's to make.
                let _ = socket.shutdown().await;

                let mut buf = [0u8; 4096];
                while let Ok(read) = socket.read(&mut buf).await {
                    if read == 0 {
                        return;
                    }
                }
            });
        }
    });

    addr
}

/// The pin on the bound above: a tunnel whose client has **not** finished its
/// sending side is left alone, however long a write parks.
///
/// This is the case the bound must not reach, and the reason it is gated on the
/// half-close rather than armed for every write. While both directions are live
/// each pump is the other's watchdog — a client that has abandoned the stream is
/// noticed by the read pump or by the reset watcher beside its write — so a
/// stalled write there is a client that is merely slow, and cutting it would
/// break every tunnel whose client pauses longer than an idle timeout before
/// reading on.
#[tokio::test(flavor = "multi_thread")]
async fn a_tunnel_whose_client_has_not_finished_survives_a_long_stall() {
    /// Comfortably past the client's 1.25 MB stream flow-control window, so the
    /// proxy really is parked in `send_data` during the stall below.
    const TOTAL: usize = 4 * 1024 * 1024;

    let server = TestServer::start_with(&format!("{HALF_CLOSED_TIMEOUT}{ALLOW_PRIVATE}")).await;
    let target = spawn_bounded_flood_target(TOTAL).await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    // Not a byte read for well over the bound, and the sending side left open.
    tokio::time::sleep(Duration::from_millis(2_500)).await;

    // The tunnel must still be there, and must still owe every byte.
    let received = tokio::time::timeout(TIMEOUT, read_to_end(&mut stream))
        .await
        .expect("the download must finish within the bound");
    assert_eq!(
        received.len(),
        TOTAL,
        "a tunnel whose client has not half-closed must survive a stall and finish its download"
    );
}

/// The other half of the bound: every write gets a budget of its own.
///
/// A client that half-closed and then drains a long download slowly is the
/// benign shape the bound must not reach, and it is not covered by the stall
/// test above: that one never lets a write finish at all. What this pins is the
/// rearming. The tunnel spends well over five budgets in the half-closed state,
/// but no single write is outstanding for one of them, and every byte has to
/// arrive.
///
/// It is the mutation that shows what it is worth: turning the per-write sleep
/// into one deadline for the whole half-closed life of the tunnel leaves every
/// other test in the suite green and cuts this download at the first budget.
#[tokio::test(flavor = "multi_thread")]
async fn a_half_closed_tunnel_survives_a_download_taken_in_sips() {
    /// Several times the client's 1.25 MB stream flow-control window, so the
    /// proxy is parked in `send_data` through every pause below rather than
    /// waiting on the target.
    const TOTAL: usize = 4 * 1024 * 1024;
    /// How much is taken before each pause. Comfortably over one relay chunk,
    /// so the write the pause interrupted always completes when reading
    /// resumes -- the floor the module doc describes.
    const SIP: usize = 256 * 1024;
    /// The pause between sips: under the budget, and sixteen of them are over
    /// five of it.
    const PAUSE: Duration = Duration::from_millis(400);

    let server = TestServer::start_with(&format!("{HALF_CLOSED_TIMEOUT}{ALLOW_PRIVATE}")).await;
    let target = spawn_bounded_flood_target(TOTAL).await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;
    // The half-close, which is what arms the bound at all.
    stream.finish().expect("finish the sending side");

    let started = std::time::Instant::now();
    let mut received = 0usize;
    let mut since_pause = 0usize;

    while let Some(chunk) = tokio::time::timeout(TIMEOUT, stream.recv_data())
        .await
        .expect("the download must keep arriving")
        .expect("a tunnel cut by the bound surfaces here as a reset")
    {
        received += chunk.len();
        since_pause += chunk.len();
        if since_pause >= SIP {
            since_pause = 0;
            tokio::time::sleep(PAUSE).await;
        }
    }

    assert_eq!(
        received, TOTAL,
        "a half-closed tunnel drained in sips must deliver every byte and end cleanly"
    );
    // Without this the test could pass by being too fast to reach the bound at
    // all, which is the one way it would prove nothing.
    assert!(
        started.elapsed() > 5 * HALF_CLOSED_BUDGET,
        "the download must span several budgets to say anything: it took {:?}",
        started.elapsed()
    );
}

/// A TCP target that ends its sending side at once and then stops reading until
/// it is told to look at the socket.
///
/// The mirror of [`spawn_deaf_flooding_target`]: there the *client* makes the
/// clean end and stops reading, here the target does. Reading is deferred rather
/// than merely slow because a read is exactly what must not happen while the
/// proxy's write is meant to be stalling; the deferred read is what makes the
/// end of the connection observable afterwards.
async fn spawn_eof_then_deaf_target() -> (
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::mpsc::Receiver<ConnectionEnd>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target address");
    let (look, told_to_look) = tokio::sync::oneshot::channel();
    let (tx, rx) = tokio::sync::mpsc::channel(1);

    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        // The clean end this test is about: EOF on the target's sending side,
        // with its receiving side still open.
        let _ = socket.shutdown().await;

        if told_to_look.await.is_err() {
            return;
        }

        let mut buf = [0u8; 4096];
        let end = loop {
            match socket.read(&mut buf).await {
                Ok(0) => break ConnectionEnd::Eof,
                Ok(_) => {}
                Err(error) => break ConnectionEnd::Failed(error.kind()),
            }
        };
        let _ = tx.send(end).await;
    });

    (addr, look, rx)
}

/// The mirror of the bound above, in the other direction: a target that reaches
/// EOF and then stops reading must not hold the tunnel open either.
///
/// Target EOF ends the target → client pump through its own no-teardown arm, so
/// the client → target pump is the one left unwatched — parked in `write_all` on
/// a target that has stopped taking bytes, with the client still uploading. The
/// verdict differs from its mirror because the party at fault does: the target
/// is, so the client's sending side is stopped with `H3_CONNECT_ERROR` rather
/// than cancelled, and the target socket is closed with a reset.
#[tokio::test(flavor = "multi_thread")]
async fn a_target_that_stops_reading_after_its_own_eof_is_cut() {
    let server = TestServer::start_with(&format!("{HALF_CLOSED_TIMEOUT}{ALLOW_PRIVATE}")).await;
    let (target, look, mut ended) = spawn_eof_then_deaf_target().await;
    let client = H3Client::connect(&server).await;

    // Only one pump is left to park: the other returned at the target's EOF.
    let (send, _recv) = park_both_pumps(&client.quic, target).await;

    let stopped = tokio::time::timeout(CUT_WITHIN, send.stopped())
        .await
        .expect("a half-closed tunnel whose target stopped reading must be cut")
        .expect("stop code");
    assert_eq!(
        stopped.map(quinn::VarInt::into_inner),
        Some(H3_CONNECT_ERROR),
        "a target that stopped taking bytes is a failure of the target connection"
    );

    // The target's own end of it, once it finally looks: a reset rather than the
    // FIN a tunnel that was seen through would leave.
    look.send(()).expect("wake the target");
    let end = tokio::time::timeout(TIMEOUT, ended.recv())
        .await
        .expect("the target socket must not outlive the tunnel")
        .expect("close notification");
    assert_eq!(
        end,
        ConnectionEnd::Failed(std::io::ErrorKind::ConnectionReset),
        "a tunnel cut short must reach the target as a reset, not as a clean end of stream"
    );
}

/// The 200 that opens a tunnel is bounded like every refusal.
///
/// It is the one response written after a target connection exists, which used
/// to be the argument for exempting it — but the pumps that would notice the
/// client giving up are started by the line *after* this write, so a peer that
/// grants no flow-control credit parks the request task with the target socket
/// in its hand for as long as the connection lasts. RFC 9114 §8.1's
/// H3_REQUEST_CANCELLED covers "the request or its response (including pushed
/// response) is cancelled", and a reset is the only end that reaches a peer
/// granting no window at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_tunnel_200_the_peer_will_not_take_is_reset() {
    let server = TestServer::start_with(&format!("{DELIBERATE}{ALLOW_PRIVATE}")).await;
    let target = spawn_echo_target().await;

    let endpoint = client_endpoint_with_transport(&server.ca, &["h3"], windowless_transport());
    let connection = finish_connect(&endpoint, server.addr)
        .await
        .expect("handshake");

    let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
    send.write_all(&connect_headers_frame(&target.to_string()))
        .await
        .expect("send a CONNECT that will be accepted");

    // Past the server's idle timeout, without reading a byte: reading is what
    // would grow the window and let the 200 through.
    tokio::time::sleep(Duration::from_millis(3_000)).await;

    let error = tokio::time::timeout(TIMEOUT, recv.read_to_end(4096))
        .await
        .expect("the server must not wait for a window that is not coming")
        .expect_err("a 200 the peer would not take must end in a reset");

    match error {
        quinn::ReadToEndError::Read(quinn::ReadError::Reset(code)) => assert_eq!(
            code.into_inner(),
            H3_REQUEST_CANCELLED,
            "an abandoned 200 is a cancelled request"
        ),
        other => panic!("expected the response side to be reset, got {other}"),
    }

    // One tunnel that could not be opened is not a reason to drop everything
    // else on the connection.
    assert!(
        connection.close_reason().is_none(),
        "the connection must survive a tunnel whose 200 could not be delivered"
    );
}

/// The target of a 200 that could not be delivered is closed with a reset, not
/// a FIN.
///
/// The tunnel never opened, so the connection the proxy had already made to the
/// target carries nothing and the client will never hear about it. RFC 9114
/// §4.4: "if a proxy detects an error with the stream or the QUIC connection, it
/// MUST close the TCP connection", and "In all these cases, if the underlying
/// TCP implementation permits it, the proxy SHOULD send a TCP segment with the
/// RST bit set." Dropping the socket satisfies the MUST on its own; the SHOULD
/// is what stops a target from reading a polite goodbye off a request that was
/// cancelled, and from holding a half-open connection until its own timeout.
#[tokio::test]
async fn the_target_of_a_200_the_peer_will_not_take_is_reset_too() {
    let server = TestServer::start_with(&format!("{DELIBERATE}{ALLOW_PRIVATE}")).await;
    let (target, mut ended) = spawn_end_reporting_target().await;

    let endpoint = client_endpoint_with_transport(&server.ca, &["h3"], windowless_transport());
    let connection = finish_connect(&endpoint, server.addr)
        .await
        .expect("handshake");

    let (mut send, _recv) = connection.open_bi().await.expect("open a request stream");
    send.write_all(&connect_headers_frame(&target.to_string()))
        .await
        .expect("send a CONNECT that will be accepted");

    // Past the server's idle timeout, without reading a byte: reading is what
    // would grow the window and let the 200 through.
    tokio::time::sleep(Duration::from_millis(3_000)).await;

    let end = tokio::time::timeout(TIMEOUT, ended.recv())
        .await
        .expect("the target socket must not outlive the 200 it was opened for")
        .expect("close notification");
    assert_eq!(
        end,
        ConnectionEnd::Failed(std::io::ErrorKind::ConnectionReset),
        "a target whose tunnel was cancelled must see a reset, not a clean end of stream"
    );
}

#[tokio::test]
async fn refuses_a_target_that_is_not_listening() {
    let server = TestServer::start().await;
    let target = closed_address().await;
    let mut client = H3Client::connect(&server).await;

    let response = respond_to(&mut client, connect_request(&target.to_string())).await;

    // RFC 9114 §4.4: failure to establish the connection is reported with a
    // non-2xx status, not a stream reset.
    assert_eq!(response.status, Status::BAD_GATEWAY);

    // RFC 9209 §2.1.2: the refusal names the hop that refused it, as a
    // structured field String. Only failures to reach a target carry it.
    assert_eq!(
        response
            .fields
            .get("proxy-status")
            .map(|value| value.to_str().expect("proxy-status is ASCII")),
        Some(format!("volto; error=connection_refused; next-hop=\"{target}\"").as_str()),
        "the refusal must name the address that refused the connection"
    );
}

/// A refusal ends the request stream, so a client reading the answer to its end
/// reaches one.
///
/// The response is the whole of what a refused request gets: no tunnel is opened
/// behind it and there is nothing further to send. A stream left open after it
/// puts a client that reads to the end of a message — the ordinary way to read
/// an HTTP response — into a wait that only the idle timeout ends, for a message
/// it already holds in full. Every refusal this server sends is written and
/// closed by the one helper, so any one of them pins the shape for all.
#[tokio::test]
async fn a_refusal_ends_the_request_stream() {
    let server = TestServer::start().await;
    let target = closed_address().await;
    let mut client = H3Client::connect(&server).await;

    let (response, mut stream) =
        send_and_respond(&mut client, connect_request(&target.to_string())).await;
    assert_eq!(response.status, Status::BAD_GATEWAY);

    match tokio::time::timeout(TIMEOUT, stream.recv_data()).await {
        Ok(Ok(None)) => {}
        Ok(Ok(Some(_))) => panic!("a refusal has no body to deliver"),
        Ok(Err(error)) => panic!("a refused request stream must end cleanly, not as {error:?}"),
        Err(_) => panic!("the refused request stream was left open with nothing left to come"),
    }
}

/// Arms an address that black-holes SYNs, in the only portable way there is.
///
/// A listening socket with the smallest possible backlog whose `accept` is never
/// called: once the accept queue is full the kernel simply drops further SYNs,
/// which is exactly what a target behind a silently discarding firewall looks
/// like from here — the connect neither completes nor fails, it just never
/// finishes. Filling the queue is done by connecting until an attempt stops
/// completing, which is also the proof that the arming worked.
///
/// Returns the address, the connections holding the queue full, and the listener
/// — all three must stay alive for the address to keep black-holing. `None`
/// means this kernel does not behave that way, and the caller should skip rather
/// than fail: a differently tuned host must not make the suite red.
async fn arm_a_blackholed_address() -> Option<(SocketAddr, Vec<TcpStream>, TcpListener)> {
    let socket = TcpSocket::new_v4().ok()?;
    socket
        .bind("127.0.0.1:0".parse().expect("bind address"))
        .ok()?;
    let listener = socket.listen(1).ok()?;
    let addr = listener.local_addr().ok()?;

    let mut holding = Vec::new();
    for _ in 0..20 {
        match tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(addr)).await {
            // The queue has room still; keep the connection so it stays taken.
            Ok(Ok(held)) => holding.push(held),
            // Refused rather than dropped: this kernel does not black-hole.
            Ok(Err(_)) => return None,
            // A SYN that draws no answer at all: the queue is full.
            Err(_) => return Some((addr, holding, listener)),
        }
    }

    None
}

/// A target that swallows SYNs must cost the client its connect budget and then
/// a refusal, rather than holding the tunnel slot for the operating system's own
/// retry schedule — around two minutes on Linux.
#[tokio::test]
async fn a_black_holed_target_is_refused_when_the_connect_budget_expires() {
    let Some((blackhole, _holding, _listener)) = arm_a_blackholed_address().await else {
        eprintln!(
            "skipping: this kernel does not drop SYNs for a full accept queue, so no \
             black-holed address can be arranged"
        );
        return;
    };

    let server =
        TestServer::start_with(&format!("[limits]\nconnect_timeout = 1\n{ALLOW_PRIVATE}")).await;
    let mut client = H3Client::connect(&server).await;

    let started = std::time::Instant::now();
    let response = respond_to(&mut client, connect_request(&blackhole.to_string())).await;
    let elapsed = started.elapsed();

    // RFC 9209: a target that never answered is a timeout, not an unreachable
    // one, and the status follows the registered type.
    assert_eq!(response.status, Status::GATEWAY_TIMEOUT);
    let proxy_status = response
        .fields
        .get("proxy-status")
        .map(|value| value.to_str().expect("proxy-status is ASCII"))
        .expect("a refusal must say why");
    assert!(
        proxy_status.contains("error=connection_timeout"),
        "{proxy_status}"
    );
    // And it names the hop it gave up on.
    assert!(
        proxy_status.contains(&blackhole.to_string()),
        "{proxy_status}"
    );

    // The budget, not the kernel, decided when to give up.
    assert!(
        elapsed >= Duration::from_millis(800),
        "answered before the budget expired, after {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the connect was not bounded by the budget: {elapsed:?}"
    );

    // And the tunnel slot went back: the same connection still serves a target
    // that does answer.
    let target = spawn_echo_target().await;
    let mut good = open_tcp_tunnel(&mut client, &target.to_string()).await;

    good.send_data(Bytes::from_static(b"after the timeout"))
        .await
        .expect("send payload");
    let echoed = read_at_least(&mut good, b"after the timeout".len()).await;
    assert_eq!(&echoed, b"after the timeout");
}

/// A request this proxy will not serve is answered and *finished*, never reset.
///
/// Decision D40, and the reason the second half of this test exists: a status
/// that is immediately followed by a RESET_STREAM is worse than useless, because
/// the client is entitled to read the reset as "the proxy broke" and may retry or
/// fail over instead of surfacing the 400. Only reading past the response to a
/// clean end of stream tells the two apart — `recv_response` succeeds either way.
#[tokio::test]
async fn refuses_an_authority_without_a_port() {
    let server = TestServer::start().await;
    let mut client = H3Client::connect(&server).await;

    let (response, mut stream) =
        send_and_respond(&mut client, connect_request("example.com")).await;

    assert_eq!(response.status, Status::BAD_REQUEST);

    let end = tokio::time::timeout(TIMEOUT, stream.recv_data())
        .await
        .expect("the stream ended promptly")
        .expect("a refusal must end cleanly, not with a stream error");
    assert!(
        end.is_none(),
        "a 400 carries no body: the next read is the end of the stream"
    );
}

/// A bracket that did not open the authority is not part of a host (review M3).
///
/// RFC 3986 gives "[" and "]" to the IP-literal form alone, but they are legal
/// *characters* in an authority, so the codec passes them through and the split
/// is where the shape is judged. Until it did, `127.0.0.1]:P` opened a tunnel to
/// `127.0.0.1:P` -- the resolver took the bracket off on its way past -- so the
/// connection went somewhere the request log did not name.
#[tokio::test]
async fn refuses_an_authority_with_a_stray_bracket() {
    let server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // The same target the tunnel would have reached, so what is under test is
    // the bracket and nothing about the destination.
    let authority = format!("127.0.0.1]:{}", target.port());
    let (response, mut stream) = send_and_respond(&mut client, connect_request(&authority)).await;

    assert_eq!(
        response.status,
        Status::BAD_REQUEST,
        "a host with a stray bracket is not the host without it"
    );

    let end = tokio::time::timeout(TIMEOUT, stream.recv_data())
        .await
        .expect("the stream ended promptly")
        .expect("a refusal must end cleanly, not with a stream error");
    assert!(end.is_none(), "a 400 carries no body");
}

/// RFC 9114 §4.2: "any message containing connection-specific fields MUST be
/// treated as malformed". The answer is a 400 rather than a reset, which RFC
/// 9114 §4.1.2 allows.
///
/// Table-driven over every route a request can be dispatched to and over every
/// field RFC 9110 §7.6.1 names, because the rule is about the *message*: it
/// cannot depend on which tunnel the request asked for, on whether this server
/// implements that tunnel at all, or on whether the sender has authenticated
/// (review M4). Each route is exercised with a clean request first, so a 400
/// cannot be some other refusal wearing the same status.
#[tokio::test]
async fn refuses_connection_specific_fields() {
    let server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let udp_target = common::spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // Every route through the dispatcher, with what each answers when there is
    // nothing wrong with the request: a 400 below that came from the wrong place
    // would show up here as the wrong control.
    let routes = [
        ("tcp", Status::OK),
        ("connect-udp", Status::OK),
        ("unknown-protocol", Status::NOT_IMPLEMENTED),
        ("not-connect", Status::NOT_IMPLEMENTED),
    ];

    for (route, accepted) in routes {
        let response =
            respond_to(&mut client, request_on(route, &server, target, udp_target)).await;
        assert_eq!(
            response.status, accepted,
            "{route}: the control request must reach the route it names"
        );

        for (name, value) in [
            ("proxy-connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
        ] {
            let mut request = request_on(route, &server, target, udp_target);
            request.fields.append(name, FieldValue::from_static(value));

            let (response, mut stream) = send_and_respond(&mut client, request).await;
            assert_eq!(
                response.status,
                Status::BAD_REQUEST,
                "{route}: {name}: {value} must be refused"
            );
            let end = tokio::time::timeout(TIMEOUT, stream.recv_data())
                .await
                .expect("the stream ended promptly")
                .expect("a refusal must end cleanly, not with a stream error");
            assert!(end.is_none(), "{route}: {name}: a 400 carries no body");
        }

        // `TE` is the fifth field of RFC 9110 §7.6.1 and the one RFC 9114 §4.2
        // lets through -- "it MUST NOT contain any value other than 'trailers'".
        // Any other value is malformed too, but the codec catches it while the
        // field section is still being decoded, so the answer is a reset rather
        // than a status. Same rule, different half of the pipeline.
        let mut request = request_on(route, &server, target, udp_target);
        request.fields.append("te", FieldValue::from_static("gzip"));

        let mut stream = client
            .send
            .send_request(request)
            .await
            .expect("send a request carrying TE");
        let error = tokio::time::timeout(TIMEOUT, stream.recv_response())
            .await
            .expect("the server must answer promptly")
            .expect_err("a TE other than trailers must be refused as malformed");
        assert_peer_reset(&error, H3_MESSAGE_ERROR);
    }

    // And before the credentials check, not after it: the rule is about the
    // message, so an unauthenticated peer must be told what is wrong with its
    // request rather than that it should have signed it (review M4).
    let guarded = TestServer::start_with(&format!(
        "{ALLOW_PRIVATE}{}",
        common::auth_section(&[("user1", "s3cret")])
    ))
    .await;
    let mut stranger = H3Client::connect(&guarded).await;

    let mut request = connect_request(&target.to_string());
    request
        .fields
        .append("transfer-encoding", FieldValue::from_static("chunked"));
    let response = respond_to(&mut stranger, request).await;
    assert_eq!(
        response.status,
        Status::BAD_REQUEST,
        "a malformed message is malformed whoever sent it"
    );
}

/// One request on each of the routes `conn::handle_request` dispatches to.
///
/// The unknown `:protocol` and the plain GET carry everything RFC 8441 §4 and
/// RFC 9114 §4.3.1 make mandatory, so a refusal can only be the routing arm
/// under test rather than a malformed request short of it.
fn request_on(
    route: &str,
    server: &TestServer,
    tcp_target: SocketAddr,
    udp_target: SocketAddr,
) -> Request {
    match route {
        "tcp" => connect_request(&tcp_target.to_string()),
        "connect-udp" => common::connect_udp_request(server.addr, "127.0.0.1", udp_target.port()),
        "unknown-protocol" => {
            let mut request = Request::new(Method::Connect);
            request.scheme = Some("https".into());
            request.authority = Some(server.addr.to_string().into());
            request.path = Some("/.well-known/masque/ip/*/*/".into());
            request.protocol = Some("connect-ip".into());
            request
        }
        "not-connect" => {
            let mut request = Request::new(Method::Other("GET".into()));
            request.scheme = Some("https".into());
            request.authority = Some(server.addr.to_string().into());
            request.path = Some("/".into());
            request
        }
        other => panic!("no such route: {other}"),
    }
}

/// A proxy is not an origin server: ordinary requests are refused, not panicked
/// on.
#[tokio::test]
async fn plain_get_is_not_implemented() {
    let server = TestServer::start().await;
    let mut client = H3Client::connect(&server).await;

    let mut req = Request::new(Method::Other("GET".into()));
    req.scheme = Some("https".into());
    req.authority = Some(server.addr.to_string().into());
    req.path = Some("/".into());

    let response = respond_to(&mut client, req).await;

    assert_eq!(response.status, Status::NOT_IMPLEMENTED);
}

/// Several tunnels multiplexed on one QUIC connection must stay independent.
#[tokio::test]
async fn concurrent_tunnels_on_one_connection_stay_independent() {
    let server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut streams = Vec::new();
    for i in 0..5u8 {
        let stream = open_tcp_tunnel(&mut client, &target.to_string()).await;
        streams.push((i, stream));
    }

    // Write a distinct payload per tunnel, then check each one got its own back.
    for (i, stream) in &mut streams {
        stream
            .send_data(Bytes::from(vec![*i; 8]))
            .await
            .expect("send payload");
    }
    for (i, stream) in &mut streams {
        let echoed = read_at_least(stream, 8).await;
        assert_eq!(echoed, vec![*i; 8], "tunnel {i} received another's bytes");
    }
}

/// RFC 9114 §4.4 permits only DATA on a stream whose CONNECT has completed, and
/// makes any other known frame a connection error — a trailer section included,
/// which is the one an ordinary request would be allowed.
#[tokio::test]
async fn a_trailer_section_on_a_live_tunnel_ends_the_connection() {
    let server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // A working tunnel first, so what is refused is a frame on a stream that had
    // completed its CONNECT rather than one that never got that far.
    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;
    stream
        .send_data(Bytes::from_static(b"hello volto"))
        .await
        .expect("send payload");
    let echoed = read_at_least(&mut stream, b"hello volto".len()).await;
    assert_eq!(&echoed, b"hello volto");

    stream
        .send_trailers(&[(b"x-trailer", b"volto")])
        .await
        .expect("send a trailer section");

    // A trailer section must end the connection, with the code that tells the
    // peer which rule it broke.
    assert_closed_with(&client.quic, H3_FRAME_UNEXPECTED, TIMEOUT).await;
}
