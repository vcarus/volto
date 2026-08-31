//! The peer's critical streams (RFC 9114 §6.2.1, RFC 9204 §4.2) are read, not
//! merely drained: a server that never pushes and never uses the QPACK dynamic
//! table still owes the RFC its verdict on the frames and instructions that
//! only make sense when it does.
//!
//! Every case drives a raw QUIC stream and asserts on the CONNECTION_CLOSE the
//! server answers with -- the code and the reason phrase. The phrase is what
//! tells "the offending instruction was refused" from "an earlier, harmless one
//! was": several cases send something the server must accept first, and only
//! the phrase shows it was read past rather than tripped over.

mod common;

use bytes::BytesMut;
use common::rawstream::{
    application_close, connect_headers_frame, frame, open_uni_stream, read_frame, read_varint,
    status_of, FRAME_CANCEL_PUSH, FRAME_HEADERS, FRAME_MAX_PUSH_ID, FRAME_SETTINGS,
    H3_CLOSED_CRITICAL_STREAM, H3_ID_ERROR, H3_REQUEST_CANCELLED, QPACK_DECODER_STREAM_ERROR,
    QPACK_ENCODER_STREAM_ERROR, STREAM_CONTROL, STREAM_QPACK_DECODER, STREAM_QPACK_ENCODER,
};
use common::{connect_quic, TestServer, TIMEOUT};
use volto::datagram;

/// A target the destination policy refuses before the resolver is asked.
///
/// Port 25 is on the default deny list and the port rule is checked first, so a
/// request for it is answered without touching the network.
const DENIED_TARGET: &str = "192.0.2.1:25";

/// A frame whose whole payload is one varint: CANCEL_PUSH or MAX_PUSH_ID.
fn push_id_frame(kind: u64, push_id: u64) -> Vec<u8> {
    let mut payload = BytesMut::new();
    datagram::put_varint(&mut payload, push_id);
    frame(kind, &payload)
}

/// Opens a unidirectional stream of `stream_type`, sends `bytes` on it, and
/// asserts the server ends the connection with `code` and a reason phrase that
/// names the offending instruction.
async fn expect_close(name: &str, stream_type: u64, bytes: &[u8], code: u64, names: &str) {
    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    let _stream = open_uni_stream(&connection, stream_type, bytes).await;

    let (closed_with, reason) = application_close(&connection, TIMEOUT).await;
    assert_eq!(
        closed_with, code,
        "{name}: wrong close code; reason was {reason:?}"
    );
    assert!(
        reason.contains(names),
        "{name}: the reason {reason:?} does not name the offending instruction"
    );
}

/// Accepts the server's unidirectional streams until its control stream turns
/// up, and hands it back with its type varint already read.
async fn server_control_stream(connection: &quinn::Connection) -> quinn::RecvStream {
    for _ in 0..8 {
        let mut recv = tokio::time::timeout(TIMEOUT, connection.accept_uni())
            .await
            .expect("the server opens its critical streams")
            .expect("accept a unidirectional stream");

        if read_varint(&mut recv).await == STREAM_CONTROL {
            return recv;
        }
    }

    panic!("the server never opened a control stream");
}

/// Sends one request the server answers without touching the network.
///
/// Used as a round trip rather than for its answer: a server that has replied to
/// these bytes has read past everything queued before them.
async fn round_trip(connection: &quinn::Connection) {
    let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
    send.write_all(&connect_headers_frame(DENIED_TARGET))
        .await
        .expect("send a CONNECT request");

    let (frame_type, payload) = read_frame(&mut recv).await;
    assert_eq!(frame_type, FRAME_HEADERS, "a response begins with HEADERS");
    assert_eq!(
        status_of(&payload),
        "403",
        "the server must still be serving"
    );
}

/// A control stream the peer refuses to read is H3_CLOSED_CRITICAL_STREAM on
/// the wire, not merely in this server's own head.
///
//= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
//# If either control stream is closed at any point, this MUST be treated
//# as a connection error of type H3_CLOSED_CRITICAL_STREAM.
///
/// STOP_SENDING is the only way a client can end a stream it does not own, and
/// the sentence before that one forbids it in as many words: "the receiver MUST
/// NOT request that the sender close the control stream". What the server owes
/// is the code on the wire, which it can only reach by trying to write there --
/// and the one frame it writes on that stream after its SETTINGS is the GOAWAY
/// of a graceful shutdown, so that is the trigger.
///
/// H3_NO_ERROR (0x100) is what a server that reached the verdict but never sent
/// it would end up closing with, from the drop that ends every connection.
#[tokio::test]
async fn a_stopped_control_stream_ends_the_connection() {
    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    let mut control = server_control_stream(&connection).await;
    // Any code would do here -- what is under test is the server's answer to
    // being stopped at all, not what it was stopped with. H3_REQUEST_CANCELLED
    // says why without claiming a fault of the server's.
    control
        .stop(quinn::VarInt::from_u32(H3_REQUEST_CANCELLED as u32))
        .expect("stop the server's control stream");

    // So the STOP_SENDING is not merely queued here but processed there: it was
    // written before these bytes were, and a server that has answered them has
    // read past it.
    round_trip(&connection).await;

    server.shutdown();

    let (closed_with, reason) = application_close(&connection, TIMEOUT).await;
    assert_eq!(
        closed_with, H3_CLOSED_CRITICAL_STREAM,
        "a control stream the peer refuses to read; the reason was {reason:?}"
    );
    assert!(!reason.is_empty(), "the peer must be told what it did");
}

/// RFC 9114 §7.2.3: a CANCEL_PUSH for a push ID never mentioned by a
/// PUSH_PROMISE is H3_ID_ERROR -- and this server mentions none.
#[tokio::test]
async fn a_cancel_push_is_an_id_error() {
    let mut control = frame(FRAME_SETTINGS, &[]);
    control.extend(push_id_frame(FRAME_CANCEL_PUSH, 7));

    expect_close(
        "CANCEL_PUSH",
        STREAM_CONTROL,
        &control,
        H3_ID_ERROR,
        "CANCEL_PUSH",
    )
    .await;
}

/// RFC 9114 §7.2.7: MAX_PUSH_ID may repeat or grow, but a smaller value than
/// previously received is H3_ID_ERROR. The accepted ones come first so the
/// reason phrase proves they were accepted.
#[tokio::test]
async fn a_shrinking_max_push_id_is_an_id_error() {
    let mut control = frame(FRAME_SETTINGS, &[]);
    for push_id in [10, 10, 12, 5] {
        control.extend(push_id_frame(FRAME_MAX_PUSH_ID, push_id));
    }

    expect_close(
        "a shrinking MAX_PUSH_ID",
        STREAM_CONTROL,
        &control,
        H3_ID_ERROR,
        "shrank to 5",
    )
    .await;
}

/// RFC 9204 §4.3.1 and §3.2.2: with the zero table capacity this server
/// advertises, any capacity above zero and any insertion is a connection error
/// on the encoder stream. The third case sends a capacity of zero first, which
/// must be accepted, and the reason phrase shows it was.
#[tokio::test]
async fn encoder_instructions_beyond_a_zero_table_are_refused() {
    for (name, bytes, names) in [
        // Set Dynamic Table Capacity: 5-bit prefix, 220 = 31 + (189 as 0xbd 0x01).
        (
            "a dynamic table capacity of 220",
            vec![0x3f, 0xbd, 0x01],
            "capacity",
        ),
        // Insert with Literal Name: name "a", value "b".
        (
            "an Insert with Literal Name",
            vec![0x41, b'a', 0x01, b'b'],
            "Literal Name",
        ),
        // A capacity of zero, then a Duplicate.
        (
            "a Duplicate after a zero capacity",
            vec![0x20, 0x00],
            "Duplicate",
        ),
    ] {
        expect_close(
            name,
            STREAM_QPACK_ENCODER,
            &bytes,
            QPACK_ENCODER_STREAM_ERROR,
            names,
        )
        .await;
    }
}

/// RFC 9204 §4.4.1 and §4.4.3: this encoder never uses the dynamic table, so a
/// Section Acknowledgment or an Insert Count Increment is a connection error on
/// the decoder stream. Stream Cancellation is allowed, and the second case
/// sends one whose stream id runs to two continuation bytes before the
/// offending instruction: read correctly, the reason names the Increment; read
/// byte by byte as instructions, the 0x81 would have been a Section
/// Acknowledgment instead.
///
/// The last two cases are the two sides of the bound on how far a prefixed
/// integer may run. Nine continuation bytes of seven bits each is what a 6-bit
/// prefix needs to reach the 62 bits RFC 9204 §4.1.1 requires decoding, so the
/// ninth must be read past and the tenth must not: the third case ends its
/// integer on the ninth and is refused for the Increment that follows, and only
/// the fourth is refused for the integer itself.
#[tokio::test]
async fn decoder_instructions_for_a_table_never_used_are_refused() {
    for (name, bytes, names) in [
        (
            "a Section Acknowledgment",
            vec![0x80],
            "Section Acknowledgment",
        ),
        // Stream Cancellation of stream 63 + 1 + (0x41 << 7), then Increment 0.
        (
            "an Insert Count Increment after a Stream Cancellation",
            vec![0x7f, 0x81, 0x41, 0x00],
            "Insert Count Increment",
        ),
        // Stream Cancellation whose stream id ends on the ninth continuation
        // byte, then Increment 0. The reason names the Increment only if all
        // nine were read past.
        (
            "an Insert Count Increment after a stream id of the full 62 bits",
            vec![
                0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01, 0x00,
            ],
            "Insert Count Increment",
        ),
        // Stream Cancellation whose integer never ends.
        (
            "a stream id past 62 bits",
            vec![
                0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
            ],
            "62 bits",
        ),
    ] {
        expect_close(
            name,
            STREAM_QPACK_DECODER,
            &bytes,
            QPACK_DECODER_STREAM_ERROR,
            names,
        )
        .await;
    }
}
