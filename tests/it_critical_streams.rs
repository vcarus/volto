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
use common::rawstream::{application_close, frame};
use common::{connect_quic, TestServer, TIMEOUT};
use volto::datagram;

/// Control stream type (RFC 9114 §6.2.1).
const STREAM_TYPE_CONTROL: u64 = 0x00;
/// QPACK encoder stream type (RFC 9204 §4.2).
const STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
/// QPACK decoder stream type (RFC 9204 §4.2).
const STREAM_TYPE_QPACK_DECODER: u64 = 0x03;

/// SETTINGS frame type (RFC 9114 §7.2.4).
const FRAME_SETTINGS: u64 = 0x04;
/// CANCEL_PUSH frame type (RFC 9114 §7.2.3).
const FRAME_CANCEL_PUSH: u64 = 0x03;
/// MAX_PUSH_ID frame type (RFC 9114 §7.2.7).
const FRAME_MAX_PUSH_ID: u64 = 0x0d;

/// H3_ID_ERROR (RFC 9114 §8.1).
const H3_ID_ERROR: u64 = 0x108;
/// QPACK_ENCODER_STREAM_ERROR (RFC 9204 §6).
const QPACK_ENCODER_STREAM_ERROR: u64 = 0x201;
/// QPACK_DECODER_STREAM_ERROR (RFC 9204 §6).
const QPACK_DECODER_STREAM_ERROR: u64 = 0x202;

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

    let mut stream = connection
        .open_uni()
        .await
        .expect("open a unidirectional stream");
    let mut wire = BytesMut::new();
    datagram::put_varint(&mut wire, stream_type);
    wire.extend_from_slice(bytes);
    stream.write_all(&wire).await.expect("send the stream");

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

/// RFC 9114 §7.2.3: a CANCEL_PUSH for a push ID never mentioned by a
/// PUSH_PROMISE is H3_ID_ERROR -- and this server mentions none.
#[tokio::test]
async fn a_cancel_push_is_an_id_error() {
    let mut control = frame(FRAME_SETTINGS, &[]);
    control.extend(push_id_frame(FRAME_CANCEL_PUSH, 7));

    expect_close(
        "CANCEL_PUSH",
        STREAM_TYPE_CONTROL,
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
        STREAM_TYPE_CONTROL,
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
            STREAM_TYPE_QPACK_ENCODER,
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
            STREAM_TYPE_QPACK_DECODER,
            &bytes,
            QPACK_DECODER_STREAM_ERROR,
            names,
        )
        .await;
    }
}
