//! The frame reader: a [`FrameDecoder`] fed from a QUIC receive stream, with
//! the read-ahead of a tunnel, and the loopback stream its tests and the
//! request-stream tests run on.

use std::sync::Arc;

use bytes::Bytes;

use super::{BufferBudget, Error, FrameDecoder, Item, StreamKind};
use crate::h3::error::{Code, Violation};

/// Most chunks [`FrameReader`] takes from quinn in one read, on a stream that
/// carries a tunnel.
///
/// Every read of a QUIC stream takes the connection's lock, and quinn hands out
/// one chunk per STREAM frame it received, about 1.4 KB each in a bulk upload.
/// At one chunk per read that is about 800 lock acquisitions per MiB, and one
/// `write` to the target per chunk. With up to this many chunks per read, both
/// counts fall by up to this factor: `tunnel::tcp` gathers what is already
/// decoded into one vectored write.
///
/// # What it holds
///
/// The slots are allocated when the CONNECT completes: this many `Bytes`
/// handles of 32 bytes each, 1 KiB per tunnel. The chunks in them are quinn's
/// own buffers, not copies. A read takes only what quinn already has for the
/// stream, and the reader reads again only after every chunk of the previous
/// read has gone through the decoder. So the payload held is at most what quinn
/// had buffered for the stream at one read, which quinn's stream receive window
/// (`crate::quic::STREAM_RECEIVE_WINDOW`) bounds. In an ordinary upload it is
/// this many chunks of about 1.4 KB, some 45 KB. A single `read_chunk` can
/// return that much in one chunk when quinn has merged a stream's fragments,
/// so the read-ahead does not raise the worst case per tunnel. Bytes taken from
/// quinn do not count against its flow-control windows: quinn grants the peer
/// credit for them while they wait here.
///
/// # Why only a tunnel
///
/// A request stream whose CONNECT has not completed, and the peer's control
/// stream, read one chunk at a time. A peer that has not authenticated can send
/// on both, so the read-ahead adds nothing to what such a peer can make this
/// server hold: a request stream becomes a tunnel only once its request has
/// passed the credentials check (`crate::conn`) and been answered with a 2xx.
/// A refused request is stopped first, and [`FrameReader::stop`] releases the
/// one chunk its stream holds while the refusal is written.
/// [`BufferBudget`] and `MAX_SKIPPED_FRAMES` apply only to streams that read one
/// chunk at a time, since a tunnel buffers no frame and counts no skip.
pub const READ_AHEAD_CHUNKS: usize = 32;

/// A `FrameDecoder` wired to a QUIC receive stream.
///
/// All of the awaiting happens in one place, the read from quinn
/// ([`quinn::RecvStream::read_chunk`] or, on a tunnel,
/// [`quinn::RecvStream::read_chunks`]). Every byte it produces is accounted for
/// in the decoder or the read-ahead before this returns, which makes
/// [`Self::next`] cancel-safe. Both reads are cancel-safe themselves
/// and write nothing into `self` until they complete. `tunnel::udp` reads
/// request streams inside a `select!` with a timeout, so a dropped read future
/// must never lose a parsed frame header.
///
/// # Order
///
/// The read-ahead ([`READ_AHEAD_CHUNKS`]) is drained before quinn is read
/// again, and quinn is the only source of a stream's ending: its FIN, a reset,
/// or a lost connection. So every byte of every chunk taken before an ending is
/// decoded and handed out before that ending is reported, the same order as
/// reading one chunk at a time. `read_chunks` keeps the stream's
/// order inside one read: it fills the slots in stream order, each chunk
/// starting where the one before it ended.
pub struct FrameReader {
    recv: quinn::RecvStream,
    decoder: FrameDecoder,
    /// The read-ahead, from the moment the CONNECT completes.
    ///
    /// `None`, with no allocation, until then, and whether it is `None` is what
    /// decides how [`Self::next`] reads: one chunk at a time without it, a
    /// slot-full at a time with it. Boxed so a reader that never carries a
    /// tunnel pays one pointer for it, and so the request-stream types that hold
    /// a reader do not grow by the slots.
    ahead: Option<Box<ReadAhead>>,
    /// Set once the peer has finished its sending side.
    finished: bool,
}

/// Chunks a tunnel's [`FrameReader`] has taken from quinn and not yet pushed to
/// its decoder ([`READ_AHEAD_CHUNKS`]).
struct ReadAhead {
    /// What `quinn::RecvStream::read_chunks` fills, in stream order.
    ///
    /// A slot is emptied as its chunk is pushed, so a chunk that has been
    /// decoded is not kept alive here.
    slots: [Bytes; READ_AHEAD_CHUNKS],
    /// Index of the next slot to push.
    next: usize,
    /// How many slots the last read filled.
    filled: usize,
}

impl ReadAhead {
    /// An empty read-ahead, allocated once per tunnel.
    fn new() -> Box<Self> {
        Box::new(Self {
            slots: std::array::from_fn(|_| Bytes::new()),
            next: 0,
            filled: 0,
        })
    }

    /// The next chunk the last read filled, or `None` once every one has been
    /// taken.
    fn take(&mut self) -> Option<Bytes> {
        let slot = self.slots[..self.filled].get_mut(self.next)?;
        self.next += 1;
        Some(std::mem::take(slot))
    }

    /// Drops every chunk not yet taken.
    fn clear(&mut self) {
        while self.take().is_some() {}
        self.next = 0;
        self.filled = 0;
    }
}

impl FrameReader {
    /// A reader for a stream on which every frame type this server parses may
    /// appear.
    ///
    /// The permissive constructor ([`StreamKind::Control`]), for the suite's
    /// client. The server reads its streams through the crate-internal
    /// `Self::on_server_control` and `Self::on_request_stream` instead.
    ///
    /// `budget` is the connection's, not this stream's: see [`BufferBudget`].
    pub fn new(recv: quinn::RecvStream, budget: Arc<BufferBudget>) -> Self {
        Self::with_kind(recv, StreamKind::Control, budget)
    }

    /// A reader for the peer's control stream, with its type rules applied from
    /// the frame header ([`StreamKind::ServerControl`]).
    pub(in crate::h3) fn on_server_control(
        recv: quinn::RecvStream,
        budget: Arc<BufferBudget>,
    ) -> Self {
        Self::with_kind(recv, StreamKind::ServerControl, budget)
    }

    /// A reader for a request stream whose request has not completed.
    ///
    /// Becomes a tunnel's reader once [`Self::connect_completed`] is called.
    pub(in crate::h3) fn on_request_stream(
        recv: quinn::RecvStream,
        budget: Arc<BufferBudget>,
    ) -> Self {
        Self::with_kind(recv, StreamKind::Request, budget)
    }

    /// Whether this stream has handed out a SETTINGS frame that parsed.
    pub(in crate::h3) fn settings_seen(&self) -> bool {
        self.decoder.settings_seen
    }

    fn with_kind(recv: quinn::RecvStream, stream: StreamKind, budget: Arc<BufferBudget>) -> Self {
        Self {
            recv,
            decoder: FrameDecoder::new(stream, budget),
            ahead: None,
            finished: false,
        }
    }

    /// Narrows the frame rules to RFC 9114 §4.4's, once the CONNECT is answered,
    /// and turns on the read-ahead ([`READ_AHEAD_CHUNKS`]).
    pub(in crate::h3) fn connect_completed(&mut self) {
        self.decoder.connect_completed();
        if self.ahead.is_none() {
            self.ahead = Some(ReadAhead::new());
        }
    }

    /// Asks the peer to stop sending on this stream.
    ///
    /// The read-ahead is emptied as well, and so is the rest of the chunk the
    /// decoder is working through. quinn discards a stopped stream's unread
    /// bytes, and those are bytes this reader has not decoded yet, so they go
    /// the same way: a stopped stream hands out nothing it had not already
    /// decoded when it was stopped. Dropping them also releases the chunk,
    /// which can be as large as the stream receive window, while the stream
    /// lives on to carry a refusal.
    pub fn stop(&mut self, code: Code) {
        // Fails only if the stream is already closed, which needs no reporting.
        let _ = self.recv.stop(super::super::varint(code));
        if let Some(ahead) = &mut self.ahead {
            ahead.clear();
        }
        self.decoder.chunk = Bytes::new();
    }

    /// Whether quinn has more of this stream to give, without taking it.
    ///
    /// `Ok(true)` means a read from quinn would return data now, `Ok(false)`
    /// that the peer finished and quinn has handed over every byte; a reset
    /// arrives as `quinn::ReadError::Reset`. A zero-length read is what asks the
    /// question: `quinn::RecvStream::read_chunk(0, ..)` takes the ordinary read
    /// path, but the assembler underneath copies out `min(0, available)` bytes,
    /// so the decoder above stays authoritative for every byte of the stream.
    ///
    /// The question is about quinn alone. Chunks in the read-ahead have already
    /// left quinn, so they are not counted. `Ok(false)` can be the answer while
    /// the read-ahead still holds the last of the body. When the read-ahead
    /// holds everything quinn had, the read waits until quinn receives more, or
    /// a reset.
    ///
    /// The one way to wait on a request stream without disturbing it, and the
    /// only one [`super::super::stream::Reader::reset_by_peer`] may use. Its rustdoc
    /// says why `quinn::RecvStream::received_reset` is not used.
    ///
    /// Cancel-safe, like the call underneath.
    pub(in crate::h3) async fn readable(&mut self) -> Result<bool, quinn::ReadError> {
        Ok(self.recv.read_chunk(0, true).await?.is_some())
    }

    /// Reads the next item, or `None` once the peer has finished cleanly.
    pub async fn next(&mut self) -> Result<Option<Item>, Error> {
        loop {
            if let Some(item) = self.try_next()? {
                return Ok(Some(item));
            }
            if self.finished {
                return Ok(None);
            }

            // One chunk while the read-ahead is off, which is what every
            // stream read before its request has been accepted gets; a
            // slot-full once it is on. Neither touches `self` until it
            // completes, so dropping this future here loses nothing.
            let taken = match &mut self.ahead {
                None => self
                    .recv
                    .read_chunk(usize::MAX, true)
                    .await?
                    .map(|chunk| self.decoder.push(chunk.bytes)),
                Some(ahead) => self
                    .recv
                    .read_chunks(&mut ahead.slots)
                    .await?
                    .map(|filled| {
                        ahead.next = 0;
                        ahead.filled = filled;
                    }),
            };

            if taken.is_none() {
                self.finished = true;
                if !self.decoder.at_frame_boundary() {
                    return Err(Violation::connection(
                        Code::H3_FRAME_ERROR,
                        "the stream ended part-way through a frame",
                    )
                    .into());
                }
                return Ok(None);
            }
        }
    }

    /// The next item that can be decoded from chunks already taken from quinn,
    /// without reading quinn and without waiting.
    ///
    /// `Ok(None)` means only that nothing more is decodable without a read. It
    /// is never the end of the stream, which only [`Self::next`] can report,
    /// because only quinn knows it. An error is one the decoder found in those
    /// chunks; the items before it have already been handed out, in order.
    pub(in crate::h3) fn try_next(&mut self) -> Result<Option<Item>, Error> {
        loop {
            if let Some(item) = self.decoder.next_item()? {
                return Ok(Some(item));
            }
            // `next_item` returns `None` only once the chunk it was given is
            // spent, which is the state `push` requires.
            let Some(chunk) = self.ahead.as_mut().and_then(|ahead| ahead.take()) else {
                return Ok(None);
            };
            self.decoder.push(chunk);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use bytes::BytesMut;

    use super::*;
    use crate::h3::error::StreamError;
    use crate::h3::frame::{DATA, put_header};

    // -----------------------------------------------------------------------
    // The reader over a live QUIC stream
    // -----------------------------------------------------------------------

    /// A tunnel's reader on the server side of `upload`.
    fn tunnel_reader(recv: quinn::RecvStream) -> FrameReader {
        let mut reader = FrameReader::on_request_stream(recv, BufferBudget::unshared());
        reader.connect_completed();
        reader
    }

    /// Reads DATA items into `delivered` until the reader stops, and returns
    /// how it stopped: `Ok(())` for the clean end of the stream.
    async fn read_body(reader: &mut FrameReader, delivered: &mut Vec<u8>) -> Result<(), Error> {
        loop {
            let item = tokio::time::timeout(loopback::TIMEOUT, reader.next())
                .await
                .expect("the reader must not wait on bytes that are already here")?;
            match item {
                Some(Item::Data(data)) => delivered.extend_from_slice(&data),
                Some(other) => panic!("expected only DATA, got {other:?}"),
                None => return Ok(()),
            }
        }
    }

    /// The chunks one read took from quinn are handed out in order, ahead of a
    /// reset the stream meets afterwards.
    ///
    /// The body and then the reset are each inside quinn on the server before
    /// the reader is asked for them. quinn drops a stream's unread bytes when
    /// its reset arrives, so what comes out between the first item and the
    /// reset is exactly what the first read took. A reader that takes one chunk
    /// per read hands out a single chunk here, under 1.5 KB; one with a
    /// read-ahead hands out up to `READ_AHEAD_CHUNKS` of them, every byte in
    /// the order it was sent, and only then reports the reset.
    #[tokio::test]
    async fn chunks_one_read_took_are_delivered_before_a_later_reset() {
        let (wire, payload) = loopback::numbered_frames(48, 1000);
        let mut upload = loopback::Upload::start(&wire).await;
        let mut reader = tunnel_reader(upload.take_recv());

        let mut delivered = Vec::new();
        match reader.next().await.expect("the first item") {
            Some(Item::Data(data)) => delivered.extend_from_slice(&data),
            other => panic!("expected DATA, got {other:?}"),
        }

        upload
            .send
            .reset(quinn::VarInt::from_u32(0x10c))
            .expect("reset the request stream");
        upload.settle().await;

        let error = read_body(&mut reader, &mut delivered)
            .await
            .expect_err("the reset must be reported");
        assert_matches!(
                error,
                Error::Stream(StreamError::RemoteTerminate { code }) if code.value() == 0x10c
            ,
            "expected the peer's reset, got {error:?}");

        assert_eq!(
            delivered,
            payload[..delivered.len()],
            "the bytes handed out must be the body's prefix, in order"
        );
        assert!(
            delivered.len() > 8 * 1024,
            "one read took {} bytes before the reset, which is a single chunk; \
             a read must take several",
            delivered.len()
        );
    }

    /// Before its CONNECT completes, a request stream is read one chunk at a
    /// time, as it always was.
    ///
    /// The same sequence as above on a reader still in request mode: what comes
    /// out before the reset is one chunk at most. This is what keeps the
    /// read-ahead out of reach of a peer that has not authenticated.
    #[tokio::test]
    async fn a_stream_whose_connect_has_not_completed_reads_one_chunk_at_a_time() {
        let (wire, payload) = loopback::numbered_frames(48, 1000);
        let mut upload = loopback::Upload::start(&wire).await;
        let mut reader =
            FrameReader::on_request_stream(upload.take_recv(), BufferBudget::unshared());

        let mut delivered = Vec::new();
        match reader.next().await.expect("the first item") {
            Some(Item::Data(data)) => delivered.extend_from_slice(&data),
            other => panic!("expected DATA, got {other:?}"),
        }

        upload
            .send
            .reset(quinn::VarInt::from_u32(0x10c))
            .expect("reset the request stream");
        upload.settle().await;

        read_body(&mut reader, &mut delivered)
            .await
            .expect_err("the reset must be reported");
        assert_eq!(delivered, payload[..delivered.len()]);
        assert!(
            delivered.len() < 2 * 1024,
            "a request stream took {} bytes in one read; only a tunnel reads ahead",
            delivered.len()
        );
    }

    /// Every byte before the client's FIN is handed out before the end of the
    /// stream is.
    ///
    /// The body is far more than one read-ahead, so the end is met after
    /// several reads have each been drained.
    #[tokio::test]
    async fn everything_before_the_fin_comes_out_before_the_end() {
        let (wire, payload) = loopback::numbered_frames(200, 1000);
        let mut upload = loopback::Upload::start(&wire).await;
        upload.send.finish().expect("finish the request stream");
        let mut reader = tunnel_reader(upload.take_recv());

        let mut delivered = Vec::new();
        read_body(&mut reader, &mut delivered)
            .await
            .expect("a body that ends between frames ends cleanly");
        assert_eq!(delivered, payload, "every byte, in order, then the end");
    }

    /// A stream that ends inside a frame is still refused, after every byte
    /// before that frame (RFC 9114 §7.1, quoted on `at_frame_boundary`).
    ///
    /// The truncated frame's header and part of its payload arrive in the same
    /// read as whole frames before it. The verdict depends on where the decoder
    /// stands when quinn reports the end, so it must be reached only after the
    /// read-ahead has been drained into the decoder.
    #[tokio::test]
    async fn a_stream_that_ends_inside_a_frame_is_refused_after_the_frames_before_it() {
        let (mut wire, payload) = loopback::numbered_frames(40, 1000);
        let mut truncated = BytesMut::new();
        put_header(&mut truncated, DATA, 10);
        wire.extend_from_slice(&truncated);
        wire.extend_from_slice(b"abc");

        let mut upload = loopback::Upload::start(&wire).await;
        upload.send.finish().expect("finish the request stream");
        let mut reader = tunnel_reader(upload.take_recv());

        let mut delivered = Vec::new();
        let error = read_body(&mut reader, &mut delivered)
            .await
            .expect_err("a truncated frame must be refused");
        let Error::Protocol(violation) = error else {
            panic!("expected a protocol violation, got {error:?}");
        };
        assert_eq!(violation.code(), Code::H3_FRAME_ERROR);
        assert!(violation.is_connection_error());

        let mut expected = payload;
        expected.extend_from_slice(b"abc");
        assert_eq!(
            delivered, expected,
            "everything before the end, including the truncated frame's bytes, comes first"
        );
    }

    /// `try_next` hands out what the last read took and then stops, without
    /// reading quinn.
    ///
    /// It is a plain function, so it cannot wait. What this pins is that the
    /// awaited reads take several chunks each and `try_next` hands those out,
    /// and that the end of the stream, inside quinn the whole time, still comes
    /// from `next` after the last of them.
    #[tokio::test]
    async fn try_next_hands_out_the_read_ahead_and_never_the_end() {
        let (wire, payload) = loopback::numbered_frames(100, 1000);
        let mut upload = loopback::Upload::start(&wire).await;
        upload.send.finish().expect("finish the request stream");
        upload.settle().await;
        let mut reader = tunnel_reader(upload.take_recv());

        let mut delivered = Vec::new();
        let mut reads = 0;
        loop {
            match reader.next().await.expect("the body") {
                Some(Item::Data(data)) => delivered.extend_from_slice(&data),
                Some(other) => panic!("expected DATA, got {other:?}"),
                None => break,
            }
            reads += 1;
            while let Some(item) = reader.try_next().expect("the read-ahead decodes") {
                let Item::Data(data) = item else {
                    panic!("expected DATA, got {item:?}");
                };
                delivered.extend_from_slice(&data);
            }
        }

        assert_eq!(delivered, payload);
        assert!(
            reads < 100,
            "{reads} awaited reads for a body of 100 frames: `try_next` handed out \
             nothing the reads took"
        );
    }

    /// `stop` drops what the read-ahead holds and the rest of the chunk the
    /// decoder is working through, as quinn drops a stopped stream's unread
    /// bytes.
    #[tokio::test]
    async fn stopping_a_stream_empties_its_read_ahead() {
        let (wire, _) = loopback::numbered_frames(48, 1000);
        let mut upload = loopback::Upload::start(&wire).await;
        let mut reader = tunnel_reader(upload.take_recv());

        assert_matches!(
            reader.next().await.expect("the first item"),
            Some(Item::Data(_))
        );
        reader.stop(Code::H3_REQUEST_CANCELLED);

        // Nothing is left: not the read-ahead, and not the rest of the chunk
        // the first item was cut from.
        let mut left = 0;
        while let Some(item) = reader.try_next().expect("decodes") {
            let Item::Data(data) = item else {
                panic!("expected DATA, got {item:?}");
            };
            left += data.len();
        }
        assert_eq!(
            left, 0,
            "{left} bytes were still handed out after the stream was stopped"
        );
        assert!(
            reader.decoder.chunk.is_empty(),
            "the decoder keeps its chunk"
        );
        let ahead = reader.ahead.as_ref().expect("a tunnel reads ahead");
        assert!(ahead.slots.iter().all(Bytes::is_empty));
    }
}

/// A request stream over a real QUIC connection, for the tests of the readers
/// that sit on one.
///
/// Shared by the reader tests in this module and in `super::stream`. The decoder
/// tests feed bytes by hand; what these pin is how a reader takes bytes from
/// quinn, which only a live stream shows.
#[cfg(test)]
pub(in crate::h3) mod loopback {
    use std::time::Duration;

    use bytes::BytesMut;

    use crate::h3::frame::{DATA, put_header};

    /// How long any one step may take before the test fails rather than waits.
    pub(in crate::h3) const TIMEOUT: Duration = Duration::from_secs(5);

    /// One request stream, with the client's sending half and the server's
    /// receiving half.
    pub(in crate::h3) struct Upload {
        /// Kept so the connection stays open for the whole test.
        client: quinn::Connection,
        /// The server's side, for [`Self::settle`] and for the tests that build
        /// a connection handle on it.
        pub(in crate::h3) server: quinn::Connection,
        /// The client's sending half of the request stream.
        pub(in crate::h3) send: quinn::SendStream,
        /// The server's receiving half, until a test takes it.
        recv: Option<quinn::RecvStream>,
    }

    impl Upload {
        /// Opens a request stream, writes `wire` on it, and returns once every
        /// byte of it is inside quinn on the server.
        pub(in crate::h3) async fn start(wire: &[u8]) -> Self {
            let (client, server) =
                crate::quic::tests::loopback_pair(quinn::TransportConfig::default()).await;

            let (send, _) = client.open_bi().await.expect("open a request stream");
            // Above the barrier stream's default of 0, so quinn sends every
            // byte queued here before the barrier's byte: see `settle`.
            send.set_priority(1).expect("set the stream priority");
            let mut send = send;
            send.write_all(wire).await.expect("write the body");

            let (_, recv) = server.accept_bi().await.expect("accept the request stream");

            let upload = Self {
                client,
                server,
                send,
                recv: Some(recv),
            };
            upload.settle().await;
            upload
        }

        /// The server's receiving half of the request stream.
        pub(in crate::h3) fn take_recv(&mut self) -> quinn::RecvStream {
            self.recv.take().expect("the receiving half is taken once")
        }

        /// Returns once everything the client has queued so far has been
        /// processed by the server's connection.
        ///
        /// A byte on a fresh unidirectional stream is the barrier. quinn sends
        /// a reset ahead of stream data and the data of a higher-priority stream
        /// ahead of a lower one; the loopback neither reorders nor, at these
        /// sizes, drops; and the server's connection processes packets in the
        /// order they arrive. So when the barrier byte is read on the server,
        /// everything sent before it has been processed there.
        pub(in crate::h3) async fn settle(&self) {
            let mut barrier = self.client.open_uni().await.expect("open the barrier");
            barrier.write_all(&[0]).await.expect("write the barrier");
            barrier.finish().expect("finish the barrier");

            let mut seen = self.server.accept_uni().await.expect("accept the barrier");
            let byte = tokio::time::timeout(TIMEOUT, seen.read_to_end(1))
                .await
                .expect("the barrier must arrive")
                .expect("read the barrier");
            assert_eq!(byte, [0]);
        }
    }

    /// `count` DATA frames of `size` bytes each, as the wire carries them and as
    /// the payload they add up to.
    ///
    /// Every byte of frame `i` is `i`, so a piece out of order or a byte lost
    /// changes what is read.
    pub(in crate::h3) fn numbered_frames(count: u8, size: usize) -> (Vec<u8>, Vec<u8>) {
        let mut wire = BytesMut::new();
        let mut payload = Vec::new();
        for index in 0..count {
            let body = vec![index; size];
            put_header(&mut wire, DATA, crate::varint::len_u64(size));
            wire.extend_from_slice(&body);
            payload.extend_from_slice(&body);
        }
        (wire.to_vec(), payload)
    }
}
