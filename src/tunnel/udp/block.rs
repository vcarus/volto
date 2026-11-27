//! The receive block of a UDP session: the block each target packet lands in,
//! behind room for what it is sent with.
//!
//! [`PacketBlock`]'s fields are private to this file, so the session reaches
//! the packet in hand only through its methods.

use std::cell::RefCell;
use std::io::{IoSliceMut, Read};

use bytes::{Buf, Bytes, BytesMut};
use socket2::SockRef;
use tokio::net::UdpSocket;

use crate::capsule;
use crate::datagram::{self, MAX_UDP_PAYLOAD};
use crate::h3api;

/// Bytes of block each receive from the target is offered behind the room in
/// front of it.
///
/// Every packet the QUIC datagram path can carry fits in it: a QUIC datagram
/// travels inside one QUIC packet, and this server never lets a path's MTU
/// exceed `config::MAX_MTU_UPPER_BOUND`, 1472 bytes. A longer packet continues
/// into the receiving thread's overflow buffer and is copied out of it, which
/// costs one copy on a packet the datagram path drops anyway. On the capsule
/// path that copy is the only one the packet costs.
pub const RECV_WINDOW: usize = 2 * 1024;

/// The block a session receives its target's packets into.
///
/// # Why a block
///
/// Each packet is received behind room for what it will be sent with: its
/// datagram prefix, or on the capsule path a DATA frame header and a DATAGRAM
/// capsule header (`CAPSULE_ROOM`). What goes in front is written into that
/// room, and it is cut off the block with the packet and handed to quinn as
/// one chunk, with no copy and no allocation of its own. The pieces quinn
/// holds share the block with the part the session goes on receiving into,
/// so a block is freed only when the last piece cut from it has been sent or
/// evicted.
///
/// # The arithmetic
///
/// A block is replaced only once fewer than the room plus [`RECV_WINDOW`]
/// bytes are left in it, at most 11 + 2048 = 2059, so at least 14325 bytes of
/// it have been used by then. A packet that is sent uses the room plus its
/// length; one that is dropped uses none, because the next packet is received
/// over it. On the datagram path that is its encoded length, plus up to 9
/// bytes when the session left `CAPSULE_ROOM` in front of it. quinn counts
/// each queued datagram as its encoded length plus 32 bytes of bookkeeping
/// against `datagram_send_buffer_size`, 1 MiB by default, and sends and evicts
/// in queue order. So the blocks a session's queued pieces keep alive are at
/// most its counted bytes over 14325, plus the oldest block, partly released,
/// plus the one being received into: at most 16384 / 14325 = 1.15 times what
/// quinn counts, plus two blocks per session. On the capsule path a frame uses
/// at most 6 bytes of block more than it puts on the stream, and quinn bounds
/// what it holds of the stream by the connection's send window.
///
/// # What it costs at rest
///
/// Nothing until the target first sends: the block is allocated by the first
/// receive, which runs only once the socket is readable. From then on a
/// session holds one block across every wait, 16 KiB. The overflow buffer is
/// one per runtime thread rather than one per session, 63479 bytes, and is
/// allocated by the first receive of any length on that thread, because every
/// receive offers it.
pub const RECV_BLOCK_SIZE: usize = 16 * 1024;

thread_local! {
    /// Where a target packet longer than [`RECV_WINDOW`] continues.
    ///
    /// Together with the window it offers [`MAX_UDP_PAYLOAD`] bytes, so no
    /// packet is ever truncated: a UDP receive cuts a longer packet short
    /// without saying so. One per thread is enough because it is filled and
    /// emptied inside one synchronous call, [`PacketBlock::recv`], so no other
    /// session can see its contents.
    static OVERFLOW: RefCell<Box<[u8]>> =
        RefCell::new(vec![0; MAX_UDP_PAYLOAD - RECV_WINDOW].into_boxed_slice());
}

/// Room in front of a packet for what the capsule path sends it with: a DATA
/// frame header and a DATAGRAM capsule header, 5 + 6 = 11 bytes.
///
/// It also holds every datagram prefix, at most 9 bytes, so a session that
/// starts on the capsule path and moves to QUIC datagrams once the peer's
/// SETTINGS arrive keeps its block.
const CAPSULE_ROOM: usize = h3api::DATA_HEADER_ROOM + capsule::UDP_DATAGRAM_HEADER_MAX;

/// The receive side of a session's target socket: each packet lands behind
/// room for its prefix in a [`RECV_BLOCK_SIZE`] block.
///
/// The datagram prefix is the session's Quarter Stream ID and the Context ID
/// 0, so it is the same for every packet. It is written once per piece cut
/// from the block, at the end of the room: a receive that finds nothing, and
/// a packet that is dropped, leave the prefix and the window in place for the
/// next receive. A packet sent as a capsule has its headers written over the
/// prefix instead, and is cut off the block the same way.
///
/// A receive needs initialised bytes to write into, because a safe
/// `IoSliceMut` is a `&mut [u8]`. The block is zero-filled once, when it is
/// allocated or taken back, and the window of each packet is a part of it that
/// is already initialised. Nothing is filled per packet.
pub(super) struct PacketBlock {
    quarter_stream_id: u64,
    prefix_len: usize,
    /// Bytes in front of each packet: `prefix_len` on a session that only
    /// sends QUIC datagrams, [`CAPSULE_ROOM`] on one that may send capsules.
    room: usize,
    /// What is left of the current block, all of it initialised. A piece is
    /// cut off its front by [`Self::take`] or [`Self::take_capsule`].
    block: BytesMut,
    /// Whether `block` starts with the room and the prefix, so that a packet
    /// may land behind them in the next [`RECV_WINDOW`] bytes.
    prepared: bool,
    /// The packet in hand with its room and prefix, copied out, when it was
    /// longer than the window.
    spilled: Option<BytesMut>,
    /// The payload length of the packet in hand.
    len: usize,
}

impl PacketBlock {
    /// An empty receiver for `quarter_stream_id`'s session, for a session that
    /// only sends QUIC datagrams. Allocates nothing.
    pub(super) fn new(quarter_stream_id: u64) -> Self {
        let prefix_len = datagram::udp_payload_prefix_len(quarter_stream_id);
        Self::with_room(quarter_stream_id, prefix_len)
    }

    /// [`Self::new`] for a session that may send capsules.
    pub(super) fn with_capsule_room(quarter_stream_id: u64) -> Self {
        Self::with_room(quarter_stream_id, CAPSULE_ROOM)
    }

    fn with_room(quarter_stream_id: u64, room: usize) -> Self {
        let prefix_len = datagram::udp_payload_prefix_len(quarter_stream_id);
        Self {
            quarter_stream_id,
            prefix_len,
            room: room.max(prefix_len),
            block: BytesMut::new(),
            prepared: false,
            spilled: None,
            len: 0,
        }
    }

    /// Receives one packet from `socket` without waiting, returning its length.
    ///
    /// The `io::Result` is the socket's own: `WouldBlock` when nothing is
    /// queued, which is what lets tokio's `async_io` and `try_io` drive this,
    /// and every other error unchanged for
    /// [`is_per_packet_error`](super::is_per_packet_error). A failed receive
    /// changes nothing about the packet in hand.
    pub(super) fn recv(&mut self, socket: &UdpSocket) -> std::io::Result<usize> {
        if !self.prepared {
            self.prepare();
        }

        let room = self.room;
        let window = &mut self.block[..room + RECV_WINDOW];
        let (len, spilled) = OVERFLOW.with_borrow_mut(|overflow| {
            let len = {
                let socket = SockRef::from(socket);
                let mut parts = [
                    IoSliceMut::new(&mut window[room..]),
                    IoSliceMut::new(overflow),
                ];
                (&*socket).read_vectored(&mut parts)?
            };
            // Copied out before the call returns, so the overflow is free for
            // the next session on this thread.
            let spilled = (len > RECV_WINDOW).then(|| {
                let mut whole = BytesMut::with_capacity(room + len);
                whole.extend_from_slice(window);
                whole.extend_from_slice(&overflow[..len - RECV_WINDOW]);
                whole
            });
            Ok::<_, std::io::Error>((len, spilled))
        })?;

        self.len = len;
        self.spilled = spilled;
        Ok(len)
    }

    /// Writes the prefix at the end of the room at the front of what is left
    /// of the block, replacing the block first if the room and the window no
    /// longer fit.
    ///
    /// Called only while no prefix is in place. The block is cleared before the
    /// `reserve`, so no bytes of the old one are copied. A `reserve` on an
    /// empty buffer whose pieces have all been released takes the whole block
    /// back without allocating; one whose pieces quinn still holds allocates a
    /// fresh block. Either way the `resize` zero-fills it, which is the only
    /// fill a block gets.
    fn prepare(&mut self) {
        debug_assert!(!self.prepared, "the prefix is written once");
        if self.block.len() < self.room + RECV_WINDOW {
            self.block.clear();
            self.block.reserve(RECV_BLOCK_SIZE);
            self.block.resize(RECV_BLOCK_SIZE, 0);
        }
        datagram::put_udp_payload_prefix(
            &mut &mut self.block[self.room - self.prefix_len..self.room],
            self.quarter_stream_id,
        );
        self.prepared = true;
    }

    /// The length of the packet in hand as an HTTP Datagram.
    pub(super) fn encoded_len(&self) -> usize {
        self.prefix_len + self.len
    }

    /// The packet in hand, without its prefix.
    fn payload(&self) -> &[u8] {
        self.spilled.as_ref().map_or_else(
            || &self.block[self.room..self.room + self.len],
            |whole| &whole[self.room..],
        )
    }

    /// The packet in hand with the room in front of it, cut off the block, or
    /// the copy of it when it was longer than the window.
    ///
    /// Called at most once per packet, and only for a packet that is sent: the
    /// next receive writes a fresh prefix behind it. A spilled packet leaves
    /// the block as it was, prefix and all.
    fn cut(&mut self) -> BytesMut {
        if let Some(whole) = self.spilled.take() {
            return whole;
        }

        self.prepared = false;
        self.block.split_to(self.room + self.len)
    }

    /// The packet in hand as an HTTP Datagram, cut off the block.
    ///
    /// Byte for byte what [`datagram::encode_udp_payload`] makes of
    /// [`Self::payload`].
    pub(super) fn take(&mut self) -> Bytes {
        let skip = self.room - self.prefix_len;
        let mut piece = self.cut();
        piece.advance(skip);
        piece.freeze()
    }

    /// The packet in hand as the block [`Writer::send_data_in_place`](h3api::Writer::send_data_in_place) takes:
    /// [`h3api::DATA_HEADER_ROOM`] bytes of room, then a DATAGRAM capsule with
    /// Context ID 0 carrying the packet. The capsule header is written in
    /// front of the packet, which is not copied.
    ///
    /// A session whose block has no capsule room never sends a capsule: see
    /// [`Session::run`](super::Session::run). Should one ask, the frame is built in a buffer of its
    /// own, which costs a copy and not the session.
    pub(super) fn take_capsule(&mut self) -> BytesMut {
        let header = capsule::datagram_header_len(datagram::CONTEXT_ID_UDP_PAYLOAD, self.len);
        let front = h3api::DATA_HEADER_ROOM + header;

        let Some(skip) = self.room.checked_sub(front) else {
            let mut frame = BytesMut::zeroed(front);
            capsule::put_datagram_header(
                &mut frame[h3api::DATA_HEADER_ROOM..],
                datagram::CONTEXT_ID_UDP_PAYLOAD,
                self.len,
            );
            frame.extend_from_slice(self.payload());
            return frame;
        };

        let room = self.room;
        let len = self.len;
        let mut piece = self.cut();
        capsule::put_datagram_header(
            &mut piece[room - header..room],
            datagram::CONTEXT_ID_UDP_PAYLOAD,
            len,
        );
        piece.advance(skip);
        piece
    }

    /// Whether the room and the prefix are in place for the next receive.
    #[cfg(test)]
    pub(super) fn prepared(&self) -> bool {
        self.prepared
    }
}

/// Puts `payload` in `packets` as a receive would, without a socket.
#[cfg(test)]
pub(super) fn landed(packets: &mut PacketBlock, payload: &[u8]) {
    if !packets.prepared {
        packets.prepare();
    }
    let prefix_len = packets.prefix_len;
    packets.block[prefix_len..prefix_len + payload.len()].copy_from_slice(payload);
    packets.len = payload.len();
    packets.spilled = None;
}

#[cfg(test)]
mod tests {
    use tokio::io::Interest;

    use super::*;

    // -----------------------------------------------------------------------
    // The receive block
    // -----------------------------------------------------------------------
    //
    // A pair of connected loopback sockets stands in for a session's target
    // socket and the target. The socket is driven the way the session drives
    // it, through `async_io` with the interest `UdpSocket::recv` uses.

    /// A target socket and the socket of the target it is connected to.
    async fn socket_pair() -> (UdpSocket, UdpSocket) {
        let ours = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        ours.connect(target.local_addr().expect("address"))
            .await
            .expect("connect");
        target
            .connect(ours.local_addr().expect("address"))
            .await
            .expect("connect");
        (ours, target)
    }

    /// Sends `payload` from the target and receives it into `packets`.
    async fn deliver(
        packets: &mut PacketBlock,
        ours: &UdpSocket,
        target: &UdpSocket,
        payload: &[u8],
    ) {
        target.send(payload).await.expect("send");
        let len = ours
            .async_io(Interest::READABLE | Interest::ERROR, || packets.recv(ours))
            .await
            .expect("receive");
        assert_eq!(len, payload.len(), "the packet arrived whole");
        assert_eq!(packets.payload(), payload);
    }

    /// Payload bytes that differ from packet to packet and within one.
    fn payload(seed: usize, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from((seed * 31 + i) % 251).expect("below 251"))
            .collect()
    }

    /// Two packets in a row are cut from one block, one right behind the
    /// other, and each is the datagram `encode_udp_payload` would have built.
    ///
    /// The Quarter Stream IDs are the edges of the one- and two-byte varints,
    /// so the prefix is written at both lengths a real session uses.
    #[tokio::test]
    async fn consecutive_packets_come_out_of_one_block() {
        for quarter_stream_id in [0, 0x3f, 0x40, 0x3fff] {
            let (ours, target) = socket_pair().await;
            let mut packets = PacketBlock::new(quarter_stream_id);

            let first = payload(1, 100);
            deliver(&mut packets, &ours, &target, &first).await;
            let first_piece = packets.take();

            let second = payload(2, 1200);
            deliver(&mut packets, &ours, &target, &second).await;
            let second_piece = packets.take();

            assert_eq!(
                first_piece,
                datagram::encode_udp_payload(quarter_stream_id, &first)
            );
            assert_eq!(
                second_piece,
                datagram::encode_udp_payload(quarter_stream_id, &second)
            );
            assert!(
                std::ptr::eq(first_piece.as_ptr_range().end, second_piece.as_ptr()),
                "the second datagram of quarter stream id {quarter_stream_id} was not cut \
                 from the block right behind the first"
            );
        }
    }

    /// A packet that is dropped gives its bytes to the next one.
    ///
    /// The oversize drop never cuts the packet off the block, so the next
    /// packet is received over it rather than behind it.
    #[tokio::test]
    async fn a_dropped_packet_leaves_its_bytes_to_the_next() {
        let (ours, target) = socket_pair().await;
        let mut packets = PacketBlock::new(9);

        deliver(&mut packets, &ours, &target, &payload(1, 1400)).await;
        let dropped_at = packets.payload().as_ptr();

        let kept = payload(2, 64);
        deliver(&mut packets, &ours, &target, &kept).await;
        assert!(
            std::ptr::eq(packets.payload().as_ptr(), dropped_at),
            "the packet after a drop landed somewhere other than where the drop was"
        );
        assert_eq!(packets.take(), datagram::encode_udp_payload(9, &kept));
    }

    /// A receive that finds nothing leaves the prefix in place, and the next
    /// receive does not write it again.
    ///
    /// The session's wait can end in the socket being ready with nothing to
    /// read, or in another source winning the `select!`; either way the
    /// prepared window is kept, and a second prefix in front of it would put
    /// the payload two bytes late.
    #[tokio::test]
    async fn a_receive_that_finds_nothing_keeps_one_prefix() {
        let (ours, target) = socket_pair().await;
        let mut packets = PacketBlock::new(0x40);

        let nothing = packets.recv(&ours).expect_err("nothing was sent yet");
        assert_eq!(nothing.kind(), std::io::ErrorKind::WouldBlock);

        let sent = payload(3, 500);
        deliver(&mut packets, &ours, &target, &sent).await;
        assert_eq!(packets.take(), datagram::encode_udp_payload(0x40, &sent));
    }

    /// The window a packet is received into is not filled again: only the
    /// prefix is written in front of it.
    ///
    /// The block is zero-filled once, when it is allocated. After the first
    /// packet is cut off, the test marks the rest of the block, and the window
    /// of the second packet must still carry the mark behind the packet. A fill
    /// per packet, of the window or of anything around it, overwrites the mark.
    #[tokio::test]
    async fn a_window_is_not_filled_per_packet() {
        const MARK: u8 = 0xa5;
        let (ours, target) = socket_pair().await;
        let mut packets = PacketBlock::new(0x40);

        let first = payload(5, 100);
        deliver(&mut packets, &ours, &target, &first).await;
        let first_piece = packets.take();
        packets.block.fill(MARK);

        let second = payload(6, 64);
        deliver(&mut packets, &ours, &target, &second).await;
        let prefix_len = packets.prefix_len;
        let behind = &packets.block[prefix_len + second.len()..prefix_len + RECV_WINDOW];
        assert!(
            behind.iter().all(|&byte| byte == MARK),
            "the window behind the second packet was written before the receive"
        );
        let second_piece = packets.take();

        assert_eq!(second_piece, datagram::encode_udp_payload(0x40, &second));
        assert!(
            std::ptr::eq(first_piece.as_ptr_range().end, second_piece.as_ptr()),
            "the second packet was not received into the same block"
        );
    }

    /// A packet longer than the window arrives whole, through the overflow, and
    /// the packet after it is back in the block.
    ///
    /// 8000 bytes stays under the 9216-byte datagram limit macOS applies by
    /// default, so the test runs on both hosts.
    #[tokio::test]
    async fn a_packet_longer_than_the_window_arrives_whole() {
        let (ours, target) = socket_pair().await;
        let mut packets = PacketBlock::new(5);

        for len in [RECV_WINDOW, RECV_WINDOW + 1, 8000] {
            let long = payload(len, len);
            deliver(&mut packets, &ours, &target, &long).await;
            assert_eq!(packets.encoded_len(), 2 + len);
            assert_eq!(packets.take(), datagram::encode_udp_payload(5, &long));
        }

        let short = payload(4, 300);
        deliver(&mut packets, &ours, &target, &short).await;
        assert!(packets.spilled.is_none(), "a short packet is not copied");
        assert_eq!(packets.take(), datagram::encode_udp_payload(5, &short));
    }

    /// A packet sent as a capsule is cut off the block with both headers
    /// written in front of it, and is not copied.
    ///
    /// The frame is what `Writer::send_data_in_place` takes: the DATA header
    /// room, then the capsule `capsule::encode_datagram` would build. The
    /// lengths are the edges of the one- and two-byte Capsule Length, and one
    /// packet longer than the window, which is copied once on its way in and
    /// not again. A QUIC datagram after them comes out of the same block.
    #[tokio::test]
    async fn a_capsule_is_cut_from_the_block() {
        let (ours, target) = socket_pair().await;
        let mut packets = PacketBlock::with_capsule_room(0x40);

        for len in [1, 62, 63, 1200, 8000] {
            let sent = payload(len, len);
            deliver(&mut packets, &ours, &target, &sent).await;
            let at = packets.payload().as_ptr();
            let spilled = packets.spilled.is_some();

            let frame = packets.take_capsule();
            let header = capsule::datagram_header_len(datagram::CONTEXT_ID_UDP_PAYLOAD, len);
            assert_eq!(
                &frame[h3api::DATA_HEADER_ROOM..],
                &capsule::encode_datagram(datagram::CONTEXT_ID_UDP_PAYLOAD, &sent)[..],
                "{len}"
            );
            assert_eq!(spilled, len > RECV_WINDOW, "{len}");
            assert!(
                std::ptr::eq(frame[h3api::DATA_HEADER_ROOM + header..].as_ptr(), at),
                "the packet of {len} bytes was copied into the frame"
            );
        }

        let last = packets.block.as_ptr();
        let next = payload(9, 100);
        deliver(&mut packets, &ours, &target, &next).await;
        let piece = packets.take();
        assert_eq!(piece, datagram::encode_udp_payload(0x40, &next));
        assert!(
            std::ptr::eq(
                piece.as_ptr(),
                last.wrapping_add(CAPSULE_ROOM - packets.prefix_len)
            ),
            "the datagram after the capsules did not come out of the same block"
        );
    }

    /// A block with room for the datagram prefix only still sends a capsule
    /// correctly, from a copy, and keeps the packet's bytes for the next one.
    ///
    /// No session asks this of such a block; see `Session::run`.
    #[tokio::test]
    async fn a_capsule_from_a_block_without_room_is_copied() {
        let (ours, target) = socket_pair().await;
        let mut packets = PacketBlock::new(0x40);

        let sent = payload(3, 300);
        deliver(&mut packets, &ours, &target, &sent).await;
        let at = packets.payload().as_ptr();

        let frame = packets.take_capsule();
        assert_eq!(
            &frame[h3api::DATA_HEADER_ROOM..],
            &capsule::encode_datagram(datagram::CONTEXT_ID_UDP_PAYLOAD, &sent)[..]
        );

        let next = payload(4, 100);
        deliver(&mut packets, &ours, &target, &next).await;
        assert!(
            std::ptr::eq(packets.payload().as_ptr(), at),
            "the packet after the copied one landed somewhere other than where it was"
        );
    }

    /// The window and the overflow together hold the largest UDP payload, and
    /// the window holds every packet the datagram path can carry.
    #[test]
    fn a_receive_is_offered_a_whole_udp_payload() {
        let overflow = OVERFLOW.with_borrow(|overflow| overflow.len());
        assert_eq!(RECV_WINDOW + overflow, MAX_UDP_PAYLOAD);
        assert!(RECV_WINDOW >= usize::from(crate::config::MAX_MTU_UPPER_BOUND));

        let mut packets = PacketBlock::new(datagram::MAX_QUARTER_STREAM_ID);
        packets.prepare();
        assert_eq!(packets.block.len(), RECV_BLOCK_SIZE);
        assert!(packets.block.capacity() <= RECV_BLOCK_SIZE);
        assert!(packets.block.len() >= 9 + RECV_WINDOW);
    }

    /// Small packets fill a block before it is replaced, so what a session
    /// pins is bounded by the bytes it sent rather than by how small its
    /// packets are.
    ///
    /// Every piece is held for the whole run, the way quinn holds a queued
    /// datagram, so a `reserve` cannot quietly take a block back. Blocks are
    /// counted by the pointer jumping.
    #[tokio::test]
    async fn a_block_carries_what_its_arithmetic_says() {
        const PACKET: usize = 100;
        const PACKETS: usize = 2000;
        /// What a block must carry before it may be replaced: 16384 less the
        /// largest prefix and the window. Spelled out rather than derived, so
        /// that a change to either constant has to change this as well.
        const CARRIED: usize = 14327;

        let (ours, target) = socket_pair().await;
        let mut packets = PacketBlock::new(1);
        let mut held = Vec::with_capacity(PACKETS);
        let mut blocks = 0usize;
        let mut next = std::ptr::null();

        for seed in 0..PACKETS {
            deliver(&mut packets, &ours, &target, &payload(seed, PACKET)).await;
            let piece = packets.take();
            if !std::ptr::eq(piece.as_ptr(), next) {
                blocks += 1;
            }
            next = piece.as_ptr_range().end;
            held.push(piece);
            assert!(
                packets.block.capacity() <= RECV_BLOCK_SIZE,
                "packet {seed}: a replaced block is larger than {RECV_BLOCK_SIZE} bytes"
            );
        }

        assert_eq!(RECV_BLOCK_SIZE - 9 - RECV_WINDOW, CARRIED);
        let used = PACKETS * (2 + PACKET);
        let ceiling = used / CARRIED + 1;
        assert!(
            blocks <= ceiling,
            "{PACKETS} packets of {PACKET} bytes used {used} bytes of block and took \
             {blocks} blocks, over the {ceiling} that carrying {CARRIED} bytes each allows"
        );
    }
}
