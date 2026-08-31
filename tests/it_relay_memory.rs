//! What a trickle of small target reads costs the relay in heap blocks.
//!
//! The target → client pump hands each read on with `BytesMut::split`, which
//! does not copy: the bytes handed to quinn and the capacity kept for the next
//! read are two views of one heap block, and quinn holds its view until the
//! segment carrying it is acknowledged. So a read of any size pins the whole
//! block it came out of, and the only thing bounding unacknowledged data --
//! quinn's `send_window` -- counts bytes rather than blocks.
//!
//! This binary counts that directly, with a `#[global_allocator]` that tallies
//! every allocation of at least `RELAY_BUF_SIZE` made while a trickle is in
//! flight. It is the one property the pump's own tests cannot show, because it
//! is not on the wire: both shapes relay the same bytes.

mod common;

#[path = "common/alloc.rs"]
mod alloc;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use common::{open_tcp_tunnel, H3Client, TestServer, TIMEOUT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Counting allocator
// ---------------------------------------------------------------------------

/// The smallest allocation this counts, and `tunnel::tcp`'s read window.
///
/// Written out rather than imported: it is the size the relay used to pin per
/// read, so a test that took it from the code under test would follow that code
/// wherever it went.
const RELAY_BUF_SIZE: usize = 16 * 1024;

/// A pass-through allocator that tallies large allocations while armed.
///
/// Armed rather than always counting, because the process this runs in also
/// starts a QUIC server, a QUIC client and a TCP target, and none of that
/// setup is what the measurement is about. Reallocation counts too: a `Vec`
/// that doubles into this size range really did take a block of it.
struct Counting;

static ARMED: AtomicBool = AtomicBool::new(false);
static BIG_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

/// Records one allocation of `size` bytes, if it is large and counting is on.
fn record(size: usize) {
    if size >= RELAY_BUF_SIZE && ARMED.load(Ordering::Relaxed) {
        BIG_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

impl alloc::Record for Counting {
    fn allocated(size: usize) {
        record(size);
    }

    fn reallocated(_old: usize, new: usize) {
        record(new);
    }
}

#[global_allocator]
static GLOBAL: alloc::PassThrough<Counting> = alloc::PassThrough::new();

/// Runs `body` with the tally armed, and returns what it counted.
async fn while_counting<F: std::future::Future>(body: F) -> (F::Output, u64) {
    BIG_ALLOCATIONS.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let out = body.await;
    ARMED.store(false, Ordering::Relaxed);
    (out, BIG_ALLOCATIONS.load(Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
// The lock-step target
// ---------------------------------------------------------------------------

/// Payload of one trickled answer.
const TRICKLE_BYTES: usize = 100;

/// How many answers the target sends, one per go-ahead.
const TRICKLES: usize = 2000;

/// A TCP target that answers each go-ahead byte with one small write.
///
/// Lock-step rather than free-running: a write that is only made once the
/// client has taken the previous one is a write the proxy cannot coalesce with
/// its neighbour, so the pump makes exactly [`TRICKLES`] reads of
/// [`TRICKLE_BYTES`]. Left free-running, the kernel merges the trickle into
/// roughly a hundred reads on loopback and the measurement stops being about
/// small reads at all. `TCP_NODELAY` keeps each answer its own segment.
async fn spawn_lockstep_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target address");

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = socket.set_nodelay(true);

                let chunk = vec![0x5au8; TRICKLE_BYTES];
                let mut go = [0u8; 1];
                loop {
                    if socket.read_exact(&mut go).await.is_err() {
                        return;
                    }
                    if socket.write_all(&chunk).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    addr
}

// ---------------------------------------------------------------------------
// The measurement
// ---------------------------------------------------------------------------

/// A trickle of small reads must not cost a heap block each.
///
/// # Measured
///
/// On the dev host (macOS, debug build), 2000 answers of 100 bytes each:
///
/// | shape | allocations of >= 16 KiB while the trickle is in flight |
/// |---|---|
/// | `reserve(RELAY_BLOCK_SIZE)` only when under a window remains | 5 |
/// | `reserve(RELAY_BUF_SIZE)` every iteration (the shape this fixes) | 2000 |
///
/// Both numbers are the arithmetic rather than an approximation of it: a
/// 64 KiB block is abandoned once fewer than 16 KiB of it remain, so it carries
/// at least 48 KiB, and 2000 x 100 bytes needs `200000 / 49152` = 5 of them --
/// while a reserve per read is a block per read. The bound below is 200 to
/// leave room for a noisier host on both sides: forty times the working shape,
/// a tenth of the broken one.
#[tokio::test(flavor = "multi_thread")]
async fn a_trickle_of_small_reads_does_not_pin_a_block_each() {
    let server = TestServer::start().await;
    let target = spawn_lockstep_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    let (received, allocations) = while_counting(async {
        let mut received = 0usize;
        for step in 0..TRICKLES {
            stream
                .send_data(Bytes::from_static(b"g"))
                .await
                .unwrap_or_else(|error| panic!("go-ahead {step}: {error}"));

            let mut answer = 0usize;
            while answer < TRICKLE_BYTES {
                let chunk = tokio::time::timeout(TIMEOUT, stream.recv_data())
                    .await
                    .unwrap_or_else(|_| panic!("answer {step} did not arrive"))
                    .unwrap_or_else(|error| panic!("answer {step}: {error}"))
                    .unwrap_or_else(|| panic!("the tunnel ended at step {step}"));
                answer += chunk.len();
            }
            received += answer;
        }
        received
    })
    .await;

    assert_eq!(
        received,
        TRICKLES * TRICKLE_BYTES,
        "the trickle arrived truncated"
    );

    // One block per read would be about `TRICKLES`; one block per 48 KiB
    // relayed is about five. Anything in between is a relay that has started
    // pinning per read again.
    assert!(
        allocations < 200,
        "{allocations} allocations of >= {RELAY_BUF_SIZE} bytes for {TRICKLES} reads of \
         {TRICKLE_BYTES} bytes: the relay is pinning a block per read again"
    );
}
