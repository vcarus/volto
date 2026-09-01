//! The resolver as the adversary: a name that never resolves, in bulk.
//!
//! `tokio::net::lookup_host` hands a name to `getaddrinfo` on the runtime's
//! blocking pool, and that call cannot be cancelled. `[limits] connect_timeout`
//! bounds the *answer* a client gets, not the thread the lookup is on: the
//! thread stays in the resolver until the stub gives up on its own, tens of
//! seconds later. The pool is process-wide, so without a budget one client's
//! black-holed names park threads that every other connection's lookups need —
//! including names that never needed the resolver at all (D90).
//!
//! # How the fault is injected
//!
//! A UDP socket bound to `127.0.0.1:53` that reads nothing and answers nothing,
//! plus an `/etc/resolv.conf` naming it with a [`RESOLVER_HANG`]-second timeout.
//! A bound port is the point: with nothing listening the kernel answers ICMP
//! port-unreachable and the stub fails fast, which is the opposite of the fault
//! under test. Both are process- and host-wide, so this binary holds exactly one
//! test, is `#[ignore]`d, and refuses to run outside a container it may modify —
//! see [`BlackholeResolver`]. The run takes about [`RESOLVER_HANG`] seconds.
//!
//! ```sh
//! docker run --rm -v "$PWD":/w -w /w -e CARGO_TARGET_DIR=/tmp/target rust:1 \
//!     cargo test --test it_resolver_pool -- --ignored --nocapture
//! ```
//!
//! # What is pinned
//!
//! * **A connection always has a lookup slot.** Four connections park every
//!   permit the shared allowance has ([`SHARED_LOOKUPS`] of them, each connection
//!   taking its reserved one plus [`BURST_LOOKUPS`]), and a connection that
//!   arrives after that still opens a tunnel — and carries bytes through it.
//! * **Serial at worst means all of them, not the first of them.** The same
//!   victim's [`CONCURRENT_VICTIM_LOOKUPS`] simultaneous lookups all resolve,
//!   chaining through the one reserved slot as each frees it. A budget that
//!   only checked the slot on arrival would answer the first and leave the
//!   rest to their `connect_timeout` beside an idle slot.
//! * **The name it opens needs no resolver.** The victim's target resolves from
//!   `/etc/hosts`, so a refusal could only ever be about the *thread*, never
//!   about DNS. That is what makes this a test of the budget rather than of the
//!   resolver.
//! * **A slot is held by the thread, not by the request.** [`WAVES`] of the same
//!   flood are sent, one per `connect_timeout`, which is the whole attack: a
//!   budget that released its permit when the client was answered would let each
//!   wave park another [`SHARED_LOOKUPS`] threads on top of the last, and three
//!   waves are more than the pool has. The waves after the first must find their
//!   own connection's slots still held.
//! * **The refusals are still refusals.** Every parked request is answered
//!   `504 dns_timeout` on its `connect_timeout`, unchanged by the budget: what
//!   the fix bounds is the resource, not the answer.
//!
//! The other half of the design — that the pool is sized to have a thread for
//! every slot the budget can hand out — is arithmetic, and is asserted in
//! `src/net.rs`'s own tests.

#![cfg(target_os = "linux")]

mod common;

use std::time::{Duration, Instant};

use common::{
    ALLOW_PRIVATE, H3Client, TestServer, connect_request, echoes, respond_to, spawn_echo_target,
};
use volto::h3api::Status;
use volto::net::{BURST_LOOKUPS, SHARED_LOOKUPS, blocking_pool_size};

/// Seconds the injected resolver makes one lookup take.
///
/// Long enough that every assertion below runs while the threads are still
/// parked, short enough that the binary finishes. A stock `resolv.conf` is
/// `timeout:5 attempts:2`, so this is the same order as the real thing.
const RESOLVER_HANG: u64 = 15;

/// The proxy's own resolution budget, in seconds.
const CONNECT_TIMEOUT: u64 = 1;

/// Slack allowed for a wave to reach the server and be answered.
const PACING: Duration = Duration::from_millis(500);

/// Connections the attacker opens, and lookups it parks on each.
///
/// One connection can hold its reserved slot plus [`BURST_LOOKUPS`] of the
/// shared allowance, so this is what it takes to leave the allowance empty.
const HOSTILE_CONNECTIONS: usize = SHARED_LOOKUPS.div_ceil(BURST_LOOKUPS);
const HOSTILE_LOOKUPS: usize = BURST_LOOKUPS + 1;

/// Floods sent, one per `connect_timeout`.
///
/// Sized against the pool below: [`WAVES`] x the lookups one flood parks is
/// comfortably more threads than the runtime has, so a budget that let a
/// timed-out request give its slot back would have nothing left for the victim
/// by the last wave.
const WAVES: usize = 3;

/// Connections this run's server allows, and the number the pool is sized for.
const MAX_CONNECTIONS: u32 = 8;

/// Blocking threads this run's pool has.
///
/// Sized exactly as the binary sizes it (D90), for the `max_connections` this
/// run's server is given: the point of the test is that the budget keeps the
/// pool inside its own arithmetic, so borrowing a different number here would
/// be testing a server nobody runs.
const POOL: usize = blocking_pool_size(MAX_CONNECTIONS);

/// Lookups the victim sends at once, all of which must resolve.
///
/// More than its reserved slot admits at a time, which is the point: with the
/// shared allowance parked they can only get through by taking that one slot
/// in turn.
const CONCURRENT_VICTIM_LOOKUPS: usize = 8;

/// How long the victim's tunnel may take to open while the fault lasts.
///
/// Its lookup is a `/etc/hosts` hit and its slot is reserved, so this is three
/// orders of magnitude over what it costs — but well under [`RESOLVER_HANG`],
/// which is what a failure of the guarantee would cost.
const VICTIM_BOUND: Duration = Duration::from_secs(3);

/// The stub resolver, pointed at a socket that never answers.
///
/// The original `/etc/resolv.conf` is restored by `Drop` rather than by a line
/// at the end of the test: a panic in the middle would otherwise leave the host
/// unable to resolve anything at all.
struct BlackholeResolver {
    saved: Vec<u8>,
    _socket: std::net::UdpSocket,
}

impl BlackholeResolver {
    /// Installs it, or reports why this host is not one to install it on.
    fn install() -> Result<Self, String> {
        let saved = std::fs::read("/etc/resolv.conf")
            .map_err(|error| format!("/etc/resolv.conf is unreadable: {error}"))?;

        let socket = std::net::UdpSocket::bind("127.0.0.1:53")
            .map_err(|error| format!("127.0.0.1:53 is not bindable: {error}"))?;

        std::fs::write(
            "/etc/resolv.conf",
            format!("nameserver 127.0.0.1\noptions timeout:{RESOLVER_HANG} attempts:1 ndots:1\n"),
        )
        .map_err(|error| format!("/etc/resolv.conf is not writable: {error}"))?;

        Ok(Self {
            saved,
            _socket: socket,
        })
    }
}

impl Drop for BlackholeResolver {
    fn drop(&mut self) {
        let _ = std::fs::write("/etc/resolv.conf", &self.saved);
    }
}

/// A name the injected resolver will be asked about and never answer.
fn black_hole(nth: usize) -> String {
    format!("hang-{nth}.example:443")
}

#[test]
#[ignore = "rewrites /etc/resolv.conf and binds 127.0.0.1:53; run it in a container"]
fn a_connection_keeps_its_lookup_slot_while_the_pool_is_parked() {
    let resolver = match BlackholeResolver::install() {
        Ok(resolver) => resolver,
        Err(reason) => {
            // Not a failure: the fault is host-wide, so the only sane place to
            // inject it is a container, and saying so beats a panic that reads
            // like a bug in the server.
            eprintln!("skipped: {reason}");
            return;
        }
    };

    // Built by hand for the same reason the binary does it (D90): the pool has
    // to have a thread for every slot the budget can hand out, and that is a
    // number the configuration decides.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .max_blocking_threads(POOL)
        .enable_all()
        .build()
        .expect("runtime");

    runtime.block_on(async {
        // The self-check that makes every assertion below mean something: an
        // injection that did not take would leave the server resolving every
        // name happily, and the run would pass while testing nothing.
        let hung = tokio::time::timeout(
            Duration::from_secs(2),
            volto::net::resolve("self-check.example", 443),
        )
        .await;
        assert!(hung.is_err(), "the injected resolver answered: {hung:?}");

        let from_hosts = volto::net::resolve("localhost", 80)
            .await
            .expect("localhost resolves from /etc/hosts, not from the resolver");
        assert!(
            from_hosts.iter().all(|address| address.ip().is_loopback()),
            "{from_hosts:?}"
        );

        let server = TestServer::start_with(&format!(
            "[limits]\nconnect_timeout = {CONNECT_TIMEOUT}\n\
             max_connections = {MAX_CONNECTIONS}\n{ALLOW_PRIVATE}"
        ))
        .await;
        let echo = spawn_echo_target().await;
        // A name rather than a literal: a literal never reaches the resolver, so
        // it would prove nothing about the pool. This one resolves without a
        // query, which is what makes a refusal of it a refusal about threads.
        let target = format!("localhost:{}", echo.port());

        // Every permit the shared allowance has, held by clients that will not
        // get an answer for RESOLVER_HANG seconds -- and then the same flood
        // again, once per `connect_timeout`, for as long as the attack lasts.
        let mut hostile: Vec<(H3Client, Vec<_>)> = Vec::new();
        for _ in 0..HOSTILE_CONNECTIONS {
            hostile.push((H3Client::connect(&server).await, Vec::new()));
        }

        let mut name = 0;
        for wave in 0..WAVES {
            for (client, streams) in &mut hostile {
                for _ in 0..HOSTILE_LOOKUPS {
                    let request = connect_request(&black_hole(name));
                    name += 1;
                    streams.push(
                        client
                            .send
                            .send_request(request)
                            .await
                            .expect("the request stream opens"),
                    );
                }
            }

            // Long enough for the wave to have been refused on its
            // `connect_timeout`, which is the moment a budget tied to the
            // request rather than to the thread would hand its slots back.
            if wave + 1 < WAVES {
                tokio::time::sleep(Duration::from_secs(CONNECT_TIMEOUT) + PACING).await;
            }
        }

        // The requests are sent; give the server the moment it needs to take a
        // slot for each of them before asking whether any are left.
        tokio::time::sleep(PACING).await;

        // The guarantee, from a connection that arrived after the flood.
        let mut victim = H3Client::connect(&server).await;
        let start = Instant::now();
        let opened = tokio::time::timeout(
            VICTIM_BOUND,
            respond_to(&mut victim, connect_request(&target)),
        )
        .await
        .unwrap_or_else(|_| {
            panic!("the victim's tunnel to {target} did not open within {VICTIM_BOUND:?}")
        });
        assert_eq!(
            opened.status,
            Status::OK,
            "a name that needs no resolver was refused while the pool was parked: {:?}",
            opened
                .fields
                .get("proxy-status")
                .and_then(|value| value.to_str())
        );
        println!("victim tunnel opened in {:?}", start.elapsed());

        // And it is a tunnel, not just a 200.
        let (_, mut stream) = common::send_and_respond(&mut victim, connect_request(&target)).await;
        echoes(&mut stream, b"still working").await;

        // Serial at worst, from the same victim: every one of these parks
        // behind the exhausted shared allowance, and every one of them must
        // still open by chaining through the reserved slot.
        let mut concurrent = Vec::new();
        for _ in 0..CONCURRENT_VICTIM_LOOKUPS {
            concurrent.push(
                victim
                    .send
                    .send_request(connect_request(&target))
                    .await
                    .expect("the request stream opens"),
            );
        }
        for (nth, stream) in concurrent.iter_mut().enumerate() {
            let response = tokio::time::timeout(VICTIM_BOUND, stream.recv_response())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "concurrent victim lookup {nth} was not answered within {VICTIM_BOUND:?}"
                    )
                })
                .expect("a response");

            assert_eq!(
                response.status,
                Status::OK,
                "concurrent victim lookup {nth} was refused while the pool was parked: {:?}",
                response
                    .fields
                    .get("proxy-status")
                    .and_then(|value| value.to_str())
            );
        }

        // The refusals are unchanged: what the budget bounds is the thread, not
        // the answer the client gets.
        for (index, (_client, streams)) in hostile.iter_mut().enumerate() {
            for (nth, stream) in streams.iter_mut().enumerate() {
                let response = tokio::time::timeout(
                    Duration::from_secs(RESOLVER_HANG * WAVES as u64),
                    stream.recv_response(),
                )
                .await
                .unwrap_or_else(|_| panic!("hostile request {index}/{nth} was never answered"))
                .expect("a response");

                assert_eq!(response.status, Status::GATEWAY_TIMEOUT);
                assert_eq!(
                    response
                        .fields
                        .get("proxy-status")
                        .and_then(|value| value.to_str()),
                    Some("volto; error=dns_timeout"),
                );
            }
        }
    });

    drop(resolver);
}
