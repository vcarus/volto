//! Volto, a MASQUE proxy server.
//!
//! Volto terminates HTTP/3 over QUIC and proxies client traffic:
//!
//! * **TCP** via classic CONNECT tunnels (RFC 9114 §4.4).
//! * **UDP** via CONNECT-UDP (RFC 9298) + HTTP Datagrams (RFC 9297).
//!
//! # Module layout
//!
//! * [`alloc`]: the global allocator the binary installs, mimalloc on musl.
//! * [`auth`]: HTTP Basic authentication of CONNECT requests.
//! * [`config`]: TOML configuration and its validation.
//! * [`policy`]: the destination ACL: which targets may be reached.
//! * [`tls`]: certificate/key loading and the server's TLS, volto's own quinn
//!   provider on AWS-LC's libssl with optional ECH.
//! * [`gate`]: the SNI gate: which handshakes reach quinn at all.
//! * [`hello`]: the ClientHello parser the gate, the TLS provider and the
//!   tests share.
//! * [`quic`]: the QUIC endpoint, transport parameters and the accept loop.
//! * [`congestion`]: the default `bbr` controller, quinn's BBR with its window
//!   held to 1.25 times the bandwidth-delay product it measures.
//! * [`shutdown`]: the graceful-shutdown signal shared by endpoint and connections.
//! * [`h3`]: HTTP/3 (RFC 9114) for a proxy: framing, QPACK, the control
//!   stream, request streams, and the routing of inbound HTTP Datagrams to the
//!   stream each one names.
//! * [`h3api`]: the facade over that layer, and the only HTTP/3 vocabulary
//!   the rest of the crate uses.
//! * [`conn`]: per-connection driving and request dispatch.
//! * [`capsule`]: the Capsule Protocol (RFC 9297 §3) incremental decoder.
//! * [`datagram`]: HTTP Datagram payload coding (RFC 9297) and QUIC varints.
//! * [`net`]: explicit name resolution and UDP socket setup.
//! * [`logfmt`]: how a log field spells a value, and the bounds, escaping and
//!   sampling applied to what a peer can put in a log line.
//! * [`tunnel`]: request routing, the per-connection context and the tunnels.
//!
//! # Security status
//!
//! Requests are authenticated ([`auth`]) and destinations are filtered
//! ([`policy`]), but both are **configuration-dependent**: an empty
//! `[auth].users` is an open proxy, and the `[security]` defaults leave the SNI
//! [`gate`] off, because turning it on without knowing the name is a server
//! nobody can reach. The [`config`] module doc lists the defaults.

// No `unsafe` in the server outside one module. The raw socket and resource
// calls it needs go through the safe wrappers of rustix and socket2: rustix
// carries `getrlimit` for the startup fd check and `IP_MTU_DISCOVER` for the DF
// bit, and socket2 carries `SO_RCVBUF` and `SO_SNDBUF` on the endpoint socket
// and the vectored read of a target socket in `tunnel::udp`.
//
// The exception is `tls::awslc`, the binding to AWS-LC's libssl that runs the
// server's TLS (D115). rustls has no server-side ECH, and no safe Rust crate
// wraps libssl's QUIC and ECH interfaces, so the provider calls them through
// `aws-lc-sys` and carries `#[allow(unsafe_code)]`, which `tls.rs` declares on
// that one module. That is why this is `deny` and not `forbid`: `forbid`
// cannot be lifted for one module. Any other `allow(unsafe_code)` in `src/` is
// a change to this paragraph, and `tests/it_release_assets.rs` holds the crate
// to it. `main.rs` keeps `forbid`, since the binary calls the library only.
#![deny(unsafe_code)]
// Every public item carries a doc comment, and this lint enforces it.
// `cargo doc` is published for this crate, so a `pub` item without a doc comment
// leaves the published page incomplete. `warn` here rather than `deny`,
// because CI already runs clippy with `-D warnings` and rustdoc with
// `RUSTDOCFLAGS=-D warnings`, so the lint is an error in CI and a warning
// while somebody is mid-edit. Deliberately not `[lints]` in `Cargo.toml`:
// that would reach `tests/` and `fuzz/`, whose items are scaffolding rather
// than a published surface.
#![warn(missing_docs)]
#![doc(html_logo_url = "https://vcarus.github.io/volto/assets/logo.png")]
#![doc(html_favicon_url = "https://vcarus.github.io/volto/theme/favicon.png")]

pub mod alloc;
pub mod auth;
pub mod capsule;
pub mod config;
pub mod congestion;
pub mod conn;
pub mod datagram;
pub mod gate;
pub mod h3;
pub mod h3api;
pub mod hello;
pub mod logfmt;
pub mod net;
pub mod policy;
pub mod quic;
pub mod shutdown;
pub mod tls;
pub mod tunnel;
