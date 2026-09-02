//! Volto — a MASQUE proxy server.
//!
//! Volto terminates HTTP/3 over QUIC and proxies client traffic:
//!
//! * **TCP** via classic CONNECT tunnels (RFC 9114 §4.4).
//! * **UDP** via CONNECT-UDP (RFC 9298) + HTTP Datagrams (RFC 9297).
//!
//! # Module layout
//!
//! * [`auth`] — HTTP Basic authentication of CONNECT requests.
//! * [`config`] — TOML configuration and its validation.
//! * [`policy`] — the destination ACL: which targets may be reached.
//! * [`tls`] — certificate/key loading and the rustls server configuration.
//! * [`quic`] — the QUIC endpoint, transport parameters and the accept loop.
//! * [`shutdown`] — the graceful-shutdown signal shared by endpoint and connections.
//! * [`h3`] — HTTP/3 (RFC 9114) for a proxy: framing, QPACK, the control
//!   stream, request streams, and the routing of inbound HTTP Datagrams to the
//!   stream each one names.
//! * [`h3api`] — the facade over that layer, and the only HTTP/3 vocabulary
//!   the rest of the crate uses.
//! * [`conn`] — per-connection driving and request dispatch.
//! * [`capsule`] — the Capsule Protocol (RFC 9297 §3) incremental decoder.
//! * [`datagram`] — HTTP Datagram payload coding (RFC 9297) and QUIC varints.
//! * [`net`] — explicit name resolution and UDP socket setup.
//! * [`logfmt`] — how an optional value is spelled in a log field.
//! * [`tunnel`] — request routing, the per-connection context and the tunnels.
//!
//! # Security status
//!
//! Requests are authenticated ([`auth`]) and destinations are filtered
//! ([`policy`]) — but both are **configuration-dependent**, and the defaults are
//! not the safe ones in the same way everywhere:
//!
//! * an empty `[auth].users` disables authentication, making this an open proxy.
//!   [`config::Config::warnings`] says so at startup, and it is the intended
//!   state only while debugging interop on a private network;
//! * `[security]` defaults *are* the safe ones: private address space is out of
//!   reach, port 25 is closed, and an unanswered UDP session cannot be used as an
//!   amplifier.

// The two raw syscalls this crate used to make by hand -- `getrlimit` for the
// startup fd check and `IP_MTU_DISCOVER` for the DF bit -- now go through
// rustix's safe wrappers, so "no `unsafe` in the server" is a property worth
// pinning rather than one that merely happens to hold. `forbid` rather than
// `deny` so it cannot be opted out of module by module: a future need for
// `unsafe` should be an argued change to this line, not a local `allow`.
#![forbid(unsafe_code)]
// Every public item carries prose, and the gate says so rather than the habit.
// `cargo doc` is published for this crate, so a `pub` item without a doc comment
// is a hole in the page a reader lands on; `warn` here rather than `deny`,
// because CI already runs clippy with `-D warnings` and rustdoc with
// `RUSTDOCFLAGS=-D warnings`, so the gate is an error where it matters and a
// hint where somebody is mid-edit. Deliberately not `[lints]` in `Cargo.toml`:
// that would reach `tests/` and `fuzz/`, whose items are scaffolding rather
// than a published surface.
#![warn(missing_docs)]
#![doc(html_logo_url = "https://vcarus.github.io/volto/assets/logo.png")]
#![doc(html_favicon_url = "https://vcarus.github.io/volto/theme/favicon.png")]

pub mod auth;
pub mod capsule;
pub mod config;
pub mod conn;
pub mod datagram;
pub mod h3;
pub mod h3api;
pub mod logfmt;
pub mod net;
pub mod policy;
pub mod quic;
pub mod shutdown;
pub mod tls;
pub mod tunnel;
