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
//! * [`h3api`] — the *only* module allowed to name `h3`/`h3-quinn` types. It
//!   exists so the HTTP/3 backend stays replaceable.
//! * [`conn`] — per-connection driving, request dispatch, and the datagram
//!   router shared by every UDP session on the connection.
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

pub mod auth;
pub mod capsule;
pub mod config;
pub mod conn;
pub mod datagram;
pub mod h3api;
pub mod logfmt;
pub mod net;
pub mod policy;
pub mod quic;
pub mod shutdown;
pub mod tls;
pub mod tunnel;
