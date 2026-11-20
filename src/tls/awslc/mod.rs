//! The server's TLS: volto's own quinn crypto provider on AWS-LC's libssl
//! (D115).
//!
//! rustls has client-side ECH only, so the server runs its handshakes on
//! libssl from the same `aws-lc-sys` build that already backs rustls through
//! aws-lc-rs. libssl runs the TLS 1.3 state machine and hands over traffic
//! secrets per encryption level through BoringSSL's QUIC method table; [`keys`]
//! turns those into quinn's packet and header keys. This module implements
//! quinn-proto's `crypto::ServerConfig` and `crypto::Session` over it.
//!
//! The D106 second SNI gate is a ClientHello callback here. AWS-LC calls it
//! after ECH has been decided, so the name it judges is the inner one when ECH
//! is accepted and the outer one when it is not. The same callback is the
//! second line behind the socket gate's ECH rules (D115, batch 2): with an ECH
//! key it refuses a ClientHello whose ECH extension libssl did not accept, and
//! under `require_ech` one that libssl accepted no ECH on, so that a defect in
//! the socket gate is answered with an alert rather than with this server's
//! ECHConfigList.
//!
//! This is the one module of the crate that may use `unsafe` (`crate` says
//! why). The rule inside it: every `unsafe` block carries a `SAFETY:` comment
//! naming what makes it sound, every `unsafe fn` a `# Safety` section, and the
//! file that needs none (`keys.rs`) forbids it. The ClientHello parser the
//! provider reads the outer ClientHello with is [`crate::hello`], outside this
//! module, so it is held to the crate's `deny(unsafe_code)` as well as its own
//! `forbid`.
//!
//! # Callbacks and the state they share
//!
//! libssl calls back into Rust from inside `SSL_do_handshake`,
//! `SSL_provide_quic_data` and `SSL_process_quic_post_handshake`: the five QUIC
//! method callbacks, the ALPN and ClientHello callbacks, and the keylog
//! callback when keylog is on. Those that need per-connection state reach it
//! through the `SSL`'s ex_data slot, which holds the address of the session's
//! `Arc<Mutex<Shared>>` allocation. A callback locks that mutex for the length
//! of its own body; the session locks it only between libssl calls, never
//! across one, so the lock is never taken twice on one thread. The two
//! callbacks that need the configuration (ALPN, ClientHello) receive the
//! address of the `ServerConfig`'s `Arc<CtxData>` allocation as their `arg`.
//!
//! An `Arc` rather than a `Box` holds each of the two, because a `Box` asserts
//! unique ownership of what it points at, and a raw pointer into it that
//! outlives a move of the `Box` is outside what Rust's aliasing rules allow.
//! An `Arc` makes no such claim. Neither pointer is ever turned into a `&mut`.
//!
//! A panic cannot unwind out of a callback: they are `extern "C"`, so a panic
//! inside one aborts the process. None of them calls anything that panics on
//! peer input.

mod ech;
mod ffi;
mod keys;

#[cfg(test)]
mod tests;

use std::any::Any;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::fs::File;
use std::io::Write as _;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use anyhow::{Context, Result, ensure};
use aws_lc_sys as sys;
use quinn::crypto::rustls::HandshakeData;
use quinn_proto::crypto::{
    self, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, UnsupportedVersion,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectionId, Side, TransportError, TransportErrorCode};
use tracing::debug;
use zeroize::Zeroizing;

use super::UNUSABLE_PAIR;
use crate::config;
use crate::gate::Names;
use crate::hello;

pub use ech::{EchKey, check_public_name};
use ffi::{Ssl, SslCtx};
use keys::{Secret, Suite, Version};

/// The groups this server accepts.
///
/// The set the rustls server accepted (aws-lc-rs's `DEFAULT_KX_GROUPS`
/// without `prefer-post-quantum`, D102), with X25519MLKEM768 moved to the
/// front. The order matters only when the client lists none of them first:
/// libssl, like rustls, takes the first group in the client's
/// `supported_groups` that is also here (`tls1_get_shared_group`, without
/// `SSL_OP_CIPHER_SERVER_PREFERENCE`), and asks for a new key share with a
/// HelloRetryRequest when the client sent none for it.
const GROUPS: [u16; 4] = [
    0x11ec, // X25519MLKEM768
    0x001d, // X25519
    0x0017, // secp256r1
    0x0018, // secp384r1
];
/// TLS 1.3 as a protocol version number.
const TLS13: u16 = 0x0304;
const _: () = assert!(sys::TLS1_3_VERSION == 0x0304);

/// `SSL_OP_NO_TICKET`, in the type `SSL_CTX_set_options` takes.
const OP_NO_TICKET: u32 = 0x4000;
const _: () = assert!(sys::SSL_OP_NO_TICKET == 0x4000);

/// TLS alerts this module sends or falls back to (RFC 8446 §6).
const ALERT_INTERNAL_ERROR: u8 = 80;
const _: () = assert!(sys::SSL_AD_INTERNAL_ERROR == 80);
const ALERT_UNRECOGNIZED_NAME: c_int = sys::SSL_AD_UNRECOGNIZED_NAME;
/// The alert the second ECH line refuses with. RFC 8446 §6.2:
/// "handshake_failure: Receipt of a "handshake_failure" alert message
/// indicates that the sender was unable to negotiate an acceptable set of
/// security parameters given the options available." Our choice: RFC 9849
/// defines no alert for a server that will not go on without ECH, and this one
/// says nothing about which parameter it was.
const ALERT_HANDSHAKE_FAILURE: c_int = sys::SSL_AD_HANDSHAKE_FAILURE;

/// The most Initial-level CRYPTO bytes kept for reading the outer ClientHello.
///
/// libssl's own limit for that level (`SSL_quic_max_handshake_flight_len`,
/// 16384 at `ssl_encryption_initial`): `SSL_provide_quic_data` refuses a flight
/// longer than this, so nothing past it can be a ClientHello libssl reads.
const OUTER_HELLO_LIMIT: usize = 16 * 1024;

/// What the configuration-level callbacks read.
struct CtxData {
    /// ALPN identifiers, in server preference order.
    alpn: Vec<Vec<u8>>,
    /// The D106 list; empty means every name.
    names: Names,
    /// Whether to refuse a ClientHello that carried an ECH extension libssl did
    /// not accept. On whenever an ECH key is configured.
    refuse_unaccepted_ech: bool,
    /// `[security] require_ech`: refuse every ClientHello libssl accepted no
    /// ECH on.
    require_ech: bool,
    /// Where the keylog callback writes, when `[log] keylog` is on.
    keylog: Option<Arc<KeyLog>>,
}

/// The ECH state a server was built with, for its startup line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchSummary {
    /// The ECHConfig's config_id.
    pub config_id: u8,
    /// The ECHConfig's public name.
    pub public_name: String,
}

/// The server side of the provider: one `SSL_CTX`, shared by every session.
pub struct ServerConfig {
    // Dropped before `data`. Every SSL made from the context holds a reference
    // to it and every session holds an `Arc` of this value, so the context and
    // the callback data outlive every SSL either way; the order is for the
    // reader.
    ctx: SslCtx,
    data: Arc<CtxData>,
    ech: Option<EchSummary>,
    /// The ECH key the context holds, for the socket gate, which opens ECH
    /// extensions with the same key before libssl sees them. Loaded once per
    /// build so that the two can never hold different keys.
    ech_key: Option<Arc<EchKey>>,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("tls::ServerConfig")
            .field("alpn", &self.data.alpn)
            .field("ech", &self.ech)
            .finish_non_exhaustive()
    }
}

impl ServerConfig {
    /// Whether ECH is on, and with which config_id and public name.
    pub fn ech(&self) -> Option<&EchSummary> {
        self.ech.as_ref()
    }

    /// The ECH key this configuration was built with.
    pub fn ech_key(&self) -> Option<&Arc<EchKey>> {
        self.ech_key.as_ref()
    }
}

/// Builds the provider from the configuration.
///
/// Called again on `SIGHUP`, which is how a renewed certificate or a new ECH
/// key is picked up: the files are re-read here and the result is handed to
/// `Endpoint::set_server_config`.
pub fn server_config(config: &config::Config) -> Result<ServerConfig> {
    let server = &config.server;
    let certs = super::load_certs(&server.cert)?;
    let key = super::load_key(&server.key)?;
    let ech = server
        .ech_key
        .as_deref()
        .map(EchKey::load)
        .transpose()?
        .map(Arc::new);
    let mut built = Builder {
        certs: certs.iter().map(|c| c.as_ref().to_vec()).collect(),
        key: Zeroizing::new(key.secret_der().to_vec()),
        alpn: server.alpn_wire(),
        names: Names::new(&config.security.expected_sni),
        ech: ech.as_deref(),
        refuse_unaccepted_ech: ech.is_some(),
        require_ech: config.security.require_ech,
        groups: &GROUPS,
        keylog: config.log.keylog.then(KeyLog::from_env).flatten(),
    }
    .build()?;
    built.ech_key = ech;
    Ok(built)
}

/// Everything [`ServerConfig`] is built from, already decoded.
struct Builder<'a> {
    certs: Vec<Vec<u8>>,
    key: Zeroizing<Vec<u8>>,
    alpn: Vec<Vec<u8>>,
    names: Names,
    ech: Option<&'a EchKey>,
    refuse_unaccepted_ech: bool,
    require_ech: bool,
    groups: &'a [u16],
    keylog: Option<Arc<KeyLog>>,
}

impl Builder<'_> {
    fn build(self) -> Result<ServerConfig> {
        ensure!(!self.certs.is_empty(), "no certificate to present");
        // Before libssl reads it, because libssl reads leaves webpki does not.
        super::check_leaf(&rustls::pki_types::CertificateDer::from(
            self.certs[0].as_slice(),
        ))?;
        ffi::clear_errors();
        // Here as well as in `Session::new`, so that startup and a reload fail
        // with the reason rather than every connection.
        session_index()?;
        // SAFETY: TLS_method returns a static method table; SSL_CTX_new returns
        // a new context or null, which `from_ptr` turns into an error.
        let ctx = SslCtx::from_ptr(
            unsafe { sys::SSL_CTX_new(sys::TLS_method()) },
            "SSL_CTX_new",
        )?;
        let data = Arc::new(CtxData {
            alpn: self.alpn,
            names: self.names,
            refuse_unaccepted_ech: self.refuse_unaccepted_ech,
            require_ech: self.require_ech,
            keylog: self.keylog,
        });

        // SAFETY (every call on `ctx` in this block): `ctx` is a valid SSL_CTX
        // that no SSL has been created from and no other thread can see, so
        // configuring it cannot race. Every pointer passed is valid for the
        // duration of its call; AWS-LC copies what it keeps, except the
        // callback `arg`, whose lifetime the comment at its call gives.
        unsafe {
            // TLS 1.3 and nothing else. RFC 9001 §4.2: "An endpoint MUST
            // terminate the connection if a version of TLS older than 1.3 is
            // negotiated."
            ffi::check(
                sys::SSL_CTX_set_min_proto_version(ctx.as_ptr(), TLS13),
                "SSL_CTX_set_min_proto_version",
            )?;
            ffi::check(
                sys::SSL_CTX_set_max_proto_version(ctx.as_ptr(), TLS13),
                "SSL_CTX_set_max_proto_version",
            )?;
            ffi::check(
                sys::SSL_CTX_set1_group_ids(ctx.as_ptr(), self.groups.as_ptr(), self.groups.len()),
                "SSL_CTX_set1_group_ids",
            )?;

            // 1-RTT only. No early data, which RFC 9001 §9.2 puts on the
            // application protocol to justify, and this one does not use:
            // "Disabling 0-RTT entirely is the most effective defense against
            // replay attack." Every request here is a CONNECT carrying
            // credentials. And no session tickets either (D115 item 3): a
            // resumption that is not 0-RTT saves no round trip, only a
            // certificate and a signature, Surge's connections are long-lived,
            // and a ticket links one connection to the next. With tickets off
            // there is nothing a client could resume, so 0-RTT is refused twice
            // over; `tests::a_ticket_would_not_offer_early_data_either` pins
            // the early-data switch on its own.
            sys::SSL_CTX_set_early_data_enabled(ctx.as_ptr(), 0);
            sys::SSL_CTX_set_options(ctx.as_ptr(), OP_NO_TICKET);
            ffi::check(
                sys::SSL_CTX_set_num_tickets(ctx.as_ptr(), 0),
                "SSL_CTX_set_num_tickets",
            )?;
            sys::SSL_CTX_set_session_cache_mode(ctx.as_ptr(), sys::SSL_SESS_CACHE_OFF);

            // The chain, leaf first, as `server.cert` holds it.
            let leaf = ffi::x509_from_der(&self.certs[0])
                .context("the first certificate in server.cert does not parse")?;
            ffi::check(
                sys::SSL_CTX_use_certificate(ctx.as_ptr(), leaf.as_ptr()),
                "SSL_CTX_use_certificate",
            )
            .context(UNUSABLE_PAIR)?;
            for (index, der) in self.certs[1..].iter().enumerate() {
                let cert = ffi::x509_from_der(der).with_context(|| {
                    format!("certificate {} in server.cert does not parse", index + 2)
                })?;
                // `add1` takes its own reference, so `cert` is freed on drop.
                ffi::check(
                    sys::SSL_CTX_add1_chain_cert(ctx.as_ptr(), cert.as_ptr()),
                    "SSL_CTX_add1_chain_cert",
                )?;
            }
            let key = ffi::private_key_from_der(&self.key).context(UNUSABLE_PAIR)?;
            // Fails with KEY_VALUES_MISMATCH when the key is not the leaf's.
            ffi::check(
                sys::SSL_CTX_use_PrivateKey(ctx.as_ptr(), key.as_ptr()),
                "SSL_CTX_use_PrivateKey",
            )
            .context(UNUSABLE_PAIR)?;
            ffi::check(
                sys::SSL_CTX_check_private_key(ctx.as_ptr()),
                "SSL_CTX_check_private_key",
            )
            .context(UNUSABLE_PAIR)?;

            // The address of the `CtxData` allocation. It stays valid for as
            // long as any SSL made from this context can call back: the
            // `ServerConfig` returned below owns this `Arc`, and every session
            // holds an `Arc` of that `ServerConfig` and drops its SSL first.
            let arg = Arc::as_ptr(&data).cast_mut().cast::<c_void>();
            sys::SSL_CTX_set_alpn_select_cb(ctx.as_ptr(), Some(select_alpn), arg);
            sys::SSL_CTX_set_client_hello_cb(ctx.as_ptr(), Some(judge_client_hello), arg);
            if data.keylog.is_some() {
                sys::SSL_CTX_set_keylog_callback(ctx.as_ptr(), Some(on_keylog));
            }
        }

        let ech = match self.ech {
            None => None,
            Some(key) => {
                let keys = key.keys()?;
                // SAFETY: `keys` holds one ECHConfig marked as a retry config;
                // SSL_CTX_set1_ech_keys takes its own reference to it, and the
                // context is still unshared.
                ffi::check(
                    unsafe { sys::SSL_CTX_set1_ech_keys(ctx.as_ptr(), keys.as_ptr()) },
                    "SSL_CTX_set1_ech_keys",
                )?;
                Some(EchSummary {
                    config_id: key.config_id(),
                    public_name: key.public_name().to_owned(),
                })
            }
        };

        Ok(ServerConfig {
            ctx,
            data,
            ech,
            ech_key: None,
        })
    }
}

/// The ex_data slot on each SSL that holds its session's [`Shared`] address,
/// once [`session_index`] has obtained it.
static SESSION_INDEX: OnceLock<c_int> = OnceLock::new();

/// The index of the slot in [`SESSION_INDEX`], obtained on the first call.
///
/// `SSL_get_ex_new_index` returns -1 when its allocation fails, and
/// `SSL_set_ex_data` aborts the process on a negative index
/// (`CRYPTO_set_ex_data`). So a failure is an error here, which `Builder::build`
/// and `Session::new` return before any SSL is given the index, and it is not
/// cached: the next call asks again.
fn session_index() -> Result<c_int> {
    #[cfg(test)]
    if tests::EX_INDEX_FAILS.with(std::cell::Cell::get) {
        return checked_index(-1);
    }
    if let Some(&index) = SESSION_INDEX.get() {
        return Ok(index);
    }
    // SAFETY: no argument and no free callback: the slot holds a borrowed
    // address that the session owns, so AWS-LC must not free it. Returns a
    // fresh index, or -1 when it cannot.
    let index = unsafe {
        sys::SSL_get_ex_new_index(0, std::ptr::null_mut(), std::ptr::null_mut(), None, None)
    };
    // Two threads that race here each obtain an index and one of them goes
    // unused, which costs one empty slot.
    checked_index(index).map(|index| *SESSION_INDEX.get_or_init(|| index))
}

/// `index` if `SSL_get_ex_new_index` returned one.
fn checked_index(index: c_int) -> Result<c_int> {
    ensure!(
        index >= 0,
        "SSL_get_ex_new_index failed: {}",
        ffi::error_stack()
    );
    Ok(index)
}

/// The four QUIC encryption levels, as libssl numbers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Initial,
    EarlyData,
    Handshake,
    Application,
}

impl Level {
    fn from_ffi(level: sys::ssl_encryption_level_t) -> Option<Self> {
        match level {
            sys::ssl_encryption_level_t_ssl_encryption_initial => Some(Self::Initial),
            sys::ssl_encryption_level_t_ssl_encryption_early_data => Some(Self::EarlyData),
            sys::ssl_encryption_level_t_ssl_encryption_handshake => Some(Self::Handshake),
            sys::ssl_encryption_level_t_ssl_encryption_application => Some(Self::Application),
            _ => None,
        }
    }

    fn to_ffi(self) -> sys::ssl_encryption_level_t {
        match self {
            Self::Initial => sys::ssl_encryption_level_t_ssl_encryption_initial,
            Self::EarlyData => sys::ssl_encryption_level_t_ssl_encryption_early_data,
            Self::Handshake => sys::ssl_encryption_level_t_ssl_encryption_handshake,
            Self::Application => sys::ssl_encryption_level_t_ssl_encryption_application,
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Initial => 0,
            Self::EarlyData => 1,
            Self::Handshake => 2,
            Self::Application => 3,
        }
    }
}

/// What the QUIC method callbacks write and the session reads.
#[derive(Default)]
struct Shared {
    /// Secrets libssl installed and the session has not handed to quinn yet.
    read: [Option<Secret>; 4],
    write: [Option<Secret>; 4],
    /// Handshake bytes libssl wrote and quinn has not taken yet, per level.
    out: [Vec<u8>; 4],
    /// The alert libssl asked to send, if any.
    alert: Option<u8>,
    /// A failure inside a callback that has no TLS alert of its own.
    failure: Option<String>,
    /// Where the keylog callback writes, copied from the configuration.
    keylog: Option<Arc<KeyLog>>,
}

static QUIC_METHOD: sys::SSL_QUIC_METHOD = sys::SSL_QUIC_METHOD {
    set_read_secret: Some(on_read_secret),
    set_write_secret: Some(on_write_secret),
    add_handshake_data: Some(on_handshake_data),
    flush_flight: Some(on_flush_flight),
    send_alert: Some(on_send_alert),
};

/// The `Shared` an SSL's ex_data points at.
///
/// # Safety
///
/// `ssl` must be a valid SSL. When it was made by [`Session::new`], its ex_data
/// slot holds the address of that session's `Shared`, which lives as long as
/// the SSL does; any other SSL's slot is null.
unsafe fn shared<'a>(ssl: *const sys::SSL) -> Option<&'a Mutex<Shared>> {
    // Without an index no session was made, so no SSL holds a `Shared`.
    let index = *SESSION_INDEX.get()?;
    // SAFETY: per the function contract, `ssl` is valid.
    let ptr = unsafe { sys::SSL_get_ex_data(ssl, index) };
    // SAFETY: a non-null value is the address of the session's `Shared`,
    // valid for the SSL's life; only shared references are ever made from it.
    unsafe { ptr.cast::<Mutex<Shared>>().as_ref() }
}

/// Locks a `Shared`, taking it over from a panicked holder.
///
/// A panic cannot leave the state half-written in a way that matters: every
/// write is one assignment or one `extend_from_slice`.
fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The two secret callbacks' shared body.
///
/// # Safety
///
/// `ssl` must be a valid SSL, `cipher` an AWS-LC cipher table entry, and
/// `secret` readable for `secret_len` bytes.
unsafe fn store_secret(
    ssl: *mut sys::SSL,
    level: sys::ssl_encryption_level_t,
    cipher: *const sys::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
    write: bool,
) -> c_int {
    // SAFETY: `ssl` is valid per the contract (see `shared`).
    let Some(shared) = (unsafe { shared(ssl) }) else {
        return 0;
    };
    let mut shared = lock(shared);
    let Some(level) = Level::from_ffi(level) else {
        shared.failure = Some(format!("a secret for an unknown level {level}"));
        return 0;
    };
    // SAFETY: `cipher` is the negotiated cipher, a static AWS-LC table entry.
    let id = unsafe { sys::SSL_CIPHER_get_protocol_id(cipher) };
    let Some(suite) = Suite::from_protocol_id(id) else {
        shared.failure = Some(format!(
            "cipher suite {id:#06x} cannot protect QUIC packets"
        ));
        return 0;
    };
    // SAFETY: AWS-LC passes `secret_len` readable bytes at `secret`, valid for
    // the duration of the callback; they are copied out here.
    let bytes = Zeroizing::new(unsafe { std::slice::from_raw_parts(secret, secret_len) }.to_vec());
    let slot = if write {
        &mut shared.write[level.index()]
    } else {
        &mut shared.read[level.index()]
    };
    *slot = Some(Secret { suite, bytes });
    1
}

/// # Safety
///
/// Called by AWS-LC only, through [`QUIC_METHOD`], with the arguments the
/// `SSL_QUIC_METHOD` contract in `ssl.h` describes.
unsafe extern "C" fn on_read_secret(
    ssl: *mut sys::SSL,
    level: sys::ssl_encryption_level_t,
    cipher: *const sys::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    // SAFETY: AWS-LC passes exactly what `store_secret` requires.
    unsafe { store_secret(ssl, level, cipher, secret, secret_len, false) }
}

/// # Safety
///
/// As for [`on_read_secret`].
unsafe extern "C" fn on_write_secret(
    ssl: *mut sys::SSL,
    level: sys::ssl_encryption_level_t,
    cipher: *const sys::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    // SAFETY: as in `on_read_secret`.
    unsafe { store_secret(ssl, level, cipher, secret, secret_len, true) }
}

/// # Safety
///
/// As for [`on_read_secret`].
unsafe extern "C" fn on_handshake_data(
    ssl: *mut sys::SSL,
    level: sys::ssl_encryption_level_t,
    data: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: `ssl` is the SSL being handshaken (see `shared`).
    let Some(shared) = (unsafe { shared(ssl) }) else {
        return 0;
    };
    let Some(level) = Level::from_ffi(level) else {
        return 0;
    };
    // SAFETY: AWS-LC passes `len` readable bytes at `data` for the callback's
    // duration; they are copied into the level's queue. The queue is bounded
    // by what this server writes, which is its own handshake flight.
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    lock(shared).out[level.index()].extend_from_slice(bytes);
    1
}

/// # Safety
///
/// As for [`on_read_secret`].
unsafe extern "C" fn on_flush_flight(_ssl: *mut sys::SSL) -> c_int {
    // quinn takes handshake bytes with `write_handshake` after every read, so
    // there is nothing to push here.
    1
}

/// # Safety
///
/// As for [`on_read_secret`].
unsafe extern "C" fn on_send_alert(
    ssl: *mut sys::SSL,
    _level: sys::ssl_encryption_level_t,
    alert: u8,
) -> c_int {
    // SAFETY: as in `on_handshake_data`.
    let Some(shared) = (unsafe { shared(ssl) }) else {
        return 0;
    };
    lock(shared).alert = Some(alert);
    1
}

/// Writes one keylog line.
///
/// # Safety
///
/// Called by AWS-LC only, as registered with `SSL_CTX_set_keylog_callback`,
/// with a valid `ssl` and a NUL-terminated `line`.
unsafe extern "C" fn on_keylog(ssl: *const sys::SSL, line: *const c_char) {
    // SAFETY: as in `on_handshake_data`.
    let Some(shared) = (unsafe { shared(ssl) }) else {
        return;
    };
    let Some(keylog) = lock(shared).keylog.clone() else {
        return;
    };
    // SAFETY: AWS-LC passes a NUL-terminated string valid for the callback.
    let line = unsafe { CStr::from_ptr(line) };
    keylog.write(line.to_bytes());
}

/// ALPN: the first of the server's identifiers that the client offered, which
/// is how rustls chose.
///
/// A client that offers none of them, or no ALPN at all, is refused with
/// `no_application_protocol` by libssl, as rustls refused it: for QUIC,
/// `ssl_negotiate_alpn` turns a missing extension and a "no match" answer here
/// into that alert. RFC 9001 §8.1: "When using ALPN, endpoints MUST immediately
/// close a connection (see Section 10.2 of [QUIC-TRANSPORT]) with a
/// no_application_protocol TLS alert (QUIC error code 0x0178; see Section 4.8)
/// if an application protocol is not negotiated."
///
/// # Safety
///
/// Called by AWS-LC only, as registered with `SSL_CTX_set_alpn_select_cb`,
/// with the `arg` given there and the arguments `ssl.h` describes.
unsafe extern "C" fn select_alpn(
    _ssl: *mut sys::SSL,
    out: *mut *const u8,
    out_len: *mut u8,
    input: *const u8,
    input_len: std::ffi::c_uint,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: `arg` is the `CtxData` registered with this callback, alive for
    // as long as any SSL from its context (see `Builder::build`).
    let Some(data) = (unsafe { arg.cast::<CtxData>().as_ref() }) else {
        return sys::SSL_TLSEXT_ERR_ALERT_FATAL;
    };
    let Ok(input_len) = usize::try_from(input_len) else {
        return sys::SSL_TLSEXT_ERR_ALERT_FATAL;
    };
    // SAFETY: AWS-LC passes the client's protocol list, `input_len` bytes, valid
    // for the call. libssl has already checked that it is a well-formed list
    // (`ssl_is_valid_alpn_list`); it is parsed again here with bounds checks
    // anyway.
    let offered = unsafe { std::slice::from_raw_parts(input, input_len) };
    let mut list = Vec::new();
    let mut at = 0;
    while let Some(&len) = offered.get(at) {
        let start = at + 1;
        let Some(protocol) = offered.get(start..start + usize::from(len)) else {
            return sys::SSL_TLSEXT_ERR_ALERT_FATAL;
        };
        list.push((start, protocol));
        at = start + usize::from(len);
    }
    for ours in &data.alpn {
        if let Some((start, protocol)) = list.iter().find(|(_, p)| *p == ours.as_slice()) {
            let Ok(len) = u8::try_from(protocol.len()) else {
                return sys::SSL_TLSEXT_ERR_ALERT_FATAL;
            };
            // SAFETY: both out-pointers are valid for writes. The pointer
            // written points into AWS-LC's own buffer, at an offset inside it,
            // which is what `ssl.h` requires of `*out`.
            unsafe {
                *out = input.add(*start);
                *out_len = len;
            }
            return sys::SSL_TLSEXT_ERR_OK;
        }
    }
    sys::SSL_TLSEXT_ERR_ALERT_FATAL
}

/// The D106 second gate and the second ECH line, run after ECH has been
/// decided.
///
/// The ECH line comes first. With an ECH key configured, a ClientHello that
/// carried an ECH extension libssl did not accept is refused, and under
/// `require_ech` so is every ClientHello libssl accepted no ECH on. The socket
/// gate drops both before libssl sees them, so neither should ever fire; they
/// are here so that a defect in the gate costs an alert and not the
/// ECHConfigList, which libssl would otherwise send as `retry_configs` in
/// EncryptedExtensions (RFC 9849 §7.1). The callback runs before the server
/// writes any handshake message, so a refusal here sends no ServerHello and no
/// EncryptedExtensions. When ECH was not accepted, libssl reports the outer
/// ClientHello, so `SSL_client_hello_get0_ext` finds the outer extension; when
/// it was, the inner one, whose extension is the inner variant, and the rule
/// does not ask.
///
/// `SSL_get_servername` reports the inner ClientHello's name when ECH was
/// accepted and the outer one otherwise (`ssl.h`, `SSL_CTX_set1_ech_keys`: "If
/// ECH is negotiated, the reported |SSL_CLIENT_HELLO| structure and
/// |SSL_get_servername| function will transparently reflect the inner
/// ClientHello."), so that is the name judged. A refusal is the alert RFC 6066
/// §3 names: "If the server understood the ClientHello extension but does not
/// recognize the server name, the server SHOULD take one of two actions: either
/// abort the handshake by sending a fatal-level unrecognized_name(112) alert or
/// continue the handshake." The rustls server sent `access_denied` here,
/// because rustls chose the alert (D106, addendum of 2026-11-20).
///
/// # Safety
///
/// Called by AWS-LC only, as registered with `SSL_CTX_set_client_hello_cb`,
/// with the `arg` given there, the SSL being handshaken and a writable alert.
unsafe extern "C" fn judge_client_hello(
    ssl: *mut sys::SSL,
    alert: *mut c_int,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: `arg` is the registered `CtxData`, alive as in `select_alpn`.
    let Some(data) = (unsafe { arg.cast::<CtxData>().as_ref() }) else {
        return sys::SSL_CLIENT_HELLO_ERROR;
    };
    // SAFETY: `ssl` is the SSL being handshaken; both getters only read it.
    let (name, ech_accepted) = unsafe { (server_name(ssl), sys::SSL_ech_accepted(ssl) == 1) };
    // SAFETY: as above. `SSL_client_hello_get0_ext` only looks the extension up
    // in the ClientHello libssl holds for this handshake, and with null
    // out-pointers it writes nothing.
    let ech_offered = unsafe {
        sys::SSL_client_hello_get0_ext(
            ssl,
            std::ffi::c_uint::from(hello::EXT_ECH),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 1
    };
    if !ech_accepted && (data.require_ech || (data.refuse_unaccepted_ech && ech_offered)) {
        debug!(
            ech_offered,
            require_ech = data.require_ech,
            "TLS: refused a ClientHello whose ECH was not accepted, which the socket gate should \
             have dropped"
        );
        // SAFETY: AWS-LC passes a writable alert slot.
        unsafe { *alert = ALERT_HANDSHAKE_FAILURE };
        return sys::SSL_CLIENT_HELLO_ERROR;
    }
    let admitted = data.names.is_empty() || name.as_deref().is_some_and(|n| data.names.accepts(n));
    debug!(
        name = %crate::logfmt::or_dash(name.as_deref()),
        ech_accepted,
        admitted,
        "TLS: the second SNI gate judged the ClientHello"
    );
    if admitted {
        sys::SSL_CLIENT_HELLO_SUCCESS
    } else {
        // SAFETY: AWS-LC passes a writable alert slot.
        unsafe { *alert = ALERT_UNRECOGNIZED_NAME };
        sys::SSL_CLIENT_HELLO_ERROR
    }
}

/// The server name the client asked for, if it is a DNS name.
///
/// `SSL_get_servername` returns the `host_name` bytes as the client sent them,
/// checked only for length and for a zero byte (`extract_sni`). rustls handed
/// on a name only when it parsed as a DNS name, and treated anything else as no
/// name at all; the same parser, from rustls-pki-types, gives the same answer
/// here. That matters beyond parity: the name is written into the
/// `connection established` line with `Display` (`logfmt::or_dash`), so a name
/// carrying a newline or a terminal escape must never reach it.
///
/// # Safety
///
/// `ssl` must be a valid SSL.
unsafe fn server_name(ssl: *const sys::SSL) -> Option<String> {
    // SAFETY: per the contract. AWS-LC returns null or a NUL-terminated string
    // owned by the SSL, which is copied before anything else touches the SSL.
    let raw = unsafe {
        let name = sys::SSL_get_servername(ssl, sys::TLSEXT_NAMETYPE_host_name);
        if name.is_null() {
            return None;
        }
        CStr::from_ptr(name).to_str().ok()?.to_owned()
    };
    dns_name(&raw)
}

/// `raw` if it is a DNS name, as rustls's server judged a `server_name`.
fn dns_name(raw: &str) -> Option<String> {
    match rustls::pki_types::ServerName::try_from(raw) {
        Ok(rustls::pki_types::ServerName::DnsName(name)) => Some(name.as_ref().to_owned()),
        _ => None,
    }
}

/// The file `[log] keylog` writes to, opened once per configuration build.
///
/// What rustls's `KeyLogFile` did: `SSLKEYLOGFILE` is read when the
/// configuration is built, the file is opened for appending and created if
/// missing, and an unset variable or a file that cannot be opened makes keylog
/// a no-op rather than a startup failure. The no-op is reported at debug.
struct KeyLog(Mutex<File>);

impl KeyLog {
    fn from_env() -> Option<Arc<Self>> {
        let path = std::env::var_os("SSLKEYLOGFILE")?;
        match std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
        {
            Ok(file) => Some(Arc::new(Self(Mutex::new(file)))),
            Err(error) => {
                debug!(
                    path = ?path,
                    error = %error,
                    "TLS: SSLKEYLOGFILE cannot be opened, so no TLS secrets are written"
                );
                None
            }
        }
    }

    /// Appends `line` and a newline, as one write under the lock, which is the
    /// synchronisation `ssl.h` asks of the callback.
    fn write(&self, line: &[u8]) {
        let mut record = Zeroizing::new(Vec::with_capacity(line.len() + 1));
        record.extend_from_slice(line);
        record.push(b'\n');
        let mut file = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        // A failed write loses one debugging line; the handshake goes on.
        let _ = file.write_all(&record);
    }
}

impl crypto::ServerConfig for ServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        let version = Version::from_wire(version).ok_or(UnsupportedVersion)?;
        Ok(keys::server_initial_keys(version, dst_cid))
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        // quinn never asks for a version `initial_keys` refused, since it seals
        // a Retry only for a connection whose Initial it could decrypt.
        let version = Version::from_wire(version).unwrap_or(Version::V1);
        keys::retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        let version = Version::from_wire(version).unwrap_or(Version::V1);
        let mut encoded = Vec::new();
        params.write(&mut encoded);
        match Session::new(self, version, &encoded) {
            Ok(session) => Box::new(session),
            // The trait has no error path. A session that failed to start fails
            // its first `read_handshake` with the reason instead.
            Err(error) => Box::new(FailedSession {
                version,
                reason: format!("{error:#}"),
            }),
        }
    }
}

/// One server handshake and the connection's TLS state after it.
pub struct Session {
    // Field order is drop order: the SSL goes first, while `shared` (which its
    // ex_data points at) and `config` (whose SSL_CTX and callback data it uses)
    // are still alive. `SSL_free` calls none of the callbacks either way.
    ssl: Ssl,
    shared: Arc<Mutex<Shared>>,
    _config: Arc<ServerConfig>,
    version: Version,
    /// The highest level whose keys quinn holds.
    ///
    /// quinn passes `read_handshake` the CRYPTO bytes of the packet space it
    /// currently expects, which is the one whose keys `write_handshake` handed
    /// it last (`Connection::read_crypto` in quinn-proto refuses new bytes from
    /// a lower space), and it attributes the bytes `write_handshake` returns to
    /// that same space (`Connection::write_crypto`). So this one level is both
    /// the read and the write level.
    level: Level,
    /// The next 1-RTT generation: (local, remote).
    next: Option<(Secret, Secret)>,
    handshaking: bool,
    got_handshake_data: bool,
    /// Initial-level CRYPTO bytes, kept until the outer ClientHello is whole,
    /// and never more than [`OUTER_HELLO_LIMIT`].
    initial: Vec<u8>,
    outer: Option<OuterHello>,
}

/// What the outer ClientHello said, for the debug line.
#[derive(Debug, Clone, Default)]
struct OuterHello {
    server_name: Option<String>,
    ech: Option<hello::EchOuter>,
}

impl Session {
    fn new(config: Arc<ServerConfig>, version: Version, encoded: &[u8]) -> Result<Self> {
        ffi::clear_errors();
        let index = session_index()?;
        // SAFETY: `config.ctx` is a configured SSL_CTX; SSL_new takes its own
        // reference to it and returns a new SSL or null.
        let ssl = Ssl::from_ptr(unsafe { sys::SSL_new(config.ctx.as_ptr()) }, "SSL_new")?;
        let shared = Arc::new(Mutex::new(Shared {
            keylog: config.data.keylog.clone(),
            ..Shared::default()
        }));
        // SAFETY: `ssl` is fresh and owned here. The QUIC method table is a
        // static; AWS-LC copies the transport parameters. `index` is not
        // negative (`session_index`), so `SSL_set_ex_data` does not abort. The
        // ex_data value is the address of the `Shared` allocation, which
        // `shared` keeps alive until after the SSL is freed (field order of
        // `Session`).
        unsafe {
            sys::SSL_set_accept_state(ssl.as_ptr());
            ffi::check(
                sys::SSL_set_quic_method(ssl.as_ptr(), &QUIC_METHOD),
                "SSL_set_quic_method",
            )?;
            ffi::check(
                sys::SSL_set_quic_transport_params(ssl.as_ptr(), encoded.as_ptr(), encoded.len()),
                "SSL_set_quic_transport_params",
            )?;
            // Drafts 29 to 32 carry the transport parameters under the draft
            // codepoint, as rustls's `quic::Version::V1Draft` does.
            sys::SSL_set_quic_use_legacy_codepoint(
                ssl.as_ptr(),
                c_int::from(version == Version::Draft),
            );
            let ptr = Arc::as_ptr(&shared).cast_mut().cast::<c_void>();
            ffi::check(
                sys::SSL_set_ex_data(ssl.as_ptr(), index, ptr),
                "SSL_set_ex_data",
            )?;
        }
        Ok(Self {
            ssl,
            shared,
            _config: config,
            version,
            level: Level::Initial,
            next: None,
            handshaking: true,
            got_handshake_data: false,
            initial: Vec::new(),
            outer: None,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Shared> {
        lock(&self.shared)
    }

    /// The transport error for a failed AWS-LC call.
    fn failure(&self, what: &str) -> TransportError {
        let errors = ffi::error_stack();
        let shared = self.lock();
        let alert = shared.alert.unwrap_or(ALERT_INTERNAL_ERROR);
        let detail = shared.failure.clone().unwrap_or(errors);
        TransportError {
            code: TransportErrorCode::crypto(alert),
            frame: None,
            reason: format!("TLS ({what}): {detail}"),
        }
    }

    /// Keeps Initial-level bytes until the outer ClientHello can be read.
    fn note_outer_hello(&mut self, buf: &[u8]) {
        if self.level != Level::Initial || self.outer.is_some() {
            return;
        }
        if self.initial.len() + buf.len() > OUTER_HELLO_LIMIT {
            // Longer than any ClientHello libssl reads; it refuses the flight
            // itself. Stop keeping bytes and log nothing about it.
            self.outer = Some(OuterHello::default());
            self.initial = Vec::new();
            return;
        }
        self.initial.extend_from_slice(buf);
        if let Some(body) = hello::client_hello_body(&self.initial) {
            self.outer = Some(OuterHello {
                server_name: hello::server_name(body)
                    .and_then(|name| std::str::from_utf8(name).ok())
                    .and_then(dns_name),
                ech: hello::ech_outer(body),
            });
            self.initial = Vec::new();
        }
    }

    fn log_handshake(&self) {
        // SAFETY: `self.ssl` is valid; the getters only read the completed
        // handshake's results, and the strings they return are static (group
        // and cipher names) or copied at once (`server_name`).
        let (ech_accepted, inner, group, cipher) = unsafe {
            let ssl = self.ssl.as_ptr();
            let accepted = sys::SSL_ech_accepted(ssl) == 1;
            let name = server_name(ssl);
            let group = static_str(sys::SSL_get_group_name(sys::SSL_get_group_id(ssl)));
            let cipher = static_str(sys::SSL_CIPHER_get_name(sys::SSL_get_current_cipher(ssl)));
            (accepted, name, group, cipher)
        };
        let outer = self.outer.as_ref();
        debug!(
            ech_accepted,
            inner_sni = %crate::logfmt::or_dash(if ech_accepted { inner.as_deref() } else { None }),
            outer_sni = %crate::logfmt::or_dash(outer.and_then(|o| o.server_name.as_deref())),
            ech_config_id = %crate::logfmt::or_dash(outer.and_then(|o| o.ech.as_ref()).map(|e| e.config_id)),
            group = %crate::logfmt::or_dash(group),
            cipher = %crate::logfmt::or_dash(cipher),
            "TLS handshake complete"
        );
    }

    /// Whether ECH was accepted on this handshake.
    #[cfg(test)]
    fn ech_accepted(&self) -> bool {
        // SAFETY: `self.ssl` is valid; the getter only reads.
        unsafe { sys::SSL_ech_accepted(self.ssl.as_ptr()) == 1 }
    }
}

/// A static C string from AWS-LC's tables, or `None` for null.
///
/// # Safety
///
/// `ptr` must be null or point at a NUL-terminated string that lives for the
/// rest of the program, as the group and cipher name tables do.
unsafe fn static_str(ptr: *const c_char) -> Option<&'static str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: per the contract.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

impl crypto::Session for Session {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        initial_keys(self.version, dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.got_handshake_data {
            return None;
        }
        let mut protocol = std::ptr::null();
        let mut len = 0u32;
        // SAFETY: `self.ssl` is valid; AWS-LC writes a pointer into its own
        // buffer (or null) and a length, and the bytes are copied at once.
        let (protocol, server_name) = unsafe {
            sys::SSL_get0_alpn_selected(self.ssl.as_ptr(), &mut protocol, &mut len);
            let protocol = match usize::try_from(len) {
                Ok(len) if !protocol.is_null() && len > 0 => {
                    Some(std::slice::from_raw_parts(protocol, len).to_vec())
                }
                _ => None,
            };
            (protocol, server_name(self.ssl.as_ptr()))
        };
        // quinn's own type, so `quic::peer_info` reads this provider's answer
        // exactly as it read the rustls provider's.
        Some(Box::new(HandshakeData {
            protocol,
            server_name,
        }))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        // No client certificates are asked for.
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        // 1-RTT only (see `Builder::build`).
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        self.handshaking
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        let level = self.level;
        self.note_outer_hello(buf);
        ffi::clear_errors();
        // SAFETY: `self.ssl` is valid and used by this thread alone (`&mut
        // self`); `buf` is readable for its length and AWS-LC copies it. The
        // callbacks AWS-LC runs in here lock `shared`, which this function does
        // not hold.
        let rc = unsafe {
            sys::SSL_provide_quic_data(self.ssl.as_ptr(), level.to_ffi(), buf.as_ptr(), buf.len())
        };
        if rc != 1 {
            return Err(self.failure("SSL_provide_quic_data"));
        }

        if self.handshaking {
            // SAFETY: as above.
            let rc = unsafe { sys::SSL_do_handshake(self.ssl.as_ptr()) };
            if rc == 1 {
                self.handshaking = false;
                self.log_handshake();
            } else {
                // SAFETY: as above; SSL_get_error reads the SSL's last result.
                let error = unsafe { sys::SSL_get_error(self.ssl.as_ptr(), rc) };
                if error != sys::SSL_ERROR_WANT_READ {
                    return Err(self.failure("SSL_do_handshake"));
                }
            }
        } else {
            // SAFETY: as above.
            let rc = unsafe { sys::SSL_process_quic_post_handshake(self.ssl.as_ptr()) };
            if rc != 1 {
                return Err(self.failure("SSL_process_quic_post_handshake"));
            }
        }

        // An alert with a call that still succeeded. QUIC carries no warning
        // alerts, so any alert ends the connection.
        let alert = self.lock().alert;
        if let Some(alert) = alert {
            return Err(TransportError {
                code: TransportErrorCode::crypto(alert),
                frame: None,
                reason: "TLS alert".into(),
            });
        }

        if !self.got_handshake_data {
            let mut protocol = std::ptr::null();
            let mut len = 0u32;
            // SAFETY: as in `handshake_data`; only the length is read.
            let ready = unsafe {
                sys::SSL_get0_alpn_selected(self.ssl.as_ptr(), &mut protocol, &mut len);
                len > 0 || server_name(self.ssl.as_ptr()).is_some()
            };
            if ready || !self.handshaking {
                self.got_handshake_data = true;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        let mut ptr = std::ptr::null();
        let mut len = 0usize;
        // SAFETY: `self.ssl` is valid; AWS-LC points at a buffer it owns for the
        // SSL's lifetime, which outlives this borrow of `self`.
        let params = unsafe {
            sys::SSL_get_peer_quic_transport_params(self.ssl.as_ptr(), &mut ptr, &mut len);
            if ptr.is_null() || len == 0 {
                return Ok(None);
            }
            std::slice::from_raw_parts(ptr, len)
        };
        Ok(Some(TransportParameters::read(
            Side::Server,
            &mut std::io::Cursor::new(params),
        )?))
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        let mut shared = self.lock();
        // Bytes at this level belong to the space whose keys quinn holds, even
        // in the call that returns the next level's keys: quinn reads
        // `highest_space` before it upgrades (`Connection::write_crypto`).
        buf.append(&mut shared.out[self.level.index()]);
        let next = match self.level {
            Level::Initial => Level::Handshake,
            Level::Handshake => Level::Application,
            Level::EarlyData | Level::Application => return None,
        };
        // quinn takes both directions of a space in one `Keys`. libssl installs
        // the server's 1-RTT write secret with the server Finished
        // (`do_send_server_finished`) and the 1-RTT read secret only once the
        // client's Finished is verified (`do_read_client_finished`), so the
        // 1-RTT keys are handed over then, a round trip after the write secret.
        // The server therefore sends no 0.5-RTT packet. That is one difference
        // from the rustls server, which handed quinn the 1-RTT keys with the
        // server's first flight: quinn-proto queues the server's first
        // NEW_CONNECTION_ID frames at the Initial-to-Handshake upgrade
        // (`issue_first_cids`) and sends Data-space frames as soon as it holds
        // keys for that space (`space_can_send`), so with rustls those frames
        // left in a 1-RTT packet of the first flight, and now they leave after
        // the client's Finished. Read in quinn-proto 0.11.19, not captured on
        // the wire. The server also cannot decrypt a 1-RTT packet before the
        // handshake completes, which RFC 9001 §5.7 forbids anyway: "Endpoints
        // in either role MUST NOT decrypt 1-RTT packets from their peer prior
        // to completing the handshake." quinn-proto discards a 1-RTT packet
        // that arrives before the keys (`unprotect_header`, "discarding
        // unexpected Data packet"), and the client sends it again.
        let i = next.index();
        if shared.write[i].is_none() || shared.read[i].is_none() {
            return None;
        }
        let (Some(local), Some(remote)) = (shared.write[i].take(), shared.read[i].take()) else {
            return None;
        };
        drop(shared);
        self.level = next;
        if next == Level::Application {
            // quinn asks for the first key update as soon as it has the 1-RTT
            // keys (`Connection::upgrade_crypto` calls `next_1rtt_keys`).
            self.next = Some((local.updated(), remote.updated()));
        }
        Some(keys::keys(&local, &remote))
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        // RFC 9001 §6.1, one generation ahead, as rustls's `quic::Secrets`
        // does. The header protection keys stay: "The header protection key is
        // not updated." (RFC 9001 §6.1).
        let (local, remote) = self.next.take()?;
        let keys = keys::packet_keys(&local, &remote);
        self.next = Some((local.updated(), remote.updated()));
        Some(keys)
    }

    fn is_valid_retry(
        &self,
        _orig_dst_cid: &ConnectionId,
        _header: &[u8],
        _payload: &[u8],
    ) -> bool {
        // A client-side check; this provider is a server.
        false
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        // SAFETY: `self.ssl` is valid; every buffer is valid for the length
        // passed beside it, and `output` is writable.
        let rc = unsafe {
            sys::SSL_export_keying_material(
                self.ssl.as_ptr(),
                output.as_mut_ptr(),
                output.len(),
                label.as_ptr().cast::<c_char>(),
                label.len(),
                context.as_ptr(),
                context.len(),
                1,
            )
        };
        if rc == 1 {
            Ok(())
        } else {
            Err(ExportKeyingMaterialError)
        }
    }
}

/// The Initial keys of `dst_cid` for `side`.
fn initial_keys(version: Version, dst_cid: &ConnectionId, side: Side) -> Keys {
    let (client, server) = keys::initial_secrets(version, dst_cid);
    match side {
        Side::Server => keys::keys(&server, &client),
        Side::Client => keys::keys(&client, &server),
    }
}

/// A session whose SSL could not be created: it fails its first read.
struct FailedSession {
    version: Version,
    reason: String,
}

impl crypto::Session for FailedSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        initial_keys(self.version, dst_cid, side)
    }
    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        None
    }
    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        None
    }
    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        None
    }
    fn early_data_accepted(&self) -> Option<bool> {
        None
    }
    fn is_handshaking(&self) -> bool {
        true
    }
    fn read_handshake(&mut self, _buf: &[u8]) -> Result<bool, TransportError> {
        Err(TransportError {
            code: TransportErrorCode::crypto(ALERT_INTERNAL_ERROR),
            frame: None,
            reason: self.reason.clone(),
        })
    }
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        Ok(None)
    }
    fn write_handshake(&mut self, _buf: &mut Vec<u8>) -> Option<Keys> {
        None
    }
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        None
    }
    fn is_valid_retry(&self, _: &ConnectionId, _: &[u8], _: &[u8]) -> bool {
        false
    }
    fn export_keying_material(
        &self,
        _: &mut [u8],
        _: &[u8],
        _: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        Err(ExportKeyingMaterialError)
    }
}

/// The ceiling on what one probed handshake may hold in this provider's own
/// buffers: the outer ClientHello copy, bounded by libssl's 16384-byte Initial
/// flight limit, plus
/// the handshake bytes libssl queued and quinn has not taken, which are the
/// server's own flight (a certificate chain and a few small messages).
pub const PROBE_HELD_LIMIT: usize = OUTER_HELLO_LIMIT + 64 * 1024;

/// A server configuration for [`ProbeSession`]: the certificate and key as
/// DER, ALPN `h3`, no gate list, and the ECH key if given. Everything else is
/// what [`server_config`] builds.
pub fn probe_server_config(
    cert: &[u8],
    key: &[u8],
    ech: Option<&EchKey>,
) -> Result<Arc<ServerConfig>> {
    Builder {
        certs: vec![cert.to_vec()],
        key: Zeroizing::new(key.to_vec()),
        alpn: vec![b"h3".to_vec()],
        names: Names::new(&[]),
        ech,
        refuse_unaccepted_ech: ech.is_some(),
        require_ech: false,
        groups: &GROUPS,
        keylog: None,
    }
    .build()
    .map(Arc::new)
}

/// One server handshake driven by hand rather than by quinn.
///
/// This is how `fuzz/fuzz_targets/tls.rs` reaches the provider: it reads CRYPTO
/// bytes at the level whose keys quinn would hold, and writes the way quinn's
/// `Connection::write_crypto` does, so the session moves through its levels as
/// it would on a real connection. Nothing here is used by the server itself.
pub struct ProbeSession(Session);

impl ProbeSession {
    /// A fresh server session on `config`, for QUIC version 1, with
    /// `transport_parameters` as the server's own encoded parameters.
    pub fn new(config: Arc<ServerConfig>, transport_parameters: &[u8]) -> Result<Self> {
        Session::new(config, Version::V1, transport_parameters).map(Self)
    }

    /// Hands `bytes` to the session at its current level, as quinn hands the
    /// bytes of one CRYPTO frame. `false` when the session refused them, which
    /// ends a real connection.
    pub fn read(&mut self, bytes: &[u8]) -> bool {
        crypto::Session::read_handshake(&mut self.0, bytes).is_ok()
    }

    /// Takes everything the session has to send, as quinn does after every
    /// read: one `(level, bytes)` entry per level that had bytes, where the
    /// level is 0 for Initial, 2 for Handshake and 3 for 1-RTT.
    pub fn write(&mut self) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        loop {
            let level = self.level();
            let mut buf = Vec::new();
            let keys = crypto::Session::write_handshake(&mut self.0, &mut buf);
            let empty = buf.is_empty();
            if !empty {
                out.push((level, buf));
            }
            if keys.is_none() && empty {
                return out;
            }
        }
    }

    /// The level the session reads at: 0 Initial, 2 Handshake, 3 1-RTT.
    pub fn level(&self) -> u8 {
        match self.0.level {
            Level::Initial => 0,
            Level::EarlyData => 1,
            Level::Handshake => 2,
            Level::Application => 3,
        }
    }

    /// Whether the handshake is still running.
    pub fn is_handshaking(&self) -> bool {
        self.0.handshaking
    }

    /// The bytes this provider holds for the session in its own buffers: the
    /// outer ClientHello copy and the queued handshake bytes. At most
    /// [`PROBE_HELD_LIMIT`] if buffering is bounded.
    pub fn held_bytes(&self) -> usize {
        let queued: usize = self.0.lock().out.iter().map(Vec::len).sum();
        self.0.initial.len() + queued
    }
}
