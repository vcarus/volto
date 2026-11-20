//! Owning wrappers over the AWS-LC objects this provider creates.
//!
//! Each type holds one non-null pointer that it frees on drop, so the rest of
//! the provider never frees anything by hand.

use std::ffi::{CStr, c_char, c_int};
use std::ptr::NonNull;

use anyhow::{Result, bail};
use aws_lc_sys as sys;

/// Drains AWS-LC's thread-local error queue into one line.
pub(super) fn error_stack() -> String {
    let mut parts = Vec::new();
    loop {
        // SAFETY: ERR_get_error takes no arguments and only pops the calling
        // thread's error queue.
        let code = unsafe { sys::ERR_get_error() };
        if code == 0 {
            break;
        }
        let mut buf: [c_char; 256] = [0; 256];
        // SAFETY: `buf` is a writable buffer of the length passed, and
        // ERR_error_string_n always NUL-terminates within that length, so
        // `CStr::from_ptr` finds the terminator inside `buf`.
        let text = unsafe {
            sys::ERR_error_string_n(code, buf.as_mut_ptr(), buf.len());
            CStr::from_ptr(buf.as_ptr())
        };
        parts.push(text.to_string_lossy().into_owned());
    }
    if parts.is_empty() {
        "no error on the AWS-LC error queue".to_owned()
    } else {
        parts.join("; ")
    }
}

/// Clears the error queue, so a later failure reports only its own errors.
pub(super) fn clear_errors() {
    // SAFETY: ERR_clear_error only empties the calling thread's error queue.
    unsafe { sys::ERR_clear_error() }
}

/// Fails with the AWS-LC error queue when `rc` is not 1.
pub(super) fn check(rc: c_int, what: &str) -> Result<()> {
    if rc == 1 {
        Ok(())
    } else {
        bail!("{what} failed: {}", error_stack())
    }
}

macro_rules! owned {
    ($(#[$doc:meta])* $name:ident, $ty:ty, $free:path) => {
        $(#[$doc])*
        pub(super) struct $name(NonNull<$ty>);

        impl $name {
            /// Takes ownership of `ptr`, or fails with the error queue when it
            /// is null.
            pub(super) fn from_ptr(ptr: *mut $ty, what: &str) -> Result<Self> {
                match NonNull::new(ptr) {
                    Some(ptr) => Ok(Self(ptr)),
                    None => bail!("{what} failed: {}", error_stack()),
                }
            }

            pub(super) fn as_ptr(&self) -> *mut $ty {
                self.0.as_ptr()
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: the pointer came from the matching constructor, is
                // owned by this value alone and is freed exactly once here.
                unsafe { $free(self.0.as_ptr()) }
            }
        }
    };
}

owned!(
    /// An `SSL_CTX`: the configuration every handshake of one
    /// [`super::ServerConfig`] is created from.
    SslCtx,
    sys::SSL_CTX,
    sys::SSL_CTX_free
);
owned!(
    /// An `SSL`: one handshake and the connection state after it.
    Ssl,
    sys::SSL,
    sys::SSL_free
);
owned!(
    /// A parsed certificate.
    X509,
    sys::X509,
    sys::X509_free
);
owned!(
    /// A parsed private key.
    PrivateKey,
    sys::EVP_PKEY,
    sys::EVP_PKEY_free
);
owned!(
    /// An HPKE private key, the secret half of the ECH key.
    HpkeKey,
    sys::EVP_HPKE_KEY,
    sys::EVP_HPKE_KEY_free
);
owned!(
    /// An HPKE context, set up for one decryption and dropped after it.
    HpkeCtx,
    sys::EVP_HPKE_CTX,
    sys::EVP_HPKE_CTX_free
);
owned!(
    /// A set of ECH configurations and their keys, as `SSL_CTX_set1_ech_keys`
    /// takes it.
    EchKeys,
    sys::SSL_ECH_KEYS,
    sys::SSL_ECH_KEYS_free
);

// SAFETY: AWS-LC's `ssl.h`, section "SSL contexts": "|SSL_CTX| are
// reference-counted and may be shared by connections across multiple threads.
// Once shared, functions which change the |SSL_CTX|'s configuration may not be
// used." `Builder::build` in `mod.rs` is the only code that calls such a
// function, and it does so before the `SslCtx` leaves the function that created
// it. After that the provider calls only `SSL_new` on it, which is how a
// context is shared by connections.
unsafe impl Send for SslCtx {}
// SAFETY: as above.
unsafe impl Sync for SslCtx {}

// SAFETY: an `EVP_HPKE_KEY` is written only by `EVP_HPKE_KEY_init` and
// `EVP_HPKE_KEY_generate`, which `ech.rs` calls on a key it has just created
// and that nothing else can reach yet. Every function the provider passes it to
// afterwards takes it as `const EVP_HPKE_KEY *` and only reads it
// (`EVP_HPKE_KEY_private_key`, `SSL_marshal_ech_config`, `SSL_ECH_KEYS_add`,
// which takes its own copy, and `EVP_HPKE_CTX_setup_recipient`), as `hpke.h`
// and `ssl.h` declare them. What it holds (`struct evp_hpke_key_st` in `hpke.h`)
// is a pointer to a static KEM table and key buffers it owns on the heap, none
// of it per-thread. So it may move to another thread, and several threads may
// read it at once.
unsafe impl Send for HpkeKey {}
// SAFETY: as above.
unsafe impl Sync for HpkeKey {}

// SAFETY: `ssl.h`, section "SSL connections": "an |SSL| is not thread-safe and
// may only be used on one thread at a time". It is not tied to the thread that
// created it. Every `Ssl` is owned by one `Session` in `mod.rs`, which quinn
// boxes as the `crypto: Box<dyn crypto::Session>` field of quinn-proto's
// `Connection` (`src/connection/mod.rs`). quinn holds that `Connection` as the
// `inner` field of its `State`, which it keeps in `ConnectionInner::state`, a
// `Mutex<State>` (quinn `src/connection.rs`), and reaches the session only with
// that mutex held. So an `SSL` moves between threads but is used by one thread
// at a time, which is the property this relies on.
unsafe impl Send for Ssl {}
// SAFETY: `Session: Sync` is required by quinn-proto's `crypto::Session` trait.
// The calls `Session` makes through `&self` are AWS-LC getters that read
// handshake results (the server name, the ALPN protocol, the peer's transport
// parameters, whether ECH was accepted) and the keying-material exporter, which
// derives from a stored secret. None of them writes to the `SSL`. They are
// still never concurrent, for the reason given on `Send` above: quinn calls
// every `Session` method with `ConnectionInner::state` locked.
unsafe impl Sync for Ssl {}

/// A buffer AWS-LC allocated and the caller must release with `OPENSSL_free`.
pub(super) struct OpensslBytes {
    ptr: NonNull<u8>,
    len: usize,
}

impl OpensslBytes {
    /// Takes ownership of a buffer an AWS-LC `marshal` function returned.
    pub(super) fn from_raw(ptr: *mut u8, len: usize, what: &str) -> Result<Self> {
        match NonNull::new(ptr) {
            Some(ptr) => Ok(Self { ptr, len }),
            None => bail!("{what} returned no buffer"),
        }
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        // SAFETY: AWS-LC wrote `len` bytes at `ptr`, nothing else holds the
        // buffer, and it lives until this value is dropped.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for OpensslBytes {
    fn drop(&mut self) {
        // SAFETY: the buffer was allocated by AWS-LC and is released once.
        unsafe { sys::OPENSSL_free(self.ptr.as_ptr().cast()) }
    }
}

/// Parses one DER certificate.
pub(super) fn x509_from_der(der: &[u8]) -> Result<X509> {
    let len = std::ffi::c_long::try_from(der.len())?;
    let mut input = der.as_ptr();
    // SAFETY: `input` points at `len` readable bytes; d2i_X509 reads at most
    // that many and advances `input` within them. A null first argument asks
    // for a new object, which the caller then owns.
    let ptr = unsafe { sys::d2i_X509(std::ptr::null_mut(), &mut input, len) };
    X509::from_ptr(ptr, "d2i_X509")
}

/// Parses a DER private key: PKCS#8, or a bare PKCS#1 RSA or SEC1 EC key.
///
/// `d2i_AutoPrivateKey` tells the three apart itself, which is what keeps the
/// three PEM forms `docs/configuration.md` promises for `server.key`.
pub(super) fn private_key_from_der(der: &[u8]) -> Result<PrivateKey> {
    let len = std::ffi::c_long::try_from(der.len())?;
    let mut input = der.as_ptr();
    // SAFETY: as for d2i_X509: `len` readable bytes and a null output slot.
    let ptr = unsafe { sys::d2i_AutoPrivateKey(std::ptr::null_mut(), &mut input, len) };
    PrivateKey::from_ptr(ptr, "d2i_AutoPrivateKey")
}
