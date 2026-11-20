//! The server's ECH key: one X25519 HPKE key and the one ECHConfig made from
//! it, kept together in one file.
//!
//! A client holds the ECHConfigList as something an operator typed in
//! (Surge's `ech-config`), so the list has to be the same on every start and
//! after every reload. The file therefore stores the ECHConfig itself, not only
//! the private key: the config_id, the public name, the HPKE suites and the
//! maximum name length are fixed when the key is generated, and printing the
//! list again from the file gives the same bytes. Nothing in the server's
//! configuration file can change them.
//!
//! The format is two PEM blocks, a `PRIVATE KEY` holding the X25519 key as
//! PKCS#8 and an `ECHCONFIG` holding the ECHConfigList with its one ECHConfig.
//! That is the layout rustls-pki-types reads as an "ECHConfig file"
//! (`EchConfigListBytes::config_and_key_from_iter`), which is where the
//! `ECHCONFIG` label comes from. This module reads the blocks itself so that a
//! second key or a second list is refused rather than ignored.

use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use aws_lc_sys as sys;
use rustls::pki_types::pem::{PemObject, SectionKind};
use zeroize::Zeroizing;

use super::ffi::{self, EchKeys, HpkeCtx, HpkeKey, OpensslBytes};
use crate::hello::{EchOuter, Reader};

/// The ECHConfig version this server writes and reads. RFC 9849 §4:
/// "case 0xfe0d: ECHConfigContents contents;".
const ECH_VERSION: u16 = 0xfe0d;

/// DHKEM(X25519, HKDF-SHA256), the only KEM AWS-LC's ECH server takes
/// (`ECHServerConfig::Init` refuses any other).
const KEM_X25519_HKDF_SHA256: u16 = 0x0020;

/// The PKCS#8 encoding of an X25519 private key, up to the 32 key bytes.
///
/// RFC 8410 §7: "To encode an EdDSA, X25519, or X448 private key, the
/// "privateKey" field will hold the encoded private key. The
/// "privateKeyAlgorithm" field uses the AlgorithmIdentifier structure." The
/// algorithm is RFC 8410 §3's "id-X25519    OBJECT IDENTIFIER ::= { 1 3 101 110 }",
/// with no parameters, and the private key is a CurvePrivateKey (an OCTET
/// STRING) inside the privateKey OCTET STRING. As DER: SEQUENCE (46 bytes) of
/// INTEGER 0, SEQUENCE (5 bytes) of the OID 2b 65 6e, and OCTET STRING (34
/// bytes) of OCTET STRING (32 bytes). This is the form OpenSSL writes for an
/// X25519 key. Reading goes through AWS-LC's PKCS#8 parser, which also takes
/// the form with the optional public key.
const X25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];

/// An X25519 private key is 32 bytes.
const X25519_KEY_LEN: usize = 32;

/// The label the HPKE `info` starts with, including the zero byte after it.
///
//= https://www.rfc-editor.org/rfc/rfc9849#section-7.1
//# The info parameter to SetupBaseR is the concatenation
//# "tls ech", a zero byte, and the serialized ECHConfig.
const INFO_LABEL: &[u8; 8] = b"tls ech\0";

/// The ECH key and its ECHConfig, read from a key file or freshly generated.
pub struct EchKey {
    hpke: HpkeKey,
    /// The raw private key, kept only to write the file again.
    private: Zeroizing<[u8; X25519_KEY_LEN]>,
    /// One serialized ECHConfig (version, length, contents).
    config: Vec<u8>,
    config_id: u8,
    public_name: String,
    /// The ECHConfig's HPKE suites, as (KDF, AEAD) pairs.
    suites: Vec<(u16, u16)>,
}

impl std::fmt::Debug for EchKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The private key is left out on purpose.
        f.debug_struct("EchKey")
            .field("config_id", &self.config_id)
            .field("public_name", &self.public_name)
            .finish_non_exhaustive()
    }
}

impl EchKey {
    /// A new key with a new ECHConfig.
    ///
    /// `max_name_length` is the ECHConfig's `maximum_name_length`, which only
    /// steers how much a client pads its inner ClientHello. RFC 9849 §4: "If not
    /// known, this value can be set to zero."
    pub fn generate(public_name: &str, config_id: u8, max_name_length: u8) -> Result<Self> {
        check_public_name(public_name)?;
        // SAFETY: EVP_HPKE_KEY_new takes no arguments and returns a new key or
        // null, which `from_ptr` turns into an error.
        let hpke = HpkeKey::from_ptr(unsafe { sys::EVP_HPKE_KEY_new() }, "EVP_HPKE_KEY_new")?;
        // SAFETY: `hpke` is a fresh key owned here; EVP_hpke_x25519_hkdf_sha256
        // returns a pointer to a static KEM table. AWS-LC draws the key from its
        // own random number generator.
        ffi::check(
            unsafe {
                sys::EVP_HPKE_KEY_generate(hpke.as_ptr(), sys::EVP_hpke_x25519_hkdf_sha256())
            },
            "EVP_HPKE_KEY_generate",
        )?;
        let private = raw_private_key(&hpke)?;
        let config = marshal_config(&hpke, config_id, public_name, max_name_length)?;
        let fields = ConfigFields::parse(&config)?;

        let key = Self {
            hpke,
            private,
            config,
            config_id,
            public_name: public_name.to_owned(),
            suites: fields.suites,
        };
        // The same check `from_pem` makes, so a generated key is one this
        // server will load.
        key.keys()?;
        Ok(key)
    }

    /// Reads and checks a key file.
    ///
    /// Errors name the file, prefixed `server.ech_key = <path>`, because that is
    /// where an operator has to look.
    pub fn load(path: &Path) -> Result<Self> {
        let what = || format!("server.ech_key = {}", path.display());
        let text = Zeroizing::new(
            std::fs::read(path).with_context(|| format!("failed to read {}", what()))?,
        );
        Self::from_pem(&text).with_context(what)
    }

    /// Parses the two PEM blocks and checks that they belong together.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let mut key_der: Option<Zeroizing<Vec<u8>>> = None;
        let mut list: Option<Vec<u8>> = None;
        for item in <(SectionKind, Vec<u8>)>::pem_slice_iter(pem) {
            let (kind, der) = item.context("not a well-formed PEM file")?;
            match kind {
                SectionKind::PrivateKey => {
                    ensure!(
                        key_der.is_none(),
                        "it holds more than one PRIVATE KEY block"
                    );
                    key_der = Some(Zeroizing::new(der));
                }
                SectionKind::EchConfigList => {
                    ensure!(list.is_none(), "it holds more than one ECHCONFIG block");
                    list = Some(der);
                }
                other => bail!(
                    "it holds a {other:?} block, and an ECH key file holds only a PRIVATE KEY and an ECHCONFIG"
                ),
            }
        }
        let key_der = key_der.context("it holds no PRIVATE KEY block")?;
        let list = list.context("it holds no ECHCONFIG block")?;

        let config = single_config(&list)?.to_vec();
        let fields = ConfigFields::parse(&config)?;
        check_public_name(&fields.public_name)?;

        let private = x25519_from_pkcs8(&key_der)?;
        // SAFETY: as in `generate`.
        let hpke = HpkeKey::from_ptr(unsafe { sys::EVP_HPKE_KEY_new() }, "EVP_HPKE_KEY_new")?;
        // SAFETY: `hpke` is a fresh key owned here, the KEM table is static,
        // and `private` holds the 32 bytes whose length is passed. AWS-LC
        // copies them.
        let rc = unsafe {
            sys::EVP_HPKE_KEY_init(
                hpke.as_ptr(),
                sys::EVP_hpke_x25519_hkdf_sha256(),
                private.as_ptr(),
                private.len(),
            )
        };
        ffi::check(rc, "EVP_HPKE_KEY_init")?;

        let key = Self {
            hpke,
            private,
            config,
            config_id: fields.config_id,
            public_name: fields.public_name,
            suites: fields.suites,
        };
        // AWS-LC's own check of the pair: the version, the KEM, every HPKE
        // suite, every extension, and that the ECHConfig's public key is the
        // public half of the private key (`ECHServerConfig::Init`). Run here so
        // that `--check-config` and a reload refuse what startup would refuse.
        key.keys()
            .context("the PRIVATE KEY and the ECHCONFIG do not form a usable ECH key")?;
        Ok(key)
    }

    /// The key file's text: the private key and the ECHConfigList.
    pub fn to_pem(&self) -> Zeroizing<String> {
        let mut der = Zeroizing::new(Vec::with_capacity(
            X25519_PKCS8_PREFIX.len() + X25519_KEY_LEN,
        ));
        der.extend_from_slice(&X25519_PKCS8_PREFIX);
        der.extend_from_slice(&self.private[..]);
        let mut out = Zeroizing::new(String::new());
        pem_block(&mut out, "PRIVATE KEY", &der);
        pem_block(&mut out, "ECHCONFIG", &self.config_list());
        out
    }

    /// The ECHConfigList a client is given: a two-byte length and the one
    /// ECHConfig. RFC 9849 §4 defines the ECHConfig; the list is the
    /// `ECHConfig ECHConfigList<4..2^16-1>` its DNS and TLS uses carry.
    pub fn config_list(&self) -> Vec<u8> {
        let len = u16::try_from(self.config.len())
            .expect("SSL_marshal_ech_config wrote an ECHConfig under 64 KiB");
        let mut list = Vec::with_capacity(2 + self.config.len());
        list.extend_from_slice(&len.to_be_bytes());
        list.extend_from_slice(&self.config);
        list
    }

    /// [`Self::config_list`] in standard base64 with padding (RFC 4648 §4),
    /// the form Surge's `ech-config` takes.
    pub fn config_list_base64(&self) -> String {
        base64(&self.config_list())
    }

    /// The ECHConfig's config_id.
    pub fn config_id(&self) -> u8 {
        self.config_id
    }

    /// The ECHConfig's public name.
    pub fn public_name(&self) -> &str {
        &self.public_name
    }

    /// Whether the outer ECH extension `ech` of the ClientHello body `body`
    /// opens under this key.
    ///
    /// This is the decryption libssl runs on the same bytes, done for the socket
    /// gate before libssl sees them. The checks that cost nothing come first:
    /// the config_id has to be this ECHConfig's, and the (KDF, AEAD) pair has
    /// to be one the ECHConfig lists, which RFC 9849 §7.1 puts ahead of the
    /// decryption: "The server verifies that the ECHConfig supports the cipher
    /// suite indicated by the ECHClientHello.cipher_suite and that the version
    /// of ECH indicated by the client matches the ECHConfig.version. If not,
    /// the server continues to the next candidate ECHConfig." The extension
    /// names no KEM; the KEM is the ECHConfig's, and the key file is refused at
    /// load unless it is DHKEM(X25519, HKDF-SHA256). Only then does HPKE run, as
    /// RFC 9849 §7.1 gives it:
    ///
    /// ```text
    /// context = SetupBaseR(ECHClientHello.enc, skR,
    ///                      "tls ech" || 0x00 || ECHConfig)
    /// EncodedClientHelloInner = context.Open(ClientHelloOuterAAD,
    ///                                        ECHClientHello.payload)
    /// ```
    ///
    /// where the associated data is the body with the payload zeroed, RFC 9849
    /// §5.2: "The ClientHelloOuterAAD is a serialized ClientHello structure,
    /// defined in Section 4.1.2 of \[RFC8446\] for TLS and Section 5.3 of
    /// \[RFC9147\] for DTLS, which matches the ClientHelloOuter except that the
    /// payload field of the "encrypted_client_hello" is replaced with a byte
    /// string of the same length but whose contents are zeros. This value does
    /// not include the Handshake structure's four-byte header in TLS nor the
    /// twelve-byte header in DTLS." AWS-LC builds both the same way:
    /// `ECHServerConfig::SetupContext` writes the label with its NUL and then
    /// the raw ECHConfig as `info`, and `ssl_client_hello_decrypt` copies the
    /// ClientHello body and zeroes the payload span for the AAD
    /// (`ssl/encrypted_client_hello.cc`). The serialized ECHConfig here is the
    /// one the key file holds, version and length included, which is the
    /// `raw` AWS-LC keeps for the same key.
    ///
    /// The inner ClientHello is decrypted into a buffer that is cleared on
    /// drop and is not returned: what the gate needs is whether the client
    /// holds this key. libssl decrypts it again when the handshake runs.
    pub fn opens(&self, body: &[u8], ech: &EchOuter) -> bool {
        if ech.config_id != self.config_id || !self.suites.contains(&(ech.kdf, ech.aead)) {
            return false;
        }
        let (Some(kdf), Some(aead)) = (hpke_kdf(ech.kdf), hpke_aead(ech.aead)) else {
            return false;
        };
        let (Some(enc), Some(payload)) = (body.get(ech.enc.clone()), body.get(ech.payload.clone()))
        else {
            return false;
        };

        let mut aad = body.to_vec();
        aad[ech.payload.clone()].fill(0);
        let mut info = Vec::with_capacity(INFO_LABEL.len() + self.config.len());
        info.extend_from_slice(INFO_LABEL);
        info.extend_from_slice(&self.config);

        // SAFETY: EVP_HPKE_CTX_new takes no arguments and returns a new context
        // or null, which `from_ptr` turns into an error.
        let Ok(ctx) = HpkeCtx::from_ptr(unsafe { sys::EVP_HPKE_CTX_new() }, "EVP_HPKE_CTX_new")
        else {
            return false;
        };
        let mut inner = Zeroizing::new(vec![0u8; payload.len()]);
        let mut written = 0usize;
        // SAFETY: `ctx` is a fresh context owned here; `self.hpke` is an
        // initialised key that AWS-LC only reads; `kdf` and `aead` are static
        // tables; `enc`, `info`, `payload` and `aad` are readable for the
        // lengths passed beside them, and `inner` is writable for its length,
        // which is the `max_out_len` passed. `written` receives the length
        // AWS-LC wrote. The context is freed on drop on every path.
        let opened = unsafe {
            sys::EVP_HPKE_CTX_setup_recipient(
                ctx.as_ptr(),
                self.hpke.as_ptr(),
                kdf,
                aead,
                enc.as_ptr(),
                enc.len(),
                info.as_ptr(),
                info.len(),
            ) == 1
                && sys::EVP_HPKE_CTX_open(
                    ctx.as_ptr(),
                    inner.as_mut_ptr(),
                    &mut written,
                    inner.len(),
                    payload.as_ptr(),
                    payload.len(),
                    aad.as_ptr(),
                    aad.len(),
                ) == 1
        };
        // A failure leaves its reason on this thread's error queue, which a
        // later failure on the same thread would otherwise report as its own.
        ffi::clear_errors();
        opened
    }

    /// The keys object an `SSL_CTX` takes, holding this one ECHConfig.
    ///
    /// The config is added with `is_retry_config = 1`. AWS-LC refuses a set
    /// with no retry config (`SSL_CTX_set1_ech_keys` fails with
    /// `ECH_SERVER_WOULD_HAVE_NO_RETRY_CONFIGS`), and RFC 9849 §7.1 asks the
    /// same: "If the server is configured with any ECHConfigs, it MUST include
    /// the "encrypted_client_hello" extension in its EncryptedExtensions with
    /// the "retry_configs" field set to one or more ECHConfig structures with
    /// up-to-date keys." So a ClientHello that carries an ECH extension this
    /// key does not open (GREASE, another key, a damaged payload) is answered
    /// on the outer ClientHello with this ECHConfigList in its
    /// EncryptedExtensions, which the client reads once it has the handshake
    /// keys. A ClientHello with no ECH extension gets no ECH extension back.
    pub(super) fn keys(&self) -> Result<EchKeys> {
        // SAFETY: SSL_ECH_KEYS_new takes no arguments and returns a new set or
        // null, which `from_ptr` turns into an error.
        let keys = EchKeys::from_ptr(unsafe { sys::SSL_ECH_KEYS_new() }, "SSL_ECH_KEYS_new")?;
        // SAFETY: `keys` is a fresh set nothing else holds yet; the config
        // buffer and the HPKE key are valid for the call. AWS-LC parses and
        // copies the config and takes its own copy of the key.
        let rc = unsafe {
            sys::SSL_ECH_KEYS_add(
                keys.as_ptr(),
                1,
                self.config.as_ptr(),
                self.config.len(),
                self.hpke.as_ptr(),
            )
        };
        ffi::check(rc, "SSL_ECH_KEYS_add")?;
        Ok(keys)
    }
}

/// AWS-LC's KDF table for an HPKE KDF id, if it is the one ECH uses.
///
/// HKDF-SHA256 alone, as in `ECHServerConfig::Init`, which refuses an
/// ECHConfig naming any other KDF. The id is compared with AWS-LC's own
/// rather than with a number written here.
fn hpke_kdf(id: u16) -> Option<*const sys::EVP_HPKE_KDF> {
    // SAFETY: both functions return or read a static KDF table.
    let kdf = unsafe { sys::EVP_hpke_hkdf_sha256() };
    // SAFETY: as above.
    (unsafe { sys::EVP_HPKE_KDF_id(kdf) } == id).then_some(kdf)
}

/// AWS-LC's AEAD table for an HPKE AEAD id: the three `get_ech_aead` in
/// `ssl/encrypted_client_hello.cc` accepts.
fn hpke_aead(id: u16) -> Option<*const sys::EVP_HPKE_AEAD> {
    // SAFETY: each function returns a pointer to a static AEAD table, and
    // `EVP_HPKE_AEAD_id` only reads one.
    unsafe {
        [
            sys::EVP_hpke_aes_128_gcm(),
            sys::EVP_hpke_aes_256_gcm(),
            sys::EVP_hpke_chacha20_poly1305(),
        ]
        .into_iter()
        .find(|aead| sys::EVP_HPKE_AEAD_id(*aead) == id)
    }
}

/// One serialized ECHConfig for `hpke`, from AWS-LC's `SSL_marshal_ech_config`,
/// which also applies the public name rules of [`check_public_name`].
fn marshal_config(
    hpke: &HpkeKey,
    config_id: u8,
    public_name: &str,
    max_name_length: u8,
) -> Result<Vec<u8>> {
    let name = std::ffi::CString::new(public_name).context("the public name contains a NUL")?;
    let mut out = std::ptr::null_mut();
    let mut out_len = 0usize;
    // SAFETY: `hpke` is an initialised HPKE key, `name` a NUL-terminated
    // string that outlives the call, and both out-pointers are valid for
    // writes. On success AWS-LC allocates the buffer that `OpensslBytes` then
    // owns and frees.
    let rc = unsafe {
        sys::SSL_marshal_ech_config(
            &mut out,
            &mut out_len,
            config_id,
            hpke.as_ptr(),
            name.as_ptr(),
            usize::from(max_name_length),
        )
    };
    ffi::check(rc, "SSL_marshal_ech_config")?;
    let config = OpensslBytes::from_raw(out, out_len, "SSL_marshal_ech_config")?;
    Ok(config.as_slice().to_vec())
}

/// The raw 32 bytes of an initialised X25519 HPKE key.
fn raw_private_key(hpke: &HpkeKey) -> Result<Zeroizing<[u8; X25519_KEY_LEN]>> {
    let mut private = Zeroizing::new([0u8; X25519_KEY_LEN]);
    let mut len = 0usize;
    // SAFETY: `hpke` is initialised, `private` is writable for the maximum
    // length passed, and `len` is valid for a write.
    let rc = unsafe {
        sys::EVP_HPKE_KEY_private_key(
            hpke.as_ptr(),
            private.as_mut_ptr(),
            &mut len,
            X25519_KEY_LEN,
        )
    };
    ffi::check(rc, "EVP_HPKE_KEY_private_key")?;
    ensure!(len == X25519_KEY_LEN, "an X25519 key of {len} bytes");
    Ok(private)
}

/// The raw private key of a PKCS#8 X25519 key.
fn x25519_from_pkcs8(der: &[u8]) -> Result<Zeroizing<[u8; X25519_KEY_LEN]>> {
    let pkey =
        ffi::private_key_from_der(der).context("the PRIVATE KEY block is not a PKCS#8 key")?;
    // SAFETY: `pkey` is a parsed key owned here; EVP_PKEY_id only reads it.
    let id = unsafe { sys::EVP_PKEY_id(pkey.as_ptr()) };
    ensure!(
        id == sys::EVP_PKEY_X25519,
        "the PRIVATE KEY block is not an X25519 key, which is the only ECH key AWS-LC serves"
    );
    let mut private = Zeroizing::new([0u8; X25519_KEY_LEN]);
    let mut len = X25519_KEY_LEN;
    // SAFETY: `pkey` is an X25519 key; `private` is writable for `len` bytes,
    // which is passed in and receives the length written.
    let rc =
        unsafe { sys::EVP_PKEY_get_raw_private_key(pkey.as_ptr(), private.as_mut_ptr(), &mut len) };
    ffi::check(rc, "EVP_PKEY_get_raw_private_key")?;
    ensure!(len == X25519_KEY_LEN, "an X25519 key of {len} bytes");
    Ok(private)
}

/// The one ECHConfig inside an ECHConfigList.
fn single_config(list: &[u8]) -> Result<&[u8]> {
    let (len, rest) = list
        .split_first_chunk::<2>()
        .context("the ECHCONFIG block is too short to be an ECHConfigList")?;
    ensure!(
        usize::from(u16::from_be_bytes(*len)) == rest.len(),
        "the ECHCONFIG block's length field does not match its contents"
    );
    let (header, _) = rest
        .split_first_chunk::<4>()
        .context("the ECHConfigList holds no ECHConfig")?;
    let config_len = 4 + usize::from(u16::from_be_bytes([header[2], header[3]]));
    ensure!(
        config_len <= rest.len(),
        "the ECHConfig is longer than the ECHConfigList that holds it"
    );
    ensure!(
        config_len == rest.len(),
        "the ECHConfigList holds more than one ECHConfig, and this server serves one"
    );
    Ok(rest)
}

/// The fields of one ECHConfig this server reports.
#[derive(Debug, PartialEq, Eq)]
struct ConfigFields {
    config_id: u8,
    public_name: String,
    /// `HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>`, as (KDF, AEAD).
    suites: Vec<(u16, u16)>,
}

impl ConfigFields {
    /// Reads the ECHConfig layout of RFC 9849 §4 far enough to find the
    /// config_id and the public name. AWS-LC checks the rest when the key is
    /// added (`EchKey::keys`).
    fn parse(config: &[u8]) -> Result<Self> {
        let mut r = Reader::new(config);
        let version = r.u16().context(ENDS_EARLY)?;
        ensure!(
            version == ECH_VERSION,
            "the ECHConfig has version {version:#06x}, and this server reads {ECH_VERSION:#06x}"
        );
        let contents = r.vec16().context(ENDS_EARLY)?;
        ensure!(r.is_empty(), "bytes follow the ECHConfig");
        let mut r = Reader::new(contents);
        let config_id = r.u8().context(ENDS_EARLY)?;
        let kem = r.u16().context(ENDS_EARLY)?;
        ensure!(
            kem == KEM_X25519_HKDF_SHA256,
            "the ECHConfig names KEM {kem:#06x}, and this server serves only {KEM_X25519_HKDF_SHA256:#06x}"
        );
        r.vec16().context(ENDS_EARLY)?; // public_key
        let mut list = Reader::new(r.vec16().context(ENDS_EARLY)?);
        let mut suites = Vec::new();
        while !list.is_empty() {
            let kdf = list.u16().context(ENDS_EARLY)?;
            let aead = list.u16().context(ENDS_EARLY)?;
            suites.push((kdf, aead));
        }
        r.u8().context(ENDS_EARLY)?; // maximum_name_length
        let name = r.vec8().context(ENDS_EARLY)?;
        r.vec16().context(ENDS_EARLY)?; // extensions
        ensure!(r.is_empty(), "bytes follow the ECHConfig's extensions");
        let public_name =
            String::from_utf8(name.to_vec()).context("the ECHConfig's public name is not text")?;
        Ok(Self {
            config_id,
            public_name,
            suites,
        })
    }
}

/// What a read off the end of an ECHConfig is reported as.
const ENDS_EARLY: &str = "the ECHConfig ends early";

/// Refuses a public name a client would ignore the ECHConfig for.
///
/// RFC 9849 §4 has `opaque public_name<1..255>`, and §6.1.7: "Clients SHOULD
/// ignore any ECHConfig structure with a public_name that is not a valid host
/// name in preferred name syntax (see Section 2 of \[DNS-TERMS\]). That is, to be
/// valid, the public_name needs to be a dot-separated sequence of LDH labels,
/// as defined in Section 2.3.1 of \[RFC5890\], where: * the sequence does not
/// begin or end with an ASCII dot, and * all labels are at most 63 octets.
/// Clients additionally SHOULD ignore the structure if the final LDH label
/// either consists of all ASCII digits (i.e., '0' through '9') or is "0x" or
/// "0X" followed by some, possibly empty, sequence of ASCII hexadecimal digits
/// (i.e., '0' through '9', 'a' through 'f', and 'A' through 'F')."
///
/// An LDH label is ASCII letters, digits and the hyphen, with no hyphen first or
/// last. AWS-LC's `ssl_is_valid_ech_public_name` applies the same rules, and
/// `SSL_marshal_ech_config` refuses a name that fails them; this check comes
/// first so that the error says which rule.
pub fn check_public_name(name: &str) -> Result<()> {
    ensure!(!name.is_empty(), "the ECH public name is empty");
    ensure!(
        name.len() <= 255,
        "the ECH public name is {} bytes, and an ECHConfig holds at most 255",
        name.len()
    );
    ensure!(
        !name.starts_with('.') && !name.ends_with('.'),
        "the ECH public name {name:?} begins or ends with a dot"
    );
    let mut last = "";
    for label in name.split('.') {
        ensure!(
            !label.is_empty(),
            "the ECH public name {name:?} has an empty label"
        );
        ensure!(
            label.len() <= 63,
            "the ECH public name {name:?} has a label longer than 63 bytes"
        );
        ensure!(
            label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "the ECH public name {name:?} has a character outside ASCII letters, digits and '-'"
        );
        ensure!(
            !label.starts_with('-') && !label.ends_with('-'),
            "the ECH public name {name:?} has a label that begins or ends with '-'"
        );
        last = label;
    }
    let all_digits = last.bytes().all(|b| b.is_ascii_digit());
    let hex = last
        .strip_prefix("0x")
        .or_else(|| last.strip_prefix("0X"))
        .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_hexdigit()));
    ensure!(
        !all_digits && !hex,
        "the ECH public name {name:?} ends in a numeric label, which a client reads as an IPv4 address"
    );
    Ok(())
}

/// Appends one PEM block, 64 base64 characters to a line.
pub(super) fn pem_block(out: &mut String, label: &str, der: &[u8]) {
    let text = Zeroizing::new(base64(der));
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for line in text.as_bytes().chunks(64) {
        // base64 output is ASCII, so every chunk is valid UTF-8.
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
}

/// Standard base64 with padding (RFC 4648 §4).
pub(crate) fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                let index = usize::try_from((n >> (18 - 6 * i)) & 0x3f).unwrap_or(0);
                out.push(char::from(ALPHABET[index]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10: "BASE64("") = """, "BASE64("f") = "Zg=="" and the rest
    /// of that list.
    #[test]
    fn base64_matches_rfc_4648() {
        for (input, output) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), output);
        }
    }

    /// A generated key written out and read back is the same key: the same
    /// ECHConfigList, config_id and public name, and the same file text.
    #[test]
    fn a_key_file_reads_back_as_the_key_that_wrote_it() {
        let key = EchKey::generate("public.example", 7, 32).expect("generate");
        let pem = key.to_pem();
        let back = EchKey::from_pem(pem.as_bytes()).expect("read back");
        assert_eq!(back.config_list(), key.config_list());
        assert_eq!(back.config_id(), 7);
        assert_eq!(back.public_name(), "public.example");
        assert_eq!(*back.to_pem(), *pem);
        assert!(
            pem.starts_with("-----BEGIN PRIVATE KEY-----\n"),
            "{}",
            &*pem
        );
        assert!(pem.contains("-----BEGIN ECHCONFIG-----\n"), "{}", &*pem);

        // Two keys differ, so the file is what pins the list.
        let other = EchKey::generate("public.example", 7, 32).expect("generate");
        assert_ne!(other.config_list(), key.config_list());
    }

    /// The list carries what the file fixes: version 0xfe0d, the config_id, the
    /// X25519 KEM, the two suites `SSL_marshal_ech_config` writes, the maximum
    /// name length and the public name.
    #[test]
    fn the_list_carries_the_fields_the_key_was_generated_with() {
        let key = EchKey::generate("public.example", 9, 40).expect("generate");
        let list = key.config_list();
        let config = single_config(&list).expect("one config");
        assert_eq!(config[..2], [0xfe, 0x0d]);
        assert_eq!(config[4], 9);
        assert_eq!(config[5..7], [0x00, 0x20]);
        // public_key<1..2^16-1>: 32 bytes of X25519.
        assert_eq!(config[7..9], [0x00, 0x20]);
        let rest = &config[41..];
        // (HKDF-SHA256, AES-128-GCM) and (HKDF-SHA256, ChaCha20-Poly1305).
        assert_eq!(
            rest[..10],
            [0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x03]
        );
        assert_eq!(rest[10], 40);
        assert_eq!(usize::from(rest[11]), "public.example".len());
        assert_eq!(&rest[12..12 + 14], b"public.example");
        assert_eq!(rest[26..], [0x00, 0x00]);
    }

    /// The PKCS#8 form written for the private key is one AWS-LC's parser reads
    /// back as the same X25519 key.
    #[test]
    fn the_private_key_is_written_as_pkcs8_x25519() {
        let key = EchKey::generate("public.example", 1, 0).expect("generate");
        let mut der = X25519_PKCS8_PREFIX.to_vec();
        der.extend_from_slice(&key.private[..]);
        assert_eq!(der.len(), 48);
        assert_eq!(*x25519_from_pkcs8(&der).expect("parses"), *key.private);
    }

    fn file_with(key: &EchKey, list: &[u8]) -> String {
        let mut der = X25519_PKCS8_PREFIX.to_vec();
        der.extend_from_slice(&key.private[..]);
        let mut out = String::new();
        pem_block(&mut out, "PRIVATE KEY", &der);
        pem_block(&mut out, "ECHCONFIG", list);
        out
    }

    #[track_caller]
    fn refused(text: &str, says: &str) {
        let error = EchKey::from_pem(text.as_bytes()).expect_err("must be refused");
        let message = format!("{error:#}");
        assert!(message.contains(says), "expected {says:?} in: {message}");
    }

    /// Every way a key file can be wrong is refused, with a reason.
    #[test]
    fn a_bad_key_file_is_refused_with_its_reason() {
        let key = EchKey::generate("public.example", 1, 0).expect("generate");
        let other = EchKey::generate("public.example", 1, 0).expect("generate");
        let good = key.to_pem();

        refused("", "no PRIVATE KEY block");
        refused("not pem at all\n", "no PRIVATE KEY block");

        let only_key: String = good
            .split("-----BEGIN ECHCONFIG")
            .next()
            .unwrap_or_default()
            .to_owned();
        refused(&only_key, "no ECHCONFIG block");

        let mut key_only_list = String::new();
        pem_block(&mut key_only_list, "ECHCONFIG", &key.config_list());
        refused(&key_only_list, "no PRIVATE KEY block");

        // Two of a block.
        refused(
            &format!("{}{}", *good, key_only_list),
            "more than one ECHCONFIG",
        );
        refused(
            &format!("{}{}", only_key, *good),
            "more than one PRIVATE KEY",
        );

        // A block of another kind.
        let mut cert = String::new();
        pem_block(&mut cert, "CERTIFICATE", b"anything");
        refused(&format!("{}{cert}", *good), "Certificate");

        // The key of one ECHConfig with the ECHConfig of another.
        refused(
            &file_with(&key, &other.config_list()),
            "do not form a usable ECH key",
        );

        // A list whose length field lies, and a list with two configs.
        let mut list = key.config_list();
        list[1] ^= 1;
        refused(&file_with(&key, &list), "length field does not match");
        let mut two = key.config.clone();
        two.extend_from_slice(&key.config);
        let mut list = u16::try_from(two.len())
            .expect("short")
            .to_be_bytes()
            .to_vec();
        list.extend_from_slice(&two);
        refused(&file_with(&key, &list), "more than one ECHConfig");

        // A version this server does not read.
        let mut config = key.config.clone();
        config[1] = 0x0c;
        let mut list = u16::try_from(config.len())
            .expect("short")
            .to_be_bytes()
            .to_vec();
        list.extend_from_slice(&config);
        refused(&file_with(&key, &list), "version 0xfe0c");

        // A private key that is not X25519.
        let p256 = rcgen::KeyPair::generate().expect("an ECDSA key");
        let mut text = String::new();
        pem_block(&mut text, "PRIVATE KEY", &p256.serialize_der());
        pem_block(&mut text, "ECHCONFIG", &key.config_list());
        refused(&text, "not an X25519 key");
    }

    /// The public name rules of RFC 9849 §6.1.7, each one red on its own row.
    #[test]
    fn public_names_a_client_would_ignore_are_refused() {
        for good in [
            "public.example",
            "a",
            "a-b.example",
            "xn--bcher-kva.example",
            "host1.example",
            "example.0a",
            "0x1g",
        ] {
            check_public_name(good).unwrap_or_else(|e| panic!("{good:?} refused: {e:#}"));
            EchKey::generate(good, 1, 0).unwrap_or_else(|e| panic!("{good:?}: {e:#}"));
        }
        let hpke = EchKey::generate("public.example", 1, 0)
            .expect("generate")
            .hpke;
        let long_label = "a".repeat(64);
        let long_name = format!("{}.example", vec!["a".repeat(63); 4].join("."));
        for (bad, says) in [
            ("", "empty"),
            (".example", "begins or ends with a dot"),
            ("example.", "begins or ends with a dot"),
            ("a..example", "empty label"),
            (long_label.as_str(), "longer than 63"),
            (long_name.as_str(), "at most 255"),
            ("under_score.example", "outside ASCII"),
            ("caf\u{e9}.example", "outside ASCII"),
            ("-a.example", "begins or ends with '-'"),
            ("a-.example", "begins or ends with '-'"),
            ("192.0.2.1", "numeric label"),
            ("host.123", "numeric label"),
            ("host.0x1f", "numeric label"),
            ("host.0X", "numeric label"),
        ] {
            let error = check_public_name(bad).expect_err(bad);
            assert!(format!("{error}").contains(says), "{bad:?}: {error}");
            // AWS-LC refuses the same names, so the check is no stricter than
            // what `SSL_marshal_ech_config` does on its own.
            assert!(EchKey::generate(bad, 1, 0).is_err(), "{bad:?}");
            assert!(
                marshal_config(&hpke, 1, bad, 0).is_err(),
                "AWS-LC took {bad:?}"
            );
        }
    }
}
