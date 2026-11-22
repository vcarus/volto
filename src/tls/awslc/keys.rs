//! QUIC packet protection from TLS traffic secrets (RFC 9001 §5).
//!
//! AWS-LC's QUIC interface hands over traffic secrets and the negotiated
//! cipher, and leaves the packet protection to the caller. This module turns a
//! secret into the four things quinn asks for: a packet key, a header
//! protection key, the Initial keys of a connection ID, and the key update
//! secret. It is safe code over aws-lc-rs, which is linked from the same AWS-LC
//! build as libssl, and it uses the same AEAD and header protection primitives
//! rustls's QUIC keys use.
//!
//! The keys of every level are made here, the Initial keys included. rustls
//! exports the Initial keys (`quic::Keys::initial`), but no way to make a
//! packet key from a secret libssl hands over: `KeyBuilder`, `Secrets::new`
//! and `AeadKey::with_length` are `pub(crate)`, and `AeadKey`'s public
//! constructor makes 32-byte keys only, so an AES-128 key cannot be built from
//! outside. One implementation for every level is simpler than two. Neither
//! quinn nor rustls exports the Retry key. The unit tests below check every
//! value against RFC 9001 Appendix A.

#![forbid(unsafe_code)]

use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf;
use bytes::BytesMut;
use quinn_proto::Side;
use quinn_proto::crypto::{CryptoError, HeaderKey, KeyPair, Keys, PacketKey};
use zeroize::Zeroizing;

/// The three TLS 1.3 cipher suites QUIC can run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Suite {
    /// TLS_AES_128_GCM_SHA256 (0x1301).
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384 (0x1302).
    Aes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256 (0x1303).
    Chacha20Poly1305Sha256,
}

impl Suite {
    /// The suite for an IANA cipher suite number, if QUIC can use it.
    pub(crate) fn from_protocol_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    fn hkdf(self) -> hkdf::Algorithm {
        match self {
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => hkdf::HKDF_SHA256,
            Self::Aes256GcmSha384 => hkdf::HKDF_SHA384,
        }
    }

    fn aead(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128GcmSha256 => &aead::AES_128_GCM,
            Self::Aes256GcmSha384 => &aead::AES_256_GCM,
            Self::Chacha20Poly1305Sha256 => &aead::CHACHA20_POLY1305,
        }
    }

    fn header(self) -> &'static aead::quic::Algorithm {
        match self {
            Self::Aes128GcmSha256 => &aead::quic::AES_128,
            Self::Aes256GcmSha384 => &aead::quic::AES_256,
            Self::Chacha20Poly1305Sha256 => &aead::quic::CHACHA20,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::Chacha20Poly1305Sha256 => 32,
        }
    }

    /// RFC 9001 §6.6, "For AEAD_AES_128_GCM and AEAD_AES_256_GCM, the
    /// confidentiality limit is 2^23 encrypted packets", and "For
    /// AEAD_CHACHA20_POLY1305, the confidentiality limit is greater than the
    /// number of possible packets (2^62) and so can be disregarded."
    fn confidentiality_limit(self) -> u64 {
        match self {
            Self::Aes128GcmSha256 | Self::Aes256GcmSha384 => 1 << 23,
            Self::Chacha20Poly1305Sha256 => u64::MAX,
        }
    }

    /// RFC 9001 §6.6, "For AEAD_AES_128_GCM and AEAD_AES_256_GCM, the
    /// integrity limit is 2^52 invalid packets" and "For
    /// AEAD_CHACHA20_POLY1305, the integrity limit is 2^36 invalid packets".
    fn integrity_limit(self) -> u64 {
        match self {
            Self::Aes128GcmSha256 | Self::Aes256GcmSha384 => 1 << 52,
            Self::Chacha20Poly1305Sha256 => 1 << 36,
        }
    }
}

/// QUIC versions this provider derives keys for, which are the ones quinn's
/// own rustls provider accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Version {
    /// QUIC version 1 (RFC 9000).
    V1,
    /// Drafts 29 to 32, which share one salt and one Retry key.
    Draft,
}

impl Version {
    /// The same mapping as quinn-proto's `interpret_version`
    /// (`src/crypto/rustls.rs`), so this provider accepts exactly the versions
    /// the rustls provider it replaces accepted.
    pub(crate) fn from_wire(version: u32) -> Option<Self> {
        match version {
            0xff00_001d..=0xff00_0020 => Some(Self::Draft),
            0x0000_0001 | 0xff00_0021..=0xff00_0022 => Some(Self::V1),
            _ => None,
        }
    }

    fn initial_salt(self) -> &'static [u8; 20] {
        match self {
            // RFC 9001 §5.2: "initial_salt =
            // 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a".
            Self::V1 => &[
                0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
            ],
            // Drafts 29 to 32 of the QUIC TLS document: the value of
            // rustls's `quic::Version::V1Draft` `initial_salt`. Not an RFC, so
            // not quoted.
            Self::Draft => &[
                0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61,
                0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
            ],
        }
    }

    fn retry_key_and_nonce(self) -> (&'static [u8; 16], &'static [u8; 12]) {
        match self {
            // RFC 9001 §5.8: "The secret key, K, is 128 bits equal to
            // 0xbe0c690b9f66575a1d766b54e368c84e." and "The nonce, N, is 96
            // bits equal to 0x461599d35d632bf2239825bb."
            Self::V1 => (
                &[
                    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3,
                    0x68, 0xc8, 0x4e,
                ],
                &[
                    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
                ],
            ),
            // quinn-proto's `RETRY_INTEGRITY_KEY_DRAFT` and
            // `RETRY_INTEGRITY_NONCE_DRAFT` (`src/crypto/rustls.rs`).
            Self::Draft => (
                &[
                    0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c,
                    0xb9, 0x6b, 0xe1,
                ],
                &[
                    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
                ],
            ),
        }
    }
}

/// An output length for aws-lc-rs's HKDF, which takes it as a type.
struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-Expand-Label from RFC 8446 §7.1 with an empty context, which is the
/// only form RFC 9001 uses.
fn expand_label(alg: hkdf::Algorithm, secret: &[u8], label: &[u8], out: &mut [u8]) {
    let prk = hkdf::Prk::new_less_safe(alg, secret);
    expand_label_prk(&prk, label, out);
}

fn expand_label_prk(prk: &hkdf::Prk, label: &[u8], out: &mut [u8]) {
    const PREFIX: &[u8] = b"tls13 ";
    // Every caller in this module passes a fixed label and a length of at most
    // 48 bytes, so both narrowings hold; a failure is a programming error.
    let length = u16::try_from(out.len()).expect("HKDF output length fits a u16");
    let label_len = u8::try_from(PREFIX.len() + label.len()).expect("label fits a u8");
    let length = length.to_be_bytes();
    let info: [&[u8]; 5] = [&length, &[label_len], PREFIX, label, &[0]];
    prk.expand(&info, Len(out.len()))
        .and_then(|okm| okm.fill(out))
        .expect("HKDF-Expand-Label with a fixed label and a short output");
}

/// One direction's traffic secret, with the suite that derived it.
///
/// The bytes are cleared when the value is dropped, so a secret that libssl
/// handed over and quinn no longer needs does not stay in freed memory.
#[derive(Clone)]
pub(crate) struct Secret {
    pub(crate) suite: Suite,
    pub(crate) bytes: Zeroizing<Vec<u8>>,
}

impl Secret {
    fn packet_key(&self) -> AeadPacketKey {
        let mut key = Zeroizing::new(vec![0u8; self.suite.key_len()]);
        expand_label(self.suite.hkdf(), &self.bytes, b"quic key", &mut key);
        let mut iv = [0u8; 12];
        expand_label(self.suite.hkdf(), &self.bytes, b"quic iv", &mut iv);
        AeadPacketKey {
            key: LessSafeKey::new(
                UnboundKey::new(self.suite.aead(), &key).expect("key length matches the suite"),
            ),
            iv,
            suite: self.suite,
        }
    }

    fn header_key(&self) -> AeadHeaderKey {
        let mut hp = Zeroizing::new(vec![0u8; self.suite.key_len()]);
        expand_label(self.suite.hkdf(), &self.bytes, b"quic hp", &mut hp);
        AeadHeaderKey(
            aead::quic::HeaderProtectionKey::new(self.suite.header(), &hp)
                .expect("key length matches the suite"),
        )
    }

    /// RFC 9001 §6.1: the next generation's secret, "quic ku".
    pub(crate) fn updated(&self) -> Self {
        let mut bytes = Zeroizing::new(vec![0u8; self.bytes.len()]);
        expand_label(self.suite.hkdf(), &self.bytes, b"quic ku", &mut bytes);
        Self {
            suite: self.suite,
            bytes,
        }
    }
}

/// quinn's `Keys` for one packet number space, from the local (write) and the
/// remote (read) secret of that space.
pub(crate) fn keys(local: &Secret, remote: &Secret) -> Keys {
    Keys {
        header: KeyPair {
            local: Box::new(local.header_key()),
            remote: Box::new(remote.header_key()),
        },
        packet: KeyPair {
            local: Box::new(local.packet_key()),
            remote: Box::new(remote.packet_key()),
        },
    }
}

/// quinn's packet key pair for one 1-RTT generation.
pub(crate) fn packet_keys(local: &Secret, remote: &Secret) -> KeyPair<Box<dyn PacketKey>> {
    KeyPair {
        local: Box::new(local.packet_key()),
        remote: Box::new(remote.packet_key()),
    }
}

/// The client and server Initial secrets of a connection ID (RFC 9001 §5.2).
pub(crate) fn initial_secrets(version: Version, dst_cid: &[u8]) -> (Secret, Secret) {
    let prk = initial_prk(version, dst_cid);
    (
        initial_secret(&prk, b"client in"),
        initial_secret(&prk, b"server in"),
    )
}

/// The `initial_secret` of RFC 9001 §5.2, which both Initial secrets expand.
fn initial_prk(version: Version, dst_cid: &[u8]) -> hkdf::Prk {
    hkdf::Salt::new(hkdf::HKDF_SHA256, version.initial_salt()).extract(dst_cid)
}

/// One side's Initial secret, `label` being "client in" or "server in".
fn initial_secret(prk: &hkdf::Prk, label: &[u8]) -> Secret {
    let mut bytes = Zeroizing::new(vec![0u8; 32]);
    expand_label_prk(prk, label, &mut bytes);
    Secret {
        suite: Suite::Aes128GcmSha256,
        bytes,
    }
}

/// The keys a client protects its Initial packets with: the half of the
/// Initial keys a server reads with.
pub(crate) struct ClientInitialKeys {
    pub(crate) header: Box<dyn HeaderKey>,
    pub(crate) packet: Box<dyn PacketKey>,
}

/// The client's Initial keys of `dst_cid`, without the server's.
///
/// For the socket gate, which opens a client's Initial and sends nothing. The
/// server's secret and its three keys are four of the nine HKDF operations
/// [`initial_keys`] runs, and the gate pays for a derivation on every first
/// packet, before any peer is known.
pub(crate) fn client_initial_keys(version: Version, dst_cid: &[u8]) -> ClientInitialKeys {
    let client = initial_secret(&initial_prk(version, dst_cid), b"client in");
    ClientInitialKeys {
        header: Box::new(client.header_key()),
        packet: Box::new(client.packet_key()),
    }
}

/// The Initial keys of `dst_cid` for `side`.
pub(crate) fn initial_keys(version: Version, dst_cid: &[u8], side: Side) -> Keys {
    let (client, server) = initial_secrets(version, dst_cid);
    match side {
        Side::Server => keys(&server, &client),
        Side::Client => keys(&client, &server),
    }
}

/// The Retry Integrity Tag over a Retry pseudo-packet (RFC 9001 §5.8).
pub(crate) fn retry_tag(version: Version, orig_dst_cid: &[u8], packet: &[u8]) -> [u8; 16] {
    let (key, nonce) = version.retry_key_and_nonce();
    let mut pseudo = Vec::with_capacity(1 + orig_dst_cid.len() + packet.len());
    // A connection ID is at most 20 bytes (RFC 9000 §17.2), which quinn's
    // `ConnectionId` enforces, so its length fits a byte.
    pseudo.push(u8::try_from(orig_dst_cid.len()).expect("a connection ID is at most 20 bytes"));
    pseudo.extend_from_slice(orig_dst_cid);
    pseudo.extend_from_slice(packet);
    let key = LessSafeKey::new(
        UnboundKey::new(&aead::AES_128_GCM, key).expect("a 16-byte AES-128-GCM key"),
    );
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(&pseudo[..]),
            &mut [],
        )
        .expect("sealing an empty plaintext cannot fail");
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_ref());
    out
}

/// A packet protection key: an AEAD key and the IV it is nonced from.
struct AeadPacketKey {
    key: LessSafeKey,
    /// A plain array rather than `Zeroizing`, unlike the key and the secrets.
    /// RFC 9001 §5.3 uses the IV only to form each packet's nonce: "The
    /// exclusive OR of the padded packet number and the IV forms the AEAD
    /// nonce." The protection rests on the key; a nonce has to be unique, not
    /// secret, so the IV is not key material. Our own reading.
    iv: [u8; 12],
    suite: Suite,
}

impl AeadPacketKey {
    /// RFC 9001 §5.3: "The 62 bits of the reconstructed QUIC packet number in
    /// network byte order are left-padded with zeros to the size of the IV.
    /// The exclusive OR of the padded packet number and the IV forms the AEAD
    /// nonce."
    fn nonce(&self, packet: u64) -> Nonce {
        let mut nonce = self.iv;
        for (byte, pn) in nonce[4..].iter_mut().zip(packet.to_be_bytes()) {
            *byte ^= pn;
        }
        Nonce::assume_unique_for_key(nonce)
    }
}

impl PacketKey for AeadPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, rest) = buf.split_at_mut(header_len);
        let tag_at = rest.len() - self.tag_len();
        let (payload, tag_storage) = rest.split_at_mut(tag_at);
        let tag = self
            .key
            .seal_in_place_separate_tag(self.nonce(packet), Aad::from(&*header), payload)
            .expect("a QUIC packet is far below the AEAD's size limit");
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plain_len = self
            .key
            .open_in_place(self.nonce(packet), Aad::from(header), payload.as_mut())
            .map_err(|_| CryptoError)?
            .len();
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.key.algorithm().tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        self.suite.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.suite.integrity_limit()
    }
}

/// A header protection key (RFC 9001 §5.4).
struct AeadHeaderKey(aead::quic::HeaderProtectionKey);

impl AeadHeaderKey {
    /// Applies or removes the mask; the two differ only in when the packet
    /// number length is read from the first byte.
    ///
    /// Indexes `packet` up to `pn_offset + 4 + sample_size()` without a check.
    /// Both callers make that length certain first: quinn-proto refuses a
    /// shorter packet before it removes header protection (`decrypt_header`),
    /// and the socket gate's `open_with` hands over a copy of exactly that
    /// length.
    fn xor_in_place(&self, pn_offset: usize, packet: &mut [u8], encrypting: bool) {
        let sample_at = pn_offset + 4;
        let sample_len = self.sample_size();
        let mask = self
            .0
            .new_mask(&packet[sample_at..sample_at + sample_len])
            .expect("the sample is the length the algorithm takes");
        let long_header = packet[0] & 0x80 != 0;
        let bits = if long_header { 0x0f } else { 0x1f };
        let pn_len = if encrypting {
            usize::from(packet[0] & 0x03) + 1
        } else {
            packet[0] ^= mask[0] & bits;
            usize::from(packet[0] & 0x03) + 1
        };
        if encrypting {
            packet[0] ^= mask[0] & bits;
        }
        for (byte, m) in packet[pn_offset..pn_offset + pn_len]
            .iter_mut()
            .zip(&mask[1..])
        {
            *byte ^= m;
        }
    }
}

impl HeaderKey for AeadHeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.xor_in_place(pn_offset, packet, false);
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.xor_in_place(pn_offset, packet, true);
    }

    fn sample_size(&self) -> usize {
        self.0.algorithm().sample_len()
    }
}

#[cfg(test)]
mod tests {
    //! Values from RFC 9001 Appendix A, copied from `dev_docs/rfc/rfc9001.txt`.

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    const CID: &str = "8394c8f03e515708";

    /// A.1: client_initial_secret and server_initial_secret, and the key, iv
    /// and hp of each.
    #[test]
    fn initial_secrets_and_keys_match_appendix_a1() {
        let (client, server) = initial_secrets(Version::V1, &hex(CID));
        assert_eq!(
            *client.bytes,
            hex("c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea")
        );
        assert_eq!(
            *server.bytes,
            hex("3c199828fd139efd216c155ad844cc81 fb82fa8d7446fa7d78be803acdda951b")
        );

        let expand = |secret: &Secret, label: &[u8], len: usize| {
            let mut out = vec![0u8; len];
            expand_label(secret.suite.hkdf(), &secret.bytes, label, &mut out);
            out
        };
        assert_eq!(
            expand(&client, b"quic key", 16),
            hex("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(
            expand(&client, b"quic iv", 12),
            hex("fa044b2f42a3fd3b46fb255c")
        );
        assert_eq!(
            expand(&client, b"quic hp", 16),
            hex("9f50449e04a0e810283a1e9933adedd2")
        );
        assert_eq!(
            expand(&server, b"quic key", 16),
            hex("cf3a5331653c364c88f0f379b6067e37")
        );
        assert_eq!(
            expand(&server, b"quic iv", 12),
            hex("0ac1493ca1905853b0bba03e")
        );
        assert_eq!(
            expand(&server, b"quic hp", 16),
            hex("c206b8d9b9f0f37644430b490eeaa314")
        );
    }

    /// A.2, header protection: "sample = d1b1c98dd7689fb8ec11d242b123dc9b",
    /// "mask = AES-ECB(hp, sample)[0..4] = 437b9aec36".
    #[test]
    fn client_initial_header_protection_matches_appendix_a2() {
        let (client, _) = initial_secrets(Version::V1, &hex(CID));
        let header = hex("c300000001088394c8f03e5157080000449e00000002");
        let sample = hex("d1b1c98dd7689fb8ec11d242b123dc9b");
        let mut packet = header.clone();
        packet.extend_from_slice(&sample);
        // The packet number starts after the 18 header bytes before it.
        client.header_key().encrypt(18, &mut packet);
        assert_eq!(
            packet[..header.len()],
            hex("c000000001088394c8f03e5157080000449e7b9aec34")[..]
        );
        client.header_key().decrypt(18, &mut packet);
        assert_eq!(packet[..header.len()], header[..]);
    }

    /// A.2: the whole client Initial, sealed with the client's Initial keys,
    /// which is how `gate::sealed_initial` seals a client's packet, and opened
    /// again with the same keys, which is how the socket gate opens one
    /// (`tls::client_initial_keys` is this call).
    #[test]
    fn client_initial_packet_matches_appendix_a2() {
        let keys = client_initial_keys(Version::V1, &hex(CID));
        let header = hex("c300000001088394c8f03e5157080000449e00000002");
        let mut payload = hex(
            "060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
             04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
             616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
             04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
             baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
             0d0010000e0403050306030203080408 050806002d00020101001c0002400100
             3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
             75300901100f088394c8f03e51570806 048000ffff",
        );
        // "plus enough PADDING frames to make a 1162-byte payload"
        payload.resize(1162, 0);
        let mut packet = header.clone();
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(&[0u8; 16]);
        keys.packet.encrypt(2, &mut packet, header.len());
        // The packet number is the last four header bytes.
        keys.header.encrypt(header.len() - 4, &mut packet);
        assert_eq!(
            packet,
            hex(
                "c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
                 d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
                 1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
                 8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
                 30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
                 457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
                 4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
                 4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
                 485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
                 059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
                 7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
                 9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
                 be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
                 68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
                 c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
                 f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
                 291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
                 25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
                 14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
                 ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
                 e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
                 c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
                 203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
                 cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
                 fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
                 a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
                 90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
                 162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
                 40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
                 6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
                 8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
                 be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
                 54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
                 760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
                 f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
                 056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
                 7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
                 e221af44860018ab0856972e194cd934"
            )
        );

        keys.header.decrypt(header.len() - 4, &mut packet);
        assert_eq!(packet[..header.len()], header[..]);
        let mut body = BytesMut::from(&packet[header.len()..]);
        keys.packet
            .decrypt(2, &header, &mut body)
            .expect("the RFC's packet opens");
        assert_eq!(&body[..], &payload[..]);
    }

    /// A.3: the whole server Initial, sealed with the server Initial keys
    /// through the trait objects quinn calls.
    #[test]
    fn server_initial_packet_matches_appendix_a3() {
        let keys = initial_keys(Version::V1, &hex(CID), Side::Server);
        let header = hex("c1000000010008f067a5502a4262b50040750001");
        let payload = hex(
            "02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739
             88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94
             0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00
             020304",
        );
        let mut packet = header.clone();
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(&[0u8; 16]);
        keys.packet.local.encrypt(1, &mut packet, header.len());
        // The packet number is the last two header bytes.
        keys.header.local.encrypt(header.len() - 2, &mut packet);
        assert_eq!(
            packet,
            hex(
                "cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a
                 5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3
                 dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84
                 022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4
                 2158407dd074ee"
            )
        );

        // And back, through the client's keys.
        let client = {
            let (client, server) = initial_secrets(Version::V1, &hex(CID));
            super::keys(&client, &server)
        };
        client.header.remote.decrypt(header.len() - 2, &mut packet);
        assert_eq!(packet[..header.len()], header[..]);
        let mut body = BytesMut::from(&packet[header.len()..]);
        client
            .packet
            .remote
            .decrypt(1, &header, &mut body)
            .expect("the RFC's packet opens");
        assert_eq!(&body[..], &payload[..]);
    }

    /// A.4: "ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f
    /// 0f2496ba", whose last 16 bytes are the tag over the rest.
    #[test]
    fn retry_tag_matches_appendix_a4() {
        let retry =
            hex("ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f 0f2496ba");
        let (body, tag) = retry.split_at(retry.len() - 16);
        assert_eq!(retry_tag(Version::V1, &hex(CID), body)[..], tag[..]);
    }

    /// A.5: the ChaCha20-Poly1305 short header packet, and the "quic ku"
    /// secret, which is the key update this provider performs.
    #[test]
    fn chacha20_short_header_and_key_update_match_appendix_a5() {
        let secret = Secret {
            suite: Suite::Chacha20Poly1305Sha256,
            bytes: Zeroizing::new(hex(
                "9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b",
            )),
        };
        assert_eq!(
            *secret.updated().bytes,
            hex("1223504755036d556342ee9361d25342 1a826c9ecdf3c7148684b36b714881f9")
        );

        let header = hex("4200bff4");
        let mut packet = header.clone();
        packet.push(0x01);
        packet.extend_from_slice(&[0u8; 16]);
        secret
            .packet_key()
            .encrypt(654_360_564, &mut packet, header.len());
        assert_eq!(
            packet[header.len()..],
            hex("655e5cd55c41f69080575d7999c25a5bfb")[..]
        );
        // "pn_offset" is 1: an empty Destination Connection ID.
        secret.header_key().encrypt(1, &mut packet);
        assert_eq!(packet, hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));
    }
}
