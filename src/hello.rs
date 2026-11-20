//! The TLS bytes this server reads for itself: a ClientHello and the
//! `encrypted_client_hello` extension in it.
//!
//! libssl parses every ClientHello it is handed, and it is the parser that
//! decides a handshake. Three places read the same bytes first, without
//! libssl: the socket gate ([`crate::gate`]), which judges a first flight
//! before quinn has seen it; the TLS provider (`tls::awslc`), which reads the
//! outer ClientHello for one debug line; and the tests, which find and alter
//! extensions in ClientHellos a real client wrote. They share this one module,
//! so that a field read one way in the gate cannot be read another way in the
//! provider. The ECHConfig reader in `tls::awslc` uses [`Reader`] from here as
//! well.
//!
//! Every function takes a borrowed slice and answers with an `Option` or an
//! enum, and every read is bounds-checked: all of these bytes are chosen by a
//! peer that has not authenticated. Nothing here allocates except
//! [`extensions`], whose list has one entry per extension the ClientHello
//! declared and so is bounded by its length.

#![forbid(unsafe_code)]

use std::ops::Range;

/// The TLS `client_hello` handshake message type (RFC 8446 §4).
pub const CLIENT_HELLO: u8 = 1;

/// The most Initial-level CRYPTO bytes libssl takes, so the longest
/// ClientHello it reads.
///
/// libssl's own limit for that level (`SSL_quic_max_handshake_flight_len`,
/// 16384 at `ssl_encryption_initial`): `SSL_provide_quic_data` refuses a flight
/// that would grow past it, so nothing past it can be a ClientHello libssl
/// reads. The gate's hold reassembles no more than this, and the TLS provider
/// keeps no more than this for reading the outer ClientHello.
pub const MAX_INITIAL_FLIGHT: usize = 16 * 1024;

/// The `server_name` extension type. RFC 6066 §1.1: "server_name(0)".
pub const EXT_SERVER_NAME: u16 = 0;

/// The `encrypted_client_hello` extension type. RFC 9849 §5:
/// "encrypted_client_hello(0xfe0d), (65535)".
pub const EXT_ECH: u16 = 0xfe0d;

/// The `host_name` NameType of a `server_name` entry (RFC 6066 §3).
const HOST_NAME: u8 = 0;

/// The outer variant of `ECHClientHelloType`. RFC 9849 §5: "enum { outer(0),
/// inner(1) } ECHClientHelloType;".
const ECH_OUTER: u8 = 0;

/// A cursor over bytes that never panics and never wraps.
///
/// TLS structures are length-prefixed all the way down and every one of those
/// lengths is peer-chosen, so each read is an `Option` and a `None` propagates.
/// [`Reader::position`] says how far into the original slice the cursor is,
/// which is how [`extensions`] reports where each extension's data lies.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    /// A cursor at the start of `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// How many bytes have been read.
    pub fn position(&self) -> usize {
        self.at
    }

    /// Whether every byte has been read.
    pub fn is_empty(&self) -> bool {
        self.at >= self.bytes.len()
    }

    /// The next `count` bytes.
    pub fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(count)?;
        let bytes = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(bytes)
    }

    /// One byte.
    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    /// A big-endian 16-bit integer.
    pub fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// A big-endian 24-bit integer, the length of a handshake message.
    pub fn u24(&mut self) -> Option<usize> {
        let bytes = self.take(3)?;
        Some((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
    }

    /// A vector with a one-byte length prefix.
    pub fn vec8(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u8()?);
        self.take(length)
    }

    /// A vector with a two-byte length prefix.
    pub fn vec16(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }
}

/// How far a run of handshake bytes is from being a ClientHello.
#[derive(Debug, PartialEq, Eq)]
pub enum Message<'a> {
    /// Not enough bytes yet to say, or a ClientHello whose declared length
    /// has not all arrived.
    Incomplete,
    /// The first handshake message is something other than a ClientHello.
    NotAClientHello,
    /// A whole ClientHello: its body, without the four-byte handshake header.
    ClientHello(&'a [u8]),
}

/// Reads the first handshake message out of the start of a CRYPTO stream.
///
/// Only the declared length decides whether the message is whole, so a cut
/// anywhere before its last byte is [`Message::Incomplete`], whichever field it
/// lands in. Bytes after the message are not looked at.
pub fn client_hello(handshake: &[u8]) -> Message<'_> {
    let mut reader = Reader::new(handshake);
    let Some(kind) = reader.u8() else {
        return Message::Incomplete;
    };
    if kind != CLIENT_HELLO {
        return Message::NotAClientHello;
    }
    let Some(length) = reader.u24() else {
        return Message::Incomplete;
    };
    match reader.take(length) {
        Some(body) => Message::ClientHello(body),
        None => Message::Incomplete,
    }
}

/// The ClientHello body if `handshake` starts with a whole ClientHello.
pub fn client_hello_body(handshake: &[u8]) -> Option<&[u8]> {
    match client_hello(handshake) {
        Message::ClientHello(body) => Some(body),
        Message::Incomplete | Message::NotAClientHello => None,
    }
}

/// What a first flight's CRYPTO bytes said about the name being asked for.
#[derive(Debug, PartialEq, Eq)]
pub enum FirstFlight<'a> {
    /// The ClientHello is not all here yet.
    Truncated,
    /// The first handshake message is something other than a ClientHello.
    NotAClientHello,
    /// A whole ClientHello with no `server_name` extension.
    Anonymous,
    /// The host name it asked for, as it arrived, borrowed out of the CRYPTO
    /// bytes it was read from.
    Named(&'a [u8]),
}

/// Reads the `server_name` a first flight asks for.
///
/// The one judgement that has to be made carefully is between "no name" and
/// "not all here": a ClientHello may be spread over several Initial packets,
/// and refusing one because its extensions had not arrived would turn a large
/// first flight into an unreachable server. So every read that runs off the end
/// of the message *length* is [`FirstFlight::Truncated`], and only a message
/// whose declared length is entirely present can be [`FirstFlight::Anonymous`].
/// A whole message that does not parse names nobody.
pub fn first_flight(crypto: &[u8]) -> FirstFlight<'_> {
    match client_hello(crypto) {
        Message::Incomplete => FirstFlight::Truncated,
        Message::NotAClientHello => FirstFlight::NotAClientHello,
        Message::ClientHello(body) => match server_name(body) {
            Some(name) => FirstFlight::Named(name),
            None => FirstFlight::Anonymous,
        },
    }
}

/// The extension block of a ClientHello body, with the position in `body` at
/// which it starts.
///
/// The fields ahead of it are skipped by their own length prefixes, which is
/// the layout of RFC 8446 §4.1.2: `legacy_version`, `random`,
/// `legacy_session_id`, `cipher_suites`, `legacy_compression_methods`, then
/// `extensions`. A ClientHello that ends before the block has none, and is
/// `None` here.
fn extension_block(body: &[u8]) -> Option<(usize, &[u8])> {
    let mut reader = Reader::new(body);
    reader.take(2)?; // legacy_version
    reader.take(32)?; // random
    reader.vec8()?; // legacy_session_id
    reader.vec16()?; // cipher_suites
    reader.vec8()?; // legacy_compression_methods
    let length = usize::from(reader.u16()?);
    let start = reader.position();
    Some((start, reader.take(length)?))
}

/// The data of the first extension of `kind` in a ClientHello body.
///
/// The block is walked from the front and the walk stops at the first match,
/// so an extension is found even when what follows it in the block is
/// malformed. That is how libssl looks one up too
/// (`ssl_client_hello_get_extension`), once it has checked the whole message.
fn find_extension(body: &[u8], kind: u16) -> Option<&[u8]> {
    let (_, block) = extension_block(body)?;
    let mut reader = Reader::new(block);
    while !reader.is_empty() {
        let found = reader.u16()?;
        let data = reader.vec16()?;
        if found == kind {
            return Some(data);
        }
    }
    None
}

/// Every extension in a ClientHello body: its type and the byte range of its
/// data within `body`.
///
/// Stricter than the lookup [`server_name`] makes: the block has to end exactly where the
/// body does and every extension in it has to parse, which is what libssl
/// requires of a ClientHello before it reads any extension
/// (`ssl_parse_client_hello_with_trailing_data` and the `CBS_len(&cbs) != 0`
/// test after it).
///
/// `None` is a block that is absent or whose framing does not parse. That is
/// not the same set as the ClientHellos libssl refuses, in either direction.
/// libssl reads a ClientHello that ends after `legacy_compression_methods` as
/// one without extensions, and this returns `None` for it. libssl refuses a
/// ClientHello that repeats an extension type (`tls1_check_duplicate_extensions`),
/// and this returns both entries. Neither ClientHello can complete a QUIC
/// handshake: the first carries no `supported_versions` and no transport
/// parameters, and libssl refuses the second.
pub fn extensions(body: &[u8]) -> Option<Vec<(u16, Range<usize>)>> {
    let mut out = Vec::new();
    walk_extensions(body, |kind, range| out.push((kind, range)))?;
    Some(out)
}

/// Calls `visit` with the type and data range of every extension in `body`,
/// in order, under the framing rule of [`extensions`], and `None` where that
/// returns `None`. The one walk both [`extensions`] and [`ech`] make, so the
/// two cannot judge the framing differently.
fn walk_extensions(body: &[u8], mut visit: impl FnMut(u16, Range<usize>)) -> Option<()> {
    let (start, block) = extension_block(body)?;
    if start.checked_add(block.len())? != body.len() {
        return None;
    }
    let mut reader = Reader::new(block);
    while !reader.is_empty() {
        let kind = reader.u16()?;
        let length = usize::from(reader.u16()?);
        let at = start.checked_add(reader.position())?;
        reader.take(length)?;
        visit(kind, at..at.checked_add(length)?);
    }
    Some(())
}

/// The `host_name` of a ClientHello body's `server_name` extension, as sent.
///
/// The first `host_name` entry, since RFC 6066 §3 allows one: "The
/// ServerNameList MUST NOT contain more than one name of the same name_type."
/// Entries of other types ahead of it are skipped by their own length.
pub fn server_name(body: &[u8]) -> Option<&[u8]> {
    let extension = find_extension(body, EXT_SERVER_NAME)?;
    let mut reader = Reader::new(extension);
    let list = reader.vec16()?;

    let mut reader = Reader::new(list);
    while !reader.is_empty() {
        let kind = reader.u8()?;
        let name = reader.vec16()?;
        if kind == HOST_NAME {
            return Some(name);
        }
    }
    None
}

/// The fields of an outer `encrypted_client_hello` extension, as RFC 9849 §5
/// lays them out:
///
/// ```text
/// struct {
///    ECHClientHelloType type;
///    select (ECHClientHello.type) {
///        case outer:
///            HpkeSymmetricCipherSuite cipher_suite;
///            uint8 config_id;
///            opaque enc<0..2^16-1>;
///            opaque payload<1..2^16-1>;
///        case inner:
///            Empty;
///    };
/// } ECHClientHello;
/// ```
///
/// `enc` and `payload` are ranges into the ClientHello body the extension was
/// read from, because the HPKE associated data is that body with the payload
/// zeroed in place (RFC 9849 §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchOuter {
    /// The HPKE KDF of `cipher_suite`.
    pub kdf: u16,
    /// The HPKE AEAD of `cipher_suite`.
    pub aead: u16,
    /// The config_id the client chose.
    pub config_id: u8,
    /// Where the HPKE encapsulated key lies in the body.
    pub enc: Range<usize>,
    /// Where the encrypted inner ClientHello lies in the body.
    pub payload: Range<usize>,
}

/// What a ClientHello says about ECH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ech {
    /// No `encrypted_client_hello` extension.
    Absent,
    /// An outer extension that parses.
    Outer(EchOuter),
    /// An `encrypted_client_hello` extension that is not a well-formed outer
    /// one: the inner variant, an unknown type, or fields that do not fit.
    Malformed,
}

/// What `body`'s `encrypted_client_hello` extension is, or `None` when the
/// ClientHello's extension block is absent or its framing does not parse
/// ([`extensions`]).
///
/// libssl ignores an extension of the inner type in a ClientHello it reads as
/// the outer one and alerts on an outer one it cannot parse
/// (`decrypt_ech` in `handshake_server.cc`); both are
/// [`Ech::Malformed`] here, because neither is an extension a key can open.
pub fn ech(body: &[u8]) -> Option<Ech> {
    let mut first = None;
    walk_extensions(body, |kind, range| {
        if kind == EXT_ECH && first.is_none() {
            first = Some(range);
        }
    })?;
    let Some(range) = first else {
        return Some(Ech::Absent);
    };
    Some(ech_fields(body, range).map_or(Ech::Malformed, Ech::Outer))
}

/// The outer ECH extension of a ClientHello body, if it carries one that
/// parses.
pub fn ech_outer(body: &[u8]) -> Option<EchOuter> {
    match ech(body)? {
        Ech::Outer(outer) => Some(outer),
        Ech::Absent | Ech::Malformed => None,
    }
}

/// Reads the outer variant out of the extension data at `range` of `body`.
fn ech_fields(body: &[u8], range: Range<usize>) -> Option<EchOuter> {
    let data = body.get(range.clone())?;
    let mut reader = Reader::new(data);
    if reader.u8()? != ECH_OUTER {
        return None;
    }
    let kdf = reader.u16()?;
    let aead = reader.u16()?;
    let config_id = reader.u8()?;
    let enc_length = usize::from(reader.u16()?);
    let enc_at = range.start.checked_add(reader.position())?;
    reader.take(enc_length)?;
    let payload_length = usize::from(reader.u16()?);
    let payload_at = range.start.checked_add(reader.position())?;
    reader.take(payload_length)?;
    // RFC 9849 §5 gives the payload a floor of one byte, and nothing may
    // follow it: libssl refuses the extension otherwise (`CBS_len(&body) != 0`).
    if payload_length == 0 || !reader.is_empty() {
        return None;
    }
    Some(EchOuter {
        kdf,
        aead,
        config_id,
        enc: enc_at..enc_at.checked_add(enc_length)?,
        payload: payload_at..payload_at.checked_add(payload_length)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello message with the given extensions block appended.
    fn client_hello_message(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0x00; 32]); // random
        body.push(0); // legacy_session_id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        body.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend_from_slice(extensions);

        let mut message = vec![CLIENT_HELLO];
        let length = body.len();
        message.extend_from_slice(&[
            u8::try_from(length >> 16).unwrap(),
            u8::try_from((length >> 8) & 0xff).unwrap(),
            u8::try_from(length & 0xff).unwrap(),
        ]);
        message.extend_from_slice(&body);
        message
    }

    /// One extension of `kind` carrying `data`.
    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    /// A `server_name` extension naming `host`.
    fn sni_extension(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let mut entry = vec![HOST_NAME];
        entry.extend_from_slice(&u16::try_from(host.len()).unwrap().to_be_bytes());
        entry.extend_from_slice(host);

        let mut list = u16::try_from(entry.len()).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&entry);
        extension(EXT_SERVER_NAME, &list)
    }

    /// An outer ECH extension with the given fields.
    fn ech_extension(config_id: u8, enc: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut data = vec![ECH_OUTER, 0x00, 0x01, 0x00, 0x01, config_id];
        data.extend_from_slice(&u16::try_from(enc.len()).unwrap().to_be_bytes());
        data.extend_from_slice(enc);
        data.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        data.extend_from_slice(payload);
        extension(EXT_ECH, &data)
    }

    #[test]
    fn a_client_hello_naming_a_host_is_read_back() {
        let hello = client_hello_message(&sni_extension("proxy.example"));
        assert_eq!(first_flight(&hello), FirstFlight::Named(b"proxy.example"));
    }

    /// The extension is found even when it is not the first one.
    #[test]
    fn extensions_are_walked_rather_than_assumed_to_be_in_any_order() {
        let mut extensions = vec![0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]; // supported_versions
        extensions.extend_from_slice(&sni_extension("proxy.example"));
        let hello = client_hello_message(&extensions);

        assert_eq!(first_flight(&hello), FirstFlight::Named(b"proxy.example"));
    }

    #[test]
    fn a_complete_client_hello_without_the_extension_names_nobody() {
        let hello = client_hello_message(&[]);
        assert_eq!(first_flight(&hello), FirstFlight::Anonymous);
    }

    /// The fail-open branch: a first flight larger than one Initial packet.
    ///
    /// Every prefix that stops before the message is complete has to read as
    /// truncated, whichever field the cut lands in. That is what stops a large
    /// ClientHello from being refused for a name it had not got to yet.
    #[test]
    fn a_client_hello_cut_short_is_truncated_not_anonymous() {
        let hello = client_hello_message(&sni_extension("proxy.example"));

        for cut in 0..hello.len() {
            assert_eq!(
                first_flight(&hello[..cut]),
                FirstFlight::Truncated,
                "a ClientHello cut at {cut} of {} bytes must fail open",
                hello.len()
            );
            assert_eq!(client_hello(&hello[..cut]), Message::Incomplete);
        }

        assert_eq!(first_flight(&hello), FirstFlight::Named(b"proxy.example"));
    }

    /// A cut inside the *extensions* is the case the design argument is about,
    /// and it is only truncated because the message length said so.
    #[test]
    fn extensions_cut_before_the_server_name_fail_open() {
        let mut extensions = vec![0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
        extensions.extend_from_slice(&sni_extension("proxy.example"));
        let hello = client_hello_message(&extensions);

        // Anywhere inside the extensions block, which is the tail of the message.
        let inside = hello.len() - 4;
        assert_eq!(first_flight(&hello[..inside]), FirstFlight::Truncated);
    }

    #[test]
    fn a_first_message_that_is_not_a_client_hello_is_refused() {
        // A ServerHello (2) is not something a client's first flight opens with.
        assert_eq!(first_flight(&[0x02, 0, 0, 0]), FirstFlight::NotAClientHello);
        assert_eq!(client_hello(&[0x02]), Message::NotAClientHello);
    }

    /// A `server_name` list whose declared lengths do not fit its own extension
    /// is malformed rather than truncated: the message length already said the
    /// whole ClientHello was here.
    #[test]
    fn a_malformed_server_name_extension_names_nobody() {
        let mut extension = EXT_SERVER_NAME.to_be_bytes().to_vec();
        extension.extend_from_slice(&[0x00, 0x04]); // extension length
        extension.extend_from_slice(&[0xff, 0xff, 0x00, 0x00]); // list length lies
        let hello = client_hello_message(&extension);

        assert_eq!(first_flight(&hello), FirstFlight::Anonymous);
    }

    /// The ClientHello inside the CRYPTO frame of RFC 9001 Appendix A.2, which
    /// asks for `example.com`.
    #[test]
    fn reads_the_server_name_of_the_rfc_9001_client_hello() {
        // The frame as the RFC prints it: type 0x06, offset 0, length 0x40f1.
        let frame = "060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
                     04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
                     616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
                     04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
                     baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
                     0d0010000e0403050306030203080408 050806002d00020101001c0002400100
                     3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
                     75300901100f088394c8f03e51570806 048000ffff";
        let frame: String = frame.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes: Vec<u8> = (8..frame.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&frame[i..i + 2], 16).expect("hex"))
            .collect();
        let body = client_hello_body(&bytes).expect("a whole ClientHello");
        assert_eq!(server_name(body), Some(&b"example.com"[..]));
        assert_eq!(ech(body), Some(Ech::Absent));
        assert!(extensions(body).is_some());
        assert!(client_hello_body(&bytes[..bytes.len() - 1]).is_none());
    }

    /// The ranges `extensions` reports are where each extension's data is.
    #[test]
    fn every_extension_is_reported_where_its_data_lies() {
        let mut block = extension(0x002b, &[0x02, 0x03, 0x04]);
        block.extend_from_slice(&sni_extension("a.example"));
        let hello = client_hello_message(&block);
        let body = client_hello_body(&hello).expect("whole");

        let all = extensions(body).expect("parses");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0, 0x002b);
        assert_eq!(&body[all[0].1.clone()], &[0x02, 0x03, 0x04]);
        assert_eq!(all[1].0, EXT_SERVER_NAME);
        assert!(body[all[1].1.clone()].ends_with(b"a.example"));
    }

    /// A block that does not end where the body does, or an extension that
    /// runs past the block, is a ClientHello libssl refuses, and so is one
    /// that `extensions` refuses; the lenient lookup the gate's name reading
    /// uses still finds what comes first.
    #[test]
    fn trailing_bytes_or_a_cut_extension_make_the_whole_list_unreadable() {
        let mut hello = client_hello_message(&sni_extension("a.example"));
        hello.push(0x00);
        // The message length now covers the trailing byte too.
        let length = u16::try_from(hello.len() - 4).unwrap().to_be_bytes();
        hello[1..4].copy_from_slice(&[0, length[0], length[1]]);
        let body = client_hello_body(&hello).expect("whole");
        assert_eq!(extensions(body), None);
        assert_eq!(ech(body), None);
        assert_eq!(server_name(body), Some(&b"a.example"[..]));
    }

    /// The outer ECH extension is read field by field, with the two ranges
    /// pointing at the bytes they name.
    #[test]
    fn an_outer_ech_extension_is_read_with_its_enc_and_payload() {
        let mut block = sni_extension("public.example");
        block.extend_from_slice(&ech_extension(7, &[0xe1; 32], &[0xa5; 40]));
        let hello = client_hello_message(&block);
        let body = client_hello_body(&hello).expect("whole");

        let Some(Ech::Outer(outer)) = ech(body) else {
            panic!("an outer ECH extension")
        };
        assert_eq!((outer.kdf, outer.aead, outer.config_id), (1, 1, 7));
        assert_eq!(&body[outer.enc.clone()], &[0xe1; 32]);
        assert_eq!(&body[outer.payload.clone()], &[0xa5; 40]);
        assert_eq!(outer.payload.end, body.len());
        assert_eq!(ech_outer(body), Some(outer));
    }

    /// Each way an ECH extension can fail to be an outer one is `Malformed`,
    /// not `Absent`: the extension is there, and a gate must not mistake it
    /// for a ClientHello without one.
    #[test]
    fn an_ech_extension_that_is_not_a_whole_outer_one_is_malformed() {
        let inner = extension(EXT_ECH, &[0x01]);
        let empty_payload = ech_extension(1, &[0xe1; 32], &[]);
        let mut trailing = ech_extension(1, &[0xe1; 32], &[0xa5; 8]);
        trailing[3] += 1; // the extension length covers one more byte
        trailing.push(0x00);
        let mut cut = ech_extension(1, &[0xe1; 32], &[0xa5; 8]);
        cut.truncate(cut.len() - 1);
        cut[3] -= 1;
        for (what, ext) in [
            ("the inner variant", inner),
            ("an empty payload", empty_payload),
            ("a byte after the payload", trailing),
            ("a payload cut short", cut),
            ("an empty extension", extension(EXT_ECH, &[])),
        ] {
            let hello = client_hello_message(&ext);
            let body = client_hello_body(&hello).expect("whole");
            assert_eq!(ech(body), Some(Ech::Malformed), "{what}");
            assert_eq!(ech_outer(body), None, "{what}");
        }
    }

    /// The reader is total over arbitrary bytes, and so is everything built on
    /// it.
    #[test]
    fn every_reader_is_total_over_arbitrary_bytes() {
        for seed in 0u16..=255 {
            let bytes: Vec<u8> = (0..96u16)
                .map(|i| u8::try_from((i.wrapping_mul(37).wrapping_add(seed)) & 0xff).unwrap())
                .collect();
            for cut in [0, 1, 4, 40, 96] {
                let slice = &bytes[..cut];
                let _ = first_flight(slice);
                let _ = extensions(slice);
                let _ = ech(slice);
                let _ = server_name(slice);
            }
        }
    }
}
