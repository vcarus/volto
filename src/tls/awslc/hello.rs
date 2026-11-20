//! Just enough ClientHello parsing to read the outer ClientHello.
//!
//! When ECH is accepted, AWS-LC reports the inner ClientHello everywhere,
//! including `SSL_get_servername`. The outer server name is still worth
//! logging beside it, so the provider reads it from the Initial CRYPTO bytes
//! itself. The tests use the same functions to find and corrupt the
//! `encrypted_client_hello` extension.
//!
//! Every function here reads a borrowed slice and returns `None` on anything
//! it does not understand, so a malformed ClientHello costs a debug field, not
//! a handshake: libssl parses the same bytes on its own and decides.

#![forbid(unsafe_code)]

use std::ops::Range;

/// The `encrypted_client_hello` extension type. RFC 9849 §5:
/// "encrypted_client_hello(0xfe0d), (65535)".
pub(crate) const EXT_ECH: u16 = 0xfe0d;
/// The `server_name` extension type. RFC 6066 §1.1: "server_name(0)".
const EXT_SERVER_NAME: u16 = 0;

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let byte = *self.buf.get(self.at)?;
        self.at += 1;
        Some(byte)
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(len)?;
        let bytes = self.buf.get(self.at..end)?;
        self.at = end;
        Some(bytes)
    }

    fn vec8(&mut self) -> Option<&'a [u8]> {
        let len = self.u8()?;
        self.take(usize::from(len))
    }

    fn vec16(&mut self) -> Option<&'a [u8]> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }
}

/// The ClientHello body if `handshake` starts with a complete ClientHello
/// message, or `None` while more bytes are needed or if it is not one.
pub(crate) fn client_hello_body(handshake: &[u8]) -> Option<&[u8]> {
    let (&kind, rest) = handshake.split_first()?;
    if kind != 1 || rest.len() < 3 {
        return None;
    }
    let len = usize::from(rest[0]) << 16 | usize::from(rest[1]) << 8 | usize::from(rest[2]);
    rest.get(3..3usize.checked_add(len)?)
}

/// Every extension in a ClientHello body: its type and the byte range of its
/// data within `body`.
pub(crate) fn extensions(body: &[u8]) -> Option<Vec<(u16, Range<usize>)>> {
    let mut r = Reader { buf: body, at: 0 };
    r.take(2 + 32)?; // legacy_version, random
    r.vec8()?; // legacy_session_id
    r.vec16()?; // cipher_suites
    r.vec8()?; // legacy_compression_methods
    let block_len = usize::from(r.u16()?);
    let end = r.at.checked_add(block_len)?;
    if end != body.len() {
        return None;
    }
    let mut out = Vec::new();
    while r.at < end {
        let kind = r.u16()?;
        let len = usize::from(r.u16()?);
        let start = r.at;
        r.take(len)?;
        out.push((kind, start..start + len));
    }
    Some(out)
}

/// The host_name in a ClientHello body's `server_name` extension.
pub(crate) fn server_name(body: &[u8]) -> Option<String> {
    let (_, range) = extensions(body)?
        .into_iter()
        .find(|(kind, _)| *kind == EXT_SERVER_NAME)?;
    let mut r = Reader {
        buf: &body[range],
        at: 0,
    };
    let mut list = Reader {
        buf: r.vec16()?,
        at: 0,
    };
    while list.at < list.buf.len() {
        let name_type = list.u8()?;
        let name = list.vec16()?;
        if name_type == 0 {
            return String::from_utf8(name.to_vec()).ok();
        }
    }
    None
}

/// What the outer `encrypted_client_hello` extension says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EchOuter {
    /// The config_id the client chose.
    pub(crate) config_id: u8,
    /// Length of the HPKE encapsulated key.
    pub(crate) enc_len: usize,
    /// Length of the encrypted inner ClientHello.
    pub(crate) payload_len: usize,
}

/// The outer ECH extension of a ClientHello body, if it carries one.
pub(crate) fn ech_outer(body: &[u8]) -> Option<EchOuter> {
    let (_, range) = extensions(body)?
        .into_iter()
        .find(|(kind, _)| *kind == EXT_ECH)?;
    let mut r = Reader {
        buf: &body[range],
        at: 0,
    };
    // RFC 9849 §5: "enum { outer(0), inner(1) } ECHClientHelloType;".
    if r.u8()? != 0 {
        return None;
    }
    r.take(4)?; // HpkeSymmetricCipherSuite
    let config_id = r.u8()?;
    let enc_len = r.vec16()?.len();
    let payload_len = r.vec16()?.len();
    Some(EchOuter {
        config_id,
        enc_len,
        payload_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(server_name(body).as_deref(), Some("example.com"));
        assert_eq!(ech_outer(body), None);
        assert!(client_hello_body(&bytes[..bytes.len() - 1]).is_none());
    }
}
