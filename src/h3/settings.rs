//! The SETTINGS frame's payload (RFC 9114 §7.2.4): the identifiers this
//! server knows, the payload it sends, and the parser of the peer's.

use std::collections::HashSet;

use bytes::BytesMut;

use crate::varint::{peek_varint, put_varint};

use super::MAX_FIELD_SECTION_SIZE;
use super::error::{Code, Violation};

/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (RFC 9204 §5).
pub const SETTING_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114 §7.2.4.1).
pub const SETTING_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
/// `SETTINGS_QPACK_BLOCKED_STREAMS` (RFC 9204 §5).
pub const SETTING_QPACK_BLOCKED_STREAMS: u64 = 0x07;
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 9220 §3).
pub const SETTING_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
/// `SETTINGS_H3_DATAGRAM` (RFC 9297 §2.1.1).
pub const SETTING_H3_DATAGRAM: u64 = 0x33;

/// Setting identifiers RFC 9114 §11.2.2 reserves because HTTP/2 used them.
const RESERVED_HTTP2_SETTINGS: [u64; 5] = [0x00, 0x02, 0x03, 0x04, 0x05];

/// The peer's SETTINGS, reduced to what this server acts on.
///
/// Only one setting changes any behaviour here: RFC 9297 §2.1.1 forbids sending
/// HTTP Datagrams until the peer has advertised support for them, and a
/// CONNECT-UDP session falls back to capsules on the request stream until it
/// has. Everything else is validated as the RFC requires and then dropped,
/// because keeping a value nothing reads is how a setting silently stops being
/// honoured.
///
/// One of the dropped values carries a SHOULD this server knowingly does not
/// honour:
///
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
//# An implementation that has received this parameter SHOULD NOT send an
//# HTTP message header that exceeds the indicated size, as the peer will
//# likely refuse to process it.
///
/// A peer's `SETTINGS_MAX_FIELD_SECTION_SIZE` is parsed, so that a malformed or
/// duplicated one is still caught, and then dropped. Every response this server
/// sends is a status line and at most two short fields, some 200 bytes by
/// §4.2.2's own accounting. Honouring the SHOULD would mean carrying the value
/// through the connection, the request and the response writer, and it would
/// only affect a peer advertising a limit small enough to refuse a bare `407`.
/// Such a peer cannot use this proxy anyway. Trimming fields to fit would also
/// mean dropping either a `Proxy-Status` explanation or a `Proxy-Authenticate`
/// challenge, and neither is better sent truncated than in full.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Settings {
    /// `SETTINGS_H3_DATAGRAM = 1`.
    pub datagrams: bool,
}

/// Parses a SETTINGS payload (RFC 9114 §7.2.4).
pub(super) fn parse_settings(mut payload: &[u8]) -> Result<Settings, Violation> {
    let mut settings = Settings::default();

    // A set rather than a list: the payload is bounded only by
    // `MAX_BUFFERED_FRAME`, and 64 KiB holds some sixteen thousand distinct
    // identifiers. A quadratic scan over them is work an unauthenticated peer
    // could ask for on its control stream. A SETTINGS frame on a request stream
    // is refused in `begin` from its header and never reaches this parser.
    let mut seen = HashSet::new();

    while !payload.is_empty() {
        let (identifier, used) = peek_varint(payload).ok_or_else(truncated_settings)?;
        payload = &payload[used..];
        let (value, used) = peek_varint(payload).ok_or_else(truncated_settings)?;
        payload = &payload[used..];

        if RESERVED_HTTP2_SETTINGS.contains(&identifier) {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
            //# These reserved settings MUST NOT be sent, and their receipt MUST
            //# be treated as a connection error of type H3_SETTINGS_ERROR.
            return Err(settings_error(format!(
                "setting {identifier:#x} is reserved for HTTP/2"
            )));
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
        //# The same setting identifier MUST NOT occur more than once in the
        //# SETTINGS frame.
        if !seen.insert(identifier) {
            return Err(settings_error(format!(
                "setting {identifier:#x} occurs more than once"
            )));
        }

        match identifier {
            //= https://www.rfc-editor.org/rfc/rfc9297#section-2.1.1
            //# If the SETTINGS_H3_DATAGRAM setting is received with a value
            //# that is neither 0 nor 1, the receiver MUST terminate the
            //# connection with error H3_SETTINGS_ERROR.
            SETTING_H3_DATAGRAM => settings.datagrams = boolean(identifier, value)?,

            // RFC 9220 §3 gives this setting the semantics it has in HTTP/2,
            // where RFC 8441 §3 constrains the value ("The value of the
            // parameter MUST be 0 or 1") but says of the direction this
            // server receives it in:
            //
            //= https://www.rfc-editor.org/rfc/rfc8441#section-3
            //# Receipt of this parameter by a server does not have any impact.
            //
            // So the setting has no meaning here, whatever its value. Nothing
            // in RFC 9114 §7.2.4 makes a malformed *value* of an otherwise
            // ignored setting a connection error, and closing on one would drop
            // tunnels over a field this server does not read. It is logged and
            // ignored.
            SETTING_ENABLE_CONNECT_PROTOCOL if value > 1 => tracing::debug!(
                value,
                "ignoring SETTINGS_ENABLE_CONNECT_PROTOCOL with a value other \
                 than 0 or 1, which has no meaning at a server"
            ),
            // Everything else is ignored: RFC 9114 §7.2.4 for an identifier
            // this server does not understand, §7.2.4.1 for a reserved one.
            _ => {}
        }
    }

    Ok(settings)
}

/// Reads a setting whose value the RFC restricts to 0 or 1.
fn boolean(identifier: u64, value: u64) -> Result<bool, Violation> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(settings_error(format!(
            "setting {identifier:#x} must be 0 or 1, not {other}"
        ))),
    }
}

/// A SETTINGS payload that ends in the middle of a pair.
///
/// H3_FRAME_ERROR rather than H3_SETTINGS_ERROR: this is a frame whose payload
/// does not hold the fields its length promised, which §7.1 answers for every
/// frame type alike, before any of §7.2.4's rules about *which* settings are
/// allowed can apply.
fn truncated_settings() -> Violation {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.1
    //# A frame payload that contains additional bytes after the identified
    //# fields or a frame payload that terminates before the end of the
    //# identified fields MUST be treated as a connection error of type
    //# H3_FRAME_ERROR.
    Violation::connection(Code::H3_FRAME_ERROR, "the SETTINGS payload ends mid-pair")
}

/// A SETTINGS payload whose identifiers or values break RFC 9114 §7.2.4's
/// rules, as opposed to its layout.
fn settings_error(detail: impl Into<std::borrow::Cow<'static, str>>) -> Violation {
    Violation::connection(Code::H3_SETTINGS_ERROR, detail)
}

/// The SETTINGS frame this server sends, payload only.
///
/// Surge validates `SETTINGS_ENABLE_CONNECT_PROTOCOL` and `SETTINGS_H3_DATAGRAM`
/// and disconnects without them. The two QPACK settings are sent as zeroes on
/// purpose: [`super::qpack`] says why they make a static-table-only decoder
/// correct.
///
/// Not public: [`super::connection`] is the one caller.
pub(super) fn settings_payload() -> BytesMut {
    /// One reserved identifier of the form 0x1f * N + 0x21, which RFC 9114
    /// §7.2.4.1 says endpoints SHOULD send so that peers keep exercising the
    /// rule that unknown identifiers are ignored.
    ///
    /// N is arbitrary: every value of it names a reserved identifier, and the
    /// test client and `it_settings` pick different ones only so that the three
    /// greases can be told apart in a packet capture.
    const GREASE: u64 = 0x1f * 8 + 0x21;

    let mut payload = BytesMut::new();
    for (identifier, value) in [
        (SETTING_QPACK_MAX_TABLE_CAPACITY, 0),
        (SETTING_QPACK_BLOCKED_STREAMS, 0),
        (SETTING_MAX_FIELD_SECTION_SIZE, MAX_FIELD_SECTION_SIZE),
        (SETTING_ENABLE_CONNECT_PROTOCOL, 1),
        (SETTING_H3_DATAGRAM, 1),
        (GREASE, 0),
    ] {
        put_varint(&mut payload, identifier);
        put_varint(&mut payload, value);
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(pairs: &[(u64, u64)]) -> Vec<u8> {
        let mut payload = BytesMut::new();
        for (identifier, value) in pairs {
            put_varint(&mut payload, *identifier);
            put_varint(&mut payload, *value);
        }
        payload.to_vec()
    }

    #[test]
    fn the_advertised_settings_are_the_ones_surge_checks_for() {
        let payload = settings_payload();
        let mut rest = &payload[..];
        let mut found = std::collections::HashMap::new();

        while !rest.is_empty() {
            let (identifier, used) = peek_varint(rest).expect("identifier");
            rest = &rest[used..];
            let (value, used) = peek_varint(rest).expect("value");
            rest = &rest[used..];
            assert!(found.insert(identifier, value).is_none(), "duplicate");
        }

        assert_eq!(found.get(&SETTING_ENABLE_CONNECT_PROTOCOL), Some(&1));
        assert_eq!(found.get(&SETTING_H3_DATAGRAM), Some(&1));
        assert_eq!(
            found.get(&SETTING_MAX_FIELD_SECTION_SIZE),
            Some(&MAX_FIELD_SECTION_SIZE)
        );
        assert_eq!(found.get(&SETTING_QPACK_MAX_TABLE_CAPACITY), Some(&0));
        assert_eq!(found.get(&SETTING_QPACK_BLOCKED_STREAMS), Some(&0));
    }

    /// What this server sends must survive its own parser, reserved-identifier
    /// and duplicate rules included.
    #[test]
    fn our_own_settings_parse() {
        let parsed = parse_settings(&settings_payload()).expect("parses");
        assert!(parsed.datagrams);
    }

    #[test]
    fn a_peer_that_enables_datagrams_is_recognised() {
        assert!(
            parse_settings(&settings(&[(SETTING_H3_DATAGRAM, 1)]))
                .expect("parses")
                .datagrams
        );
        assert!(
            !parse_settings(&settings(&[(SETTING_H3_DATAGRAM, 0)]))
                .expect("parses")
                .datagrams
        );
        // Absent means absent: RFC 9297 §2.1.1 defaults it to off.
        assert!(!parse_settings(&[]).expect("parses").datagrams);
    }

    #[test]
    fn unknown_and_grease_settings_are_ignored() {
        let parsed = parse_settings(&settings(&[
            (0x1f * 3 + 0x21, 0),
            (0x4242, 99),
            (SETTING_H3_DATAGRAM, 1),
        ]))
        .expect("parses");
        assert!(parsed.datagrams);
    }

    #[test]
    fn reserved_http2_setting_identifiers_are_refused() {
        for identifier in RESERVED_HTTP2_SETTINGS {
            let error = parse_settings(&settings(&[(identifier, 0)])).expect_err("refused");
            assert_eq!(error.code(), Code::H3_SETTINGS_ERROR);
            assert!(error.is_connection_error());
        }
    }

    #[test]
    fn a_repeated_setting_identifier_is_refused() {
        let error = parse_settings(&settings(&[
            (SETTING_H3_DATAGRAM, 1),
            (SETTING_H3_DATAGRAM, 1),
        ]))
        .expect_err("refused");
        assert_eq!(error.code(), Code::H3_SETTINGS_ERROR);
    }

    /// RFC 9297 §2.1.1 states the H3_DATAGRAM rule as a MUST on the receiver,
    /// so a value outside {0, 1} ends the connection.
    #[test]
    fn a_datagram_setting_with_another_value_is_refused() {
        let error = parse_settings(&settings(&[(SETTING_H3_DATAGRAM, 2)])).expect_err("refused");
        assert_eq!(error.code(), Code::H3_SETTINGS_ERROR);
        assert!(error.is_connection_error());

        // A setting whose value this server does not constrain is untouched.
        assert!(parse_settings(&settings(&[(SETTING_MAX_FIELD_SECTION_SIZE, 1 << 40)])).is_ok());
    }

    /// RFC 8441 §3: "Receipt of this parameter by a server does not have any
    /// impact." A value it never defined is ignored with the rest of it, rather
    /// than costing the peer its tunnels.
    #[test]
    fn enable_connect_protocol_is_ignored_whatever_its_value_is() {
        for value in [0, 1, 2, crate::varint::VARINT_MAX] {
            let parsed = parse_settings(&settings(&[
                (SETTING_ENABLE_CONNECT_PROTOCOL, value),
                (SETTING_H3_DATAGRAM, 1),
            ]))
            .unwrap_or_else(|error| panic!("value {value} must be ignored, got {error}"));
            assert!(parsed.datagrams, "the rest of the frame must still apply");
        }
    }

    /// RFC 9114 §7.1 answers a payload that ends before its fields do, whatever
    /// the frame type; §7.2.4's H3_SETTINGS_ERROR is for what the settings say,
    /// not for a frame that was cut short.
    #[test]
    fn a_settings_payload_that_ends_mid_pair_is_a_frame_error() {
        let mut payload = settings(&[(SETTING_H3_DATAGRAM, 1)]);
        payload.pop();
        let error = parse_settings(&payload).expect_err("refused");
        assert_eq!(error.code(), Code::H3_FRAME_ERROR);
        assert!(error.is_connection_error());

        // An identifier with no value at all is the same fault.
        let error = parse_settings(&[0x33]).expect_err("refused");
        assert_eq!(error.code(), Code::H3_FRAME_ERROR);
    }

    /// The parser is fed bytes from an unauthenticated peer, so it may reject
    /// anything but must never panic.
    #[test]
    fn arbitrary_bytes_never_panic_the_settings_parser() {
        proptest::proptest!(|(payload: Vec<u8>)| {
            let _ = parse_settings(&payload);
        });
    }
}
