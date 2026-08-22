//! What a request and a response are made of: a status, a method, field lines.
//!
//! These types replace the `http` crate, which this server reached for only
//! because the `h3` crate's API was written in it. It was never free: QPACK had
//! already produced a name and a value for every field when `HeaderName` and
//! `HeaderValue` validated and copied them a second time, and the pseudo-headers
//! were folded into a URI that [`crate::tunnel`] then took apart again. What a
//! proxy needs of an HTTP message is small enough to state here -- five
//! pseudo-headers, the fields that followed them, and a status line -- so a
//! field section is now decoded once, validated once, and carried in one type.
//!
//! # What belongs here
//!
//! Syntax: which octets a name, a value or a status may be made of. The rules
//! about a *message* -- which pseudo-headers a CONNECT request carries, what
//! makes one malformed -- belong to [`super::stream`], which is where a decoded
//! field section becomes a [`Request`] and where RFC 9114 §4.1.2's verdict is
//! reached.

use std::fmt;

/// A response status code (RFC 9110 §15).
///
/// Three decimal digits and nothing more: `:status` carries the code alone
/// (RFC 9114 §4.3.2), and the reason phrase that followed it in HTTP/1.1 has no
/// HTTP/3 representation at all. The digits are what is stored, because they are
/// what goes on the wire.
///
/// Only the codes this server sends have names. A code with no constant here is
/// one no path reaches, and adding one is how a new answer gets named rather
/// than spelled as a literal at the place it is sent from.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Status([u8; 3]);

impl Status {
    /// 200 OK: the tunnel is open (RFC 9114 §4.4).
    pub const OK: Self = Self(*b"200");
    /// 400 Bad Request: the request is not one this proxy can act on.
    pub const BAD_REQUEST: Self = Self(*b"400");
    /// 403 Forbidden: refused by this proxy's own policy (decision D11).
    pub const FORBIDDEN: Self = Self(*b"403");
    /// 407 Proxy Authentication Required (RFC 9110 §15.5.8).
    pub const PROXY_AUTHENTICATION_REQUIRED: Self = Self(*b"407");
    /// 431 Request Header Fields Too Large (RFC 6585 §5, RFC 9114 §4.2.2).
    pub const REQUEST_HEADER_FIELDS_TOO_LARGE: Self = Self(*b"431");
    /// 500 Internal Server Error: a fault on this side of the tunnel.
    pub const INTERNAL_SERVER_ERROR: Self = Self(*b"500");
    /// 501 Not Implemented: a method or `:protocol` this proxy does not serve.
    pub const NOT_IMPLEMENTED: Self = Self(*b"501");
    /// 502 Bad Gateway: the target refused the connection or could not be looked
    /// up (RFC 9209 §2.3.2).
    pub const BAD_GATEWAY: Self = Self(*b"502");
    /// 503 Service Unavailable: the target could not be reached at all, or this
    /// proxy is at a limit (RFC 9209 §2.3.2).
    pub const SERVICE_UNAVAILABLE: Self = Self(*b"503");
    /// 504 Gateway Timeout: the target never answered (RFC 9209 §2.3.2).
    pub const GATEWAY_TIMEOUT: Self = Self(*b"504");

    /// Reads a `:status` value.
    ///
    /// `None` for anything that is not three digits with a non-zero first one,
    /// which is the shape of every code RFC 9110 §15 defines.
    ///
    /// A server reads no responses, so this exists for the suite's client. It is
    /// here rather than there because a status is a status at both ends of the
    /// wire.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let digits: [u8; 3] = bytes.try_into().ok()?;
        if digits[0] == b'0' || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(Self(digits))
    }

    /// The three digits, as `:status` carries them.
    ///
    /// # Panics
    ///
    /// Never in practice: every constant here is an ASCII literal and
    /// [`Self::parse`] accepts nothing else, so the digits cannot be anything a
    /// `str` will not hold. The check is kept rather than made unchecked
    /// because it costs three comparisons on a path that writes a response.
    pub fn as_str(&self) -> &str {
        // ASCII digits by construction: every constant is a literal and `parse`
        // accepts nothing else.
        std::str::from_utf8(&self.0).expect("a status is three ASCII digits")
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A request method (RFC 9110 §9).
///
/// CONNECT is the only method this proxy serves, and it is a variant of its own
/// so that asking whether a request is one is a tag comparison rather than a
/// string compare. Every other method still has to be representable: a method
/// this server does not implement is answered with 501 (RFC 9110 §15.6.2),
/// which it cannot be if the token never survived parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    /// CONNECT (RFC 9110 §9.3.6), which for this server means a tunnel.
    Connect,
    /// Any other method. The payload is the token as it arrived.
    Other(Box<str>),
}

impl Method {
    /// Reads a `:method` value, or `None` if it is not a token.
    ///
    /// RFC 9110 §5.6.2's `token`: one or more `tchar`. A method name is
    /// case-sensitive (RFC 9110 §9.1), so nothing here folds case -- `connect`
    /// is not CONNECT and is answered with a 501 like any other method this
    /// server does not implement.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || !bytes.iter().all(|byte| is_tchar(*byte)) {
            return None;
        }

        // `tchar` is a subset of ASCII, so this cannot fail; it is written as a
        // fallible conversion rather than an `expect` because the bytes are a
        // peer's and nothing on that path should be able to panic.
        let token = std::str::from_utf8(bytes).ok()?;
        Some(match token {
            "CONNECT" => Self::Connect,
            other => Self::Other(other.into()),
        })
    }

    /// The method as it appears on the wire.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Connect => "CONNECT",
            Self::Other(token) => token,
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The value of one field line.
///
/// Bytes rather than a `str`: RFC 9110 §5.5 admits `obs-text` (%x80-FF) into a
/// field value, so one is not necessarily UTF-8. The single place this server
/// reads a value as text -- credentials -- asks for it with [`Self::to_str`] and
/// says what it does when the answer is no.
#[derive(Clone, PartialEq, Eq)]
pub struct FieldValue(Box<[u8]>);

impl FieldValue {
    /// Wraps a value this server authored.
    ///
    /// # Panics
    ///
    /// On an octet no field value may carry. The bound to `'static` is what
    /// makes that acceptable: the argument is a literal in this tree, so a panic
    /// here is a bug found by the first test that sends the field, never
    /// something a peer can provoke.
    pub fn from_static(value: &'static str) -> Self {
        assert!(
            is_field_value(value.as_bytes()),
            "{value:?} is not a field value"
        );
        Self(value.as_bytes().into())
    }

    /// Reads a value that arrived from a peer, or one built at runtime.
    ///
    /// `None` for an octet that may not appear in a field value; RFC 9114 §10.3
    /// makes that a malformed message, and [`super::stream`] is where it becomes
    /// one.
    ///
    /// The accepted set is `VCHAR` (%x21-7E), `obs-text` (%x80-FF), SP and HTAB
    /// -- so CR, LF, NUL, every other control character and DEL are refused.
    /// RFC 9110 §5.5's `field-content` additionally forbids a leading or
    /// trailing SP or HTAB, and that placement rule is deliberately not enforced
    /// here: §10.3's concern is the three characters that would be exploited by
    /// an intermediary translating the message, all three of which are refused,
    /// and refusing a value with a stray leading space would turn a request that
    /// every other HTTP/3 implementation accepts into a stream error.
    pub fn parse(value: &[u8]) -> Option<Self> {
        is_field_value(value).then(|| Self(value.into()))
    }

    /// The value as it appears on the wire.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The value as text, or `None` if it is not UTF-8.
    pub fn to_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// How many octets the value is.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value is the empty string, which is a legal field value.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for FieldValue {
    /// As text where the value is text, so a failing assertion is readable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_str() {
            Some(text) => fmt::Debug::fmt(text, f),
            None => write!(f, "{:?}", self.0),
        }
    }
}

/// The field lines of a request or a response, in the order they arrived.
///
/// A list rather than a map, because a field section is a list: RFC 9110 §5.3
/// lets a name repeat, and the order of the values under one name is part of
/// what they mean. Lookups walk it, which for the two or three fields a CONNECT
/// request carries is what any map would have done more slowly.
///
/// Names are compared without regard to case. On the wire they are lowercase
/// already -- RFC 9114 §4.2 makes an uppercase one malformed, and
/// [`super::stream`] enforces it -- so the folding is not what makes a lookup
/// find the field; it is what keeps a lookup from depending on that rule holding
/// somewhere else.
#[derive(Debug, Clone, Default)]
pub struct Fields(Vec<(Box<str>, FieldValue)>);

impl Fields {
    /// An empty field section.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Adds a field, keeping every value a repeated name already had.
    ///
    /// The name must be a lowercase token, since it goes on the wire as it is
    /// given and RFC 9114 §4.2 makes an uppercase one malformed. Asserted in
    /// debug builds, and for the reason [`FieldValue::from_static`] gives: every
    /// name this server appends is a literal in this tree or one
    /// [`field_name`] has already accepted, so a violation is a bug rather than
    /// something a peer can provoke -- and a release build has no business
    /// panicking over it.
    pub fn append(&mut self, name: impl Into<Box<str>>, value: FieldValue) {
        let name = name.into();
        debug_assert!(
            field_name(name.as_bytes()).is_some(),
            "{name:?} is not a field name"
        );
        self.0.push((name, value));
    }

    /// The first value of `name`, or `None` if there is none.
    pub fn get(&self, name: &str) -> Option<&FieldValue> {
        self.0
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    /// Every value of `name`, in the order they arrived.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a FieldValue> {
        self.0
            .iter()
            .filter(move |(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    /// Whether any field is named `name`.
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Every field line, in the order they arrived.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &FieldValue)> {
        self.0.iter().map(|(name, value)| (&**name, value))
    }

    /// How many field lines there are, counting a repeated name once per value.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no field lines at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<N: Into<Box<str>>> FromIterator<(N, FieldValue)> for Fields {
    fn from_iter<I: IntoIterator<Item = (N, FieldValue)>>(fields: I) -> Self {
        Self(
            fields
                .into_iter()
                .map(|(name, value)| (name.into(), value))
                .collect(),
        )
    }
}

/// A request: the pseudo-headers of RFC 9114 §4.3, then the fields that followed
/// them.
///
/// [`super::stream`] builds one out of a decoded field section, which is where
/// every rule that makes a request malformed is applied: by the time one of
/// these exists, all of them have been passed. The suite's client builds them
/// too, with [`Request::new`], because the pseudo-headers a client sends are the
/// pseudo-headers a server reads.
#[derive(Debug, Clone)]
pub struct Request {
    /// The `:method` pseudo-header.
    pub method: Method,
    /// The `:scheme` pseudo-header, which a classic CONNECT omits
    /// (RFC 9114 §4.4).
    pub scheme: Option<Box<str>>,
    /// The authority this request names.
    ///
    /// Its `:authority` pseudo-header, or the Host field where RFC 9114 §4.3.1
    /// lets that stand in for one -- the two are required to agree, so which of
    /// them it came from changes nothing downstream.
    pub authority: Option<Box<str>>,
    /// The path part of `:path`: everything before the first "?".
    ///
    /// RFC 9114 §4.3.1 makes `:path` "the path and query parts of the target
    /// URI", and the two are kept apart here because the RFC 9298 template is
    /// one rule about the path and another about the query.
    pub path: Option<Box<str>>,
    /// The query part of `:path`: whatever followed the first "?".
    ///
    /// `Some("")` for a `:path` ending in "?", which is a query that is present
    /// and empty rather than one that is absent.
    pub query: Option<Box<str>>,
    /// The `:protocol` pseudo-header of an extended CONNECT (RFC 8441 §4).
    ///
    /// Kept as the token that arrived rather than mapped onto a fixed set, so a
    /// protocol this server does not implement can be answered with the 501
    /// RFC 9220 §3 calls for instead of being rejected as malformed before
    /// anything has looked at it.
    pub protocol: Option<Box<str>>,
    /// The regular field lines, in the order they arrived.
    pub fields: Fields,
}

impl Request {
    /// A request carrying `method` and nothing else.
    ///
    /// The parser fills every field at once and has no use for this; it is here
    /// for the suite's client, which sets one pseudo-header at a time.
    pub fn new(method: Method) -> Self {
        Self {
            method,
            scheme: None,
            authority: None,
            path: None,
            query: None,
            protocol: None,
            fields: Fields::new(),
        }
    }
}

/// The name of one field line, if it is one this server will accept.
///
/// Lowercase `tchar` and at least one of them: RFC 9110 §5.6.2's `token`
/// restricted by RFC 9114 §4.2's rule that a field name arriving with an
/// uppercase character makes the message malformed. Shared with the suite's
/// client, which holds the server to the same rule in the other direction.
pub fn field_name(bytes: &[u8]) -> Option<&str> {
    if bytes.is_empty()
        || !bytes
            .iter()
            .all(|byte| is_tchar(*byte) && !byte.is_ascii_uppercase())
    {
        return None;
    }

    // `tchar` is a subset of ASCII, so this cannot fail; written fallibly for
    // the reason `Method::parse` gives.
    std::str::from_utf8(bytes).ok()
}

/// Whether `byte` is an RFC 9110 §5.6.2 `tchar`.
///
/// Every VCHAR except the delimiters -- DQUOTE and `(),/:;<=>?@[\]{}`.
fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Whether every octet of `value` may appear in a field value.
///
/// The set [`FieldValue::parse`] documents, and the one place it is decided.
fn is_field_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| matches!(byte, 0x21..=0x7e | 0x80..=0xff | b' ' | b'\t'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(text: &str) -> FieldValue {
        FieldValue::parse(text.as_bytes()).expect("a field value")
    }

    fn fields(pairs: &[(&str, &str)]) -> Fields {
        pairs
            .iter()
            .map(|(name, text)| ((*name).to_owned(), value(text)))
            .collect()
    }

    /// A lookup folds case, so nothing depends on RFC 9114 §4.2's lowercase rule
    /// having been enforced somewhere else.
    #[test]
    fn a_lookup_ignores_the_case_of_the_name() {
        let fields = fields(&[("proxy-authorization", "Basic dXNlcjE6czNjcmV0")]);

        for name in [
            "proxy-authorization",
            "Proxy-Authorization",
            "PROXY-AUTHORIZATION",
            "pRoXy-AuThOrIzAtIoN",
        ] {
            assert_eq!(
                fields.get(name).map(FieldValue::as_bytes),
                Some(&b"Basic dXNlcjE6czNjcmV0"[..]),
                "{name} must find the field"
            );
            assert!(fields.contains(name));
        }

        assert_eq!(fields.get("authorization"), None);
        assert!(!fields.contains("authorization"));
    }

    /// A repeated name keeps every value, in the order they arrived: this is
    /// what lets `auth` try each credential the client sent.
    #[test]
    fn a_repeated_name_keeps_every_value_in_order() {
        let fields = fields(&[
            ("proxy-authorization", "first"),
            ("user-agent", "volto-test"),
            ("proxy-authorization", "second"),
        ]);

        let values: Vec<&[u8]> = fields
            .get_all("Proxy-Authorization")
            .map(FieldValue::as_bytes)
            .collect();
        assert_eq!(values, vec![&b"first"[..], &b"second"[..]]);

        // `get` is the first of them, not the last and not an arbitrary one.
        assert_eq!(fields.get("proxy-authorization"), Some(&value("first")));
        assert_eq!(fields.len(), 3);
    }

    /// Iteration is the arrival order, which is what the request log prints.
    #[test]
    fn iteration_is_the_order_the_fields_arrived_in() {
        let fields = fields(&[("b", "1"), ("a", "2"), ("b", "3")]);

        let seen: Vec<(&str, &str)> = fields
            .iter()
            .map(|(name, value)| (name, value.to_str().expect("text")))
            .collect();
        assert_eq!(seen, vec![("b", "1"), ("a", "2"), ("b", "3")]);
    }

    #[test]
    fn an_empty_field_section_is_empty() {
        let empty = Fields::new();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.get("proxy-authorization"), None);
        assert_eq!(empty.iter().count(), 0);
    }

    /// RFC 9114 §4.2 with RFC 9110 §5.6.2: a lowercase token, and nothing else.
    #[test]
    fn a_field_name_is_a_lowercase_token() {
        for name in [
            "proxy-authorization",
            "te",
            "x-volto-probe",
            "a1!#$%&'*+-.^_`|~",
        ] {
            assert_eq!(field_name(name.as_bytes()), Some(name));
        }

        for name in [
            &b"Proxy-Authorization"[..],
            b"TE",
            b"",
            b"user agent",
            b"user\tagent",
            b"user:agent",
            b"user(agent)",
            b"\xff",
            b":method",
        ] {
            assert_eq!(field_name(name), None, "{name:?} is not a field name");
        }
    }

    /// RFC 9114 §10.3's rule, whose point is that CR, LF and NUL never reach a
    /// downstream parser.
    #[test]
    fn a_field_value_admits_obs_text_but_no_control_characters() {
        for value in [
            &b"Basic dXNlcjE6czNjcmV0"[..],
            b"",
            b"?1",
            b"a b\tc",
            b" leading and trailing ",
            b"\x80\xff",
            b"\x21\x7e",
        ] {
            assert!(
                FieldValue::parse(value).is_some(),
                "{value:?} is a field value"
            );
        }

        for value in [
            &b"one\r\ntwo"[..],
            b"one\rtwo",
            b"one\ntwo",
            b"one\0two",
            b"one\x7ftwo",
            b"one\x1btwo",
        ] {
            assert!(
                FieldValue::parse(value).is_none(),
                "{value:?} is not a field value"
            );
        }
    }

    /// A value is not required to be UTF-8, and asking for it as text says so.
    #[test]
    fn a_value_that_is_not_utf8_survives_as_bytes() {
        let value = FieldValue::parse(b"Basic \xff\xfe").expect("a field value");
        assert_eq!(value.to_str(), None);
        assert_eq!(value.as_bytes(), b"Basic \xff\xfe");
        assert_eq!(value.len(), 8);
        assert!(!value.is_empty());
    }

    #[test]
    fn a_status_is_three_digits() {
        assert_eq!(Status::OK.as_str(), "200");
        assert_eq!(Status::PROXY_AUTHENTICATION_REQUIRED.as_str(), "407");
        assert_eq!(Status::GATEWAY_TIMEOUT.as_str(), "504");
        assert_eq!(format!("{}", Status::NOT_IMPLEMENTED), "501");

        assert_eq!(Status::parse(b"200"), Some(Status::OK));
        assert_eq!(
            Status::parse(b"431"),
            Some(Status::REQUEST_HEADER_FIELDS_TOO_LARGE)
        );
        for invalid in [
            &b"20"[..],
            b"2000",
            b"",
            b"0200",
            b"099",
            b"2 0",
            b"abc",
            b"20\xff",
        ] {
            assert_eq!(Status::parse(invalid), None, "{invalid:?} is not a status");
        }
    }

    /// The method this server serves is a variant; every other token survives so
    /// it can be answered with a 501.
    #[test]
    fn a_method_is_a_token_and_connect_is_the_one_that_matters() {
        assert_eq!(Method::parse(b"CONNECT"), Some(Method::Connect));
        assert_eq!(
            Method::parse(b"CONNECT").as_ref().map(Method::as_str),
            Some("CONNECT")
        );

        for token in ["GET", "POST", "connect", "Connect", "M-SEARCH"] {
            assert_eq!(
                Method::parse(token.as_bytes()),
                Some(Method::Other(token.into())),
                "{token} is not CONNECT"
            );
        }

        for invalid in [&b""[..], b"GET POST", b"GET\r\n", b"GE(T", b"\xff"] {
            assert_eq!(Method::parse(invalid), None, "{invalid:?} is not a method");
        }
    }
}
