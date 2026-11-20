//! Request validation: a decoded field section turned into a [`Request`], or
//! the reason it is malformed (RFC 9114 §4.1.2).
//!
//! Pure functions with no QUIC stream, called by `stream::read_request`. The
//! stream's life is in [`super::stream`].

use std::borrow::Cow;

use super::error::{Code, Violation};
use super::message::{self, FieldValue, Fields, Method, Request};
use super::qpack::Field;

/// Turns a decoded field section into a request, or says why it cannot.
///
/// Every rejection here is RFC 9114 §4.1.2's "malformed", and the checks are in
/// the order the RFC states them: field syntax (§4.2, §10.3), pseudo-header
/// placement and identity (§4.3), then the per-method shape (§4.3.1, §4.4,
/// RFC 8441 §4).
///
/// Public, though [`Resolver::resolve`](super::stream::Resolver::resolve) is the only caller the server has and
/// `crate::h3api` re-exports neither. It needs nothing but a decoded field
/// section, so `tests/it_fuzz.rs` states properties over arbitrary
/// pseudo-header *combinations* against it without one QUIC connection per
/// combination.
pub fn build_request(section: Vec<Field>) -> Result<Request, Violation> {
    let mut method = None;
    let mut scheme = None;
    let mut authority = None;
    let mut target = None;
    let mut protocol = None;
    let mut fields = Fields::new();
    let mut regular_field_seen = false;

    for Field { name, value } in section {
        if !name.starts_with(b":") {
            regular_field_seen = true;
            add_field(&mut fields, name, value)?;
            continue;
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //# All pseudo-header fields MUST appear in the header section before
        //# regular header fields.
        if regular_field_seen {
            return Err(malformed("a pseudo-header field after a regular field"));
        }

        let slot = match &name[..] {
            b":method" => &mut method,
            b":scheme" => &mut scheme,
            b":authority" => &mut authority,
            b":path" => &mut target,
            b":protocol" => &mut protocol,

            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
            //# Endpoints MUST NOT generate pseudo-header fields other than
            //# those defined in this document. [...] Endpoints MUST treat a
            //# request or response that contains undefined or invalid
            //# pseudo-header fields as malformed.
            _ => return Err(malformed("an undefined pseudo-header field")),
        };

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //# All HTTP/3 requests MUST include exactly one value for the :method,
        //# :scheme, and :path pseudo-header fields, unless the request is a
        //# CONNECT request; see Section 4.4.
        if slot.replace(value).is_some() {
            return Err(malformed("a repeated pseudo-header field"));
        }
    }

    let method = method.ok_or_else(|| malformed("a request without :method"))?;
    let method = Method::parse(&method).ok_or_else(|| malformed("an invalid :method"))?;

    // RFC 8441 §4 defines :protocol for the extended CONNECT method and for
    // nothing else, so on any other request it is a pseudo-header used outside
    // the context it was defined in.
    //
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
    //# Pseudo-header fields are only valid in the context in which they are
    //# defined. [...] Endpoints MUST treat a request or response that contains
    //# undefined or invalid pseudo-header fields as malformed.
    if protocol.is_some() && method != Method::Connect {
        return Err(malformed(":protocol on a request that is not CONNECT"));
    }

    let (scheme, authority, path, query) = if method == Method::Connect && protocol.is_none() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
        //# The :scheme and :path pseudo-header fields are omitted [...] The
        //# :authority pseudo-header field contains the host and port to
        //# connect to [...] A CONNECT request that does not conform to these
        //# restrictions is malformed.
        if scheme.is_some() || target.is_some() {
            return Err(malformed("a CONNECT request carrying :scheme or :path"));
        }
        let authority =
            authority.ok_or_else(|| malformed("a CONNECT request without :authority"))?;

        (None, Some(uri_authority(&authority)?.into()), None, None)
    } else {
        // Extended CONNECT and ordinary requests are built the same way; only
        // where the authority may come from differs.
        //
        //= https://www.rfc-editor.org/rfc/rfc8441#section-4
        //# On requests that contain the :protocol pseudo-header field, the
        //# :scheme and :path pseudo-header fields of the target URI [...]
        //# MUST also be included.
        let scheme = scheme.ok_or_else(|| malformed("a request without :scheme"))?;
        let target = target.ok_or_else(|| malformed("a request without :path"))?;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component [...] the request MUST contain
        //# either an :authority pseudo-header field or a Host header field.
        //# If these fields are present, they MUST NOT be empty. If both
        //# fields are present, they MUST contain the same value.
        //
        // One table for both request shapes, because §4.3.1's agreement rule is
        // the same rule either way: an extended CONNECT is still an HTTP/3
        // request. RFC 8441 §4 does not make :authority mandatory on a request
        // carrying :protocol; it says what :authority means when it is present:
        //
        //= https://www.rfc-editor.org/rfc/rfc8441#section-4
        //# On requests bearing the :protocol pseudo-header field, the
        //# :authority pseudo-header field is interpreted according to
        //# Section 8.1.2.3 of [RFC7540] instead of Section 8.3 of that
        //# document.
        //
        // The one requirement is RFC 9298 §3.4's, and it is connect-udp's
        // alone:
        //
        //= https://www.rfc-editor.org/rfc/rfc9298#section-3.4
        //# The :authority pseudo-header field SHALL contain the authority of
        //# the UDP proxy.
        //
        // The comparison is exact, matching `tunnel::route`: a different case
        // or spelling is an unsupported protocol, not a connect-udp request,
        // and may name the proxy through Host.
        let named = match (authority.as_deref(), fields.get("host")) {
            (Some(authority), Some(host)) if authority != host.as_bytes() => {
                return Err(malformed(":authority and Host disagree"));
            }
            (Some(authority), _) => authority,
            (None, _) if protocol.as_deref() == Some(b"connect-udp".as_slice()) => {
                return Err(malformed("a connect-udp request without :authority"));
            }
            (None, Some(host)) => host.as_bytes(),
            (None, None) => return Err(malformed("a request with neither :authority nor Host")),
        };

        let (path, query) = split_target(&target, protocol.is_some())?;
        (
            Some(uri_scheme(&scheme)?.into()),
            Some(uri_authority(named)?.into()),
            Some(path.into()),
            query.map(Into::into),
        )
    };

    let protocol = protocol
        .map(|protocol| connect_protocol(&protocol).map(Into::into))
        .transpose()?;

    Ok(Request {
        method,
        scheme,
        authority,
        path,
        query,
        protocol,
        fields,
    })
}

/// Checks a `:protocol` value (RFC 8441 §4).
///
/// The value names a registered upgrade token, and an upgrade token is a
/// `token`: RFC 9110 §16.7 says the registry "defines the namespace for
/// protocol-name tokens", and §7.8 defines `protocol-name = token`. So a value
/// that is not a token names nothing that could be in the registry, which makes
/// it an invalid pseudo-header field and the message malformed.
///
/// `:method`, `:scheme`, `:authority` and `:path` each have a character-set
/// check, and this is the one for `:protocol`. Without it a value carrying CR
/// or LF would be answered 501, as a protocol this server has not implemented,
/// where the RFC verdict is malformed. RFC 9114 §10.3 names carriage return,
/// line feed and the null character as octets an intermediary might translate
/// verbatim, so no field on an *accepted* request may carry unvalidated octets.
fn connect_protocol(protocol: &[u8]) -> Result<&str, Violation> {
    //= https://www.rfc-editor.org/rfc/rfc8441#section-4
    //# A new pseudo-header field :protocol MAY be included on request
    //# HEADERS indicating the desired protocol to be spoken on the tunnel
    //# created by CONNECT.  The pseudo-header field is single valued and
    //# contains a value from the "Hypertext Transfer Protocol (HTTP)
    //# Upgrade Token Registry"

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
    //# Endpoints MUST treat a request or response that contains
    //# undefined or invalid pseudo-header fields as malformed.
    message::token(protocol).ok_or_else(|| malformed("a :protocol that is not a token"))
}

/// Checks a `:scheme` value (RFC 3986 §3.1).
///
/// `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, which is the whole of the rule:
/// what the scheme *says* decides nothing here, and `tunnel::udp` gives the
/// reason a CONNECT-UDP request is not required to call itself `https`.
fn uri_scheme(scheme: &[u8]) -> Result<&str, Violation> {
    let invalid = || malformed("a :scheme that is not a URI scheme");

    if !scheme.first().is_some_and(u8::is_ascii_alphabetic)
        || !scheme
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return Err(invalid());
    }

    ascii(scheme, invalid)
}

/// Checks an authority (RFC 3986 §3.2).
///
/// The characters an authority is made of and no others: unreserved (§2.3),
/// percent-encoding, sub-delims (§2.2), and ":", "@", "[", "]": the union of
/// what a userinfo, a host and a port may contain, which is every `pchar` and
/// the two brackets of an IP literal. Only the *syntax* is judged
/// here, not the shape. `tunnel::tcp` splits the host from the port and
/// refuses a userinfo, an unbracketed IPv6 literal and a port that is not a
/// port. It answers each of them with a 400 rather than a stream error, which
/// tells a client more.
fn uri_authority(authority: &[u8]) -> Result<&str, Violation> {
    let invalid = || malformed("an :authority that is not an authority");

    // RFC 9114 §4.3.1 requires a non-empty one, and this is the only pseudo-
    // header where emptiness has to be said: an empty :scheme is not a scheme
    // and an empty :path is not an absolute path, so the syntax below refuses
    // both on its own. Every character an authority may contain is optional, so
    // nothing here would refuse the empty string.
    if authority.is_empty() {
        return Err(malformed("an empty :authority"));
    }

    if !authority
        .iter()
        .all(|byte| is_pchar(*byte) || matches!(byte, b'[' | b']'))
    {
        return Err(invalid());
    }

    ascii(authority, invalid)
}

/// Splits a `:path` into its path and its query, checking both.
///
/// RFC 9114 §4.3.1 makes `:path` an absolute path optionally followed by a "?"
/// and a query, which are the productions of RFC 3986 §3.3 and §3.4: a leading
/// "/", then `pchar` and "/", and after the "?" those and "?" again. A "#" is
/// refused along with everything else outside that set, because a fragment is
/// not part of a request target (RFC 9110 §7.1) and silently dropping one would
/// mean acting on a target the client did not send.
fn split_target(target: &[u8], extended: bool) -> Result<(&str, Option<&str>), Violation> {
    // §4.3.1's asterisk form, which belongs to OPTIONS. This server answers such
    // a request with the 501 every method it does not implement gets, and can
    // only do so if the request is not malformed first. It is not a path, so it
    // is refused on an extended CONNECT, where RFC 8441 §4 asks for the :path of
    // a target URI and the tunnel that follows has to parse one.
    if target == b"*" && !extended {
        return Ok(("*", None));
    }

    if target.first() != Some(&b'/') {
        return Err(malformed("a :path that is not an absolute path"));
    }

    let (path, query) = target
        .iter()
        .position(|byte| *byte == b'?')
        .map_or((target, None), |mark| {
            (&target[..mark], Some(&target[mark + 1..]))
        });

    if !path.iter().all(|byte| is_pchar(*byte) || *byte == b'/') {
        return Err(malformed("a :path with a character no path may contain"));
    }
    if !query.is_none_or(|query| {
        query
            .iter()
            .all(|byte| is_pchar(*byte) || matches!(byte, b'/' | b'?'))
    }) {
        return Err(malformed("a :path with a character no query may contain"));
    }

    let invalid = || malformed("a :path that is not valid UTF-8");
    Ok((
        ascii(path, invalid)?,
        query.map(|query| ascii(query, invalid)).transpose()?,
    ))
}

/// The last step of each of the three target parsers above: bytes an ASCII
/// check has already accepted, as a `&str`.
///
/// None of the four conversions can fail, because every byte was matched
/// against an ASCII set on the way in. It is written fallibly rather than as an
/// `expect` because these are a peer's bytes: an `expect` here would panic if
/// one of the checks above were widened. `invalid` is the error each caller
/// returns instead.
fn ascii(bytes: &[u8], invalid: impl Fn() -> Violation) -> Result<&str, Violation> {
    std::str::from_utf8(bytes).map_err(|_| invalid())
}

/// Whether `byte` is an RFC 3986 §3.3 `pchar`, or the "%" one begins with.
///
/// `unreserved / pct-encoded / sub-delims / ":" / "@"`.
fn is_pchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~%!$&'()*+,;=:@".contains(&byte)
}

/// Adds one regular field, applying RFC 9114 §4.2's rules on the way.
///
/// Takes the decoded name and value by value. A literal that `qpack::decode`
/// allocated becomes the stored name or value with no copy; only a static-table
/// entry, a few bytes, is copied.
fn add_field(
    fields: &mut Fields,
    name: Cow<'static, [u8]>,
    value: Cow<'static, [u8]>,
) -> Result<(), Violation> {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
    //# A request or response containing uppercase characters in field names
    //# MUST be treated as malformed.
    let name = owned_field_name(name)
        .ok_or_else(|| malformed("a field name that is uppercase or not a token"))?;

    //= https://www.rfc-editor.org/rfc/rfc9110#section-5.5
    //# A field value does not include leading or trailing whitespace. When a
    //# specific version of HTTP allows such whitespace to appear in a message,
    //# a field parsing implementation MUST exclude such whitespace prior to
    //# evaluating the field value.
    //
    // HTTP/3 is one of the versions that allows it: SP and HTAB are ordinary
    // field-value octets on the wire (`FieldValue::parse` accepts them). It is
    // excluded *here* so that every later reading evaluates the value the RFC
    // says was sent. That covers the agreement between `:authority` and Host,
    // and `crate::auth`, which would otherwise see " Basic ..." as a credential
    // with no scheme and answer a well-formed request with a 407 that costs the
    // peer an attempt.
    //
    // Only SP and HTAB are stripped, and only from the ends. Trimming the wider
    // ASCII whitespace set would strip a leading CR or LF as well, and those are
    // the octets §10.3 refuses below.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
    //# Any request or response that contains a character not permitted in a
    //# field value MUST be treated as malformed.
    let value = owned_field_value(value)
        .ok_or_else(|| malformed("a field value with a forbidden character"))?;

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
    //# An endpoint MUST NOT generate an HTTP/3 field section containing
    //# connection-specific fields; any message containing connection-specific
    //# fields MUST be treated as malformed.
    //
    // Only the Connection field itself is refused here, with the stream reset
    // a malformed request gets. RFC 9110 §7.6.1's wider list is judged in
    // `crate::tunnel::connection_specific_field`, which says which fields it
    // covers and why TE is not among them; the answer there can be a 400
    // (RFC 9114 §4.1.2 allows a response before the stream is closed), which
    // tells the client rather more than a bare reset would.
    if &*name == "connection" {
        return Err(malformed(
            "the Connection field, which HTTP/3 has no use for",
        ));
    }

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
    //# The only exception to this is the TE header field, which MAY be
    //# present in an HTTP/3 request header; when it is, it MUST NOT contain
    //# any value other than "trailers".
    if &*name == "te" && value.as_bytes() != b"trailers" {
        return Err(malformed("a TE field with a value other than \"trailers\""));
    }

    //= https://www.rfc-editor.org/rfc/rfc9110#section-7.2
    //# Host = uri-host [ ":" port ] ; Section 4
    //
    // One host and one optional port: the grammar leaves no room for a list,
    // and RFC 9110 §7.2 states no rule for a repeated Host field. So this rule
    // is this server's own, and it is the strict reading. RFC 9114 §4.3.1
    // requires :authority and Host to "contain the same value", and the
    // agreement check in `build_request` reads only the first Host. A second
    // Host that disagrees would then go unchecked, which is a request-smuggling
    // pattern.
    if &*name == "host" && fields.contains("host") {
        return Err(malformed("more than one Host field"));
    }

    fields.append(name, value);
    Ok(())
}

/// Drops the leading and trailing SP and HTAB RFC 9110 §5.5 excludes from a
/// field value.
///
/// A value that is nothing but whitespace becomes the empty string, which is a
/// field value like any other.
fn trim_optional_whitespace(mut value: &[u8]) -> &[u8] {
    // Slice patterns rather than a pair of index searches: SP and HTAB are the
    // only two octets `[u8]::trim_ascii` would go beyond, and peeling them off
    // each end leaves the all-whitespace case as the empty slice with no arm of
    // its own.
    while let [b' ' | b'\t', rest @ ..] = value {
        value = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = value {
        value = rest;
    }

    value
}

/// [`trim_optional_whitespace`] on an owned buffer, in place.
///
/// The tail is cut with `truncate`, which moves nothing. The remaining bytes
/// are moved to the front only when a leading SP or HTAB is present, so a value
/// without padding is left exactly as it arrived.
fn trim_optional_whitespace_in_place(value: &mut Vec<u8>) {
    let kept = trim_optional_whitespace(value).len();
    let leading = value
        .iter()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .count();

    // For a value that is all whitespace, `leading` is its whole length and
    // `kept` is 0, so the truncate keeps everything and the drain empties it.
    value.truncate(leading + kept);
    if leading > 0 {
        value.drain(..leading);
    }
}

/// The name of one decoded field line, if [`message::field_name`] accepts it.
///
/// An owned name becomes the stored name with no copy. A static-table name is
/// copied, which is a few bytes.
fn owned_field_name(name: Cow<'static, [u8]>) -> Option<Box<str>> {
    match name {
        Cow::Borrowed(name) => message::field_name(name).map(Box::from),
        Cow::Owned(name) => {
            message::field_name(&name)?;
            // A token is ASCII, so this cannot fail once `field_name` has
            // accepted the bytes. The error arm is still a refusal rather than
            // a panic.
            String::from_utf8(name).ok().map(String::into_boxed_str)
        }
    }
}

/// The value of one decoded field line with RFC 9110 §5.5's whitespace
/// excluded, if [`FieldValue::parse`] accepts what is left.
///
/// An owned value is trimmed in place and becomes the stored value with no
/// copy. A static-table value is copied, which is a few bytes.
fn owned_field_value(value: Cow<'static, [u8]>) -> Option<FieldValue> {
    match value {
        Cow::Borrowed(value) => FieldValue::parse(trim_optional_whitespace(value)),
        Cow::Owned(mut value) => {
            trim_optional_whitespace_in_place(&mut value);
            FieldValue::from_vec(value)
        }
    }
}

/// A message this server will not process (RFC 9114 §4.1.2).
fn malformed(detail: impl Into<Cow<'static, str>>) -> Violation {
    Violation::stream(Code::H3_MESSAGE_ERROR, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, value: &str) -> Field {
        Field {
            name: Cow::Owned(name.as_bytes().to_vec()),
            value: Cow::Owned(value.as_bytes().to_vec()),
        }
    }

    /// A classic CONNECT: authority only, exactly as RFC 9114 §4.4 requires.
    fn connect() -> Vec<Field> {
        vec![
            field(":method", "CONNECT"),
            field(":authority", "example.com:443"),
        ]
    }

    /// A CONNECT-UDP request, the shape RFC 9298 §3 and RFC 9220 §3 give it.
    fn connect_udp() -> Vec<Field> {
        vec![
            field(":method", "CONNECT"),
            field(":protocol", "connect-udp"),
            field(":scheme", "https"),
            field(":authority", "proxy.example:443"),
            field(":path", "/.well-known/masque/udp/192.0.2.1/443/"),
        ]
    }

    #[track_caller]
    fn refused(fields: Vec<Field>) {
        let error = build_request(fields).expect_err("malformed");
        assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
        assert!(
            !error.is_connection_error(),
            "a malformed message ends the stream, not the connection"
        );
    }

    #[test]
    fn a_classic_connect_becomes_an_authority_form_request() {
        let request = build_request(connect()).expect("accepted");

        assert_eq!(request.method, Method::Connect);
        assert_eq!(request.authority.as_deref(), Some("example.com:443"));
        assert_eq!(request.scheme, None);
        assert_eq!(request.path, None);
        assert_eq!(request.query, None);
        assert_eq!(request.protocol, None);
    }

    #[test]
    fn an_extended_connect_keeps_its_protocol_scheme_and_path() {
        let request = build_request(connect_udp()).expect("accepted");

        assert_eq!(request.scheme.as_deref(), Some("https"));
        assert_eq!(
            request.path.as_deref(),
            Some("/.well-known/masque/udp/192.0.2.1/443/")
        );
        assert_eq!(request.query, None);
        assert_eq!(request.protocol.as_deref(), Some("connect-udp"));
    }

    /// The point of decoding `:protocol` as bytes: an unimplemented protocol
    /// has to reach the router, which answers it with a 501, rather than being
    /// rejected as malformed before anyone can look at it.
    #[test]
    fn an_unknown_protocol_is_accepted_so_it_can_be_answered() {
        let mut fields = connect_udp();
        fields[1] = field(":protocol", "connect-ip");

        let request = build_request(fields).expect("accepted");
        assert_eq!(request.protocol.as_deref(), Some("connect-ip"));
    }

    #[test]
    fn an_ordinary_request_is_accepted() {
        let request = build_request(vec![
            field(":method", "GET"),
            field(":scheme", "https"),
            field(":authority", "example.com"),
            field(":path", "/"),
        ])
        .expect("accepted");

        assert_eq!(request.method, Method::Other("GET".into()));
        assert_eq!(request.path.as_deref(), Some("/"));
    }

    /// RFC 9114 §4.3.1 lets the authority arrive as a Host field instead.
    #[test]
    fn host_stands_in_for_an_absent_authority() {
        let request = build_request(vec![
            field(":method", "GET"),
            field(":scheme", "https"),
            field(":path", "/"),
            field("host", "example.com"),
        ])
        .expect("accepted");

        assert_eq!(request.authority.as_deref(), Some("example.com"));
    }

    #[test]
    fn authority_and_host_must_agree() {
        refused(vec![
            field(":method", "GET"),
            field(":scheme", "https"),
            field(":authority", "one.example"),
            field(":path", "/"),
            field("host", "other.example"),
        ]);

        // A Host field that says the same thing is not a disagreement, on an
        // ordinary request or an extended CONNECT.
        let mut agreeing = connect_udp();
        agreeing.push(field("host", "proxy.example:443"));
        assert!(build_request(agreeing).is_ok());
    }

    /// A second Host field is refused rather than resolved: the check above
    /// reads one of them, and the other would be free to say anything.
    #[test]
    fn a_repeated_host_field_is_refused() {
        for second in ["one.example", "other.example"] {
            refused(vec![
                field(":method", "GET"),
                field(":scheme", "https"),
                field(":path", "/"),
                field("host", "one.example"),
                field("host", second),
            ]);
        }

        // Repeating a field that is not Host is ordinary HTTP.
        let mut repeated = connect();
        repeated.push(field("x-volto-probe", "one"));
        repeated.push(field("x-volto-probe", "two"));
        assert!(build_request(repeated).is_ok());
    }

    /// The table of malformed requests, each naming the rule it breaks.
    #[test]
    fn malformed_requests_are_refused() {
        // RFC 9114 §4.4: a classic CONNECT omits :scheme and :path.
        let mut with_path = connect();
        with_path.push(field(":path", "/"));
        refused(with_path);

        let mut with_scheme = connect();
        with_scheme.push(field(":scheme", "https"));
        refused(with_scheme);

        // RFC 9114 §4.4: and it must carry :authority.
        refused(vec![field(":method", "CONNECT")]);

        // RFC 8441 §4 requires :scheme and :path on an extended CONNECT, and
        // RFC 9298 §3.4 requires :authority for the connect-udp request this
        // one is.
        for missing in [":scheme", ":path", ":authority"] {
            let fields = connect_udp()
                .into_iter()
                .filter(|f| f.name.as_ref() != missing.as_bytes())
                .collect();
            refused(fields);
        }

        // RFC 9114 §4.3.1: the agreement rule holds for an extended CONNECT
        // too. For connect-udp :authority is mandatory (RFC 9298 §3.4), but the
        // rule about the two values agreeing is the same either way.
        let mut disagreeing = connect_udp();
        disagreeing.push(field("host", "other.example:443"));
        refused(disagreeing);

        // RFC 9114 §4.3 with RFC 8441 §4: :protocol is defined for the
        // extended CONNECT method only, so anywhere else it is an undefined
        // pseudo-header field.
        refused(vec![
            field(":method", "GET"),
            field(":protocol", "connect-udp"),
            field(":scheme", "https"),
            field(":authority", "example.com"),
            field(":path", "/"),
        ]);

        // RFC 9114 §4.3: only the five defined pseudo-headers, each once, all
        // before any regular field, and none defined for responses.
        let mut undefined = connect();
        undefined.insert(0, field(":volto", "1"));
        refused(undefined);

        let mut status = connect();
        status.insert(0, field(":status", "200"));
        refused(status);

        let mut repeated = connect();
        repeated.push(field(":authority", "example.com:443"));
        refused(repeated);

        refused(vec![
            field(":method", "CONNECT"),
            field("user-agent", "volto-test"),
            field(":authority", "example.com:443"),
        ]);

        // RFC 9114 §4.3.1: no request at all without :method.
        refused(vec![field(":authority", "example.com:443")]);

        // RFC 9114 §4.3.1: a present pseudo-header must not be empty.
        refused(vec![field(":method", "CONNECT"), field(":authority", "")]);

        // RFC 9114 §4.2: uppercase field names, and the Connection field.
        refused(vec![
            field(":method", "CONNECT"),
            field(":authority", "example.com:443"),
            field("User-Agent", "volto-test"),
        ]);

        let mut connection = connect();
        connection.push(field("connection", "keep-alive"));
        refused(connection);

        // RFC 9114 §4.2: TE may only say "trailers".
        let mut te = connect();
        te.push(field("te", "gzip"));
        refused(te);
    }

    /// RFC 9110 §5.5: the whitespace around a field value is not part of the
    /// value, so what every reading below sees is what was sent rather than how
    /// it was padded.
    #[test]
    fn optional_whitespace_is_excluded_from_a_field_value() {
        for (padded, value) in [
            (&b" \tvalue \t"[..], &b"value"[..]),
            (b"value", b"value"),
            (b" \t ", b""),
            (b"", b""),
            // Only the ends: whitespace inside a value is part of it.
            (b" a b ", b"a b"),
        ] {
            assert_eq!(trim_optional_whitespace(padded), value, "{padded:?}");
        }

        // The field this most matters for: `auth` reads a scheme and a token,
        // and a leading space would leave it reading a scheme that is empty.
        let mut padded = connect();
        padded.push(field("proxy-authorization", " Basic dXNlcjE6czNjcmV0\t"));
        let request = build_request(padded).expect("accepted");
        assert_eq!(
            request
                .fields
                .get("proxy-authorization")
                .map(FieldValue::as_bytes),
            Some(&b"Basic dXNlcjE6czNjcmV0"[..])
        );

        // And the :authority/Host agreement of RFC 9114 §4.3.1 is judged on the
        // values rather than on their padding.
        assert!(
            build_request(vec![
                field(":method", "GET"),
                field(":scheme", "https"),
                field(":authority", "example.com"),
                field(":path", "/"),
                field("host", "  example.com "),
            ])
            .is_ok()
        );
    }

    /// The owned path of a decoded value trims in place, and accepts and refuses
    /// exactly what trimming a slice and parsing it does.
    #[test]
    fn an_owned_value_is_trimmed_and_checked_like_a_borrowed_one() {
        for padded in [
            &b"value"[..],
            b" \tvalue",
            b"value\t ",
            b" \tvalue \t",
            b"\t a b \t",
            b" \t ",
            b"",
            b" \t\nvalue",
            b"  value\0",
            b"\tva\rlue ",
        ] {
            let expected = FieldValue::parse(trim_optional_whitespace(padded));
            assert_eq!(
                owned_field_value(Cow::Owned(padded.to_vec())),
                expected,
                "{padded:?}"
            );
            assert_eq!(
                owned_field_value(Cow::Borrowed(padded)),
                expected,
                "{padded:?}"
            );
        }
    }

    /// The same equivalence over arbitrary bytes.
    #[test]
    fn an_owned_value_matches_a_borrowed_one_for_any_bytes() {
        proptest::proptest!(|(value: Vec<u8>, leading in 0usize..4, trailing in 0usize..4)| {
            let mut padded = vec![b' '; leading];
            padded.extend_from_slice(&value);
            padded.extend(std::iter::repeat_n(b'\t', trailing));
            proptest::prop_assert_eq!(
                owned_field_value(Cow::Owned(padded.clone())),
                FieldValue::parse(trim_optional_whitespace(&padded))
            );
        });
    }

    /// A decoded literal name and value with no padding become the stored name
    /// and value: the buffers `qpack::decode` allocated are kept, not copied.
    #[test]
    fn a_literal_field_keeps_the_buffers_it_was_decoded_into() {
        let name = b"proxy-authorization".to_vec();
        let value = b"Basic dXNlcjE6czNjcmV0".to_vec();
        let (name_at, value_at) = (name.as_ptr(), value.as_ptr());

        let mut section = connect();
        section.push(Field {
            name: Cow::Owned(name),
            value: Cow::Owned(value),
        });
        let request = build_request(section).expect("accepted");

        let (stored_name, stored_value) = request.fields.iter().next().expect("one field");
        assert_eq!(stored_name.as_ptr(), name_at, "the name was copied");
        assert_eq!(
            stored_value.as_bytes().as_ptr(),
            value_at,
            "the value was copied"
        );
    }

    /// An owned name is refused on the same grounds as a borrowed one.
    #[test]
    fn an_owned_name_is_checked_like_a_borrowed_one() {
        for name in [&b"accept"[..], b"Accept", b"", b"a b", b"x:y", b"\xff"] {
            let expected = message::field_name(name).map(Box::<str>::from);
            assert_eq!(
                owned_field_name(Cow::Owned(name.to_vec())),
                expected,
                "{name:?}"
            );
            assert_eq!(owned_field_name(Cow::Borrowed(name)), expected, "{name:?}");
        }
    }

    /// The one exception §4.2 makes for TE.
    #[test]
    fn te_trailers_is_allowed() {
        let mut fields = connect();
        fields.push(field("te", "trailers"));
        assert!(build_request(fields).is_ok());
    }

    /// Ordinary fields survive intact: this is how credentials reach `auth`.
    #[test]
    fn regular_fields_reach_the_request() {
        let mut fields = connect();
        fields.push(field("proxy-authorization", "Basic dXNlcjE6czNjcmV0"));

        let request = build_request(fields).expect("accepted");
        assert_eq!(
            request
                .fields
                .get("proxy-authorization")
                .map(FieldValue::as_bytes),
            Some(&b"Basic dXNlcjE6czNjcmV0"[..])
        );
    }

    /// The query is kept apart from the path, because the CONNECT-UDP template
    /// is a rule about each (RFC 9298 §2).
    #[test]
    fn a_path_carries_its_query_separately() {
        let with_query = |path: &str| {
            let mut fields = connect_udp();
            fields[4] = field(":path", path);
            let request = build_request(fields).expect("accepted");
            (request.path.clone().expect("a path"), request.query.clone())
        };

        let (path, query) = with_query("/a/b?x=1&y=2");
        assert_eq!(&*path, "/a/b");
        assert_eq!(query.as_deref(), Some("x=1&y=2"));

        // A trailing "?" is a query that is present and empty, which is not the
        // same as one that is absent.
        let (path, query) = with_query("/a/b?");
        assert_eq!(&*path, "/a/b");
        assert_eq!(query.as_deref(), Some(""));

        let (path, query) = with_query("/a/b");
        assert_eq!(&*path, "/a/b");
        assert_eq!(query, None);
    }

    /// The pseudo-headers that name a target are checked for the characters
    /// RFC 3986 allows them, since nothing downstream would refuse the rest
    /// as loudly.
    #[test]
    fn pseudo_headers_that_name_a_target_are_checked_for_syntax() {
        let replacing = |name: &str, value: &str| {
            let mut fields = connect_udp();
            for existing in &mut fields {
                if existing.name.as_ref() == name.as_bytes() {
                    *existing = field(name, value);
                }
            }
            fields
        };

        // A scheme is ALPHA then ALPHA / DIGIT / "+" / "-" / "." (RFC 3986 §3.1).
        assert!(build_request(replacing(":scheme", "coap+tcp")).is_ok());
        for scheme in ["1https", "http s", "http/1"] {
            refused(replacing(":scheme", scheme));
        }

        // An authority is unreserved / pct-encoded / sub-delims / ":@[]"
        // (RFC 3986 §3.2); its shape is `tunnel::tcp`'s to judge, not this.
        assert!(build_request(replacing(":authority", "[2001:db8::1]:443")).is_ok());
        assert!(build_request(replacing(":authority", "user@host:443")).is_ok());
        for authority in ["proxy example:443", "proxy.example:443/", "proxy\u{7f}:443"] {
            refused(replacing(":authority", authority));
        }

        // A path is an absolute path, and a fragment is not part of a target.
        for path in ["masque/udp/", "/a b", "/a#b", "/a\u{1}b"] {
            refused(replacing(":path", path));
        }

        // A query is pchar / "/" / "?" (RFC 3986 §3.4), and "#" opens a fragment
        // there as much as it does in a path.
        assert!(build_request(replacing(":path", "/a?b=c&d=%20e")).is_ok());
        for path in ["/a?b#c", "/a?b[c", "/a?b c", "/a?b\u{1}c"] {
            refused(replacing(":path", path));
        }

        // §4.3.1's asterisk form is OPTIONS's and is not a path: an ordinary
        // request may carry it so that the answer is the 501 an unimplemented
        // method gets, and an extended CONNECT may not, because RFC 8441 §4 asks
        // it for the :path of a target URI.
        let mut options = vec![
            field(":method", "OPTIONS"),
            field(":scheme", "https"),
            field(":authority", "proxy.example:443"),
            field(":path", "*"),
        ];
        assert!(build_request(options.clone()).is_ok());
        refused(replacing(":path", "*"));

        // And an ordinary request is not thereby excused a real path.
        options[3] = field(":path", "masque/udp/");
        refused(options);
    }
}
