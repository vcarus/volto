//! Two modes on the request validator, chosen by the first byte.
//!
//! [`build_request`] is where RFC 9114 §4.1.2's "malformed" verdict is reached,
//! and every pseudo-header syntax rule in `h3::message` is reached through it.
//! It sits one step past [`qpack::decode`], which the `qpack` target already
//! covers on its own; what is new here is the pass that turns a decoded section
//! into a [`Request`].
//!
//! Even inputs: the whole path a peer's bytes take — a field block through
//! [`qpack::decode`], then [`build_request`]. This is the reachability check:
//! only a section some encoding could have produced gets validated.
//!
//! Odd inputs: a section cut straight out of the input, so the fuzzer varies
//! *pseudo-header combinations* rather than QPACK encodings. Names and values
//! are drawn from dictionaries as well as from raw bytes, because the rules
//! worth reaching — a CONNECT carrying `:scheme`, an `:authority` disagreeing
//! with Host, `:protocol` on a request that is not CONNECT — are combinations
//! of plausible fields, which random bytes practically never spell.
//!
//! Both modes check the same invariants on a request that was accepted. They
//! are what the rest of the crate is entitled to assume of a [`Request`]:
//! `tunnel::tcp` splits `authority` without re-checking it is not empty, and
//! `tunnel::udp` reads `path` as a URI path.

#![no_main]

use std::borrow::Cow;

use libfuzzer_sys::fuzz_target;
use volto::h3::message::{field_name, FieldValue, Method, Request};
use volto::h3::qpack::{self, Field};
use volto::h3::stream::build_request;
use volto::h3::MAX_FIELD_SECTION_SIZE;

/// Names worth spelling exactly: the five pseudo-headers of RFC 9114 §4.3, the
/// Host field §4.3.1 lets stand in for `:authority`, and the fields the tunnels
/// refuse a request for.
const NAMES: [&[u8]; 12] = [
    b":method",
    b":scheme",
    b":authority",
    b":path",
    b":protocol",
    b":status",
    b"host",
    b"te",
    b"connection",
    b"content-length",
    b"content-type",
    b"proxy-authorization",
];

/// Values worth spelling exactly: what a real CONNECT or CONNECT-UDP carries.
const VALUES: [&[u8]; 10] = [
    b"CONNECT",
    b"GET",
    b"https",
    b"connect-udp",
    b"example.com:443",
    b"[2001:db8::1]:443",
    b"/.well-known/masque/udp/example.com/53/",
    b"/",
    b"trailers",
    b"",
];

/// Most fields one section may carry, so a huge input cannot make one run long.
const MAX_FIELDS: usize = 64;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };

    if mode & 1 == 0 {
        // The reachable path: only a section QPACK could have produced.
        let Ok(section) = qpack::decode(rest, MAX_FIELD_SECTION_SIZE) else {
            return;
        };
        if let Ok(request) = build_request(section) {
            check(&request);
        }
        return;
    }

    if let Ok(request) = build_request(cut_section(rest)) {
        check(&request);
    }
});

/// Cuts a field section out of arbitrary bytes.
///
/// Each field is a selector byte, then a name and a value that are either an
/// index into the dictionaries above or a length-prefixed run of raw bytes.
fn cut_section(mut input: &[u8]) -> Vec<Field> {
    let mut section = Vec::new();

    while section.len() < MAX_FIELDS {
        let Some((&selector, rest)) = input.split_first() else {
            break;
        };
        input = rest;

        let Some((name, rest)) = cut_token(input, selector & 0x0f, &NAMES) else {
            break;
        };
        input = rest;
        let Some((value, rest)) = cut_token(input, selector >> 4, &VALUES) else {
            break;
        };
        input = rest;

        section.push(Field { name, value });
    }

    section
}

/// One name or value: a dictionary entry, or a length-prefixed run of bytes.
///
/// `choice` below the dictionary's length picks an entry and costs no input
/// bytes; anything else takes a length byte and that many bytes of input, so a
/// value the dictionary does not hold is still reachable.
fn cut_token<'a>(
    input: &'a [u8],
    choice: u8,
    dictionary: &[&'static [u8]],
) -> Option<(Cow<'static, [u8]>, &'a [u8])> {
    if let Some(entry) = dictionary.get(usize::from(choice)) {
        return Some((Cow::Borrowed(entry), input));
    }

    let (&length, rest) = input.split_first()?;
    let length = usize::from(length) % 40;
    let token = rest.get(..length)?;
    Some((Cow::Owned(token.to_vec()), &rest[length..]))
}

/// What every accepted request promises, whichever shape it has.
fn check(request: &Request) {
    // A method survives a round trip through its own parser: the token is kept
    // as it arrived, which is what a 501 has to name.
    assert_eq!(
        Method::parse(request.method.as_str().as_bytes()).as_ref(),
        Some(&request.method),
        "a method must re-parse as itself"
    );

    let mut hosts = 0;
    for (name, value) in request.fields.iter() {
        assert!(
            !name.starts_with(':'),
            "a pseudo-header must not reach the regular fields: {name:?}"
        );
        assert!(
            field_name(name.as_bytes()).is_some(),
            "a field name must be a lowercase token: {name:?}"
        );
        assert!(
            FieldValue::parse(value.as_bytes()).is_some(),
            "a field value must be one every octet of which is legal: {value:?}"
        );

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //# any message containing connection-specific fields MUST be treated
        //# as malformed
        assert_ne!(name, "connection", "the Connection field survived");

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //# The only exception to this is the TE header field [...] it MUST NOT
        //# contain any value other than "trailers".
        if name == "te" {
            assert_eq!(value.as_bytes(), b"trailers", "a TE field said something");
        }

        // RFC 9110 §5.5's optional whitespace was excluded before anything
        // evaluated the value -- which is what makes the agreement check below
        // and `auth` read the value the peer actually sent.
        let bytes = value.as_bytes();
        assert!(
            !matches!(bytes.first(), Some(b' ' | b'\t')),
            "leading whitespace survived: {value:?}"
        );
        assert!(
            !matches!(bytes.last(), Some(b' ' | b'\t')),
            "trailing whitespace survived: {value:?}"
        );

        hosts += usize::from(name == "host");
    }

    // A second Host field could say anything at all, since the agreement check
    // reads whichever came first: the request-smuggling shape this proxy least
    // wants to be the first hop of.
    assert!(hosts <= 1, "{hosts} Host fields survived");

    let classic_connect = request.method == Method::Connect && request.protocol.is_none();
    if classic_connect {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
        //# The :scheme and :path pseudo-header fields are omitted
        assert!(request.scheme.is_none(), "a CONNECT carries no :scheme");
        assert!(request.path.is_none(), "a CONNECT carries no :path");
        assert!(request.query.is_none(), "a CONNECT carries no query");
        assert!(
            request.authority.is_some(),
            "a CONNECT names the host and port to connect to"
        );
    } else {
        // Every other shape is built from a scheme, an authority and a path.
        assert!(request.scheme.is_some(), "a request names a :scheme");
        assert!(request.authority.is_some(), "a request names an authority");
        assert!(request.path.is_some(), "a request names a :path");

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //# If both fields are present, they MUST contain the same value.
        //
        // The authority is what gets dialled, so a Host field that outlived a
        // disagreement is a target the client did not name.
        if let Some(host) = request.fields.get("host") {
            assert_eq!(
                Some(host.as_bytes()),
                request.authority.as_deref().map(str::as_bytes),
                "the authority and the Host field disagree"
            );
        }
    }

    if let Some(scheme) = request.scheme.as_deref() {
        assert!(
            scheme.starts_with(|first: char| first.is_ascii_alphabetic()),
            "a scheme begins with a letter: {scheme:?}"
        );
    }

    if let Some(authority) = request.authority.as_deref() {
        // `tunnel::tcp` and `net::resolve` are handed this without re-checking.
        assert!(!authority.is_empty(), "an authority is never empty");
        assert!(authority.is_ascii(), "an authority is ASCII: {authority:?}");
    }

    if let Some(path) = request.path.as_deref() {
        assert!(
            path == "*" || path.starts_with('/'),
            "a path is absolute or the asterisk form: {path:?}"
        );
        // The query was split off, so the path cannot still carry one.
        assert!(!path.contains('?'), "a path holds no query: {path:?}");
    }
}
