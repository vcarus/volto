//! The two parsers that turn a client-named target into a host and a port,
//! chosen by the first byte.
//!
//! They are one decision reached along two routes: `tcp::split_authority` reads
//! the `:authority` of a classic CONNECT (RFC 9114 §4.4), `udp::parse_target`
//! reads the RFC 9298 §2 URI template of a CONNECT-UDP. What comes out of
//! either is what gets dialled and what gets logged, so they are fuzzed
//! together and held to the same invariants.
//!
//! Even inputs: the template, with the well-known prefix optionally prepended
//! so the fuzzer reaches the segment rules without having to spell it, and the
//! query split off at the first "?" exactly as `stream::split_target` does
//! before handing the two halves over.
//!
//! Odd inputs: the authority form.
//!
//! Both parsers take a `&str`, because a peer's bytes have already been through
//! RFC 3986's character rules by the time either is called; an input that is
//! not UTF-8 is one no route can produce, so it is dropped rather than coerced.

#![no_main]

use libfuzzer_sys::fuzz_target;
use volto::tunnel::tcp::split_authority;
use volto::tunnel::udp::{parse_target, WELL_KNOWN_PREFIX};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let Ok(rest) = std::str::from_utf8(rest) else {
        return;
    };

    if mode & 1 == 1 {
        if let Ok((host, port)) = split_authority(rest) {
            check(&host, port);
            // The host is a slice of what the client sent, never something
            // assembled here: `example.com]:443` must not be dialled as
            // `example.com`.
            assert!(
                rest.contains(&host),
                "the dialled host {host:?} is not part of {rest:?}"
            );
        }
        return;
    }

    // `:path` is split at the first "?" before either half reaches the
    // template parser; an absent "?" is an absent query, and a trailing one is
    // a query that is present and empty.
    let (path, query) = match rest.find('?') {
        Some(mark) => (&rest[..mark], Some(&rest[mark + 1..])),
        None => (rest, None),
    };

    let prefixed;
    let path = if mode & 2 == 0 {
        path
    } else {
        prefixed = format!("{WELL_KNOWN_PREFIX}{path}");
        &prefixed
    };

    if let Ok((host, port)) = parse_target(path, query) {
        check(&host, port);
    }
});

/// What both parsers promise about a target they accepted.
fn check(host: &str, port: u16) {
    assert!(!host.is_empty(), "an accepted target names a host");
    assert_ne!(port, 0, "port zero is not a port");
    // Brackets belong to the URI syntax the host was cut out of, and RFC 3986
    // §3.2.2 gives them to the IP-literal form alone. One that survived the
    // parser is a host neither form describes.
    assert!(
        !host.contains(['[', ']']),
        "a bracket survived into the host: {host:?}"
    );
}
