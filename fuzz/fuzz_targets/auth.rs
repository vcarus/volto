//! Two modes on HTTP Basic authentication, chosen by the first byte.
//!
//! The credentials field is the one attacker-shaped byte string this server
//! reads *before* anything has authenticated, and it goes through three
//! hand-written passes: the scheme split, the RFC 4648 base64 decoder that
//! `auth.rs` owns rather than depends on, and the user-id/password split at the
//! first colon. What comes out of the last one reaches a log line, bounded by
//! [`logfmt::bounded_bytes`], which cuts a byte string on a character boundary.
//!
//! Even inputs: arbitrary field values against an arbitrary set of configured
//! users. Both field names are used, since either may carry credentials (D3).
//!
//! Odd inputs: a round trip. Up to two users are cut from the input and
//! configured. The first user's own credentials are offered back as
//! `Basic <base64>` encoded here, so the accept path, and the constant-time
//! comparison on it, is reached rather than left to a fuzzer that would have
//! to spell valid base64 by luck. When there are two, the first user's name is
//! also offered with the second user's password, which must pass only if some
//! configured user holds that exact pair.
//!
//! Both modes also feed the raw input to [`logfmt::bounded`] and
//! [`logfmt::bounded_bytes`] directly. A rejected user-id reaches them on its
//! own, but only through a base64 decode, so a long or oddly-cut one is far
//! cheaper to reach from here than through the credential the peer sends.

#![no_main]

use libfuzzer_sys::fuzz_target;
use volto::auth::{Authenticator, MAX_CREDENTIAL_VALUES};
use volto::config::{Auth, User};
use volto::h3api::{FieldValue, Fields};
use volto::logfmt;

/// The two fields credentials are accepted in (D3).
const CREDENTIAL_FIELDS: [&str; 2] = ["proxy-authorization", "authorization"];

/// Longest user-id or password cut out of the input.
///
/// `config` refuses a user-id longer than `logfmt::MAX_TOKEN`, so a longer one
/// is not a configuration this server would have started with.
const MAX_SECRET: usize = 32;

/// Most credential fields one request built here may carry.
///
/// More than [`MAX_CREDENTIAL_VALUES`], which is all a request reaching this
/// server may carry: `conn` refuses the rest with 400 before any value is tried
/// (D76 addendum of 2026-09-04). The extra values are kept because they cost
/// nothing and they drive the scheme split and the base64 decoder, which is what
/// this target is for.
const MAX_VALUES: usize = 8;

/// Longest a bounded token may print as: at most [`MAX_SECRET`] bytes of head,
/// each of which may decode to a three-byte replacement character, plus the
/// suffix naming the original length.
const MAX_BOUNDED: usize = 256;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };

    // The log-side bound, reached with raw bytes rather than through base64.
    let bounded = logfmt::bounded_bytes(rest);
    assert!(bounded.len() < MAX_BOUNDED, "an unbounded log token");
    if let Ok(text) = std::str::from_utf8(rest) {
        assert!(
            logfmt::bounded(text).len() < MAX_BOUNDED,
            "an unbounded token"
        );
    }

    if mode & 1 == 1 {
        round_trip(rest);
        return;
    }

    let (users, rest) = cut_users(rest, usize::from(mode >> 1) % 4);
    let authenticator = authenticator(users.clone());

    let mut fields = Fields::new();
    let mut input = rest;
    while fields.len() < MAX_VALUES {
        let Some((&selector, tail)) = input.split_first() else {
            break;
        };
        let Some((&length, tail)) = tail.split_first() else {
            break;
        };
        let length = usize::from(length) % 64;
        let Some(value) = tail.get(..length) else {
            break;
        };
        input = &tail[length..];

        // A value that would not survive `h3::message` never reaches `auth`.
        let Some(value) = FieldValue::parse(value) else {
            continue;
        };
        fields.append(
            CREDENTIAL_FIELDS[usize::from(selector) % CREDENTIAL_FIELDS.len()],
            value,
        );
    }

    let verdict = authenticator.authenticate(&fields);

    // A pass names a user that was configured, never one assembled out of the
    // request: mixing one user's name with another's password must not pass.
    // So a pass needs an offered user-id and password that are, together, one
    // configured user's pair, and that user's name is the one returned.
    if let Ok(Some(username)) = verdict {
        let offered = offered_pairs(&fields);
        assert!(
            users.iter().any(|user| {
                user.username == username
                    && offered.iter().any(|(id, password)| {
                        id == user.username.as_bytes() && password == user.password.as_bytes()
                    })
            }),
            "{username:?} passed without any offered pair matching a configured one"
        );
    }
    if users.is_empty() {
        assert_eq!(
            verdict,
            Ok(None),
            "no users configured is no authentication"
        );
    }
    if let Err(denials) = &verdict {
        // One refusal per credential value tried and refused, which is the unit
        // the failure budget charges, and never more than the request offered.
        assert!(
            denials.charged() <= fields.len().max(1),
            "more failures charged than credential values offered"
        );
        assert!(
            fields.len() > MAX_CREDENTIAL_VALUES || denials.charged() <= MAX_CREDENTIAL_VALUES,
            "a request within the limit charged more than it may"
        );
        for username in denials.claims().flatten() {
            assert!(
                username.len() < MAX_BOUNDED,
                "an unbounded user-id was kept"
            );
        }
    }

    // The same request twice is the same answer: nothing here may depend on
    // state carried between requests.
    assert_eq!(
        authenticator.authenticate(&fields),
        verdict,
        "authentication is not a function of the request"
    );
});

/// The credentials a configured user offers must be accepted, and one user's
/// name with another user's password must not be.
fn round_trip(input: &[u8]) {
    let (users, _) = cut_users(input, 2);
    let Some(user) = users.first() else {
        return;
    };
    // RFC 7617 §2 forbids a colon in a user-id; one that carries a colon would
    // split somewhere else and is a configuration `config` refuses.
    if user.username.contains(':') {
        return;
    }
    let authenticator = authenticator(users.clone());

    assert_eq!(
        authenticator.authenticate(&basic(&user.username, &user.password)),
        Ok(Some(user.username.as_str())),
        "a configured user's own credentials must be accepted"
    );

    let Some(other) = users.get(1) else {
        return;
    };
    let mixed = authenticator.authenticate(&basic(&user.username, &other.password));
    let configured = users.iter().any(|candidate| {
        candidate.username == user.username && candidate.password == other.password
    });
    if configured {
        assert_eq!(
            mixed,
            Ok(Some(user.username.as_str())),
            "a pair some configured user holds must be accepted"
        );
    } else {
        assert!(
            mixed.is_err(),
            "{:?} with another user's password must not pass, got {mixed:?}",
            user.username
        );
    }
}

/// A request carrying one `Basic` credential for `username` and `password`.
fn basic(username: &str, password: &str) -> Fields {
    let token = encode_base64(format!("{username}:{password}").as_bytes());
    let value = FieldValue::parse(format!("Basic {token}").as_bytes()).expect("a field value");
    let mut fields = Fields::new();
    fields.append(CREDENTIAL_FIELDS[0], value);
    fields
}

/// Every user-id and password pair the credential fields of `fields` offer.
///
/// Decoded here rather than through `auth.rs`, so a pass is judged by a reader
/// that is not the one under test. It is more lenient than the server's: it
/// ignores the base64 framing rules the server enforces, and keeps every value
/// whose scheme is `Basic`. For any value the server accepts it produces the
/// same pair, so a pass the server grants always has its pair in this list.
fn offered_pairs(fields: &Fields) -> Vec<(Vec<u8>, Vec<u8>)> {
    fields
        .iter()
        .filter(|(name, _)| CREDENTIAL_FIELDS.contains(name))
        .filter_map(|(_, value)| {
            let (scheme, token) = value.to_str()?.split_once(' ')?;
            if !scheme.eq_ignore_ascii_case("basic") {
                return None;
            }
            let decoded = decode_base64_leniently(token.trim_start_matches(' '));
            let colon = decoded.iter().position(|byte| *byte == b':')?;
            Some((decoded[..colon].to_vec(), decoded[colon + 1..].to_vec()))
        })
        .collect()
}

/// Standard base64 (RFC 4648 §4) without its framing rules: the alphabet is
/// read up to the first `=` or the first byte outside it, and every whole
/// octet of the bits read so far is kept.
fn decode_base64_leniently(token: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = Vec::new();
    let mut bits: u32 = 0;
    let mut held = 0;
    for byte in token.bytes() {
        let Some(sextet) = ALPHABET.iter().position(|letter| *letter == byte) else {
            break;
        };
        bits = (bits << 6) | sextet as u32;
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push((bits >> held) as u8);
            bits &= (1 << held) - 1;
        }
    }
    out
}

/// Cuts up to `count` users out of the input, each a user-id and a password.
fn cut_users(mut input: &[u8], count: usize) -> (Vec<User>, &[u8]) {
    let mut users = Vec::new();

    for _ in 0..count {
        let Some((username, rest)) = cut_secret(input) else {
            break;
        };
        let Some((password, rest)) = cut_secret(rest) else {
            break;
        };
        input = rest;
        users.push(User { username, password });
    }

    (users, input)
}

/// One length-prefixed secret. Configured credentials are text, so bytes that
/// are not UTF-8 end the list rather than being coerced into something the
/// config file could not have held.
fn cut_secret(input: &[u8]) -> Option<(String, &[u8])> {
    let (&length, rest) = input.split_first()?;
    let length = usize::from(length) % (MAX_SECRET + 1);
    let secret = std::str::from_utf8(rest.get(..length)?).ok()?;
    Some((secret.to_owned(), &rest[length..]))
}

fn authenticator(users: Vec<User>) -> Authenticator {
    Authenticator::new(&Auth { users })
}

/// Standard base64 (RFC 4648 §4), written here so the round trip is judged by
/// an encoder that is not the decoder under test.
fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::new();
    for quantum in input.chunks(3) {
        let mut bits: u32 = 0;
        for index in 0..3 {
            bits = (bits << 8) | u32::from(quantum.get(index).copied().unwrap_or(0));
        }
        let significant = quantum.len() + 1;
        for index in 0..significant {
            let sextet = (bits >> (18 - 6 * index)) & 0x3f;
            out.push(char::from(ALPHABET[sextet as usize]));
        }
        for _ in significant..4 {
            out.push('=');
        }
    }
    out
}
