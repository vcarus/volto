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
//! Odd inputs: a round trip. A user-id and password are cut from the input,
//! configured, and offered back as `Basic <base64>` encoded here — so the
//! accept path, and the constant-time comparison on it, is reached rather than
//! left to a fuzzer that would have to spell valid base64 by luck.
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
    if let Ok(Some(username)) = verdict {
        assert!(
            users.iter().any(|user| user.username == username),
            "{username:?} is nobody"
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

/// The credentials a configured user offers must be accepted.
fn round_trip(input: &[u8]) {
    let (users, _) = cut_users(input, 1);
    let Some(user) = users.first() else {
        return;
    };
    // RFC 7617 §2 forbids a colon in a user-id; one that carries a colon would
    // split somewhere else and is a configuration `config` refuses.
    if user.username.contains(':') {
        return;
    }

    let token = encode_base64(format!("{}:{}", user.username, user.password).as_bytes());
    let value = FieldValue::parse(format!("Basic {token}").as_bytes()).expect("a field value");
    let mut fields = Fields::new();
    fields.append(CREDENTIAL_FIELDS[0], value);

    assert_eq!(
        authenticator(users.clone()).authenticate(&fields),
        Ok(Some(user.username.as_str())),
        "a configured user's own credentials must be accepted"
    );
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
