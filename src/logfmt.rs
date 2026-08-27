//! Formatting helpers for log fields.
//!
//! Operator-facing fields print the value, never Rust's `Option` spelling: a line
//! reads `alpn=h3`, not `alpn=Some("h3")`. When the value is absent the field
//! still appears, carrying [`ABSENT`] — dropping it instead would make the shape
//! of the line depend on its contents, which is exactly what a `grep` or a log
//! shipper cannot cope with.
//!
//! The rule is about *audience*, not about level: `info`/`warn` lines are read by
//! whoever is running the server, so they print values. The `debug` forensic dump
//! in [`crate::conn`] deliberately keeps `Debug` shapes — there the Rust spelling
//! of a header map, or of an absent `:protocol`, *is* the evidence D3 is waiting
//! for.
//!
//! The third rule is about *provenance*: [`or_dash`] prints with `Display`, which
//! escapes nothing, so it is only for values the server produced or validated
//! itself — the ALPN it negotiated from its own list, the SNI rustls accepted as
//! a DNS name, a `SocketAddr` it resolved. Bytes the peer chose (the user-id of
//! a rejected credential) are recorded as a plain `str` field instead, which
//! tracing prints quoted and `Debug`-escaped: `username="user1"`, and a newline
//! or a terminal escape sequence inside it stays on the one line, spelled out.
//! systemd splits a service's stdout on `\n`, so an unescaped newline would
//! otherwise hand an unauthenticated client a journal entry of its own.
//!
//! The fourth rule is about *size*: several of those peer-chosen values are a
//! whole field section's worth of bytes, so [`bounded`] caps what any one of
//! them can write into the journal. Length and provenance are separate
//! concerns, and both apply to the same fields -- `bounded` does not escape
//! anything, and recording its result with `%` would undo the third rule.

use std::borrow::Cow;
use std::fmt;

/// What an absent value prints as.
pub const ABSENT: &str = "-";

/// Longest peer-chosen token echoed into a log line whole.
///
/// `connect-udp` is 11 bytes and a plausible user-id is shorter still, so
/// nothing this server expects to see is ever cut.
///
/// Visible to the crate because one thing depends on it beyond the shape of a
/// log line: [`crate::config`] refuses a configured user-id longer than this,
/// since a failure naming one would be charged under the truncated copy
/// [`bounded_bytes`] hands out and could never be cleared by that user's own
/// success. That rule and this bound have to be the same number.
pub(crate) const MAX_TOKEN: usize = 32;

/// Caps a peer-chosen token at what a log line can afford to carry.
///
/// Some of the tokens that reach a log line are a field section's worth of
/// bytes -- up to [`crate::h3api::MAX_FIELD_SECTION_SIZE`] -- from a peer that
/// has not authenticated: the `:protocol` of an extended CONNECT, the user-id
/// of a rejected credential. Logging one whole puts tens of kilobytes in the
/// journal per request, for free, and journald's rate limiting counts lines
/// rather than bytes, so it is no backstop. The routing decision and the
/// response still see the whole value; only the log is bounded.
///
/// The length is kept because a token cut short is otherwise indistinguishable
/// from a short one, and the cut lands on a character boundary because slicing
/// a `str` anywhere else panics.
///
/// This bounds **length only**. Escaping is the recording sigil's job: the
/// result goes into a line as a `str` field or with `?`, never with `%`, or a
/// newline inside it forges a journal entry exactly as the third rule above
/// describes.
///
/// ```
/// # use volto::logfmt::bounded;
/// assert_eq!(bounded("connect-udp"), "connect-udp");
/// ```
pub fn bounded(token: &str) -> Cow<'_, str> {
    if token.len() <= MAX_TOKEN {
        return Cow::Borrowed(token);
    }

    // A search over a fixed range rather than a hand-stepped index: this runs
    // on logging paths, where a defect must come out as a wrong cut, never as
    // a hang. Position 0 is always a boundary, so the fallback is unreachable
    // and total either way.
    let end = (0..=MAX_TOKEN)
        .rev()
        .find(|&end| token.is_char_boundary(end))
        .unwrap_or(0);
    Cow::Owned(truncated(&token[..end], token.len()))
}

/// [`bounded`] for bytes that are not known to be UTF-8.
///
/// The cut happens before the decoding rather than after it, so a user-id the
/// size of a field section is never allocated whole just to be thrown away.
/// Whatever character the cut lands inside becomes U+FFFD, which is what every
/// other byte an invalid user-id is made of becomes anyway.
pub fn bounded_bytes(token: &[u8]) -> Cow<'_, str> {
    if token.len() <= MAX_TOKEN {
        return String::from_utf8_lossy(token);
    }

    let head = String::from_utf8_lossy(&token[..MAX_TOKEN]);
    Cow::Owned(truncated(&head, token.len()))
}

/// How a token that had to be cut is spelled: its head, and its real length.
fn truncated(head: &str, whole: usize) -> String {
    format!("{head}... <truncated from {whole} bytes>")
}

/// Formats an optional log field: the value itself, or [`ABSENT`].
///
/// ```
/// # use volto::logfmt::or_dash;
/// assert_eq!(or_dash(Some("h3")).to_string(), "h3");
/// assert_eq!(or_dash(None::<&str>).to_string(), "-");
/// ```
pub fn or_dash<T: fmt::Display>(value: Option<T>) -> impl fmt::Display {
    /// Carries the option to the point tracing actually formats the field, so
    /// nothing is allocated for a field that a filter discards.
    struct OrDash<T>(Option<T>);

    impl<T: fmt::Display> fmt::Display for OrDash<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match &self.0 {
                Some(value) => value.fmt(f),
                None => f.write_str(ABSENT),
            }
        }
    }

    OrDash(value)
}

#[cfg(test)]
mod tests {
    use super::{bounded, bounded_bytes, or_dash, ABSENT};
    use std::net::SocketAddr;

    /// A value present prints as itself, with no wrapper and no quotes.
    #[test]
    fn a_present_value_prints_as_itself() {
        assert_eq!(or_dash(Some("h3")).to_string(), "h3");
        assert_eq!(
            or_dash(Some(String::from("localhost"))).to_string(),
            "localhost"
        );

        let address: SocketAddr = "127.0.0.1:443".parse().expect("address");
        assert_eq!(or_dash(Some(address)).to_string(), "127.0.0.1:443");
    }

    /// An absent value prints as the placeholder, so the field keeps its shape.
    #[test]
    fn an_absent_value_prints_as_the_placeholder() {
        assert_eq!(or_dash(None::<&str>).to_string(), ABSENT);
        assert_eq!(or_dash(None::<SocketAddr>).to_string(), ABSENT);
    }

    /// The placeholder is not something a real value could be confused with in a
    /// `grep`: it is one character, and none of the fields this is used on can
    /// produce it.
    #[test]
    fn the_placeholder_is_a_single_dash() {
        assert_eq!(ABSENT, "-");
    }

    /// An unauthenticated peer can name a 64 KiB `:protocol`; the log gets the
    /// head of it and the length, not the whole thing.
    #[test]
    fn a_logged_token_is_bounded() {
        assert_eq!(bounded("connect-udp"), "connect-udp");
        assert_eq!(bounded(""), "");
        // Exactly at the bound is still echoed whole.
        let full = "p".repeat(32);
        assert_eq!(bounded(&full), full);

        let long = "p".repeat(64 * 1024);
        let logged = bounded(&long);
        assert_eq!(
            logged,
            format!("{full}... <truncated from 65536 bytes>"),
            "the head and the real length, and nothing else"
        );
        assert!(logged.len() < 80, "{logged}");
    }

    /// Truncation must land on a character boundary, or slicing panics — and on
    /// the boundary *below* [`MAX_TOKEN`], since the one above it is past the
    /// bound and so no bound at all.
    #[test]
    fn a_multibyte_token_is_cut_on_a_boundary() {
        // Twenty three-byte characters: the 32-byte cut falls inside the
        // eleventh, whose own boundary is at 30.
        let token = "\u{20ac}".repeat(20);
        assert_eq!(
            bounded(&token),
            format!("{}... <truncated from 60 bytes>", "\u{20ac}".repeat(10)),
            "ten whole characters, not eleven"
        );

        // A cut three bytes into a character rather than one: an ASCII byte
        // followed by four-byte characters puts a boundary at 29 and the next
        // at 33.
        let token = format!("a{}", "\u{1f600}".repeat(10));
        assert_eq!(
            bounded(&token),
            format!("a{}... <truncated from 41 bytes>", "\u{1f600}".repeat(7)),
            "seven whole characters, not eight"
        );
    }

    /// The same bound on bytes that were never promised to be text, which is
    /// what a claimed user-id is.
    #[test]
    fn a_logged_byte_string_is_bounded_and_decoded_leniently() {
        assert_eq!(bounded_bytes(b"user1"), "user1");
        // Invalid bytes are replaced rather than losing the whole value: who
        // was guessed at is the diagnostic point.
        assert_eq!(bounded_bytes(&[0xff, 0xfe]), "\u{fffd}\u{fffd}");

        let long = vec![b'u'; 48_000];
        let logged = bounded_bytes(&long);
        assert_eq!(
            logged,
            format!("{}... <truncated from 48000 bytes>", "u".repeat(32)),
            "a huge user-id costs a bounded log line, and says how huge it was"
        );
        assert!(logged.len() < 80, "{logged}");
    }
}
