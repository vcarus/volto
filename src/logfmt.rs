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
//!
//! Some peer bytes have no field of their own to be recorded in: they arrive
//! already inside somebody else's `Display`, and the log sees only the sentence
//! they ended up in -- a QUIC close reason phrase inside the error the closing
//! line reports, say. The sigil cannot save those, because by the time the sigil
//! is chosen the peer's bytes are already part of a value that formats itself.
//! [`escaped_bytes`] is the answer for them: applied where the peer's bytes
//! enter the value rather than where the value is logged, it applies both rules
//! at once and hands back something the rest of the program may print with
//! `Display` from then on. [`peer_error`] is that answer applied to the value
//! this server meets it in -- a QUIC connection error -- so that the two places
//! one of those reaches a log line apply the rule by calling the same name.

use std::borrow::Cow;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// [`bounded_bytes`] with the escaping applied too, for peer bytes that will be
/// printed with `Display`.
///
/// The rest of this module divides the work: `bounded` cuts, and the recording
/// sigil escapes. That division needs a *field* to record, and some peer bytes
/// never get one -- a QUIC close reason phrase is inside `quinn`'s error by the
/// time this server sees it, and the closing line in [`crate::quic`] records the
/// whole error with `%`. Escaping at the call site is not available there, and
/// choosing `?` instead would change how every other error on that line reads.
///
/// So both rules are applied here instead, once, where the peer's bytes enter
/// the value: the result is quoted and `Debug`-escaped, so a newline in it stays
/// on the one line and cannot forge a journal entry, and it carries the same
/// length bound as everything else a peer writes into a log.
///
/// ```
/// # use volto::logfmt::escaped_bytes;
/// assert_eq!(escaped_bytes(b"unexpected frame"), "\"unexpected frame\"");
/// assert!(!escaped_bytes(b"a\nb").contains('\n'));
/// ```
pub fn escaped_bytes(token: &[u8]) -> String {
    // `Debug` for `Cow<str>` forwards to the `str`'s, which is the quoted,
    // control-character-escaping spelling tracing gives a `str` field.
    format!("{:?}", bounded_bytes(token))
}

/// The same error, with any reason phrase the peer wrote passed through
/// [`escaped_bytes`].
///
/// Both kinds of QUIC close carry a reason phrase of the peer's own composition
/// (RFC 9000 §19.19), and `quinn`'s `Display` prints it as it arrived. Every
/// door a `quinn::ConnectionError` reaches a log line through goes through here
/// first, so that "a connection error a peer may have authored is escaped where
/// it enters this program" is one name rather than a rule to remember: the
/// handshake that never completed ([`crate::quic`]) and the connection that did
/// ([`crate::h3api::ConnectionError`]) are the two of them.
///
/// Every other variant is this server's own account of what went wrong -- a
/// timeout, a transport error it raised itself -- and is left alone.
pub fn peer_error(error: quinn::ConnectionError) -> quinn::ConnectionError {
    match error {
        quinn::ConnectionError::ConnectionClosed(close) => {
            quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
                reason: escaped_bytes(&close.reason).into(),
                ..close
            })
        }
        quinn::ConnectionError::ApplicationClosed(close) => {
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                reason: escaped_bytes(&close.reason).into(),
                ..close
            })
        }
        other => other,
    }
}

/// How a token that had to be cut is spelled: its head, and its real length.
fn truncated(head: &str, whole: usize) -> String {
    format!("{head}... <truncated from {whole} bytes>")
}

/// How often a warning a peer can repeat at will is allowed to be loud.
///
/// The rules above bound what one line may carry. This bounds how many lines
/// there are, which is the other half of the same problem and the one an
/// operator feels first: `journald` rate limiting counts *lines*, per unit, so a
/// peer that can buy one warning per request does not merely fill a disk — it
/// spends this service's whole allowance and the genuine lines that follow are
/// dropped. Suppressing the real signal is the more expensive half of the
/// attack, and a peer needs no privilege to run it: a refusal is a request that
/// went nowhere, so the refusals are the cheapest lines there are.
///
/// Silencing the repeats is not the answer either. The two warnings this guards
/// are read as evidence — a client probing the private side of the host, a
/// client sitting on its tunnel limit — and evidence that reports "it happened"
/// while hiding "it happened sixty thousand times" is worse than useless.
///
/// So the schedule doubles: occurrence 1 is reported, then 2, 4, 8, and so on,
/// each carrying the running total. A scan of every port on a host is 17 lines
/// instead of 65535, the first of them lands as immediately as it does today,
/// and the last one *says* it was 65536 — which is more than the unsampled
/// version ever told anybody, since counting identical lines was left to whoever
/// read the journal. The cost is that the count between reports is only known to
/// within a factor of two until the next one arrives.
///
/// One of these per connection, so a peer cannot use a quiet neighbour's
/// allowance, and nothing here is ever reset: the schedule is about a
/// connection's whole life.
#[derive(Debug, Default)]
pub struct Sampler(AtomicU64);

impl Sampler {
    /// A sampler that has seen nothing yet.
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Records an occurrence: `Some(total)` when this one is to be reported.
    ///
    /// `Relaxed` because the only thing ordered against is the counter itself —
    /// two threads racing here get two distinct totals and at most one of them
    /// is a power of two, which is all the schedule asks. Wrapping is
    /// unreachable (a `u64` of refusals is longer than the hardware lasts) and
    /// harmless if it happened: zero is not a power of two, so the pass is
    /// quiet rather than wrong.
    pub fn record(&self) -> Option<u64> {
        let total = self.0.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        total.is_power_of_two().then_some(total)
    }

    /// How many occurrences have been recorded, reported or not.
    ///
    /// Only a test asks: it is how a caller's wiring is shown to reach the
    /// sampler at all, which the log lines cannot show for a schedule whose
    /// whole point is that most occurrences produce none.
    #[cfg(test)]
    pub fn seen(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
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

/// How many addresses of a resolved list a log line prints.
///
/// A dual-stack name has two, a load balancer a handful; past that the list has
/// stopped being something an operator reads and become something the log has to
/// carry.
const MAX_ADDRESSES: usize = 8;

/// Renders a resolved address list at a length a log line can afford.
///
/// The list on the two refusal lines in [`crate::tunnel`] is what the *resolver*
/// answered, before the policy filter, and nothing between `getaddrinfo` and the
/// line bounds it: a name whose owner returns four thousand records — which a
/// DNS answer over TCP has room for — puts every one of them on the line. The
/// client picks the name, and on the blackhole line, which is deliberately not
/// sampled because it fires on ordinary ad-blocked traffic, that is tens of
/// kilobytes of INFO per request. The two `debug` lines naming the addresses a
/// tunnel failed to reach come through here as well, so that a list this server
/// prints has one length rule rather than one per call site.
///
/// So the head is printed and the rest is counted. The count is the part worth
/// keeping: "and 3992 more" is itself the diagnosis, where a line that simply
/// stopped would look like a short list.
///
/// The addresses go in with `Display` rather than a `str` field, and may: they
/// are `SocketAddr`s this server parsed, not bytes a peer chose, which is the
/// third rule above. Written as a lazy adapter so a filtered-out line pays for
/// none of it.
///
/// ```
/// # use volto::logfmt::addresses;
/// # use std::net::SocketAddr;
/// let one: Vec<SocketAddr> = vec!["127.0.0.1:443".parse().unwrap()];
/// assert_eq!(addresses(&one).to_string(), "[127.0.0.1:443]");
/// ```
pub fn addresses(list: &[std::net::SocketAddr]) -> impl fmt::Display + '_ {
    struct Addresses<'a>(&'a [std::net::SocketAddr]);

    impl fmt::Display for Addresses<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("[")?;
            for (index, address) in self.0.iter().take(MAX_ADDRESSES).enumerate() {
                if index > 0 {
                    f.write_str(", ")?;
                }
                write!(f, "{address}")?;
            }
            if let Some(rest) = self.0.len().checked_sub(MAX_ADDRESSES).filter(|n| *n > 0) {
                write!(f, ", and {rest} more")?;
            }
            f.write_str("]")
        }
    }

    Addresses(list)
}

#[cfg(test)]
mod tests {
    use super::{
        addresses, bounded, bounded_bytes, escaped_bytes, or_dash, peer_error, Sampler, ABSENT,
    };
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

    /// Both rules at once, for the bytes that reach a line inside somebody
    /// else's `Display` and so have no sigil of their own.
    #[test]
    fn escaped_bytes_bounds_and_escapes() {
        assert_eq!(escaped_bytes(b"unexpected frame"), "\"unexpected frame\"");

        // The attack the escaping is for: systemd splits on `\n`, so a raw one
        // would end the line and start a forged entry.
        let forged = escaped_bytes(b"bye\nINFO volto: all is well");
        assert!(!forged.contains('\n'), "{forged}");
        assert!(forged.contains("bye"), "{forged}");

        // A carriage return and an escape are the other two a terminal or a log
        // reader acts on; neither survives as itself.
        let control = escaped_bytes(b"a\r\x1b[2Jb");
        assert!(
            !control.contains('\r') && !control.contains('\x1b'),
            "{control}"
        );

        let long = escaped_bytes(&vec![b'r'; 4096]);
        assert!(long.len() < 80, "{long}");
        assert!(long.contains("4096"), "{long}");
    }

    /// Both kinds of QUIC close carry a peer-written reason phrase, and the
    /// handshake door in [`crate::quic`] meets both: a transport close is what a
    /// peer's TLS stack sends when it refuses the certificate, and an
    /// application close is what a peer sends the moment it has 1-RTT keys.
    #[test]
    fn a_peer_authored_reason_phrase_is_bounded_and_escaped() {
        let forged = b"bye\nINFO volto: all is well".as_slice();

        let transport = peer_error(quinn::ConnectionError::ConnectionClosed(
            quinn::ConnectionClose {
                error_code: quinn::TransportErrorCode::crypto(40),
                frame_type: None,
                reason: forged.into(),
            },
        ))
        .to_string();
        assert!(!transport.contains('\n'), "{transport}");
        assert!(transport.contains("bye"), "{transport}");

        let application = peer_error(quinn::ConnectionError::ApplicationClosed(
            quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(0x0100),
                reason: forged.into(),
            },
        ))
        .to_string();
        assert!(!application.contains('\n'), "{application}");
        assert!(application.contains("bye"), "{application}");

        // What this server said about itself is not a peer's to rewrite, and is
        // passed through as it was.
        let ours = peer_error(quinn::ConnectionError::TimedOut).to_string();
        assert_eq!(ours, quinn::ConnectionError::TimedOut.to_string());
    }

    /// The first occurrence is never held back — a bound that made an operator
    /// wait for the second probe before saying anything would have traded the
    /// flood for a blind spot — and the reports carry the running total.
    #[test]
    fn a_sampler_reports_on_a_doubling_schedule() {
        let sampler = Sampler::new();

        let reported: Vec<u64> = (0..64).filter_map(|_| sampler.record()).collect();
        assert_eq!(reported, vec![1, 2, 4, 8, 16, 32, 64]);
    }

    /// The list a name resolves to is the name owner's choice, and a DNS answer
    /// has room for thousands: a log line may not carry all of them, and may not
    /// hide that there were thousands either.
    #[test]
    fn an_address_list_is_printed_at_a_length_a_line_can_afford() {
        let none: Vec<SocketAddr> = Vec::new();
        assert_eq!(addresses(&none).to_string(), "[]");

        let two: Vec<SocketAddr> = vec![
            "127.0.0.1:443".parse().expect("address"),
            "[::1]:443".parse().expect("address"),
        ];
        assert_eq!(addresses(&two).to_string(), "[127.0.0.1:443, [::1]:443]");

        // Exactly at the bound is still printed whole, with nothing appended.
        let eight: Vec<SocketAddr> = (0..8)
            .map(|n| SocketAddr::from(([10, 0, 0, n], 443)))
            .collect();
        let printed = addresses(&eight).to_string();
        assert!(printed.ends_with("10.0.0.7:443]"), "{printed}");
        assert!(!printed.contains("more"), "{printed}");

        let flood: Vec<SocketAddr> = (0..4000)
            .map(|n| SocketAddr::from(([0, 0, 0, 0], n)))
            .collect();
        let printed = addresses(&flood).to_string();
        assert!(
            printed.ends_with(", and 3992 more]"),
            "the count is the diagnosis, not the list: {printed}"
        );
        assert!(
            printed.len() < 200,
            "one line must not carry {} bytes of resolver answer",
            printed.len()
        );
    }

    /// The property that makes it a bound rather than a slower flood: the line
    /// count grows with the *logarithm* of the occurrences.
    #[test]
    fn a_sampler_turns_a_flood_into_a_handful_of_lines() {
        let sampler = Sampler::new();
        let reported = (0..65_536).filter(|_| sampler.record().is_some()).count();

        assert_eq!(reported, 17, "every port on a host, in seventeen lines");
    }
}
