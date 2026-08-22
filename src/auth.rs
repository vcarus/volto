//! HTTP Basic authentication (RFC 7617) for CONNECT requests.
//!
//! # Which header
//!
//! Surge sends credentials on *every* CONNECT request, but its manual does not
//! say in which field — `Proxy-Authorization` is the proxy-semantics answer and
//! what comparable implementations use, while `Authorization` is what a client
//! that treats the proxy as an origin would send. This is the one point the
//! research left open (decision D3), so both are accepted: every value of
//! `Proxy-Authorization` is tried first, then every value of `Authorization`, and
//! any one of them matching is enough. When the first live Surge connection
//! settles the question, nothing here needs to change.
//!
//! # Comparison discipline
//!
//! Username *and* password are compared with [`subtle::ConstantTimeEq`], and the
//! loop over configured users deliberately does not stop at the first match, so
//! neither the position of the matching user nor the length of a matching prefix
//! is observable in the response time. What does remain observable is the
//! *length* of the configured secrets: `ct_eq` reports a mismatch immediately
//! when two slices differ in length. Credentials live in the config file as
//! plaintext, so there is no way around that short of hashing them, and a length
//! oracle on a password is not a meaningful attack.
//!
//! Comparison is on raw bytes rather than decoded text, so it is independent of
//! whether the client encoded the credentials as UTF-8 or ISO-8859-1
//! (RFC 7617 §2.1 leaves that partly open).

use subtle::ConstantTimeEq;

use crate::config;
use crate::h3api::{FieldValue, Fields};

/// The field a 407 carries its challenge in (RFC 9110 §11.7.1).
const PROXY_AUTHENTICATE: &str = "proxy-authenticate";

/// The two fields credentials are accepted in, in the order they are tried
/// (decision D3).
const CREDENTIAL_FIELDS: [&str; 2] = ["proxy-authorization", "authorization"];

/// The challenge offered when credentials are missing or wrong.
///
/// RFC 9110 §11.7.1 requires a `Proxy-Authenticate` field on every 407. Surge
/// sends credentials up front and does not wait to be challenged, so this is for
/// interoperability and for whoever is debugging with `curl`.
pub const CHALLENGE: &str = "Basic realm=\"masque\"";

/// Checks request credentials against the configured users.
pub struct Authenticator {
    users: Vec<config::User>,
}

/// Why a request's credentials were not accepted.
///
/// No variant carries anything derived from the password: this type exists to be
/// logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    /// Neither `Proxy-Authorization` nor `Authorization` was present.
    Missing,
    /// A credentials field was present but unusable.
    Malformed(&'static str),
    /// Well-formed credentials that match no configured user.
    Rejected {
        /// The user-id the client claimed. Not a secret, and the only way to tell
        /// a typo apart from a scan in the logs.
        ///
        /// Bounded by [`crate::logfmt::bounded_bytes`] where it is built rather
        /// than where it is logged: the peer chooses its length as well as its
        /// bytes, and a user-id is everything before the first colon of a whole
        /// field section, so an unbounded one costs a 49 KB allocation on the
        /// way to a log line five times that size (review H3).
        username: String,
    },
}

impl Denied {
    /// A short, credential-free description, suitable for a log field.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Missing => "no credentials",
            Self::Malformed(reason) => reason,
            Self::Rejected { .. } => "credentials rejected",
        }
    }

    /// The user-id the client claimed, when it sent a parseable one.
    pub fn username(&self) -> Option<&str> {
        match self {
            Self::Rejected { username } => Some(username),
            _ => None,
        }
    }
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl Authenticator {
    /// Builds an authenticator from the `[auth]` section.
    pub fn new(auth: &config::Auth) -> Self {
        Self {
            users: auth.users.clone(),
        }
    }

    /// Whether no credentials are required at all.
    ///
    /// True when no users are configured, which makes this an open proxy;
    /// [`config::Config::warnings`] reports it at startup.
    pub fn is_disabled(&self) -> bool {
        self.users.is_empty()
    }

    /// Authenticates a request's headers.
    ///
    /// `Ok(None)` means authentication is disabled, `Ok(Some(username))` names the
    /// user that matched.
    pub fn authenticate(&self, fields: &Fields) -> Result<Option<&str>, Denied> {
        if self.is_disabled() {
            return Ok(None);
        }

        // The first failure is the one reported: it comes from the
        // highest-priority header, which is the one most likely to be the
        // client's real attempt.
        let mut denial: Option<Denied> = None;

        for value in credentials(fields) {
            match self.check(value) {
                Ok(username) => return Ok(Some(username)),
                Err(reason) => denial = denial.or(Some(reason)),
            }
        }

        Err(denial.unwrap_or(Denied::Missing))
    }

    /// Validates one credentials field value.
    fn check(&self, value: &FieldValue) -> Result<&str, Denied> {
        let value = value
            .to_str()
            .ok_or(Denied::Malformed("credentials are not valid UTF-8"))?;

        let token = basic_token(value)?;
        let decoded = decode_base64(token.as_bytes())
            .ok_or(Denied::Malformed("credentials are not valid base64"))?;

        // RFC 7617 §2: `user-id ":" password`, split at the *first* colon since
        // a password may contain colons of its own.
        let colon = decoded
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(Denied::Malformed(
                "credentials have no user-id/password colon",
            ))?;
        let (username, password) = (&decoded[..colon], &decoded[colon + 1..]);

        self.verify(username, password)
            .ok_or_else(|| Denied::Rejected {
                username: crate::logfmt::bounded_bytes(username).into_owned(),
            })
    }

    /// Constant-time lookup of a username/password pair.
    ///
    /// Runs over every configured user, whatever happens, and combines the two
    /// comparisons with a non-short-circuiting `&`.
    fn verify(&self, username: &[u8], password: &[u8]) -> Option<&str> {
        let mut matched = None;

        for user in &self.users {
            let hit =
                user.username.as_bytes().ct_eq(username) & user.password.as_bytes().ct_eq(password);

            if bool::from(hit) {
                matched = Some(user.username.as_str());
            }
        }

        matched
    }
}

/// The `Proxy-Authenticate` header a 407 response carries.
pub fn challenge_fields() -> Fields {
    let mut fields = Fields::new();
    fields.append(PROXY_AUTHENTICATE, FieldValue::from_static(CHALLENGE));
    fields
}

/// Whether a field carries credentials, and so must never be logged verbatim.
///
/// Both names this server accepts (decision D3), matched case-insensitively —
/// a field name is lowercase by the time it gets here (RFC 9114 §4.2, enforced
/// by `h3::stream`), but this must not depend on that. It reads the same list
/// [`credentials`] does, so settling D3 cannot accept a third field name here
/// and go on printing it in [`crate::conn`]'s request log.
pub(crate) fn is_credential_field(name: &str) -> bool {
    CREDENTIAL_FIELDS
        .iter()
        .any(|field| name.eq_ignore_ascii_case(field))
}

/// Every credentials field value, in the order they are tried.
fn credentials(fields: &Fields) -> impl Iterator<Item = &FieldValue> {
    CREDENTIAL_FIELDS
        .into_iter()
        .flat_map(|name| fields.get_all(name))
}

/// Strips the `Basic` scheme, returning the base64 token.
///
/// RFC 9110 §11.1 makes the scheme name case-insensitive.
fn basic_token(value: &str) -> Result<&str, Denied> {
    let (scheme, token) = value
        .split_once(' ')
        .ok_or(Denied::Malformed("credentials have no auth scheme"))?;

    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(Denied::Malformed("auth scheme is not Basic"));
    }

    // A single space is the norm, but the grammar allows more whitespace between
    // the scheme and the token.
    Ok(token.trim_start_matches(' '))
}

/// Decodes standard base64 (RFC 4648 §4).
///
/// Hand-rolled for the same reason `datagram.rs` is (decision D2): this is the
/// only base64 in the server, and ~40 lines is a smaller thing to own than
/// another dependency in the production binary. Deliberately strict about
/// framing — length a multiple of four, padding only at the very end — because
/// the input is an authentication credential, and lenient only about the unused
/// low bits of a padded quantum, which some encoders leave non-zero.
fn decode_base64(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() || input.len() % 4 != 0 {
        return None;
    }

    let quanta = input.len() / 4;
    let mut out = Vec::with_capacity(quanta * 3);

    for (index, quantum) in input.chunks_exact(4).enumerate() {
        let padding = if index + 1 == quanta {
            quantum.iter().filter(|byte| **byte == b'=').count()
        } else {
            0
        };
        // "====" carries nothing and "=xxx" is not padding at all.
        if padding > 2 {
            return None;
        }

        let significant = 4 - padding;
        let mut bits: u32 = 0;
        for byte in &quantum[..significant] {
            // Catches '=' inside a quantum as well as any non-alphabet byte,
            // whitespace and newlines included.
            bits = (bits << 6) | u32::from(sextet(*byte)?);
        }

        // Left-align the significant bits into a full 24-bit group.
        bits <<= 6 * padding;
        let group = bits.to_be_bytes();
        out.extend_from_slice(&group[1..4 - padding]);
    }

    Some(out)
}

/// The 6-bit value of one base64 alphabet character.
fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard base64, built without the decoder under test.
    fn encode_base64(input: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut out = String::new();
        for quantum in input.chunks(3) {
            let mut bits: u32 = 0;
            for i in 0..3 {
                bits = (bits << 8) | u32::from(quantum.get(i).copied().unwrap_or(0));
            }
            let significant = quantum.len() + 1;
            for i in 0..significant {
                let sextet = (bits >> (18 - 6 * i)) & 0x3f;
                out.push(char::from(ALPHABET[sextet as usize]));
            }
            for _ in significant..4 {
                out.push('=');
            }
        }
        out
    }

    fn authenticator(users: &[(&str, &str)]) -> Authenticator {
        Authenticator::new(&config::Auth {
            users: users
                .iter()
                .map(|(username, password)| config::User {
                    username: (*username).to_owned(),
                    password: (*password).to_owned(),
                })
                .collect(),
        })
    }

    /// The two fields credentials may arrive in (decision D3).
    const PROXY_AUTHORIZATION: &str = "proxy-authorization";
    const AUTHORIZATION: &str = "authorization";

    fn value(text: &str) -> FieldValue {
        FieldValue::parse(text.as_bytes()).expect("field value")
    }

    fn basic(username: &str, password: &str) -> FieldValue {
        let token = encode_base64(format!("{username}:{password}").as_bytes());
        value(&format!("Basic {token}"))
    }

    fn fields(pairs: &[(&str, FieldValue)]) -> Fields {
        let mut fields = Fields::new();
        for (name, value) in pairs {
            fields.append(*name, value.clone());
        }
        fields
    }

    #[test]
    fn no_users_disables_authentication() {
        let auth = authenticator(&[]);
        assert!(auth.is_disabled());
        // Even a nonsense credential is irrelevant when nothing is required.
        assert_eq!(auth.authenticate(&Fields::new()), Ok(None));
        assert_eq!(
            auth.authenticate(&fields(&[(PROXY_AUTHORIZATION, value("garbage"))])),
            Ok(None)
        );
    }

    #[test]
    fn proxy_authorization_is_accepted() {
        let auth = authenticator(&[("user1", "s3cret")]);
        let fields = fields(&[(PROXY_AUTHORIZATION, basic("user1", "s3cret"))]);
        assert_eq!(auth.authenticate(&fields), Ok(Some("user1")));
    }

    /// The fallback that makes decision D3 safe to leave open.
    #[test]
    fn authorization_is_accepted_as_a_fallback() {
        let auth = authenticator(&[("user1", "s3cret")]);
        let fields = fields(&[(AUTHORIZATION, basic("user1", "s3cret"))]);
        assert_eq!(auth.authenticate(&fields), Ok(Some("user1")));
    }

    /// Whichever header carries the good credentials, the request passes.
    #[test]
    fn either_header_matching_is_enough() {
        let auth = authenticator(&[("user1", "s3cret")]);

        let good_fallback = fields(&[
            (PROXY_AUTHORIZATION, basic("user1", "wrong")),
            (AUTHORIZATION, basic("user1", "s3cret")),
        ]);
        assert_eq!(auth.authenticate(&good_fallback), Ok(Some("user1")));

        let good_primary = fields(&[
            (PROXY_AUTHORIZATION, basic("user1", "s3cret")),
            (AUTHORIZATION, basic("user1", "wrong")),
        ]);
        assert_eq!(auth.authenticate(&good_primary), Ok(Some("user1")));
    }

    #[test]
    fn the_right_user_out_of_several_is_reported() {
        let auth = authenticator(&[("a", "pw-a"), ("b", "pw-b"), ("c", "pw-c")]);

        for (username, password) in [("a", "pw-a"), ("b", "pw-b"), ("c", "pw-c")] {
            let fields = fields(&[(PROXY_AUTHORIZATION, basic(username, password))]);
            assert_eq!(auth.authenticate(&fields), Ok(Some(username)));
        }
    }

    /// A username from one user and a password from another must not combine into
    /// a valid credential — the trap a per-field lookup would fall into.
    #[test]
    fn credentials_may_not_be_mixed_between_users() {
        let auth = authenticator(&[("a", "pw-a"), ("b", "pw-b")]);
        let fields = fields(&[(PROXY_AUTHORIZATION, basic("a", "pw-b"))]);

        assert_eq!(
            auth.authenticate(&fields),
            Err(Denied::Rejected {
                username: "a".to_owned()
            })
        );
    }

    #[test]
    fn wrong_credentials_are_rejected_and_name_the_attempted_user() {
        let auth = authenticator(&[("user1", "s3cret")]);

        for (username, password) in [("user1", "wrong"), ("user2", "s3cret"), ("", "")] {
            let fields = fields(&[(PROXY_AUTHORIZATION, basic(username, password))]);
            let denied = auth.authenticate(&fields).expect_err("must be rejected");
            assert_eq!(denied.username(), Some(username), "{denied:?}");
        }
    }

    /// A near-miss must not pass: no prefix, case or padding leniency anywhere.
    #[test]
    fn near_misses_are_rejected() {
        let auth = authenticator(&[("user1", "s3cret")]);

        for (username, password) in [
            ("user1", "s3cre"),
            ("user1", "s3crett"),
            ("user1", "S3cret"),
            ("user1", " s3cret"),
            ("user1", "s3cret "),
            ("USER1", "s3cret"),
            ("user1 ", "s3cret"),
        ] {
            let fields = fields(&[(PROXY_AUTHORIZATION, basic(username, password))]);
            assert!(
                auth.authenticate(&fields).is_err(),
                "{username:?}/{password:?} must not authenticate"
            );
        }
    }

    #[test]
    fn missing_credentials_are_reported_as_missing() {
        let auth = authenticator(&[("user1", "s3cret")]);
        assert_eq!(auth.authenticate(&Fields::new()), Err(Denied::Missing));
        assert_eq!(Denied::Missing.username(), None);
    }

    #[test]
    fn malformed_credentials_are_rejected() {
        let auth = authenticator(&[("user1", "s3cret")]);

        let cases = [
            // No scheme at all.
            "dXNlcjE6czNjcmV0",
            // The wrong scheme.
            "Bearer dXNlcjE6czNjcmV0",
            "Digest dXNlcjE6czNjcmV0",
            // Not base64.
            "Basic not base64!",
            "Basic dXNlcjE6czNjcmV",
            // Base64 without a colon in it.
            "Basic dXNlcjE=",
            // Empty token.
            "Basic ",
        ];

        for case in cases {
            let fields = fields(&[(PROXY_AUTHORIZATION, value(case))]);
            let denied = auth.authenticate(&fields).expect_err("must be rejected");
            assert!(
                matches!(denied, Denied::Malformed(_)),
                "{case:?} gave {denied:?}"
            );
            // Whatever the reason, it must not quote the credentials back.
            assert!(!denied.reason().contains("dXNl"), "{denied:?}");
        }
    }

    /// The scheme is case-insensitive (RFC 9110 §11.1) and extra spaces are legal.
    #[test]
    fn the_scheme_is_case_insensitive() {
        let auth = authenticator(&[("user1", "s3cret")]);
        let token = encode_base64(b"user1:s3cret");

        for text in [
            format!("basic {token}"),
            format!("BASIC {token}"),
            format!("bAsIc {token}"),
            format!("Basic  {token}"),
        ] {
            let fields = fields(&[(PROXY_AUTHORIZATION, value(&text))]);
            assert_eq!(
                auth.authenticate(&fields),
                Ok(Some("user1")),
                "{text:?} must authenticate"
            );
        }
    }

    /// RFC 7617 lets a password contain colons; only the first one separates.
    #[test]
    fn passwords_may_contain_colons() {
        let auth = authenticator(&[("user1", "a:b:c")]);
        let fields = fields(&[(PROXY_AUTHORIZATION, basic("user1", "a:b:c"))]);
        assert_eq!(auth.authenticate(&fields), Ok(Some("user1")));
    }

    /// Credentials are bytes, so non-ASCII passwords work as long as the client
    /// encodes them the same way the config file does.
    #[test]
    fn non_ascii_credentials_round_trip() {
        let auth = authenticator(&[("üser", "pässwörd")]);
        let fields = fields(&[(PROXY_AUTHORIZATION, basic("üser", "pässwörd"))]);
        assert_eq!(auth.authenticate(&fields), Ok(Some("üser")));
    }

    #[test]
    fn the_challenge_names_the_realm() {
        let fields = challenge_fields();
        assert_eq!(
            fields.get(PROXY_AUTHENTICATE).and_then(FieldValue::to_str),
            Some("Basic realm=\"masque\"")
        );
    }

    #[test]
    fn base64_decodes_every_padding_case() {
        // One, two and zero padding characters respectively.
        for plain in [
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"abcd"[..],
            &b"user1:s3cret"[..],
            &[0x00, 0xff, 0x80, 0x7f][..],
        ] {
            let encoded = encode_base64(plain);
            assert_eq!(
                decode_base64(encoded.as_bytes()).as_deref(),
                Some(plain),
                "{encoded:?}"
            );
        }
    }

    #[test]
    fn base64_matches_a_known_vector() {
        // RFC 7617 §2's own example.
        assert_eq!(
            decode_base64(b"QWxhZGRpbjpvcGVuIHNlc2FtZQ==").as_deref(),
            Some(&b"Aladdin:open sesame"[..])
        );
    }

    #[test]
    fn base64_rejects_malformed_input() {
        for case in [
            &b""[..],
            // Not a multiple of four.
            &b"YQ"[..],
            &b"YWJjZA"[..],
            // Padding in the middle.
            &b"YQ==YQ=="[..],
            &b"Y=JD"[..],
            // Too much padding.
            &b"===="[..],
            &b"Y==="[..],
            // Outside the alphabet: whitespace, newline, url-safe variants.
            &b"YQ =="[..],
            &b"YWJj\nZA=="[..],
            &b"YQ-="[..],
            &b"YQ_="[..],
        ] {
            assert_eq!(
                decode_base64(case),
                None,
                "{:?} must not decode",
                String::from_utf8_lossy(case)
            );
        }
    }
}
