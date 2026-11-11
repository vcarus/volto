use std::path::Path;

use anyhow::anyhow;

/// Renders a TOML parse failure without the source line it points at.
///
/// The `toml` crate's `Display` for a deserialization error prints the offending
/// line under a caret, the way a compiler does. That is the wrong shape for this
/// file, and only for this file: a syntax error on a `password = ...` line puts
/// the password on stderr at startup and into the journal on every `SIGHUP`
/// reload, where `Restart=on-failure` reprints it every few seconds until
/// somebody notices. So the error never reaches the chain at all — what is
/// reported is the parser's own message plus the position it points at, and the
/// configuration text is not in scope for either.
///
/// The operator loses nothing they need: the file, the line and the column are
/// all still named, which is what it takes to find a typo. What the message
/// carries is the parser's account of what it found and what it expected there,
/// rather than a copy of what was written — see [`redact_quoted`] for the half
/// of that account which is a copy after all.
pub(super) fn parse_error(path: &Path, text: &str, error: &toml::de::Error) -> anyhow::Error {
    let message = redact_quoted(error.message());

    // No span, or a span this text cannot place: the message is worth having
    // without a position, and a position that is not the mistake's is worse
    // than none.
    let Some((line, column)) = error
        .span()
        .and_then(|span| line_and_column(text, span.start))
    else {
        return anyhow!("failed to parse config file {}: {message}", path.display());
    };

    anyhow!(
        "failed to parse config file {} at line {line}, column {column}: {message}",
        path.display()
    )
}

/// What a redacted quoted segment is replaced by.
///
/// Backticks are kept around it so the sentence still reads the way the parser
/// wrote it, and they are kept whichever quotes the segment had: one marker to
/// look for is worth more than a faithful copy of the punctuation around
/// something that is no longer there.
const REDACTED: &str = "`<redacted>`";

/// Replaces every quoted segment of a parser message with [`REDACTED`].
///
/// Keeping the source line out of the error is not enough on its own, because
/// `toml::de::Error::message` quotes the offending value itself whenever serde
/// is the one that objected. Which quotes it uses is decided by the type serde
/// found, and both kinds carry a value: `password = 8675309` renders as
/// ``invalid type: integer `8675309`, expected a string``, while anything serde
/// reads as a string keeps its double quotes, so `users = ["user1:hunter2"]`
/// renders as `invalid type: string "user1:hunter2", expected struct User` —
/// credentials and all. Either way that is the password on stderr again by a
/// different route, and the double-quoted route survived the first fix, which
/// knew only about backticks.
///
/// So both characters open a segment, and a segment ends at the same character
/// that opened it: a backtick inside a double-quoted string belongs to the
/// redaction rather than starting another one, which is what keeps a password
/// containing a backtick from splitting its own rendering into "safe" halves.
/// Keys are quoted the same way and are redacted with them; that costs the
/// operator nothing the line and column do not still give them.
///
/// A double quote inside the value is the same trap one level down. serde
/// renders a string with `{:?}`, so `hun"ter2` arrives as `hun\"ter2`, and a
/// scan that stops at the first `"` it sees closes the segment in the middle of
/// the secret and puts the rest of it back in the sentence. Hence
/// [`closing_quote`], which skips the character after every backslash.
fn redact_quoted(message: &str) -> String {
    let mut redacted = String::with_capacity(message.len());
    let mut rest = message;

    while let Some(open) = rest.find(is_quote) {
        redacted.push_str(&rest[..open]);
        redacted.push_str(REDACTED);

        // Both quote characters are ASCII, so this byte is the whole character.
        let quote = char::from(rest.as_bytes()[open]);

        // An unpaired opening quote opens a segment with no end, so everything
        // after it is part of the redaction rather than part of the message.
        let Some(close) = closing_quote(&rest[open + 1..], quote) else {
            return redacted;
        };
        rest = &rest[open + 1 + close + 1..];
    }

    redacted.push_str(rest);
    redacted
}

/// The offset of the character that closes a segment `quote` opened, if there
/// is one, counted from the character after that opening quote.
///
/// Only a double-quoted segment has an escape convention to respect, because
/// only it is a `{:?}` rendering: serde spells the value it rejected with
/// `Debug`, so a double quote inside it arrives as `\"` and a backslash as
/// `\\`. Skipping the character after every backslash is what keeps both from
/// being read as the end of the segment -- and the last backslash before the
/// real closing quote is `\\`'s second half, so the skip lands on that quote
/// rather than over it.
///
/// A backtick segment is `{}`-rendered and has no escapes at all, so it is
/// scanned as it always was: anything else would make a backslash in a value
/// swallow the character behind it.
///
/// Bytes rather than characters throughout. Neither the backslash nor either
/// quote can appear inside a multi-byte UTF-8 character, so a skip that lands
/// mid-character cannot be mistaken for one of them, and the offset returned
/// always points at an ASCII quote.
fn closing_quote(rest: &str, quote: char) -> Option<usize> {
    if quote != '"' {
        return rest.find(quote);
    }

    // An iterator rather than a hand-stepped index: every pass consumes at
    // least one byte, so the scan cannot fail to terminate, and a defect in
    // the skip is a wrong answer instead of a hung error path.
    let mut bytes = rest.bytes().enumerate();
    while let Some((index, byte)) = bytes.next() {
        match byte {
            // The skip lands on the escaped byte. A message that ends in a
            // lone backslash has nothing to skip and the iterator runs out: an
            // opening quote with no close, redacted to the end.
            b'\\' => {
                bytes.next();
            }
            b'"' => return Some(index),
            _ => {}
        }
    }

    None
}

/// Whether `character` is one of the two a parser message quotes with.
fn is_quote(character: char) -> bool {
    character == '`' || character == '"'
}

/// The 1-based line and column of a byte offset into `text`, if it has one.
///
/// The `toml` crate reports a span and renders the position itself, but only as
/// part of the caret block [`parse_error`] exists to avoid, so the arithmetic is
/// repeated here. Columns are counted in characters rather than bytes, which is
/// what an editor shows.
///
/// `None` for an offset past the end of `text` or one landing inside a
/// multi-byte character: the position is a convenience on the way to an error
/// message, so it must not become a panic of its own — and it must not become a
/// fabricated line 1, column 1 either, which would send the operator to a line
/// that is not the one at fault.
fn line_and_column(text: &str, offset: usize) -> Option<(usize, usize)> {
    let before = text.get(..offset)?;

    let line = before.matches('\n').count() + 1;
    let column = before
        .rsplit_once('\n')
        .map_or(before, |(_, tail)| tail)
        .chars()
        .count()
        + 1;

    Some((line, column))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::Config;

    /// A file that removes itself however the test ends.
    ///
    /// The test below writes a password into the system temp directory, and a
    /// plain `remove_file` after the assertions only cleans up when they all
    /// pass — the failing run, the one somebody is about to go and look at, is
    /// exactly the run that would leave the file behind.
    struct TempConfig(std::path::PathBuf);

    impl TempConfig {
        fn write(tag: &str, body: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("volto-config-{tag}-{}.toml", std::process::id()));
            std::fs::write(&path, body).expect("write the broken config");
            Self(path)
        }
    }

    impl Drop for TempConfig {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Wraps `entry` in the smallest config that reaches the `[auth]` users
    /// array, with the entry on line 7.
    fn config_with_raw_user(entry: &str) -> String {
        format!(
            "[server]\n\
             listen = \"127.0.0.1:4433\"\n\
             cert = \"/tmp/c.pem\"\n\
             key = \"/tmp/k.pem\"\n\
             [auth]\n\
             users = [\n\
             {entry},\n\
             ]\n"
        )
    }

    /// [`config_with_raw_user`] with `password` written into a user table, so
    /// the password is the value serde rejects — on line 7.
    fn config_with_raw_password(password: &str) -> String {
        config_with_raw_user(&format!(
            "{{ username = \"user1\", password = {password} }}"
        ))
    }

    /// A secret written where an integer belongs, also on line 7.
    ///
    /// Nothing in `[limits]` is a credential, but what serde does with a string
    /// does not depend on the key it was written under: this is the same leak in
    /// a section an operator would never think to be careful in.
    fn config_with_raw_max_connections(value: &str) -> String {
        format!(
            "[server]\n\
             listen = \"127.0.0.1:4433\"\n\
             cert = \"/tmp/c.pem\"\n\
             key = \"/tmp/k.pem\"\n\
             [limits]\n\
             \n\
             max_connections = {value}\n"
        )
    }

    /// A parse error must name where it is, and must not quote what is there.
    ///
    /// The `toml` crate renders a parse error as the offending source line under
    /// a caret, so a typo on a `password = ...` line used to print the password
    /// on stderr at startup and into the journal on every `SIGHUP` reload — and
    /// `Restart=on-failure` makes the startup path repeat every few seconds.
    ///
    /// Six ways of getting the quotes wrong, because they fail at different
    /// depths and only one of them was covered before. A bare word is rejected
    /// by the lexer, which never sees a value and so cannot quote one. An
    /// integer and a boolean are *valid* TOML values of the wrong type, and
    /// there serde is the one that objects — with the value in its message
    /// (``invalid type: integer `8675309`, expected a string``), which is the
    /// password on stderr by a route the caret block never touched.
    ///
    /// The last three are the same objection about a value serde reads as a
    /// *string*, which it renders in double quotes rather than backticks:
    /// `invalid type: string "user1:hunter2", expected struct User`. A
    /// redaction that knew only about backticks left every one of them
    /// untouched, whatever section the mistake was in — and the third of them is
    /// the case that decides where a segment ends, a secret with a backtick of
    /// its own inside a double-quoted rendering.
    ///
    /// Both renderings of an `anyhow` error are checked because the two print
    /// different things: `{:#}` walks the chain of messages, `{:?}` adds the
    /// sources and any backtrace.
    #[test]
    fn a_parse_error_does_not_echo_the_value_it_rejects() {
        // Tag, the broken config, what must not survive in the message, and
        // whether the parser quoted a value at all: the lexer's complaint names
        // none, so there is nothing there for the marker to replace.
        let cases: [(&str, String, &[&str], bool); 9] = [
            (
                "bare",
                config_with_raw_password("correct-horse-battery-staple"),
                &["correct-horse-battery-staple"],
                false,
            ),
            (
                "integer",
                config_with_raw_password("8675309"),
                &["8675309"],
                true,
            ),
            ("boolean", config_with_raw_password("true"), &["true"], true),
            (
                "string-for-struct",
                config_with_raw_user("\"user1:hunter2\""),
                &["hunter2"],
                true,
            ),
            (
                "string-for-integer",
                config_with_raw_max_connections("\"correct-horse-battery-staple\""),
                &["correct-horse-battery-staple"],
                true,
            ),
            // A backtick inside the secret. With only backticks redacted, the
            // one in the middle opened a segment that never closed and the
            // message kept everything in front of it -- `hunter2` included.
            (
                "backticked-string",
                config_with_raw_user("\"user1:hunter2`x\""),
                &["hunter2"],
                true,
            ),
            // A double quote inside the secret, which serde renders escaped
            // (`{:?}`) and a scan for the closing quote used to stop on: the
            // segment closed inside the secret and its tail went to stderr as
            // if it were part of the parser's sentence. Written as a TOML
            // literal string, which needs no escaping of its own to carry one.
            (
                "quote-in-secret",
                config_with_raw_user("'user1:hun\"ter2-TAILSECRET'"),
                &["hunter2", "TAILSECRET"],
                true,
            ),
            // The same character reached through a TOML basic string, so the
            // file itself escapes it as well: the value serde sees is identical
            // and so is the rendering.
            (
                "escaped-quote-in-secret",
                config_with_raw_user("\"user1:hun\\\"ter2-TAILSECRET\""),
                &["hunter2", "TAILSECRET"],
                true,
            ),
            // A secret ending in a backslash. Its rendering ends `\\"`, so a
            // scan that skips the character after every backslash must not
            // skip the closing quote itself -- and must not run off the end
            // looking for another one.
            (
                "backslash-before-the-close",
                config_with_raw_user("'user1:hunter2-TAILSECRET\\'"),
                &["hunter2", "TAILSECRET"],
                true,
            ),
        ];

        for (tag, body, secrets, marked) in cases {
            let file = TempConfig::write(tag, &body);
            let error = Config::load(&file.0).expect_err("a mistyped value must not load");

            for rendered in [format!("{error:#}"), format!("{error:?}")] {
                for secret in secrets {
                    assert!(
                        !rendered.contains(secret),
                        "the {tag} value leaked {secret}: {rendered}"
                    );
                }
                assert!(
                    rendered.contains(REDACTED) == marked,
                    "the {tag} value must {}leave a marker behind: {rendered}",
                    if marked { "" } else { "not " }
                );
                assert!(
                    rendered.contains("line 7"),
                    "the operator still has to be told where the mistake is: {rendered}"
                );
            }
        }
    }

    /// The redaction has to leave the parser's account of the mistake behind.
    ///
    /// A message with the value cut out of it is only useful if what is left
    /// still says what went wrong, so this pins the shape rather than only the
    /// absence: the type serde found, the type it wanted, and a marker where the
    /// value was.
    #[test]
    fn a_rejected_value_is_replaced_rather_than_dropped() {
        let file = TempConfig::write("typed", &config_with_raw_password("8675309"));
        let error = Config::load(&file.0).expect_err("an integer password must not load");
        let rendered = format!("{error:#}");

        assert!(
            rendered.contains(REDACTED),
            "the value must leave a marker behind: {rendered}"
        );
        assert!(
            rendered.contains("invalid type") && rendered.contains("expected a string"),
            "the parser's account of the mistake must survive: {rendered}"
        );
    }

    /// Each quote kind is scanned by its own escape rules, and closing a
    /// segment in the right place is what keeps the rest of the sentence alive.
    ///
    /// A backtick segment is a `{}` rendering with no escapes: a backslash
    /// inside one is just a byte, and skipping the character behind it would
    /// swallow the closing backtick and take the rest of the message with it.
    /// A double-quoted segment is a `{:?}` rendering where `\\` must be
    /// stepped over whole — a scan that read its second half as an escape
    /// would run past the real closing quote and redact the `expected` clause,
    /// which is the half of the message the operator fixes the typo by.
    /// (Both halves were unpinned when the batch-10 verification mutated them.)
    #[test]
    fn each_quote_kind_is_scanned_by_its_own_rules() {
        assert_eq!(
            redact_quoted("expected `\\` at the start, kept `this` whole"),
            format!("expected {REDACTED} at the start, kept {REDACTED} whole"),
            "a backslash inside a backtick segment is a byte, not an escape"
        );

        let file = TempConfig::write(
            "trailing-backslash-keeps-expected",
            &config_with_raw_user("'user1:hunter2-TAILSECRET\\'"),
        );
        let error =
            Config::load(&file.0).expect_err("a string where a table belongs must not load");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(", expected struct User"),
            "the escape skip must close at the real quote, not run past it: {rendered}"
        );
    }

    /// A double-quoted segment with nothing closing it must run out *at* the end
    /// of the message rather than one byte past it.
    ///
    /// The scan indexes bytes directly, so a bound that admitted the length
    /// itself would panic on the empty slot behind the last character — inside
    /// the error path whose whole job is to keep a password off stderr, and on
    /// the input that reaches it, since serde renders an unterminated string in
    /// the file as a value with no closing quote of its own.
    #[test]
    fn an_unclosed_double_quoted_segment_runs_out_at_the_end() {
        assert_eq!(closing_quote("hunter2", '"'), None, "no quote at all");
        // The other way of reaching the end: the escape skip steps over the
        // last byte instead of landing on it.
        assert_eq!(closing_quote("hunter2\\", '"'), None, "a lone backslash");
        assert_eq!(closing_quote("hunter2\"", '"'), Some(7), "a closed segment");

        assert_eq!(
            redact_quoted("invalid type: string \"user1:hunter2"),
            format!("invalid type: string {REDACTED}"),
            "an unpaired quote redacts everything after it"
        );
    }

    /// A span the text cannot place must cost the position, not the message.
    ///
    /// `line_and_column` used to answer line 1, column 1 for an offset past the
    /// end of the file or one landing inside a multi-byte character, which sends
    /// the operator to a line that is not the one at fault.
    #[test]
    fn an_unplaceable_offset_has_no_position() {
        let text = "a = \"é\"\n";

        assert_eq!(line_and_column(text, 0), Some((1, 1)));
        // Column 7 rather than the byte offset's 8: the accented character is
        // two bytes and one column, which is what an editor shows.
        assert_eq!(line_and_column(text, 7), Some((1, 7)));
        assert_eq!(line_and_column(text, 6), None, "inside a character");
        assert_eq!(line_and_column(text, 99), None, "past the end");
    }
}
