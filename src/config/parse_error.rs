use std::path::Path;

use anyhow::anyhow;

/// Renders a TOML parse failure without the source line it points at.
///
/// The `toml` crate's `Display` for a deserialization error prints the offending
/// line under a caret, the way a compiler does. That is the wrong shape for this
/// file, and only for this file: a syntax error on a `password = ...` line puts
/// the password on stderr at startup and on every `SIGHUP` reload, and
/// `Restart=on-failure` repeats a failing start every few seconds. So the error
/// never reaches the chain at all. What is
/// reported is the parser's own message plus the position it points at, and the
/// configuration text is not in scope for either.
///
/// The file, line and column are still named. See [`redact_quoted`] for the
/// part of the message that would otherwise copy the value.
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
const REDACTED: &str = "`<redacted>`";

/// Replaces every quoted segment of a parser message with [`REDACTED`].
///
/// Keeping the source line out of the error is not enough on its own, because
/// `toml::de::Error::message` quotes the offending value itself whenever serde
/// is the one that objected. Which quotes it uses is decided by the type serde
/// found, and both kinds carry a value: `password = 8675309` renders as
/// ``invalid type: integer `8675309`, expected a string``, while anything serde
/// reads as a string keeps its double quotes, so `users = ["user1:hunter2"]`
/// renders as `invalid type: string "user1:hunter2", expected struct User`,
/// credentials included. Either way that is the password on stderr by a
/// different route.
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
/// being read as the end of the segment. The last backslash before the real
/// closing quote is `\\`'s second half, so the skip lands on that quote rather
/// than over it.
///
/// A backtick segment has no escapes; see [`closing_backtick`].
///
/// Bytes rather than characters throughout. Neither the backslash nor either
/// quote can appear inside a multi-byte UTF-8 character, so a skip that lands
/// mid-character cannot be mistaken for one of them, and the offset returned
/// always points at an ASCII quote.
fn closing_quote(rest: &str, quote: char) -> Option<usize> {
    if quote != '"' {
        return closing_backtick(rest);
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

/// The clauses serde writes after a value it quotes in backticks.
///
/// serde writes the value, then one of these, once, and nothing it quotes from
/// the file comes after it.
const CLAUSES: [&str; 2] = [", expected ", ", there are "];

/// What follows a closing backtick in a list of names serde writes, such as
/// `` `a`, `b` `` or `` `a` or `b` ``.
const LIST_SEPARATORS: [&str; 2] = [", `", " or `"];

/// The offset of the backtick that closes a backtick segment, counted like
/// [`closing_quote`].
///
/// The last backtick followed by one of [`CLAUSES`], if there is one: the value
/// comes before serde's own clause, so a value that holds a clause of its own
/// cannot close its segment before serde's. Otherwise the first backtick that
/// ends the message or is followed by one of [`LIST_SEPARATORS`], which is how
/// the names after a clause are closed. A backtick followed by anything else is
/// inside the value. `None` when no backtick qualifies, which redacts to the
/// end of the message: the lexer's own messages can end that way, and they
/// quote no value, so the cost is the rest of a sentence and never a secret.
fn closing_backtick(rest: &str) -> Option<usize> {
    let followed_by = |index: usize, phrases: &[&str]| {
        let after = &rest[index + 1..];
        phrases.iter().any(|phrase| after.starts_with(phrase))
    };
    rest.rmatch_indices('`')
        .map(|(index, _)| index)
        .find(|&index| followed_by(index, &CLAUSES))
        .or_else(|| {
            rest.match_indices('`')
                .map(|(index, _)| index)
                .find(|&index| index + 1 == rest.len() || followed_by(index, &LIST_SEPARATORS))
        })
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
/// message, so it must not become a panic of its own. Nor may it become a
/// fabricated line 1, column 1, which would send the operator to a line that is
/// not the one at fault.
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

    /// A secret written where an enum value belongs, on line 7, which serde
    /// quotes in backticks: ``unknown variant `{value}`, expected one of ...``.
    fn config_with_raw_congestion_control(value: &str) -> String {
        config_with_raw_max_connections(value).replace("max_connections", "congestion_control")
    }

    /// A parse error must name where it is, and must not quote what is there.
    ///
    /// Ways of getting the quotes wrong, because they fail at different depths.
    /// A bare word is rejected by the lexer, which never sees a value and so
    /// cannot quote one. An integer and a boolean are *valid* TOML values of the
    /// wrong type, and there serde is the one that objects, with the value in
    /// its message (``invalid type: integer `8675309`, expected a string``):
    /// the password on stderr by a route the caret block never touched.
    ///
    /// The rest are the same objection about a value serde renders in double
    /// quotes (`invalid type: string "user1:hunter2", expected struct User`)
    /// or, for an enum value, in backticks, most of them with a quote character
    /// or a phrase of the parser's own inside the secret.
    ///
    /// Both renderings of an `anyhow` error are checked because the two print
    /// different things: `{:#}` walks the chain of messages, `{:?}` adds the
    /// sources and any backtrace.
    #[test]
    fn a_parse_error_does_not_echo_the_value_it_rejects() {
        // Tag, the broken config, what must not survive in the message, and
        // whether the parser quoted a value at all: the lexer's complaint names
        // none, so there is nothing there for the marker to replace.
        let cases: [(&str, String, &[&str], bool); 14] = [
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
            // A backtick inside a double-quoted secret belongs to the
            // redaction rather than opening a segment of its own.
            (
                "backticked-string",
                config_with_raw_user("\"user1:hunter2`x\""),
                &["hunter2"],
                true,
            ),
            // A double quote inside the secret, which serde renders escaped
            // (`{:?}`). Written as a TOML literal string, which needs no
            // escaping of its own to carry one.
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
            // A backtick inside a value serde quotes in backticks. The three
            // cases are the characters a closing backtick is followed by in a
            // real message: a word, a space and a comma.
            (
                "backtick-in-enum-value",
                config_with_raw_congestion_control("\"a`hunter2-TAILSECRET\""),
                &["hunter2", "TAILSECRET"],
                true,
            ),
            (
                "backtick-space-in-enum-value",
                config_with_raw_congestion_control("\"a` hunter2-TAILSECRET\""),
                &["hunter2", "TAILSECRET"],
                true,
            ),
            (
                "backtick-comma-in-enum-value",
                config_with_raw_congestion_control("\"a`, hunter2-TAILSECRET\""),
                &["hunter2", "TAILSECRET"],
                true,
            ),
            // The two clauses serde writes after the value, inside the value.
            // A segment that ended at the first backtick followed by one of
            // them closed after `x` and printed the rest.
            (
                "expected-clause-in-enum-value",
                config_with_raw_congestion_control("\"x`, expected hunter2-TAILSECRET\""),
                &["hunter2", "TAILSECRET"],
                true,
            ),
            (
                "there-are-clause-in-enum-value",
                config_with_raw_congestion_control("\"x`, there are hunter2-TAILSECRET\""),
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
    #[test]
    fn each_quote_kind_is_scanned_by_its_own_rules() {
        assert_eq!(
            redact_quoted("unknown variant `\\`, expected one of `this`, `that`"),
            format!("unknown variant {REDACTED}, expected one of {REDACTED}, {REDACTED}"),
            "a backslash inside a backtick segment is a byte, not an escape"
        );

        // A backtick segment ends only where a real message goes on. A
        // backtick followed by anything else is part of the value, and a
        // segment that never meets a real end runs to the end of the message.
        assert_eq!(
            redact_quoted("unknown variant `a`b c`, expected `x` or `y`"),
            format!("unknown variant {REDACTED}, expected {REDACTED} or {REDACTED}"),
        );
        assert_eq!(
            redact_quoted("unknown variant `a` b"),
            format!("unknown variant {REDACTED}"),
        );
        // A value that holds serde's own clause closes at the clause serde
        // wrote, the last one, and the list after it is still read as a list.
        assert_eq!(
            redact_quoted("unknown variant `x`, expected y`, expected one of `a`, `b`"),
            format!("unknown variant {REDACTED}, expected one of {REDACTED}, {REDACTED}"),
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

    /// A double-quoted segment with nothing closing it redacts to the end of the
    /// message.
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

    /// A span the text cannot place must cost the position, not the message,
    /// and must not become a line the fault is not on.
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
