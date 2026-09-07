//! The prose documentation is an accounted set, not a hope.
//!
//! `docs/` is the operator's copy of what this server does, and until now
//! nothing checked it against the server. Every other gate in this suite reads
//! the tree as text -- `it_scrub` over the tracked files, `it_log_lines` over
//! every production log statement, `it_clock` over the wall clock -- and prose
//! was the one part of the tree with no such reader. `cargo doc` covers the
//! rustdoc, but that is a *structural* gate: it proves every public item has a
//! sentence, never that the sentence is true. This binary asks the questions
//! about prose that a machine can actually answer.
//!
//! # The five gates
//!
//! 1. **Configuration keys are one set, counted from both ends.** Every key
//!    `script/config.example.toml` assigns -- live or commented as
//!    `#key = value` -- must appear in `docs/configuration.md`, and every key
//!    that page documents must exist in the example and be accepted by
//!    [`volto::config::Config`], whose `deny_unknown_fields` makes the second
//!    half a real question rather than a formality.
//! 2. **Numbers quoted from the crate are the crate's numbers.** A doc page
//!    quotes a constant as `` `IDENT` = value `` -- backticked
//!    SCREAMING_SNAKE identifier, ` = `, then the value -- and this gate reads
//!    those pairs back and compares them with the items themselves.
//! 3. **Anchors resolve.** Every `docs/<page>.md#<anchor>` named in `src/` or
//!    `tests/`, and every `](...#anchor)` link inside `docs/` and `README.md`,
//!    has to name a heading that exists, judged by GitHub's own slug rules.
//! 4. **A procedure written twice is written once.** The manual installation
//!    appears in `docs/deployment.md`'s `## systemd` section and again in
//!    `script/masque.service`'s header comment, and the two command sequences
//!    have to be the same one.
//! 5. **A default written twice is written once.** The `# Default: X` line the
//!    example writes above each optional key and the Default column of the
//!    page's reference table are the same value.
//!
//! The set those five read is itself accounted for. Every `*.md` under `docs/`
//! is either in `DOC_PAGES` or exempt by name in `EXEMPT`, so a page added
//! without a decision fails here rather than going unread, the way a new file
//! under `src/` fails `it_log_lines` by default.
//!
//! # How each set is extracted, and why that way
//!
//! `docs/configuration.md` documents keys as **markdown table rows** under a
//! section heading: `## ` + a backticked table name, then rows whose first cell
//! is the backticked key. So that is what is read -- the first cell of a row,
//! while a heading naming a table is in force. It is deliberately not "every
//! backticked lowercase word on the page": the prose names keys constantly, in
//! sentences *about* them, and the "Introduced in" table under
//! `## Version compatibility` writes them qualified (`` `[limits].connect_timeout` ``)
//! for a different purpose. Reading rows under a table heading picks up exactly
//! the reference tables and nothing else.
//!
//! The example configuration is read with the convention `src/config.rs`'s own
//! tests describe: an optional key is written `#key = value` with the `#` hard
//! against the key, and prose is `# sentence` with a space. A value that spans
//! lines (`[auth] users`) is taken to its closing bracket.
//!
//! # What this cannot do
//!
//! It cannot read. Nothing here knows whether a sentence describes the server
//! correctly, whether an explanation is still true after a refactor, or whether
//! a paragraph documents behaviour that was removed two releases ago. What it
//! pins is the *mechanical* surface of the prose -- the key set, the numbers and
//! the links -- which is the part that goes stale silently. The semantic half
//! stays a human's job, and D104 says so rather than pretending otherwise.
//!
//! # Floors
//!
//! Each gate asserts a minimum count before it asserts anything about what it
//! found (D100's lesson: a gate that extracts nothing must fail, never pass
//! quietly). The floors are set below today's counts with room for ordinary
//! editing, so a page renamed, a heading convention changed, or a parser that
//! silently stops matching turns into a failure here rather than a green run
//! over an empty set.
//!
//! # Where the neighbouring claims live
//!
//! `src/config.rs`'s `the_example_documents_every_key_and_pins_every_default`
//! already owns the other two corners of the same triangle: the example against
//! `Config`'s fields, and every `# Default: N` in it against the compiled
//! default. This binary adds `docs/` as the third corner and does not repeat
//! either of those; gate 5 is the edge that closes it, since a Default column
//! is a table cell rather than the `` `IDENT` = value `` notation gate 2 reads
//! and was pinned by nothing before. `tests/it_bounds.rs` weighs the memory figures
//! `docs/configuration.md` quotes; gate 2 here is what makes its claim that
//! "`docs/configuration.md` quotes the same numbers" mechanical.

// The package-wide default is `deny` (`Cargo.toml`); this file argues for its
// allow: the counting is over the documentation this file scans.
#![allow(clippy::as_conversions)]

#[path = "common/scripts.rs"]
mod scripts;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use scripts::{read_text, repo_root, rust_files};
use volto::config::Config;

/// The prose pages this binary reads.
///
/// Named rather than globbed: a page added to `docs/` should arrive with a
/// decision about whether these gates cover it, and an empty glob would be one
/// more way for the whole file to pass without asserting anything.
///
/// `index.md` is the manual's landing page (D105) and is read like the rest, so
/// a link it writes to a section of another page is held to the same promise.
/// `docs/SUMMARY.md` is deliberately *not* here; [`EXEMPT`] carries it and the
/// reason. That the two lists together account for every `*.md` under `docs/`
/// is itself a test, [`every_page_under_docs_is_read_or_exempt_by_name`].
const DOC_PAGES: [&str; 4] = [
    "architecture.md",
    "configuration.md",
    "deployment.md",
    "index.md",
];

/// Keys the example must document and the page must carry, at the very least.
///
/// Today both sides hold 27. The floor is what stops a parser that quietly
/// stops matching -- a heading convention changed, a table reflowed -- from
/// comparing two empty sets and calling them equal.
const KEY_FLOOR: usize = 25;

/// Distinct constants the pages must be quoting, at the very least.
const CONSTANT_FLOOR: usize = 8;

/// Anchored references the tree must contain, at the very least.
const ANCHOR_FLOOR: usize = 10;

// ---------------------------------------------------------------------------
// Reading the tree
// ---------------------------------------------------------------------------

/// `docs/<name>`.
fn doc_path(name: &str) -> PathBuf {
    repo_root().join("docs").join(name)
}

/// Pages under `docs/` that are deliberately outside [`DOC_PAGES`].
///
/// `SUMMARY.md` is the book's table of contents rather than prose: it carries
/// no anchors, quotes no constants, and the chapter files it names are checked
/// by the site crawl in `.github/workflows/docs.yml`, which fails on a chapter
/// that does not build. That is D104's own reason, recorded in its 2026-09-02
/// addendum, and naming the file here is what keeps the reason attached to the
/// exemption.
const EXEMPT: [&str; 1] = ["SUMMARY.md"];

/// Every `*.md` under `docs/` is either read by these gates or exempt by name.
///
/// [`DOC_PAGES`] is hand-written and, until this test, nothing compared it with
/// the directory: a new page's `` `IDENT` = value `` quotes went unchecked and
/// its outgoing anchors unresolved. `it_log_lines` fails on a new file under
/// `src/` by default; this is the same latch for `docs/`, and it is what makes
/// the module comment's "should arrive with a decision" enforceable.
///
/// Both directions, because either one alone passes on an empty scan: a page on
/// disk that no list names, and a name on a list that no file answers to.
#[test]
fn every_page_under_docs_is_read_or_exempt_by_name() {
    let dir = repo_root().join("docs");
    let entries = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", dir.display()));

    let mut pages = BTreeSet::new();
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.extension().is_some_and(|kind| kind == "md")
            && let Some(name) = path.file_name().and_then(|name| name.to_str())
        {
            pages.insert(name.to_owned());
        }
    }

    let accounted: BTreeSet<&str> = DOC_PAGES.into_iter().chain(EXEMPT).collect();

    let unread: Vec<&String> = pages
        .iter()
        .filter(|name| !accounted.contains(name.as_str()))
        .collect();
    assert!(
        unread.is_empty(),
        "these pages are under docs/ and no gate in this binary reads them: \
         {unread:?}. Add each to `DOC_PAGES`, or to `EXEMPT` with the reason a \
         decision recorded"
    );

    let missing: Vec<&str> = accounted
        .iter()
        .copied()
        .filter(|name| !pages.contains(*name))
        .collect();
    assert!(
        missing.is_empty(),
        "`DOC_PAGES` and `EXEMPT` name pages that are not under docs/: \
         {missing:?}. A renamed page leaves this list guarding nothing"
    );
}

/// The lines of a markdown file that are prose, numbered from one.
///
/// Fenced code blocks are dropped whole. They carry shell comments that start
/// with `#` (`deployment.md` has several), which a heading scanner would read as
/// headings, and configuration snippets that a link or constant scanner would
/// read as claims the file is making.
fn prose_lines(text: &str) -> Vec<(usize, &str)> {
    let mut lines = Vec::new();
    let mut fenced = false;

    for (index, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if !fenced {
            lines.push((index + 1, line));
        }
    }

    lines
}

// ---------------------------------------------------------------------------
// Gate 1: the configuration keys
// ---------------------------------------------------------------------------

/// The key a line assigns, if it is a table-level assignment.
///
/// Column zero and a bare `lower_snake` name, which is what keeps the
/// `{ username = ... }` entries inside the example's `users` array -- indented,
/// and inside a value besides -- from being read as keys of the table they sit
/// in. The same rule `src/config.rs`'s tests use, for the same reason.
fn assigned_key(line: &str) -> Option<&str> {
    let (name, _) = line.split_once(" = ")?;
    let plausible = !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c == '_');
    plausible.then_some(name)
}

/// How many more brackets and braces `text` opens than it closes.
fn bracket_depth(text: &str) -> i32 {
    text.chars().fold(0, |depth, c| match c {
        '[' | '{' => depth + 1,
        ']' | '}' => depth - 1,
        _ => depth,
    })
}

/// Every key `script/config.example.toml` assigns, with the text of its value.
///
/// Commented keys are included: the file writes an optional key as
/// `#key = value` precisely so the operator can read the default, so a key that
/// is only ever commented is still a key the page has to document. A value that
/// spans lines is taken to the line that closes its brackets, comments and all
/// -- a comment inside a TOML array is still a comment, so the collected text
/// stays parseable.
fn example_keys() -> BTreeMap<(String, String), String> {
    let path = repo_root().join("script/config.example.toml");
    let text = read_text(&path);
    let lines: Vec<&str> = text.lines().collect();

    let mut keys = BTreeMap::new();
    let mut table = String::new();
    let mut index = 0;

    while index < lines.len() {
        let raw = lines[index];
        // `#key = value` is a commented key; `# sentence` is prose.
        let code = match raw.strip_prefix('#') {
            Some(rest) if rest.starts_with(' ') || rest.is_empty() => raw,
            Some(rest) => rest,
            None => raw,
        };

        if let Some(name) = code
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            table = name.to_owned();
            index += 1;
            continue;
        }

        let Some(key) = assigned_key(code) else {
            index += 1;
            continue;
        };
        let (_, first) = code.split_once(" = ").expect("assigned_key found one");

        let mut value = first.to_owned();
        let mut depth = bracket_depth(first);
        while depth > 0 {
            index += 1;
            let continuation = lines
                .get(index)
                .unwrap_or_else(|| panic!("{key} in the example has an unclosed value"));
            value.push('\n');
            value.push_str(continuation);
            depth += bracket_depth(continuation);
        }

        assert!(
            !table.is_empty(),
            "{key} in the example sits outside any table"
        );
        keys.insert((table.clone(), key.to_owned()), value);
        index += 1;
    }

    keys
}

/// Every key `docs/configuration.md` documents, as `(table, key)`.
///
/// Rows of the reference table under each `` ## `[table]` `` heading, and
/// nothing else -- see the module documentation for why that is the right
/// extraction for this page.
fn documented_keys() -> BTreeSet<(String, String)> {
    let text = read_text(&doc_path("configuration.md"));
    let mut keys = BTreeSet::new();
    let mut table: Option<String> = None;

    for (_, line) in prose_lines(&text) {
        if let Some(heading) = line.strip_prefix("## ") {
            table = heading
                .trim()
                .strip_prefix("`[")
                .and_then(|rest| rest.strip_suffix("]`"))
                .map(str::to_owned);
            continue;
        }

        let (Some(table), Some(rest)) = (table.as_ref(), line.strip_prefix("| `")) else {
            continue;
        };
        let Some((key, _)) = rest.split_once('`') else {
            continue;
        };
        if !key.is_empty() && key.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            keys.insert((table.clone(), key.to_owned()));
        }
    }

    keys
}

/// The example's keys and the page's keys are one set, and that set parses.
///
/// Both directions, because they fail differently. A key the example ships and
/// the page omits is a setting an operator can only find by reading the shipped
/// file; a key the page documents and the example does not have is advice about
/// a key that may not exist at all -- which is why the documented set is also
/// assembled into a TOML document and handed to the deserializer, where
/// `deny_unknown_fields` answers that question directly rather than by
/// transitivity through the example.
#[test]
fn every_configuration_key_is_documented_and_every_documented_key_parses() {
    let example = example_keys();
    let documented = documented_keys();

    assert!(
        example.len() >= KEY_FLOOR,
        "only {} keys found in script/config.example.toml; the reader is broken, \
         not the file",
        example.len()
    );
    assert!(
        documented.len() >= KEY_FLOOR,
        "only {} keys found in docs/configuration.md; the reader is broken, not \
         the page",
        documented.len()
    );

    let shipped: BTreeSet<(String, String)> = example.keys().cloned().collect();
    let undocumented: Vec<String> = shipped
        .difference(&documented)
        .map(|(table, key)| format!("[{table}].{key}"))
        .collect();
    assert!(
        undocumented.is_empty(),
        "script/config.example.toml ships keys docs/configuration.md does not \
         document: {undocumented:?}"
    );

    let invented: Vec<String> = documented
        .difference(&shipped)
        .map(|(table, key)| format!("[{table}].{key}"))
        .collect();
    assert!(
        invented.is_empty(),
        "docs/configuration.md documents keys script/config.example.toml does \
         not ship: {invented:?}"
    );

    // Built from the documented set rather than from the example, so that what
    // the deserializer judges is what the page told the operator to write.
    let mut document = String::new();
    let mut current: Option<&str> = None;
    for (table, key) in &documented {
        if current != Some(table.as_str()) {
            document.push_str(&format!("[{table}]\n"));
            current = Some(table);
        }
        let value = example
            .get(&(table.clone(), key.clone()))
            .unwrap_or_else(|| panic!("[{table}].{key} has no value in the example"));
        document.push_str(&format!("{key} = {value}\n"));
    }

    let config: Config = toml::from_str(&document).unwrap_or_else(|error| {
        panic!("the keys docs/configuration.md documents must parse: {error}\n{document}")
    });
    assert_eq!(
        config.auth.users.len(),
        1,
        "the document assembled from the documented keys must carry the \
         example's values, not defaults"
    );
}

// ---------------------------------------------------------------------------
// Gate 2: the constants the pages quote
// ---------------------------------------------------------------------------

/// The constants a doc page may quote, and what they actually are.
///
/// Every one of these is `pub` for this reason as much as any other: a number an
/// operator reads in `docs/` is part of the interface, so the item behind it is
/// too. A page that quotes an identifier missing from this table fails as
/// loudly as one that quotes a wrong value -- otherwise a renamed constant would
/// simply stop being checked.
///
/// Read in the other direction as well, by
/// [`the_table_names_no_constant_the_pages_stopped_quoting`]: an entry no page
/// quotes any more is guarding nothing, so it comes out.
fn crate_constants() -> BTreeMap<&'static str, u64> {
    BTreeMap::from([
        ("SEND_WINDOW", volto::quic::SEND_WINDOW),
        ("FD_HEADROOM", volto::quic::FD_HEADROOM),
        (
            "MAX_PEER_UNI_STREAMS",
            u64::from(volto::quic::MAX_PEER_UNI_STREAMS),
        ),
        (
            "INITIAL_BIDI_STREAMS",
            u64::from(volto::quic::INITIAL_BIDI_STREAMS),
        ),
        (
            "MAX_FIELD_SECTION_SIZE",
            volto::h3api::MAX_FIELD_SECTION_SIZE,
        ),
        (
            "HEADERS_BUFFER_BUDGET",
            volto::h3::HEADERS_BUFFER_BUDGET as u64,
        ),
        (
            "CONNECTION_UNANSWERED_MULTIPLIER",
            u64::from(volto::tunnel::CONNECTION_UNANSWERED_MULTIPLIER),
        ),
        ("RELAY_BUF_SIZE", volto::tunnel::tcp::RELAY_BUF_SIZE as u64),
        (
            "RELAY_BLOCK_SIZE",
            volto::tunnel::tcp::RELAY_BLOCK_SIZE as u64,
        ),
        (
            "DEFAULT_UDP_SESSION_TIMEOUT",
            volto::config::DEFAULT_UDP_SESSION_TIMEOUT,
        ),
        (
            "DEFAULT_SOCKET_RECV_BUFFER",
            volto::config::DEFAULT_SOCKET_RECV_BUFFER as u64,
        ),
        (
            "DEFAULT_SOCKET_SEND_BUFFER",
            volto::config::DEFAULT_SOCKET_SEND_BUFFER as u64,
        ),
    ])
}

/// The units a quoted value may carry, and what each one multiplies by.
///
/// `s` and `ms` are here as units of the value's own dimension rather than as
/// multipliers: a timeout in seconds is stored in seconds, and writing "180 s"
/// beside it is what makes the sentence readable.
const UNITS: [(&str, u64); 8] = [
    ("B", 1),
    ("KiB", 1024),
    ("MiB", 1024 * 1024),
    ("GiB", 1024 * 1024 * 1024),
    ("kB", 1_000),
    ("MB", 1_000_000),
    ("s", 1),
    ("ms", 1),
];

/// The value a quote carries, in the constant's own unit.
///
/// `None` when what follows ` = ` is not a number at all, which is how prose
/// that happens to put an equals sign after a backticked word stays prose.
fn quoted_value(rest: &str) -> Option<u64> {
    let digits: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '_' || *c == ',')
        .collect();
    let number: u64 = digits.replace(['_', ','], "").parse().ok()?;

    let tail = rest[digits.len()..].strip_prefix(' ').unwrap_or("");
    let word: String = tail
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    let multiplier = UNITS
        .iter()
        .find(|(unit, _)| *unit == word)
        .map_or(1, |(_, multiplier)| *multiplier);

    Some(number * multiplier)
}

/// One `` `IDENT` = value `` quote, and where it was found.
struct Quote {
    /// The source's path relative to the repository root.
    source: String,
    line: usize,
    name: String,
    value: Option<u64>,
}

/// Every constant quote on the doc pages and in the example configuration.
///
/// The example is read too, and not only the pages: it is the file that lands on
/// the host and the one most operators read, so a number it quotes from the crate
/// has to be the crate's number for the same reason a page's does. Nothing in it
/// used the notation until `CONNECTION_UNANSWERED_MULTIPLIER` arrived in the
/// `unanswered_packet_budget` comment, and this is what makes that quote a claim
/// rather than a copy. `prose_lines` drops fenced blocks, of which a TOML file has
/// none, so every line of it is read.
fn quotes() -> Vec<Quote> {
    let mut found = Vec::new();

    let sources = DOC_PAGES
        .map(doc_path)
        .into_iter()
        .chain([repo_root().join("script/config.example.toml")]);

    for source in sources {
        let named = if source.extension().is_some_and(|kind| kind == "toml") {
            "script/config.example.toml".to_owned()
        } else {
            let name = DOC_PAGES
                .into_iter()
                .find(|name| source.ends_with(name))
                .expect("every markdown source is one of DOC_PAGES");
            format!("docs/{name}")
        };
        let text = read_text(&source);
        for (line, content) in prose_lines(&text) {
            let mut rest = content;
            while let Some(open) = rest.find('`') {
                let after_open = &rest[open + 1..];
                let Some(close) = after_open.find('`') else {
                    break;
                };
                let name = &after_open[..close];
                let tail = &after_open[close + 1..];

                let screaming = !name.is_empty()
                    && name.starts_with(|c: char| c.is_ascii_uppercase())
                    && name
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
                if screaming && let Some(value) = tail.strip_prefix(" = ") {
                    let parsed = quoted_value(value);
                    if parsed.is_some() {
                        found.push(Quote {
                            source: named.clone(),
                            line,
                            name: name.to_owned(),
                            value: parsed,
                        });
                    }
                }

                rest = tail;
            }
        }
    }

    found
}

/// Every number a doc page quotes from the crate is the crate's number.
///
/// The notation is one thing and only one thing: a backticked SCREAMING_SNAKE
/// identifier, ` = `, then the value, optionally with a unit. That is what makes
/// the claim checkable at all -- prose can say "sixteen" and "64 KiB" in as many
/// ways as it likes, but a quote of a *constant* has one spelling, and this gate
/// is what keeps a value from drifting away from the item it names.
#[test]
fn every_constant_quoted_in_the_docs_matches_the_crate() {
    let constants = crate_constants();
    let quotes = quotes();

    let quoted: BTreeSet<&str> = quotes.iter().map(|quote| quote.name.as_str()).collect();
    assert!(
        quoted.len() >= CONSTANT_FLOOR,
        "only {} distinct constants are quoted in docs/ and the example \
         ({quoted:?}); the reader is broken, or the notation `IDENT` = value has \
         been edited away",
        quoted.len()
    );

    for quote in &quotes {
        let Quote {
            source,
            line,
            name,
            value,
        } = quote;
        let actual = constants.get(name.as_str()).unwrap_or_else(|| {
            panic!(
                "{source}:{line} quotes `{name}`, which is not a constant this \
                 gate knows; add it to `crate_constants` or fix the name"
            )
        });
        let value = value.expect("only parsed quotes are collected");
        assert_eq!(
            value, *actual,
            "{source}:{line} says `{name}` = {value}, the crate says {actual}"
        );
    }
}

/// And an entry in the table that no page quotes any more is guarding nothing.
///
/// The allowlist was read in one direction only: a page that drops its last
/// quote of a constant left the entry behind, silently, and the gate above went
/// on passing over a smaller set than it was written for. This is the asymmetry
/// `it_log_lines` closes for its own table with
/// `the_table_names_no_statement_that_is_gone`, and the two gates were written
/// days apart with the same stated design.
///
/// It asserts rather than reports, because a reporting test that cannot fail is
/// a probe that asserts nothing, which is the standard this file applies
/// everywhere else.
#[test]
fn the_table_names_no_constant_the_pages_stopped_quoting() {
    let quoted: BTreeSet<String> = quotes().into_iter().map(|quote| quote.name).collect();

    let unquoted: Vec<&str> = crate_constants()
        .into_keys()
        .filter(|name| !quoted.contains(*name))
        .collect();

    assert!(
        unquoted.is_empty(),
        "`crate_constants` is the constants a doc page *may* quote, and no page \
         quotes these any more: {unquoted:?}. Drop the row, or put the quote back \
         on the page that lost it"
    );
}

// ---------------------------------------------------------------------------
// Gate 3: the anchors
// ---------------------------------------------------------------------------

/// GitHub's heading slug for `heading`.
///
/// Lowercased, formatting characters dropped, spaces hyphenated: `` ## `[log]` ``
/// becomes `log` and `### ACME with DNS-01` becomes `acme-with-dns-01`, which is
/// what the links in these pages are written against.
fn slug(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// Every anchor a markdown file offers, GitHub's duplicate suffixes included.
fn anchors_of(path: &Path) -> BTreeSet<String> {
    let text = read_text(path);
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut anchors = BTreeSet::new();

    for (_, line) in prose_lines(&text) {
        let hashes = line.chars().take_while(|c| *c == '#').count();
        if hashes == 0 || hashes > 6 || !line[hashes..].starts_with(' ') {
            continue;
        }
        let base = slug(&line[hashes..]);
        if base.is_empty() {
            continue;
        }
        let count = seen.entry(base.clone()).or_insert(0);
        anchors.insert(if *count == 0 {
            base.clone()
        } else {
            format!("{base}-{count}")
        });
        *count += 1;
    }

    anchors
}

/// One `<page>#<anchor>` reference, and where it was written.
struct Reference {
    source: String,
    page: String,
    anchor: String,
}

/// The `docs/<page>.md#<anchor>` references written in `src/` and `tests/`.
///
/// A comment that points a reader at a section is a promise like any other, and
/// the one thing about it a machine can check is that the section is still
/// there.
fn code_references() -> Vec<Reference> {
    let root = repo_root();
    let mut found = Vec::new();

    for directory in ["src", "tests"] {
        for file in rust_files(&root.join(directory)) {
            let text = read_text(&file);
            let source = file
                .strip_prefix(&root)
                .unwrap_or(&file)
                .display()
                .to_string();

            for (number, line) in text.lines().enumerate() {
                let mut rest = line;
                while let Some(at) = rest.find("docs/") {
                    let tail = &rest[at + "docs/".len()..];
                    if let Some((page, after)) = tail.split_once(".md#") {
                        let anchor: String = after
                            .chars()
                            .take_while(|c| {
                                c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'
                            })
                            .collect();
                        if !page.is_empty() && !anchor.is_empty() {
                            found.push(Reference {
                                source: format!("{source}:{}", number + 1),
                                page: format!("docs/{page}.md"),
                                anchor,
                            });
                        }
                    }
                    rest = tail;
                }
            }
        }
    }

    found
}

/// The `](...#anchor)` links the documentation writes to itself.
fn link_references() -> Vec<Reference> {
    let root = repo_root();
    let mut found = Vec::new();

    let pages: Vec<(String, PathBuf)> =
        std::iter::once(("README.md".to_owned(), root.join("README.md")))
            .chain(DOC_PAGES.map(|page| (format!("docs/{page}"), doc_path(page))))
            .collect();

    for (name, path) in pages {
        let text = read_text(&path);
        for (number, line) in prose_lines(&text) {
            let mut rest = line;
            while let Some(at) = rest.find("](") {
                let tail = &rest[at + 2..];
                let Some((target, after)) = tail.split_once(')') else {
                    break;
                };
                rest = after;

                let Some((file, anchor)) = target.split_once('#') else {
                    continue;
                };
                if anchor.is_empty() {
                    continue;
                }
                // A link with no file part points inside the page it is on;
                // one with a file part is relative to that page's directory.
                let page = match file {
                    "" => name.clone(),
                    other if other.ends_with(".md") => {
                        let directory = name.rsplit_once('/').map_or("", |(head, _)| head);
                        match (directory, other.strip_prefix("docs/")) {
                            ("", Some(inside)) => format!("docs/{inside}"),
                            ("", _) => other.to_owned(),
                            (directory, _) => format!("{directory}/{other}"),
                        }
                    }
                    _ => continue,
                };
                found.push(Reference {
                    source: format!("{name}:{number}"),
                    page,
                    anchor: anchor.to_owned(),
                });
            }
        }
    }

    found
}

/// Every anchored reference in the tree names a heading that exists.
#[test]
fn every_documentation_anchor_resolves() {
    let root = repo_root();
    let mut references = code_references();
    references.extend(link_references());

    assert!(
        references.len() >= ANCHOR_FLOOR,
        "only {} anchored references found; the reader is broken, not the tree",
        references.len()
    );

    // Every page a reference names has to be one this gate reads, so a link to
    // a page outside `DOC_PAGES` is a failure rather than a silent pass.
    let mut anchors: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    anchors.insert("README.md", anchors_of(&root.join("README.md")));
    for page in DOC_PAGES {
        anchors.insert(page, anchors_of(&doc_path(page)));
    }

    for reference in &references {
        let page = reference
            .page
            .strip_prefix("docs/")
            .unwrap_or(&reference.page);
        let known = anchors.get(page).unwrap_or_else(|| {
            panic!(
                "{} points at {}#{}, which is not a page this gate reads",
                reference.source, reference.page, reference.anchor
            )
        });
        assert!(
            known.contains(&reference.anchor),
            "{} points at {}#{}, which is not a heading there; it has {known:?}",
            reference.source,
            reference.page,
            reference.anchor
        );
    }
}

// ---------------------------------------------------------------------------
// Gate 4: the manual installation block
// ---------------------------------------------------------------------------

/// Commands the manual installation must be written with, at the very least.
///
/// Today both sides carry eight. The floor is what stops a heading renamed or a
/// fence reflowed from comparing two empty lists and calling them equal.
const INSTALL_COMMAND_FLOOR: usize = 6;

/// The `## systemd` section of `docs/deployment.md`.
///
/// Bounded by that heading and the next second-level one, both asserted, so a
/// renamed heading fails here rather than leaving this gate reading a section
/// that is not the one it is about.
fn systemd_section(text: &str) -> &str {
    let start = text.find("\n## systemd\n").unwrap_or_else(|| {
        panic!(
            "docs/deployment.md carries no `## systemd` section, which is where \
             the manual installation this gate compares is written"
        )
    });
    let rest = &text[start + 1..];
    let end = rest.find("\n## ").unwrap_or_else(|| {
        panic!("the `## systemd` section of docs/deployment.md is the last one; this gate reads it by its bounds and needs the next heading")
    });
    &rest[..end]
}

/// The installation part of `script/masque.service`'s header comment.
///
/// Bounded by `# Install:` and the paragraph that begins `# Reload after`, both
/// asserted. The reload paragraph carries a `sudo` line of its own, which is not
/// part of the installation and must stay outside the comparison.
fn install_comment(text: &str) -> &str {
    let start = text
        .find("# Install:")
        .unwrap_or_else(|| panic!("script/masque.service carries no `# Install:` header comment"));
    let rest = &text[start..];
    let end = rest.find("\n# Reload after").unwrap_or_else(|| {
        panic!(
            "script/masque.service's header no longer carries the `# Reload after` \
             paragraph, which is what bounds the installation comment; without it \
             this gate would read the reload command as an installation step"
        )
    });
    &rest[..end]
}

/// Every `sudo` line inside a fenced block of `section`, in order.
fn fenced_commands(section: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut fenced = false;

    for line in section.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced && line.starts_with("sudo ") {
            commands.push(line.to_owned());
        }
    }

    commands
}

/// Every `sudo` line of `comment`, in order, with the comment marker taken off.
fn commented_commands(comment: &str) -> Vec<String> {
    comment
        .lines()
        .filter_map(|line| line.strip_prefix('#'))
        .map(str::trim)
        .filter(|line| line.starts_with("sudo "))
        .map(str::to_owned)
        .collect()
}

/// The manual installation is written twice and the two copies must agree.
///
/// `docs/deployment.md`'s `## systemd` section and `script/masque.service`'s
/// header comment carry the same sequence of commands. The copy in the unit
/// exists so the file that lands on the host explains itself without a browser,
/// and it is worth exactly as much as the two agree, the way
/// `it_release_assets::cross_yml_runs_the_release_build_step_verbatim` holds the
/// mirrored build step of two workflow files to the same rule.
///
/// The order of these commands is the finding this gate was written for: the
/// block used to end on `systemctl enable --now volto`, which starts the server
/// on the placeholder password `script/config.example.toml` ships, before the
/// step that tells the operator to replace it. Splitting `enable` from `start`
/// is only a fix while both copies say so.
#[test]
fn the_manual_installation_is_written_the_same_way_in_both_places() {
    let page = repo_root().join("docs/deployment.md");
    let unit = repo_root().join("script/masque.service");

    let documented = fenced_commands(systemd_section(&read_text(&page)));
    let shipped = commented_commands(install_comment(&read_text(&unit)));

    for (source, commands) in [(&page, &documented), (&unit, &shipped)] {
        assert!(
            commands.len() >= INSTALL_COMMAND_FLOOR,
            "only {} installation commands were read out of {}; the reader is \
             broken, not the tree",
            commands.len(),
            source.display()
        );
    }

    assert_eq!(
        documented, shipped,
        "the manual installation in docs/deployment.md has drifted from the copy \
         in script/masque.service's header comment. Both describe the same \
         procedure to the same operator, and the unit is the copy that reaches \
         the host inside the release tarball, so a step present in one and not \
         the other is a host installed a way nobody documented.\n\n\
         docs/deployment.md:\n{documented:#?}\n\nscript/masque.service:\n{shipped:#?}"
    );

    // The finding itself, stated as its own claim rather than left implicit in
    // the sequence above: `--now` would start the server on the shipped
    // placeholder password, and `start` has to come after the edit step, which
    // sits between the two fences on the page and between the two comment
    // paragraphs in the unit.
    for (source, commands) in [(&page, &documented), (&unit, &shipped)] {
        assert!(
            commands
                .iter()
                .any(|line| line == "sudo systemctl enable volto"),
            "{} no longer enables the unit without --now. `enable --now` starts \
             the server on the placeholder password script/config.example.toml \
             ships, before the operator has been told to replace it",
            source.display()
        );
        let start = commands
            .iter()
            .position(|line| line == "sudo systemctl start volto")
            .unwrap_or_else(|| {
                panic!(
                    "{} never starts the service; the installation it describes \
                     leaves the operator with a unit that is enabled and not running",
                    source.display()
                )
            });
        assert_eq!(
            start,
            commands.len() - 1,
            "{} starts the service before the end of the installation. The start \
             is last because everything before it has to have happened, the edit \
             of /etc/volto/config.toml above all",
            source.display()
        );
    }
}

// ---------------------------------------------------------------------------
// Gate 5: the defaults the example promises and the page prints
// ---------------------------------------------------------------------------

/// Keys whose default is written in both places, at the very least.
///
/// Today 23 of the 25 page keys that print a default: the three required
/// `[server]` keys print none, and `users` and `initial_rtt_ms` are live in the
/// example rather than commented with a `# Default:` line, so the gate never
/// reaches those two.
const DEFAULT_FLOOR: usize = 20;

/// The `# Default: …` text the example writes above each key, as `(table, key)`.
///
/// The convention is the one the file keeps everywhere: the line immediately
/// above the assignment, live or commented. Anything further up is prose about
/// the key, which is why only the line directly above counts.
///
/// The text is taken whole rather than cut at the first word: `alpn` writes
/// `["h3"], which is what Surge speaks`, and cutting it would need a rule about
/// where a value ends that this file would then have to keep.
fn example_defaults() -> BTreeMap<(String, String), String> {
    let path = repo_root().join("script/config.example.toml");
    let text = read_text(&path);

    let mut defaults = BTreeMap::new();
    let mut table = String::new();
    let mut previous = "";

    for line in text.lines() {
        // The same reading `example_keys` uses: `#key = value` is a commented
        // key, `# sentence` is prose.
        let code = match line.strip_prefix('#') {
            Some(rest) if rest.starts_with(' ') || rest.is_empty() => line,
            Some(rest) => rest,
            None => line,
        };

        if let Some(name) = code
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            table = name.to_owned();
        } else if let Some(key) = assigned_key(code)
            && let Some(stated) = previous.strip_prefix("# Default: ")
        {
            defaults.insert((table.clone(), key.to_owned()), stated.trim().to_owned());
        }

        previous = line;
    }

    defaults
}

/// The Default column of `docs/configuration.md`, as `(table, key)`.
///
/// `None` for a row whose Default cell is not a backticked value, which is how
/// the three required `[server]` keys, whose cell reads `required`, stay out of
/// the comparison rather than being compared against nothing.
fn documented_defaults() -> BTreeMap<(String, String), Option<String>> {
    let text = read_text(&doc_path("configuration.md"));
    let mut defaults = BTreeMap::new();
    let mut table: Option<String> = None;

    for (_, line) in prose_lines(&text) {
        if let Some(heading) = line.strip_prefix("## ") {
            table = heading
                .trim()
                .strip_prefix("`[")
                .and_then(|rest| rest.strip_suffix("]`"))
                .map(str::to_owned);
            continue;
        }

        let (Some(table), true) = (table.as_ref(), line.starts_with("| `")) else {
            continue;
        };

        // Only the first four fields are read, so whatever the Meaning cell
        // holds -- a table pipe of its own included -- cannot move the columns
        // this gate looks at.
        let cells: Vec<&str> = line.splitn(5, '|').collect();
        let [_, key, _, default, ..] = cells.as_slice() else {
            continue;
        };
        let Some((key, _)) = key.trim().strip_prefix('`').and_then(|r| r.split_once('`')) else {
            continue;
        };
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            continue;
        }

        let default = default
            .trim()
            .strip_prefix('`')
            .and_then(|rest| rest.strip_suffix('`'))
            .map(str::to_owned);
        defaults.insert((table.clone(), key.to_owned()), default);
    }

    defaults
}

/// The default the example promises is the default the page prints.
///
/// This is the numeric half of the duplication between the two files made
/// self-checking. Every key is described twice at length, and until now
/// `it_docs` pinned only that the two key *sets* are equal, so a default
/// changed in one file and not the other was invisible; that is the drift the
/// 2026-09-07 review found in the `allow_private_networks` and
/// `unanswered_packet_budget` comments.
///
/// It closes the last edge of a triangle. `src/config.rs`'s
/// `the_example_documents_every_key_and_pins_every_default` holds the example's
/// own values to the compiled defaults, and gate 2 above holds the constants the
/// pages quote to the crate; the page's Default column was pinned by nothing,
/// because a table cell is not the `` `IDENT` = value `` notation gate 2 reads.
/// With this edge the column is the example's promise, which is the crate's
/// value.
///
/// What it does not reach: the `# Default:` comment text is compared against the
/// page and not against the value beside it, which is the one thing
/// `src/config.rs` holds. The three keys the example deliberately sets away from
/// their defaults (`initial_mtu`, `mtu_upper_bound`, `initial_rtt_ms`) are why
/// that comparison cannot be made unconditionally.
#[test]
fn every_default_the_example_promises_is_the_default_the_page_prints() {
    let promised = example_defaults();
    let printed = documented_defaults();

    assert!(
        promised.len() >= DEFAULT_FLOOR,
        "only {} `# Default:` lines were read out of script/config.example.toml; \
         the reader is broken, not the file",
        promised.len()
    );

    let mut compared = 0;
    for ((table, key), stated) in &promised {
        let cell = printed
            .get(&(table.clone(), key.clone()))
            .unwrap_or_else(|| {
                panic!(
                    "script/config.example.toml gives [{table}].{key} a default and \
                 docs/configuration.md has no row for it. The key sets are one \
                 set, so this is a row that moved out from under its heading"
                )
            });
        let cell = cell.as_ref().unwrap_or_else(|| {
            panic!(
                "script/config.example.toml says [{table}].{key} defaults to \
                 {stated:?}, and docs/configuration.md's Default column for it \
                 carries no value. One of the two is wrong about whether this key \
                 has a default"
            )
        });

        // Either the whole line is the value, or the value followed by a comma
        // and a sentence about it, which is how `alpn` writes its own. A bare
        // prefix test would let `2560` pass for `256`; the comma is the boundary.
        let agrees = stated == cell || stated.starts_with(&format!("{cell},"));
        assert!(
            agrees,
            "docs/configuration.md prints `{cell}` as the default of \
             [{table}].{key}, and script/config.example.toml promises \
             {stated:?}. The example is the file that lands on the host and the \
             page is the one an operator reads first; they cannot say different \
             numbers"
        );
        compared += 1;
    }

    assert!(
        compared >= DEFAULT_FLOOR,
        "only {compared} defaults were actually compared; the reader is broken, \
         not the tree"
    );
}
