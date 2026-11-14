//! Nothing this server decides may depend on the wall clock.
//!
//! The two clocks are not interchangeable. `Instant` is monotonic: it counts
//! forward from an arbitrary origin, never jumps, and is what every deadline in
//! this tree is built on. `SystemTime` is the wall clock, and on the production
//! host it is a moving target — `systemd-timesyncd` steps it at boot and slews
//! it afterwards, and a VM that is paused, migrated or snapshotted comes back
//! with it wherever the host says. A timeout measured against it would expire
//! early, late, or in the past.
//!
//! There is no wall clock anywhere in `src/` today, and this is what keeps it
//! that way. `SystemTime::now()` is the natural thing to reach for when a log
//! line, a metric or a cache wants a date, and the mistake is not the reaching —
//! it is that the value then gets compared to another one and becomes a
//! decision.
//!
//! Rendering a timestamp *is* the wall clock's job, and this server does that:
//! every log line carries one. It just does not do it here. The timestamp is
//! `tracing-subscriber`'s, formatted inside the subscriber `main` installs, and
//! under systemd the journal stamps its own besides. Neither is anything this
//! crate reads back.
//!
//! # What is scanned, and what is not
//!
//! Every `.rs` file under `src/`, comments excluded — so the paragraph you are
//! reading does not trip the gate it describes. Test code is included on
//! purpose: a test that pinned a deadline against the wall clock would be a
//! test that fails when the host slews, and there is no reason for one to exist.
//!
//! Dependencies are out of scope and are a separate matter, written down rather
//! than enforced. `quinn-proto` really does use `SystemTime`, for the issue time
//! inside an address-validation token (`token.rs`) and for the two-period
//! bookkeeping of `BloomTokenLog` — both of which this server enables
//! deliberately (the `bloom` feature, see `Cargo.toml`). A backwards step there
//! costs a returning client the round trip its `NEW_TOKEN` would have saved,
//! because a token that fails either check is treated as no token at all
//! (`IncomingToken::from_header` returns the unvalidated state rather than an
//! error). That is a degradation and not a fault, it is quinn's to fix if it
//! ever becomes one, and it is bounded — which is exactly why it is worth
//! knowing that nothing on *this* side of the boundary adds to it.

#[path = "common/scripts.rs"]
mod scripts;

use scripts::{code_lines, read_text, rust_files, source_root};

/// The identifiers that would put a wall-clock reading into this crate.
///
/// `SystemTime` and `UNIX_EPOCH` are `std`'s; `chrono` and `OffsetDateTime` are
/// the two crates that would arrive with a date type of their own, named here
/// so that adding one is a decision rather than an import.
///
/// The rest read the wall clock without naming its type. A file's modification,
/// access and creation times are `SystemTime` values, so comparing them, or
/// asking one for its `elapsed()`, is a wall-clock decision. `clock_gettime`
/// and `Realtime` are the system call and the clock id that `rustix`, already a
/// dependency, would reach it through. `clock_gettime_dynamic`, `RealtimeCoarse`
/// and `RealtimeAlarm` are the other `rustix` names for the same clock. They are
/// listed on their own because an identifier entry matches only a whole
/// identifier (see [`names`]).
const WALL_CLOCK: [&str; 12] = [
    "SystemTime",
    "UNIX_EPOCH",
    "chrono",
    "OffsetDateTime",
    ".modified(",
    ".accessed(",
    ".created(",
    "clock_gettime",
    "clock_gettime_dynamic",
    "Realtime",
    "RealtimeCoarse",
    "RealtimeAlarm",
];

/// Whether `code` names the [`WALL_CLOCK`] entry `entry`.
///
/// An entry that starts with `.` or ends with `(` is a method call or a call,
/// and it matches wherever its text appears. Every other entry is an
/// identifier. It matches only where the character before it and the
/// character after it cannot be part of an identifier. So `chrono` is found in
/// `use chrono;` and not in `synchronous`.
fn names(code: &str, entry: &str) -> bool {
    if entry.starts_with('.') || entry.ends_with('(') {
        return code.contains(entry);
    }

    let identifier_char = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices(entry).any(|(at, _)| {
        let before = code[..at].chars().next_back();
        let after = code[at + entry.len()..].chars().next();
        !before.is_some_and(identifier_char) && !after.is_some_and(identifier_char)
    })
}

#[test]
fn no_source_file_reads_the_wall_clock() {
    let root = source_root();

    // The way a source-scanning gate fails without saying so: it stops finding
    // anything and reports that nothing offended (`it_scrub`'s lesson, learned
    // the hard way, and the same latch `it_log_lines` keeps over the same two
    // helpers). `rust_files` panics on a directory it cannot read, so what is
    // left to catch here is a scan that found no file at all.
    let files = rust_files(&root);
    assert!(
        !files.is_empty(),
        "the scan found no Rust file at all in {}, which cannot be true of this \
         crate: the gate is broken, not satisfied",
        root.display()
    );

    let mut offences = Vec::new();

    for path in files {
        let text = read_text(&path);

        for (number, code) in code_lines(&text).into_iter().enumerate() {
            let Some(code) = code else {
                continue;
            };
            for identifier in WALL_CLOCK {
                if names(&code, identifier) {
                    let relative = path.trim_prefix(&root);
                    offences.push(format!(
                        "src/{}:{}: {identifier}",
                        relative.display(),
                        number + 1
                    ));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "the wall clock reached this crate's logic, where an NTP step or a \
         resumed VM would move it under a running deadline. Use \
         `tokio::time::Instant` for anything measured, and leave dates to the \
         tracing subscriber:\n  {}",
        offences.join("\n  ")
    );
}

/// The gate can fail, which is the half a passing gate never shows.
///
/// Both halves of the scanner are exercised: a banned identifier in code is
/// found, and the same identifier in the comment that explains why it is banned
/// is not — the second being the case that would otherwise have made this file
/// unable to describe itself.
#[test]
fn the_scanner_tells_code_from_the_comment_about_it() {
    // One line of source, as the gate sees it.
    let code = |line: &str| code_lines(line).pop().flatten();

    assert_eq!(
        code("    let now = SystemTime::now();").as_deref(),
        Some("    let now = SystemTime::now();")
    );
    assert_eq!(code("/// Never call SystemTime::now() here."), None);
    assert_eq!(code("//! `UNIX_EPOCH` is not a deadline."), None);
    assert_eq!(
        code("    let d = 1; // SystemTime is wrong here").as_deref(),
        Some("    let d = 1; ")
    );

    let banned = |line: &str| {
        code_lines(line)
            .into_iter()
            .flatten()
            .any(|code| WALL_CLOCK.iter().any(|entry| names(&code, entry)))
    };
    assert!(banned("use std::time::SystemTime;"));
    assert!(banned("let since = now.duration_since(UNIX_EPOCH);"));
    assert!(!banned("/// See `SystemTime` for why this is not one."));
    assert!(!banned(
        "let deadline = tokio::time::Instant::now() + budget;"
    ));

    // A wall-clock reading that never names the type.
    assert!(banned(
        "let age = std::fs::metadata(&cert)?.modified()?.elapsed();"
    ));

    // A `//` inside a string is text, so what follows it on the line is still
    // code, and a comment after the string is still a comment.
    assert!(banned(
        "let stamp = (\"https://example.invalid\", std::time::SystemTime::now());"
    ));
    assert!(!banned(
        "let home = \"https://example.invalid\"; // not SystemTime"
    ));

    // A string that continues onto the next line is still a string there, so
    // a `//` at the start of that line is text, and the text is scanned.
    assert!(banned(
        "let long = \"first \\\n // SystemTime, quoted rather than commented\";"
    ));

    // A character literal holding a quote opens no string, so the comment
    // after it is still a comment.
    assert!(!banned("let quote = '\"'; // SystemTime, in a comment"));

    // An identifier entry matches a whole identifier only. A longer word that
    // contains it, before or after, is a different word.
    assert!(!banned("let mode = \"synchronous\";"));
    assert!(!banned("let chronology = Vec::new();"));
    assert!(banned("let now = chrono::Utc::now();"));
    assert!(banned("use chrono;"));

    // The longer `rustix` names for the same clock are entries of their own.
    assert!(banned("let id = ClockId::RealtimeCoarse;"));
    assert!(banned("let now = clock_gettime_dynamic(id)?;"));
}
