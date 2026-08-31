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

use std::fs;
use std::path::{Path, PathBuf};

use scripts::repo_root;

/// The identifiers that would put a wall-clock reading into this crate.
///
/// `SystemTime` and `UNIX_EPOCH` are `std`'s; `chrono` and `OffsetDateTime` are
/// the two crates that would arrive with a date type of their own, named here
/// so that adding one is a decision rather than an import.
const WALL_CLOCK: [&str; 4] = ["SystemTime", "UNIX_EPOCH", "chrono", "OffsetDateTime"];

fn source_root() -> PathBuf {
    repo_root().join("src")
}

/// Every `.rs` file under `root`, in a stable order so a failure names the same
/// file twice running.
fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];

    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()));

        for entry in entries {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|kind| kind == "rs") {
                found.push(path);
            }
        }
    }

    found.sort();
    found
}

/// `line` with a trailing `//` comment removed, and `None` for a line that is
/// nothing but a comment.
///
/// Deliberately crude: this crate has no `/* */` comments and no string literal
/// carrying a `//`, so the only thing a cleverer parser would buy is the chance
/// of a subtler bug in the gate itself. What it must get right is the doc
/// comments — the module above names every banned identifier, and so does the
/// prose beside the `bloom` feature in `Cargo.toml`.
fn code_only(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return None;
    }
    match line.split_once("//") {
        Some((code, _)) => Some(code),
        None => Some(line),
    }
}

#[test]
fn no_source_file_reads_the_wall_clock() {
    let root = source_root();
    let mut offences = Vec::new();

    for path in rust_files(&root) {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));

        for (number, line) in text.lines().enumerate() {
            let Some(code) = code_only(line) else {
                continue;
            };
            for identifier in WALL_CLOCK {
                if code.contains(identifier) {
                    let relative = path.strip_prefix(&root).unwrap_or(&path);
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
    assert_eq!(
        code_only("    let now = SystemTime::now();"),
        Some("    let now = SystemTime::now();")
    );
    assert_eq!(code_only("/// Never call SystemTime::now() here."), None);
    assert_eq!(code_only("//! `UNIX_EPOCH` is not a deadline."), None);
    assert_eq!(
        code_only("    let d = 1; // SystemTime is wrong here"),
        Some("    let d = 1; ")
    );

    let banned = |line: &str| {
        code_only(line).is_some_and(|code| WALL_CLOCK.iter().any(|name| code.contains(name)))
    };
    assert!(banned("use std::time::SystemTime;"));
    assert!(banned("let since = now.duration_since(UNIX_EPOCH);"));
    assert!(!banned("/// See `SystemTime` for why this is not one."));
    assert!(!banned(
        "let deadline = tokio::time::Instant::now() + budget;"
    ));
}
