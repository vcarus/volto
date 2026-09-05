//! The tracked tree must stay scrubbed.
//!
//! This repository is public, and the development notes it grew out of are not:
//! they carry a private identity, a production topology, real addresses and
//! ports, and prose in another script. `dev_docs/` is gitignored, but that only
//! stops the obvious mistake — a quoted line pasted into a comment, a doc
//! copied to `docs/`, a commit made from the wrong file is exactly as
//! irreversible once it is pushed (GitHub keeps caches and forks). Until now the
//! only defence was remembering to grep.
//!
//! Two checks over `git ls-files`:
//!
//! * CJK characters and the scripts written alongside them, which are
//!   self-describing and can be spelled out here as escapes, so this file stays
//!   clean of them itself.
//! * A list of private literals, which cannot be written down in a public
//!   repository at all. They come from outside the tree: `VOLTO_SCRUB_PATTERNS`
//!   (`|`-separated, from a repository secret in CI) and, on the dev host, the
//!   gitignored `dev_docs/scrub-patterns.txt`. Matches are reported by file and
//!   line with the pattern *redacted* — CI logs are public too.
//!
//! With neither source present the literal check simply does not run, which is
//! the right outcome for a fork or a checkout without the notes — with one
//! exception. On a push to the canonical repository the secret is supposed to be
//! there, and a run that finds it missing must say so loudly rather than pass
//! with the gate half open: a renamed or expired secret would otherwise turn the
//! whole check into a no-op without anyone noticing.

// The package-wide default is `deny` (`Cargo.toml`); this file argues for its
// allow: the counting is over the tree this file scans.
#![allow(clippy::as_conversions)]

#[path = "common/scripts.rs"]
mod scripts;

use std::fs;
use std::path::Path;
use std::process::Command;

use scripts::repo_root;

/// Ranges that no tracked file may contain.
///
/// The enclosed alphanumerics (the circled digits used as markers in notes),
/// Hangul Jamo, the whole CJK run from the symbols and punctuation block
/// through the compatibility block (so kana, Bopomofo, enclosed CJK forms and
/// the like are all inside it), the three common ideograph blocks including the
/// compatibility ideographs, Hangul syllables, fullwidth/halfwidth forms, and
/// the supplementary ideograph planes — so the check covers the scripts the
/// notes are written in, their neighbours and their markers, not only Han
/// characters.
const CJK_RANGES: [(char, char); 9] = [
    ('\u{1100}', '\u{11ff}'),
    ('\u{2460}', '\u{24ff}'),
    ('\u{3000}', '\u{33ff}'),
    ('\u{3400}', '\u{4dbf}'),
    ('\u{4e00}', '\u{9fff}'),
    ('\u{ac00}', '\u{d7af}'),
    ('\u{f900}', '\u{faff}'),
    ('\u{ff00}', '\u{ffef}'),
    ('\u{20000}', '\u{2fa1f}'),
];

fn is_cjk(ch: char) -> bool {
    CJK_RANGES
        .iter()
        .any(|(first, last)| ch >= *first && ch <= *last)
}

/// The tracked files, or `None` when there is no usable git checkout here.
fn tracked_files(root: &Path) -> Option<Vec<String>> {
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output();

    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            eprintln!(
                "skipping the scrub gate: `git ls-files` failed ({})",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            return None;
        }
        Err(error) => {
            eprintln!("skipping the scrub gate: git is not available ({error})");
            return None;
        }
    };

    let paths: Vec<String> = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8_lossy(path).into_owned())
        .collect();

    if paths.is_empty() {
        eprintln!("skipping the scrub gate: no tracked files were listed");
        return None;
    }
    Some(paths)
}

/// The text of a tracked file, or `None` if it is binary or unreadable.
fn tracked_text(root: &Path, path: &str) -> Option<String> {
    let bytes = fs::read(root.join(path)).ok()?;
    String::from_utf8(bytes).ok()
}

/// Adds a literal unless it is empty or already known.
fn push_pattern(patterns: &mut Vec<String>, candidate: &str) {
    let candidate = candidate.trim();
    if !candidate.is_empty() && !patterns.iter().any(|known| known == candidate) {
        patterns.push(candidate.to_string());
    }
}

/// The literals to look for, from outside the tree. Never printed anywhere.
fn scrub_patterns(root: &Path) -> Vec<String> {
    let mut patterns: Vec<String> = Vec::new();

    if let Ok(from_env) = std::env::var("VOLTO_SCRUB_PATTERNS") {
        for candidate in from_env.split('|') {
            push_pattern(&mut patterns, candidate);
        }
    }

    // Gitignored, and present only on the dev host.
    if let Ok(from_file) = fs::read_to_string(root.join("dev_docs/scrub-patterns.txt")) {
        for line in from_file.lines() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            push_pattern(&mut patterns, line);
        }
    }

    patterns
}

/// Whether this is GitHub Actions running a `push` in the repository that owns
/// the secret.
///
/// Only there is an empty pattern list a failure: a fork has no secret, and a
/// pull request — including Dependabot's — runs without repository secrets by
/// design, so both legitimately fall back to the CJK check alone.
fn is_push_to_canonical_repository() -> bool {
    std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("push")
        && std::env::var("GITHUB_REPOSITORY").as_deref() == Ok("vcarus/volto")
}

/// Public repository, English only: no CJK anywhere in the tracked tree.
#[test]
fn no_tracked_file_contains_cjk_characters() {
    let root = repo_root();
    let Some(paths) = tracked_files(&root) else {
        return;
    };

    let mut violations = Vec::new();
    for path in &paths {
        let Some(text) = tracked_text(&root, path) else {
            continue;
        };
        for (number, line) in text.lines().enumerate() {
            for (column, ch) in line.chars().enumerate() {
                if is_cjk(ch) {
                    violations.push(format!(
                        "{path}:{}:{} U+{:04X}",
                        number + 1,
                        column + 1,
                        ch as u32
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "tracked files must be English only ({} occurrence(s)):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

/// The private literals that must never reach a public commit.
#[test]
fn no_tracked_file_contains_a_private_literal() {
    let root = repo_root();
    let Some(paths) = tracked_files(&root) else {
        return;
    };

    let patterns = scrub_patterns(&root);
    if patterns.is_empty() {
        assert!(
            !is_push_to_canonical_repository(),
            "no scrub patterns available on a push to the canonical repository: the \
             VOLTO_SCRUB_PATTERNS secret is missing or empty, so the private-literal \
             gate did not run"
        );
        eprintln!(
            "no scrub patterns available (set VOLTO_SCRUB_PATTERNS or provide \
             dev_docs/scrub-patterns.txt); only the CJK check ran"
        );
        return;
    }

    let mut violations = Vec::new();
    for path in &paths {
        let Some(text) = tracked_text(&root, path) else {
            continue;
        };
        for (number, line) in text.lines().enumerate() {
            for (index, pattern) in patterns.iter().enumerate() {
                if line.contains(pattern) {
                    // Redacted on purpose: this output can end up in a public
                    // CI log. The file and line are enough to find it.
                    violations.push(format!(
                        "{path}:{} (pattern #{}, len {})",
                        number + 1,
                        index + 1,
                        pattern.chars().count()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "tracked files must not carry private literals ({} occurrence(s), \
         patterns redacted):\n{}",
        violations.len(),
        violations.join("\n")
    );
}
