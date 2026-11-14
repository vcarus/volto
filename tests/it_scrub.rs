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
//! Two checks over `git ls-files`, each over the path of every tracked file as
//! well as its contents:
//!
//! * CJK characters and the scripts written alongside them, which are
//!   self-describing and can be spelled out here as escapes, so this file stays
//!   clean of them itself. A tracked file must be UTF-8, because text in a
//!   legacy CJK encoding never is; the one exception is a file whose extension
//!   is on [`BINARY_EXTENSIONS`].
//! * A list of private literals, which cannot be written down in a public
//!   repository at all. They come from outside the tree: `VOLTO_SCRUB_PATTERNS`
//!   (`|`-separated, from a repository secret in CI) and, on the dev host, the
//!   gitignored `dev_docs/scrub-patterns.txt`. They are searched for in the raw
//!   bytes of every file, binary ones included, without regard to ASCII letter
//!   case. Matches are reported by file and line with the pattern *redacted*:
//!   CI logs are public too.
//!
//! With neither source present the literal check simply does not run, which is
//! the right outcome for a fork or a checkout without the notes — with one
//! exception. On a push to the canonical repository the secret is supposed to be
//! there, and a run that finds it missing must say so loudly rather than pass
//! with the gate half open: a renamed or expired secret would otherwise turn the
//! whole check into a no-op without anyone noticing. The same push fails when
//! `git ls-files` fails or lists fewer than [`TRACKED_FLOOR`] files, which
//! would otherwise turn both checks into a pass.

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

/// The extensions of the tracked files that are not text. Their contents are
/// still searched for the private literals, as raw bytes; only the UTF-8
/// requirement and the CJK check of the contents skip them, because compressed
/// data decodes into CJK characters by chance.
const BINARY_EXTENSIONS: [&str; 1] = ["png"];

/// Fewer tracked files than this is a listing that went wrong, not a tree.
/// The tree tracks about 150.
const TRACKED_FLOOR: usize = 100;

/// One tracked file: its path as git lists it, and its contents.
struct Tracked {
    /// The path as UTF-8, with anything invalid replaced, for messages and the
    /// CJK check.
    path: String,
    /// The path's raw bytes, for the literal check.
    path_bytes: Vec<u8>,
    /// The contents, or `None` when the file cannot be read, as when it is
    /// deleted in the working tree and not yet in the index.
    bytes: Option<Vec<u8>>,
}

impl Tracked {
    fn is_binary(&self) -> bool {
        Path::new(&self.path)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                BINARY_EXTENSIONS
                    .iter()
                    .any(|known| extension.eq_ignore_ascii_case(known))
            })
    }
}

/// The tracked files, or `None` when there is no usable git checkout here.
///
/// On a push to the canonical repository a failed or implausibly short listing
/// fails the test instead, because there the checkout is supposed to be whole.
fn tracked_files(root: &Path) -> Option<Vec<Tracked>> {
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output();

    let listed = match output {
        Ok(output) if output.status.success() => Ok(output.stdout),
        Ok(output) => Err(format!(
            "`git ls-files` failed ({})",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
        Err(error) => Err(format!("git is not available ({error})")),
    };
    let paths: Vec<Vec<u8>> = match listed {
        Ok(stdout) => stdout
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
            .map(<[u8]>::to_vec)
            .collect(),
        Err(reason) => {
            assert!(
                !is_push_to_canonical_repository(),
                "the scrub gate cannot list the tree on a push to the canonical \
                 repository: {reason}"
            );
            eprintln!("skipping the scrub gate: {reason}");
            return None;
        }
    };

    if paths.len() < TRACKED_FLOOR {
        assert!(
            !is_push_to_canonical_repository(),
            "`git ls-files` listed {} files on a push to the canonical repository, \
             fewer than the {TRACKED_FLOOR} a whole checkout has",
            paths.len()
        );
        eprintln!(
            "skipping the scrub gate: `git ls-files` listed {} files, fewer than {TRACKED_FLOOR}",
            paths.len()
        );
        return None;
    }

    Some(
        paths
            .into_iter()
            .map(|path_bytes| {
                let path = String::from_utf8_lossy(&path_bytes).into_owned();
                let bytes = fs::read(root.join(&path)).ok();
                Tracked {
                    path,
                    path_bytes,
                    bytes,
                }
            })
            .collect(),
    )
}

/// Whether the line `haystack` contains `needle`. Both are already in ASCII
/// lower case, which is how the literal check ignores letter case.
///
/// A line that is UTF-8 is searched as text, which is much faster than a
/// byte-by-byte scan over a tree this size; any other line is scanned.
fn contains(haystack: &[u8], needle: &str) -> bool {
    match std::str::from_utf8(haystack) {
        Ok(text) => text.contains(needle),
        Err(_) => haystack
            .windows(needle.len())
            .any(|window| window == needle.as_bytes()),
    }
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

/// Public repository, English only: no CJK anywhere in the tracked tree, in a
/// path or in a file, and no file in an encoding the check cannot read.
#[test]
fn no_tracked_file_contains_cjk_characters() {
    let root = repo_root();
    let Some(files) = tracked_files(&root) else {
        return;
    };

    let mut violations = Vec::new();
    for file in &files {
        let path = &file.path;
        for (column, ch) in path.chars().enumerate() {
            if is_cjk(ch) {
                violations.push(format!(
                    "{path} (in the path, column {}) U+{:04X}",
                    column + 1,
                    ch as u32
                ));
            }
        }

        let Some(bytes) = &file.bytes else {
            continue;
        };
        let text = match std::str::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) if file.is_binary() => continue,
            Err(error) => {
                violations.push(format!(
                    "{path}: not UTF-8 ({error}), and its extension is not one of \
                     {BINARY_EXTENSIONS:?}"
                ));
                continue;
            }
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
    let Some(files) = tracked_files(&root) else {
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

    // Redacted on purpose: this output can end up in a public CI log. The file
    // and line are enough to find a match.
    let redacted = |index: usize, pattern: &str| {
        format!("pattern #{}, len {}", index + 1, pattern.chars().count())
    };

    // ASCII letters compare without regard to case: a name written with a
    // capital in a heading is the same private literal as the entry in the list.
    let lowered: Vec<String> = patterns.iter().map(|p| p.to_ascii_lowercase()).collect();

    let mut violations = Vec::new();
    for file in &files {
        let path = &file.path;
        let path_bytes = file.path_bytes.to_ascii_lowercase();
        for (index, pattern) in lowered.iter().enumerate() {
            if contains(&path_bytes, pattern) {
                violations.push(format!(
                    "{path} (in the path, {})",
                    redacted(index, pattern)
                ));
            }
        }

        // Raw bytes, so a file that is not UTF-8 is searched like any other. A
        // binary file has no lines, and the number is then only a way to find
        // the match.
        let Some(bytes) = &file.bytes else {
            continue;
        };
        let bytes = bytes.to_ascii_lowercase();
        for (number, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
            for (index, pattern) in lowered.iter().enumerate() {
                if contains(line, pattern) {
                    violations.push(format!(
                        "{path}:{} ({})",
                        number + 1,
                        redacted(index, pattern)
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
