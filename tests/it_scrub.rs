//! The tracked tree must stay scrubbed.
//!
//! This repository is public, and the development notes it grew out of are not:
//! they carry a private identity, a production topology, real addresses and
//! ports, and prose in another script. `dev_docs/` is gitignored, but that only
//! stops the obvious mistake. A quoted line pasted into a comment, a doc copied
//! to `docs/`, or a commit made from the wrong file is irreversible once it is
//! pushed (GitHub keeps caches and forks).
//!
//! The gate scans what the next commit can carry: the working copy of every
//! file git tracks or would add (`git ls-files --cached --others
//! --exclude-standard`), and the staged copy of every file whose index entry
//! differs from its working copy. Ignored files, `dev_docs/` and `CLAUDE.md`
//! among them, are outside it. Two checks run over the path of each file as
//! well as its contents:
//!
//! * CJK characters and the scripts written alongside them, which are
//!   self-describing and can be spelled out here as escapes, so this file stays
//!   clean of them itself. A file must be UTF-8, because text in a legacy CJK
//!   encoding never is; the one exception is a file whose extension is on
//!   [`BINARY_EXTENSIONS`].
//! * A list of private literals, which cannot be written down in a public
//!   repository at all. They come from outside the tree: `VOLTO_SCRUB_PATTERNS`
//!   (`|`-separated, from a repository secret in CI) and, on the dev host, the
//!   gitignored `dev_docs/scrub-patterns.txt`. They are searched for in the raw
//!   bytes of every file, binary ones included, without regard to letter case.
//!   A PNG may carry no compressed text chunk, whose bytes a search cannot see.
//!   Matches are reported by file and line with the pattern *redacted*: CI logs
//!   are public too.
//!
//! The presence of `dev_docs/` marks the dev host, the one place where the gate
//! runs before a push. There every way the gate could stop short fails the
//! test: a missing or empty word list, a `git` that fails, a listing shorter
//! than [`TRACKED_FLOOR`], or a listed file that cannot be read. A push to the
//! canonical repository fails the same way, since the secret must be there.
//! Anywhere else (a fork, a pull request, a fresh clone) the word list does not
//! exist, so the literal check is skipped and the CJK check still runs.

#[path = "common/scripts.rs"]
mod scripts;

use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use scripts::{Scratch, repo_root, scratch_tree};

/// Ranges that no scanned file may contain.
///
/// Hangul Jamo and its two extensions, the enclosed alphanumerics (the circled
/// digits used as markers in notes), the whole CJK run from the radicals
/// through the compatibility block (Kangxi radicals, ideographic description
/// characters, symbols and punctuation, kana, Bopomofo and enclosed CJK forms
/// are all inside it), the ideograph blocks and the compatibility ideographs,
/// Hangul syllables, the vertical and compatibility forms, fullwidth and
/// halfwidth forms, the enclosed ideographic supplement, and the ideographs of
/// planes 2 and 3. So the check covers the scripts the notes are written in,
/// their neighbours and their markers, not only Han characters.
const CJK_RANGES: [(char, char); 13] = [
    ('\u{1100}', '\u{11ff}'),
    ('\u{2460}', '\u{24ff}'),
    ('\u{2e80}', '\u{33ff}'),
    ('\u{3400}', '\u{4dbf}'),
    ('\u{4e00}', '\u{9fff}'),
    ('\u{a960}', '\u{a97f}'),
    ('\u{ac00}', '\u{d7ff}'),
    ('\u{f900}', '\u{faff}'),
    ('\u{fe10}', '\u{fe1f}'),
    ('\u{fe30}', '\u{fe4f}'),
    ('\u{ff00}', '\u{ffef}'),
    ('\u{1f200}', '\u{1f2ff}'),
    ('\u{20000}', '\u{323af}'),
];

fn is_cjk(ch: char) -> bool {
    CJK_RANGES
        .iter()
        .any(|(first, last)| ch >= *first && ch <= *last)
}

/// One character of each block around the ideographs that the check covers,
/// and two that it must not flag: a letter and the emoji variation selector.
#[test]
fn the_cjk_ranges_cover_the_blocks_around_the_ideographs() {
    for ch in [
        '\u{2e80}',
        '\u{2f00}',
        '\u{2ff0}',
        '\u{a960}',
        '\u{d7b0}',
        '\u{fe10}',
        '\u{fe30}',
        '\u{1f200}',
        '\u{30000}',
    ] {
        assert!(is_cjk(ch), "U+{:04X} must count as CJK", u32::from(ch));
    }
    for ch in ['a', '\u{fe0f}'] {
        assert!(!is_cjk(ch), "U+{:04X} is not CJK", u32::from(ch));
    }
}

/// The extensions of the files that are not text. Their contents are still
/// searched for the private literals, as raw bytes; only the UTF-8 requirement
/// and the CJK check of the contents skip them, because compressed data
/// decodes into CJK characters by chance.
const BINARY_EXTENSIONS: [&str; 1] = ["png"];

/// Fewer listed files than this is a listing that went wrong, not a tree.
const TRACKED_FLOOR: usize = 100;

/// The id of the canonical repository on GitHub, which a rename or a transfer
/// keeps and a fork does not share.
const CANONICAL_REPOSITORY_ID: &str = "1333836681";

/// The word list on the dev host, a path `CLAUDE.md` fixes.
const WORD_LIST: &str = "dev_docs/scrub-patterns.txt";

/// Where the gate runs and what it is told.
struct Gate<'a> {
    root: &'a Path,
    /// The `|`-separated literals of `VOLTO_SCRUB_PATTERNS`, when it is set.
    env_patterns: Option<String>,
    /// Whether this is a push to the canonical repository in CI.
    canonical_push: bool,
    floor: usize,
}

impl Gate<'_> {
    /// The gate over this checkout, as CI or the dev host runs it.
    fn here(root: &Path) -> Gate<'_> {
        Gate {
            root,
            env_patterns: std::env::var("VOLTO_SCRUB_PATTERNS").ok(),
            canonical_push: is_push_to_canonical_repository(),
            floor: TRACKED_FLOOR,
        }
    }

    fn dev_host(&self) -> bool {
        self.root.join("dev_docs").is_dir()
    }

    /// Whether a gate that cannot run fails the test rather than skipping.
    fn must_run(&self) -> bool {
        self.dev_host() || self.canonical_push
    }
}

/// Whether this is GitHub Actions running a `push` in the repository that owns
/// the secret.
///
/// Only there is an empty pattern list a failure away from the dev host: a fork
/// has no secret, and a pull request, Dependabot's included, runs without
/// repository secrets by design, so both fall back to the CJK check alone.
fn is_push_to_canonical_repository() -> bool {
    std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("push")
        && std::env::var("GITHUB_REPOSITORY_ID").as_deref() == Ok(CANONICAL_REPOSITORY_ID)
}

/// One file the next commit can carry: its path as git lists it, and each copy
/// of its contents the commit could take.
struct Listed {
    /// The path as UTF-8, with anything invalid replaced, for messages and the
    /// CJK check.
    path: String,
    /// The path's raw bytes, for the literal check.
    path_bytes: Vec<u8>,
    /// The working copy and the staged copy, each with its label. Empty for a
    /// directory, which is another repository's.
    copies: Vec<(&'static str, Vec<u8>)>,
}

impl Listed {
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

    /// `path` for a working copy, `path (staged)` for the index's.
    fn name(&self, label: &str) -> String {
        if label.is_empty() {
            self.path.clone()
        } else {
            format!("{} ({label})", self.path)
        }
    }
}

/// Runs `git` in `root` and returns its standard output.
fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    match Command::new("git").args(args).current_dir(root).output() {
        Ok(output) if output.status.success() => Ok(output.stdout),
        Ok(output) => Err(format!(
            "`git {}` failed ({})",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )),
        Err(error) => Err(format!("git is not available ({error})")),
    }
}

/// The NUL-separated paths of a `-z` listing.
fn paths_of(stdout: &[u8]) -> BTreeSet<Vec<u8>> {
    stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

/// What the next commit can carry, `Ok(None)` when the gate is skipped here,
/// and `Err` when it cannot run where it must.
fn listing(gate: &Gate) -> Result<Option<Vec<Listed>>, String> {
    let skip_or_fail = |reason: String| {
        if gate.must_run() {
            Err(reason)
        } else {
            eprintln!("skipping the scrub gate: {reason}");
            Ok(None)
        }
    };
    let listed = git(
        gate.root,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    );
    let changed = git(gate.root, &["diff", "--name-only", "-z"]);
    let (paths, changed) = match (listed, changed) {
        (Ok(listed), Ok(changed)) => (paths_of(&listed), paths_of(&changed)),
        (Err(reason), _) | (_, Err(reason)) => return skip_or_fail(reason),
    };
    if paths.len() < gate.floor {
        return skip_or_fail(format!(
            "`git ls-files` listed {} files, fewer than the {} a whole checkout has",
            paths.len(),
            gate.floor
        ));
    }

    let mut files = Vec::new();
    for path_bytes in paths {
        let path = String::from_utf8_lossy(&path_bytes).into_owned();
        let on_disk = gate.root.join(&path);
        let mut copies = Vec::new();
        // A symbolic link is committed as the text of its target, which is
        // what is read here; `fs::read` would follow it.
        let working = match fs::symlink_metadata(&on_disk) {
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Ok(meta) if meta.is_dir() => Ok(None),
            Ok(meta) if meta.file_type().is_symlink() => fs::read_link(&on_disk)
                .map(|target| Some(target.into_os_string().into_encoded_bytes())),
            _ => fs::read(&on_disk).map(Some),
        };
        match working {
            Ok(Some(bytes)) => copies.push(("", bytes)),
            Ok(None) => {}
            Err(error) => {
                if gate.must_run() {
                    return Err(format!("{path} cannot be read: {error}"));
                }
                eprintln!("the scrub gate skips {path}: {error}");
            }
        }
        if changed.contains(&path_bytes) {
            match git(gate.root, &["show", &format!(":{path}")]) {
                Ok(bytes) => copies.push(("staged", bytes)),
                Err(reason) if gate.must_run() => return Err(reason),
                Err(reason) => eprintln!("the scrub gate skips the staged {path}: {reason}"),
            }
        }
        files.push(Listed {
            path,
            path_bytes,
            copies,
        });
    }
    Ok(Some(files))
}

/// Adds a literal unless it is empty or already known.
fn push_pattern(patterns: &mut Vec<String>, candidate: &str) {
    let candidate = candidate.trim();
    if !candidate.is_empty() && !patterns.iter().any(|known| known == candidate) {
        patterns.push(candidate.to_string());
    }
}

/// The literals to look for, from outside the tree, in lower case. Never
/// printed anywhere.
///
/// On the dev host the word list must exist and name at least one literal, and
/// on a push to the canonical repository the secret must; anywhere else an
/// empty list skips the literal check.
fn scrub_patterns(gate: &Gate) -> Result<Vec<String>, String> {
    let mut patterns: Vec<String> = Vec::new();
    if let Some(from_env) = &gate.env_patterns {
        for candidate in from_env.split('|') {
            push_pattern(&mut patterns, candidate);
        }
    }

    if gate.dev_host() {
        let from_file = fs::read_to_string(gate.root.join(WORD_LIST))
            .map_err(|error| format!("{WORD_LIST} cannot be read on the dev host: {error}"))?;
        let entries: Vec<&str> = from_file
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            .collect();
        if entries.is_empty() {
            return Err(format!("{WORD_LIST} names no literal"));
        }
        for entry in entries {
            push_pattern(&mut patterns, entry);
        }
    }

    if patterns.is_empty() && gate.canonical_push {
        return Err(
            "no scrub patterns on a push to the canonical repository: the \
                    VOLTO_SCRUB_PATTERNS secret is missing or empty"
                .to_owned(),
        );
    }
    Ok(patterns
        .iter()
        .map(|pattern| pattern.to_lowercase())
        .collect())
}

/// Every CJK character in a path or in the text of a file, and every file that
/// is neither UTF-8 nor binary by its extension.
fn cjk_violations(files: &[Listed]) -> Vec<String> {
    let mut violations = Vec::new();
    for file in files {
        for (column, ch) in file.path.chars().enumerate() {
            if is_cjk(ch) {
                violations.push(format!(
                    "{} (in the path, column {}) U+{:04X}",
                    file.path,
                    column + 1,
                    u32::from(ch)
                ));
            }
        }

        for (label, bytes) in &file.copies {
            let name = file.name(label);
            let text = match std::str::from_utf8(bytes) {
                Ok(text) => text,
                Err(_) if file.is_binary() => continue,
                Err(error) => {
                    violations.push(format!(
                        "{name}: not UTF-8 ({error}), and its extension is not one of \
                         {BINARY_EXTENSIONS:?}"
                    ));
                    continue;
                }
            };
            for (number, line) in text.lines().enumerate() {
                for (column, ch) in line.chars().enumerate() {
                    if is_cjk(ch) {
                        violations.push(format!(
                            "{name}:{}:{} U+{:04X}",
                            number + 1,
                            column + 1,
                            u32::from(ch)
                        ));
                    }
                }
            }
        }
    }
    violations
}

/// Whether a PNG carries a chunk whose text is compressed: `zTXt`, or `iTXt`
/// with its compression flag set. A byte search cannot see into either.
fn png_has_compressed_text(bytes: &[u8]) -> bool {
    let mut at = 8;
    while let Some(header) = bytes.get(at..at + 8) {
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let Ok(length) = usize::try_from(length) else {
            return false;
        };
        let kind = &header[4..8];
        let data = bytes.get(at + 8..).unwrap_or_default();
        let data = &data[..length.min(data.len())];
        let compressed_itxt = kind == b"iTXt"
            && data
                .iter()
                .position(|byte| *byte == 0)
                .and_then(|keyword_end| data.get(keyword_end + 1))
                == Some(&1);
        if kind == b"zTXt" || compressed_itxt {
            return true;
        }
        at += 12 + length;
    }
    false
}

/// Every occurrence of one of `patterns` (already in lower case) in a path or
/// in the bytes of a file, with the pattern redacted, and every PNG whose text
/// the search cannot read.
fn literal_violations(files: &[Listed], patterns: &[String]) -> Vec<String> {
    // Redacted on purpose: this output can end up in a public CI log. The file
    // and line are enough to find a match.
    let redacted = |index: usize, pattern: &str| {
        format!("pattern #{}, len {}", index + 1, pattern.chars().count())
    };

    let mut violations = Vec::new();
    for file in files {
        let path = lowered(&file.path_bytes);
        for (index, pattern) in patterns.iter().enumerate() {
            if contains(&path, pattern) {
                violations.push(format!(
                    "{} (in the path, {})",
                    file.path,
                    redacted(index, pattern)
                ));
            }
        }

        // A binary file has no lines, and the number is then only a way to
        // find the match.
        for (label, bytes) in &file.copies {
            let name = file.name(label);
            if file.is_binary() && png_has_compressed_text(bytes) {
                violations.push(format!(
                    "{name}: carries a compressed text chunk, which the search cannot read"
                ));
            }
            let bytes = lowered(bytes);
            let go_sum = Path::new(&file.path).file_name() == Some("go.sum".as_ref());
            for (number, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
                let line = if go_sum {
                    without_go_sum_checksum(line)
                } else {
                    line
                };
                for (index, pattern) in patterns.iter().enumerate() {
                    if contains(line, pattern) {
                        violations.push(format!(
                            "{name}:{} ({})",
                            number + 1,
                            redacted(index, pattern)
                        ));
                    }
                }
            }
        }
    }
    violations
}

/// A `go.sum` line without its checksum, when the line has the shape `go`
/// writes, `<module> <version>[/go.mod] h1:<hash>` with the hash in base64 of
/// 32 bytes. Any other line comes back whole.
///
/// The checksum is the one part of the tree that no person writes: `go mod
/// tidy` copies it from the checksum database, and it is 43 characters of
/// base64 with letter case dropped before the search. A short literal from the
/// word list then matches inside a hash by chance (a three-letter one did, in
/// the 520 lines of the sing-box module's go.sum), and no edit of ours can
/// change the hash. The module path and the version stay searched, and so does
/// every line of any other shape.
fn without_go_sum_checksum(line: &[u8]) -> &[u8] {
    let Ok(text) = std::str::from_utf8(line) else {
        return line;
    };
    let mut fields = text.split(' ');
    let (Some(module), Some(version), Some(checksum), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return line;
    };
    let is_hash = checksum.strip_prefix("h1:").is_some_and(|hash| {
        hash.len() == 44
            && hash.ends_with('=')
            && hash.as_bytes()[..43]
                .iter()
                .all(|&byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
    });
    if is_hash && !module.is_empty() && !version.is_empty() {
        &line[..module.len() + 1 + version.len()]
    } else {
        line
    }
}

/// `bytes` in lower case: every letter when they are UTF-8, the ASCII letters
/// otherwise. A name written with a capital in a heading is the same private
/// literal as the entry in the list.
fn lowered(bytes: &[u8]) -> Vec<u8> {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_lowercase().into_bytes(),
        Err(_) => bytes.to_ascii_lowercase(),
    }
}

/// Whether the line `haystack` contains `needle`.
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

/// Public repository, English only: no CJK anywhere the next commit can carry,
/// in a path or in a file, and no file in an encoding the check cannot read.
#[test]
fn no_tracked_file_contains_cjk_characters() {
    let root = repo_root();
    let Some(files) = listing(&Gate::here(&root)).unwrap_or_else(|reason| panic!("{reason}"))
    else {
        return;
    };

    let violations = cjk_violations(&files);
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
    let gate = Gate::here(&root);
    let patterns = scrub_patterns(&gate).unwrap_or_else(|reason| panic!("{reason}"));
    let Some(files) = listing(&gate).unwrap_or_else(|reason| panic!("{reason}")) else {
        return;
    };
    if patterns.is_empty() {
        eprintln!("no scrub patterns here, so only the CJK check ran");
        return;
    }

    let violations = literal_violations(&files, &patterns);
    assert!(
        violations.is_empty(),
        "tracked files must not carry private literals ({} occurrence(s), \
         patterns redacted):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

/// A literal made up for the tests of the gate itself. It is in no word list.
const MADE_UP_LITERAL: &str = "Quorbleflax";

/// A scratch git repository in which `.gitignore` names `dev_docs/` and
/// `ignored.txt`, as the real one names its private files, and `tracked.txt`
/// is staged.
///
/// `--exclude-standard` also reads the excludes file of the user's global git
/// configuration. The repository's own configuration names an empty file
/// instead, so a global ignore of `*.md` or `*.png` cannot hide a file these
/// tests plant.
fn scratch_repository(name: &str) -> Scratch {
    let root = scratch_tree("scrub", name, &[]);
    git(&root, &["init", "-q"]).expect("git init must work in a scratch directory");
    let no_excludes = root.join(".git/no-excludes");
    fs::write(&no_excludes, "").expect("write an empty excludes file");
    git(
        &root,
        &[
            "config",
            "core.excludesFile",
            no_excludes.to_str().expect("a UTF-8 scratch path"),
        ],
    )
    .expect("git config must work in a scratch repository");
    fs::write(root.join(".gitignore"), "dev_docs/\nignored.txt\n").expect("write .gitignore");
    fs::write(root.join("tracked.txt"), "nothing to see\n").expect("write a tracked file");
    git(&root, &["add", ".gitignore", "tracked.txt"]).expect("git add");
    root
}

/// The gate over a scratch repository, with no secret and a floor of one.
fn scratch_gate(root: &Path) -> Gate<'_> {
    Gate {
        root,
        env_patterns: None,
        canonical_push: false,
        floor: 1,
    }
}

/// The gate finds a literal in a file not yet added and in a file staged with
/// it and then edited, and does not read an ignored file.
#[test]
fn the_gate_scans_what_the_next_commit_can_carry() {
    let root = scratch_repository("next-commit");
    fs::create_dir(root.join("dev_docs")).expect("create dev_docs");
    fs::write(
        root.join(WORD_LIST),
        format!("# a comment\n{}\n", MADE_UP_LITERAL.to_uppercase()),
    )
    .expect("write the word list");
    fs::write(root.join("untracked.txt"), format!("a {MADE_UP_LITERAL}\n")).expect("untracked");
    fs::write(
        root.join("staged.txt"),
        format!("x\nthe {MADE_UP_LITERAL}\n"),
    )
    .expect("staged");
    git(&root, &["add", "staged.txt"]).expect("git add");
    fs::write(root.join("staged.txt"), "x\nedited away\n").expect("edit the staged file");
    fs::write(root.join("ignored.txt"), MADE_UP_LITERAL).expect("ignored");

    let gate = scratch_gate(&root);
    let patterns = scrub_patterns(&gate).expect("the word list names a literal");
    let files = listing(&gate)
        .expect("the scratch repository can be listed")
        .expect("the dev host never skips");
    let violations = literal_violations(&files, &patterns);

    assert_eq!(
        violations,
        [
            "staged.txt (staged):2 (pattern #1, len 11)",
            "untracked.txt:1 (pattern #1, len 11)",
        ],
        "the untracked and the staged copy must be caught, the ignored file not read"
    );
}

/// In a `go.sum` the checksum of a line in go's shape is not searched, and
/// everything else is: the module path and version of that line, a line of
/// another shape in the same file, and the same line in a file of another
/// name.
#[test]
fn a_go_sum_checksum_is_the_one_part_not_searched() {
    let root = scratch_repository("go-sum");
    fs::create_dir_all(root.join("dev_docs")).expect("create dev_docs");
    fs::create_dir_all(root.join("module")).expect("create module");
    fs::write(root.join(WORD_LIST), format!("{MADE_UP_LITERAL}\n")).expect("write the word list");
    // 11 letters and 32 more characters of base64, then the padding.
    let hashed = format!(
        "example.com/a v1.0.0 h1:{MADE_UP_LITERAL}{}=",
        "A".repeat(32)
    );
    let go_sum = format!(
        "{hashed}\n\
         example.com/{MADE_UP_LITERAL} v1.0.0/go.mod h1:{}=\n\
         a note about {MADE_UP_LITERAL}\n",
        "B".repeat(43)
    );
    fs::write(root.join("module/go.sum"), go_sum).expect("write go.sum");
    fs::write(root.join("notes.txt"), format!("{hashed}\n")).expect("write notes.txt");

    let gate = scratch_gate(&root);
    let patterns = scrub_patterns(&gate).expect("the word list names a literal");
    let files = listing(&gate)
        .expect("the scratch repository can be listed")
        .expect("the dev host never skips");
    let violations = literal_violations(&files, &patterns);

    assert_eq!(
        violations,
        [
            "module/go.sum:2 (pattern #1, len 11)",
            "module/go.sum:3 (pattern #1, len 11)",
            "notes.txt:1 (pattern #1, len 11)",
        ],
        "only the checksum of a go.sum line in go's shape may go unsearched"
    );
}

/// On the dev host each way the gate could stop short is a failure.
#[test]
fn on_the_dev_host_the_gate_fails_rather_than_skips() {
    let root = scratch_repository("dev-host");
    fs::create_dir(root.join("dev_docs")).expect("create dev_docs");
    let gate = scratch_gate(&root);

    let missing = scrub_patterns(&gate).expect_err("a missing word list must fail");
    assert!(missing.contains(WORD_LIST), "{missing}");
    fs::write(root.join(WORD_LIST), "# only a comment\n\n").expect("write the word list");
    let empty = scrub_patterns(&gate).expect_err("a word list with no literal must fail");
    assert!(empty.contains("names no literal"), "{empty}");

    // A file deleted from the working copy is not an error; its staged copy is
    // what the next commit carries, and it is read.
    fs::write(root.join("deleted.txt"), "staged text\n").expect("write");
    git(&root, &["add", "deleted.txt"]).expect("git add");
    fs::remove_file(root.join("deleted.txt")).expect("delete the working copy");
    let files = listing(&gate)
        .expect("a deleted working copy is not an error")
        .expect("the dev host never skips");
    let deleted = files
        .iter()
        .find(|file| file.path == "deleted.txt")
        .expect("the deleted file is still listed");
    assert_eq!(deleted.copies, [("staged", b"staged text\n".to_vec())]);

    let locked = root.join("locked.txt");
    fs::write(&locked, "text\n").expect("write");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("chmod 000");
    // Root reads a file of mode 000, so this case has nothing to show there.
    if fs::read(&locked).is_err() {
        let unreadable = listing(&gate).err().expect("an unreadable file must fail");
        assert!(
            unreadable.contains("locked.txt cannot be read"),
            "{unreadable}"
        );
    }
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).expect("chmod 644");

    let not_a_repository = scratch_tree("scrub", "dev-host-no-git", &["dev_docs"]);
    let failed = listing(&scratch_gate(&not_a_repository))
        .err()
        .expect("a git that fails must fail the gate");
    assert!(failed.contains("git"), "{failed}");

    let short = Gate {
        floor: 100,
        ..scratch_gate(&root)
    };
    let few = listing(&short).err().expect("a short listing must fail");
    assert!(few.contains("fewer than the 100"), "{few}");
}

/// Away from the dev host the word-list part is skipped and nothing fails for
/// its absence, while the CJK check still runs and still finds a hit.
#[test]
fn away_from_the_dev_host_only_the_word_list_part_is_skipped() {
    let root = scratch_repository("no-dev-host");
    fs::write(root.join("notes.md"), "a note \u{3002}\n").expect("write");
    let gate = scratch_gate(&root);

    assert_eq!(scrub_patterns(&gate), Ok(Vec::new()));
    let files = listing(&gate)
        .expect("the scratch repository can be listed")
        .expect("a listing that works is scanned");
    assert_eq!(cjk_violations(&files), ["notes.md:1:8 U+3002"]);

    let not_a_repository = scratch_tree("scrub", "no-dev-host-no-git", &[]);
    assert!(
        matches!(listing(&scratch_gate(&not_a_repository)), Ok(None)),
        "without dev_docs a git that fails skips the gate"
    );
}

/// The gate reads the bytes git stores: a symbolic link as the text of its
/// target, a letter in any case, and a PNG's compressed text, which it cannot
/// search and so refuses.
#[test]
fn the_gate_reads_what_git_would_publish() {
    let root = scratch_repository("published-bytes");
    fs::create_dir(root.join("dev_docs")).expect("create dev_docs");
    fs::write(
        root.join(WORD_LIST),
        format!("{MADE_UP_LITERAL}\nSm\u{f8}rgaflux\n"),
    )
    .expect("write the word list");
    std::os::unix::fs::symlink(format!("/nowhere/{MADE_UP_LITERAL}"), root.join("link.md"))
        .expect("plant a dangling link");
    fs::write(root.join("upper.md"), "SM\u{d8}RGAFLUX\n").expect("write");
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&5u32.to_be_bytes());
    png.extend_from_slice(b"zTXtk\0\0xx");
    png.extend_from_slice(&[0; 4]);
    fs::write(root.join("pic.png"), png).expect("write");

    let gate = scratch_gate(&root);
    let patterns = scrub_patterns(&gate).expect("the word list names literals");
    let files = listing(&gate)
        .expect("the scratch repository can be listed")
        .expect("the dev host never skips");

    assert_eq!(
        literal_violations(&files, &patterns),
        [
            "link.md:1 (pattern #1, len 11)",
            "pic.png: carries a compressed text chunk, which the search cannot read",
            "upper.md:1 (pattern #2, len 10)",
        ]
    );
}
