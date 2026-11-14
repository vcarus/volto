//! Scaffolding for the test binaries that run a program instead of linking one.
//!
//! `it_cli`, `it_deploy`, `it_installer`, `it_scrub`, `it_clock`,
//! `it_log_lines` and
//! `it_release_assets` judge volto from the outside: a shell script run as a
//! file, the binary run as a process, or the tracked tree read as text. None of
//! them opens a QUIC connection, and none of them wants the harness in
//! [`super`] — which builds certificates with `rcgen`, binds a server and
//! speaks HTTP/3.
//!
//! That is why this is a leaf module reached with
//! `#[path = "common/scripts.rs"] mod scripts;` rather than an item inside
//! `common`. `tests/common/mod.rs` does not declare it, so `mod common;` does
//! not compile it, and a binary that names it this way links exactly what the
//! file below uses: the standard library. D66's QR5 rejected sharing anything
//! with these binaries on the grounds that `mod common;` would drag rcgen,
//! quinn and rustls into a process that only runs `bash`; that objection is
//! about `mod common;`, and this is the way round it.
//!
//! Nothing here asserts anything about volto. It is paths, process output, and
//! the files a run has to plant before it can ask a question: the certificate
//! pair a configuration names, and the stand-in for a volto too old to know a
//! flag.

#![allow(dead_code)] // Each of these binaries uses a subset of this.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

/// The root of the checkout, wherever cargo ran from.
///
/// `CARGO_MANIFEST_DIR` rather than the working directory, which `cargo test`
/// does not promise and a test that spawns a shell cannot rely on.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The `src/` tree, which is what the two gates that read this crate as text
/// scan.
///
/// Beside [`rust_files`] rather than inside it, because "which directory" and
/// "which files in it" are separate questions: the callers below hand the root
/// to `strip_prefix` as well, so a failure names `src/foo.rs` rather than an
/// absolute path.
pub fn source_root() -> PathBuf {
    repo_root().join("src")
}

/// The volto binary this test run built, which is the only thing that can answer
/// what the real program does with a file.
///
/// `CARGO_BIN_EXE_volto` is cargo's promise to an integration test: the path to
/// the freshly built binary, so a script asked to run `volto --check-config`
/// runs the one under test rather than whatever is on `PATH`.
pub fn real_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_volto"))
}

/// Every `.rs` file under `root`, in a stable order so a failure names the same
/// file twice running.
///
/// The two gates that read this crate as text -- `it_clock`, which refuses the
/// wall clock, and `it_log_lines`, which accounts for every production log
/// statement -- both start here, so "what `src/` is" is one answer rather than
/// two that can drift.
pub fn rust_files(root: &Path) -> Vec<PathBuf> {
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

/// The text of a file this gate cannot do its job without.
///
/// `it_scrub`'s lesson pointed the other way: a check that reads a file has to
/// fail loudly when the file is not there, or a rename turns the gate into a
/// no-op that nobody notices. So this panics naming the path rather than
/// returning a `Result` a caller could quietly ignore, and the five gates that
/// read the tree as text share one wording for it.
pub fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

/// Each line of `text` with its comments removed: one entry per line of
/// `text.lines()`, and `None` for a line that holds a comment and no code.
///
/// What it must get right is the doc comments -- `it_clock`'s module names
/// every banned identifier, and so does the prose beside the `bloom` feature in
/// `Cargo.toml`; `it_log_lines`'s entries quote log messages that also appear in
/// the comments explaining them.
///
/// A `//` starts a comment only outside a literal. `src/lib.rs` names its logo
/// by an `https://` URL, and a cut at the first `//` of that line would hide the
/// rest of the line from both gates. A cut inside a string that continues on
/// later lines would also leave its closing quote behind, and every quote after
/// it would then open a string where one closes. So literals are skipped whole
/// with [`literal_len`], across lines, and only what remains is searched for
/// comments. Line comments, doc comments and nested block comments are removed.
/// A block comment leaves one space, so the code on either side of it stays
/// apart.
pub fn code_lines(text: &str) -> Vec<Option<String>> {
    if text.is_empty() {
        return Vec::new();
    }

    // Each line's code so far, and whether a comment was removed from it.
    let mut lines = vec![(String::new(), false)];
    let mut at = 0;

    while at < text.len() {
        let rest = &text[at..];
        let (len, comment) = if rest.starts_with("//") {
            (rest.find('\n').unwrap_or(rest.len()), true)
        } else if rest.starts_with("/*") {
            (block_comment_len(rest), true)
        } else if let Some(len) = literal_len(text, at) {
            (len, false)
        } else {
            (rest.chars().next().map_or(1, char::len_utf8), false)
        };

        for ch in rest[..len].chars() {
            if ch == '\n' {
                lines.push((String::new(), false));
            } else if comment {
                lines.last_mut().expect("there is always a line").1 = true;
            } else {
                lines.last_mut().expect("there is always a line").0.push(ch);
            }
        }
        if comment && rest.starts_with("/*") {
            lines
                .last_mut()
                .expect("there is always a line")
                .0
                .push(' ');
        }
        at += len;
    }

    // `lines()` does not report an empty line after a final newline.
    if text.ends_with('\n') {
        lines.pop();
    }

    lines
        .into_iter()
        .map(|(code, comment)| (!comment || !code.trim().is_empty()).then_some(code))
        .collect()
}

/// The length in bytes of the block comment at the start of `rest`, nested ones
/// included, or the rest of the text when it never closes.
fn block_comment_len(rest: &str) -> usize {
    let bytes = rest.as_bytes();
    let mut depth = 0usize;
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at..].starts_with(b"/*") {
            depth += 1;
            at += 2;
        } else if bytes[at..].starts_with(b"*/") {
            depth -= 1;
            at += 2;
            if depth == 0 {
                return at;
            }
        } else {
            at += 1;
        }
    }
    rest.len()
}

/// The length in bytes of the string, raw string or character literal that
/// starts at byte `at` of `text`, or `None` when no literal starts there.
///
/// A byte string's `b` is read as code and its quote as the start of a string,
/// which skips the same text. A lifetime or a label (`'a`, `'outer:`) is not a
/// literal, and neither is the `r` that ends an identifier such as `for`, which
/// is why the text before `at` is part of the input. A literal that never
/// closes runs to the end of the text.
pub fn literal_len(text: &str, at: usize) -> Option<usize> {
    let rest = &text[at..];
    match rest.chars().next()? {
        '"' => Some(string_len(rest)),
        '\'' => char_literal_len(rest),
        'r' if starts_a_raw_string(&text[..at]) => raw_string_len(rest),
        _ => None,
    }
}

/// The length of the ordinary string literal at the start of `rest`.
///
/// Escapes are honoured, so a `\"` does not end it. Reading bytes is safe here:
/// neither `"` nor `\` occurs inside a multi-byte character.
fn string_len(rest: &str) -> usize {
    let bytes = rest.as_bytes();
    let mut at = 1;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' => at += 2,
            b'"' => return at + 1,
            _ => at += 1,
        }
    }
    rest.len()
}

/// The length of the character literal at the start of `rest`, or `None` when
/// the quote opens a lifetime or a label instead.
fn char_literal_len(rest: &str) -> Option<usize> {
    let mut chars = rest.char_indices().skip(1);
    match chars.next()?.1 {
        // An escape: `'\n'`, `'\''`, `'\u{7f}'`. The escaped character may be a
        // quote, so the search for the closing one starts after it.
        '\\' => {
            chars.next()?;
            chars
                .find(|(_, ch)| *ch == '\'')
                .map(|(close, _)| close + 1)
        }
        '\'' | '\n' => None,
        _ => {
            let (close, ch) = chars.next()?;
            (ch == '\'').then_some(close + 1)
        }
    }
}

/// Whether an `r` after `before` can open a raw string, which it cannot when it
/// is the tail of an identifier. A `b` or `c` prefix (`br"…"`, `cr"…"`) is part
/// of the literal and is looked past.
fn starts_a_raw_string(before: &str) -> bool {
    let before = before
        .strip_suffix('b')
        .or_else(|| before.strip_suffix('c'))
        .unwrap_or(before);
    !before.ends_with(|ch: char| ch.is_alphanumeric() || ch == '_')
}

/// The length of the raw string at the start of `rest`, or `None` when the `r`
/// is followed by something other than `#`s and a quote, as in `r#type`.
fn raw_string_len(rest: &str) -> Option<usize> {
    let hashes = rest[1..].bytes().take_while(|byte| *byte == b'#').count();
    let body = 1 + hashes;
    if rest.as_bytes().get(body) != Some(&b'"') {
        return None;
    }
    let close = format!("\"{}", "#".repeat(hashes));
    Some(
        rest[body + 1..]
            .find(&close)
            .map_or(rest.len(), |end| body + 1 + end + close.len()),
    )
}

/// A process's standard output as text, with anything invalid replaced.
///
/// Lossy on purpose: these tests assert on what a program *said*, and a run
/// that produced invalid UTF-8 should fail on the assertion that names the
/// missing line rather than on the decode.
pub fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A process's standard error as text, with anything invalid replaced.
pub fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A scratch directory named for this process, emptied if it already exists.
///
/// Named by pid so two `cargo test` runs at once do not share one, and cleared
/// rather than trusted, so a run that crashed before its cleanup cannot leave a
/// file behind that makes the next one pass. The directory itself is not
/// created: some callers want it empty and some want a tree inside it.
///
/// That clearing is why no caller deletes its tree on the way out. A trailing
/// `remove_dir_all` is skipped exactly when a test panics, which is the one run
/// whose leftovers anybody wants to open, and it buys nothing on a green run
/// that this does not already buy on the next one. A `Drop` guard would run on
/// the panic and take that evidence away, which is why there is not one.
pub fn scratch_dir(tag: &str, name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("volto-{tag}-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// [`scratch_dir`] with `dirs` created inside it, all of them.
///
/// The three binaries that drive a shipped script each stand a directory tree up
/// for it: a stand-in `/etc/volto` for `it_cli`, the four directories a Linux
/// host already has for `it_deploy`, one configuration directory for
/// `it_installer`. Which directories differ, and so does whether a certificate
/// pair is planted afterwards, which each caller still does itself; creating
/// them is the shared half.
///
/// An empty `dirs` creates the scratch directory and nothing under it, which
/// [`scratch_dir`] on its own deliberately does not do.
pub fn scratch_tree(tag: &str, name: &str, dirs: &[&str]) -> PathBuf {
    let root = scratch_dir(tag, name);
    fs::create_dir_all(&root).expect("the temporary root must be creatable");
    for dir in dirs {
        fs::create_dir_all(root.join(dir)).expect("the temporary root must be creatable");
    }
    root
}

/// Writes the certificate pair a loadable configuration has to point at.
///
/// `Config::validate` insists both paths exist and are files; nothing in these
/// tests parses them, because the certificate is not what any of this is about.
/// Returns the two paths in the order the configuration names them.
pub fn plant_placeholder_certificates(dir: &Path) -> (PathBuf, PathBuf) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    fs::write(&cert, "not a certificate\n").expect("cert must be writable");
    fs::write(&key, "not a key\n").expect("key must be writable");
    (cert, key)
}

/// Writes a stand-in for a volto from before `--check-config` existed, at
/// `root/name`, and returns its path.
///
/// It answers `--help` the way clap does, without the flag, and treats anything
/// it does not know the way clap does too: a usage error on stderr and a
/// non-zero status. That second half is the trap both scripts have to get right
/// — a script that tried the flag and read the failure as a verdict on the
/// configuration would fail every install with an older binary, and would
/// abandon `deploy.sh`'s rollback — so the stand-in fails loudly rather than
/// quietly.
///
/// The file name is the caller's because it is what a failure names: the
/// installer's stand-in is the volto it would install, the deploy script's is
/// the candidate it just unpacked.
pub fn plant_binary_without_the_flag(root: &Path, name: &str) -> PathBuf {
    let path = root.join(name);
    fs::write(
        &path,
        "#!/bin/sh\n\
         if [ \"$1\" = --help ]; then\n\
         \x20 echo 'Usage: volto [OPTIONS] --config <FILE>'\n\
         \x20 echo '  -c, --config <FILE>  Path to the TOML configuration file'\n\
         \x20 exit 0\n\
         fi\n\
         echo \"error: unexpected argument '$1' found\" >&2\n\
         exit 2\n",
    )
    .expect("the stand-in binary must be writable");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
        .expect("the stand-in binary must be executable");
    path
}

/// The smallest configuration file the real binary will load.
///
/// `listen` is a parameter because one test needs a port it has already taken
/// for itself; `body` is appended verbatim, tables and all, which is how a test
/// adds a key from the future to a file an older binary must refuse.
pub fn loadable_config_text(
    cert: &Path,
    key: &Path,
    listen: &str,
    password: &str,
    body: &str,
) -> String {
    format!(
        "[server]\n\
         listen = \"{listen}\"\n\
         cert = \"{}\"\n\
         key = \"{}\"\n\
         \n\
         [auth]\n\
         users = [{{ username = \"user1\", password = \"{password}\" }}]\n\
         {body}",
        cert.display(),
        key.display(),
    )
}
