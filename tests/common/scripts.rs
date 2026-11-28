//! Scaffolding for the test binaries that run a program instead of linking one.
//!
//! The binaries that run a program, run a script, or read the tracked tree as
//! text judge volto from the outside. None of them opens a QUIC connection,
//! and none of them wants the harness in [`super`], which builds certificates
//! with `rcgen`, binds a server and speaks HTTP/3.
//!
//! That is why this is a leaf module reached with
//! `#[path = "common/scripts.rs"] mod scripts;` rather than an item inside
//! `common`. `tests/common/mod.rs` does not declare it, so `mod common;` does
//! not compile it, and a binary that names it this way links exactly what the
//! file below uses: the standard library, and rustix to signal a process
//! group. D66 allows sharing with them only through a leaf module like this
//! one.
//!
//! Nothing here asserts anything about volto. It is paths, process output, and
//! the files a run has to plant before it can ask a question: the certificate
//! pair a configuration names, and the stand-in for a volto too old to know a
//! flag.

#![allow(dead_code)] // Each of these binaries uses a subset of this.

use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// The root of the checkout, wherever cargo ran from.
///
/// `CARGO_MANIFEST_DIR` rather than the working directory, which `cargo test`
/// does not promise and a test that spawns a shell cannot rely on.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The `src/` tree, which the text gates scan.
pub fn source_root() -> PathBuf {
    repo_root().join("src")
}

/// Writes a configuration file with mode 0600, as an installed one is kept
/// from other users, so that loading it draws no warning about its mode.
pub fn write_private(path: &Path, text: &str) {
    fs::write(path, text).expect("the config must be writable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("the config's mode must be settable");
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
/// The text gates share this one list.
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
/// A check that reads a file has to fail loudly when the file is not there, or
/// a rename turns the gate into a no-op that nobody notices. So this panics
/// naming the path rather than returning a `Result` a caller could quietly
/// ignore.
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

/// How long one run of a script may take before [`run_within_deadline`] kills
/// it. The slowest run in these tests, a full install with its sleeps, takes a
/// few seconds.
pub const SCRIPT_DEADLINE: Duration = Duration::from_secs(120);

/// [`run_within`] with [`SCRIPT_DEADLINE`].
pub fn run_within_deadline(command: &mut Command) -> Output {
    run_within(command, SCRIPT_DEADLINE)
}

/// Runs `command` to its end, as [`Command::output`] does, and kills it and
/// panics when it is still running after `limit`.
///
/// A script that loops, or waits on a `read`, would otherwise hold the test
/// binary until CI's job timeout, and forever on the dev host. Standard input
/// is the caller's to set: the runners give it a null stdin, as
/// [`Command::output`] does, or a file to pipe the script from.
///
/// The run ends when the command has exited and both of its output pipes have
/// closed, as with [`Command::output`]. A process the command started in the
/// background keeps the pipes open after the command exits, so the deadline
/// covers the pipes too. The command runs in a process group of its own, and
/// the deadline kills the whole group, so it reaches such a process as well.
pub fn run_within(command: &mut Command, limit: Duration) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap_or_else(|error| panic!("{command:?} must be runnable: {error}"));
    let group = rustix::process::Pid::from_child(&child);
    let kill_group = || {
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    };
    let expired = || {
        format!(
            "{command:?} or a process it started was still running after {limit:?}, so its \
             process group was killed"
        )
    };

    // Each reader sends its pipe's bytes once the pipe closes, so the wait for
    // them can be bounded. A reader still blocked at the deadline is left
    // behind, since killing the group closes its pipe.
    let (sent, received) = std::sync::mpsc::channel();
    let drain = |is_stdout: bool, mut pipe: Box<dyn Read + Send>| {
        let sent = sent.clone();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            let _ = sent.send((is_stdout, bytes));
        });
    };
    drain(
        true,
        Box::new(child.stdout.take().expect("stdout is piped")),
    );
    drain(
        false,
        Box::new(child.stderr.take().expect("stderr is piped")),
    );

    let deadline = Instant::now() + limit;
    let mut pause = Duration::from_millis(1);
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .expect("the child's status must be readable")
        {
            break status;
        }
        if Instant::now() >= deadline {
            kill_group();
            let _ = child.wait();
            panic!("{}", expired());
        }
        std::thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_millis(20));
    };

    let (mut stdout, mut stderr) = (None, None);
    while stdout.is_none() || stderr.is_none() {
        let left = deadline.saturating_duration_since(Instant::now());
        let Ok((is_stdout, bytes)) = received.recv_timeout(left) else {
            kill_group();
            panic!("{}", expired());
        };
        if is_stdout {
            stdout = Some(bytes);
        } else {
            stderr = Some(bytes);
        }
    }
    Output {
        status,
        stdout: stdout.unwrap_or_default(),
        stderr: stderr.unwrap_or_default(),
    }
}

/// The body of the shell function `name` in `script` (a path under the
/// checkout), from its first line to the line before the closing brace at
/// column zero. A caller appends the brace.
///
/// The braces bound the function, so a test runs exactly that function and
/// none of the script around it.
pub fn shell_function_body(script: &str, name: &str) -> String {
    let text = read_text(&repo_root().join(script));
    let start = text
        .find(&format!("\n{name}() {{"))
        .unwrap_or_else(|| panic!("{script} carries no `{name}()` function"));
    let rest = &text[start + 1..];
    let end = rest
        .find("\n}")
        .unwrap_or_else(|| panic!("`{name}()` in {script} is never closed"));
    rest[..end].to_owned()
}

/// The first executable called `name` on the inherited `PATH`.
///
/// Resolved from the test's own `PATH`, before any stand-in goes in front of
/// it, so a stand-in can hand its arguments to the real tool by absolute path.
pub fn real_tool(name: &str) -> PathBuf {
    try_real_tool(name).unwrap_or_else(|| panic!("no {name} on PATH"))
}

/// [`real_tool`], or `None` when the host has no such tool.
pub fn try_real_tool(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").expect("PATH must be set");
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// A scratch directory tree, removed when this value is dropped on a green run
/// and kept when it is dropped while the thread panics.
///
/// A failed test is the run whose files somebody wants to open, so its tree
/// stays behind under the system temp directory. Every other tree goes with
/// the value that owns it. The value derefs to the root's [`Path`], so a caller
/// keeps it bound for as long as anything uses the tree, and returns it rather
/// than a [`PathBuf`] from a helper that builds one.
pub struct Scratch {
    root: PathBuf,
}

impl std::ops::Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.root
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.root
    }
}

impl AsRef<std::ffi::OsStr> for Scratch {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.root.as_os_str()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

/// Creates a scratch root with `dirs` inside it, all of them.
///
/// The root is `volto-{tag}-{pid}-{name}` under the system temp directory.
/// The pid keeps two `cargo test` runs at once apart. A tree already there is
/// removed first, so a file a failed run left behind cannot make this one pass.
pub fn scratch_tree(tag: &str, name: &str, dirs: &[&str]) -> Scratch {
    let root = std::env::temp_dir().join(format!("volto-{tag}-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("the temporary root must be creatable");
    for dir in dirs {
        fs::create_dir_all(root.join(dir)).expect("the temporary root must be creatable");
    }
    Scratch { root }
}

/// Writes `text` to `path` with mode 0755.
///
/// The stand-ins `it_deploy` and `it_installer` put in front of `PATH` are
/// written this way, and so are the binaries a script is handed.
pub fn write_executable(path: &Path, text: &str) {
    fs::write(path, text).expect("the stub must be writable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .expect("the stub must be executable");
}

/// The inherited `PATH` with `dir` in front of it, so a script run under it
/// finds the stand-ins in `dir` before the host's own commands.
pub fn path_with_stubs(dir: &Path) -> OsString {
    let path = std::env::var_os("PATH").expect("PATH must be set");
    std::env::join_paths(std::iter::once(dir.to_path_buf()).chain(std::env::split_paths(&path)))
        .expect("the stub directory must fit in PATH")
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
    write_executable(
        &path,
        "#!/bin/sh\n\
         if [ \"$1\" = --help ]; then\n\
         \x20 echo 'Usage: volto [OPTIONS] --config <FILE>'\n\
         \x20 echo '  -c, --config <FILE>  Path to the TOML configuration file'\n\
         \x20 exit 0\n\
         fi\n\
         echo \"error: unexpected argument '$1' found\" >&2\n\
         exit 2\n",
    );
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
        "{}\n\
         [auth]\n\
         users = [{{ username = \"user1\", password = \"{password}\" }}]\n\
         {body}",
        server_section(cert, key, listen),
    )
}

// Also loaded by `common/mod.rs`, and `it_cli` and `it_reload` load both.
#[allow(clippy::duplicate_mod)]
#[path = "server_table.rs"]
mod server_table;
pub use server_table::server_section;
