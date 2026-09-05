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

/// `line` with a trailing `//` comment removed, and `None` for a line that is
/// nothing but a comment.
///
/// Deliberately crude: this crate has no `/* */` comments and no string literal
/// carrying a `//`, so the only thing a cleverer parser would buy is the chance
/// of a subtler bug in the gates that use it. What it must get right is the doc
/// comments -- `it_clock`'s module names every banned identifier, and so does
/// the prose beside the `bloom` feature in `Cargo.toml`; `it_log_lines`'s
/// entries quote log messages that also appear in the comments explaining them.
pub fn code_only(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return None;
    }
    match line.split_once("//") {
        Some((code, _)) => Some(code),
        None => Some(line),
    }
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
pub fn scratch_dir(tag: &str, name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("volto-{tag}-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
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
