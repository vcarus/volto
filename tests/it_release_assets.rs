//! The release plumbing, which otherwise only fails at tag time.
//!
//! Everything here reads a tracked file as text and asserts a relationship
//! between two of them. They share a shape: each pins an agreement that is
//! today held together by a comment asking the next reader to keep it, and each
//! one's failure mode is a release that builds, publishes and then does not
//! work — discovered on a host, days later, in one line of
//! `journalctl -u volto-deploy`.
//!
//! * **Everything in `script/` is inside the tarball.** The four deployment
//!   assets are siblings on purpose: `install-selfsigned.sh` resolves the other
//!   two through `SCRIPT_DIR`, and `deploy.sh` runs the bundled installer
//!   straight out of an unpacked release. `release.yml` copies them in by name,
//!   so a new asset that nobody adds to that list — or a renamed one nobody
//!   updates — produces a tarball that looks fine and fails on the host: the
//!   first-install branch cannot find the installer, or the update branch
//!   cannot find the unit file.
//! * **`docs/` is inside it too.** Both scripts name `docs/configuration.md` or
//!   `docs/deployment.md` in the message they print when they refuse to
//!   install, which is precisely when a host has no browser open.
//! * **cross.yml runs release.yml's build step, not one like it.** That
//!   workflow exists so a dependency bump that breaks the musl cross-build
//!   fails on the pull request rather than at tag time, and it is worth exactly
//!   as much as the two steps are identical.
//! * **Neither manifest patches `quinn-proto`, and both lockfiles take it from
//!   the registry.** D60 redirected that crate to a git revision until 0.11.18
//!   shipped the fixes it carried, and a `[patch.crates-io]` stanza costs two
//!   things that report nothing when they stop working: Dependabot proposes no
//!   bump for a git revision, and cargo-audit skips a lockfile entry whose
//!   source is not the default registry. A patch reintroduced in either
//!   workspace would take quinn-proto back out of both.
//! * **`src/` cites quinn-proto by symbol, not by line number.** A line number
//!   goes stale on every quinn-proto bump, and a stale one still points at
//!   some line.
//! * **One MSRV.** `fuzz/Cargo.toml`, the `msrv` job in `ci.yml`, `README.md`
//!   and `docs/deployment.md` state the `rust-version` of `Cargo.toml`.

#[path = "common/scripts.rs"]
mod scripts;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use scripts::{read_text, repo_root, rust_files, source_root};

/// The indentation of `line`, in spaces.
fn indentation(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The `cp` commands of the `Package` step of the `build` job in
/// `release.yml`, each as its list of words with quotes removed.
///
/// A step ends at the next line indented no deeper than its `- name:` line,
/// and the job ends at the next line indented no deeper than its key, so a
/// `cp` in any other step or job is not read. A `cp` invocation may be spread
/// over several lines with trailing backslashes; those are folded into one
/// line first.
fn package_copies() -> Vec<Vec<String>> {
    let workflow = repo_root().join(".github/workflows/release.yml");
    let text = read_text(&workflow).replace("\\\n", " ");
    let lines: Vec<&str> = text.lines().collect();

    let job = lines
        .iter()
        .position(|line| *line == "  build:")
        .unwrap_or_else(|| panic!("{} has no `build` job", workflow.display()));
    let job_end = lines[job + 1..]
        .iter()
        .position(|line| !line.trim().is_empty() && indentation(line) <= 2)
        .map_or(lines.len(), |end| job + 1 + end);
    let step = (job..job_end)
        .find(|at| lines[*at].trim() == "- name: Package")
        .unwrap_or_else(|| {
            panic!(
                "the `build` job of {} has no `Package` step",
                workflow.display()
            )
        });
    let depth = indentation(lines[step]);
    let step_end = lines[step + 1..job_end]
        .iter()
        .position(|line| !line.trim().is_empty() && indentation(line) <= depth)
        .map_or(job_end, |end| step + 1 + end);

    let copies: Vec<Vec<String>> = lines[step + 1..step_end]
        .iter()
        .map(|line| line.trim())
        .filter(|line| line.starts_with("cp "))
        .map(|line| {
            line.split_whitespace()
                .map(|word| word.trim_matches(|c| c == '"' || c == '\'').to_owned())
                .collect()
        })
        .collect();
    assert!(
        !copies.is_empty(),
        "the `Package` step of {} copies nothing; the reader is broken, or the \
         step moved",
        workflow.display()
    );
    copies
}

/// Where the `Package` step puts the deployment assets, relative to the
/// archive's directory: `deploy.sh` runs them from `$SRC/script/`.
const SCRIPT_DESTINATION: &str = "dist/${name}/script/";

/// Every `script/…` path the release workflow copies into the tarball.
///
/// Each `cp` line that names one must copy into [`SCRIPT_DESTINATION`], so a
/// path counts only where it lands in the archive's `script/` directory.
fn packaged_paths() -> BTreeSet<String> {
    let mut packaged = BTreeSet::new();
    for copy in package_copies() {
        let sources: Vec<&String> = copy[1..copy.len() - 1]
            .iter()
            .filter(|word| word.starts_with("script/"))
            .collect();
        if sources.is_empty() {
            continue;
        }
        let destination = copy.last().expect("a cp line has words");
        assert_eq!(
            destination, SCRIPT_DESTINATION,
            "release.yml copies {sources:?} to {destination}, but deploy.sh runs the \
             deployment assets from the archive's script/ directory"
        );
        packaged.extend(sources.into_iter().cloned());
    }

    assert!(
        !packaged.is_empty(),
        "no `cp script/… ` line was found in the Package step of release.yml; \
         has the packaging step moved?"
    );
    packaged
}

/// The files under `script/` that git ignores, such as the `.DS_Store` Finder
/// writes on the dev host. None of them can reach a commit or the tarball.
///
/// Empty when git cannot answer, which leaves the directory listing below as
/// strict as it is without this.
fn ignored_in_script_dir() -> BTreeSet<String> {
    let output = std::process::Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--",
            "script/",
        ])
        .current_dir(repo_root())
        .output();
    match output {
        Ok(output) if output.status.success() => output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
            .map(|path| String::from_utf8_lossy(path).into_owned())
            .collect(),
        _ => BTreeSet::new(),
    }
}

/// Every file that sits in `script/`, apart from the ones git ignores.
///
/// The directory is listed rather than `git ls-files`, so a new asset fails
/// this test before it is ever added to the index.
fn assets_on_disk() -> BTreeSet<String> {
    let dir = repo_root().join("script");
    let ignored = ignored_in_script_dir();
    let mut assets = BTreeSet::new();
    for entry in fs::read_dir(&dir).expect("script/ must exist") {
        let entry = entry.expect("script/ must be readable");
        if entry.file_type().expect("a file type").is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_str().expect("asset names are UTF-8");
        let path = format!("script/{name}");
        if !ignored.contains(&path) {
            assets.insert(path);
        }
    }
    assets
}

/// A deployment asset that is not packaged never reaches a host.
#[test]
fn every_deployment_asset_is_packaged_into_the_release() {
    let packaged = packaged_paths();
    let on_disk = assets_on_disk();

    let unpackaged: Vec<_> = on_disk.difference(&packaged).collect();
    assert!(
        unpackaged.is_empty(),
        "these files live in script/ but are not copied into the release tarball \
         by .github/workflows/release.yml: {unpackaged:?}"
    );
}

/// And a packaged path that no longer exists breaks the packaging step itself.
#[test]
fn every_packaged_path_still_exists() {
    let root = repo_root();
    let missing: Vec<_> = packaged_paths()
        .into_iter()
        .filter(|path| !root.join(path).is_file())
        .collect();

    assert!(
        missing.is_empty(),
        ".github/workflows/release.yml packages paths that do not exist: {missing:?}"
    );
}

/// The `docs/` directory has to reach the host as well.
///
/// Not by name, because `release.yml` copies the directory whole and a new page
/// needs no change there — but the copy itself is one line, and deleting it
/// would put every `docs/…` pointer both scripts print back to naming a file
/// that is not on the host.
#[test]
fn the_documentation_the_scripts_point_at_is_packaged() {
    let workflow = repo_root().join(".github/workflows/release.yml");

    // The directory must land at the top of the archive, beside `script/`, which
    // is where the scripts' relative `docs/…` pointers resolve.
    let packages_docs = package_copies().iter().any(|copy| {
        copy[1..copy.len() - 1].iter().any(|word| word == "docs")
            && copy
                .last()
                .is_some_and(|destination| destination == "dist/${name}/")
    });

    assert!(
        packages_docs,
        "the Package step of {} no longer copies `docs` to the top of the \
         tarball, but script/deploy.sh and script/install-selfsigned.sh still send \
         the operator to docs/configuration.md and docs/deployment.md when they \
         refuse to install",
        workflow.display()
    );

    // The other half of that same sentence, which nothing checked: the copy is
    // only worth having while the scripts still point at those pages. Renaming
    // the directory in both scripts would leave the assertion above green.
    // Each page is asserted in the script that prints it. `deploy.sh` names the
    // configuration page when it refuses a config from the future, and
    // `install-selfsigned.sh` names the deployment page when it refuses the
    // host it was run on. Comment lines are skipped, because both scripts also
    // name pages in their header comments, which no operator sees.
    for (script, page) in [
        ("script/deploy.sh", "docs/configuration.md"),
        ("script/install-selfsigned.sh", "docs/deployment.md"),
    ] {
        let path = repo_root().join(script);
        assert!(
            read_text(&path)
                .lines()
                .filter(|line| !line.trim_start().starts_with('#'))
                .any(|line| line.contains(page)),
            "{script} no longer sends the operator to {page}, which is half the \
             reason {} has to package `docs`",
            workflow.display()
        );
    }
}

// ---------------------------------------------------------------------------
// cross.yml mirrors release.yml's build step
// ---------------------------------------------------------------------------

/// Opens the block both workflow files must spell identically.
const MIRROR_OPEN: &str = ">>> mirrored build step";
/// And closes it.
const MIRROR_CLOSE: &str = "<<< mirrored build step";

/// Opens the smoke block both workflow files must spell identically.
const SMOKE_OPEN: &str = ">>> mirrored smoke step";
/// And closes it.
const SMOKE_CLOSE: &str = "<<< mirrored smoke step";

/// The lines between a pair of mirror markers in `.github/workflows/<name>`.
///
/// Markers rather than line numbers: the blocks sit at different offsets in
/// files of different lengths, and an offset is wrong the first time either file
/// grows a line — silently, since a wrong offset still yields *some* text to
/// compare. The prose above each block differs on purpose and stays outside the
/// markers; everything inside them, comments included, has to match byte for
/// byte.
fn mirrored_block(name: &str, open: &str, close: &str) -> String {
    let path = repo_root().join(".github/workflows").join(name);
    let text = read_text(&path);

    let mut block: Vec<&str> = Vec::new();
    let mut inside = false;
    let mut closed = false;

    for line in text.lines() {
        if line.contains(open) {
            assert!(
                !inside && !closed,
                "{} opens the mirrored block more than once",
                path.display()
            );
            inside = true;
        } else if line.contains(close) {
            assert!(
                inside,
                "{} closes a mirrored block it never opened",
                path.display()
            );
            inside = false;
            closed = true;
        } else if inside {
            block.push(line);
        }
    }

    assert!(
        closed,
        "{} carries no `{open}` … `{close}` block. Has the step moved, or were \
         the markers dropped?",
        path.display()
    );
    assert!(
        !block.is_empty(),
        "the mirrored block in {} is empty",
        path.display()
    );

    block.join("\n")
}

/// The build step both workflow files run.
fn mirrored_build_step(name: &str) -> String {
    mirrored_block(name, MIRROR_OPEN, MIRROR_CLOSE)
}

/// The smoke step both workflow files run.
fn mirrored_smoke_step(name: &str) -> String {
    mirrored_block(name, SMOKE_OPEN, SMOKE_CLOSE)
}

/// A green cross build is only evidence about the release build if it *is* the
/// release build.
#[test]
fn cross_yml_runs_the_release_build_step_verbatim() {
    let release = mirrored_build_step("release.yml");
    let cross = mirrored_build_step("cross.yml");

    assert_eq!(
        release, cross,
        "the build step in .github/workflows/cross.yml has drifted from the one \
         in release.yml. cross.yml exists so a dependency bump that breaks the \
         musl cross-build fails on the pull request instead of at tag time; a \
         step that differs proves something about a build nobody ships.\n\n\
         release.yml:\n{release}\n\ncross.yml:\n{cross}"
    );
}

/// A green cross build is not evidence that the released binary runs.
///
/// Nothing used to execute the musl artifact, so a binary that builds and then
/// fails at startup, or a config the binary refuses, reached the release page
/// with every job green. The smoke step runs the built binary with `--version`
/// and with `--check-config` on a minimal planted configuration.
///
/// The step is gated to `x86_64-unknown-linux-musl` because the aarch64 artifact
/// cannot execute on the x86_64 runner. The aarch64 artifact is still covered by
/// the strip assertion in cross.yml and by the packaging assertion in
/// release.yml.
#[test]
fn the_released_binary_is_executed_before_publishing() {
    let release = mirrored_smoke_step("release.yml");
    let cross = mirrored_smoke_step("cross.yml");

    assert_eq!(
        release, cross,
        "the smoke step in .github/workflows/cross.yml has drifted from the one \
         in release.yml. The two exist so that the same binary is executed on the \
         pull request that can break it and before it is published; a step that \
         differs proves something about a binary nobody ships.\n\n\
         release.yml:\n{release}\n\ncross.yml:\n{cross}"
    );

    for needle in [
        "--version",
        "--check-config",
        "matrix.target == 'x86_64-unknown-linux-musl'",
    ] {
        assert!(
            release.contains(needle),
            "the mirrored smoke step no longer contains {needle:?}:\n{release}"
        );
    }
}

/// The workflow must not publish. A published release without `SHA256SUMS.sig`
/// is one every host refuses and the README's one-line install fails on, and
/// the signature is made off GitHub, after the provenance of the tarballs has
/// been checked. So the release step leaves a draft, and the job attests the
/// tarballs it uploads.
#[test]
fn the_release_workflow_attests_its_tarballs_and_leaves_a_draft() {
    let text = read_text(&repo_root().join(".github/workflows/release.yml"));
    let code: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .collect();

    for needle in [
        "draft: true",
        "id-token: write",
        "attestations: write",
        "subject-path: artifacts/*.tar.gz",
    ] {
        assert!(
            code.contains(&needle),
            "release.yml no longer carries `{needle}`"
        );
    }
    assert!(
        code.iter()
            .any(|line| line.starts_with("- uses: actions/attest-build-provenance@")),
        "release.yml no longer attests the provenance of the tarballs"
    );

    // `draft: true` has to belong to the step that creates the release, which
    // is the last step of the file.
    let release_step = code
        .iter()
        .position(|line| line.starts_with("- uses: softprops/action-gh-release@"))
        .expect("release.yml creates the release with softprops/action-gh-release");
    assert!(
        code[release_step..].contains(&"draft: true"),
        "the step that creates the release no longer leaves a draft"
    );
    assert!(
        !code[release_step + 1..]
            .iter()
            .any(|line| line.starts_with("- ")),
        "a step now follows the one that creates the release; check that it cannot publish"
    );
}

/// And it is only evidence at all if editing release.yml runs it.
///
/// One occurrence on each side of the `pull_request:` key rather than two
/// anywhere in the file. The property is "one under `push` and one under
/// `pull_request`", and a count of two is also what moving both entries under
/// `push:` produces, which is precisely the failure the reasoning below
/// describes: a pull request that only the `push` filter named would run the
/// check after the merge that needed it. Exact counts rather than minima here,
/// because "one on each side" is the whole property.
#[test]
fn editing_release_yml_triggers_the_cross_workflow() {
    let path = repo_root().join(".github/workflows/cross.yml");
    let text = read_text(&path);

    let entry = "- .github/workflows/release.yml";
    let (under_push, under_pull_request) =
        text.split_once("\n  pull_request:").unwrap_or_else(|| {
            panic!(
                "{} carries no `pull_request:` trigger, so half the filter this test \
             is about does not exist",
                path.display()
            )
        });

    for (half, key, text) in [
        ("push", "push", under_push),
        ("pull request", "pull_request", under_pull_request),
    ] {
        assert_eq!(
            text.matches(entry).count(),
            1,
            "{} must list `.github/workflows/release.yml` in its `{key}` paths \
             filter exactly once, and the {half} half does not. Without it, the \
             one change this workflow most needs to react to, an edit to the \
             build step it mirrors, is the one change that runs nothing.",
            path.display()
        );
    }
}

// ---------------------------------------------------------------------------
// ci.yml and cross.yml give every push to main its own concurrency group
// ---------------------------------------------------------------------------

/// A push to main keys its concurrency group on the commit, not on the branch.
///
/// `release.yml` requires a successful `ci.yml` run for the exact commit a tag
/// names, and the release checklist waits for a green `cross.yml` run on that
/// commit as well. With one group for `refs/heads/main` and
/// `cancel-in-progress: false`, GitHub keeps one pending run per group, so a
/// newer push cancels the pending one and an earlier commit can end with only a
/// cancelled run. A pull request keeps one group per ref, because cancelling
/// its superseded run is the point there.
#[test]
fn every_push_to_main_keys_its_concurrency_group_on_the_commit() {
    for (file, prefix) in [("ci.yml", "group: ci-"), ("cross.yml", "group: cross-")] {
        let path = repo_root().join(".github/workflows").join(file);
        let text = read_text(&path);

        let group = text
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with(prefix))
            .unwrap_or_else(|| {
                panic!(
                    "{} carries no `{prefix}` line under `concurrency:`; has the \
                     block moved or been renamed?",
                    path.display()
                )
            });

        // The whole expression, because which operand follows the
        // `pull_request` test is the property: swapped, the same two names key
        // every push on the branch again.
        let expected = format!(
            "{prefix}${{{{ github.event_name == 'pull_request' && github.ref || github.sha }}}}"
        );
        assert_eq!(
            group,
            expected,
            "{} keys the concurrency group as {group:?}. A pull request must key \
             on its ref and a push on the commit. A release needs a successful run \
             of this workflow for the exact tagged commit, and with \
             `cancel-in-progress: false` a newer push cancels the one pending run \
             of its group, so a push keyed on the branch can leave a commit with \
             only a cancelled run",
            path.display()
        );
    }
}

// ---------------------------------------------------------------------------
// quinn-proto comes from the registry
// ---------------------------------------------------------------------------

/// The `[[package]]` block a lockfile records for `package`, its header line
/// excluded.
fn locked_package(lockfile: &Path, package: &str) -> String {
    let text = read_text(lockfile);
    let needle = format!("name = \"{package}\"\n");
    let start = text
        .find(&needle)
        .unwrap_or_else(|| panic!("{} records no package named {package}", lockfile.display()));
    text[start..]
        .lines()
        .take_while(|line| !line.starts_with("[[package]]"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// quinn-proto is an ordinary registry dependency in both workspaces.
///
/// Asserted: neither `Cargo.toml` nor `fuzz/Cargo.toml` carries a
/// `[patch.crates-io]` table, and the `quinn-proto` entry in each lockfile names
/// the crates.io registry as its source and carries a `checksum`. D60 pointed
/// that crate at a git revision from 2026-08-18 until 0.11.18 shipped every fix
/// it carried, and `fuzz/` held a second copy of the stanza because a patch does
/// not cross a workspace boundary.
///
/// Without this, a patch put back in either manifest costs two things and
/// announces neither. Dependabot proposes no bump for a git revision, so
/// quinn-proto stops being watched; and cargo-audit skips a lockfile entry whose
/// source is not the default registry, so an advisory filed against the version
/// that entry records is never reported. Both are absences, and a green CI run
/// looks exactly the same either way.
#[test]
fn quinn_proto_is_an_unpatched_registry_dependency() {
    const REGISTRY: &str = "source = \"registry+https://github.com/rust-lang/crates.io-index\"";

    let root = repo_root();

    for manifest in ["Cargo.toml", "fuzz/Cargo.toml"] {
        let path = root.join(manifest);
        assert!(
            !read_text(&path).contains("[patch.crates-io]"),
            "{} carries a [patch.crates-io] table. D60 removed the quinn-proto \
             patch when 0.11.18 shipped its fixes; a patch here puts the crate \
             back outside Dependabot and outside cargo-audit, and nothing else \
             in this tree says so.",
            path.display()
        );
    }

    for lockfile in ["Cargo.lock", "fuzz/Cargo.lock"] {
        let path = root.join(lockfile);
        let entry = locked_package(&path, "quinn-proto");

        assert!(
            entry.contains(REGISTRY),
            "{}: quinn-proto does not come from the crates.io registry, so \
             cargo-audit skips it:\n{entry}",
            path.display()
        );
        assert!(
            entry.lines().any(|line| line.starts_with("checksum = \"")),
            "{}: the quinn-proto entry has no checksum line, which a registry \
             entry always has:\n{entry}",
            path.display()
        );
    }
}

/// The quinn-proto source paths this crate's comments cite.
///
/// A path alone marks a line as a citation, because a citation often names the
/// crate on the line before. A path can also carry its line number after a
/// colon, as in `src/connection/mod.rs:42`, so the colon form is checked
/// against these paths rather than against the crate name.
const QUINN_PROTO_SOURCE_PATHS: [&str; 4] = [
    "src/congestion/",
    "src/connection/",
    "src/config/mod.rs",
    "src/endpoint.rs",
];

/// Paths and names that mark a line of `src/` as a citation of quinn-proto.
///
/// The crate name, then every source path above. A marker is matched against
/// the text of a line, not against the path of the file being scanned, so
/// `src/config/mod.rs` above is quinn-proto's file. This crate's own
/// `src/config/` files are not marked by their path, and their comments speak of
/// "line 7" in a TOML document.
const QUINN_PROTO_MARKERS: [&str; 5] = [
    "quinn-proto",
    QUINN_PROTO_SOURCE_PATHS[0],
    QUINN_PROTO_SOURCE_PATHS[1],
    QUINN_PROTO_SOURCE_PATHS[2],
    QUINN_PROTO_SOURCE_PATHS[3],
];

/// Whether `line` carries a line number.
///
/// Two spellings: `line N` or `lines N to M`, where the word starts at a word
/// boundary and is followed by a digit; and a source path followed by a colon
/// and digits, as in `src/connection/mod.rs:42`. For a directory prefix the
/// text before the colon is the file name and must contain no whitespace; a
/// full file path may be followed by the colon directly.
fn carries_a_line_number(line: &str) -> bool {
    let bytes = line.as_bytes();
    let word_form = line.match_indices("line").any(|(at, _)| {
        let starts_a_word = at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
        let rest = &line[at + "line".len()..];
        let rest = rest.trim_prefix('s');
        starts_a_word
            && rest
                .strip_prefix(' ')
                .is_some_and(|after| after.starts_with(|c: char| c.is_ascii_digit()))
    });

    let colon_form = QUINN_PROTO_SOURCE_PATHS.iter().any(|path| {
        line.match_indices(path).any(|(at, _)| {
            let rest = &line[at + path.len()..];
            rest.find(':').is_some_and(|colon| {
                let file_name = &rest[..colon];
                !file_name.chars().any(|c: char| c.is_whitespace())
                    && rest[colon + 1..]
                        .trim_start()
                        .starts_with(|c: char| c.is_ascii_digit())
            })
        })
    });

    word_form || colon_form
}

#[test]
fn carries_a_line_number_recognizes_each_spelling() {
    // The word form.
    assert!(carries_a_line_number("see line 42"));
    assert!(carries_a_line_number("see lines 42 to 44"));

    // The colon form, with a file name after a directory prefix and with a
    // full file path.
    assert!(carries_a_line_number(
        "quinn-proto src/connection/mod.rs:42"
    ));
    assert!(carries_a_line_number(
        "quinn-proto src/congestion/bbr.rs:42"
    ));
    assert!(carries_a_line_number("quinn-proto src/config/mod.rs:42"));
    assert!(carries_a_line_number("quinn-proto src/endpoint.rs:42"));
    assert!(carries_a_line_number(
        "quinn-proto src/connection/mod.rs: 42"
    ));

    // Not a line-number citation.
    assert!(!carries_a_line_number("quinn-proto src/connection/mod.rs"));
    assert!(!carries_a_line_number(
        "quinn-proto src/connection/mod.rs: see the function"
    ));
    assert!(!carries_a_line_number(
        "quinn-proto src/connection/ has no file name"
    ));
}

/// No comment in `src/` cites quinn-proto by line number.
///
/// Asserted: no line of any `.rs` file under `src/` both names quinn-proto or
/// one of the source paths in [`QUINN_PROTO_MARKERS`] and carries a line number,
/// in any of the spellings [`carries_a_line_number`] recognizes. A citation
/// names the file and the symbol instead: the function, method, constant or
/// field.
///
/// The check scans a three-line window, because a citation may be split over
/// two comment lines: for every line that carries a marker it looks ahead for a
/// line number, and for every line that carries a line number it looks back for
/// a marker. The window is deliberately small so an unrelated comment within a
/// few lines does not trip it; if a real source file has such an adjacent pair,
/// name the symbol instead and do not weaken the lint.
///
/// A line number goes stale on every quinn-proto bump and a symbol does not.
/// The lock file moved from 0.11.18 to 0.11.19 with every line-number citation
/// in `src/congestion.rs` and `src/quic.rs` left unchecked, and one of them,
/// the call to `Controller::on_ack` in `src/connection/mod.rs`, had already
/// moved by three lines. A stale line number still points at some line, so
/// nothing reports it. A renamed symbol is not found at all, which the reader
/// sees at once.
#[test]
fn no_source_comment_cites_quinn_proto_by_line_number() {
    let root = source_root();
    let mut offenders = Vec::new();

    for path in rust_files(&root) {
        let relative = path
            .strip_prefix(&root)
            .expect("under src/")
            .display()
            .to_string();
        let text = read_text(&path);
        let lines: Vec<&str> = text.lines().collect();
        let mut reported = BTreeSet::new();

        for (index, line) in lines.iter().enumerate() {
            let cites_quinn_proto = QUINN_PROTO_MARKERS
                .iter()
                .any(|marker| line.contains(marker));
            let carries_number = carries_a_line_number(line);

            // The fast path: both on the same line. The insert guards against a
            // pair already reported as a split from an earlier marker line.
            if cites_quinn_proto && carries_number {
                if reported.insert(index) {
                    offenders.push(format!("src/{relative}:{}: {}", index + 1, line.trim()));
                }
                continue;
            }

            // A split citation: the marker here, the number within three lines.
            if cites_quinn_proto {
                let end = (index + 4).min(lines.len());
                if let Some(number) = (index + 1..end).find(|at| carries_a_line_number(lines[*at]))
                {
                    if reported.insert(number) {
                        offenders.push(format!(
                            "src/{relative}:{}: {} (the line number is on line {}: {})",
                            index + 1,
                            line.trim(),
                            number + 1,
                            lines[number].trim()
                        ));
                    }
                    continue;
                }
            }

            // The same split seen from the other end: the number here, the
            // marker within the previous three lines.
            if carries_number {
                let start = index.saturating_sub(3);
                if let Some(marker) = (start..index)
                    .rev()
                    .find(|at| QUINN_PROTO_MARKERS.iter().any(|m| lines[*at].contains(m)))
                    .filter(|_| reported.insert(index))
                {
                    offenders.push(format!(
                        "src/{relative}:{}: {} (the marker is on line {}: {})",
                        index + 1,
                        line.trim(),
                        marker + 1,
                        lines[marker].trim()
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these lines cite quinn-proto by line number; name the file and the symbol \
         instead, because a line number goes stale on every quinn-proto bump:\n{}",
        offenders.join("\n")
    );
}

/// The `version` a `[[package]]` block records in a lockfile, by package name.
fn locked_version(lockfile: &Path, package: &str) -> String {
    let text = read_text(lockfile);
    let needle = format!("name = \"{package}\"\n");
    let start = text
        .find(&needle)
        .unwrap_or_else(|| panic!("{} records no package named {package}", lockfile.display()));
    let block = &text[start..];
    block
        .lines()
        .skip(1)
        .take_while(|line| !line.starts_with("[[package]]"))
        .find_map(|line| line.strip_prefix("version = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{} has no version line for {package}", lockfile.display()))
        .to_owned()
}

/// The `version` under `[package]` in a manifest.
fn package_version(manifest: &Path) -> String {
    let text = format!("\n{}", read_text(manifest));
    let package = text
        .split("\n[")
        .find(|section| section.starts_with("package]"))
        .unwrap_or_else(|| panic!("{} has no [package] table", manifest.display()));
    package
        .lines()
        .find_map(|line| line.strip_prefix("version = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{} has no version under [package]", manifest.display()))
        .to_owned()
}

/// `fuzz/Cargo.lock` names the root crate as a path dependency, version
/// included, and the `fuzz` job in ci.yml checks that workspace with
/// `--locked`. A release bump that touches only the root manifest therefore
/// fails CI on the fuzz job with "cannot update the lock file", which is what
/// happened at v0.8.0; this pins the two together where a bump is made.
#[test]
fn the_fuzz_lockfile_records_the_current_crate_version() {
    let root = repo_root();
    let manifest = package_version(&root.join("Cargo.toml"));
    let locked = locked_version(&root.join("fuzz/Cargo.lock"), "volto");

    assert_eq!(
        manifest, locked,
        "Cargo.toml says volto is {manifest} but fuzz/Cargo.lock records {locked}; run \
         `cargo update -p volto --manifest-path fuzz/Cargo.toml` alongside the version bump"
    );
}

// ---------------------------------------------------------------------------
// The unit allows the address families libc name resolution needs
// ---------------------------------------------------------------------------

/// The unit must let libc resolution open every address family it may need.
///
/// `RestrictAddressFamilies=AF_INET AF_INET6` covered the sockets volto opens
/// itself and nothing else. The own-address check is one of those: it binds an
/// AF_INET or AF_INET6 socket and needs neither extra family. In a glibc build
/// getaddrinfo resolves through NSS modules, and on a host whose nsswitch.conf
/// names `resolve` or `myhostname` those modules open AF_UNIX and AF_NETLINK
/// sockets. A denied family can fail the lookup and the tunnel with it. The
/// static musl release binary has no NSS, but one unit serves both builds. The
/// unit is the only place that restriction is expressed.
#[test]
fn the_unit_allows_the_address_families_name_resolution_needs() {
    let unit = read_text(&repo_root().join("script/masque.service"));
    let line = unit
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("RestrictAddressFamilies="))
        .expect("script/masque.service must restrict address families");

    let families: Vec<&str> = line
        .trim_start_matches("RestrictAddressFamilies=")
        .split_whitespace()
        .collect();
    for family in ["AF_INET", "AF_INET6", "AF_UNIX", "AF_NETLINK"] {
        assert!(
            families.contains(&family),
            "the unit must allow {family}, or libc name resolution can fail; it allows {families:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// One MSRV
// ---------------------------------------------------------------------------

/// The files that state the MSRV besides `Cargo.toml`, each with the number of
/// statements of it this test finds there today.
const MSRV_COPIES: [(&str, usize); 4] = [
    ("fuzz/Cargo.toml", 1),
    ("README.md", 3),
    ("docs/deployment.md", 1),
    (".github/workflows/ci.yml", 3),
];

/// What precedes a toolchain version where these files state the MSRV: the
/// manifest key, the workflow's pin, the prose, and the README badge.
const MSRV_MARKERS: [&str; 4] = ["rust-version = \"", "MSRV: \"", "Rust ", "rust-"];

/// Every version `text` states after one of [`MSRV_MARKERS`].
fn stated_versions(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for marker in MSRV_MARKERS {
        for (offset, _) in text.match_indices(marker) {
            let rest = &text[offset + marker.len()..];
            let version: String = rest
                .chars()
                .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
                .collect();
            let version = version.trim_end_matches('.');
            if version.starts_with(|ch: char| ch.is_ascii_digit()) {
                found.push(version.to_owned());
            }
        }
    }
    found
}

/// The manifests, the MSRV job and the prose state the same MSRV as
/// `Cargo.toml`'s `rust-version`.
///
/// The `msrv` job in `ci.yml` compares its own pin with `Cargo.toml` and
/// nothing else, so the fuzz manifest and the prose are held here.
#[test]
fn every_copy_of_the_msrv_is_the_one_cargo_toml_declares() {
    let root = repo_root();
    let declared = stated_versions(&read_text(&root.join("Cargo.toml")));
    let [declared] = declared.as_slice() else {
        panic!("Cargo.toml must state exactly one rust-version, and states {declared:?}");
    };

    for (file, expected) in MSRV_COPIES {
        let stated = stated_versions(&read_text(&root.join(file)));
        assert!(
            stated.len() >= expected,
            "{file} states the MSRV {} time(s), and this test expects {expected}; \
             the reader is broken or a statement was removed: {stated:?}",
            stated.len()
        );
        let wrong: Vec<&String> = stated
            .iter()
            .filter(|version| *version != declared)
            .collect();
        assert!(
            wrong.is_empty(),
            "Cargo.toml declares rust-version {declared}, and {file} states {wrong:?}"
        );
    }
}
