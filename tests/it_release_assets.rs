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
//! * **`fuzz/Cargo.toml` pins the quinn-proto revision `Cargo.toml` pins.** The
//!   fuzz crate is its own workspace, so the root `[patch.crates-io]` does not
//!   reach it and the stanza is duplicated; a bump applied to one and not the
//!   other fuzzes a QUIC stack the server does not use.

#[path = "common/scripts.rs"]
mod scripts;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use scripts::{read_text, repo_root};

/// Every `script/…` path the release workflow copies into the tarball.
fn packaged_paths() -> BTreeSet<String> {
    let workflow = repo_root().join(".github/workflows/release.yml");
    let text = read_text(&workflow);

    // A `cp` invocation may be spread over several lines with trailing
    // backslashes; fold those back into one line before looking at it.
    let folded = text.replace("\\\n", " ");

    let mut packaged = BTreeSet::new();
    for line in folded.lines() {
        let line = line.trim();
        if !line.starts_with("cp ") {
            continue;
        }
        for token in line.split_whitespace() {
            let token = token.trim_matches(|c| c == '"' || c == '\'');
            // The destination is `dist/${name}/script/`; only sources count.
            if token.starts_with("script/") {
                packaged.insert(token.to_string());
            }
        }
    }

    assert!(
        !packaged.is_empty(),
        "no `cp script/… ` line was found in {} — has the packaging step moved?",
        workflow.display()
    );
    packaged
}

/// Every file that actually sits in `script/`.
fn assets_on_disk() -> BTreeSet<String> {
    let dir = repo_root().join("script");
    let mut assets = BTreeSet::new();
    for entry in fs::read_dir(&dir).expect("script/ must exist") {
        let entry = entry.expect("script/ must be readable");
        if entry.file_type().expect("a file type").is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_str().expect("asset names are UTF-8");
        assets.insert(format!("script/{name}"));
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
    let folded = read_text(&workflow).replace("\\\n", " ");

    let packages_docs = folded
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("cp "))
        .any(|line| line.split_whitespace().any(|token| token == "docs"));

    assert!(
        packages_docs,
        "{} no longer copies `docs` into the tarball, but script/deploy.sh and \
         script/install-selfsigned.sh still send the operator to \
         docs/configuration.md and docs/deployment.md when they refuse to install",
        workflow.display()
    );

    // The other half of that same sentence, which nothing checked: the copy is
    // only worth having while the scripts still point at those pages. Renaming
    // the directory in both scripts would leave the assertion above green.
    // Each page is asserted where the pointer actually is -- `deploy.sh` names
    // the configuration page when it refuses a config from the future,
    // `install-selfsigned.sh` names the deployment page when it refuses the
    // host it was run on -- so a check cannot pass on a mention somewhere else.
    for (script, page) in [
        ("script/deploy.sh", "docs/configuration.md"),
        ("script/install-selfsigned.sh", "docs/deployment.md"),
    ] {
        let path = repo_root().join(script);
        assert!(
            read_text(&path).contains(page),
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

/// The lines between the mirror markers in `.github/workflows/<name>`.
///
/// Markers rather than line numbers: the two blocks sit at different offsets in
/// files of different lengths, and an offset is wrong the first time either file
/// grows a line — silently, since a wrong offset still yields *some* text to
/// compare. The prose above each block differs on purpose and stays outside the
/// markers; only the step itself has to match.
fn mirrored_build_step(name: &str) -> String {
    let path = repo_root().join(".github/workflows").join(name);
    let text = read_text(&path);

    let mut block: Vec<&str> = Vec::new();
    let mut inside = false;
    let mut closed = false;

    for line in text.lines() {
        if line.contains(MIRROR_OPEN) {
            assert!(
                !inside && !closed,
                "{} opens the mirrored block more than once",
                path.display()
            );
            inside = true;
        } else if line.contains(MIRROR_CLOSE) {
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
        "{} carries no `{MIRROR_OPEN}` … `{MIRROR_CLOSE}` block — has the build \
         step moved, or were the markers dropped?",
        path.display()
    );
    assert!(
        !block.is_empty(),
        "the mirrored block in {} is empty",
        path.display()
    );

    block.join("\n")
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
// The two quinn-proto pins
// ---------------------------------------------------------------------------

/// The `rev` of the `quinn-proto` `[patch.crates-io]` entry in `manifest`.
fn quinn_proto_rev(manifest: &Path) -> String {
    let text = read_text(manifest);

    let entry = text
        .split_once("quinn-proto = {")
        .unwrap_or_else(|| {
            panic!(
                "{} carries no `quinn-proto = {{ … }}` patch entry — has the \
                 stanza been removed? If a quinn-proto 0.11.x release now ships \
                 the fixes, both manifests lose it together and this test goes \
                 with them.",
                manifest.display()
            )
        })
        .1;
    let entry = entry
        .split_once('}')
        .unwrap_or_else(|| panic!("{}: unterminated quinn-proto entry", manifest.display()))
        .0;

    let rev = entry
        .split_once("rev = \"")
        .unwrap_or_else(|| {
            panic!(
                "{}: the quinn-proto patch carries no `rev`: {entry}",
                manifest.display()
            )
        })
        .1;

    rev.split_once('"')
        .unwrap_or_else(|| panic!("{}: unterminated rev string", manifest.display()))
        .0
        .to_string()
}

/// The fuzz crate must fuzz the QUIC stack the server runs.
///
/// `fuzz/` is its own cargo workspace, which is how cargo-fuzz wants it, and a
/// `[patch.crates-io]` does not reach across that boundary — so the pin is
/// written twice and kept equal by a comment in each file asking for it. Moving
/// the rev in one place and not the other leaves the fuzz targets exercising a
/// quinn-proto nothing deploys: a finding nobody can reproduce, or one nobody
/// ever sees.
#[test]
fn the_fuzz_crate_pins_the_same_quinn_proto_revision() {
    let root = repo_root();
    let crate_rev = quinn_proto_rev(&root.join("Cargo.toml"));
    let fuzz_rev = quinn_proto_rev(&root.join("fuzz/Cargo.toml"));

    assert_eq!(
        crate_rev, fuzz_rev,
        "Cargo.toml pins quinn-proto at {crate_rev} and fuzz/Cargo.toml at \
         {fuzz_rev}. The two are separate workspaces, so the root's \
         [patch.crates-io] does not reach the fuzz crate and both revisions have \
         to move together; the reasoning and the exit condition live in Cargo.toml."
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
