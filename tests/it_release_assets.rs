//! Everything in `script/` must be inside the release tarball.
//!
//! The four deployment assets are siblings on purpose: `install-selfsigned.sh`
//! resolves the other two through `SCRIPT_DIR`, and `deploy.sh` runs the
//! bundled installer straight out of an unpacked release. `release.yml` copies
//! them in by name, so a new asset that nobody adds to that list — or a renamed
//! one nobody updates — produces a tarball that looks fine and fails on the
//! host: the first-install branch cannot find the installer, or the update
//! branch cannot find the unit file. The symptom would surface a release later,
//! in one line of `journalctl -u volto-deploy`. This turns it into a test
//! failure instead.

#[path = "common/scripts.rs"]
mod scripts;

use std::collections::BTreeSet;
use std::fs;

use scripts::repo_root;

/// Every `script/…` path the release workflow copies into the tarball.
fn packaged_paths() -> BTreeSet<String> {
    let workflow = repo_root().join(".github/workflows/release.yml");
    let text = fs::read_to_string(&workflow)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", workflow.display()));

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
