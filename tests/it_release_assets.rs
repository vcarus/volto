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
//! * **The release binary checks integer overflow in this crate.** Debug
//!   builds always do, so no other test notices when the release profile stops.
//! * **The fuzz workflow runs every target.** ci.yml only compiles them, so a
//!   target missing from fuzz.yml's matrix would compile and never run.
//! * **The release build compiles no rustls.** Every test build does, for the
//!   test clients, so no other test notices when the manifest puts it back.

#[path = "common/scripts.rs"]
mod scripts;

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

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
    let output = Command::new("git")
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

/// The `target:` list under `matrix:` in `.github/workflows/<name>`, in order.
fn matrix_targets(name: &str) -> Vec<String> {
    let path = repo_root().join(".github/workflows").join(name);
    let text = read_text(&path);
    let lines: Vec<&str> = text.lines().collect();

    let matrix = lines
        .iter()
        .position(|line| line.trim() == "matrix:")
        .unwrap_or_else(|| panic!("{} has no `matrix:`", path.display()));
    let target = lines[matrix + 1..]
        .iter()
        .position(|line| line.trim() == "target:")
        .map(|at| matrix + 1 + at)
        .unwrap_or_else(|| panic!("the matrix of {} has no `target:` list", path.display()));
    let targets: Vec<String> = lines[target + 1..]
        .iter()
        .map(|line| line.trim())
        .map_while(|line| line.strip_prefix("- "))
        .map(str::to_owned)
        .collect();

    assert!(
        targets.len() >= 2,
        "{} lists {targets:?} under `matrix.target`; the reader is broken, or a \
         target was dropped",
        path.display()
    );
    targets
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

    // The step is the same for every target, so it is evidence about a target
    // only while cross.yml builds that target too.
    let release_targets = matrix_targets("release.yml");
    let cross_targets = matrix_targets("cross.yml");
    assert_eq!(
        release_targets, cross_targets,
        "cross.yml builds {cross_targets:?} and release.yml builds \
         {release_targets:?}; a target only release.yml builds breaks at tag time"
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

/// The code lines of `job` in `.github/workflows/<name>`: comments dropped,
/// each trimmed, and a command spread over lines with trailing backslashes
/// folded into one.
fn job_code(name: &str, job: &str) -> Vec<String> {
    let path = repo_root().join(".github/workflows").join(name);
    let text = read_text(&path).replace("\\\n", " ");
    let lines: Vec<&str> = text.lines().collect();

    let header = format!("  {job}:");
    let start = lines
        .iter()
        .position(|line| *line == header)
        .unwrap_or_else(|| panic!("{} has no `{job}` job", path.display()));
    let end = lines[start + 1..]
        .iter()
        .position(|line| !line.trim().is_empty() && indentation(line) <= 2)
        .map_or(lines.len(), |end| start + 1 + end);

    lines[start + 1..end]
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

/// The release gate counts only a push run on `main` (R8-L1).
///
/// A `pull_request` run reports the pull request's head commit as its SHA, so
/// a query by commit alone also finds it. That run tested the merge with the
/// base rather than the commit, and it ran without the scrub secret. The query
/// asks GitHub for push runs on `main`, and the `jq` filter that counts green
/// runs checks the same two fields again, so neither half alone decides.
#[test]
fn the_release_gate_counts_only_a_push_run_on_main() {
    let code = job_code("release.yml", "ci-passed");

    let query = code
        .iter()
        .find(|line| line.contains("gh run list"))
        .expect("the `ci-passed` job of release.yml no longer runs `gh run list`");
    for flag in [
        "--commit \"${{ github.sha }}\"",
        "--workflow ci.yml",
        "--event push",
        "--branch main",
    ] {
        assert!(
            query.contains(flag),
            "the release gate's query no longer passes `{flag}`: {query}"
        );
    }

    let green = code
        .iter()
        .find(|line| line.contains("select(") && line.contains(".conclusion == \"success\""))
        .expect("the `ci-passed` job of release.yml no longer counts successful runs");
    for condition in [
        ".event == \"push\"",
        ".headBranch == \"main\"",
        ".headSha == $sha",
        ".status == \"completed\"",
    ] {
        assert!(
            green.contains(condition),
            "the release gate counts a run as green without `{condition}`: {green}"
        );
    }
}

/// The steps of the composite action in `.github/actions/<name>/action.yml`,
/// each as its lines.
fn composite_steps(name: &str) -> Vec<Vec<String>> {
    let path = repo_root()
        .join(".github/actions")
        .join(name)
        .join("action.yml");
    let text = read_text(&path);
    let lines: Vec<&str> = text.lines().collect();

    let start = lines
        .iter()
        .position(|line| line.trim() == "steps:")
        .unwrap_or_else(|| panic!("{} has no `steps:`", path.display()));
    let depth = lines[start + 1..]
        .iter()
        .find(|line| line.trim_start().starts_with("- "))
        .map(|line| indentation(line))
        .unwrap_or_else(|| panic!("the steps of {} are empty", path.display()));

    let mut steps: Vec<Vec<String>> = Vec::new();
    for line in &lines[start + 1..] {
        if line.trim().is_empty() {
            continue;
        }
        if indentation(line) < depth {
            break;
        }
        if indentation(line) == depth && line.trim_start().starts_with("- ") {
            steps.push(Vec::new());
        }
        if let Some(step) = steps.last_mut() {
            step.push(line.trim().to_owned());
        }
    }
    steps
}

/// The `uses:` reference of `step`, if it has one.
fn step_uses(step: &[String]) -> Option<&str> {
    step.iter().find_map(|line| {
        line.strip_prefix("- uses: ")
            .or_else(|| line.strip_prefix("uses: "))
    })
}

/// The cached packages are saved straight after apt wrote them (R8-L2).
///
/// A later job installs what the cache restores with `sudo dpkg -i`, with no
/// signature or hash check. `actions/cache` saves in its post step, at the end
/// of the job, so every step after the install (build scripts, `pip install`,
/// Go modules) could change the files that are saved. The split actions save
/// in the step right after the install, before the job runs anything else.
#[test]
fn the_cached_packages_are_saved_before_the_job_runs_anything_else() {
    let steps = composite_steps("cmake-libclang");

    assert!(
        !steps
            .iter()
            .filter_map(|step| step_uses(step))
            .any(|uses| uses.starts_with("actions/cache@")),
        "the cmake-libclang action uses the combined `actions/cache`, which saves \
         at the end of the job"
    );

    let position = |prefix: &str| {
        steps
            .iter()
            .position(|step| step_uses(step).is_some_and(|uses| uses.starts_with(prefix)))
            .unwrap_or_else(|| panic!("the cmake-libclang action has no `{prefix}` step"))
    };
    let restore = position("actions/cache/restore@");
    let save = position("actions/cache/save@");
    let install = steps
        .iter()
        .position(|step| step.iter().any(|line| line.contains("apt-get install")))
        .expect("the cmake-libclang action no longer runs `apt-get install`");

    assert!(
        restore < install,
        "the cmake-libclang action restores the cache after the install step"
    );
    assert_eq!(
        save,
        install + 1,
        "the cmake-libclang action must save the cache in the step right after \
         the install, so nothing but apt writes what is saved"
    );

    let pin = |at: usize| {
        step_uses(&steps[at])
            .and_then(|uses| uses.split_once('@'))
            .map(|(_, pin)| pin.to_owned())
            .unwrap_or_default()
    };
    assert_eq!(
        pin(restore),
        pin(save),
        "the restore and save halves of actions/cache are pinned to different commits"
    );
}

/// Where the Dockerfile that pins the build image of `target` lives.
fn cross_dockerfile(target: &str) -> String {
    format!(".github/cross/{target}.Dockerfile")
}

/// The release binaries are built in images pinned by digest (R8-L3).
///
/// Without `Cross.toml`, cross runs its default image for each target by tag,
/// and a tag can be moved. Each target's image is named by tag and digest in a
/// Dockerfile of its own, which Dependabot's `docker` entry watches, so an
/// update arrives as a pull request that runs cross.yml. The digest is not
/// checked here, only its form: a test that ran offline could not look it up.
#[test]
fn every_release_target_is_built_in_an_image_pinned_by_digest() {
    let root = repo_root();
    let cross_toml = read_text(&root.join("Cross.toml"));
    let cross_toml: toml::Table = cross_toml
        .parse()
        .unwrap_or_else(|error| panic!("Cross.toml does not parse: {error}"));

    for target in matrix_targets("release.yml") {
        let dockerfile = cross_dockerfile(&target);
        let table = cross_toml
            .get("target")
            .and_then(|targets| targets.get(&target))
            .and_then(|table| table.get("dockerfile"))
            .unwrap_or_else(|| {
                panic!(
                    "Cross.toml sets no `dockerfile` for {target}, so cross runs its image by tag"
                )
            });
        assert_eq!(
            table.get("file").and_then(toml::Value::as_str),
            Some(dockerfile.as_str()),
            "Cross.toml builds {target} from another Dockerfile than {dockerfile}"
        );
        assert_eq!(
            table.get("context").and_then(toml::Value::as_str),
            Some(".github/cross"),
            "Cross.toml sends another build context than .github/cross for {target}"
        );
        assert!(
            cross_toml
                .get("target")
                .and_then(|targets| targets.get(&target))
                .and_then(|table| table.get("image"))
                .is_none(),
            "Cross.toml sets an `image` for {target}, which Dependabot does not watch"
        );

        let text = read_text(&root.join(&dockerfile));
        let froms: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("FROM "))
            .collect();
        assert_eq!(
            froms.len(),
            1,
            "{dockerfile} carries {} `FROM` lines where one is expected",
            froms.len()
        );
        let image = froms[0].trim_start_matches("FROM ").trim();
        let (name, digest) = image
            .split_once("@sha256:")
            .unwrap_or_else(|| panic!("{dockerfile} names its image without a digest: {image}"));
        let prefix = format!("ghcr.io/cross-rs/{target}:");
        let tag = name.strip_prefix(&prefix).unwrap_or_else(|| {
            panic!("{dockerfile} builds from {name}, which is not cross's image for {target}")
        });
        assert!(
            !tag.is_empty() && tag.chars().all(|c| c.is_ascii_digit() || c == '.'),
            "{dockerfile} names the tag {tag:?}; Dependabot moves a version tag, not a \
             name like `main` or `latest`"
        );
        assert!(
            digest.len() == 64
                && digest
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "{dockerfile} carries a malformed digest: {digest}"
        );
    }

    let dependabot = read_text(&root.join(".github/dependabot.yml"));
    assert!(
        dependabot.contains("- package-ecosystem: docker\n    directory: \"/.github/cross\""),
        ".github/dependabot.yml does not watch /.github/cross, so the pinned images \
         would never be updated"
    );

    // An image bump changes only these two paths, so cross.yml has to run on
    // them to build the release targets in the new image.
    let cross_yml = read_text(&root.join(".github/workflows/cross.yml"));
    let (under_push, under_pull_request) = cross_yml
        .split_once("\n  pull_request:")
        .expect("cross.yml carries no `pull_request:` trigger");
    for entry in ["- Cross.toml", "- .github/cross/**"] {
        for (key, half) in [("push", under_push), ("pull_request", under_pull_request)] {
            assert_eq!(
                half.matches(entry).count(),
                1,
                "cross.yml must list `{entry}` once in its `{key}` paths filter"
            );
        }
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

/// Whether a line of TOML opens a `patch` table or sets a dotted `patch.` key,
/// in any of the spellings TOML allows: `[patch.crates-io]`,
/// `[patch.crates-io.<crate>]`, `[ patch."crates-io" ]`, `patch.crates-io.x = …`.
fn opens_a_patch_table(line: &str) -> bool {
    let bare: String = line
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
        .collect();
    bare.starts_with("[patch") || bare.starts_with("patch.")
}

/// quinn-proto is an ordinary registry dependency in both workspaces.
///
/// Asserted: no `patch` table, in any spelling [`opens_a_patch_table`] reads,
/// in `Cargo.toml`, `fuzz/Cargo.toml` or a cargo configuration file either
/// workspace reads; no lockfile entry in either workspace comes from git; and
/// the `quinn-proto` entry in each lockfile names the crates.io registry as its
/// source and carries a `checksum`. D60 pointed
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

    // Cargo reads `[patch]` from a configuration file as well as from a
    // manifest. The two manifests must exist; a configuration file is read when
    // it is there.
    let configs = [".cargo/config.toml", "fuzz/.cargo/config.toml"]
        .into_iter()
        .filter(|config| root.join(config).is_file());
    for file in ["Cargo.toml", "fuzz/Cargo.toml"].into_iter().chain(configs) {
        let path = root.join(file);
        let patches: Vec<String> = read_text(&path)
            .lines()
            .filter(|line| opens_a_patch_table(line))
            .map(str::to_owned)
            .collect();
        assert!(
            patches.is_empty(),
            "{} carries a patch table: {patches:?}. D60 removed the quinn-proto \
             patch when 0.11.18 shipped its fixes; a patch here puts a crate \
             outside Dependabot and outside cargo-audit, and nothing else in this \
             tree says so.",
            path.display()
        );
    }

    for lockfile in ["Cargo.lock", "fuzz/Cargo.lock"] {
        let path = root.join(lockfile);
        let from_git: Vec<String> = read_text(&path)
            .lines()
            .filter(|line| line.starts_with("source = \"git+"))
            .map(str::to_owned)
            .collect();
        assert!(
            from_git.is_empty(),
            "{} takes crates from git, which cargo-audit does not check and \
             Dependabot does not bump: {from_git:?}",
            path.display()
        );

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

/// The value of `NIGHTLY:` under `env:` in `.github/workflows/<name>`.
fn workflow_nightly(name: &str) -> String {
    let path = repo_root().join(".github/workflows").join(name);
    read_text(&path)
        .lines()
        .find_map(|line| line.trim().strip_prefix("NIGHTLY: "))
        .unwrap_or_else(|| panic!("{} sets no `NIGHTLY:`", path.display()))
        .to_owned()
}

/// fuzz.yml runs the targets its matrix lists, so a target missing from the
/// list is compiled by ci.yml and never run. The list is held equal to the
/// files in `fuzz/fuzz_targets/` and to the `[[bin]]` names in
/// `fuzz/Cargo.toml`, which is where `cargo fuzz run <name>` looks.
#[test]
fn the_fuzz_workflow_runs_every_target() {
    let root = repo_root();

    let listed: BTreeSet<String> = matrix_targets("fuzz.yml").into_iter().collect();

    let files: BTreeSet<String> = fs::read_dir(root.join("fuzz/fuzz_targets"))
        .expect("fuzz/fuzz_targets is a directory")
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .map(|path| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .expect("a UTF-8 file name")
                .to_owned()
        })
        .collect();

    let manifest: toml::Table = read_text(&root.join("fuzz/Cargo.toml"))
        .parse()
        .expect("fuzz/Cargo.toml is TOML");
    let bins: BTreeSet<String> = manifest["bin"]
        .as_array()
        .expect("fuzz/Cargo.toml has `[[bin]]` tables")
        .iter()
        .map(|bin| bin["name"].as_str().expect("a bin has a name").to_owned())
        .collect();

    assert!(
        files.len() >= 11,
        "fuzz/fuzz_targets holds {files:?}; the reader is broken, or targets were removed"
    );
    assert_eq!(
        listed, files,
        "the matrix of .github/workflows/fuzz.yml and the files in fuzz/fuzz_targets differ"
    );
    assert_eq!(
        bins, files,
        "the `[[bin]]` names in fuzz/Cargo.toml and the files in fuzz/fuzz_targets differ"
    );
}

/// `fuzz/withhold-input.awk` is what keeps a failing input of the
/// pre-authentication targets out of a public log. It is run here over the
/// output of a failed run, with the input in every form the tools print it:
/// the oracle's panic message, libFuzzer's hex, text and base64 lines, and
/// cargo-fuzz's `Debug` line after the `artifact_prefix=` line. The text form
/// begins with bytes the input chose, here ones that look like a line the
/// filter prints. The panic location and both stack traces must come through.
#[test]
fn the_fuzz_filter_withholds_the_failing_input_in_every_form() {
    let root = repo_root();
    let workflow = read_text(&root.join(".github/workflows/fuzz.yml"));
    assert!(
        workflow.contains("run 2>&1 | awk -f fuzz/withhold-input.awk ;;"),
        "fuzz.yml pipes the withheld targets through the filter this test runs"
    );
    assert!(
        workflow.contains("export RUST_BACKTRACE=1"),
        "the trace is all the filter keeps of a panic, so the run asks for one"
    );

    // Every line that carries input holds one of these.
    let secrets = ["SECRET", "0x53,0x45", "U0VDUkVU", "[83, 69, 67"];
    let transcript = "\x20  Compiling volto-fuzz v0.0.0 (/work/fuzz)
    Finished `release` profile [optimized + debuginfo] target(s) in 1m 02s
     Running `fuzz/target/x86_64-unknown-linux-gnu/release/hold -artifact_prefix=/work/fuzz/artifacts/hold/`
INFO: Seed: 1234
#2\tINITED cov: 10 ft: 11 corp: 1/1b exec/s: 0 rss: 40Mb
#512\tNEW    cov: 12 ft: 13 corp: 2/9b lim: 4 exec/s: 0 rss: 41Mb L: 8/8 MS: 1 InsertByte-

thread '<unnamed>' (4242) panicked at fuzz_targets/hold.rs:149:5:
the released flight names SECRET
stack backtrace:
   0: __rustc::rust_begin_unwind
             at /rustc/abc/library/std/src/panicking.rs:697:5
   1: hold::_::__libfuzzer_sys_run
             at ./fuzz_targets/hold.rs:149:5
==4242== ERROR: libFuzzer: deadly signal
    #0 0x55d0c0a1b2c3 in __sanitizer_print_stack_trace (/work/hold+0x1b2c3)
    #1 0x55d0c0a2b2c3 in fuzzer::PrintStackTrace() (/work/hold+0x2b2c3)
NOTE: libFuzzer has rudimentary signal handlers.
SUMMARY: libFuzzer: deadly signal
MS: 2 ChangeByte-InsertByte-; base unit: adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
0x53,0x45,0x43,0x52,0x45,0x54,
INFO: SECRET
artifact_prefix='/work/fuzz/artifacts/hold/'; Test unit written to /work/fuzz/artifacts/hold/crash-1
Base64: U0VDUkVU

────────────────────────────────────────

Failing input:

\tfuzz/artifacts/hold/crash-1

Output of `std::fmt::Debug`:

\t[83, 69, 67, 82, 69, 84]

Reproduce with:

\tcargo fuzz run hold fuzz/artifacts/hold/crash-1
";

    let mut awk = Command::new("awk")
        .arg("-f")
        .arg(root.join("fuzz/withhold-input.awk"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("awk is installed");
    awk.stdin
        .take()
        .expect("a piped stdin")
        .write_all(transcript.as_bytes())
        .expect("write the transcript");
    let output = awk.wait_with_output().expect("awk ran");
    assert!(output.status.success(), "awk failed");
    let printed = String::from_utf8(output.stdout).expect("UTF-8 output");

    for secret in secrets {
        assert!(
            transcript.contains(secret),
            "the transcript holds {secret:?}"
        );
        assert!(
            !printed.contains(secret),
            "the filter printed the input as {secret:?}:\n{printed}"
        );
    }
    for kept in [
        "thread '<unnamed>' (4242) panicked at fuzz_targets/hold.rs:149:5:",
        "             at ./fuzz_targets/hold.rs:149:5",
        "   1: hold::_::__libfuzzer_sys_run",
        "==4242== ERROR: libFuzzer: deadly signal",
        "    #1 0x55d0c0a2b2c3 in fuzzer::PrintStackTrace() (/work/hold+0x2b2c3)",
        "SUMMARY: libFuzzer: deadly signal",
        "#512\tNEW    cov: 12",
    ] {
        assert!(
            printed.contains(kept),
            "the filter dropped {kept:?}:\n{printed}"
        );
    }
    assert!(
        printed.ends_with(
            "(the failing input is withheld, with every line after this one)\n\
             (2 other lines withheld)\n"
        ),
        "{printed}"
    );
}

/// Both workflows that need nightly name a dated one, and each says the two
/// move together.
#[test]
fn the_nightly_workflows_name_the_same_toolchain() {
    let asan = workflow_nightly("asan.yml");
    let fuzz = workflow_nightly("fuzz.yml");

    assert!(
        asan.starts_with("nightly-20"),
        "asan.yml's NIGHTLY is {asan:?}; the reader is broken, or the date was dropped"
    );
    assert_eq!(
        asan, fuzz,
        "asan.yml builds with {asan} and fuzz.yml with {fuzz}"
    );
}

// ---------------------------------------------------------------------------
// The release build compiles one TLS implementation
// ---------------------------------------------------------------------------

/// The dependency tables of `manifest` that a release build compiles:
/// `[dependencies]`, `[build-dependencies]` and their `[target.<cfg>.…]`
/// forms, each with the name it is reported under.
fn compiled_dependency_tables(manifest: &toml::Table) -> Vec<(String, &toml::Table)> {
    const KINDS: [&str; 2] = ["dependencies", "build-dependencies"];
    let mut tables: Vec<(String, &toml::Table)> = KINDS
        .into_iter()
        .filter_map(|kind| {
            let table = manifest.get(kind)?.as_table()?;
            Some((kind.to_owned(), table))
        })
        .collect();
    let targets = manifest.get("target").and_then(toml::Value::as_table);
    for (cfg, target) in targets.into_iter().flatten() {
        for kind in KINDS {
            if let Some(table) = target.get(kind).and_then(toml::Value::as_table) {
                tables.push((format!("target.{cfg}.{kind}"), table));
            }
        }
    }
    tables
}

/// The release binary is built from one TLS implementation, AWS-LC's libssl
/// through volto's own provider in `src/tls/awslc/` (D115). rustls is a
/// dev-dependency, for the test clients alone.
///
/// Every test build compiles rustls, so no other test notices when a release
/// build starts to compile it again. Three manifest changes would do that: an
/// entry for rustls in a table a release build compiles, under its own name or
/// renamed; a quinn or quinn-proto entry that turns on a rustls feature, which
/// is any `rustls-*` feature, `platform-verifier`, or quinn's default features;
/// and a package feature that names rustls. This reads the root manifest for
/// each of the three. A rustls reached through some other new dependency is not
/// seen here; `cargo tree -e normal -i rustls --target all` prints nothing
/// while none is.
#[test]
fn the_release_build_compiles_no_rustls() {
    let path = repo_root().join("Cargo.toml");
    let manifest: toml::Table = read_text(&path)
        .parse()
        .unwrap_or_else(|error| panic!("{} does not parse: {error}", path.display()));
    let names_rustls =
        |feature: &str| feature.contains("rustls") || feature.contains("platform-verifier");

    let tables = compiled_dependency_tables(&manifest);
    assert!(
        tables.iter().any(|(name, table)| name == "dependencies"
            && table.contains_key("quinn")
            && table.contains_key("quinn-proto")),
        "the reader found no [dependencies] table with quinn and quinn-proto in {}",
        path.display()
    );
    for (table_name, table) in tables {
        for (name, entry) in table {
            let package = entry
                .get("package")
                .and_then(toml::Value::as_str)
                .unwrap_or(name);
            assert_ne!(
                package, "rustls",
                "[{table_name}] names rustls (as `{name}`), so a release build compiles a \
                 second TLS implementation; the tests take rustls from [dev-dependencies]"
            );
            if !matches!(package, "quinn" | "quinn-proto") {
                continue;
            }
            assert_eq!(
                entry.get("default-features").and_then(toml::Value::as_bool),
                Some(false),
                "[{table_name}] {name} keeps its default features, which turn on rustls"
            );
            let rustls_features: Vec<&str> = entry
                .get("features")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(toml::Value::as_str)
                .filter(|feature| names_rustls(feature))
                .collect();
            assert!(
                rustls_features.is_empty(),
                "[{table_name}] {name} turns on {rustls_features:?}, so a release build \
                 compiles rustls; the tests turn on quinn's rustls provider from \
                 [dev-dependencies]"
            );
        }
    }

    let features = manifest.get("features").and_then(toml::Value::as_table);
    for (feature, enables) in features.into_iter().flatten() {
        let rustls: Vec<&str> = enables
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .filter(|enabled| names_rustls(enabled))
            .collect();
        assert!(
            rustls.is_empty(),
            "the package feature `{feature}` turns on {rustls:?}, so a build with it \
             compiles rustls"
        );
    }
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

/// The directives `script/masque.service` sets, one `Key=value` per entry, from
/// the lines that are not comments.
fn unit_directives() -> Vec<String> {
    read_text(&repo_root().join("script/masque.service"))
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with('['))
        .map(str::to_owned)
        .collect()
}

/// The unit carries the hardening the 2026-11-21 review judged safe for what
/// the binary needs, and not the directive that did nothing (R8-L11).
///
/// What the binary needs: bind one UDP port, possibly below 1024, through
/// `CAP_NET_BIND_SERVICE`; read `/etc/volto`; open TCP and UDP sockets to
/// anywhere and resolve names through the system resolver; take `SIGHUP` as a
/// reload, which `RestartForceExitStatus=SIGHUP` keeps from ending the service
/// in its first milliseconds; write a keylog file only when a drop-in grants a
/// path. `Type=notify` makes a start done only when the server says its
/// listener is bound, and `TimeoutStartSec=15` fails a start that never says
/// so; `NotifyAccess=` stays unset because `Type=notify` already makes it
/// `main`. `UMask=0077` keeps any file it creates to its user, `ProcSubset=pid` hides
/// the `/proc` entries only `--diagnostics` reads, and `RemoveIPC=yes` removes
/// IPC objects it never makes. `ReadOnlyPaths=/etc/volto` added nothing under
/// `ProtectSystem=strict`. `SystemCallFilter=~@resources` removes the calls that
/// set scheduling, affinity, memory policy and limits, which a trace of the
/// release binary on systemd 255 and 259 showed it never makes; the
/// `RLIMIT_NOFILE` read is `prlimit64`, which systemd keeps in `@default`.
/// `SystemCallErrorNumber=EPERM` makes a refused call fail rather than kill the
/// process. The directives that would break the binary (`PrivateUsers=`,
/// `PrivateNetwork=`, `IPAddressDeny=`, `SocketBindDeny=`) stay out.
#[test]
fn the_unit_carries_the_safe_hardening_and_nothing_that_breaks_the_binary() {
    let directives = unit_directives();
    for expected in [
        "Type=notify",
        "TimeoutStartSec=15",
        "UMask=0077",
        "ProcSubset=pid",
        "RemoveIPC=yes",
        "ProtectSystem=strict",
        "ProtectProc=invisible",
        "User=volto",
        "Group=volto",
        "AmbientCapabilities=CAP_NET_BIND_SERVICE",
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
        "RestartForceExitStatus=SIGHUP",
        "ExecReload=/bin/kill -HUP $MAINPID",
        "SystemCallFilter=@system-service",
        "SystemCallFilter=~@resources",
        "SystemCallErrorNumber=EPERM",
    ] {
        assert!(
            directives.iter().any(|line| line == expected),
            "script/masque.service must set {expected}: {directives:#?}"
        );
    }
    for absent in [
        "ReadOnlyPaths=",
        "ReadWritePaths=",
        "DynamicUser=",
        "PrivateUsers=",
        "PrivateNetwork=",
        "IPAddressDeny=",
        "SocketBindDeny=",
        "Type=simple",
        "Type=exec",
        // `Type=notify` makes it `main`; `all` would let any process of the
        // unit report readiness for the server.
        "NotifyAccess=",
        // It changes how `systemctl reload` reaches the server, and the
        // server implements none of it (D124).
        "Type=notify-reload",
    ] {
        assert!(
            !directives.iter().any(|line| line.starts_with(absent)),
            "script/masque.service must not set {absent}: {directives:#?}"
        );
    }

    // systemd takes the default action from the first `SystemCallFilter=`
    // line. If that line is a `~` list, every call it does not name is
    // allowed, and the `@system-service` line after it only removes names from
    // the deny list: the filter is gone.
    let filters: Vec<&String> = directives
        .iter()
        .filter(|line| line.starts_with("SystemCallFilter="))
        .collect();
    assert_eq!(
        filters.first().map(|line| line.as_str()),
        Some("SystemCallFilter=@system-service"),
        "the first SystemCallFilter= line must be the allow list, or the unit allows \
         every call: {filters:?}"
    );
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

#[test]
fn opens_a_patch_table_reads_every_spelling() {
    for line in [
        "[patch.crates-io]",
        "[patch.crates-io.rustls]",
        "[ patch.\"crates-io\" ]",
        "[patch.'https://github.com/example/crate']",
        "patch.crates-io.rustls = { git = \"https://example.com/rustls\" }",
    ] {
        assert!(
            opens_a_patch_table(line),
            "a patch table was missed: {line}"
        );
    }
    for line in [
        "# [patch.crates-io] was removed by D60",
        "[profile.release]",
        "dispatch = 1",
    ] {
        assert!(!opens_a_patch_table(line), "not a patch table: {line}");
    }
}

/// The value `key` is set to inside the TOML table `header` of `manifest`, with
/// whitespace and quotes removed, or `None` when the table or the key is absent.
///
/// The table runs from its header line to the next line that opens a table.
/// Comment lines are skipped, so a commented-out setting does not count.
fn table_setting(manifest: &str, header: &str, key: &str) -> Option<String> {
    let bare = |line: &str| -> String {
        line.chars()
            .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
            .collect()
    };
    let mut lines = manifest.lines().map(bare);
    lines.find(|line| *line == header)?;
    lines
        .take_while(|line| !line.starts_with('['))
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            line.strip_prefix(key)?
                .strip_prefix('=')
                .map(|value| value.split('#').next().unwrap_or_default().to_owned())
        })
}

/// The released binary panics on integer overflow in volto's own code.
///
/// Debug builds check overflow already, so every test run passes whether or not
/// the release profile does; only this assertion notices the setting going
/// away. Without it, an unsigned subtraction that underflows in a release build
/// wraps silently, and a bound computed from it turns into a very large number
/// that lets its check pass. The reasoning is in the comment above the table in
/// `Cargo.toml`.
#[test]
fn the_release_profile_checks_overflow_in_this_crate() {
    let manifest = read_text(&repo_root().join("Cargo.toml"));
    assert_eq!(
        table_setting(
            &manifest,
            "[profile.release.package.volto]",
            "overflow-checks"
        )
        .as_deref(),
        Some("true"),
        "Cargo.toml no longer sets `overflow-checks = true` under \
         `[profile.release.package.volto]`, so an integer overflow in a release \
         build wraps silently instead of panicking"
    );
}

/// The package table that turns overflow checks on also says `strip = true`.
///
/// With a `[profile.release.package.volto]` table, cargo passes volto's own
/// units `-C strip=debuginfo` unless the table repeats the setting, and the
/// binary is linked as one of those units, so it keeps its symbol table. No
/// test run links a release binary; cross.yml's strip step is the only other
/// thing that notices, and only on a pull request that touches `Cargo.toml`.
#[test]
fn the_package_table_repeats_the_strip_setting() {
    let manifest = read_text(&repo_root().join("Cargo.toml"));
    for table in ["[profile.release]", "[profile.release.package.volto]"] {
        assert_eq!(
            table_setting(&manifest, table, "strip").as_deref(),
            Some("true"),
            "Cargo.toml no longer sets `strip = true` under `{table}`, so the \
             released binary would carry its symbol table"
        );
    }
}

#[test]
fn table_setting_reads_only_the_named_table() {
    let manifest = "\
[profile.release]
overflow-checks = false

[ profile.release.package.\"volto\" ]
# overflow-checks = false
overflow-checks = true # checked

[profile.release.package.other]
lto = true
";
    let read = |header, key| table_setting(manifest, header, key);
    assert_eq!(
        read("[profile.release.package.volto]", "overflow-checks").as_deref(),
        Some("true")
    );
    assert_eq!(
        read("[profile.release]", "overflow-checks").as_deref(),
        Some("false")
    );
    assert_eq!(
        read("[profile.release.package.other]", "overflow-checks"),
        None
    );
    assert_eq!(read("[profile.bench]", "overflow-checks"), None);
}

/// Whether `code` holds the keyword `unsafe` rather than `unsafe_code`.
fn has_unsafe_keyword(code: &str) -> bool {
    code.match_indices("unsafe").any(|(at, _)| {
        let before = code[..at].chars().next_back();
        let after = code[at + "unsafe".len()..].chars().next();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
            && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// `unsafe` in `src/` is confined to the libssl binding, and each use of it
/// says why it is sound.
///
/// `src/lib.rs` carries `#![deny(unsafe_code)]` rather than `forbid`, because
/// the server's TLS (D115) is a binding to AWS-LC's libssl that needs `unsafe`,
/// and `forbid` cannot be lifted for one module. What `forbid` gave by itself is
/// asserted here instead: `main.rs` still forbids it, `lib.rs` denies it, the
/// one `allow(unsafe_code)` in `src/` is the one on `mod awslc` in `src/tls.rs`,
/// and no file outside `src/tls/awslc/` writes the keyword. Inside that
/// directory every `unsafe` block and `unsafe impl` has a `SAFETY:` comment
/// above it, among the lines of the same statement, and every `unsafe fn` a
/// `# Safety` section in its doc comment.
#[test]
fn unsafe_code_in_src_is_confined_to_the_libssl_binding() {
    let root = source_root();
    let mut allows = Vec::new();
    let mut outside = Vec::new();
    let mut unexplained = Vec::new();
    for path in rust_files(&root) {
        let relative = path
            .strip_prefix(&root)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        let text = read_text(&path);
        let raw: Vec<&str> = text.lines().collect();
        let code = scripts::code_lines(&text);
        let in_binding = relative.starts_with("tls/awslc/");
        for (index, line) in code.iter().enumerate() {
            let Some(line) = line else { continue };
            if line.contains("allow(unsafe_code)") {
                allows.push(format!("src/{relative}"));
            }
            if !has_unsafe_keyword(line) {
                continue;
            }
            if !in_binding {
                outside.push(format!("src/{relative}:{}: {}", index + 1, line.trim()));
                continue;
            }
            let explained = if line.contains("unsafe fn") || line.contains("unsafe extern") {
                raw[..index]
                    .iter()
                    .rev()
                    .take_while(|l| {
                        l.trim_start().starts_with("///") || l.trim_start().starts_with("#[")
                    })
                    .any(|l| l.contains("# Safety"))
            } else {
                // Up through the lines of the same statement to the comment
                // above it: stop at a line whose code ends one.
                let mut found = false;
                for back in (0..index).rev().take(20) {
                    if raw[back].trim_start().starts_with("//") {
                        if raw[back].contains("SAFETY") {
                            found = true;
                            break;
                        }
                        continue;
                    }
                    match &code[back] {
                        Some(previous)
                            if previous.trim_end().ends_with(';')
                                || previous.trim_end().ends_with('}') =>
                        {
                            break;
                        }
                        _ => {}
                    }
                }
                found
            };
            if !explained {
                unexplained.push(format!("src/{relative}:{}: {}", index + 1, line.trim()));
            }
        }
    }
    assert_eq!(
        allows,
        ["src/tls.rs"],
        "allow(unsafe_code) outside the one argued place"
    );
    assert!(
        outside.is_empty(),
        "`unsafe` outside src/tls/awslc/:\n{}",
        outside.join("\n")
    );
    assert!(
        unexplained.is_empty(),
        "`unsafe` without a SAFETY comment or a # Safety section:\n{}",
        unexplained.join("\n")
    );

    let code_of = |file: &str| {
        scripts::code_lines(&read_text(&root.join(file)))
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
    };
    assert!(
        code_of("main.rs")
            .iter()
            .any(|l| l.trim() == "#![forbid(unsafe_code)]")
    );
    assert!(
        code_of("lib.rs")
            .iter()
            .any(|l| l.trim() == "#![deny(unsafe_code)]")
    );
}

#[test]
fn has_unsafe_keyword_tells_the_keyword_from_the_lint() {
    assert!(has_unsafe_keyword("let x = unsafe { f() };"));
    assert!(has_unsafe_keyword("unsafe impl Send for X {}"));
    assert!(!has_unsafe_keyword("#![deny(unsafe_code)]"));
    assert!(!has_unsafe_keyword("not_unsafe()"));
}
