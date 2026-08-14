//! The release deploy script must stay runnable and honest about its flags.
//!
//! `script/deploy.sh` downloads a release, verifies it and installs it — all of
//! which needs root, a Linux host and the network, none of which a test should
//! touch. What can rot silently and *is* checkable everywhere: the script no
//! longer parsing at all (a quoting error anywhere aborts `bash` before the
//! first case arm), the usage text losing the flags the docs point at, and the
//! argument parser accepting garbage. The privileged paths are covered by
//! shellcheck plus first-run review, the same deal as install-selfsigned.sh.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_deploy(args: &[&str]) -> std::process::Output {
    let script = repo_root().join("script/deploy.sh");
    Command::new("bash")
        .arg(&script)
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("the deploy script must be runnable")
}

/// `-h` must work and describe the flags the documentation relies on.
#[test]
fn the_script_documents_itself() {
    let output = run_deploy(&["-h"]);

    assert!(output.status.success());
    let usage = String::from_utf8_lossy(&output.stdout);
    for expected in ["--tag", "--enable-timer", "--sni", "Re-running is safe"] {
        assert!(
            usage.contains(expected),
            "usage must mention {expected}: {usage}"
        );
    }
}

/// Garbage flags must be rejected before anything privileged is attempted.
#[test]
fn unknown_options_are_rejected() {
    let output = run_deploy(&["--definitely-not-a-flag"]);

    assert!(!output.status.success(), "garbage flags must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown option: --definitely-not-a-flag"),
        "the error must name the offending flag: {stderr}"
    );
}

/// A tag that is not a tag must be caught before any download starts.
#[test]
fn a_malformed_tag_is_rejected_in_argument_form() {
    let output = run_deploy(&["--tag"]);

    assert!(!output.status.success(), "--tag without a value must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--tag needs a value"),
        "the error must say what is missing: {stderr}"
    );
}
