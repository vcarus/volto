//! TLS identity and the server's TLS.
//!
//! The handshake runs on AWS-LC's libssl through volto's own quinn crypto
//! provider in `tls/awslc/` (D115), which also carries the ECH key. This module
//! holds what the provider and the configuration checks share: reading the
//! certificate chain and the private key, and judging which names the
//! certificate covers. Those use rustls's PEM parser and its certificate name
//! check, which are not the server's TLS but are the same code a rustls client
//! applies.

use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use zeroize::{Zeroize as _, Zeroizing};

// The one module of the crate allowed `unsafe` code: the binding to libssl.
// `crate` says why the rest of the crate denies it.
#[allow(unsafe_code)]
mod awslc;

pub(crate) use awslc::server_initial_keys;
pub use awslc::{
    EchKey, PROBE_HELD_LIMIT, ProbeSession, ServerConfig, probe_server_config, server_config,
};

/// What an operator is told when the two configured files do not pair up.
///
/// The wording the rustls server used, kept so that a reload log reads the
/// same as before the provider changed.
pub(crate) const UNUSABLE_PAIR: &str =
    "server.cert and server.key do not form a usable certificate/key pair";

/// Refuses a leaf certificate webpki cannot parse, as the rustls server did.
///
/// AWS-LC's `d2i_X509` reads certificates webpki refuses, an X.509
/// version 1 certificate for one, so without this such a certificate would
/// bind, [`names_not_covered`] would report nothing for it, and a client that
/// verifies it would refuse every handshake. Called where the provider is
/// built and where the configuration is checked, so startup, a reload and
/// `--check-config` refuse the same leaf with the same words.
pub(crate) fn check_leaf(leaf: &CertificateDer<'_>) -> Result<()> {
    rustls::server::ParsedCertificate::try_from(leaf)
        .map(drop)
        .context(UNUSABLE_PAIR)
}

/// The names in `names` that the leaf certificate `cert` is not valid for.
///
/// Judged the way a client judges it, with rustls's own name check over the
/// certificate's Subject Alternative Names, so what is reported here is what a
/// client verifying the certificate by that name would refuse. A certificate
/// webpki cannot parse reports nothing: [`check_leaf`] refuses that one at
/// startup and on reload, with the reason, and a second complaint would only
/// bury it.
pub(crate) fn names_not_covered(cert: &CertificateDer<'_>, names: &[String]) -> Vec<String> {
    let Ok(parsed) = rustls::server::ParsedCertificate::try_from(cert) else {
        return Vec::new();
    };
    names
        .iter()
        .filter(|name| {
            // The gate ignores a trailing root dot (`Names::new`); the name
            // check does not take one. The same helper, so the two cannot judge
            // the same string differently; see `names::root_relative`.
            let bare = crate::names::root_relative(name);
            !rustls::pki_types::ServerName::try_from(bare).is_ok_and(|server_name| {
                rustls::client::verify_server_name(&parsed, &server_name).is_ok()
            })
        })
        .cloned()
        .collect()
}

/// Loads a PEM certificate chain, leaf first.
pub(crate) fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open server.cert = {}", path.display()))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(file)
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("failed to parse server.cert = {}", path.display()))?;

    if certs.is_empty() {
        bail!(
            "server.cert = {} contains no CERTIFICATE block",
            path.display()
        );
    }

    Ok(certs)
}

/// Loads the first private key in a PEM file (PKCS#8, PKCS#1 or SEC1), as DER.
///
/// The file's text and the parsed key are cleared before they are freed. One
/// copy is not: the PEM parser's base64 buffer, which rustls-pki-types drops
/// without clearing and gives no way to reach.
fn load_key(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let text = Zeroizing::new(
        std::fs::read(path)
            .with_context(|| format!("failed to open server.key = {}", path.display()))?,
    );
    // `PrivateKeyDer` accepts PKCS#8, PKCS#1 and SEC1 sections and skips any
    // other PEM object on the way, so a bundle file works too.
    match PrivateKeyDer::from_pem_slice(&text) {
        Ok(mut key) => {
            let der = Zeroizing::new(key.secret_der().to_vec());
            // `PrivateKeyDer` implements `Zeroize` but not `Drop`.
            key.zeroize();
            Ok(der)
        }
        Err(pem::Error::NoItemsFound) => bail!(
            "server.key = {} contains no PRIVATE KEY block",
            path.display()
        ),
        Err(error) => {
            Err(error).with_context(|| format!("failed to parse server.key = {}", path.display()))
        }
    }
}

/// Fills `out` from AWS-LC's random number generator.
pub fn random_bytes(out: &mut [u8]) -> Result<()> {
    aws_lc_rs::rand::fill(out).map_err(|_| anyhow::anyhow!("the random number generator failed"))
}

/// Writes `key` to a new file at `path`, readable by its owner only.
///
/// Refuses a path that exists: the file is a credential a client was given, and
/// overwriting it would lock every such client out without a word.
pub fn write_new_key_file(path: &Path, key: &EchKey) -> Result<()> {
    use std::io::Write as _;
    write_new_file(path, |file| file.write_all(key.to_pem().as_bytes()))
}

/// Creates `path`, which must not exist yet, readable by its owner only, lets
/// `fill` write it, and syncs it to disk.
///
/// When `fill` or the sync fails (a full disk, say), the file is removed
/// again. It is ours to remove, because `create_new` made it a moment
/// earlier, and leaving the partial file would make the next attempt at the
/// same path fail, since an existing file is never replaced.
fn write_new_file(path: &Path, fill: impl FnOnce(&mut File) -> std::io::Result<()>) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| {
            format!(
                "failed to create {} (an existing file is never replaced)",
                path.display()
            )
        })?;
    let Err(error) = fill(&mut file).and_then(|()| file.sync_all()) else {
        return Ok(());
    };
    drop(file);
    let removed = std::fs::remove_file(path);
    Err(error).with_context(|| match removed {
        Ok(()) => format!(
            "failed to write {}, and removed what was written",
            path.display()
        ),
        Err(cause) => format!(
            "failed to write {}, and failed to remove the partial file: {cause}",
            path.display()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// A fresh directory for one test, named by process and a counter. The
    /// test removes it. `awslc`'s tests use it too.
    pub(super) fn scratch() -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("volto-tls-test-{}-{serial}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the directory");
        dir
    }

    /// A write that fails half way leaves no file, so the next attempt at the
    /// same path is not refused as an existing file.
    #[test]
    fn a_failed_write_leaves_no_partial_file_behind() {
        let dir = scratch();
        let path = dir.join("ech.pem");
        let error = write_new_file(&path, |file| {
            file.write_all(b"-----BEGIN PRIVATE KEY-----\n")?;
            Err(std::io::Error::other("no space left on the test device"))
        })
        .expect_err("the fill failed");
        let message = format!("{error:#}");
        assert!(
            message.contains("no space left on the test device"),
            "{message}"
        );
        assert!(message.contains("removed what was written"), "{message}");
        assert!(!path.exists(), "a partial file was left behind");

        let key = EchKey::generate("public.example", 7, 0).expect("a key");
        write_new_key_file(&path, &key).expect("the next attempt writes the file");
        assert!(EchKey::load(&path).is_ok());
        std::fs::remove_dir_all(&dir).expect("clean up");
    }
}
