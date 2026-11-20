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

// The one module of the crate allowed `unsafe` code: the binding to libssl.
// `crate` says why the rest of the crate denies it.
#[allow(unsafe_code)]
mod awslc;

pub use awslc::{EchKey, EchSummary, ServerConfig, check_public_name, server_config};

/// The names in `names` that the leaf certificate `cert` is not valid for.
///
/// Judged the way a client judges it, with rustls's own name check over the
/// certificate's Subject Alternative Names, so what is reported here is what a
/// client verifying the certificate by that name would refuse. A certificate
/// webpki cannot parse reports nothing: the server refuses that one at bind,
/// with the reason, and a second complaint would only bury it.
pub(crate) fn names_not_covered(cert: &CertificateDer<'_>, names: &[String]) -> Vec<String> {
    let Ok(parsed) = rustls::server::ParsedCertificate::try_from(cert) else {
        return Vec::new();
    };
    names
        .iter()
        .filter(|name| {
            // The gate ignores a trailing root dot (`Names::new`); the name
            // check does not take one. The same helper, so the two cannot judge
            // the same string differently; see `gate::root_relative`.
            let bare = crate::gate::root_relative(name);
            match rustls::pki_types::ServerName::try_from(bare) {
                Ok(server_name) => {
                    rustls::client::verify_server_name(&parsed, &server_name).is_err()
                }
                Err(_) => true,
            }
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

/// Loads the first private key in a PEM file (PKCS#8, PKCS#1 or SEC1).
fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open server.key = {}", path.display()))?;
    // `PrivateKeyDer` accepts PKCS#8, PKCS#1 and SEC1 sections and skips any
    // other PEM object on the way, so a bundle file works too.
    match PrivateKeyDer::from_pem_reader(file) {
        Ok(key) => Ok(key),
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
    file.write_all(key.to_pem().as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("failed to write {}", path.display()))
}
