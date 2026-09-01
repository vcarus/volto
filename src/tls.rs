//! TLS identity: certificate/key loading and the rustls server configuration.
//!
//! QUIC mandates TLS 1.3, so the configuration is pinned to it explicitly
//! rather than relying on rustls' defaults. The crypto provider is also passed
//! explicitly (aws-lc-rs, D102) instead of going through the process-wide
//! default, which keeps behaviour independent of initialisation order elsewhere
//! in the process.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config;

/// Builds the rustls server configuration.
///
/// Called again on `SIGHUP`, which is how a renewed certificate is picked up: the
/// files are re-read here and the result handed to `Endpoint::set_server_config`.
pub fn server_crypto(config: &config::Config) -> Result<rustls::ServerConfig> {
    let server = &config.server;
    let certs = load_certs(&server.cert)?;
    let key = load_key(&server.key)?;

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("the aws-lc-rs crypto provider does not support TLS 1.3")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("server.cert and server.key do not form a usable certificate/key pair")?;

    // Stated rather than inherited. rustls already defaults this to 0, so not a
    // byte on the wire changes, and QUIC allows only 0 or `u32::MAX` anyway --
    // but a security property that holds because nobody set it is one nobody
    // notices losing, and quinn's own `ServerConfig::with_single_cert` sets the
    // other value. RFC 9001 §9.2 puts the choice on the application protocol:
    // one that uses QUIC "MUST describe how the protocol uses 0-RTT and the
    // measures that are employed to protect against replay attack". This one
    // does not use it. Every request here is a CONNECT carrying credentials,
    // and the resumption that matters to a mobile client -- not paying for a
    // full handshake after a network switch -- is ordinary 1-RTT resumption,
    // which this leaves untouched.
    //
    //= https://www.rfc-editor.org/rfc/rfc9001#section-9.2
    //# Disabling 0-RTT entirely is the most effective defense against replay
    //# attack.
    crypto.max_early_data_size = 0;

    crypto.alpn_protocols = server.alpn_wire();

    if config.log.keylog {
        // `KeyLogFile` reads SSLKEYLOGFILE once, here, and is a no-op when the
        // variable is unset — so enabling this without setting the variable is
        // harmless rather than a silent misconfiguration.
        crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    Ok(crypto)
}

/// Loads a PEM certificate chain, leaf first.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
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
