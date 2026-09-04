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

use anyhow::{Context, Result, bail};
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::config;
use crate::gate::Names;

/// What an operator is told when the two configured files do not pair up.
///
/// Written once so the gate-on and the gate-off branch of [`server_crypto`]
/// cannot report the same failure in two wordings.
const UNUSABLE_PAIR: &str = "server.cert and server.key do not form a usable certificate/key pair";

/// Builds the rustls server configuration.
///
/// Called again on `SIGHUP`, which is how a renewed certificate is picked up: the
/// files are re-read here and the result handed to `Endpoint::set_server_config`.
pub fn server_crypto(config: &config::Config) -> Result<rustls::ServerConfig> {
    let server = &config.server;
    let certs = load_certs(&server.cert)?;
    let key = load_key(&server.key)?;

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("the aws-lc-rs crypto provider does not support TLS 1.3")?
        .with_no_client_auth();

    // The second SNI gate (D106). The first one is at the socket, in
    // [`crate::gate`], and it cannot see a ClientHello that arrives split across
    // several Initial packets -- it passes those through deliberately, because
    // refusing a first flight it has not finished reading would turn a large
    // ClientHello into an unreachable server. This is where such a handshake is
    // stopped instead: no certificate is resolved for a name that is not ours,
    // and rustls ends the handshake with a fatal alert rather than presenting a
    // certificate and answering the request behind it.
    //
    //= https://www.rfc-editor.org/rfc/rfc6066#section-3
    //# If the server understood the ClientHello extension but
    //# does not recognize the server name, the server SHOULD take one of two
    //# actions: either abort the handshake by sending a fatal-level
    //# unrecognized_name(112) alert or continue the handshake.
    //
    // The first of those two, with a different alert: rustls sends
    // `access_denied`. Which alert it is has no bearing on the client, which
    // fails the handshake either way, and volto does not choose it.
    let names = Names::new(&config.security.expected_sni);
    let mut crypto = if names.is_empty() {
        builder
            .with_single_cert(certs, key)
            .context(UNUSABLE_PAIR)?
    } else {
        let certified = CertifiedKey::from_der(certs, key, &provider).context(UNUSABLE_PAIR)?;
        builder.with_cert_resolver(Arc::new(OneOfTheseNames {
            names,
            certified: Arc::new(certified),
        }))
    };

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

/// Presents the certificate only to a client that asked for a name we answer to.
///
/// Not a certificate *selection* mechanism -- there is one certificate and one
/// key, exactly as `with_single_cert` installs -- but a refusal: the resolver is
/// the only place in rustls where a server can see the requested name and decline
/// before anything is sent back.
#[derive(Debug)]
struct OneOfTheseNames {
    names: Names,
    certified: Arc<CertifiedKey>,
}

impl ResolvesServerCert for OneOfTheseNames {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // `None` from rustls means the ClientHello carried no `server_name` at
        // all, which is a client that cannot be asking for this server by name.
        let name = client_hello.server_name()?;
        self.names.accepts(name).then(|| self.certified.clone())
    }
}

/// The names in `names` that the leaf certificate `cert` is not valid for.
///
/// Judged the way a client judges it, with rustls's own name check over the
/// certificate's Subject Alternative Names, so what is reported here is what a
/// client verifying the certificate by that name would refuse. A certificate
/// webpki cannot parse reports nothing: rustls refuses that one at bind, with
/// the reason, and a second complaint would only bury it.
pub(crate) fn names_not_covered(cert: &CertificateDer<'_>, names: &[String]) -> Vec<String> {
    let Ok(parsed) = rustls::server::ParsedCertificate::try_from(cert) else {
        return Vec::new();
    };
    names
        .iter()
        .filter(|name| {
            // The gate ignores a trailing root dot (`Names::new`); the name
            // check does not take one. The same helper, so the two cannot judge
            // the same string differently -- this line read
            // `trim_end_matches('.')` and so removed every trailing dot, which
            // reported a name the gate held in an unmatchable form as covered.
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
