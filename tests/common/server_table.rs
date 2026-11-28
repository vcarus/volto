//! The `[server]` table every configuration file a test writes starts with.
//!
//! A leaf module of its own (D66), because both sides of the D66 line write
//! this table: `TestServer::server_section` in `common/mod.rs` and
//! `scripts::server_section` in the leaf `scripts.rs`. Each includes this file
//! with `#[path]`, so the two spellings are one.

/// The `[server]` table naming `listen` and the certificate pair.
pub fn server_section(cert: &std::path::Path, key: &std::path::Path, listen: &str) -> String {
    format!(
        "[server]\nlisten = \"{listen}\"\ncert = \"{}\"\nkey = \"{}\"\n",
        cert.display(),
        key.display(),
    )
}
