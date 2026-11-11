use super::{Config, EXAMPLE_PLACEHOLDER_PASSWORD};

impl Config {
    /// Settings that are legal but that an operator should be told about.
    ///
    /// Returned rather than logged, so the caller can emit them *after* the
    /// tracing subscriber exists and so they can be asserted on in tests. A
    /// warning logged during `load()` would be written to a subscriber that has
    /// not been installed yet, which is nowhere.
    ///
    /// This opens and parses `server.cert` when `security.expected_sni` is not
    /// empty, so it is a blocking file read and not only a walk over the parsed
    /// configuration. `ReloadHandle::reload` calls it before it takes the
    /// `ConfigSwap` guard for that reason.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        if self.auth.users.is_empty() {
            warnings.push(
                "[auth].users is empty, so authentication is DISABLED: this is an open proxy and \
                 anyone who can reach the port can use it. Add users before exposing it."
                    .to_owned(),
            );
        }

        // The sibling of the warning above, for a table that is not empty and
        // admits everybody anyway. The example is meant to be edited and is
        // startable unedited, so this is the one mistake that leaves a server
        // authenticating against a secret published in the repository. The
        // entries are named by index and the password is not printed, for the
        // reason `parse_error` gives: nothing out of `[auth]` goes to stderr.
        let placeholders: Vec<String> = self
            .auth
            .users
            .iter()
            .enumerate()
            .filter(|(_, user)| user.password == EXAMPLE_PLACEHOLDER_PASSWORD)
            .map(|(i, _)| format!("auth.users[{i}]"))
            .collect();
        if !placeholders.is_empty() {
            warnings.push(format!(
                "{} still carries the placeholder password shipped in \
                 script/config.example.toml, which is published with the source: anyone who \
                 can reach the port can authenticate. Replace it with a long random secret \
                 and reload.",
                placeholders.join(", ")
            ));
        }

        // `h3` is the identifier HTTP/3 is negotiated under, and HTTP/3 is the
        // only thing this server can serve once a connection is up. A list
        // without it is legal (the key exists for interop debugging), but it
        // is a server nobody can reach.
        if !self.server.alpn.iter().any(|id| id == "h3") {
            warnings.push(format!(
                "server.alpn = [{}] does not offer \"h3\", the only protocol this server \
                 speaks: every client is turned away during the TLS handshake with \
                 no_application_protocol, an alert that carries no explanation of its own, \
                 so the server reads as unreachable rather than as misconfigured",
                self.server.alpn.join(", ")
            ));
        }

        // The SNI gate admits exactly the names in `expected_sni`, and a name the
        // certificate does not cover is one no client that verifies the
        // certificate by it can complete a handshake under: the gate was told to
        // expect a name nobody will send. A typo here makes the server silent,
        // and silence is what the gate is for, so this is the one place the
        // mistake can be noticed. The certificate is read here rather than
        // threaded through because this runs before the TLS configuration
        // exists at startup and again on every reload; one that cannot be read
        // is left for the bind to refuse, loudly.
        //
        // `load_certs` refuses an empty chain, so the leaf is always there;
        // asking for it rather than indexing at zero keeps that reliance local.
        if !self.security.expected_sni.is_empty()
            && let Ok(certs) = crate::tls::load_certs(&self.server.cert)
            && let Some(leaf) = certs.first()
        {
            for name in crate::tls::names_not_covered(leaf, &self.security.expected_sni) {
                warnings.push(format!(
                    "security.expected_sni names \"{name}\", which server.cert = {} does not \
                     cover: a client that verifies the certificate by that name fails its \
                     handshake, and one that sends any other name is dropped by the SNI gate \
                     without a reply. Check the name for a typo, or that the certificate was \
                     issued for it.",
                    self.server.cert.display()
                ));
            }
        }

        if self.limits.udp_session_timeout < 120 {
            warnings.push(format!(
                "limits.udp_session_timeout = {} is below the two minutes RFC 9298 §3.1 \
                 recommends; long-lived UDP flows may be cut off, and it is also how long \
                 a write in a half-closed TCP tunnel has to complete in before that tunnel \
                 is cut",
                self.limits.udp_session_timeout
            ));
        }

        if self.security.allow_private_networks {
            warnings.push(
                "security.allow_private_networks is on: clients can reach loopback, RFC 1918 and \
                 link-local addresses through this proxy, including services that trust \
                 127.0.0.1"
                    .to_owned(),
            );
        }

        if self.security.denied_ports.contains(&53) {
            warnings.push(
                "security.denied_ports contains 53: Surge's UDP availability test is a DNS query \
                 through the proxy, so it will report the policy as broken"
                    .to_owned(),
            );
        }

        if self.limits.max_connections == 0 {
            warnings.push(
                "limits.max_connections = 0 removes the cap on simultaneous connections: \
                 an unauthenticated peer can open as many as it likes, each with its own \
                 receive buffers"
                    .to_owned(),
            );
        }

        if self.security.max_auth_failures == 0 && !self.auth.users.is_empty() {
            warnings.push(
                "security.max_auth_failures = 0 lets one connection retry credentials \
                 without limit; guessing then costs a single QUIC handshake"
                    .to_owned(),
            );
        }

        if self.limits.keep_alive_interval == 0 {
            warnings.push(format!(
                "limits.keep_alive_interval = 0 disables QUIC keep-alives: behind a relay \
                 doing UDP DNAT, an idle connection will be dropped when the relay's \
                 conntrack entry expires (30s by default) even though both ends still \
                 believe it is alive, since limits.max_idle_timeout is {}s",
                self.limits.max_idle_timeout
            ));
        }

        if !self.limits.mtu_discovery {
            warnings.push(format!(
                "limits.mtu_discovery is off: the packet size starts at \
                 limits.initial_mtu = {} bytes and is never probed larger; it can still \
                 fall to 1200 if quinn's black-hole detector fires, and nothing brings it \
                 back up. Deliberate on a path that black-holes large packets, a throughput \
                 loss anywhere else",
                self.limits.initial_mtu
            ));
        }

        if let (false, Some(upper_bound)) = (self.limits.mtu_discovery, self.limits.mtu_upper_bound)
        {
            warnings.push(format!(
                "limits.mtu_upper_bound = {} has no effect while limits.mtu_discovery \
                 is off: the value is a ceiling for the upward search, and there is no \
                 search to bound",
                upper_bound
            ));
        }

        if self.log.keylog {
            warnings.push(
                "log.keylog is on: TLS secrets are being written to the file named by \
                 SSLKEYLOGFILE, which lets anyone holding that file decrypt every session \
                 through this proxy. Never leave this on in production."
                    .to_owned(),
            );
        }

        if self.security.unanswered_packet_budget == 0 {
            warnings.push(
                "security.unanswered_packet_budget = 0 disables the RFC 9298 §7 amplification \
                 mitigation: a client can make this proxy flood a target that never answers"
                    .to_owned(),
            );
        }

        if self.limits.connect_timeout == 0 {
            warnings.push(
                "limits.connect_timeout = 0 hands the connect wait back to the operating \
                 system: a request for a target that drops SYNs holds its tunnel slot until \
                 the kernel gives up (about two minutes on Linux), and a client that resets \
                 the request stream in the meantime does not shorten that, so a burst of \
                 black-holed targets can spend a connection's whole max_targets_per_conn"
                    .to_owned(),
            );
        }

        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::tests::{assert_valid_apart_from_certs, parse};

    /// Zero disables keep-alives rather than failing the ratio check — but it is
    /// warned about, because behind a relay it is how idle connections die.
    #[test]
    fn disabling_keep_alives_is_allowed_but_warned_about() {
        let cfg = parse("[limits]\nkeep_alive_interval = 0");
        assert_valid_apart_from_certs(&cfg, "keep_alive_interval = 0");
        assert_eq!(cfg.limits.keep_alive_interval(), None);
        assert!(
            cfg.warnings()
                .iter()
                .any(|w| w.contains("keep_alive_interval") && w.contains("conntrack")),
            "{:?}",
            cfg.warnings()
        );
    }

    /// With discovery off there is no search to bound, and a key the operator
    /// wrote deserves a word about why nothing changed. That holds for a
    /// written value equal to the default too: the operator still set it.
    #[test]
    fn an_mtu_upper_bound_without_discovery_is_allowed_but_warned_about() {
        let cfg = parse("[limits]\nmtu_discovery = false\nmtu_upper_bound = 1464");
        assert_valid_apart_from_certs(&cfg, "mtu_discovery = false");
        assert!(
            cfg.warnings()
                .iter()
                .any(|w| w.contains("mtu_upper_bound") && w.contains("1464")),
            "{:?}",
            cfg.warnings()
        );

        let cfg = parse("[limits]\nmtu_discovery = false\nmtu_upper_bound = 1436");
        assert!(
            cfg.warnings()
                .iter()
                .any(|w| w.contains("mtu_upper_bound") && w.contains("1436")),
            "{:?}",
            cfg.warnings()
        );

        // An absent key draws no warning: nothing was configured away.
        let cfg = parse("[limits]\nmtu_discovery = false");
        assert!(
            !cfg.warnings().iter().any(|w| w.contains("mtu_upper_bound")),
            "{:?}",
            cfg.warnings()
        );
    }

    #[test]
    fn pinning_the_mtu_is_allowed_but_warned_about() {
        let cfg = parse("[limits]\nmtu_discovery = false\ninitial_mtu = 1350");
        assert_valid_apart_from_certs(&cfg, "mtu_discovery = false");
        assert!(
            cfg.warnings()
                .iter()
                .any(|w| w.contains("mtu_discovery") && w.contains("1350")),
            "{:?}",
            cfg.warnings()
        );
    }

    /// The open-proxy warning is the single most important thing an operator can
    /// be told at startup, so it is asserted rather than assumed.
    #[test]
    fn an_empty_user_list_warns_about_being_an_open_proxy() {
        let warnings = parse("").warnings();
        assert!(
            warnings.iter().any(|w| w.contains("open proxy")),
            "{warnings:?}"
        );
    }

    #[test]
    fn configured_users_produce_no_open_proxy_warning() {
        let warnings = parse(
            r#"
            [auth]
            users = [{ username = "u", password = "p" }]
            "#,
        )
        .warnings();
        assert!(
            !warnings.iter().any(|w| w.contains("open proxy")),
            "{warnings:?}"
        );
    }

    /// The example's password is startable, published, and warned about.
    ///
    /// The install paths copy `script/config.example.toml` into place and the
    /// ACME instructions leave the certificate where it already points, so an
    /// operator who follows them and stops before the edit has a running server
    /// that anybody can authenticate against. The warning is what tells them.
    #[test]
    fn the_example_placeholder_password_warns() {
        let warnings = parse(&format!(
            r#"
            [auth]
            users = [
                {{ username = "u", password = "a long secret nobody published" }},
                {{ username = "v", password = "{EXAMPLE_PLACEHOLDER_PASSWORD}" }},
            ]
            "#
        ))
        .warnings();

        let found = warnings
            .iter()
            .find(|w| w.contains("placeholder password"))
            .unwrap_or_else(|| panic!("no placeholder warning in {warnings:?}"));
        assert!(
            found.contains("auth.users[1]"),
            "the warning names the entry that carries it: {found}"
        );
        assert!(
            !found.contains("auth.users[0]"),
            "and only that one: {found}"
        );
        assert!(
            !found.contains(EXAMPLE_PLACEHOLDER_PASSWORD),
            "a password is never echoed, not even this one: {found}"
        );
    }

    /// The other half: a table with no placeholder in it draws nothing.
    #[test]
    fn a_replaced_password_draws_no_placeholder_warning() {
        let warnings = parse(
            r#"
            [auth]
            users = [{ username = "u", password = "a long secret nobody published" }]
            "#,
        )
        .warnings();
        assert!(
            !warnings.iter().any(|w| w.contains("placeholder password")),
            "{warnings:?}"
        );
    }

    /// A certificate for `names`, written to a fresh directory; returns the
    /// paths a `[server]` section can point at.
    fn minted_certificate(names: &[&str]) -> (std::path::PathBuf, std::path::PathBuf) {
        let issued = rcgen::generate_simple_self_signed(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("a self-signed certificate");
        // Distinct per call, not per instant: two tests minting in the same
        // microsecond would otherwise share a directory and read each other's
        // certificate.
        static MINTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let serial = MINTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("volto-config-test-{}-{serial}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the directory");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, issued.cert.pem()).expect("write the certificate");
        std::fs::write(&key, issued.signing_key.serialize_pem()).expect("write the key");
        (cert, key)
    }

    fn parse_with_certificate(cert: &std::path::Path, key: &std::path::Path, body: &str) -> Config {
        toml::from_str(&format!(
            r#"
            [server]
            listen = "127.0.0.1:4433"
            cert = {cert:?}
            key = {key:?}
            {body}
            "#,
            cert = cert.display().to_string(),
            key = key.display().to_string(),
        ))
        .expect("parses")
    }

    /// The gate's one failure mode is silence, so the misconfiguration that
    /// causes it -- a name the certificate cannot vouch for -- is the one
    /// warning that has to be there.
    #[test]
    fn an_expected_name_the_certificate_does_not_cover_is_warned_about() {
        let (cert, key) = minted_certificate(&["proxy.example"]);
        let warnings = parse_with_certificate(
            &cert,
            &key,
            "[security]\nexpected_sni = [\"proxy.example\", \"porxy.example\"]",
        )
        .warnings();
        let about_names: Vec<_> = warnings
            .iter()
            .filter(|w| w.contains("does not cover"))
            .collect();
        assert_eq!(about_names.len(), 1, "{warnings:?}");
        assert!(
            about_names[0].contains("\"porxy.example\"") && about_names[0].contains("cert.pem"),
            "{warnings:?}"
        );
    }

    /// Covered names, in any case and with the root dot the gate also ignores,
    /// draw nothing; and a certificate that is not there is the bind's
    /// complaint, not this one's.
    #[test]
    fn covered_expected_names_draw_no_warning() {
        let (cert, key) = minted_certificate(&["proxy.example", "localhost"]);
        let warnings = parse_with_certificate(
            &cert,
            &key,
            "[security]\nexpected_sni = [\"PROXY.example.\", \"localhost\"]",
        )
        .warnings();
        assert!(
            !warnings.iter().any(|w| w.contains("does not cover")),
            "{warnings:?}"
        );

        let warnings = parse("[security]\nexpected_sni = [\"proxy.example\"]").warnings();
        assert!(
            !warnings.iter().any(|w| w.contains("does not cover")),
            "{warnings:?}"
        );
    }

    #[test]
    fn risky_but_legal_settings_are_warned_about() {
        let cfg = parse(
            r#"
            [auth]
            users = [{ username = "u", password = "p" }]

            [limits]
            udp_session_timeout = 30
            connect_timeout = 0

            [security]
            allow_private_networks = true
            denied_ports = [25, 53]
            unanswered_packet_budget = 0

            [log]
            keylog = true
            "#,
        );

        let warnings = cfg.warnings();
        // One per risky setting, and nothing else.
        assert_eq!(warnings.len(), 6, "{warnings:?}");
        for expected in [
            "udp_session_timeout",
            "connect_timeout = 0",
            "allow_private_networks",
            "denied_ports contains 53",
            "unanswered_packet_budget",
            "log.keylog",
        ] {
            assert!(
                warnings.iter().any(|w| w.contains(expected)),
                "missing a warning about {expected}: {warnings:?}"
            );
        }
    }

    /// RFC 9298 §3.1 recommends two minutes, and a configuration that meets the
    /// recommendation exactly has nothing to be told about: 120 is the first
    /// value that draws no warning, 119 the last that does.
    #[test]
    fn the_udp_session_timeout_warning_stops_at_the_recommended_two_minutes() {
        let warned = parse("[limits]\nudp_session_timeout = 119").warnings();
        assert!(
            warned.iter().any(|w| w.contains("udp_session_timeout")),
            "{warned:?}"
        );

        let quiet = parse("[limits]\nudp_session_timeout = 120").warnings();
        assert!(
            !quiet.iter().any(|w| w.contains("udp_session_timeout")),
            "{quiet:?}"
        );
    }

    /// An unlimited retry budget is a warning about guessing configured
    /// credentials, so it belongs to a configuration that has some. With no
    /// users there is nothing to guess and no counter to exhaust, and repeating
    /// it under the open-proxy warning would only dilute that one.
    #[test]
    fn an_unlimited_auth_failure_budget_warns_only_where_there_are_credentials() {
        let with_users = parse(
            r#"
            [auth]
            users = [{ username = "u", password = "p" }]

            [security]
            max_auth_failures = 0
            "#,
        )
        .warnings();
        assert!(
            with_users.iter().any(|w| w.contains("max_auth_failures")),
            "{with_users:?}"
        );

        let without_users = parse("[security]\nmax_auth_failures = 0").warnings();
        assert!(
            !without_users
                .iter()
                .any(|w| w.contains("max_auth_failures")),
            "{without_users:?}"
        );
    }

    /// An ALPN list without `h3` is legal and starts a server every client
    /// fails against: TLS ends the handshake with `no_application_protocol`,
    /// which says nothing about why, so without the warning the only trace is a
    /// handshake error at each end.
    #[test]
    fn an_alpn_list_without_h3_is_allowed_but_warned_about() {
        let cfg = parse(r#"alpn = ["h3-29"]"#);
        assert_valid_apart_from_certs(&cfg, "an ALPN list without h3");
        assert!(
            cfg.warnings()
                .iter()
                .any(|w| w.contains("server.alpn") && w.contains("h3-29")),
            "{:?}",
            cfg.warnings()
        );

        // A list that still offers h3 alongside another identifier is exactly
        // what the key is for, and draws nothing.
        let quiet = parse(r#"alpn = ["h3", "h3-29"]"#).warnings();
        assert!(
            !quiet.iter().any(|w| w.contains("server.alpn")),
            "{quiet:?}"
        );

        let default = parse("").warnings();
        assert!(
            !default.iter().any(|w| w.contains("server.alpn")),
            "the default list must draw no warning: {default:?}"
        );
    }
}
