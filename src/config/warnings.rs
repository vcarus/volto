use super::{Config, EXAMPLE_PLACEHOLDER_PASSWORD};

/// Ports that `security.denied_ports` may hold but that clients depend on.
///
/// Each row is a port and the reason the warning gives for it. A port on this
/// list in `denied_ports` draws one warning with its own reason.
const PORTS_CLIENTS_NEED: &[(u16, &str)] = &[
    (
        53,
        "every DNS query a client sends through the proxy is refused, which breaks name \
         resolution for a client that resolves names through the tunnel",
    ),
    (
        123,
        "Surge's UDP availability test is an NTP query to port 123 through the proxy, so \
         Surge will report the policy as broken",
    ),
];

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
    ///
    /// The warnings come in groups, each from its own function, in this order.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        self.access_warnings(&mut warnings);
        self.handshake_warnings(&mut warnings);
        self.tunnel_warnings(&mut warnings);
        self.unbounded_peer_warnings(&mut warnings);
        self.path_warnings(&mut warnings);
        self.disabled_safeguard_warnings(&mut warnings);
        warnings
    }

    /// Who can use this server, and who can read its passwords.
    fn access_warnings(&self, warnings: &mut Vec<String>) {
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

        // The file holds every password in clear text. Group-readable (0640) is
        // the installed state, where the service reads it through its group; a
        // file readable by others is usually a copy made under a permissive
        // umask. `file_mode` is set by `load`, on Unix only.
        if let Some((path, mode)) = &self.file_mode
            && mode & 0o004 != 0
        {
            warnings.push(format!(
                "the configuration file {} has mode {:04o}, so every user on this host can \
                 read it, and it holds the [auth] passwords in clear text. Run chmod o-r {} \
                 to keep it to its owner and group.",
                path.display(),
                mode & 0o7777,
                path.display()
            ));
        }
    }

    /// Settings under which every client, or every client but those sending
    /// one name, fails its handshake with no explanation.
    fn handshake_warnings(&self, warnings: &mut Vec<String>) {
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

        // A typo in `expected_sni` makes the server silent, and silence is what
        // the gate is for, so this is the one place the mistake can be noticed.
        // The certificate is read here because this runs before the TLS
        // configuration exists; one that cannot be read is left for the bind to
        // refuse, loudly. `first()` rather than an index keeps the reliance on
        // `load_certs` refusing an empty chain local.
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
    }

    /// How long a tunnel lasts and what it may reach.
    fn tunnel_warnings(&self, warnings: &mut Vec<String>) {
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

        for (port, reason) in PORTS_CLIENTS_NEED {
            if self.security.denied_ports.contains(port) {
                warnings.push(format!("security.denied_ports contains {port}: {reason}"));
            }
        }
    }

    /// A cap on what a peer can try that has been removed.
    fn unbounded_peer_warnings(&self, warnings: &mut Vec<String>) {
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
    }

    /// What keeps an idle connection alive on the path, and the packet size.
    fn path_warnings(&self, warnings: &mut Vec<String>) {
        if self.limits.keep_alive_interval == 0 {
            let mut warning = "limits.keep_alive_interval = 0 disables QUIC keep-alives: \
                               behind a relay doing UDP DNAT, an idle connection will be \
                               dropped when the relay's conntrack entry expires (30s by \
                               default)"
                .to_owned();
            // At 30 or below the idle timeout fires first, and both ends know.
            if self.limits.max_idle_timeout > 30 {
                warning.push_str(&format!(
                    " even though both ends still believe it is alive, since \
                     limits.max_idle_timeout is {}s",
                    self.limits.max_idle_timeout
                ));
            }
            warnings.push(warning);
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
    }

    /// A protection that is on by default and has been switched off.
    fn disabled_safeguard_warnings(&self, warnings: &mut Vec<String>) {
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
    }
}

/// Writes the configuration warnings to stderr when the log filter hides
/// them, so that they reach the operator whatever the filter.
///
/// `shown` is whether the filter enables WARN at the target the caller's own
/// warning lines carry. The caller asks, because `tracing::enabled!` judges
/// the target of the place it is written. The filter is the one installed at
/// startup, on a reload as well, because the subscriber is built once. The
/// warnings say such things as "authentication is DISABLED", and an accepted
/// filter such as `log.level = "error"` hides WARN, so without this copy a
/// file that opens the proxy would leave no line anywhere.
///
/// One line each, `warning: ` first as `--check-config` writes them, and the
/// warning priority `<4>` before that when journald reads stderr.
pub fn copy_hidden_warnings(warnings: &[String], shown: bool) {
    if shown {
        return;
    }
    let journal = crate::systemd::logs_to_journal(
        std::env::var_os(crate::systemd::JOURNAL_STREAM).as_deref(),
    );
    // Not `eprint!`, which panics when stderr cannot be written.
    let _ = std::io::Write::write_all(
        &mut std::io::stderr(),
        hidden_warnings_report(warnings, journal).as_bytes(),
    );
}

/// The text [`copy_hidden_warnings`] writes, with the warning priority on
/// each line when `journal` is true.
fn hidden_warnings_report(warnings: &[String], journal: bool) -> String {
    let prefix = if journal {
        crate::systemd::syslog_prefix(&tracing::Level::WARN)
    } else {
        ""
    };
    warnings
        .iter()
        .map(|warning| format!("{prefix}warning: {warning}\n"))
        .collect()
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

    /// The reason the keep-alive warning gives holds only when the idle timeout
    /// outlasts the relay's 30 s conntrack expiry. At 30 or below the idle
    /// timeout fires first and both ends know the connection is gone, so the
    /// warning stops before the reason; above 30 it is the whole text.
    #[test]
    fn the_keep_alive_warning_gives_its_reason_only_where_it_holds() {
        const WARNING: &str = "limits.keep_alive_interval = 0 disables QUIC keep-alives: \
                               behind a relay doing UDP DNAT, an idle connection will be \
                               dropped when the relay's conntrack entry expires (30s by \
                               default)";
        let warning_for = |idle: u64| {
            parse(&format!(
                "[limits]\nkeep_alive_interval = 0\nmax_idle_timeout = {idle}"
            ))
            .warnings()
            .into_iter()
            .find(|w| w.starts_with("limits.keep_alive_interval"))
            .unwrap_or_else(|| panic!("no keep-alive warning at max_idle_timeout = {idle}"))
        };

        for idle in [1, 30] {
            assert_eq!(warning_for(idle), WARNING, "max_idle_timeout = {idle}");
        }
        for idle in [31, 60] {
            assert_eq!(
                warning_for(idle),
                format!(
                    "{WARNING} even though both ends still believe it is alive, since \
                     limits.max_idle_timeout is {idle}s"
                ),
                "max_idle_timeout = {idle}"
            );
        }
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

    /// A certificate and its private key in a directory of their own, which is
    /// removed with everything in it when this is dropped, however the test
    /// ends.
    struct Minted {
        dir: std::path::PathBuf,
        cert: std::path::PathBuf,
        key: std::path::PathBuf,
    }

    impl Drop for Minted {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A certificate for `names`, written to a fresh directory.
    fn minted_certificate(names: &[&str]) -> Minted {
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
        Minted { dir, cert, key }
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

    /// A configuration file every local user can read is warned about, naming
    /// the file, its mode and the fix; a group-readable or private one is not.
    /// The mode is read by `load`, so the file is loaded the way the server
    /// loads it.
    #[cfg(unix)]
    #[test]
    fn a_configuration_file_readable_by_others_is_warned_about() {
        use std::os::unix::fs::PermissionsExt as _;

        let Minted { dir, cert, key } = &minted_certificate(&["proxy.example"]);
        for (mode, warns) in [(0o644, true), (0o604, true), (0o640, false), (0o600, false)] {
            let path = dir.join(format!("config-{mode:o}.toml"));
            std::fs::write(
                &path,
                format!(
                    "[server]\nlisten = \"127.0.0.1:4433\"\ncert = {:?}\nkey = {:?}\n\
                     [auth]\nusers = [{{ username = \"u\", password = \"a long secret\" }}]\n",
                    cert.display().to_string(),
                    key.display().to_string(),
                ),
            )
            .expect("write the configuration");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("set the mode");

            let warnings = Config::load(&path).expect("the file loads").warnings();
            let about_mode: Vec<_> = warnings.iter().filter(|w| w.contains("chmod")).collect();
            if warns {
                assert_eq!(about_mode.len(), 1, "{mode:o}: {warnings:?}");
                let warning = about_mode[0];
                assert!(warning.contains(&path.display().to_string()), "{warning}");
                assert!(warning.contains(&format!("mode 0{mode:o}")), "{warning}");
                assert!(warning.contains("chmod o-r"), "{warning}");
                assert!(warning.contains("passwords in clear text"), "{warning}");
            } else {
                assert!(about_mode.is_empty(), "{mode:o}: {warnings:?}");
            }
        }
    }

    /// The gate's one failure mode is silence, so the misconfiguration that
    /// causes it -- a name the certificate cannot vouch for -- is the one
    /// warning that has to be there.
    #[test]
    fn an_expected_name_the_certificate_does_not_cover_is_warned_about() {
        let Minted { cert, key, .. } = &minted_certificate(&["proxy.example"]);
        let warnings = parse_with_certificate(
            cert,
            key,
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
        let Minted { cert, key, .. } = &minted_certificate(&["proxy.example", "localhost"]);
        let warnings = parse_with_certificate(
            cert,
            key,
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

    /// Each port in the table draws its own warning with its own reason, and a
    /// port outside the table draws none of them.
    #[test]
    fn denying_a_port_clients_need_is_warned_about_by_port() {
        let ntp = parse("[security]\ndenied_ports = [25, 123]").warnings();
        assert!(
            ntp.iter()
                .any(|w| w.contains("denied_ports contains 123") && w.contains("NTP query")),
            "{ntp:?}"
        );
        assert!(
            !ntp.iter().any(|w| w.contains("denied_ports contains 53")),
            "{ntp:?}"
        );

        let dns = parse("[security]\ndenied_ports = [53]").warnings();
        assert!(
            dns.iter()
                .any(|w| w.contains("denied_ports contains 53") && w.contains("DNS query")),
            "{dns:?}"
        );
        assert!(
            !dns.iter().any(|w| w.contains("denied_ports contains 123")),
            "{dns:?}"
        );

        let unrelated = parse("[security]\ndenied_ports = [25, 8080]").warnings();
        assert!(
            !unrelated
                .iter()
                .any(|w| w.contains("denied_ports contains")),
            "{unrelated:?}"
        );
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
