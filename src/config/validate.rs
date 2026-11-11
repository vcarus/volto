use anyhow::{Context, Result, bail};

use super::{
    Config, INITIAL_RTT_RANGE_MS, MAX_EXPECTED_SNI, MAX_IDLE_TIMEOUT_CEILING, MAX_INITIAL_MTU,
    MAX_MTU_UPPER_BOUND, MAX_SHUTDOWN_GRACE, MAX_SOCKET_BUFFER, MAX_STREAMS_BIDI_CEILING,
    MAX_TARGETS_PER_CONN_CEILING, MIN_INITIAL_MTU,
};

impl Config {
    /// Checks everything that TOML deserialization cannot express.
    ///
    /// Every error names the offending field so the operator does not have to
    /// guess which key is wrong.
    /// Checks are ordered cheapest first, so a syntactic mistake is reported
    /// without touching the filesystem.
    pub fn validate(&self) -> Result<()> {
        validate_log_level(&self.log.level)?;

        if self.server.alpn.is_empty() {
            bail!("server.alpn must list at least one protocol identifier");
        }
        for (i, id) in self.server.alpn.iter().enumerate() {
            if id.is_empty() {
                bail!("server.alpn[{i}] is empty");
            }
            // An ALPN identifier is length-prefixed with a single byte on the
            // wire, so it cannot exceed 255 bytes.
            if id.len() > 255 {
                bail!(
                    "server.alpn[{i}] is {} bytes, the wire format allows at most 255",
                    id.len()
                );
            }
        }

        if self.server.shutdown_grace > MAX_SHUTDOWN_GRACE {
            bail!(
                "server.shutdown_grace = {} exceeds {MAX_SHUTDOWN_GRACE} seconds; \
                 a drain that long outlives the service manager's own kill timeout, \
                 and use 0 to close every tunnel at once instead",
                self.server.shutdown_grace
            );
        }

        if self.limits.udp_session_timeout == 0
            || self.limits.udp_session_timeout > MAX_IDLE_TIMEOUT_CEILING
        {
            bail!(
                "limits.udp_session_timeout = {} must be between 1 and \
                 {MAX_IDLE_TIMEOUT_CEILING} seconds",
                self.limits.udp_session_timeout
            );
        }
        if self.limits.connect_timeout > MAX_IDLE_TIMEOUT_CEILING {
            bail!(
                "limits.connect_timeout = {} exceeds {MAX_IDLE_TIMEOUT_CEILING} seconds; \
                 use 0 to disable the budget instead",
                self.limits.connect_timeout
            );
        }
        if self.limits.max_targets_per_conn == 0 {
            bail!("limits.max_targets_per_conn must be greater than zero");
        }
        if self.limits.max_targets_per_conn > MAX_TARGETS_PER_CONN_CEILING {
            bail!(
                "limits.max_targets_per_conn = {} exceeds the {MAX_TARGETS_PER_CONN_CEILING} \
                 this server allows; every tunnel costs a file descriptor",
                self.limits.max_targets_per_conn
            );
        }

        if self.limits.max_streams_bidi == 0 {
            bail!(
                "limits.max_streams_bidi must be greater than zero, or no tunnel could \
                 ever be opened"
            );
        }
        if self.limits.max_streams_bidi > MAX_STREAMS_BIDI_CEILING {
            bail!(
                "limits.max_streams_bidi = {} exceeds the {MAX_STREAMS_BIDI_CEILING} this \
                 server allows; a stream slot is reserved for every unit of the credit when \
                 the allowance is granted, so the value is paid in one go by a connection's \
                 first authenticated request rather than when a stream is opened",
                self.limits.max_streams_bidi
            );
        }

        if self.limits.max_idle_timeout == 0
            || self.limits.max_idle_timeout > MAX_IDLE_TIMEOUT_CEILING
        {
            bail!(
                "limits.max_idle_timeout = {} must be between 1 and \
                 {MAX_IDLE_TIMEOUT_CEILING} seconds",
                self.limits.max_idle_timeout
            );
        }

        // Strictly below half, not at it: at exactly half, losing a single
        // keep-alive packet is enough for the connection to time out. The relay in
        // front of this server is the reason keep-alives exist at all — its UDP
        // conntrack entry expires on its own schedule (30s by default), and only a
        // keep-alive that comfortably beats both timeouts keeps the NAT mapping
        // alive.
        //
        // Written as `interval >= ceil(idle / 2)` rather than the more obvious
        // `interval * 2 >= idle`: the two reject exactly the same pairs of
        // integers, and this one cannot overflow. The doubling could, and a
        // `u64` large enough to make it — anything above `u64::MAX / 2` — is
        // reachable straight from the file, since TOML integers deserialize
        // across the whole target type's range. A debug build panicked inside
        // this function; a release build wrapped the product to something small,
        // accepted the interval, and handed it to quinn, where it becomes
        // `Instant::now() + interval` the moment a connection is established and
        // panics the connection driver instead (D86).
        if self.limits.keep_alive_interval > 0
            && self.limits.keep_alive_interval >= self.limits.max_idle_timeout.div_ceil(2)
        {
            // The ceiling on this field is 3600 seconds, so the halving is
            // always exact in an `f64`; `From` has no `u64` impl to say so.
            #[allow(clippy::as_conversions)]
            let half = self.limits.max_idle_timeout as f64 / 2.0;
            bail!(
                "limits.keep_alive_interval = {} must be less than half of \
                 limits.max_idle_timeout = {} (i.e. below {}), so that a lost keep-alive \
                 packet cannot let the connection time out",
                self.limits.keep_alive_interval,
                self.limits.max_idle_timeout,
                half
            );
        }

        if self.limits.initial_mtu < MIN_INITIAL_MTU {
            bail!(
                "limits.initial_mtu = {} is below the {MIN_INITIAL_MTU} bytes QUIC \
                 requires (RFC 9000 §14); a smaller value cannot carry a QUIC \
                 handshake packet",
                self.limits.initial_mtu
            );
        }

        if self.limits.initial_mtu > MAX_INITIAL_MTU {
            bail!(
                "limits.initial_mtu = {} is above the {MAX_INITIAL_MTU} bytes this \
                 server allows; the value is a UDP payload size, and an Ethernet \
                 frame leaves that much of one over IPv6, so a handshake sent in \
                 larger packets is dropped by the path with nothing to fall back to",
                self.limits.initial_mtu
            );
        }

        // Only a ceiling the file writes is checked. An absent one resolves to
        // a value that is in range by construction (`Limits::mtu_upper_bound`).
        if let Some(upper_bound) = self.limits.mtu_upper_bound {
            if upper_bound < self.limits.initial_mtu {
                bail!(
                    "limits.mtu_upper_bound = {} is below limits.initial_mtu = {}; \
                     discovery searches upward from the initial size, so a ceiling \
                     under the start describes a search that cannot happen",
                    upper_bound,
                    self.limits.initial_mtu
                );
            }

            if upper_bound > MAX_MTU_UPPER_BOUND {
                bail!(
                    "limits.mtu_upper_bound = {} is above the {MAX_MTU_UPPER_BOUND} bytes this \
                     server allows; the value is a UDP payload size, and an Ethernet \
                     frame leaves at most that much of one over IPv4, so a larger \
                     bound could only probe sizes no standard path carries",
                    upper_bound
                );
            }
        }

        if !INITIAL_RTT_RANGE_MS.contains(&self.limits.initial_rtt_ms) {
            bail!(
                "limits.initial_rtt_ms = {} must be between {} and {}; it seeds the \
                 handshake retransmission timers, and a value below the real path \
                 RTT retransmits packets that were never lost",
                self.limits.initial_rtt_ms,
                INITIAL_RTT_RANGE_MS.start(),
                INITIAL_RTT_RANGE_MS.end()
            );
        }

        // `socket2` converts these with `size as c_int`, so a value above
        // `i32::MAX` reaches the kernel truncated to a different number: 2^32
        // becomes 0, which is the operating system's minimum rather than the
        // default the operator asked to leave alone. Refusing at load time is
        // what makes the number in the file the number the kernel receives.
        for (key, value) in [
            ("limits.socket_recv_buffer", self.limits.socket_recv_buffer),
            ("limits.socket_send_buffer", self.limits.socket_send_buffer),
        ] {
            if value > MAX_SOCKET_BUFFER {
                bail!(
                    "{key} = {value} is above the {MAX_SOCKET_BUFFER} bytes the socket \
                     API accepts; the value is passed to setsockopt as a signed 32-bit \
                     integer, so a larger one is truncated before the kernel sees it. \
                     Use 0 to keep the operating system default instead"
                );
            }
        }

        for (i, user) in self.auth.users.iter().enumerate() {
            if user.username.is_empty() {
                bail!("auth.users[{i}].username is empty");
            }
            if user.username.contains(':') {
                // RFC 7617 §2: the colon separates user-id from password inside
                // the credentials, so a user-id containing one is unusable.
                bail!(
                    "auth.users[{i}].username contains a colon, which RFC 7617 §2 does not allow \
                     in HTTP Basic credentials"
                );
            }
            if user.username.len() > crate::logfmt::MAX_TOKEN {
                // A user-id this long is unusable in a subtler way. Failures are
                // bucketed by the user-id the request claimed, in the form a log
                // line carries it -- truncated at `logfmt::MAX_TOKEN` -- so a
                // name past that bound never matches the configured one, and its
                // failures land in the bucket no success can clear. The client
                // that really does hold those credentials would then lose its
                // connection at the `security.max_auth_failures`-th lifetime
                // failure however often it authenticates in between. Refusing
                // the name here is what makes that state unreachable.
                //
                // The name is not echoed: it is not a secret, but it lives in
                // the same table as one, and nothing out of `[auth]` goes to
                // stderr -- see `parse_error`. The index and the limit are what
                // it takes to find and fix it.
                bail!(
                    "auth.users[{i}].username is {} bytes, over the {}-byte limit a user-id has \
                     to stay within to be told apart in the logs and in the authentication \
                     failure counters",
                    user.username.len(),
                    crate::logfmt::MAX_TOKEN
                );
            }
            if user.password.is_empty() {
                bail!("auth.users[{i}].password is empty");
            }
            if let Some(first) = self.auth.users[..i]
                .iter()
                .position(|other| other.username == user.username)
            {
                // Not echoed either, for the reason given above: the two
                // indices name both entries, which is what it takes to find
                // and fix them.
                bail!("auth.users[{i}].username duplicates auth.users[{first}].username");
            }
        }

        if let Some(i) = self
            .security
            .denied_ports
            .iter()
            .position(|port| *port == 0)
        {
            bail!("security.denied_ports[{i}] is 0, which is not a usable port");
        }

        for (i, name) in self.security.expected_sni.iter().enumerate() {
            validate_expected_sni(i, name)?;
        }

        if !self.server.cert.is_file() {
            bail!(
                "server.cert = {} is not a readable file",
                self.server.cert.display()
            );
        }
        if !self.server.key.is_file() {
            bail!(
                "server.key = {} is not a readable file",
                self.server.key.display()
            );
        }

        Ok(())
    }
}

/// Levels accepted as a bare `log.level`.
const LOG_LEVELS: [&str; 5] = ["trace", "debug", "info", "warn", "error"];

/// Validates `log.level`.
///
/// A plain word must name a level. This extra strictness matters because
/// `EnvFilter` would otherwise read a typo like `"warning"` as a *target* name,
/// accept it, and then log nothing at all. Anything containing filter syntax is
/// handed to `EnvFilter` as-is.
fn validate_log_level(level: &str) -> Result<()> {
    if level.contains([',', '=', '[']) {
        tracing_subscriber::EnvFilter::try_new(level)
            .with_context(|| format!("log.level = {level:?} is not a valid filter"))?;
        return Ok(());
    }

    if !LOG_LEVELS.iter().any(|l| level.eq_ignore_ascii_case(l)) {
        bail!(
            "log.level = {level:?} is not one of {LOG_LEVELS:?}; for anything more \
             specific use a filter directive such as \"volto=debug,quinn=info\""
        );
    }

    Ok(())
}

/// Validates one `security.expected_sni` entry.
///
/// Rejected rather than normalised away, because every one of these is a name an
/// operator meant to type and none of them can ever match: a name that cannot
/// appear in a ClientHello turns the gate into a server nobody can reach, and
/// that failure is silent by construction — the whole point of the gate is that
/// a refused handshake gets no answer, so the operator would see a working
/// service that no client can open.
///
//= https://www.rfc-editor.org/rfc/rfc6066#section-3
//# The hostname is represented as a byte
//# string using ASCII encoding without a trailing dot.
fn validate_expected_sni(index: usize, name: &str) -> Result<()> {
    let bare = crate::gate::root_relative(name);

    if bare.is_empty() {
        bail!("security.expected_sni[{index}] is empty, which is not a host name");
    }

    // One trailing dot spells the root and is stripped above; a second one, or a
    // dot at the start, or two in a row, is an empty label. Refused here rather
    // than left to rustls, for the reason the whole function exists: `Names`
    // would hold `host.tw.` for `host.tw..`, no ClientHello can carry that form
    // (RFC 6066 §3 has the name represented "without a trailing dot"), and the
    // gate would refuse every client in silence. `ServerName::try_from` would refuse
    // it too, but only in the certificate-coverage warning, which is a warning
    // and not a refusal to start.
    if bare.split('.').any(str::is_empty) {
        bail!(
            "security.expected_sni[{index}] = {name:?} has an empty label; a host name \
             has no leading dot and no two dots in a row, and only one trailing dot, \
             which spells the root"
        );
    }

    if bare.len() > MAX_EXPECTED_SNI {
        bail!(
            "security.expected_sni[{index}] is {} bytes; a DNS host name is at most \
             {MAX_EXPECTED_SNI}, so no ClientHello could ever carry it",
            bare.len()
        );
    }

    if bare.contains('*') {
        bail!(
            "security.expected_sni[{index}] = {name:?} looks like a wildcard, and this \
             list is matched name for name: write out each host it should accept"
        );
    }

    if let Some(bad) = bare
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && !matches!(c, '-' | '.' | '_'))
    {
        bail!(
            "security.expected_sni[{index}] = {name:?} contains {bad:?}; a server_name \
             carries an ASCII DNS host name, so an internationalized domain goes here \
             in its A-label form (xn--...)"
        );
    }

    // The character set above already turns away every IPv6 literal, since none
    // of them can be written without a colon, but the rule is stated as the rule
    // rather than left as a side effect of the character class. It is exactly
    // the class this function exists for: an operator who typed the address the
    // relay is reached on has a name no conforming client will ever send, and
    // the gate then refuses every handshake in silence.
    //
    //= https://www.rfc-editor.org/rfc/rfc6066#section-3
    //# Literal IPv4 and IPv6 addresses are not permitted in "HostName".
    if bare.parse::<std::net::Ipv4Addr>().is_ok() || bare.parse::<std::net::Ipv6Addr>().is_ok() {
        bail!(
            "security.expected_sni[{index}] = {name:?} is an IP address literal, which \
             RFC 6066 §3 does not permit in a server_name, so no conforming client can \
             send it and the gate would refuse every handshake without a reply. Name the \
             host the certificate is issued for instead"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    use crate::config::Limits;
    use crate::config::tests::{
        any_limits, around, assert_valid_apart_from_certs, config_with, parse,
    };

    /// Asserts that `body` is refused by [`Config::validate`], that the refusal
    /// names `key`, and returns the whole message.
    ///
    /// About twenty tests here are the same four lines: build a body, expect the
    /// error, render it, assert it names the key. The key stays a literal at the
    /// call site so nothing becomes less greppable, and a test that checks a
    /// second phrase checks it against the returned string.
    fn rejected(body: &str, key: &str) -> String {
        let message = parse(body)
            .validate()
            .expect_err("must be rejected")
            .to_string();
        assert!(message.contains(key), "{key} must be named: {message}");
        message
    }

    #[test]
    fn malformed_users_are_rejected_with_their_index() {
        let cases = [
            (
                r#"[auth]
                   users = [{ username = "", password = "p" }]"#,
                "auth.users[0].username",
            ),
            (
                r#"[auth]
                   users = [{ username = "a:b", password = "p" }]"#,
                "auth.users[0].username",
            ),
            (
                r#"[auth]
                   users = [{ username = "u", password = "" }]"#,
                "auth.users[0].password",
            ),
            (
                r#"[auth]
                   users = [
                     { username = "u", password = "p" },
                     { username = "u", password = "q" },
                   ]"#,
                "auth.users[1].username",
            ),
        ];

        for (body, expected) in cases {
            rejected(body, expected);
        }

        // The duplicate branch names both entries and echoes neither name, the
        // same rule the over-long branch beside it follows.
        let duplicate = rejected(
            r#"[auth]
               users = [
                 { username = "greppable", password = "p" },
                 { username = "greppable", password = "q" },
               ]"#,
            "auth.users[0].username",
        );
        assert!(duplicate.contains("auth.users[1].username"), "{duplicate}");
        assert!(
            !duplicate.contains("greppable"),
            "nothing out of [auth] goes to stderr: {duplicate}"
        );
    }

    /// A user-id longer than a log line carries whole is refused at load.
    ///
    /// Not a style rule: such a name can never be cleared by its own success.
    /// A failure that names it is charged by the truncated copy the log format
    /// hands out, which matches no configured user, so it lands in the bucket
    /// no success ever clears — and the client that really does hold those
    /// credentials loses the connection on the fifth lifetime failure however
    /// often it authenticates in between. Refusing the configuration is what
    /// makes that state unreachable.
    ///
    /// The limit is exactly the log format's, and the message must name it
    /// without echoing the user-id: a name is not a password, but it sits next
    /// to one in the same table, and this file's whole discipline is that
    /// nothing out of `[auth]` reaches stderr.
    #[test]
    fn an_over_long_username_is_rejected_without_echoing_it() {
        let username = "u".repeat(crate::logfmt::MAX_TOKEN + 1);
        // The entry it is, which the operator has to be told.
        let rendered = rejected(
            &format!("[auth]\nusers = [{{ username = \"{username}\", password = \"p\" }}]"),
            "auth.users[0].username",
        );

        assert!(
            rendered.contains(&crate::logfmt::MAX_TOKEN.to_string()),
            "the message has to name the limit: {rendered}"
        );
        assert!(
            !rendered.contains(&username),
            "the name itself must not be echoed: {rendered}"
        );

        // The limit itself is legal, so the rejection is of what is past it
        // rather than of a length that merely approaches it.
        let cfg = parse(&format!(
            "[auth]\nusers = [{{ username = \"{}\", password = \"p\" }}]",
            "u".repeat(crate::logfmt::MAX_TOKEN)
        ));
        assert_valid_apart_from_certs(&cfg, "a user-id exactly at the log bound");
    }

    #[test]
    fn a_zero_or_oversized_target_quota_is_rejected() {
        for value in ["0", "70000"] {
            rejected(
                &format!("[limits]\nmax_targets_per_conn = {value}"),
                "max_targets_per_conn",
            );
        }

        // The ceiling is a sanity limit rather than a protocol one, so the value
        // at it is still a quota the operator meant: only what is past it is
        // read as a typo.
        let cfg = parse(&format!(
            "[limits]\nmax_targets_per_conn = {MAX_TARGETS_PER_CONN_CEILING}"
        ));
        assert_valid_apart_from_certs(&cfg, "a quota of exactly the ceiling");

        rejected(
            &format!(
                "[limits]\nmax_targets_per_conn = {}",
                MAX_TARGETS_PER_CONN_CEILING + 1
            ),
            "max_targets_per_conn",
        );
    }

    /// Zero disables the connect budget rather than meaning "give up at once",
    /// which is the same shape `keep_alive_interval = 0` has.
    #[test]
    fn a_zero_connect_timeout_disables_the_budget() {
        let cfg = parse("[limits]\nconnect_timeout = 0");
        assert_valid_apart_from_certs(&cfg, "connect_timeout = 0");
        assert_eq!(cfg.limits.connect_timeout, 0);
        assert_eq!(cfg.limits.connect_timeout(), None);

        // And an ordinary value is carried through as a duration.
        let cfg = parse("[limits]\nconnect_timeout = 3");
        assert_valid_apart_from_certs(&cfg, "connect_timeout = 3");
        assert_eq!(
            cfg.limits.connect_timeout(),
            Some(std::time::Duration::from_secs(3))
        );
    }

    /// The rule that exists because of the relay: a keep-alive at or above half the
    /// idle timeout cannot survive losing a single packet.
    #[test]
    fn a_keep_alive_at_or_above_half_the_idle_timeout_is_rejected() {
        // Exactly half, and above it.
        for (idle, keepalive) in [(40, 20), (60, 30), (60, 45), (10, 5)] {
            let msg = rejected(
                &format!("[limits]\nmax_idle_timeout = {idle}\nkeep_alive_interval = {keepalive}"),
                "keep_alive_interval",
            );
            // The message has to say what to compare against, not just complain.
            assert!(msg.contains("max_idle_timeout"), "{msg}");
        }

        // Just below half is fine.
        for (idle, keepalive) in [(41, 20), (60, 20), (60, 29), (1, 0)] {
            let cfg = parse(&format!(
                "[limits]\nmax_idle_timeout = {idle}\nkeep_alive_interval = {keepalive}"
            ));
            assert_valid_apart_from_certs(&cfg, &format!("idle={idle} keepalive={keepalive}"));
        }
    }

    /// The ratio check must survive the interval it is checking (D86).
    ///
    /// TOML integers deserialize across the whole of the target type, so every
    /// `u64` here is something an operator can write in the file, `u64::MAX`
    /// included. The check used to double the interval before comparing it,
    /// which above `u64::MAX / 2` has no answer to give: a debug build panicked
    /// inside `validate` — a validator that aborts the process instead of
    /// returning `Err` — and a release build wrapped the product to a small
    /// number, accepted the interval and passed it to quinn, where the first
    /// established connection turns it into `Instant::now() + interval` and
    /// panics the connection driver instead.
    #[test]
    fn an_overflowing_keep_alive_interval_is_rejected_rather_than_panicking() {
        for keepalive in [u64::MAX, u64::MAX - 1, u64::MAX / 2 + 1, 1u64 << 63] {
            rejected(
                &format!("[limits]\nkeep_alive_interval = {keepalive}"),
                "keep_alive_interval",
            );
        }
    }

    #[test]
    fn an_initial_mtu_below_the_quic_floor_is_rejected() {
        for value in [0, 1, 576, 1199] {
            let msg = rejected(&format!("[limits]\ninitial_mtu = {value}"), "initial_mtu");
            assert!(msg.contains("1200"), "the floor must be named: {msg}");
        }

        // The floor itself, and the range above it up to the ceiling.
        for value in [1200, 1350, MAX_INITIAL_MTU] {
            let cfg = parse(&format!("[limits]\ninitial_mtu = {value}"));
            assert_valid_apart_from_certs(&cfg, &format!("initial_mtu = {value}"));
        }
    }

    /// The other end of the same range, and the dangerous one.
    ///
    /// Below the floor quinn silently clamps up, so the worst a missing check
    /// costs is a value that is not the one configured. Above the ceiling there
    /// is no clamp at all: the handshake goes out in packets no path delivers,
    /// the black-hole detector never runs because no connection is ever
    /// established, and a reload makes that the state of a server that was
    /// working a moment ago.
    ///
    /// 1453 is the first rejected value and 1500 is in the list because it is
    /// the number the mistake reaches for: `initial_mtu` is a UDP payload size,
    /// so an Ethernet frame's 1500 bytes is an IP packet, not a payload.
    #[test]
    fn an_initial_mtu_above_the_ethernet_ceiling_is_rejected() {
        for value in [MAX_INITIAL_MTU + 1, 1500, 9000, u16::MAX] {
            let msg = rejected(&format!("[limits]\ninitial_mtu = {value}"), "initial_mtu");
            assert!(
                msg.contains(&MAX_INITIAL_MTU.to_string()),
                "the ceiling must be named: {msg}"
            );
        }
    }

    /// A ceiling below the start describes a search that cannot happen, and the
    /// operator meant *something*, so the mistake is reported rather than
    /// silently reduced to "no discovery". Equal is fine: it pins the search's
    /// destination to its start, which is a coherent (if pointless) request.
    #[test]
    fn an_mtu_upper_bound_below_the_initial_mtu_is_rejected() {
        let msg = rejected(
            "[limits]\ninitial_mtu = 1350\nmtu_upper_bound = 1300",
            "mtu_upper_bound",
        );
        assert!(msg.contains("initial_mtu"), "{msg}");

        for body in [
            "[limits]\ninitial_mtu = 1350\nmtu_upper_bound = 1350",
            "[limits]\nmtu_upper_bound = 1452",
            // The example shipped 1464 from v0.4.5 to v1.1.1, so a host installed
            // from it carries that value, and an upgrade must still load it. The
            // ceiling is the IPv4 Ethernet limit.
            "[limits]\nmtu_upper_bound = 1464",
            "[limits]\nmtu_upper_bound = 1472",
        ] {
            assert_valid_apart_from_certs(&parse(body), body);
        }
    }

    /// A file that sets only `initial_mtu`, at any value it was allowed before
    /// the default ceiling fell to 1436, still loads.
    ///
    /// Before that change the default ceiling was 1452, equal to
    /// [`MAX_INITIAL_MTU`], so no legal `initial_mtu` could sit above it. An
    /// absent ceiling now resolves to the larger of the default and the
    /// starting size, so such a file probes nothing below where it starts.
    #[test]
    fn an_initial_mtu_above_the_default_ceiling_loads_without_a_ceiling() {
        let cfg = parse("[limits]\ninitial_mtu = 1452");
        assert_valid_apart_from_certs(&cfg, "initial_mtu = 1452 alone");
        assert_eq!(cfg.limits.mtu_upper_bound, None);
        assert_eq!(cfg.limits.mtu_upper_bound(), 1452);
    }

    /// The same pair with the ceiling written out is still the operator's
    /// mistake, and is still reported: the exemption is for an absent key only.
    #[test]
    fn an_explicit_default_ceiling_below_the_initial_mtu_is_rejected() {
        let msg = rejected(
            "[limits]\ninitial_mtu = 1440\nmtu_upper_bound = 1436",
            "mtu_upper_bound",
        );
        assert!(msg.contains("initial_mtu"), "{msg}");
    }

    /// 1500 is in the list for the same reason as in the `initial_mtu` test:
    /// the value is a UDP payload size, and an Ethernet frame's 1500 bytes is
    /// an IP packet, not a payload.
    #[test]
    fn an_mtu_upper_bound_above_the_ipv4_ethernet_ceiling_is_rejected() {
        for value in [MAX_MTU_UPPER_BOUND + 1, 1500, 9000, u16::MAX] {
            let msg = rejected(
                &format!("[limits]\nmtu_upper_bound = {value}"),
                "mtu_upper_bound",
            );
            assert!(
                msg.contains(&MAX_MTU_UPPER_BOUND.to_string()),
                "the ceiling must be named: {msg}"
            );
        }
    }

    #[test]
    fn an_initial_rtt_outside_the_sane_range_is_rejected() {
        for value in [0, 9, 10_001] {
            rejected(
                &format!("[limits]\ninitial_rtt_ms = {value}"),
                "initial_rtt_ms",
            );
        }

        // Both ends of the range, the default, and a tuned long-haul value.
        for value in [10, 150, 333, 10_000] {
            let cfg = parse(&format!("[limits]\ninitial_rtt_ms = {value}"));
            assert_valid_apart_from_certs(&cfg, &format!("initial_rtt_ms = {value}"));
        }
    }

    #[test]
    fn a_zero_stream_limit_or_idle_timeout_is_rejected() {
        for (body, field) in [
            ("[limits]\nmax_streams_bidi = 0", "max_streams_bidi"),
            ("[limits]\nmax_idle_timeout = 0", "max_idle_timeout"),
            ("[limits]\nmax_idle_timeout = 4000", "max_idle_timeout"),
        ] {
            rejected(body, field);
        }

        // The ceiling is a legal idle timeout, and the default keep-alive stays
        // well under half of it, so nothing else in the config objects to it.
        let cfg = parse(&format!(
            "[limits]\nmax_idle_timeout = {MAX_IDLE_TIMEOUT_CEILING}"
        ));
        assert_valid_apart_from_certs(&cfg, "an idle timeout of exactly the ceiling");

        rejected(
            &format!(
                "[limits]\nmax_idle_timeout = {}",
                MAX_IDLE_TIMEOUT_CEILING + 1
            ),
            "max_idle_timeout",
        );
    }

    /// The stream credit is work per handshake, so it has a ceiling (D86).
    ///
    /// quinn reserves a slot for every unit of it when the allowance is
    /// granted — once per connection since the pre-authentication clamp, at
    /// its first authenticated request — so an operator writing a large number
    /// here is not raising a limit but adding work to every connection. D86's
    /// per-handshake measurements ran 11 ms at the default 1024 to 7.3 s at a
    /// million, with no completed handshake within ten seconds at four
    /// million; `u32::MAX` is a config file away from any of those.
    #[test]
    fn a_stream_limit_past_the_ceiling_is_rejected() {
        for streams in [u32::MAX, MAX_STREAMS_BIDI_CEILING + 1] {
            rejected(
                &format!("[limits]\nmax_streams_bidi = {streams}"),
                "max_streams_bidi",
            );
        }

        let cfg = parse(&format!(
            "[limits]\nmax_streams_bidi = {MAX_STREAMS_BIDI_CEILING}"
        ));
        assert_valid_apart_from_certs(&cfg, "a stream limit of exactly the ceiling");
    }

    /// The two application timers share the transport timeout's ceiling: both
    /// are added to `Instant::now()` to make deadlines, so an unbounded `u64`
    /// of seconds would panic that arithmetic instead of meaning anything.
    #[test]
    fn the_session_and_connect_timers_share_the_ceiling() {
        for (body, field) in [
            (
                format!(
                    "[limits]\nudp_session_timeout = {}",
                    MAX_IDLE_TIMEOUT_CEILING + 1
                ),
                "udp_session_timeout",
            ),
            (
                format!(
                    "[limits]\nconnect_timeout = {}",
                    MAX_IDLE_TIMEOUT_CEILING + 1
                ),
                "connect_timeout",
            ),
            // The panic the ceiling exists to keep unreachable.
            (
                "[limits]\nudp_session_timeout = 9300000000000000000".to_string(),
                "udp_session_timeout",
            ),
        ] {
            rejected(&body, field);
        }

        // The ceiling itself is legal for both.
        let cfg = parse(&format!(
            "[limits]\nudp_session_timeout = {MAX_IDLE_TIMEOUT_CEILING}\n\
             connect_timeout = {MAX_IDLE_TIMEOUT_CEILING}"
        ));
        assert_valid_apart_from_certs(&cfg, "both timers at exactly the ceiling");
    }

    /// The positive half of D86: the largest legal configuration is one every
    /// deadline in this server can actually be built from.
    ///
    /// The tests above prove the ceiling *rejects*. That is only half a bound —
    /// a ceiling that rejected everything would pass them all — and the half it
    /// leaves out is the one an operator meets: a value the file accepts and
    /// the first connection then panics on. So this does the arithmetic itself,
    /// every sum a running server makes out of these four keys, on the largest
    /// values the file will take.
    ///
    /// It has teeth because of where it runs. `Duration`'s `Mul` and `Instant`'s
    /// `Add` panic on overflow rather than saturating, and `cargo test` is a
    /// debug build where integer overflow panics too — so a ceiling raised past
    /// what the arithmetic can carry fails here rather than in production, which
    /// is the whole point of having one.
    ///
    /// The factor is `crate::conn`'s own rather than a copy: a copy would go on
    /// agreeing with itself after the real one moved.
    #[test]
    fn every_deadline_can_be_built_from_the_largest_legal_configuration() {
        let cfg = parse(&format!(
            "[limits]\nmax_idle_timeout = {MAX_IDLE_TIMEOUT_CEILING}\n\
             udp_session_timeout = {MAX_IDLE_TIMEOUT_CEILING}\n\
             connect_timeout = {MAX_IDLE_TIMEOUT_CEILING}\n\
             keep_alive_interval = {}",
            MAX_IDLE_TIMEOUT_CEILING / 2 - 1
        ));
        assert_valid_apart_from_certs(&cfg, "every timer at exactly the ceiling");

        let now = tokio::time::Instant::now();

        // `crate::conn`: D76's absolute deadline, the only product of two
        // configured numbers in the tree.
        let silence = cfg.limits.max_idle_timeout() * crate::conn::SILENCE_FACTOR;
        let deadline = now + silence;
        assert!(deadline > now, "the D76 deadline did not move forward");

        // `crate::tunnel::udp`: the session deadline, armed at setup and pushed
        // out by every packet that crosses.
        assert!(now + cfg.limits.udp_session_timeout() > now);

        // `crate::tunnel::tcp`: the connect budget, and the same budget spent a
        // second time on the address list -- one request can hold both.
        let connect = cfg.limits.connect_timeout().expect("the ceiling is not 0");
        assert!(now + connect + connect > now);

        // `crate::quic`: the drain, and the transport parameters quinn is given.
        assert!(now + cfg.server.shutdown_grace() >= now);
        assert!(
            quinn::IdleTimeout::try_from(cfg.limits.max_idle_timeout()).is_ok(),
            "the ceiling is past what a QUIC idle timeout can carry"
        );

        // And the whole of it together, which is what a single unauthenticated
        // connection can spend: one idle timeout for the QUIC handshake, one for
        // the HTTP/3 handshake, then D76's two.
        let lifetime = cfg.limits.max_idle_timeout() * 2 + silence;
        assert!(
            now + lifetime > now,
            "an unauthenticated connection's whole lifetime overflows the clock"
        );
    }

    /// The drain period is a bound, so it has to stay one (D86).
    ///
    /// Unlike the timers above, an absurd grace period does not panic anything:
    /// `tokio::time::timeout` folds a duration it cannot add to `Instant::now()`
    /// into a deadline in the far future, so `u64::MAX` seconds was accepted and
    /// silently removed the bound `crate::quic`'s drain is built around — a
    /// `SIGTERM` would then wait on connections that may never end until the
    /// service manager's `SIGKILL` arrived, which is the ungraceful ending the
    /// grace period exists to avoid.
    #[test]
    fn an_unbounded_shutdown_grace_is_rejected() {
        for grace in [u64::MAX, MAX_SHUTDOWN_GRACE + 1] {
            let err = toml::from_str::<Config>(&format!(
                "[server]\nlisten = \"127.0.0.1:4433\"\ncert = \"/tmp/c.pem\"\n\
                 key = \"/tmp/k.pem\"\nshutdown_grace = {grace}\n"
            ))
            .expect("parses")
            .validate()
            .expect_err("a grace period past the ceiling must be rejected");
            assert!(err.to_string().contains("shutdown_grace"), "{err}");
        }

        // Both ends of the accepted range stay accepted: zero closes everything
        // at once, and the ceiling itself is a legal drain.
        for grace in [0, MAX_SHUTDOWN_GRACE] {
            let cfg: Config = toml::from_str(&format!(
                "[server]\nlisten = \"127.0.0.1:4433\"\ncert = \"/tmp/c.pem\"\n\
                 key = \"/tmp/k.pem\"\nshutdown_grace = {grace}\n"
            ))
            .expect("parses");
            assert_valid_apart_from_certs(&cfg, &format!("shutdown_grace = {grace}"));
            assert_eq!(
                cfg.server.shutdown_grace(),
                std::time::Duration::from_secs(grace)
            );
        }
    }

    #[test]
    fn port_zero_cannot_be_denied() {
        rejected(
            "[security]\ndenied_ports = [25, 0]",
            "security.denied_ports[1]",
        );
    }

    /// A list of names parses, and the trailing dot a client may or may not send
    /// is accepted on the configuration side too.
    #[test]
    fn expected_sni_accepts_the_names_a_client_hello_can_carry() {
        let cfg = parse(
            "[security]\nexpected_sni = [\"proxy.example\", \"alt.example.\", \"xn--80ak6aa92e.example\"]",
        );
        assert_eq!(cfg.security.expected_sni.len(), 3);
        assert_valid_apart_from_certs(&cfg, "a list of expected SNI names");
    }

    /// Every rejection names the entry, because a gate misconfigured this way
    /// fails silently by design: the server starts and no client can open it.
    #[test]
    fn expected_sni_rejects_names_no_client_hello_could_carry() {
        for (entry, wanted) in [
            ("\"\"", "is empty"),
            ("\".\"", "is empty"),
            // One trailing dot spells the root and is accepted above; a second
            // is an empty label, and the gate would hold the name in a form no
            // ClientHello can carry while the certificate check read it as the
            // name without either dot. Refused here instead (D106).
            ("\"host.tw..\"", "empty label"),
            ("\"host..\"", "empty label"),
            ("\"host..tw\"", "empty label"),
            ("\".host.tw\"", "empty label"),
            ("\"*.example\"", "wildcard"),
            ("\"proxy example\"", "contains"),
            ("\"[2001:db8::1]\"", "contains"),
            // RFC 6066 §3: "Literal IPv4 and IPv6 addresses are not permitted
            // in "HostName"." The dotted-quad passes the character class, so it
            // needs the rule of its own; the IPv6 forms are refused by the class
            // and are here to say that the rule covers them too.
            ("\"192.0.2.1\"", "IP address literal"),
            ("\"192.0.2.1.\"", "IP address literal"),
            ("\"2001:db8::1\"", "contains"),
            ("\"::1\"", "contains"),
        ] {
            let message = rejected(
                &format!("[security]\nexpected_sni = [{entry}]"),
                "security.expected_sni[0]",
            );
            assert!(message.contains(wanted), "{entry}: {message}");
        }

        let long = "a".repeat(MAX_EXPECTED_SNI + 1);
        rejected(
            &format!("[security]\nexpected_sni = [\"{long}\"]"),
            "security.expected_sni[0]",
        );
    }

    /// The length rule's own boundary, which the case above only reaches from
    /// the far side.
    ///
    /// [`MAX_EXPECTED_SNI`] bytes is the longest name a ClientHello can carry,
    /// so it has to be accepted; one more has to be refused, and the refusal has
    /// to print both the length it got and the limit, because that pair is what
    /// tells an operator whether the entry is a typo or a name no client could
    /// ever send. Nothing pinned the accepting side, so `>=` in place of the `>`
    /// refused the longest legal name and every test stayed green.
    #[test]
    fn the_longest_expected_sni_is_accepted_and_one_byte_more_is_not() {
        let longest = "a".repeat(MAX_EXPECTED_SNI);
        let cfg = parse(&format!("[security]\nexpected_sni = [\"{longest}\"]"));
        assert_valid_apart_from_certs(&cfg, "a name of exactly the maximum length");

        let over = "a".repeat(MAX_EXPECTED_SNI + 1);
        let message = rejected(
            &format!("[security]\nexpected_sni = [\"{over}\"]"),
            "security.expected_sni[0]",
        );
        assert!(
            message.contains(&format!("is {} bytes", MAX_EXPECTED_SNI + 1)),
            "the refusal must print the length it was given: {message}"
        );
        assert!(
            message.contains(&format!("at most {MAX_EXPECTED_SNI}")),
            "and the limit it broke: {message}"
        );
    }

    /// A socket buffer above the socket API's limit is refused, and the
    /// boundary is accepted.
    ///
    /// `socket2` converts the value with `size as c_int`, so `2147483648`
    /// truncates to a negative number and the kernel receives a different size
    /// than the file names. `0` stays the escape hatch that leaves the socket
    /// alone.
    #[test]
    fn socket_buffer_sizes_above_the_32_bit_api_limit_are_rejected() {
        for key in ["socket_recv_buffer", "socket_send_buffer"] {
            let message = rejected(&format!("[limits]\n{key} = 2147483648"), key);
            assert!(message.contains("2147483648"), "{message}");
            assert!(
                message.contains("2147483647"),
                "the refusal must name the API limit: {message}"
            );
        }

        // The largest value the API accepts is legal.
        for key in ["socket_recv_buffer", "socket_send_buffer"] {
            let cfg = parse(&format!("[limits]\n{key} = 2147483647"));
            assert_valid_apart_from_certs(&cfg, key);
        }
    }

    #[test]
    fn empty_alpn_is_rejected() {
        let cfg: Config = toml::from_str(
            r#"
            [server]
            listen = "127.0.0.1:4433"
            cert = "/tmp/c.pem"
            key = "/tmp/k.pem"
            alpn = []
            "#,
        )
        .expect("parses");
        let err = cfg.validate().expect_err("empty alpn must be rejected");
        assert!(err.to_string().contains("server.alpn"), "{err}");
    }

    /// An ALPN identifier is length-prefixed with a single byte, so 255 bytes is
    /// the longest one the wire format can count -- and the longest is legal.
    /// The first identifier that cannot be sent at all is the one after it.
    #[test]
    fn an_alpn_identifier_is_capped_at_what_its_length_prefix_can_count() {
        let cfg = parse(&format!("alpn = [\"{}\"]", "h".repeat(255)));
        assert_valid_apart_from_certs(&cfg, "an ALPN identifier of exactly 255 bytes");

        let msg = rejected(
            &format!("alpn = [\"{}\"]", "h".repeat(256)),
            "server.alpn[0]",
        );
        assert!(msg.contains("255"), "the limit must be named: {msg}");
    }

    #[test]
    fn missing_cert_file_is_reported_with_the_path() {
        let cfg: Config = toml::from_str(
            r#"
            [server]
            listen = "127.0.0.1:4433"
            cert = "/nonexistent/volto/cert.pem"
            key = "/nonexistent/volto/key.pem"
            "#,
        )
        .expect("parses");
        let err = cfg.validate().expect_err("missing cert must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("server.cert"), "{msg}");
        assert!(msg.contains("/nonexistent/volto/cert.pem"), "{msg}");
    }

    #[test]
    fn plain_log_levels_are_accepted() {
        for level in ["trace", "debug", "info", "warn", "error", "INFO"] {
            validate_log_level(level).unwrap_or_else(|e| panic!("{level} should be valid: {e}"));
        }
    }

    #[test]
    fn filter_directives_are_accepted() {
        validate_log_level("volto=debug,quinn=info").expect("directive list is valid");
    }

    #[test]
    fn a_level_typo_is_rejected_rather_than_silently_disabling_logs() {
        // EnvFilter would accept these as target names and then log nothing.
        for level in ["warning", "verbose", "definitely not a level"] {
            let err = validate_log_level(level).expect_err("{level} must be rejected");
            assert!(err.to_string().contains("log.level"), "{err}");
        }
    }

    #[test]
    fn a_malformed_filter_directive_is_rejected() {
        let err = validate_log_level("volto=notalevel").expect_err("must be rejected");
        assert!(err.to_string().contains("log.level"), "{err}");
    }

    proptest! {
        /// Property 1: validation answers. It never panics (D86).
        ///
        /// Every integer here is reachable from the file — TOML deserializes
        /// across the whole of each target type — so a `u64` that breaks the
        /// arithmetic *inside* `validate` is an operator's typo turning startup
        /// into an abort, and a `SIGHUP` into one on a running server. The
        /// property is deliberately weak on purpose: `Ok` or `Err`, but a third
        /// outcome is not allowed to exist.
        #[test]
        fn validation_of_any_limits_answers_rather_than_panicking(limits in any_limits()) {
            let config = config_with(limits);
            let _ = config.validate();
            // The warnings run over the same values, and are rendered on the
            // startup path right after validation.
            let _ = config.warnings();
        }

        /// The rewritten keep-alive comparison is the doubling it replaced.
        ///
        /// Same accept/reject boundary for every pair of integers, computed in
        /// arithmetic wide enough to hold the product the check no longer takes
        /// (D86). The idle timeout is generated inside its own range so that
        /// this is the only check that can object.
        #[test]
        fn the_keep_alive_ratio_keeps_the_boundary_its_doubling_had(
            max_idle_timeout in 1..=MAX_IDLE_TIMEOUT_CEILING,
            keep_alive_interval in around(MAX_IDLE_TIMEOUT_CEILING / 2),
        ) {
            let limits = Limits {
                max_idle_timeout,
                keep_alive_interval,
                ..Limits::default()
            };

            let rejected = config_with(limits)
                .validate()
                .is_err_and(|error| error.to_string().contains("keep_alive_interval"));

            let doubling = keep_alive_interval > 0
                && u128::from(keep_alive_interval) * 2 >= u128::from(max_idle_timeout);

            prop_assert_eq!(rejected, doubling);
        }
    }
}
