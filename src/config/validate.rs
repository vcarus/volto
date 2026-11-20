use std::ops::RangeInclusive;

use anyhow::{Context, Result, bail};

use super::{
    Auth, Config, INITIAL_RTT_RANGE_MS, Limits, MAX_EXPECTED_SNI, MAX_IDLE_TIMEOUT_CEILING,
    MAX_INITIAL_MTU, MAX_MTU_UPPER_BOUND, MAX_SHUTDOWN_GRACE, MAX_SOCKET_BUFFER,
    MAX_STREAMS_BIDI_CEILING, MAX_TARGETS_PER_CONN_CEILING, MIN_INITIAL_MTU, Security, Server,
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
        validate_server(&self.server)?;
        validate_limits(&self.limits)?;
        validate_auth(&self.auth)?;
        validate_security(&self.security)?;
        validate_require_ech(&self.security, &self.server)?;
        validate_certificate_paths(&self.server)?;

        Ok(())
    }
}

/// `security.require_ech` needs `server.ech_key`.
///
/// Without a key no ClientHello can open, so the gate would drop every client
/// without a word, which is the silent misconfiguration D106's validation
/// exists to refuse. Checked on the configuration, so startup, `--check-config`
/// and a reload all refuse it.
fn validate_require_ech(security: &Security, server: &Server) -> Result<()> {
    if security.require_ech && server.ech_key.is_none() {
        bail!(
            "security.require_ech = true needs server.ech_key: without an ECH key no \
             handshake can carry ECH, so every client would be dropped without a reply"
        );
    }
    Ok(())
}

/// Validates `[server]` apart from the certificate and key paths, which
/// [`validate_certificate_paths`] checks last.
fn validate_server(server: &Server) -> Result<()> {
    if server.alpn.is_empty() {
        bail!("server.alpn must list at least one protocol identifier");
    }
    for (i, id) in server.alpn.iter().enumerate() {
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

    Bound {
        key: "server.shutdown_grace",
        value: server.shutdown_grace,
        range: 0..=MAX_SHUTDOWN_GRACE,
        unit: " seconds",
        why: "a longer drain outlives the service manager's own kill timeout, and 0 \
              closes every tunnel at once",
    }
    .check()?;

    Ok(())
}

/// An integer key, the inclusive range its value must fall in, and why the
/// range ends where it does.
struct Bound {
    key: &'static str,
    value: u64,
    range: RangeInclusive<u64>,
    /// Appended to both ends of the range: `" seconds"`, `" bytes"`, or empty
    /// for a count.
    unit: &'static str,
    why: &'static str,
}

impl Bound {
    /// The one refusal every range in the configuration shares.
    fn check(&self) -> Result<()> {
        if !self.range.contains(&self.value) {
            bail!(
                "{} = {} must be between {} and {}{}; {}",
                self.key,
                self.value,
                self.range.start(),
                self.range.end(),
                self.unit,
                self.why
            );
        }
        Ok(())
    }
}

/// A socket buffer size as a [`Bound`] value. `usize` is never wider than 64
/// bits on a target this builds for, and a value that did not fit would still
/// be refused as past the ceiling.
fn wide(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

/// Validates `[limits]`.
///
/// Every key is a [`Bound`] except `keep_alive_interval`, which is judged
/// against `max_idle_timeout` by [`validate_keep_alive`]. The keys are checked
/// in the order listed, the keep-alive after the idle timeout it depends on.
fn validate_limits(limits: &Limits) -> Result<()> {
    let timers_and_counts = [
        Bound {
            key: "limits.udp_session_timeout",
            value: limits.udp_session_timeout,
            range: 1..=MAX_IDLE_TIMEOUT_CEILING,
            unit: " seconds",
            why: "0 is not a timeout, and the value is added to the clock to make a deadline",
        },
        Bound {
            key: "limits.connect_timeout",
            value: limits.connect_timeout,
            range: 0..=MAX_IDLE_TIMEOUT_CEILING,
            unit: " seconds",
            why: "the value is added to the clock to make a deadline, and 0 disables the budget",
        },
        Bound {
            key: "limits.max_targets_per_conn",
            value: limits.max_targets_per_conn.into(),
            range: 1..=MAX_TARGETS_PER_CONN_CEILING.into(),
            unit: "",
            why: "0 refuses every tunnel, and every tunnel costs a file descriptor",
        },
        Bound {
            key: "limits.max_streams_bidi",
            value: limits.max_streams_bidi.into(),
            range: 1..=MAX_STREAMS_BIDI_CEILING.into(),
            unit: "",
            why: "0 lets no tunnel open, and a stream slot is reserved for every unit of \
                  the credit when it is granted, so the whole value is paid by a \
                  connection's first authenticated request",
        },
        Bound {
            key: "limits.max_idle_timeout",
            value: limits.max_idle_timeout,
            range: 1..=MAX_IDLE_TIMEOUT_CEILING,
            unit: " seconds",
            why: "0 is not a timeout, and past an hour any relay's conntrack entry has \
                  expired long before",
        },
    ];
    let sizes = [
        Bound {
            key: "limits.initial_mtu",
            value: limits.initial_mtu.into(),
            range: MIN_INITIAL_MTU.into()..=MAX_INITIAL_MTU.into(),
            unit: " bytes",
            why: "QUIC needs at least the lower end (RFC 9000 §14), and the value is a UDP \
                  payload size, of which an Ethernet frame leaves at most the upper end \
                  over IPv6, so a larger handshake packet is dropped by the path with \
                  nothing to fall back to",
        },
        // The ceiling in effect. An absent key resolves to a value in this range
        // by construction (`Limits::mtu_upper_bound`), once `initial_mtu` is in
        // its own, so only a ceiling the file writes can be refused.
        Bound {
            key: "limits.mtu_upper_bound",
            value: limits.mtu_upper_bound().into(),
            range: limits.initial_mtu.into()..=MAX_MTU_UPPER_BOUND.into(),
            unit: " bytes",
            why: "discovery searches upward from limits.initial_mtu, so a ceiling below \
                  it describes a search that cannot happen, and an Ethernet frame leaves \
                  at most the upper end of UDP payload over IPv4",
        },
        Bound {
            key: "limits.initial_rtt_ms",
            value: limits.initial_rtt_ms,
            range: INITIAL_RTT_RANGE_MS,
            unit: " milliseconds",
            why: "it seeds the handshake retransmission timers, and a value below the real \
                  path RTT retransmits packets that were never lost",
        },
        // Refused rather than truncated on the way to the kernel; see
        // `MAX_SOCKET_BUFFER`.
        Bound {
            key: "limits.socket_recv_buffer",
            value: wide(limits.socket_recv_buffer),
            range: 0..=wide(MAX_SOCKET_BUFFER),
            unit: " bytes",
            why: SOCKET_BUFFER_WHY,
        },
        Bound {
            key: "limits.socket_send_buffer",
            value: wide(limits.socket_send_buffer),
            range: 0..=wide(MAX_SOCKET_BUFFER),
            unit: " bytes",
            why: SOCKET_BUFFER_WHY,
        },
    ];

    timers_and_counts.iter().try_for_each(Bound::check)?;
    validate_keep_alive(limits)?;
    sizes.iter().try_for_each(Bound::check)
}

/// The reason both socket buffer keys share.
const SOCKET_BUFFER_WHY: &str = "the value is passed to setsockopt as a signed 32-bit \
                                 integer, so a larger one is truncated before the kernel \
                                 sees it, and 0 keeps the operating system default";

/// `limits.keep_alive_interval` against `limits.max_idle_timeout`, the one
/// `[limits]` rule that is not a fixed range.
fn validate_keep_alive(limits: &Limits) -> Result<()> {
    // Strictly below half, not at it: at exactly half, losing a single
    // keep-alive packet is enough for the connection to time out. The relay in
    // front of this server is the reason keep-alives exist at all. Its UDP
    // conntrack entry expires on its own schedule (30s by default), and only a
    // keep-alive well inside both timeouts keeps the NAT mapping alive.
    //
    // Written as `interval >= ceil(idle / 2)` rather than the more obvious
    // `interval * 2 >= idle`: the two reject exactly the same pairs of
    // integers, and this one cannot overflow. The doubling overflows above
    // `u64::MAX / 2`, a value the file can hold, since TOML integers
    // deserialize across the whole target type's range, and the overflow would
    // panic inside this function in every build: the release profile keeps
    // overflow checks on for this crate (D86).
    if limits.keep_alive_interval > 0
        && limits.keep_alive_interval >= limits.max_idle_timeout.div_ceil(2)
    {
        // The ceiling on this field is 3600 seconds, so the halving is
        // always exact in an `f64`; `From` has no `u64` impl to say so.
        #[allow(clippy::as_conversions)]
        let half = limits.max_idle_timeout as f64 / 2.0;
        bail!(
            "limits.keep_alive_interval = {} must be less than half of \
             limits.max_idle_timeout = {} (i.e. below {}), so that a lost keep-alive \
             packet cannot let the connection time out",
            limits.keep_alive_interval,
            limits.max_idle_timeout,
            half
        );
    }

    Ok(())
}

/// Validates `[auth]`.
fn validate_auth(auth: &Auth) -> Result<()> {
    for (i, user) in auth.users.iter().enumerate() {
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
            // Failures are counted under the user-id as a log line carries
            // it, truncated at `logfmt::MAX_TOKEN`, so a longer name could
            // never be cleared by its own success, and its owner would lose
            // the connection at the `security.max_auth_failures`-th failure
            // however often it authenticates in between.
            //
            // The name is not echoed: it is not a secret, but it lives in
            // the same table as one, and nothing out of `[auth]` goes to
            // stderr (see `parse_error`). The index and the limit are what
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
        if let Some(first) = auth.users[..i]
            .iter()
            .position(|other| other.username == user.username)
        {
            // Not echoed either, for the reason given above: the two
            // indices name both entries, which is what it takes to find
            // and fix them.
            bail!("auth.users[{i}].username duplicates auth.users[{first}].username");
        }
    }

    Ok(())
}

/// Validates `[security]`.
fn validate_security(security: &Security) -> Result<()> {
    if let Some(i) = security.denied_ports.iter().position(|port| *port == 0) {
        bail!("security.denied_ports[{i}] is 0, which is not a usable port");
    }

    for (i, name) in security.expected_sni.iter().enumerate() {
        validate_expected_sni(i, name)?;
    }

    Ok(())
}

/// Checks that `server.cert` and `server.key` name files, that the leaf
/// certificate is one the server's TLS takes, and that `server.ech_key`, when
/// set, is a usable ECH key file. The only check that touches the filesystem,
/// so [`Config::validate`] runs it last.
fn validate_certificate_paths(server: &Server) -> Result<()> {
    if !server.cert.is_file() {
        bail!("server.cert = {} is not a file", server.cert.display());
    }
    if !server.key.is_file() {
        bail!("server.key = {} is not a file", server.key.display());
    }
    // A leaf the server's TLS would refuse at startup is refused here too, in
    // the same words (`tls::check_leaf`). A file that does not read as a
    // certificate chain at all is left to startup, which reports it.
    if let Ok(certs) = crate::tls::load_certs(&server.cert)
        && let Some(leaf) = certs.first()
    {
        crate::tls::check_leaf(leaf)?;
    }
    // Read and checked whole, not only found: the private key, the ECHConfig,
    // the public name and that the two halves belong together. A client holds
    // this ECHConfigList as typed in, so a file the server would refuse at
    // startup is refused here too, which is what `--check-config` and a
    // reload promise.
    if let Some(path) = &server.ech_key {
        crate::tls::EchKey::load(path)?;
    }

    Ok(())
}

/// Levels accepted as a bare `log.level` or `RUST_LOG`.
const LOG_LEVELS: [&str; 5] = ["trace", "debug", "info", "warn", "error"];

/// The target of this server's own log lines. Every module's target is this
/// followed by `::`.
const OWN_TARGET: &str = "volto";

/// Validates `log.level`.
///
/// Filter syntax is handed to `EnvFilter` first, then the value is held to
/// [`filter_refusal`], the rule `RUST_LOG` is held to as well.
fn validate_log_level(level: &str) -> Result<()> {
    if level.contains([',', '=', '[']) {
        tracing_subscriber::EnvFilter::try_new(level)
            .with_context(|| format!("log.level = {level:?} is not a valid filter"))?;
    }
    match filter_refusal("log.level", level) {
        Some(refusal) => bail!("{}", refusal.message()),
        None => Ok(()),
    }
}

/// Why [`filter_refusal`] refuses a log filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterRefusal {
    /// The filter turns this server's own lines off, and with them every
    /// configuration warning, the open-proxy warning among them. Refused at
    /// startup from either source, so the log cannot be switched off without
    /// an error.
    Silences(String),
    /// Empty, or a single word that is not one of the five level names: a
    /// typo such as `warning` is read by `EnvFilter` as a target name, and the
    /// digits `1` to `5` are left to the directive form (`volto=3`).
    /// `log.level` refuses it; a `RUST_LOG` of this kind is ignored with a
    /// warning and `log.level` applies.
    NotALevel(String),
}

impl FilterRefusal {
    /// The refusal, naming the source, the value and the accepted values.
    pub fn message(&self) -> &str {
        match self {
            Self::Silences(message) | Self::NotALevel(message) => message,
        }
    }
}

/// The rule `log.level` and `RUST_LOG` share, or `None` for a filter it
/// accepts. `source` names the key or the variable in the message.
///
/// A single word must be one of the five level names, in any letter case.
/// `off` and `0` are [`FilterRefusal::Silences`]; any other word is
/// [`FilterRefusal::NotALevel`]. A directive list is refused when it turns this
/// server's own lines off (`silences_own_lines`). The list's syntax is not
/// judged here: both callers ask `EnvFilter` first.
pub fn filter_refusal(source: &str, filter: &str) -> Option<FilterRefusal> {
    let bare = !filter.contains([',', '=', '[']);
    if bare && filter.is_empty() {
        return Some(FilterRefusal::NotALevel(format!(
            "{source} is empty, which enables no log line; use one of {LOG_LEVELS:?}"
        )));
    }
    if bare
        && LOG_LEVELS
            .iter()
            .any(|name| filter.eq_ignore_ascii_case(name))
    {
        return None;
    }
    if silences_own_lines(filter) && (!bare || is_off(filter)) {
        return Some(FilterRefusal::Silences(format!(
            "{source} = {filter:?} turns off this server's own log lines, and with them \
             every configuration warning, the open-proxy warning among them; use one of \
             {LOG_LEVELS:?}, or a directive list that leaves the {OWN_TARGET} target on, \
             such as \"info,quinn=off\""
        )));
    }
    if bare {
        return Some(FilterRefusal::NotALevel(format!(
            "{source} = {filter:?} is not one of {LOG_LEVELS:?}; for anything more \
             specific use a filter directive such as \"volto=debug,quinn=info\""
        )));
    }
    None
}

/// Whether a filter `EnvFilter` accepts disables an ERROR event at
/// [`OWN_TARGET`] or at one of its modules.
///
/// Follows `EnvFilter`'s static directives (tracing-subscriber 0.3.23,
/// `filter/env/directive.rs` and `filter/directive.rs`): a directive matches an
/// event whose target starts with the directive's target, the most specific
/// match decides (a longer target over a shorter one over none, and the later
/// of two equal ones), and an event that no directive matches is disabled. So
/// a list that names only other targets, such as a lone `quinn=off`, silences
/// this server as surely as `volto=off`. A directive with a span or field
/// filter (`[...]`) is not judged.
fn silences_own_lines(filter: &str) -> bool {
    // The specificity and the verdict of the directive that decides for
    // `OWN_TARGET` itself; `None` when no directive matches it yet.
    let mut deciding: Option<(Option<usize>, bool)> = None;
    for directive in filter.split(',').map(str::trim).filter(|d| !d.is_empty()) {
        if directive.contains('[') {
            continue;
        }
        let (target, off) = match directive.split_once('=') {
            Some((target, level)) => (Some(target), is_off(level)),
            None if directive
                .parse::<tracing::level_filters::LevelFilter>()
                .is_ok() =>
            {
                (None, is_off(directive))
            }
            // A bare target, at every level.
            None => (Some(directive), false),
        };
        match target {
            // More specific than any directive that matches `OWN_TARGET`, so it
            // decides for the modules it matches.
            Some(target) if target.starts_with("volto:") => {
                if off {
                    return true;
                }
            }
            Some(target) if !OWN_TARGET.starts_with(target) => {}
            _ => {
                let specificity = target.map(str::len);
                if deciding.is_none_or(|(current, _)| specificity >= current) {
                    deciding = Some((specificity, off));
                }
            }
        }
    }
    deciding.is_none_or(|(_, off)| off)
}

/// Whether a level, as written in a filter, is `off`: the word in any letter
/// case, or a number `LevelFilter` reads as 0. An empty level is `trace`.
fn is_off(level: &str) -> bool {
    !level.is_empty()
        && level
            .parse::<tracing::level_filters::LevelFilter>()
            .is_ok_and(|parsed| parsed == tracing::level_filters::LevelFilter::OFF)
}

/// Validates one `security.expected_sni` entry.
///
/// Rejected rather than normalised away, because every one of these is a name an
/// operator meant to type and none of them can ever match: a name that cannot
/// appear in a ClientHello turns the gate into a server nobody can reach. That
/// failure is silent by construction: the gate gives a refused handshake no
/// answer, so the operator would see a working service that no client can open.
///
//= https://www.rfc-editor.org/rfc/rfc6066#section-3
//# The hostname is represented as a byte
//# string using ASCII encoding without a trailing dot.
fn validate_expected_sni(index: usize, name: &str) -> Result<()> {
    let bare = crate::names::root_relative(name);

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

    // The second SNI gate reads the client's name through `names::host_name`
    // and treats a name it refuses as no name, so an entry that judge refuses
    // admits no client. The checks above refuse a subset of what it refuses and
    // keep their own messages; this is the judge itself, so the two cannot
    // disagree. What it adds: a label is at most 63 bytes, no label starts or
    // ends with `-`, and the last label is not a number (all digits, or `0x`
    // and hex digits).
    if crate::names::host_name(bare).is_none() {
        bail!(
            "security.expected_sni[{index}] = {name:?} is not a DNS host name the server's \
             TLS accepts, so the gate would refuse every handshake that names it: a label \
             is at most 63 bytes and does not start or end with '-', and the last label is \
             not a number"
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

    /// `require_ech` without a key would drop every client, so it is refused,
    /// naming both keys; off, or with a key, it is not.
    #[test]
    fn require_ech_without_an_ech_key_is_refused() {
        let message = rejected("[security]\nrequire_ech = true", "security.require_ech");
        assert!(message.contains("server.ech_key"), "{message}");

        assert_valid_apart_from_certs(&parse("[security]\nrequire_ech = false"), "require_ech off");
        assert_valid_apart_from_certs(
            &parse("ech_key = \"/tmp/ech.pem\"\n[security]\nrequire_ech = true"),
            "require_ech with a key",
        );
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
    /// The limit is exactly the log format's, and the message must name it
    /// without echoing the user-id.
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
    /// included, and doubling one above `u64::MAX / 2` overflows.
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
    /// An operator writing a large number here is not raising a limit but
    /// adding work to every connection; `MAX_STREAMS_BIDI_CEILING` gives the
    /// cost.
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
    /// Unlike the timers above, an absurd grace period does not panic anything;
    /// it removes the bound silently, as `MAX_SHUTDOWN_GRACE` describes.
    #[test]
    fn an_unbounded_shutdown_grace_is_rejected() {
        for grace in [u64::MAX, MAX_SHUTDOWN_GRACE + 1] {
            rejected(&format!("shutdown_grace = {grace}"), "shutdown_grace");
        }

        // Both ends of the accepted range stay accepted: zero closes everything
        // at once, and the ceiling itself is a legal drain.
        for grace in [0, MAX_SHUTDOWN_GRACE] {
            let cfg = parse(&format!("shutdown_grace = {grace}"));
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

        // Names the TLS layer's `DnsName` accepts, at the edges of its rules:
        // `_` anywhere in a label, an inner `-`, a 63-byte label, an all-digit
        // label that is not the last, and a last label that starts like a hex
        // number but is not one.
        let label = "a".repeat(63);
        for name in [
            "_acme.example",
            "host_.example",
            "a-b.example",
            &format!("{label}.example"),
            "123.example",
            "host.0xg",
        ] {
            assert!(
                rustls::pki_types::DnsName::try_from(name).is_ok(),
                "{name} is a premise of this test"
            );
            let cfg = parse(&format!("[security]\nexpected_sni = [\"{name}\"]"));
            assert_valid_apart_from_certs(&cfg, name);
        }
    }

    /// Every rejection names the entry, because a gate misconfigured this way
    /// fails silently by design: the server starts and no client can open it.
    #[test]
    fn expected_sni_rejects_names_no_client_hello_could_carry() {
        let long_label = format!("\"{}.example\"", "a".repeat(64));
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
            // What the TLS layer's `DnsName` refuses and the checks above do
            // not: such a name never reaches the second SNI gate as a name, so
            // the gate admits no client for it (R7-M1).
            ("\"proxy-.example\"", "not a DNS host name"),
            ("\"-proxy.example\"", "not a DNS host name"),
            ("\"host.123\"", "not a DNS host name"),
            ("\"host.0\"", "not a DNS host name"),
            ("\"host.0x1f\"", "not a DNS host name"),
            (long_label.as_str(), "not a DNS host name"),
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
    /// [`MAX_EXPECTED_SNI`] bytes in labels of at most 63 is the longest name a
    /// ClientHello can carry, so it has to be accepted; one more byte has to be
    /// refused, and the refusal has to print both the length it got and the
    /// limit, because that pair is what tells an operator whether the entry is a
    /// typo or a name no client could ever send. Nothing pinned the accepting
    /// side, so `>=` in place of the `>` refused the longest legal name and every
    /// test stayed green.
    #[test]
    fn the_longest_expected_sni_is_accepted_and_one_byte_more_is_not() {
        let label = |len: usize| "a".repeat(len);
        let longest = [label(63), label(63), label(63), label(61)].join(".");
        assert_eq!(longest.len(), MAX_EXPECTED_SNI);
        let cfg = parse(&format!("[security]\nexpected_sni = [\"{longest}\"]"));
        assert_valid_apart_from_certs(&cfg, "a name of exactly the maximum length");

        let over = [label(63), label(63), label(63), label(62)].join(".");
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
    /// See `MAX_SOCKET_BUFFER`.
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

    /// Every range in the configuration, end by end: each end is accepted, the
    /// integer past it is refused in the one shared wording, naming the key and
    /// both ends.
    ///
    /// The ranges are written out here rather than read from the table in
    /// `validate_limits`, so a row that moved is caught rather than followed.
    #[test]
    fn every_range_accepts_its_ends_and_refuses_one_past_each() {
        let ceiling = MAX_IDLE_TIMEOUT_CEILING;
        let buffer = u64::try_from(MAX_SOCKET_BUFFER).expect("fits");
        // (table, key, lower end, upper end, a line the lower end needs)
        let ranges: [(&str, &str, u64, u64, &str); 11] = [
            ("[server]", "shutdown_grace", 0, MAX_SHUTDOWN_GRACE, ""),
            ("[limits]", "udp_session_timeout", 1, ceiling, ""),
            ("[limits]", "connect_timeout", 0, ceiling, ""),
            (
                "[limits]",
                "max_targets_per_conn",
                1,
                MAX_TARGETS_PER_CONN_CEILING.into(),
                "",
            ),
            (
                "[limits]",
                "max_streams_bidi",
                1,
                MAX_STREAMS_BIDI_CEILING.into(),
                "",
            ),
            // An idle timeout of 1 leaves room for no keep-alive but none.
            (
                "[limits]",
                "max_idle_timeout",
                1,
                ceiling,
                "keep_alive_interval = 0",
            ),
            (
                "[limits]",
                "initial_mtu",
                MIN_INITIAL_MTU.into(),
                MAX_INITIAL_MTU.into(),
                "",
            ),
            // The lower end is the default `initial_mtu`.
            (
                "[limits]",
                "mtu_upper_bound",
                crate::config::DEFAULT_INITIAL_MTU.into(),
                MAX_MTU_UPPER_BOUND.into(),
                "",
            ),
            (
                "[limits]",
                "initial_rtt_ms",
                *INITIAL_RTT_RANGE_MS.start(),
                *INITIAL_RTT_RANGE_MS.end(),
                "",
            ),
            ("[limits]", "socket_recv_buffer", 0, buffer, ""),
            ("[limits]", "socket_send_buffer", 0, buffer, ""),
        ];

        for (table, key, low, high, companion) in ranges {
            // `parse` opens the body inside `[server]`, so a `[server]` key
            // goes in bare.
            let body = |value: u64| {
                let header = if table == "[server]" { "" } else { table };
                format!("{header}\n{key} = {value}\n{companion}")
            };
            for value in [low, high] {
                assert_valid_apart_from_certs(&parse(&body(value)), &body(value));
            }
            let past = low.checked_sub(1).into_iter().chain([high + 1]);
            for value in past {
                let message = rejected(&body(value), key);
                let section = &table[1..table.len() - 1];
                assert!(
                    message.starts_with(&format!(
                        "{section}.{key} = {value} must be between {low} and {high}"
                    )),
                    "one wording for every range: {message}"
                );
            }
        }
    }

    #[test]
    fn empty_alpn_is_rejected() {
        rejected("alpn = []", "server.alpn");
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

    /// The server's own log cannot be switched off: not as a bare level, not
    /// for the `volto` target or a module of it, and not by a list that
    /// matches none of this server's lines. Another crate may be turned off
    /// beside a level that keeps this server on.
    #[test]
    fn a_filter_that_silences_this_server_is_refused() {
        for level in [
            "off",
            "OFF",
            "Off",
            "0",
            "00",
            "volto=off",
            "volto=OFF",
            "volto=0",
            "vol=off",
            "volto::quic=off",
            "info,volto=off",
            "volto=info,volto::tunnel=off",
            "volto=off,volto::quic=info",
            "off,quinn=info",
            "quinn=off",
            "quinn=debug,rustls=info",
            "[handshake]=info",
        ] {
            let err = validate_log_level(level)
                .err()
                .unwrap_or_else(|| panic!("{level:?} must be refused"));
            std::assert_matches!(
                filter_refusal("log.level", level),
                Some(FilterRefusal::Silences(_)),
                "{level}"
            );
            let message = err.to_string();
            assert!(message.contains("log.level"), "{message}");
            assert!(message.contains(&format!("{level:?}")), "{message}");
            assert!(
                message.contains(&format!("{LOG_LEVELS:?}")),
                "the accepted values must be named: {message}"
            );
        }

        for level in [
            "info,quinn=off",
            "off,volto=info",
            "volto=info,quinn=off",
            "volto=",
            "volto,quinn=off",
            "volto=3",
            "warn,volto::tunnel=error",
            "info,[handshake]=off",
            "volto_other=off,info",
        ] {
            assert_eq!(filter_refusal("log.level", level), None, "{level}");
        }
    }

    /// The digits `LevelFilter` reads are refused as a bare `log.level`, as
    /// they were before the rule was shared with `RUST_LOG`; `0` is refused as
    /// `off`, and the others as words that are not level names.
    #[test]
    fn a_bare_digit_is_not_a_level_name() {
        std::assert_matches!(
            filter_refusal("log.level", "0"),
            Some(FilterRefusal::Silences(_))
        );
        for digit in ["1", "2", "3", "4", "5", "6"] {
            std::assert_matches!(
                filter_refusal("log.level", digit),
                Some(FilterRefusal::NotALevel(_)),
                "{digit}"
            );
        }
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
