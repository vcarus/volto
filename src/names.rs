//! Host names: the list both SNI gates accept, and the rule for a string that
//! is a DNS host name.
//!
//! The socket gate ([`crate::gate`]), the ClientHello callback of the server's
//! TLS (`tls::awslc`), the `expected_sni` check in `config::validate` and the
//! certificate coverage warning (`tls::names_not_covered`) all judge the same
//! configured names, so the rules they share are written here once.

use rustls_pki_types::DnsName;

/// The hosts a handshake may name, compared the way a name is compared.
///
/// Held without the root dot and compared ignoring ASCII case, so that the
/// dot is removed once at load rather than once per Initial packet.
#[derive(Debug)]
pub struct Names {
    names: Vec<String>,
}

impl Names {
    /// The names the configuration file gave, each without its root dot.
    pub fn new(configured: &[String]) -> Self {
        Self {
            names: configured
                .iter()
                .map(|name| root_relative(name).to_owned())
                .collect(),
        }
    }

    /// Whether the gate is off, which an empty list is.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Whether `name` is one of them.
    ///
    /// DNS names are case-insensitive and a trailing dot is the same name
    /// spelled absolutely, so the case is ignored and the dot is removed on
    /// each side, the held side at load. Nothing else is: no wildcards, no
    /// suffix matching. A name that is not on the list is not this server's.
    pub fn accepts(&self, name: &str) -> bool {
        let name = root_relative(name);
        self.names
            .iter()
            .any(|held| held.eq_ignore_ascii_case(name))
    }

    /// Whether `name`, as a ClientHello carried it, is one of them: a name
    /// that is not UTF-8 is on no list, and any other is judged by
    /// [`Names::accepts`]. The rule both of the gate's judgements apply to a
    /// `server_name`.
    pub fn accepts_bytes(&self, name: &[u8]) -> bool {
        std::str::from_utf8(name).is_ok_and(|text| self.accepts(text))
    }
}

/// `name` without its trailing root dot, which is the same name spelled
/// relative to the root.
///
/// One dot and no more, because a second dot is an empty label rather than a
/// spelling of the root, and `Config::validate` refuses those. Its four
/// callers must agree: if one removed every trailing dot, `host.tw..` would be
/// held by the gate as a name no ClientHello can carry (RFC 6066 §3: "without
/// a trailing dot") and judged covered by the certificate, so the D106
/// warning would not fire.
pub(crate) fn root_relative(name: &str) -> &str {
    name.trim_suffix('.')
}

/// `name` as a DNS host name by the rustls-pki-types rules, or `None`.
///
/// The second SNI gate reads a client's name through this, and the
/// `expected_sni` check refuses an entry this refuses, so a configured name and
/// a name a client sends are judged by one rule. One trailing dot is accepted
/// and left out of the result; an IP literal is not a DNS name.
pub(crate) fn host_name(name: &str) -> Option<DnsName<'_>> {
    DnsName::try_from(name).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_matched_case_insensitively_and_without_its_root_dot() {
        let names = Names::new(&["Example.COM.".to_owned()]);

        assert!(names.accepts("example.com"));
        assert!(names.accepts("EXAMPLE.com"));
        assert!(names.accepts("example.com."));
        assert!(!names.accepts("www.example.com"));
        assert!(!names.accepts("example.co"));
        assert!(!names.accepts(""));
    }

    /// A name as a ClientHello carried it is judged as text, and a name that
    /// is not UTF-8 is on no list.
    #[test]
    fn a_name_in_bytes_is_judged_as_the_same_text() {
        let names = Names::new(&["example.com".to_owned()]);
        assert!(names.accepts_bytes(b"EXAMPLE.com."));
        assert!(!names.accepts_bytes(b"www.example.com"));
        assert!(!names.accepts_bytes(b"example.com\xff"));
        assert!(!names.accepts_bytes(b""));
    }

    /// One dot and no more, which is what makes the four callers agree.
    ///
    /// `trim_end_matches('.')` would answer `host.tw` for the last two of
    /// these, and a certificate check and a ClientHello match would then run
    /// on different strings.
    #[test]
    fn only_one_trailing_dot_is_the_root() {
        assert_eq!(root_relative("host.tw"), "host.tw");
        assert_eq!(root_relative("host.tw."), "host.tw");
        assert_eq!(root_relative("host.tw.."), "host.tw.");
        assert_eq!(root_relative("host.tw..."), "host.tw..");
        assert_eq!(root_relative("."), "");
        assert_eq!(root_relative(""), "");
        // Nothing else about the name is touched: not the case, not a leading
        // dot, not an inner one.
        assert_eq!(root_relative(".Host.TW"), ".Host.TW");
    }

    /// The host-name rule at its edges, as the second SNI gate and the
    /// `expected_sni` check both apply it. A second trailing dot is an empty
    /// label, not the root, so `host_name` must not strip a dot itself.
    #[test]
    fn a_host_name_is_judged_by_the_dns_name_rules() {
        let long = format!("{}.example", "a".repeat(63));
        for name in [
            "example.com",
            "_acme.example",
            "a-b.example",
            "123.example",
            &long,
        ] {
            assert_eq!(host_name(name).as_ref().map(AsRef::as_ref), Some(name));
        }
        assert_eq!(
            host_name("Host.TW.").as_ref().map(AsRef::as_ref),
            Some("Host.TW")
        );
        let too_long = format!("{}.example", "a".repeat(64));
        for name in [
            "",
            "host.tw..",
            ".host.tw",
            "-a.example",
            "a-.example",
            "host.123",
            "host.0x1f",
            "192.0.2.1",
            "::1",
            "a b.example",
            "h\nost",
            &too_long,
        ] {
            assert!(host_name(name).is_none(), "{name:?}");
        }
    }

    #[test]
    fn an_empty_list_is_the_gate_being_off() {
        assert!(Names::new(&[]).is_empty());
        assert!(!Names::new(&["a".to_owned()]).is_empty());

        let two = Names::new(&["a".to_owned(), "b".to_owned()]);
        assert!(two.accepts("a") && two.accepts("b") && !two.accepts("c"));
    }
}
