//! Request routing, the per-connection context, and the tunnel implementations.

pub mod tcp;
pub mod udp;

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::debug;

use crate::auth::Authenticator;
use crate::config::Config;
use crate::h3api::{self, ConnectProtocol, Stream};
use crate::policy::Policy;

/// How a request should be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// CONNECT with no `:protocol`: a TCP tunnel (RFC 9114 §4.4).
    Tcp,
    /// CONNECT with `:protocol = connect-udp`: a UDP tunnel (RFC 9298).
    ConnectUdp,
    /// CONNECT with a `:protocol` this proxy does not implement.
    UnsupportedProtocol(&'static str),
    /// Not a CONNECT request at all. This server is a proxy, not an origin.
    NotConnect,
}

/// Classifies a request by method and `:protocol`.
pub fn route(req: &Request<()>) -> Route {
    if req.method() != Method::CONNECT {
        return Route::NotConnect;
    }

    match h3api::connect_protocol(req) {
        ConnectProtocol::Absent => Route::Tcp,
        ConnectProtocol::ConnectUdp => Route::ConnectUdp,
        ConnectProtocol::Unsupported(name) => Route::UnsupportedProtocol(name),
    }
}

/// Everything a request handler needs from the connection it arrived on.
///
/// Cloned per request — the cost is a handful of refcount bumps. The UDP-specific
/// members are here rather than in [`udp`] because a connection owns them
/// regardless of which tunnel type ends up using them: the datagram router is
/// started before the first request arrives.
#[derive(Clone)]
pub struct Context {
    /// The QUIC connection, used directly for datagram I/O.
    pub datagrams: quinn::Connection,
    /// Connection-wide Quarter Stream ID routing table.
    pub sessions: Arc<udp::SessionRegistry>,
    /// Whether the peer advertised `SETTINGS_H3_DATAGRAM = 1`.
    ///
    /// RFC 9297 §2.1.1 forbids sending QUIC datagrams when this is false; such
    /// sessions fall back to DATAGRAM capsules on the request stream. Shared with
    /// the connection so a late SETTINGS frame is still picked up.
    pub peer_datagrams: Arc<AtomicBool>,
    /// The credentials every request is checked against.
    pub auth: Arc<Authenticator>,
    /// Authentication failures seen on this connection so far.
    ///
    /// Connection-scoped on purpose: no shared table across connections means no
    /// lock, no eviction policy and no memory that an attacker can grow.
    pub auth_failures: Arc<AtomicU32>,
    /// Failures tolerated before the connection is closed. Zero disables it.
    pub max_auth_failures: u32,
    /// The peer's address, for logs that a fail2ban rule can act on.
    pub remote: std::net::SocketAddr,
    /// Which destinations this proxy may reach.
    pub policy: Arc<Policy>,
    /// How many tunnels this connection may hold open at once.
    pub quota: Arc<Quota>,
    /// How long a UDP session may sit idle.
    pub idle_timeout: Duration,
    /// Packets a UDP session may send before its target has answered.
    pub unanswered_packet_budget: u32,
}

impl Context {
    /// Builds the context for one accepted connection.
    pub fn new(config: &Config, datagrams: quinn::Connection) -> Self {
        Self {
            remote: datagrams.remote_address(),
            auth_failures: Arc::new(AtomicU32::new(0)),
            max_auth_failures: config.security.max_auth_failures,
            datagrams,
            sessions: Arc::new(udp::SessionRegistry::default()),
            peer_datagrams: Arc::new(AtomicBool::new(false)),
            auth: Arc::new(Authenticator::new(&config.auth)),
            policy: Arc::new(Policy::new(&config.security)),
            quota: Arc::new(Quota::new(config.limits.max_targets_per_conn)),
            idle_timeout: config.limits.udp_session_timeout(),
            unanswered_packet_budget: config.security.unanswered_packet_budget,
        }
    }

    /// Records an authentication failure, reporting whether that was one too many.
    ///
    /// Counts across the whole connection, so opening more streams does not reset
    /// the budget.
    pub(crate) fn record_auth_failure(&self) -> bool {
        let failures = self.auth_failures.fetch_add(1, Ordering::Relaxed) + 1;
        self.max_auth_failures > 0 && failures >= self.max_auth_failures
    }

    /// Whether QUIC datagrams may be sent to the peer right now.
    pub(crate) fn datagrams_allowed(&self) -> bool {
        self.peer_datagrams.load(Ordering::Relaxed)
    }
}

/// One connection's tunnel budget.
///
/// Every tunnel — TCP or UDP — costs a file descriptor on the target side, and a
/// single client multiplexes as many as it likes onto one QUIC connection. This
/// is the bound that keeps one client from exhausting the process fd limit, so
/// both tunnel types draw on the *same* budget rather than one each.
///
/// A semaphore rather than a counter, because it gives the M5 shutdown path the
/// other half for free: acquiring every permit at once is exactly "wait until all
/// tunnels have finished".
pub struct Quota {
    permits: Arc<Semaphore>,
    limit: u32,
}

/// One occupied tunnel slot, released when dropped.
///
/// Dropping is the *only* way a slot is returned, which is what makes every exit
/// path — response failure, idle timeout, reset, panic — leak-free by
/// construction, in the same spirit as [`udp::SessionRegistry`]'s guard.
pub type Slot = OwnedSemaphorePermit;

impl Quota {
    /// Creates a quota allowing `limit` concurrent tunnels.
    pub fn new(limit: u32) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(limit as usize)),
            limit,
        }
    }

    /// Takes a slot, or `None` when the connection is at its limit.
    pub fn acquire(&self) -> Option<Slot> {
        Arc::clone(&self.permits).try_acquire_owned().ok()
    }

    /// How many tunnels are open right now.
    pub fn live(&self) -> u32 {
        self.limit - self.permits.available_permits() as u32
    }

    /// Resolves once every tunnel on this connection has finished.
    ///
    /// Used by the graceful shutdown path: all permits back means all slots
    /// dropped. The caller is responsible for bounding the wait — a tunnel that
    /// never ends would otherwise hold shutdown open forever.
    pub async fn wait_until_idle(&self) {
        // The semaphore is never closed, so this cannot fail.
        let _all = self.permits.acquire_many(self.limit).await;
    }
}

/// An RFC 9209 proxy error type, for the `Proxy-Status` field of a refusal.
///
/// Only registered types (RFC 9209 §2.3.2) appear here. There is no registered
/// type for "that port is closed by policy", so a denied port is reported as
/// `http_request_denied` — the registry's general "denied per policy" type —
/// rather than stretching `destination_ip_prohibited` to cover something that is
/// not about the address at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyError {
    /// The target name could not be resolved.
    DnsError,
    /// Every address the target resolved to is prohibited by policy.
    DestinationIpProhibited,
    /// The target is a legal destination but could not be reached.
    DestinationUnavailable,
    /// The target actively refused the connection.
    ConnectionRefused,
    /// The connection attempt timed out.
    ConnectionTimeout,
    /// This connection already holds as many tunnels as it may.
    ConnectionLimitReached,
    /// The request is refused by policy.
    HttpRequestDenied,
}

/// A target that could not be reached, and the address the attempt failed on.
///
/// The address is what RFC 9209 §2.1.2 calls the `next-hop`: "the intermediary or
/// origin server selected (and used, if contacted) to obtain this response".
/// Carried out of the connect helpers rather than recomputed, because with
/// several resolved addresses only they know which one was tried last.
pub(crate) struct Unreachable {
    /// The last address attempted, or `None` if there was nothing to attempt.
    pub(crate) next_hop: Option<std::net::SocketAddr>,
    /// Why that attempt failed.
    pub(crate) error: std::io::Error,
}

impl ProxyError {
    /// The complete `Proxy-Status` field value.
    ///
    /// RFC 9209 §2 shape: an identifier for this proxy, then parameters. Kept as
    /// static strings so building a refusal cannot itself fail.
    fn field_value(self) -> &'static str {
        match self {
            Self::DnsError => "volto; error=dns_error",
            Self::DestinationIpProhibited => "volto; error=destination_ip_prohibited",
            Self::DestinationUnavailable => "volto; error=destination_unavailable",
            Self::ConnectionRefused => "volto; error=connection_refused",
            Self::ConnectionTimeout => "volto; error=connection_timeout",
            Self::ConnectionLimitReached => "volto; error=connection_limit_reached",
            Self::HttpRequestDenied => "volto; error=http_request_denied",
        }
    }

    /// The registered error type name, for logs.
    pub fn as_str(self) -> &'static str {
        // Everything after `error=`; the field value is the single source of truth
        // so the two cannot drift apart.
        self.field_value()
            .rsplit_once("error=")
            .expect("every field value carries an error parameter")
            .1
    }

    /// This error as a response header map.
    pub fn headers(self) -> HeaderMap {
        let mut headers = HeaderMap::with_capacity(1);
        headers.insert(
            HeaderName::from_static("proxy-status"),
            HeaderValue::from_static(self.field_value()),
        );
        headers
    }

    /// Whether this error may name the address it happened on.
    ///
    /// Only the three failures that are *about reaching a specific hop* qualify.
    /// RFC 9209 §2.1.2 allows the parameter anywhere, so this list is a privacy
    /// judgement rather than a syntactic one, and every exclusion is deliberate:
    ///
    /// * `dns_error` — there is no hop to name. The lookup is what failed, so any
    ///   address in the response would be invented.
    /// * `destination_ip_prohibited` and `http_request_denied` — the request was
    ///   refused *by this proxy*, and echoing the resolved address would turn
    ///   every refusal into a lookup oracle: a client that cannot reach an
    ///   internal resolver could read this server's view of a name straight out
    ///   of the refusal. The policy exists to keep exactly that reachable-only-
    ///   from-here information in, so the refusal must not carry it out.
    /// * `connection_limit_reached`, and the 407 path, say nothing about a
    ///   target: they are verdicts on the client.
    fn discloses_next_hop(self) -> bool {
        matches!(
            self,
            Self::ConnectionRefused | Self::ConnectionTimeout | Self::DestinationUnavailable
        )
    }

    /// This error as a response header map, naming the hop it happened on.
    ///
    /// The address is dropped unless [`Self::discloses_next_hop`] allows it, so a
    /// caller cannot leak one by passing it to the wrong error type.
    pub fn headers_with_next_hop(self, next_hop: Option<std::net::SocketAddr>) -> HeaderMap {
        let Some(address) = next_hop.filter(|_| self.discloses_next_hop()) else {
            return self.headers();
        };

        // `<identifier>; error=<type>; next-hop="<address>"`. RFC 9209 §2.1.2
        // accepts a String or a Token; an IPv6 address needs its brackets, which
        // no Token may contain, so the String form is used for both families.
        let value = format!(
            "{}; next-hop={}",
            self.field_value(),
            sf_string(&address.to_string())
        );

        let mut headers = HeaderMap::with_capacity(1);
        headers.insert(
            HeaderName::from_static("proxy-status"),
            // A rendered socket address is printable ASCII, so this cannot fail;
            // falling back to the parameterless value keeps that from being a
            // panic if it ever somehow did, which is the property the whole
            // refusal path is built on: refusing must never itself fail.
            HeaderValue::from_str(&value)
                .unwrap_or_else(|_| HeaderValue::from_static(self.field_value())),
        );
        headers
    }

    /// The error type that best describes a failure to reach a target.
    pub fn from_connect_error(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            std::io::ErrorKind::TimedOut => Self::ConnectionTimeout,
            _ => Self::DestinationUnavailable,
        }
    }

    /// The HTTP status code RFC 9209 §2.3.2 recommends for this error type.
    ///
    /// The registry pairs each type with a status, and following it costs
    /// nothing while telling an operator reading a log which failure it was: a
    /// 504 is a target that never answered, a 503 is one that could not be
    /// reached at all, and a 502 is one that actively refused.
    ///
    /// One deliberate departure: `destination_ip_prohibited` is recommended as
    /// 502, and this server answers 403. Decision D11 made both policy refusals
    /// — denied port and denied address — a 403, because they are refusals by
    /// this proxy rather than reports about an upstream hop, and a client that
    /// sees 502 would reasonably retry.
    pub fn recommended_status(self) -> StatusCode {
        match self {
            Self::DnsError | Self::ConnectionRefused => StatusCode::BAD_GATEWAY,
            Self::ConnectionTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::DestinationUnavailable | Self::ConnectionLimitReached => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::DestinationIpProhibited | Self::HttpRequestDenied => StatusCode::FORBIDDEN,
        }
    }
}

/// Renders `value` as a structured field String (RFC 8941 §3.3.3).
///
/// A String is DQUOTE-delimited, and inside it only DQUOTE and backslash are
/// escaped. A rendered socket address contains neither, so this never actually
/// escapes anything today — it exists so that the one field value this server
/// builds at runtime is correct by construction rather than by argument about its
/// inputs.
fn sf_string(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        if character == '"' || character == '\\' {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

/// Answers a request we will not serve, then closes the stream tidily.
///
/// Any request body is unwanted, so the client is told to stop sending before
/// the status goes out.
pub(crate) async fn refuse(stream: &mut Stream, status: StatusCode, stream_id: u64) {
    refuse_with(stream, status, HeaderMap::new(), stream_id).await;
}

/// Refuses a request, explaining why in an RFC 9209 `Proxy-Status` field.
pub(crate) async fn refuse_because(
    stream: &mut Stream,
    status: StatusCode,
    error: ProxyError,
    stream_id: u64,
) {
    refuse_with(stream, status, error.headers(), stream_id).await;
}

/// Refuses a request whose target could not be reached, naming the failed hop.
///
/// Both tunnel types end up here from their connect step, so the mapping from an
/// `io::Error` to a status and an RFC 9209 field is written once: the type
/// decides the status (`recommended_status`) and whether the address may be
/// disclosed (`discloses_next_hop`).
pub(crate) async fn refuse_unreachable(stream: &mut Stream, failure: &Unreachable, stream_id: u64) {
    let error = ProxyError::from_connect_error(&failure.error);
    refuse_with(
        stream,
        error.recommended_status(),
        error.headers_with_next_hop(failure.next_hop),
        stream_id,
    )
    .await;
}

/// Refuses a request with an explicit set of response headers.
pub(crate) async fn refuse_with(
    stream: &mut Stream,
    status: StatusCode,
    headers: HeaderMap,
    stream_id: u64,
) {
    stream.stop_receiving(h3api::NO_ERROR);

    if let Err(error) = stream.respond_with(status, headers).await {
        debug!(stream_id, %error, "failed to send error response");
        return;
    }
    if let Err(error) = stream.finish().await {
        debug!(stream_id, %error, "failed to finish error response");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_status_values_are_rfc_9209_shaped() {
        for (error, expected) in [
            (ProxyError::DnsError, "dns_error"),
            (
                ProxyError::DestinationIpProhibited,
                "destination_ip_prohibited",
            ),
            (
                ProxyError::ConnectionLimitReached,
                "connection_limit_reached",
            ),
            (ProxyError::HttpRequestDenied, "http_request_denied"),
        ] {
            assert_eq!(error.as_str(), expected);

            let value = error.field_value();
            // `<identifier>; error=<type>`: the identifier names this proxy, the
            // parameter names the failure.
            assert_eq!(value, format!("volto; error={expected}"));

            let headers = error.headers();
            assert_eq!(
                headers.get("proxy-status").and_then(|v| v.to_str().ok()),
                Some(value)
            );
        }
    }

    /// RFC 9209 §2.3.2 pairs each registered type with a recommended status.
    /// Every pairing here is the registry's, except the documented D11 choice of
    /// 403 for a destination the policy refuses.
    #[test]
    fn every_error_type_carries_its_recommended_status() {
        for (error, expected) in [
            (ProxyError::DnsError, StatusCode::BAD_GATEWAY),
            (ProxyError::ConnectionRefused, StatusCode::BAD_GATEWAY),
            (ProxyError::ConnectionTimeout, StatusCode::GATEWAY_TIMEOUT),
            (
                ProxyError::DestinationUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                ProxyError::ConnectionLimitReached,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (ProxyError::HttpRequestDenied, StatusCode::FORBIDDEN),
            (ProxyError::DestinationIpProhibited, StatusCode::FORBIDDEN),
        ] {
            assert_eq!(
                error.recommended_status(),
                expected,
                "{} must answer {expected}",
                error.as_str()
            );
        }
    }

    /// The three failures `from_connect_error` distinguishes must stay
    /// distinguishable in the response, which is the point of computing them.
    #[test]
    fn connect_failures_do_not_collapse_onto_one_status() {
        use std::io::{Error, ErrorKind};

        let statuses: Vec<StatusCode> = [
            ErrorKind::ConnectionRefused,
            ErrorKind::TimedOut,
            ErrorKind::PermissionDenied,
        ]
        .into_iter()
        .map(|kind| ProxyError::from_connect_error(&Error::from(kind)).recommended_status())
        .collect();

        assert_eq!(
            statuses,
            vec![
                StatusCode::BAD_GATEWAY,
                StatusCode::GATEWAY_TIMEOUT,
                StatusCode::SERVICE_UNAVAILABLE
            ]
        );
    }

    #[test]
    fn connect_errors_map_onto_registered_types() {
        use std::io::{Error, ErrorKind};

        assert_eq!(
            ProxyError::from_connect_error(&Error::from(ErrorKind::ConnectionRefused)),
            ProxyError::ConnectionRefused
        );
        assert_eq!(
            ProxyError::from_connect_error(&Error::from(ErrorKind::TimedOut)),
            ProxyError::ConnectionTimeout
        );
        assert_eq!(
            ProxyError::from_connect_error(&Error::from(ErrorKind::PermissionDenied)),
            ProxyError::DestinationUnavailable
        );
    }

    /// Reads the `Proxy-Status` field out of a header map.
    fn proxy_status(headers: &HeaderMap) -> String {
        headers
            .get("proxy-status")
            .and_then(|value| value.to_str().ok())
            .expect("every refusal carries a Proxy-Status field")
            .to_owned()
    }

    /// RFC 9209 §2.1.2's `next-hop` "identifies the intermediary or origin server
    /// selected (and used, if contacted) to obtain this response" — so it belongs
    /// on the failures that are about reaching one, and nowhere else.
    #[test]
    fn only_failures_to_reach_a_hop_name_it() {
        let hop: std::net::SocketAddr = "192.0.2.7:443".parse().expect("address");

        for error in [
            ProxyError::ConnectionRefused,
            ProxyError::ConnectionTimeout,
            ProxyError::DestinationUnavailable,
        ] {
            assert_eq!(
                proxy_status(&error.headers_with_next_hop(Some(hop))),
                format!(
                    "volto; error={}; next-hop=\"192.0.2.7:443\"",
                    error.as_str()
                )
            );
        }
    }

    /// The exclusions, and the reason for the middle two: a policy refusal that
    /// echoed the resolved address would hand the client this server's view of a
    /// name it is not allowed to reach — an internal DNS mapping, read straight
    /// out of the refusal. `dns_error` has no hop to name at all.
    #[test]
    fn refusals_that_are_not_about_a_hop_never_echo_an_address() {
        let hop: std::net::SocketAddr = "10.1.2.3:53".parse().expect("address");

        for error in [
            ProxyError::DnsError,
            ProxyError::DestinationIpProhibited,
            ProxyError::HttpRequestDenied,
            ProxyError::ConnectionLimitReached,
        ] {
            let value = proxy_status(&error.headers_with_next_hop(Some(hop)));
            assert_eq!(
                value,
                error.field_value(),
                "{} must stay exactly as it is without a next-hop",
                error.as_str()
            );
            assert!(
                !value.contains("10.1.2.3") && !value.contains("next-hop"),
                "{} leaked an address: {value}",
                error.as_str()
            );
        }
    }

    /// No address to report — an empty candidate list — leaves the field as the
    /// plain one, byte for byte.
    #[test]
    fn a_missing_address_leaves_the_field_untouched() {
        for error in [
            ProxyError::ConnectionRefused,
            ProxyError::ConnectionTimeout,
            ProxyError::DestinationUnavailable,
        ] {
            assert_eq!(
                error.headers_with_next_hop(None).get("proxy-status"),
                error.headers().get("proxy-status")
            );
        }
    }

    /// RFC 9209 §2.1.2 accepts a String or a Token, and RFC 8941 §3.3.3 defines
    /// the String: DQUOTE-delimited, with DQUOTE and backslash escaped. An IPv6
    /// hop is the case that decides it — its brackets are not Token characters.
    #[test]
    fn a_next_hop_is_a_quoted_structured_field_string() {
        let ipv6: std::net::SocketAddr = "[2001:db8::1]:53".parse().expect("address");
        assert_eq!(
            proxy_status(&ProxyError::ConnectionRefused.headers_with_next_hop(Some(ipv6))),
            "volto; error=connection_refused; next-hop=\"[2001:db8::1]:53\""
        );

        // The escaping rule itself, on inputs a socket address cannot produce but
        // the encoder must still handle.
        assert_eq!(sf_string("192.0.2.7:443"), "\"192.0.2.7:443\"");
        assert_eq!(sf_string("[2001:db8::1]:53"), "\"[2001:db8::1]:53\"");
        assert_eq!(sf_string(r#"a"b"#), r#""a\"b""#);
        assert_eq!(sf_string(r"a\b"), r#""a\\b""#);
        assert_eq!(sf_string(""), "\"\"");
    }

    #[tokio::test]
    async fn a_quota_hands_out_exactly_its_limit() {
        let quota = Quota::new(2);
        assert_eq!(quota.live(), 0);

        let first = quota.acquire().expect("first slot");
        let second = quota.acquire().expect("second slot");
        assert_eq!(quota.live(), 2);
        assert!(quota.acquire().is_none(), "the limit must be enforced");

        // Slots are returned by dropping them, on every path.
        drop(first);
        assert_eq!(quota.live(), 1);
        let third = quota.acquire().expect("a freed slot is reusable");
        assert!(quota.acquire().is_none());

        drop(second);
        drop(third);
        assert_eq!(quota.live(), 0);
    }

    #[tokio::test]
    async fn waiting_for_idle_resolves_when_the_last_slot_goes() {
        let quota = Arc::new(Quota::new(4));
        let slot = quota.acquire().expect("slot");

        // Still busy: the wait must not resolve yet.
        let idle = quota.clone();
        let waiter = tokio::spawn(async move { idle.wait_until_idle().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), async {})
                .await
                .is_ok(),
            "the timer works"
        );
        assert!(!waiter.is_finished());

        drop(slot);
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("idle within the timeout")
            .expect("waiter task");
    }
}
