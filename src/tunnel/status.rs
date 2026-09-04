//! Refusing a request, and the RFC 9209 vocabulary a refusal is written in.
//!
//! Everything about *answering* a request this server will not tunnel: the
//! `Proxy-Status` error types, the failure a connect attempt carries out of its
//! address walk, and the handful of helpers that put a status on the wire under
//! the bound [`h3api::Stream::respond_within`] sets.
//!
//! The choice of which answer to send is not here. It is made where the fact
//! is known -- in [`super::admit_target`], in each tunnel's connect step, in
//! [`crate::conn`] -- and this module is what those choices are said in.

use tracing::debug;

use crate::h3api::{self, FieldValue, Fields, RespondError, Status, Stream};

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
    /// The resolver did not answer inside the `[limits] connect_timeout` budget.
    DnsTimeout,
    /// Every address the target resolved to is prohibited by policy.
    DestinationIpProhibited,
    /// The target is a legal destination but could not be reached.
    DestinationUnavailable,
    /// The target actively refused the connection.
    ConnectionRefused,
    /// The connection attempt timed out.
    ConnectionTimeout,
    /// This host could not spare the resources to reach the target at all.
    ///
    /// RFC 9209 §2.3.30 describes the type as "the intermediary encountered an
    /// internal error unrelated to the origin", which is exactly the case: the
    /// descriptor, the buffer or the source port ran out here, and nothing at
    /// all was learned about the destination. See `is_local_exhaustion`.
    ProxyInternalError,
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

impl Unreachable {
    /// The failure of a target that offered nothing to attempt.
    ///
    /// Both tunnel types walk a list of addresses and keep the last failure, so
    /// both need an answer for a list that was empty. Neither can actually reach
    /// it — [`super::admit_target`] never hands back an empty list — so this is the
    /// empty-list arm written out rather than asserted, and there is no hop to
    /// name in it.
    pub(crate) fn no_addresses() -> Self {
        Self {
            next_hop: None,
            error: std::io::Error::new(std::io::ErrorKind::InvalidInput, "no addresses to try"),
        }
    }
}

impl ProxyError {
    /// The complete `Proxy-Status` field value.
    ///
    /// RFC 9209 §2 shape: an identifier for this proxy, then parameters. Kept as
    /// static strings so building a refusal cannot itself fail.
    fn field_value(self) -> &'static str {
        match self {
            Self::DnsError => "volto; error=dns_error",
            Self::DnsTimeout => "volto; error=dns_timeout",
            Self::DestinationIpProhibited => "volto; error=destination_ip_prohibited",
            Self::DestinationUnavailable => "volto; error=destination_unavailable",
            Self::ConnectionRefused => "volto; error=connection_refused",
            Self::ConnectionTimeout => "volto; error=connection_timeout",
            Self::ProxyInternalError => "volto; error=proxy_internal_error",
            Self::ConnectionLimitReached => "volto; error=connection_limit_reached",
            Self::HttpRequestDenied => "volto; error=http_request_denied",
        }
    }

    /// This error as the field lines of a response.
    pub fn fields(self) -> Fields {
        let mut fields = Fields::new();
        fields.append(PROXY_STATUS, FieldValue::from_static(self.field_value()));
        fields
    }

    /// Whether this error may name the address it happened on.
    ///
    /// Only the three failures that are *about reaching a specific hop* qualify.
    /// RFC 9209 §2.1.2 allows the parameter anywhere, so this list is a privacy
    /// judgement rather than a syntactic one, and every exclusion is deliberate:
    ///
    /// * `dns_error` and `dns_timeout` — there is no hop to name. The lookup is
    ///   what failed, so any address in the response would be invented.
    /// * `destination_ip_prohibited` and `http_request_denied` — the request was
    ///   refused *by this proxy*, and echoing the resolved address would turn
    ///   every refusal into a lookup oracle: a client that cannot reach an
    ///   internal resolver could read this server's view of a name straight out
    ///   of the refusal. The policy exists to keep exactly that reachable-only-
    ///   from-here information in, so the refusal must not carry it out.
    /// * `connection_limit_reached`, and the 407 path, say nothing about a
    ///   target: they are verdicts on the client.
    /// * `proxy_internal_error` — nothing was contacted. The allocation this
    ///   host could not make failed before the first packet, so naming the
    ///   address would be reporting a hop that was never tried, and would hand
    ///   a client this server's resolution of a name it never reached (D89).
    fn discloses_next_hop(self) -> bool {
        matches!(
            self,
            Self::ConnectionRefused | Self::ConnectionTimeout | Self::DestinationUnavailable
        )
    }

    /// This error as the field lines of a response, naming the hop it happened on.
    ///
    /// The address is dropped unless `Self::discloses_next_hop` allows it, so a
    /// caller cannot leak one by passing it to the wrong error type.
    pub fn fields_with_next_hop(self, next_hop: Option<std::net::SocketAddr>) -> Fields {
        let Some(address) = next_hop.filter(|_| self.discloses_next_hop()) else {
            return self.fields();
        };

        // `<identifier>; error=<type>; next-hop="<address>"`. RFC 9209 §2.1.2
        // accepts a String or a Token; an IPv6 address needs its brackets, which
        // no Token may contain, so the String form is used for both families.
        let value = format!(
            "{}; next-hop={}",
            self.field_value(),
            sf_string(&address.to_string())
        );

        let mut fields = Fields::new();
        fields.append(
            PROXY_STATUS,
            // A rendered socket address is printable ASCII, so this cannot fail;
            // falling back to the parameterless value keeps that from being a
            // panic if it ever somehow did, which is the property the whole
            // refusal path is built on: refusing must never itself fail.
            FieldValue::parse(value.as_bytes())
                .unwrap_or_else(|| FieldValue::from_static(self.field_value())),
        );
        fields
    }

    /// The error type that best describes a failure to reach a target.
    ///
    /// The local failures are separated out first, because everything below
    /// them is a statement *about the target* and they are not one: see
    /// `is_local_exhaustion`.
    pub fn from_connect_error(error: &std::io::Error) -> Self {
        if is_local_exhaustion(error) {
            return Self::ProxyInternalError;
        }

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
    ///
    /// One address refusal never arrives here at all (decision D49, a carve-out
    /// from D11 rather than a revision of it): a target whose every resolved
    /// address is the unspecified one is a name the upstream resolver filtered,
    /// so it is answered with a 200 that closes on the spot — see
    /// `accept_then_close` — and carries no `Proxy-Status` field, because
    /// nothing about it is this proxy's verdict. Every refusal that is actually
    /// sent still follows the table below.
    pub fn recommended_status(self) -> Status {
        match self {
            Self::DnsError | Self::ConnectionRefused => Status::BAD_GATEWAY,
            Self::DnsTimeout | Self::ConnectionTimeout => Status::GATEWAY_TIMEOUT,
            Self::DestinationUnavailable | Self::ConnectionLimitReached => {
                Status::SERVICE_UNAVAILABLE
            }
            Self::DestinationIpProhibited | Self::HttpRequestDenied => Status::FORBIDDEN,
            Self::ProxyInternalError => Status::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Whether a socket could not be opened because *this host* had nothing left.
///
/// The distinction the RFC 9209 registry draws, and the one D89 is about.
/// `destination_unavailable` is defined as "the intermediary considers the next
/// hop to be unavailable; e.g., recent attempts to communicate with it may have
/// failed, or a health check may indicate that it is down" (§2.3.4) — a
/// statement about the target. None of the errors below is one. They are raised
/// by the allocation itself, before a single packet is addressed anywhere, so
/// what they report is that this process ran out of something:
///
/// * `EMFILE` / `ENFILE` — no descriptor, per process or system-wide. This is
///   the one an operator meets: `max_connections` x `max_targets_per_conn`
///   sockets is what `crate::quic`'s startup check sizes `RLIMIT_NOFILE`
///   against, and a host that is over it fails every `socket()` at once.
/// * `ENOBUFS` / `ENOMEM` — no kernel buffer or memory for another socket.
/// * `EADDRNOTAVAIL` — no source address left to bind, which on a connect to a
///   remote address is the ephemeral port range exhausted. A target address
///   that is itself unassignable cannot reach here: the unspecified address is
///   answered by decision D49 before any dial, and every other refusal by the
///   destination policy.
///
/// Reported as `proxy_internal_error` — "the intermediary encountered an
/// internal error unrelated to the origin" (§2.3.30) — which is the registry's
/// own name for this, rather than as a healthy destination being down.
///
/// Deliberately *not* here: `EACCES` and `EPERM`. A local firewall refusing the
/// route to one target is a fact about reaching that target, so it keeps
/// `destination_unavailable`; running out of descriptors is not.
///
/// A plain function over the OS error number, for the reason
/// `udp::is_per_packet_error` gives for the same shape: `std` maps none of
/// these onto an `ErrorKind` that is stable to match on, and both hosts this
/// server builds for define every constant.
fn is_local_exhaustion(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM | libc::EADDRNOTAVAIL)
    )
}

/// The field an RFC 9209 refusal explains itself in.
const PROXY_STATUS: &str = "proxy-status";

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

/// What became of a response written under [`h3api::Stream::respond_within`]'s
/// bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Responded {
    /// The response is on the stream.
    Sent,
    /// The write failed outright, and [`respond`] has already reported it.
    Failed,
    /// The write did not complete within its bound, and the stream has already
    /// been reset with H3_REQUEST_CANCELLED.
    ///
    /// [`Responded::landed`] is the follow-up three of the four callers share:
    /// it writes the line and answers that the write did not land. `tcp::run`
    /// keeps a `match` of its own, because a lapse there also leaves a target
    /// connection that RFC 9114 section 4.4 asks to be aborted, and an
    /// authority worth naming beside the line.
    Expired,
}

impl Responded {
    /// Whether the response reached the stream, reporting a lapse as `gave_up`.
    ///
    /// The follow-up is the same at every call site that has nothing else to
    /// clean up: a sent response is what the caller asked for, a failed one has
    /// already been reported by [`respond`], and a lapsed one owes one line.
    /// Written here so a fourth caller cannot answer it a fourth way.
    ///
    /// What a lapse leaves behind is still the caller's business. `false` says
    /// to stop; anything past that stays where the thing to undo is.
    pub(crate) fn landed(self, stream_id: u64, status: Status, gave_up: &'static str) -> bool {
        match self {
            Self::Sent => true,
            Self::Failed => false,
            Self::Expired => {
                debug!(stream_id, status = status.as_str(), "{gave_up}");
                false
            }
        }
    }
}

/// Sends `status` with `fields` under the bound
/// [`h3api::Stream::respond_within`] carries, reporting a write that fails
/// outright.
///
/// Every response this server sends with no tunnel behind it is written this
/// way, and for the reason the bound exists: a peer that grants no flow-control
/// credit never takes even the few bytes of a status line, and nothing else
/// would ever end the wait — whatever the caller does next does not exist until
/// this write returns. It is also why the count of authentication failures that
/// is meant to cost a guesser a handshake is recorded by the caller before this
/// call rather than after it (review H1/H2).
///
/// `failed` is the caller's own wording for a write that failed, kept a literal
/// at the call site so what this server can say still reads out of `src/`.
pub(crate) async fn respond(
    stream: &mut Stream,
    status: Status,
    fields: Fields,
    failed: &'static str,
) -> Responded {
    let stream_id = stream.id();

    match stream.respond_within(status, fields).await {
        Ok(()) => Responded::Sent,
        Err(RespondError::Failed(error)) => {
            debug!(stream_id, %error, "{failed}");
            Responded::Failed
        }
        Err(RespondError::Expired) => Responded::Expired,
    }
}

/// Answers a request we will not serve, then closes the stream tidily.
///
/// Any request body is unwanted, so the client is told to stop sending before
/// the status goes out.
pub(crate) async fn refuse(stream: &mut Stream, status: Status) {
    refuse_with(stream, status, Fields::new()).await;
}

/// Refuses a request, explaining why in an RFC 9209 `Proxy-Status` field.
///
/// The status is the error's own (`recommended_status`), so the table that
/// argues for each pairing — including D11's departure from the registry — is
/// the only thing that decides one.
pub(crate) async fn refuse_because(stream: &mut Stream, error: ProxyError) {
    refuse_with(stream, error.recommended_status(), error.fields()).await;
}

/// Refuses a request whose target could not be reached, naming the failed hop.
///
/// Both tunnel types end up here from their connect step, so the mapping from an
/// `io::Error` to a status and an RFC 9209 field is written once: the type
/// decides the status (`recommended_status`) and whether the address may be
/// disclosed (`discloses_next_hop`).
pub(crate) async fn refuse_unreachable(stream: &mut Stream, failure: &Unreachable) {
    let error = ProxyError::from_connect_error(&failure.error);
    refuse_with(
        stream,
        error.recommended_status(),
        error.fields_with_next_hop(failure.next_hop),
    )
    .await;
}

/// Refuses a request with an explicit set of response fields.
///
/// The write is bounded by one QUIC idle timeout and a lapsed one is abandoned
/// with a reset; [`respond`] carries the reasoning.
pub(crate) async fn refuse_with(stream: &mut Stream, status: Status, fields: Fields) {
    let stream_id = stream.id();
    stream.stop_receiving(h3api::NO_ERROR);

    if !respond(stream, status, fields, "failed to send error response")
        .await
        .landed(
            stream_id,
            status,
            "gave up on an error response the peer would not take",
        )
    {
        return;
    }

    if let Err(error) = stream.finish() {
        debug!(stream_id, %error, "failed to finish error response");
    }
}

/// Accepts a request with a 200 and closes the tunnel again immediately.
///
/// **Not a refusal, and deliberately not named like one.** The response carries
/// no `Proxy-Status` field and says nothing about a failure; `fields` is
/// whatever an accepted response of that tunnel type has to carry — nothing for
/// a TCP tunnel, the RFC 9297 `Capsule-Protocol` field for CONNECT-UDP.
///
/// Exactly one case uses it (decision D49): a target whose every resolved
/// address is the unspecified one, which is how a filtering resolver upstream
/// says "this name is blocked". That block is not this proxy's verdict, and an
/// error status makes the client attribute it here; a tunnel that opens and
/// closes at once is instead what every transport without an in-band refusal
/// channel shows for such a name, and what a target that accepts a connection
/// and hangs up immediately looks like on the wire.
///
/// Mechanically the close is the tidy one, and it is the same one an
/// established session ends with: STOP_SENDING with H3_NO_ERROR for anything
/// the client is still sending, then a FIN on the response stream. **Never a
/// reset** — RFC 9114 §4.4 reserves an abruptly terminated stream for a failure
/// of the target connection (H3_CONNECT_ERROR), which this is not, and a reset
/// would also be the one signal a client is entitled to read as "the proxy
/// broke".
///
/// The FIN that follows is this server's own choice rather than a rule read off
/// a spec. RFC 9297 §3.3 mentions a cleanly terminated capsule stream only to
/// rule on what a truncated last capsule means then — "If the receive side of a
/// stream carrying Capsules is terminated cleanly (for example, in HTTP/3 this
/// is defined as receiving a QUIC STREAM frame with the FIN bit set) and the
/// last Capsule on the stream was truncated, this MUST be treated as if it were
/// a malformed or incomplete message" — and says nothing about ending one on
/// purpose. RFC 9298 §3.1 ties the request stream to a socket that exists: a
/// UDP proxy "MUST keep the socket open while the request stream is open", and
/// when it closes a socket it "MUST close the request stream". No socket is
/// ever opened here, so neither sentence reaches this case. So this is this
/// server's own, and the FIN is what it picks: the ending an established
/// session gets, and the only one that says nothing went wrong.
///
/// The STOP_SENDING up front is the shape to keep. RFC 9114 §4.1 leaves the
/// choice open — a server may abort reading the request, or leave the client to
/// finish and close it — and the other shape was tried once (D59): 200 and FIN
/// only, then read and discard until the client closed, on the theory that a
/// stop landing on a client still writing its first bytes was what made one
/// client stack answer with a transport-level PROTOCOL_VIOLATION. A frame-level
/// A/B against that very stack showed the two shapes are indistinguishable to it
/// (it resets within a round trip either way) and production kept failing under
/// the drain, so the simpler shape came back. That fault is on the client's
/// side and does not depend on what this close sends.
pub(crate) async fn accept_then_close(stream: &mut Stream, fields: Fields) {
    let stream_id = stream.id();
    stream.stop_receiving(h3api::NO_ERROR);

    let sent = respond(
        stream,
        Status::OK,
        fields,
        "failed to send 200 for a tunnel closed on the spot",
    )
    .await;

    if !sent.landed(
        stream_id,
        Status::OK,
        "gave up on a 200 the peer would not take for a tunnel closed on the spot",
    ) {
        return;
    }

    if let Err(error) = stream.finish() {
        debug!(stream_id, %error, "failed to close a tunnel after its 200");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_status_values_are_rfc_9209_shaped() {
        for (error, expected) in [
            (ProxyError::DnsError, "dns_error"),
            (ProxyError::DnsTimeout, "dns_timeout"),
            (
                ProxyError::DestinationIpProhibited,
                "destination_ip_prohibited",
            ),
            (
                ProxyError::ConnectionLimitReached,
                "connection_limit_reached",
            ),
            (ProxyError::HttpRequestDenied, "http_request_denied"),
            (ProxyError::ProxyInternalError, "proxy_internal_error"),
        ] {
            let value = error.field_value();
            // `<identifier>; error=<type>`: the identifier names this proxy, the
            // parameter names the failure.
            assert_eq!(value, format!("volto; error={expected}"));

            let fields = error.fields();
            assert_eq!(
                fields.get(PROXY_STATUS).and_then(FieldValue::to_str),
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
            (ProxyError::DnsError, Status::BAD_GATEWAY),
            (ProxyError::DnsTimeout, Status::GATEWAY_TIMEOUT),
            (ProxyError::ConnectionRefused, Status::BAD_GATEWAY),
            (ProxyError::ConnectionTimeout, Status::GATEWAY_TIMEOUT),
            (
                ProxyError::DestinationUnavailable,
                Status::SERVICE_UNAVAILABLE,
            ),
            (
                ProxyError::ConnectionLimitReached,
                Status::SERVICE_UNAVAILABLE,
            ),
            (ProxyError::HttpRequestDenied, Status::FORBIDDEN),
            (ProxyError::DestinationIpProhibited, Status::FORBIDDEN),
            (
                ProxyError::ProxyInternalError,
                Status::INTERNAL_SERVER_ERROR,
            ),
        ] {
            assert_eq!(
                error.recommended_status(),
                expected,
                "{error:?} must answer {expected}"
            );
        }
    }

    /// A failure of *this host* is not a report about the target (D89).
    ///
    /// Every errno here is raised by the allocation itself, before anything is
    /// addressed anywhere, so none of them can be evidence that "the next hop
    /// [is] unavailable" — RFC 9209 §2.3.4's definition of the type they used
    /// to be reported as. `proxy_internal_error` is §2.3.30's "internal error
    /// unrelated to the origin", which is what happened.
    #[test]
    fn a_local_resource_failure_does_not_blame_the_target() {
        for code in [
            libc::EMFILE,
            libc::ENFILE,
            libc::ENOBUFS,
            libc::ENOMEM,
            libc::EADDRNOTAVAIL,
        ] {
            let error = std::io::Error::from_raw_os_error(code);
            assert_eq!(
                ProxyError::from_connect_error(&error),
                ProxyError::ProxyInternalError,
                "errno {code} ({error}) is this host's failure, not the target's"
            );
            assert_eq!(
                ProxyError::from_connect_error(&error).recommended_status(),
                Status::INTERNAL_SERVER_ERROR
            );
        }
    }

    /// The other side of that line: a failure that really is about reaching
    /// this target keeps saying so.
    ///
    /// `EACCES` and `EPERM` are the pair worth naming — a local firewall
    /// refusing the route to one destination is a fact about that destination,
    /// however local the component enforcing it is.
    #[test]
    fn a_failure_to_reach_the_target_still_blames_the_target() {
        for code in [
            libc::ECONNREFUSED,
            libc::ETIMEDOUT,
            libc::EHOSTUNREACH,
            libc::ENETUNREACH,
            libc::EACCES,
            libc::EPERM,
        ] {
            let error = std::io::Error::from_raw_os_error(code);
            assert_ne!(
                ProxyError::from_connect_error(&error),
                ProxyError::ProxyInternalError,
                "errno {code} ({error}) is about the target"
            );
        }
    }

    /// The three failures `from_connect_error` distinguishes must stay
    /// distinguishable in the response, which is the point of computing them.
    #[test]
    fn connect_failures_do_not_collapse_onto_one_status() {
        use std::io::{Error, ErrorKind};

        let statuses: Vec<Status> = [
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
                Status::BAD_GATEWAY,
                Status::GATEWAY_TIMEOUT,
                Status::SERVICE_UNAVAILABLE
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

    /// Reads the `Proxy-Status` field out of a field list.
    fn proxy_status(fields: &Fields) -> String {
        fields
            .get(PROXY_STATUS)
            .and_then(FieldValue::to_str)
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
                proxy_status(&error.fields_with_next_hop(Some(hop))),
                format!("{}; next-hop=\"192.0.2.7:443\"", error.field_value())
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
            ProxyError::DnsTimeout,
            ProxyError::DestinationIpProhibited,
            ProxyError::HttpRequestDenied,
            ProxyError::ConnectionLimitReached,
            // Nothing was contacted, so there is no hop this one could name
            // even though it is produced by the connect step (D89).
            ProxyError::ProxyInternalError,
        ] {
            let value = proxy_status(&error.fields_with_next_hop(Some(hop)));
            assert_eq!(
                value,
                error.field_value(),
                "{error:?} must stay exactly as it is without a next-hop"
            );
            assert!(
                !value.contains("10.1.2.3") && !value.contains("next-hop"),
                "{error:?} leaked an address: {value}"
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
                error.fields_with_next_hop(None).get(PROXY_STATUS),
                error.fields().get(PROXY_STATUS)
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
            proxy_status(&ProxyError::ConnectionRefused.fields_with_next_hop(Some(ipv6))),
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
}
