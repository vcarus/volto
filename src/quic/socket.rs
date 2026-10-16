//! The endpoint socket's buffer sizes and the file descriptor budget check.

use std::io;

use socket2::SockRef;
use tracing::{debug, warn};

#[cfg(doc)]
use super::{ReloadHandle, Server};

/// Warns when the fd limit leaves no room for the configured tunnel quota.
///
/// Every tunnel costs one descriptor, and the quota is per connection, so the
/// budget the process actually has to meet is
/// `max_connections * max_targets_per_conn` — not one connection's share of it.
/// The two keys are halves of one number and only their product can be compared
/// against `RLIMIT_NOFILE`; checking one connection's worth was checking a bound
/// no adversary is under, since a client holding credentials may open
/// `max_connections` of them (review M7).
///
/// fd exhaustion is not a graceful failure mode. It degrades rather than
/// crashes here — a `socket()` that fails becomes one refused tunnel — but it
/// does so for every connection at once and for anything else the process needs
/// a descriptor for, a certificate reload included (spec §5.2).
pub(super) fn warn_if_fd_budget_is_tight(limits: &crate::config::Limits) {
    // `None` is `RLIM_INFINITY` rather than a failed read (the call cannot
    // fail): no ceiling means no budget to be tight against, so the check has
    // passed rather than been skipped.
    let Some(limit) = crate::net::fd_soft_limit() else {
        debug!("RLIMIT_NOFILE is unlimited; the fd budget cannot be exceeded");
        return;
    };

    if fd_budget_is_tight(limit, limits.max_connections, limits.max_targets_per_conn) {
        warn!(
            log_id = "bt1hbfco",
            fd_soft_limit = limit,
            max_connections = limits.max_connections,
            max_targets_per_conn = limits.max_targets_per_conn,
            needed = fd_budget(limits.max_connections, limits.max_targets_per_conn),
            "RLIMIT_NOFILE leaves no room for limits.max_connections x \
             limits.max_targets_per_conn: clients at their quotas can exhaust the \
             process. Raise LimitNOFILE (systemd) or lower either limit."
        );
    }
}

/// Whether `limit` descriptors are too few for every connection at its full
/// quota.
///
/// Split out from the warning so the arithmetic is testable without changing the
/// process's actual limit.
fn fd_budget_is_tight(limit: u64, max_connections: u32, max_targets_per_conn: u32) -> bool {
    limit < fd_budget(max_connections, max_targets_per_conn)
}

/// Descriptors the configured limits allow to be open at once.
///
/// `max_connections = 0` means no cap on connections at all, which makes the
/// product meaningless; the check falls back to one connection's quota there,
/// which is the weakest claim that is still true. `Config::warnings` already
/// says what removing that cap costs, and this is not the place to say it twice.
fn fd_budget(max_connections: u32, max_targets_per_conn: u32) -> u64 {
    let connections = u64::from(max_connections.max(1));
    connections * u64::from(max_targets_per_conn) + FD_HEADROOM
}

/// One direction of the endpoint socket's buffer, with the names its messages
/// need.
///
/// The two directions differ only in which setsockopt they use and which sysctl
/// caps them, so they are one code path with this as the parameter rather than
/// two near-identical ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SocketBuffer {
    /// `SO_RCVBUF`: what the kernel holds for us until the endpoint reads it.
    Recv,
    /// `SO_SNDBUF`: what the kernel holds for us until the interface sends it.
    Send,
}

impl SocketBuffer {
    /// The `[limits]` key that asks for this buffer.
    pub(super) fn key(self) -> &'static str {
        match self {
            Self::Recv => "limits.socket_recv_buffer",
            Self::Send => "limits.socket_send_buffer",
        }
    }

    /// The Linux sysctl that caps what may be asked for.
    fn ceiling_sysctl(self) -> &'static str {
        match self {
            Self::Recv => "net.core.rmem_max",
            Self::Send => "net.core.wmem_max",
        }
    }

    /// Asks the kernel for `size` bytes in this direction.
    fn set(self, socket: &SockRef<'_>, size: usize) -> io::Result<()> {
        match self {
            Self::Recv => socket.set_recv_buffer_size(size),
            Self::Send => socket.set_send_buffer_size(size),
        }
    }

    /// Reads back what the kernel holds in this direction.
    fn get(self, socket: &SockRef<'_>) -> io::Result<usize> {
        match self {
            Self::Recv => socket.recv_buffer_size(),
            Self::Send => socket.send_buffer_size(),
        }
    }
}

/// The socket buffer sizes `[limits]` asked for, as configured rather than as
/// granted.
///
/// Kept from [`Server::bind`] to [`ReloadHandle`] for the same reason `listen`
/// is: all three keys are applied to the socket when it is created, a reload
/// never rebinds, and a reload carrying new values for them therefore applies
/// nothing. The operator being told is the whole point, so the reload compares a
/// reloaded file against these and warns per direction that differs. The granted
/// sizes in [`SocketBuffers`] cannot serve here, because Linux reports back
/// double what it granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RequestedBuffers {
    /// `limits.socket_recv_buffer` as the file that bound the socket spelled it.
    pub(super) recv: usize,
    /// `limits.socket_send_buffer`, likewise.
    pub(super) send: usize,
}

/// What the kernel reports the endpoint socket's buffers are, after being asked.
///
/// Carried from [`Server::bind`] to [`Server::run`] for one reason: the startup
/// line prints them. They are also the only place the granted sizes are visible
/// at all, since neither quinn nor this module reads them again.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct SocketBuffers {
    /// `SO_RCVBUF` as the kernel reports it, or `None` if it would not say.
    pub(super) recv: Option<usize>,
    /// `SO_SNDBUF` as the kernel reports it, or `None` if it would not say.
    pub(super) send: Option<usize>,
}

impl SocketBuffers {
    /// Asks for the configured sizes and reads back what the kernel granted.
    pub(super) fn request(socket: &std::net::UdpSocket, limits: &crate::config::Limits) -> Self {
        let socket = SockRef::from(socket);

        Self {
            recv: request_socket_buffer(&socket, SocketBuffer::Recv, limits.socket_recv_buffer),
            send: request_socket_buffer(&socket, SocketBuffer::Send, limits.socket_send_buffer),
        }
    }
}

/// Asks the kernel for `requested` bytes of buffer and reports what it granted.
///
/// The socket half of the pair; [`socket_buffer_was_capped`] is the judgement,
/// kept separate so both of its answers can be tested without a socket. Every
/// fact that depends on the direction lives on [`SocketBuffer`], so this
/// function does not branch on the variant at all.
///
/// Nothing here is fatal, and that is deliberate. A refused `setsockopt` leaves
/// the socket exactly where it was — on the operating system's default, which is
/// where every release before this one ran — so refusing to start over it would
/// trade a working server for a tuning preference.
///
/// Two ways a host can decline. It can clamp, which is what both hosts we build
/// for do: Linux at `net.core.rmem_max`, macOS at `kern.ipc.maxsockbuf` (8 MiB
/// by default, measured on Darwin 24). Or it can fail the call outright, which
/// older macOS releases are documented to do above the same ceiling and which
/// costs nothing to handle. Both endings are warned about and neither stops the
/// server; `0` asks for nothing at all, the escape hatch for a host whose
/// operator has already sized these elsewhere.
fn request_socket_buffer(
    socket: &SockRef<'_>,
    which: SocketBuffer,
    requested: usize,
) -> Option<usize> {
    let refused = if requested == 0 {
        false
    } else {
        match which.set(socket, requested) {
            Ok(()) => false,
            Err(error) => {
                warn!(
                    log_id = "djabk3lf",
                    key = which.key(),
                    requested,
                    %error,
                    "the kernel refused the UDP socket buffer {} asks for, so the socket \
                     keeps the operating system default. Lower the value, or raise this \
                     host's ceiling ({} on Linux, kern.ipc.maxsockbuf on macOS).",
                    which.key(),
                    which.ceiling_sysctl(),
                );
                true
            }
        }
    };

    let granted = match which.get(socket) {
        Ok(granted) => granted,
        Err(error) => {
            debug!(
                key = which.key(),
                %error,
                "could not read back the UDP socket buffer size"
            );
            return None;
        }
    };

    // Skipped after a refusal: that path has already said its piece, and the
    // read-back would only repeat it in different words.
    if requested > 0 && !refused && socket_buffer_was_capped(requested, granted) {
        warn!(
            log_id = "einsvqj5",
            key = which.key(),
            requested,
            actual = granted,
            "the kernel granted less UDP socket buffer than {} asks for: a burst that \
             outruns this socket is dropped there, silently, and has to be sent again. \
             Raise this host's ceiling (sysctl -w {}=<bytes> on Linux, \
             kern.ipc.maxsockbuf on macOS) or lower {} so it stops asking for more than \
             the host allows.",
            which.key(),
            which.ceiling_sysctl(),
            which.key(),
        );
    }

    Some(granted)
}

/// Whether the kernel granted less buffer than was asked for.
///
/// Split out from the socket I/O so both answers can be asserted on without one,
/// and written as `<` rather than `!=` deliberately: Linux reports back **twice**
/// the size it granted, because `SO_RCVBUF`'s accounting includes per-packet
/// overhead, while macOS reports the number unchanged. An equality check would
/// call every Linux host truncated — including the ones that got exactly what
/// they asked for.
fn socket_buffer_was_capped(requested: usize, granted: usize) -> bool {
    granted < requested
}

/// Descriptors assumed to be needed beyond the tunnel quota: the endpoint
/// socket, the request streams, stdio, and the certificate reads a reload does.
pub const FD_HEADROOM: u64 = 64;

#[cfg(test)]
mod tests {
    use super::*;

    /// The check has to fire on the configuration that actually bites: a macOS
    /// default limit of 256 with the default quota of 256, where one connection
    /// at its quota consumes every descriptor the process has.
    ///
    /// And on the shipped quotas under a 65536-descriptor limit, which is the
    /// case that made the old single-connection arithmetic wrong (review M7):
    /// 256 connections x 256 tunnels is that limit exactly, so the defaults
    /// leave not one descriptor of headroom and the check said nothing. That
    /// pairing is synthetic now that the shipped unit sets 131072, and is kept
    /// because the product landing on the limit is the tightest case there is.
    #[test]
    fn a_tight_fd_budget_is_recognised() {
        assert!(fd_budget_is_tight(256, 1, 256), "the macOS default pairing");
        assert!(fd_budget_is_tight(1024, 1, 1024));
        assert!(fd_budget_is_tight(64, 1, 1));

        let defaults = crate::config::Limits::default();
        assert!(
            fd_budget_is_tight(
                65536,
                defaults.max_connections,
                defaults.max_targets_per_conn
            ),
            "the shipped quotas against a limit their product meets exactly: {} \
             x {} leaves nothing over",
            defaults.max_connections,
            defaults.max_targets_per_conn
        );
    }

    /// `max_connections = 0` is "no cap", which has no product to check, so the
    /// budget falls back to one connection's quota rather than to zero.
    #[test]
    fn an_uncapped_connection_count_falls_back_to_one_connection() {
        assert_eq!(fd_budget(0, 256), fd_budget(1, 256));
        assert!(!fd_budget_is_tight(1024, 0, 256));
        assert!(fd_budget_is_tight(256, 0, 256));
    }

    /// The read-back convention differs by platform, so the judgement is written
    /// as `<` and has to stay that way.
    ///
    /// Linux reports twice what it granted; macOS reports it unchanged. The two
    /// middle cases below are the ones an equality check would get wrong.
    #[test]
    fn a_capped_socket_buffer_is_recognised() {
        // Linux, request satisfied: doubled on the way back.
        assert!(!socket_buffer_was_capped(2 * 1024 * 1024, 4 * 1024 * 1024));
        // macOS, request satisfied: reported unchanged.
        assert!(!socket_buffer_was_capped(2 * 1024 * 1024, 2 * 1024 * 1024));
        // Linux, clamped at a stock `net.core.rmem_max` of 212992.
        assert!(socket_buffer_was_capped(2 * 1024 * 1024, 425_984));
        // The socket left on an untouched default while a size was asked for.
        assert!(socket_buffer_was_capped(2 * 1024 * 1024, 212_992));
    }

    /// A size every host allows is granted, in both directions.
    ///
    /// 128 KiB, not the 2 MiB default, and the difference is the whole point:
    /// GitHub's runners ship `net.core.rmem_max` = 212992, so asserting that the
    /// default is obtained would fail on CI while saying nothing about this code.
    /// What is under test is that a request the host *can* satisfy comes back
    /// classified as satisfied — on either platform's read-back convention.
    #[test]
    fn a_modest_socket_buffer_request_is_granted() {
        const MODEST: usize = 128 * 1024;

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a UDP socket");
        let socket = SockRef::from(&socket);

        for which in [SocketBuffer::Recv, SocketBuffer::Send] {
            let granted =
                request_socket_buffer(&socket, which, MODEST).expect("the kernel reports the size");
            assert!(
                !socket_buffer_was_capped(MODEST, granted),
                "{which:?}: 128 KiB is below every stock ceiling, but the kernel \
                 reported {granted}"
            );
        }
    }

    /// A size no host allows is reported as not granted, however it was declined.
    ///
    /// A host may clamp the request (Linux at `net.core.rmem_max`, macOS at
    /// `kern.ipc.maxsockbuf`) or fail the `setsockopt` outright and leave the
    /// default in place, and the assertion deliberately does not say which — that
    /// is a property of the host, not of this code. Both endings must arrive at
    /// "we did not get what we asked for", because that is the one condition the
    /// startup warning is built on.
    #[test]
    fn an_absurd_socket_buffer_request_is_seen_as_capped() {
        const ABSURD: usize = 1024 * 1024 * 1024;

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a UDP socket");
        let socket = SockRef::from(&socket);

        for which in [SocketBuffer::Recv, SocketBuffer::Send] {
            let granted =
                request_socket_buffer(&socket, which, ABSURD).expect("the kernel reports the size");
            assert!(
                socket_buffer_was_capped(ABSURD, granted),
                "{which:?}: 1 GiB cannot have been granted, but the kernel reported \
                 {granted}"
            );
        }
    }

    /// `0` is the escape hatch: the socket is left exactly as the OS made it.
    ///
    /// Measured against a second, untouched socket rather than a constant,
    /// because the default is a host property (and a doubled one on Linux).
    #[test]
    fn a_zero_socket_buffer_request_leaves_the_socket_alone() {
        let asked = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a UDP socket");
        let untouched = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a UDP socket");
        let asked = SockRef::from(&asked);
        let untouched = SockRef::from(&untouched);

        assert_eq!(
            request_socket_buffer(&asked, SocketBuffer::Recv, 0),
            untouched.recv_buffer_size().ok(),
            "a zero receive buffer request must not touch the socket"
        );
        assert_eq!(
            request_socket_buffer(&asked, SocketBuffer::Send, 0),
            untouched.send_buffer_size().ok(),
            "a zero send buffer request must not touch the socket"
        );
    }

    #[test]
    fn a_roomy_fd_budget_is_left_alone() {
        // The Ubuntu default, and the dev host, against a single connection.
        assert!(!fd_budget_is_tight(1024, 1, 256));
        assert!(!fd_budget_is_tight(1_048_576, 1, 256));
        // Exactly the headroom, and one better.
        assert!(!fd_budget_is_tight(FD_HEADROOM + 8, 1, 8));
        assert!(fd_budget_is_tight(FD_HEADROOM + 7, 1, 8));
        // The product is what the limit is compared against: eight connections
        // of eight tunnels need eight times as many descriptors as one does.
        assert!(!fd_budget_is_tight(FD_HEADROOM + 64, 8, 8));
        assert!(fd_budget_is_tight(FD_HEADROOM + 63, 8, 8));
        // The shipped defaults, with the headroom the docs ask an operator for.
        assert!(!fd_budget_is_tight(131_072, 256, 256));
    }
}
