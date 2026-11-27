//! The service manager's notification protocol: readiness (D124).
//!
//! A unit of `Type=notify` sets `NOTIFY_SOCKET` in the service's environment.
//! The value names an `AF_UNIX` datagram socket, and a message is one datagram
//! of `KEY=VALUE` assignments (`sd_notify(3)`). This module sends one of them:
//! [`READY`], once the listener is bound, after which systemd counts the start
//! as done.
//!
//! No crate is used for it. `std::os::unix::net::UnixDatagram` sends the
//! datagram, and the kernel attaches the sender's credentials, which systemd
//! reads to accept the message from the main process alone.
//!
//! `main` reads the environment once and passes its values in as an
//! [`Environment`]. Every function here takes values, so no test sets the
//! process environment, which the tests of a binary share across threads.
//!
//! The protocol exists on Unix only. On any other platform [`Notifier::connect`]
//! returns `None` and nothing is sent.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

#[cfg(unix)]
use tracing::warn;

/// The message that tells the service manager the listener is bound.
pub const READY: &[u8] = b"READY=1";

/// What the service manager put in this process's environment, as `main` read
/// it.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    /// `NOTIFY_SOCKET`: where notifications go. Absent outside a unit of
    /// `Type=notify`, and then nothing is sent and nothing is logged.
    pub notify_socket: Option<OsString>,
}

/// Where `NOTIFY_SOCKET` points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// A socket file, named by an absolute path.
    Path(PathBuf),
    /// A Linux abstract socket name: the value without its leading `@`.
    #[cfg(target_os = "linux")]
    Abstract(Vec<u8>),
}

/// Reads a `NOTIFY_SOCKET` value, or says why it cannot be used.
///
/// The two forms systemd sets: an absolute path, on every Unix, and an abstract
/// socket name with a leading `@`, which only Linux has. Any other value is
/// refused, and notifications are then off.
pub fn address(value: &OsStr) -> Result<Address, &'static str> {
    let bytes = value.as_encoded_bytes();
    match bytes.first() {
        Some(b'/') => Ok(Address::Path(PathBuf::from(value))),
        #[cfg(target_os = "linux")]
        Some(b'@') if bytes.len() > 1 => Ok(Address::Abstract(bytes[1..].to_vec())),
        #[cfg(target_os = "linux")]
        Some(b'@') => Err("an abstract socket name has to be more than the `@`"),
        #[cfg(not(target_os = "linux"))]
        Some(b'@') => Err("it is an abstract socket name, and only Linux has those"),
        _ => Err("it is neither an absolute path nor an abstract socket name"),
    }
}

/// A connected notification socket.
#[derive(Debug)]
pub struct Notifier {
    /// Connected to the service manager's socket, and non-blocking, so a send
    /// never waits on the receiver.
    #[cfg(unix)]
    socket: std::os::unix::net::UnixDatagram,
}

impl Notifier {
    /// The notifier for `environment`, or `None` when notifications are off.
    ///
    /// Without `NOTIFY_SOCKET` that is silent. A value that cannot be used, or
    /// a socket that cannot be reached, is one WARN line, and the server runs
    /// on without notifications.
    pub fn connect(environment: &Environment) -> Option<Self> {
        #[cfg(unix)]
        {
            let value = environment.notify_socket.as_deref()?;
            let address = match address(value) {
                Ok(address) => address,
                Err(reason) => {
                    warn!(
                        log_id = "wkj009dk",
                        notify_socket = ?value,
                        reason,
                        "NOTIFY_SOCKET cannot be used, so the service manager is not notified"
                    );
                    return None;
                }
            };
            match open(&address) {
                Ok(socket) => Some(Self { socket }),
                Err(error) => {
                    warn!(
                        log_id = "h6ro04gv",
                        notify_socket = ?value,
                        %error,
                        "could not connect to the service manager's notification socket, \
                         so it is not notified"
                    );
                    None
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = environment;
            None
        }
    }

    /// Tells the service manager the listener is bound.
    ///
    /// A failed send is one WARN line and nothing more: the server serves
    /// whether or not systemd heard it.
    pub fn ready(&self) {
        #[cfg(unix)]
        if let Err(error) = self.send(READY) {
            warn!(
                log_id = "kyd7134y",
                %error,
                "could not tell the service manager that volto is ready"
            );
        }
    }

    /// Sends one message as one datagram.
    #[cfg(unix)]
    fn send(&self, message: &[u8]) -> std::io::Result<()> {
        let sent = self.socket.send(message)?;
        if sent == message.len() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "sent {sent} of the {} bytes",
                message.len()
            )))
        }
    }
}

/// An unbound datagram socket connected to `address`, set non-blocking.
#[cfg(unix)]
fn open(address: &Address) -> std::io::Result<std::os::unix::net::UnixDatagram> {
    let socket = std::os::unix::net::UnixDatagram::unbound()?;
    match address {
        Address::Path(path) => socket.connect(path)?,
        #[cfg(target_os = "linux")]
        Address::Abstract(name) => {
            use std::os::linux::net::SocketAddrExt as _;
            let address = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
            socket.connect_addr(&address)?;
        }
    }
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[cfg(all(test, unix))]
pub(crate) mod tests {
    use std::os::unix::net::UnixDatagram;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use super::*;

    /// A directory of the test's own, short enough for a socket path.
    ///
    /// `sun_path` holds 104 bytes on macOS and 108 on Linux, and the temporary
    /// directory on macOS is already about 50 of them.
    pub(crate) fn socket_dir(name: &str) -> PathBuf {
        static MADE: AtomicU64 = AtomicU64::new(0);
        let serial = MADE.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("volto-sd-{}-{serial}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the socket directory");
        dir
    }

    /// The environment of a unit whose notification socket is `path`.
    fn notifying_to(path: &Path) -> Environment {
        Environment {
            notify_socket: Some(path.as_os_str().to_owned()),
        }
    }

    /// The next datagram on `socket`, within a few seconds.
    fn next_message(socket: &UnixDatagram) -> Vec<u8> {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set a read timeout");
        let mut buf = [0u8; 256];
        let len = socket.recv(&mut buf).expect("a notification arrives");
        buf[..len].to_vec()
    }

    #[test]
    fn the_ready_message_is_the_one_sd_notify_defines() {
        assert_eq!(READY, b"READY=1");
    }

    #[test]
    fn an_absolute_path_is_a_socket_file() {
        assert_eq!(
            address(OsStr::new("/run/systemd/notify")),
            Ok(Address::Path(PathBuf::from("/run/systemd/notify")))
        );
    }

    #[test]
    fn any_other_value_is_refused() {
        for value in ["", "run/systemd/notify", "./notify", "notify", "@"] {
            assert!(
                address(OsStr::new(value)).is_err(),
                "NOTIFY_SOCKET={value:?} must be refused"
            );
        }
    }

    /// The leading `@` names an abstract socket on Linux, and is refused
    /// elsewhere, where the kernel has no such names.
    #[test]
    fn an_abstract_name_is_linux_only() {
        let read = address(OsStr::new("@/org/freedesktop/systemd1/notify"));
        #[cfg(target_os = "linux")]
        assert_eq!(
            read,
            Ok(Address::Abstract(
                b"/org/freedesktop/systemd1/notify".to_vec()
            ))
        );
        #[cfg(not(target_os = "linux"))]
        assert!(read.is_err(), "{read:?}");
    }

    #[test]
    fn without_notify_socket_there_is_no_notifier() {
        assert!(Notifier::connect(&Environment::default()).is_none());
    }

    #[test]
    fn readiness_reaches_a_socket_file_as_one_datagram() {
        let path = socket_dir("ready").join("notify");
        let receiver = UnixDatagram::bind(&path).expect("bind the receiver");
        let notifier = Notifier::connect(&notifying_to(&path)).expect("the socket is reachable");
        notifier.ready();
        assert_eq!(next_message(&receiver), READY);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn readiness_reaches_an_abstract_socket() {
        use std::os::linux::net::SocketAddrExt as _;
        use std::os::unix::net::SocketAddr;

        let name = format!("volto-sd-test-{}", std::process::id());
        let receiver = UnixDatagram::bind_addr(
            &SocketAddr::from_abstract_name(name.as_bytes()).expect("an abstract name"),
        )
        .expect("bind the receiver");
        let environment = Environment {
            notify_socket: Some(format!("@{name}").into()),
        };
        let notifier = Notifier::connect(&environment).expect("the socket is reachable");
        notifier.ready();
        assert_eq!(next_message(&receiver), READY);
    }

    /// A path where nothing listens turns notifications off rather than
    /// failing; the WARN line it writes is asserted on the real binary in
    /// `tests/it_cli.rs`.
    #[test]
    fn a_socket_nobody_listens_on_turns_notifications_off() {
        let path = socket_dir("absent").join("notify");
        assert!(Notifier::connect(&notifying_to(&path)).is_none());
    }
}
