//! The service manager's notification protocol: readiness and the watchdog's
//! keep-alive (D124).
//!
//! A unit of `Type=notify` sets `NOTIFY_SOCKET` in the service's environment.
//! The value names an `AF_UNIX` datagram socket, and a message is one datagram
//! of `KEY=VALUE` assignments (`sd_notify(3)`). This module sends two of them.
//! [`READY`] goes once the listener is bound, after which systemd counts the
//! start as done. [`WATCHDOG`] goes every half of `WATCHDOG_USEC` when the unit
//! sets `WatchdogSec=`, and systemd restarts the service when one does not
//! arrive in time.
//!
//! What the keep-alive covers is decided by where it is polled, which
//! [`with_keep_alive`] states. What it does not cover, on purpose: a full
//! blocking pool (name lookups, D90) and a connection whose own tasks wait on
//! each other. Both are partial failures, and a restart would cut every live
//! connection for them.
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
use std::time::Duration;

#[cfg(unix)]
use tracing::warn;

/// The message that tells the service manager the listener is bound.
pub const READY: &[u8] = b"READY=1";

/// The watchdog's keep-alive.
pub const WATCHDOG: &[u8] = b"WATCHDOG=1";

/// The shortest period the keep-alive is sent at.
///
/// `tokio::time::interval` panics on a zero period, and half of a
/// `WATCHDOG_USEC` of 1 is zero microseconds. A watchdog that short cannot be
/// met by any period, so the floor only has to keep the interval legal.
pub const SHORTEST_HEARTBEAT: Duration = Duration::from_millis(1);

/// What the service manager put in this process's environment, as `main` read
/// it.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    /// `NOTIFY_SOCKET`: where notifications go. Absent outside a unit of
    /// `Type=notify`, and then nothing is sent and nothing is logged.
    pub notify_socket: Option<OsString>,
    /// `WATCHDOG_USEC`: the unit's `WatchdogSec=`, in microseconds. Absent when
    /// the unit sets no watchdog.
    pub watchdog_usec: Option<OsString>,
    /// `WATCHDOG_PID`: the process the watchdog variables are meant for, when
    /// systemd says.
    pub watchdog_pid: Option<OsString>,
}

/// How often the keep-alive is sent, from `WATCHDOG_USEC` and `WATCHDOG_PID`,
/// or why the two cannot be used.
///
/// `Ok(None)` is no watchdog: `WATCHDOG_USEC` is absent, or `WATCHDOG_PID` names
/// another process, which inherited variables do. The period is half of
/// `WATCHDOG_USEC`, so that one keep-alive can be late by a whole period and
/// systemd still hears from the server in time, with [`SHORTEST_HEARTBEAT`] as
/// its floor. A value that is not a number of microseconds above zero, or a
/// `WATCHDOG_PID` that is not a process id, is an error, which the caller
/// writes as one WARN line.
pub fn heartbeat(
    watchdog_usec: Option<&OsStr>,
    watchdog_pid: Option<&OsStr>,
    own_pid: u32,
) -> Result<Option<Duration>, &'static str> {
    let Some(usec) = watchdog_usec else {
        return Ok(None);
    };
    if let Some(pid) = watchdog_pid {
        let pid: u32 = pid
            .to_str()
            .and_then(|text| text.parse().ok())
            .ok_or("WATCHDOG_PID is not a process id")?;
        if pid != own_pid {
            return Ok(None);
        }
    }
    let usec: u64 = usec
        .to_str()
        .and_then(|text| text.parse().ok())
        .ok_or("WATCHDOG_USEC is not a number of microseconds")?;
    if usec == 0 {
        return Err("WATCHDOG_USEC is zero");
    }
    Ok(Some(
        Duration::from_micros(usec / 2).max(SHORTEST_HEARTBEAT),
    ))
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
    /// How often [`WATCHDOG`] is sent, or `None` when the unit sets no
    /// watchdog for this process.
    heartbeat: Option<Duration>,
}

impl Notifier {
    /// The notifier for `environment`, or `None` when notifications are off.
    ///
    /// Without `NOTIFY_SOCKET` that is silent. A value that cannot be used, or
    /// a socket that cannot be reached, is one WARN line, and the server runs
    /// on without notifications. Watchdog variables that cannot be used are one
    /// WARN line too, and then readiness is sent with no keep-alive.
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
            let socket = match open(&address) {
                Ok(socket) => socket,
                Err(error) => {
                    warn!(
                        log_id = "h6ro04gv",
                        notify_socket = ?value,
                        %error,
                        "could not connect to the service manager's notification socket, \
                         so it is not notified"
                    );
                    return None;
                }
            };
            let heartbeat = heartbeat(
                environment.watchdog_usec.as_deref(),
                environment.watchdog_pid.as_deref(),
                std::process::id(),
            )
            .unwrap_or_else(|reason| {
                warn!(
                    log_id = "4s9p4dd7",
                    watchdog_usec = ?environment.watchdog_usec,
                    watchdog_pid = ?environment.watchdog_pid,
                    reason,
                    "the watchdog variables cannot be used, so no keep-alive is sent"
                );
                None
            });
            Some(Self { socket, heartbeat })
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

/// Runs `work` with the watchdog's keep-alive polled beside it, in the same
/// future, and returns what `work` returns.
///
/// Where this is polled is the design (D124). `main` awaits it inside the future
/// it hands to `block_on`, with the accept loop as `work`. That future runs on
/// the thread that called `block_on`, and the keep-alive's timer is turned by
/// the runtime's worker threads, which drive the time driver. So a keep-alive
/// needs both: the accept loop's thread free to poll, and at least one worker
/// running. It stops when either stops, and systemd then restarts the service.
/// A spawned task would keep sending while the accept loop is stuck, and an OS
/// thread of its own would say nothing about the runtime. The stall tests below
/// hold this arrangement to both halves.
pub async fn with_keep_alive<F: Future>(notifier: Option<&Notifier>, work: F) -> F::Output {
    tokio::select! {
        output = work => output,
        never = keep_alive(notifier) => match never {},
    }
}

/// Sends [`WATCHDOG`] every heartbeat period, the first one at once, and never
/// returns.
///
/// Pending for ever when there is no notifier or no heartbeat, so that
/// [`with_keep_alive`] can poll it in every case. A failed send never ends the
/// server: it is a WARN line on the doubling schedule of
/// [`crate::logfmt::Sampler`] (D97), since a failure that lasts repeats every
/// period.
async fn keep_alive(notifier: Option<&Notifier>) -> std::convert::Infallible {
    #[cfg(unix)]
    if let Some((notifier, period)) = notifier.and_then(|n| Some((n, n.heartbeat?))) {
        let mut ticks = tokio::time::interval(period);
        // After a stall, one keep-alive at once, and the period from there; not
        // one per period missed.
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let failures = crate::logfmt::Sampler::new();
        loop {
            ticks.tick().await;
            if let Err(error) = notifier.send(WATCHDOG)
                && let Some(total) = failures.record()
            {
                warn!(
                    log_id = "30nndon9",
                    %error,
                    failures = total,
                    "could not send the watchdog keep-alive to the service manager; \
                     further failures are logged when the count doubles"
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = notifier;
    std::future::pending().await
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
mod tests {
    use std::os::unix::net::UnixDatagram;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Instant;

    use super::*;

    /// One datagram the receiving socket read, and when.
    type Arrival = (Instant, Vec<u8>);

    /// What [`heartbeat`] is expected to answer, with the error's text left out.
    type Expected = Result<Option<Duration>, ()>;

    /// A directory of the test's own, short enough for a socket path, removed
    /// with the socket in it when this is dropped.
    ///
    /// `sun_path` holds 104 bytes on macOS and 108 on Linux, and the temporary
    /// directory on macOS is already about 50 of them.
    struct SocketDir(PathBuf);

    impl SocketDir {
        fn new(name: &str) -> Self {
            static MADE: AtomicU64 = AtomicU64::new(0);
            let serial = MADE.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("volto-sd-{}-{serial}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create the socket directory");
            Self(dir)
        }

        /// The socket's path in the directory.
        fn socket(&self) -> PathBuf {
            self.0.join("notify")
        }
    }

    impl Drop for SocketDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The environment of a unit whose notification socket is `path`.
    fn notifying_to(path: &Path) -> Environment {
        Environment {
            notify_socket: Some(path.as_os_str().to_owned()),
            ..Environment::default()
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
    fn the_messages_are_the_ones_sd_notify_defines() {
        assert_eq!(READY, b"READY=1");
        assert_eq!(WATCHDOG, b"WATCHDOG=1");
    }

    /// Every case of the two watchdog variables, against this process's id.
    #[test]
    fn the_watchdog_variables_decide_the_heartbeat() {
        const OWN: u32 = 4242;
        let own = OWN.to_string();
        let ok = |period: Duration| Ok(Some(period));
        let cases: [(Option<&str>, Option<&str>, Expected); 14] = [
            // No watchdog at all.
            (None, None, Ok(None)),
            (None, Some(&own), Ok(None)),
            // Half of the value, for this process or for no process named.
            (Some("60000000"), None, ok(Duration::from_secs(30))),
            (Some("60000000"), Some(&own), ok(Duration::from_secs(30))),
            (Some("+60000000"), None, ok(Duration::from_secs(30))),
            (Some("3"), None, ok(SHORTEST_HEARTBEAT)),
            // Half of 1 microsecond is zero, which `interval` would panic on.
            (Some("1"), None, ok(SHORTEST_HEARTBEAT)),
            // Meant for another process, which an inherited variable is.
            (Some("60000000"), Some("1"), Ok(None)),
            (Some("not a number"), Some("1"), Ok(None)),
            // Unusable.
            (Some("0"), None, Err(())),
            (Some(""), None, Err(())),
            (Some("-1"), None, Err(())),
            (Some("thirty seconds"), None, Err(())),
            (Some("60000000"), Some("init"), Err(())),
        ];
        for (usec, pid, expected) in cases {
            let read = heartbeat(usec.map(OsStr::new), pid.map(OsStr::new), OWN);
            assert_eq!(
                read.map_err(|_| ()),
                expected,
                "WATCHDOG_USEC={usec:?} WATCHDOG_PID={pid:?}"
            );
        }
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
        let dir = SocketDir::new("ready");
        let path = dir.socket();
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
            ..Environment::default()
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
        let dir = SocketDir::new("absent");
        let path = dir.socket();
        assert!(Notifier::connect(&notifying_to(&path)).is_none());
    }

    /// `WATCHDOG_USEC` for the stall tests: a keep-alive every 50 ms.
    const STALL_WATCHDOG_USEC: &str = "100000";

    /// How long each stall test runs before the stall and after it.
    const SETTLED: Duration = Duration::from_millis(500);

    /// How long the stall lasts.
    const STALL: Duration = Duration::from_millis(1500);

    /// How long after the stall begins a keep-alive is still allowed to be read.
    ///
    /// One sent just before the stall can be read by the receiving thread a
    /// little later on a loaded machine. Nothing else may arrive inside the
    /// stall.
    const READ_LAG: Duration = Duration::from_millis(250);

    /// The fewest keep-alives each side of the stall must show. Ten periods
    /// fit in [`SETTLED`], so this holds on a machine that runs a third of
    /// them late.
    const AT_LEAST: usize = 3;

    /// Worker threads of the stall tests' runtime: `start` in `src/main.rs`
    /// builds the same multi-thread runtime, with as many as the host has
    /// cores, and a small fixed number makes every one of them reachable.
    const WORKERS: usize = 2;

    /// The datagrams that reach a socket file, each with the moment the
    /// receiving thread read it.
    struct Arrivals {
        /// Held so the directory goes when the arrivals do.
        _dir: SocketDir,
        path: PathBuf,
        seen: Arc<Mutex<Vec<Arrival>>>,
        stop: Arc<AtomicBool>,
        reader: std::thread::JoinHandle<()>,
    }

    impl Arrivals {
        /// Binds a receiving socket in a directory of its own and starts
        /// reading it.
        fn listen(name: &str) -> Self {
            let dir = SocketDir::new(name);
            let path = dir.socket();
            let socket = UnixDatagram::bind(&path).expect("bind the receiver");
            socket
                .set_read_timeout(Some(Duration::from_millis(10)))
                .expect("set a read timeout");
            let seen = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let reader = std::thread::spawn({
                let seen = seen.clone();
                let stop = stop.clone();
                move || {
                    let mut buf = [0u8; 256];
                    while !stop.load(Ordering::Relaxed) {
                        if let Ok(len) = socket.recv(&mut buf) {
                            seen.lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .push((Instant::now(), buf[..len].to_vec()));
                        }
                    }
                }
            });
            Self {
                _dir: dir,
                path,
                seen,
                stop,
                reader,
            }
        }

        /// A notifier for this socket, with a watchdog of `watchdog_usec`.
        fn notifier(&self, watchdog_usec: &str) -> Notifier {
            Notifier::connect(&Environment {
                notify_socket: Some(self.path.as_os_str().to_owned()),
                watchdog_usec: Some(watchdog_usec.into()),
                watchdog_pid: Some(std::process::id().to_string().into()),
            })
            .expect("the socket is reachable")
        }

        /// Everything read, once the datagrams still in flight have landed.
        fn finish(self) -> Vec<Arrival> {
            std::thread::sleep(Duration::from_millis(100));
            self.stop.store(true, Ordering::Relaxed);
            self.reader.join().expect("the receiving thread");
            std::mem::take(&mut *self.seen.lock().unwrap_or_else(PoisonError::into_inner))
        }
    }

    /// The runtime `start` in `src/main.rs` builds, with [`WORKERS`] workers.
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(WORKERS)
            .enable_all()
            .build()
            .expect("build the runtime")
    }

    /// Holds a stall test's arrivals to its three phases: keep-alives before
    /// the stall, none inside it, and keep-alives again after it.
    #[track_caller]
    fn assert_stalled(arrivals: &[Arrival], began: Instant, ended: Instant) {
        assert!(
            ended.saturating_duration_since(began) >= STALL / 2,
            "the stall lasted {:?}, so the test did not stall what it meant to",
            ended.saturating_duration_since(began)
        );
        assert!(
            arrivals.iter().all(|(_, message)| message == WATCHDOG),
            "only keep-alives are sent: {arrivals:?}"
        );
        let before = arrivals.iter().filter(|(at, _)| *at < began).count();
        let inside: Vec<Duration> = arrivals
            .iter()
            .filter(|(at, _)| *at > began + READ_LAG && *at < ended)
            .map(|(at, _)| at.duration_since(began))
            .collect();
        let after = arrivals.iter().filter(|(at, _)| *at >= ended).count();
        assert!(before >= AT_LEAST, "{before} keep-alives before the stall");
        assert!(
            inside.is_empty(),
            "keep-alives arrived during the stall, this long after it began: {inside:?}"
        );
        assert!(after >= AT_LEAST, "{after} keep-alives after the stall");
    }

    /// Case A: with every worker blocked, no keep-alive is sent, though the
    /// future that sends them is free to run.
    ///
    /// The accept loop's stand-in spawns one task per worker, each of which
    /// blocks its thread, and awaits them. Its own thread stays free. The
    /// keep-alive's timer is turned by the workers alone, so it does not fire.
    #[test]
    fn keep_alives_stop_while_every_worker_is_blocked() {
        let arrivals = Arrivals::listen("workers");
        let notifier = arrivals.notifier(STALL_WATCHDOG_USEC);
        let (began, ended) = runtime().block_on(with_keep_alive(Some(&notifier), async {
            tokio::time::sleep(SETTLED).await;
            let marks = Arc::new(Mutex::new(Vec::new()));
            let blocked: Vec<_> = (0..WORKERS)
                .map(|_| {
                    let marks = marks.clone();
                    tokio::spawn(async move {
                        let began = Instant::now();
                        std::thread::sleep(STALL);
                        marks
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push((began, Instant::now()));
                    })
                })
                .collect();
            for task in blocked {
                task.await.expect("the blocking task");
            }
            tokio::time::sleep(SETTLED).await;
            let marks = marks.lock().unwrap_or_else(PoisonError::into_inner);
            // Every worker is blocked from the last start to the first end.
            let began = marks.iter().map(|mark| mark.0).max().expect("a mark");
            let ended = marks.iter().map(|mark| mark.1).min().expect("a mark");
            (began, ended)
        }));
        assert_stalled(&arrivals.finish(), began, ended);
    }

    /// Case B: with the accept loop's thread blocked, no keep-alive is sent,
    /// though every worker is free and the timer fires.
    #[test]
    fn keep_alives_stop_while_the_accept_loop_is_blocked() {
        let arrivals = Arrivals::listen("main");
        let notifier = arrivals.notifier(STALL_WATCHDOG_USEC);
        let (began, ended) = runtime().block_on(with_keep_alive(Some(&notifier), async {
            tokio::time::sleep(SETTLED).await;
            let began = Instant::now();
            std::thread::sleep(STALL);
            let ended = Instant::now();
            tokio::time::sleep(SETTLED).await;
            (began, ended)
        }));
        assert_stalled(&arrivals.finish(), began, ended);
    }

    /// The first keep-alive goes at once, and the rest follow at the period.
    #[test]
    fn keep_alives_start_at_once_and_repeat() {
        let arrivals = Arrivals::listen("repeat");
        let notifier = arrivals.notifier(STALL_WATCHDOG_USEC);
        let started = Instant::now();
        runtime().block_on(with_keep_alive(Some(&notifier), async {
            tokio::time::sleep(SETTLED).await;
        }));
        let seen = arrivals.finish();
        let first = seen.first().expect("a keep-alive").0;
        assert!(
            first.duration_since(started) < Duration::from_millis(250),
            "the first keep-alive took {:?}",
            first.duration_since(started)
        );
        assert!(seen.len() >= AT_LEAST, "{} keep-alives", seen.len());
    }

    /// Without a heartbeat the work runs and nothing is sent.
    #[test]
    fn without_a_watchdog_no_keep_alive_is_sent() {
        let arrivals = Arrivals::listen("quiet");
        let notifier = Notifier::connect(&notifying_to(&arrivals.path)).expect("reachable");
        let answer = runtime().block_on(with_keep_alive(Some(&notifier), async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            42
        }));
        assert_eq!(answer, 42, "the work's output is handed back");
        assert!(arrivals.finish().is_empty());
    }
}
