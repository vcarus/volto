//! `volto`, the MASQUE proxy server binary: CLI, logging, assembly.

// As in `lib.rs`: the binary crate is assembly over the library, and there is
// nothing here that could need `unsafe` either.
#![forbid(unsafe_code)]
// And, as in `lib.rs`, every item here is documented; this keeps it that way.
#![warn(missing_docs)]

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{Event, Level, Subscriber, error, info, warn};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;
use volto::config::{Config, FilterRefusal};
use volto::quic::Server;
use volto::shutdown::Trigger;

// mimalloc on the musl targets, `System` elsewhere. `volto::alloc` says why.
#[global_allocator]
static GLOBAL: volto::alloc::Global = volto::alloc::GLOBAL;

// Serving takes `--config`; the two ECH subcommands take none, because they
// read or write one key file and touch nothing else. `subcommand_negates_reqs`
// is what lets `--config` be required everywhere except there.
/// Command line arguments.
#[derive(Debug, Parser)]
#[command(
    name = "volto",
    version,
    about = "MASQUE proxy server",
    subcommand_negates_reqs = true,
    args_conflicts_with_subcommands = true
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, value_name = "FILE", required = true)]
    config: Option<PathBuf>,

    /// Load and validate the configuration, then exit without serving.
    ///
    /// Answers whether this binary can read that file, which is the question a
    /// rollback turns on: nothing is bound, started or written.
    #[arg(long)]
    check_config: bool,

    /// Print a support bundle to stdout, then exit without serving.
    ///
    /// `conflicts_with` rather than a precedence rule: the two flags answer
    /// different questions and neither is the obvious winner, so a command line
    /// naming both is refused by clap with a message naming them, rather than
    /// one of them being silently ignored.
    #[arg(long, conflicts_with = "check_config")]
    diagnostics: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

/// The subcommands, which manage the ECH key file instead of serving.
#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a new ECH key file and print its ECHConfigList.
    ///
    /// The file holds the X25519 private key and the one ECHConfig made from
    /// it, which fixes the config_id, the public name and the HPKE suites. Point
    /// `server.ech_key` at it. The ECHConfigList printed on stdout, in base64,
    /// is the value a client's `ech-config` takes. An existing file is never
    /// overwritten.
    EchKeygen {
        /// The ECHConfig's public name: the name an ECH client sends in the
        /// clear, and checks the certificate against when ECH is rejected.
        #[arg(long, value_name = "NAME")]
        public_name: String,
        /// Where to write the key file. Created with mode 0600.
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// The ECHConfig's config_id. Random when left out.
        #[arg(long, value_name = "ID")]
        config_id: Option<u8>,
        /// The ECHConfig's maximum_name_length, which only steers how much a
        /// client pads its encrypted ClientHello.
        #[arg(long, value_name = "N", default_value_t = 0)]
        max_name_length: u8,
    },
    /// Print the ECHConfigList of an existing ECH key file.
    ///
    /// The same base64 value `ech-keygen` printed when it wrote the file.
    EchConfig {
        /// The key file, as `server.ech_key` names it.
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
}

/// Runs [`start`] and reports its error the way the standard library would,
/// with a priority prefix on every line when journald reads stderr.
///
/// The standard library prints an error returned from `main` as `Error: {:?}`
/// and exits 1. Under the shipped unit that line goes to the journal, which
/// files a line without a prefix at `SyslogLevel=`, whose default is info, so
/// `journalctl -p warning` would not show why a start failed. The subscriber's
/// [`JournalPriority`] cannot help here: a configuration error happens before
/// the subscriber exists, and nothing else on this path goes through it.
fn main() -> ExitCode {
    match start() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let journal = logs_to_journal(std::env::var_os(JOURNAL_STREAM).as_deref());
            eprint!("{}", failure_report(&error, journal));
            ExitCode::FAILURE
        }
    }
}

/// The text `main` writes to stderr for an error, newline included.
///
/// The same text the standard library writes for an error returned from `main`.
/// When `journal` is true each line starts with `<3>`, priority err, because
/// journald reads the prefix per line and the `{:?}` of an `anyhow::Error`
/// spans several lines when the error has causes.
fn failure_report(error: &anyhow::Error, journal: bool) -> String {
    let text = format!("Error: {error:?}");
    if !journal {
        return text + "\n";
    }
    text.lines().fold(String::new(), |mut report, line| {
        use std::fmt::Write as _;
        // Writing into a `String` cannot fail.
        let _ = writeln!(report, "{}{line}", syslog_prefix(&Level::ERROR));
        report
    })
}

/// Everything `main` does, with its error returned for [`main`] to report.
fn start() -> Result<()> {
    let cli = Cli::parse();

    if let Some(command) = &cli.command {
        return run_command(command);
    }
    // clap requires `--config` whenever no subcommand is given.
    let path = cli.config.clone().context("--config is required")?;

    // Loaded and validated before logging exists, so configuration errors are
    // reported by returning them to `main`. It is also before the runtime
    // exists, which the hand-built runtime below needs: the blocking pool is
    // sized from `max_connections` rather than left at tokio's 512, so that
    // every connection's reserved name-lookup slot has a thread to run on
    // (D90). `#[tokio::main]` cannot express that.
    let config = Config::load(&path)?;

    // Deliberately the very next thing, and before the runtime is built: what
    // the flag promises is that nothing happens except reading the file.
    if cli.check_config {
        report_config_check(&path, &config);
        return Ok(());
    }

    // The same place and the same promise. The two cannot both be set (clap
    // refuses that command line), so the order between them does not matter.
    if cli.diagnostics {
        report_diagnostics(&path, &config);
        return Ok(());
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(volto::net::blocking_pool_size(
            config.limits.max_connections,
        ))
        .build()
        .context("failed to build the async runtime")?;

    // Only the fallback. `run` returns the grace that was in force when the
    // server stopped, which a `SIGHUP` may have raised since startup, and it
    // fails only before the server exists, where the file this process started
    // on is the right answer.
    let startup_grace = config.server.shutdown_grace();

    let served = runtime.block_on(run(path, config));
    let grace = served.as_ref().copied().unwrap_or(startup_grace);

    // Deliberately not an implicit drop: tokio's `Runtime::drop` waits without
    // limit for blocking tasks that have started, and a name lookup is one of
    // those (D90). `volto::shutdown::blocking_grace` gives the bound and why.
    volto::shutdown::stop_runtime(runtime, grace);

    served.map(|_| ())
}

/// Runs one of the ECH subcommands.
///
/// Like `--check-config`, these come before any runtime or subscriber exists
/// and print to stdout, so nothing goes through `tracing`. The key file's
/// private half is written once, to the file, and never printed.
fn run_command(command: &Command) -> Result<()> {
    match command {
        Command::EchKeygen {
            public_name,
            out,
            config_id,
            max_name_length,
        } => {
            let config_id = match config_id {
                Some(id) => *id,
                None => {
                    let mut byte = [0u8; 1];
                    volto::tls::random_bytes(&mut byte)?;
                    byte[0]
                }
            };
            let key = volto::tls::EchKey::generate(public_name, config_id, *max_name_length)?;
            volto::tls::write_new_key_file(out, &key)?;
            eprintln!(
                "wrote {}: config_id {config_id}, public name {public_name}",
                out.display()
            );
            println!("{}", key.config_list_base64());
        }
        Command::EchConfig { file } => {
            let key = volto::tls::EchKey::load(file)?;
            println!("{}", key.config_list_base64());
        }
    }
    Ok(())
}

/// Says that the file loaded, and repeats what starting on it would warn about.
///
/// Reached only when [`Config::load`] has already succeeded. The failure is
/// the `?` in `start`, which prints the error the service would print at
/// startup on the same file, the answer `script/deploy.sh` relies on (D93, D94).
///
/// What it therefore covers is exactly what `Config::load` covers: the TOML
/// itself, every table's refusal of a key it does not know, and every range and
/// cross-field rule in `Config::validate`, the certificate and key existing as
/// files and the leaf certificate, when the file reads as PEM, being one the
/// server's TLS takes included. What it does not cover is left to startup:
/// whether the port is free, a certificate file that does not read as PEM,
/// whether the private key parses and matches the certificate, and whether
/// `RLIMIT_NOFILE` (a property of the unit, not of the file) leaves room for the
/// configured quotas. `docs/configuration.md` says so to the operator.
///
/// The warnings go to stderr and leave the status alone. They are the ones the
/// service logs at startup on the same file, and none of them describes a
/// configuration that fails to start, so making them fatal here would refuse to
/// deploy a host that runs perfectly well.
fn report_config_check(path: &Path, config: &Config) {
    for warning in config.warnings() {
        eprintln!("warning: {warning}");
    }

    println!(
        "{}: loads and validates on volto {}",
        path.display(),
        env!("CARGO_PKG_VERSION")
    );
}

/// Prints the support bundle `--diagnostics` promises.
///
/// One question: what would an operator have to be asked for, one message at a
/// time, before an issue about this host could be read at all. The answer is
/// the version, the file as this binary parsed it, the two host limits that
/// decide whether the configured quotas are reachable, and what kernel this is.
/// Printing it in one go turns that exchange into a paste.
///
/// What it deliberately does not do bounds the trust it needs. Nothing is bound,
/// connected or resolved, no journal is read, and nothing goes through
/// `tracing`: the subscriber is not installed at this point in `main` and this
/// output is not a log line, so D100's accounted set is untouched. Everything
/// here is either this process's own memory, a `getrlimit` on itself, four files
/// under `/proc/sys`, the `exe` link, `comm` and `limits` of the processes
/// listed under `/proc`, or one `uname`. The `/proc/<pid>` reads are Linux only
/// and every one of them is allowed to fail: a refused or missing file becomes
/// a line saying so, never a non-zero exit.
///
/// Passwords are redacted because `Config` is printed through its `Debug`, and
/// `impl Debug for config::User` renders the password as `<redacted>`.
fn report_diagnostics(path: &Path, config: &Config) {
    println!("volto {} diagnostics", env!("CARGO_PKG_VERSION"));
    println!();
    println!("[configuration]");
    println!("path = {}", path.display());
    println!();
    println!("[server]\n{:#?}", config.server);
    println!();
    // The passwords are `<redacted>` here, by `Debug for config::User`.
    println!("[auth]\n{:#?}", config.auth);
    println!();
    // After serde's defaults, so these are the values the server would run on
    // and not the subset the file happens to name.
    println!("[limits]\n{:#?}", config.limits);
    println!();
    println!("[security]\n{:#?}", config.security);
    println!();
    println!("[log]\n{:#?}", config.log);
    println!();

    println!("[warnings]");
    let warnings = config.warnings();
    if warnings.is_empty() {
        println!("none");
    }
    for warning in &warnings {
        println!("{warning}");
    }
    println!();

    println!("[file descriptors]");
    let (soft, hard) = volto::net::fd_limits();
    println!("RLIMIT_NOFILE soft = {}", or_unlimited(soft));
    println!("RLIMIT_NOFILE hard = {}", or_unlimited(hard));
    println!(
        "these two are this process's own limits, not the service's \
         (the service's are in /proc/<MainPID>/limits)"
    );
    print_service_fd_limits();
    println!();

    println!("[udp socket buffers]");
    print_udp_buffer_sysctls();
    println!();

    println!("[operating system]");
    println!("{}", uname());
}

/// A `getrlimit` value, where absent means `RLIM_INFINITY`.
fn or_unlimited(limit: Option<u64>) -> String {
    limit.map_or_else(|| "unlimited".to_string(), |value| value.to_string())
}

/// The four `net.core` values `docs/deployment.md` tells an operator to look at.
///
/// Read as files rather than by shelling out to `sysctl`, so the bundle does not
/// depend on a binary being installed, and only on Linux: these keys do not
/// exist on the macOS development host, where the equivalent ceiling is
/// `kern.ipc.maxsockbuf` and the two are not comparable enough to print side by
/// side.
#[cfg(target_os = "linux")]
fn print_udp_buffer_sysctls() {
    for key in ["rmem_default", "rmem_max", "wmem_default", "wmem_max"] {
        let path = format!("/proc/sys/net/core/{key}");
        match std::fs::read_to_string(&path) {
            Ok(value) => println!("net.core.{key} = {}", value.trim()),
            Err(error) => println!("net.core.{key} = unreadable ({error})"),
        }
    }
}

/// The same section where `/proc/sys/net/core` does not exist.
#[cfg(not(target_os = "linux"))]
fn print_udp_buffer_sysctls() {
    println!("not available on this platform (net.core.* is Linux only)");
}

/// The descriptor limits of the running volto service, if one is running.
///
/// The two `getrlimit` lines above are this process's own, usually an SSH
/// shell's, which can differ from the unit's `LimitNOFILE`. The service's
/// figure is in `/proc/<pid>/limits`, so it is read here.
///
/// The pid is found by walking `/proc`, with no process run and no assumption
/// about the unit's name. A process counts as this service when its `comm` is
/// `volto`, or when its `exe` link resolves to this binary. Both tests are
/// needed: `comm` is only a name, and the `exe` link is unreadable without
/// ptrace rights over the target and reads `(deleted)` once the deploy script
/// has replaced the file. Neither is proof, so every match is printed with its
/// pid.
///
/// Nothing here can fail the run: every read that fails is reported as a line
/// of its own.
#[cfg(target_os = "linux")]
fn print_service_fd_limits() {
    let entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(error) => {
            println!("the service's limits could not be looked up (/proc: {error})");
            return;
        }
    };

    let own_pid = std::process::id();
    // `None` when this binary's own path cannot be read, which leaves `comm` as
    // the only test rather than matching every process against nothing.
    // `/proc/self/exe` is what `current_exe` reads on Linux, so the comparison
    // is link target against link target.
    let own_exe = std::env::current_exe().ok();

    let mut pids: Vec<u32> = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            // Everything under /proc that is not a pid, such as `sys` itself.
            continue;
        };
        if pid == own_pid {
            continue;
        }

        let directory = Path::new("/proc").join(pid.to_string());
        let by_name = std::fs::read_to_string(directory.join("comm"))
            .is_ok_and(|comm| comm.trim() == "volto");
        let by_path = || {
            std::fs::read_link(directory.join("exe"))
                .is_ok_and(|exe| own_exe.as_deref() == Some(exe.as_path()))
        };
        if by_name || by_path() {
            pids.push(pid);
        }
    }
    pids.sort_unstable();

    if pids.is_empty() {
        println!("no running volto process was found under /proc");
        return;
    }

    for pid in pids {
        let path = format!("/proc/{pid}/limits");
        match std::fs::read_to_string(&path) {
            Ok(limits) => match volto::net::max_open_files(&limits) {
                Some((soft, hard)) => {
                    println!(
                        "service pid {pid} Max open files soft = {}",
                        or_unlimited(soft)
                    );
                    println!(
                        "service pid {pid} Max open files hard = {}",
                        or_unlimited(hard)
                    );
                }
                None => println!("service pid {pid} has no readable Max open files row in {path}"),
            },
            Err(error) => println!("service pid {pid} limits unreadable ({path}: {error})"),
        }
    }
}

/// The same lines where there is no `/proc` to walk.
#[cfg(not(target_os = "linux"))]
fn print_service_fd_limits() {
    println!("the service's own limits are not available on this platform (/proc is Linux only)");
}

/// `uname -srm`, or a line saying why there is none.
///
/// A process rather than `rustix::system::uname`, because rustix's `system`
/// feature is not enabled, and this runs once in a command an operator typed.
fn uname() -> String {
    match std::process::Command::new("uname")
        .args(["-s", "-r", "-m"])
        .output()
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        Ok(output) => format!("uname exited with {}", output.status),
        Err(error) => format!("uname could not be run ({error})"),
    }
}

/// Everything that needs a runtime, which is everything after the configuration.
///
/// Returns `server.shutdown_grace` as it stood when the server stopped, which is
/// what bounds the blocking pool once the runtime's own work is over. A reload
/// can move that key, and `Server::drain` reads the same live value, which is
/// the invariant [`volto::shutdown::blocking_grace`] states.
async fn run(path: PathBuf, config: Config) -> Result<Duration> {
    // First, and synchronously: a signal stream records a signal from the
    // moment it is created, and until then `SIGHUP` and `SIGTERM` keep their
    // default action, which ends the process. A stream created inside a spawned
    // task would exist only from that task's first poll, after `Server::bind`
    // has read and parsed the certificate.
    #[cfg(unix)]
    let signals = Signals::create();

    init_tracing(&config.log.level)?;

    // Only now that a subscriber exists: settings that are legal but risky
    // ("authentication is off" above all) are useless if they are logged into a
    // subscriber that has not been installed yet.
    for warning in config.warnings() {
        tracing::warn!(log_id = "f9be058r", "{warning}");
    }

    let server = Server::bind(Arc::new(config))?;

    // The streams were created at the top, so a signal that arrived since then
    // is waiting in them. A `SIGTERM` that arrived during startup fires the
    // trigger as soon as its watcher task first runs, which may be shortly
    // after the accept loop has started: the stop is graceful either way.
    #[cfg(unix)]
    {
        tokio::spawn(watch_for_signals(
            signals.terminate,
            signals.interrupt,
            server.shutdown_trigger(),
        ));
        tokio::spawn(watch_for_reload(
            signals.hangup,
            server.reload_handle(),
            path.clone(),
        ));
    }
    #[cfg(not(unix))]
    tokio::spawn(watch_for_signals(server.shutdown_trigger()));

    server.run().await;

    // After the drain, so a reload that arrived during the process's life is in
    // it.
    let grace = server.shutdown_grace();

    info!(log_id = "fle471bm", "volto stopped");
    Ok(grace)
}

/// The signal streams [`run`] creates before it does anything else.
///
/// Each one is the result of creating it, because the reason a stream could not
/// be created is logged by the task that would have used it, and no subscriber
/// exists yet when they are created.
#[cfg(unix)]
struct Signals {
    /// `SIGTERM`, for [`watch_for_signals`].
    terminate: std::io::Result<tokio::signal::unix::Signal>,
    /// `SIGINT`, for [`watch_for_signals`].
    interrupt: std::io::Result<tokio::signal::unix::Signal>,
    /// `SIGHUP`, for [`watch_for_reload`].
    hangup: std::io::Result<tokio::signal::unix::Signal>,
}

#[cfg(unix)]
impl Signals {
    /// Creates the three streams. Must run inside the runtime.
    fn create() -> Self {
        use tokio::signal::unix::{SignalKind, signal};

        Self {
            terminate: signal(SignalKind::terminate()),
            interrupt: signal(SignalKind::interrupt()),
            hangup: signal(SignalKind::hangup()),
        }
    }
}

/// Reloads the configuration on every `SIGHUP`, for as long as the process runs.
///
/// The contract is that a bad configuration is a no-op, not an outage: on any
/// failure the error is logged and the running configuration stays in force. This
/// matters because the usual sender of this signal is unattended (a
/// `certbot --deploy-hook` after a renewal), and a proxy that exited on a
/// half-written certificate file would turn a routine renewal into downtime.
///
/// Only new connections pick up the change; existing ones keep the configuration
/// they were accepted with. For a certificate that is the only sane reading (the
/// old one is still valid for the session that negotiated it), and for credentials
/// it means a revoked user keeps their current tunnels until they reconnect.
///
/// The reload itself runs on the blocking pool rather than on the async task.
/// It reads the configuration file and parses the certificate and key, which is
/// file I/O and CPU work. On a host whose runtime has one worker thread, such as
/// a one-vCPU VPS, that worker also drives the endpoint and every connection.
/// Running it inline would stop every packet and timer for the length of the
/// parse; `spawn_blocking` uses the pool `main` already sizes for this kind of
/// work.
#[cfg(unix)]
async fn watch_for_reload(
    hangup: std::io::Result<tokio::signal::unix::Signal>,
    handle: volto::quic::ReloadHandle,
    path: PathBuf,
) {
    let mut hangup = match hangup {
        Ok(stream) => stream,
        Err(error) => {
            warn!(
                log_id = "huvnt4b6",
                %error,
                "could not install the SIGHUP handler; reload is unavailable"
            );
            return;
        }
    };

    while hangup.recv().await.is_some() {
        info!(
            log_id = "ihxwv0oi",
            path = %path.display(),
            "received SIGHUP, reloading configuration"
        );

        // Both cloned because the blocking task takes ownership. The handle is
        // a set of `Arc`s and the path one allocation, so the copy costs
        // nothing next to the parse it feeds.
        let reload = handle.clone();
        let reloading = path.clone();
        let result = tokio::task::spawn_blocking(move || reload.reload(&reloading)).await;

        match result {
            Ok(Ok(_)) => {}
            // `{error:#}` prints the whole anyhow chain, which is where the
            // specific offending field ends up.
            Ok(Err(error)) => error!(
                log_id = "k977pzqe",
                error = format!("{error:#}"),
                "configuration reload failed; the running configuration is unchanged"
            ),
            // The blocking task panicked. Unlike a refused reload, a panic can
            // leave the swap half-applied, so this does not claim the running
            // configuration is unchanged; its own id lets an operator tell the
            // two failures apart in the journal.
            Err(error) => error!(
                log_id = "r7m2xq4p",
                %error,
                "the configuration reload task panicked; the running configuration \
                 may have changed"
            ),
        }
    }
}

/// Turns a termination signal into a graceful shutdown.
///
/// SIGTERM is what a service manager sends (systemd's `stop`, a container
/// runtime's `docker stop`), SIGINT is Ctrl-C in a terminal. Both mean the same
/// thing here: stop taking new work, let the existing tunnels finish, then exit.
///
/// A second signal is not special-cased into an immediate exit: the grace period
/// already bounds the wait, and an operator in a hurry has SIGKILL.
async fn watch_for_signals(
    #[cfg(unix)] terminate: std::io::Result<tokio::signal::unix::Signal>,
    #[cfg(unix)] interrupt: std::io::Result<tokio::signal::unix::Signal>,
    trigger: Trigger,
) {
    #[cfg(unix)]
    {
        // A stream that could not be created is reported, and the watcher goes
        // on with the other one. Giving up on both would leave a signal whose
        // handler is installed waiting in a stream nobody reads, so the process
        // could not be stopped gracefully at all.
        let terminate = terminate
            .inspect_err(|error| {
                warn!(log_id = "kuce6ga8", %error, "could not install the SIGTERM handler");
            })
            .ok();
        let interrupt = interrupt
            .inspect_err(|error| {
                warn!(log_id = "mkf6oai0", %error, "could not wait for SIGINT");
            })
            .ok();

        let Some(signal_name) = first_termination(terminate, interrupt).await else {
            return;
        };

        info!(
            log_id = "osdc324g",
            signal = signal_name,
            "received a termination signal"
        );
    }

    #[cfg(not(unix))]
    {
        if let Err(error) = tokio::signal::ctrl_c().await {
            warn!(log_id = "r387h9om", %error, "could not wait for Ctrl-C");
            return;
        }
        info!(log_id = "rob6myh8", "received Ctrl-C");
    }

    trigger.fire();
}

/// The name of the first of `SIGTERM` and `SIGINT` to arrive, among the streams
/// that exist, or `None` at once when neither does.
#[cfg(unix)]
async fn first_termination(
    mut terminate: Option<tokio::signal::unix::Signal>,
    mut interrupt: Option<tokio::signal::unix::Signal>,
) -> Option<&'static str> {
    /// The next signal on `stream`, or never when there is no stream.
    async fn next(stream: &mut Option<tokio::signal::unix::Signal>) {
        match stream {
            Some(stream) => {
                stream.recv().await;
            }
            None => std::future::pending().await,
        }
    }

    if terminate.is_none() && interrupt.is_none() {
        return None;
    }
    tokio::select! {
        () = next(&mut terminate) => Some("SIGTERM"),
        () = next(&mut interrupt) => Some("SIGINT"),
    }
}

/// The variable systemd sets when a service's standard streams go to the journal.
///
/// Its value is the `device:inode` of that connection (`systemd.exec(5)`); only
/// its presence is used here, see [`logs_to_journal`].
const JOURNAL_STREAM: &str = "JOURNAL_STREAM";

/// Installs the tracing subscriber.
///
/// `RUST_LOG` wins over `log.level` so verbosity can be raised without touching
/// the config file. A `RUST_LOG` value that does not parse, or that parses and
/// is [`FilterRefusal::NotALevel`], is not silently treated as absent: the
/// subscriber is installed on `log.level` and the reason is reported
/// immediately after, so the operator can see that the variable did not do what
/// they meant. A value that would turn this server's own lines off
/// ([`FilterRefusal::Silences`]) is an error, returned before any subscriber
/// exists, so startup fails the way a refused configuration does.
///
/// Under systemd each line additionally carries a syslog priority prefix; see
/// [`JournalPriority`]. In a terminal the output is unchanged.
fn init_tracing(level: &str) -> Result<()> {
    let rust_log = std::env::var_os("RUST_LOG");

    let mut invalid_rust_log = None;
    let filter = match filter_source(rust_log.as_deref()) {
        FilterSource::Config => tracing_subscriber::EnvFilter::try_new(level)
            .with_context(|| format!("log.level = {level:?} is not a valid filter"))?,
        FilterSource::RustLog => tracing_subscriber::EnvFilter::try_from_default_env()
            .context("RUST_LOG is set and parses, but could not be read back")?,
        FilterSource::InvalidRustLog(error) => {
            invalid_rust_log = Some(error);
            tracing_subscriber::EnvFilter::try_new(level)
                .with_context(|| format!("log.level = {level:?} is not a valid filter"))?
        }
        FilterSource::Refused(reason) => anyhow::bail!("{reason}"),
    };

    let builder = tracing_subscriber::fmt().with_env_filter(filter);

    if logs_to_journal(std::env::var_os(JOURNAL_STREAM).as_deref()) {
        builder
            // The journal stores whatever bytes arrive, and the default ANSI
            // detection only consults NO_COLOR. Without this, colour escapes
            // end up inside journald and the forwarded syslog files.
            .with_ansi(false)
            .event_format(JournalPriority(
                tracing_subscriber::fmt::format::Format::default(),
            ))
            .init();
    } else {
        builder.init();
    }

    // After `init`, or the line goes nowhere. `log.level` has already been
    // validated by `Config::validate`, so `level` is the level in force.
    if let Some(error) = invalid_rust_log {
        warn!(
            log_id = "c3n8kq2w",
            %error,
            level = %level,
            "RUST_LOG is set but is not a valid filter, so it was ignored; \
             log.level is in force instead. Fix or unset RUST_LOG and restart."
        );
    }

    Ok(())
}

/// What decides the filter [`init_tracing`] installs.
///
/// An unset `RUST_LOG` and a set-but-unparseable one are not the same thing:
/// the first says nothing and `log.level` is the only instruction, while the
/// second is an operator's mistake worth a line in the journal.
/// [`EnvFilter::try_from_default_env`] alone cannot tell them apart, because it
/// returns `Err` for both. That is why the variable's presence is read first.
/// [`FilterSource::Refused`] is the outcome that stops the start.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FilterSource {
    /// `RUST_LOG` is absent: `log.level` applies.
    Config,
    /// `RUST_LOG` is set and parses: it applies, overriding `log.level`.
    RustLog,
    /// `RUST_LOG` is set and does not parse, or is
    /// [`FilterRefusal::NotALevel`]: `log.level` applies, and this is the
    /// reason to report once the subscriber exists.
    InvalidRustLog(String),
    /// `RUST_LOG` parses and turns this server's own lines off
    /// ([`FilterRefusal::Silences`]): startup fails with this reason.
    Refused(String),
}

/// Reads `RUST_LOG`'s value, as returned by `std::env::var_os`, into the
/// decision [`init_tracing`] acts on.
///
/// Split out so every outcome is testable without mutating the process
/// environment, which this binary's tests share across threads. The value is
/// taken as an argument rather than read here for the same reason.
///
/// The rule is `volto::config::filter_refusal`, the one `log.level` is held to,
/// so a bare word must be one of the five level names and nothing may turn the
/// `volto` target off. Two things differ, both because the value comes from the
/// environment: it is trimmed first, and only a value that silences this
/// server stops the start. Any other refusal falls back to `log.level`, which
/// has already passed the same rule.
fn filter_source(rust_log: Option<&OsStr>) -> FilterSource {
    let Some(raw) = rust_log else {
        return FilterSource::Config;
    };
    let Some(text) = raw.to_str() else {
        return FilterSource::InvalidRustLog("RUST_LOG is not valid UTF-8".to_owned());
    };
    let parsed = tracing_subscriber::EnvFilter::try_new(text);
    match (
        volto::config::filter_refusal("RUST_LOG", text.trim()),
        parsed,
    ) {
        (Some(FilterRefusal::NotALevel(reason)), _) => FilterSource::InvalidRustLog(reason),
        (_, Err(error)) => FilterSource::InvalidRustLog(error.to_string()),
        (Some(FilterRefusal::Silences(reason)), Ok(_)) => FilterSource::Refused(reason),
        (None, Ok(_)) => FilterSource::RustLog,
    }
}

/// Whether this process's log output is being read by journald.
///
/// Deliberately a presence test rather than an `fstat` of stdout compared against
/// the `device:inode` in the value: the shipped unit sends both standard streams
/// to the journal, so anything that sets the variable is a journal, and a wrong
/// answer here costs a cosmetic prefix rather than a log line. Taking the value as
/// an argument keeps it testable without mutating the environment of a running
/// test binary.
fn logs_to_journal(journal_stream: Option<&OsStr>) -> bool {
    journal_stream.is_some_and(|value| !value.is_empty())
}

/// The syslog severity for a tracing level, formatted as a `printk` prefix.
///
/// Syslog has eight severities and tracing has five, so the mapping is not onto:
/// ERROR/WARN/INFO land on their namesakes (3/4/6), while DEBUG and TRACE share
/// 7, debug, the least severe thing syslog can say.
fn syslog_prefix(level: &Level) -> &'static str {
    match *level {
        Level::ERROR => "<3>",
        Level::WARN => "<4>",
        Level::INFO => "<6>",
        // DEBUG and TRACE.
        _ => "<7>",
    }
}

/// Wraps an event formatter so each line starts with its syslog priority.
///
/// volto writes plain text to stdout, and journald files plain text as PRIORITY=6
/// (info) whatever the line says, so without a prefix `journalctl -u volto -p
/// warning` returns nothing. A leading `<N>` fixes that: journald parses it,
/// strips it, and files the record with that priority. `SyslogLevelPrefix=`
/// defaults to true, so the shipped unit needs no change for this to take
/// effect.
///
/// Only the prefix is ours; everything after it is the wrapped formatter's
/// output, so the log format does not fork into two. The default formatter emits
/// exactly one line per event, which is what makes writing the prefix once per
/// event the same thing as writing it at the start of the line, the only place
/// systemd looks for it.
struct JournalPriority<F>(F);

impl<S, N, F> FormatEvent<S, N> for JournalPriority<F>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
    F: FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        writer.write_str(syslog_prefix(event.metadata().level()))?;
        self.0.format_event(ctx, writer, event)
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::Registry;
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::fmt::format::{DefaultFields, Format};

    use super::*;

    /// Collects everything a subscriber writes, so the formatted bytes can be
    /// asserted on directly.
    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedBuffer {
        fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("buffer lock")).into_owned()
        }
    }

    impl std::io::Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("buffer lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for SharedBuffer {
        type Writer = SharedBuffer;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// One event per level, captured with the given formatter, newest last.
    fn capture<E>(format: E) -> String
    where
        E: FormatEvent<Registry, DefaultFields> + Send + Sync + 'static,
    {
        let buffer = SharedBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter("trace")
            .with_ansi(false)
            .with_writer(buffer.clone())
            .event_format(format)
            .finish();

        // A scoped subscriber rather than the global one: this binary's tests all
        // share a process, and a global default can only be installed once.
        tracing::subscriber::with_default(subscriber, || {
            error!("an error");
            warn!("a warning");
            info!("some information");
            tracing::debug!("a debug note");
            tracing::trace!("a trace note");
        });

        buffer.contents()
    }

    #[test]
    fn every_level_maps_to_its_syslog_severity() {
        assert_eq!(syslog_prefix(&Level::ERROR), "<3>");
        assert_eq!(syslog_prefix(&Level::WARN), "<4>");
        assert_eq!(syslog_prefix(&Level::INFO), "<6>");
        assert_eq!(syslog_prefix(&Level::DEBUG), "<7>");
        assert_eq!(syslog_prefix(&Level::TRACE), "<7>");
    }

    /// A `SIGINT` stream that could not be created leaves `SIGTERM` watched.
    ///
    /// The signal is raised in this test process, which is safe because the
    /// `SIGTERM` stream exists first, so tokio's handler takes it.
    #[cfg(unix)]
    #[tokio::test]
    async fn sigterm_is_still_awaited_without_a_sigint_stream() {
        use rustix::process::{Signal, getpid, kill_process};
        use tokio::signal::unix::{SignalKind, signal};

        let terminate = signal(SignalKind::terminate()).expect("a SIGTERM stream");
        let waiting = tokio::spawn(first_termination(Some(terminate), None));
        // Before any signal the wait is still on: a stream is waited on, not
        // taken as having fired.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !waiting.is_finished(),
            "the wait ended before any signal was sent"
        );

        kill_process(getpid(), Signal::TERM).expect("SIGTERM must be deliverable");

        let name = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("SIGTERM must end the wait")
            .expect("the waiting task");
        assert_eq!(name, Some("SIGTERM"));

        assert_eq!(first_termination(None, None).await, None);
    }

    /// systemd sets the variable to `device:inode`; nothing else sets it.
    #[test]
    fn the_journal_is_detected_from_the_environment() {
        assert!(logs_to_journal(Some(OsStr::new("8:12345"))));
        // Not set: an interactive `cargo run`, which must be left alone.
        assert!(!logs_to_journal(None));
        // Set but empty is not a journal either.
        assert!(!logs_to_journal(Some(OsStr::new(""))));
    }

    /// An error with a cause spans several lines, and journald reads the
    /// priority per line, so each one carries it. Off the journal the text is
    /// the standard library's own `Error: {:?}`.
    #[test]
    fn a_start_failure_is_prefixed_on_every_line_in_the_journal() {
        let error = anyhow::anyhow!("the root cause").context("failed to start");

        let plain = failure_report(&error, false);
        assert_eq!(plain, format!("Error: {error:?}\n"));
        assert!(
            plain.lines().count() > 1,
            "the cause is on a line of its own"
        );

        let journal = failure_report(&error, true);
        assert_eq!(journal.lines().count(), plain.lines().count());
        for (prefixed, line) in journal.lines().zip(plain.lines()) {
            assert_eq!(prefixed, format!("<3>{line}"));
        }
        assert!(journal.ends_with('\n'));
    }

    /// A `RUST_LOG` that is set but does not parse is not the same as one that
    /// is absent: the first has an error worth reporting, the second does not.
    #[test]
    fn an_invalid_rust_log_is_told_apart_from_an_unset_one() {
        assert_eq!(filter_source(None), FilterSource::Config);
        assert_eq!(
            filter_source(Some(OsStr::new("volto=debug,quinn=info"))),
            FilterSource::RustLog
        );

        match filter_source(Some(OsStr::new("volto=notalevel"))) {
            FilterSource::InvalidRustLog(error) => {
                assert!(
                    !error.trim().is_empty(),
                    "the parse error has to be kept for the warning"
                );
            }
            other => panic!("a set but unparseable RUST_LOG must be invalid: {other:?}"),
        }

        // `EnvFilter` accepts all of these. An empty value is an empty
        // directive set and enables nothing. A bare word that is not a level is
        // read as a target name, so `warning` means "the target named warning,
        // at trace" and enables nothing either. `volto` is a real target, and
        // is refused because the filter cannot tell it from such a typo. A bare
        // digit is a level to the filter, and refused because `log.level`
        // refuses it.
        for value in ["", "  ", "warning", "volto", "3", "5"] {
            match filter_source(Some(OsStr::new(value))) {
                FilterSource::InvalidRustLog(error) => assert!(
                    !error.trim().is_empty(),
                    "the reason has to be kept for the warning: {value:?}"
                ),
                other => panic!("RUST_LOG={value:?} must be reported and ignored: {other:?}"),
            }
        }

        // A bare level name is still a level, in any case. A target directive
        // is still accepted, numeric levels included, which is the reason
        // RUST_LOG is more than a level, and so is one that turns another
        // crate off while a default keeps this server on.
        for value in [
            "warn",
            " INFO ",
            "volto=debug",
            "volto=3",
            "volto=trace,quinn=warn",
            "info,quinn=off",
            "off,volto=info",
        ] {
            assert_eq!(
                filter_source(Some(OsStr::new(value))),
                FilterSource::RustLog,
                "RUST_LOG={value:?} must still apply"
            );
        }

        // A value that turns this server's own lines off stops the start, in
        // any letter case and in tracing's numeric form, and so does a list
        // that turns the `volto` target or one of its modules off, or names
        // only other targets and so matches none of this server's lines.
        for value in [
            "off",
            " OFF",
            "0",
            "volto=off",
            "volto=0",
            "volto::quic=off",
            "info,volto=off",
            "quinn=off",
        ] {
            match filter_source(Some(OsStr::new(value))) {
                FilterSource::Refused(reason) => {
                    assert!(reason.contains("RUST_LOG"), "{reason}");
                    assert!(reason.contains(value.trim()), "{reason}");
                    assert!(reason.contains("\"info\""), "{reason}");
                }
                other => panic!("RUST_LOG={value:?} must stop the start: {other:?}"),
            }
        }

        // Non-UTF-8 is set but unreadable, not unset: the filter parser needs a
        // string, so there is an error to report and `log.level` to fall back to.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            assert_matches!(
                filter_source(Some(OsStr::from_bytes(b"volto=\xff"))),
                FilterSource::InvalidRustLog(_)
            );
        }
    }

    /// The prefix has to be the *first* thing on the line, or journald files the
    /// line verbatim at PRIORITY=6 and prints the `<N>` to the operator.
    #[test]
    fn each_line_starts_with_its_priority() {
        let logged = capture(JournalPriority(Format::default()));
        let lines: Vec<&str> = logged.lines().collect();

        // `with_ansi(false)` on the builder must reach the wrapped formatter:
        // these bytes end up inside journald and the forwarded syslog otherwise.
        assert!(
            !logged.contains('\u{1b}'),
            "no ANSI escapes may reach the journal; log was:\n{logged}"
        );
        assert_eq!(lines.len(), 5, "one line per event; log was:\n{logged}");
        for (line, (prefix, message)) in lines.iter().zip([
            ("<3>", "an error"),
            ("<4>", "a warning"),
            ("<6>", "some information"),
            ("<7>", "a debug note"),
            ("<7>", "a trace note"),
        ]) {
            assert!(
                line.starts_with(prefix),
                "{line:?} must start with {prefix}"
            );
            // Everything after the prefix is still the default rendering: the
            // prefix is added to the format, it does not replace it.
            assert!(line.contains(message), "{line:?} must carry its message");
        }
        assert!(lines[0].contains("ERROR"), "log was:\n{logged}");
        assert!(lines[1].contains("WARN"), "log was:\n{logged}");
    }

    /// Off the journal the output is byte-for-byte what it always was.
    #[test]
    fn without_the_wrapper_no_prefix_is_written() {
        let logged = capture(Format::default());

        for line in logged.lines() {
            assert!(
                !line.starts_with('<'),
                "a terminal must not see a priority prefix: {line:?}"
            );
        }
        assert!(logged.contains("a warning"), "log was:\n{logged}");
    }
}
