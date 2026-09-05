//! `volto` — MASQUE proxy server binary: CLI, logging, assembly.

// As in `lib.rs`: the binary crate is assembly over the library, and there is
// nothing here that could need `unsafe` either.
#![forbid(unsafe_code)]
// And, as in `lib.rs`, every item here is documented; this keeps it that way.
#![warn(missing_docs)]

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{Event, Level, Subscriber, error, info, warn};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;
use volto::config::Config;
use volto::quic::Server;
use volto::shutdown::Trigger;

/// Command line arguments.
#[derive(Debug, Parser)]
#[command(name = "volto", version, about = "MASQUE proxy server")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,

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
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Loaded and validated before logging exists, so configuration errors are
    // reported by returning them from main -- and before the runtime exists,
    // which is what the hand-built runtime below needs: the blocking pool is
    // sized from `max_connections` rather than left at tokio's 512, so that
    // every connection's reserved name-lookup slot has a thread to run on
    // (D90). `#[tokio::main]` cannot express that, which is the only reason it
    // is gone.
    let config = Config::load(&cli.config)?;

    // Deliberately the very next thing, and before the runtime is built: what
    // the flag promises is that nothing happens except reading the file.
    if cli.check_config {
        report_config_check(&cli.config, &config);
        return Ok(());
    }

    // The same place and the same promise. The two cannot both be set -- clap
    // refuses that command line -- so the order between them decides nothing.
    if cli.diagnostics {
        report_diagnostics(&cli.config, &config);
        return Ok(());
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(volto::net::blocking_pool_size(
            config.limits.max_connections,
        ))
        .build()
        .context("failed to build the async runtime")?;

    // Read before the configuration moves into `run`: it is what bounds the
    // wait below, and a `SIGHUP` cannot change it, since the runtime it applies
    // to was built from the file this process started on.
    let grace = config.server.shutdown_grace();

    let served = runtime.block_on(run(cli, config));

    // Deliberately not the implicit drop this used to end on. tokio's
    // `Runtime::drop` waits without limit for blocking tasks that have started,
    // and name resolution is one of those: `getaddrinfo` cannot be cancelled,
    // the thread stays in the stub resolver for as long as it takes, and a
    // client chooses the name (D90). So the process used to exit one resolver
    // timeout after the grace period rather than one grace period after the
    // signal, which `script/masque.service` turns into a SIGKILL at
    // `TimeoutStopSec`. Bounding it leaks the thread instead, which the process
    // is about to end anyway.
    volto::shutdown::stop_runtime(runtime, grace);

    served
}

/// Says that the file loaded, and repeats what starting on it would warn about.
///
/// Reached only when [`Config::load`] has already succeeded, so the failure
/// direction is not here: it is the `?` in `main`, which prints the same error
/// the service would print at startup and exits non-zero. That symmetry is the
/// whole value of the flag — `script/deploy.sh` asks the binary it is about to
/// install whether it can read the configuration this host already has, and an
/// answer that did not match what the service does on the same file would be
/// worse than no answer (D93, D94).
///
/// What it therefore covers is exactly what `Config::load` covers: the TOML
/// itself, every table's refusal of a key it does not know, and every range and
/// cross-field rule in `Config::validate` — the certificate and key existing as
/// files included. What it cannot cover is everything that is only decidable
/// once the process is the service: whether the port is free, whether the
/// certificate and key parse and match, whether `RLIMIT_NOFILE` (a property of
/// the unit, not of the file) leaves room for the configured quotas. Those stay
/// startup's business, and `docs/configuration.md` says so to the operator.
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
/// `tracing` -- the subscriber is not installed at this point in `main` and this
/// output is not a log line, so D100's accounted set is untouched. Everything
/// here is either this process's own memory, a `getrlimit` on itself, four files
/// under `/proc/sys`, or one `uname`.
///
/// Secrets are redacted because `Config` is printed through the `Debug` that
/// already does it: `impl Debug for config::User` renders the password as
/// `<redacted>`, which is the same guard that keeps a password out of the error
/// a malformed file produces. `conn::redact_credentials` is the other half of
/// that rule and is not reachable here -- it is for a header value, and no
/// header exists in this process.
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

/// `uname -srm`, or a line saying why there is none.
///
/// A process rather than a crate, because a dependency for three words is not
/// worth the supply chain, and this runs once in a command an operator typed.
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
async fn run(cli: Cli, config: Config) -> Result<()> {
    init_tracing(&config.log.level)?;

    // Only now that a subscriber exists: settings that are legal but risky —
    // "authentication is off" above all — are useless if they are logged into a
    // subscriber that has not been installed yet.
    for warning in config.warnings() {
        tracing::warn!(log_id = "f9be058r", "{warning}");
    }

    let server = Server::bind(Arc::new(config))?;

    // Both installed before the accept loop starts, so a signal arriving during
    // startup is not missed.
    tokio::spawn(watch_for_signals(server.shutdown_trigger()));
    #[cfg(unix)]
    tokio::spawn(watch_for_reload(server.reload_handle(), cli.config.clone()));

    server.run().await;

    info!(log_id = "fle471bm", "volto stopped");
    Ok(())
}

/// Reloads the configuration on every `SIGHUP`, for as long as the process runs.
///
/// The contract is that a bad configuration is a no-op, not an outage: on any
/// failure the error is logged and the running configuration stays in force. This
/// matters because the usual sender of this signal is unattended — a
/// `certbot --deploy-hook` after a renewal — and a proxy that exited on a
/// half-written certificate file would turn a routine renewal into downtime.
///
/// Only new connections pick up the change; existing ones keep the configuration
/// they were accepted with. For a certificate that is the only sane reading (the
/// old one is still valid for the session that negotiated it), and for credentials
/// it means a revoked user keeps their current tunnels until they reconnect.
#[cfg(unix)]
async fn watch_for_reload(handle: volto::quic::ReloadHandle, path: PathBuf) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hangup = match signal(SignalKind::hangup()) {
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

        if let Err(error) = handle.reload(&path) {
            // `{error:#}` prints the whole anyhow chain, which is where the
            // specific offending field ends up.
            error!(
                log_id = "k977pzqe",
                error = format!("{error:#}"),
                "configuration reload failed; the running configuration is unchanged"
            );
        }
    }
}

/// Turns a termination signal into a graceful shutdown.
///
/// SIGTERM is what a service manager sends (systemd's `stop`, a container
/// runtime's `docker stop`), SIGINT is Ctrl-C in a terminal. Both mean the same
/// thing here: stop taking new work, let the existing tunnels finish, then exit.
///
/// A second signal is not special-cased into an immediate exit — the grace period
/// already bounds the wait, and an operator in a hurry has SIGKILL.
async fn watch_for_signals(trigger: Trigger) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(error) => {
                // Without this the process can still be stopped, just not
                // gracefully, so it is not worth refusing to start over.
                warn!(log_id = "kuce6ga8", %error, "could not install the SIGTERM handler");
                return;
            }
        };

        let signal_name = tokio::select! {
            _ = terminate.recv() => "SIGTERM",
            result = tokio::signal::ctrl_c() => match result {
                Ok(()) => "SIGINT",
                Err(error) => {
                    warn!(log_id = "mkf6oai0", %error, "could not wait for SIGINT");
                    return;
                }
            },
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

/// The variable systemd sets when a service's standard streams go to the journal.
///
/// Its value is the `device:inode` of that connection (`systemd.exec(5)`); only
/// its presence is used here, see [`logs_to_journal`].
const JOURNAL_STREAM: &str = "JOURNAL_STREAM";

/// Installs the tracing subscriber.
///
/// `RUST_LOG` wins over `log.level` so verbosity can be raised without touching
/// the config file.
///
/// Under systemd each line additionally carries a syslog priority prefix; see
/// [`JournalPriority`]. In a terminal the output is unchanged.
fn init_tracing(level: &str) -> Result<()> {
    let filter = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => tracing_subscriber::EnvFilter::try_new(level)
            .with_context(|| format!("log.level = {level:?} is not a valid filter"))?,
    };

    let builder = tracing_subscriber::fmt().with_env_filter(filter);

    if logs_to_journal(std::env::var_os(JOURNAL_STREAM).as_deref()) {
        builder
            // The journal stores whatever bytes arrive, and the default ANSI
            // detection only consults NO_COLOR — without this, colour escapes
            // end up inside journald and the forwarded syslog files.
            .with_ansi(false)
            .event_format(JournalPriority(
                tracing_subscriber::fmt::format::Format::default(),
            ))
            .init();
    } else {
        builder.init();
    }

    Ok(())
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
/// 7 — debug, the least severe thing syslog can say.
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
/// (info) whatever the line says — so `journalctl -u volto -p warning` used to
/// return nothing and an operator had to grep for the word "WARN". A leading
/// `<N>` fixes that: journald parses it, strips it, and files the record with that
/// priority. `SyslogLevelPrefix=` defaults to true, so the shipped unit needs no
/// change for this to take effect.
///
/// Only the prefix is ours; everything after it is the wrapped formatter's
/// output, so the log format does not fork into two. The default formatter emits
/// exactly one line per event, which is what makes writing the prefix once per
/// event the same thing as writing it at the start of the line — the only place
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

    /// systemd sets the variable to `device:inode`; nothing else sets it.
    #[test]
    fn the_journal_is_detected_from_the_environment() {
        assert!(logs_to_journal(Some(OsStr::new("8:12345"))));
        // Not set: an interactive `cargo run`, which must be left alone.
        assert!(!logs_to_journal(None));
        // Set but empty is not a journal either.
        assert!(!logs_to_journal(Some(OsStr::new(""))));
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
