//! `volto` — MASQUE proxy server binary: CLI, logging, assembly.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info, warn};
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Loaded and validated before logging exists, so configuration errors are
    // reported by returning them from main.
    let config = Config::load(&cli.config)?;
    init_tracing(&config.log.level)?;

    // Only now that a subscriber exists: settings that are legal but risky —
    // "authentication is off" above all — are useless if they are logged into a
    // subscriber that has not been installed yet.
    for warning in config.warnings() {
        tracing::warn!("{warning}");
    }

    let server = Server::bind(Arc::new(config))?;

    // Both installed before the accept loop starts, so a signal arriving during
    // startup is not missed.
    tokio::spawn(watch_for_signals(server.shutdown_trigger()));
    #[cfg(unix)]
    tokio::spawn(watch_for_reload(server.reload_handle(), cli.config.clone()));

    server.run().await;

    info!("volto stopped");
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
    use tokio::signal::unix::{signal, SignalKind};

    let mut hangup = match signal(SignalKind::hangup()) {
        Ok(stream) => stream,
        Err(error) => {
            warn!(%error, "could not install the SIGHUP handler; reload is unavailable");
            return;
        }
    };

    while hangup.recv().await.is_some() {
        info!(path = %path.display(), "received SIGHUP, reloading configuration");

        if let Err(error) = handle.reload(&path) {
            // `{error:#}` prints the whole anyhow chain, which is where the
            // specific offending field ends up.
            error!(
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
        use tokio::signal::unix::{signal, SignalKind};

        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(error) => {
                // Without this the process can still be stopped, just not
                // gracefully, so it is not worth refusing to start over.
                warn!(%error, "could not install the SIGTERM handler");
                return;
            }
        };

        let signal_name = tokio::select! {
            _ = terminate.recv() => "SIGTERM",
            result = tokio::signal::ctrl_c() => match result {
                Ok(()) => "SIGINT",
                Err(error) => {
                    warn!(%error, "could not wait for SIGINT");
                    return;
                }
            },
        };

        info!(signal = signal_name, "received a termination signal");
    }

    #[cfg(not(unix))]
    {
        if let Err(error) = tokio::signal::ctrl_c().await {
            warn!(%error, "could not wait for Ctrl-C");
            return;
        }
        info!("received Ctrl-C");
    }

    trigger.fire();
}

/// Installs the tracing subscriber.
///
/// `RUST_LOG` wins over `log.level` so verbosity can be raised without touching
/// the config file.
fn init_tracing(level: &str) -> Result<()> {
    let filter = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => tracing_subscriber::EnvFilter::try_new(level)
            .with_context(|| format!("log.level = {level:?} is not a valid filter"))?,
    };

    tracing_subscriber::fmt().with_env_filter(filter).init();

    Ok(())
}
