//! Reloading a running server: the live configuration generation an accept
//! runs a connection on, and the lock that orders a reload against the drain.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};

use anyhow::{Context, Result, bail};
use tracing::{info, warn};

use crate::config::Config;
use crate::gate::{Expected, Policy};
use crate::names::Names;
use crate::shutdown::Shutdown;
use crate::{tls, tunnel};

#[cfg(doc)]
use super::Server;
use super::socket::{RequestedBuffers, SocketBuffer, warn_if_fd_budget_is_tight};
use super::transport::transport_config;

/// Builds the quinn server configuration: TLS identity plus transport parameters.
///
/// Shared by [`Server::bind`] and [`ReloadHandle::reload`] so the two cannot drift
/// apart. A reload that quietly dropped the stream limit or the keep-alive would
/// be hard to find, since everything would work until the connection went idle
/// behind a relay. It is also what makes every value below reloadable: a
/// `SIGHUP` rebuilds this, writes it into the [`Live`] generation
/// [`Server::accept_on_one_generation`] reads and hands a copy to
/// `Endpoint::set_server_config`, so the new numbers apply to every connection
/// this process accepts from then on.
///
/// The endpoint's copy governs the pending path: quinn-proto reads it as a
/// connection's first Initial arrives, for the Initial keys, token validation
/// and the Retry seal. The handshake runs on the generation's copy instead; see
/// [`Server::accept_on_one_generation`].
///
/// Connections already open keep the transport parameters they negotiated at
/// handshake time. QUIC has no way to renegotiate them mid-connection, so this
/// is a property of the protocol rather than a shortcut.
///
/// It also returns the ECH keys the TLS layer was built with, for the startup
/// and reload lines, and the gate's policy. Both are taken from the TLS
/// configuration that was built rather than from the files again, so the line
/// reports the keys in force and the socket gate opens ECH extensions with the
/// very keys libssl holds.
pub(super) fn server_config(
    config: &Config,
) -> Result<(quinn::ServerConfig, Option<Arc<tls::EchKeySet>>, Policy)> {
    let crypto = tls::server_config(config)?;
    let ech = crypto.ech().cloned();
    let policy = Policy::new(
        Names::new(&config.security.expected_sni),
        ech.clone(),
        config.security.require_ech,
    );
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(transport_config(&config.limits)?));

    Ok((server_config, ech, policy))
}

/// What a new connection is accepted with, one value per configuration
/// generation, so one read gets a matching pair (D22).
pub(super) struct Live {
    /// The configuration, with the credentials and destination rules built
    /// from it, shared by every connection of the generation.
    pub(super) generation: Arc<tunnel::Generation>,
    /// The transport parameters and the TLS identity, kept beside the
    /// endpoint's own copy rather than read back out of it, because quinn
    /// exposes no getter and because the endpoint's copy may be a generation
    /// old by the time a connection is accepted
    /// ([`Server::accept_on_one_generation`] says why).
    pub(super) quic: Arc<quinn::ServerConfig>,
}

/// The live generation, swapped wholesale on reload.
///
/// A plain `RwLock` rather than anything fancier: it is read once per accepted
/// connection and written once per `SIGHUP`, and the guard is never held across an
/// await, only long enough to clone the `Arc`.
pub(super) type LiveSlot = Arc<RwLock<Arc<Live>>>;

/// Orders a reload against the drain.
///
/// [`ReloadHandle::reload`] reads the shutdown latch and then re-opens the
/// listener, so a `SIGTERM` landing between the two would put the endpoint back
/// to accepting handshakes [`Server::drain`] has just refused, and quinn's
/// unaccepted `Incoming` queue would grow for the whole grace period. D22 states
/// that this must not happen. `reload` holds the guard across the latch read and
/// its writes, `drain` across its own `set_server_config(None)`. An accept does
/// not take it: the [`Live`] it reads is one value.
///
/// A `std::sync::Mutex<()>` because there is nothing to protect but the order.
/// It is never held across an await, since `reload` is synchronous throughout
/// and `drain` holds it for one `set_server_config` call. The slow half of a
/// reload, parsing the file and the certificate, happens before it is taken.
#[derive(Clone)]
pub(super) struct ConfigSwap(Arc<Mutex<()>>);

impl ConfigSwap {
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(())))
    }

    /// Holds the swap for as long as the returned guard lives.
    ///
    /// Poisoning would mean a panic between two of the writes, which is a
    /// half-applied reload however the lock is treated; taking the guard anyway
    /// leaves the next reload able to finish the job, where refusing would
    /// freeze the configuration for the life of the process.
    pub(super) fn hold(&self) -> MutexGuard<'_, ()> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Replaces the configuration of a running server.
///
/// The point of this type is a guarantee: a `SIGHUP` with a broken configuration
/// file (a typo, a half-written certificate mid-renewal) must leave the server
/// running exactly as it was. A proxy that exits when handed a bad config would
/// turn a typo into an outage, and `certbot --deploy-hook` sends `SIGHUP` with
/// nobody watching.
///
/// So nothing is applied until everything has been parsed and validated: the file
/// is read, the new certificate and key are loaded, and only then is anything
/// swapped. There is no intermediate state where the endpoint has the new
/// certificate but the old users, or vice versa.
#[derive(Clone)]
pub struct ReloadHandle {
    pub(super) endpoint: quinn::Endpoint,
    /// The server's own slot, written in the same guarded block as the
    /// endpoint's copy; see [`Live`].
    pub(super) live: LiveSlot,
    pub(super) shutdown: Shutdown,
    /// The SNI gate's list, which is swapped with the rest (D106).
    pub(super) expected: Expected,
    /// The server's own, so a reload and the drain cannot interleave their
    /// writes; see [`ConfigSwap`].
    pub(super) swap: ConfigSwap,
    /// The `[server] listen` the endpoint was bound with, for one of the three
    /// keys a reload has to say it is ignoring.
    pub(super) listen: SocketAddr,
    /// The other two, which are startup-only for the same reason; see
    /// [`RequestedBuffers`].
    pub(super) requested_buffers: RequestedBuffers,
    /// The `[log].level` the tracing subscriber was built with.
    ///
    /// The subscriber is installed once, before the server binds, and nothing
    /// rebuilds it: a reload can swap the live [`Config`] but not the filter
    /// every line is judged by. Kept from bind so a reload can compare the file
    /// against the value actually in force and say that a restart is needed;
    /// see [`ReloadHandle::reload`].
    pub(super) startup_log_level: String,
}

impl ReloadHandle {
    /// Re-reads the configuration file and applies it, or changes nothing.
    ///
    /// Returns the newly applied configuration, or an error describing why the old
    /// one is still in force. Existing connections are deliberately unaffected:
    /// they keep the configuration they were accepted with (see `Server::serve`).
    pub fn reload(&self, path: &Path) -> Result<Arc<Config>> {
        // Parses, validates, and checks that the certificate files are readable.
        let config = Arc::new(Config::load(path)?);

        // Loads and parses the certificate and key, which is the step most likely
        // to fail during a renewal, and the ECH key. Done before anything is
        // swapped.
        let (quic_config, ech, policy) = server_config(&config)
            .context("the new configuration's certificate and key are not usable")?;

        // Rendered before the guard is taken, because it opens and parses
        // `server.cert` a second time (see `Config::warnings`), and the drain
        // waits for the guard. The strings are logged after the swap.
        let warnings = config.warnings();

        // One value for the slot and the endpoint's copy (see
        // `server_config`), so the two cannot be two different configurations.
        let live = Arc::new(Live {
            generation: Arc::new(tunnel::Generation::new(config.clone())),
            quic: Arc::new(quic_config),
        });

        // Held from the latch read through the last write, because reading the
        // latch and then re-opening the listener is the race D22 forbids. Every
        // parse is before it and every report after it, so neither a large
        // certificate nor a blocked log sink can delay a drain that waits for
        // it.
        let swapping = self.swap.hold();

        // A reload during shutdown must not re-open the listener that `drain` just
        // closed. Refusing is safer than racing it.
        if self.shutdown.is_fired() {
            bail!("the server is shutting down; the configuration was not reloaded");
        }

        // Past this point nothing can fail, so the swaps cannot half-apply.
        //
        // The gate's policy goes first, and deliberately: between it and the
        // endpoint's own configuration the socket admits the new set of names
        // while the endpoint still holds the old certificate, which is a
        // handshake that gets as far as the TLS layer and is refused there. The
        // other order would have the endpoint present the new certificate to a
        // name the socket still drops, which is the same refusal without the
        // reply. The gate exists so that a name it does not know gets no reply
        // at all. A new ECH key is answered in between as well, and the answer
        // never carries an ECHConfigList. When the old configuration had a
        // key, the socket admits a flight that opens under the new key while
        // libssl still holds the old one, which does not accept it, and the TLS
        // layer's second line refuses a ClientHello whose ECH it did not accept
        // before it sends anything. When the old configuration had no key, that
        // second line is off and libssl has no ECH keys, so it goes on with the
        // outer ClientHello: the outer name is judged by the old name list, and
        // a name it admits gets an ordinary handshake with the certificate.
        // libssl sends retry configs only when it holds ECH keys, so that
        // handshake carries no ECHConfigList either.
        //
        // The slot goes second, as one write, so an accept reads the old pair or
        // the new pair and never one of each. An accept between the gate's list
        // and the slot runs wholly on the old generation, certificate included,
        // which is the TLS refusal of the paragraph above for a name only the
        // new list admits. `set_server_config` goes after the slot so the
        // endpoint never holds a configuration the slot does not hold yet; an
        // accept between the two states the new configuration over an
        // `Incoming` the endpoint's old copy opened, as for any handshake
        // queued before a reload.
        //
        // One flight can still be answered across this swap. A flight the
        // gate admitted under a key this reload removes, and whose datagrams
        // quinn reads only after `set_server_config`, reaches a libssl that no
        // longer holds that key. libssl does not accept its ECH and the
        // ClientHello callback refuses it with an alert. The peer held a key
        // the server accepted a moment earlier, and the alert carries no
        // ECHConfigList.
        self.expected.set(policy);
        *self.live.write().unwrap_or_else(PoisonError::into_inner) = live.clone();
        self.endpoint.set_server_config(Some((*live.quic).clone()));
        drop(swapping);

        self.report(path, &config, ech.as_ref(), warnings);
        Ok(config)
    }

    /// The lines a reload that has been applied writes: what is now in force,
    /// then each startup-only key the file changed, the configuration's own
    /// warnings, and the descriptor budget.
    ///
    /// Each one reports what was swapped and decides nothing, which is why
    /// [`Self::reload`] calls this after it has let go of the swap.
    fn report(
        &self,
        path: &Path,
        config: &Config,
        ech: Option<&Arc<tls::EchKeySet>>,
        warnings: Vec<String>,
    ) {
        info!(
            log_id = "aie853ib",
            path = %path.display(),
            users = config.auth.users.len(),
            cert = %config.server.cert.display(),
            // The ECH keys in force from now on: the current key, and the
            // previous key a rotation still accepts. The public name is one
            // the key file's check accepted, an LDH host name, so `Display`
            // is safe.
            ech = ech.is_some(),
            ech_config_id = %crate::logfmt::or_dash(ech.map(|e| e.current().config_id())),
            ech_previous_config_id = %crate::logfmt::or_dash(
                ech.and_then(|e| e.previous()).map(|e| e.config_id())
            ),
            ech_public_name = %crate::logfmt::or_dash(ech.map(|e| e.current().public_name())),
            // Whether the gate drops every handshake without ECH (D115).
            require_ech = config.security.require_ech,
            "configuration reloaded; new connections will use it"
        );

        // Said rather than done. A reload never rebinds: `docs/configuration.md`
        // and `docs/deployment.md` both promise that, because the usual sender of
        // SIGHUP is a renewal hook that rewrites the whole file, and a rebind
        // would take the proxy offline over a key nobody meant to change. This
        // line tells the operator that the rest of the file applied and this one
        // key did not.
        if config.server.listen != self.listen {
            warn!(
                log_id = "amplq5bv",
                bound = %self.listen,
                configured = %config.server.listen,
                "server.listen changed, but a reload cannot move the listening socket; \
                 the server is still bound where it started. Restart to apply it."
            );
        }

        // The subscriber that applies `log.level` is installed once, before the
        // server binds, and nothing rebuilds it. A reload stores the new value in
        // the live configuration, where nothing reads it, so without this line a
        // `SIGHUP` that raised verbosity looks exactly like one that did. The
        // strings are compared, not parsed filters: any textual change is one
        // the operator should hear about.
        if config.log.level != self.startup_log_level {
            warn!(
                log_id = "w8t2n5kr",
                startup = %self.startup_log_level,
                configured = %config.log.level,
                "log.level changed, but the tracing subscriber is built once at \
                 startup and a reload cannot change it; the server keeps the level \
                 it started with. Restart to apply it. RUST_LOG, if set, overrides \
                 log.level."
            );
        }

        for warning in &warnings {
            warn!(log_id = "bg9ux69o", "{warning}");
        }
        crate::config::copy_hidden_warnings(&warnings, tracing::enabled!(tracing::Level::WARN));

        // The same no-op as `listen` above, for the same reason and with the
        // same remedy: the sizes are asked of the socket when it is created and
        // a reload does not rebind it, so a changed value applies nothing. The
        // configured number is compared rather than the granted one, because
        // Linux reports back double what it granted.
        for (which, bound, configured) in [
            (
                SocketBuffer::Recv,
                self.requested_buffers.recv,
                config.limits.socket_recv_buffer,
            ),
            (
                SocketBuffer::Send,
                self.requested_buffers.send,
                config.limits.socket_send_buffer,
            ),
        ] {
            if configured != bound {
                warn!(
                    log_id = "om0np2q6",
                    key = which.key(),
                    bound,
                    configured,
                    "a startup-only socket buffer changed, but a reload cannot resize the \
                     socket the endpoint is bound to; it keeps the size it started with. \
                     Restart to apply it."
                );
            }
        }

        // Both halves of the product are reloadable, and `docs/deployment.md`
        // says a reload applies a raised `limits.max_connections`, so the check
        // `Server::bind` runs belongs here too. An operator raising a quota
        // during an incident is the case D19 wrote it for.
        warn_if_fd_budget_is_tight(&config.limits);
    }
}
