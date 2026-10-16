//! Reloading a running server: the live configuration, the server
//! configuration an accept runs a connection on, and the lock that orders the
//! writes to both.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};

use anyhow::{Context, Result, bail};
use quinn::crypto::rustls::QuicServerConfig;
use tracing::{info, warn};

use crate::config::Config;
use crate::gate::{Expected, Names};
use crate::shutdown::Shutdown;
use crate::tls;

#[cfg(doc)]
use super::Server;
use super::socket::{RequestedBuffers, SocketBuffer, warn_if_fd_budget_is_tight};
use super::transport::transport_config;

/// Builds the quinn server configuration: TLS identity plus transport parameters.
///
/// Shared by [`Server::bind`] and [`ReloadHandle::reload`] so the two cannot drift
/// — a reload that quietly dropped the stream limit or the keep-alive would be a
/// miserable bug to find, since everything would work until the connection went
/// idle behind a relay. It is also what makes every value below reloadable: a
/// `SIGHUP` rebuilds this, writes it to the slot [`Server::accept_under_the_swap`]
/// reads and hands a copy to `Endpoint::set_server_config`, so the new numbers
/// apply to every connection this process accepts from then on.
///
/// The endpoint's copy governs a different thing. quinn-proto 0.11.x reads it as
/// a connection's first Initial arrives, to derive the Initial keys and to
/// validate an address-validation token, and copies it into the buffer it keeps
/// for that pending `Incoming`, where it is what seals a Retry. It is not what
/// the handshake runs on: `Incoming::accept_with` replaces it with the one the
/// slot holds, which is what keeps the transport parameters and the live
/// [`Config`] on one side of a reload (D22).
///
/// Connections already open keep the transport parameters they negotiated at
/// handshake time — QUIC has no
/// way to renegotiate them mid-connection, so this is a property of the protocol
/// rather than a shortcut.
pub(super) fn server_config(config: &Config) -> Result<quinn::ServerConfig> {
    let crypto = tls::server_crypto(config)?;
    let quic_crypto = QuicServerConfig::try_from(crypto)
        .context("rustls configuration is not usable for QUIC (TLS 1.3 is required)")?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(Arc::new(transport_config(&config.limits)?));

    Ok(server_config)
}

/// The live configuration, swapped wholesale on reload.
///
/// A plain `RwLock` rather than anything fancier: it is read once per accepted
/// connection and written once per `SIGHUP`, and the guard is never held across an
/// await — only long enough to clone the `Arc`.
pub(super) type LiveConfig = Arc<RwLock<Arc<Config>>>;

/// The `quinn::ServerConfig` a new connection is accepted with.
///
/// The transport parameters and the TLS identity, kept beside the endpoint's own
/// copy rather than read back out of it, because quinn exposes no getter and
/// because the endpoint's copy is not what an accept has to use: since
/// quinn-proto 0.11.18 a pending `Incoming` carries the configuration the
/// endpoint held when its first Initial arrived, which is one generation too old
/// whenever a `SIGHUP` lands in between. [`Server::accept_under_the_swap`] reads
/// this slot and hands what it finds to `Incoming::accept_with`, so the accepted
/// connection runs on the same generation as the live [`Config`] beside it.
///
/// The same `RwLock` shape as [`LiveConfig`], for the same reasons: one read per
/// accepted connection, one write per `SIGHUP`, and the guard held only long
/// enough to clone the `Arc`. `quinn::ServerConfig` is a set of `Arc`s, so both
/// the clone into this slot and the clone out of it are a few reference counts.
pub(super) type LiveQuicConfig = Arc<RwLock<Arc<quinn::ServerConfig>>>;

/// Serialises everything that decides what a new connection is accepted with.
///
/// Four writes make a reload, the SNI gate's list, the live [`Config`], the
/// `quinn::ServerConfig` an accept runs on and the endpoint's own copy of it, and
/// a fifth closes the listener at the start of the drain. Held apart, they are
/// two check-then-act races on the same state.
///
/// The first is [`ReloadHandle::reload`] against [`Server::drain`]: the reload
/// reads the shutdown latch and then re-opens the listener, so a `SIGTERM`
/// landing between the two puts the endpoint back to accepting handshakes the
/// drain has just refused, and quinn's unaccepted `Incoming` queue grows for the
/// whole grace period. D22 states that this must not happen. The second is the
/// reload against an accept: a connection taken off `endpoint.accept()` between
/// two of the four writes runs on one generation's transport parameters and
/// another's `Authenticator`, `Policy` and quotas for its whole life, which is
/// the half-applied state the same ADR says there is none of.
///
/// Three callers take it. `reload` holds it across the latch read and all four
/// writes, `drain` across its own `set_server_config(None)`, and
/// [`Server::accept_under_the_swap`] across the pair of reads that decide what
/// one new connection runs on. The third closes the second race rather than
/// narrowing it, because both of those reads are now reads this process makes.
/// The first is the live [`Config`]. The second is [`LiveQuicConfig`], which
/// `Incoming::accept_with` then uses in place of the copy quinn-proto 0.11.x
/// pinned to the connection when its first Initial arrived. Nothing about the
/// accepted connection is decided by a read the endpoint driver makes on its own
/// (D22, addendum of 2026-09-17).
///
/// A `std::sync::Mutex<()>` because there is nothing to protect but the order:
/// the values themselves each have their own lock. It is never held across an
/// await, since `reload` is synchronous throughout, `drain` holds it for one
/// `set_server_config` call, and `accept_under_the_swap` for two synchronous
/// reads and the synchronous `Incoming::accept_with` they feed. The slow half of
/// a reload, parsing the file and the certificate, happens before it is taken.
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
/// file — a typo, a half-written certificate mid-renewal — must leave the server
/// running exactly as it was. A proxy that exits when handed a bad config would
/// turn a typo into an outage, and `certbot --deploy-hook` will send `SIGHUP` at
/// three in the morning with nobody watching.
///
/// So nothing is applied until everything has been parsed and validated: the file
/// is read, the new certificate and key are loaded, and only then is anything
/// swapped. There is no intermediate state where the endpoint has the new
/// certificate but the old users, or vice versa.
#[derive(Clone)]
pub struct ReloadHandle {
    pub(super) endpoint: quinn::Endpoint,
    pub(super) config: LiveConfig,
    /// The server's own slot, written in the same guarded block as `config` and
    /// as the endpoint's copy; see [`LiveQuicConfig`].
    pub(super) quic_config: LiveQuicConfig,
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
}

impl ReloadHandle {
    /// Re-reads the configuration file and applies it, or changes nothing.
    ///
    /// Returns the newly applied configuration, or an error describing why the old
    /// one is still in force. Existing connections are deliberately unaffected —
    /// they keep the configuration they were accepted with (see `Server::serve`).
    pub fn reload(&self, path: &Path) -> Result<Arc<Config>> {
        // Parses, validates, and checks that the certificate files are readable.
        let config = Arc::new(Config::load(path)?);

        // Loads and parses the certificate and key, which is the step most likely
        // to fail during a renewal. Done before anything is swapped.
        let quic_config = server_config(&config)
            .context("the new configuration's certificate and key are not usable")?;

        // Rendered before the guard is taken, because it opens and parses
        // `server.cert` a second time (see `Config::warnings`), and the guard
        // is the one `Server::accept_under_the_swap` takes for every connection
        // it accepts. The strings are logged after the swap, where they were.
        let warnings = config.warnings();

        // One value, two homes. `Server::accept_under_the_swap` reads the slot
        // and `Incoming::accept_with` uses what it finds, while the endpoint's
        // own copy governs the pending path: as a first Initial arrives it
        // derives the Initial keys and validates an address-validation token,
        // and quinn-proto 0.11.x pins it to that connection, where it seals a
        // Retry. Built here so the two cannot be two different configurations.
        let accepted_with = Arc::new(quic_config);

        // Everything from the latch read to the last write is one step, and the
        // drain takes the same lock around its own `set_server_config`. Held
        // here rather than only around the writes because the latch is a
        // check-then-act: reading it and then re-opening the listener is
        // precisely the race D22 forbids. Every parse above is deliberately
        // outside it, so a `SIGHUP` with a large certificate cannot delay a
        // drain that is waiting for this.
        let _swapping = self.swap.hold();

        // A reload during shutdown must not re-open the listener that `drain` just
        // closed. Refusing is safer than racing it.
        if self.shutdown.is_fired() {
            bail!("the server is shutting down; the configuration was not reloaded");
        }

        // Past this point nothing can fail, so the swaps cannot half-apply.
        //
        // The gate's list goes first, and deliberately: between it and the
        // endpoint's own configuration the socket admits the new set of names
        // while the endpoint still holds the old certificate, which is a
        // handshake that gets as far as the TLS layer and is refused there. The
        // other order would have the endpoint present the new certificate to a
        // name the socket still drops, which is the same refusal with the reply
        // removed -- and the gate's whole point is that a name it does not know
        // gets no reply at all.
        //
        // The live `Config` goes before the slot for a second reason, now that
        // `Server::accept_under_the_swap` takes this lock across both of the
        // reads a new connection makes: an accept can no longer land between the
        // two at all, so the order of these two is what a reader of this
        // function should be able to follow rather than what a connection
        // depends on. New users before new transport parameters is the order the
        // sentence above describes for the gate, read the same way: the half
        // that decides who gets in goes first.
        //
        // Two of the four writes are read in the endpoint driver, which never
        // takes the swap: `Gate::poll_recv` reads the gate's list on every
        // receive batch, and quinn-proto reads the endpoint's configuration
        // when a first Initial arrives. Their order is the one a connection can
        // see, and it is the order the first paragraph gives: the list before
        // the endpoint's configuration. The slot is read only under the swap, so
        // its place between them changes nothing a connection sees.
        // `set_server_config` goes after it so that the endpoint never holds a
        // configuration the slot does not hold yet. The live `Config` is also
        // read outside the swap, by `admit` for the connection cap and by
        // `Server::shutdown_grace`, but each of those reads one key and does
        // not compare it with any of the other three values, so the order of
        // the writes does not change what they see.
        self.expected.set(Names::new(&config.security.expected_sni));
        *self.config.write().unwrap_or_else(PoisonError::into_inner) = config.clone();
        *self
            .quic_config
            .write()
            .unwrap_or_else(PoisonError::into_inner) = accepted_with.clone();
        self.endpoint
            .set_server_config(Some((*accepted_with).clone()));

        info!(
            log_id = "aie853ib",
            path = %path.display(),
            users = config.auth.users.len(),
            cert = %config.server.cert.display(),
            "configuration reloaded; new connections will use it"
        );

        // Said rather than done. A reload never rebinds -- `docs/configuration.md`
        // and `docs/deployment.md` both promise that, because the usual sender of
        // SIGHUP is a renewal hook that rewrites the whole file and a rebind
        // would take the proxy off the air over a key nobody meant to change.
        // What was missing was the operator being told: the rest of the file
        // applied, this one key silently did not, and until now the only way to
        // find out was to notice the socket had not moved.
        if config.server.listen != self.listen {
            warn!(
                log_id = "amplq5bv",
                bound = %self.listen,
                configured = %config.server.listen,
                "server.listen changed, but a reload cannot move the listening socket; \
                 the server is still bound where it started. Restart to apply it."
            );
        }

        for warning in warnings {
            warn!(log_id = "bg9ux69o", "{warning}");
        }

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

        Ok(config)
    }
}
