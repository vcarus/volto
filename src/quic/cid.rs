//! The connection ID generator the endpoint runs with: quinn's own, with a
//! `validate` that never accepts, so that the endpoint never sends a Stateless
//! Reset (RFC 9000 §10.3).
//!
//! A Stateless Reset is an answer, and the socket gate (`crate::gate`) exists
//! so that a peer who is not our client hears nothing. A short-header packet
//! carries no version, no type and nothing the gate could judge, so the gate
//! passes every one, and quinn alone decides what happens to it. With quinn's
//! default generator, a short-header packet whose connection ID the endpoint no
//! longer holds draws a Stateless Reset whenever that connection ID passes
//! `HashedConnectionIdGenerator::validate`. Every connection ID this endpoint
//! ever issued passes it, so a packet of a finished connection, recorded and
//! sent again later from any address, draws one for certain, with no ECH key
//! and past the gate's hold.
//!
//! Not sending one is our choice, and it conforms, because RFC 9000 §10.3
//! makes sending optional: "An endpoint MAY send a Stateless Reset in response
//! to receiving a packet that it cannot associate with an active connection."
//!
//! How the wrapper removes it, read in quinn-proto 0.11.19 `src/endpoint.rs`.
//! `Endpoint::handle` first routes a datagram to a live connection by its
//! connection ID (`ConnectionIndex::get`), so a packet of a live connection
//! never reaches `validate`. A short-header packet it cannot route then goes
//! through one test, the only call of `ConnectionIdGenerator::validate` in the
//! crate: when `validate` fails the packet is dropped without a reply ("dropping
//! packet with invalid CID"), and otherwise `Endpoint::stateless_reset` sends
//! the reset. So a `validate` that always fails turns that branch into a
//! silent drop. Everything else the generator does is quinn's: the connection
//! IDs, their length and their lifetime come from the `HashedConnectionIdGenerator`
//! this wraps, which is what `EndpointConfig::default` installs.
//!
//! The one other caller of `Endpoint::stateless_reset` is
//! `Endpoint::handle_first_packet`, and it calls it only when the endpoint has
//! no server configuration. This server has one from bind until
//! `Server::drain` removes it at shutdown, and `Server::drain` closes the gate
//! first (`gate::Expected::close`), which from then on drops every datagram
//! that starts with an Initial. So that caller is never reached with a packet
//! from the network, and this wrapper has nothing to do with it.
//!
//! The cost: a client whose connection the server has forgotten, and that
//! missed the CONNECTION_CLOSE, learns that the connection is gone from its own
//! idle timeout instead of from a reset. After a restart that was already so,
//! because the generator's key is drawn at random per process, and no
//! connection ID of the previous process passes `validate`.

use std::time::Duration;

use quinn_proto::{ConnectionId, ConnectionIdGenerator, HashedConnectionIdGenerator, InvalidCid};

/// quinn's `HashedConnectionIdGenerator`, with `validate` refusing every
/// connection ID. The module documentation says why.
pub(crate) struct NoStatelessReset(HashedConnectionIdGenerator);

impl NoStatelessReset {
    /// The wrapper around a new generator with a random key, as quinn's
    /// default makes one per endpoint.
    pub(crate) fn new() -> Self {
        Self(HashedConnectionIdGenerator::new())
    }
}

impl ConnectionIdGenerator for NoStatelessReset {
    fn generate_cid(&mut self) -> ConnectionId {
        self.0.generate_cid()
    }

    /// Never: the one branch of `Endpoint::handle` that reads this then drops
    /// the packet instead of sending a Stateless Reset.
    fn validate(&self, _cid: &ConnectionId) -> Result<(), InvalidCid> {
        Err(InvalidCid)
    }

    fn cid_len(&self) -> usize {
        self.0.cid_len()
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        self.0.cid_lifetime()
    }
}

/// quinn's default endpoint configuration with [`NoStatelessReset`] as its
/// connection ID generator. Always installed; there is no configuration key.
pub(crate) fn endpoint_config() -> quinn::EndpointConfig {
    let mut config = quinn::EndpointConfig::default();
    config.cid_generator(|| Box::new(NoStatelessReset::new()));
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wrapper's connection IDs have the length and the lifetime of the
    /// generator it wraps, and it accepts none of them, its own included.
    #[test]
    fn the_wrapper_keeps_quinns_ids_and_validates_none() {
        let mut quinns = HashedConnectionIdGenerator::new();
        let mut wrapper = NoStatelessReset::new();
        assert_eq!(wrapper.cid_len(), quinns.cid_len());
        assert_eq!(wrapper.cid_lifetime(), quinns.cid_lifetime());
        for _ in 0..64 {
            let ours = wrapper.generate_cid();
            assert_eq!(ours.len(), quinns.cid_len());
            assert!(wrapper.validate(&ours).is_err());
            let theirs = quinns.generate_cid();
            assert!(quinns.validate(&theirs).is_ok());
            assert!(wrapper.validate(&theirs).is_err());
        }
    }

    /// A lifetime set on the wrapped generator is the wrapper's lifetime.
    #[test]
    fn the_wrapper_reports_the_lifetime_it_wraps() {
        let mut inner = HashedConnectionIdGenerator::new();
        inner.set_lifetime(Duration::from_secs(90));
        let wrapper = NoStatelessReset(inner);
        assert_eq!(wrapper.cid_lifetime(), Some(Duration::from_secs(90)));
        assert_eq!(wrapper.cid_len(), 8);
    }
}
