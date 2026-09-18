//! The per-address relays a UDP-family service is made of.
//!
//! Two kinds, one question. `SO_ORIGINAL_DST` is TCP and SCTP only, so neither a
//! datagram relay nor a QUIC endpoint can recover where traffic was headed: both are
//! bound one per protected address with the upstream already known, and both answer the
//! backend with the port it should point that address's rule at. Which of the two a
//! service gets is decided once, by what the service speaks.
//!
//! An enum rather than a trait: there are two, the set is not open, and the control
//! channel only ever asks them the one thing.

use std::io;
use std::net::SocketAddr;

use crate::quic::QuicManager;
use crate::udp::UdpManager;

#[derive(Clone)]
pub enum Relays {
    /// Datagrams relayed as they are, each client's flow filtered on its own.
    Datagram(UdpManager),
    /// QUIC, terminated: the streams inside are what the filters see.
    Quic(QuicManager),
}

impl Relays {
    /// Bind a relay for one protected address, or report the one already bound.
    pub async fn add_relay(
        &self,
        upstream: SocketAddr,
        onward: crate::proxy::Onward,
    ) -> io::Result<u16> {
        match self {
            // A plain datagram relay forwards bytes; there is nothing for it to speak.
            Relays::Datagram(manager) => manager.add_relay(upstream).await,
            Relays::Quic(manager) => manager.add_relay(upstream, onward).await,
        }
    }
}
