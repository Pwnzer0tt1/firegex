//! QUIC, terminated by the engine.
//!
//! TLS over TCP could in principle be left alone: the bytes on the wire are framed by a
//! transport the kernel understands, and a layer that only forwards still has packets to
//! count. QUIC does not leave even that. After the Initial packet every frame, every
//! stream boundary and the packet number itself are encrypted, so a layer that forwards
//! has nothing a filter could be shown — the choice is to terminate it or to admit that
//! nothing is being inspected. That is why QUIC lives here and on no other layer.
//!
//! On the wire it is UDP, which is what the rules match and what the relay map is made
//! of: one endpoint per protected address, exactly as [`crate::udp`] binds one socket
//! per address and for the same reason — `SO_ORIGINAL_DST` is TCP and SCTP only, so a
//! single listener could not recover where a datagram was headed.
//!
//! **The ALPN is asked of the service, not of the client**, which is the one place this
//! differs from the TLS path beside it. There the ClientHello is held open
//! (`LazyConfigAcceptor`), the service is asked, and the client is told what the service
//! picked. In QUIC the ClientHello arrives inside an encrypted Initial whose processing
//! *is* the handshake, and there is nothing to hold it at. So the order is reversed: the
//! service is offered the candidates, and the client is told the one thing the service
//! agreed to. The invariant that matters is unchanged — the client is never told a
//! protocol the service did not choose — and what is lost is knowing in advance whether
//! the client would have accepted it. When it does not, the handshake fails and says so,
//! rather than a protocol being quietly broken.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, Incoming, VarInt};

use crate::capture::{Capture, Tap};
use crate::filter::{
    next_connection_id, ChainHandle, ChainSessions, ConnectionId, ConnectionMeta, Direction,
    FilterChain, Verdict, L4,
};
use crate::proxy::{join_pumps, pump, spawn_pumps, Onward, ProxyStats, PumpOutcome, Slot};
use crate::transparent::unmap;

/// What the client is told when a rule refuses one of its streams.
///
/// An application error code, because by then the connection is established and QUIC has
/// no other way to say anything: `0x1f3` is in the application range and firegex is the
/// application here. The reason travels with it, so a developer who blocks themselves out
/// of their own service reads why in their client rather than guessing from a reset.
const REFUSED_CODE: u32 = 0x1f3;

/// How long an idle QUIC connection is kept.
///
/// Longer than the datagram relay's flow timeout, and for the opposite reason: a QUIC
/// connection *does* have a close to observe, so this is a backstop for a peer that
/// vanished rather than the only thing that ends it.
const IDLE: Duration = Duration::from_secs(60);

/// How much unread datagram traffic one connection may have waiting.
///
/// Bounded on purpose, and small: datagrams are dropped when it is full, which is what
/// unreliable means and exactly what the sender already has to handle. Unbounded, a peer
/// that sends faster than the chain judges would be buying memory in this process.
const DATAGRAM_BUFFER: usize = 256 * 1024;

/// Everything a QUIC service needs decided once, before any client arrives.
pub struct QuicSetup {
    /// One accept-side configuration per protocol the service might pick, built up front
    /// rather than per connection: the candidate list is short and known, and a rustls
    /// config clone plus a cipher-suite lookup on the accept path is work done while a
    /// client is waiting.
    answering: HashMap<Vec<u8>, Arc<quinn::ServerConfig>>,
    /// For the case the service agreed to nothing. QUIC requires ALPN, so this is a
    /// configuration that will refuse — kept so the refusal is the handshake's, with a
    /// reason, rather than a panic here.
    silent: Arc<quinn::ServerConfig>,
    /// Offered to the service, in the operator's order.
    client: quinn::ClientConfig,
    candidates: Vec<Vec<u8>>,
}

impl QuicSetup {
    /// Build both edges from the service's certificate and the protocols it may speak.
    pub fn build(cert_pem: &str, key_pem: &str, candidates: Vec<Vec<u8>>) -> Result<Self, String> {
        if candidates.is_empty() {
            return Err("a QUIC service needs at least one ALPN protocol".to_string());
        }
        // Two of them, differing in one advertisement. **HTTP/3 connections do not carry
        // datagrams here**, and the honest way to say that is not to advertise the
        // extension on them: a peer then knows from the handshake and falls back, instead
        // of sending datagrams that vanish. The reason is the one thing a datagram would
        // need that this engine cannot give it — an HTTP/3 datagram names the stream it
        // belongs to, and the request streams this proxy opens towards the service are
        // not the ones the client opened, so the name would point somewhere else on the
        // far side. Everything that is not h3 has no such coupling and carries them.
        let streams_only = transport_config(false);
        let with_datagrams = transport_config(true);
        let base = crate::tls::server_config(cert_pem, key_pem)?;

        let mut answering = HashMap::new();
        for protocol in &candidates {
            let transport = if protocol == b"h3" { &streams_only } else { &with_datagrams };
            answering.insert(
                protocol.clone(),
                Arc::new(server_config(&base, &[protocol.clone()], transport)?),
            );
        }
        let silent = Arc::new(server_config(&base, &[], &streams_only)?);

        let mut rustls_client = crate::tls::quic_client_config()?;
        rustls_client.alpn_protocols = candidates.clone();
        let crypto = QuicClientConfig::try_from(rustls_client)
            .map_err(|e| format!("cannot configure QUIC towards the service: {e}"))?;
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        // The service is dialled before it has said which protocol it speaks, so this
        // edge is decided by the candidate list rather than by the answer: with h3 the
        // only candidate there is nothing a datagram could be for, and advertising it
        // upstream would invite what this end would then have to drop.
        client.transport_config(if candidates.iter().all(|p| p == b"h3") {
            Arc::clone(&streams_only)
        } else {
            Arc::clone(&with_datagrams)
        });

        Ok(Self {
            answering,
            silent,
            client,
            candidates,
        })
    }

    /// The configuration that advertises the one protocol the service agreed to.
    fn answering_with(&self, agreed: Option<&[u8]>) -> Arc<quinn::ServerConfig> {
        agreed
            .and_then(|p| self.answering.get(p))
            .map(Arc::clone)
            .unwrap_or_else(|| Arc::clone(&self.silent))
    }

    /// What the endpoint answers with before a service has been asked. Only ever used
    /// for the connections this relay turns away, which need a configuration to be
    /// turned away *by*.
    fn default_server(&self) -> Arc<quinn::ServerConfig> {
        self.candidates
            .first()
            .and_then(|p| self.answering.get(p))
            .map(Arc::clone)
            .unwrap_or_else(|| Arc::clone(&self.silent))
    }
}

fn server_config(
    base: &Arc<rustls::ServerConfig>,
    alpn: &[Vec<u8>],
    transport: &Arc<quinn::TransportConfig>,
) -> Result<quinn::ServerConfig, String> {
    let mut rustls_config = (**base).clone();
    rustls_config.alpn_protocols = alpn.to_vec();
    // Left at zero deliberately. 0-RTT data is replayable by anyone who watched it go
    // past, and a filter that refused a request has no way to un-deliver the copy of it
    // the service already acted on. A round trip is the price of that not being true.
    rustls_config.max_early_data_size = 0;
    let crypto = QuicServerConfig::try_from(rustls_config)
        .map_err(|e| format!("the certificate cannot carry QUIC: {e}"))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::clone(transport));
    Ok(config)
}

/// The transport parameters an edge is built with.
fn transport_config(datagrams: bool) -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        IDLE.try_into().expect("the idle timeout fits in a VarInt"),
    ));
    // Advertised only where they are carried, because a peer that finds the extension
    // announced and then watches its datagrams disappear is worse off than one that knows
    // from the handshake to do without. What a filter is shown for one is a `RawPacket`
    // and nothing more, which is the same answer the datagram relay gives on plain UDP —
    // there is no stream, so there is nothing for the stream models to be built on.
    transport.datagram_receive_buffer_size(datagrams.then_some(DATAGRAM_BUFFER));
    Arc::new(transport)
}

/// The settings a relay is built with, shared by every address of one service.
#[derive(Clone)]
pub struct QuicConfig {
    pub setup: Arc<QuicSetup>,
    /// Where a reconstruction of each stream is written, when anything is listening.
    /// `None` is the ordinary case — no capture interface — and never a failure.
    pub capture: Option<Arc<Capture>>,
    pub self_mark: Option<u32>,
    pub spoof_source: bool,
    pub max_connections: usize,
    pub over_limit_forwards: bool,
    pub first_byte_timeout: Option<Duration>,
    pub connect_timeout: Duration,
    /// What the service behind this *relay* speaks — QUIC unless it says otherwise.
    ///
    /// One per relay rather than one per process, because a relay is one protected
    /// address and the question belongs to the address: two ports of one service can
    /// be reached differently. The other two values put an ordinary HTTP/1.1 service
    /// behind an HTTP/3 edge, with firegex terminating QUIC on its behalf.
    pub upstream: Onward,
}

/// One protected address, terminated.
pub struct QuicRelay {
    endpoint: Endpoint,
    upstream: SocketAddr,
    chain: ChainHandle,
    cfg: QuicConfig,
    stats: Arc<ProxyStats>,
}

impl QuicRelay {
    pub fn bind(
        listen: SocketAddr,
        upstream: SocketAddr,
        chain: ChainHandle,
        cfg: QuicConfig,
        stats: Arc<ProxyStats>,
    ) -> io::Result<Self> {
        // Unmarked, exactly as the datagram relay's listener is. The mark is what tells
        // the intercept rules to leave *our own dial* alone; this socket is the one the
        // rules are pointing at, and its answers go back the way conntrack sends them.
        let socket = std::net::UdpSocket::bind(listen)?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| io::Error::other("no async runtime for the QUIC endpoint"))?;
        let endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some((*cfg.setup.default_server()).clone()),
            socket,
            runtime,
        )?;
        Ok(Self {
            endpoint,
            upstream,
            chain,
            cfg,
            stats,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Accept forever. Nothing one connection does may end this loop.
    pub async fn serve(self: Arc<Self>) {
        while let Some(incoming) = self.endpoint.accept().await {
            let relay = Arc::clone(&self);
            tokio::spawn(async move { relay.admit(incoming).await });
        }
        eprintln!("[warn] [quic] the endpoint for {} closed", self.upstream);
    }

    /// Decide whether this connection is carried at all, and on what terms.
    async fn admit(self: Arc<Self>, incoming: Incoming) {
        let client = unmap(incoming.remote_address());

        // Before anything at all is opened towards the service. An Initial packet is one
        // datagram carrying no proof that its source address is real, and answering it by
        // opening a connection to the protected service is how a spoofed source turns
        // this relay into the amplifier — the same shape as the datagram flood the flow
        // cap exists for, but with a handshake in front of it. A Retry costs the honest
        // client one round trip and costs the forged one everything, because the token
        // has to come back from an address that can receive it.
        if !incoming.remote_address_validated() {
            if let Err(e) = incoming.retry() {
                // Only possible if it was validated after all, which this branch has
                // just established it was not. Refuse rather than assume.
                e.into_incoming().refuse();
            }
            return;
        }

        self.stats.accepted.fetch_add(1, Ordering::Relaxed);
        let live = self.stats.live.fetch_add(1, Ordering::Relaxed) + 1;
        let slot = Slot(Arc::clone(&self.stats));
        let limit = self.cfg.max_connections;
        let over = limit > 0 && live > limit as u64;
        if over {
            self.stats.over_limit.fetch_add(1, Ordering::Relaxed);
            if !self.stats.warned_limit.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "[warn] [quic] {limit} concurrent connections reached; further \
                     connections are being {} until it clears",
                    if self.cfg.over_limit_forwards {
                        "carried unfiltered"
                    } else {
                        "refused"
                    },
                );
            }
            if !self.cfg.over_limit_forwards {
                // A refusal the client can read, rather than a silence it has to time
                // out on: this connection reached a working service that chose not to
                // carry it.
                incoming.refuse();
                drop(slot);
                return;
            }
        } else if live * 2 <= limit as u64 {
            self.stats.warned_limit.store(false, Ordering::Relaxed);
        }

        // Past the limit and told to carry it anyway: the streams are relayed against an
        // empty chain. The traffic reaches the service and nothing claims to have looked
        // at it, which is the operator's choice made literal. It is not free here the way
        // it is on TCP — the connection is still terminated, decrypted and re-encrypted,
        // because there is no such thing as forwarding a QUIC connection unopened.
        let chain = if over {
            ChainHandle::new(FilterChain::empty())
        } else {
            self.chain.clone()
        };

        let _slot = slot;
        if let Err(e) = self.serve_connection(incoming, client, chain).await {
            eprintln!("[info] [quic] connection from {client} ended: {e}");
        }
    }

    /// Both handshakes, in the order that lets the service decide the protocol.
    async fn serve_connection(
        &self,
        incoming: Incoming,
        client: SocketAddr,
        chain: ChainHandle,
    ) -> io::Result<()> {
        // Two shapes, decided by what the service speaks. With QUIC behind, the service
        // is dialled *first* and asked which protocol it wants — that ordering is the
        // whole reason the client can be told something the service actually chose.
        // With HTTP/1.1 behind there is nobody to ask: firegex is the thing speaking
        // HTTP/3, so it answers `h3` for itself and nothing is dialled until there is a
        // request to send.
        let (endpoint, behind, agreed) = match self.cfg.upstream {
            Onward::Same => {
                // The endpoint is held for as long as the connection is: it owns the
                // socket the connection speaks through, and dropping it would take the
                // connection with it.
                let (endpoint, service) = self.dial_upstream(client).await?;
                let agreed = negotiated_protocol(&service);
                (Some(endpoint), Behind::Quic(service), agreed)
            }
            protocol => (
                None,
                Behind::Http1(crate::h1up::H1Upstream {
                    upstream: self.upstream,
                    client,
                    tls: match protocol {
                        Onward::Tls => Some(
                            crate::tls::client_config().map_err(io::Error::other)?,
                        ),
                        _ => None,
                    },
                    // Known only once the client's handshake is done, below.
                    server_name: None,
                    connect_timeout: self.cfg.connect_timeout,
                    self_mark: self.cfg.self_mark,
                    spoof: self.cfg.spoof_source,
                }),
                Some(b"h3".to_vec()),
            ),
        };

        let accepting = incoming
            .accept_with(self.cfg.setup.answering_with(agreed.as_deref()))
            .map_err(io::Error::other)?;
        let peer = match tokio::time::timeout(self.cfg.connect_timeout, accepting).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(e)) => {
                // Nearly always the one mismatch this ordering can produce, so it is
                // named rather than left as a handshake error the operator has to decode.
                // Which end chose it differs: with QUIC behind it is the service's pick,
                // and with HTTP/1.1 behind it is `h3`, which is what firegex itself is
                // offering to speak on the service's behalf.
                if let Some(protocol) = &agreed {
                    eprintln!(
                        "[warn] [quic] {client} would not take `{}`, which is what {} chose: {e}",
                        String::from_utf8_lossy(protocol),
                        match behind {
                            Behind::Quic(_) => self.upstream.to_string(),
                            Behind::Http1(_) => "firegex, for a service that speaks HTTP/1.1"
                                .to_string(),
                        },
                    );
                }
                if let Some(service) = behind.quic() {
                    service.close(VarInt::from_u32(0), b"client handshake failed");
                }
                return Err(io::Error::other(e));
            }
            Err(_) => {
                if let Some(service) = behind.quic() {
                    service.close(VarInt::from_u32(0), b"client handshake timed out");
                }
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the client's QUIC handshake timed out",
                ));
            }
        };

        // The name the client asked for, now that its handshake has said it, for an
        // upstream that re-encrypts: a service choosing its certificate or virtual host by
        // SNI must not be handed the bare address instead. A QUIC upstream is dialled
        // before the client's handshake (see `dial_upstream`) and cannot be told.
        let mut behind = behind;
        if let Behind::Http1(upstream) = &mut behind {
            upstream.server_name = peer
                .handshake_data()
                .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|data| data.server_name);
        }
        self.relay(peer, behind, client, chain, agreed.as_deref()).await;
        drop(endpoint);
        Ok(())
    }

    /// Open the connection to the service, from the client's own address where we can.
    async fn dial_upstream(&self, client: SocketAddr) -> io::Result<(Endpoint, Connection)> {
        let endpoint = match self.endpoint_as(client) {
            Ok(endpoint) => endpoint,
            Err(e) => {
                // Losing the client's address is bad; losing the connection is worse —
                // the same trade the TCP dial makes, and just as loud about it.
                self.stats
                    .source_spoof_failures
                    .fetch_add(1, Ordering::Relaxed);
                if !self.stats.warned_spoof.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "[warn] [quic] cannot reach {} as {}: {e}. Falling back to our own \
                         address — the service will not see real client IPs.",
                        self.upstream,
                        client.ip()
                    );
                }
                self.endpoint_plain()?
            }
        };

        // An IP literal is what the TCP path presents too. Nothing verifies it — the
        // service being protected is the thing we are defending, not a peer to be
        // authenticated — but rustls needs a name to put in the handshake.
        let name = self.upstream.ip().to_string();
        let connecting = endpoint
            .connect_with(self.cfg.setup.client.clone(), self.upstream, &name)
            .map_err(io::Error::other)?;
        let connection = tokio::time::timeout(self.cfg.connect_timeout, connecting)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{} did not complete a QUIC handshake", self.upstream),
                )
            })?
            .map_err(io::Error::other)?;
        Ok((endpoint, connection))
    }

    /// An endpoint wearing the client's address.
    fn endpoint_as(&self, client: SocketAddr) -> io::Result<Endpoint> {
        if !self.cfg.spoof_source {
            return self.endpoint_plain();
        }
        let socket =
            crate::transparent::bind_as_udp(client.ip(), self.upstream, self.cfg.self_mark)?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| io::Error::other("no async runtime for the QUIC endpoint"))?;
        Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
    }

    fn endpoint_plain(&self) -> io::Result<Endpoint> {
        let bind: SocketAddr = if self.upstream.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let socket = std::net::UdpSocket::bind(bind)?;
        if let Some(mark) = self.cfg.self_mark {
            use std::os::fd::AsRawFd;
            crate::transparent::set_self_mark(socket.as_raw_fd(), mark)?;
        }
        let runtime = quinn::default_runtime()
            .ok_or_else(|| io::Error::other("no async runtime for the QUIC endpoint"))?;
        Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
    }

    /// Carry one connection until either end is done with it.
    async fn relay(
        &self,
        peer: Connection,
        service: Behind,
        client: SocketAddr,
        chain: ChainHandle,
        agreed: Option<&[u8]>,
    ) {
        // One flag for the whole connection, not one per stream. The question the
        // deadline asks is whether this peer has said anything at all, and a connection
        // that opens a hundred streams and speaks on none is exactly the shape it is
        // there to catch.
        let spoken = Arc::new(AtomicBool::new(false));
        let watchdog = self.cfg.first_byte_timeout.map(|deadline| {
            let spoken = Arc::clone(&spoken);
            let peer = peer.clone();
            let service = service.quic().cloned();
            let stats = Arc::clone(&self.stats);
            tokio::spawn(async move {
                tokio::select! {
                    _ = tokio::time::sleep(deadline) => {
                        if !spoken.load(Ordering::Relaxed) {
                            stats.no_first_byte.fetch_add(1, Ordering::Relaxed);
                            peer.close(VarInt::from_u32(0), b"nothing was ever said");
                            if let Some(service) = &service {
                                service.close(VarInt::from_u32(0), b"nothing was ever said");
                            }
                        }
                    }
                    // Closed rather than slept through, or a service taking short
                    // connections would hold one sleeping task per connection for the
                    // whole deadline.
                    _ = peer.closed() => {}
                }
            })
        });

        let carrier = Carrier {
            peer: peer.clone(),
            service,
            client,
            upstream: self.upstream,
            capture: self.cfg.capture.clone(),
            chain,
            stats: Arc::clone(&self.stats),
            spoken,
        };

        // HTTP/3 is carried by something that understands it, and everything else by
        // something that does not have to. The difference is not an optimisation: h3
        // puts a request's method, path and headers in a QPACK-compressed HEADERS frame,
        // so a filter shown the raw stream would be shown a compression format. Ending
        // the protocol here is what lets the chain be shown a request.
        if agreed == Some(b"h3") {
            crate::h3::carry(&carrier).await;
        } else if carrier.service.quic().is_none() {
            // Everything that is not HTTP/3 is opaque bytes on a stream, and opaque bytes
            // have no HTTP/1.1 form to be sent in. Refused here, once, with a reason the
            // client can read — rather than carried into a translation nobody could
            // describe, or dropped silently.
            eprintln!(
                "[warn] [quic] {client}: this service is reached over HTTP/1.1, so only \
                 HTTP/3 can be carried to it — the connection agreed on something else.",
            );
            peer.close(
                VarInt::from_u32(REFUSED_CODE),
                b"this endpoint carries HTTP/3 only",
            );
        } else {
            // Together, because a connection carrying both must not have one wait for the
            // other: each ends when the connection does.
            tokio::join!(carrier.carry_streams(), carrier.carry_datagrams());
        }

        if let Some(watchdog) = watchdog {
            watchdog.abort();
        }
    }
}

/// What one established connection's streams are carried with.
///
/// Cloned per stream rather than shared behind a lock: everything in it is a handle
/// already — two connection handles, the chain's watch receiver, two `Arc`s — so a clone
/// is a few reference counts and the streams need nothing from each other.
/// What is behind this connection, and therefore what its exchanges are forwarded to.
///
/// It was always a QUIC connection: the engine dialled the service before accepting the
/// client, so that the protocol the client is told is the one the service chose. That is
/// still the default and still the only thing a *raw* QUIC stream can be relayed to — a
/// stream of opaque bytes has nowhere else to go.
///
/// The second arm is for the service that does not speak QUIC at all. An HTTP/3 exchange
/// is already rendered to the chain as HTTP/1.1, so it can be sent to a service that
/// speaks HTTP/1.1 and nothing else, which is what puts firegex in front of an ordinary
/// web service as the thing that terminates QUIC for it. Two things follow and are worth
/// stating where they are decided:
///
/// * **it is HTTP/3 or nothing.** A raw QUIC stream has no HTTP/1.1 form, so a connection
///   that agrees on anything else is refused rather than carried into a translation
///   nobody could describe;
/// * **the ALPN stops being mirrored**, because there is no longer a service to ask. The
///   invariant everywhere else — never tell the client something the service did not say
///   — changes meaning here rather than being broken: the service does not speak QUIC,
///   firegex does, and `h3` is what firegex is speaking.
#[derive(Clone)]
pub(crate) enum Behind {
    /// The service speaks QUIC. Streams are opened on this connection.
    Quic(Connection),
    /// The service speaks HTTP/1.1, dialled once per exchange.
    Http1(crate::h1up::H1Upstream),
}

impl Behind {
    /// The upstream QUIC connection, where there is one.
    pub(crate) fn quic(&self) -> Option<&Connection> {
        match self {
            Behind::Quic(connection) => Some(connection),
            Behind::Http1(_) => None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Carrier {
    pub(crate) peer: Connection,
    pub(crate) service: Behind,
    pub(crate) client: SocketAddr,
    pub(crate) upstream: SocketAddr,
    pub(crate) capture: Option<Arc<Capture>>,
    pub(crate) chain: ChainHandle,
    pub(crate) stats: Arc<ProxyStats>,
    pub(crate) spoken: Arc<AtomicBool>,
}

impl Carrier {
    /// Relay whatever streams either end opens, as byte streams and nothing more.
    async fn carry_streams(&self) {
        let peer = self.peer.clone();
        // Raw streams are opaque bytes, so the only thing they can be relayed to is
        // another QUIC connection. A service that speaks HTTP/1.1 is refused before a
        // client is ever accepted — there is no HTTP/1.1 form of "some bytes on a
        // stream" — so this is unreachable rather than a case to handle.
        let Some(service) = self.service.quic().cloned() else {
            return;
        };
        let client = self.client;
        loop {
            tokio::select! {
                // A stream the client opened. Both halves exist already, so the only
                // thing that can block is opening its twin upstream — which is done in
                // the task, or one stream waiting on the service's flow control would
                // stop this loop accepting anybody else's.
                opened = peer.accept_bi() => match opened {
                    Ok((send, recv)) => self.spawn_bi(recv, send, Origin::Client),
                    Err(e) => { service.close(VarInt::from_u32(0), b"the client is gone"); break log_end(client, "client", e); }
                },
                opened = peer.accept_uni() => match opened {
                    Ok(recv) => self.spawn_uni(recv, Origin::Client),
                    Err(e) => { service.close(VarInt::from_u32(0), b"the client is gone"); break log_end(client, "client", e); }
                },
                // And one the service opened. Rare outside HTTP/3's control streams, but
                // a protocol nobody here has heard of may do it at any time.
                opened = service.accept_bi() => match opened {
                    Ok((send, recv)) => self.spawn_bi(recv, send, Origin::Service),
                    Err(e) => { peer.close(VarInt::from_u32(0), b"the service is gone"); break log_end(client, "service", e); }
                },
                opened = service.accept_uni() => match opened {
                    Ok(recv) => self.spawn_uni(recv, Origin::Service),
                    Err(e) => { peer.close(VarInt::from_u32(0), b"the service is gone"); break log_end(client, "service", e); }
                },
            }
        }
    }
}

/// Close both ends because a rule refused something on one of them.
fn refuse(peer: &Connection, service: &Connection) {
    peer.close(VarInt::from_u32(REFUSED_CODE), b"blocked by firegex");
    service.close(VarInt::from_u32(REFUSED_CODE), b"blocked by firegex");
}

fn log_end(client: SocketAddr, side: &str, e: quinn::ConnectionError) {
    match e {
        quinn::ConnectionError::ApplicationClosed(_)
        | quinn::ConnectionError::LocallyClosed
        | quinn::ConnectionError::ConnectionClosed(_) => {}
        other => eprintln!("[info] [quic] {client}: the {side} ended the connection: {other}"),
    }
}

/// Which end opened a stream. Not the same question as which direction its bytes go:
/// both ends can write to a bidirectional stream whoever opened it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin {
    Client,
    Service,
}

impl Carrier {
    /// End this connection because a rule said so.
    ///
    /// Both ends, with the same reason, spelled once: a client reading why it was cut off
    /// and a service reading why its peer went away are the same event, and the two
    /// halves drifting apart is how a close comes to mean two things.
    pub(crate) fn refuse(&self) {
        match self.service.quic() {
            Some(service) => refuse(&self.peer, service),
            // An HTTP/1.1 service has no connection of its own to end: the socket under
            // this exchange is dropped with it, which is what closing one means there.
            None => self
                .peer
                .close(VarInt::from_u32(REFUSED_CODE), b"blocked by firegex"),
        }
    }

    /// Tell the chain about a stream, in the words the rest of the engine uses.
    ///
    /// **One stream is one connection to a filter.** That is the honest mapping rather
    /// than a convenience: a filter's state — for Python, a whole set of module globals —
    /// follows a stream of bytes from its start to its end, which is what a QUIC stream
    /// is and what a QUIC *connection* is not. On HTTP/3 it also lands where an operator
    /// would expect, one request to a stream. The addresses are the connection's, because
    /// they are the same for every stream on it.
    pub(crate) fn open(&self) -> ConnectionId {
        // Neither of the two answers that existed before this: a QUIC stream is a stream,
        // so everything the library builds on one applies, and it rides on UDP, which is
        // what the rules matched to get here.
        self.open_as(L4::Quic)
    }

    /// Tell the chain about this connection's datagrams, which are one flow of their own.
    ///
    /// One for the connection and not one per datagram: a datagram carries no identity a
    /// flow could be keyed on beyond the connection it arrived in, which is the same
    /// answer the plain UDP relay reaches from the other direction, where the flow is the
    /// client address. Both directions share it, as they do there.
    fn open_datagrams(&self) -> ConnectionId {
        self.open_as(L4::QuicDatagram)
    }

    fn open_as(&self, l4: L4) -> ConnectionId {
        let connection = next_connection_id();
        self.chain.current().connection_opened(
            connection,
            &ConnectionMeta {
                client: self.client,
                server: self.upstream,
                l4,
            },
        );
        connection
    }

    /// This connection's datagrams, in both directions.
    ///
    /// A refused datagram is **dropped, and the connection carries on**. That is a block
    /// meaning something different from what it means one function up, and the difference
    /// belongs to the traffic rather than to a preference: a stream is a conversation that
    /// can be ended, and a datagram is already complete by the time it is judged — ending
    /// the connection over one would cost every stream riding on it. The plain UDP relay
    /// answers the same way.
    ///
    /// What a datagram does *not* lose is the filter's memory of the ones before it: the
    /// flow keeps its sessions, so a pattern split across two datagrams a millisecond
    /// apart is still found, which is the relay's rule again. What it loses is everything
    /// built on a stream, and that is [`L4::QuicDatagram`]'s doing rather than this
    /// function's.
    async fn carry_datagrams(&self) {
        // Nothing is opened for a connection that cannot carry them. A flow costs a
        // filter its state — for Python, a whole set of module globals — and the flow is
        // built on the first datagram rather than here, so a connection that negotiates
        // the extension and never uses it costs nothing at all.
        // Datagrams go from one QUIC connection to another and nowhere else: there is no
        // HTTP/1.1 spelling of one, so a service reached that way carries none.
        let Some(service) = self.service.quic().cloned() else {
            return;
        };
        if self.peer.max_datagram_size().is_none() && service.max_datagram_size().is_none() {
            return;
        }
        let flow = tokio::sync::OnceCell::new();
        tokio::join!(
            self.datagrams(&service, Direction::ClientToServer, &flow),
            self.datagrams(&service, Direction::ServerToClient, &flow),
        );
        // Released once, by whichever direction opened it: the two share one flow, and a
        // filter told twice that a connection ended would be asked to forget it twice.
        if let Some(&connection) = flow.get() {
            self.chain.current().connection_closed(connection);
        }
    }

    /// One direction of the datagram flow.
    async fn datagrams(
        &self,
        service: &Connection,
        direction: Direction,
        flow: &tokio::sync::OnceCell<ConnectionId>,
    ) {
        let (from, to) = match direction {
            Direction::ClientToServer => (&self.peer, service),
            Direction::ServerToClient => (service, &self.peer),
        };
        let mut sessions: Option<ChainSessions> = None;
        let mut complained = false;
        loop {
            // The error is the connection ending, which the stream carrier is already
            // watching and reporting; saying it twice would put two lines in the log for
            // one event.
            let Ok(datagram) = from.read_datagram().await else {
                return;
            };
            // A datagram is something said, exactly as a byte on a stream is.
            self.spoken.store(true, Ordering::Relaxed);
            let connection = *flow.get_or_init(|| async { self.open_datagrams() }).await;
            let sessions = sessions.get_or_insert_with(|| ChainSessions::new(connection));
            // Re-read every time, so a ruleset pushed mid-flow takes effect without
            // anybody losing a connection.
            if let Verdict::Reject(_) = self
                .chain
                .current()
                .run(direction, &datagram, sessions)
                .await
            {
                continue;
            }
            if let Err(e) = to.send_datagram(datagram) {
                // Once per direction per connection: a datagram too large for the far end
                // is a property of the two peers, so the second one fails for the same
                // reason as the first and the thousandth would too.
                if !complained {
                    complained = true;
                    eprintln!("[info] [quic] {}: cannot carry a datagram: {e}", self.client);
                }
            }
        }
    }

    /// A reconstruction of one stream, for whoever is watching the capture interface.
    ///
    /// Per stream and not per connection, because a stream is the thing that has a
    /// beginning, an order and an end — everything a TCP conversation is made of. What it
    /// does not have is a port of its own, so [`Tap::open_stream`] invents one; the
    /// documentation says so wherever this interface is offered.
    pub(crate) fn tap(&self) -> Option<Arc<Tap>> {
        Tap::open_stream(self.capture.clone(), self.client, self.upstream)
    }

    /// A bidirectional stream: both directions, inspected independently.
    fn spawn_bi(&self, near_recv: quinn::RecvStream, near_send: quinn::SendStream, origin: Origin) {
        let connection = self.open();
        let tap = self.tap();
        let peer = self.peer.clone();
        // As in `carry_streams`: opaque bytes have nowhere but another QUIC connection
        // to go, so this arm cannot be reached with an HTTP/1.1 service behind.
        let Some(service) = self.service.quic().cloned() else {
            return;
        };
        let chain = self.chain.clone();
        let stats = Arc::clone(&self.stats);
        let spoken = Arc::clone(&self.spoken);
        tokio::spawn(async move {
            // Opened here rather than in the accept loop: the far end's flow control can
            // make this wait, and waiting must cost this stream and no other.
            let far = match origin {
                Origin::Client => service.open_bi().await,
                Origin::Service => peer.open_bi().await,
            };
            let (far_send, far_recv) = match far {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("[info] [quic] cannot carry a stream through: {e}");
                    chain.current().connection_closed(connection);
                    return;
                }
            };

            // Which end the bytes came *from* is what names the direction, whoever opened
            // the stream: the service answering on a stream it opened itself is still the
            // service talking.
            let (client_rd, client_wr, service_rd, service_wr) = match origin {
                Origin::Client => (near_recv, near_send, far_recv, far_send),
                Origin::Service => (far_recv, far_send, near_recv, near_send),
            };

            let (up, down) = spawn_pumps(
                client_rd, client_wr, service_rd, service_wr, &chain, &stats, connection,
                tap.clone(), spoken,
                // The deadline is the connection's, and its watchdog is already running.
                None,
            );
            if join_pumps(up, down).await {
                // A refusal ends the connection, not the stream. Killing one stream of
                // many would leave the client free to ask again on the next one, which is
                // not what a block means anywhere else in firegex — and on HTTP/3 it is
                // the same thing keep-alive does on HTTP/1.1, where a refused request
                // takes the connection with it.
                peer.close(VarInt::from_u32(REFUSED_CODE), b"blocked by firegex");
                service.close(VarInt::from_u32(REFUSED_CODE), b"blocked by firegex");
            }
            if let Some(tap) = tap {
                tap.closed();
            }
            chain.current().connection_closed(connection);
        });
    }

    /// A unidirectional stream: one pump, and nothing coming back.
    fn spawn_uni(&self, near_recv: quinn::RecvStream, origin: Origin) {
        let connection = self.open();
        let tap = self.tap();
        let peer = self.peer.clone();
        // As in `carry_streams`: opaque bytes have nowhere but another QUIC connection
        // to go, so this arm cannot be reached with an HTTP/1.1 service behind.
        let Some(service) = self.service.quic().cloned() else {
            return;
        };
        let chain = self.chain.clone();
        let stats = Arc::clone(&self.stats);
        let spoken = Arc::clone(&self.spoken);
        tokio::spawn(async move {
            let far = match origin {
                Origin::Client => service.open_uni().await,
                Origin::Service => peer.open_uni().await,
            };
            let far_send = match far {
                Ok(send) => send,
                Err(e) => {
                    eprintln!("[info] [quic] cannot carry a stream through: {e}");
                    chain.current().connection_closed(connection);
                    return;
                }
            };
            let direction = match origin {
                Origin::Client => Direction::ClientToServer,
                Origin::Service => Direction::ServerToClient,
            };
            // Its own stop channel, which nothing else holds: there is no other direction
            // of this stream to wind down, and the refusal below closes the connection
            // that every other stream is riding on anyway.
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            let outcome = pump(
                near_recv, far_send, direction, chain.clone(), stats, connection, tap.clone(),
                spoken, stop_tx, stop_rx,
            )
            .await;
            if matches!(outcome, Ok(PumpOutcome::Rejected)) {
                refuse(&peer, &service);
            }
            if let Some(tap) = tap {
                tap.closed();
            }
            chain.current().connection_closed(connection);
        });
    }
}

/// What the service agreed to speak.
fn negotiated_protocol(connection: &Connection) -> Option<Vec<u8>> {
    let data = connection.handshake_data()?;
    let data = data.downcast::<quinn::crypto::rustls::HandshakeData>().ok()?;
    data.protocol
}

/// Binds and tracks the QUIC endpoints of one service, one per protected address.
///
/// The same shape as [`crate::udp::UdpManager`] and answering the same question, because
/// the backend asks it in the same words: a QUIC service is UDP as far as the rules are
/// concerned, so what it wants back is a port per address to point them at.
#[derive(Clone)]
pub struct QuicManager {
    chain: ChainHandle,
    cfg: QuicConfig,
    stats: Arc<ProxyStats>,
    /// One relay per service **and** per what that service speaks. Keyed on the service
    /// alone, a second address sending to the same port with a different answer — HTTP/3
    /// relayed as QUIC to `udp/443` beside HTTP/3 turned into HTTPS on `tcp/443`, both
    /// perfectly real — was handed the first one's relay, and so was an address whose
    /// answer was edited on a running service: the new choice reached nothing until a
    /// restart, while the interface said it was in force.
    relays: Arc<tokio::sync::Mutex<HashMap<(SocketAddr, Onward), u16>>>,
}

impl QuicManager {
    pub fn new(chain: ChainHandle, cfg: QuicConfig, stats: Arc<ProxyStats>) -> Self {
        Self {
            chain,
            cfg,
            stats,
            relays: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    pub async fn add_relay(&self, upstream: SocketAddr, onward: Onward) -> io::Result<u16> {
        let mut map = self.relays.lock().await;
        if let Some(&port) = map.get(&(upstream, onward)) {
            return Ok(port);
        }
        let bind: SocketAddr = if upstream.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        // The relay's own copy, because what the service behind it speaks is this
        // address's answer and not the process's.
        let mut cfg = self.cfg.clone();
        cfg.upstream = onward;
        let relay = QuicRelay::bind(
            bind,
            upstream,
            self.chain.clone(),
            cfg,
            Arc::clone(&self.stats),
        )?;
        let port = relay.local_addr()?.port();
        map.insert((upstream, onward), port);
        tokio::spawn(Arc::new(relay).serve());
        Ok(port)
    }
}
