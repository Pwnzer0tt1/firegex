//! The proxy layer for UDP: relays with transparent source IP preservation.
//!
//! The TCP side of this engine stays invisible in two ways at once: it recovers where
//! the client was originally headed with `SO_ORIGINAL_DST`, and it dials the service
//! *from the client's own address* via `IP_TRANSPARENT`.
//!
//! On UDP:
//! * **`SO_ORIGINAL_DST` is TCP and SCTP only.** The kernel answers `ENOPROTOOPT` for a
//!   UDP socket, so a single listener cannot ask where a datagram was going. This relay
//!   handles it by binding **one socket per protected address**, each with the
//!   upstream already known.
//! * **The client's address is preserved.** The relay dials the upstream service from
//!   the client's own address using `IP_TRANSPARENT` and mark-based policy routing,
//!   keeping source IP transparency on both TCP and UDP.
//!
//! What is kept is everything the filter layer cares about: each client flow is a
//! connection with its own filter state and its own module globals, both directions are
//! inspected.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::proxy::{ProxyStats, Slot};
use crate::filter::{
    next_connection_id, ChainHandle, ChainSessions, ConnectionId, ConnectionMeta, Direction,
    FilterChain, Verdict, L4,
};

/// The largest datagram this relay will carry. Comfortably past the practical MTU and
/// past anything a filter is going to be shown in one piece.
const MAX_DATAGRAM: usize = 65_535;

/// How long a client flow with no traffic is kept before its filter state is released.
///
/// UDP has no close to observe, so this is the only thing that ends a flow. Too short
/// and a filter keeping per-stream state forgets mid-conversation; too long and a
/// service under a spoofed-source flood accumulates one session per forged address.
const IDLE: Duration = Duration::from_secs(60);

/// How often idle flows are swept.
const SWEEP: Duration = Duration::from_secs(10);

struct Flow {
    /// The socket this relay dials the service from, bound to the client's own address
    /// where the kernel allows it.
    upstream: Arc<UdpSocket>,
    connection: ConnectionId,
    /// Filter state for the client→service direction. Owned by the receive loop, which
    /// is single-threaded, so it needs no lock.
    sessions: ChainSessions,
    /// What this flow is judged by: the service's chain, or no chain at all for a flow
    /// admitted past the limit because the operator chose to forward what does not fit.
    /// Decided once, when the flow opens — the same trade a TCP connection admitted past
    /// the limit makes for its whole life.
    chain: ChainHandle,
    /// Whether anything of this flow has been refused yet, in either direction. A refusal
    /// is counted once per flow, because the number it goes into is compared with flows
    /// seen, and one flow refusing a thousand datagrams is still one flow refused.
    refused: Arc<AtomicBool>,
    reply_task: tokio::task::JoinHandle<()>,
    last_seen: Instant,
    /// This flow's place in the service's count of what it is carrying, released when the
    /// flow is. Held for the side effect of dropping it.
    _slot: Slot,
}

/// One protected address, relayed.
pub struct UdpRelay {
    listener: Arc<UdpSocket>,
    /// Where this listener's traffic goes. Fixed, which is the whole trick: with the
    /// upstream known up front there is nothing to recover per datagram, and the kernel
    /// option that cannot answer for UDP is never asked.
    upstream: SocketAddr,
    chain: ChainHandle,
    self_mark: Option<u32>,
    pub spoof_source: bool,
    /// How many connections and flows the service may carry at once, counted together
    /// with its TCP connections in `stats.live`. `0` means no limit.
    max_flows: usize,
    /// Whether a flow from a new source past the limit is carried unfiltered rather than
    /// dropped. The operator's choice, the same one the TCP side offers.
    over_limit_forwards: bool,
    /// Shared with the TCP side, so one service reports one pair of numbers and spends one
    /// budget.
    stats: Arc<ProxyStats>,
}

impl UdpRelay {
    /// Bind a listener for one protected address. Port 0 lets the kernel choose, and
    /// [`UdpRelay::local_addr`] reports what it chose.
    #[allow(clippy::too_many_arguments)]
    pub async fn bind(
        listen: SocketAddr,
        upstream: SocketAddr,
        chain: ChainHandle,
        self_mark: Option<u32>,
        spoof_source: bool,
        max_flows: usize,
        over_limit_forwards: bool,
        stats: Arc<ProxyStats>,
    ) -> io::Result<Self> {
        let listener = UdpSocket::bind(listen).await?;
        Ok(Self {
            listener: Arc::new(listener),
            upstream,
            chain,
            self_mark,
            spoof_source,
            max_flows,
            over_limit_forwards,
            stats,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Relay forever.
    ///
    /// Nothing one flow does may end this loop: a datagram that cannot be forwarded
    /// costs that datagram, and a filter that refuses one costs that one too. The
    /// listener outliving every flow is the same property the TCP side has.
    pub async fn serve(self) -> io::Result<()> {
        let mut flows: HashMap<SocketAddr, Flow> = HashMap::new();
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let mut sweep = tokio::time::interval(SWEEP);
        sweep.tick().await;

        loop {
            let (len, client) = tokio::select! {
                received = self.listener.recv_from(&mut buf) => match received {
                    Ok(pair) => pair,
                    // A per-datagram error (an ICMP port-unreachable landing on the
                    // socket, most often) must not end the relay.
                    Err(e) => {
                        eprintln!("[warn] [udp] receive failed: {e}");
                        continue;
                    }
                },
                _ = sweep.tick() => {
                    self.expire(&mut flows);
                    continue;
                }
            };

            let flow = match flows.get_mut(&client) {
                Some(flow) => flow,
                None => {
                    // The cheapest attack there is, and it was unbounded: a flow is
                    // created per *source address*, a datagram's source is not verified
                    // by any handshake, and a flow holds a socket, a task and a set of
                    // filter sessions for `IDLE` after the last datagram. Six hundred
                    // datagrams from six hundred forged sources, sent in three
                    // hundredths of a second, took four hundred descriptors and held
                    // them for a minute after the sender had gone.
                    //
                    // Counted in the **same** number as the service's TCP connections,
                    // because they spend the same descriptors and the limit is one budget:
                    // it was a count of this relay's own flows, so a service with three UDP
                    // addresses could hold three times its limit in flows and every one of
                    // them beside a full complement of TCP connections.
                    let live = self.stats.live.fetch_add(1, Ordering::Relaxed) + 1;
                    let slot = Slot(Arc::clone(&self.stats));
                    let limit = self.max_flows;
                    let over = limit > 0 && live > limit as u64;
                    let chain = if over {
                        self.stats.over_limit.fetch_add(1, Ordering::Relaxed);
                        if !self.stats.warned_limit.swap(true, Ordering::Relaxed) {
                            eprintln!(
                                "[warn] [udp] {limit} concurrent connections and flows \
                                 reached; new flows are being {} until it clears",
                                if self.over_limit_forwards { "carried unfiltered" } else { "dropped" },
                            );
                        }
                        if !self.over_limit_forwards {
                            drop(slot);
                            continue;
                        }
                        // Carried as a flow of its own, with no chain in front of it. It
                        // used to be a datagram sent from a socket closed straight after,
                        // so the service's answer reached a port nobody was listening on:
                        // the request went through and the client never heard back, which
                        // is not what forwarding is for.
                        ChainHandle::new(FilterChain::empty())
                    } else {
                        if live * 2 <= limit as u64 {
                            // Armed again once there is real room, as on the TCP side.
                            self.stats.warned_limit.store(false, Ordering::Relaxed);
                        }
                        self.chain.clone()
                    };
                    match self.open(client, chain, slot).await {
                        Ok(flow) => {
                            self.stats.accepted.fetch_add(1, Ordering::Relaxed);
                            flows.entry(client).or_insert(flow)
                        }
                        Err(e) => {
                            eprintln!("[warn] [udp] cannot reach {} for {client}: {e}", self.upstream);
                            continue;
                        }
                    }
                }
            };
            flow.last_seen = Instant::now();

            // Re-read the handle every datagram, so a chain swapped in mid-flow takes
            // effect without anyone losing their session.
            let verdict = flow
                .chain
                .current()
                .run(Direction::ClientToServer, &buf[..len], &mut flow.sessions)
                .await;
            let payload: &[u8] = match &verdict {
                Verdict::Accept => &buf[..len],
                Verdict::Reject(_) => {
                    if !flow.refused.swap(true, Ordering::Relaxed) {
                        self.stats.closed_by_filter.fetch_add(1, Ordering::Relaxed);
                    }
                    continue;
                }
            };
            if let Err(e) = flow.upstream.send(payload).await {
                eprintln!("[warn] [udp] cannot forward to {}: {e}", self.upstream);
            }
        }
    }

    /// Start relaying one client's flow: a socket towards the service, and a task
    /// carrying the answers back, both judged by `chain`.
    async fn open(&self, client: SocketAddr, chain: ChainHandle, slot: Slot) -> io::Result<Flow> {
        let upstream = if self.spoof_source {
            match crate::transparent::connect_as_udp(client.ip(), self.upstream, self.self_mark).await {
                Ok(s) => s,
                Err(e) => {
                    self.stats.source_spoof_failures.fetch_add(1, Ordering::Relaxed);
                    if !self.stats.warned_spoof.swap(true, Ordering::Relaxed) {
                        eprintln!(
                            "[warn] [udp] cannot reach {} as {}: {e}. \
                             Falling back to our own address — the service will not see real client IPs.",
                            self.upstream,
                            client.ip()
                        );
                    }
                    crate::transparent::connect_plain_udp(self.upstream, self.self_mark).await?
                }
            }
        } else {
            crate::transparent::connect_plain_udp(self.upstream, self.self_mark).await?
        };
        let upstream = Arc::new(upstream);

        let connection = next_connection_id();
        // Told once, before any datagram of this flow is judged. `client` is the real
        // peer: a filter reads who is talking, and that stays true whatever address the
        // relay dials from.
        chain.current().connection_opened(
            connection,
            &ConnectionMeta {
                client,
                server: self.upstream,
                l4: L4::Udp,
            },
        );

        let refused = Arc::new(AtomicBool::new(false));
        let reply_task = tokio::spawn(replies(
            Arc::clone(&upstream),
            Arc::clone(&self.listener),
            client,
            chain.clone(),
            connection,
            Arc::clone(&refused),
            Arc::clone(&self.stats),
        ));

        Ok(Flow {
            upstream,
            connection,
            sessions: ChainSessions::new(connection),
            chain,
            refused,
            reply_task,
            last_seen: Instant::now(),
            _slot: slot,
        })
    }

    /// Release the flows nothing has been heard from.
    ///
    /// The only thing that ends a UDP flow: there is no close to observe. Without it a
    /// service would accumulate one set of filter state — and, for a Python filter, one
    /// set of module globals — per client address for as long as it ran.
    fn expire(&self, flows: &mut HashMap<SocketAddr, Flow>) {
        let now = Instant::now();
        let done: Vec<SocketAddr> = flows
            .iter()
            .filter(|(_, flow)| now.duration_since(flow.last_seen) > IDLE)
            .map(|(addr, _)| *addr)
            .collect();
        for addr in done {
            if let Some(flow) = flows.remove(&addr) {
                flow.reply_task.abort();
                flow.chain.current().connection_closed(flow.connection);
            }
        }
    }
}

/// Carry one flow's answers back, inspecting them on the way.
///
/// Replies leave through the *listener* socket, so conntrack rewrites them to appear
/// from the address the client dialled. Sending them from the upstream socket would
/// reach a client that is not expecting that source and would be dropped by it.
async fn replies(
    upstream: Arc<UdpSocket>,
    listener: Arc<UdpSocket>,
    client: SocketAddr,
    chain: ChainHandle,
    connection: ConnectionId,
    refused: Arc<AtomicBool>,
    stats: Arc<ProxyStats>,
) {
    // This direction's own filter state, exactly as the TCP pumps keep theirs.
    let mut sessions = ChainSessions::new(connection);
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let len = match upstream.recv(&mut buf).await {
            Ok(len) => len,
            // The service's port answered a datagram with ICMP "unreachable", which a
            // connected socket reports once, on its next call: the service was down for a
            // moment — being restarted, most often. Nothing about the flow is over. This
            // used to end the task, which left the flow in the relay's table with nobody
            // reading the service's answers, so a client that went on talking never heard
            // back again while its datagrams kept the flow from ever going idle.
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => continue,
            Err(e) => {
                eprintln!("[info] [udp] flow for {client} ended: {e}");
                return;
            }
        };
        let verdict = chain
            .current()
            .run(Direction::ServerToClient, &buf[..len], &mut sessions)
            .await;
        let payload: &[u8] = match &verdict {
            Verdict::Accept => &buf[..len],
            // There is no connection to close, so refusing the datagram is the whole of
            // what refusing can mean here. The client simply never receives it.
            Verdict::Reject(_) => {
                if !refused.swap(true, Ordering::Relaxed) {
                    stats.closed_by_filter.fetch_add(1, Ordering::Relaxed);
                }
                continue;
            }
        };
        if let Err(e) = listener.send_to(payload, client).await {
            eprintln!("[warn] [udp] cannot answer {client}: {e}");
        }
    }
}

/// Manages running UDP relays and allows adding new relays dynamically at runtime.
#[derive(Clone)]
pub struct UdpManager {
    chain: ChainHandle,
    self_mark: Option<u32>,
    spoof_source: bool,
    max_flows: usize,
    over_limit_forwards: bool,
    stats: Arc<ProxyStats>,
    relays: Arc<tokio::sync::Mutex<HashMap<SocketAddr, u16>>>,
}

impl UdpManager {
    pub fn new(
        chain: ChainHandle,
        self_mark: Option<u32>,
        spoof_source: bool,
        max_flows: usize,
        over_limit_forwards: bool,
        stats: Arc<ProxyStats>,
    ) -> Self {
        Self {
            chain,
            self_mark,
            spoof_source,
            max_flows,
            over_limit_forwards,
            stats,
            relays: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    pub async fn add_relay(&self, upstream: SocketAddr) -> io::Result<u16> {
        let mut map = self.relays.lock().await;
        if let Some(&port) = map.get(&upstream) {
            return Ok(port);
        }
        let bind: SocketAddr = if upstream.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let relay = UdpRelay::bind(
            bind,
            upstream,
            self.chain.clone(),
            self.self_mark,
            self.spoof_source,
            self.max_flows,
            self.over_limit_forwards,
            Arc::clone(&self.stats),
        )
        .await?;

        let port = relay.local_addr()?.port();
        map.insert(upstream, port);
        tokio::spawn(async move {
            if let Err(e) = relay.serve().await {
                eprintln!("[fatal] [udp] relay for {upstream} died: {e}");
            }
        });
        Ok(port)
    }
}

