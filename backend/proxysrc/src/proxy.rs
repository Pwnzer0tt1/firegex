//! The datapath: accept, dial the real service, relay both halves through the chain.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::filter::{
    next_connection_id, ChainHandle, ChainSessions, ConnectionId, ConnectionMeta, Direction,
    FilterChain, Verdict,
};
use crate::capture::{Capture, Tap};
use crate::tls;
use crate::transparent::{
    bind_listener, connect_as, connect_plain, original_destination, unmap,
};

/// Either half of a connection, whether or not TLS is in the way.
///
/// Boxed only when TLS is on: a plain connection keeps the concrete types the
/// benchmark was run against, and a TLS one is paying for cryptography anyway, so a
/// virtual call per read is not what it will notice.
type Duplex = Box<dyn AsyncReadWrite + Unpin + Send>;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// What the engine does about TLS for one service.
#[derive(Clone, Default)]
pub struct TlsSetup {
    /// Terminate the client's TLS here, with this certificate.
    pub server: Option<std::sync::Arc<rustls::ServerConfig>>,
    /// Re-encrypt towards the service, the way nginx's `proxy_ssl on` does.
    pub upstream: Option<std::sync::Arc<rustls::ClientConfig>>,
}

impl TlsSetup {
    pub fn is_off(&self) -> bool {
        self.server.is_none() && self.upstream.is_none()
    }
}

const RELAY_BUF: usize = 64 * 1024;

/// Backstop for a direction that will not wind down — one blocked writing to a peer
/// that has stopped reading, say. The normal path is the stop signal below, which is
/// prompt.
const REJECT_GRACE: Duration = Duration::from_secs(2);

/// Where a connection should be forwarded.
#[derive(Clone, Copy, Debug)]
pub enum Upstream {
    /// One service behind one listener.
    Fixed(SocketAddr),
    /// Wherever the client was originally headed — one listener in front of many
    /// services, which is the point of a central proxy.
    Original,
}

pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub upstream: Upstream,
    /// Dial the service as the client, so it sees the real source address.
    ///
    /// Not a setting the operator sees: the proxy is supposed to be invisible, and a
    /// service that suddenly sees one address for every client is the opposite of
    /// that. It is here only so the fallback below has something to turn off.
    pub spoof_source: bool,
    /// Cap on the upstream handshake. A spoofed connect whose return path is not
    /// diverted does not fail, it hangs — this turns that into a visible fallback.
    pub connect_timeout: Duration,
    /// TLS on either edge. Rules always see plaintext.
    pub tls: TlsSetup,
    /// Where the decrypted stream is written out, when TLS is terminated here and the
    /// capture interface exists. `None` is the ordinary case, not a failure.
    pub capture: Option<std::sync::Arc<Capture>>,
    /// How many connections may be in flight at once. `0` means no limit.
    ///
    /// There was none, and the cost of that was measured rather than argued: roughly 505
    /// connections that are opened and then say nothing take a service down, because each
    /// one holds two descriptors — one from the client, one to the service, since the
    /// upstream is dialled on accept — against a 1024 limit. No data has to be sent.
    pub max_connections: usize,
    /// What happens to a connection that arrives while the limit is reached.
    ///
    /// Refusing keeps the promise that everything reaching the service was inspected,
    /// and costs reachability under attack. Forwarding keeps the service reachable and
    /// admits traffic nothing looked at. Neither is right in general, which is why it is
    /// the operator's to choose; refusing is the default because a filter that quietly
    /// stops filtering is the worse surprise.
    pub over_limit_forwards: bool,
    /// How long a connection may carry no bytes at all before it is closed. `None` is
    /// off, which is what it was before.
    ///
    /// Until the **first** byte moves, and never afterwards: this is not an idle
    /// timeout. A connection that has said something and then goes quiet is a session,
    /// and sessions are allowed to think. One that has said nothing in either direction
    /// since it was accepted is the shape of the attack the limit only contains — it
    /// holds a descriptor here and one on the service, having asked for nothing.
    ///
    /// Either direction counts, which is what makes it safe for the protocols where the
    /// *server* speaks first. A banner from SMTP or SSH satisfies the deadline exactly as
    /// a request would; requiring the client to speak would have hung every one of them.
    pub first_byte_timeout: Option<Duration>,
    /// Stamped on the connections the engine opens, so the intercept rules can skip
    /// them. `None` only where nothing could loop back.
    pub self_mark: Option<u32>,
}

impl ProxyConfig {
    pub fn fixed(listen: SocketAddr, upstream: SocketAddr) -> Self {
        Self {
            listen,
            upstream: Upstream::Fixed(upstream),
            spoof_source: false,
            connect_timeout: Duration::from_secs(5),
            tls: TlsSetup::default(),
            capture: None,
            max_connections: 0,
            over_limit_forwards: false,
            first_byte_timeout: None,
            self_mark: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct ProxyStats {
    pub accepted: AtomicU64,
    pub upstream_failures: AtomicU64,
    pub closed_by_filter: AtomicU64,
    /// Connections that reached the service under the proxy's own address because
    /// the transparent dial did not work. Traffic flows, identity is lost.
    pub source_spoof_failures: AtomicU64,
    /// Connections dropped because their original destination could not be recovered.
    pub origin_lookup_failures: AtomicU64,
    /// How many connections are being carried right now. The number the limit is about.
    pub live: AtomicU64,
    /// How many were closed for never saying anything. Cumulative, like the rest.
    pub no_first_byte: AtomicU64,
    /// How many arrived while the limit was reached — refused or forwarded unfiltered,
    /// whichever the operator chose. Cumulative, so a service that hit the wall once an
    /// hour ago still says so.
    pub over_limit: AtomicU64,
    warned_spoof: AtomicBool,
    /// Whether the limit has already been announced. Shared by both paths, so a service
    /// carrying TCP and UDP says it once rather than twice.
    pub warned_limit: AtomicBool,
}

/// Holds a slot in the connection count for as long as the connection lives.
///
/// A guard rather than a decrement at the end of `handle_connection`: that function has
/// a dozen ways out — a refused chain, a dial that fails, a handshake that times out, a
/// panic — and a counter that leaks on any one of them is a limit that tightens until it
/// refuses everything.
struct Slot(Arc<ProxyStats>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::Relaxed);
    }
}

/// How long to wait after an accept that failed before trying again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(20);

pub struct Proxy {
    listener: TcpListener,
    cfg: Arc<ProxyConfig>,
    chain: ChainHandle,
    pub stats: Arc<ProxyStats>,
}

impl Proxy {
    pub async fn bind(cfg: ProxyConfig, chain: ChainHandle) -> io::Result<Self> {
        let listener = bind_listener(cfg.listen)?;
        Ok(Self {
            listener,
            cfg: Arc::new(cfg),
            chain,
            stats: Arc::new(ProxyStats::default()),
        })
    }

    /// The address actually bound, so a caller passing port 0 can find it.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn stats(&self) -> Arc<ProxyStats> {
        Arc::clone(&self.stats)
    }

    /// Accept forever.
    ///
    /// Nothing a single connection does may end this loop: each one is handled in
    /// its own task, so even an outright panic in there costs that connection and
    /// nothing else. The listener outliving its connections is the whole point.
    pub async fn serve(self) -> io::Result<()> {
        loop {
            let (client, peer) = match self.listener.accept().await {
                // Unmapped here and nowhere else: past this line the rest of the engine
                // only ever sees the address the client really had, whether it arrived
                // on a v4 listener or on the v4 half of a dual-stack one.
                Ok((client, peer)) => (client, unmap(peer)),
                // Per-connection accept errors (fd limits, a client gone between
                // SYN and accept) must not be fatal.
                Err(e) => {
                    eprintln!("[warn] [proxy] accept failed: {e}");
                    // Out of descriptors, the condition does not clear by trying again
                    // immediately: the loop spins on `accept` → `EMFILE` → print →
                    // `accept`, which was measured burning about 40% of a core with four
                    // clients knocking, and writing a log line per attempt into the pipe
                    // the backend reads. A pause costs a few milliseconds of latency when
                    // accepting was going to fail anyway.
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            };
            self.stats.accepted.fetch_add(1, Ordering::Relaxed);

            // Claimed before the connection is spawned and released when it ends,
            // whichever way it ends.
            let live = self.stats.live.fetch_add(1, Ordering::Relaxed) + 1;
            let slot = Slot(Arc::clone(&self.stats));
            let limit = self.cfg.max_connections;
            let over = limit > 0 && live > limit as u64;
            if over {
                self.stats.over_limit.fetch_add(1, Ordering::Relaxed);
                // Once, not once per connection: the whole point of being at the limit
                // is that connections are arriving faster than they leave, and a line
                // each would be the flood arriving twice.
                if !self.stats.warned_limit.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "[warn] [proxy] {limit} concurrent connections reached; further \
                         connections are being {} until it clears",
                        if self.cfg.over_limit_forwards { "forwarded unfiltered" } else { "refused" },
                    );
                }
                if !self.cfg.over_limit_forwards {
                    // Dropped here, which closes it: refusing costs the client a
                    // connection and costs the service nothing.
                    drop(client);
                    drop(slot);
                    continue;
                }
            } else if live * 2 <= limit as u64 {
                // Armed again once there is real room, so the *next* time the wall is
                // hit is reported too. Halfway rather than at the limit, or a service
                // sitting exactly at it would log on every connection.
                self.stats.warned_limit.store(false, Ordering::Relaxed);
            }

            let cfg = Arc::clone(&self.cfg);
            let chain = self.chain.clone();
            let stats = Arc::clone(&self.stats);
            tokio::spawn(async move {
                let _slot = slot;
                // Over the limit and told to forward: the connection is relayed with no
                // chain at all. That is the operator's choice made literal — the traffic
                // reaches the service, and nothing claims to have looked at it.
                let result = if over {
                    handle_connection(client, peer, cfg, ChainHandle::new(FilterChain::empty()), stats).await
                } else {
                    handle_connection(client, peer, cfg, chain, stats).await
                };
                if let Err(e) = result {
                    eprintln!("[info] [proxy] connection from {peer} ended: {e}");
                }
            });
        }
    }
}

async fn dial(
    peer: SocketAddr,
    upstream: SocketAddr,
    cfg: &ProxyConfig,
    stats: &ProxyStats,
) -> io::Result<TcpStream> {
    if !cfg.spoof_source {
        return tokio::time::timeout(cfg.connect_timeout, connect_plain(upstream, cfg.self_mark))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream connect timed out"))?;
    }

    match tokio::time::timeout(
        cfg.connect_timeout,
        connect_as(peer.ip(), upstream, cfg.self_mark),
    )
    .await
    {
        Ok(Ok(stream)) => Ok(stream),
        // Losing the client's address is bad; losing the connection is worse. Fall
        // back, but make the degradation loud — a service silently seeing one source
        // address for everyone is exactly the kind of thing nobody notices in time.
        failed => {
            stats.source_spoof_failures.fetch_add(1, Ordering::Relaxed);
            if !stats.warned_spoof.swap(true, Ordering::Relaxed) {
                let why = match failed {
                    Ok(Err(e)) => e.to_string(),
                    _ => "timed out (is the return path diverted?)".to_string(),
                };
                eprintln!(
                    "[warn] [proxy] cannot reach {upstream} as {}: {why}. \
                     Falling back to our own address — the service will not see real client IPs.",
                    peer.ip()
                );
            }
            tokio::time::timeout(cfg.connect_timeout, connect_plain(upstream, cfg.self_mark))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "upstream connect timed out")
                })?
        }
    }
}

async fn handle_connection(
    client: TcpStream,
    peer: SocketAddr,
    cfg: Arc<ProxyConfig>,
    chain: ChainHandle,
    stats: Arc<ProxyStats>,
) -> io::Result<()> {
    let upstream = match cfg.upstream {
        Upstream::Fixed(addr) => addr,
        Upstream::Original => match original_destination(&client) {
            Ok(addr) => addr,
            Err(e) => {
                stats.origin_lookup_failures.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        },
    };

    // A rule that steers our own outbound traffic back at us would spin forever.
    if upstream == cfg.listen {
        stats.origin_lookup_failures.fetch_add(1, Ordering::Relaxed);
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to forward {upstream} to ourselves: check the intercept rules"),
        ));
    }

    let server = match dial(peer, upstream, &cfg, &stats).await {
        Ok(s) => s,
        Err(e) => {
            stats.upstream_failures.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }
    };
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);

    // Both directions share it: to a filter this is one stream, and a filter keeping
    // per-stream state must not see the two halves as unrelated clients.
    let connection = next_connection_id();
    // Told once, up front. These are the real addresses — this proxy knows both ends,
    // which is more than the header on the wire could say once the connection has been
    // terminated and reopened.
    chain.current().connection_opened(
        connection,
        &ConnectionMeta {
            client: peer,
            server: upstream,
            tcp: true,
        },
    );

    // Only where there is something to reconstruct: with TLS off, the bytes on the wire
    // *are* the plaintext, and anybody wanting them can capture the interface they are
    // already crossing rather than a copy this process invents.
    let tap = if cfg.tls.is_off() {
        None
    } else {
        Tap::open(cfg.capture.clone(), peer, upstream)
    };

    let (mut up, mut down) = if cfg.tls.is_off() {
        let (client_rd, client_wr) = tokio::io::split(client);
        let (server_rd, server_wr) = tokio::io::split(server);
        spawn_pumps(
            client_rd, client_wr, server_rd, server_wr, &chain, &stats, connection, None,
            cfg.first_byte_timeout,
        )
    } else {
        // Handshakes before anything is relayed, and all of them on the deadline: a peer
        // that opens a connection and then says nothing must not tie up a task.
        //
        // The order is the interesting part. The client's handshake is *started* and
        // then held open at the ClientHello, because that message carries the protocols
        // the client is willing to speak and this proxy has no business deciding them.
        // The upstream handshake goes next, offering the service exactly that list; what
        // the service picks is what the client is then told. Terminating in the middle
        // of a connection means answering for a service, and answering something the
        // service did not say is how a proxy breaks a protocol it was only supposed to
        // carry — a client told `h2` while the service speaks HTTP/1.1 sends frames to
        // something that cannot read them.
        let (started, wanted) = match &cfg.tls.server {
            Some(_) => {
                let start = tokio::time::timeout(
                    cfg.connect_timeout,
                    tokio_rustls::LazyConfigAcceptor::new(
                        rustls::server::Acceptor::default(),
                        client,
                    ),
                )
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
                let wanted: Vec<Vec<u8>> = start
                    .client_hello()
                    .alpn()
                    .map(|it| it.map(|p| p.to_vec()).collect())
                    .unwrap_or_default();
                (Some(start), wanted)
            }
            None => (None, Vec::new()),
        };

        let (server, agreed): (Duplex, Option<Vec<u8>>) = match &cfg.tls.upstream {
            Some(config) => {
                let name = tls::server_name(&upstream.ip().to_string())?;
                let connected = tokio::time::timeout(
                    cfg.connect_timeout,
                    tls::connector(tls::with_alpn(config, &wanted)).connect(name, server),
                )
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "upstream TLS handshake timed out")
                })??;
                let agreed = connected.get_ref().1.alpn_protocol().map(|p| p.to_vec());
                (Box::new(connected), agreed)
            }
            // Nothing upstream to ask, so nothing to relay back: the client is told no
            // protocol rather than one this end invented.
            None => (Box::new(server), None),
        };

        let client: Duplex = match (started, &cfg.tls.server) {
            (Some(start), Some(config)) => {
                let accepted = tokio::time::timeout(
                    cfg.connect_timeout,
                    start.into_stream(tls::answering_with(config, agreed.as_deref())),
                )
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out")
                })??;
                Box::new(accepted)
            }
            _ => unreachable!("a started handshake means a server config"),
        };
        let (client_rd, client_wr) = tokio::io::split(client);
        let (server_rd, server_wr) = tokio::io::split(server);
        spawn_pumps(
            client_rd, client_wr, server_rd, server_wr, &chain, &stats, connection,
            tap.clone(), cfg.first_byte_timeout,
        )
    };

    // A rule blocks a connection, not a direction. Half-closing would leave the
    // other side free to answer anyway — a service that replies without waiting for
    // the request would then still reach a client whose request was refused.
    fn rejected(r: &Result<io::Result<PumpOutcome>, tokio::task::JoinError>) -> bool {
        matches!(r, Ok(Ok(PumpOutcome::Rejected)))
    }
    async fn wind_down(
        other: &mut tokio::task::JoinHandle<io::Result<PumpOutcome>>,
        rejected: bool,
    ) {
        if !rejected {
            let _ = other.await;
            return;
        }
        if tokio::time::timeout(REJECT_GRACE, &mut *other)
            .await
            .is_err()
        {
            other.abort();
        }
    }

    tokio::select! {
        r = &mut up => wind_down(&mut down, rejected(&r)).await,
        r = &mut down => wind_down(&mut up, rejected(&r)).await,
    }
    // Both directions are finished, so anything a filter was keeping for this stream
    // can go. Filters whose state lives in a session were already freed by dropping
    // it; this is for the ones whose state lives somewhere the session cannot reach.
    chain.current().connection_closed(connection);
    // The reconstruction gets an end as well as a beginning, or Wireshark holds the
    // stream open waiting for bytes that are never coming.
    if let Some(tap) = &tap {
        tap.closed();
    }
    Ok(())
}

/// Why a direction stopped moving bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum PumpOutcome {
    /// The peer closed, or the stream simply ended.
    Finished,
    /// A rule refused the traffic, and the connection goes with it.
    Rejected,
}

/// Start both directions. Split out so the plain and the TLS paths share it.
#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
fn spawn_pumps<CR, CW, SR, SW>(
    client_rd: CR,
    client_wr: CW,
    server_rd: SR,
    server_wr: SW,
    chain: &ChainHandle,
    stats: &Arc<ProxyStats>,
    connection: ConnectionId,
    tap: Option<Arc<Tap>>,
    cfg_first_byte: Option<Duration>,
) -> (
    tokio::task::JoinHandle<io::Result<PumpOutcome>>,
    tokio::task::JoinHandle<io::Result<PumpOutcome>>,
)
where
    CR: AsyncReadExt + Unpin + Send + 'static,
    CW: AsyncWriteExt + Unpin + Send + 'static,
    SR: AsyncReadExt + Unpin + Send + 'static,
    SW: AsyncWriteExt + Unpin + Send + 'static,
{
    // A refusal has to stop the other direction too, but stopping it by aborting the
    // task drops its socket mid-stream: over TLS that reaches the peer as a
    // truncation error instead of a close. Telling it to stop lets it forward nothing
    // more and still shut down properly.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

    // Set by whichever direction moves a byte first. Both pumps hold it, so a server
    // that speaks before its client satisfies the deadline just as a request would.
    let spoken = Arc::new(AtomicBool::new(false));
    if let Some(deadline) = cfg_first_byte {
        let spoken = Arc::clone(&spoken);
        let stop = stop_tx.clone();
        let stats = Arc::clone(stats);
        tokio::spawn(async move {
            // Raced against the connection ending, not just slept through. Both pumps
            // hold a receiver, so `closed()` resolves the moment the connection is over
            // — and without that the timer outlives it for the whole deadline. A service
            // taking a few thousand short connections a second with a minute's deadline
            // would hold hundreds of thousands of sleeping tasks, which is the resource
            // exhaustion this feature exists to prevent, arriving by the front door.
            tokio::select! {
                _ = tokio::time::sleep(deadline) => {
                    if !spoken.load(Ordering::Relaxed) {
                        stats.no_first_byte.fetch_add(1, Ordering::Relaxed);
                        // Through the same channel a refusal uses, so both directions are
                        // shut down rather than dropped: a peer dropped mid-stream reads
                        // a truncation, and this connection has done nothing to deserve
                        // one.
                        let _ = stop.send(true);
                    }
                }
                _ = stop.closed() => {}
            }
        });
    }

    let up = tokio::spawn(pump(
        client_rd,
        server_wr,
        Direction::ClientToServer,
        chain.clone(),
        Arc::clone(stats),
        connection,
        tap.clone(),
        Arc::clone(&spoken),
        stop_tx.clone(),
        stop_rx.clone(),
    ));
    let down = tokio::spawn(pump(
        server_rd,
        client_wr,
        Direction::ServerToClient,
        chain.clone(),
        Arc::clone(stats),
        connection,
        tap,
        spoken,
        stop_tx,
        stop_rx,
    ));
    (up, down)
}

/// Move one direction of the stream, asking the chain about every chunk.
// Seven arguments rather than a struct: every one of them is moved into the task and
// used exactly once, so a struct would be a wrapper around the argument list.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
async fn pump<R, W>(
    mut rd: R,
    mut wr: W,
    dir: Direction,
    chain: ChainHandle,
    stats: Arc<ProxyStats>,
    connection: ConnectionId,
    tap: Option<Arc<Tap>>,
    spoken: Arc<AtomicBool>,
    stop_tx: tokio::sync::watch::Sender<bool>,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) -> io::Result<PumpOutcome>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    // This direction's filter state, opened on the first chunk and dropped with the
    // connection. Nothing here is shared with any other connection.
    let mut sessions = ChainSessions::new(connection);
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        let read = tokio::select! {
            r = rd.read(&mut buf) => r,
            // The other direction refused the connection. Nothing more is forwarded,
            // and this side is closed rather than dropped.
            _ = stop_rx.changed() => {
                let _ = wr.shutdown().await;
                return Ok(PumpOutcome::Finished);
            }
        };
        let n = match read {
            Ok(0) => break,
            Ok(n) => n,
            // However badly the other end goes away, this end is closed properly.
            // Returning here without shutting down leaves a TLS peer reading a
            // truncated stream instead of a close, which is the peer having to guess
            // again.
            Err(e) => {
                let _ = wr.shutdown().await;
                return Err(e);
            }
        };

        // Before the chain has a say: a chunk a filter goes on to refuse is still a
        // connection that said something, and the deadline is about silence.
        spoken.store(true, Ordering::Relaxed);

        // Re-read the handle every chunk so a chain swapped in mid-connection
        // takes effect without dropping anyone.
        let verdict = chain.current().run(dir, &buf[..n], &mut sessions).await;

        match verdict {
            Verdict::Accept => {
                if let Err(e) = wr.write_all(&buf[..n]).await {
                    let _ = wr.shutdown().await;
                    return Err(e);
                }
                // After the write, and only what was written: a reconstruction that
                // showed bytes the peer never received would disagree with the one
                // thing it exists to report.
                if let Some(tap) = &tap {
                    tap.wrote(dir == Direction::ClientToServer, &buf[..n]);
                }
            }

            Verdict::Reject(_) => {
                stats.closed_by_filter.fetch_add(1, Ordering::Relaxed);
                // Owning the connection means we can close it cleanly, instead of
                // dropping packets and leaving the peer to guess.
                let _ = stop_tx.send(true);
                let _ = wr.shutdown().await;
                return Ok(PumpOutcome::Rejected);
            }
        }
    }
    let _ = wr.shutdown().await;
    Ok(PumpOutcome::Finished)
}
