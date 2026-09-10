//! The filter layer, and the isolation that keeps it from taking the datapath down.
//!
//! Everything here exists to uphold one rule: **a filter may fail, the traffic may
//! not**. The NFQUEUE engine gets that property from the kernel (`NFQA_CFG_F_FAIL_OPEN`
//! plus the `bypass` flag on the nft rule): if userspace stops answering, packets flow
//! anyway. A userspace proxy has no such backstop, so it has to be built here.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Which half of the connection a chunk came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Data travelling from the client towards the protected service.
    ClientToServer,
    /// Data travelling from the protected service back to the client.
    ServerToClient,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::ClientToServer => "c->s",
            Direction::ServerToClient => "s->c",
        }
    }
}

/// What a filter decided about a chunk of stream data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Forward the chunk unchanged.
    Accept,
    /// Close the connection. Carries the id of the rule that refused it, so a block
    /// is attributed without a shared slot two connections could race over.
    Reject(Option<String>),
}

/// What a filter is shown about one chunk of traffic. Borrowed, so a filter that
/// cannot block is handed the relay's own buffers with nothing copied.
///
/// Only the new bytes. There is deliberately no re-scan region: a filter that has to
/// find a pattern straddling two chunks keeps the state to do so in its own session,
/// which costs nothing per chunk. An overlap window was the previous answer and it
/// was both slower and bounded — it could only find patterns shorter than itself.
pub struct FilterCtx<'a> {
    pub direction: Direction,
    /// The bytes that just arrived.
    pub chunk: &'a [u8],
    /// Which connection these bytes belong to.
    ///
    /// Both directions of one connection share it, because that is what a stream is
    /// to a filter. A filter that keeps state — the user's Python keeps a whole set of
    /// module globals — needs this to keep one client's state away from another's, and
    /// nothing else in the datapath can tell it for them.
    pub connection: ConnectionId,
}

/// What a filter is allowed to know about the layers below the application one.
///
/// Addresses and ports, and nothing else — no header bytes in either direction. The
/// two network layers cannot honestly offer the same thing below this line: the proxy
/// terminated the connection and writes its own headers, so a filter rewriting one
/// here would be rewriting nothing, while on NFQUEUE the same edit desynchronises the
/// stream. Metadata is the part that means the same thing on both, so metadata is what
/// crosses.
#[derive(Clone, Copy, Debug)]
pub struct ConnectionMeta {
    /// The peer that opened the connection.
    pub client: std::net::SocketAddr,
    /// Where it was actually headed — the protected service, not this proxy.
    pub server: std::net::SocketAddr,
    /// Whether this is a TCP connection or a UDP flow. A filter is shown it because the
    /// library's stream and HTTP models only apply to one of them, and a filter written
    /// against `RawPacket` may legitimately want to know which it is looking at.
    pub tcp: bool,
}

/// Identifies one connection for the lifetime of the process.
pub type ConnectionId = u64;

/// Hands out connection ids. Wrapping would take 585 years at a million per second.
static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);

pub fn next_connection_id() -> ConnectionId {
    NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed)
}

/// A unit of inspection. Deliberately synchronous and blocking: filters are user
/// code (today C++-embedded Python, tomorrow whatever we choose), and the engine
/// must stay correct when that code misbehaves rather than assume it will not.
pub trait Filter: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn inspect(&self, ctx: &FilterCtx<'_>) -> Verdict;

    /// Whether this filter might not return.
    ///
    /// User code has to be assumed capable of hanging, so it runs on a blocking
    /// thread under a deadline — which costs a thread hop and a copy of every chunk.
    /// A compiled regular expression cannot hang (the engine has no backtracking),
    /// so it says so and is run inline instead. A benchmark put that overhead at
    /// most of the difference between filtering and not filtering.
    fn may_block(&self) -> bool {
        true
    }

    /// Do whatever has to succeed before this filter can be trusted to run.
    ///
    /// Called when a ruleset is applied, never on the datapath. A filter that cannot
    /// get ready refuses the whole update, which is deliberately not fail-open: that
    /// covers a rule breaking under traffic, not a rule the operator asked for and
    /// never got.
    fn prepare(&self) -> Result<(), String> {
        Ok(())
    }

    /// Open this filter's state for one direction of one connection.
    ///
    /// `None` means the filter is stateless for that direction and [`Filter::inspect`]
    /// answers instead. Matching state must never be shared between connections —
    /// one client's bytes deciding another client's verdict is both a false positive
    /// and a way to smuggle a pattern past the filter by splitting it across two
    /// connections.
    ///
    /// A stateful filter has to be non-blocking. The blocking path abandons its
    /// thread when a filter blows the deadline, and a thread that owns connection
    /// state cannot be abandoned without losing it; [`FilterChain::with_policy`]
    /// refuses the combination rather than leaving it to be discovered under load.
    fn open_session(&self, _dir: Direction) -> Option<Box<dyn FilterSession>> {
        None
    }

    /// A connection has started, and here is what is known about it.
    ///
    /// Called once per connection before any of its chunks, so a filter that reports
    /// metadata to something outside this process has it before the first verdict is
    /// asked for. Most filters do not care and take the default.
    fn connection_opened(&self, _connection: ConnectionId, _meta: &ConnectionMeta) {}

    /// This connection is over; release whatever was being kept for it.
    ///
    /// Sessions are dropped by the connection that owned them, so a filter whose state
    /// is entirely in its session need not implement this. A filter holding state
    /// somewhere else — the Python worker keeps a set of globals per connection, in a
    /// process of its own — has no other way to learn that it can let go, and would
    /// otherwise grow for as long as the service runs.
    fn connection_closed(&self, _connection: ConnectionId) {}
}

/// One filter's state for one direction of one connection.
///
/// Split from [`Filter`] because the two have different lifetimes: the filter is the
/// compiled configuration, shared and swapped wholesale, while the session is the
/// per-connection position in the stream.
pub trait FilterSession: Send + 'static {
    fn inspect(&mut self, ctx: &FilterCtx<'_>) -> Verdict;
}

/// Every filter's state for one direction of one connection.
///
/// Held by the relay and handed to [`FilterChain::run`], so the sessions live and die
/// with the connection they belong to. Rebuilt when the chain underneath is replaced:
/// the sessions belong to the old chain's filters, and a swap means the operator
/// changed the rules — matching a new ruleset against old partial state would report
/// matches for patterns that were never in force.
pub struct ChainSessions {
    /// The connection these belong to, handed to every filter that is consulted.
    connection: ConnectionId,
    /// Which chain these sessions were opened against. Zero means "none yet"; live
    /// chains number from one.
    generation: u64,
    slots: Vec<Option<Box<dyn FilterSession>>>,
}

impl ChainSessions {
    pub fn new(connection: ConnectionId) -> Self {
        Self {
            connection,
            generation: 0,
            slots: Vec::new(),
        }
    }
}

/// Why a filter stopped being consulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisableReason {
    Panicked,
    TimedOut,
}

/// Counters worth reporting back to the backend. Kept plain so the spike does not
/// grow a metrics dependency before it has earned one.
#[derive(Debug, Default)]
pub struct ChainStats {
    pub inspected: AtomicU64,
    pub accepted: AtomicU64,
    pub rejected: AtomicU64,
    pub panics: AtomicU64,
    pub timeouts: AtomicU64,
    pub filters_disabled: AtomicU64,
    pub bypassed_chunks: AtomicU64,
}

/// Numbers chains so a connection can notice its sessions are stale. Starts at one
/// because zero means "no sessions opened yet".
static CHAIN_GENERATION: AtomicU64 = AtomicU64::new(1);

struct Slot {
    filter: Arc<dyn Filter>,
    /// Set once the filter has misbehaved enough to lose its say.
    disabled: AtomicBool,
    consecutive_timeouts: AtomicU64,
}

/// An immutable set of filters. Swapping the whole chain is how configuration
/// changes reach live connections, so a chain is never mutated in place.
pub struct FilterChain {
    slots: Vec<Slot>,
    /// Identifies this chain, so a connection can tell that the one it opened its
    /// sessions against is no longer the live one.
    generation: u64,
    deadline: Duration,
    max_consecutive_timeouts: u64,
    /// Trips when no filter is left to consult, making the chain a pure relay.
    degraded: AtomicBool,
    pub stats: Arc<ChainStats>,
}

impl FilterChain {
    pub fn new(filters: Vec<Arc<dyn Filter>>, deadline: Duration) -> Self {
        Self::with_policy(filters, deadline, 3)
    }

    pub fn with_policy(
        filters: Vec<Arc<dyn Filter>>,
        deadline: Duration,
        max_consecutive_timeouts: u64,
    ) -> Self {
        let degraded = AtomicBool::new(filters.is_empty());
        // A stateful filter on the blocking path would lose its state the first time
        // it blew the deadline, silently and only under load. Refusing it here makes
        // that a programming error instead of an incident.
        debug_assert!(
            filters
                .iter()
                .all(|f| !f.may_block()
                    || f.open_session(Direction::ClientToServer).is_none()),
            "a filter that may block cannot carry per-connection state"
        );
        Self {
            slots: filters
                .into_iter()
                .map(|filter| Slot {
                    filter,
                    disabled: AtomicBool::new(false),
                    consecutive_timeouts: AtomicU64::new(0),
                })
                .collect(),
            generation: CHAIN_GENERATION.fetch_add(1, Ordering::Relaxed),
            deadline,
            max_consecutive_timeouts,
            degraded,
            stats: Arc::new(ChainStats::default()),
        }
    }

    pub fn empty() -> Self {
        Self::new(Vec::new(), Duration::from_millis(50))
    }

    /// True when the chain has nothing left to say and the relay can skip it
    /// entirely — no copy, no thread hop. The degraded path has to be the cheap
    /// one, otherwise failing open costs more than working normally.
    pub fn is_bypassed(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    pub fn disabled_filters(&self) -> Vec<&str> {
        self.slots
            .iter()
            .filter(|s| s.disabled.load(Ordering::Relaxed))
            .map(|s| s.filter.name())
            .collect()
    }

    fn disable(&self, slot: &Slot, reason: DisableReason) {
        if slot.disabled.swap(true, Ordering::Relaxed) {
            return; // already out of the loop, do not double count
        }
        self.stats.filters_disabled.fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "[warn] [filter] '{}' disabled after {:?}: traffic keeps flowing without it",
            slot.filter.name(),
            reason
        );
        if self
            .slots
            .iter()
            .all(|s| s.disabled.load(Ordering::Relaxed))
        {
            self.degraded.store(true, Ordering::Relaxed);
            eprintln!("[warn] [filter] every filter is disabled, chain is now a plain relay");
        }
    }

    /// Tell every filter that a connection has started, and what it is.
    pub fn connection_opened(&self, connection: ConnectionId, meta: &ConnectionMeta) {
        for slot in &self.slots {
            slot.filter.connection_opened(connection, meta);
        }
    }

    /// Tell every filter that a connection is over.
    ///
    /// Called once per connection, not once per direction: a stream is one thing to a
    /// filter, and telling it twice would free state the other direction still needs.
    pub fn connection_closed(&self, connection: ConnectionId) {
        for slot in &self.slots {
            slot.filter.connection_closed(connection);
        }
    }

    /// Run the chain over one chunk.
    ///
    /// Any way a filter can fail — panic, or simply never returning — resolves to
    /// `Accept` for the chunk in flight. The chunk is never held hostage by the
    /// filter's failure.
    pub async fn run(
        &self,
        dir: Direction,
        data: &[u8],
        sessions: &mut ChainSessions,
    ) -> Verdict {
        if self.is_bypassed() {
            self.stats.bypassed_chunks.fetch_add(1, Ordering::Relaxed);
            return Verdict::Accept;
        }

        // First chunk of this connection, or the chain was swapped underneath it.
        if sessions.generation != self.generation {
            sessions.slots = self
                .slots
                .iter()
                .map(|slot| slot.filter.open_session(dir))
                .collect();
            sessions.generation = self.generation;
        }

        self.stats.inspected.fetch_add(1, Ordering::Relaxed);

        for (index, slot) in self.slots.iter().enumerate() {
            if slot.disabled.load(Ordering::Relaxed) {
                continue;
            }

            // A filter that cannot hang is run right here: no thread hop, no copy.
            // The deadline exists for code that might never return, and paying for
            // it on code that cannot is what the benchmark showed we were doing.
            if !slot.filter.may_block() {
                let ctx = FilterCtx {
                    direction: dir,
                    chunk: data,
                    connection: sessions.connection,
                };
                let outcome = match sessions.slots.get_mut(index).and_then(Option::as_mut) {
                    Some(session) => {
                        catch_unwind(AssertUnwindSafe(|| session.inspect(&ctx)))
                    }
                    None => catch_unwind(AssertUnwindSafe(|| slot.filter.inspect(&ctx))),
                };
                match outcome {
                    Ok(Verdict::Accept) => {}
                    Ok(Verdict::Reject(by)) => {
                        self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                        let id = by.clone().unwrap_or_else(|| slot.filter.name().to_string());
                        println!("BLOCKED {id}");
                        use std::io::Write;
                        let _ = std::io::stdout().flush();
                        return Verdict::Reject(by);
                    }
                    Err(_) => {
                        self.stats.panics.fetch_add(1, Ordering::Relaxed);
                        self.disable(slot, DisableReason::Panicked);
                    }
                }
                continue;
            }

            // The filter needs owned data: it runs on a blocking thread that may
            // outlive this call if it hangs, so it cannot borrow the relay buffer.
            let owned_chunk = data.to_vec();
            let filter = Arc::clone(&slot.filter);
            let connection = sessions.connection;

            let handle = tokio::task::spawn_blocking(move || {
                let ctx = FilterCtx {
                    direction: dir,
                    chunk: &owned_chunk,
                    connection,
                };
                catch_unwind(AssertUnwindSafe(|| filter.inspect(&ctx)))
            });

            match tokio::time::timeout(self.deadline, handle).await {
                Ok(Ok(Ok(verdict))) => {
                    slot.consecutive_timeouts.store(0, Ordering::Relaxed);
                    match verdict {
                        Verdict::Accept => {}
                        Verdict::Reject(by) => {
                            self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                            // The backend attributes the block to a rule by this id,
                            // the same way cppregex reports `BLOCKED <id>`.
                            let id = by.clone().unwrap_or_else(|| slot.filter.name().to_string());
                            println!("BLOCKED {id}");
                            use std::io::Write;
                            let _ = std::io::stdout().flush();
                            return Verdict::Reject(by);
                        }
                    }
                }
                // The filter panicked: it is broken code, not a transient hiccup,
                // so it loses its say immediately.
                Ok(Ok(Err(_))) | Ok(Err(_)) => {
                    self.stats.panics.fetch_add(1, Ordering::Relaxed);
                    self.disable(slot, DisableReason::Panicked);
                }
                // The filter blew the deadline. One slow call can be load, so it
                // takes a few in a row to lose the filter. The blocking thread is
                // abandoned; it cannot be cancelled, and waiting for it is exactly
                // the stall we refuse to have.
                Err(_) => {
                    self.stats.timeouts.fetch_add(1, Ordering::Relaxed);
                    let seen = slot.consecutive_timeouts.fetch_add(1, Ordering::Relaxed) + 1;
                    if seen >= self.max_consecutive_timeouts {
                        self.disable(slot, DisableReason::TimedOut);
                    }
                }
            }
        }

        self.stats.accepted.fetch_add(1, Ordering::Relaxed);
        Verdict::Accept
    }
}

/// Hands the live chain to every connection, and lets it be swapped underneath
/// them. Reconfiguring must not cost established connections: dropping them on a
/// filter edit would be a regression against the NFQUEUE engine, which reloads
/// its rules in place.
#[derive(Clone)]
pub struct ChainHandle {
    rx: tokio::sync::watch::Receiver<Arc<FilterChain>>,
    tx: Arc<tokio::sync::watch::Sender<Arc<FilterChain>>>,
}

impl ChainHandle {
    pub fn new(chain: FilterChain) -> Self {
        let (tx, rx) = tokio::sync::watch::channel(Arc::new(chain));
        Self {
            rx,
            tx: Arc::new(tx),
        }
    }

    /// The chain to use for the next chunk. Cheap enough to call per chunk.
    pub fn current(&self) -> Arc<FilterChain> {
        self.rx.borrow().clone()
    }

    /// Install a new chain. Connections in flight pick it up on their next chunk.
    pub fn replace(&self, chain: FilterChain) {
        let _ = self.tx.send(Arc::new(chain));
    }
}
