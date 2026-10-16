//! Filters built from a text spec.
//!
//! Provisional: the real engine will take its filters from the backend. This exists
//! so the datapath's guarantees can be driven from outside the process — the Python
//! suite needs to be able to ask for a filter that panics, or one that never returns,
//! without linking against the crate.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::filter::{Direction, Filter, FilterCtx, FilterSession, Verdict};

/// Panics on every chunk. Stands in for user code with a bug in it.
pub struct PanicFilter {
    name: String,
}

impl Filter for PanicFilter {
    fn name(&self) -> &str {
        &self.name
    }
    fn inspect(&self, _ctx: &FilterCtx<'_>) -> Verdict {
        panic!("filter '{}' panicked on purpose", self.name);
    }
}

/// Set only by [`release_hangs`], so a test can let abandoned filter threads exit.
/// The binary never sets it: for the Python suite the hang has to be genuine.
static HANG_RELEASE: AtomicBool = AtomicBool::new(false);

/// Let every [`HangFilter`] currently stuck in `inspect` return.
///
/// Needed because a blocking filter thread cannot be cancelled: the engine walks
/// away from it, but the thread lives until its own code decides to stop. Tests
/// would otherwise hang on runtime shutdown, which waits for the blocking pool —
/// the same reason a hung filter costs a pool thread until the process restarts.
pub fn release_hangs() {
    HANG_RELEASE.store(true, Ordering::Relaxed);
}

/// Never returns on its own. Stands in for user code that deadlocks or waits on
/// something that will not happen — the failure mode `catch_unwind` cannot help with.
pub struct HangFilter {
    name: String,
}

impl Filter for HangFilter {
    fn name(&self) -> &str {
        &self.name
    }
    fn inspect(&self, _ctx: &FilterCtx<'_>) -> Verdict {
        while !HANG_RELEASE.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(20));
        }
        Verdict::Accept
    }
}

/// Closes the connection when the needle shows up.
///
/// Stateful for the same reason the real regex filter is: a needle that arrives in
/// two writes is still a needle, and a test filter that missed it would let the
/// integration suite pass on a datapath that had lost the property.
pub struct BlockFilter {
    name: String,
    needle: Vec<u8>,
}

impl Filter for BlockFilter {
    fn name(&self) -> &str {
        &self.name
    }
    fn may_block(&self) -> bool {
        false
    }
    fn inspect(&self, _ctx: &FilterCtx<'_>) -> Verdict {
        Verdict::Accept // never reached: this filter always opens a session
    }
    fn open_session(&self, _dir: Direction) -> Option<Box<dyn FilterSession>> {
        Some(Box::new(BlockSession {
            name: self.name.clone(),
            needle: self.needle.clone(),
            tail: Vec::new(),
        }))
    }
}

struct BlockSession {
    name: String,
    needle: Vec<u8>,
    tail: Vec<u8>,
}

impl FilterSession for BlockSession {
    fn inspect(&mut self, ctx: &FilterCtx<'_>) -> Verdict {
        let mut window = std::mem::take(&mut self.tail);
        window.extend_from_slice(ctx.chunk);
        let hit = contains(&window, &self.needle);
        // Keep just enough of the tail that a needle straddling the boundary is
        // found once, and never twice.
        let keep = window.len().min(self.needle.len().saturating_sub(1));
        self.tail = window[window.len() - keep..].to_vec();
        if hit {
            Verdict::Reject(Some(self.name.clone()))
        } else {
            Verdict::Accept
        }
    }
}


fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Parse one spec: `panic`, `hang` or `block:<needle>`.
///
/// There was a `replace:<from>:<to>` here, and it went with the rewriting verdict rather
/// than being dropped from the scaffolding on its own — there is nothing left for a test
/// filter to ask the chain to do but accept or refuse.
pub fn parse_filter(spec: &str) -> Result<Arc<dyn Filter>, String> {
    let spec = spec.trim();
    let (kind, rest) = match spec.split_once(':') {
        Some((k, r)) => (k, Some(r)),
        None => (spec, None),
    };

    match (kind, rest) {
        ("panic", _) => Ok(Arc::new(PanicFilter {
            name: "panic".to_string(),
        })),
        ("hang", _) => Ok(Arc::new(HangFilter {
            name: "hang".to_string(),
        })),
        ("block", Some(needle)) if !needle.is_empty() => Ok(Arc::new(BlockFilter {
            name: format!("block({needle})"),
            needle: needle.as_bytes().to_vec(),
        })),

        _ => Err(format!("unknown filter spec '{spec}'")),
    }
}

/// Parse a comma-separated list. An empty string yields no filters.
pub fn parse_filters(specs: &str) -> Result<Vec<Arc<dyn Filter>>, String> {
    specs
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_filter)
        .collect()
}
