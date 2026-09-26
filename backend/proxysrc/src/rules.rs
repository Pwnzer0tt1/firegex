//! The filters the backend actually configures, and the wire format that carries them.
//!
//! One JSON line in, the whole ruleset at once — the same shape `cppregex` uses when
//! it takes its filter codes on stdin. Replacing the set wholesale means there is no
//! partial state to reason about, and [`crate::filter::ChainHandle`] swaps it under
//! live connections so a rule change costs nobody their connection.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use crate::filter::{Direction, Filter, FilterCtx, FilterSession, Verdict};
use crate::hyperscan;
use crate::pyworker::PyWorkerRule;

/// Which half of the traffic a rule looks at.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleDirection {
    #[default]
    Both,
    /// Client to server: requests.
    C2s,
    /// Server to client: responses, where a leaked flag would show up.
    S2c,
}

impl RuleDirection {
    fn label(self) -> &'static str {
        match self {
            RuleDirection::Both => "both ways",
            RuleDirection::C2s => "c->s",
            RuleDirection::S2c => "s->c",
        }
    }

    fn covers(self, dir: Direction) -> bool {
        match self {
            RuleDirection::Both => true,
            RuleDirection::C2s => dir == Direction::ClientToServer,
            RuleDirection::S2c => dir == Direction::ServerToClient,
        }
    }
}

// A matching pattern refuses the connection. There is no second action.
//
// could not keep its promise on a stream. Rewriting scanned one chunk at a time — bytes
// already forwarded cannot be taken back, so a match straddling two chunks was never
// rewritable — and the failure was silent: no block, no log, nothing to see. Measured,
// a pattern sent in one write reached the service rewritten and the same pattern split
// across two segments reached it untouched. Blocking scans in stream mode and caught
// both. Whether a rule fires should not depend on how the sender happened to segment.

/// One rule as the backend sends it.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum RuleSpec {
    /// A pattern, and what to do where it matches.
    Regex {
        id: String,
        /// Which filter this pattern belongs to.
        ///
        /// It decides what shares a compiled database, and therefore what the operator
        /// ordered: patterns of one filter are one thing they placed, and two filters
        /// are two. Grouping by "whatever arrived next" would silently merge two filters
        /// the operator deliberately separated.
        #[serde(default)]
        filter: String,
        pattern: String,
        #[serde(default)]
        direction: RuleDirection,
        #[serde(default = "default_true")]
        case_sensitive: bool,
    },
    /// Hand the traffic to the user's Python, in a process of its own.
    Python {
        id: String,
        /// File the worker executes. The backend writes it; the engine only runs it.
        code_path: String,
        /// Which of the file's `@pyfilter` functions are switched on.
        ///
        /// Absent means every one the file defines; a list means exactly those, and an
        /// empty list means none. The three are deliberately distinct: "not configured"
        /// and "the operator switched everything off" want opposite answers, and
        /// collapsing them would either run filters that were turned off or stop
        /// running filters nobody touched.
        #[serde(default)]
        enabled: Option<Vec<String>>,
        /// How to start the worker. Configured rather than hardcoded so a standalone
        /// install can point at its own interpreter.
        #[serde(default)]
        command: Vec<String>,
        #[serde(default = "default_python_timeout_ms")]
        timeout_ms: u64,
    },
}

fn default_true() -> bool {
    true
}

/// Generous compared to the chain's own deadline: this one has a process start-up
/// behind it the first time round.
fn default_python_timeout_ms() -> u64 {
    1000
}

/// Every blocking pattern that applies to one direction, matched in a single pass.
///
/// This is hyperscan, the same library `cppregex` matches with on the NFQUEUE side —
/// not a second engine that happens to accept similar syntax. One engine is what lets
/// a pattern mean the same thing whichever transport carries it, and what lets the
/// in-app debugger show the operator what will actually happen.
///
/// One database per direction rather than one per rule: hyperscan merges the automata,
/// so scanning for fifty patterns costs about what scanning for one costs. That is the
/// property a per-rule loop gave away, and a benchmark against nfregex made the loss
/// impossible to miss.
pub struct HyperscanRule {
    db: Arc<hyperscan::Database>,
    /// Parallel to the database's pattern ids: which rule each index belongs to.
    ids: Arc<Vec<String>>,
    label: String,
    direction: RuleDirection,
}

impl Filter for HyperscanRule {
    fn name(&self) -> &str {
        &self.label
    }
    fn may_block(&self) -> bool {
        false
    }
    fn inspect(&self, _ctx: &FilterCtx<'_>) -> Verdict {
        // Only reached for a direction this rule does not cover, or when opening the
        // scanner failed. Both mean "this rule has nothing to say about this chunk",
        // and a rule with nothing to say must never be the reason traffic stops.
        Verdict::Accept
    }
    fn open_session(&self, dir: Direction) -> Option<Box<dyn FilterSession>> {
        if !self.direction.covers(dir) {
            return None;
        }
        match hyperscan::StreamScanner::open(Arc::clone(&self.db)) {
            Ok(scanner) => Some(Box::new(HyperscanSession {
                scanner,
                ids: Arc::clone(&self.ids),
            })),
            // Fail open, loudly. The alternative is refusing connections because the
            // engine could not allocate scratch space, which is the traffic paying
            // for our problem.
            Err(e) => {
                eprintln!("[warn] [filter] '{}' could not open a scanner ({e}): this connection goes unfiltered", self.label);
                None
            }
        }
    }
}

/// One connection's position in the stream, for one direction.
struct HyperscanSession {
    scanner: hyperscan::StreamScanner,
    ids: Arc<Vec<String>>,
}

impl FilterSession for HyperscanSession {
    fn inspect(&mut self, ctx: &FilterCtx<'_>) -> Verdict {
        match self.scanner.scan(ctx.chunk) {
            Ok(Some(index)) => {
                // The id travels with the verdict rather than being stashed on the
                // rule, so two connections blocking at the same instant cannot be
                // credited to each other's pattern.
                let id = self
                    .ids
                    .get(index as usize)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                // Reset the stream so that subsequent scans on this session (e.g. further UDP datagrams
                // or connections) don't fail due to HS_SCAN_TERMINATED.
                let _ = self.scanner.reset();
                Verdict::Reject(Some(id))
            }
            Ok(None) => Verdict::Accept,
            // A scan that errors has told us nothing about the chunk, so the chunk
            // goes through. Reset the scanner so future chunks/datagrams can still be scanned.
            Err(e) => {
                let _ = self.scanner.reset();
                eprintln!("[warn] [filter] scan failed ({e}): scanner reset, chunk forwarded");
                Verdict::Accept
            }
        }
    }
}

/// Parse a whole ruleset from one JSON line.
///
/// All or nothing: a single bad rule rejects the update and leaves the running chain
/// untouched, because half a ruleset is worse than the previous one.
pub fn parse_ruleset(line: &str) -> Result<Vec<Arc<dyn Filter>>, String> {
    parse_ruleset_reusing(line, &[])
}

/// [`parse_ruleset`], carrying over any filter of `previous` that the new ruleset
/// describes exactly as it was (`Filter::reuse_key`).
///
/// A ruleset is sent whole on every edit, so without this a pattern changed in one
/// filter restarted the Python worker of another, and the new worker met every open
/// connection in the middle: its module globals were gone, its HTTP parser started on
/// the second half of whatever request was in flight, and the addresses it had been told
/// when each connection opened were never told again.
pub fn parse_ruleset_reusing(
    line: &str,
    previous: &[Arc<dyn Filter>],
) -> Result<Vec<Arc<dyn Filter>>, String> {
    let specs: Vec<RuleSpec> =
        serde_json::from_str(line).map_err(|e| format!("malformed ruleset: {e}"))?;

    // The order the backend sent is the order the operator set, and it is kept. An
        // Python — which quietly turned the chain into a set, so a filter placed after
    // another could run before it. Nothing visible said so until a test asked whether
    // a pattern could catch what the filter before it had written.
    //
    // Patterns of one filter still share a database, because that is what makes matching
    // cost the same at fifty rules as at one. A group is exactly a filter, so grouping
    // never crosses a boundary the operator can see.
    let mut out: Vec<Arc<dyn Filter>> = Vec::new();
    let mut pending: Vec<(String, RuleDirection, hyperscan::Pattern)> = Vec::new();
    let mut pending_filter: Option<String> = None;

    fn flush(
        pending: &mut Vec<(String, RuleDirection, hyperscan::Pattern)>,
        out: &mut Vec<Arc<dyn Filter>>,
    ) -> Result<(), String> {
        if pending.is_empty() {
            return Ok(());
        }
        for direction in [RuleDirection::C2s, RuleDirection::S2c] {
            let selected: Vec<_> = pending
                .iter()
                .filter(|(_, d, _)| {
                    d.covers(match direction {
                        RuleDirection::C2s => Direction::ClientToServer,
                        _ => Direction::ServerToClient,
                    })
                })
                .collect();
            if selected.is_empty() {
                continue;
            }
            let patterns: Vec<hyperscan::Pattern> = selected
                .iter()
                .map(|(_, _, p)| hyperscan::Pattern {
                    expr: p.expr.clone(),
                    case_sensitive: p.case_sensitive,
                })
                .collect();

            let ids: Vec<String> =
                selected.iter().map(|(id, _, _)| id.clone()).collect();
            let db = hyperscan::Database::compile(&patterns, hyperscan::Mode::Stream)
                .map_err(|e| format!("cannot build the rule set: {e}"))?;
            out.push(Arc::new(HyperscanRule {
                label: format!("{} blocking rule(s) {}", ids.len(), direction.label()),
                db: Arc::new(db),
                ids: Arc::new(ids),
                direction,
            }));
        }
        pending.clear();
        Ok(())
    }

    for spec in specs {
        match spec {
            RuleSpec::Regex {
                id,
                filter,
                pattern,
                direction,
                case_sensitive,
            } => {
                // A different filter is a different thing the operator placed, so it
                // ends the group before it and takes its own position.
                if pending_filter.as_deref() != Some(filter.as_str()) {
                    flush(&mut pending, &mut out)?;
                    pending_filter = Some(filter.clone());
                }
                // Compiled alone first, only to be thrown away: hyperscan reports the
                // first pattern that failed and stops, so a set that fails to build says
                // nothing about which of the others were fine. The operator needs to know
                // which rule to fix.
                hyperscan::Database::validate(&pattern, case_sensitive, hyperscan::Mode::Stream)
                    .map_err(|e| format!("invalid regex '{pattern}': {e}"))?;
                pending.push((
                    id,
                    direction,
                    hyperscan::Pattern { expr: pattern, case_sensitive },
                ));
            }
            RuleSpec::Python {
                id,
                code_path,
                command,
                enabled,
                timeout_ms,
            } => {
                // A process is not a pattern, so it ends the run of patterns before it
                // and takes its place in the order.
                flush(&mut pending, &mut out)?;
                pending_filter = None;
                let command = if command.is_empty() {
                    // The engine has no idea where the backend installed the worker, so
                    // the backend says. The env var is the fallback for a hand-run
                    // engine; there is no sensible hardcoded path.
                    let worker = std::env::var("FGEX_PROXY_PYWORKER").map_err(|_| {
                        "a python rule needs `command`, or FGEX_PROXY_PYWORKER set".to_string()
                    })?;
                    vec!["python3".to_string(), worker]
                } else {
                    command
                };
                let deadline = Duration::from_millis(timeout_ms);
                let key = PyWorkerRule::key_for(&id, &command, &code_path, &enabled, deadline);
                let kept = key.as_deref().and_then(|key| {
                    previous
                        .iter()
                        .find(|filter| filter.reuse_key() == Some(key))
                        .cloned()
                });
                out.push(match kept {
                    Some(filter) => filter,
                    None => Arc::new(
                        PyWorkerRule::new(id, command, code_path, enabled, deadline)
                            .reusable_as(key),
                    ),
                })
            }
        }
    }
    flush(&mut pending, &mut out)?;
    Ok(out)
}
