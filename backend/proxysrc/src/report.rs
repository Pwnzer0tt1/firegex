//! Every line this engine sends the backend, written by a thread of its own.
//!
//! stdout is a pipe the backend reads, and a pipe fills. Each refused connection used to
//! be a `println!("BLOCKED …")` from the thread that refused it — so when the backend fell
//! behind, which a flood of refused connections makes it do, the pipe filled and those
//! writes blocked: the runtime threads carrying every other connection sat waiting on it.
//! Measured, 5000 refused connections took 74 seconds to get through, and a legitimate
//! client meanwhile waited a median 4.5 seconds and half the time not at all — an attacker
//! slowing a service to a halt by sending it exactly what firegex was there to refuse.
//!
//! So nothing on the datapath writes to stdout any more. Lines go into a bounded queue and
//! a thread of their own writes them out; a report of what happened (`BLOCKED`, `STATS`)
//! is dropped and counted when the queue is full, and a reply the backend is waiting for
//! (`PORT`, `UDP`, `ACK`) waits for room, so it is never lost and never overtakes a line
//! sent before it.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// How many lines may wait for the backend. At a few dozen bytes each this is a megabyte;
/// what it buys is that a burst of refusals is reported whole rather than cut off.
const QUEUE: usize = 32 * 1024;

/// How often a count of reports that had to be dropped is written out.
const DROPS_SAID_EVERY: Duration = Duration::from_secs(5);

static SENDER: OnceLock<SyncSender<String>> = OnceLock::new();
static DROPPED: AtomicU64 = AtomicU64::new(0);

fn sender() -> &'static SyncSender<String> {
    SENDER.get_or_init(|| {
        let (tx, rx) = sync_channel::<String>(QUEUE);
        std::thread::Builder::new()
            .name("fgex-report".to_string())
            .spawn(move || {
                let stdout = std::io::stdout();
                let mut said = Instant::now();
                while let Ok(first) = rx.recv() {
                    let mut out = stdout.lock();
                    let _ = writeln!(out, "{first}");
                    // Whatever else is already waiting goes in the same write.
                    while let Ok(line) = rx.try_recv() {
                        let _ = writeln!(out, "{line}");
                    }
                    let _ = out.flush();
                    drop(out);
                    if said.elapsed() >= DROPS_SAID_EVERY {
                        let dropped = DROPPED.swap(0, Ordering::Relaxed);
                        if dropped > 0 {
                            eprintln!(
                                "[warn] [report] {dropped} refusals were not reported to the \
                                 backend: it was not reading fast enough. They were refused all \
                                 the same; only the counters and the log are short of them."
                            );
                        }
                        said = Instant::now();
                    }
                }
            })
            .expect("cannot start the thread that talks to the backend");
        tx
    })
}

/// A reply the backend is waiting for. Waits for room rather than being dropped.
pub fn reply(line: String) {
    let _ = sender().send(line);
}

/// A report of something that happened. Never waits: dropped and counted when the backend
/// is too far behind, so the datapath is never held up by it.
pub fn event(line: String) {
    if let Err(TrySendError::Full(_)) = sender().try_send(line) {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

/// A rule refused a connection.
pub fn blocked(id: &str) {
    event(format!("BLOCKED {id}"));
}

// --- what the datapath says about itself ------------------------------------------------
//
// stderr is a pipe the backend reads too, and it fills the same way stdout did. Worse, it
// is written straight from the threads carrying traffic: a line per connection that ended
// with an error, or per client that spoke the wrong thing at a TLS address, was a write
// every runtime thread queued up on — `eprintln!` takes one lock for the whole process —
// and once the backend fell behind, one that blocked them all. Several of those lines are
// the client's to trigger at will. So the datapath's diagnostics go through a queue and a
// thread of their own, exactly as its reports do, and the ones a client can cause as often
// as it likes are counted rather than written past a few.

static DIAG: OnceLock<SyncSender<String>> = OnceLock::new();
static DIAG_DROPPED: AtomicU64 = AtomicU64::new(0);

fn diag_sender() -> &'static SyncSender<String> {
    DIAG.get_or_init(|| {
        let (tx, rx) = sync_channel::<String>(QUEUE);
        std::thread::Builder::new()
            .name("fgex-diag".to_string())
            .spawn(move || {
                let stderr = std::io::stderr();
                while let Ok(first) = rx.recv() {
                    let mut out = stderr.lock();
                    let _ = writeln!(out, "{first}");
                    while let Ok(line) = rx.try_recv() {
                        let _ = writeln!(out, "{line}");
                    }
                    let dropped = DIAG_DROPPED.swap(0, Ordering::Relaxed);
                    if dropped > 0 {
                        let _ = writeln!(
                            out,
                            "[warn] [report] {dropped} diagnostic line(s) were dropped: the \
                             backend was not reading them fast enough"
                        );
                    }
                    let _ = out.flush();
                }
            })
            .expect("cannot start the thread that writes the engine's diagnostics");
        tx
    })
}

/// A line about the datapath's own health. Never waits: dropped and counted when the
/// backend is too far behind, so nothing carrying traffic is held up by it.
pub fn diag(line: String) {
    if let Err(TrySendError::Full(_)) = diag_sender().try_send(line) {
        DIAG_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Milliseconds on a monotonic clock, never zero.
fn now_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1
}

/// At most `per_window` lines per window from one place in the code; the rest counted and
/// said as one line when the next window opens.
///
/// For the lines a client can make the engine write as often as it likes — a connection
/// ending badly, a cleartext client at a TLS address, a malformed request. The first few
/// of a window are what an operator needs to see what is happening; the count says how
/// much of it there is; the thousands in between would only push everything else out of
/// a log that holds a few hundred lines.
pub struct Throttle {
    /// Says what was held back, tag included: `[warn] [proxy] cleartext clients at a TLS
    /// address`, so the summary is classified like the lines it stands for.
    what: &'static str,
    per_window: u64,
    window_ms: u64,
    opened_ms: AtomicU64,
    said: AtomicU64,
    held: AtomicU64,
}

impl Throttle {
    pub const fn new(what: &'static str, per_window: u64, window_secs: u64) -> Self {
        Self {
            what,
            per_window,
            window_ms: window_secs * 1000,
            opened_ms: AtomicU64::new(0),
            said: AtomicU64::new(0),
            held: AtomicU64::new(0),
        }
    }

    pub fn say(&self, line: impl FnOnce() -> String) {
        self.say_at(now_ms(), line, &mut diag);
    }

    fn say_at(&self, now: u64, line: impl FnOnce() -> String, out: &mut dyn FnMut(String)) {
        let opened = self.opened_ms.load(Ordering::Relaxed);
        if now.saturating_sub(opened) >= self.window_ms
            && self
                .opened_ms
                .compare_exchange(opened, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.said.store(0, Ordering::Relaxed);
            let held = self.held.swap(0, Ordering::Relaxed);
            if held > 0 {
                out(format!(
                    "{}: {held} more like this in the last {}s, not written",
                    self.what,
                    now.saturating_sub(opened) / 1000,
                ));
            }
        }
        if self.said.fetch_add(1, Ordering::Relaxed) < self.per_window {
            out(line());
        } else {
            self.held.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// `eprintln!` for the datapath: through the queue, never blocking. See [`diag`].
#[macro_export]
macro_rules! diag {
    ($($arg:tt)*) => {
        $crate::report::diag(format!($($arg)*))
    };
}

/// [`diag!`], at most `per` times every `secs` seconds from this call site. See [`Throttle`].
#[macro_export]
macro_rules! diag_throttled {
    ($what:expr, $per:expr, $secs:expr, $($arg:tt)*) => {{
        static THROTTLE: $crate::report::Throttle =
            $crate::report::Throttle::new($what, $per, $secs);
        THROTTLE.say(|| format!($($arg)*));
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(throttle: &Throttle, at: u64, n: usize) -> Vec<String> {
        let mut said = Vec::new();
        for i in 0..n {
            throttle.say_at(at, || format!("line {i}"), &mut |line| said.push(line));
        }
        said
    }

    #[test]
    fn a_window_says_its_first_lines_and_holds_the_rest() {
        let throttle = Throttle::new("[info] [test] things", 3, 10);
        assert_eq!(run(&throttle, 50_000, 100), vec!["line 0", "line 1", "line 2"]);
    }

    #[test]
    fn what_was_held_is_counted_when_the_next_window_opens() {
        let throttle = Throttle::new("[warn] [test] things", 2, 10);
        run(&throttle, 50_000, 7);
        let said = run(&throttle, 61_000, 1);
        assert_eq!(said.len(), 2, "{said:?}");
        assert!(said[0].starts_with("[warn] [test] things: 5 more"), "{said:?}");
        assert_eq!(said[1], "line 0");
    }

    #[test]
    fn a_quiet_window_says_nothing_about_holding_anything_back() {
        let throttle = Throttle::new("[info] [test] things", 2, 10);
        run(&throttle, 50_000, 1);
        assert_eq!(run(&throttle, 70_000, 1), vec!["line 0"]);
    }
}
