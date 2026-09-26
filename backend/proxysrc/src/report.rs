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
