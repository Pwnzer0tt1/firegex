//! User Python code, kept out of the datapath process.
//!
//! The C++ engine embeds CPython, which is where a good share of its
//! complexity lives: sub-interpreters with their own GIL, `check_multi_interp_extensions`
//! locking out most of the ecosystem, and `allow_threads = 0` locking out the user's own.
//!
//! Here the code runs in a child process instead, for one reason above all: **a hung
//! worker can be killed, a hung thread cannot**. The engine's own filter deadline can
//! only walk away from a blocking thread and leave it holding a pool slot until the
//! process restarts — measured and asserted in `tests/fail_open.rs`. A child that
//! misses its deadline is killed outright and respawned on the next chunk, and the
//! chunk it was holding is forwarded.
//!
//! Frames are length-prefixed and binary, in both directions:
//!
//! ```text
//! engine -> worker   [u32 len][u8 kind][u64 connection][payload]
//!                     kind: 0 client->server, 1 server->client,
//!                           2 connection closed, 3 connection opened
//! worker -> engine   [u32 len][u8 verdict][u8 name len][name][payload]
//!                     verdict: 0 accept, 1 reject
//! ```
//!
//! The name is the `@pyfilter` function that decided, which is what makes a block
//! attributable to one function of a file rather than to the file as a whole — a file
//! routinely holds several, and "this filter blocked 900 connections" is not an answer
//! when you are trying to find out which of them is doing it.
//!
//! Neither an open nor a close frame is answered. A close has no verdict to give about
//! a connection that is already over, and waiting for one would make tearing down a
//! connection depend on a process the engine is willing to kill; an open carries the
//! connection's metadata — the addresses and ports a filter is allowed to read — once,
//! rather than repeating it on every chunk.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::filter::{ConnectionId, ConnectionMeta, Direction, Filter, FilterCtx, Verdict, L4};

const VERDICT_ACCEPT: u8 = 0;
const VERDICT_REJECT: u8 = 1;
/// Sent by the worker once the user's file has run. Waiting for it is what turns
/// "this code does not load" into a refused ruleset instead of a service that
/// silently stopped filtering.
const READY: u8 = 0xFF;

/// What a frame means. The worker keeps one set of the user's module globals per
/// connection, which is what the documented API promises, so every frame has to say
/// which connection it belongs to — and something has to say when one is over, or the
/// worker would grow for as long as the service runs.
const KIND_C2S: u8 = 0;
const KIND_S2C: u8 = 1;
const KIND_CLOSE: u8 = 2;
/// Carries the connection's metadata as one JSON object. Everything below the
/// application layer that a filter may see arrives here and nowhere else — there are no
/// header bytes in the data frames, and no way to ask for any.
const KIND_OPEN: u8 = 3;

/// `[u32 len][u8 kind][u64 connection][payload]`, big-endian, len covering everything
/// after itself.
fn build_frame(connection: ConnectionId, kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 13);
    frame.extend_from_slice(&(payload.len() as u32 + 9).to_be_bytes());
    frame.push(kind);
    frame.extend_from_slice(&connection.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// How long a worker gets to import and execute the user's file. Longer than a
/// per-chunk deadline on purpose: this one pays for interpreter start-up.
const STARTUP_GRACE: Duration = Duration::from_secs(10);

/// Cap on one frame, so a confused worker cannot ask us to allocate the machine away.
const MAX_FRAME: u32 = 64 * 1024 * 1024;

/// Cap on the open and close frames waiting for the next exchange. Reached only when
/// nothing has asked the worker anything for thousands of connections — a filter that
/// has lost its say is still told about every connection — and past it they are
/// dropped: a connection then reaches the worker without its addresses, or leaves state
/// behind in a worker that was not going to be asked anything anyway.
const MAX_PENDING: usize = 1024 * 1024;

#[derive(Debug, Default)]
pub struct WorkerStats {
    /// Times the worker was killed for missing its deadline or dying on its own.
    pub restarts: AtomicU64,
    /// Chunks forwarded because the worker could not answer for them.
    pub failed_open: AtomicU64,
}

/// A filter backed by a child process running the user's Python.
pub struct PyWorkerRule {
    id: String,
    command: Vec<String>,
    code_path: String,
    /// The subset of the file's `@pyfilter` functions to run; `None` means all of them.
    enabled: Option<Vec<String>>,
    deadline: Duration,
    /// One worker, one conversation at a time. Serialising is the honest simple
    /// thing: a frame is a request and a response, and interleaving them would need
    /// request ids and a worker able to answer out of order. A pool comes later.
    child: Mutex<Option<Child>>,
    /// Open and close frames not yet written, in order. They need no answer, and they
    /// are told from the relay itself — on the async runtime — where taking `child`
    /// meant waiting out whatever exchange held it, up to its whole deadline, and where
    /// a worker that had to be started first was started right there. A filter hanging
    /// on one connection held every new connection of the service in that queue, on the
    /// threads that carry all the others. The next exchange writes them ahead of its own
    /// chunk, which runs where blocking is allowed and keeps an open ahead of the data.
    pending: Mutex<Vec<u8>>,
    pub stats: std::sync::Arc<WorkerStats>,
}

impl PyWorkerRule {
    pub fn new(
        id: String,
        command: Vec<String>,
        code_path: String,
        enabled: Option<Vec<String>>,
        deadline: Duration,
    ) -> Self {
        Self {
            id,
            command,
            code_path,
            enabled,
            deadline,
            child: Mutex::new(None),
            pending: Mutex::new(Vec::new()),
            stats: std::sync::Arc::new(WorkerStats::default()),
        }
    }

    fn spawn(&self) -> Result<Child, String> {
        let (program, args) = self
            .command
            .split_first()
            .ok_or_else(|| "no command for the worker".to_string())?;
        let mut child = Command::new(program)
            .args(args)
            // The file, and which of its functions are switched on. Which protocol it
            // speaks is the file's own business — the library reads it off what the
            // filters ask for, so there is nothing here that could disagree with the
            // code.
            //
            // The selection is a marker plus a comma-separated list, because "run
            // everything" and "run nothing" are both real answers and an empty string
            // cannot mean both: `*` is all of them, `=` followed by names is exactly
            // those, and `=` alone is none.
            .arg(&self.code_path)
            .arg(match &self.enabled {
                None => "*".to_string(),
                Some(names) => format!("={}", names.join(",")),
            })
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Tracebacks go to our stderr, where the backend already reads them.
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("cannot start the worker: {e}"))?;

        // Wait for it to say it loaded. A file that raises on import never gets here.
        let deadline_at = Instant::now() + STARTUP_GRACE;
        let ready = (|| -> Result<(), String> {
            let stdout = child.stdout.as_mut().ok_or("worker has no stdout")?;
            let mut header = [0u8; 4];
            read_before(stdout, &mut header, deadline_at)?;
            // The same shape as a verdict — marker plus an empty name — so there is one
            // frame layout on this channel rather than one for the handshake and
            // another for everything after it.
            if u32::from_be_bytes(header) != 2 {
                return Err("worker did not announce itself".to_string());
            }
            let mut marker = [0u8; 2];
            read_before(stdout, &mut marker, deadline_at)?;
            if marker[0] != READY {
                return Err("worker did not announce itself".to_string());
            }
            Ok(())
        })();
        if let Err(why) = ready {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("the filter code did not load: {why}"));
        }
        Ok(child)
    }

    /// Which `@pyfilter` functions of the file are switched on, or `None` for all.
    ///
    /// Deciding here rather than in the file is the point: a function is turned off
    /// without editing the code that defines it, and turned back on without the
    /// operator having to remember what they deleted.
    /// Hold a frame that needs no answer for the next exchange. See `pending`.
    fn queue(&self, frame: Vec<u8>) {
        let Ok(mut pending) = self.pending.lock() else { return };
        if pending.len() + frame.len() > MAX_PENDING {
            pending.clear();
        }
        pending.extend_from_slice(&frame);
    }

    pub fn enabled(&self) -> Option<&[String]> {
        self.enabled.as_deref()
    }

    /// Start the worker now, so a ruleset carrying code that cannot load is refused
    /// at the moment it is applied rather than discovered later as unfiltered traffic.
    pub fn warm_up(&self) -> Result<(), String> {
        let mut slot = self
            .child
            .lock()
            .map_err(|_| "worker lock poisoned".to_string())?;
        if slot.is_none() {
            *slot = Some(self.spawn()?);
        }
        Ok(())
    }

    /// Kill and forget, so the next chunk starts a fresh one.
    fn discard(&self, slot: &mut Option<Child>, why: &str) {
        if let Some(mut child) = slot.take() {
            let _ = child.kill();
            let _ = child.wait();
            self.stats.restarts.fetch_add(1, Ordering::Relaxed);
            eprintln!("[warn] [pyworker] '{}' killed: {why}", self.id);
        }
    }

    fn exchange(
        &self,
        connection: ConnectionId,
        dir: Direction,
        chunk: &[u8],
    ) -> Result<Verdict, String> {
        let mut slot = self
            .child
            .lock()
            .map_err(|_| "worker lock poisoned".to_string())?;
        if slot.is_none() {
            *slot = Some(self.spawn()?);
        }

        let deadline_at = Instant::now() + self.deadline;
        let result = (|| -> Result<Verdict, String> {
            let child = slot.as_mut().expect("just spawned");
            let stdin = child.stdin.as_mut().ok_or("worker has no stdin")?;
            let frame = build_frame(
                connection,
                match dir {
                    Direction::ClientToServer => KIND_C2S,
                    Direction::ServerToClient => KIND_S2C,
                },
                chunk,
            );

            let queued = std::mem::take(
                &mut *self.pending.lock().map_err(|_| "worker queue poisoned".to_string())?,
            );
            if !queued.is_empty() {
                write_before(stdin, &queued, deadline_at)?;
            }
            write_before(stdin, &frame, deadline_at)?;
            let stdout = child.stdout.as_mut().ok_or("worker has no stdout")?;
            let mut header = [0u8; 4];
            read_before(stdout, &mut header, deadline_at)?;
            let len = u32::from_be_bytes(header);
            if len == 0 || len > MAX_FRAME {
                return Err(format!("worker sent a {len} byte frame"));
            }
            let mut body = vec![0u8; len as usize];
            read_before(stdout, &mut body, deadline_at)?;
            // `[verdict][name len][name][payload]`. The name is whichever function
            // decided; it is what lets a block be counted against one function of the
            // file instead of the whole file.
            if body.len() < 2 {
                return Err("worker sent a truncated verdict".to_string());
            }
            let name_len = body[1] as usize;
            if body.len() < 2 + name_len {
                return Err("worker sent a verdict whose name runs past the frame".to_string());
            }
            let name = String::from_utf8_lossy(&body[2..2 + name_len]).into_owned();
            match body[0] {
                VERDICT_ACCEPT => Ok(Verdict::Accept),
                VERDICT_REJECT => Ok(Verdict::Reject(Some(if name.is_empty() {
                    self.id.clone()
                } else {
                    // `<rule>/<function>`, the one token both network layers report, so
                    // the backend has a single way to attribute a block.
                    format!("{}/{}", self.id, name)
                }))),
                other => Err(format!("worker sent verdict {other}")),
            }
        })();

        if let Err(ref why) = result {
            // Anything that goes wrong here — a deadline, a crash, a protocol
            // violation — costs the worker its life, not the traffic.
            self.discard(&mut slot, why);
        }
        result
    }
}

impl Filter for PyWorkerRule {
    fn name(&self) -> &str {
        &self.id
    }
    fn connection_opened(&self, connection: ConnectionId, meta: &ConnectionMeta) {
        // Best effort and unanswered, like the close frame: the metadata is a
        // convenience for the filter, and a worker that has died will be respawned by
        // the first chunk anyway — which then arrives without endpoints rather than not
        // at all. Losing the traffic over it would be the wrong trade.
        let payload = serde_json::json!({
            "client_ip": meta.client.ip().to_string(),
            "client_port": meta.client.port(),
            "server_ip": meta.server.ip().to_string(),
            "server_port": meta.server.port(),
            "is_ipv6": meta.server.is_ipv6(),
            // Both, and they are not the same question. `is_tcp` is what the NFQUEUE
            // side has always sent and what a filter reads to know the wire; `l4` is what
            // decides whether a stream can be built, which is true of QUIC and not of a
            // datagram. A library that only received the first would have to guess one
            // of them.
            "is_tcp": meta.l4 == L4::Tcp,
            "l4": meta.l4.name(),
        })
        .to_string();
        self.queue(build_frame(connection, KIND_OPEN, payload.as_bytes()));
    }
    fn connection_closed(&self, connection: ConnectionId) {
        // Best effort, and deliberately not on the datapath's critical path: the
        // connection is already over, so nothing is waiting on this. A worker that
        // has died in the meantime simply has no state left to free.
        self.queue(build_frame(connection, KIND_CLOSE, &[]));
    }
    fn prepare(&self) -> Result<(), String> {
        self.warm_up()
    }
    fn inspect(&self, ctx: &FilterCtx<'_>) -> Verdict {
        match self.exchange(ctx.connection, ctx.direction, ctx.chunk) {
            Ok(verdict) => verdict,
            Err(_) => {
                // The rule loses its say for this chunk; the chunk goes through.
                self.stats.failed_open.fetch_add(1, Ordering::Relaxed);
                Verdict::Accept
            }
        }
    }
}

/// Wait until the fd is ready, or the deadline passes.
fn wait_ready(fd: i32, writable: bool, deadline_at: Instant) -> Result<(), String> {
    let remaining = deadline_at.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("worker missed its deadline".to_string());
    }
    let mut pfd = libc::pollfd {
        fd,
        events: if writable {
            libc::POLLOUT
        } else {
            libc::POLLIN
        },
        revents: 0,
    };
    let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as libc::c_int;
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    match rc {
        0 => Err("worker missed its deadline".to_string()),
        n if n < 0 => Err(format!("poll failed: {}", std::io::Error::last_os_error())),
        _ => {
            if pfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err("worker pipe broke".to_string());
            }
            Ok(())
        }
    }
}

/// Write it all, giving up when the deadline passes rather than blocking forever on
/// a worker that has stopped reading.
fn write_before<W: Write + AsRawFd>(
    out: &mut W,
    mut buf: &[u8],
    deadline_at: Instant,
) -> Result<(), String> {
    while !buf.is_empty() {
        wait_ready(out.as_raw_fd(), true, deadline_at)?;
        match out.write(buf) {
            Ok(0) => return Err("worker closed its input".to_string()),
            Ok(n) => buf = &buf[n..],
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("cannot write to the worker: {e}")),
        }
    }
    out.flush()
        .map_err(|e| format!("cannot flush to the worker: {e}"))
}

fn read_before<R: Read + AsRawFd>(
    input: &mut R,
    buf: &mut [u8],
    deadline_at: Instant,
) -> Result<(), String> {
    let mut filled = 0;
    while filled < buf.len() {
        wait_ready(input.as_raw_fd(), false, deadline_at)?;
        match input.read(&mut buf[filled..]) {
            Ok(0) => return Err("worker exited".to_string()),
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("cannot read from the worker: {e}")),
        }
    }
    Ok(())
}

impl Drop for PyWorkerRule {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.child.lock() {
            if let Some(mut child) = slot.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}
