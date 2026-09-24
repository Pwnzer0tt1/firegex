//! User Python, and the promise that moving it out of process was worth it.
//!
//! The engine's own deadline can only walk away from a blocking thread; the thread
//! keeps its pool slot until the process restarts, which `fail_open.rs` asserts and
//! the README calls out. A child process is different: it can be killed. These tests
//! are the difference being real rather than claimed.
//!
//! Every filter here is written against the real `firegex.pyfilters` API — parameters
//! annotated with a model, verdicts from the library — because that is the only API
//! there is. These tests used to use a look-alike that took `(data, direction)`, which
//! meant they passed against something no user could have written from the docs.

use std::io::Write;
use std::time::{Duration, Instant};

use fgex_proxy::filter::{
    next_connection_id, ChainSessions, ConnectionMeta, Direction, FilterChain, Verdict, L4,
};
use fgex_proxy::rules::parse_ruleset;

/// Write a filter file and give back its path, kept for the process's lifetime.
fn filter_file(name: &str, body: &str) -> String {
    let path = std::env::temp_dir().join(format!("fgex-pyworker-{name}.py"));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    path.to_string_lossy().into_owned()
}

/// The worker the backend ships, found relative to this crate.
fn worker() -> String {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../modules/services/pyworker.py")
        .to_string_lossy()
        .into_owned()
}

fn chain_for(path: &str, timeout_ms: u64) -> FilterChain {
    chain_with_timeout(path, None, timeout_ms)
}

/// A chain over one python file, saying which of its functions are switched on.
///
/// `None` leaves the field out entirely, which means every function the file defines;
/// `Some(&[])` switches all of them off. The two are deliberately different answers.
fn chain_with(path: &str, enabled: Option<&[&str]>) -> FilterChain {
    chain_with_timeout(path, Some(enabled), 2000)
}

fn chain_with_timeout(
    path: &str,
    enabled: Option<Option<&[&str]>>,
    timeout_ms: u64,
) -> FilterChain {
    let selection = match enabled {
        None | Some(None) => String::new(),
        Some(Some(names)) => format!(
            r#""enabled":[{}],"#,
            names
                .iter()
                .map(|n| format!("\"{n}\""))
                .collect::<Vec<_>>()
                .join(",")
        ),
    };
    let json = format!(
        r#"[{{"kind":"python","id":"py1","code_path":"{path}","timeout_ms":{timeout_ms},
             {selection}"command":["python3","{}"]}}]"#,
        worker()
    );
    FilterChain::new(
        parse_ruleset(&json).unwrap(),
        // Well past the worker's own, so the worker's deadline is what fires and the
        // chain is not the thing masking it.
        Duration::from_millis(timeout_ms * 4 + 2000),
    )
}

async fn feed(c: &FilterChain, chunks: &[&[u8]]) -> Vec<Verdict> {
    feed_from(c, chunks, None).await
}

/// Feed chunks, optionally telling the chain who is talking to whom first.
async fn feed_from(
    c: &FilterChain,
    chunks: &[&[u8]],
    meta: Option<ConnectionMeta>,
) -> Vec<Verdict> {
    let connection = next_connection_id();
    if let Some(meta) = meta {
        c.connection_opened(connection, &meta);
    }
    let mut sessions = ChainSessions::new(connection);
    let mut out = Vec::new();
    for chunk in chunks {
        out.push(c.run(Direction::ClientToServer, chunk, &mut sessions).await);
    }
    out
}

#[tokio::test]
async fn a_python_filter_blocks_and_passes() {
    let path = filter_file(
        "block",
        r#"
from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket

@pyfilter
def block_traversal(packet: RawPacket):
    return REJECT if b"../" in packet.data else ACCEPT
"#,
    );
    let c = chain_for(&path, 1000);

    assert_eq!(feed(&c, &[b"GET /index"]).await, vec![Verdict::Accept]);
    assert_eq!(
        feed(&c, &[b"GET /../../etc/passwd"]).await,
        vec![Verdict::Reject(Some("py1/block_traversal".to_string()))]
    );
}

/// The headline. A filter that never returns is killed, the chunk it was holding
/// goes through, and the next chunk gets a fresh worker rather than a dead engine.
#[tokio::test]
async fn a_hanging_python_filter_is_killed_and_traffic_continues() {
    let path = filter_file(
        "hang",
        r#"
import time
from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import RawPacket

# Module level, so it is per connection: the library gives each stream its own globals.
seen = 0

@pyfilter
def sometimes_hangs(packet: RawPacket):
    global seen
    seen += 1
    if seen == 1:
        time.sleep(3600)
    return ACCEPT
"#,
    );
    let c = chain_for(&path, 300);

    let started = Instant::now();
    assert_eq!(feed(&c, &[b"first"]).await, vec![Verdict::Accept]);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the chunk waited on the worker instead of failing open (took {:?})",
        started.elapsed()
    );

    // A fresh worker takes over, so filtering resumes instead of being lost for good.
    assert_eq!(feed(&c, &[b"second"]).await, vec![Verdict::Accept]);
    assert_eq!(feed(&c, &[b"third"]).await, vec![Verdict::Accept]);
    // The chain never had to disable anything: the worker absorbed the failure.
    assert!(!c.is_bypassed());
    assert!(c.disabled_filters().is_empty());
}

/// Telling the worker about a connection is not allowed to wait on it.
///
/// The open and close frames are sent from the relay itself, on the async runtime. They
/// used to take the worker's lock there — held by whatever exchange was in progress, up
/// to its whole deadline — so one connection feeding a hanging filter held every new
/// connection of the service on the threads that carry all the others.
#[tokio::test]
async fn a_connection_opening_does_not_wait_on_a_hanging_filter() {
    let path = filter_file(
        "hang-open",
        r#"
import time
from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import RawPacket

@pyfilter
def hangs_on_request(packet: RawPacket):
    if b"HANG" in packet.data:
        time.sleep(3600)
    return ACCEPT
"#,
    );
    let c = std::sync::Arc::new(chain_for(&path, 1500));
    // Started first, so the worker is up and the only thing held is the exchange.
    assert_eq!(feed(&c, &[b"warm"]).await, vec![Verdict::Accept]);

    let stuck = {
        let c = std::sync::Arc::clone(&c);
        tokio::spawn(async move { feed(&c, &[b"HANG"]).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;

    let meta = ConnectionMeta {
        client: "10.0.0.9:51000".parse().unwrap(),
        server: "10.0.0.1:8080".parse().unwrap(),
        l4: L4::Tcp,
    };
    let started = Instant::now();
    let other = next_connection_id();
    c.connection_opened(other, &meta);
    c.connection_closed(other);
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "a new connection waited {:?} on another connection's hanging filter",
        started.elapsed()
    );

    assert_eq!(stuck.await.unwrap(), vec![Verdict::Accept]);
}

/// A filter that crashes on one chunk must not cost the ones after it.
#[tokio::test]
async fn a_crashing_python_filter_recovers() {
    let path = filter_file(
        "crash",
        r#"
import os
from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket

@pyfilter
def dies_once(packet: RawPacket):
    if b"boom" in packet.data:
        os._exit(1)
    return REJECT if b"deny" in packet.data else ACCEPT
"#,
    );
    let c = chain_for(&path, 500);

    assert_eq!(feed(&c, &[b"hello"]).await, vec![Verdict::Accept]);
    // The worker dies mid-answer: the chunk is forwarded rather than held.
    assert_eq!(feed(&c, &[b"boom"]).await, vec![Verdict::Accept]);
    // And the replacement is enforcing again.
    assert_eq!(
        feed(&c, &[b"deny me"]).await,
        vec![Verdict::Reject(Some("py1/dies_once".to_string()))]
    );
}

/// A filter file that does not even import must not take the traffic with it.
#[tokio::test]
async fn a_worker_that_cannot_start_fails_open() {
    let path = filter_file("broken", "this is not python at all(((\n");
    let c = chain_for(&path, 500);
    assert_eq!(feed(&c, &[b"still moving"]).await, vec![Verdict::Accept]);
}

/// A filter that raises costs the chunk its filtering, and nothing else.
///
/// The library runs the chain in one pass and does not isolate a filter that raises:
/// the exception aborts the whole chain for that packet, which is also what happens on
/// NFQUEUE. So the honest promise is not "the other filters still get a say", it is
/// "the traffic keeps moving and the next chunk is filtered again". Asserting the
/// former would be asserting a behaviour no transport actually has.
#[tokio::test]
async fn a_raising_filter_fails_open_and_the_worker_survives() {
    let path = filter_file(
        "raises",
        r#"
from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket

@pyfilter
def sometimes_raises(packet: RawPacket):
    if b"boom" in packet.data:
        raise ValueError("boom")
    return REJECT if b"deny" in packet.data else ACCEPT
"#,
    );
    let c = chain_for(&path, 1000);

    assert_eq!(feed(&c, &[b"fine"]).await, vec![Verdict::Accept]);
    // The chunk that made it raise goes through rather than being held.
    assert_eq!(feed(&c, &[b"boom"]).await, vec![Verdict::Accept]);
    // And the worker is still there, still enforcing.
    assert_eq!(
        feed(&c, &[b"deny me"]).await,
        vec![Verdict::Reject(Some("py1/sometimes_raises".to_string()))]
    );
    assert!(!c.is_bypassed());
    assert!(c.disabled_filters().is_empty());
}

/// A filter that prints must not break the protocol.
///
/// `print()` is the first thing anybody reaches for while debugging a filter, and the
/// worker shares its process with the user's code. On stdout that text lands inside a
/// length-prefixed frame: the engine reads it as a frame header, sees an absurd length
/// and kills the worker — so the filter is restarted on every packet, filters nothing,
/// and says nothing about why. The worker sends the user's output to stderr instead.
#[tokio::test]
async fn a_filter_that_prints_keeps_working() {
    let path = filter_file(
        "chatty",
        r#"
from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket

@pyfilter
def noisy(packet: RawPacket):
    print("saw", len(packet.data), "bytes")
    return REJECT if b"deny" in packet.data else ACCEPT
"#,
    );
    let c = chain_for(&path, 1000);

    assert_eq!(feed(&c, &[b"hello"]).await, vec![Verdict::Accept]);
    // Still enforcing after having printed, which it would not be if the output had
    // gone down the protocol channel and cost the worker its life.
    assert_eq!(
        feed(&c, &[b"deny me"]).await,
        vec![Verdict::Reject(Some("py1/noisy".to_string()))]
    );
    assert_eq!(feed(&c, &[b"and again"]).await, vec![Verdict::Accept]);
    assert_eq!(
        feed(&c, &[b"deny me too"]).await,
        vec![Verdict::Reject(Some("py1/noisy".to_string()))]
    );
}

/// The documented promise: each stream gets its own module globals.
///
/// This is why every frame carries a connection id. Sharing one set of globals across
/// connections would let one client's history decide another client's verdict — a
/// false positive that only shows up under concurrent traffic, and a way to smuggle a
/// pattern past a stateful filter by splitting it over two connections.
#[tokio::test]
async fn each_connection_gets_its_own_globals() {
    let path = filter_file(
        "percall",
        r#"
from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket

seen = 0

@pyfilter
def second_chunk_is_refused(packet: RawPacket):
    global seen
    seen += 1
    return REJECT if seen > 1 else ACCEPT
"#,
    );
    let c = chain_for(&path, 1000);

    let first = next_connection_id();
    let mut a = ChainSessions::new(first);
    assert_eq!(
        c.run(Direction::ClientToServer, b"one", &mut a).await,
        Verdict::Accept
    );
    assert_eq!(
        c.run(Direction::ClientToServer, b"two", &mut a).await,
        Verdict::Reject(Some("py1/second_chunk_is_refused".to_string())),
        "the counter did not survive between chunks of one connection"
    );

    // A different connection starts from zero, whatever the first one did.
    let mut b = ChainSessions::new(next_connection_id());
    assert_eq!(
        c.run(Direction::ClientToServer, b"one", &mut b).await,
        Verdict::Accept,
        "one connection's globals leaked into another's"
    );

    // Closing releases them, so a long-lived service does not accumulate one set of
    // globals per connection it has ever carried.
    c.connection_closed(first);
    let mut again = ChainSessions::new(first);
    assert_eq!(
        c.run(Direction::ClientToServer, b"one", &mut again).await,
        Verdict::Accept,
        "the closed connection's globals were still there"
    );
}

/// Python and regex rules coexist: the compiled ones run inline, the worker does not.
#[tokio::test]
async fn python_and_regex_rules_run_together() {
    let path = filter_file(
        "coexist",
        r#"
from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket

@pyfilter
def block_py(packet: RawPacket):
    return REJECT if b"by-python" in packet.data else ACCEPT
"#,
    );
    let json = format!(
        r#"[{{"kind":"regex","id":"re1","pattern":"by-regex"}},
            {{"kind":"python","id":"py1","code_path":"{path}","timeout_ms":1000,
              "command":["python3","{}"]}}]"#,
        worker()
    );
    let c = FilterChain::new(parse_ruleset(&json).unwrap(), Duration::from_secs(5));

    assert_eq!(feed(&c, &[b"harmless"]).await, vec![Verdict::Accept]);
    assert_eq!(
        feed(&c, &[b"blocked by-regex here"]).await,
        vec![Verdict::Reject(Some("re1".to_string()))]
    );
    assert_eq!(
        feed(&c, &[b"blocked by-python here"]).await,
        vec![Verdict::Reject(Some("py1/block_py".to_string()))]
    );
}

/// A filter reads the addresses, and cannot read anything below the application layer.
///
/// This is the boundary the whole model rests on: metadata in, payload out. It also has
/// to be *real* metadata — the proxy terminated the connection, so the headers on the
/// wire are the engine's own, and an earlier version handed the filter a literal
/// `FAKE:IP:TCP:HEADERS:` prefix instead. A filter written against that did one thing
/// here and a different thing on NFQUEUE.
#[tokio::test]
async fn a_filter_is_told_who_is_talking_to_whom() {
    let path = filter_file(
        "endpoints",
        r#"
from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket

@pyfilter
def only_from_that_client(packet: RawPacket):
    if packet.client_ip != "10.0.0.9" or packet.client_port != 51000:
        return REJECT
    if packet.server_ip != "10.0.0.1" or packet.server_port != 8080:
        return REJECT
    # There is nothing below the application layer to read, and asking for it fails
    # rather than answering with something invented.
    if hasattr(packet, "raw_packet"):
        return REJECT
    return ACCEPT
"#,
    );
    let c = chain_for(&path, 2000);
    let meta = ConnectionMeta {
        client: "10.0.0.9:51000".parse().unwrap(),
        server: "10.0.0.1:8080".parse().unwrap(),
        l4: L4::Tcp,
    };
    assert_eq!(
        feed_from(&c, &[b"hello"], Some(meta)).await,
        vec![Verdict::Accept],
        "the filter did not see the addresses it was told about"
    );
}

/// The protocol a filter file speaks is read off the file, not passed to it.
///
/// Nothing in the ruleset says `http`, and the worker is started with the path alone.
/// The file is an HTTP filter because it asks for an `HttpRequest`, and a `RawPacket`
/// filter sits beside it in the same file because `http` provides both.
#[tokio::test]
async fn the_protocol_is_read_off_the_code() {
    let path = filter_file(
        "detected",
        r#"
from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import HttpRequest, RawPacket

@pyfilter
def refuse_traversal(request: HttpRequest):
    return REJECT if "../" in (request.url or "") else ACCEPT

@pyfilter
def look_at_the_bytes(packet: RawPacket):
    return ACCEPT
"#,
    );
    let c = chain_for(&path, 2000);
    assert_eq!(
        feed(&c, &[b"GET /shop HTTP/1.1\r\nHost: x\r\n\r\n"]).await,
        vec![Verdict::Accept]
    );
    assert_eq!(
        feed(&c, &[b"GET /../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"]).await,
        vec![Verdict::Reject(Some("py1/refuse_traversal".to_string()))]
    );
}

/// A file holds several functions, and each one can be switched off on its own.
///
/// The code is untouched: only the list of names the library is given changes, and that
/// list is what decides whether a function is ever called. Deleting the code to stop
/// consulting a filter, and pasting it back to resume, is what this replaces.
#[tokio::test]
async fn one_function_of_a_file_can_be_switched_off() {
    let path = filter_file(
        "selectable",
        r#"
from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket

@pyfilter
def refuse_a(packet: RawPacket):
    return REJECT if b"AAA" in packet.data else ACCEPT

@pyfilter
def refuse_b(packet: RawPacket):
    return REJECT if b"BBB" in packet.data else ACCEPT
"#,
    );

    // Nothing said: every function the file defines runs.
    let all = chain_with(&path, None);
    assert_eq!(
        feed(&all, &[b"carrying AAA"]).await,
        vec![Verdict::Reject(Some("py1/refuse_a".to_string()))],
        "a block has to name the function that made it, not just the file"
    );
    assert_eq!(
        feed(&all, &[b"carrying BBB"]).await,
        vec![Verdict::Reject(Some("py1/refuse_b".to_string()))]
    );

    // One of the two: the other is still in the file, and no longer consulted.
    let only_a = chain_with(&path, Some(&["refuse_a"]));
    assert_eq!(
        feed(&only_a, &[b"carrying AAA"]).await,
        vec![Verdict::Reject(Some("py1/refuse_a".to_string()))]
    );
    assert_eq!(
        feed(&only_a, &[b"carrying BBB"]).await,
        vec![Verdict::Accept],
        "a switched-off function must not decide anything"
    );

    // An empty list is not the same as saying nothing: the operator switched every one
    // of them off, and the file inspects nothing until one is switched back on.
    let none: [&str; 0] = [];
    let off = chain_with(&path, Some(&none));
    assert_eq!(feed(&off, &[b"carrying AAA"]).await, vec![Verdict::Accept]);
    assert_eq!(feed(&off, &[b"carrying BBB"]).await, vec![Verdict::Accept]);
}
