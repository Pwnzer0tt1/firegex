//! The claims the proxy engine has to earn before it deserves to exist.
//!
//! Every test drives real sockets: an echo server standing in for the protected
//! service, the proxy in front of it, and a client that must keep working no matter
//! what the filters do.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fgex_proxy::filter::{ChainHandle, Filter, FilterChain, FilterCtx, Verdict};
use fgex_proxy::proxy::{Proxy, ProxyConfig};
use fgex_proxy::spec::parse_filters;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Echo server: whatever it receives, it sends straight back.
async fn spawn_echo() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn spawn_proxy(filters: &str, deadline_ms: u64) -> (std::net::SocketAddr, ChainHandle) {
    spawn_proxy_with(FilterChain::new(
        parse_filters(filters).unwrap(),
        Duration::from_millis(deadline_ms),
    ))
    .await
}

async fn spawn_proxy_with(chain: FilterChain) -> (std::net::SocketAddr, ChainHandle) {
    let upstream = spawn_echo().await;
    let chain = ChainHandle::new(chain);
    let proxy = Proxy::bind(
        ProxyConfig::fixed("127.0.0.1:0".parse().unwrap(), upstream),
        chain.clone(),
    )
    .await
    .unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());
    (addr, chain)
}

/// Send one payload, read one reply.
async fn roundtrip(addr: std::net::SocketAddr, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut sock = TcpStream::connect(addr).await?;
    sock.write_all(payload).await?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await??;
    buf.truncate(n);
    Ok(buf)
}

#[tokio::test]
async fn relays_traffic_with_no_filters() {
    let (addr, _chain) = spawn_proxy("", 200).await;
    let got = roundtrip(addr, b"hello firegex").await.unwrap();
    assert_eq!(got, b"hello firegex");
}

/// The headline guarantee: user code that panics costs its own say, not the traffic.
#[tokio::test]
async fn panicking_filter_keeps_traffic_flowing() {
    let (addr, chain) = spawn_proxy("panic", 200).await;

    let got = roundtrip(addr, b"payload one").await.unwrap();
    assert_eq!(
        got, b"payload one",
        "a panicking filter must not eat the data"
    );

    // And the next connection is served too: the failure is contained, not fatal.
    let got = roundtrip(addr, b"payload two").await.unwrap();
    assert_eq!(got, b"payload two");

    let live = chain.current();
    assert!(live.stats.panics.load(Ordering::Relaxed) >= 1);
    assert_eq!(live.disabled_filters(), vec!["panic"]);
    assert!(
        live.is_bypassed(),
        "with its only filter disabled the chain should degrade to a plain relay"
    );
}

/// The failure `catch_unwind` cannot catch: a filter that simply never returns.
///
/// One test rather than three because releasing the stuck threads at the end is
/// process-wide, and the harness runs tests in parallel within one process.
#[tokio::test]
async fn hanging_filter_fails_open_then_loses_its_say() {
    let rearm = Duration::from_millis(1500);
    let (addr, chain) = spawn_proxy_with(
        FilterChain::new(parse_filters("hang").unwrap(), Duration::from_millis(50))
            .rearming_after(rearm),
    )
    .await;

    // The deadline, not the filter, decides when the chunk moves.
    let started = Instant::now();
    let got = roundtrip(addr, b"still moving").await.unwrap();
    assert_eq!(got, b"still moving");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the chunk waited on the filter instead of failing open (took {:?})",
        started.elapsed()
    );
    assert!(chain.current().stats.timeouts.load(Ordering::Relaxed) >= 1);

    // A single slow call could be load, so it takes a few in a row to lose it.
    for _ in 0..4 {
        assert_eq!(roundtrip(addr, b"tick").await.unwrap(), b"tick");
    }
    let live = chain.current();
    assert_eq!(live.disabled_filters(), vec!["hang"]);
    assert!(live.is_bypassed());

    // Each timeout abandons a blocking thread that cannot be cancelled, so the
    // damage has to be bounded: once disabled, the filter is never called again
    // and the leak stops growing however much traffic follows.
    let leaked = live.stats.timeouts.load(Ordering::Relaxed);
    for _ in 0..10 {
        assert_eq!(roundtrip(addr, b"more").await.unwrap(), b"more");
    }
    assert_eq!(
        live.stats.timeouts.load(Ordering::Relaxed),
        leaked,
        "a disabled filter is still being called, so the thread leak is unbounded"
    );

    // Slow is not broken: after a pause it is asked again, rather than staying out until
    // somebody next edits a rule. It used to stay out for the life of the chain — which
    // for a Python filter meant a flood, the one moment it was wanted, switched it off.
    tokio::time::sleep(rearm + Duration::from_millis(300)).await;
    let answered = roundtrip(addr, b"again").await.unwrap();
    let asked = live.stats.timeouts.load(Ordering::Relaxed) - leaked;
    let back_in = live.disabled_filters().is_empty();
    let bypassed = live.is_bypassed();

    // Let the abandoned threads exit, otherwise dropping the runtime waits on them — and
    // before asserting, so a failure below fails the test rather than hanging it.
    fgex_proxy::spec::release_hangs();

    assert_eq!(answered, b"again");
    // Once per direction: the echo comes back through the chain as well.
    assert_eq!(asked, 2, "the filter was not asked again after its pause");
    assert!(back_in, "two misses after the pause took it out again");
    assert!(!bypassed);
}

/// Failing open is only worth anything if the filters do something when healthy.
#[tokio::test]
async fn healthy_filter_still_blocks() {
    let (addr, _chain) = spawn_proxy("block:FLAG{", 200).await;

    let got = roundtrip(addr, b"harmless request").await.unwrap();
    assert_eq!(got, b"harmless request");

    // Rejected: the proxy closes cleanly, so the client reads EOF rather than
    // hanging on a silently dropped packet.
    let got = roundtrip(addr, b"give me FLAG{...}").await.unwrap();
    assert!(got.is_empty(), "blocked payload came through: {got:?}");
}

/// A rule refuses a connection, not a direction: a service that answers without
/// waiting for the request must not still reach a client whose request was blocked.
#[tokio::test]
async fn a_reject_closes_the_whole_connection() {
    // A server that greets on connect, before it has read anything.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(80)).await;
                let _ = sock.write_all(b"UNSOLICITED").await;
            });
        }
    });

    let chain = ChainHandle::new(FilterChain::new(
        parse_filters("block:FLAG{").unwrap(),
        Duration::from_millis(200),
    ));
    let proxy = Proxy::bind(
        ProxyConfig::fixed("127.0.0.1:0".parse().unwrap(), upstream),
        chain,
    )
    .await
    .unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());

    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"give me FLAG{x}").await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(3), sock.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        n,
        0,
        "the server's greeting reached a client whose request was blocked: {:?}",
        &buf[..n]
    );
}



/// A broken filter must not take its healthy neighbours down with it.
#[tokio::test]
async fn one_broken_filter_does_not_disable_the_others() {
    let (addr, chain) = spawn_proxy("panic,block:FLAG{", 200).await;

    // Trip the panicking filter.
    let got = roundtrip(addr, b"warmup").await.unwrap();
    assert_eq!(got, b"warmup");

    let live = chain.current();
    assert_eq!(live.disabled_filters(), vec!["panic"]);
    assert!(
        !live.is_bypassed(),
        "the surviving filter should keep the chain active"
    );

    // The healthy one is still enforcing.
    let got = roundtrip(addr, b"take the FLAG{x}").await.unwrap();
    assert!(got.is_empty(), "the surviving filter stopped enforcing");
}

/// Reconfiguration must not cost established connections — the NFQUEUE engine
/// reloads its rules in place, and this one may not be worse.
#[tokio::test]
async fn chain_swap_applies_to_live_connections() {
    let (addr, chain) = spawn_proxy("", 200).await;

    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"before").await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = sock.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"before");

    // Swap in a rewriting chain while the connection is open.
    chain.replace(FilterChain::new(
        parse_filters("block:after").unwrap(),
        Duration::from_millis(200),
    ));

    sock.write_all(b"after").await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        n,
        0,
        "the swapped-in chain did not close the connection"
    );
}

/// A filter that panics only sometimes still loses its say on the first panic,
/// and the chunk that tripped it is forwarded rather than dropped.
struct FlakyFilter {
    seen: std::sync::atomic::AtomicU64,
}

impl Filter for FlakyFilter {
    fn name(&self) -> &str {
        "flaky"
    }
    fn inspect(&self, _ctx: &FilterCtx<'_>) -> Verdict {
        if self.seen.fetch_add(1, Ordering::Relaxed) == 1 {
            panic!("second call blows up");
        }
        Verdict::Accept
    }
}

#[tokio::test]
async fn chunk_that_trips_a_panic_is_still_delivered() {
    let upstream = spawn_echo().await;
    let chain = ChainHandle::new(FilterChain::new(
        vec![Arc::new(FlakyFilter {
            seen: std::sync::atomic::AtomicU64::new(0),
        })],
        Duration::from_millis(200),
    ));
    let proxy = Proxy::bind(
        ProxyConfig::fixed("127.0.0.1:0".parse().unwrap(), upstream),
        chain.clone(),
    )
    .await
    .unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());

    let mut sock = TcpStream::connect(addr).await.unwrap();
    let mut buf = vec![0u8; 1024];

    for expected in [&b"first"[..], &b"second"[..], &b"third"[..]] {
        sock.write_all(expected).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], expected, "a chunk was lost around the panic");
    }
    assert_eq!(chain.current().disabled_filters(), vec!["flaky"]);
}
