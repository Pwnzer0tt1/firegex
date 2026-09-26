//! The datagram relay: what the connection limit means for it, and what it counts.
//!
//! Everything here dials the service plainly (`spoof_source` off), because a test has no
//! policy route to bring a transparent reply home. What is being asked is independent of
//! it: whether a flow past the limit hears back, whether flows spend the same budget TCP
//! connections do, and whether the counters the backend divides are in the same unit.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use fgex_proxy::filter::{ChainHandle, FilterChain};
use fgex_proxy::proxy::ProxyStats;
use fgex_proxy::spec::parse_filters;
use fgex_proxy::udp::UdpRelay;
use tokio::net::UdpSocket;

/// A UDP service answering every datagram with the same bytes.
async fn spawn_echo() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                continue;
            };
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

async fn spawn_relay(
    upstream: std::net::SocketAddr,
    filters: &str,
    limit: usize,
    over_limit_forwards: bool,
    stats: Arc<ProxyStats>,
) -> std::net::SocketAddr {
    let chain = ChainHandle::new(FilterChain::new(
        parse_filters(filters).unwrap(),
        Duration::from_millis(500),
    ));
    let relay = UdpRelay::bind(
        "127.0.0.1:0".parse().unwrap(),
        upstream,
        chain,
        None,
        false,
        limit,
        over_limit_forwards,
        stats,
    )
    .await
    .unwrap();
    let addr = relay.local_addr().unwrap();
    tokio::spawn(relay.serve());
    addr
}

/// Send one datagram from a fresh source and wait a moment for an answer.
async fn ask(relay: std::net::SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(payload, relay).await.unwrap();
    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_millis(700), client.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// "Forward what does not fit" has to mean the client is answered.
///
/// A flow past the limit used to be one datagram sent from a socket closed straight after,
/// so the request reached the service and its answer went to a port nobody held any more:
/// forwarded, and useless to every request/response protocol UDP carries.
#[tokio::test]
async fn a_flow_past_the_limit_is_answered_when_forwarding() {
    let upstream = spawn_echo().await;
    let stats = Arc::new(ProxyStats::default());
    let relay = spawn_relay(upstream, "", 1, true, Arc::clone(&stats)).await;

    // The first source takes the one place and keeps it: flows are kept until idle.
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    first.send_to(b"first", relay).await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), first.recv(&mut buf))
        .await
        .expect("the first flow was not answered")
        .unwrap();
    assert_eq!(&buf[..n], b"first");

    assert_eq!(ask(relay, b"second").await.as_deref(), Some(&b"second"[..]));
    assert_eq!(stats.over_limit.load(Ordering::Relaxed), 1);
}

/// Without forwarding, what does not fit is dropped, and the limit says so.
#[tokio::test]
async fn a_flow_past_the_limit_is_dropped_otherwise() {
    let upstream = spawn_echo().await;
    let stats = Arc::new(ProxyStats::default());
    let relay = spawn_relay(upstream, "", 1, false, Arc::clone(&stats)).await;

    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    first.send_to(b"first", relay).await.unwrap();
    let mut buf = vec![0u8; 64];
    tokio::time::timeout(Duration::from_secs(2), first.recv(&mut buf))
        .await
        .expect("the first flow was not answered")
        .unwrap();

    assert_eq!(ask(relay, b"second").await, None);
    assert_eq!(stats.over_limit.load(Ordering::Relaxed), 1);
}

/// One budget for TCP connections and UDP flows, because they spend the same descriptors.
///
/// Each relay used to count only its own flows, so a service with several UDP addresses
/// could hold several times its limit beside a full complement of TCP connections.
#[tokio::test]
async fn flows_spend_the_same_budget_as_connections() {
    let upstream = spawn_echo().await;
    let stats = Arc::new(ProxyStats::default());
    // As if the TCP side of the service were already carrying one connection.
    stats.live.store(1, Ordering::Relaxed);
    let relay = spawn_relay(upstream, "", 1, false, Arc::clone(&stats)).await;

    assert_eq!(ask(relay, b"no room").await, None, "a flow was admitted past the limit");
    assert_eq!(stats.live.load(Ordering::Relaxed), 1, "a refused flow kept its place");
}

/// A service that goes away for a moment and comes back is answering again, for the
/// client that kept talking through it.
///
/// A datagram sent while it was down is answered with ICMP "port unreachable", which the
/// flow's connected socket reports as an error on its next call. That error ended the task
/// carrying the answers back while the flow stayed in the table — and a client that kept
/// sending kept it from ever going idle, so it never heard from the service again.
#[tokio::test]
async fn a_flow_outlives_its_service_restarting() {
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = first.local_addr().unwrap();
    let echo = |socket: UdpSocket| {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                    continue;
                };
                let _ = socket.send_to(&buf[..n], from).await;
            }
        })
    };
    let service = echo(first);
    let relay = spawn_relay(upstream, "", 0, false, Arc::new(ProxyStats::default())).await;

    // One source throughout: this is about a flow that already exists.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(exchange(&client, relay, b"before").await.as_deref(), Some(&b"before"[..]));

    service.abort();
    let _ = service.await;
    assert_eq!(exchange(&client, relay, b"while down").await, None);

    echo(UdpSocket::bind(upstream).await.unwrap());
    assert_eq!(
        exchange(&client, relay, b"after").await.as_deref(),
        Some(&b"after"[..]),
        "the service came back and the flow that kept talking was not answered"
    );
}

/// One datagram from `client`, and the answer if one comes.
async fn exchange(
    client: &UdpSocket,
    relay: std::net::SocketAddr,
    payload: &[u8],
) -> Option<Vec<u8>> {
    client.send_to(payload, relay).await.unwrap();
    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_millis(700), client.recv(&mut buf)).await {
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// Flows are counted in the unit the backend divides by: flows seen, flows refused.
///
/// UDP counted neither, so a service refusing datagrams all day reported no connections
/// and a refused share of zero.
#[tokio::test]
async fn flows_and_refusals_are_counted_once_each() {
    let upstream = spawn_echo().await;
    let stats = Arc::new(ProxyStats::default());
    let relay = spawn_relay(upstream, "block:DENYME", 0, false, Arc::clone(&stats)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = vec![0u8; 64];
    client.send_to(b"hello", relay).await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("an innocent datagram was not answered")
        .unwrap();
    assert_eq!(&buf[..n], b"hello");
    for _ in 0..3 {
        client.send_to(b"DENYME please", relay).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(stats.accepted.load(Ordering::Relaxed), 1, "one flow, counted once");
    assert_eq!(stats.live.load(Ordering::Relaxed), 1, "the flow holds one place");
    assert_eq!(
        stats.closed_by_filter.load(Ordering::Relaxed),
        1,
        "three refused datagrams of one flow are one refused flow"
    );
}
