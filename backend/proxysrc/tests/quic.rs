//! QUIC terminated by the engine, and the three things that has to get right.
//!
//! A client and a service, both speaking real QUIC, either side of the relay. What is
//! being proved is not that bytes arrive — it is that a rule can see them at all, which
//! on this transport is only true because the connection is terminated: on the wire the
//! stream boundaries and the frames are encrypted along with the payload.
//!
//! The protocol negotiated here is deliberately **not** `h3`. These are the tests for a
//! QUIC service that speaks something of its own, where a stream is a stream of bytes and
//! nothing reads them but the chain; HTTP/3 is carried by a module that understands it,
//! and is tested in `h3.rs`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fgex_proxy::filter::{ChainHandle, FilterChain};
use fgex_proxy::proxy::ProxyStats;
use fgex_proxy::proxy::Onward;
use fgex_proxy::quic::{QuicConfig, QuicRelay, QuicSetup};
use fgex_proxy::spec::parse_filters;
use fgex_proxy::tls;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};

/// Generated per run: no key material belongs in the repository.
fn self_signed() -> (String, String) {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    (cert.cert.pem(), cert.key_pair.serialize_pem())
}

fn alpn(list: &[&str]) -> Vec<Vec<u8>> {
    list.iter().map(|p| p.as_bytes().to_vec()).collect()
}

/// A service that speaks QUIC and echoes every stream, standing in for the real one.
async fn spawn_quic_echo(cert: &str, key: &str, speaks: &[&str]) -> SocketAddr {
    let mut config = (*tls::server_config(cert, key).unwrap()).clone();
    config.alpn_protocols = alpn(speaks);
    let crypto = QuicServerConfig::try_from(config).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                // Datagrams, echoed the same way the streams are: their own task, so a
                // service that is answering one is still accepting the other.
                let datagrams = connection.clone();
                tokio::spawn(async move {
                    while let Ok(datagram) = datagrams.read_datagram().await {
                        if datagrams.send_datagram(datagram).is_err() {
                            return;
                        }
                    }
                });
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        while let Ok(Some(n)) = recv.read(&mut buf).await {
                            if send.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        let _ = send.finish();
                    });
                }
            });
        }
    });
    addr
}

/// The relay, in front of that service.
async fn spawn_relay(upstream: SocketAddr, filters: &str, offers: &[&str]) -> SocketAddr {
    let (cert, key) = self_signed();
    let chain = ChainHandle::new(FilterChain::new(
        parse_filters(filters).unwrap(),
        Duration::from_millis(500),
    ));
    let cfg = QuicConfig {
        setup: Arc::new(QuicSetup::build(&cert, &key, alpn(offers)).unwrap()),
        // No mark and no impersonation: `SO_MARK` and `IP_TRANSPARENT` both need
        // CAP_NET_ADMIN, which a test run has no business requiring. What they change is
        // which address the service sees, and nothing here is asking about that.
        self_mark: None,
        spoof_source: false,
        max_connections: 0,
        over_limit_forwards: false,
        first_byte_timeout: None,
        connect_timeout: Duration::from_secs(5),
        upstream: Onward::Same,
        // Nothing to write a reconstruction to, which is the ordinary case on any host
        // without the capture interface and the case every test here runs in.
        capture: None,
    };
    let relay = QuicRelay::bind(
        "127.0.0.1:0".parse().unwrap(),
        upstream,
        chain,
        cfg,
        Arc::new(ProxyStats::default()),
    )
    .unwrap();
    let addr = relay.local_addr().unwrap();
    tokio::spawn(Arc::new(relay).serve());
    addr
}

/// One message, and every message underneath it.
///
/// quinn nests the reason: a read failing because the connection went away says only
/// "connection lost", and *why* it was lost — the application close, with the reason
/// firegex put in it — is one `source()` further down. A test that looked at the top
/// line alone could not tell a block from a crash.
fn because(error: &dyn std::error::Error) -> String {
    let mut parts = vec![error.to_string()];
    let mut current = error.source();
    while let Some(inner) = current {
        parts.push(inner.to_string());
        current = inner.source();
    }
    parts.join(": ")
}

struct Exchange {
    /// What the client ended up speaking — which is what the *service* chose.
    protocol: Option<String>,
    echoed: Result<Vec<u8>, String>,
}

/// One client, one stream, one answer.
async fn roundtrip(addr: SocketAddr, payload: &[u8], speaks: &[&str]) -> Exchange {
    let mut config = tls::quic_client_config().unwrap();
    config.alpn_protocols = alpn(speaks);
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(config).unwrap(),
    )));

    let connecting = endpoint.connect(addr, "localhost").unwrap();
    let connection = match tokio::time::timeout(Duration::from_secs(5), connecting).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(e)) => {
            return Exchange {
                protocol: None,
                echoed: Err(e.to_string()),
            }
        }
        Err(_) => {
            return Exchange {
                protocol: None,
                echoed: Err("the handshake timed out".to_string()),
            }
        }
    };
    let protocol = connection
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.protocol)
        .map(|p| String::from_utf8_lossy(&p).into_owned());

    let echoed = async {
        let (mut send, mut recv) = connection.open_bi().await.map_err(|e| because(&e))?;
        send.write_all(payload).await.map_err(|e| because(&e))?;
        send.finish().map_err(|e| because(&e))?;
        recv.read_to_end(64 * 1024).await.map_err(|e| because(&e))
    }
    .await;

    Exchange { protocol, echoed }
}

/// The whole point: a stream goes through, and it went through something that decrypted
/// it on the way.
///
/// It also exercises the Retry this relay answers a new client with — every first
/// connection from an address arrives unvalidated, so a malformed token would show up
/// here as a handshake that never completes rather than as a subtle weakness.
#[tokio::test]
async fn carries_a_stream_through() {
    let (cert, key) = self_signed();
    let upstream = spawn_quic_echo(&cert, &key, &["fgex-raw"]).await;
    let addr = spawn_relay(upstream, "", &["fgex-raw"]).await;

    let exchange = roundtrip(addr, b"hello over quic", &["fgex-raw"]).await;
    assert_eq!(exchange.echoed.unwrap(), b"hello over quic");
}

/// The reason terminating it is worth the trouble: a rule matches bytes that on the wire
/// were inside an encrypted packet, with the frame headers encrypted too.
#[tokio::test]
async fn rules_see_the_plaintext_inside_the_streams() {
    let (cert, key) = self_signed();
    let upstream = spawn_quic_echo(&cert, &key, &["fgex-raw"]).await;
    let addr = spawn_relay(upstream, "block:FLAG{", &["fgex-raw"]).await;

    let harmless = roundtrip(addr, b"harmless request", &["fgex-raw"]).await;
    assert_eq!(harmless.echoed.unwrap(), b"harmless request");

    let blocked = roundtrip(addr, b"give me FLAG{secret}", &["fgex-raw"]).await;
    let error = blocked
        .echoed
        .expect_err("a rule let the payload through, or the connection was left open");
    // Closed on purpose, with a reason the client can read — not a stream reset and not
    // a silence to time out on.
    assert!(
        error.contains("blocked by firegex"),
        "the client was not told why: {error}"
    );
}

/// A refusal ends the connection, not just the stream that carried it.
///
/// The alternative — resetting one stream — would leave the client free to ask again on
/// the next one, which is not what a block means anywhere else in firegex.
#[tokio::test]
async fn a_refusal_takes_the_whole_connection() {
    let (cert, key) = self_signed();
    let upstream = spawn_quic_echo(&cert, &key, &["fgex-raw"]).await;
    let addr = spawn_relay(upstream, "block:FLAG{", &["fgex-raw"]).await;

    let mut config = tls::quic_client_config().unwrap();
    config.alpn_protocols = alpn(&["fgex-raw"]);
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(config).unwrap(),
    )));
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    // One stream says something forbidden...
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(b"here is a FLAG{x}").await.unwrap();
    let _ = send.finish();
    let _ = recv.read_to_end(4096).await;

    // ...and a second one, on the same connection, has nowhere to go.
    let opened = tokio::time::timeout(Duration::from_secs(2), connection.open_bi()).await;
    assert!(
        matches!(opened, Ok(Err(_))),
        "the connection outlived the block"
    );
}

/// The service picks the protocol, and the client is told that and nothing else.
///
/// This is the ordering that had to change from the TLS path: there the ClientHello is
/// held open and the service is asked what the *client* offered, which QUIC gives no
/// opportunity to do. So the relay offers its candidates to the service and passes the
/// answer on — and a service speaking something unusual is carried without firegex
/// having to guess.
#[tokio::test]
async fn the_service_chooses_the_protocol() {
    let (cert, key) = self_signed();
    let upstream = spawn_quic_echo(&cert, &key, &["fgex-test"]).await;
    let addr = spawn_relay(upstream, "", &["h3", "fgex-test"]).await;

    let exchange = roundtrip(addr, b"ping", &["h3", "fgex-test"]).await;
    assert_eq!(exchange.protocol.as_deref(), Some("fgex-test"));
    assert_eq!(exchange.echoed.unwrap(), b"ping");
}

/// A client that cannot speak what the service chose is refused by the handshake, which
/// is the honest failure this ordering costs.
#[tokio::test]
async fn a_client_that_speaks_something_else_is_refused() {
    let (cert, key) = self_signed();
    let upstream = spawn_quic_echo(&cert, &key, &["fgex-test"]).await;
    let addr = spawn_relay(upstream, "", &["fgex-test"]).await;

    let exchange = roundtrip(addr, b"ping", &["h3"]).await;
    assert!(
        exchange.echoed.is_err(),
        "a client was told a protocol the service never agreed to"
    );
}

/// One client connection, for the tests that need more of it than `roundtrip` gives.
async fn connect(addr: SocketAddr, speaks: &[&str]) -> quinn::Connection {
    let mut config = tls::quic_client_config().unwrap();
    config.alpn_protocols = alpn(speaks);
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(config).unwrap(),
    )));
    endpoint.connect(addr, "localhost").unwrap().await.unwrap()
}

/// A datagram goes through, and comes back.
#[tokio::test]
async fn datagrams_are_carried_both_ways() {
    let (cert, key) = self_signed();
    let upstream = spawn_quic_echo(&cert, &key, &["fgex-raw"]).await;
    let addr = spawn_relay(upstream, "", &["fgex-raw"]).await;

    let connection = connect(addr, &["fgex-raw"]).await;
    assert!(
        connection.max_datagram_size().is_some(),
        "the extension was not advertised to a client that could have used it"
    );
    connection
        .send_datagram(bytes::Bytes::from_static(b"ping"))
        .unwrap();
    let back = tokio::time::timeout(Duration::from_secs(5), connection.read_datagram())
        .await
        .expect("the datagram never came back")
        .unwrap();
    assert_eq!(&back[..], b"ping");
}

/// A rule refusing a datagram drops that datagram, and nothing else.
///
/// The opposite of what a refusal does to a stream, on purpose: there is no conversation
/// to end, so ending the connection would take a hundred other streams with it over one
/// message that was already complete when it was judged.
#[tokio::test]
async fn a_refused_datagram_is_dropped_and_the_connection_lives() {
    let (cert, key) = self_signed();
    let upstream = spawn_quic_echo(&cert, &key, &["fgex-raw"]).await;
    let addr = spawn_relay(upstream, "block:forbidden", &["fgex-raw"]).await;

    let connection = connect(addr, &["fgex-raw"]).await;
    connection
        .send_datagram(bytes::Bytes::from_static(b"forbidden"))
        .unwrap();
    // Nothing comes back, because nothing was forwarded.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), connection.read_datagram())
            .await
            .is_err(),
        "a refused datagram reached the service anyway"
    );

    // And the connection is still there to be used.
    connection
        .send_datagram(bytes::Bytes::from_static(b"allowed"))
        .unwrap();
    let back = tokio::time::timeout(Duration::from_secs(5), connection.read_datagram())
        .await
        .expect("the connection was closed by a datagram that should only have been dropped")
        .unwrap();
    assert_eq!(&back[..], b"allowed");
}

/// The datagrams of one connection are one flow, and a filter keeps its state across
/// them.
///
/// The same answer the plain UDP relay gives — its sessions live on the flow, not on the
/// datagram — and the reason is that the alternative is a way through: a pattern split
/// over two datagrams would otherwise be two halves that match nothing, sent a
/// millisecond apart. What a datagram does *not* get is the stream models built on top of
/// a session, which is `L4::QuicDatagram`'s job and not this one's.
#[tokio::test]
async fn a_datagram_flow_keeps_its_filter_state() {
    let (cert, key) = self_signed();
    let upstream = spawn_quic_echo(&cert, &key, &["fgex-raw"]).await;
    let addr = spawn_relay(upstream, "block:secret", &["fgex-raw"]).await;

    let connection = connect(addr, &["fgex-raw"]).await;
    connection
        .send_datagram(bytes::Bytes::from_static(b"sec"))
        .unwrap();
    let back = tokio::time::timeout(Duration::from_secs(5), connection.read_datagram())
        .await
        .expect("half a needle is not a needle, and this one was blocked")
        .unwrap();
    assert_eq!(&back[..], b"sec");

    // The half that completes it is refused, though it arrived in a datagram of its own.
    connection
        .send_datagram(bytes::Bytes::from_static(b"ret"))
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(500), connection.read_datagram())
            .await
            .is_err(),
        "a needle split across two datagrams went through"
    );
}
