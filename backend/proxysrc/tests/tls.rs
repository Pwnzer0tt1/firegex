//! TLS terminated by the engine, and the reason that is worth doing.
//!
//! The TLS module gets here with nginx: terminate on one loopback port, forward
//! plaintext to a second, re-encrypt, forward on — and attach a filter engine to the
//! leg in between, which is the one hop where the traffic is in the clear. Doing it
//! in the engine means the plaintext exists only inside this process, and the rules
//! that need to see it are already there.

use std::sync::Arc;
use std::time::Duration;

use fgex_proxy::filter::{ChainHandle, FilterChain};
use fgex_proxy::proxy::{Edge, Onward, Proxy, ProxyConfig, Published, TlsSetup};
use fgex_proxy::spec::parse_filters;
use fgex_proxy::tls;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Generated per run: no key material belongs in the repository.
fn self_signed() -> (String, String) {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    (cert.cert.pem(), cert.key_pair.serialize_pem())
}

/// Plain echo, standing in for a service that does not speak TLS itself.
async fn spawn_plain_echo() -> std::net::SocketAddr {
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

/// An echo that speaks TLS, standing in for the CTF service that natively does.
async fn spawn_tls_echo(cert: &str, key: &str) -> std::net::SocketAddr {
    let config = tls::server_config(cert, key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let acceptor = tls::acceptor(config);
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(sock).await else {
                    return;
                };
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
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

async fn spawn_proxy(
    upstream: std::net::SocketAddr,
    filters: &str,
    tls_setup: TlsSetup,
) -> std::net::SocketAddr {
    let chain = ChainHandle::new(FilterChain::new(
        parse_filters(filters).unwrap(),
        Duration::from_millis(500),
    ));
    let mut cfg = ProxyConfig::fixed("127.0.0.1:0".parse().unwrap(), upstream);
    cfg.tls = tls_setup;
    let proxy = Proxy::bind(cfg, chain).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());
    addr
}

/// A client that speaks TLS to the proxy, accepting whatever it presents.
async fn tls_roundtrip(addr: std::net::SocketAddr, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let connector = tls::connector(tls::client_config().unwrap());
    let sock = TcpStream::connect(addr).await?;
    let name = tls::server_name("localhost").unwrap();
    let mut stream = connector.connect(name, sock).await?;
    stream.write_all(payload).await?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
    buf.truncate(n);
    Ok(buf)
}

#[tokio::test]
async fn terminates_tls_and_relays_to_a_plain_service() {
    let (cert, key) = self_signed();
    let upstream = spawn_plain_echo().await;
    let addr = spawn_proxy(
        upstream,
        "",
        TlsSetup {
            server: Some(tls::server_config(&cert, &key).unwrap()),
            upstream: None,
            optional: false,
        },
    )
    .await;

    let got = tls_roundtrip(addr, b"hello over tls").await.unwrap();
    assert_eq!(got, b"hello over tls");
}

/// The shape the TLS module is for: the service speaks TLS too, so the engine
/// decrypts, inspects, and re-encrypts. nginx needs two listeners and a loopback hop
/// in the clear to do this.
#[tokio::test]
async fn decrypts_inspects_and_re_encrypts() {
    let (cert, key) = self_signed();
    let upstream = spawn_tls_echo(&cert, &key).await;
    let addr = spawn_proxy(
        upstream,
        "",
        TlsSetup {
            server: Some(tls::server_config(&cert, &key).unwrap()),
            upstream: Some(tls::client_config().unwrap()),
            optional: false,
        },
    )
    .await;

    let got = tls_roundtrip(addr, b"end to end").await.unwrap();
    assert_eq!(got, b"end to end");
}

/// The point of decrypting at all: a rule that could never have matched the
/// ciphertext blocks the connection.
#[tokio::test]
async fn rules_see_the_plaintext() {
    let (cert, key) = self_signed();
    let upstream = spawn_tls_echo(&cert, &key).await;
    let addr = spawn_proxy(
        upstream,
        "block:FLAG{",
        TlsSetup {
            server: Some(tls::server_config(&cert, &key).unwrap()),
            upstream: Some(tls::client_config().unwrap()),
            optional: false,
        },
    )
    .await;

    let got = tls_roundtrip(addr, b"harmless request").await.unwrap();
    assert_eq!(got, b"harmless request");

    // Blocked, and closed properly: over TLS an abrupt drop reaches the peer as a
    // truncation error, which is exactly the "left to guess" this engine avoids.
    let got = tls_roundtrip(addr, b"give me FLAG{secret}")
        .await
        .expect("a blocked TLS connection was torn down instead of closed");
    assert!(
        got.is_empty(),
        "a rule missed the decrypted payload: {got:?}"
    );
}

/// A certificate and key that do not go together is a configuration error, and has to
/// be one at startup rather than a listener that refuses every handshake.
#[tokio::test]
async fn a_mismatched_key_is_refused() {
    let (cert, _) = self_signed();
    let (_, other_key) = self_signed();
    let err = tls::server_config(&cert, &other_key).unwrap_err();
    assert!(err.contains("do not go together"), "unhelpful error: {err}");
    assert!(tls::server_config("", "").is_err());
}

/// TLS is off by default, and off must cost nothing: the plain path is the one the
/// benchmark measured.
#[tokio::test]
async fn tls_off_leaves_the_plain_path_alone() {
    let upstream = spawn_plain_echo().await;
    let addr = spawn_proxy(upstream, "", TlsSetup::default()).await;
    assert!(TlsSetup::default().is_off());

    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"plain as ever").await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = sock.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"plain as ever");
    let _ = Arc::new(());
}

/// A TLS service that answers with the server name its client asked for, and nothing else.
async fn spawn_sni_reporter(cert: &str, key: &str) -> std::net::SocketAddr {
    let config = tls::server_config(cert, key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let acceptor = tls::acceptor(config);
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(sock).await else {
                    return;
                };
                let mut buf = vec![0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let name = stream.get_ref().1.server_name().unwrap_or("<none>").to_string();
                let _ = stream.write_all(name.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// The engine as an `http` service runs it: TLS terminated only for the connections that
/// start a handshake, with the service's address declared as the encrypted one and the
/// service behind it speaking `upstream_speaks`.
async fn spawn_http_edge(
    upstream: std::net::SocketAddr,
    filters: &str,
    cert: &str,
    key: &str,
    upstream_speaks: Onward,
) -> std::net::SocketAddr {
    let chain = ChainHandle::new(FilterChain::new(
        parse_filters(filters).unwrap(),
        Duration::from_millis(500),
    ));
    let mut cfg = ProxyConfig::fixed("127.0.0.1:0".parse().unwrap(), upstream);
    cfg.tls = TlsSetup {
        server: Some(tls::server_config(cert, key).unwrap()),
        upstream: Some(tls::client_config().unwrap()),
        optional: true,
    };
    cfg.targets.publish(
        upstream,
        Published { target: None, edge: Edge::Tls, upstream: upstream_speaks },
    );
    let proxy = Proxy::bind(cfg, chain).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());
    addr
}

/// An HTTPS address answers whether or not a filter is attached yet.
///
/// A chain with nothing to say used to skip the look at what the client opened with, so
/// every connection to an address declared as the encrypted one was refused as "not TLS":
/// a brand new `http` service answered nobody until its first filter, and one whose
/// filters were all switched off — or had all lost their say by panicking — went dark
/// the same way. The opposite of failing open.
#[tokio::test]
async fn a_tls_address_answers_with_no_filter_attached() {
    let (cert, key) = self_signed();
    let upstream = spawn_plain_echo().await;
    for filters in ["", "block:ZZ-NO-SUCH-BYTES-ZZ"] {
        let addr = spawn_http_edge(upstream, filters, &cert, &key, Onward::Plain).await;
        let got = tls_roundtrip(addr, b"hello").await;
        assert_eq!(
            got.as_deref().ok(),
            Some(&b"hello"[..]),
            "the TLS address did not answer with the chain {filters:?}: {got:?}"
        );
    }
}

/// The same for a service that speaks TLS itself: re-encrypted, chain or no chain.
#[tokio::test]
async fn a_tls_address_re_encrypts_with_no_filter_attached() {
    let (cert, key) = self_signed();
    let upstream = spawn_tls_echo(&cert, &key).await;
    let addr = spawn_http_edge(upstream, "", &cert, &key, Onward::Same).await;
    let got = tls_roundtrip(addr, b"end to end").await.unwrap();
    assert_eq!(got, b"end to end");
}

/// And the promise the declaration makes still holds without a filter: a client that
/// opens the encrypted address in the clear is refused rather than carried.
#[tokio::test]
async fn a_tls_address_refuses_the_clear_with_no_filter_attached() {
    let (cert, key) = self_signed();
    let upstream = spawn_plain_echo().await;
    let addr = spawn_http_edge(upstream, "", &cert, &key, Onward::Plain).await;
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
        .await
        .expect("the refused connection was left hanging")
        .unwrap_or(0);
    assert_eq!(n, 0, "a cleartext client was carried: {:?}", &buf[..n]);
}

/// The name the client asked for is the name the service is asked for.
///
/// A service choosing its certificate or its virtual host by SNI was handed the bare
/// address instead — which TLS does not even send — and answered as its default host.
#[tokio::test]
async fn the_client_s_server_name_reaches_the_service() {
    let (cert, key) = self_signed();
    let upstream = spawn_sni_reporter(&cert, &key).await;
    let addr = spawn_proxy(
        upstream,
        "",
        TlsSetup {
            server: Some(tls::server_config(&cert, &key).unwrap()),
            upstream: Some(tls::client_config().unwrap()),
            optional: false,
        },
    )
    .await;
    let got = tls_roundtrip(addr, b"who am I talking to").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&got), "localhost");
}
