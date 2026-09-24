//! HTTP/3 carried by the engine, and shown to the filters as HTTP/1.1.
//!
//! The point of the translation is that a filter written once works on both: a pattern
//! that blocks a path over TCP has to block the same path over QUIC, where on the wire
//! that path was a QPACK-compressed header block. These tests put a real HTTP/3 client and
//! a real HTTP/3 service either side of the relay and check what the chain was shown.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use fgex_proxy::filter::{ChainHandle, FilterChain};
use fgex_proxy::proxy::ProxyStats;
use fgex_proxy::proxy::Onward;
use fgex_proxy::quic::{QuicConfig, QuicRelay, QuicSetup};
use fgex_proxy::spec::parse_filters;
use fgex_proxy::tls;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};

fn self_signed() -> (String, String) {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    (cert.cert.pem(), cert.key_pair.serialize_pem())
}

/// An HTTP/3 service that answers with what it was asked, body and all.
async fn spawn_h3_echo(cert: &str, key: &str) -> SocketAddr {
    let mut config = (*tls::server_config(cert, key).unwrap()).clone();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(config).unwrap())),
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
                let Ok(mut h3) = h3::server::builder()
                    .build(h3_quinn::Connection::new(connection))
                    .await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = h3.accept().await {
                    tokio::spawn(async move {
                        let Ok((request, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        let mut body = Vec::new();
                        while let Ok(Some(mut chunk)) = stream.recv_data().await {
                            let len = chunk.remaining();
                            body.extend_from_slice(&chunk.copy_to_bytes(len));
                        }
                        // One path answers with something a rule is looking for, and
                        // says it in bytes that appear nowhere in the request: that is
                        // what makes a test of the *answer* a test of the answer.
                        let answer = if request.uri().path() == "/secret" {
                            "here is FLAG{only-in-the-answer}".to_string()
                        } else {
                            format!(
                                "you asked for {} and sent {} bytes: {}",
                                request.uri().path(),
                                body.len(),
                                String::from_utf8_lossy(&body)
                            )
                        };
                        let response = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .header("content-length", answer.len().to_string())
                            .body(())
                            .unwrap();
                        let _ = stream.send_response(response).await;
                        let _ = stream.send_data(Bytes::from(answer)).await;
                        let _ = stream.finish().await;
                    });
                }
            });
        }
    });
    addr
}

/// A service that speaks HTTP/1.1 and nothing else, which is what most of the web is.
///
/// Deliberately hand-written rather than a crate: what these tests are about is what
/// leaves this engine, so the far end has to be something that reads exactly what an
/// HTTP/1.1 service reads and nothing more forgiving.
async fn spawn_h1_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // The head, then whatever the framing says the body is.
                let head_end = loop {
                    let n = match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break at + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let declared = head
                    .split("content-length:")
                    .nth(1)
                    .and_then(|rest| rest.split("\r\n").next())
                    .and_then(|v| v.trim().parse::<usize>().ok());
                let mut body = buf[head_end..].to_vec();
                match declared {
                    Some(want) => {
                        while body.len() < want {
                            let n = match socket.read(&mut chunk).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            body.extend_from_slice(&chunk[..n]);
                        }
                        body.truncate(want.min(body.len()));
                    }
                    // Chunked, which is what an undeclared body is in HTTP/1.1 — and what
                    // the rendering shows a filter, so it is what has to arrive here.
                    None if head.contains("transfer-encoding: chunked") => {
                        let mut decoded = Vec::new();
                        loop {
                            while !body.windows(2).any(|w| w == b"\r\n") {
                                let n = match socket.read(&mut chunk).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => n,
                                };
                                body.extend_from_slice(&chunk[..n]);
                            }
                            let Some(at) = body.windows(2).position(|w| w == b"\r\n") else {
                                break;
                            };
                            let size = usize::from_str_radix(
                                String::from_utf8_lossy(&body[..at]).trim(),
                                16,
                            )
                            .unwrap_or(0);
                            if size == 0 {
                                break;
                            }
                            body.drain(..at + 2);
                            while body.len() < size + 2 {
                                let n = match socket.read(&mut chunk).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => n,
                                };
                                body.extend_from_slice(&chunk[..n]);
                            }
                            decoded.extend_from_slice(&body[..size.min(body.len())]);
                            body.drain(..(size + 2).min(body.len()));
                        }
                        body = decoded;
                    }
                    None => body.clear(),
                }
                let answer = format!(
                    "you asked for {path} and sent {} bytes: {}",
                    body.len(),
                    String::from_utf8_lossy(&body)
                );
                let _ = socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{answer}",
                            answer.len()
                        )
                        .as_bytes(),
                    )
                    .await;
                let _ = socket.flush().await;
            });
        }
    });
    addr
}

async fn spawn_relay(upstream: SocketAddr, filters: &str) -> SocketAddr {
    spawn_relay_to(upstream, filters, Onward::Same).await
}

async fn spawn_relay_to(
    upstream: SocketAddr,
    filters: &str,
    protocol: Onward,
) -> SocketAddr {
    let (cert, key) = self_signed();
    let chain = ChainHandle::new(FilterChain::new(
        parse_filters(filters).unwrap(),
        Duration::from_millis(500),
    ));
    let cfg = QuicConfig {
        setup: Arc::new(QuicSetup::build(&cert, &key, vec![b"h3".to_vec()]).unwrap()),
        self_mark: None,
        spoof_source: false,
        max_connections: 0,
        over_limit_forwards: false,
        first_byte_timeout: None,
        connect_timeout: Duration::from_secs(5),
        upstream: protocol,
        // No interface to reconstruct anything onto, which is every host without the
        // capture device — what it would carry is pinned by the integration suite, which
        // has a real one.
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

/// One request through the relay, and what came back.
async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    declare_length: bool,
) -> Result<String, String> {
    let mut config = tls::quic_client_config().unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(config).unwrap(),
    )));
    let connection = endpoint
        .connect(addr, "localhost")
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| e.to_string())?;
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|e| e.to_string())?;
    let driving = tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    let answer = async {
        let mut builder = http::Request::builder()
            .method(method)
            .uri(format!("https://localhost{path}"));
        if declare_length {
            builder = builder.header("content-length", body.map(|b| b.len()).unwrap_or(0).to_string());
        }
        let outgoing = builder.body(()).map_err(|e| e.to_string())?;
        let mut stream = sender.send_request(outgoing).await.map_err(|e| e.to_string())?;
        if let Some(body) = body {
            stream
                .send_data(Bytes::copy_from_slice(body))
                .await
                .map_err(|e| e.to_string())?;
        }
        stream.finish().await.map_err(|e| e.to_string())?;
        stream.recv_response().await.map_err(|e| e.to_string())?;
        let mut got = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.map_err(|e| e.to_string())? {
            let len = chunk.remaining();
            got.extend_from_slice(&chunk.copy_to_bytes(len));
        }
        Ok(String::from_utf8_lossy(&got).into_owned())
    }
    .await;
    driving.abort();
    answer
}

#[tokio::test]
async fn an_exchange_goes_through() {
    let (cert, key) = self_signed();
    let upstream = spawn_h3_echo(&cert, &key).await;
    let addr = spawn_relay(upstream, "").await;

    let answer = request(addr, "GET", "/hello", None, false).await.unwrap();
    assert_eq!(answer, "you asked for /hello and sent 0 bytes: ");
}

/// The whole reason for rendering the exchange: a pattern written against an HTTP
/// request matches one that arrived as a QPACK header block.
#[tokio::test]
async fn a_pattern_matches_the_request_line() {
    let (cert, key) = self_signed();
    let upstream = spawn_h3_echo(&cert, &key).await;
    let addr = spawn_relay(upstream, "block:GET /admin").await;

    let allowed = request(addr, "GET", "/public", None, false).await.unwrap();
    assert!(allowed.contains("/public"), "an unrelated request was affected: {allowed}");

    let refused = request(addr, "GET", "/admin", None, false).await;
    assert!(
        refused.is_err(),
        "a request the chain refused was answered anyway: {refused:?}"
    );
}

/// A header the request did not carry must not appear in what the filters are shown.
///
/// This is what the head is held back for. A bodiless request rendered as
/// `transfer-encoding: chunked` would be a lie in front of every filter looking for that
/// header — and a filter looking for it is usually looking for request smuggling, which
/// makes a fabricated one the worst possible answer.
#[tokio::test]
async fn a_request_with_no_body_is_shown_no_framing_header() {
    let (cert, key) = self_signed();
    let upstream = spawn_h3_echo(&cert, &key).await;
    let addr = spawn_relay(upstream, "block:transfer-encoding").await;

    let answer = request(addr, "GET", "/plain", None, false).await.unwrap();
    assert!(answer.contains("/plain"), "a framing header was invented: {answer}");
}

/// And a body whose length was never declared is shown chunked, because that is what
/// that message is in HTTP/1.1 — so a parser reading the rendering finds a body.
#[tokio::test]
async fn a_body_of_unknown_length_is_shown_chunked() {
    let (cert, key) = self_signed();
    let upstream = spawn_h3_echo(&cert, &key).await;
    let addr = spawn_relay(upstream, "block:transfer-encoding").await;

    let refused = request(addr, "POST", "/upload", Some(b"anything"), false).await;
    assert!(
        refused.is_err(),
        "a body with no declared length was shown unframed: {refused:?}"
    );
}

/// A declared length is passed through as it was, and the body shown raw beneath it.
#[tokio::test]
async fn a_declared_length_is_left_alone() {
    let (cert, key) = self_signed();
    let upstream = spawn_h3_echo(&cert, &key).await;
    let addr = spawn_relay(upstream, "block:transfer-encoding").await;

    let answer = request(addr, "POST", "/upload", Some(b"declared"), true)
        .await
        .unwrap();
    assert!(answer.contains("sent 8 bytes"), "the body did not arrive: {answer}");
}

/// Both directions are inspected, and a refused answer does not reach the client.
#[tokio::test]
async fn the_answer_is_inspected_too() {
    let (cert, key) = self_signed();
    let upstream = spawn_h3_echo(&cert, &key).await;
    let addr = spawn_relay(upstream, "block:FLAG{").await;

    let answer = request(addr, "GET", "/harmless", None, false).await;
    assert!(answer.is_ok(), "an unrelated exchange was affected: {answer:?}");

    // Nothing in this request carries the needle; everything that does is in the reply.
    let refused = request(addr, "GET", "/secret", None, false).await;
    match refused {
        Err(_) => {}
        Ok(body) => panic!("the answer reached the client anyway: {body}"),
    }
}

/// A service that answers a fixed body and remembers the trailer section it was sent.
///
/// Separate from the echo above on purpose: what these tests are asking is what reached
/// the *service*, which an answer that reflects the request cannot tell them apart from
/// what reached the client.
async fn spawn_h3_recorder(
    cert: &str,
    key: &str,
) -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut config = (*tls::server_config(cert, key).unwrap()).clone();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(config).unwrap())),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else { return };
                let Ok(mut h3) = h3::server::builder()
                    .build(h3_quinn::Connection::new(connection))
                    .await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = h3.accept().await {
                    let recorded = Arc::clone(&recorded);
                    tokio::spawn(async move {
                        let Ok((_request, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        while let Ok(Some(_)) = stream.recv_data().await {}
                        if let Ok(Some(trailers)) = stream.recv_trailers().await {
                            for (name, value) in trailers.iter() {
                                recorded.lock().unwrap().push(format!(
                                    "{name}={}",
                                    value.to_str().unwrap_or("?")
                                ));
                            }
                        }
                        let answer = "recorded";
                        let response = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .header("content-length", answer.len().to_string())
                            .body(())
                            .unwrap();
                        let _ = stream.send_response(response).await;
                        let _ = stream.send_data(Bytes::from(answer)).await;
                        let _ = stream.finish().await;
                    });
                }
            });
        }
    });
    (addr, seen)
}

/// A service that answers the moment the head arrives, without waiting for a body.
///
/// The shape of a bidirectional RPC and of every service that replies before an upload
/// finishes — a `413`, a redirect, a refusal.
async fn spawn_h3_eager(cert: &str, key: &str) -> SocketAddr {
    let mut config = (*tls::server_config(cert, key).unwrap()).clone();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(config).unwrap())),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else { return };
                let Ok(mut h3) = h3::server::builder()
                    .build(h3_quinn::Connection::new(connection))
                    .await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = h3.accept().await {
                    tokio::spawn(async move {
                        let Ok((_request, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        let answer = "the service spoke first";
                        let response = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .header("content-length", answer.len().to_string())
                            .body(())
                            .unwrap();
                        let _ = stream.send_response(response).await;
                        let _ = stream.send_data(Bytes::from(answer)).await;
                        let _ = stream.finish().await;
                    });
                }
            });
        }
    });
    addr
}

/// One request that ends with a trailer section, and what came back.
async fn request_with_trailer(
    addr: SocketAddr,
    body: &[u8],
    declare_length: bool,
    trailer: &str,
) -> Result<String, String> {
    let mut config = tls::quic_client_config().unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(config).unwrap(),
    )));
    let connection = endpoint
        .connect(addr, "localhost")
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| e.to_string())?;
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|e| e.to_string())?;
    let driving = tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    let answer = async {
        let mut builder = http::Request::builder()
            .method("POST")
            .uri("https://localhost/up");
        if declare_length {
            builder = builder.header("content-length", body.len().to_string());
        }
        let outgoing = builder.body(()).map_err(|e| e.to_string())?;
        let mut stream = sender.send_request(outgoing).await.map_err(|e| e.to_string())?;
        if !body.is_empty() {
            stream
                .send_data(Bytes::copy_from_slice(body))
                .await
                .map_err(|e| e.to_string())?;
        }
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-note", http::HeaderValue::from_str(trailer).unwrap());
        stream.send_trailers(trailers).await.map_err(|e| e.to_string())?;
        let _ = stream.finish().await;
        stream.recv_response().await.map_err(|e| e.to_string())?;
        let mut got = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.map_err(|e| e.to_string())? {
            let len = chunk.remaining();
            got.extend_from_slice(&chunk.copy_to_bytes(len));
        }
        Ok(String::from_utf8_lossy(&got).into_owned())
    }
    .await;
    driving.abort();
    answer
}

/// A trailer section on a message whose body was never framed by a declared length is
/// shown to the chain, which is the only reason it may then be forwarded.
///
/// The bodiless case is the one that matters most and the one that used to slip past: a
/// message of HEADERS and TRAILERS and nothing in between — which is exactly a gRPC
/// trailers-only answer — had no chunked body to hang a trailer section off, so the
/// rendering ended at the head and the trailers travelled to the far side unread. They
/// decide the framing now: in HTTP/1.1 a message with trailers *is* a chunked one.
#[tokio::test]
async fn a_trailer_section_is_shown_to_the_chain() {
    let (cert, key) = self_signed();
    let upstream = spawn_h3_echo(&cert, &key).await;
    let addr = spawn_relay(upstream, "block:SNEAKY").await;

    for (body, declared, what) in [
        (&b""[..], false, "no body at all"),
        (&b"harmless"[..], false, "a body of undeclared length"),
    ] {
        let refused = request_with_trailer(addr, body, declared, "SNEAKY").await;
        assert!(
            refused.is_err(),
            "a needle in the trailers of a message with {what} was not seen: {refused:?}"
        );
    }
}

/// And where the rendering cannot carry one, it is dropped rather than forwarded unread.
///
/// A declared length means the HTTP/1.1 view of the message ends where the header said it
/// would, so there is nowhere to put a trailer section — and forwarding a piece of a
/// message no filter was shown is the one thing this engine does not do anywhere else.
/// Dropping is what an intermediary is allowed to do with a trailer section it cannot
/// carry; the exchange itself is untouched.
#[tokio::test]
async fn a_trailer_the_rendering_cannot_carry_is_not_forwarded() {
    let (cert, key) = self_signed();
    let (upstream, seen) = spawn_h3_recorder(&cert, &key).await;
    let addr = spawn_relay(upstream, "").await;

    let answer = request_with_trailer(addr, b"harmless", true, "SNEAKY").await;
    assert_eq!(answer.as_deref(), Ok("recorded"), "the exchange was disturbed");
    assert!(
        seen.lock().unwrap().is_empty(),
        "a trailer section no filter was shown reached the service: {:?}",
        seen.lock().unwrap()
    );

    // Without the declared length the same trailers are renderable, so they are shown and
    // then carried: the rule is what the chain saw, not a dislike of trailers.
    let (upstream, seen) = spawn_h3_recorder(&cert, &key).await;
    let addr = spawn_relay(upstream, "").await;
    let answer = request_with_trailer(addr, b"harmless", false, "SNEAKY").await;
    assert_eq!(answer.as_deref(), Ok("recorded"));
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        ["x-note=SNEAKY"],
        "a trailer section the chain accepted was dropped anyway"
    );
}

/// An exchange the service is supposed to speak first in is not held waiting for a body.
///
/// The head is held only until the framing is known, and a client that sends a head and
/// then waits to be answered — a bidirectional RPC, gRPC's among them — never sends one.
/// Holding it there deadlocked the exchange: the proxy waiting for a body, the client
/// waiting for the answer that would tell it what to send.
#[tokio::test]
async fn a_service_that_speaks_first_is_not_waited_out() {
    let (cert, key) = self_signed();
    let upstream = spawn_h3_eager(&cert, &key).await;
    let addr = spawn_relay(upstream, "").await;

    let mut config = tls::quic_client_config().unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(config).unwrap(),
    )));
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .unwrap();
    let driving = tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    let outgoing = http::Request::builder()
        .method("POST")
        .uri("https://localhost/stream")
        .body(())
        .unwrap();
    let mut stream = sender.send_request(outgoing).await.unwrap();
    // Deliberately no body and no finish: this client is waiting to be spoken to.
    let answered = tokio::time::timeout(Duration::from_secs(5), stream.recv_response()).await;
    driving.abort();
    assert!(
        answered.is_ok(),
        "the head never reached a service that answers without waiting for a body"
    );
    assert_eq!(answered.unwrap().unwrap().status(), http::StatusCode::OK);
}

// --- a service that speaks HTTP/1.1, behind an HTTP/3 edge ----------------------------
//
// The one place in this engine where what leaves is not the version that arrived. It is
// the operator's choice (`FGEX_PROXY_UPSTREAM`) and it exists because most of the web is
// an HTTP/1.1 service that will never speak QUIC: firegex terminates HTTP/3 in front of
// it and sends on the rendering the filters were already being shown.

#[tokio::test]
async fn an_http1_service_answers_an_http3_client() {
    let upstream = spawn_h1_echo().await;
    let addr = spawn_relay_to(upstream, "", Onward::Plain).await;

    let answer = request(addr, "GET", "/hello", None, false).await.unwrap();
    assert_eq!(answer, "you asked for /hello and sent 0 bytes: ");
}

/// A body, declared — which is the framing that travels as a `content-length` and is
/// read back by the far end as one.
#[tokio::test]
async fn a_declared_body_reaches_an_http1_service() {
    let upstream = spawn_h1_echo().await;
    let addr = spawn_relay_to(upstream, "", Onward::Plain).await;

    let answer = request(addr, "POST", "/upload", Some(b"twelve bytes"), true)
        .await
        .unwrap();
    assert_eq!(answer, "you asked for /upload and sent 12 bytes: twelve bytes");
}

/// And one that declared nothing, which is chunked in HTTP/1.1 — the framing the chain
/// is shown, so it had better be the framing the service is sent.
#[tokio::test]
async fn an_undeclared_body_reaches_an_http1_service_chunked() {
    let upstream = spawn_h1_echo().await;
    let addr = spawn_relay_to(upstream, "", Onward::Plain).await;

    let answer = request(addr, "POST", "/upload", Some(b"twelve bytes"), false)
        .await
        .unwrap();
    assert_eq!(answer, "you asked for /upload and sent 12 bytes: twelve bytes");
}

/// The promise that makes the whole thing worth having: one filter file, and it does not
/// care which version either end speaks. The same pattern that blocks this request
/// against an HTTP/3 service blocks it against an HTTP/1.1 one.
#[tokio::test]
async fn a_pattern_matches_with_an_http1_service_behind() {
    let upstream = spawn_h1_echo().await;
    let addr = spawn_relay_to(upstream, "block:GET /admin", Onward::Plain).await;

    assert!(
        request(addr, "GET", "/admin", None, false).await.is_err(),
        "the request reached an HTTP/1.1 service that a pattern should have refused"
    );
    let answer = request(addr, "GET", "/public", None, false).await.unwrap();
    assert_eq!(answer, "you asked for /public and sent 0 bytes: ");
}

/// A `host` header that disagrees with `:authority` is malformed, and never reaches the
/// service — the HTTP/3 half of the same case in `h2.rs`.
#[tokio::test]
async fn a_host_that_disagrees_with_the_authority_is_refused() {
    let (cert, key) = self_signed();
    let upstream = spawn_h3_echo(&cert, &key).await;
    let addr = spawn_relay(upstream, "").await;

    let ask = |host: &'static str| async move {
        let mut config = tls::quic_client_config().unwrap();
        config.alpn_protocols = vec![b"h3".to_vec()];
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(config).unwrap(),
        )));
        let connection = endpoint
            .connect(addr, "localhost")
            .map_err(|e| e.to_string())?
            .await
            .map_err(|e| e.to_string())?;
        let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .map_err(|e| e.to_string())?;
        let driving = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        let answer = async {
            let outgoing = http::Request::builder()
                .method("GET")
                .uri("https://localhost/who")
                .header("host", host)
                .body(())
                .map_err(|e| e.to_string())?;
            let mut stream = sender.send_request(outgoing).await.map_err(|e| e.to_string())?;
            stream.finish().await.map_err(|e| e.to_string())?;
            stream.recv_response().await.map_err(|e| e.to_string())?;
            let mut got = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.map_err(|e| e.to_string())? {
                let len = chunk.remaining();
                got.extend_from_slice(&chunk.copy_to_bytes(len));
            }
            Ok::<String, String>(String::from_utf8_lossy(&got).into_owned())
        }
        .await;
        driving.abort();
        answer
    };

    let agreeing = ask("localhost").await;
    assert!(
        agreeing.as_deref().is_ok_and(|a| a.contains("/who")),
        "a host agreeing with :authority was not carried: {agreeing:?}"
    );
    let disagreeing = tokio::time::timeout(Duration::from_secs(5), ask("admin.internal"))
        .await
        .expect("a malformed request was left hanging");
    assert!(disagreeing.is_err(), "a disagreeing host was carried: {disagreeing:?}");
}

/// One GET through the relay carrying `headers`, and the answer's status, head and body.
async fn ask_with(
    addr: SocketAddr,
    headers: &[(&'static str, &'static str)],
) -> Result<(u16, http::HeaderMap, String), String> {
    let mut config = tls::quic_client_config().unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(config).unwrap(),
    )));
    let connection = endpoint
        .connect(addr, "localhost")
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| e.to_string())?;
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|e| e.to_string())?;
    let driving = tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });
    let answer = async {
        let mut builder = http::Request::builder().method("GET").uri("https://localhost/who");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let outgoing = builder.body(()).map_err(|e| e.to_string())?;
        let mut stream = sender.send_request(outgoing).await.map_err(|e| e.to_string())?;
        stream.finish().await.map_err(|e| e.to_string())?;
        let response = stream.recv_response().await.map_err(|e| e.to_string())?;
        let mut got = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.map_err(|e| e.to_string())? {
            let len = chunk.remaining();
            got.extend_from_slice(&chunk.copy_to_bytes(len));
        }
        Ok::<_, String>((
            response.status().as_u16(),
            response.headers().clone(),
            String::from_utf8_lossy(&got).into_owned(),
        ))
    }
    .await;
    driving.abort();
    answer
}

/// A header about a connection is malformed in HTTP/3, and the h3 crate does not refuse
/// it. Carried to a service reached over HTTP/1.1 it would be read there as a statement
/// about *that* connection — which headers to drop, which transfer coding to undo — and a
/// filter shown the rendering would not recognise the request the service got.
#[tokio::test]
async fn a_connection_header_is_refused_over_http3() {
    let upstream = spawn_h1_echo().await;
    let addr = spawn_relay_to(upstream, "", Onward::Plain).await;

    let trailers = ask_with(addr, &[("te", "trailers")]).await;
    assert!(trailers.is_ok(), "`te: trailers`, the one allowed, was refused: {trailers:?}");
    for header in [("transfer-encoding", "chunked"), ("connection", "x-forwarded-for"),
                   ("keep-alive", "timeout=5"), ("upgrade", "websocket"), ("te", "gzip")] {
        let refused = tokio::time::timeout(Duration::from_secs(5), ask_with(addr, &[header]))
            .await
            .expect("a malformed request was left hanging");
        assert!(refused.is_err(), "a request carrying {header:?} was carried: {refused:?}");
    }
}

/// What an HTTP/1.1 service answers with says things about its own connection — a body
/// sent chunked, a connection offered for reuse — that an HTTP/3 client is required to
/// reject a response for. They are the service's, and they stay behind.
#[tokio::test]
async fn an_http1_answer_reaches_an_http3_client_without_its_connection_headers() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nconnection: keep-alive, x-internal\r\n\
                          keep-alive: timeout=5\r\nx-internal: secret\r\n\
                          content-type: text/plain\r\ntransfer-encoding: chunked\r\n\r\n\
                          5\r\nhello\r\n0\r\n\r\n",
                    )
                    .await;
            });
        }
    });
    let addr = spawn_relay_to(upstream, "", Onward::Plain).await;

    let (_, headers, body) = ask_with(addr, &[]).await.unwrap();
    assert_eq!(body, "hello");
    for name in ["connection", "keep-alive", "transfer-encoding", "x-internal"] {
        assert!(!headers.contains_key(name), "`{name}` reached the HTTP/3 client: {headers:?}");
    }
    assert_eq!(headers.get("content-type").map(|v| v.as_bytes()), Some(&b"text/plain"[..]));
}

/// A head is bounded, which the h3 crate does not do by default at all.
#[tokio::test]
async fn a_head_past_the_limit_is_refused_over_http3() {
    let upstream = spawn_h1_echo().await;
    let addr = spawn_relay_to(upstream, "", Onward::Plain).await;
    let big: &'static str = Box::leak("a".repeat(2 * 1024 * 1024).into_boxed_str());
    let refused = tokio::time::timeout(Duration::from_secs(10), ask_with(addr, &[("x-big", big)]))
        .await
        .expect("an oversized head was left hanging");
    // The crate answers `431 Request Header Fields Too Large` itself, and nothing is sent on.
    assert!(
        !matches!(refused, Ok((200, _, _))),
        "a 2 MiB head was carried: {:?}",
        refused.map(|r| r.2)
    );
    let large: &'static str = Box::leak("a".repeat(256 * 1024).into_boxed_str());
    assert!(
        matches!(ask_with(addr, &[("x-large", large)]).await, Ok((200, _, _))),
        "a 256 KiB head was refused"
    );
}
