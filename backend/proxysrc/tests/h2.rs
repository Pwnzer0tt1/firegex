//! HTTP/2 terminated by the engine, and shown to the filters as HTTP/1.1.
//!
//! The point of the rendering is that a filter written once works on every version: a
//! pattern that blocks a path over HTTP/1.1 has to block the same path over HTTP/2, where
//! on the wire that path was an HPACK-compressed header block. These tests put a real h2
//! client and a real h2 service either side of the proxy and check what the chain was
//! shown — and, where the question is what reached the *service*, what arrived there.
//!
//! They are the h3 suite's cases, asked again of the other protocol, plus the two that
//! only HTTP/2 can get wrong: a head that is the whole message has to go out as one, and
//! concurrent streams on one connection must not share a filter's state.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use fgex_proxy::filter::{ChainHandle, FilterChain};
use fgex_proxy::proxy::{Proxy, ProxyConfig, TlsSetup};
use fgex_proxy::spec::parse_filters;
use fgex_proxy::tls;
use tokio::net::{TcpListener, TcpStream};

fn self_signed() -> (String, String) {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    (cert.cert.pem(), cert.key_pair.serialize_pem())
}

/// What a service did with one exchange, as the tests need to see it.
#[derive(Default)]
struct Seen {
    /// Every trailer the service was handed, as `name=value`.
    trailers: Mutex<Vec<String>>,
    /// How many requests it answered.
    requests: AtomicUsize,
}

/// How the stand-in service behaves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Service {
    /// Answers with what it was asked, body and all.
    Echo,
    /// Answers the moment the head arrives, without waiting for a body — the shape of a
    /// bidirectional RPC and of every service that replies before an upload finishes.
    Eager,
    /// Answers with a head and nothing else, the way a gRPC status-only reply does.
    TrailersOnly,
}

/// A real HTTP/2 service, over TLS, standing where the protected service would be.
async fn spawn_service(cert: &str, key: &str, how: Service) -> (SocketAddr, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let mut config = (*tls::server_config(cert, key).unwrap()).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(sock).await else {
                    return;
                };
                let Ok(connection) = h2::server::handshake(tls).await else {
                    return;
                };
                serve(connection, how, recorded).await;
            });
        }
    });
    (addr, seen)
}

/// What the stand-in service does with the exchanges on one connection.
///
/// Shared by the TLS and the cleartext service so the two cannot answer differently: the
/// h2c tests are asking whether the *proxy* behaves the same without TLS in the way, and a
/// service that differed would make that unanswerable.
async fn serve<T>(mut connection: h2::server::Connection<T, Bytes>, how: Service, seen: Arc<Seen>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(Ok((request, mut respond))) = connection.accept().await {
        let seen = Arc::clone(&seen);
        tokio::spawn(async move {
            seen.requests.fetch_add(1, Ordering::Relaxed);
            let path = request.uri().path().to_string();
            let (_, mut body) = request.into_parts();

            if how == Service::Eager {
                let answer = "the service spoke first";
                let response = http::Response::builder()
                    .status(200)
                    .header("content-length", answer.len().to_string())
                    .body(())
                    .unwrap();
                let mut out = respond.send_response(response, false).unwrap();
                let _ = out.send_data(Bytes::from(answer), true);
                return;
            }

            let mut collected = Vec::new();
            while let Some(Ok(chunk)) = body.data().await {
                let len = chunk.len();
                collected.extend_from_slice(&chunk);
                let _ = body.flow_control().release_capacity(len);
            }
            if let Ok(Some(trailers)) = body.trailers().await {
                for (name, value) in trailers.iter() {
                    seen.trailers
                        .lock()
                        .unwrap()
                        .push(format!("{name}={}", value.to_str().unwrap_or("?")));
                }
            }

            if how == Service::TrailersOnly {
                // HEADERS with END_STREAM and nothing else — what a gRPC status-only
                // answer is on the wire.
                let response = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .header("grpc-status", "5")
                    .body(())
                    .unwrap();
                let _ = respond.send_response(response, true);
                return;
            }

            // One path answers with something a rule is looking for, in bytes that appear
            // nowhere in the request: that is what makes a test of the *answer* a test of
            // the answer.
            let answer = if path == "/secret" {
                "here is FLAG{only-in-the-answer}".to_string()
            } else {
                format!(
                    "you asked for {path} and sent {} bytes: {}",
                    collected.len(),
                    String::from_utf8_lossy(&collected)
                )
            };
            let response = http::Response::builder()
                .status(200)
                .header("content-length", answer.len().to_string())
                .body(())
                .unwrap();
            let mut out = respond.send_response(response, false).unwrap();
            let _ = out.send_data(Bytes::from(answer), true);
        });
    }
}

/// The same service, speaking HTTP/2 in the clear: no TLS, prior knowledge, which is how
/// most gRPC is actually deployed behind a load balancer.
async fn spawn_cleartext_service(how: Service) -> (SocketAddr, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let Ok(connection) = h2::server::handshake(sock).await else {
                    return;
                };
                serve(connection, how, recorded).await;
            });
        }
    });
    (addr, seen)
}

/// A plain relay with no TLS on either edge, which is what a `tcp` service is.
async fn spawn_plain_proxy(upstream: SocketAddr, filters: &str) -> SocketAddr {
    let chain = ChainHandle::new(FilterChain::new(
        parse_filters(filters).unwrap(),
        Duration::from_millis(500),
    ));
    let cfg = ProxyConfig::fixed("127.0.0.1:0".parse().unwrap(), upstream);
    let proxy = Proxy::bind(cfg, chain).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());
    addr
}

/// An h2 connection in the clear, the way a prior-knowledge client opens one.
async fn connect_cleartext(
    addr: SocketAddr,
) -> Result<(h2::client::SendRequest<Bytes>, tokio::task::JoinHandle<()>), String> {
    let sock = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let (sender, connection) = h2::client::handshake(sock).await.map_err(|e| e.to_string())?;
    let driving = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok((sender, driving))
}

/// The engine in front of it, terminating TLS on both edges as a `tls` service does.
async fn spawn_proxy(upstream: SocketAddr, cert: &str, key: &str, filters: &str) -> SocketAddr {
    let chain = ChainHandle::new(FilterChain::new(
        parse_filters(filters).unwrap(),
        Duration::from_millis(500),
    ));
    let mut cfg = ProxyConfig::fixed("127.0.0.1:0".parse().unwrap(), upstream);
    cfg.tls = TlsSetup {
        server: Some(tls::server_config(cert, key).unwrap()),
        upstream: Some(tls::client_config().unwrap()),
        optional: false,
    };
    let proxy = Proxy::bind(cfg, chain).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());
    addr
}

/// An h2 connection to the proxy, offering `h2` so the service's answer is `h2`.
async fn connect(addr: SocketAddr) -> Result<(h2::client::SendRequest<Bytes>, tokio::task::JoinHandle<()>), String> {
    let mut config = (*tls::client_config().unwrap()).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let sock = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let name = tls::server_name("localhost").map_err(|e| e.to_string())?;
    let tls = connector.connect(name, sock).await.map_err(|e| e.to_string())?;
    let (sender, connection) = h2::client::handshake(tls).await.map_err(|e| e.to_string())?;
    let driving = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok((sender, driving))
}

/// How a request's body is framed on the way out.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Body {
    /// No body at all: HEADERS with END_STREAM.
    None,
    /// A body whose length is declared up front.
    Declared(&'static [u8]),
    /// A body whose length is not declared, so the rendering has to frame it.
    Undeclared(&'static [u8]),
}

/// One request through the proxy, and what came back.
async fn request(addr: SocketAddr, method: &str, path: &str, body: Body) -> Result<String, String> {
    request_with_trailer(addr, method, path, body, None).await
}

/// The same, optionally ending with a trailer section.
async fn request_with_trailer(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Body,
    trailer: Option<&str>,
) -> Result<String, String> {
    let (mut sender, driving) = connect(addr).await?;
    let answer = async {
        let mut builder = http::Request::builder()
            .method(method)
            .uri(format!("https://localhost{path}"));
        let payload = match body {
            Body::None => None,
            Body::Declared(bytes) => {
                builder = builder.header("content-length", bytes.len().to_string());
                Some(bytes)
            }
            Body::Undeclared(bytes) => Some(bytes),
        };
        let outgoing = builder.body(()).map_err(|e| e.to_string())?;
        let ends_here = payload.is_none() && trailer.is_none();
        let (response, mut out) = sender
            .send_request(outgoing, ends_here)
            .map_err(|e| e.to_string())?;
        if let Some(bytes) = payload {
            out.send_data(Bytes::from_static(bytes), trailer.is_none())
                .map_err(|e| e.to_string())?;
        }
        if let Some(trailer) = trailer {
            let mut trailers = http::HeaderMap::new();
            trailers.insert("x-note", http::HeaderValue::from_str(trailer).unwrap());
            out.send_trailers(trailers).map_err(|e| e.to_string())?;
        }
        let response = response.await.map_err(|e| e.to_string())?;
        let mut got = Vec::new();
        let mut incoming = response.into_body();
        while let Some(chunk) = incoming.data().await {
            let chunk = chunk.map_err(|e| e.to_string())?;
            let len = chunk.len();
            got.extend_from_slice(&chunk);
            let _ = incoming.flow_control().release_capacity(len);
        }
        Ok(String::from_utf8_lossy(&got).into_owned())
    }
    .await;
    driving.abort();
    answer
}

/// A chain with a rule in it that nothing will ever match.
///
/// Not the same as no chain at all, and the difference is the whole of what these tests
/// are about: a service with no filters is **bypassed**, and a bypassed connection is
/// carried as bytes rather than terminated, so nothing below would be exercised. Spelling
/// it `""` here passed every assertion while proving nothing about HTTP/2 — which is the
/// class of false green this engine's tests exist to avoid, so it is spelled out.
const LIVE: &str = "block:ZZ-NO-SUCH-BYTES-ZZ";

/// The whole arrangement, for the cases that only need to ask one question.
async fn relay(how: Service, filters: &str) -> (SocketAddr, Arc<Seen>) {
    let (cert, key) = self_signed();
    let (upstream, seen) = spawn_service(&cert, &key, how).await;
    let addr = spawn_proxy(upstream, &cert, &key, filters).await;
    (addr, seen)
}

#[tokio::test]
async fn an_exchange_goes_through() {
    let (addr, _) = relay(Service::Echo, LIVE).await;
    let answer = request(addr, "GET", "/hello", Body::None).await.unwrap();
    assert_eq!(answer, "you asked for /hello and sent 0 bytes: ");
}

/// The whole reason for rendering the exchange: a pattern written against an HTTP request
/// matches one that arrived as an HPACK header block.
#[tokio::test]
async fn a_pattern_matches_the_request_line() {
    let (addr, _) = relay(Service::Echo, "block:GET /admin").await;

    let allowed = request(addr, "GET", "/public", Body::None).await.unwrap();
    assert!(allowed.contains("/public"), "an unrelated request was affected: {allowed}");

    let refused = request(addr, "GET", "/admin", Body::None).await;
    assert!(
        refused.is_err(),
        "a request the chain refused was answered anyway: {refused:?}"
    );
}

/// A header the request did not carry must not appear in what the filters are shown.
///
/// A filter looking for `transfer-encoding` is usually looking for request smuggling, so
/// one invented by the proxy in front of it is the worst possible answer.
#[tokio::test]
async fn a_request_with_no_body_is_shown_no_framing_header() {
    let (addr, _) = relay(Service::Echo, "block:transfer-encoding").await;
    let answer = request(addr, "GET", "/plain", Body::None).await.unwrap();
    assert!(answer.contains("/plain"), "a framing header was invented: {answer}");
}

/// And a body whose length was never declared is shown chunked, because that is what that
/// message is in HTTP/1.1 — so a parser reading the rendering finds a body.
#[tokio::test]
async fn a_body_of_unknown_length_is_shown_chunked() {
    let (addr, _) = relay(Service::Echo, "block:transfer-encoding").await;
    let refused = request(addr, "POST", "/upload", Body::Undeclared(b"anything")).await;
    assert!(
        refused.is_err(),
        "a body with no declared length was shown unframed: {refused:?}"
    );
}

/// A declared length is passed through as it was, and the body shown raw beneath it.
#[tokio::test]
async fn a_declared_length_is_left_alone() {
    let (addr, _) = relay(Service::Echo, "block:transfer-encoding").await;
    let answer = request(addr, "POST", "/upload", Body::Declared(b"declared"))
        .await
        .unwrap();
    assert!(answer.contains("sent 8 bytes"), "the body did not arrive: {answer}");
}

/// Both directions are inspected, and a refused answer does not reach the client.
#[tokio::test]
async fn the_answer_is_inspected_too() {
    let (addr, _) = relay(Service::Echo, "block:FLAG{").await;

    let answer = request(addr, "GET", "/harmless", Body::None).await;
    assert!(answer.is_ok(), "an unrelated exchange was affected: {answer:?}");

    // Nothing in this request carries the needle; everything that does is in the reply.
    let refused = request(addr, "GET", "/secret", Body::None).await;
    match refused {
        Err(_) => {}
        Ok(body) => panic!("the answer reached the client anyway: {body}"),
    }
}

/// A trailer section on a message the rendering can frame is shown to the chain, which is
/// the only reason it may then be forwarded.
///
/// The bodiless case is the one that matters most: a message of HEADERS and TRAILERS and
/// nothing in between is exactly a gRPC trailers-only request, and without a chunked body
/// to hang a trailer section off the rendering would end at the head and the trailers
/// would travel to the far side unread.
#[tokio::test]
async fn a_trailer_section_is_shown_to_the_chain() {
    for (body, what) in [
        (Body::None, "no body at all"),
        (Body::Undeclared(b"harmless"), "a body of undeclared length"),
    ] {
        let (addr, _) = relay(Service::Echo, "block:SNEAKY").await;
        let refused = request_with_trailer(addr, "POST", "/up", body, Some("SNEAKY")).await;
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
#[tokio::test]
async fn a_trailer_the_rendering_cannot_carry_is_not_forwarded() {
    let (addr, seen) = relay(Service::Echo, LIVE).await;
    let answer =
        request_with_trailer(addr, "POST", "/up", Body::Declared(b"harmless"), Some("SNEAKY")).await;
    assert!(answer.is_ok(), "the exchange was disturbed: {answer:?}");
    assert!(
        seen.trailers.lock().unwrap().is_empty(),
        "a trailer section no filter was shown reached the service: {:?}",
        seen.trailers.lock().unwrap()
    );

    // Without the declared length the same trailers are renderable, so they are shown and
    // then carried: the rule is what the chain saw, not a dislike of trailers.
    let (addr, seen) = relay(Service::Echo, LIVE).await;
    let answer = request_with_trailer(
        addr,
        "POST",
        "/up",
        Body::Undeclared(b"harmless"),
        Some("SNEAKY"),
    )
    .await;
    assert!(answer.is_ok(), "the exchange was disturbed: {answer:?}");
    assert_eq!(
        seen.trailers.lock().unwrap().as_slice(),
        ["x-note=SNEAKY"],
        "a trailer section the chain accepted was dropped anyway"
    );
}

/// An exchange the service is supposed to speak first in is not held waiting for a body.
///
/// The head is held only until the framing is known, and a client that sends a head and
/// then waits to be answered — a bidirectional RPC, gRPC's among them — never sends one.
/// Holding it there deadlocks the exchange: the proxy waiting for a body, the client
/// waiting for the answer that would tell it what to send.
#[tokio::test]
async fn a_service_that_speaks_first_is_not_waited_out() {
    let (addr, _) = relay(Service::Eager, LIVE).await;
    let (mut sender, driving) = connect(addr).await.unwrap();

    let outgoing = http::Request::builder()
        .method("POST")
        .uri("https://localhost/stream")
        .body(())
        .unwrap();
    // Deliberately no body and no end of stream: this client is waiting to be spoken to.
    let (response, _out) = sender.send_request(outgoing, false).unwrap();
    let answered = tokio::time::timeout(Duration::from_secs(5), response).await;
    driving.abort();
    assert!(
        answered.is_ok(),
        "the head never reached a service that answers without waiting for a body"
    );
    assert_eq!(answered.unwrap().unwrap().status(), 200);
}

/// A head that is the whole message goes out as one, and does not grow a body on the way.
///
/// This is the case HTTP/3 could not get wrong and HTTP/2 can: the end of a message rides
/// on its last frame, so sending the head open and closing it with an empty DATA frame
/// turns a *trailers-only* answer into a message with a body. That is precisely the shape
/// of a gRPC status-only reply, and gRPC clients refuse the mangled version.
#[tokio::test]
async fn a_head_that_ends_the_message_stays_that_way() {
    let (addr, _) = relay(Service::TrailersOnly, LIVE).await;
    let (mut sender, driving) = connect(addr).await.unwrap();

    let outgoing = http::Request::builder()
        .method("POST")
        .uri("https://localhost/rpc")
        .header("content-type", "application/grpc")
        .body(())
        .unwrap();
    let (response, _out) = sender.send_request(outgoing, true).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("the answer never arrived")
        .expect("the answer was an error");
    assert_eq!(response.headers().get("grpc-status").unwrap(), "5");
    let mut body = response.into_body();
    assert!(
        body.is_end_stream(),
        "a head-only answer reached the client with a body attached to it"
    );
    assert!(
        body.data().await.is_none(),
        "an empty DATA frame was invented on the way through"
    );
    driving.abort();
}

/// Concurrent streams on one connection are separate connections to the chain.
///
/// On HTTP/1.1 a keep-alive connection carries its requests one after another, so one set
/// of filter state is the honest answer. HTTP/2 interleaves them, and a filter whose state
/// was shared between two streams would be one client's bytes deciding another client's
/// verdict — which is also a way to smuggle a pattern past a filter by splitting it across
/// two streams. Here half a needle goes up each of two concurrent streams; neither may
/// block.
#[tokio::test]
async fn concurrent_streams_do_not_share_filter_state() {
    let (addr, _) = relay(Service::Echo, "block:NEEDLEHALVES").await;
    let (mut sender, driving) = connect(addr).await.unwrap();

    let mut waiting = Vec::new();
    for half in ["NEEDLE", "HALVES"] {
        let outgoing = http::Request::builder()
            .method("POST")
            .uri("https://localhost/split")
            .body(())
            .unwrap();
        let (response, mut out) = sender.send_request(outgoing, false).unwrap();
        out.send_data(Bytes::from(half), true).unwrap();
        waiting.push(response);
    }
    for response in waiting {
        let answered = tokio::time::timeout(Duration::from_secs(5), response).await;
        assert!(
            matches!(&answered, Ok(Ok(r)) if r.status() == 200),
            "a pattern split across two streams was matched as if they were one: {answered:?}"
        );
    }
    driving.abort();
}

/// And one connection really does carry them at the same time.
#[tokio::test]
async fn one_connection_carries_many_streams() {
    let (addr, seen) = relay(Service::Echo, LIVE).await;
    let (mut sender, driving) = connect(addr).await.unwrap();

    let mut waiting = Vec::new();
    for n in 0..8 {
        let outgoing = http::Request::builder()
            .method("GET")
            .uri(format!("https://localhost/n{n}"))
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(outgoing, true).unwrap();
        waiting.push((n, response));
    }
    for (n, response) in waiting {
        let response = tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .expect("an answer never arrived")
            .expect("an answer was an error");
        let mut body = response.into_body();
        let mut got = Vec::new();
        while let Some(Ok(chunk)) = body.data().await {
            let len = chunk.len();
            got.extend_from_slice(&chunk);
            let _ = body.flow_control().release_capacity(len);
        }
        let got = String::from_utf8_lossy(&got).into_owned();
        assert!(
            got.contains(&format!("/n{n}")),
            "two streams of one connection were mixed up: {got}"
        );
    }
    driving.abort();
    assert_eq!(seen.requests.load(Ordering::Relaxed), 8);
}

/// A refusal ends the connection carrying it, not just the stream.
///
/// Resetting one stream would leave the client free to ask again on the next, which is not
/// what a block means anywhere else in firegex — and on HTTP/1.1 keep-alive a refused
/// request already takes the connection with it.
#[tokio::test]
async fn a_refusal_ends_the_connection() {
    let (addr, _) = relay(Service::Echo, "block:GET /admin").await;
    let (mut sender, driving) = connect(addr).await.unwrap();

    let refused = http::Request::builder()
        .method("GET")
        .uri("https://localhost/admin")
        .body(())
        .unwrap();
    let (response, _) = sender.send_request(refused, true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), response).await;

    // The connection is gone, so a second request on it cannot be answered — whether it is
    // refused outright or simply never answered.
    let again = http::Request::builder()
        .method("GET")
        .uri("https://localhost/public")
        .body(())
        .unwrap();
    let answered = match sender.send_request(again, true) {
        Err(_) => None,
        Ok((response, _)) => tokio::time::timeout(Duration::from_secs(2), response)
            .await
            .ok()
            .and_then(|r| r.ok()),
    };
    driving.abort();
    assert!(
        answered.is_none(),
        "a connection whose stream was refused went on answering: {answered:?}"
    );
}

/// A service with no filters is carried as bytes, and that is deliberate.
///
/// Rendering an exchange for a chain that has nothing to say is work paid for no answer,
/// so a bypassed chain — a service with no filters, or one whose filters have all been
/// disabled, or a connection admitted past the limit with `over_limit_forwards` — takes
/// the byte pump instead. The visible consequence is that nothing is dropped, filtered or
/// rendered, which this pins with the one case that can tell the two paths apart: a
/// trailer section on a message of declared length, which a terminated connection drops
/// and a forwarded one carries.
///
/// The cost of the trade is that a connection admitted while the chain was empty stays a
/// byte pump for its whole life, even if a filter is pushed a moment later.
#[tokio::test]
async fn an_empty_chain_is_carried_as_bytes() {
    let (addr, seen) = relay(Service::Echo, "").await;
    let answer =
        request_with_trailer(addr, "POST", "/up", Body::Declared(b"harmless"), Some("SNEAKY")).await;
    assert!(answer.is_ok(), "the exchange was disturbed: {answer:?}");
    assert_eq!(
        seen.trailers.lock().unwrap().as_slice(),
        ["x-note=SNEAKY"],
        "an unfiltered connection was terminated and rendered anyway"
    );
}

/// HTTP/2 in the clear is rendered too, which is how most gRPC is actually deployed.
///
/// A `tcp` service with no TLS anywhere: the client opens with the connection preface and
/// the proxy recognises it. Without this the exchange is HPACK on the wire and nothing in
/// the chain can read it — the same silence the TLS path had, on the layer where a gRPC
/// service behind a load balancer usually lives.
#[tokio::test]
async fn cleartext_http2_is_rendered_as_well() {
    let (upstream, _) = spawn_cleartext_service(Service::Echo).await;
    let addr = spawn_plain_proxy(upstream, "block:GET /admin").await;

    let (mut sender, driving) = connect_cleartext(addr).await.unwrap();
    let outgoing = http::Request::builder()
        .method("GET")
        .uri("http://localhost/public")
        .body(())
        .unwrap();
    let (response, _) = sender.send_request(outgoing, true).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("no answer came back")
        .expect("the answer was an error");
    assert_eq!(response.status(), 200);
    driving.abort();

    // And the pattern matches a request line that was HPACK on the wire.
    let (mut sender, driving) = connect_cleartext(addr).await.unwrap();
    let outgoing = http::Request::builder()
        .method("GET")
        .uri("http://localhost/admin")
        .body(())
        .unwrap();
    let (response, _) = sender.send_request(outgoing, true).unwrap();
    let answered = tokio::time::timeout(Duration::from_secs(5), response).await;
    driving.abort();
    assert!(
        !matches!(&answered, Ok(Ok(_))),
        "a cleartext HTTP/2 request the chain refused was answered anyway: {answered:?}"
    );
}

/// Looking for the preface must not make a service that speaks first wait for it.
///
/// This is the trap the whole sniff is arranged around: SMTP, SSH and most game protocols
/// send a banner before the client says anything, and a proxy that holds the connection
/// until the client speaks breaks all of them in a way that looks random. The service
/// having spoken is proof this is not a prior-knowledge HTTP/2 client, so the banner is
/// what ends the wait.
#[tokio::test]
async fn a_banner_service_is_not_held_by_the_preface_check() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let _ = sock.write_all(b"220 service ready\r\n").await;
                let _ = sock.flush().await;
                // Held open, as a real banner protocol would, so the test is about the
                // banner arriving and not about the connection ending.
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    let addr = spawn_plain_proxy(upstream, LIVE).await;

    let mut sock = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 19];
    let banner = tokio::time::timeout(Duration::from_millis(200), async {
        use tokio::io::AsyncReadExt;
        sock.read_exact(&mut buf).await
    })
    .await;
    assert!(
        matches!(banner, Ok(Ok(_))),
        "a service that speaks first was held waiting for an HTTP/2 preface: {banner:?}"
    );
    assert_eq!(&buf[..], b"220 service ready\r\n");
}

/// And a plain HTTP/1.1 client is not mistaken for one, nor delayed by the check.
#[tokio::test]
async fn cleartext_http1_is_not_mistaken_for_http2() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 1024];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let seen = String::from_utf8_lossy(&buf[..n]).into_owned();
                let body = format!("saw {} bytes", seen.len());
                let _ = sock
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    let addr = spawn_plain_proxy(upstream, LIVE).await;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"GET /plain HTTP/1.1\r\nhost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
        .await
        .expect("an HTTP/1.1 client was left waiting by the preface check")
        .unwrap();
    let answer = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(
        answer.starts_with("HTTP/1.1 200"),
        "a plain HTTP/1.1 exchange was disturbed: {answer}"
    );
}

/// One relay, one certificate, one chain — carrying the clear and the encrypted alike.
///
/// This is what an `http` service is: a daemon answering in the clear on one port and
/// under TLS on another used to need two firegex services with their filter chains copied
/// between them by hand, and a chain kept in step by hand is one that stops protecting one
/// of them silently. The edge is decided per connection, from what the client actually
/// sent, which is the same rule the ALPN mirroring follows — firegex carries what the two
/// ends are doing rather than deciding it for them.
#[tokio::test]
async fn optional_tls_carries_both_edges_through_one_chain() {
    let (cert, key) = self_signed();
    // Two services, because a real daemon listens twice: one socket in the clear and one
    // under TLS. One relay in front of both.
    let (encrypted, _) = spawn_service(&cert, &key, Service::Echo).await;
    let (cleartext, _) = spawn_cleartext_service(Service::Echo).await;

    for (upstream, tls_on_the_wire) in [(encrypted, true), (cleartext, false)] {
        let chain = ChainHandle::new(FilterChain::new(
            parse_filters("block:GET /admin").unwrap(),
            Duration::from_millis(500),
        ));
        let mut cfg = ProxyConfig::fixed("127.0.0.1:0".parse().unwrap(), upstream);
        cfg.tls = TlsSetup {
            server: Some(tls::server_config(&cert, &key).unwrap()),
            upstream: Some(tls::client_config().unwrap()),
            optional: true,
        };
        let proxy = Proxy::bind(cfg, chain).await.unwrap();
        let addr = proxy.local_addr().unwrap();
        tokio::spawn(proxy.serve());

        let open = |addr| async move {
            if tls_on_the_wire {
                connect(addr).await
            } else {
                connect_cleartext(addr).await
            }
        };

        let (mut sender, driving) = open(addr).await.unwrap();
        let outgoing = http::Request::builder()
            .method("GET")
            .uri("https://localhost/public")
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(outgoing, true).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .unwrap_or_else(|_| panic!("no answer on the {} edge", edge(tls_on_the_wire)))
            .unwrap_or_else(|e| panic!("the {} edge answered an error: {e}", edge(tls_on_the_wire)));
        assert_eq!(response.status(), 200);
        driving.abort();

        // And the one chain refuses on both, which is the whole point of one service.
        let (mut sender, driving) = open(addr).await.unwrap();
        let outgoing = http::Request::builder()
            .method("GET")
            .uri("https://localhost/admin")
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(outgoing, true).unwrap();
        let answered = tokio::time::timeout(Duration::from_secs(5), response).await;
        driving.abort();
        assert!(
            !matches!(&answered, Ok(Ok(_))),
            "the {} edge answered a request the chain refused: {answered:?}",
            edge(tls_on_the_wire)
        );
    }
}

fn edge(tls: bool) -> &'static str {
    if tls {
        "TLS"
    } else {
        "cleartext"
    }
}

/// A cleartext **HTTP/1.1** service, which is what most of the web is.
async fn spawn_http1_service(seen: Arc<Mutex<Vec<String>>>) -> SocketAddr {
    spawn_http1_service_answering(
        seen,
        b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello",
    )
    .await
}

/// The same, answering with whatever head and body it is given.
async fn spawn_http1_service_answering(
    seen: Arc<Mutex<Vec<String>>>,
    answer: &'static [u8],
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 8192];
                let read = match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..read]).to_string());
                let _ = socket.write_all(answer).await;
            });
        }
    });
    addr
}

/// The engine terminating HTTP/2 from the client in front of an HTTP/1.1 service.
async fn spawn_proxy_to_http1(
    upstream: SocketAddr,
    cert: &str,
    key: &str,
    filters: &str,
) -> SocketAddr {
    use fgex_proxy::proxy::{Edge, Onward, Published};
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
    // What the address says: the service behind it speaks HTTP/1.1 in the clear, whatever
    // the client brought. That is the whole of what makes this edge different.
    cfg.targets.publish(
        upstream,
        Published { target: None, edge: Edge::Whatever, upstream: Onward::Plain },
    );
    let proxy = Proxy::bind(cfg, chain).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());
    addr
}

#[tokio::test]
async fn http2_is_carried_to_a_service_that_speaks_http1() {
    // The deployment an operator actually has: an ordinary cleartext web service, reached
    // over HTTP/2 with only firegex holding a certificate. It was reachable over HTTP/3
    // long before it was reachable over HTTP/2 — same rendering underneath, and the TLS
    // edge simply had nobody to copy an ALPN from, so it answered nothing and every
    // client fell back to HTTP/1.1.
    let (cert, key) = self_signed();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let service = spawn_http1_service(Arc::clone(&seen)).await;
    let proxy = spawn_proxy_to_http1(service, &cert, &key, LIVE).await;

    let answer = request(proxy, "GET", "/files/ok", Body::None).await.unwrap();
    assert!(answer.contains("hello"), "the answer did not come back: {answer}");

    // And what the service was handed is HTTP/1.1 — the same bytes the chain was shown,
    // which is what makes this a forward rather than a translation invented here.
    let arrived = seen.lock().unwrap().clone();
    assert_eq!(arrived.len(), 1, "the service saw {} requests", arrived.len());
    assert!(
        arrived[0].starts_with("GET /files/ok HTTP/1.1\r\n"),
        "the service was not spoken to in HTTP/1.1: {:?}",
        arrived[0]
    );
}

/// What an HTTP/1.1 service actually answers with: a body of unknown length sent chunked,
/// and a connection it offers to keep open. Both are headers about *that* connection,
/// which HTTP/2 forbids outright — the h2 crate refuses to send a response carrying one —
/// so they were passed through and every such answer failed on its way to the client.
#[tokio::test]
async fn an_http1_answer_is_relayed_without_its_connection_headers() {
    let (cert, key) = self_signed();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let service = spawn_http1_service_answering(
        Arc::clone(&seen),
        b"HTTP/1.1 200 OK\r\nconnection: keep-alive\r\nkeep-alive: timeout=5\r\n\
          content-type: text/plain\r\ntransfer-encoding: chunked\r\n\r\n\
          5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
    let proxy = spawn_proxy_to_http1(service, &cert, &key, LIVE).await;

    let answer = request(proxy, "GET", "/files/ok", Body::None).await;
    assert!(
        answer.as_deref().is_ok_and(|a| a.contains("hello")),
        "a chunked keep-alive answer did not reach an HTTP/2 client: {answer:?}"
    );
}

/// One client connection is one connection to the limit, and each of its streams is an
/// exchange of its own — towards an HTTP/1.1 service, a connection of its own. With no cap
/// on concurrent streams, one client could open as many connections to the service as it
/// liked past `max_connections`.
#[tokio::test]
async fn one_client_connection_cannot_open_the_service_a_thousand_times() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let service = listener.local_addr().unwrap();
    let open = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let most = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let (open, most) = (Arc::clone(&open), Arc::clone(&most));
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let (open, most) = (Arc::clone(&open), Arc::clone(&most));
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    // Counted from the request, not from the accept: a connection that
                    // closes without asking anything is not one the service is serving.
                    let mut buf = [0u8; 4096];
                    if !matches!(socket.read(&mut buf).await, Ok(n) if n > 0) {
                        return;
                    }
                    let now = open.fetch_add(1, Ordering::SeqCst) + 1;
                    most.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    // Counted down before answering: once the answer is out the stream
                    // can end and the client open the next, before this task resumes.
                    open.fetch_sub(1, Ordering::SeqCst);
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                        .await;
                });
            }
        });
    }
    let (cert, key) = self_signed();
    let proxy = spawn_proxy_to_http1(service, &cert, &key, LIVE).await;

    let (sender, driving) = connect(proxy).await.unwrap();
    let mut asked = Vec::new();
    for _ in 0..250 {
        let sender = sender.clone();
        asked.push(tokio::spawn(async move {
            let mut sender = sender.ready().await.map_err(|e| e.to_string())?;
            let outgoing = http::Request::builder()
                .method("GET")
                .uri("https://localhost/")
                .body(())
                .map_err(|e| e.to_string())?;
            let (response, _) = sender.send_request(outgoing, true).map_err(|e| e.to_string())?;
            response.await.map_err(|e| e.to_string()).map(|_| ())
        }));
    }
    for one in asked {
        let _ = tokio::time::timeout(Duration::from_secs(20), one).await;
    }
    driving.abort();
    let most = most.load(Ordering::SeqCst);
    assert!(most > 0, "nothing reached the service at all");
    assert!(most <= 100, "one client connection held {most} connections to the service open");
}

/// A head is bounded: the h2 crate's own limit is 16 MiB, a hundred streams to a
/// connection. Well past what services accept, though — a large head is still carried.
#[tokio::test]
async fn a_head_past_the_limit_is_refused_over_http2() {
    let (addr, seen) = relay(Service::Echo, LIVE).await;
    let ask = |size: usize| async move {
        let (mut sender, driving) = connect(addr).await?;
        let answer = async {
            let outgoing = http::Request::builder()
                .method("GET")
                .uri("https://localhost/who")
                .header("x-big", "a".repeat(size))
                .body(())
                .map_err(|e| e.to_string())?;
            let (response, _) = sender.send_request(outgoing, true).map_err(|e| e.to_string())?;
            response.await.map_err(|e| e.to_string()).map(|r| r.status().as_u16())
        }
        .await;
        driving.abort();
        answer
    };
    assert_eq!(ask(256 * 1024).await, Ok(200), "a 256 KiB head was refused");
    let answered = seen.requests.load(Ordering::Relaxed);
    let refused = tokio::time::timeout(Duration::from_secs(10), ask(2 * 1024 * 1024))
        .await
        .expect("an oversized head was left hanging");
    // The crate answers `431 Request Header Fields Too Large` itself, as RFC 9113 suggests.
    assert!(!matches!(refused, Ok(200)), "a 2 MiB head was carried: {refused:?}");
    assert_eq!(seen.requests.load(Ordering::Relaxed), answered, "it reached the service");
}

#[tokio::test]
async fn a_pattern_blocks_over_http2_in_front_of_http1() {
    // The promise the rendering exists for, on the edge that just gained it: one filter,
    // written once, refusing the same request whatever version carried it.
    let (cert, key) = self_signed();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let service = spawn_http1_service(Arc::clone(&seen)).await;
    let proxy = spawn_proxy_to_http1(service, &cert, &key, "block:/secret").await;

    let refused = request(proxy, "GET", "/secret", Body::None).await;
    assert!(refused.is_err(), "the request was carried: {refused:?}");
    assert!(
        seen.lock().unwrap().is_empty(),
        "the refused request reached the service anyway"
    );
}

/// One request with an explicit `host` header beside its `:authority`, and what came back.
async fn request_with_host(addr: SocketAddr, host: &str) -> Result<String, String> {
    let (mut sender, driving) = connect(addr).await?;
    let answer = async {
        let outgoing = http::Request::builder()
            .method("GET")
            .uri("https://localhost/who")
            .header("host", host)
            .body(())
            .map_err(|e| e.to_string())?;
        let (response, _) = sender.send_request(outgoing, true).map_err(|e| e.to_string())?;
        let response = response.await.map_err(|e| e.to_string())?;
        let mut got = Vec::new();
        let mut incoming = response.into_body();
        while let Some(chunk) = incoming.data().await {
            let chunk = chunk.map_err(|e| e.to_string())?;
            let len = chunk.len();
            got.extend_from_slice(&chunk);
            let _ = incoming.flow_control().release_capacity(len);
        }
        Ok(String::from_utf8_lossy(&got).into_owned())
    }
    .await;
    driving.abort();
    answer
}

/// A `host` header that disagrees with `:authority` is malformed, and never reaches the
/// service.
///
/// The chain is shown one `Host` line and the service is handed the request as it came,
/// and an HTTP/2 service routes on `:authority`. So `:authority: admin.internal` beside
/// `host: public.example` showed every filter the public host while the request went to
/// the admin one — a rule written against the admin host walked straight past.
#[tokio::test]
async fn a_host_that_disagrees_with_the_authority_is_refused() {
    let (addr, seen) = relay(Service::Echo, LIVE).await;

    let agreeing = request_with_host(addr, "localhost").await;
    assert!(agreeing.is_ok(), "a host agreeing with :authority was refused: {agreeing:?}");
    let answered = seen.requests.load(Ordering::Relaxed);

    let disagreeing = request_with_host(addr, "admin.internal").await;
    assert!(disagreeing.is_err(), "a disagreeing host was carried: {disagreeing:?}");
    assert_eq!(
        seen.requests.load(Ordering::Relaxed),
        answered,
        "the service answered a request the filters were shown under another host"
    );
}
