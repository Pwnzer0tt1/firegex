//! HTTP/3, terminated on top of QUIC — and shown to the filters as HTTP/1.1.
//!
//! The rendering itself lives in [`crate::http1`], which is where the reasoning about it
//! belongs now that HTTP/2 is shown to the chain the same way. What is left here is the
//! adapter: hyperium's `h3` parses and re-encodes the frames, this module decides when to
//! ask the chain and what to do with the answer.
//!
//! Terminating is not a choice on this layer the way it is on TCP. Past its Initial packet
//! QUIC encrypts the frames, the stream boundaries and the packet number, so a layer that
//! only forwards has nothing a filter could be shown. What goes on to the service is
//! HTTP/3 again, re-encoded — the rendering is a view, never a translation the service
//! sees. Unless the operator says the service speaks HTTP/1.1 and nothing else, which is
//! the one place that sentence stops being true and is written down where it is chosen:
//! see [`crate::h1up`].
//!
//! One request is one connection to the chain, which is [`Carrier::open`]'s rule applied
//! to h3: a request stream carries exactly one exchange, so a filter's per-connection
//! state — for Python, a whole set of module globals — lives exactly as long as the
//! request it belongs to.

use std::future::Future;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use h3::error::StreamError;

use crate::capture::Tap;
use crate::filter::{ChainSessions, ConnectionId, Direction};
use crate::http1::{
    carried, close_body, conflicting_authority, connection_specific, head_framing, judge,
    push_body, render_request,
    render_response, Answer,
    Framing, Incoming, Outbound, OutboundBody, Rendered,
};
use crate::quic::{Behind, Carrier};

impl<S, B> Incoming for h3::server::RequestStream<S, B>
where
    S: h3::quic::RecvStream + Send,
    B: Buf + Send,
{
    type Error = StreamError;

    fn data(&mut self) -> impl Future<Output = Result<Option<Bytes>, StreamError>> + Send {
        async move { Ok(self.recv_data().await?.map(collect)) }
    }

    fn trailers(
        &mut self,
    ) -> impl Future<Output = Result<Option<http::HeaderMap>, StreamError>> + Send {
        self.recv_trailers()
    }
}

impl<S, B> Incoming for h3::client::RequestStream<S, B>
where
    S: h3::quic::RecvStream + Send,
    B: Buf + Send,
{
    type Error = StreamError;

    fn data(&mut self) -> impl Future<Output = Result<Option<Bytes>, StreamError>> + Send {
        async move { Ok(self.recv_data().await?.map(collect)) }
    }

    fn trailers(
        &mut self,
    ) -> impl Future<Output = Result<Option<http::HeaderMap>, StreamError>> + Send {
        self.recv_trailers()
    }
}

/// How this connection's exchanges are described to the shared rendering.
fn rendered<'a>(carrier: &'a Carrier) -> Rendered<'a> {
    Rendered {
        chain: &carrier.chain,
        stats: &carrier.stats,
        client: carrier.client,
        layer: "h3",
    }
}

/// The two halves of one h3 request stream, as the shared rendering wants them.
type H3Send = h3::client::RequestStream<
    <h3_quinn::BidiStream<Bytes> as h3::quic::BidiStream<Bytes>>::SendStream,
    Bytes,
>;
type H3Recv = h3::client::RequestStream<
    <h3_quinn::BidiStream<Bytes> as h3::quic::BidiStream<Bytes>>::RecvStream,
    Bytes,
>;

/// HTTP/3 towards the service, which is what every HTTP/3 client edge used to get.
impl Outbound for h3::client::SendRequest<h3_quinn::OpenStreams, Bytes> {
    type Error = StreamError;
    type Body = H3Send;
    type Answer = H3Recv;

    async fn open(
        &mut self,
        request: http::Request<()>,
        // HTTP/3 frames the end of a message on the stream, so nothing has to be said on
        // the head: the body half is finished by the caller when there is none, exactly
        // as it is when there is one. The flag is HTTP/2's problem.
        _ends_it: bool,
    ) -> Result<(Self::Body, Self::Answer), StreamError> {
        // The parts travel as they arrived; only the version is restated, because what
        // goes out is HTTP/3 again.
        let (mut parts, _) = request.into_parts();
        parts.version = http::Version::HTTP_3;
        let stream = self
            .send_request(http::Request::from_parts(parts, ()))
            .await?;
        let (send, recv) = stream.split();
        Ok((send, recv))
    }
}

impl OutboundBody for H3Send {
    type Error = StreamError;

    async fn data(&mut self, chunk: Bytes) -> Result<(), StreamError> {
        self.send_data(chunk).await
    }

    async fn trailers(&mut self, trailers: http::HeaderMap) -> Result<(), StreamError> {
        self.send_trailers(trailers).await
    }

    async fn finish(&mut self) -> Result<(), StreamError> {
        h3::client::RequestStream::finish(self).await
    }
}

impl Answer for H3Recv {
    async fn response(&mut self) -> Result<http::Response<()>, StreamError> {
        self.recv_response().await
    }
}

/// Carry one HTTP/3 connection: accept requests, and forward each one.
///
/// Where they are forwarded *to* is the operator's choice, and the only thing that
/// changes with it is which sender the exchanges are handed. Everything the chain is
/// shown is built by [`crate::http1`] either way — which is the whole reason the choice
/// could be offered at all.
pub(crate) async fn carry(carrier: &Carrier) {
    // **No GREASE, in either direction.** The reserved frame and stream types exist so
    // that implementations keep their handling of unknown extensions honest, which is a
    // worthy thing for a browser to do and is not firegex's to do on somebody's service.
    // Sending them means putting a frame on the wire that the client never sent, and the
    // first real server this was pointed at — aioquic — stopped answering requests
    // entirely because of it: the trailing grease frame left its end-of-stream
    // unreported, so the request was received and never completed. A firewall that
    // breaks the service it is protecting in order to exercise that service's protocol
    // handling has its priorities backwards.
    let mut server = match h3::server::builder()
        .send_grease(false)
        .max_field_section_size(u64::from(crate::http1::MAX_HEAD_BYTES))
        .build(h3_quinn::Connection::new(carrier.peer.clone()))
        .await
    {
        Ok(connection) => connection,
        Err(e) => {
            eprintln!("[info] [h3] the client's HTTP/3 connection did not start: {e}");
            return;
        }
    };

    match carrier.service.clone() {
        Behind::Quic(connection) => {
            let (mut driver, sender) = match h3::client::builder()
                .send_grease(false)
                .build(h3_quinn::Connection::new(connection))
                .await
            {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("[warn] [h3] {} does not speak HTTP/3: {e}", carrier.upstream);
                    carrier.peer.close(0u32.into(), b"the service did not speak HTTP/3");
                    return;
                }
            };
            // The client half of h3 needs something to run its connection: control
            // streams, settings, and the QPACK streams underneath every header block.
            // Without this task nothing upstream ever completes.
            let driving = tokio::spawn(async move { driver.wait_idle().await.to_string() });
            accept_loop(carrier, &mut server, sender, Some(driving)).await;
        }
        // A service that speaks HTTP/1.1 has no connection to run and nothing to keep
        // alive between exchanges: each one dials its own, so there is no driver here
        // and nothing for the loop to watch but the client.
        Behind::Http1(upstream) => accept_loop(carrier, &mut server, upstream, None).await,
    }
}

/// Take requests until the client is done, and let each one run on its own.
async fn accept_loop<O>(
    carrier: &Carrier,
    server: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
    sender: O,
    driving: Option<tokio::task::JoinHandle<String>>,
) where
    O: Outbound + Clone + Send + 'static,
{
    // The requests already in flight, kept rather than detached. A client winding the
    // connection down — a GOAWAY, or simply no more requests — leaves `accept()`
    // answering `None` while answers are still owed, and walking away there would cut
    // off the last exchange of every well-behaved client.
    let mut inflight = tokio::task::JoinSet::new();
    let mut driving = driving;

    loop {
        let accepted = tokio::select! {
            accepted = server.accept() => accepted,
            // The service ended its side. Waiting for the client to notice would mean
            // waiting out the idle timeout with a connection that has nowhere to go.
            // With an HTTP/1.1 service there is no such side to watch — its connections
            // live and die with one exchange — so this arm simply never fires.
            reason = async {
                match driving.as_mut() {
                    Some(driver) => driver.await.ok(),
                    None => std::future::pending().await,
                }
            } => {
                if let Some(reason) = reason {
                    eprintln!("[info] [h3] the service ended the connection: {reason}");
                }
                carrier.peer.close(0u32.into(), b"the service closed the connection");
                break;
            }
        };
        match accepted {
            Ok(Some(resolver)) => {
                let carrier = carrier.clone();
                let mut sender = sender.clone();
                inflight.spawn(async move {
                    let connection = carrier.open();
                    let outcome = exchange(&carrier, connection, resolver, &mut sender).await;
                    // Whatever happened, the filter's state for this request goes — a
                    // refused request and a completed one both end it.
                    carrier.chain.current().connection_closed(connection);
                    if let Err(e) = outcome {
                        eprintln!("[info] [h3] request ended: {e}");
                    }
                });
            }
            // The client is done with the connection, which is the ordinary way out.
            Ok(None) => break,
            Err(e) => {
                eprintln!("[info] [h3] the client's connection ended: {e}");
                break;
            }
        }
    }
    // Nothing here is unbounded: each exchange rides on connections with an idle
    // timeout, and every filter it consults runs under the chain's own deadline.
    while inflight.join_next().await.is_some() {}
    if let Some(driving) = driving {
        driving.abort();
    }
}

/// One request and its answer.
///
/// The two directions are carried **at the same time**, not one after the other, which
/// is the same shape the TCP pumps have and for the same reason: a service is allowed to
/// answer before it has read the whole request — a refusal, a redirect, a `413` — and a
/// proxy that insists on finishing the upload first turns that into a stall neither end
/// can explain.
///
/// Generic over where it is going, and over nothing else: what the chain is shown is the
/// same rendering whatever answers, which is the promise the whole module makes.
async fn exchange<O: Outbound>(
    carrier: &Carrier,
    connection: ConnectionId,
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    sender: &mut O,
) -> io::Result<()> {
    let (request, mut from_client) = resolver.resolve_request().await.map_err(io::Error::other)?;
    carrier.spoken.store(true, Ordering::Relaxed);

    // One authority, or none: the chain is shown one `Host` and the service is handed the
    // request as it came, so two that disagree would be a filter reading one host while
    // the service answers for another. Malformed, and the stream is stopped as such.
    if let Some(why) = conflicting_authority(&request) {
        eprintln!(
            "[warn] [h3] {}: {why}, so the filters would be shown one host while the \
             service routes on the other. The stream is stopped as malformed.",
            carrier.client
        );
        from_client.stop_stream(h3::error::Code::H3_MESSAGE_ERROR);
        return Ok(());
    }
    // Malformed as well (RFC 9114 §4.2), and not refused by the h3 crate: see
    // `connection_specific`. HTTP/2 needs no such line, because h2 refuses them itself.
    if let Some(why) = connection_specific(request.headers()) {
        eprintln!(
            "[warn] [h3] {}: {why}. The stream is stopped as malformed.",
            carrier.client
        );
        from_client.stop_stream(h3::error::Code::H3_MESSAGE_ERROR);
        return Ok(());
    }

    // A request that carries no body must not be shown `transfer-encoding: chunked`,
    // which it never had — a filter looking for that header is usually looking for
    // smuggling, and one invented by the proxy in front of it is the worst possible
    // answer. So the framing is settled before the head is rendered, and settled from
    // as little as will do it.
    let (framing, first, early) = head_framing(&mut from_client, request.headers())
        .await
        .map_err(io::Error::other)?;

    // One reconstruction for the exchange, not one per direction: a request and its
    // response are one conversation, which is what they would have been on TCP.
    let tap = carrier.tap();
    let rendered = rendered(carrier);

    // This direction's filter state, and the head as the chain will see it.
    let mut sessions = ChainSessions::new(connection);
    let mut view = render_request(&request, &framing);
    if let Some(chunk) = &first {
        push_body(&mut view, chunk, &framing);
    }
    // A message that ended with a trailer section and no body is rendered whole here,
    // terminator and trailers included: there is no later chunk to hang them off, and a
    // trailer section shown to nobody is a piece of the message that travelled unread.
    if let Some(trailers) = early.as_ref() {
        close_body(&mut view, &framing, trailers.as_ref());
    }
    if !judge(&rendered, Direction::ClientToServer, &view, &mut sessions, tap.as_ref()).await {
        carrier.refuse();
        return Ok(());
    }

    // Only now does the service hear about it, in whatever version it speaks.
    let (parts, _) = request.into_parts();
    // Whether this head is the whole message. On HTTP/3 the request stream says so the
    // way HTTP/2 does, and the flag only matters to an upstream that has to state it on
    // the head — but it is computed from the same three answers wherever it is asked.
    let ends_it = first.is_none() && !matches!(early, Some(Some(_))) && from_client.ended();
    let (mut to_service, from_service) = sender
        .open(http::Request::from_parts(parts, ()), ends_it)
        .await
        .map_err(io::Error::other)?;
    if let Some(chunk) = first {
        to_service.data(chunk).await.map_err(io::Error::other)?;
    }

    let (to_client, from_client) = from_client.split();

    let (asked, answered) = tokio::join!(
        carry_request(carrier, from_client, to_service, framing, sessions, tap.clone(), early),
        // Its own sessions, the same id: both halves of one exchange are one connection
        // to a filter that keeps state, and each direction keeps its own position in it.
        carry_response(carrier, connection, from_service, to_client, tap.clone()),
    );
    if let Some(tap) = tap {
        tap.closed();
    }
    asked?;
    answered
}

/// The rest of the request body, judged chunk by chunk and forwarded.
#[allow(clippy::too_many_arguments)]
async fn carry_request<B: OutboundBody>(
    carrier: &Carrier,
    mut from_client: h3::server::RequestStream<
        <h3_quinn::BidiStream<Bytes> as h3::quic::BidiStream<Bytes>>::RecvStream,
        Bytes,
    >,
    mut to_service: B,
    framing: Framing,
    mut sessions: ChainSessions,
    tap: Option<Arc<Tap>>,
    early: Option<Option<http::HeaderMap>>,
) -> io::Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let rendered = rendered(carrier);
    let trailers = match early {
        // The body was over before the head was rendered, so both were shown to the chain
        // together. Reading either again would be reading past the end of the stream.
        Some(trailers) => trailers,
        None => {
            // A pattern split across two DATA frames is still a pattern, so the session
            // carries on from the head.
            while let Some(chunk) = from_client.data().await.map_err(io::Error::other)? {
                let mut view = Vec::new();
                push_body(&mut view, &chunk, &framing);
                if !judge(&rendered, Direction::ClientToServer, &view, &mut sessions, tap.as_ref())
                    .await
                {
                    carrier.refuse();
                    return Ok(());
                }
                to_service.data(chunk).await.map_err(io::Error::other)?;
            }
            let trailers = from_client.trailers().await.map_err(io::Error::other)?;
            let mut tail = Vec::new();
            close_body(&mut tail, &framing, trailers.as_ref());
            if !tail.is_empty()
                && !judge(&rendered, Direction::ClientToServer, &tail, &mut sessions, tap.as_ref())
                    .await
            {
                carrier.refuse();
                return Ok(());
            }
            carried(&rendered, framing, trailers)
        }
    };
    if let Some(trailers) = trailers {
        to_service
            .trailers(trailers)
            .await
            .map_err(io::Error::other)?;
    }
    to_service.finish().await.map_err(io::Error::other)
}

/// The answer, rendered and judged the same way.
async fn carry_response<A: Answer>(
    carrier: &Carrier,
    connection: ConnectionId,
    mut from_service: A,
    mut to_client: h3::server::RequestStream<
        <h3_quinn::BidiStream<Bytes> as h3::quic::BidiStream<Bytes>>::SendStream,
        Bytes,
    >,
    tap: Option<Arc<Tap>>,
) -> io::Result<()>
where
    <A as Incoming>::Error: std::error::Error + Send + Sync + 'static,
{
    let rendered = rendered(carrier);
    let response = from_service.response().await.map_err(io::Error::other)?;
    let mut sessions = ChainSessions::new(connection);
    // The answer's framing is settled the same way the request's was, and for the second
    // half of the same reason: a service that sends its head and then waits — a streaming
    // RPC, a long poll — must not have that head held here, or the client is waiting for
    // something that is waiting for the client.
    let (framing, first, early) = head_framing(&mut from_service, response.headers())
        .await
        .map_err(io::Error::other)?;

    let mut view = render_response(&response, &framing);
    if let Some(chunk) = &first {
        push_body(&mut view, chunk, &framing);
    }
    if let Some(trailers) = early.as_ref() {
        close_body(&mut view, &framing, trailers.as_ref());
    }
    if !judge(&rendered, Direction::ServerToClient, &view, &mut sessions, tap.as_ref()).await {
        carrier.refuse();
        return Ok(());
    }

    let (mut parts, _) = response.into_parts();
    parts.version = http::Version::HTTP_3;
    to_client
        .send_response(http::Response::from_parts(parts, ()))
        .await
        .map_err(io::Error::other)?;
    if let Some(chunk) = first {
        to_client.send_data(chunk).await.map_err(io::Error::other)?;
    }
    let trailers = match early {
        Some(trailers) => trailers,
        None => {
            while let Some(chunk) = from_service.data().await.map_err(io::Error::other)? {
                let mut view = Vec::new();
                push_body(&mut view, &chunk, &framing);
                if !judge(&rendered, Direction::ServerToClient, &view, &mut sessions, tap.as_ref())
                    .await
                {
                    carrier.refuse();
                    return Ok(());
                }
                to_client.send_data(chunk).await.map_err(io::Error::other)?;
            }
            let trailers = from_service.trailers().await.map_err(io::Error::other)?;
            let mut tail = Vec::new();
            close_body(&mut tail, &framing, trailers.as_ref());
            if !tail.is_empty()
                && !judge(&rendered, Direction::ServerToClient, &tail, &mut sessions, tap.as_ref())
                    .await
            {
                carrier.refuse();
                return Ok(());
            }
            carried(&rendered, framing, trailers)
        }
    };
    if let Some(trailers) = trailers {
        to_client
            .send_trailers(trailers)
            .await
            .map_err(io::Error::other)?;
    }
    to_client.finish().await.map_err(io::Error::other)
}

/// One DATA frame's bytes, however many pieces the parser had them in.
fn collect(mut buf: impl Buf) -> Bytes {
    let len = buf.remaining();
    buf.copy_to_bytes(len)
}
