//! HTTP/2, terminated by the engine — and shown to the filters as HTTP/1.1.
//!
//! The rendering lives in [`crate::http1`]; what is here is the adapter, and the reason it
//! exists is the same one that put [`crate::h3`] there. HTTP/2 puts the method, the path
//! and the headers in an **HPACK-compressed** HEADERS frame, so a connection that
//! negotiated `h2` and was only forwarded showed a filter a compression format: a pattern
//! written against a request line matched nothing, and a filter asking for an
//! `HttpRequest` was handed the `PRI * HTTP/2.0` preface — parsed as one fictitious
//! request — and then frames it could not read, so it was never called again. No block, no
//! log, no counter: the exact failure everything else in this engine is arranged against.
//! Only a body travelled in the clear. Since gRPC *is* HTTP/2, that also meant gRPC could
//! not be filtered at all.
//!
//! Unlike QUIC, terminating was never forced here — the bytes are framed by a transport
//! the kernel understands, and firegex could have gone on forwarding them. It is forced by
//! the promise instead: a filter written once has to work everywhere, and there is no way
//! to keep that promise over HPACK without decompressing it, which is what parsing HTTP/2
//! means.
//!
//! Three things differ from h3 and are worth stating, because each of them is a way to get
//! this wrong:
//!
//! * **Flow control is ours to run.** `h2` hands received bytes over and waits for them to
//!   be released; a proxy that releases on read has no backpressure and buffers whatever
//!   the faster side sends, and one that never releases stalls after the first window. So
//!   capacity is released **after the piece has been forwarded**, which is what makes the
//!   window follow the service rather than this process, and outbound writes reserve
//!   capacity first rather than queueing in memory.
//! * **The end of a message rides on its last frame**, not on a separate close. A response
//!   of head-and-nothing-else must be sent with `end_of_stream` **on the head**: send it
//!   open and then close it with an empty DATA frame and a *trailers-only* answer stops
//!   being one — which is precisely the shape of a gRPC status-only reply, and gRPC
//!   clients refuse it. [`head_is_the_message`] is the one place that decision is made,
//!   for both directions.
//! * **A stream is a connection to the chain**, which on HTTP/1.1 it is not. There a
//!   keep-alive connection carries many requests through one set of filter state; here the
//!   streams are concurrent and interleaved, and sharing state between them is exactly
//!   "one client's bytes deciding another client's verdict" — the thing [`ChainSessions`]
//!   exists to prevent. So an h2 stream gets its own, as an h3 request stream does.
//!
//! **Server push is not carried, and the service is told so in the handshake**
//! (`enable_push(false)`) rather than having its pushes dropped — the same courtesy the
//! QUIC edge pays about datagrams. **Extended CONNECT is not advertised**, and a plain
//! `CONNECT` stream is refused rather than rendered: a tunnel is opaque bytes, and
//! inventing an HTTP/1.1 request for one would be the fabrication this module exists to
//! avoid.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::capture::{Capture, Tap};
use crate::filter::{
    next_connection_id, ChainHandle, ChainSessions, ConnectionId, ConnectionMeta, Direction, L4,
};
use crate::http1::{
    carried, close_body, head_framing, judge, push_body, render_request, render_response, Answer,
    Framing, Incoming, Outbound, OutboundBody, Rendered,
};
use crate::proxy::ProxyStats;

/// How long a refused connection is given to put its GOAWAY on the wire.
///
/// A refusal that simply dropped the socket would reach the client as a truncated TLS
/// stream, which is the peer having to guess — the same reason the byte pumps shut down
/// rather than abort. Bounded, because a peer that has stopped reading must not be able to
/// hold the task open.
const GOAWAY_GRACE: Duration = Duration::from_secs(2);

impl Incoming for h2::RecvStream {
    type Error = h2::Error;

    fn data(&mut self) -> impl std::future::Future<Output = Result<Option<Bytes>, h2::Error>> + Send {
        // Named through the trait's own path rather than `self.data()`: the inherent
        // method has the same name, and which one a bare call resolves to is not something
        // this file should depend on.
        async move { h2::RecvStream::data(self).await.transpose() }
    }

    fn trailers(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Option<http::HeaderMap>, h2::Error>> + Send {
        h2::RecvStream::trailers(self)
    }

    fn release(&mut self, taken: usize) -> Result<(), h2::Error> {
        self.flow_control().release_capacity(taken)
    }

    fn ended(&self) -> bool {
        self.is_end_stream()
    }
}

/// HTTP/2 towards the service, which is what an HTTP/2 client edge used to always get.
///
/// A handle to the connection `carry` opened, cloned per stream — which is what HTTP/2
/// multiplexing is, and why this is a clone rather than a dial.
#[derive(Clone)]
pub(crate) struct H2Upstream(h2::client::SendRequest<Bytes>);

impl Outbound for H2Upstream {
    type Error = io::Error;
    type Body = H2Send;
    type Answer = H2Recv;

    async fn open(
        &mut self,
        request: http::Request<()>,
        ends_it: bool,
    ) -> io::Result<(Self::Body, Self::Answer)> {
        // The parts travel as they arrived; only the version is restated, because what
        // goes out is HTTP/2 again.
        let (mut parts, _) = request.into_parts();
        parts.version = http::Version::HTTP_2;
        let (response, to_service) = self
            .0
            .send_request(http::Request::from_parts(parts, ()), ends_it)
            .map_err(io::Error::other)?;
        Ok((
            H2Send { inner: to_service, done: ends_it },
            H2Recv { pending: Some(response), body: None, trailers: None },
        ))
    }
}

/// The request body on its way to the service, over HTTP/2.
pub(crate) struct H2Send {
    inner: h2::SendStream<Bytes>,
    /// Whether the end of the stream has already gone out. Writing past it is a user
    /// error `h2` reports rather than ignores, and the end can leave on the head, on a
    /// trailer section, or on an empty final frame — three ways to get here once.
    done: bool,
}

impl OutboundBody for H2Send {
    type Error = io::Error;

    async fn data(&mut self, chunk: Bytes) -> io::Result<()> {
        send_body(&mut self.inner, chunk, false).await.map_err(io::Error::other)
    }

    async fn trailers(&mut self, trailers: http::HeaderMap) -> io::Result<()> {
        self.done = true;
        self.inner.send_trailers(trailers).map_err(io::Error::other)
    }

    async fn finish(&mut self) -> io::Result<()> {
        if self.done {
            return Ok(());
        }
        self.done = true;
        self.inner.send_data(Bytes::new(), true).map_err(io::Error::other)
    }
}

/// The service's answer over HTTP/2, read the way every other answer in this engine is.
pub(crate) struct H2Recv {
    pending: Option<h2::client::ResponseFuture>,
    body: Option<h2::RecvStream>,
    trailers: Option<http::HeaderMap>,
}

impl Answer for H2Recv {
    async fn response(&mut self) -> io::Result<http::Response<()>> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| io::Error::other("the answer was already taken"))?;
        let response = pending.await.map_err(io::Error::other)?;
        let (parts, body) = response.into_parts();
        self.body = Some(body);
        Ok(http::Response::from_parts(parts, ()))
    }
}

impl Incoming for H2Recv {
    type Error = io::Error;

    async fn data(&mut self) -> io::Result<Option<Bytes>> {
        let Some(body) = self.body.as_mut() else {
            return Ok(None);
        };
        Incoming::data(body).await.map_err(io::Error::other)
    }

    async fn trailers(&mut self) -> io::Result<Option<http::HeaderMap>> {
        if let Some(trailers) = self.trailers.take() {
            return Ok(Some(trailers));
        }
        let Some(body) = self.body.as_mut() else {
            return Ok(None);
        };
        Incoming::trailers(body).await.map_err(io::Error::other)
    }

    fn release(&mut self, taken: usize) -> io::Result<()> {
        match self.body.as_mut() {
            Some(body) => body.release(taken).map_err(io::Error::other),
            None => Ok(()),
        }
    }

    fn ended(&self) -> bool {
        self.body.as_ref().is_some_and(|body| body.is_end_stream())
    }
}

/// Everything one terminated HTTP/2 connection is carried with.
///
/// Cloned per stream: every field is a handle already, so a clone is a few reference
/// counts and the streams need nothing from each other.
#[derive(Clone)]
pub struct Carriage {
    pub client: SocketAddr,
    pub upstream: SocketAddr,
    pub chain: ChainHandle,
    pub stats: Arc<ProxyStats>,
    /// Where a reconstruction of each stream is written, when anything is listening.
    pub capture: Option<Arc<Capture>>,
    /// How long this connection may say nothing at all. The question is the
    /// *connection's*, exactly as it is on QUIC: a peer that opens twenty streams and
    /// speaks on none is the shape it is there to catch.
    pub first_byte_timeout: Option<Duration>,
}

impl Carriage {
    fn rendered(&self) -> Rendered<'_> {
        Rendered {
            chain: &self.chain,
            stats: &self.stats,
            client: self.client,
            layer: "h2",
        }
    }

    /// Tell the chain about a stream, in the words the rest of the engine uses.
    ///
    /// `L4::Tcp`, with nothing to distinguish it from HTTP/1.1 on the same service — which
    /// is the whole point. An h2 stream is a stream, and it is TCP on the wire, so both
    /// questions the enum answers have the same answer they have one layer up.
    fn open(&self) -> ConnectionId {
        let connection = next_connection_id();
        self.chain.current().connection_opened(
            connection,
            &ConnectionMeta {
                client: self.client,
                server: self.upstream,
                l4: L4::Tcp,
            },
        );
        connection
    }

    /// A reconstruction of one stream, for whoever is watching the capture interface.
    ///
    /// Per stream and not per connection: a stream is what has a beginning, an order and
    /// an end. What it has not got is a port of its own — every stream of one connection
    /// shares the four-tuple — so [`Tap::open_stream`] invents one, and the documentation
    /// says so wherever this interface is offered.
    fn tap(&self) -> Option<Arc<Tap>> {
        Tap::open_stream(self.capture.clone(), self.client, self.upstream)
    }
}

/// Ends the whole connection because a rule refused something on one of its streams.
///
/// A refusal ends the connection, not the stream. Resetting one stream of many would leave
/// the client free to ask again on the next, which is not what a block means anywhere else
/// in firegex — and on HTTP/1.1 keep-alive a refused request already takes the connection
/// with it.
#[derive(Clone)]
struct Refusal(Arc<tokio::sync::watch::Sender<bool>>);

impl Refusal {
    fn new() -> (Self, tokio::sync::watch::Receiver<bool>) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        (Self(Arc::new(tx)), rx)
    }

    fn refuse(&self) {
        let _ = self.0.send(true);
    }
}

/// Carry one connection that both ends agreed to speak HTTP/2 on.
pub async fn carry<C, S>(client_io: C, service_io: S, ctx: Carriage) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, driver) = h2::client::Builder::new()
        // Said in the handshake rather than by dropping what arrives: a pushed response
        // this proxy cannot render is one the service should not spend a stream on, and a
        // peer that learns from SETTINGS is better off than one that watches pushes
        // vanish. The same answer the QUIC edge gives about datagrams on h3.
        .enable_push(false)
        .handshake::<_, Bytes>(service_io)
        .await
        .map_err(io::Error::other)?;
    carry_with(client_io, H2Upstream(sender), Some(tokio::spawn(driver)), ctx).await
}

/// Carry an HTTP/2 client in front of a service that speaks **HTTP/1.1**.
///
/// The edge the QUIC side has had all along, arriving here: what the filters are shown is
/// the same HTTP/1.1 rendering either way, so sending that rendering on to the service
/// invents nothing. It is what lets an ordinary cleartext web service be reached over
/// HTTP/2 with only firegex holding a certificate — the deployment that could already be
/// reached over HTTP/3 and, until this existed, not over HTTP/2, for no reason an operator
/// could see.
///
/// No connection driver, because there is no connection: `H1Upstream` dials once per
/// exchange, which is also what keeps two clients' requests off one socket.
pub(crate) async fn carry_to_h1<C>(
    client_io: C,
    upstream: crate::h1up::H1Upstream,
    ctx: Carriage,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    carry_with(client_io, upstream, None, ctx).await
}

async fn carry_with<C, U>(
    client_io: C,
    upstream: U,
    mut driving: Option<tokio::task::JoinHandle<Result<(), h2::Error>>>,
    ctx: Carriage,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: Outbound + Clone + Send + 'static,
{
    // Extended CONNECT is left unadvertised, which is the default: a service that wants
    // WebTransport over HTTP/2 needs a session model this proxy has not got, and
    // advertising it would invite streams whose rendering would be a fabrication. Push is
    // turned off towards the service above, in the same spirit.
    let mut server = h2::server::Builder::new()
        .handshake::<_, Bytes>(client_io)
        .await
        .map_err(io::Error::other)?;

    let (refusal, mut refused) = Refusal::new();

    // Set by the first head that crosses in either direction. A service that answers
    // before its client has spoken satisfies it, exactly as a request would — the
    // deadline is about silence, not about who speaks first.
    let spoken = Arc::new(AtomicBool::new(false));
    let watchdog = ctx.first_byte_timeout.map(|deadline| {
        let spoken = Arc::clone(&spoken);
        let refusal = refusal.clone();
        let stats = Arc::clone(&ctx.stats);
        tokio::spawn(async move {
            tokio::time::sleep(deadline).await;
            if !spoken.load(Ordering::Relaxed) {
                stats.no_first_byte.fetch_add(1, Ordering::Relaxed);
                // Through the same channel a refusal uses, so the connection is wound
                // down with a GOAWAY rather than dropped: a peer dropped mid-stream reads
                // a truncation, and this connection has done nothing to deserve one.
                refusal.refuse();
            }
        })
    });

    // The exchanges already in flight, kept rather than detached. A client winding the
    // connection down leaves `accept()` answering `None` while answers are still owed, and
    // walking away there would cut off the last request of every well-behaved client.
    let mut inflight = tokio::task::JoinSet::new();
    // A refusal and a first-byte deadline both end the connection here rather than
    // letting it run out; the difference between them is in the log, not in what is
    // done about it.
    let mut ended_early = false;

    loop {
        tokio::select! {
            accepted = server.accept() => match accepted {
                Some(Ok((request, respond))) => {
                    let ctx = ctx.clone();
                    let refusal = refusal.clone();
                    let mut sender = upstream.clone();
                    let spoken = Arc::clone(&spoken);
                    inflight.spawn(async move {
                        let connection = ctx.open();
                        let outcome =
                            exchange(&ctx, &refusal, &spoken, connection, request, respond, &mut sender)
                                .await;
                        // Whatever happened, the filter's state for this stream goes — a
                        // refused request and a completed one both end it.
                        ctx.chain.current().connection_closed(connection);
                        if let Err(e) = outcome {
                            eprintln!("[info] [h2] stream ended: {e}");
                        }
                    });
                }
                Some(Err(e)) => {
                    eprintln!("[info] [h2] the client's connection ended: {e}");
                    break;
                }
                // The client is done with the connection, which is the ordinary way out.
                None => break,
            },
            // The service ended its side. Waiting for the client to notice would mean
            // holding a connection that has nowhere to go. Only where there *is* a
            // connection: an HTTP/1.1 upstream opens one per exchange, so there is no
            // shared driver to outlive and nothing to watch here.
            reason = async { driving.as_mut().unwrap().await }, if driving.is_some() => {
                if let Ok(Err(e)) = reason {
                    eprintln!("[info] [h2] the service ended the connection: {e}");
                }
                break;
            }
            _ = refused.changed() => {
                ended_early = true;
                break;
            }
        }
    }

    if ended_early {
        // CANCEL rather than REFUSED_STREAM: the latter tells a client the request was
        // never acted on and may be retried, and a block a client retries past is not a
        // block. The reason reaches the operator through the service log, which is where
        // the filter that refused it is already named.
        server.abrupt_shutdown(h2::Reason::CANCEL);
        // Polled rather than dropped, so the GOAWAY is actually written before the socket
        // goes. Bounded: a peer that has stopped reading must not hold this open.
        let _ = tokio::time::timeout(
            GOAWAY_GRACE,
            std::future::poll_fn(|cx| server.poll_closed(cx)),
        )
        .await;
        // Drained even here, and this is the part that is easy to get wrong: the
        // exchanges still in flight have to *end* rather than be dropped, because ending
        // is what releases the filter state each of them holds — for Python, a whole set
        // of module globals, living in the worker under a connection id that only
        // `connection_closed` frees. Aborting them by dropping the set leaked one of
        // those per stream, on the path an attacker triggers on purpose. They finish
        // immediately: the connection under them is already shut down.
        let _ = tokio::time::timeout(GOAWAY_GRACE, drain(&mut inflight)).await;
    } else {
        // Nothing here is unbounded: every filter an exchange consults runs under the
        // chain's own deadline, and the connection has the socket's. Unbounded on
        // purpose, though — a client winding the connection down leaves answers still
        // owed, and walking away would cut off its last exchange.
        drain(&mut inflight).await;
    }
    drop(upstream);
    if let Some(driving) = driving {
        driving.abort();
    }
    if let Some(watchdog) = watchdog {
        watchdog.abort();
    }
    Ok(())
}

/// Wait for every exchange still in flight to end.
///
/// Ending is what releases what a filter is holding for that stream, so this is not
/// tidiness: a set of exchanges dropped rather than joined leaves their state behind.
async fn drain(inflight: &mut tokio::task::JoinSet<()>) {
    while inflight.join_next().await.is_some() {}
}

/// Whether a message's head is the whole of the message.
///
/// Its own function because getting it wrong is invisible on HTTP/1.1 and fatal on
/// HTTP/2: the end of a message rides on its last frame, so a head that *is* the entire
/// message has to be sent as one. Sending it open and closing with an empty DATA frame
/// turns a trailers-only answer — a gRPC status-only reply is exactly that — into a
/// message with a body, which gRPC clients refuse.
///
/// Three things have to hold together, and the sender is the authority on the third: no
/// first chunk was read, no trailer section is still owed, and the peer really did end its
/// half. The last one is why a `content-length: 0` request stays headers-only through this
/// proxy instead of growing an empty DATA frame it did not have.
fn head_is_the_message<I: Incoming>(
    first: &Option<Bytes>,
    early: &Option<Option<http::HeaderMap>>,
    from: &I,
) -> bool {
    first.is_none() && !matches!(early, Some(Some(_))) && from.ended()
}

/// One request and its answer.
///
/// The two directions are carried **at the same time**, not one after the other, which is
/// the same shape the byte pumps have and for the same reason: a service is allowed to
/// answer before it has read the whole request — a refusal, a redirect, a `413` — and a
/// proxy that insists on finishing the upload first turns that into a stall neither end
/// can explain.
#[allow(clippy::too_many_arguments)]
async fn exchange<O: Outbound>(
    ctx: &Carriage,
    refusal: &Refusal,
    spoken: &AtomicBool,
    connection: ConnectionId,
    request: http::Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    sender: &mut O,
) -> io::Result<()> {
    spoken.store(true, Ordering::Relaxed);
    let (parts, mut from_client) = request.into_parts();
    let head = http::Request::from_parts(parts, ());

    // A tunnel is opaque bytes with no HTTP/1.1 message to render, so it is refused rather
    // than shown to the chain as something it is not. Naming it beats a stream that hangs.
    if head.method() == http::Method::CONNECT {
        eprintln!(
            "[warn] [h2] {}: a CONNECT stream arrived. firegex terminates HTTP/2 to show \
             the filters each exchange as HTTP/1.1, and a tunnel has no such exchange in \
             it, so the stream is refused rather than carried unread.",
            ctx.client
        );
        let mut respond = respond;
        respond.send_reset(h2::Reason::REFUSED_STREAM);
        return Ok(());
    }

    // A request that carries no body must not be shown `transfer-encoding: chunked`, which
    // it never had — a filter looking for that header is usually looking for smuggling,
    // and one invented by the proxy in front of it is the worst possible answer. So the
    // framing is settled before the head is rendered, and settled from as little as will
    // do it.
    let (framing, first, early) = head_framing(&mut from_client, head.headers())
        .await
        .map_err(io::Error::other)?;
    let head_ends_it = head_is_the_message(&first, &early, &from_client);

    // One reconstruction for the exchange, not one per direction: a request and its
    // response are one conversation, which is what they would have been on HTTP/1.1.
    let tap = ctx.tap();
    let rendered = ctx.rendered();

    let mut sessions = ChainSessions::new(connection);
    let mut view = render_request(&head, &framing);
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
        refusal.refuse();
        return Ok(());
    }

    // Only now does the service hear about it, in whatever version it speaks — HTTP/2
    // again where the service speaks it, HTTP/1.1 where the address said the service is a
    // cleartext one. The rendering above is the same either way, which is what makes the
    // second case a forward rather than a translation invented here.
    let (parts, _) = head.into_parts();
    let (mut to_service, from_service) = sender
        .open(http::Request::from_parts(parts, ()), head_ends_it)
        .await
        .map_err(io::Error::other)?;

    if let Some(chunk) = first {
        let len = chunk.len();
        to_service.data(chunk).await.map_err(io::Error::other)?;
        // After the forward, never before: the window that reopens is the one the service
        // has actually taken the bytes off, which is what backpressure means here.
        from_client.release(len).map_err(io::Error::other)?;
    }

    let (asked, answered) = tokio::join!(
        carry_request(
            ctx, refusal, from_client, to_service, framing, sessions, tap.clone(), early,
            head_ends_it,
        ),
        // Its own sessions, the same id: both halves of one exchange are one connection to
        // a filter that keeps state, and each direction keeps its own position in it.
        carry_response(ctx, refusal, spoken, connection, from_service, respond, tap.clone()),
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
    ctx: &Carriage,
    refusal: &Refusal,
    mut from_client: h2::RecvStream,
    mut to_service: B,
    framing: Framing,
    mut sessions: ChainSessions,
    tap: Option<Arc<Tap>>,
    early: Option<Option<http::HeaderMap>>,
    head_ended_it: bool,
) -> io::Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    // The head carried the end of the stream, so this half is already finished. Touching
    // it again would be writing past the end, which `h2` reports as a user error rather
    // than ignoring.
    if head_ended_it {
        return Ok(());
    }
    let rendered = ctx.rendered();
    let trailers = match early {
        // The body was over before the head was rendered, so both were shown to the chain
        // together. Reading either again would be reading past the end of the stream.
        Some(trailers) => trailers,
        None => {
            // A pattern split across two DATA frames is still a pattern, so the session
            // carries on from the head.
            while let Some(chunk) = Incoming::data(&mut from_client)
                .await
                .map_err(io::Error::other)?
            {
                let mut view = Vec::new();
                push_body(&mut view, &chunk, &framing);
                if !judge(&rendered, Direction::ClientToServer, &view, &mut sessions, tap.as_ref())
                    .await
                {
                    refusal.refuse();
                    return Ok(());
                }
                let len = chunk.len();
                to_service.data(chunk).await.map_err(io::Error::other)?;
                from_client.release(len).map_err(io::Error::other)?;
            }
            let trailers = Incoming::trailers(&mut from_client)
                .await
                .map_err(io::Error::other)?;
            let mut tail = Vec::new();
            close_body(&mut tail, &framing, trailers.as_ref());
            if !tail.is_empty()
                && !judge(&rendered, Direction::ClientToServer, &tail, &mut sessions, tap.as_ref())
                    .await
            {
                refusal.refuse();
                return Ok(());
            }
            carried(&rendered, framing, trailers)
        }
    };
    if let Some(trailers) = trailers {
        to_service.trailers(trailers).await.map_err(io::Error::other)?;
    }
    to_service.finish().await.map_err(io::Error::other)
}

/// The answer, rendered and judged the same way.
#[allow(clippy::too_many_arguments)]
async fn carry_response<A: Answer>(
    ctx: &Carriage,
    refusal: &Refusal,
    spoken: &AtomicBool,
    connection: ConnectionId,
    mut from_service: A,
    mut respond: h2::server::SendResponse<Bytes>,
    tap: Option<Arc<Tap>>,
) -> io::Result<()>
where
    <A as Incoming>::Error: std::error::Error + Send + Sync + 'static,
{
    let rendered = ctx.rendered();
    let head = from_service.response().await.map_err(io::Error::other)?;
    spoken.store(true, Ordering::Relaxed);

    let mut sessions = ChainSessions::new(connection);
    // The answer's framing is settled the same way the request's was, and for the second
    // half of the same reason: a service that sends its head and then waits — a streaming
    // RPC, a long poll — must not have that head held here, or the client is waiting for
    // something that is waiting for the client.
    let (framing, first, early) = head_framing(&mut from_service, head.headers())
        .await
        .map_err(io::Error::other)?;
    let head_ends_it = head_is_the_message(&first, &early, &from_service);

    let mut view = render_response(&head, &framing);
    if let Some(chunk) = &first {
        push_body(&mut view, chunk, &framing);
    }
    if let Some(trailers) = early.as_ref() {
        close_body(&mut view, &framing, trailers.as_ref());
    }
    if !judge(&rendered, Direction::ServerToClient, &view, &mut sessions, tap.as_ref()).await {
        refusal.refuse();
        return Ok(());
    }

    let (mut parts, _) = head.into_parts();
    parts.version = http::Version::HTTP_2;
    // `end_of_stream` on the head where the head is the message: a status-only gRPC answer
    // is HEADERS and nothing else, and closing it with an empty DATA frame instead would
    // make it a message with a body that gRPC clients then refuse.
    let mut to_client = respond
        .send_response(http::Response::from_parts(parts, ()), head_ends_it)
        .map_err(io::Error::other)?;

    if let Some(chunk) = first {
        let len = chunk.len();
        send_body(&mut to_client, chunk, false).await.map_err(io::Error::other)?;
        from_service.release(len).map_err(io::Error::other)?;
    }

    if head_ends_it {
        return Ok(());
    }

    let trailers = match early {
        Some(trailers) => trailers,
        None => {
            while let Some(chunk) = Incoming::data(&mut from_service)
                .await
                .map_err(io::Error::other)?
            {
                let mut view = Vec::new();
                push_body(&mut view, &chunk, &framing);
                if !judge(&rendered, Direction::ServerToClient, &view, &mut sessions, tap.as_ref())
                    .await
                {
                    refusal.refuse();
                    return Ok(());
                }
                let len = chunk.len();
                send_body(&mut to_client, chunk, false).await.map_err(io::Error::other)?;
                from_service.release(len).map_err(io::Error::other)?;
            }
            let trailers = Incoming::trailers(&mut from_service)
                .await
                .map_err(io::Error::other)?;
            let mut tail = Vec::new();
            close_body(&mut tail, &framing, trailers.as_ref());
            if !tail.is_empty()
                && !judge(&rendered, Direction::ServerToClient, &tail, &mut sessions, tap.as_ref())
                    .await
            {
                refusal.refuse();
                return Ok(());
            }
            carried(&rendered, framing, trailers)
        }
    };
    finish(&mut to_client, trailers).map_err(io::Error::other)
}

/// End a half of an exchange, with the trailer section it is allowed to carry.
///
/// A message whose head already carried `end_of_stream` is finished, and touching the
/// stream again would be writing past the end of it; `h2` reports that as a user error
/// rather than ignoring it, so the emptiness is checked here rather than at each call.
fn finish(
    to: &mut h2::SendStream<Bytes>,
    trailers: Option<http::HeaderMap>,
) -> Result<(), h2::Error> {
    match trailers {
        Some(trailers) => to.send_trailers(trailers),
        None => to.send_data(Bytes::new(), true),
    }
}

/// Write one piece of a body, taking the window as it opens.
///
/// `send_data` on its own queues whatever it is given inside the connection, so a client
/// that uploads faster than the service reads would be buying memory in this process —
/// which is the resource the connection limit exists to defend. Reserving first and
/// writing what is granted is what turns the far end's window into backpressure on the
/// near one, and it is the other half of releasing capacity only after a forward.
async fn send_body(
    to: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
    end: bool,
) -> Result<(), h2::Error> {
    if data.is_empty() {
        return to.send_data(data, end);
    }
    while !data.is_empty() {
        to.reserve_capacity(data.len());
        let granted = match std::future::poll_fn(|cx| to.poll_capacity(cx)).await {
            Some(granted) => granted?,
            // The far end is gone. Saying so as an error lets the caller wind the
            // exchange down the way every other failure here does.
            None => return to.send_data(data, end),
        };
        if granted == 0 {
            continue;
        }
        let piece = data.split_to(granted.min(data.len()));
        to.send_data(piece, end && data.is_empty())?;
    }
    Ok(())
}
