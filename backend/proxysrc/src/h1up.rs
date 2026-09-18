//! Speaking HTTP/1.1 to the service, under an edge that is not HTTP/1.1.
//!
//! Everything else in this engine forwards to the service in the version the client
//! arrived in: the rendering is a view shown to the filters, never a translation the
//! service sees. This module is the one exception, and it is the operator's to ask for
//! (`FGEX_PROXY_UPSTREAM`): an ordinary web service that speaks HTTP/1.1 and nothing else
//! can be put behind an HTTP/3 edge, with firegex terminating QUIC in front of it.
//!
//! **Half of it is free and half of it needed a crate.** The request direction is already
//! done by the time it gets here — [`crate::http1`] renders every exchange as the HTTP/1.1
//! it would have been, because that is what the chain has to be shown, so putting those
//! same bytes on a socket invents nothing. The *answer* is what could not be done: HTTP/1.1
//! is the one version this engine has never parsed. An HTTP/1.1 connection elsewhere is a
//! byte pump — the filters look at bytes, and what parses them is the library on the Python
//! side — so there was no response parser to reach for, and writing one beside hyper's is
//! exactly what `AGENTS.md` forbids. So the answer comes back through hyper's client, and
//! this module is a binding: framing, chunked encoding and keep-alive are the crate's
//! problem.
//!
//! **One connection per exchange.** HTTP/1.1 has no multiplexing, and the edge above does:
//! a QUIC stream is one request, so it gets one upstream connection of its own, dialled
//! from the client's own address like every other dial this engine makes. Pooling would
//! put two clients' requests on one socket, and with it the thing `ChainSessions` exists
//! to prevent — one client's bytes deciding another's verdict — at a layer where nobody
//! would think to look for it.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;

use crate::http1::{Answer, Incoming, Outbound, OutboundBody};

/// The body of a request being written piece by piece into hyper.
///
/// hyper takes a body as one value and pulls from it; the chain produces pieces as it
/// accepts them. A channel is the join between the two, and its bound is what keeps a
/// fast client from buying memory in this process while a slow service reads.
struct Streamed {
    rx: tokio::sync::mpsc::Receiver<http_body::Frame<Bytes>>,
}

impl http_body::Body for Streamed {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        self.get_mut().rx.poll_recv(cx).map(|frame| frame.map(Ok))
    }
}

/// How many pieces of one request may be waiting for the service at once.
const IN_FLIGHT: usize = 8;

/// How this engine reaches a service that speaks HTTP/1.1.
///
/// Dial parameters and nothing else: there is no connection here, because each exchange
/// opens its own. Cloned per exchange the way the HTTP/3 sender above it is.
#[derive(Clone)]
pub(crate) struct H1Upstream {
    pub(crate) upstream: SocketAddr,
    /// Dialled as this address, so the service sees the real client. The same
    /// unconditional source preservation every other dial here makes.
    pub(crate) client: SocketAddr,
    /// Present when the service speaks TLS: the client half of the handshake.
    pub(crate) tls: Option<Arc<rustls::ClientConfig>>,
    pub(crate) connect_timeout: Duration,
    pub(crate) self_mark: Option<u32>,
    /// Dial as the client. Off is the fallback the TCP path also has, and it is here for
    /// the same reason: a service seeing one source address for everyone is a regression
    /// nobody would attribute to us.
    pub(crate) spoof: bool,
}

impl H1Upstream {
    async fn connect(&self) -> io::Result<tokio::net::TcpStream> {
        if !self.spoof {
            return tokio::time::timeout(
                self.connect_timeout,
                crate::transparent::connect_plain(self.upstream, self.self_mark),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream connect timed out"))?;
        }
        // Losing the client's address is bad, losing the connection is worse — the same
        // trade, and just as loud about it, as the TCP and QUIC dials make.
        match tokio::time::timeout(
            self.connect_timeout,
            crate::transparent::connect_as(self.client.ip(), self.upstream, self.self_mark),
        )
        .await
        {
            Ok(Ok(stream)) => Ok(stream),
            failed => {
                let why = match failed {
                    Ok(Err(e)) => e.to_string(),
                    _ => "timed out (is the return path diverted?)".to_string(),
                };
                eprintln!(
                    "[warn] [h1] cannot reach {} as {}: {why}. Falling back to our own \
                     address — the service will not see real client IPs.",
                    self.upstream,
                    self.client.ip(),
                );
                tokio::time::timeout(
                    self.connect_timeout,
                    crate::transparent::connect_plain(self.upstream, self.self_mark),
                )
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "upstream connect timed out")
                })?
            }
        }
    }
}

impl Outbound for H1Upstream {
    type Error = io::Error;
    type Body = H1Body;
    type Answer = H1Answer;

    async fn open(
        &mut self,
        request: http::Request<()>,
        ends_it: bool,
    ) -> io::Result<(Self::Body, Self::Answer)> {
        let socket = self.connect().await?;
        let _ = socket.set_nodelay(true);
        let (tx, rx) = tokio::sync::mpsc::channel(IN_FLIGHT);
        let body = Streamed { rx };
        // The head goes out as HTTP/1.1 whatever it arrived as, and that is more than
        // restating the version. HTTP/2 and HTTP/3 carry the target split across
        // `:scheme`, `:authority` and `:path`, which `http::Uri` holds as one absolute
        // URI — and written to a socket unchanged that is the *proxy* form of a request
        // line, `GET https://host/path`, which an origin server is entitled to refuse and
        // which every service reading the path back gets wrong. So the target is reduced
        // to its origin form and the authority moves to `host`, which is exactly the
        // decision `http1::render_request` already makes for the chain: what the filters
        // were shown and what the service receives are the same message, and the two
        // deciding it differently is the drift this engine is arranged against.
        let (mut parts, _) = request.into_parts();
        parts.version = http::Version::HTTP_11;
        if let Some(authority) = parts.uri.authority().map(|a| a.to_string()) {
            if !parts.headers.contains_key(http::header::HOST) {
                if let Ok(value) = http::HeaderValue::from_str(&authority) {
                    parts.headers.insert(http::header::HOST, value);
                }
            }
        }
        parts.uri = parts
            .uri
            .path_and_query()
            .map(|target| target.as_str())
            .unwrap_or("/")
            .parse()
            .map_err(|e| io::Error::other(format!("cannot render the request target: {e}")))?;
        let request = http::Request::from_parts(parts, body);

        let answer = match &self.tls {
            Some(config) => {
                let name = crate::tls::server_name(&self.upstream.ip().to_string())?;
                let stream = tokio::time::timeout(
                    self.connect_timeout,
                    crate::tls::connector(config.clone()).connect(name, socket),
                )
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "upstream TLS handshake timed out")
                })??;
                Self::handshake(stream, request).await?
            }
            None => Self::handshake(socket, request).await?,
        };
        // A head that is the whole message gets a body that is already over: hyper then
        // frames the request with no body at all, which is what HTTP/1.1 does for one.
        // The flag exists for HTTP/2, where it has to ride on the head; here it only
        // saves a channel nobody will write to.
        Ok((H1Body { tx: (!ends_it).then_some(tx) }, answer))
    }
}

impl H1Upstream {
    /// The hyper side of opening one exchange, shared by the two kinds of socket.
    async fn handshake<S>(io: S, request: http::Request<Streamed>) -> io::Result<H1Answer>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io))
                .await
                .map_err(io::Error::other)?;
        // hyper drives the socket from here; without this task nothing is ever written.
        // Its end is this exchange's end, so it is dropped with the answer rather than
        // detached — one connection per exchange is what makes that safe to say.
        let driving = tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("[info] [h1] the connection to the service ended: {e}");
            }
        });
        // Not awaited here: the service is allowed to answer before it has read the whole
        // request — a refusal, a redirect, a `413` — and the body is still being written
        // into the channel above by the other half of this exchange. Awaiting it now is a
        // deadlock with a name.
        let pending = Box::pin(sender.send_request(request));
        Ok(H1Answer {
            pending: Some(pending),
            body: None,
            trailers: None,
            _driving: driving,
        })
    }
}

/// The request body's writing half.
pub(crate) struct H1Body {
    /// Taken by `finish`, because dropping the sender is what ends the body: hyper reads
    /// the close as the last frame and writes the terminating chunk. Waiting on the
    /// channel instead — for the *receiver* to go — is waiting for the service to answer
    /// a request this end has not finished sending, which is a deadlock with a name.
    tx: Option<tokio::sync::mpsc::Sender<http_body::Frame<Bytes>>>,
}

impl H1Body {
    async fn send(&mut self, frame: http_body::Frame<Bytes>) -> io::Result<()> {
        let Some(tx) = self.tx.as_ref() else {
            return Err(io::Error::other("this request body has already ended"));
        };
        tx.send(frame)
            .await
            .map_err(|_| io::Error::other("the service stopped reading the request"))
    }
}

impl OutboundBody for H1Body {
    type Error = io::Error;

    async fn data(&mut self, chunk: Bytes) -> io::Result<()> {
        self.send(http_body::Frame::data(chunk)).await
    }

    async fn trailers(&mut self, trailers: http::HeaderMap) -> io::Result<()> {
        self.send(http_body::Frame::trailers(trailers)).await
    }

    async fn finish(&mut self) -> io::Result<()> {
        self.tx.take();
        Ok(())
    }
}

type Pending = Pin<
    Box<dyn std::future::Future<Output = hyper::Result<http::Response<hyper::body::Incoming>>> + Send>,
>;

/// The service's answer, read the way every other answer in this engine is.
pub(crate) struct H1Answer {
    /// Taken by `response()`, which is the first thing the reading half does.
    pending: Option<Pending>,
    body: Option<hyper::body::Incoming>,
    /// A trailer section arrives as a frame among the body's, so it is kept here until
    /// the body is done and somebody asks for it — which is the order the rendering
    /// wants it in.
    trailers: Option<http::HeaderMap>,
    /// Dropped with the answer, which cancels the connection task: one connection per
    /// exchange means its life is exactly this one's.
    _driving: tokio::task::JoinHandle<()>,
}

impl Answer for H1Answer {
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

impl Incoming for H1Answer {
    type Error = io::Error;

    fn ended(&self) -> bool {
        // hyper knows: a response framed with no body at all — `204`, `304`, a declared
        // length of zero — is over before anybody reads it.
        use http_body::Body;
        self.body.as_ref().is_none_or(|body| body.is_end_stream())
    }

    async fn data(&mut self) -> io::Result<Option<Bytes>> {
        let Some(body) = self.body.as_mut() else {
            return Ok(None);
        };
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(io::Error::other)?;
            match frame.into_data() {
                Ok(data) => return Ok(Some(data)),
                // Not data, so it is the trailer section, and it is the last thing the
                // body will produce. Kept for whoever asks next rather than dropped.
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        self.trailers = Some(trailers);
                    }
                }
            }
        }
        Ok(None)
    }

    async fn trailers(&mut self) -> io::Result<Option<http::HeaderMap>> {
        Ok(self.trailers.take())
    }
}
