//! The HTTP/1.1 view every terminated HTTP protocol is shown to the chain as.
//!
//! A filter written against `HttpRequest` is a filter written once. The same file is
//! supposed to work on every layer, and the library decides when to call it from what its
//! parameters are annotated with — not from what the service happens to speak. HTTP/2
//! puts the method, the path and the headers in an HPACK-compressed HEADERS frame and
//! HTTP/3 in a QPACK one, so a filter handed the bytes of either would be handed a
//! compression format, and every pattern written for the HTTP/1.1 service beside it would
//! silently stop matching.
//!
//! So each exchange is rendered as the HTTP/1.1 message it would have been, and that is
//! what the chain is shown. `HttpRequest`, `HttpResponse` and a hyperscan pattern all mean
//! the same thing on every version, and nothing had to learn a new protocol. The same
//! bargain the capture interface makes: **the bytes are real and the framing is
//! reconstructed**. Concretely, and this belongs wherever this is documented —
//!
//! * the request line says `HTTP/1.1`, because there is no other version an HTTP/1 parser
//!   will read, and the version on the wire was not it;
//! * a body with no `content-length` is shown chunked, which is what that message is in
//!   HTTP/1.1 — and the head is held until it is known whether a body is coming, so that a
//!   request without one is not shown a framing header it never had. Held *briefly*: a
//!   declared length settles the question outright and waits for nothing, a message with
//!   no body has already ended its stream, and what is left is a sender holding the stream
//!   open, which [`HEAD_HOLD`] ends rather than deadlocking an exchange the service is
//!   supposed to speak first in;
//! * a **trailer section is always shown to the chain**, which is what decides the framing
//!   of a message that has one and no body: in HTTP/1.1 a trailer section belongs to a
//!   chunked message and nowhere else. The one message that cannot carry one in the
//!   rendering is one that declared its length, and there the trailers are dropped rather
//!   than forwarded past a filter that never saw them;
//! * `host` is rendered from the `:authority` pseudo-header, which is where both HTTP/2
//!   and HTTP/3 put it;
//! * hop-by-hop headers do not appear: both versions forbid them, a request carrying one
//!   is refused as malformed ([`connection_specific`]), and an answer from a service
//!   reached over HTTP/1.1 has its own taken out before it goes on
//!   ([`drop_connection_headers`]).
//!
//! A message whose declared `content-length` disagrees with the body it then sends is
//! malformed in HTTP/2 and HTTP/3 as well, and nothing here tries to repair it: the frames
//! are forwarded as they came, and the rendering carries the same disagreement — which an
//! HTTP/1 parser reads as a message that does not end where it said it would. That is what
//! the library's invalid-encoding action is for, and it refuses by default, which is the
//! same answer the same traffic gets over HTTP/1.1.
//!
//! What it is *not* is a translation the service ever sees: upstream, the message goes
//! back out in the version it arrived in, re-encoded by the same library that parsed it.
//!
//! **The capture interface is shown this same rendering**, one TCP conversation per
//! exchange, which is the only way `firegex0` can keep the promise it makes everywhere
//! else: what is written there is what the filters saw. It is not what left this process
//! towards the service, so the rendering is a view in the capture exactly as it is a view
//! to a filter, and the two cannot disagree because they are the same bytes.
//!
//! # Why this module exists at all
//!
//! It was inside `h3.rs`, and HTTP/2 wanted every line of it. Copying it would have been
//! two renderings that can come to disagree — the same argument the [`Incoming`] trait
//! already makes *within* one protocol, one level up. The day they diverge the symptom is
//! a pattern that matches over HTTP/3 and not over HTTP/2, silently, which is the failure
//! this whole engine is arranged against. So the rendering lives here once, and
//! [`crate::h2`] and [`crate::h3`] are what is left of each protocol after it is taken
//! out: an adapter to somebody else's parser.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::capture::Tap;
use crate::filter::{ChainHandle, ChainSessions, Direction, Verdict};
use crate::proxy::ProxyStats;

/// How the body of one message is framed in the view the filters are shown.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framing {
    /// The message said how long it is, so the body is shown as it arrives.
    Sized,
    /// It did not, so it is shown chunked — the HTTP/1.1 spelling of that.
    Chunked,
    /// There is no body at all, and nothing is added to say so.
    Empty,
}

/// How long the head is held while it is still unknown whether a body follows.
///
/// Only ever paid by a message that declared no length *and* has not yet said whether it
/// has a body — which is to say, one whose sender is holding the stream open. A message
/// with a `content-length` is rendered from its head alone and waits for nothing; one
/// without a body has already finished its stream, so the answer is there before this
/// timer starts.
///
/// It exists because holding the head indefinitely deadlocks an exchange the service is
/// supposed to speak first in: a bidirectional RPC — gRPC's among them — sends a head and
/// then waits to be answered, and a proxy that will not forward the head until a body
/// arrives is waiting for something that is waiting for it. When it expires the message is
/// rendered chunked, which is what a message of undeclared length *is* in HTTP/1.1, so
/// nothing is invented that the sender did not already imply.
pub(crate) const HEAD_HOLD: Duration = Duration::from_millis(100);

/// Everything the rendering needs about who is being carried, and no more.
///
/// Neither protocol's connection type appears here on purpose: what this module does is
/// the same on both, and a parameter that differed would be the seam along which the two
/// renderings could start to drift again.
pub(crate) struct Rendered<'a> {
    pub(crate) chain: &'a ChainHandle,
    pub(crate) stats: &'a Arc<ProxyStats>,
    pub(crate) client: SocketAddr,
    /// `h2` or `h3`, for the one log line this module writes.
    pub(crate) layer: &'static str,
}

/// The receiving half of one direction of an exchange.
///
/// Four types end up here — a server and a client request stream on each of two crates —
/// and nothing unifies them, while every question this module asks a message is the same
/// on all of them. One trait rather than the same framing decision written four times: the
/// copies are renderings that can come to disagree, and the whole point of the rendering
/// is that a filter sees one thing.
pub(crate) trait Incoming {
    /// Whatever the underlying crate says went wrong. Never inspected here — the caller
    /// owns the protocol and its errors, this module owns the framing.
    type Error;

    fn data(&mut self) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> + Send;
    fn trailers(
        &mut self,
    ) -> impl Future<Output = Result<Option<http::HeaderMap>, Self::Error>> + Send;

    /// Give back the window one piece took, once it has been forwarded and not before.
    ///
    /// HTTP/2 is the only protocol here that asks: it hands received bytes over and waits
    /// for them to be released, so releasing on *read* would mean no backpressure and
    /// this process buying memory for whichever side is faster, while never releasing
    /// stalls the stream after its first window. Everything else frames its own flow and
    /// answers with the default.
    fn release(&mut self, taken: usize) -> Result<(), Self::Error> {
        let _ = taken;
        Ok(())
    }

    /// Whether the sender has already said there is nothing more coming.
    ///
    /// Only meaningful beside a head that produced no body and no trailer section: the
    /// three together are what decide whether the head **is** the message, which HTTP/2
    /// has to state on the head itself (see [`Outbound::open`]). A protocol whose sender
    /// cannot say it in advance answers `false`, which is always safe — the message is
    /// then framed the ordinary way and ends when its body does.
    fn ended(&self) -> bool {
        false
    }
}

/// Where a rendered message is sent once the chain has agreed to it.
///
/// The mirror of [`Incoming`], and it exists for the same reason one level further out:
/// what leaves this engine towards the service used to be, always, the protocol the
/// client arrived in — so the sending half could be written against one crate's concrete
/// types. It is a choice now (`FGEX_PROXY_UPSTREAM`), because a service that speaks
/// HTTP/1.1 can be put behind an HTTP/3 edge, and the alternative to this trait was a
/// second copy of the orchestration in [`crate::h3`] — request in one direction, answer
/// in the other, framing decided on both — which is the drift this module exists to
/// prevent, one level down.
///
/// Note what is *not* here: nothing about rendering. The bytes a filter sees are built by
/// this module whatever the service turns out to speak, so an implementation of this
/// trait only has to know how to put a head, a body and a trailer section on the wire.
pub(crate) trait Outbound: Send {
    type Error: std::error::Error + Send + Sync + 'static;
    /// Where this exchange's body is written.
    type Body: OutboundBody<Error = Self::Error> + Send;
    /// Where its answer comes back.
    type Answer: Answer<Error = Self::Error> + Send;

    /// Send the head, and take the two halves the rest of the exchange runs on.
    ///
    /// `ends_it` says the head **is** the whole message. It is a parameter rather than a
    /// later `finish()` because not every protocol can say it afterwards: on HTTP/2 the
    /// end of a message rides on its last frame, so a head sent open and then closed with
    /// an empty DATA frame is a message *with a body* — which is exactly what a
    /// status-only gRPC answer is not, and what gRPC clients refuse. HTTP/1.1 frames it
    /// from the headers and has nothing to do with the flag but close the body early.
    fn open(
        &mut self,
        request: http::Request<()>,
        ends_it: bool,
    ) -> impl Future<Output = Result<(Self::Body, Self::Answer), Self::Error>> + Send;
}

/// The body of a message on its way to the service.
///
/// Imperative rather than a stream handed over whole, because that is the shape both ends
/// of this already have: the chain judges one piece at a time and forwards what it
/// accepts, so a piece is written when it is allowed and not before.
pub(crate) trait OutboundBody: Send {
    type Error;

    fn data(&mut self, chunk: Bytes) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn trailers(
        &mut self,
        trailers: http::HeaderMap,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// No more of it is coming. Separate from dropping, because on some protocols the
    /// end of a message is a frame and not the absence of one.
    fn finish(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// The service's answer: its head first, then the body every [`Incoming`] gives.
pub(crate) trait Answer: Incoming + Send {
    fn response(
        &mut self,
    ) -> impl Future<Output = Result<http::Response<()>, <Self as Incoming>::Error>> + Send;
}

/// What has to be known before a message's head can be rendered, and no more than that.
///
/// Three answers come back together because they are one decision: the framing, the first
/// body chunk if reading it is what settled the question, and — where the body was over
/// before it began — the trailer section, which is already in hand by then and which
/// decides the framing too. A message that ends with trailers and no body *is* a chunked
/// message in HTTP/1.1, and that is the only place a trailer section can be rendered, so
/// it has to be known here rather than discovered after the head has gone out.
///
/// `Some(trailers)` in the third slot means the body stream is finished and its trailer
/// section has already been taken; the caller must not read either again.
#[allow(clippy::type_complexity)]
pub(crate) async fn head_framing<B: Incoming + Send>(
    body: &mut B,
    headers: &http::HeaderMap,
) -> Result<(Framing, Option<Bytes>, Option<Option<http::HeaderMap>>), B::Error> {
    // A declared length frames the body by itself, so there is nothing to wait for and
    // nothing a later frame could change. This is also what keeps an upload that the
    // service answers early — a `413`, a redirect, a refusal — moving in both directions.
    if headers.contains_key(http::header::CONTENT_LENGTH) {
        return Ok((Framing::Sized, None, None));
    }
    // Both crates keep a half-read frame's state in the stream rather than in the future,
    // so letting the deadline drop it loses nothing.
    match tokio::time::timeout(HEAD_HOLD, body.data()).await {
        Ok(first) => match first? {
            Some(chunk) => Ok((Framing::Chunked, Some(chunk), None)),
            None => {
                // The body is over. Whatever ended it — the end of the stream or a
                // trailer section — has already been read into the stream, so this
                // resolves without waiting for anything.
                let trailers = body.trailers().await?;
                let framing = if trailers.is_some() {
                    Framing::Chunked
                } else {
                    Framing::Empty
                };
                Ok((framing, None, Some(trailers)))
            }
        },
        Err(_) => Ok((Framing::Chunked, None, None)),
    }
}

/// The trailer section this engine is willing to forward.
///
/// A trailer section the chain was never shown is a piece of the message that travelled
/// unfiltered, which is the one thing nothing else here does. Only one framing leaves
/// nowhere to render it: a message that declared its length, whose HTTP/1.1 view ends
/// where the header said it would — anything appended after that is not part of the
/// message any parser reading the rendering would see. So it is dropped, which is what an
/// intermediary is allowed to do with a trailer section it cannot carry, and said out loud
/// rather than done quietly.
pub(crate) fn carried(
    rendered: &Rendered<'_>,
    framing: Framing,
    trailers: Option<http::HeaderMap>,
) -> Option<http::HeaderMap> {
    if framing == Framing::Sized && trailers.is_some() {
        eprintln!(
            "[warn] [{}] {}: a trailer section arrived on a message that declared its \
             length. The HTTP/1.1 the filters are shown has nowhere to put one, so it is \
             dropped rather than forwarded unread.",
            rendered.layer, rendered.client,
        );
        return None;
    }
    trailers
}

/// Ask the chain about one piece of the rendered message.
pub(crate) async fn judge(
    rendered: &Rendered<'_>,
    direction: Direction,
    view: &[u8],
    sessions: &mut ChainSessions,
    tap: Option<&Arc<Tap>>,
) -> bool {
    // Re-read every time, so a ruleset pushed mid-request takes effect without anybody
    // losing their connection — the same rule the byte pumps follow.
    match rendered
        .chain
        .current()
        .run(direction, view, sessions)
        .await
    {
        Verdict::Accept => {
            // Written on the way past, and only once the chain has agreed: what a capture
            // shows has to be what was let through, or it is a record of a decision that
            // was not taken. A refused piece leaves the conversation ending where the
            // traffic did, which is the truth about it.
            if let Some(tap) = tap {
                tap.wrote(direction == Direction::ClientToServer, view);
            }
            true
        }
        Verdict::Reject(_) => {
            rendered
                .stats
                .closed_by_filter
                .fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

/// Why a request names its authority twice and disagrees with itself, or `None`.
///
/// HTTP/2 and HTTP/3 carry the authority in `:authority`, and a client may send a `host`
/// header beside it. The rendering shows the chain one `Host` line, while the request goes
/// on to the service with both — and a service reading HTTP/2 or HTTP/3 routes on
/// `:authority`, which RFC 9113 §8.3.1 says wins. So a request whose two disagree would
/// show a filter one host and deliver itself to another: `:authority: admin.internal` with
/// `host: public.example` walks past every rule written against the admin host. The RFC
/// calls such a request malformed, and so does this. A second `host` header is the same
/// question asked twice, and is answered the same way.
pub(crate) fn conflicting_authority(request: &http::Request<()>) -> Option<String> {
    let mut hosts = request.headers().get_all(http::header::HOST).iter();
    let host = hosts.next();
    if hosts.next().is_some() {
        return Some("the request carries more than one host header".to_string());
    }
    match (request.uri().authority(), host) {
        (Some(authority), Some(host))
            if !host.as_bytes().eq_ignore_ascii_case(authority.as_str().as_bytes()) =>
        {
            Some(format!(
                ":authority says {authority} and the host header says {}",
                String::from_utf8_lossy(host.as_bytes())
            ))
        }
        _ => None,
    }
}

/// The most a client's head may take — the header section of one request, decoded.
///
/// Neither crate bounds it usefully by default: h2 allows 16 MiB, and h3 sets no limit at
/// all, so an HTTP/3 request could keep one header block growing for as long as flow
/// control kept crediting it, a hundred streams to a connection. A mebibyte is the budget
/// the filter library holds a stream to by default (`FGEX_STREAM_MAX_SIZE`), well past
/// what any HTTP/1.1 server accepts in a head, and far enough from the usual range that
/// a large cookie or a heavy set of gRPC metadata is never what it refuses.
pub(crate) const MAX_HEAD_BYTES: u32 = 1024 * 1024;

/// Headers about one connection rather than about the message it carries.
///
/// HTTP/2 and HTTP/3 have no such thing (RFC 9113 §8.2.2, RFC 9114 §4.2): the framing and
/// the connection's lifetime are the protocol's own business, so a message carrying one
/// is malformed. `te` is the exception, and only as `trailers`.
const CONNECTION_SPECIFIC: [&str; 6] =
    ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te"];

/// Why a request that arrived over HTTP/2 or HTTP/3 carries a header only a connection
/// can, or `None`.
///
/// The h2 crate refuses these itself; h3 does not, so an HTTP/3 client could hand a
/// service reached over HTTP/1.1 a `connection` naming headers for it to drop, or a `te`
/// the upstream then extends into a transfer coding the service is told to undo — none of
/// which a filter shown the rendering would recognise as the request the service got.
pub(crate) fn connection_specific(headers: &http::HeaderMap) -> Option<String> {
    for name in CONNECTION_SPECIFIC {
        for value in headers.get_all(name) {
            if name == "te" && value.as_bytes().eq_ignore_ascii_case(b"trailers") {
                continue;
            }
            return Some(format!(
                "the request carries `{name}`, which belongs to a connection rather than to \
                 a message"
            ));
        }
    }
    None
}

/// Take out of an HTTP/1.1 answer what belongs to that connection, before it goes on in
/// a version that forbids it.
///
/// Every HTTP/1.1 service says something about its connection — a body of unknown length
/// comes `transfer-encoding: chunked`, a connection it will keep open says `keep-alive` —
/// and those were passed on as they came: HTTP/2 refused to send the response at all, and
/// an HTTP/3 client is required to reject one. What `connection` itself names goes too,
/// since that is what the header is for (RFC 9110 §7.6.1).
pub(crate) fn drop_connection_headers(headers: &mut http::HeaderMap) {
    let named: Vec<http::HeaderName> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| http::HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in CONNECTION_SPECIFIC {
        headers.remove(name);
    }
}

/// The request, as the HTTP/1.1 it would have been.
///
/// Called only for a request that has passed [`conflicting_authority`], so a `host` header
/// and `:authority`, where both are present, say the same thing.
pub(crate) fn render_request(request: &http::Request<()>, framing: &Framing) -> Vec<u8> {
    let target = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let mut view = format!("{} {} HTTP/1.1\r\n", request.method(), target).into_bytes();
    // Both versions carry it as `:authority`, and an HTTP/1.1 parser wants a `Host` line.
    // A request that also sent `host` outright keeps its own, which is the same value.
    if !request.headers().contains_key(http::header::HOST) {
        if let Some(authority) = request.uri().authority() {
            view.extend_from_slice(format!("host: {authority}\r\n").as_bytes());
        }
    }
    render_headers(&mut view, request.headers(), framing);
    view
}

/// And the response.
pub(crate) fn render_response(response: &http::Response<()>, framing: &Framing) -> Vec<u8> {
    let status = response.status();
    let mut view = format!(
        "HTTP/1.1 {} {}\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    )
    .into_bytes();
    render_headers(&mut view, response.headers(), framing);
    view
}

fn render_headers(view: &mut Vec<u8>, headers: &http::HeaderMap, framing: &Framing) {
    for (name, value) in headers {
        view.extend_from_slice(name.as_str().as_bytes());
        view.extend_from_slice(b": ");
        view.extend_from_slice(value.as_bytes());
        view.extend_from_slice(b"\r\n");
    }
    if matches!(framing, Framing::Chunked) {
        view.extend_from_slice(b"transfer-encoding: chunked\r\n");
    }
    view.extend_from_slice(b"\r\n");
}

/// One body frame, framed the way the head said it would be.
pub(crate) fn push_body(view: &mut Vec<u8>, chunk: &[u8], framing: &Framing) {
    match framing {
        Framing::Chunked => {
            view.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            view.extend_from_slice(chunk);
            view.extend_from_slice(b"\r\n");
        }
        _ => view.extend_from_slice(chunk),
    }
}

/// The end of the body, where the framing has one to show.
pub(crate) fn close_body(view: &mut Vec<u8>, framing: &Framing, trailers: Option<&http::HeaderMap>) {
    if !matches!(framing, Framing::Chunked) {
        return;
    }
    view.extend_from_slice(b"0\r\n");
    if let Some(trailers) = trailers {
        for (name, value) in trailers {
            view.extend_from_slice(name.as_str().as_bytes());
            view.extend_from_slice(b": ");
            view.extend_from_slice(value.as_bytes());
            view.extend_from_slice(b"\r\n");
        }
    }
    view.extend_from_slice(b"\r\n");
}

#[cfg(test)]
mod tests {
    use super::conflicting_authority;

    fn request(authority: Option<&str>, hosts: &[&str]) -> http::Request<()> {
        let uri = match authority {
            Some(authority) => format!("https://{authority}/path"),
            None => "/path".to_string(),
        };
        let mut builder = http::Request::builder().uri(uri);
        for host in hosts {
            builder = builder.header(http::header::HOST, *host);
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn one_authority_said_once_or_twice_alike_is_fine() {
        assert_eq!(conflicting_authority(&request(Some("example.com"), &[])), None);
        assert_eq!(conflicting_authority(&request(None, &["example.com"])), None);
        assert_eq!(conflicting_authority(&request(Some("example.com"), &["example.com"])), None);
        assert_eq!(conflicting_authority(&request(Some("Example.com"), &["example.COM"])), None);
    }

    #[test]
    fn two_authorities_that_disagree_are_malformed() {
        assert!(conflicting_authority(&request(Some("admin.internal"), &["public.example"])).is_some());
        assert!(conflicting_authority(&request(None, &["a.example", "b.example"])).is_some());
    }
}
