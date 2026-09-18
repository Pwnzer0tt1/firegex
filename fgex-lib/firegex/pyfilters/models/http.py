from firegex import _llhttp
from firegex.pyfilters.internals.exceptions import NotReadyToRun
from firegex.pyfilters.internals.data import DataStreamCtx
from firegex.pyfilters.internals.exceptions import (
    StreamFullDrop,
    StreamFullReject,
    RejectConnection,
    DropPacket,
)
from firegex.pyfilters.internals.models import FullStreamAction, ExceptionAction
from dataclasses import dataclass, field
from collections import deque
from firegex.pyfilters.internals import zstd_compat
import gzip
import io
import zlib
import brotli
import traceback
from websockets.frames import Frame
from websockets.extensions.permessage_deflate import PerMessageDeflate
from firegex._llhttp import PAUSED_H2_UPGRADE, PAUSED_UPGRADE


@dataclass
class InternalHTTPMessage:
    """Internal class to handle HTTP messages"""

    url: str | None = field(default=None)
    headers: dict[str, str] = field(default_factory=dict)
    lheaders: dict[str, str] = field(
        default_factory=dict
    )  # lowercase copy of the headers
    body: bytes | None = field(default=None)
    body_decoded: bool = field(default=False)
    headers_complete: bool = field(default=False)
    message_complete: bool = field(default=False)
    #: The reason phrase, as the server wrote it. Free text.
    status: str | None = field(default=None)
    #: The numeric status. Separate from the phrase because they are different things,
    #: and because for a long time only the phrase was reachable at all: the binding
    #: never exposed `llhttp`'s status code, so `status_code` on the public model handed
    #: back the phrase while the documentation promised an int.
    status_code: int | None = field(default=None)
    total_size: int = field(default=0)
    user_agent: str = field(default_factory=str)
    content_encoding: str = field(default=str)
    content_type: str = field(default=str)
    keep_alive: bool = field(default=False)
    should_upgrade: bool = field(default=False)
    http_version: str = field(default=str)
    method: str = field(default=str)
    content_length: int = field(default=0)
    stream: bytes = field(default_factory=bytes)
    ws_stream: list[Frame] = field(default_factory=list)  # Decoded websocket stream
    upgrading_to_h2: bool = field(default=False)
    upgrading_to_ws: bool = field(default=False)
    added_to_history: bool = field(default=False)
    #: How much of `body` has already been handed to a model that consumes it.
    #:
    #: On the message rather than beside it because that is what it belongs to: a
    #: keep-alive connection carries many messages through one parser, and a cursor kept
    #: per connection would start the second message part-way in.
    grpc_consumed: int = field(default=0)


@dataclass
class InternalHttpBuffer:
    """Internal class to handle HTTP messages"""

    _url_buffer: bytes = field(default_factory=bytes)
    _raw_header_fields: dict[str, str | list[str]] = field(default_factory=dict)
    _header_fields: dict[str, str] = field(default_factory=dict)
    _body_buffer: bytes = field(default_factory=bytes)
    _status_buffer: bytes = field(default_factory=bytes)
    _current_header_field: bytes = field(default_factory=bytes)
    _current_header_value: bytes = field(default_factory=bytes)
    _ws_packet_stream: bytes = field(default_factory=bytes)


class InternalCallbackHandler:
    buffers = InternalHttpBuffer()
    msg = InternalHTTPMessage()
    save_body = True
    raised_error = False
    has_begun = False
    messages: deque[InternalHTTPMessage] = deque()
    _ws_extentions = None
    _ws_raised_error = False
    release_message_headers = True
    #: Hand the message over as its body arrives, not only when it is finished.
    #:
    #: Off everywhere but the gRPC models, and each model gets a parser of its own
    #: (`_parser_class`), so `HttpRequest` keeps its contract exactly: called twice, once
    #: with the headers and once with the whole message. It exists because a gRPC stream
    #: that is answered message by message — a server-streaming or bidirectional RPC —
    #: has a body that does not finish until the stream does, so a filter shown only
    #: finished bodies would be called once, at the end, which is too late to be a
    #: firewall.
    release_body_chunks = False
    #: Whether a chunk has arrived that has not been handed over yet.
    _body_chunk_pending = False

    def reset_data(self):
        self.msg = InternalHTTPMessage()
        self.buffers = InternalHttpBuffer()
        self.messages.clear()

    def on_message_begin(self):
        self.buffers = InternalHttpBuffer()
        self.msg = InternalHTTPMessage()
        self.has_begun = True
        self._body_chunk_pending = False

    def on_url(self, url):
        self.buffers._url_buffer += url
        self.msg.total_size += len(url)

    def on_url_complete(self):
        self.msg.url = self.buffers._url_buffer.decode(errors="ignore")
        self.buffers._url_buffer = b""

    def on_status(self, status: bytes):
        self.msg.total_size += len(status)
        self.buffers._status_buffer += status

    def on_status_complete(self):
        self.msg.status = self.buffers._status_buffer.decode(errors="ignore")
        self.buffers._status_buffer = b""

    def on_header_field(self, field):
        self.msg.total_size += len(field)
        self.buffers._current_header_field += field

    def on_header_field_complete(self):
        pass  # Nothing to do

    def on_header_value(self, value):
        self.msg.total_size += len(value)
        self.buffers._current_header_value += value

    def on_header_value_complete(self):
        if self.buffers._current_header_field:
            k, v = (
                self.buffers._current_header_field.decode(errors="ignore"),
                self.buffers._current_header_value.decode(errors="ignore"),
            )
            old_value = self.buffers._raw_header_fields.get(k, None)

            # raw headers are stored as thay were, considering to check changes between headers encoding
            if isinstance(old_value, list):
                old_value.append(v)
            elif isinstance(old_value, str):
                self.buffers._raw_header_fields[k] = [old_value, v]
            else:
                self.buffers._raw_header_fields[k] = v

            # Decoding headers normally
            kl = k.lower()
            if kl in self.buffers._header_fields:
                self.buffers._header_fields[kl] += (
                    f", {v}"  # Should be considered as a single list separated by commas as said in the RFC
                )
            else:
                self.buffers._header_fields[kl] = v

        self.buffers._current_header_field = b""
        self.buffers._current_header_value = b""

    def on_headers_complete(self):
        self.msg.headers = self.buffers._raw_header_fields
        self.msg.lheaders = self.buffers._header_fields
        self.buffers._raw_header_fields = {}
        self.buffers._current_header_field = b""
        self.buffers._current_header_value = b""
        self.msg.headers_complete = True
        self.msg.method = self.method_parsed
        self.msg.status_code = self.status_code
        self.msg.content_length = self.content_length_parsed
        self.msg.should_upgrade = self.should_upgrade
        self.msg.keep_alive = self.keep_alive
        self.msg.http_version = self.http_version
        self.msg.content_type = self.content_type
        self.msg.content_encoding = self.content_encoding
        self.msg.user_agent = self.user_agent

    def on_body(self, body: bytes):
        if self.save_body:
            self.msg.total_size += len(body)
            self.buffers._body_buffer += body
            if self.release_body_chunks:
                # Visible as it arrives rather than only at the end. **Undecoded**, and
                # that is not an oversight: `content-encoding` is undone once, in
                # `on_message_complete`, and half a gzip stream is not half a body. The
                # models that read this decline while an encoding is in the way.
                self.msg.body = self.buffers._body_buffer
                self._body_chunk_pending = True

    def on_message_complete(self):
        self.msg.body = self.buffers._body_buffer
        self.msg.should_upgrade = self.should_upgrade
        self.buffers._body_buffer = b""
        encodings = [ele.strip() for ele in self.content_encoding.lower().split(",")]
        decode_success = True
        decoding_body = self.msg.body
        for enc in reversed(encodings):
            if not enc:
                continue
            if enc == "deflate":
                # Both spellings, because both are on the wire. RFC 7230 defines
                # `deflate` as the zlib format of RFC 1950, and plenty of servers send
                # the raw stream instead — browsers accept either, and a decoder that
                # takes only one lets half the compressed traffic reach a filter still
                # compressed, where a pattern finds nothing and the only trace is a line
                # on stdout saying it skipped.
                for wbits in (-zlib.MAX_WBITS, zlib.MAX_WBITS):
                    try:
                        decompress = zlib.decompressobj(wbits)
                        decoded = decompress.decompress(decoding_body)
                        decoded += decompress.flush()
                    except Exception:
                        continue
                    decoding_body = decoded
                    break
                else:
                    print("Error decompressing deflate: neither raw nor zlib-wrapped: "
                          "skipping", flush=True)
                    decode_success = False
                    break
            elif enc == "br":
                try:
                    decoding_body = brotli.decompress(decoding_body)
                except Exception as e:
                    print(f"Error decompressing brotli: {e}: skipping", flush=True)
                    decode_success = False
                    break
            elif (
                enc == "gzip" or enc == "x-gzip"
            ):  # https://datatracker.ietf.org/doc/html/rfc2616#section-3.5
                try:
                    if "gzip" in self.content_encoding.lower():
                        with gzip.GzipFile(fileobj=io.BytesIO(decoding_body)) as f:
                            decoding_body = f.read()
                except Exception as e:
                    print(f"Error decompressing gzip: {e}: skipping", flush=True)
                    decode_success = False
                    break
            elif enc == "zstd":
                try:
                    decoding_body = zstd_compat.decompress(decoding_body)
                except Exception as e:
                    print(f"Error decompressing zstd: {e}: skipping", flush=True)
                    decode_success = False
                    break
            elif enc == "identity":
                pass  # No need to do anything https://datatracker.ietf.org/doc/html/rfc2616#section-3.5 (it's possible to be found also if it should't be used)
            else:
                decode_success = False
                break

        if decode_success:
            self.msg.body = decoding_body
            self.msg.body_decoded = True

        self.msg.message_complete = True
        self.has_begun = False
        if not self._packet_to_stream():
            self.messages.append(self.msg)

    @property
    def user_agent(self) -> str:
        return self.msg.lheaders.get("user-agent", "")

    @property
    def content_encoding(self) -> str:
        return self.msg.lheaders.get("content-encoding", "")

    @property
    def content_type(self) -> str:
        return self.msg.lheaders.get("content-type", "")

    @property
    def keep_alive(self) -> bool:
        return self.should_keep_alive

    @property
    def should_upgrade(self) -> bool:
        return self.is_upgrading

    @property
    def http_version(self) -> str:
        """`"1.1"`, `"1.0"`, `""` if the parser has not read a version yet.

        Written `if self.major and self.minor` before — so a minor of zero is falsy and
        HTTP/1.0, and HTTP/2.0, both reported the empty string. A filter keying on the
        version never saw either, and nothing said why.
        """
        if self.major is None or self.minor is None:
            return ""
        return f"{self.major}.{self.minor}"

    @property
    def method_parsed(self) -> str:
        return self.method

    @property
    def total_size(self) -> int:
        """Total size used by the parser"""
        tot = self.msg.total_size
        for msg in self.messages:
            tot += msg.total_size
        return tot

    @property
    def content_length_parsed(self) -> int:
        return self.content_length

    def _is_input(self) -> bool:
        raise NotImplementedError()

    def _packet_to_stream(self):
        return self.should_upgrade and self.save_body

    def _stream_parser(self, data: bytes):
        if self.msg.upgrading_to_ws:
            if self._ws_raised_error:
                self.msg.stream += data
                self.msg.total_size += len(data)
                return
            self.buffers._ws_packet_stream += data
            while True:
                try:
                    new_frame, self.buffers._ws_packet_stream = (
                        self._parse_websocket_frame(self.buffers._ws_packet_stream)
                    )
                except Exception:
                    print(
                        "[WARNING] Websocket parsing failed, passing data to stream...",
                        flush=True,
                    )
                    traceback.print_exc()
                    self._ws_raised_error = True
                    self.msg.stream += self.buffers._ws_packet_stream
                    self.buffers._ws_packet_stream = b""
                    self.msg.total_size += len(data)
                    return
                if new_frame is None:
                    break
                self.msg.ws_stream.append(new_frame)
                self.msg.total_size += len(new_frame.data)
        if self.msg.upgrading_to_h2:
            self.msg.total_size += len(data)
            self.msg.stream += data

    def _parse_websocket_ext(self):
        ext_ws = []
        req_ext = []
        for ele in self.msg.lheaders.get("sec-websocket-extensions", "").split(","):
            for xt in ele.split(";"):
                req_ext.append(xt.strip().lower())

        for ele in req_ext:
            if ele == "permessage-deflate":
                ext_ws.append(PerMessageDeflate(False, False, 15, 15))
        return ext_ws

    def _parse_websocket_frame(self, data: bytes) -> tuple[Frame | None, bytes]:
        if self._ws_extentions is None:
            if self._is_input():
                self._ws_extentions = []  # Fallback to no options
            else:
                self._ws_extentions = (
                    self._parse_websocket_ext()
                )  # Extentions used are choosen by the server response
        read_buffering = bytearray()

        def read_exact(n: int):
            nonlocal read_buffering
            buffer = bytearray(read_buffering)
            while len(buffer) < n:
                data = yield
                if data is None:
                    raise RuntimeError("Should not send None to this generator")
                buffer.extend(data)
            new_data = bytes(buffer[:n])
            read_buffering = buffer[n:]
            return new_data

        parsing = Frame.parse(
            read_exact, extensions=self._ws_extentions, mask=self._is_input()
        )
        parsing.send(None)
        try:
            parsing.send(bytearray(data))
        except StopIteration as e:
            return e.value, read_buffering

        return None, read_buffering

    def parse_data(self, data: bytes):
        if self._packet_to_stream():  # This is a websocket upgrade!
            self._stream_parser(data)
        else:
            try:
                reason, consumed = self.execute(data)
                if reason == PAUSED_UPGRADE:
                    self.msg.upgrading_to_ws = True
                    self.msg.message_complete = True
                    self._stream_parser(data[consumed:])
                elif reason == PAUSED_H2_UPGRADE:
                    self.msg.upgrading_to_h2 = True
                    self.msg.message_complete = True
                    self._stream_parser(data[consumed:])
            except Exception as e:
                self.raised_error = True
                raise e

    def pop_message(self):
        return self.messages.popleft()

    def pop_all_messages(self):
        tmp = self.messages
        self.messages = deque()
        return tmp

    def __repr__(self):
        return f"<InternalCallbackHandler msg={self.msg} buffers={self.buffers} save_body={self.save_body} raised_error={self.raised_error} has_begun={self.has_begun} messages={self.messages}>"


class InternalHttpRequest(InternalCallbackHandler, _llhttp.Request):
    def __init__(self):
        super(InternalCallbackHandler, self).__init__()
        super(_llhttp.Request, self).__init__()

    def _is_input(self):
        return True


class InternalHttpResponse(InternalCallbackHandler, _llhttp.Response):
    def __init__(self):
        super(InternalCallbackHandler, self).__init__()
        super(_llhttp.Response, self).__init__()

    def _is_input(self):
        return False


class HttpHistory:
    """
    HTTP History handler for pyfilters.
    Provides access to completed previous requests and responses in the current TCP stream.
    """

    def __init__(
        self,
        requests: list["HttpFullRequest"] | None = None,
        responses: list["HttpFullResponse"] | None = None,
    ):
        self._requests = list(requests) if requests is not None else []
        self._responses = list(responses) if responses is not None else []

    @property
    def requests(self) -> list["HttpFullRequest"]:
        """List of previous completed HTTP requests"""
        return self._requests.copy()

    @property
    def responses(self) -> list["HttpFullResponse"]:
        """List of previous completed HTTP responses"""
        return self._responses.copy()

    @classmethod
    def _fetch_packet(cls, internal_data: DataStreamCtx):
        if (
            internal_data.current_pkt is None
            or internal_data.current_pkt.is_stream is False
        ):
            raise NotReadyToRun()

        for key in ("http_module", "http_full", "http_header"):
            obj = internal_data.call_mem.get(f"_fetched_obj_{key}")
            if obj is not None:
                if isinstance(obj, list) and obj:
                    return [item.history for item in obj]
                elif hasattr(obj, "history"):
                    return obj.history

        req_history_deque = internal_data.data_handler_context.get(
            "http_history_requests", deque()
        )
        resp_history_deque = internal_data.data_handler_context.get(
            "http_history_responses", deque()
        )
        return HttpHistory(list(req_history_deque), list(resp_history_deque))

    def __repr__(self):
        return f"<HttpHistory requests={len(self._requests)} responses={len(self._responses)}>"


HttpStreamHistory = HttpHistory


class InternalBasicHttpMetaClass:
    """Internal class to handle HTTP requests and responses"""

    def __init__(
        self,
        parser: InternalHttpRequest | InternalHttpResponse,
        msg: InternalHTTPMessage,
    ):
        self._parser = parser
        self.raised_error = False
        self._message: InternalHTTPMessage | None = msg
        self._history: HttpHistory | None = None
        self._contructor_hook()

    def _contructor_hook(self):
        pass

    @property
    def history(self) -> HttpHistory:
        """HTTP History for the current stream connection"""
        if self._history is None:
            return HttpHistory([], [])
        return self._history

    @property
    def total_size(self) -> int:
        """Total size of the message"""
        return self._message.total_size

    @property
    def url(self) -> str | None:
        """URL of the message"""
        return self._message.url

    @property
    def headers(self) -> dict[str, str]:
        """Headers of the message"""
        return self._message.headers

    @property
    def user_agent(self) -> str:
        """User agent of the message"""
        return self._message.user_agent

    @property
    def content_encoding(self) -> str:
        """Content encoding of the message"""
        return self._message.content_encoding

    @property
    def body(self) -> bytes:
        """Body of the message"""
        return self._message.body

    @property
    def headers_complete(self) -> bool:
        """If the headers are complete"""
        return self._message.headers_complete

    @property
    def message_complete(self) -> bool:
        """If the message is complete"""
        return self._message.message_complete

    @property
    def http_version(self) -> str:
        """HTTP version of the message"""
        return self._message.http_version

    @property
    def keep_alive(self) -> bool:
        """If the message should keep alive"""
        return self._message.keep_alive

    @property
    def should_upgrade(self) -> bool:
        """If the message should upgrade"""
        return self._message.should_upgrade

    @property
    def content_length(self) -> int | None:
        """Content length of the message"""
        return self._message.content_length

    @property
    def upgrading_to_h2(self) -> bool:
        """If the message is upgrading to HTTP/2"""
        return self._message.upgrading_to_h2

    @property
    def upgrading_to_ws(self) -> bool:
        """If the message is upgrading to Websocket"""
        return self._message.upgrading_to_ws

    @property
    def ws_stream(self) -> list[Frame]:
        """Websocket stream"""
        return self._message.ws_stream

    @property
    def stream(self) -> bytes:
        """Stream of the message"""
        return self._message.stream

    def get_header(self, header: str, default=None) -> str:
        """Get a header from the message without caring about the case"""
        return self._message.lheaders.get(header.lower(), default)

    @classmethod
    def _should_release_message_headers(cls) -> bool:
        return True

    @classmethod
    def _should_release_body_chunks(cls) -> bool:
        return False

    @staticmethod
    def _before_fetch_callable_checks(internal_data: DataStreamCtx) -> bool:
        raise NotImplementedError()

    @staticmethod
    def _parser_class() -> str:
        raise NotImplementedError()

    @classmethod
    def _fetch_packet(cls, internal_data: DataStreamCtx):
        if (
            internal_data.current_pkt is None
            or internal_data.current_pkt.is_stream is False
        ):
            raise NotReadyToRun()

        ParserType = (
            InternalHttpRequest
            if internal_data.current_pkt.is_input
            else InternalHttpResponse
        )
        parser_key = f"{cls._parser_class()}_{'in' if internal_data.current_pkt.is_input else 'out'}"

        parser = internal_data.data_handler_context.get(parser_key, None)
        if parser is None or parser.raised_error:
            parser: InternalHttpRequest | InternalHttpResponse = ParserType()
            internal_data.data_handler_context[parser_key] = parser

        parser.release_message_headers = cls._should_release_message_headers()
        # Set here and not only in the constructor hook, for the same reason the line
        # above is: parsing happens before any instance exists, and a flag applied
        # afterwards would take effect one packet late.
        parser.release_body_chunks = cls._should_release_body_chunks()


        if not internal_data.call_mem.get(
            cls._parser_class(), False
        ):  # Need to parse HTTP
            internal_data.call_mem[cls._parser_class()] = True
            parser.pop_all_messages()  # Delete content on message deque

            # Setting websocket options if needed to the client parser
            if internal_data.current_pkt.is_input:
                ext_opt = internal_data.data_handler_context.get(
                    f"{cls._parser_class()}_ws_options_client"
                )
                if ext_opt is not None and parser._ws_extentions != ext_opt:
                    parser._ws_extentions = ext_opt

            # Memory size managment
            if (
                parser.total_size + len(internal_data.current_pkt.data)
                > internal_data.stream_max_size
            ):
                match internal_data.full_stream_action:
                    case FullStreamAction.FLUSH:
                        # Deleting parser and re-creating it
                        parser.messages.clear()
                        parser.msg.total_size -= len(parser.msg.stream)
                        parser.msg.stream = b""
                        parser.msg.total_size -= len(parser.msg.body)
                        parser.msg.body = b""
                        print("[WARNING] Flushing stream", flush=True)
                        if (
                            parser.total_size + len(internal_data.current_pkt.data)
                            > internal_data.stream_max_size
                        ):
                            parser.reset_data()
                    case FullStreamAction.REJECT:
                        raise StreamFullReject()
                    case FullStreamAction.DROP:
                        raise StreamFullDrop()
                    case FullStreamAction.ACCEPT:
                        raise NotReadyToRun()

            internal_data.call_mem["headers_were_set"] = (
                parser.msg.headers_complete
            )  # This information is usefull for building the real object

            try:
                parser.parse_data(internal_data.current_pkt.data)
            except Exception as e:
                traceback.print_exc()
                match internal_data.invalid_encoding_action:
                    case ExceptionAction.REJECT:
                        raise RejectConnection()
                    case ExceptionAction.DROP:
                        raise DropPacket()
                    case ExceptionAction.NOACTION:
                        raise e
                    case ExceptionAction.ACCEPT:
                        raise NotReadyToRun()

            if parser.should_upgrade and not internal_data.current_pkt.is_input:
                # Creating ws_option for the client
                if not internal_data.data_handler_context.get(
                    f"{cls._parser_class()}_ws_options_client"
                ):
                    ext = parser._parse_websocket_ext()
                    internal_data.data_handler_context[
                        f"{cls._parser_class()}_ws_options_client"
                    ] = ext

        # Once the parsers has been triggered, we can return the object if needed
        if not cls._before_fetch_callable_checks(internal_data):
            raise NotReadyToRun()

        messages_tosend: list[InternalHTTPMessage] = []
        for i in range(len(parser.messages)):
            messages_tosend.append(parser.pop_message())

        if len(messages_tosend) > 0:
            internal_data.call_mem["headers_were_set"] = (
                False  # New messages completed so the current message headers were not set in this case
            )

        if (
            not internal_data.call_mem["headers_were_set"]
            and parser.msg.headers_complete
            and not parser.msg.message_complete
            and parser.release_message_headers
        ):
            # The message still being read, handed over early because its headers are
            # already known — which is what lets a filter act before a body arrives.
            #
            # `not message_complete` is the load-bearing half. `on_message_complete`
            # appends the finished message to the queue but leaves `parser.msg` pointing
            # at it, so without this a packet carrying two pipelined messages delivered
            # the second one twice: once from the queue and once from here. Blocking is
            # idempotent and survived that, which is why it went unnoticed — anything
            # that counts did not.
            messages_tosend.append(parser.msg)

        if (
            parser.release_body_chunks
            and parser._body_chunk_pending
            and not parser.msg.message_complete
            and not any(msg is parser.msg for msg in messages_tosend)
        ):
            # A body still arriving, handed over as it does. Identity rather than
            # equality on the guard: `InternalHTTPMessage` is a dataclass, so `in` would
            # compare every field of every message to decide something that is a question
            # about which object this is.
            messages_tosend.append(parser.msg)
        parser._body_chunk_pending = False

        if parser._packet_to_stream():
            messages_tosend.append(
                parser.msg
            )  # Also the current message needs to beacase a stream is going on

        messages_to_call = len(messages_tosend)

        if messages_to_call == 0:
            raise NotReadyToRun()

        raw_max = internal_data.filter_glob.get("FGEX_MAX_HISTORY_SIZE", 100)
        try:
            max_history = max(0, int(raw_max))
        except (ValueError, TypeError):
            max_history = 100

        req_history_deque: deque = (
            internal_data.data_handler_context.setdefault(
                "http_history_requests", deque(maxlen=max_history)
            )
        )
        if req_history_deque.maxlen != max_history:
            req_history_deque = deque(req_history_deque, maxlen=max_history)
            internal_data.data_handler_context["http_history_requests"] = req_history_deque

        resp_history_deque: deque = (
            internal_data.data_handler_context.setdefault(
                "http_history_responses", deque(maxlen=max_history)
            )
        )
        if resp_history_deque.maxlen != max_history:
            resp_history_deque = deque(resp_history_deque, maxlen=max_history)
            internal_data.data_handler_context["http_history_responses"] = resp_history_deque

        built_instances = []
        for msg in messages_tosend:
            history_snapshot = HttpHistory(
                list(req_history_deque), list(resp_history_deque)
            )
            instance = cls(parser, msg)
            instance._history = history_snapshot
            built_instances.append(instance)

            if msg.message_complete and not msg.added_to_history:
                msg.added_to_history = True
                if internal_data.current_pkt.is_input:
                    req_history_deque.append(HttpFullRequest(parser, msg))
                else:
                    resp_history_deque.append(HttpFullResponse(parser, msg))

        if len(built_instances) == 1:
            res = built_instances[0]
            internal_data.call_mem[f"_fetched_obj_{cls._parser_class()}"] = res
            return res

        internal_data.call_mem[f"_fetched_obj_{cls._parser_class()}"] = built_instances
        return built_instances



class HttpRequest(InternalBasicHttpMetaClass):
    """
    HTTP Request handler
    This data handler will be called twice, first with the headers complete, and second with the body complete
    """

    @staticmethod
    def _before_fetch_callable_checks(internal_data: DataStreamCtx):
        return internal_data.current_pkt.is_input

    @property
    def method(self) -> bytes:
        """Method of the request"""
        return self._message.method

    @staticmethod
    def _parser_class() -> str:
        return "http_module"

    def __repr__(self):
        return f"<HttpRequest method={self.method} url={self.url} headers={self.headers} body=[{0 if not self.body else len(self.body)} bytes] http_version={self.http_version} keep_alive={self.keep_alive} should_upgrade={self.should_upgrade} headers_complete={self.headers_complete} message_complete={self.message_complete} content_length={self.content_length} stream={self.stream} ws_stream={self.ws_stream}>"


class HttpResponse(InternalBasicHttpMetaClass):
    """
    HTTP Response handler
    This data handler will be called twice, first with the headers complete, and second with the body complete
    """

    @staticmethod
    def _before_fetch_callable_checks(internal_data: DataStreamCtx):
        return not internal_data.current_pkt.is_input

    @property
    def status_code(self) -> int | None:
        """The numeric status, e.g. `404`.

        This used to hand back the reason phrase while being documented and annotated as
        an int, so `if res.status_code == 500` never matched and nothing said why. It was
        not carelessness: the binding did not expose llhttp's status code, and there was
        no way to reach it. The binding ships with this package now and does.
        """
        return self._message.status_code

    @property
    def status_phrase(self) -> str | None:
        """The reason phrase, e.g. `"Not Found"`.

        Free text — a server may write anything here — so read it and decide on the code
        above, a header, or the body.
        """
        return self._message.status


    @staticmethod
    def _parser_class() -> str:
        return "http_module"

    def __repr__(self):
        return f"<HttpResponse status_code={self.status_code} status_phrase={self.status_phrase!r} url={self.url} headers={self.headers} body=[{0 if not self.body else len(self.body)} bytes] http_version={self.http_version} keep_alive={self.keep_alive} should_upgrade={self.should_upgrade} headers_complete={self.headers_complete} message_complete={self.message_complete} content_length={self.content_length} stream={self.stream} ws_stream={self.ws_stream}>"


class HttpFullRequest(HttpRequest):
    """
    HTTP Request handler
    This data handler will be called when the request data is complete
    """

    @classmethod
    def _should_release_message_headers(cls) -> bool:
        return False

    def _contructor_hook(self):
        self._parser.release_message_headers = False

    @staticmethod
    def _parser_class() -> str:
        return "http_full"

    def __repr__(self):
        return f"<HttpFullRequest method={self.method} url={self.url} headers={self.headers} body=[{0 if not self.body else len(self.body)} bytes] http_version={self.http_version} keep_alive={self.keep_alive} should_upgrade={self.should_upgrade} headers_complete={self.headers_complete} message_complete={self.message_complete} content_length={self.content_length} stream={self.stream} ws_stream={self.ws_stream}>"


class HttpFullResponse(HttpResponse):
    """
    HTTP Response handler
    This data handler will be called when the response data is complete
    """

    @classmethod
    def _should_release_message_headers(cls) -> bool:
        return False

    def _contructor_hook(self):
        self._parser.release_message_headers = False

    @staticmethod
    def _parser_class() -> str:
        return "http_full"

    def __repr__(self):
        return f"<HttpFullResponse status_code={self.status_code} status_phrase={self.status_phrase!r} url={self.url} headers={self.headers} body=[{0 if not self.body else len(self.body)} bytes] http_version={self.http_version} keep_alive={self.keep_alive} should_upgrade={self.should_upgrade} headers_complete={self.headers_complete} message_complete={self.message_complete} content_length={self.content_length} stream={self.stream} ws_stream={self.ws_stream}>"



class HttpRequestHeader(HttpRequest):
    """
    HTTP Request Header handler
    This data handler will be called only once, the headers are complete, the body will be empty and not buffered
    """

    def _contructor_hook(self):
        self._parser.save_body = False

    @staticmethod
    def _parser_class() -> str:
        return "http_header"


class HttpResponseHeader(HttpResponse):
    """
    HTTP Response Header handler
    This data handler will be called only once, the headers are complete, the body will be empty and not buffered
    """

    def _contructor_hook(self):
        self._parser.save_body = False

    @staticmethod
    def _parser_class() -> str:
        return "http_header"


#: The header in front of every gRPC message: one flag byte, then a big-endian length.
GRPC_HEADER_SIZE = 5


@dataclass
class GrpcFrame:
    """One length-prefixed message out of a gRPC body."""

    #: Whether this message is compressed, which its own flag byte says. What it is
    #: compressed *with* is `grpc-encoding` on the message that carried it.
    compressed: bool
    #: The bytes between the length prefix and the next one — a protobuf message, in
    #: whatever schema the two ends agreed on out of band.
    payload: bytes


def _grpc_frames(msg: InternalHTTPMessage) -> list[GrpcFrame]:
    """Take every complete message the body has grown since the last look.

    Nothing is allocated on a claimed length: a frame is taken only once the bytes behind
    it have actually arrived, so a header claiming four gigabytes costs nothing but the
    wait — and the wait is already bounded by `FGEX_STREAM_MAX_SIZE`, which is what stops
    a sender buying memory in this process.
    """
    body = msg.body or b""
    taken: list[GrpcFrame] = []
    at = msg.grpc_consumed
    while len(body) - at >= GRPC_HEADER_SIZE:
        length = int.from_bytes(body[at + 1 : at + GRPC_HEADER_SIZE], "big")
        end = at + GRPC_HEADER_SIZE + length
        if len(body) < end:
            break
        taken.append(
            GrpcFrame(compressed=body[at] != 0, payload=body[at + GRPC_HEADER_SIZE : end])
        )
        at = end
    msg.grpc_consumed = at
    return taken


def _speaks_grpc(msg: InternalHTTPMessage) -> bool:
    return (msg.content_type or "").lower().startswith("application/grpc")


def _body_can_be_framed(msg: InternalHTTPMessage) -> bool:
    """Whether the body as it stands can be read as gRPC frames at all.

    A `content-encoding` is undone once, when the message finishes, so while one is in
    the way the bytes in hand are compressed and the framing is not in them. gRPC does not
    use it — it compresses each message on its own and says so in the frame's flag byte —
    so in practice this only ever declines for traffic that was never gRPC to begin with.
    """
    if msg.message_complete:
        return True
    encodings = {e.strip() for e in (msg.content_encoding or "").lower().split(",")}
    return not (encodings - {"", "identity"})


class GrpcMessage(InternalBasicHttpMetaClass):
    """One gRPC message, in either direction.

    gRPC is HTTP/2, so everything a filter could already ask about the exchange — the
    method in the path, the headers, the trailer section carrying `grpc-status` — arrives
    through `HttpRequest` and `HttpResponse`, because the engine renders every version of
    HTTP as HTTP/1.1 before the chain sees it. What did not arrive was the *body*: a gRPC
    body is a sequence of length-prefixed messages, so a filter reading `request.body` was
    reading a five-byte header glued to a protobuf blob, and a pattern written against the
    payload had to know to skip it.

    This hands over one message at a time, as each one completes. It is called **per
    message and not per body**, which is what makes it usable on a streaming RPC: a
    server-streaming or bidirectional call has a body that does not finish until the
    stream does, and a filter shown only finished bodies would be called once, at the end.

    What it does **not** do is decompress a message whose own flag byte says it is
    compressed, or decode the protobuf inside it. The first because what it is compressed
    with is the peers' agreement (`grpc-encoding`) and guessing is how a filter comes to
    read something that is not there; the second because without the `.proto` there is no
    schema, and a pattern against the raw payload is what a ruleset has today.
    """

    @staticmethod
    def _before_fetch_callable_checks(internal_data: DataStreamCtx) -> bool:
        return True

    @staticmethod
    def _parser_class() -> str:
        return "http_grpc"

    @classmethod
    def _should_release_message_headers(cls) -> bool:
        # There is no message to show at the head: a gRPC exchange is its messages, and
        # what is in the headers is what `HttpRequest` is for.
        return False

    @classmethod
    def _should_release_body_chunks(cls) -> bool:
        return True

    def _contructor_hook(self):
        self._parser.release_message_headers = False
        self._parser.release_body_chunks = True
        self._frame: GrpcFrame | None = None
        self._is_input: bool = True

    @classmethod
    def _fetch_packet(cls, internal_data: DataStreamCtx):
        # The base drives the parser and decides which messages are ready; this only
        # takes the gRPC framing out of the ones that have it. Written that way round so
        # there is still exactly one HTTP parser in this library and this is not a second.
        carried = super()._fetch_packet(internal_data)
        if not isinstance(carried, list):
            carried = [carried]

        pieces = []
        for one in carried:
            msg = one._message
            if not _speaks_grpc(msg) or not _body_can_be_framed(msg):
                continue
            for frame in _grpc_frames(msg):
                piece = cls(one._parser, msg)
                piece._history = one._history
                piece._frame = frame
                piece._is_input = internal_data.current_pkt.is_input
                pieces.append(piece)

        if not pieces:
            # Not "nothing matched" but "there is nothing to show yet" — a body half-way
            # through a message, or an exchange that is not gRPC at all. The filter is not
            # called, which is what `NotReadyToRun` means everywhere else.
            raise NotReadyToRun()

        result = pieces[0] if len(pieces) == 1 else pieces
        internal_data.call_mem[f"_fetched_obj_{cls._parser_class()}"] = result
        return result

    @property
    def payload(self) -> bytes:
        """This message's bytes: the protobuf, without the length prefix."""
        return self._frame.payload if self._frame else b""

    @property
    def compressed(self) -> bool:
        """Whether this message's own flag byte says it is compressed.

        What with is `grpc-encoding` on the message that carried it. Nothing here
        decompresses it, so `payload` is the compressed bytes when this is true.
        """
        return bool(self._frame and self._frame.compressed)

    @property
    def is_request(self) -> bool:
        """Whether this went from the client towards the service."""
        return self._is_input

    @property
    def method(self) -> str | None:
        """The gRPC method, which is the HTTP path: `/package.Service/Method`.

        Present on both directions, because both halves of an exchange belong to the same
        stream and the engine renders the request that opened it.
        """
        return self.url

    @property
    def grpc_status(self) -> str | None:
        """The status, where the message carrying this frame stated one.

        A gRPC status lives in the trailer section, and on a reply that refuses before
        sending anything it lives in the headers instead — the *trailers-only* shape. Read
        it where it is; on a reply that is still streaming it is not there yet, and this
        is `None` rather than a guess.
        """
        return self.get_header("grpc-status")

    def __repr__(self):
        return (
            f"<GrpcMessage method={self.method} "
            f"{'request' if self.is_request else 'response'} "
            f"payload=[{len(self.payload)} bytes] compressed={self.compressed} "
            f"grpc_status={self.grpc_status}>"
        )


class GrpcRequest(GrpcMessage):
    """A gRPC message on its way to the service, and nothing coming back."""

    @staticmethod
    def _before_fetch_callable_checks(internal_data: DataStreamCtx) -> bool:
        return internal_data.current_pkt.is_input

    @staticmethod
    def _parser_class() -> str:
        # Its own parser, as `HttpFullRequest` has one beside `HttpRequest`. Not tidiness:
        # taking a frame *consumes* it, so two models sharing one parser would mean the
        # second one is handed nothing and silently never runs.
        return "http_grpc_req"


class GrpcResponse(GrpcMessage):
    """A gRPC message on its way back to the client."""

    @staticmethod
    def _before_fetch_callable_checks(internal_data: DataStreamCtx) -> bool:
        return not internal_data.current_pkt.is_input

    @staticmethod
    def _parser_class() -> str:
        return "http_grpc_res"
