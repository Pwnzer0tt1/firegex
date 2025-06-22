import pyllhttp
from firegex.nfproxy.internals.exceptions import NotReadyToRun
from firegex.nfproxy.internals.data import DataStreamCtx
from firegex.nfproxy.internals.exceptions import (
    StreamFullDrop,
    StreamFullReject,
    RejectConnection,
    DropPacket,
)
from firegex.nfproxy.internals.models import FullStreamAction, ExceptionAction
from dataclasses import dataclass, field
from collections import deque
from zstd import ZSTD_uncompress
import gzip
import io
import zlib
import brotli
import traceback
from websockets.frames import Frame
from websockets.extensions.permessage_deflate import PerMessageDeflate
from pyllhttp import PAUSED_H2_UPGRADE, PAUSED_UPGRADE


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
    status: str | None = field(default=None)
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

    def reset_data(self):
        self.msg = InternalHTTPMessage()
        self.buffers = InternalHttpBuffer()
        self.messages.clear()

    def on_message_begin(self):
        self.buffers = InternalHttpBuffer()
        self.msg = InternalHTTPMessage()
        self.has_begun = True

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
                try:
                    decompress = zlib.decompressobj(-zlib.MAX_WBITS)
                    decoding_body = decompress.decompress(decoding_body)
                    decoding_body += decompress.flush()
                except Exception as e:
                    print(f"Error decompressing deflate: {e}: skipping", flush=True)
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
                    decoding_body = ZSTD_uncompress(decoding_body)
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
        if self.major and self.minor:
            return f"{self.major}.{self.minor}"
        else:
            return ""

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


class InternalHttpRequest(InternalCallbackHandler, pyllhttp.Request):
    def __init__(self):
        super(InternalCallbackHandler, self).__init__()
        super(pyllhttp.Request, self).__init__()

    def _is_input(self):
        return True


class InternalHttpResponse(InternalCallbackHandler, pyllhttp.Response):
    def __init__(self):
        super(InternalCallbackHandler, self).__init__()
        super(pyllhttp.Response, self).__init__()

    def _is_input(self):
        return False


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
        self._contructor_hook()

    def _contructor_hook(self):
        pass

    @property
    def total_size(self) -> int:
        """Total size of the stream"""
        return self._parser.total_size

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
        return self._parser.should_upgrade

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
            or internal_data.current_pkt.is_tcp is False
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
            and parser.release_message_headers
        ):
            messages_tosend.append(
                parser.msg
            )  # Also the current message needs to be sent due to complete headers

        if parser._packet_to_stream():
            messages_tosend.append(
                parser.msg
            )  # Also the current message needs to beacase a stream is going on

        messages_to_call = len(messages_tosend)

        if messages_to_call == 0:
            raise NotReadyToRun()
        elif messages_to_call == 1:
            return cls(parser, messages_tosend[0])

        return [cls(parser, ele) for ele in messages_tosend]


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
        return self._parser.msg.method

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
    def status_code(self) -> int:
        """Status code of the response"""
        return self._parser.msg.status

    @staticmethod
    def _parser_class() -> str:
        return "http_module"

    def __repr__(self):
        return f"<HttpResponse status_code={self.status_code} url={self.url} headers={self.headers} body=[{0 if not self.body else len(self.body)} bytes] http_version={self.http_version} keep_alive={self.keep_alive} should_upgrade={self.should_upgrade} headers_complete={self.headers_complete} message_complete={self.message_complete} content_length={self.content_length} stream={self.stream} ws_stream={self.ws_stream}>"


class HttpFullRequest(HttpRequest):
    """
    HTTP Request handler
    This data handler will be called when the request data is complete
    """

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

    def _contructor_hook(self):
        self._parser.release_message_headers = False

    @staticmethod
    def _parser_class() -> str:
        return "http_full"

    def __repr__(self):
        return f"<HttpFullResponse status_code={self.status_code} url={self.url} headers={self.headers} body=[{0 if not self.body else len(self.body)} bytes] http_version={self.http_version} keep_alive={self.keep_alive} should_upgrade={self.should_upgrade} headers_complete={self.headers_complete} message_complete={self.message_complete} content_length={self.content_length} stream={self.stream} ws_stream={self.ws_stream}>"


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
