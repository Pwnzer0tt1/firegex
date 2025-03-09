import pyllhttp         
from firegex.nfproxy.internals.exceptions import NotReadyToRun
from firegex.nfproxy.internals.data import DataStreamCtx
from firegex.nfproxy.internals.exceptions import StreamFullDrop, StreamFullReject, RejectConnection, DropPacket
from firegex.nfproxy.internals.models import FullStreamAction, ExceptionAction
from dataclasses import dataclass, field
from collections import deque
from typing import Type

@dataclass
class InternalHTTPMessage:
    """Internal class to handle HTTP messages"""
    url: str|None = field(default=None)
    headers: dict[str, str] = field(default_factory=dict)
    lheaders: dict[str, str] = field(default_factory=dict) # lowercase copy of the headers
    body: bytes|None = field(default=None)
    headers_complete: bool = field(default=False)
    message_complete: bool = field(default=False)
    status: str|None = field(default=None)
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

@dataclass
class InternalHttpBuffer:
    """Internal class to handle HTTP messages"""
    _url_buffer: bytes = field(default_factory=bytes)
    _header_fields: dict[bytes, bytes] = field(default_factory=dict)
    _body_buffer: bytes = field(default_factory=bytes)
    _status_buffer: bytes = field(default_factory=bytes)
    _current_header_field: bytes = field(default_factory=bytes)
    _current_header_value: bytes = field(default_factory=bytes)

class InternalCallbackHandler():
    
    buffers = InternalHttpBuffer()
    msg = InternalHTTPMessage()
    save_body = True
    raised_error = False
    has_begun = False
    messages: deque[InternalHTTPMessage] = deque()

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
        pass # Nothing to do
        
    def on_header_value(self, value):
        self.msg.total_size += len(value)
        self.buffers._current_header_value += value

    def on_header_value_complete(self):
        if self.buffers._current_header_field:
            self.buffers._header_fields[self.buffers._current_header_field.decode(errors="ignore")] = self.buffers._current_header_value.decode(errors="ignore")
        self.buffers._current_header_field = b""
        self.buffers._current_header_value = b""
    
    def on_headers_complete(self):
        self.msg.headers = self.buffers._header_fields
        self.msg.lheaders = {k.lower(): v for k, v in self.buffers._header_fields.items()}
        self.buffers._header_fields = {}
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
        self.buffers._body_buffer = b""
        try:
            if "gzip" in self.content_encoding.lower():
                import gzip
                import io
                with gzip.GzipFile(fileobj=io.BytesIO(self.msg.body)) as f:
                    self.msg.body = f.read()
        except Exception as e:
            print(f"Error decompressing gzip: {e}: skipping", flush=True)
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
    
    def _packet_to_stream(self):
        return self.should_upgrade and self.save_body
    
    def parse_data(self, data: bytes):
        if self._packet_to_stream(): # This is a websocket upgrade!
            self.msg.message_complete = True # The message is complete but becomed a stream, so need to be called every time a new packet is received
            self.msg.total_size += len(data)
            self.msg.stream += data #buffering stream
        else:
            try:
                self.execute(data)
            except Exception as e:
                self.raised_error = True
                print(f"Error parsing HTTP packet: {e} with data {data}", flush=True)
                raise e
    
    def pop_message(self):
        return self.messages.popleft()
    
    def __repr__(self):
        return f"<InternalCallbackHandler msg={self.msg} buffers={self.buffers} save_body={self.save_body} raised_error={self.raised_error} has_begun={self.has_begun} messages={self.messages}>"
    

class InternalHttpRequest(InternalCallbackHandler, pyllhttp.Request):
    def __init__(self):
        super(InternalCallbackHandler, self).__init__()
        super(pyllhttp.Request, self).__init__()
        
class InternalHttpResponse(InternalCallbackHandler, pyllhttp.Response):
    def __init__(self):
        super(InternalCallbackHandler, self).__init__()
        super(pyllhttp.Response, self).__init__()
        
class InternalBasicHttpMetaClass:
    """Internal class to handle HTTP requests and responses"""
    
    def __init__(self, parser: InternalHttpRequest|InternalHttpResponse, msg: InternalHTTPMessage):
        self._parser = parser
        self.stream = b""
        self.raised_error = False
        self._message: InternalHTTPMessage|None = msg
        self._contructor_hook()
    
    def _contructor_hook(self):
        pass
    
    @property
    def total_size(self) -> int:
        """Total size of the stream"""
        return self._parser.total_size
    
    @property
    def url(self) -> str|None:
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
    def content_length(self) -> int|None:
        """Content length of the message"""
        return self._message.content_length
    
    def get_header(self, header: str, default=None) -> str:
        """Get a header from the message without caring about the case"""
        return self._message.lheaders.get(header.lower(), default)
    
    @staticmethod
    def _associated_parser_class() -> Type[InternalHttpRequest]|Type[InternalHttpResponse]:
        raise NotImplementedError()
    
    @staticmethod
    def _before_fetch_callable_checks(internal_data: DataStreamCtx):
        return True
    
    @classmethod
    def _fetch_packet(cls, internal_data: DataStreamCtx):
        if internal_data.current_pkt is None or internal_data.current_pkt.is_tcp is False:
            raise NotReadyToRun()
        
        ParserType = cls._associated_parser_class()
        
        parser = internal_data.data_handler_context.get(cls, None)
        if parser is None or parser.raised_error:
            parser: InternalHttpRequest|InternalHttpResponse = ParserType()
            internal_data.data_handler_context[cls] = parser
        
        if not cls._before_fetch_callable_checks(internal_data):
            raise NotReadyToRun()

        # Memory size managment
        if parser.total_size+len(internal_data.current_pkt.data) > internal_data.stream_max_size:
            match internal_data.full_stream_action:
                case FullStreamAction.FLUSH:
                    # Deleting parser and re-creating it
                    parser.messages.clear()
                    parser.msg.total_size -= len(parser.msg.stream)
                    parser.msg.stream = b""
                    parser.msg.total_size -= len(parser.msg.body)
                    parser.msg.body = b""
                    print("[WARNING] Flushing stream", flush=True)
                    if parser.total_size+len(internal_data.current_pkt.data) > internal_data.stream_max_size:
                        parser.reset_data()
                case FullStreamAction.REJECT:
                    raise StreamFullReject()
                case FullStreamAction.DROP:
                    raise StreamFullDrop()
                case FullStreamAction.ACCEPT:
                    raise NotReadyToRun()
        
        headers_were_set = parser.msg.headers_complete
        try:
            parser.parse_data(internal_data.current_pkt.data)
        except Exception as e:
            match internal_data.invalid_encoding_action:
                case ExceptionAction.REJECT:
                    raise RejectConnection()
                case ExceptionAction.DROP:
                    raise DropPacket()
                case ExceptionAction.NOACTION:
                    raise e
                case ExceptionAction.ACCEPT:
                    raise NotReadyToRun()

        messages_tosend:list[InternalHTTPMessage] = []
        for i in range(len(parser.messages)):
            messages_tosend.append(parser.pop_message())
        
        if len(messages_tosend) > 0:
            headers_were_set = False # New messages completed so the current message headers were not set in this case
        
        if not headers_were_set and parser.msg.headers_complete:
            messages_tosend.append(parser.msg) # Also the current message needs to be sent due to complete headers
        
        if headers_were_set and parser.msg.message_complete and parser.msg.should_upgrade and parser.save_body:
            messages_tosend.append(parser.msg) # Also the current message needs to beacase a websocket stream is going on
        
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
    def _associated_parser_class() -> Type[InternalHttpRequest]:
        return InternalHttpRequest

    @staticmethod
    def _before_fetch_callable_checks(internal_data: DataStreamCtx):
        return internal_data.current_pkt.is_input

    @property
    def method(self) -> bytes:
        """Method of the request"""
        return self._parser.msg.method
    
    def __repr__(self):
        return f"<HttpRequest method={self.method} url={self.url} headers={self.headers} body={self.body} http_version={self.http_version} keep_alive={self.keep_alive} should_upgrade={self.should_upgrade} headers_complete={self.headers_complete} message_complete={self.message_complete} content_length={self.content_length} stream={self.stream}>"

class HttpResponse(InternalBasicHttpMetaClass):
    """
    HTTP Response handler
    This data handler will be called twice, first with the headers complete, and second with the body complete
    """

    @staticmethod
    def _associated_parser_class() -> Type[InternalHttpResponse]:
        return InternalHttpResponse

    @staticmethod
    def _before_fetch_callable_checks(internal_data: DataStreamCtx):
        return not internal_data.current_pkt.is_input

    @property
    def status_code(self) -> int:
        """Status code of the response"""
        return self._parser.msg.status
    
    def __repr__(self):
        return f"<HttpResponse status_code={self.status_code} url={self.url} headers={self.headers} body={self.body} http_version={self.http_version} keep_alive={self.keep_alive} should_upgrade={self.should_upgrade} headers_complete={self.headers_complete} message_complete={self.message_complete} content_length={self.content_length} stream={self.stream}>"

class HttpRequestHeader(HttpRequest):
    """
    HTTP Request Header handler
    This data handler will be called only once, the headers are complete, the body will be empty and not buffered
    """
        
    def _contructor_hook(self):
        self._parser.save_body = False

class HttpResponseHeader(HttpResponse):
    """
    HTTP Response Header handler
    This data handler will be called only once, the headers are complete, the body will be empty and not buffered
    """
    
    def _contructor_hook(self):
        self._parser.save_body = False