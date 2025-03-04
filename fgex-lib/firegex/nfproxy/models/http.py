import pyllhttp         
from firegex.nfproxy.internals.exceptions import NotReadyToRun
from firegex.nfproxy.internals.data import DataStreamCtx
from firegex.nfproxy.internals.exceptions import StreamFullDrop, StreamFullReject
from firegex.nfproxy.internals.models import FullStreamAction

class InternalCallbackHandler():
    
    url: str|None = None
    _url_buffer: bytes = b""
    headers: dict[str, str] = {}
    lheaders: dict[str, str] = {} # Lowercase headers
    _header_fields: dict[bytes, bytes] = {}
    has_begun: bool = False
    body: bytes = None
    _body_buffer: bytes = b""
    headers_complete: bool = False
    message_complete: bool = False
    status: str|None = None
    _status_buffer: bytes = b""
    _current_header_field = b""
    _current_header_value = b""
    _save_body = True
    total_size = 0

    def on_message_begin(self):
        self.has_begun = True
    
    def on_url(self, url):
        self.total_size += len(url)
        self._url_buffer += url
    
    def on_url_complete(self):
        self.url = self._url_buffer.decode(errors="ignore")
        self._url_buffer = None
    
    def on_header_field(self, field):
        self.total_size += len(field)
        self._current_header_field += field

    def on_header_field_complete(self):
        self._current_header_field = self._current_header_field
        
    def on_header_value(self, value):
        self.total_size += len(value)
        self._current_header_value += value

    def on_header_value_complete(self):
        if self._current_header_value is not None and self._current_header_field is not None:
            self._header_fields[self._current_header_field.decode(errors="ignore")] = self._current_header_value.decode(errors="ignore")
        self._current_header_field = b""
        self._current_header_value = b""
    
    def on_headers_complete(self):
        self.headers_complete = True
        self.headers = self._header_fields
        self.lheaders = {k.lower(): v for k, v in self._header_fields.items()}
        self._header_fields = {}
        self._current_header_field = b""
        self._current_header_value = b""

    def on_body(self, body: bytes):
        if self._save_body:
            self.total_size += len(body)
            self._body_buffer += body

    def on_message_complete(self):
        self.body = self._body_buffer
        self._body_buffer = b""
        try:
            if "gzip" in self.content_encoding.lower():
                import gzip
                import io
                with gzip.GzipFile(fileobj=io.BytesIO(self.body)) as f:
                    self.body = f.read()
        except Exception as e:
            print(f"Error decompressing gzip: {e}: skipping", flush=True)
        self.message_complete = True
    
    def on_status(self, status: bytes):
        self.total_size += len(status)
        self._status_buffer += status
    
    def on_status_complete(self):
        self.status = self._status_buffer.decode(errors="ignore")
        self._status_buffer = b""
    
    @property
    def user_agent(self) -> str:
        return self.lheaders.get("user-agent", "")
    
    @property
    def content_encoding(self) -> str:
        return self.lheaders.get("content-encoding", "")
    
    @property
    def content_type(self) -> str:
        return self.lheaders.get("content-type", "")

    @property
    def keep_alive(self) -> bool:
        return self.should_keep_alive

    @property
    def should_upgrade(self) -> bool:
        return self.is_upgrading
    
    @property
    def http_version(self) -> str:
        return f"{self.major}.{self.minor}"
    
    @property
    def method_parsed(self) -> str:
        return self.method.decode(errors="ignore")
    
    @property
    def content_length_parsed(self) -> int:
        return self.content_length
    

class InternalHttpRequest(InternalCallbackHandler, pyllhttp.Request):
    def __init__(self):
        super(InternalCallbackHandler, self).__init__()
        super(pyllhttp.Request, self).__init__()
        
class InternalHttpResponse(InternalCallbackHandler, pyllhttp.Response):
    def __init__(self):
        super(InternalCallbackHandler, self).__init__()
        super(pyllhttp.Response, self).__init__()
        
class InternalBasicHttpMetaClass:
    
    def __init__(self):
        self._parser: InternalHttpRequest|InternalHttpResponse
        self._headers_were_set = False
        self.stream = b""
        self.raised_error = False
    
    @property
    def total_size(self) -> int:
        return self._parser.total_size
    
    @property
    def url(self) -> str|None:
        return self._parser.url
    
    @property
    def headers(self) -> dict[str, str]:
        return self._parser.headers
    
    @property
    def user_agent(self) -> str:
        return self._parser.user_agent
    
    @property
    def content_encoding(self) -> str:
        return self._parser.content_encoding
    
    @property
    def has_begun(self) -> bool:
        return self._parser.has_begun
    
    @property
    def body(self) -> bytes:
        return self._parser.body
    
    @property
    def headers_complete(self) -> bool:
        return self._parser.headers_complete
    
    @property
    def message_complete(self) -> bool:
        return self._parser.message_complete
    
    @property
    def http_version(self) -> str:
        return self._parser.http_version

    @property
    def keep_alive(self) -> bool:
        return self._parser.keep_alive

    @property
    def should_upgrade(self) -> bool:
        return self._parser.should_upgrade

    @property
    def content_length(self) -> int|None:
        return self._parser.content_length_parsed
    
    @property
    def method(self) -> str|None:
        return self._parser.method_parsed
    
    def get_header(self, header: str, default=None) -> str:
        return self._parser.lheaders.get(header.lower(), default)
    
    def _packet_to_stream(self, internal_data: DataStreamCtx):
        return self.should_upgrade and self._parser._save_body
    
    def _fetch_current_packet(self, internal_data: DataStreamCtx):
        if self._packet_to_stream(internal_data): # This is a websocket upgrade!
            self._parser.total_size += len(internal_data.current_pkt.data)
            self.stream += internal_data.current_pkt.data
        else:
            try:
                self._parser.execute(internal_data.current_pkt.data)
                if not self._parser.message_complete and self._parser.headers_complete and len(self._parser._body_buffer) == self._parser.content_length_parsed:
                    self._parser.on_message_complete()
            except Exception as e:
                self.raised_error = True
                print(f"Error parsing HTTP packet: {e} {internal_data.current_pkt}", self, flush=True)
                raise e

    #It's called the first time if the headers are complete, and second time with body complete
    def _after_fetch_callable_checks(self, internal_data: DataStreamCtx):
        if self._parser.headers_complete and not self._headers_were_set:
            self._headers_were_set = True
            return True
        return self._parser.message_complete or self.should_upgrade
    
    def _before_fetch_callable_checks(self, internal_data: DataStreamCtx):
        return True

    def _trigger_remove_data(self, internal_data: DataStreamCtx):
        return self.message_complete and not self.should_upgrade
    
    @classmethod
    def _fetch_packet(cls, internal_data: DataStreamCtx):
        if internal_data.current_pkt is None or internal_data.current_pkt.is_tcp is False:
            raise NotReadyToRun()
        
        datahandler:InternalBasicHttpMetaClass = internal_data.data_handler_context.get(cls, None)
        if datahandler is None or datahandler.raised_error:
            datahandler = cls()
            internal_data.data_handler_context[cls] = datahandler
        
        if not datahandler._before_fetch_callable_checks(internal_data):
            raise NotReadyToRun()

        # Memory size managment
        if datahandler.total_size+len(internal_data.current_pkt.data) > internal_data.stream_max_size:
            match internal_data.full_stream_action:
                case FullStreamAction.FLUSH:
                    datahandler = cls()
                    internal_data.data_handler_context[cls] = datahandler
                case FullStreamAction.REJECT:
                    raise StreamFullReject()
                case FullStreamAction.DROP:
                    raise StreamFullDrop()
                case FullStreamAction.ACCEPT:
                    raise NotReadyToRun()
        
        datahandler._fetch_current_packet(internal_data)

        if not datahandler._after_fetch_callable_checks(internal_data):
            raise NotReadyToRun()
        
        if datahandler._trigger_remove_data(internal_data):
            if internal_data.data_handler_context.get(cls):
                del internal_data.data_handler_context[cls]
        
        return datahandler

class HttpRequest(InternalBasicHttpMetaClass):
    def __init__(self):
        super().__init__()
        # These will be used in the metaclass
        self._parser: InternalHttpRequest = InternalHttpRequest()
        self._headers_were_set = False

    @property
    def method(self) -> bytes:
        return self._parser.method
    
    def _before_fetch_callable_checks(self, internal_data: DataStreamCtx):
        return internal_data.current_pkt.is_input
    
    def __repr__(self):
        return f"<HttpRequest method={self.method} url={self.url} headers={self.headers} body={self.body} http_version={self.http_version} keep_alive={self.keep_alive} should_upgrade={self.should_upgrade} headers_complete={self.headers_complete} message_complete={self.message_complete} has_begun={self.has_begun} content_length={self.content_length} stream={self.stream}>"

class HttpResponse(InternalBasicHttpMetaClass):
    def __init__(self):
        super().__init__()
        self._parser: InternalHttpResponse = InternalHttpResponse()
        self._headers_were_set = False

    @property
    def status_code(self) -> int:
        return self._parser.status
    
    def _before_fetch_callable_checks(self, internal_data: DataStreamCtx):
        return not internal_data.current_pkt.is_input
    
    def __repr__(self):
        return f"<HttpResponse status_code={self.status_code} url={self.url} headers={self.headers} body={self.body} http_version={self.http_version} keep_alive={self.keep_alive} should_upgrade={self.should_upgrade} headers_complete={self.headers_complete} message_complete={self.message_complete} has_begun={self.has_begun} content_length={self.content_length} stream={self.stream}>"

class HttpRequestHeader(HttpRequest):
    def __init__(self):
        super().__init__()
        self._parser._save_body = False
    
    def _before_fetch_callable_checks(self, internal_data: DataStreamCtx):
        return internal_data.current_pkt.is_input and not self._headers_were_set
    
    def _after_fetch_callable_checks(self, internal_data: DataStreamCtx):
        if self._parser.headers_complete and not self._headers_were_set:
            self._headers_were_set = True
            return True
        return False

class HttpResponseHeader(HttpResponse):
    def __init__(self):
        super().__init__()
        self._parser._save_body = False
    
    def _before_fetch_callable_checks(self, internal_data: DataStreamCtx):
        return not internal_data.current_pkt.is_input and not self._headers_were_set
    
    def _after_fetch_callable_checks(self, internal_data: DataStreamCtx):
        if self._parser.headers_complete and not self._headers_were_set:
            self._headers_were_set = True
            return True
        return False