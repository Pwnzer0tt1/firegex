import pyllhttp         
from firegex.nfproxy.internals.exceptions import NotReadyToRun
from firegex.nfproxy.internals.data import DataStreamCtx

class InternalCallbackHandler():
    
    url: str|None = None
    _url_buffer: bytes = b""
    headers: dict[str, str] = {}
    _header_fields: dict[bytes, bytes] = {}
    has_begun: bool = False
    body: bytes = None
    _body_buffer: bytes = b""
    headers_complete: bool = False
    message_complete: bool = False
    status: str|None = None
    _status_buffer: bytes = b""
    current_header_field = None
    current_header_value = None
    _save_body = True

    def on_message_begin(self):
        self.has_begun = True
    
    def on_url(self, url):
        self._url_buffer += url
    
    def on_url_complete(self):
        self.url = self._url_buffer.decode(errors="ignore")
        self._url_buffer = None
    
    def on_header_field(self, field):
        if self.current_header_field is None:
            self.current_header_field = bytearray(field)
        else:
            self.current_header_field += field

    def on_header_field_complete(self):
        self.current_header_field = self.current_header_field
        
    def on_header_value(self, value):
        if self.current_header_value is None:
            self.current_header_value = bytearray(value)
        else:
            self.current_header_value += value

    def on_header_value_complete(self):
        if self.current_header_value is not None and self.current_header_field is not None:
            self._header_fields[self.current_header_field.decode(errors="ignore")] = self.current_header_value.decode(errors="ignore")
        self.current_header_field = None
        self.current_header_value = None
    
    def on_headers_complete(self):
        self.headers_complete = True
        self.headers = self._header_fields
        self._header_fields = {}
        self.current_header_field = None
        self.current_header_value = None

    def on_body(self, body: bytes):
        if self._save_body:
            self._body_buffer += body

    def on_message_complete(self):
        self.body = self._body_buffer
        self._body_buffer = b""
        self.message_complete = True
    
    def on_status(self, status: bytes):
        self._status_buffer += status
    
    def on_status_complete(self):
        self.status = self._status_buffer.decode(errors="ignore")
        self._status_buffer = b""
    
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
        super(pyllhttp.Request, self).__init__()
        super(InternalCallbackHandler, self).__init__()

class InternalHttpResponse(InternalCallbackHandler, pyllhttp.Response):
    def __init__(self):
        super(pyllhttp.Response, self).__init__()
        super(InternalCallbackHandler, self).__init__()

class InternalBasicHttpMetaClass:
    
    def __init__(self):
        self._parser: InternalHttpRequest|InternalHttpResponse
        self._headers_were_set = False
        self.stream = b""
        self.raised_error = False
    
    @property
    def url(self) -> str|None:
        return self._parser.url
    
    @property
    def headers(self) -> dict[str, str]:
        return self._parser.headers
    
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
    
    def _fetch_current_packet(self, internal_data: DataStreamCtx):
        # TODO: if an error is triggered should I reject the connection?
        if internal_data.save_http_data_in_streams: # This is a websocket upgrade!
            self.stream += internal_data.current_pkt.data
        else:
            try:
                self._parser.execute(internal_data.current_pkt.data)
                if self._parser.headers_complete and len(self._parser._body_buffer) == self._parser.content_length_parsed:
                    self._parser.on_message_complete()
            except Exception as e:
                self.raised_error = True
                raise e

    #It's called the first time if the headers are complete, and second time with body complete
    def _callable_checks(self, internal_data: DataStreamCtx):
        if self._parser.headers_complete and not self._headers_were_set:
            self._headers_were_set = True
            return True
        return self._parser.message_complete or internal_data.save_http_data_in_streams
    
    def _before_fetch_callable_checks(self, internal_data: DataStreamCtx):
        return True

    def _trigger_remove_data(self, internal_data: DataStreamCtx):
        return self.message_complete
    
    @classmethod
    def _fetch_packet(cls, internal_data: DataStreamCtx):
        if internal_data.current_pkt is None or internal_data.current_pkt.is_tcp is False:
            raise NotReadyToRun()
        
        datahandler:InternalBasicHttpMetaClass = internal_data.http_data_objects.get(cls, None)
        if datahandler is None or datahandler.raised_error:
            datahandler = cls()
            internal_data.http_data_objects[cls] = datahandler
        
        if not datahandler._before_fetch_callable_checks(internal_data):
            raise NotReadyToRun()
        datahandler._fetch_current_packet(internal_data)
        if not datahandler._callable_checks(internal_data):
            raise NotReadyToRun()
        
        if datahandler.should_upgrade:
            internal_data.save_http_data_in_streams = True
        
        if datahandler._trigger_remove_data(internal_data):
            if internal_data.http_data_objects.get(cls):
                del internal_data.http_data_objects[cls]
        
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
    
    def _callable_checks(self, internal_data: DataStreamCtx):
        if self._parser.headers_complete and not self._headers_were_set:
            self._headers_were_set = True
            return True
        return False

class HttpResponseHeader(HttpResponse):
    def __init__(self):
        super().__init__()
        self._parser._save_body = False
    
    def _callable_checks(self, internal_data: DataStreamCtx):
        if self._parser.headers_complete and not self._headers_were_set:
            self._headers_were_set = True
            return True
        return False

"""
#TODO include this?

import codecs

# Null bytes; no need to recreate these on each call to guess_json_utf
_null = "\x00".encode("ascii")  # encoding to ASCII for Python 3
_null2 = _null * 2
_null3 = _null * 3

def guess_json_utf(data):
    ""
    :rtype: str
    ""
    # JSON always starts with two ASCII characters, so detection is as
    # easy as counting the nulls and from their location and count
    # determine the encoding. Also detect a BOM, if present.
    sample = data[:4]
    if sample in (codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE):
        return "utf-32"  # BOM included
    if sample[:3] == codecs.BOM_UTF8:
        return "utf-8-sig"  # BOM included, MS style (discouraged)
    if sample[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE):
        return "utf-16"  # BOM included
    nullcount = sample.count(_null)
    if nullcount == 0:
        return "utf-8"
    if nullcount == 2:
        if sample[::2] == _null2:  # 1st and 3rd are null
            return "utf-16-be"
        if sample[1::2] == _null2:  # 2nd and 4th are null
            return "utf-16-le"
        # Did not detect 2 valid UTF-16 ascii-range characters
    if nullcount == 3:
        if sample[:3] == _null3:
            return "utf-32-be"
        if sample[1:] == _null3:
            return "utf-32-le"
        # Did not detect a valid UTF-32 ascii-range character
    return None

from http_parser.pyparser import HttpParser
import json
from urllib.parse import parse_qsl
from dataclasses import dataclass

@dataclass
class HttpMessage():
    fragment: str
    headers: dict
    method: str
    parameters: dict
    path: str
    query_string: str
    raw_body: bytes
    status_code: int
    url: str
    version: str

class HttpMessageParser(HttpParser):
    def __init__(self, data:bytes, decompress_body=True):
        super().__init__(decompress = decompress_body)
        self.execute(data, len(data))
        self._parameters = {}
        try:
            self._parse_parameters()
        except Exception as e:
            print("Error in parameters parsing:", data)
            print("Exception:", str(e))

    def get_raw_body(self):
        return b"\r\n".join(self._body)
    
    def _parse_query_string(self, raw_string):
        parameters = parse_qsl(raw_string)
        for key,value in parameters:
            try:
                key = key.decode()
                value = value.decode()
            except:
                pass
            if self._parameters.get(key):
                if isinstance(self._parameters[key], list):
                    self._parameters[key].append(value)
                else:
                    self._parameters[key] = [self._parameters[key], value]
            else:
                self._parameters[key] = value

    def _parse_parameters(self):
        if self._method == "POST":
            body = self.get_raw_body()
            if len(body) == 0:
                return
            content_type = self.get_headers().get("Content-Type")
            if not content_type or "x-www-form-urlencoded" in content_type:
                try:
                    self._parse_query_string(body.decode())
                except:
                    pass
            elif "json" in content_type:
                self._parameters = json.loads(body)
        elif self._method == "GET":
            self._parse_query_string(self._query_string)
        
    def get_parameters(self):
        ""returns parameters parsed from query string or body""
        return self._parameters
    
    def get_version(self):
        if self._version:
            return ".".join([str(x) for x in self._version])
        return None

    def to_message(self):
        return HttpMessage(self._fragment, self._headers, self._method,
                           self._parameters, self._path, self._query_string,
                           self.get_raw_body(), self._status_code,
                           self._url, self.get_version()
                           )
"""