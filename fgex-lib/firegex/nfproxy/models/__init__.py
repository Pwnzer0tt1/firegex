from firegex.nfproxy.models.tcp import (
    TCPInputStream,
    TCPOutputStream,
    TCPClientStream,
    TCPServerStream,
)
from firegex.nfproxy.models.http import (
    HttpRequest,
    HttpResponse,
    HttpRequestHeader,
    HttpResponseHeader,
    HttpFullRequest,
    HttpFullResponse,
)
from firegex.nfproxy.internals.data import RawPacket
from enum import Enum

type_annotations_associations = {
    "tcp": {
        RawPacket: RawPacket._fetch_packet,
        TCPInputStream: TCPInputStream._fetch_packet,
        TCPOutputStream: TCPOutputStream._fetch_packet,
    },
    "http": {
        RawPacket: RawPacket._fetch_packet,
        TCPInputStream: TCPInputStream._fetch_packet,
        TCPOutputStream: TCPOutputStream._fetch_packet,
        HttpRequest: HttpRequest._fetch_packet,
        HttpResponse: HttpResponse._fetch_packet,
        HttpRequestHeader: HttpRequestHeader._fetch_packet,
        HttpResponseHeader: HttpResponseHeader._fetch_packet,
        HttpFullRequest: HttpFullRequest._fetch_packet,
        HttpFullResponse: HttpFullResponse._fetch_packet,
    },
}


class Protocols(Enum):
    TCP = "tcp"
    HTTP = "http"


__all__ = [
    "RawPacket",
    "TCPInputStream",
    "TCPOutputStream",
    "TCPClientStream",
    "TCPServerStream",
    "HttpRequest",
    "HttpResponse",
    "HttpRequestHeader",
    "HttpResponseHeader",
    "HttpFullRequest",
    "HttpFullResponse",
    "Protocols",
]
