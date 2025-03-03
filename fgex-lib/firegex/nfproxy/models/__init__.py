from firegex.nfproxy.models.tcp import TCPInputStream, TCPOutputStream, TCPClientStream, TCPServerStream, TCPStreams
from firegex.nfproxy.models.http import HttpRequest, HttpResponse, HttpRequestHeader, HttpResponseHeader
from firegex.nfproxy.internals.data import RawPacket

type_annotations_associations = {
    "tcp": {
        RawPacket: RawPacket._fetch_packet,
        TCPInputStream: TCPInputStream._fetch_packet,
        TCPOutputStream: TCPOutputStream._fetch_packet,
        TCPStreams: TCPStreams._fetch_packet,
    },
    "http": {
        RawPacket: RawPacket._fetch_packet,
        TCPInputStream: TCPInputStream._fetch_packet,
        TCPOutputStream: TCPOutputStream._fetch_packet,
        TCPStreams: TCPStreams._fetch_packet,
        HttpRequest: HttpRequest._fetch_packet,
        HttpResponse: HttpResponse._fetch_packet,
        HttpRequestHeader: HttpRequestHeader._fetch_packet,
        HttpResponseHeader: HttpResponseHeader._fetch_packet,
    }
}

__all__ = [
    "RawPacket",
    "TCPInputStream", "TCPOutputStream", "TCPClientStream", "TCPServerStream", "TCPStreams",
    "HttpRequest", "HttpResponse", "HttpRequestHeader", "HttpResponseHeader",
]