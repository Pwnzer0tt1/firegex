from firegex.pyfilters.models.tcp import (
    TCPInputStream,
    TCPOutputStream,
    TCPClientStream,
    TCPServerStream,
)
from firegex.pyfilters.models.http import (
    HttpRequest,
    HttpResponse,
    HttpRequestHeader,
    HttpResponseHeader,
    HttpFullRequest,
    HttpFullResponse,
    HttpHistory,
    HttpStreamHistory,
)
from firegex.pyfilters.internals.data import RawPacket

#: What each application protocol can hand a filter.
#:
#: This table is the only place a protocol is defined, and a filter file's protocol is
#: read back off it rather than declared: whatever a filter's parameters are annotated
#: with is what decides both when it is called and which protocol its file speaks. A
#: second list of protocol names would be one more thing to keep in step, and the day
#: it fell behind the symptom would be a filter that silently never runs.
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
        HttpHistory: HttpHistory._fetch_packet,
        HttpStreamHistory: HttpStreamHistory._fetch_packet,
    },
}


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
    "HttpHistory",
    "HttpStreamHistory",
]

