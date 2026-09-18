from firegex.pyfilters.internals.models import ExceptionAction, FullStreamAction

class RawPacket:
    """One chunk of a connection, with what is known about where it came from.

    Everything below the application layer is **metadata** here, and read-only: the
    addresses, the ports, the address family, which way the chunk is going. There is no
    way to read an IP or TCP header as bytes, and no way to write one.

    That is a deliberate boundary rather than a missing feature. The two network layers
    cannot honestly offer the same thing: on NFQUEUE a real header exists and rewriting
    it desynchronises the connection in ways that surface minutes later somewhere else;
    on the proxy the connection was terminated and reopened, so the headers on the wire
    are the engine's own and a filter editing them would be editing nothing. The old
    model papered over that by handing the proxy a literal `FAKE:IP:TCP:HEADERS:`
    prefix, which meant a filter written against `raw_packet` did something different
    depending on the transport it happened to be attached to — the exact failure the
    unified model exists to prevent.

    So: read the metadata, edit `data`. `data` is the application payload and the only
    thing a filter can change, which is also the only change that means the same thing
    on both layers.
    """

    def __init__(self,
        data: bytes,
        is_input: bool,
        is_ipv6: bool,
        is_tcp: bool,
        src_ip: str = "",
        dst_ip: str = "",
        src_port: int = 0,
        dst_port: int = 0,
        l4: str | None = None,
    ):
        self.__data = bytes(data)
        self.__is_input = bool(is_input)
        self.__is_ipv6 = bool(is_ipv6)
        # Derived from `is_tcp` when nothing said otherwise, because one of the engines
        # sending this has only ever had two answers to give: the NFQUEUE binaries carry
        # TCP and UDP and nothing else, and asking them to learn a third word to say the
        # same thing would be a change with no question behind it.
        self.__l4 = str(l4) if l4 else ("tcp" if is_tcp else "udp")
        self.__is_tcp = self.__l4 == "tcp"
        self.__src_ip = str(src_ip)
        self.__dst_ip = str(dst_ip)
        self.__src_port = int(src_port)
        self.__dst_port = int(dst_port)

    @property
    def is_input(self) -> bool:
        "True if the chunk is going from the client to the service"
        return self.__is_input

    @property
    def is_output(self) -> bool:
        "True if the chunk is going from the service to the client"
        return not self.__is_input

    @property
    def is_ipv6(self) -> bool:
        "True if the connection is IPv6, false if it is IPv4"
        return self.__is_ipv6

    @property
    def is_tcp(self) -> bool:
        "True if the connection is TCP. False for a datagram, and false for QUIC"
        return self.__is_tcp

    @property
    def l4(self) -> str:
        """What carries this connection.

        `tcp`, `udp`, `quic` for a stream inside a QUIC connection, or `quic-datagram`
        for a DATAGRAM frame in one — which is in a connection carrying streams and is
        not one, the distinction `is_stream` is there to answer.
        """
        return self.__l4

    @property
    def is_stream(self) -> bool:
        """True if these bytes arrive in order, once each, as part of a stream.

        The question every model above `RawPacket` actually asks. It used to be spelled
        `is_tcp`, and the two came apart the day QUIC arrived: a QUIC stream is ordered
        and reliable, so an assembled stream and a parsed HTTP message mean exactly what
        they mean on TCP — and it is carried by UDP, so a filter asking what is on the
        wire has to be told UDP. One flag answering both got one of them wrong whichever
        way it was set. A datagram — plain UDP or QUIC's own — answers false here, so a
        filter asking for a stream model is simply not called for one and a single file
        can carry both.
        """
        return self.__l4 in ("tcp", "quic")

    @property
    def src_ip(self) -> str:
        "Where this chunk came from"
        return self.__src_ip

    @property
    def dst_ip(self) -> str:
        "Where this chunk is going"
        return self.__dst_ip

    @property
    def src_port(self) -> int:
        "The port this chunk came from"
        return self.__src_port

    @property
    def dst_port(self) -> int:
        "The port this chunk is going to"
        return self.__dst_port

    @property
    def client_ip(self) -> str:
        "The client's address, whichever way this chunk is going"
        return self.__src_ip if self.__is_input else self.__dst_ip

    @property
    def client_port(self) -> int:
        "The client's port, whichever way this chunk is going"
        return self.__src_port if self.__is_input else self.__dst_port

    @property
    def server_ip(self) -> str:
        "The protected service's address, whichever way this chunk is going"
        return self.__dst_ip if self.__is_input else self.__src_ip

    @property
    def server_port(self) -> int:
        "The protected service's port, whichever way this chunk is going"
        return self.__dst_port if self.__is_input else self.__src_port

    @property
    def data(self) -> bytes:
        """The application payload: the only part a filter can change."""
        return self.__data

    @data.setter
    def data(self, value: bytes):
        self.__data = bytes(value)

    @property
    def data_size(self) -> int:
        "How many bytes of application payload this chunk carries"
        return len(self.__data)

    @classmethod
    def _fetch_packet(cls, internal_data:"DataStreamCtx"):
        if not isinstance(internal_data, DataStreamCtx):
            if isinstance(internal_data, dict):
                internal_data = DataStreamCtx(internal_data)
            else:
                raise Exception("Invalid data type, data MUST be of type DataStream, or glob dict")

        if "__firegex_packet_info" not in internal_data.filter_glob.keys():
            raise Exception("Packet info not found")
        return cls(**internal_data.filter_glob["__firegex_packet_info"])

    def __repr__(self):
        way = "client -> service" if self.is_input else "service -> client"
        return (
            f"RawPacket({way}, {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}, "
            f"{self.l4}/{'ip6' if self.is_ipv6 else 'ip4'}, "
            f"{self.data_size} bytes)"
        )


#: The documented default for `FGEX_STREAM_MAX_SIZE`. It read `1*8e20` — eight hundred
#: exabytes, commented "1MB default value" — which meant `FGEX_FULL_STREAM_ACTION` never
#: fired unless the operator set a size by hand, and the float it produced would have
#: been refused by the setter beside it.
DEFAULT_STREAM_MAX_SIZE = 1024 * 1024


class _Kept:
    """One value in the per-connection context, with its default and its type.

    Five of these were five pairs of property/setter differing only in a name, a default
    and one isinstance check — seventy lines in which the interesting part was three
    words per entry.
    """

    def __init__(self, default, kind: type | None = None):
        self.default = default
        self.kind = kind

    def __set_name__(self, owner, name):
        self.key = name

    def __get__(self, obj, _owner=None):
        if obj is None:
            return self
        if self.key not in obj.store:
            obj.store[self.key] = self.default() if callable(self.default) else self.default
        return obj.store[self.key]

    def __set__(self, obj, value):
        if self.kind is not None and not isinstance(value, self.kind):
            raise Exception(f"Invalid data type, data MUST be of type {self.kind.__name__}")
        obj.store[self.key] = value


class DataStreamCtx:
    """The context of the data handler: what survives between packets of one connection.

    Everything below lives in a dict inside the filter's own globals, so it is per
    connection and per direction — which is what keeps one client's bytes from deciding
    another client's verdict.
    """

    filter_call_info = _Kept(list)
    stream_max_size = _Kept(DEFAULT_STREAM_MAX_SIZE, int)
    full_stream_action = _Kept(FullStreamAction.FLUSH, FullStreamAction)
    invalid_encoding_action = _Kept(ExceptionAction.REJECT, ExceptionAction)
    data_handler_context = _Kept(dict)

    def __init__(self, glob: dict, init_pkt: bool = True):
        self.store = glob.setdefault("__firegex_pyfilter_ctx", {})
        self.filter_glob = glob
        self.current_pkt = RawPacket._fetch_packet(self) if init_pkt else None
        self.call_mem = {}  # A memory space valid only for the current packet handler
