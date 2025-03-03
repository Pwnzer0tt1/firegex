from firegex.nfproxy.internals.data import DataStreamCtx
from firegex.nfproxy.internals.exceptions import NotReadyToRun

class TCPStreams:
    """
    This datamodel will assemble the TCP streams from the input and output data.
    The function that use this data model will be handled when:
    - The packet is TCP
    - At least 1 packet has been sent
    """
    
    def __init__(self,
        input_data: bytes,
        output_data: bytes,
        is_ipv6: bool,
    ):
        self.__input_data = bytes(input_data)
        self.__output_data = bytes(output_data)
        self.__is_ipv6 = bool(is_ipv6)
    
    @property
    def input_data(self) -> bytes:
        return self.__input_data
    
    @property
    def output_data(self) -> bytes:
        return self.__output_data
    
    @property
    def is_ipv6(self) -> bool:
        return self.__is_ipv6
    
    @classmethod
    def _fetch_packet(cls, internal_data:DataStreamCtx):

        if internal_data.current_pkt is None or internal_data.current_pkt.is_tcp is False:
            raise NotReadyToRun()
        return cls(
            input_data=b"".join([ele.data for ele in internal_data.stream if ele.is_input]),
            output_data=b"".join([ele.data for ele in internal_data.stream if not ele.is_input]),
            is_ipv6=internal_data.current_pkt.is_ipv6,
        )


class TCPInputStream:
    """
    This datamodel will assemble the TCP input stream from the client sent data.
    The function that use this data model will be handled when:
    - The packet is TCP
    - At least 1 packet has been sent
    - A new client packet has been received
    """
    def __init__(self,
        data: bytes,
        is_ipv6: bool,
    ):
        self.__data = bytes(data)
        self.__is_ipv6 = bool(is_ipv6)

    @property
    def data(self) -> bool:
        return self.__data
    
    @property
    def is_ipv6(self) -> bool:
        return self.__is_ipv6
    
    @classmethod
    def _fetch_packet(cls, internal_data:DataStreamCtx):
        if internal_data.current_pkt is None or internal_data.current_pkt.is_tcp is False or internal_data.current_pkt.is_input is False:
            raise NotReadyToRun()
        return cls(
            data=internal_data.current_pkt.get_related_raw_stream(),
            is_ipv6=internal_data.current_pkt.is_ipv6,
        )

TCPClientStream = TCPInputStream

class TCPOutputStream:
    """
    This datamodel will assemble the TCP output stream from the server sent data.
    The function that use this data model will be handled when:
    - The packet is TCP
    - At least 1 packet has been sent
    - A new server packet has been sent
    """
    
    
    def __init__(self,
        data: bytes,
        is_ipv6: bool,
    ):
        self.__data = bytes(data)
        self.__is_ipv6 = bool(is_ipv6)

    @property
    def data(self) -> bool:
        return self.__data
    
    @property
    def is_ipv6(self) -> bool:
        return self.__is_ipv6
    
    @classmethod
    def _fetch_packet(cls, internal_data:DataStreamCtx):
        if internal_data.current_pkt is None or internal_data.current_pkt.is_tcp is False or internal_data.current_pkt.is_input is True:
            raise NotReadyToRun()
        return cls(
            data=internal_data.current_pkt.get_related_raw_stream(),
            is_ipv6=internal_data.current_pkt.is_ipv6,
        )

TCPServerStream = TCPOutputStream
