from firegex.nfproxy.internals.data import DataStreamCtx
from firegex.nfproxy.internals.exceptions import NotReadyToRun, StreamFullDrop, StreamFullReject
from firegex.nfproxy.internals.models import FullStreamAction

class InternalTCPStream:
    def __init__(self,
        data: bytes,
        is_ipv6: bool,
    ):
        self.__data = bytes(data)
        self.__is_ipv6 = bool(is_ipv6)
        self.__total_stream_size = len(data)
    
    @property
    def data(self) -> bytes:
        """The data of the packets assembled and sorted from TCP"""
        return self.__data
    
    @property
    def is_ipv6(self) -> bool:
        """It's true if the packet is an ipv6 packet, false if it's an ipv4 packet"""
        return self.__is_ipv6
    
    @property
    def total_stream_size(self) -> int:
        """The size of the stream"""
        return self.__total_stream_size
    
    def _push_new_data(self, data: bytes):
        self.__data += data
        self.__total_stream_size += len(data)
    
    @classmethod
    def _fetch_packet(cls, internal_data:DataStreamCtx, is_input:bool=False):
        if internal_data.current_pkt is None or internal_data.current_pkt.is_tcp is False:
            raise NotReadyToRun()
        if internal_data.current_pkt.is_input != is_input:
            raise NotReadyToRun()
        datahandler: TCPInputStream = internal_data.data_handler_context.get(cls, None)
        if datahandler is None:
            datahandler = cls(internal_data.current_pkt.data, internal_data.current_pkt.is_ipv6)
            internal_data.data_handler_context[cls] = datahandler
        else:
            if datahandler.total_stream_size+len(internal_data.current_pkt.data) > internal_data.stream_max_size:
                match internal_data.full_stream_action:
                    case FullStreamAction.FLUSH:
                        datahandler = cls(internal_data.current_pkt.data, internal_data.current_pkt.is_ipv6)
                        internal_data.data_handler_context[cls] = datahandler
                    case FullStreamAction.REJECT:
                        raise StreamFullReject()
                    case FullStreamAction.DROP:
                        raise StreamFullDrop()
                    case FullStreamAction.ACCEPT:
                        raise NotReadyToRun()
            else:
                datahandler._push_new_data(internal_data.current_pkt.data)
        return datahandler

class TCPInputStream(InternalTCPStream):
    """
    This datamodel will assemble the TCP input stream from the client sent data.
    The function that use this data model will be handled when:
    - The packet is TCP
    - At least 1 packet has been sent
    - A new client packet has been received
    """

    @classmethod
    def _fetch_packet(cls, internal_data:DataStreamCtx):
        return super()._fetch_packet(internal_data, is_input=True)

TCPClientStream = TCPInputStream

class TCPOutputStream(InternalTCPStream):
    """
    This datamodel will assemble the TCP output stream from the server sent data.
    The function that use this data model will be handled when:
    - The packet is TCP
    - At least 1 packet has been sent
    - A new server packet has been sent
    """
    
    @classmethod
    def _fetch_packet(cls, internal_data:DataStreamCtx):
        return super()._fetch_packet(internal_data, is_input=False)

TCPServerStream = TCPOutputStream
