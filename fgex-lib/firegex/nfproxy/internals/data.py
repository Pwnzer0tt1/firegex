from firegex.nfproxy.internals.models import FilterHandler
from firegex.nfproxy.internals.models import FullStreamAction, ExceptionAction

class RawPacket:
    "class rapresentation of the nfqueue packet sent in python context by the c++ core"
    
    def __init__(self,
        data: bytes,
        raw_packet: bytes,
        is_input: bool,
        is_ipv6: bool,
        is_tcp: bool,
        l4_size: int,
    ):
        self.__data = bytes(data)
        self.__raw_packet = bytes(raw_packet)
        self.__is_input = bool(is_input)
        self.__is_ipv6 = bool(is_ipv6)
        self.__is_tcp = bool(is_tcp)
        self.__l4_size = int(l4_size)
        self.__raw_packet_header_size = len(self.__raw_packet)-self.__l4_size
    
    @property
    def is_input(self) -> bool:
        "It's true if the packet is an input packet, false if it's an output packet"
        return self.__is_input
    
    @property
    def is_ipv6(self) -> bool:
        "It's true if the packet is an ipv6 packet, false if it's an ipv4 packet"
        return self.__is_ipv6
    
    @property
    def is_tcp(self) -> bool:
        "It's true if the packet is a tcp packet, false if it's an udp packet"
        return self.__is_tcp
    
    @property
    def data(self) -> bytes:
        "The data of the packet assembled and sorted from TCP"
        return self.__data
    
    @property
    def l4_size(self) -> int:
        "The size of the layer 4 data"
        return self.__l4_size
    
    @property
    def raw_packet_header_len(self) -> int:
        "The size of the original packet header"
        return self.__raw_packet_header_size
    
    @property
    def l4_data(self) -> bytes:
        "The layer 4 payload of the packet"
        return self.__raw_packet[self.raw_packet_header_len:]
    
    @l4_data.setter
    def l4_data(self, v:bytes):
        if not isinstance(v, bytes):
            raise Exception("Invalid data type, data MUST be of type bytes")
        #if len(v) != self.__l4_size:
        #    raise Exception("Invalid data size, must be equal to the original packet header size (due to a technical limitation)")
        self.raw_packet = self.__raw_packet[:self.raw_packet_header_len]+v
    
    @property
    def raw_packet(self) -> bytes:
        "The raw packet with IP and TCP headers"
        return self.__raw_packet

    @raw_packet.setter
    def raw_packet(self, v:bytes):
        if not isinstance(v, bytes):
            raise Exception("Invalid data type, data MUST be of type bytes")
        if len(v) > 2**16:
            raise Exception("Invalid data size, must be less than 2^16 bytes")
        #if len(v) != len(self.__raw_packet):
        #    raise Exception("Invalid data size, must be equal to the original packet size (due to a technical limitation)")
        if len(v) < self.raw_packet_header_len:
            raise Exception("Invalid data size, must be greater than the original packet header size")
        self.__raw_packet = v
        self.__l4_size = len(v)-self.raw_packet_header_len

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
        return f"RawPacket(data={self.data}, raw_packet={self.raw_packet}, is_input={self.is_input}, is_ipv6={self.is_ipv6}, is_tcp={self.is_tcp}, l4_size={self.l4_size})"


class DataStreamCtx:
    "class to store the context of the data handler"
    
    def __init__(self, glob: dict, init_pkt: bool = True):
        if "__firegex_pyfilter_ctx" not in glob.keys():
            glob["__firegex_pyfilter_ctx"] = {}
        self.__data = glob["__firegex_pyfilter_ctx"]
        self.filter_glob = glob
        self.current_pkt = RawPacket._fetch_packet(self) if init_pkt else None
        self.call_mem = {} #A memory space valid only for the current packet handler
    
    @property
    def filter_call_info(self) -> list[FilterHandler]:
        if "filter_call_info" not in self.__data.keys():
            self.__data["filter_call_info"] = []
        return self.__data.get("filter_call_info")
    
    @filter_call_info.setter
    def filter_call_info(self, v: list[FilterHandler]):
        self.__data["filter_call_info"] = v
    
    @property
    def stream_max_size(self) -> int:
        if "stream_max_size" not in self.__data.keys():
            self.__data["stream_max_size"] = 1*8e20 # 1MB default value
        return self.__data.get("stream_max_size")
    
    @stream_max_size.setter
    def stream_max_size(self, v: int):
        if not isinstance(v, int):
            raise Exception("Invalid data type, data MUST be of type int")
        self.__data["stream_max_size"] = v
    
    @property
    def full_stream_action(self) -> FullStreamAction:
        if "full_stream_action" not in self.__data.keys():
            self.__data["full_stream_action"] = FullStreamAction.FLUSH
        return self.__data.get("full_stream_action")
    
    @full_stream_action.setter
    def full_stream_action(self, v: FullStreamAction):
        if not isinstance(v, FullStreamAction):
            raise Exception("Invalid data type, data MUST be of type FullStreamAction")
        self.__data["full_stream_action"] = v
    
    @property
    def invalid_encoding_action(self) -> ExceptionAction:
        if "invalid_encoding_action" not in self.__data.keys():
            self.__data["invalid_encoding_action"] = ExceptionAction.REJECT
        return self.__data.get("invalid_encoding_action")

    @invalid_encoding_action.setter
    def invalid_encoding_action(self, v: ExceptionAction):
        if not isinstance(v, ExceptionAction):
            raise Exception("Invalid data type, data MUST be of type ExceptionAction")
        self.__data["invalid_encoding_action"] = v
    
    @property
    def data_handler_context(self) -> dict:
        if "data_handler_context" not in self.__data.keys():
            self.__data["data_handler_context"] = {}
        return self.__data.get("data_handler_context")
    
    @data_handler_context.setter
    def data_handler_context(self, v: dict):
        self.__data["data_handler_context"] = v

