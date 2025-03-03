from firegex.nfproxy.internals.models import FilterHandler
from typing import Callable

class RawPacket:
    """
    class rapresentation of the nfqueue packet sent in this context by the c++ core
    """
    
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
        return self.__is_input
    
    @property
    def is_ipv6(self) -> bool:
        return self.__is_ipv6
    
    @property
    def is_tcp(self) -> bool:
        return self.__is_tcp
    
    @property
    def data(self) -> bytes:
        return self.__data
    
    @property
    def l4_size(self) -> int:
        return self.__l4_size
    
    @property
    def raw_packet_header_len(self) -> int:
        return self.__raw_packet_header_size
    
    @property
    def l4_data(self) -> bytes:
        return self.__raw_packet[self.raw_packet_header_len:]
    
    @l4_data.setter
    def l4_data(self, v:bytes):
        if not isinstance(v, bytes):
            raise Exception("Invalid data type, data MUST be of type bytes")
        #if len(v) != self.__l4_size:
        #    raise Exception("Invalid data size, must be equal to the original packet header size (due to a technical limitation)")
        self.__raw_packet = self.__raw_packet[:self.raw_packet_header_len]+v
        self.__l4_size = len(v)
    
    @property
    def raw_packet(self) -> bytes:
        return self.__raw_packet

    @raw_packet.setter
    def raw_packet(self, v:bytes):
        if not isinstance(v, bytes):
            raise Exception("Invalid data type, data MUST be of type bytes")
        #if len(v) != len(self.__raw_packet):
        #    raise Exception("Invalid data size, must be equal to the original packet size (due to a technical limitation)")
        if len(v) < self.raw_packet_header_len:
            raise Exception("Invalid data size, must be greater than the original packet header size")
        self.__raw_packet = v
        self.__l4_size = len(v)-self.raw_packet_header_len

    @classmethod
    def _fetch_packet(cls, internal_data):
        from firegex.nfproxy.internals.data import DataStreamCtx
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
    
    def __init__(self, glob: dict):
        if "__firegex_pyfilter_ctx" not in glob.keys():
            glob["__firegex_pyfilter_ctx"] = {}
        self.__data = glob["__firegex_pyfilter_ctx"]
        self.filter_glob = glob
    
    @property
    def filter_call_info(self) -> list[FilterHandler]:
        if "filter_call_info" not in self.__data.keys():
            self.__data["filter_call_info"] = []
        return self.__data.get("filter_call_info")
    
    @filter_call_info.setter
    def filter_call_info(self, v: list[FilterHandler]):
        self.__data["filter_call_info"] = v
    
    @property
    def stream(self) -> list[RawPacket]:
        if "stream" not in self.__data.keys():
            self.__data["stream"] = []
        return self.__data.get("stream")
    
    @stream.setter
    def stream(self, v: list[RawPacket]):
        self.__data["stream"] = v
    
    @property
    def stream_size(self) -> int:
        if "stream_size" not in self.__data.keys():
            self.__data["stream_size"] = 0
        return self.__data.get("stream_size")
    
    @stream_size.setter
    def stream_size(self, v: int):
        self.__data["stream_size"] = v
    
    @property
    def stream_max_size(self) -> int:
        if "stream_max_size" not in self.__data.keys():
            self.__data["stream_max_size"] = 1*8e20
        return self.__data.get("stream_max_size")
    
    @stream_max_size.setter
    def stream_max_size(self, v: int):
        self.__data["stream_max_size"] = v
    
    @property
    def full_stream_action(self) -> str:
        if "full_stream_action" not in self.__data.keys():
            self.__data["full_stream_action"] = "flush"
        return self.__data.get("full_stream_action")
    
    @full_stream_action.setter
    def full_stream_action(self, v: str):
        self.__data["full_stream_action"] = v
        
    @property
    def current_pkt(self) -> RawPacket:
        return self.__data.get("current_pkt", None)
    
    @current_pkt.setter
    def current_pkt(self, v: RawPacket):
        self.__data["current_pkt"] = v
    
    @property
    def http_data_objects(self) -> dict:
        if "http_data_objects" not in self.__data.keys():
            self.__data["http_data_objects"] = {}
        return self.__data.get("http_data_objects")
    
    @http_data_objects.setter
    def http_data_objects(self, v: dict):
        self.__data["http_data_objects"] = v
    
    @property
    def save_http_data_in_streams(self) -> bool:
        if "save_http_data_in_streams" not in self.__data.keys():
            self.__data["save_http_data_in_streams"] = False
        return self.__data.get("save_http_data_in_streams")
    
    @save_http_data_in_streams.setter
    def save_http_data_in_streams(self, v: bool):
        self.__data["save_http_data_in_streams"] = v
    
    @property
    def flush_action_set(self) -> set[Callable]:
        if "flush_action_set" not in self.__data.keys():
            self.__data["flush_action_set"] = set()
        return self.__data.get("flush_action_set")
    
    @flush_action_set.setter
    def flush_action_set(self, v: set[Callable]):
        self.__data["flush_action_set"] = v
    

