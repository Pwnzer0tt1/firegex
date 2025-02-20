
class NotReadyToRun(Exception): # raise this exception if the stream state is not ready to parse this object, the call will be skipped
    pass

class RawPacket:
    def __init__(self,
        data: bytes,
        raw_packet: bytes,
        is_input: bool,
        is_ipv6: bool,
        is_tcp: bool,
    ):
        self.__data = bytes(data)
        self.__raw_packet = bytes(raw_packet)
        self.__is_input = bool(is_input)
        self.__is_ipv6 = bool(is_ipv6)
        self.__is_tcp = bool(is_tcp)
    
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
    def proto_header(self) -> bytes:
        return self.__raw_packet[:self.proto_header_len]
    
    @property
    def proto_header_len(self) -> int:
        return len(self.__raw_packet) - len(self.__data)
    
    @data.setter
    def data(self, v:bytes):
        if not isinstance(v, bytes):
            raise Exception("Invalid data type, data MUST be of type bytes")
        self.__raw_packet = self.proto_header + v
        self.__data = v
    
    @property
    def raw_packet(self) -> bytes:
        return self.__raw_packet

    @raw_packet.setter
    def raw_packet(self, v:bytes):
        if not isinstance(v, bytes):
            raise Exception("Invalid data type, data MUST be of type bytes")
        if len(v) < self.proto_header_len:
            raise Exception("Invalid packet length")
        header_len = self.proto_header_len
        self.__data = v[header_len:]
        self.__raw_packet = v

    @staticmethod
    def fetch_from_global():
        glob = globals()
        if "__firegex_packet_info" not in glob.keys():
            raise Exception("Packet info not found")
        return RawPacket(**glob["__firegex_packet_info"])


