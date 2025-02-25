
class NotReadyToRun(Exception): # raise this exception if the stream state is not ready to parse this object, the call will be skipped
    pass

class RawPacket:
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
    def fetch_from_global(cls, glob):
        if "__firegex_packet_info" not in glob.keys():
            raise Exception("Packet info not found")
        return cls(**glob["__firegex_packet_info"])

