class Service:
    def __init__(self, service_id: str, status: str, port: int, name: str, proto: str, ip_int: str, **other):
        self.id = service_id
        self.status = status
        self.port = port
        self.name = name
        self.proto = proto
        self.ip_int = ip_int
    
    @classmethod
    def from_dict(cls, var: dict):
        return cls(**var)


class PyFilter:
    def __init__(self, filter_id:int, name: str, blocked_packets: int, edited_packets: int, active: bool, **other):
        self.filter_id = filter_id
        self.name = name
        self.blocked_packets = blocked_packets
        self.edited_packets = edited_packets
        self.active = active

    @classmethod
    def from_dict(cls, var: dict):
        return cls(**var)
