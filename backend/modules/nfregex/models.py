import base64

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


class Regex:
    def __init__(self, regex_id: int, regex: bytes, mode: str, service_id: str, is_blacklist: bool, blocked_packets: int, is_case_sensitive: bool, active: bool, **other):
        self.regex = regex
        self.mode = mode
        self.service_id = service_id
        self.is_blacklist = is_blacklist
        self.blocked_packets = blocked_packets
        self.id = regex_id
        self.is_case_sensitive = is_case_sensitive
        self.active = active
        
    @classmethod
    def from_dict(cls, var: dict):
        var['regex'] = base64.b64decode(var['regex'])
        return cls(**var)