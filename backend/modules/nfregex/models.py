import base64

class Service:
    def __init__(self, id: str, status: str, port: int, name: str, proto: str, ip_int: str):
        self.id = id
        self.status = status
        self.port = port
        self.name = name
        self.proto = proto
        self.ip_int = ip_int
    
    @classmethod
    def from_dict(cls, var: dict):
        return cls(
            id=var["service_id"],
            status=var["status"],
            port=var["port"],
            name=var["name"],
            proto=var["proto"],
            ip_int=var["ip_int"]
        )


class Regex:
    def __init__(self, id: int, regex: bytes, mode: str, service_id: str, is_blacklist: bool, blocked_packets: int, is_case_sensitive: bool, active: bool):
        self.regex = regex
        self.mode = mode
        self.service_id = service_id
        self.is_blacklist = is_blacklist
        self.blocked_packets = blocked_packets
        self.id = id
        self.is_case_sensitive = is_case_sensitive
        self.active = active
        
    @classmethod
    def from_dict(cls, var: dict):
        return cls(
            id=var["regex_id"],
            regex=base64.b64decode(var["regex"]),
            mode=var["mode"],
            service_id=var["service_id"],
            is_blacklist=var["is_blacklist"],
            blocked_packets=var["blocked_packets"],
            is_case_sensitive=var["is_case_sensitive"],
            active=var["active"]
        )