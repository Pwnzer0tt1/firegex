import base64

class Service:
    def __init__(self, service_id: str, status: str, port: int | None, name: str, proto: str, ip_int: str | None, fail_open: bool, target_type: str = "flow", tls_stream_id: str | None = None, tls_cert: str | None = None, tls_key: str | None = None, **other):
        self.id = service_id
        self.status = status
        self.port = port
        self.name = name
        self.proto = proto
        self.ip_int = ip_int
        self.fail_open = fail_open
        self.target_type = target_type
        self.tls_stream_id = tls_stream_id
        self.tls_cert = tls_cert
        self.tls_key = tls_key
    
    @classmethod
    def from_dict(cls, var: dict):
        return cls(**var)


class Regex:
    def __init__(self, regex_id: int, regex: bytes, mode: str, service_id: str, blocked_packets: int, is_case_sensitive: bool, active: bool, **other):
        self.regex = regex
        self.mode = mode
        self.service_id = service_id
        self.blocked_packets = blocked_packets
        self.id = regex_id
        self.is_case_sensitive = is_case_sensitive
        self.active = active
        
    @classmethod
    def from_dict(cls, var: dict):
        var['regex'] = base64.b64decode(var['regex'])
        return cls(**var)