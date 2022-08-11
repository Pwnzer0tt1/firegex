class Service:
    def __init__(self, service_id: str, active: bool, public_port: int, proxy_port: int, name: str, proto: str, ip_int: str):
        self.service_id = service_id
        self.active = active
        self.public_port = public_port
        self.proxy_port = proxy_port
        self.name = name
        self.proto = proto
        self.ip_int = ip_int
    
    @classmethod
    def from_dict(cls, var: dict):
        return cls(id=var["service_id"], active=var["active"], public_port=var["public_port"], proxy_port=var["proxy_port"], name=var["name"], proto=var["proto"], ip_int=var["ip_int"])
