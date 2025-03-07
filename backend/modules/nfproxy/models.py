
class Service:
    def __init__(self, service_id: str, status: str, port: int, name: str, proto: str, ip_int: str, fail_open: bool, **other):
        self.id = service_id
        self.status = status
        self.port = port
        self.name = name
        self.proto = proto
        self.ip_int = ip_int
        self.fail_open = fail_open
    
    @classmethod
    def from_dict(cls, var: dict):
        return cls(**var)


class PyFilter:
    def __init__(self, name: str, blocked_packets: int, edited_packets: int, active: bool, db, **other):
        self.name = name
        self.blocked_packets = blocked_packets
        self.edited_packets = edited_packets
        self.active = active
        self.__db = db

    async def update(self):
        self.__db.query("UPDATE pyfilter SET blocked_packets = ?, edited_packets = ? WHERE name = ?;", self.blocked_packets, self.edited_packets, self.name)

    def __repr__(self):
        return f"<PyFilter {self.name}>"

    @classmethod
    def from_dict(cls, var: dict, db):
        return cls(**var, db=db)
