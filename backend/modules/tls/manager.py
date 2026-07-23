import hashlib
from ipaddress import ip_interface
from utils.sqlite import SQLite

def ip_parse(ip: str) -> str:
    try:
        return str(ip_interface(ip).network)
    except Exception:
        return ip

def get_tls_ports(ip: str, port: int) -> tuple[int, int]:
    ip_addr = ip.split("/")[0]
    key = f"{ip_addr}:{port}"
    h = int.from_bytes(hashlib.sha256(key.encode('utf-8')).digest()[:4], 'big')
    ssl_port = 10000 + (h % 10000)
    clear_port = 20000 + (h % 10000)
    return ssl_port, clear_port

TLS_SCHEMA = {
    'tls_streams': {
        'id': 'VARCHAR(100) PRIMARY KEY',
        'name': 'VARCHAR(100) NOT NULL',
        'ip_int': 'VARCHAR(100) NOT NULL',
        'port': 'INT NOT NULL',
        'cert': 'TEXT NOT NULL',
        'key': 'TEXT NOT NULL',
        'status': 'VARCHAR(50) NOT NULL', # 'active' or 'stop'
        'ssl_port': 'INT NOT NULL',
        'clear_port': 'INT NOT NULL',
        'UNIQUE': '(ip_int, port)'
    }
}

class TLSManager:
    def __init__(self, db_path='db/nft-tls.db'):
        self.db = SQLite(db_path, schema=TLS_SCHEMA)
        self.db.init()

    def add_stream(self, stream_id: str, name: str, ip_int: str, port: int, cert: str, key: str, status: str = 'stop') -> None:
        ip_int = ip_parse(ip_int)
        ssl_port, clear_port = get_tls_ports(ip_int, port)
        self.db.query(
            "INSERT INTO tls_streams (id, name, ip_int, port, cert, key, status, ssl_port, clear_port) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
            stream_id, name, ip_int, port, cert, key, status, ssl_port, clear_port
        )

    def get_streams(self) -> list[dict]:
        return self.db.query("SELECT * FROM tls_streams;")

    def get_stream(self, stream_id: str) -> dict | None:
        res = self.db.query("SELECT * FROM tls_streams WHERE id = ?;", stream_id)
        return res[0] if res else None

    def get_stream_by_ip_port(self, ip_int: str, port: int) -> dict | None:
        ip_int = ip_parse(ip_int)
        res = self.db.query("SELECT * FROM tls_streams WHERE ip_int = ? AND port = ?;", ip_int, port)
        return res[0] if res else None

    def update_status(self, stream_id: str, status: str) -> None:
        self.db.query("UPDATE tls_streams SET status = ? WHERE id = ?;", status, stream_id)

    def update_stream(self, stream_id: str, name: str | None = None, ip_int: str | None = None, port: int | None = None, cert: str | None = None, key: str | None = None) -> None:
        stream = self.get_stream(stream_id)
        if not stream:
            return
        fields: dict = {}
        if name is not None:
            fields["name"] = name
        if cert is not None:
            fields["cert"] = cert
        if key is not None:
            fields["key"] = key
        new_ip = ip_parse(ip_int) if ip_int is not None else stream["ip_int"]
        new_port = port if port is not None else stream["port"]
        if ip_int is not None:
            fields["ip_int"] = new_ip
        if port is not None:
            fields["port"] = new_port
        if ip_int is not None or port is not None:
            ssl_port, clear_port = get_tls_ports(new_ip, new_port)
            fields["ssl_port"] = ssl_port
            fields["clear_port"] = clear_port
        if not fields:
            return
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        self.db.query(f"UPDATE tls_streams SET {set_clause} WHERE id = ?;", *fields.values(), stream_id)

    def delete_stream(self, stream_id: str) -> None:
        self.db.query("DELETE FROM tls_streams WHERE id = ?;", stream_id)

    def get_active_streams(self) -> list[dict]:
        return self.db.query("SELECT * FROM tls_streams WHERE status = 'active';")
