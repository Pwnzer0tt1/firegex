import hashlib
from ipaddress import ip_interface
from utils.sqlite import SQLite

CERTIFICATES_SCHEMA = {
    'certificates': {
        'ip_int': 'VARCHAR(100) NOT NULL',
        'port': 'INT NOT NULL',
        'cert': 'TEXT NOT NULL',
        'key': 'TEXT NOT NULL',
        'PRIMARY KEY': '(ip_int, port)'
    }
}

_certs_db = SQLite('db/firegex.db', schema=CERTIFICATES_SCHEMA)

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

class CertsDB:
    def __init__(self, db_path='db/firegex.db'):
        # Ignore db_path if it matches the default, otherwise instantiate SQLite
        # (mostly for compatibility with tests if they pass custom paths)
        if db_path == 'db/firegex.db':
            self.db = _certs_db
        else:
            self.db = SQLite(db_path)
            
        if self.db.conn is None:
            self.db.connect()
        
    def get_cert_and_key(self, ip_int: str, port: int) -> tuple[str | None, str | None]:
        ip_int = ip_parse(ip_int)
        res = self.db.query("SELECT cert, key FROM certificates WHERE ip_int = ? AND port = ?;", ip_int, port)
        if res:
            return res[0]["cert"], res[0]["key"]
        return None, None

    def get_multiple_certs_and_keys(self, services: list[dict]) -> dict[tuple[str, int], tuple[str, str]]:
        if not services:
            return {}
        conditions = []
        params = []
        for s in services:
            conditions.append("(ip_int = ? AND port = ?)")
            params.extend([ip_parse(s["ip_int"]), s["port"]])
        query_str = "SELECT ip_int, port, cert, key FROM certificates WHERE " + " OR ".join(conditions) + ";"
        res = self.db.query(query_str, *params)
        return {(ip_parse(row["ip_int"]), row["port"]): (row["cert"], row["key"]) for row in res}

    def upsert_cert_and_key(self, ip_int: str, port: int, cert: str, key: str) -> None:
        ip_int = ip_parse(ip_int)
        self.db.query("INSERT OR REPLACE INTO certificates (ip_int, port, cert, key) VALUES (?, ?, ?, ?);", ip_int, port, cert, key)

    def delete_cert_and_key(self, ip_int: str, port: int) -> None:
        ip_int = ip_parse(ip_int)
        
        # Check if the certificate is still used by any service in regex DB
        regex_db = SQLite('db/nft-regex.db')
        regex_db.connect()
        try:
            regex_used = regex_db.query("SELECT 1 FROM services WHERE ip_int = ? AND port = ?;", ip_int, port)
        except Exception:
            regex_used = []
        finally:
            regex_db.disconnect()
            
        # Check if the certificate is still used by any service in proxy DB
        proxy_db = SQLite('db/nft-pyfilters.db')
        proxy_db.connect()
        try:
            proxy_used = proxy_db.query("SELECT 1 FROM services WHERE ip_int = ? AND port = ?;", ip_int, port)
        except Exception:
            proxy_used = []
        finally:
            proxy_db.disconnect()
            
        if not regex_used and not proxy_used:
            self.db.query("DELETE FROM certificates WHERE ip_int = ? AND port = ?;", ip_int, port)


def populate_services_tls_config(services: list[dict]) -> list[dict]:
    if not services:
        return services
    certs_map = CertsDB().get_multiple_certs_and_keys(services)
    for srv in services:
        if srv.get("tls_enabled"):
            srv["ssl_port"], srv["clear_port"] = get_tls_ports(srv["ip_int"], srv["port"])
            cert, key = certs_map.get((ip_parse(srv["ip_int"]), srv["port"]), (None, None))
            srv["tls_cert"] = cert
            srv["tls_key"] = key
        else:
            srv["ssl_port"], srv["clear_port"] = None, None
            srv["tls_cert"], srv["tls_key"] = None, None
    return services
