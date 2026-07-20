import subprocess
import os
import glob
from utils.sqlite import SQLite
from utils.certs import CertsDB, get_tls_ports, ip_parse as certs_ip_parse

NGINX_CONF_PATH = "/tmp/firegex_nginx.conf"
NGINX_PID_PATH = "/tmp/firegex_nginx.pid"
NGINX_LOG_PATH = "/tmp/firegex_nginx_error.log"

def _get_active_tls_services(db_name: str) -> list[dict]:
    db = SQLite(db_name)
    db.connect()
    try:
        return db.query("SELECT * FROM services WHERE status = 'active' AND tls_enabled = 1;")
    except Exception:
        return []
    finally:
        db.disconnect()

def update_nginx(services: list[dict]) -> None:
    if not services:
        subprocess.run(["nginx", "-c", NGINX_CONF_PATH, "-s", "stop", "-e", NGINX_LOG_PATH], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Clean up certificates, configuration, and pid
        for pattern in ("/tmp/firegex_cert_*", "/tmp/firegex_key_*", NGINX_CONF_PATH, NGINX_PID_PATH, NGINX_LOG_PATH):
            for path in (glob.glob(pattern) if "*" in pattern else [pattern]):
                try:
                    os.remove(path)
                except OSError:
                    pass
        return

    servers_config = []
    for srv in services:
        srv_id = srv["service_id"]
        cert_path = f"/tmp/firegex_cert_{srv_id}.crt"
        key_path = f"/tmp/firegex_key_{srv_id}.key"
        
        with open(cert_path, "w") as f:
            f.write(srv.get("tls_cert") or "")
        with open(key_path, "w") as f:
            f.write(srv.get("tls_key") or "")
            
        ssl_port, clear_port = get_tls_ports(srv["ip_int"], srv["port"])
        
        ip_addr = srv["ip_int"].split("/")[0]
        is_ipv6 = ":" in ip_addr
        loopback_ip = "[::1]" if is_ipv6 else "127.0.0.1"
        dest_ip = f"[{ip_addr}]" if is_ipv6 else ip_addr
        
        servers_config.append(
            f"    server {{\n"
            f"        listen {loopback_ip}:{ssl_port} ssl;\n"
            f"        proxy_pass {loopback_ip}:{clear_port};\n"
            f"        ssl_certificate {cert_path};\n"
            f"        ssl_certificate_key {key_path};\n"
            f"        ssl_protocols TLSv1.2 TLSv1.3;\n"
            f"    }}\n"
            f"    server {{\n"
            f"        listen {loopback_ip}:{clear_port};\n"
            f"        proxy_pass {dest_ip}:{srv['port']};\n"
            f"        proxy_ssl on;\n"
            f"        proxy_ssl_verify off;\n"
            f"        proxy_ssl_protocols TLSv1.2 TLSv1.3;\n"
            f"    }}"
        )

    config_content = ""
    if os.path.isdir("/usr/share/nginx/modules"):
        config_content += "include /usr/share/nginx/modules/*.conf;\n"

    config_content += (
        f"pid {NGINX_PID_PATH};\n"
        f"error_log {NGINX_LOG_PATH} info;\n\n"
        f"events {{\n"
        f"    worker_connections 1024;\n"
        f"}}\n\n"
        f"stream {{\n"
        + "\n".join(servers_config) + "\n"
        f"}}\n"
    )
    
    with open(NGINX_CONF_PATH, "w") as f:
        f.write(config_content)

    # Try to reload. If Nginx is not running, start it.
    res = subprocess.run(["nginx", "-c", NGINX_CONF_PATH, "-s", "reload", "-e", NGINX_LOG_PATH], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if res.returncode != 0:
        subprocess.run(["nginx", "-c", NGINX_CONF_PATH, "-e", NGINX_LOG_PATH], check=True)

def sync_nginx_state() -> None:
    services = _get_active_tls_services('db/nft-pyfilters.db') + _get_active_tls_services('db/nft-regex.db')
    
    # Batch-resolve certificates using CertsDB
    certs_map = CertsDB().get_multiple_certs_and_keys(services)
    for srv in services:
        cert, key = certs_map.get((certs_ip_parse(srv["ip_int"]), srv["port"]), (None, None))
        srv["tls_cert"] = cert
        srv["tls_key"] = key
        
    update_nginx(services)

