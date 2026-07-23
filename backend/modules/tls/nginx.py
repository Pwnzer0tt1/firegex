import subprocess
import os
import glob
from modules.tls.manager import TLSManager

NGINX_CONF_PATH = "/tmp/firegex_nginx.conf"
NGINX_PID_PATH = "/tmp/firegex_nginx.pid"
NGINX_LOG_PATH = "/tmp/firegex_nginx_error.log"

def update_nginx() -> None:
    manager = TLSManager()
    streams = manager.get_active_streams()

    if not streams:
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
    for srv in streams:
        srv_id = srv["id"]
        cert_path = f"/tmp/firegex_cert_{srv_id}.crt"
        key_path = f"/tmp/firegex_key_{srv_id}.key"
        
        with open(cert_path, "w") as f:
            f.write(srv.get("cert") or "")
        with open(key_path, "w") as f:
            f.write(srv.get("key") or "")
            
        ssl_port = srv["ssl_port"]
        clear_port = srv["clear_port"]
        
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
