#!/bin/sh

chown nobody -R /execute/

# Create socket directory if SOCKET_DIR is set
if [ -n "$SOCKET_DIR" ]; then
    mkdir -p "$SOCKET_DIR"
    chown nobody:nobody "$SOCKET_DIR"
    chmod 755 "$SOCKET_DIR"
fi

# Set host sysctls while running as root. 
if [ -d "/sys_host" ]; then
    echo "[*] Setting host sysctls..."
    echo 1 > /sys_host/net.ipv4.conf.all.forwarding 2>/dev/null || true
    echo 1 > /sys_host/net.ipv6.conf.all.forwarding 2>/dev/null || true
    echo 1 > /sys_host/net.ipv4.conf.all.route_localnet 2>/dev/null || true
    echo 1 > /sys_host/net.ipv4.ip_forward 2>/dev/null || true
fi

echo "[*] Attempting to start with capabilities..."

if capsh --caps="cap_net_admin,cap_setpcap,cap_setuid,cap_setgid,cap_sys_nice+eip" \
    --keep=1 \
    --user=nobody \
    --addamb=cap_net_admin,cap_sys_nice \
    -- -c "exit 0"
then
  exec capsh --caps="cap_net_admin,cap_setpcap,cap_setuid,cap_setgid,cap_sys_nice+eip" \
    --keep=1 \
    --user=nobody \
    --addamb=cap_net_admin,cap_sys_nice \
    --shell=/usr/bin/python3 \
    -- /execute/app.py DOCKER
else
    echo "[!] capsh failed, running with root user"
    exec python3 /execute/app.py DOCKER
fi

