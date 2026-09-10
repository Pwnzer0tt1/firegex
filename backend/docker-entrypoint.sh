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

# Two sets, tried in order, because they are not equally important.
#
# `cap_net_raw` is what lets the proxy engine open the packet socket it writes decrypted
# traffic to, for an operator capturing `firegex0`. It is a capture aid: a host that will
# not grant it should lose the capture, not the firewall. So the set without it is tried
# next, and only if *that* fails does anything run as root.
try_caps() {
    caps="$1"
    ambient="$2"
    capsh --caps="$caps" --keep=1 --user=nobody --addamb="$ambient" -- -c "exit 0" 2>/dev/null
}

run_caps() {
    exec capsh --caps="$1" --keep=1 --user=nobody --addamb="$2" \
        --shell=/usr/bin/python3 -- /execute/app.py DOCKER
}

FULL="cap_net_admin,cap_net_raw,cap_setpcap,cap_setuid,cap_setgid,cap_sys_nice+eip"
FULL_AMB="cap_net_admin,cap_net_raw,cap_sys_nice"
BASE="cap_net_admin,cap_setpcap,cap_setuid,cap_setgid,cap_sys_nice+eip"
BASE_AMB="cap_net_admin,cap_sys_nice"

if try_caps "$FULL" "$FULL_AMB"; then
    run_caps "$FULL" "$FULL_AMB"
elif try_caps "$BASE" "$BASE_AMB"; then
    echo "[!] no cap_net_raw: TLS services will run, but their decrypted traffic"
    echo "    cannot be written to the capture interface"
    run_caps "$BASE" "$BASE_AMB"
else
    echo "[!] capsh failed, running with root user"
    exec python3 /execute/app.py DOCKER
fi

