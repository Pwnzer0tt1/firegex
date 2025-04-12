#!/bin/sh

chown nobody -R /execute/

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
    -- -c "python3 /execute/app.py DOCKER"
else
    echo "[!] capsh failed, running with root user"
    exec python3 /execute/app.py DOCKER
fi

