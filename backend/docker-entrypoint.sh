#!/bin/sh

chown nobody:nobody -R /execute/

capsh --caps="cap_net_admin+eip cap_setpcap,cap_setuid,cap_setgid+ep" \
    --keep=1 --user=nobody --addamb=cap_net_admin -- \
    -c "python3 /execute/app.py DOCKER"


