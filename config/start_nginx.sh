#/bin/bash

chmod g+w -R /execute/db
envsubst '$NGINX_PORT' < /tmp/nginx.conf > /etc/nginx/nginx.conf
/usr/sbin/nginx -g "daemon off;" || exit 1
