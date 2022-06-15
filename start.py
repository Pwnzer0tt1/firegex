#!/usr/bin/env python3

import argparse, sys, platform

parser = argparse.ArgumentParser()
parser.add_argument('port', type=int, help='Port where open the web service of the firewall')
args = parser.parse_args()


with open("docker-compose.yml","wt") as compose:

    if "linux" in sys.platform and not 'microsoft-standard' in platform.uname().release: #Check if not is a wsl also
        compose.write(f"""
version: '3.9'

services:
    firewall:
        restart: unless-stopped
        build: .
        network_mode: "host"
        environment:
            - NGINX_PORT={args.port}
        volumes:
            - /execute/db
""")
        print("Done! You can start firegex with docker-compose up -d --build")
    else:
        print("-----------------------------------")
        print("You are not in a linux machine, due to docker limitation on other platform, the firewall will not work in this machine. You will only see the interface of firegex.")
        print("-----------------------------------")
        compose.write(f"""
version: '3.9'

services:
    firewall:
        restart: unless-stopped
        build: .
        ports:
            - {args.port}:{args.port}
        environment:
            - NGINX_PORT={args.port}
        volumes:
            - /execute/db
""")
        print("Done! You can start firegex with docker-compose up -d --build")
