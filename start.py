#!/usr/bin/env python3

import argparse, sys, platform, os

pref = "\033["
reset = f"{pref}0m"

class colors:
    black = "30m"
    red = "31m"
    green = "32m"
    yellow = "33m"
    blue = "34m"
    magenta = "35m"
    cyan = "36m"
    white = "37m"

def puts(text, *args, color=colors.white, is_bold=False, **kwargs):
    print(f'{pref}{1 if is_bold else 0};{color}' + text + reset, *args, **kwargs)

def sep(): puts("-----------------------------------", is_bold=True)
parser = argparse.ArgumentParser()
parser.add_argument('--port', "-p", type=int, required=False, help='Port where open the web service of the firewall', default=4444)
parser.add_argument('--no-autostart', "-n", required=False, action="store_true", help='Auto-execute "docker-compose up -d --build"', default=False)
parser.add_argument('--single-thread', "-s", required=False, action="store_true", help='Disable multi-threaded proxy"', default=False)
parser.add_argument('--thread-num', "-t", type=int, required=False, help='Number of threads to use', default=None)

args = parser.parse_args()
sep()
puts(f"Firegex", color=colors.yellow, end="")
puts(" will start on port ", end="")
puts(f"{args.port}", color=colors.cyan)

os.chdir(os.path.dirname(os.path.realpath(__file__)))

gcc_params = "-D MULTI_THREAD" if not args.single_thread else ""
gcc_params+= f" -D THREAD_NUM={args.thread_num}" if args.thread_num else ""
with open("docker-compose.yml","wt") as compose:

    if "linux" in sys.platform and not 'microsoft-standard' in platform.uname().release: #Check if not is a wsl also
        compose.write(f"""
version: '3.9'

services:
    firewall:
        restart: unless-stopped
        build: 
            context: .
            args:
                - GCC_PARAMS={gcc_params}
        network_mode: "host"
        environment:
            - PORT={args.port}
        volumes:
            - /execute/db
""")
        #print("Done! You can start firegex with docker-compose up -d --build")
    else:
        sep()
        puts("--- WARNING ---", color=colors.yellow)
        puts("You are not in a linux machine, due to docker limitation on other platform, the firewall will not work in this machine. You will only see the interface of firegex.", color=colors.red)
        compose.write(f"""
version: '3.9'

services:
    firewall:
        restart: unless-stopped
        build: 
            context: .
            args:
                - GCC_PARAMS={gcc_params}
        ports:
            - {args.port}:{args.port}
        environment:
            - PORT={args.port}
            - LOCALHOST_IP=host.docker.internal
        volumes:
            - /execute/db
        extra_hosts:
            - host.docker.internal:host-gateway
""")
        #
sep()
if not args.no_autostart:
    puts("Running 'docker-compose up -d --build'\n", color=colors.green)
    os.system("docker-compose up -d --build")
else:
    puts("Done! You can start firegex with docker-compose up -d --build", color=colors.yellow)
    sep()

