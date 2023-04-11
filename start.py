#!/usr/bin/env python3

import argparse, sys, platform, os, multiprocessing

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

def composecmd(cmd):
    return os.system(f"(hash docker-compose &> /dev/null && (docker-compose -p firegex {cmd} || exit 0)) || (hash docker &> /dev/null && (docker compose -p firegex {cmd} || exit 0)) || echo 'Docker not found!, please install docker and docker compose'")

def dockercmd(cmd):
    return os.system(f"(hash docker &> /dev/null && (docker {cmd} || exit 0)) || echo 'Docker not found!, please install docker and docker-compose'")

parser = argparse.ArgumentParser()
parser.add_argument('--port', "-p", type=int, required=False, help='Port where open the web service of the firewall', default=4444)
parser.add_argument('--threads', "-t", type=int, required=False, help='Number of threads started for each service/utility', default=-1)
parser.add_argument('--no-autostart', "-n", required=False, action="store_true", help='Save docker-compose file and not start the container', default=False)
parser.add_argument('--keep','-k', required=False, action="store_true", help='Keep the docker-compose file generated', default=False)
parser.add_argument('--build', "-b", required=False, action="store_true", help='Build the container locally', default=False)
parser.add_argument('--stop', '-s', required=False, action="store_true", help='Stop firegex execution', default=False)
parser.add_argument('--restart', '-r', required=False, action="store_true", help='Restart firegex', default=False)
parser.add_argument('--psw-no-interactive',type=str, required=False, help='Password for no-interactive mode', default=None)
parser.add_argument('--startup-psw','-P', required=False, action="store_true", help='Insert password in the startup screen of firegex', default=False)


args = parser.parse_args()
os.chdir(os.path.dirname(os.path.realpath(__file__)))

start_operation = not (args.stop or args.restart)

if args.build and not os.path.isfile("./Dockerfile"):
    puts("This is not a clone of firegex, to build firegex the clone of the repository is needed!", color=colors.red)
    exit()

if args.threads < 1: 
    args.threads = multiprocessing.cpu_count()

if start_operation:
    sep()
    puts(f"Firegex", color=colors.yellow, end="")
    puts(" will start on port ", end="")
    puts(f"{args.port}", color=colors.cyan)

psw_set = None
if start_operation:
    if args.psw_no_interactive:
        psw_set = args.psw_no_interactive
    elif not args.startup_psw:
        puts("Insert the password for firegex: ", end="" , color=colors.yellow, is_bold=True)
        psw_set = input()
    
with open("docker-compose.yml","wt") as compose:

    if "linux" in sys.platform and not 'microsoft-standard' in platform.uname().release: #Check if not is a wsl also
        compose.write(f"""
version: '3.9'

services:
    firewall:
        restart: unless-stopped
        {"build: ." if args.build else "image: ghcr.io/pwnzer0tt1/firegex"}
        network_mode: "host"
        environment:
            - PORT={args.port}
            - NTHREADS={args.threads}
            {"- HEX_SET_PSW="+psw_set.encode().hex() if psw_set else ""}
        volumes:
            - /execute/db
        cap_add:
            - NET_ADMIN
""")

    else:
        sep()
        puts("--- WARNING ---", color=colors.yellow)
        puts("You are not in a linux machine, due to docker limitation on other platform, the firewall will not work in this machine. You will only see the interface of firegex.", color=colors.red)
        compose.write(f"""
version: '3.9'

services:
    firewall:
        restart: unless-stopped
        {"build: ." if args.build else "image: ghcr.io/pwnzer0tt1/firegex"}
        ports:
            - {args.port}:{args.port}
        environment:
            - PORT={args.port}
            - NTHREADS={args.threads}
            {"- HEX_SET_PSW="+psw_set.encode().hex() if psw_set else ""}
        volumes:
            - /execute/db
        cap_add:
            - NET_ADMIN
""")
sep()
if not args.no_autostart:
    try:
        if args.restart:
            puts("Running 'docker-compose restart'\n", color=colors.green)
            composecmd("restart")
        elif args.stop:
            puts("Running 'docker-compose down'\n", color=colors.green)
            composecmd("down")
        else:
            if not args.build:
                puts("Downloading docker image from github packages 'docker pull ghcr.io/pwnzer0tt1/firegex'", color=colors.green)
                dockercmd("pull ghcr.io/pwnzer0tt1/firegex")
            puts("Running 'docker-compose up -d --build'\n", color=colors.green)
            composecmd("up -d --build")
    finally:
        if not args.keep:
            os.remove("docker-compose.yml")
else:
    puts("Done! You can start/stop firegex with docker-compose up -d --build", color=colors.yellow)
    sep()
