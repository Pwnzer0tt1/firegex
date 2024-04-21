#!/usr/bin/env python3

import argparse, sys, platform, os, multiprocessing, subprocess, getpass

pref = "\033["
reset = f"{pref}0m"
composefile = "firegex-compose-tmp-file.yml"
os.chdir(os.path.dirname(os.path.realpath(__file__)))

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

def check_if_exists(program):
    return subprocess.call(['sh', '-c',program], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT) == 0

def composecmd(cmd, composefile=None):
    if composefile:
        cmd = f"-f {composefile} {cmd}"
    if not check_if_exists("docker ps"):
        return puts("Cannot use docker, the user hasn't the permission or docker isn't running", color=colors.red)
    elif check_if_exists("docker compose"):
        return os.system(f"docker compose -p firegex {cmd}")
    elif check_if_exists("docker-compose"):
        return os.system(f"docker-compose -p firegex {cmd}")
    else:
        puts("Docker compose not found! please install docker compose!", color=colors.red)

def dockercmd(cmd):
    if check_if_exists("docker"):
        return os.system(f"docker {cmd}")
    elif not check_if_exists("docker ps"):
        puts("Cannot use docker, the user hasn't the permission or docker isn't running", color=colors.red)
    else:
        puts("Docker not found! please install docker!", color=colors.red)

def gen_args():
    parser = argparse.ArgumentParser()

    subcommands = parser.add_subparsers(dest="command", help="Command to execute [Default start if not running]")
    
    #Compose Command
    parser_compose = subcommands.add_parser('compose', help='Run docker compose command')
    parser_compose.add_argument('compose_args', nargs=argparse.REMAINDER, help='Arguments to pass to docker compose', default=[])
    
    #Start Command
    parser_start = subcommands.add_parser('start', help='Start the firewall')
    parser_start.add_argument('--threads', "-t", type=int, required=False, help='Number of threads started for each service/utility', default=-1)
    parser_start.add_argument('--build', "-b", required=False, action="store_true", help='Build the container locally', default=False)
    parser_start.add_argument('--psw-no-interactive',type=str, required=False, help='Password for no-interactive mode', default=None)
    parser_start.add_argument('--startup-psw','-P', required=False, action="store_true", help='Insert password in the startup screen of firegex', default=False)
    parser_start.add_argument('--port', "-p", type=int, required=False, help='Port where open the web service of the firewall', default=4444)
    parser_start.add_argument('--logs', required=False, action="store_true", help='Show firegex logs', default=False)
    
    #Stop Command
    parser_stop = subcommands.add_parser('stop', help='Stop the firewall')
    parser_stop.add_argument('--clear', required=False, action="store_true", help='Delete docker volume associated to firegex resetting all the settings', default=False)
    
    parser_restart = subcommands.add_parser('restart', help='Restart the firewall')
    parser_restart.add_argument('--logs', required=False, action="store_true", help='Show firegex logs', default=False)
    
    #General args
    if os.path.isfile("./Dockerfile"):
        parser.add_argument('--build', "-b", required=False, action="store_true", help='Build the container from source', default=False)
    return parser.parse_args()

args = gen_args()

def is_linux():
    return "linux" in sys.platform and not 'microsoft-standard' in platform.uname().release

def write_compose(skip_password = True):
    psw_set = get_password() if not skip_password else None
    with open(composefile,"wt") as compose:

        if is_linux(): #Check if not is a wsl also
             compose.write(f"""
services:
    firewall:
        restart: unless-stopped
        container_name: firegex
        {"build: ." if args.build else "image: ghcr.io/pwnzer0tt1/firegex"}
        network_mode: "host"
        environment:
            - PORT={args.port}
            - NTHREADS={args.threads}
            {"- HEX_SET_PSW="+psw_set.encode().hex() if psw_set else ""}
        volumes:
            - firegex_data:/execute/db
            - type: bind
              source: /proc/sys/net/ipv4/conf/all/route_localnet
              target: /sys_host/net.ipv4.conf.all.route_localnet
            - type: bind
              source: /proc/sys/net/ipv4/ip_forward
              target: /sys_host/net.ipv4.ip_forward
            - type: bind
              source: /proc/sys/net/ipv4/conf/all/forwarding
              target: /sys_host/net.ipv4.conf.all.forwarding
            - type: bind
              source: /proc/sys/net/ipv6/conf/all/forwarding
              target: /sys_host/net.ipv6.conf.all.forwarding
        cap_add:
            - NET_ADMIN
volumes:
    firegex_data:
""")

        else:
            compose.write(f"""
services:
    firewall:
        restart: unless-stopped
        container_name: firegex
        {"build: ." if args.build else "image: ghcr.io/pwnzer0tt1/firegex"}
        ports:
            - {args.port}:{args.port}
        environment:
            - PORT={args.port}
            - NTHREADS={args.threads}
            {"- HEX_SET_PSW="+psw_set.encode().hex() if psw_set else ""}
        volumes:
            - firegex_data:/execute/db
        cap_add:
            - NET_ADMIN
volumes:
    firegex_data:
""")

def check_already_running():
    return check_if_exists("docker ps --filter 'name=^firegex$' --no-trunc | grep firegex")
      
def get_password():
    if volume_exists() or args.startup_psw:
        return None
    if args.psw_no_interactive:
        return args.psw_no_interactive
    psw_set = None
    while True:
        while True:
            puts("Insert a password for firegex: ", end="" , color=colors.yellow, is_bold=True, flush=True)
            psw_set = getpass.getpass("")
            if (len(psw_set) < 8):
                puts("The password has to be at least 8 char long", color=colors.red, is_bold=True, flush=True)
            else:
                break
        puts("Confirm the password: ", end="" , color=colors.yellow, is_bold=True, flush=True)
        check = getpass.getpass("")
        if check != psw_set:
            puts("Passwords don't match!" , color=colors.red, is_bold=True, flush=True)
        else:
            break
    return psw_set

def volume_exists():
    return check_if_exists('docker volume ls --filter="name=^firegex_firegex_data$" --quiet | grep firegex_firegex_data')

def nfqueue_exists():
    return check_if_exists('ls /lib/modules/$(uname -r)/kernel/net/netfilter/nfnetlink_queue.*')

def delete_volume():
    return dockercmd("volume rm firegex_firegex_data")

def main():
    
    print(args)
    
    if not check_if_exists("docker"):
        puts("Docker not found! please install docker and docker compose!", color=colors.red)
        exit()
    elif not check_if_exists("docker-compose") and not check_if_exists("docker compose"):
        print(check_if_exists("docker-compose"), check_if_exists("docker compose"))
        puts("Docker compose not found! please install docker compose!", color=colors.red)
        exit()
    if not check_if_exists("docker ps"):
        puts("Cannot use docker, the user hasn't the permission or docker isn't running", color=colors.red)
        exit()
    
    if args.command is None:
        if not check_already_running() and not args.clear:
            args.command = "start"
    
    if not is_linux():
        sep()
        puts("--- WARNING ---", color=colors.yellow)
        puts("You are not in a linux machine, the firewall will not work in this machine.", color=colors.red)
        sep()
    elif not nfqueue_exists():
        sep()
        puts("--- WARNING ---", color=colors.yellow)
        puts("The nfqueue kernel module seems not loaded, some features of firegex may not work.", color=colors.red)
        sep()

    if not "threads" in args or args.threads < 1:
        args.threads = multiprocessing.cpu_count()
    
    if not "port" in args or args.port < 1:
        args.port = 4444

    if args.command:
        match args.command:
            case "start":
                if check_already_running():
                    puts("Firegex is already running! use --help to see options useful to manage firegex execution", color=colors.yellow)
                else:
                    puts(f"Firegex", color=colors.yellow, end="")
                    puts(" will start on port ", end="")
                    puts(f"{args.port}", color=colors.cyan)
                    write_compose(skip_password=False)
                    if not args.build:
                        puts("Downloading docker image from github packages 'docker pull ghcr.io/pwnzer0tt1/firegex'", color=colors.green)
                        dockercmd("pull ghcr.io/pwnzer0tt1/firegex")
                    puts("Running 'docker compose up -d --build'\n", color=colors.green)
                    composecmd("up -d --build", composefile)
            case "compose":
                write_compose()
                compose_cmd = " ".join(args.compose_args)
                puts(f"Running 'docker compose {compose_cmd}'\n", color=colors.green)
                composecmd(compose_cmd, composefile)
            case "restart":
                if check_already_running():
                    write_compose()
                    puts("Running 'docker compose restart'\n", color=colors.green)
                    composecmd("restart", composefile)
                else:
                    puts("Firegex is not running!" , color=colors.red, is_bold=True, flush=True)
            case "stop":
                if check_already_running():
                    write_compose()
                    puts("Running 'docker compose down'\n", color=colors.green)
                    composecmd("down", composefile)
                else:
                    puts("Firegex is not running!" , color=colors.red, is_bold=True, flush=True)
    
    write_compose()
    
    if "clear" in args and args.clear:
        if volume_exists():
            delete_volume()
        else:
            puts("Firegex volume not found!", color=colors.red)

    if "logs" in args and args.logs:
        composecmd("logs -f")


if __name__ == "__main__":
    try:
        try:
            main()
        finally:
            if os.path.isfile(composefile):
                os.remove(composefile)
    except KeyboardInterrupt:
        print()
