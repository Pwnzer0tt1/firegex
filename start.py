#!/usr/bin/env python3
from __future__ import annotations
import argparse, sys, platform, os, multiprocessing, subprocess, getpass

pref = "\033["
reset = f"{pref}0m"
class g:
    composefile = "firegex-compose-tmp-file.yml"
    build = False
os.chdir(os.path.dirname(os.path.realpath(__file__)))

if os.path.isfile("./Dockerfile"):
    with open("./Dockerfile", "rt") as dockerfile:
        if "cf1795af-3284-4183-a888-81ad3590ad84" in dockerfile.read():
            g.build = True

#Terminal colors

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

def dict_to_yaml(data, indent_spaces:int=4, base_indent:int=0, additional_spaces:int=0, add_text_on_dict:str|None=None):
    yaml = ''
    spaces = ' '*((indent_spaces*base_indent)+additional_spaces)
    if isinstance(data, dict):
        for key, value in data.items():
            if not add_text_on_dict is None:
                spaces_len = len(spaces)-len(add_text_on_dict)
                spaces = (' '*max(spaces_len, 0))+add_text_on_dict
                add_text_on_dict = None
            if isinstance(value, dict) or isinstance(value, list):
                yaml += f"{spaces}{key}:\n"
                yaml += dict_to_yaml(value, indent_spaces=indent_spaces, base_indent=base_indent+1, additional_spaces=additional_spaces)
            else:
                yaml += f"{spaces}{key}: {value}\n"
            spaces = ' '*((indent_spaces*base_indent)+additional_spaces)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yaml += dict_to_yaml(item, indent_spaces=indent_spaces, base_indent=base_indent, additional_spaces=additional_spaces+2, add_text_on_dict="- ")
            elif isinstance(item, list):
                yaml += dict_to_yaml(item, indent_spaces=indent_spaces, base_indent=base_indent+1, additional_spaces=additional_spaces)
            else:
                yaml += f"{spaces}- {item}\n"
    else:
        yaml += f"{data}\n"
    return yaml

def cmd_check(program, get_output=False, print_output=False, no_stderr=False):
    if get_output:
        return subprocess.getoutput(program)
    if print_output:
        return subprocess.call(program, shell=True) == 0
    return subprocess.call(program, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL if no_stderr else subprocess.STDOUT, shell=True) == 0

def composecmd(cmd, composefile=None):
    if composefile:
        cmd = f"-f {composefile} {cmd}"
    if cmd_check("docker compose --version"):
        return os.system(f"docker compose -p firegex {cmd}")
    elif cmd_check("docker-compose --version"):
        return os.system(f"docker-compose -p firegex {cmd}")
    else:
        puts("Docker compose not found! please install docker compose!", color=colors.red)

def check_already_running():
    return "firegex" in cmd_check(f'docker ps --filter "name=^firegex$"', get_output=True)

def gen_args(args_to_parse: list[str]|None = None):                     
    
    #Main parser
    parser = argparse.ArgumentParser(description="Firegex Manager")
    parser.add_argument('--clear', dest="bef_clear", required=False, action="store_true", help='Delete docker volume associated to firegex resetting all the settings', default=False)

    subcommands = parser.add_subparsers(dest="command", help="Command to execute [Default start if not running]")
    
    #Compose Command
    parser_compose = subcommands.add_parser('compose', help='Run docker compose command')
    parser_compose.add_argument('compose_args', nargs=argparse.REMAINDER, help='Arguments to pass to docker compose', default=[])
    
    #Start Command
    parser_start = subcommands.add_parser('start', help='Start the firewall')
    parser_start.add_argument('--threads', "-t", type=int, required=False, help='Number of threads started for each service/utility', default=-1)
    parser_start.add_argument('--psw-no-interactive',type=str, required=False, help='Password for no-interactive mode', default=None)
    parser_start.add_argument('--startup-psw','-P', required=False, action="store_true", help='Insert password in the startup screen of firegex', default=False)
    parser_start.add_argument('--port', "-p", type=int, required=False, help='Port where open the web service of the firewall', default=4444)
    parser_start.add_argument('--logs', required=False, action="store_true", help='Show firegex logs', default=False)

    #Stop Command
    parser_stop = subcommands.add_parser('stop', help='Stop the firewall')
    parser_stop.add_argument('--clear', required=False, action="store_true", help='Delete docker volume associated to firegex resetting all the settings', default=False)
    
    parser_restart = subcommands.add_parser('restart', help='Restart the firewall')
    parser_restart.add_argument('--logs', required=False, action="store_true", help='Show firegex logs', default=False)
    args = parser.parse_args(args=args_to_parse)
    
    if not "clear" in args:
        args.clear = False
    
    if not "threads" in args or args.threads < 1:
        args.threads = multiprocessing.cpu_count()
    
    if not "port" in args or args.port < 1:
        args.port = 4444
    
    if args.command is None:
        if not args.clear:
            return gen_args(["start", *sys.argv[1:]])
    
    args.clear = args.bef_clear or args.clear

    return args

args = gen_args()

def is_linux():
    return "linux" in sys.platform and not 'microsoft-standard' in platform.uname().release

def write_compose(skip_password = True):
    psw_set = get_password() if not skip_password else None
    with open(g.composefile,"wt") as compose:

        if is_linux(): #Check if not is a wsl also
            compose.write(dict_to_yaml({
                "services": {
                    "firewall": {
                        "restart": "unless-stopped",
                        "container_name": "firegex",
                        "build" if g.build else "image": "." if g.build else "ghcr.io/pwnzer0tt1/firegex",
                        "network_mode": "host",
                        "environment": [
                            f"PORT={args.port}",
                            f"NTHREADS={args.threads}",
                            *([f"HEX_SET_PSW={psw_set.encode().hex()}"] if psw_set else [])
                        ],
                        "volumes": [
                            "firegex_data:/execute/db",
                            {
                                "type": "bind",
                                "source": "/proc/sys/net/ipv4/conf/all/route_localnet",
                                "target": "/sys_host/net.ipv4.conf.all.route_localnet"
                            },
                            {
                                "type": "bind",
                                "source": "/proc/sys/net/ipv4/ip_forward",
                                "target": "/sys_host/net.ipv4.ip_forward"
                            },
                            {
                                "type": "bind",
                                "source": "/proc/sys/net/ipv4/conf/all/forwarding",
                                "target": "/sys_host/net.ipv4.conf.all.forwarding"
                            },
                            {
                                "type": "bind",
                                "source": "/proc/sys/net/ipv6/conf/all/forwarding",
                                "target": "/sys_host/net.ipv6.conf.all.forwarding"
                            }
                        ],
                        "cap_add": [
                            "NET_ADMIN"
                        ]
                    }
                },
                "volumes": {
                    "firegex_data": ""
                }
            }))
        else:
            compose.write(dict_to_yaml({
                "services": {
                    "firewall": {
                        "restart": "unless-stopped",
                        "container_name": "firegex",
                        "build" if g.build else "image": "." if g.build else "ghcr.io/pwnzer0tt1/firegex",
                        "ports": [
                            f"{args.port}:{args.port}"
                        ],
                        "environment": [
                            f"PORT={args.port}",
                            f"NTHREADS={args.threads}",
                            *([f"HEX_SET_PSW={psw_set.encode().hex()}"] if psw_set else [])
                        ],
                        "volumes": [
                            "firegex_data:/execute/db"
                        ],
                        "cap_add": [
                            "NET_ADMIN"
                        ]
                    }
                },
                "volumes": {
                    "firegex_data": ""
                }
            }))
      
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
    return "firegex_firegex_data" in cmd_check(f'docker volume ls --filter "name=^firegex_firegex_data$"', get_output=True)

def nfqueue_exists():
    import socket, fcntl, os, time

    NETLINK_NETFILTER = 12
    SOL_NETLINK = 270
    NETLINK_EXT_ACK = 11
    try:
        nfsock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        fcntl.fcntl(nfsock, fcntl.F_SETFL, os.O_RDONLY|os.O_NONBLOCK)
        nfsock.setsockopt(SOL_NETLINK, NETLINK_EXT_ACK, 1)
    except Exception as e:
        return False
    
    for rev in [3,2,1,0]:
        timestamp = int(time.time()).to_bytes(4, byteorder='big')
        rev = rev.to_bytes(4, byteorder='big')
        #Prepared payload to check if the nfqueue module is loaded (from iptables code "nft_compatible_revision")
        payload = b"\x30\x00\x00\x00\x00\x0b\x05\x00"+timestamp+b"\x00\x00\x00\x00\x02\x00\x00\x00\x0c\x00\x01\x00\x4e\x46\x51\x55\x45\x55\x45\x00\x08\x00\x02\x00"+rev+b"\x08\x00\x03\x00\x00\x00\x00\x01"
        nfsock.send(payload)
        data = nfsock.recv(1024)
        is_error = data[4] == 2
        if not is_error: return True # The module exists and we have permission to use it
        error_code = int.from_bytes(data[16:16+4], signed=True, byteorder='little')
        if error_code == -1: return True # EPERM (the user is not root, but the module exists)
        if error_code == -2: pass # ENOENT (the module does not exist)
        else:
            puts("Error while trying to check if the nfqueue module is loaded, this check will be skipped!", color=colors.yellow)
            return True
    return False


def delete_volume():
    return cmd_check("docker volume rm firegex_firegex_data")

def main():
    
    if not cmd_check("docker --version"):
        puts("Docker not found! please install docker and docker compose!", color=colors.red)
        exit()
    elif not cmd_check("docker-compose --version") and not cmd_check("docker compose --version"):
        puts("Docker compose not found! please install docker compose!", color=colors.red)
        exit()
    if not cmd_check("docker ps"):
        puts("Cannot use docker, the user hasn't the permission or docker isn't running", color=colors.red)
        exit()
    
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
                    if not g.build:
                        puts("Downloading docker image from github packages 'docker pull ghcr.io/pwnzer0tt1/firegex'", color=colors.green)
                        cmd_check("docker pull ghcr.io/pwnzer0tt1/firegex", print_output=True)
                    puts("Running 'docker compose up -d --build'\n", color=colors.green)
                    composecmd("up -d --build", g.composefile)
            case "compose":
                write_compose()
                compose_cmd = " ".join(args.compose_args)
                puts(f"Running 'docker compose {compose_cmd}'\n", color=colors.green)
                composecmd(compose_cmd, g.composefile)
            case "restart":
                if check_already_running():
                    write_compose()
                    puts("Running 'docker compose restart'\n", color=colors.green)
                    composecmd("restart", g.composefile)
                else:
                    puts("Firegex is not running!" , color=colors.red, is_bold=True, flush=True)
            case "stop":
                if check_already_running():
                    write_compose()
                    puts("Running 'docker compose down'\n", color=colors.green)
                    composecmd("down", g.composefile)
                else:
                    puts("Firegex is not running!" , color=colors.red, is_bold=True, flush=True)
    
    write_compose()
    
    if args.clear:
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
            if os.path.isfile(g.composefile):
                os.remove(g.composefile)
    except KeyboardInterrupt:
        print()
