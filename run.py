#!/usr/bin/env python3

from __future__ import annotations
import argparse
import sys
import platform
import os
import multiprocessing
import subprocess
import getpass
import tarfile
import hashlib
import secrets

pref = "\033["
reset = f"{pref}0m"
class g:
    composefile = ".firegex-compose.yml"
    configfile = ".firegex-conf.json"
    build = False
    standalone_mode = False
    rootfs_path = "./firegexfs"
    pid_file = "./.firegex-standalone.pid"
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

def hash_psw(psw: str):
    salt = secrets.token_hex(32)
    return hashlib.pbkdf2_hmac("sha256", psw.encode(), salt.encode(), 500_000).hex()+"-"+salt

def puts(text, *args, color=colors.white, is_bold=False, **kwargs):
    print(f'{pref}{1 if is_bold else 0};{color}' + text + reset, *args, **kwargs)

def sep(): puts("-----------------------------------", is_bold=True)

def dict_to_yaml(data, indent_spaces:int=4, base_indent:int=0, additional_spaces:int=0, add_text_on_dict:str|None=None):
    yaml = ''
    spaces = ' '*((indent_spaces*base_indent)+additional_spaces)
    if isinstance(data, dict):
        for key, value in data.items():
            if add_text_on_dict is not None:
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
    return "firegex" in cmd_check('docker ps --filter "name=^firegex$"', get_output=True)

def load_config():
    """Load configuration from .firegex-conf.json"""
    import json
    default_config = {
        "port": 4444,
        # any allow to bind service also on ipv6 (see the main of backend to understand why)
        "host": "any"
    }
    
    if os.path.isfile(g.configfile):
        try:
            with open(g.configfile, 'r') as f:
                config = json.load(f)
                # Ensure all required keys exist
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
        except (json.JSONDecodeError, IOError) as e:
            puts(f"Warning: Failed to load config file {g.configfile}: {e}", color=colors.yellow)
            puts("Using default configuration", color=colors.yellow)
    
    return default_config

def save_config(config):
    """Save configuration to .firegex-conf.json"""
    import json
    try:
        with open(g.configfile, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except IOError as e:
        puts(f"Warning: Failed to save config file {g.configfile}: {e}", color=colors.yellow)
        return False

def gen_args(args_to_parse: list[str]|None = None):                     
    
    # Load configuration
    config = load_config()
    
    #Main parser
    parser = argparse.ArgumentParser(description="Firegex Manager")
    parser.add_argument('--clear', dest="bef_clear", required=False, action="store_true", help='Delete docker volume associated to firegex resetting all the settings', default=False)
    parser.add_argument('--standalone', required=False, action="store_true", help='Force standalone mode', default=False)

    subcommands = parser.add_subparsers(dest="command", help="Command to execute [Default start if not running]")
    
    #Compose Command
    parser_compose = subcommands.add_parser('compose', help='Run docker compose command')
    parser_compose.add_argument('compose_args', nargs=argparse.REMAINDER, help='Arguments to pass to docker compose', default=[])
    
    #Start Command
    parser_start = subcommands.add_parser('start', help='Start the firewall')
    parser_start.add_argument('--threads', "-t", type=int, required=False, help='Number of threads started for each service/utility', default=-1)
    parser_start.add_argument('--startup-psw','-P', required=False, help='Insert password in the startup screen of firegex', type=str, default=None)
    parser_start.add_argument('--psw-on-web', required=False, help='Setup firegex password on the web interface', action="store_true", default=False)
    parser_start.add_argument('--port', "-p", type=int, required=False, help=f'Port where open the web service of the firewall (default from config: {config["port"]})', default=config["port"])
    parser_start.add_argument('--host', required=False, help=f'Host IP address to bind the service to (default from config: {config["host"]})', default=config["host"])
    parser_start.add_argument('--logs', required=False, action="store_true", help='Show firegex logs', default=False)
    parser_start.add_argument('--version', '-v', required=False, type=str , help='Version of the firegex image to use', default=None)
    parser_start.add_argument('--prebuilt', required=False, action="store_true", help='Use prebuilt docker image', default=False)
    parser_start.add_argument('--standalone', required=False, action="store_true", help='Force standalone mode', default=False)

    #Stop Command
    parser_stop = subcommands.add_parser('stop', help='Stop the firewall')
    parser_stop.add_argument('--clear', required=False, action="store_true", help='Delete docker volume associated to firegex resetting all the settings', default=False)
    parser_stop.add_argument('--standalone', required=False, action="store_true", help='Force standalone mode', default=False)
    
    parser_restart = subcommands.add_parser('restart', help='Restart the firewall')
    parser_restart.add_argument('--port', "-p", type=int, required=False, help=f'Port where open the web service of the firewall (default from config: {config["port"]})', default=config["port"])
    parser_restart.add_argument('--host', required=False, help=f'Host IP address to bind the service to (default from config: {config["host"]})', default=config["host"])
    parser_restart.add_argument('--logs', required=False, action="store_true", help='Show firegex logs', default=False)
    parser_restart.add_argument('--standalone', required=False, action="store_true", help='Force standalone mode', default=False)
    
    #Status Command
    parser_status = subcommands.add_parser('status', help='Show firewall status')
    parser_status.add_argument('--port', "-p", type=int, required=False, help=f'Port where open the web service of the firewall (default from config: {config["port"]})', default=config["port"])
    parser_status.add_argument('--host', required=False, help=f'Host IP address to bind the service to (default from config: {config["host"]})', default=config["host"])
    parser_status.add_argument('--standalone', required=False, action="store_true", help='Force standalone mode', default=False)
    
    #Config Command
    parser_config = subcommands.add_parser('config', help='Manage configuration settings')
    parser_config.add_argument('--port', "-p", type=int, required=False, help='Set default port for web service')
    parser_config.add_argument('--host', required=False, help='Set default host IP address to bind the service to')
    parser_config.add_argument('--show', required=False, action="store_true", help='Show current configuration', default=False)
    args = parser.parse_args(args=args_to_parse)
    
    if "version" in args and args.version and g.build:
        puts("The version argument is not used when the image is built from the Dockerfile", color=colors.yellow)
        puts("The version will be ignored", color=colors.yellow)
    
    if "version" not in args or not args.version:
        args.version = "latest"
    
    if "prebuilt" in args and args.prebuilt:
        g.build = False
    
    if "psw_on_web" not in args:
        args.psw_on_web = False
    
    if "startup_psw" not in args:
        args.startup_psw = None
    
    if "clear" not in args:
        args.clear = False
    
    if "standalone" not in args:
        args.standalone = False
    
    if "threads" not in args or args.threads < 1:
        args.threads = multiprocessing.cpu_count()
    
    # Use config values as fallback, but allow command line to override
    if "port" not in args or args.port < 1:
        args.port = config["port"]
    
    if "host" not in args:
        args.host = config["host"]
    
    # Save configuration if values were specified via command line and differ from config
    config_changed = False
    if hasattr(args, 'port') and args.port != config["port"]:
        config["port"] = args.port
        config_changed = True
    if hasattr(args, 'host') and args.host != config["host"]:
        config["host"] = args.host
        config_changed = True
    
    if config_changed:
        save_config(config)
    
    if args.command is None:
        if not args.clear:
            return gen_args(["start", *sys.argv[1:]])
    
    args.clear = args.bef_clear or args.clear

    return args

args = gen_args()

def is_linux():
    return "linux" in sys.platform and 'microsoft-standard' not in platform.uname().release

def get_web_interface_url():
    # In modalità host network (Linux), l'host configurato non è applicabile
    # quindi usiamo sempre localhost
    if is_linux():
        return f"http://localhost:{args.port}"
    # Per altre piattaforme, usiamo l'host configurato se non è 0.0.0.0
    # altrimenti usiamo localhost per evitare confusione
    display_host = "localhost" if args.host == "0.0.0.0" else args.host
    return f"http://{display_host}:{args.port}"

def write_compose(skip_password = True):
    psw_set = get_password() if not skip_password else None
    with open(g.composefile,"wt") as compose:

        if is_linux(): #Check if not is a wsl also
            compose.write(dict_to_yaml({
                "services": {
                    "firewall": {
                        "restart": "unless-stopped",
                        "container_name": "firegex",
                        "build" if g.build else "image": "." if g.build else f"ghcr.io/pwnzer0tt1/firegex:{args.version}",
                        "network_mode": "host",
                        "environment": [
                            f"PORT={args.port}",
                            f"HOST={args.host}",
                            f"NTHREADS={args.threads}",
                            *([f"PSW_HASH_SET={hash_psw(psw_set)}"] if psw_set else [])
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
                            "NET_ADMIN",
                            "SYS_NICE"
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
                        "build" if g.build else "image": "." if g.build else f"ghcr.io/pwnzer0tt1/firegex:{args.version}",
                        "ports": [
                            f"{'' if args.host == 'any' else args.host+':'}{args.port}:{args.port}"
                        ],
                        "environment": [
                            f"PORT={args.port}",
                            f"NTHREADS={args.threads}",
                            *([f"PSW_HASH_SET={hash_psw(psw_set)}"] if psw_set else [])
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
    if volume_exists() or args.psw_on_web or (g.standalone_mode and os.path.isfile(os.path.join(g.rootfs_path, "execute/db/firegex.db"))):
        return None
    if args.startup_psw:
        return args.startup_psw
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
    return "firegex_firegex_data" in cmd_check('docker volume ls --filter "name=^firegex_firegex_data$"', get_output=True)

def nfqueue_exists():
    import socket
    import fcntl
    import os
    import time

    NETLINK_NETFILTER = 12
    SOL_NETLINK = 270
    NETLINK_EXT_ACK = 11
    try:
        nfsock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        fcntl.fcntl(nfsock, fcntl.F_SETFL, os.O_RDONLY|os.O_NONBLOCK)
        nfsock.setsockopt(SOL_NETLINK, NETLINK_EXT_ACK, 1)
    except Exception:
        return False
    
    for rev in [3,2,1,0]:
        timestamp = int(time.time()).to_bytes(4, byteorder='big')
        rev = rev.to_bytes(4, byteorder='big')
        #Prepared payload to check if the nfqueue module is loaded (from iptables code "nft_compatible_revision")
        payload = b"\x30\x00\x00\x00\x00\x0b\x05\x00"+timestamp+b"\x00\x00\x00\x00\x02\x00\x00\x00\x0c\x00\x01\x00\x4e\x46\x51\x55\x45\x55\x45\x00\x08\x00\x02\x00"+rev+b"\x08\x00\x03\x00\x00\x00\x00\x01"
        nfsock.send(payload)
        data = nfsock.recv(1024)
        is_error = data[4] == 2
        if not is_error:
            return True # The module exists and we have permission to use it
        error_code = int.from_bytes(data[16:16+4], signed=True, byteorder='little')
        if error_code == -1:
            return True # EPERM (the user is not root, but the module exists)
        if error_code == -2:
            pass # ENOENT (the module does not exist)
        else:
            puts("Error while trying to check if the nfqueue module is loaded, this check will be skipped!", color=colors.yellow)
            return True
    return False


def delete_volume():
    return cmd_check("docker volume rm firegex_firegex_data")

def write_pid_file(pid):
    """Write PID to file"""
    try:
        with open(g.pid_file, 'w') as f:
            f.write(str(pid))
        return True
    except Exception as e:
        puts(f"Failed to write PID file: {e}", color=colors.red)
        return False

def read_pid_file():
    """Read PID from file"""
    try:
        if os.path.exists(g.pid_file):
            with open(g.pid_file, 'r') as f:
                return int(f.read().strip())
        return None
    except Exception:
        return None

def remove_pid_file():
    """Remove PID file"""
    try:
        if os.path.exists(g.pid_file):
            os.remove(g.pid_file)
    except Exception:
        pass

def is_process_running(pid):
    """Check if process with given PID is running"""
    if pid is None:
        return False
    try:
        # Send signal 0 to check if process exists
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False

def is_standalone_running():
    """Check if standalone Firegex is already running"""
    pid = read_pid_file()
    if pid and is_process_running(pid):
        return True
    else:
        # Clean up stale PID file
        remove_pid_file()
        return False

def stop_standalone_process():
    """Stop the standalone Firegex process"""
    pid = read_pid_file()
    if pid and is_process_running(pid):
        try:
            puts(f"Stopping Firegex process (PID: {pid})...", color=colors.yellow)
            os.kill(pid, 15)  # SIGTERM
            
            # Wait a bit for graceful shutdown
            import time
            for _ in range(10):
                if not is_process_running(pid):
                    break
                time.sleep(0.5)
            
            # Force kill if still running
            if is_process_running(pid):
                puts("Process didn't stop gracefully, forcing termination...", color=colors.yellow)
                os.kill(pid, 9)  # SIGKILL
                time.sleep(1)
            
            if not is_process_running(pid):
                puts("Firegex process stopped", color=colors.green)
                return True
            else:
                puts("Failed to stop Firegex process", color=colors.red)
                return False
                
        except Exception as e:
            puts(f"Error stopping process: {e}", color=colors.red)
            return False
    else:
        puts("No running Firegex process found", color=colors.yellow)
        return True

def is_docker_rootless():
    """Check if Docker is running in rootless mode"""
    try:
        output = cmd_check('docker info -f "{{println .SecurityOptions}}"', get_output=True)
        return "rootless" in output.lower()
    except Exception:
        return False

def should_use_standalone():
    """Determine if standalone mode should be used"""
    # Check if standalone mode is forced
    if args.standalone:
        return True
    
    if is_standalone_running():
        return True
    
    # Check if Docker exists
    if not cmd_check("docker --version"):
        return True
    
    # Check if Docker Compose exists
    if not cmd_check("docker-compose --version") and not cmd_check("docker compose --version"):
        return True
    
    # Check if Docker is accessible
    if not cmd_check("docker ps"):
        return True
    
    # Check if Docker is in rootless mode
    if is_docker_rootless():
        return True
    
    return False

def is_root():
    """Check if running as root"""
    return os.geteuid() == 0

def get_sudo_prefix():
    """Get sudo prefix if needed, empty string if already root"""
    return "" if is_root() else "sudo "

def run_privileged_commands(commands, description="operations"):
    """Run a batch of privileged commands efficiently"""
    if not commands:
        return True
    
    if is_root():
        # If already root, run commands directly
        for cmd in commands:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                puts(f"Command failed: {cmd}", color=colors.red)
                puts(f"Error: {result.stderr}", color=colors.red)
                return False
        return True
    else:
        # If not root, create a script and run it with sudo once
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as script_file:
            script_file.write("#!/bin/sh\nset -e\n")
            for cmd in commands:
                script_file.write(f"{cmd}\n")
            script_path = script_file.name
        
        try:
            os.chmod(script_path, 0o755)
            result = subprocess.run(f"sudo sh {script_path}", shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                puts(f"Failed to execute {description}", color=colors.red)
                puts(f"Error: {result.stderr}", color=colors.red)
                return False
            return True
        finally:
            os.unlink(script_path)

def safe_run_command(cmd, check_result=True, use_sudo=False):
    """Run a command safely with proper error handling"""
    if use_sudo:
        cmd = f"{get_sudo_prefix()}{cmd}"
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if check_result and result.returncode != 0:
            puts(f"Command failed: {cmd}", color=colors.red)
            puts(f"Error: {result.stderr}", color=colors.red)
            return False
        return result.returncode == 0
    except Exception as e:
        puts(f"Error running command: {cmd}", color=colors.red)
        puts(f"Exception: {e}", color=colors.red)
        return False

def cleanup_standalone_mounts():
    """Cleanup any existing mounts for standalone mode"""
    mount_points = [
        f"{g.rootfs_path}/dev",
        f"{g.rootfs_path}/proc",
        f"{g.rootfs_path}/sys_host/net.ipv4.conf.all.route_localnet",
        f"{g.rootfs_path}/sys_host/net.ipv4.ip_forward", 
        f"{g.rootfs_path}/sys_host/net.ipv4.conf.all.forwarding",
        f"{g.rootfs_path}/sys_host/net.ipv6.conf.all.forwarding"
    ]
    
    # Create umount commands (with || true to ignore errors)
    umount_commands = [f"umount -l {mount_point} || true" for mount_point in mount_points]
    
    # Run all umount commands in one batch
    run_privileged_commands(umount_commands, "cleanup mounts")

def get_latest_release_tag():
    """Get the latest release tag from GitHub API"""
    import urllib.request
    import json
    
    try:
        url = "https://api.github.com/repos/Pwnzer0tt1/firegex/releases/latest"
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
            return data.get('tag_name')
    except Exception as e:
        puts(f"Failed to get latest release tag: {e}", color=colors.red)
        return None

def get_architecture():
    """Get current architecture (amd64 or arm64)"""
    import platform
    arch = platform.machine().lower()
    if arch in ['x86_64', 'amd64']:
        return 'amd64'
    elif arch in ['aarch64', 'arm64']:
        return 'arm64'
    else:
        puts(f"Unsupported architecture: {arch}", color=colors.red)
        return None

def download_file(url, filename):
    """Download a file using urllib with progress bar"""
    import urllib.request
    import sys
    
    def progress_hook(block_num, block_size, total_size):
        if total_size > 0:
            percent = min(100, (block_num * block_size * 100) // total_size)
            sys.stdout.write(f"\rDownloading... {percent}%")
            sys.stdout.flush()
        else:
            sys.stdout.write(f"\rDownloading... {block_num * block_size} bytes")
            sys.stdout.flush()
    
    try:
        puts(f"Downloading {filename}...", color=colors.green)
        urllib.request.urlretrieve(url, filename, reporthook=progress_hook)
        print()  # New line after progress
        return True
    except Exception as e:
        print()  # New line after progress
        puts(f"Failed to download {filename}: {e}", color=colors.red)
        return False

def setup_standalone_rootfs():
    """Set up the standalone rootfs"""
    puts("Setting up standalone mode...", color=colors.green)
    
    # Remove and recreate rootfs directory
    if os.path.exists(g.rootfs_path):
        puts("Rootfs already exists, skipping download...", color=colors.yellow)
        # Clean up any existing mounts
        cleanup_standalone_mounts()
        return True
    
    puts("Creating rootfs directory...", color=colors.green)
    try:
        os.makedirs(g.rootfs_path, exist_ok=True)
    except Exception as e:
        puts(f"Failed to create rootfs directory: {e}", color=colors.red)
        return False
    
    # Get latest release tag
    release_tag = get_latest_release_tag()
    if not release_tag:
        puts("Failed to get latest release tag", color=colors.red)
        return False
    
    # Get current architecture
    arch = get_architecture()
    if not arch:
        return False
    
    # Download rootfs from GitHub releases
    puts(f"Downloading rootfs for {arch} architecture from GitHub releases...", color=colors.green)
    
    # Construct download URL
    rootfs_filename = f"firegex-rootfs-{arch}.tar.gz"
    download_url = f"https://github.com/Pwnzer0tt1/firegex/releases/download/{release_tag}/{rootfs_filename}"
    tar_path = os.path.join(g.rootfs_path, rootfs_filename)
    
    # Download the rootfs archive
    if not download_file(download_url, tar_path):
        return False
    
    try:
        # Extract tar.gz file
        puts("Extracting rootfs...", color=colors.green)
        with tarfile.open(tar_path, 'r:gz') as tar:
            # Extract all files with tar filter (allows safe symbolic links)
            tar.extractall(path=g.rootfs_path, filter='tar')
        
        # Remove tar.gz file
        os.remove(tar_path)
        
        # Create necessary directories
        os.makedirs(os.path.join(g.rootfs_path, "dev"), exist_ok=True)
        os.makedirs(os.path.join(g.rootfs_path, "proc"), exist_ok=True)
        os.makedirs(os.path.join(g.rootfs_path, "sys_host"), exist_ok=True)
        
        puts("Rootfs setup completed", color=colors.green)
        return True
        
    except Exception as e:
        puts(f"Failed to extract rootfs: {e}", color=colors.red)
        # Clean up partial extraction
        if os.path.exists(tar_path):
            os.remove(tar_path)
        return False

def setup_standalone_mounts():
    """Set up bind mounts for standalone mode"""
    puts("Setting up bind mounts...", color=colors.green)
    
    # Create mount point files
    mount_files = [
        "net.ipv4.conf.all.route_localnet",
        "net.ipv4.ip_forward", 
        "net.ipv4.conf.all.forwarding",
        "net.ipv6.conf.all.forwarding"
    ]
    
    sys_host_dir = os.path.join(g.rootfs_path, "sys_host")
    
    # Prepare all privileged commands
    privileged_commands = []
    
    # Touch commands for mount point files
    for mount_file in mount_files:
        file_path = os.path.join(sys_host_dir, mount_file)
        privileged_commands.append(f"touch {file_path}")
    
    # Mount commands
    privileged_commands.extend([
        f"mount --bind /dev {g.rootfs_path}/dev",
        f"mount --bind /proc {g.rootfs_path}/proc",
        f"mount --bind /proc/sys/net/ipv4/conf/all/route_localnet {g.rootfs_path}/sys_host/net.ipv4.conf.all.route_localnet",
        f"mount --bind /proc/sys/net/ipv4/ip_forward {g.rootfs_path}/sys_host/net.ipv4.ip_forward",
        f"mount --bind /proc/sys/net/ipv4/conf/all/forwarding {g.rootfs_path}/sys_host/net.ipv4.conf.all.forwarding", 
        f"mount --bind /proc/sys/net/ipv6/conf/all/forwarding {g.rootfs_path}/sys_host/net.ipv6.conf.all.forwarding"
    ])
    
    # Run all privileged commands in one batch
    if not run_privileged_commands(privileged_commands, "setup bind mounts"):
        puts("Failed to set up bind mounts", color=colors.red)
        return False
    
    return True

def run_standalone():
    """Run Firegex in standalone mode as a daemon"""
    puts("Starting Firegex in standalone mode...", color=colors.green)
    
    # Check if already running
    if is_standalone_running():
        puts("Firegex is already running in standalone mode!", color=colors.yellow)
        pid = read_pid_file()
        puts(f"Process PID: {pid}", color=colors.cyan)
        return
    
    # Set up environment variables
    env_vars = [
        f"PORT={args.port}",
        f"HOST={args.host}",
        f"NTHREADS={args.threads}",
    ]
    
    # Add password if set
    psw_set = get_password()
    if psw_set:
        env_vars.append(f"PSW_HASH_SET={hash_psw(psw_set)}")
    
    # Prepare environment string for chroot
    env_string = " ".join([f"{var}" for var in env_vars])
    
    # Run chroot command in background
    chroot_cmd = f"{get_sudo_prefix()}env {env_string} chroot --userspec=root:root {g.rootfs_path} /bin/python3 /execute/app.py DOCKER"
    
    puts(f"Running: {chroot_cmd}", color=colors.cyan)
    puts("Starting as daemon...", color=colors.green)
    
    try:
        # Start process in background
        process = subprocess.Popen(
            chroot_cmd,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            preexec_fn=os.setsid  # Create new session
        )
        
        # Write PID to file
        if write_pid_file(process.pid):
            puts(f"Firegex started successfully (PID: {process.pid})", color=colors.green)
            
            if is_process_running(process.pid):
                puts(f"Web interface should be available at: {get_web_interface_url()}", color=colors.cyan)
            else:
                puts("Firegex process failed to start", color=colors.red)
                remove_pid_file()
                cleanup_standalone_mounts()
        else:
            puts("Failed to save PID file", color=colors.red)
            process.terminate()
            cleanup_standalone_mounts()
            
    except Exception as e:
        puts(f"Failed to start Firegex: {e}", color=colors.red)
        cleanup_standalone_mounts()

def stop_standalone():
    """Stop standalone mode by stopping the process and cleaning up mounts"""
    puts("Stopping standalone mode...", color=colors.green)
    
    # Stop the process
    if stop_standalone_process():
        # Clean up mounts
        cleanup_standalone_mounts()
        # Remove PID file
        remove_pid_file()
        puts("Standalone mode stopped", color=colors.green)
    else:
        # Clean up anyway
        cleanup_standalone_mounts()
        remove_pid_file()
        puts("Cleanup completed", color=colors.yellow)

def clear_standalone():
    """Clear standalone rootfs"""
    puts("Clearing standalone rootfs...", color=colors.green)
    cleanup_standalone_mounts()
    if os.path.exists(g.rootfs_path):
        # If permission denied, use privileged command
        if run_privileged_commands([f"chmod ugo+rw -R {g.rootfs_path}", f"rm -rf {g.rootfs_path}"], "remove rootfs"):
            puts("Standalone rootfs cleared", color=colors.green)
        else:
            puts("Failed to clear standalone rootfs", color=colors.red)
    else:
        puts("Standalone rootfs not found", color=colors.yellow)

def handle_config_command(args):
    """Handle config command"""
    config = load_config()
    config_changed = False
    
    if args.show:
        puts("Current configuration:", color=colors.cyan, is_bold=True)
        puts(f"Port: {config['port']}", color=colors.white)
        puts(f"Host: {config['host']}", color=colors.white)
        puts(f"Config file: {g.configfile}", color=colors.white)
        return
    
    if hasattr(args, 'port') and args.port is not None:
        if args.port < 1 or args.port > 65535:
            puts("Error: Port must be between 1 and 65535", color=colors.red)
            exit(1)
        config["port"] = args.port
        config_changed = True
        puts(f"Port set to: {args.port}", color=colors.green)
    
    if hasattr(args, 'host') and args.host is not None:
        config["host"] = args.host
        config_changed = True
        puts(f"Host set to: {args.host}", color=colors.green)
    
    if config_changed:
        if save_config(config):
            puts(f"Configuration saved to {g.configfile}", color=colors.green)
        else:
            puts("Failed to save configuration", color=colors.red)
            exit(1)
    else:
        puts("No configuration changes specified. Use --show to view current configuration.", color=colors.yellow)

def status_standalone():
    """Show standalone mode status"""
    puts("Standalone mode status:", color=colors.cyan, is_bold=True)
    
    # Check if running
    if is_standalone_running():
        pid = read_pid_file()
        puts(f"Status: Running (PID: {pid})", color=colors.green)
        puts(f"Web interface: {get_web_interface_url()}", color=colors.cyan)
    else:
        puts("Status: Not running", color=colors.red)
        if os.path.exists(g.rootfs_path):
            puts(f"Rootfs: Available ({g.rootfs_path})", color=colors.white)
        else:
            puts("Rootfs: Not available", color=colors.yellow)

def main():
    
    # Check if we should use standalone mode
    if should_use_standalone():
        if not is_linux():
            puts("Standalone mode only works on Linux!", color=colors.red)
            puts("Please install Docker and Docker Compose.", color=colors.red)
            exit(1)
        
        g.standalone_mode = True
        if args.standalone:
            puts("Standalone mode forced by --standalone option", color=colors.cyan)
        elif is_standalone_running():
            puts("Standalone mode already running, using it", color=colors.cyan)
        else:
            puts("Docker not available or in rootless mode, using standalone mode", color=colors.yellow)
        
        # Ensure we have root privileges for standalone mode operations
        if not is_root():
            puts("Standalone mode requires root privileges. 'sudo' will be used.", color=colors.yellow)
        
        if args.command == "start" or args.command is None:
            # Check if already running
            if is_standalone_running():
                pid = read_pid_file()
                puts(f"Firegex is already running in standalone mode! (PID: {pid})", color=colors.yellow)
                puts(f"Web interface available at: {get_web_interface_url()}", color=colors.cyan)
                return
            
            if not setup_standalone_rootfs():
                exit(1)
            if not setup_standalone_mounts():
                exit(1)
            run_standalone()
        elif args.command == "stop":
            stop_standalone()
        elif args.command == "status":
            status_standalone()
        elif args.command == "restart":
            stop_standalone()
            if not setup_standalone_mounts():
                exit(1)
            run_standalone()
        elif args.command == "config":
            handle_config_command(args)
        else:
            puts("Command not supported in standalone mode", color=colors.red)
            exit(1)
            
        # Handle clear option for standalone mode
        if args.clear:
            clear_standalone()
            
        return
    
    # Original Docker-based logic
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
                    puts("Firegex", color=colors.yellow, end="")
                    puts(" will start on port ", end="")
                    puts(f"{args.port}", color=colors.cyan)
                    write_compose(skip_password=False)
                    if not g.build:
                        puts("Downloading docker image from github packages 'docker pull ghcr.io/pwnzer0tt1/firegex'", color=colors.green)
                        cmd_check(f"docker pull ghcr.io/pwnzer0tt1/firegex:{args.version}", print_output=True)
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
            case "status":
                if check_already_running():
                    puts("Firegex is running in Docker mode", color=colors.green)
                    puts(f"Web interface: {get_web_interface_url()}", color=colors.cyan)
                else:
                    puts("Firegex is not running", color=colors.red)
            case "config":
                handle_config_command(args)
    
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
        main()
    except KeyboardInterrupt:
        print()
