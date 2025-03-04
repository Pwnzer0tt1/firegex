import socket
import os
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from firegex.nfproxy.internals import get_filter_names
import traceback
from multiprocessing import Process
from firegex.nfproxy import ACCEPT, DROP, REJECT, UNSTABLE_MANGLE
from rich.markup import escape
from rich import print

fake_ip_header = b"FAKE:IP:TCP:HEADERS:"
fake_ip_header_len = len(fake_ip_header)

class LogLevels:
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    DEBUG = "DEBUG"

def load_level_str(level:str):
    if level is None:
        return ""
    match level:
        case LogLevels.INFO:
            return "[chartreuse4 bold]\\[INFO][/]"
        case LogLevels.WARNING:
            return "[yellow bold]\\[WARNING][/]"
        case LogLevels.ERROR:
            return "[red bold]\\[ERROR][/]"
        case LogLevels.DEBUG:
            return "[blue bold]\\[DEBUG][/]"
        case _:
            return f"\\[[red bold]{escape(level)}[/]]"

def log_print(module:str, *args, level:str = LogLevels.INFO, **kwargs):
    return print(f"{load_level_str(level)}[deep_pink4 bold]\\[nfproxy][/][medium_orchid3 bold]\\[{escape(module)}][/]", *args, **kwargs)

class ProxyFilterHandler(FileSystemEventHandler):
    
    def __init__(self, reload_action):
        super().__init__()
        self.__reload_action = reload_action
    
    def on_modified(self, event):
        if self.__reload_action is not None:
            self.__reload_action()
        return super().on_modified(event)
    
    def on_deleted(self, event):
        if self.__reload_action is not None:
            self.__reload_action()
        return super().on_deleted(event)


def _forward_and_filter(filter_ctx:dict, source:socket.socket, destination:socket.socket, is_input:bool, is_ipv6:bool, is_tcp:bool, has_to_filter:bool = True):
    """Forward data from source to destination."""
    try:
        def forward(data:bytes):
            try:
                destination.sendall(data)
            except OSError:
                return
        def stop_filter_action(data:bytes):
            nonlocal has_to_filter
            has_to_filter = False
            forward(data)
        while True:
            try:
                data = source.recv(4096)
            except OSError:
                return
            if not data:
                break
            if has_to_filter:
                filter_ctx["__firegex_packet_info"] = {
                    "data": data,
                    "l4_size": len(data),
                    "raw_packet": fake_ip_header+data,
                    "is_input": is_input,
                    "is_ipv6": is_ipv6,
                    "is_tcp": is_tcp
                }
                try:
                    exec("firegex.nfproxy.internals.handle_packet(globals())", filter_ctx, filter_ctx)
                except Exception as e:
                    log_print("packet-handling", f"Error while executing filter: {escape(str(e))}, forwarding normally from now", level=LogLevels.ERROR)
                    traceback.print_exc()
                    stop_filter_action(data)
                    continue
                finally:
                    if "__firegex_packet_info" in filter_ctx.keys():
                        del filter_ctx["__firegex_packet_info"]
                
                result = filter_ctx.get("__firegex_pyfilter_result", None)
                
                if result is not None:
                    del filter_ctx["__firegex_pyfilter_result"]
                
                if result is None or not isinstance(result, dict):
                    log_print("filter-parsing", "No result found", level=LogLevels.ERROR)
                    stop_filter_action(data)
                    continue
                action = result.get("action", None)
                
                if action is None or not isinstance(action, int):
                    log_print("filter-parsing", "No action found", level=LogLevels.ERROR)
                    stop_filter_action(data)
                    continue
                
                if action == ACCEPT.value:
                    forward(data)
                    continue
                
                filter_name = result.get("matched_by", None)
                if filter_name is None or not isinstance(filter_name, str):
                    log_print("filter-parsing", "No matched_by found", level=LogLevels.ERROR)
                    stop_filter_action(data)
                    continue
                
                if action == DROP.value:
                    log_print("drop-action", "Dropping packet can't be simulated, so the connection will be rejected", level=LogLevels.WARNING)
                    action = REJECT.value
                
                if action == REJECT.value:
                    log_print("reject-action", f"Rejecting connection caused by {escape(filter_name)} pyfilter")
                    source.close()
                    destination.close()
                    return
                elif action == UNSTABLE_MANGLE.value:
                    mangled_packet = result.get("mangled_packet", None)
                    if mangled_packet is None or not isinstance(mangled_packet, bytes):
                        log_print("filter-parsing", "No mangled_packet found", level=LogLevels.ERROR)
                        stop_filter_action(data)
                        continue
                    log_print("mangle", f"Mangling packet caused by {escape(filter_name)} pyfilter")
                    log_print("mangle", "In the real execution mangling is not so stable as the simulation does, l4_data can be different by data", level=LogLevels.WARNING)
                    forward(mangled_packet[fake_ip_header_len:])
                    continue
                else:
                    log_print("filter-parsing", f"Invalid action {action} found", level=LogLevels.ERROR)
                    stop_filter_action(data)
                    continue
            forward(data)
    finally:
        source.close()
        destination.close()

def _execute_proxy(filter_code:str, target_ip:str, target_port:int, local_ip:str = "127.0.0.1", local_port:int = 7474, ipv6:bool = False):

    addr_family = socket.AF_INET6 if ipv6 else socket.AF_INET
    server = socket.socket(addr_family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((local_ip, local_port))
    server.listen(5)
    
    log_print("listener", f"TCP proxy listening on {escape(local_ip)}:{local_port} and forwarding to -> {escape(target_ip)}:{target_port}")
    try:
        while True:
            client_socket, addr = server.accept()
            log_print("listener", f"Accepted connection from {escape(addr[0])}:{addr[1]}")
            try:
                remote_socket = socket.socket(addr_family, socket.SOCK_STREAM)
                remote_socket.connect((target_ip, target_port))
            except Exception as e:
                log_print("listener", f"Could not connect to remote {escape(target_ip)}:{target_port}: {escape(str(e))}", level=LogLevels.ERROR)
                client_socket.close()
                continue
            try:
                filter_ctx = {}
                exec(filter_code, filter_ctx, filter_ctx)
                # Start two threads to forward data in both directions.
                threading.Thread(target=_forward_and_filter, args=(filter_ctx, client_socket, remote_socket, True, ipv6, True, True)).start()
                threading.Thread(target=_forward_and_filter, args=(filter_ctx, remote_socket, client_socket, False, ipv6, True, True)).start()
            except Exception as e:
                log_print("listener", f"Error while compiling filter context: {escape(str(e))}, forwarding normally", level=LogLevels.ERROR)
                traceback.print_exc()
                threading.Thread(target=_forward_and_filter, args=(filter_ctx, client_socket, remote_socket, True, ipv6, True, False)).start()
                threading.Thread(target=_forward_and_filter, args=(filter_ctx, remote_socket, client_socket, False, ipv6, True, False)).start()
    except KeyboardInterrupt:
        log_print("listener", "Proxy stopped by user")
    finally:
        server.close()

def _build_filter(filepath:str, proto:str):
    if os.path.isfile(filepath) is False:
        raise Exception(f"Filter file {filepath} not found")
    
    with open(filepath, "r") as f:
        filter_code = f.read()  
    
    filters = get_filter_names(filter_code, proto)
    filter_code += (
        "\n\n__firegex_pyfilter_enabled = [" + ", ".join([repr(f) for f in filters]) + "]\n"
        "__firegex_proto = " + repr(proto) + "\n"
        "import firegex.nfproxy.internals\n" 
        "firegex.nfproxy.internals.compile(globals())\n"
    )
    
    filter_glob = {}
    exec(filter_code, filter_glob, filter_glob) # test compilation of filters
    return filter_code
    

def run_proxy_simulation(filter_file:str, proto:str, target_ip:str, target_port:int, local_ip:str = None, local_port:int = 7474, ipv6:bool = False):
    
    if local_ip is None:
        if ipv6:
            local_ip = "::1"
        else:
            local_ip = "127.0.0.1"
    
    if os.path.isfile(filter_file) is False:
        raise Exception(f"\\[nfproxy]\\[init] Filter file {filter_file} not found")
    
    proxy_process:Process|None = None
    
    def reload_proxy_proc():
        nonlocal proxy_process
        if proxy_process is not None:
            proxy_process.terminate()
            proxy_process.join()
            proxy_process = None
        
        compiled_filter = None
        try:
            compiled_filter = _build_filter(filter_file, proto)
        except Exception:
            log_print("reloader", f"Failed to build filter {escape(filter_file)}!", level=LogLevels.ERROR)
            traceback.print_exc()
        if compiled_filter is not None:
            proxy_process = Process(target=_execute_proxy, args=(compiled_filter, target_ip, target_port, local_ip, local_port, ipv6))
            proxy_process.start()
        
    
    observer = Observer()
    handler = ProxyFilterHandler(reload_proxy_proc)
    observer.schedule(handler, os.path.abspath(filter_file), recursive=False)
    observer.start()
    reload_proxy_proc()
    log_print("observer", f"Listening for changes on {escape(os.path.abspath(filter_file))}")
    try:
        observer.join()
    except KeyboardInterrupt:
        observer.stop()


