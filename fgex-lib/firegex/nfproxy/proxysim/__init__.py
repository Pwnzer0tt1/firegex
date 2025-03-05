import socket
import os
from firegex.nfproxy.internals import get_filter_names
import traceback
from multiprocessing import Process
from firegex.nfproxy import ACCEPT, DROP, REJECT, UNSTABLE_MANGLE
from rich.markup import escape
from rich import print
import asyncio
from watchfiles import awatch, Change

fake_ip_header = b"FAKE:IP:TCP:HEADERS:"
fake_ip_header_len = len(fake_ip_header)

MANGLE_WARNING = True

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

async def _watch_filter_file(filter_file: str, reload_action):
    abs_path = os.path.abspath(filter_file)
    directory = os.path.dirname(abs_path)
    # Immediately call the reload action on startup.
    if reload_action is not None:
        reload_action()
    log_print("observer", f"Listening for changes on {escape(abs_path)}")
    try:
        # Monitor the directory; set recursive=False since we only care about the specific file.
        async for changes in awatch(directory, recursive=False):
            # Process events and filter for our file.
            for change in changes:
                event, path = change
                if os.path.abspath(path) == abs_path:
                    # Optionally, you can check the event type:
                    if event in {Change.modified, Change.deleted}:
                        if reload_action is not None:
                            reload_action()
    except asyncio.CancelledError:
        log_print("observer", "Watcher cancelled, stopping.")

async def _forward_and_filter(filter_ctx: dict,
                             reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter,
                             is_input: bool,
                             is_ipv6: bool,
                             is_tcp: bool,
                             has_to_filter: bool = True):
    """Asynchronously forward data from reader to writer applying filters."""
    try:
        has_to_drop = False
        while True:
            try:
                data = await reader.read(4096)
            except Exception:
                break
            if not data:
                break
            if has_to_drop:
                continue
            if has_to_filter:
                filter_ctx["__firegex_packet_info"] = {
                    "data": data,
                    "l4_size": len(data),
                    "raw_packet": fake_ip_header + data,
                    "is_input": is_input,
                    "is_ipv6": is_ipv6,
                    "is_tcp": is_tcp
                }
                try:
                    exec("firegex.nfproxy.internals.handle_packet(globals())", filter_ctx, filter_ctx)
                except Exception as e:
                    log_print("packet-handling",
                              f"Error while executing filter: {escape(str(e))}, forwarding normally from now",
                              level=LogLevels.ERROR)
                    traceback.print_exc()
                    # Stop filtering and forward the packet as is.
                    has_to_filter = False
                    writer.write(data)
                    await writer.drain()
                    continue
                finally:
                    filter_ctx.pop("__firegex_packet_info", None)

                result = filter_ctx.pop("__firegex_pyfilter_result", None)
                if result is None or not isinstance(result, dict):
                    log_print("filter-parsing", "No result found", level=LogLevels.ERROR)
                    has_to_filter = False
                    writer.write(data)
                    await writer.drain()
                    continue

                action = result.get("action")
                if action is None or not isinstance(action, int):
                    log_print("filter-parsing", "No action found", level=LogLevels.ERROR)
                    has_to_filter = False
                    writer.write(data)
                    await writer.drain()
                    continue

                if action == ACCEPT.value:
                    writer.write(data)
                    await writer.drain()
                    continue

                filter_name = result.get("matched_by")
                if filter_name is None or not isinstance(filter_name, str):
                    log_print("filter-parsing", "No matched_by found", level=LogLevels.ERROR)
                    has_to_filter = False
                    writer.write(data)
                    await writer.drain()
                    continue

                if action == DROP.value:
                    log_print("drop-action", "Dropping connection caused by {escape(filter_name)} pyfilter")
                    has_to_drop = True
                    continue

                if action == REJECT.value:
                    log_print("reject-action", f"Rejecting connection caused by {escape(filter_name)} pyfilter")
                    writer.close()
                    await writer.wait_closed()
                    return

                elif action == UNSTABLE_MANGLE.value:
                    mangled_packet = result.get("mangled_packet")
                    if mangled_packet is None or not isinstance(mangled_packet, bytes):
                        log_print("filter-parsing", "No mangled_packet found", level=LogLevels.ERROR)
                        has_to_filter = False
                        writer.write(data)
                        await writer.drain()
                        continue
                    log_print("mangle", f"Mangling packet caused by {escape(filter_name)} pyfilter")
                    if MANGLE_WARNING:
                        log_print("mangle",
                                "In the real execution mangling is not so stable as the simulation does, l4_data can be different by data",
                                level=LogLevels.WARNING)
                    writer.write(mangled_packet[fake_ip_header_len:])
                    await writer.drain()
                    continue
                else:
                    log_print("filter-parsing", f"Invalid action {action} found", level=LogLevels.ERROR)
                    has_to_filter = False
                    writer.write(data)
                    await writer.drain()
                    continue
            else:
                writer.write(data)
                await writer.drain()
    except Exception as exc:
        log_print("forward_and_filter", f"Exception occurred: {escape(str(exc))}", level=LogLevels.ERROR)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

async def _handle_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, filter_code: str,
    target_ip: str, target_port: int, ipv6: bool):
    """Handle a new incoming connection and create a remote connection."""
    addr = writer.get_extra_info('peername')
    log_print("listener", f"Accepted connection from {escape(addr[0])}:{addr[1]}")
    try:
        remote_reader, remote_writer = await asyncio.open_connection(
            target_ip, target_port,
            family=socket.AF_INET6 if ipv6 else socket.AF_INET)
    except Exception as e:
        log_print("listener",
                  f"Could not connect to remote {escape(target_ip)}:{target_port}: {escape(str(e))}",
                  level=LogLevels.ERROR)
        writer.close()
        await writer.wait_closed()
        return

    try:
        filter_ctx = {}
        exec(filter_code, filter_ctx, filter_ctx)
    except Exception as e:
        log_print("listener",
                  f"Error while compiling filter context: {escape(str(e))}, forwarding normally",
                  level=LogLevels.ERROR)
        traceback.print_exc()
        filter_ctx = {}
    # Create asynchronous tasks for bidirectional forwarding.
    task1 = asyncio.create_task(_forward_and_filter(filter_ctx, reader, remote_writer, True, ipv6, True, True))
    task2 = asyncio.create_task(_forward_and_filter(filter_ctx, remote_reader, writer, False, ipv6, True, True))
    try:
        await asyncio.gather(task1, task2)
    except (KeyboardInterrupt, asyncio.CancelledError):
        task1.cancel()
        task2.cancel()
        await asyncio.gather(task1, task2)
    finally:
        remote_writer.close()
        await remote_writer.wait_closed()

async def _execute_proxy(
    filter_code: str,
    target_ip: str, target_port: int,
    local_ip: str = "127.0.0.1", local_port: int = 7474,
    ipv6: bool = False
):
    """Start the asyncio-based TCP proxy server."""
    addr_family = socket.AF_INET6 if ipv6 else socket.AF_INET
    server = await asyncio.start_server(
        lambda r, w: _handle_connection(r, w, filter_code, target_ip, target_port, ipv6),
        local_ip, local_port, family=addr_family)
    log_print("listener", f"TCP proxy listening on {escape(local_ip)}:{local_port} and forwarding to -> {escape(target_ip)}:{target_port}")
    async with server:
        await server.serve_forever()


def _proxy_asyncio_runner(filter_code: str, target_ip: str, target_port: int, local_ip: str, local_port: int, ipv6: bool):
    try:
        return asyncio.run(_execute_proxy(filter_code, target_ip, target_port, local_ip, local_port, ipv6))
    except KeyboardInterrupt:
        log_print("listener", "Proxy server stopped", level=LogLevels.WARNING)

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
    else:
        filter_file = os.path.abspath(filter_file)
    
    proxy_process:Process|None = None
    
    def reload_proxy_proc():
        nonlocal proxy_process
        if proxy_process is not None:
            log_print("RELOADING", "Proxy reload triggered", level=LogLevels.WARNING)
            proxy_process.kill()
            proxy_process.join()
            proxy_process = None
        
        compiled_filter = None
        try:
            compiled_filter = _build_filter(filter_file, proto)
        except Exception:
            log_print("reloader", f"Failed to build filter {escape(filter_file)}!", level=LogLevels.ERROR)
            traceback.print_exc()
        if compiled_filter is not None:
            proxy_process = Process(target=_proxy_asyncio_runner, args=(compiled_filter, target_ip, target_port, local_ip, local_port, ipv6))
            proxy_process.start()
        
    try:
        asyncio.run(_watch_filter_file(filter_file, reload_proxy_proc))
    except KeyboardInterrupt:
        pass
    finally:
        if proxy_process is not None:
            proxy_process.kill()
            proxy_process.join()


