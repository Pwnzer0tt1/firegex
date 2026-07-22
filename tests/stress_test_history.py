#!/usr/bin/env python3
"""
Firegex HttpHistory Real-Time Stress Test.
Connects to Firegex API, deploys an nfproxy HTTP service with HttpHistory filter enabled,
starts an HTTP 200 OK backend server and continuous HTTP client requests.
Measures real-time memory usage (Firegex cpproxy / local process) and request throughput until stopped (Ctrl+C).
"""

import sys
import os
import time
import signal
import socket
import threading
import argparse
import traceback
from typing import Optional, List

# Add project paths
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../fgex-lib")))

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from tests.utils.colors import colors, puts, sep
from tests.utils.firegexapi import FiregexAPI

HTTP_STRESS_FILTER_CODE = """
from firegex.nfproxy.models import HttpFullRequest, HttpFullResponse, HttpHistory
from firegex.nfproxy import pyfilter, ACCEPT

req_count = 0
resp_count = 0

@pyfilter
def history_stress_req(req: HttpFullRequest, history: HttpHistory):
    global req_count
    req_count += 1
    _ = len(history.requests)
    _ = len(history.responses)
    return ACCEPT

@pyfilter
def history_stress_resp(resp: HttpFullResponse, history: HttpHistory):
    global resp_count
    resp_count += 1
    _ = len(history.requests)
    _ = len(history.responses)
    return ACCEPT
"""


def start_http_backend_server(port: int, ipv6: bool = False):
    """Starts a multithreaded HTTP backend server that returns valid HTTP 200 OK responses."""
    server_sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("::1" if ipv6 else "127.0.0.1", port))
    server_sock.listen(128)
    server_sock.settimeout(0.5)

    running = True

    def handle_client(conn):
        conn.settimeout(2.0)
        resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nConnection: keep-alive\r\n\r\nHello World!"
        try:
            while running:
                buf = conn.recv(4096)
                if not buf:
                    break
                conn.sendall(resp)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def server_loop():
        while running:
            try:
                conn, _ = server_sock.accept()
                t = threading.Thread(target=handle_client, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                break
        try:
            server_sock.close()
        except Exception:
            pass

    t = threading.Thread(target=server_loop, daemon=True)
    t.start()

    def stop_server():
        nonlocal running
        running = False
        try:
            server_sock.close()
        except Exception:
            pass

    return stop_server


def find_cpproxy_process():
    """Finds cpproxy process using psutil if running."""
    if not HAS_PSUTIL:
        return None
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            name = proc.info['name'] or ''
            cmdline = ' '.join(proc.info['cmdline'] or [])
            if 'cpproxy' in name or 'cpproxy' in cmdline:
                return proc
    except Exception:
        pass
    return None


def get_memory_mb(proc=None) -> float:
    """Returns memory usage in MB for a given process or current process."""
    try:
        if proc:
            return proc.memory_info().rss / (1024 * 1024)
        if HAS_PSUTIL:
            return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
    except Exception:
        pass
    return 0.0


def create_client_socket(port: int, ipv6: bool = False) -> socket.socket:
    s = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect(("::1" if ipv6 else "127.0.0.1", port))
    return s


def main():
    parser = argparse.ArgumentParser(description="Firegex HttpHistory Stress Test")
    parser.add_argument("--address", "-a", type=str, default="http://127.0.0.1:4444/", help="Firegex API address (default: http://127.0.0.1:4444/)")
    parser.add_argument("--password", "-p", type=str, required=True, help="Firegex admin password")
    parser.add_argument("--service-name", "-n", type=str, default="StressTestHistory", help="Service name (default: StressTestHistory)")
    parser.add_argument("--port", "-P", type=int, default=1337, help="Service port (default: 1337)")
    parser.add_argument("--ipv6", "-6", action="store_true", default=False, help="Use IPv6")
    parser.add_argument("--connections", "-c", type=int, default=4, help="Number of concurrent client connections (default: 4)")
    args = parser.parse_args()

    sep()
    puts("🔥 Firegex HttpHistory Real-Time Stress Test 🔥", color=colors.cyan, is_bold=True)
    puts(f"Firegex API:     {args.address}", color=colors.yellow)
    puts(f"Target Port:     {args.port}", color=colors.yellow)
    puts(f"Connections:     {args.connections}", color=colors.yellow)
    puts("Press Ctrl+C at any time to stop the stress test.", color=colors.magenta, is_bold=True)
    sep()

    firegex = FiregexAPI(args.address)

    # 1. Login to Firegex
    puts("Logging in to Firegex API...", color=colors.cyan)
    if firegex.login(args.password):
        puts("Successfully logged in ✔", color=colors.green)
    else:
        puts("Error: Login failed! Check password or address ✗", color=colors.red)
        sys.exit(1)

    # 2. Cleanup existing service if any
    for srv in firegex.nfproxy_get_services():
        if srv.get("name") == args.service_name or srv.get("port") == args.port:
            puts(f"Cleaning up existing service ID {srv['service_id']}...", color=colors.yellow)
            firegex.nfproxy_delete_service(srv["service_id"])

    # 3. Create service in Firegex
    ip_int = "::1" if args.ipv6 else "127.0.0.1"
    service_id = firegex.nfproxy_add_service(args.service_name, args.port, "http", ip_int, fail_open=True)
    if not service_id:
        puts("Error: Failed to create nfproxy service in Firegex ✗", color=colors.red)
        sys.exit(1)
    puts(f"Created nfproxy service ID: {service_id} ✔", color=colors.green)

    def cleanup_and_exit(code=0):
        puts("\nCleaning up Firegex service...", color=colors.yellow)
        try:
            firegex.nfproxy_stop_service(service_id)
            firegex.nfproxy_delete_service(service_id)
            puts("Successfully cleaned up Firegex service ✔", color=colors.green)
        except Exception as e:
            puts(f"Error during cleanup: {e}", color=colors.red)
        sys.exit(code)

    # 4. Upload HttpHistory filter code
    puts("Deploying HttpHistory pyfilter code to Firegex...", color=colors.cyan)
    if not firegex.nfproxy_set_code(service_id, HTTP_STRESS_FILTER_CODE):
        puts("Error: Failed to upload pyfilter code ✗", color=colors.red)
        cleanup_and_exit(1)
    puts("Successfully deployed HttpHistory filter ✔", color=colors.green)

    # 5. Start Firegex Service
    puts("Starting Firegex service...", color=colors.cyan)
    if not firegex.nfproxy_start_service(service_id):
        puts("Error: Failed to start Firegex service ✗", color=colors.red)
        cleanup_and_exit(1)
    puts("Firegex service started successfully ✔", color=colors.green)

    # 6. Start HTTP Backend Server
    stop_backend_server = start_http_backend_server(args.port, ipv6=args.ipv6)
    puts(f"HTTP Backend server listening on port {args.port} ✔", color=colors.green)
    time.sleep(0.5)

    # Find cpproxy process if available
    cpproxy_proc = find_cpproxy_process()
    if cpproxy_proc:
        puts(f"Detected Firegex cpproxy process (PID {cpproxy_proc.pid}) ✔", color=colors.green)

    # 7. Connect client sockets
    running = True

    def sig_handler(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    client_socks: List[Optional[socket.socket]] = []
    for _ in range(args.connections):
        try:
            client_socks.append(create_client_socket(args.port, args.ipv6))
        except Exception:
            client_socks.append(None)

    puts(f"Initialized {len(client_socks)} client socket slot(s) ✔", color=colors.green)
    puts("\n🚀 Spamming HTTP requests continuously. Press Ctrl+C to stop...\n", color=colors.cyan, is_bold=True)

    req_index = 0
    total_requests = 0
    start_time = time.time()
    last_print_time = start_time
    last_req_count = 0
    peak_script_mem = get_memory_mb()
    peak_cpproxy_mem = get_memory_mb(cpproxy_proc) if cpproxy_proc else 0.0

    try:
        while running:
            for i in range(len(client_socks)):
                if not running:
                    break

                s = client_socks[i]
                if s is None:
                    try:
                        s = create_client_socket(args.port, args.ipv6)
                        client_socks[i] = s
                    except Exception:
                        continue

                req_index += 1
                req_bytes = f"GET /stress_req_{req_index} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nUser-Agent: FiregexStressClient\r\n\r\n".encode()

                try:
                    s.sendall(req_bytes)
                    resp = s.recv(4096)
                    if resp and b"200 OK" in resp:
                        total_requests += 1
                    else:
                        raise ConnectionResetError("Invalid or empty HTTP response")
                except Exception:
                    # Safely close broken socket and mark slot for reconnection
                    try:
                        s.close()
                    except Exception:
                        pass
                    client_socks[i] = None

            curr_time = time.time()
            elapsed_print = curr_time - last_print_time

            if elapsed_print >= 1.0 or not running:
                script_mem = get_memory_mb()
                cpproxy_mem = get_memory_mb(cpproxy_proc) if cpproxy_proc else 0.0

                if script_mem > peak_script_mem:
                    peak_script_mem = script_mem
                if cpproxy_mem > peak_cpproxy_mem:
                    peak_cpproxy_mem = cpproxy_mem

                batch_reqs = total_requests - last_req_count
                reqs_per_sec = batch_reqs / elapsed_print if elapsed_print > 0 else 0
                total_elapsed = curr_time - start_time

                mem_str = f"Script RSS: {script_mem:.1f}MB"
                if cpproxy_proc:
                    mem_str += f" | cpproxy RSS: {cpproxy_mem:.1f}MB (Peak: {peak_cpproxy_mem:.1f}MB)"

                sys.stdout.write(
                    f"\r\033[K[{time.strftime('%H:%M:%S')}] Elapsed: {total_elapsed:.1f}s | "
                    f"Reqs: {total_requests:,} | "
                    f"Speed: {reqs_per_sec:,.0f} req/s | "
                    f"{mem_str}"
                )
                sys.stdout.flush()

                last_print_time = curr_time
                last_req_count = total_requests

    except KeyboardInterrupt:
        pass

    end_time = time.time()
    duration = end_time - start_time

    # Close client sockets
    for s in client_socks:
        if s:
            try:
                s.close()
            except Exception:
                pass

    stop_backend_server()

    print()  # New line
    sep()
    puts("🛑 Stress Test Interrupted by User", color=colors.yellow, is_bold=True)
    puts(f"Total Time Elapsed:  {duration:.2f} seconds")
    puts(f"Total HTTP Reqs:     {total_requests:,}")
    puts(f"Average Throughput:  {total_requests / max(duration, 0.001):,.0f} req/sec")
    if cpproxy_proc:
        puts(f"cpproxy Peak Memory: {peak_cpproxy_mem:.2f} MB", color=colors.cyan, is_bold=True)
    sep()

    cleanup_and_exit(0)


if __name__ == "__main__":
    main()
