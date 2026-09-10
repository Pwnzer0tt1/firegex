#!/usr/bin/env python3
"""How many short connections a second each network layer can carry.

`benchmark.py` measures fifty long-lived streams moving bulk bytes. That is the shape a
proxy is best at and the shape a CTF service almost never sees — a service under attack
is answering thousands of short requests, and the cost a terminating proxy is supposed to
pay is exactly the one that benchmark never touches: opening a connection.

So this measures the other end. Open, one small request, one small response, close,
repeated with some concurrency, and the answer is connections per second. Every layer is
measured against the same unfiltered baseline on the same host in the same run, because
the number that means something is the *share* of the baseline each one keeps, not the
absolute rate of a loopback socket on somebody's laptop.

Like `benchmark.py`, the service is created with `fail_open=False`. With fail-open on,
a queue that fills is a queue the kernel walks past, and the measurement becomes one of
how fast Linux can not-inspect packets.

**The layers are interleaved, and the order alternates.** Measuring every pass of one
layer and then every pass of the other is how you get a result that is really about the
machine drifting: whichever went second gets the drift. Here a pass measures both, and
odd passes swap which goes first, so drift lands on both and shows up as spread instead
of as a winner. Read the spread before reading the difference — on this benchmark they
have overlapped every time it has been run.
"""

import argparse
import socket
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from utils.colors import colors, puts, sep
from utils.firegexapi import FiregexAPI

parser = argparse.ArgumentParser()
parser.add_argument("--address", "-a", type=str, required=False,
                    help="Address of firegex backend", default="http://127.0.0.1:4444/")
parser.add_argument("--password", "-p", type=str, required=True, help="Firegex password")
parser.add_argument("--port", "-P", type=int, required=False,
                    help="Port of the benchmark service", default=9971)
parser.add_argument("--service-name", "-n", type=str, required=False,
                    help="Name of the benchmark service", default="connbench")
parser.add_argument("--connections", "-c", type=int, required=False,
                    help="Connections per pass", default=1500)
parser.add_argument("--concurrency", "-s", type=int, required=False,
                    help="Connections in flight at once", default=32)
parser.add_argument("--passes", type=int, required=False,
                    help="Passes per layer; the median is reported", default=3)
args = parser.parse_args()

ADDR = "127.0.0.1"
REQUEST = b"GET /ping HTTP/1.1\r\nHost: bench\r\n\r\n"
REPLY = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"

sep()
puts("Connection rate, by network layer, on ", color=colors.cyan, end="")
puts(f"{args.address}", color=colors.yellow)

# The service under test: accept, read the request, answer, close. Several acceptor
# threads, or the server itself becomes what is being measured.
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((ADDR, args.port))
server.listen(512)


def serve():
    while True:
        try:
            conn, _ = server.accept()
            conn.recv(4096)
            conn.sendall(REPLY)
            conn.close()
        except OSError:
            return


for _ in range(8):
    threading.Thread(target=serve, daemon=True).start()


def one_connection(_=None) -> bool:
    sock = socket.create_connection((ADDR, args.port), timeout=5)
    try:
        sock.sendall(REQUEST)
        return len(sock.recv(128)) > 0
    except OSError:
        return False
    finally:
        sock.close()


def rate() -> float:
    """Connections per second, for one pass."""
    started = time.monotonic()
    done = 0
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        for ok in pool.map(one_connection, range(args.connections)):
            done += 1 if ok else 0
    return done / (time.monotonic() - started)


def measure() -> float:
    return statistics.median(rate() for _ in range(args.passes))


firegex = FiregexAPI(args.address)
if not firegex.login(args.password):
    puts("Benchmark Failed: unknown response or wrong password ✗", color=colors.red)
    exit(1)


def drop_existing():
    for service in firegex.services_list():
        if service["name"] == args.service_name:
            firegex.services_delete(service["service_id"])


def measure_layer(transport: str) -> float:
    """One pass against one layer, from a service created and destroyed for it."""
    drop_existing()
    service_id = firegex.services_add(args.service_name, ADDR, args.port, transport,
                                      fail_open=False)
    if not service_id:
        puts(f"Benchmark Failed: could not create the {transport} service ✗", color=colors.red)
        exit(1)
    try:
        firegex.services_add_filter(service_id, "regex", "patterns")
        filter_id = firegex.services_filters(service_id)[0]["filter_id"]
        # One pattern that matches nothing: the point is that a filter is in the path and
        # every byte reaches it, not what it decides.
        firegex.services_add_regex(service_id, filter_id, "THISMATCHESNOTHING")
        if not firegex.services_start(service_id):
            puts(f"Benchmark Failed: could not start the {transport} service ✗", color=colors.red)
            exit(1)
        time.sleep(2)
        return rate()
    finally:
        firegex.services_delete(service_id)
        time.sleep(1)


drop_existing()
samples = {"none": [], "proxy": [], "nfqueue": []}
for i in range(args.passes):
    order = ("proxy", "nfqueue") if i % 2 == 0 else ("nfqueue", "proxy")
    samples["none"].append(rate())
    for transport in order:
        samples[transport].append(measure_layer(transport))
    puts(f"pass {i + 1}/{args.passes} done", color=colors.white)

baseline = statistics.median(samples["none"])
puts(f"Unfiltered baseline: {baseline:.0f} conn/s "
     f"({min(samples['none']):.0f}–{max(samples['none']):.0f} across passes)", color=colors.blue)
for transport in ("proxy", "nfqueue"):
    got = statistics.median(samples[transport])
    puts(f"{transport:>8}: {got:.0f} conn/s ({100 * got / baseline:.0f}% of unfiltered), "
         f"{min(samples[transport]):.0f}–{max(samples[transport]):.0f} across passes",
         color=colors.yellow)

low, high = samples["proxy"], samples["nfqueue"]
overlap = min(low) <= max(high) and min(high) <= max(low)
ratio = statistics.median(low) / statistics.median(high)
if overlap:
    puts(f"The two layers overlap across passes ({ratio:.2f}× on the medians): this "
         f"benchmark does not separate them.", color=colors.green, is_bold=True)
else:
    puts(f"The proxy layer carries {ratio:.2f}× the connection rate of NFQUEUE, with no "
         f"overlap across passes.", color=colors.green, is_bold=True)
sep()
