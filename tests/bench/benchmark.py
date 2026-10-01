#!/usr/bin/env python3
import _path  # noqa: F401
from helpers.colors import colors, puts, sep
from helpers.firegexapi import FiregexAPI
from time import sleep
import csv
import argparse
import json
import secrets
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--address", "-a", type=str , required=False, help='Address of firegex backend', default="http://127.0.0.1:4444/")
parser.add_argument("--port", "-P", type=int , required=False, help='Port of the Benchmark service', default=1337)
parser.add_argument("--service-name", "-n", type=str , required=False, help='Name of the Benchmark service', default="Benchmark Service")
parser.add_argument("--password", "-p", type=str, required=True, help='Firegex password')
parser.add_argument("--num-of-regexes", "-r", type=int, required=True, help='Number of regexes to benchmark with')
parser.add_argument("--duration", "-d", type=int, required=False, help='Duration of the Benchmark in seconds', default=5)
parser.add_argument("--output-file", "-o", type=str, required=False, help='Output results csv file', default="benchmark.csv")
parser.add_argument("--num-of-streams", "-s", type=int, required=False, help='Number of concurrent streams', default=1)
parser.add_argument("--transport", "-t", type=str, required=False, choices=["proxy", "nfqueue"],
                    help='Which network layer to benchmark', default="nfqueue")

args = parser.parse_args()
sep()
puts(f"Benchmarking the {args.transport} layer with {args.num_of_regexes} regexes will start on ", color=colors.cyan, end="")
puts(f"{args.address}", color=colors.yellow)

firegex = FiregexAPI(args.address)

#Connect to Firegex
if (firegex.login(args.password)):
    puts("Sucessfully logged in ✔", color=colors.green)
else:
    puts("Benchmark Failed: Unknown response or wrong passowrd ✗", color=colors.red)
    exit(1)

def exit_test(code):
    if service_id:
        # `globals()`, because the failures above this point happen before the iperf3
        # server exists, and a NameError here would replace the real reason with itself.
        if globals().get("server"):
            server.kill()
        if(firegex.services_delete(service_id)):
            puts("Sucessfully deleted service ✔", color=colors.green)
        else:
            puts("Test Failed: Coulnd't delete serivce ✗", color=colors.red)
            exit_test(1)        
    exit(code)

#Create new Service

srvs = firegex.services_list()
for ele in srvs:
    if ele['name'] == args.service_name:
        firegex.services_delete(ele['service_id'])

# `fail_open=False`, explicitly, and it is the single most important line in this file.
# With it on, the nft rule carries `bypass` and the queue is configured
# NFQA_CFG_F_FAIL_OPEN: when the queue fills — which under fifty iperf3 streams it does
# constantly — the kernel accepts packets *without inspecting them*. The throughput then
# measured is mostly traffic that was never filtered, which is a different question and
# an order of magnitude higher. A benchmark of the filter has to make every packet go
# through the filter.
service_id = firegex.services_add(args.service_name, "127.0.0.1", args.port, args.transport,
                                  fail_open=False)
if service_id:
    puts(f"Sucessfully created service {service_id} ✔", color=colors.green)
else:
    puts("Test Failed: Failed to create service ✗", color=colors.red)
    exit(1)

# One regex filter holds every pattern: they are compiled into a single hyperscan
# database, which is exactly the property this benchmark measures. Adding a pattern
# rebuilds that database rather than adding a second pass.
if not firegex.services_add_filter(service_id, "regex", "patterns"):
    puts("Benchmark Failed: Couldn't attach the regex filter ✗", color=colors.red)
    exit_test(1)
filter_id = firegex.services_filters(service_id)[0]["filter_id"]

args.port = int(args.port)
args.duration = int(args.duration)
args.num_of_streams = int(args.num_of_streams)

# iperf3 is driven as a **subprocess**, not through the `iperf3` python binding, and
# that is not a style preference — the binding cannot run the shape this benchmark is
# built around.
#
# It captures libiperf's output by `dup2`-ing stdout onto an `os.pipe()` and reading it
# only *after* the test returns. A Linux pipe holds 64 KiB. Measured on this host, the
# JSON one test produces is:
#
#     50 streams,  1s   55 KB    fits
#     50 streams,  2s   74 KB    over
#     50 streams,  5s  130 KB    over
#
# Past 64 KiB libiperf blocks in `write()`, so the test never returns, so the read that
# would drain the pipe never happens. The benchmark hangs for good — observed at two
# hours and 45 seconds of CPU, with no output and no error. It only ever worked because
# `--num-of-streams` defaults to 1; at the fifty streams this benchmark is *about*, it
# could not complete at any duration above one second.
#
# The binary writes to a pipe somebody is draining, so none of that can happen, and it
# is the same iperf3 an operator would run by hand. It also takes the fork/multiprocessing
# workaround with it: there is no python object to keep alive in a child any more.
def startServer():
    return subprocess.Popen(
        ["iperf3", "--server", "--bind", "127.0.0.1", "--port", str(args.port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

def getReading(port):
    out = subprocess.run(
        ["iperf3", "--client", "127.0.0.1", "--port", str(port),
         "--time", str(args.duration), "--parallel", str(args.num_of_streams),
         "--zerocopy", "--json"],
        capture_output=True, text=True,
    )
    try:
        report = json.loads(out.stdout)
    except json.JSONDecodeError:
        puts(f"Benchmark Failed: iperf3 said nothing usable ✗ {out.stderr.strip()[:200]}",
             color=colors.red)
        exit_test(1)
    if "error" in report:
        puts(f"Benchmark Failed: iperf3: {report['error']} ✗", color=colors.red)
        exit_test(1)
    return round(report["end"]["sum_received"]["bits_per_second"] / 8e+6, 3)

server = startServer()
sleep(1)

custom_regex = [
    '(?:[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*|"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])'
]

def gen_regex():
    """
    if len(custom_regex) == 0:
        regex = secrets.token_hex(8)
    else:
        regex = custom_regex.pop()
    """
    return secrets.token_hex(20)


#Get baseline reading 
puts("Baseline without proxy: ", color=colors.blue, end='')
print(f"{getReading(args.port)} MB/s")

#Start firewall

if firegex.services_start(service_id):
    puts(f"Sucessfully started service with id {service_id} ✔", color=colors.green)
else:
    puts("Benchmark Failed: Coulnd't start the service ✗", color=colors.red)
    exit_test(1)

#Get no regexs reading 
results = []
puts("Performance with no regexes: ", color=colors.yellow , end='')
results.append(getReading(args.port))
print(f"{results[0]} MB/s")

#Add all the regexs
for i in range(1,args.num_of_regexes+1):
    regex = gen_regex()
    if not firegex.services_add_regex(service_id, filter_id, regex, "B", case_sensitive=False):
        puts("Benchmark Failed: Couldn't add the regex ✗", color=colors.red)
        exit_test(1)
    puts(f"Performance with {i} regex(s): ", color=colors.red, end='')
    results.append(getReading(args.port))
    print(f"{results[i]} MB/s")

with open(args.output_file,'w') as f:
    writer = csv.writer(f)
    for i,result in enumerate(results):
        writer.writerow([i,result])

puts(f"Sucessfully written results to {args.output_file} ✔", color=colors.magenta)

#Delete the Service 
if firegex.services_delete(service_id):
    puts(f"Sucessfully delete service with id {service_id} ✔", color=colors.green)
else:
    puts("Test Failed: Couldn't delete service ✗", color=colors.red)
    exit(1)

server.terminate()
