#!/usr/bin/env python3
from utils.colors import colors, puts, sep
from utils.firegexapi import FiregexAPI
from multiprocessing import Process
from time import sleep
import iperf3
import csv
import argparse
import base64
import secrets

parser = argparse.ArgumentParser()
parser.add_argument("--address", "-a", type=str , required=False, help='Address of firegex backend', default="http://127.0.0.1:4444/")
parser.add_argument("--port", "-P", type=int , required=False, help='Port of the Benchmark service', default=1337)
parser.add_argument("--service-name", "-n", type=str , required=False, help='Name of the Benchmark service', default="Benchmark Service")
parser.add_argument("--password", "-p", type=str, required=True, help='Firegex password')
parser.add_argument("--num-of-regexes", "-r", type=int, required=True, help='Number of regexes to benchmark with')
parser.add_argument("--duration", "-d", type=int, required=False, help='Duration of the Benchmark in seconds', default=5)
parser.add_argument("--output-file", "-o", type=str, required=False, help='Output results csv file', default="benchmark.csv")
parser.add_argument("--num-of-streams", "-s", type=int, required=False, help='Number of concurrent streams', default=1)

args = parser.parse_args()
sep()
puts(f"Benchmarking with {args.num_of_regexes} regexes will start on ", color=colors.cyan, end="")
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
        server.kill()
        if(firegex.nfregex_delete_service(service_id)):
            puts("Sucessfully deleted service ✔", color=colors.green)
        else:
            puts("Test Failed: Coulnd't delete serivce ✗", color=colors.red)
            exit_test(1)        
    exit(code)

#Create new Service

srvs = firegex.nfregex_get_services()
for ele in srvs:
    if ele['name'] == args.service_name:
        firegex.nfregex_delete_service(ele['service_id'])

service_id = firegex.nfregex_add_service(args.service_name, args.port, "tcp", "127.0.0.1/24")
if service_id:
    puts(f"Sucessfully created service {service_id} ✔", color=colors.green)
else:
    puts("Test Failed: Failed to create service ✗", color=colors.red)
    exit(1)

args.port = int(args.port)
args.duration = int(args.duration)
args.num_of_streams = int(args.num_of_streams)

#Start iperf3
def startServer():
    server = iperf3.Server()
    server.bind_address = '127.0.0.1'
    server.port = args.port
    server.verbose = False
    while True:
        server.run()

def getReading(port):
    client = iperf3.Client()
    client.duration = args.duration
    client.server_hostname = '127.0.0.1'
    client.port = port
    client.zerocopy = True
    client.verbose = False
    client.protocol = 'tcp'
    client.num_streams = args.num_of_streams
    return round(client.run().json['end']['sum_received']['bits_per_second']/8e+6 , 3)

server = Process(target=startServer)
server.start()
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
    regex = secrets.token_hex(20)
    return base64.b64encode(bytes(regex.encode())).decode()

#Get baseline reading 
puts("Baseline without proxy: ", color=colors.blue, end='')
print(f"{getReading(args.port)} MB/s")

#Start firewall

if firegex.nfregex_start_service(service_id):
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
    if not firegex.nfregex_add_regex(service_id,regex,"B",active=True,is_case_sensitive=False): 
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
if firegex.nfregex_delete_service(service_id):
    puts(f"Sucessfully delete service with id {service_id} ✔", color=colors.green)
else:
    puts("Test Failed: Couldn't delete service ✗", color=colors.red)
    exit(1)

server.terminate()
