#!/usr/bin/env python3
from utils.colors import *
from utils.firegexapi import *
from utils.tcpserver import *
from multiprocessing import Process
from time import sleep
import iperf3, csv, argparse, base64, secrets


#TODO: make it work with Proxy and not only netfilter
parser = argparse.ArgumentParser()
parser.add_argument("--address", "-a", type=str , required=False, help='Address of firegex backend', default="http://127.0.0.1:4444/")
parser.add_argument("--port", "-P", type=int , required=False, help='Port of the Benchmark service', default=1337)
parser.add_argument("--service_name", "-n", type=str , required=False, help='Name of the Benchmark service', default="Benchmark Service")
parser.add_argument("--password", "-p", type=str, required=True, help='Firegex password')
parser.add_argument("--num_of_regexes", "-r", type=int, required=True, help='Number of regexes to benchmark with')
parser.add_argument("--duration", "-d", type=int, required=False, help='Duration of the Benchmark in seconds', default=5)
parser.add_argument("--output_file", "-o", type=str, required=False, help='Output results csv file', default="benchmark.csv")
parser.add_argument("--num_of_streams", "-s", type=int, required=False, help='Output results csv file', default=1)

args = parser.parse_args()
sep()
puts(f"Benchmarking with {args.num_of_regexes} regexes will start on ", color=colors.cyan, end="")
puts(f"{args.address}", color=colors.yellow)

firegex = FiregexAPI(args.address)

#Connect to Firegex
if (firegex.login(args.password)): puts(f"Sucessfully logged in ✔", color=colors.green)
else: puts(f"Benchmark Failed: Unknown response or wrong passowrd ✗", color=colors.red); exit(1)

#Create new Service
service_id = firegex.nf_add_service(args.service_name, args.port, "tcp", "127.0.0.1/24")
if service_id: puts(f"Sucessfully created service {service_id} ✔", color=colors.green)
else: puts(f"Test Failed: Failed to create service ✗", color=colors.red); exit(1)

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
    client.protocol = 'tcp'
    client.num_streams = args.num_of_streams
    return round(client.run().json['end']['sum_received']['bits_per_second']/8e+6 , 3)

server = Process(target=startServer)
server.start()
sleep(1)


#Get baseline reading 
puts(f"Baseline without proxy: ", color=colors.blue, end='')
print(f"{getReading(args.port)} MB/s")

#Start firewall
if(firegex.nf_start_service(service_id)): puts(f"Sucessfully started service with id {service_id} ✔", color=colors.green)
else: puts(f"Benchmark Failed: Coulnd't start the service ✗", color=colors.red); exit_test(1)

#Get no regexs reading 
results = []
puts(f"Performance with no regexes: ", color=colors.yellow , end='')
results.append(getReading(args.port))
print(f"{results[0]} MB/s")

#Add all the regexs
for i in range(1,args.num_of_regexes+1):
    regex = base64.b64encode(bytes(secrets.token_hex(16).encode())).decode()
    if(not firegex.nf_add_regex(service_id,regex,"B",active=True,is_blacklist=True,is_case_sensitive=False)): puts(f"Benchmark Failed: Coulnd't add the regex ✗", color=colors.red); exit_test(1)
    puts(f"Performance with {i} regex(s): ", color=colors.red, end='')
    results.append(getReading(args.port))
    print(f"{results[i]} MB/s")

with open(args.output_file,'w') as f:
    writer = csv.writer(f)
    for i,result in enumerate(results):
        writer.writerow([i,result])

puts(f"Sucessfully written results to {args.output_file} ✔", color=colors.magenta)

#Delete the Service 
if(firegex.nf_delete_service(service_id)):
    puts(f"Sucessfully delete service with id {service_id} ✔", color=colors.green)
else:
    puts(f"Test Failed: Couldn't delete service ✗", color=colors.red); exit(1)

server.terminate()
