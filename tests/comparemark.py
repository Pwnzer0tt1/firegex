#!/usr/bin/env python3
from utils.colors import colors, puts, sep
from utils.firegexapi import FiregexAPI
from multiprocessing import Process
from time import sleep
import iperf3
import csv
import argparse
import secrets

parser = argparse.ArgumentParser()
parser.add_argument("--address", "-a", type=str , required=False, help='Address of firegex backend', default="http://127.0.0.1:4444/")
parser.add_argument("--port", "-P", type=int , required=False, help='Port of the Benchmark service', default=1337)
parser.add_argument("--service-name", "-n", type=str , required=False, help='Name of the Benchmark service', default="Benchmark Service")
parser.add_argument("--password", "-p", type=str, required=True, help='Firegex password')
parser.add_argument("--duration", "-d", type=int, required=False, help='Duration of the Benchmark in seconds', default=5)
parser.add_argument("--output-file", "-o", type=str, required=False, help='Output results csv file', default="comparemark.csv")
parser.add_argument("--num-of-streams", "-s", type=int, required=False, help='Number of concurrent streams', default=1)
parser.add_argument("--number-of-values", "-V", type=int, required=False, help='Number of values to generate', default=100)

args = parser.parse_args()
sep()
puts("Benchmark for compare firegex features ", color=colors.cyan, end="")
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

#Cleaning services
srvs = firegex.nfregex_get_services()
for ele in srvs:
    if ele['name'] == args.service_name:
        firegex.nfregex_delete_service(ele['service_id'])

srvs = firegex.nfproxy_get_services()
for ele in srvs:
    if ele['name'] == args.service_name:
        firegex.nfproxy_delete_service(ele['service_id'])

#Create new Service
service_id = firegex.nfregex_add_service(args.service_name, args.port, "tcp", "127.0.0.1/32")
if service_id:
    puts(f"Sucessfully created service {service_id} ✔", color=colors.green)
else:
    puts("Test Failed: Failed to create service ✗", color=colors.red)
    exit(1)

args.port = int(args.port)
args.duration = int(args.duration)
args.num_of_streams = int(args.num_of_streams)
args.number_of_values = int(args.number_of_values)

#Start iperf3
def startServer():
    server = iperf3.Server()
    server.bind_address = '127.0.0.1'
    server.port = args.port
    server.verbose = False
    while True:
        server.run()

global server
server = Process(target=startServer)
server.start()
sleep(1)

def getReading(port):
    global server
    attempt = 1
    while True:
        try:
            client = iperf3.Client()
            client.duration = args.duration
            client.server_hostname = '127.0.0.1'
            client.port = port
            client.zerocopy = True
            client.verbose = False
            client.protocol = 'tcp'
            client.num_streams = args.num_of_streams
            return round(client.run().json['end']['sum_received']['bits_per_second']/8e+6 , 3)
        except Exception as e:
            if attempt >= 3:
                raise e
            else:
                server.kill()
                server = Process(target=startServer)
                server.start()
                sleep(1)
                puts(f"Faild to run test on attempt: {attempt}, retrying...", color=colors.red)


text_filter_key = secrets.token_hex(16)

baseline_data = []

for _ in range(args.number_of_values):
    #Get baseline reading 
    puts("Baseline without any filter: ", color=colors.blue, end='')
    data = getReading(args.port)
    baseline_data.append(data)
    print(f"{data} MB/s")

#Start nfregex service
if firegex.nfregex_start_service(service_id):
    puts(f"Sucessfully started service with id {service_id} ✔", color=colors.green)
else:
    puts("Benchmark Failed: Coulnd't start the service ✗", color=colors.red)
    exit_test(1)

#Get no regexes reading 
no_regex_nfregex = []

for _ in range(args.number_of_values):
    #Get baseline reading 
    puts("Baseline nfregex with no filter: ", color=colors.blue, end='')
    data = getReading(args.port)
    no_regex_nfregex.append(data)
    print(f"{data} MB/s")

if not firegex.nfregex_add_regex(service_id,text_filter_key,"B",active=True,is_case_sensitive=False): 
    puts("Benchmark Failed: Couldn't add the regex ✗", color=colors.red)
    exit_test(1)

nfregex_test = []

for _ in range(args.number_of_values):
    #Get baseline reading 
    puts("Baseline nfregex with 1 filter: ", color=colors.blue, end='')
    data = getReading(args.port)
    nfregex_test.append(data)
    print(f"{data} MB/s")

if(firegex.nfregex_delete_service(service_id)):
    puts("Sucessfully deleted service ✔", color=colors.green)
else:
    puts("Test Failed: Coulnd't delete serivce ✗", color=colors.red)
    exit_test(1)

service_id = firegex.nfproxy_add_service(args.service_name, args.port, "http" , "127.0.0.1" )
if service_id:
    puts(f"Sucessfully created service {service_id} ✔", color=colors.green)
else:
    puts("Test Failed: Failed to create service ✗", color=colors.red)
    exit(1)

def exit_test(code):
    if service_id:
        server.stop()
        if firegex.nfproxy_delete_service(service_id):
            puts("Sucessfully deleted service ✔", color=colors.green)
        else:
            puts("Test Failed: Coulnd't delete serivce ✗", color=colors.red)   
            exit(1)   
    exit(code)
    
if(firegex.nfproxy_start_service(service_id)):
    puts("Sucessfully started service ✔", color=colors.green)
else:
    puts("Test Failed: Failed to start service ✗", color=colors.red)
    exit_test(1)

#Get no filters
no_nfproxy_filter = []

for _ in range(args.number_of_values):
    #Get baseline reading 
    puts("Baseline nfregex with no filter: ", color=colors.blue, end='')
    data = getReading(args.port)
    no_nfproxy_filter.append(data)
    print(f"{data} MB/s")

BASE_FILTER = f"""
from firegex.nfproxy.models import RawPacket
from firegex.nfproxy import pyfilter, REJECT

@pyfilter
def verdict_test(packet:RawPacket):
    if {repr(text_filter_key)} in packet.data:
        return REJECT
"""

if firegex.nfproxy_set_code(service_id, BASE_FILTER): 
    puts(f"Sucessfully added filter for {str(text_filter_key)} in REJECT mode ✔", color=colors.green)
else:
    puts(f"Test Failed: Couldn't add the filter {str(text_filter_key)} ✗", color=colors.red)
    exit_test(1)

nfproxy_test = []

for _ in range(args.number_of_values):
    #Get baseline reading 
    puts("Baseline nfproxy with 1 filter: ", color=colors.blue, end='')
    data = getReading(args.port)
    nfproxy_test.append(data)
    print(f"{data} MB/s")

if(firegex.nfproxy_delete_service(service_id)):
    puts("Sucessfully deleted service ✔", color=colors.green)
else:
    puts("Test Failed: Coulnd't delete serivce ✗", color=colors.red)
    exit_test(1)

with open(args.output_file,'w') as f:
    writer = csv.writer(f)
    writer.writerow(["Baseline","No NFRegex","NFRegex test","No NFProxy","NFProxy test"])
    for data in zip(baseline_data,no_regex_nfregex,nfregex_test,no_nfproxy_filter,nfproxy_test):
        writer.writerow(data)

puts(f"Sucessfully written results to {args.output_file} ✔", color=colors.magenta)

server.terminate()
