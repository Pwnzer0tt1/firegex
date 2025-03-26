#!/usr/bin/env python3
from utils.colors import colors, puts, sep
from utils.firegexapi import FiregexAPI
from multiprocessing import Process
from time import sleep
import iperf3
import csv
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("module", type=str, help='module to analyse', choices=['nfregex','nfproxy'])
parser.add_argument("--address", "-a", type=str , required=False, help='Address of firegex backend', default="http://127.0.0.1:4444/")
parser.add_argument("--port", "-P", type=int , required=False, help='Port of the Benchmark service', default=1337)
parser.add_argument("--service-name", "-n", type=str , required=False, help='Name of the Benchmark service', default="Benchmark Service")
parser.add_argument("--password", "-p", type=str, required=True, help='Firegex password')
parser.add_argument("--duration", "-d", type=int, required=False, help='Duration of the Benchmark in seconds', default=1)
parser.add_argument("--output-file", "-o", type=str, required=False, help='Output results csv file', default="comparemark.csv")
parser.add_argument("--num-of-streams", "-s", type=int, required=False, help='Number of concurrent streams', default=1)
parser.add_argument("--number-of-values", "-V", type=int, required=False, help='Number of values to generate', default=10)
parser.add_argument("--test-baseline", action='store_true', required=False, help='Test baseline without any filters')

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

#Cleaning services
srvs = firegex.nfregex_get_services()
for ele in srvs:
    if ele['name'] == args.service_name:
        firegex.nfregex_delete_service(ele['service_id'])

srvs = firegex.nfproxy_get_services()
for ele in srvs:
    if ele['name'] == args.service_name:
        firegex.nfproxy_delete_service(ele['service_id'])

args.port = int(args.port)
args.duration = int(args.duration)
args.num_of_streams = int(args.num_of_streams)
args.number_of_values = int(args.number_of_values)

#Start iperf3
def startServer():
    try:
        server = iperf3.Server()
        server.bind_address = '127.0.0.1'
        server.port = args.port
        server.verbose = False
        while True:
            server.run()
    except Exception as e:
        puts(f"Failed to start/run iperf3 server: {e}", color=colors.red)

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
                attempt += 1

baseline_data = []
no_filters = []
test_data = []

if args.test_baseline:
    for _ in range(args.number_of_values):
        #Get baseline reading 
        data = getReading(args.port)
        baseline_data.append(data)
        puts("Baseline without any filter: ", color=colors.blue, end='')
        print(f"{data} MB/s")

#Create new Service
test_regex = '(?:[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*|"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])'

BASE_FILTER = f"""
from firegex.nfproxy.models import RawPacket
from firegex.nfproxy import pyfilter, REJECT
import re

@pyfilter
def verdict_test(packet:RawPacket):
    if re.match({repr(test_regex.encode())}, packet.data):
        return REJECT
"""

if args.module == "nfregex":
    def exit_test(code):
        if service_id:
            server.kill()
            if(firegex.nfregex_delete_service(service_id)):
                puts("Sucessfully deleted service ✔", color=colors.green)
            else:
                puts("Test Failed: Coulnd't delete serivce ✗", color=colors.red)
                exit_test(1)        
        exit(code)
    service_id = firegex.nfregex_add_service(args.service_name, args.port, "tcp", "127.0.0.1/32")
    if service_id:
        puts(f"Sucessfully created service {service_id} ✔", color=colors.green)
    else:
        puts("Test Failed: Failed to create service ✗", color=colors.red)
        exit(1)
    #Start nfregex service
    if firegex.nfregex_start_service(service_id):
        puts(f"Sucessfully started service with id {service_id} ✔", color=colors.green)
    else:
        puts("Benchmark Failed: Coulnd't start the service ✗", color=colors.red)
        exit_test(1)

    #Get no regexes reading 
    for _ in range(args.number_of_values):
        #Get baseline reading 
        data = getReading(args.port)
        no_filters.append(data)
        puts("Baseline nfregex with no filter: ", color=colors.blue, end='')
        print(f"{data} MB/s")

    if firegex.nfregex_add_regex(service_id,test_regex,"B",active=True,is_case_sensitive=False):
        puts("Sucessfully added test regex ✔", color=colors.green)
    else:
        puts("Benchmark Failed: Couldn't add the regex ✗", color=colors.red)
        exit_test(1)

    for _ in range(args.number_of_values):
        #Get baseline reading 
        data = getReading(args.port)
        puts("Baseline nfregex with 1 filter: ", color=colors.blue, end='')
        test_data.append(data)
        print(f"{data} MB/s")

    if(firegex.nfregex_delete_service(service_id)):
        puts("Sucessfully deleted service ✔", color=colors.green)
    else:
        puts("Test Failed: Coulnd't delete serivce ✗", color=colors.red)
        exit_test(1)

elif args.module == "nfproxy":
    
    service_id = firegex.nfproxy_add_service(args.service_name, args.port, "http" , "127.0.0.1")
    if service_id:
        puts(f"Sucessfully created service {service_id} ✔", color=colors.green)
    else:
        puts("Test Failed: Failed to create service ✗", color=colors.red)
        exit(1)

    def exit_test(code):
        if service_id:
            server.kill()
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
    for _ in range(args.number_of_values):
        #Get baseline reading 
        data = getReading(args.port)
        puts("Baseline nfproxy with no filter: ", color=colors.blue, end='')
        no_filters.append(data)
        print(f"{data} MB/s")

    if firegex.nfproxy_set_code(service_id, BASE_FILTER): 
        puts("Sucessfully added filter for test in REJECT mode ✔", color=colors.green)
    else:
        puts("Test Failed: Couldn't add the filter for test ✗", color=colors.red)
        exit_test(1)

    for _ in range(args.number_of_values):
        #Get baseline reading 
        data = getReading(args.port)
        puts("Baseline nfproxy with 1 filter: ", color=colors.blue, end='')
        test_data.append(data)
        print(f"{data} MB/s")

    if(firegex.nfproxy_delete_service(service_id)):
        puts("Sucessfully deleted service ✔", color=colors.green)
    else:
        puts("Test Failed: Coulnd't delete serivce ✗", color=colors.red)
        exit_test(1)

with open(args.output_file,'w') as f:
    writer = csv.writer(f)
    if baseline_data:
        writer.writerow(["Baseline","No filters","test data"])
        for data in zip(baseline_data, no_filters, test_data):
            writer.writerow(data)
    else:
        writer.writerow(["No filters","test data"])
        for data in zip(no_filters, test_data):
            writer.writerow(data)

puts(f"Sucessfully written results to {args.output_file} ✔", color=colors.magenta)

server.terminate()
