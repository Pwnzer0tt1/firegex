#!/usr/bin/env python3
import argparse, socket,secrets, base64, iperf3, csv
from time import sleep
from requests import Session
from multiprocessing  import Process

pref = "\033["
reset = f"{pref}0m"

class colors:
    black = "30m"
    red = "31m"
    green = "32m"
    yellow = "33m"
    blue = "34m"
    magenta = "35m"
    cyan = "36m"
    white = "37m"

def puts(text, *args, color=colors.white, is_bold=False, **kwargs):
    print(f'{pref}{1 if is_bold else 0};{color}' + text + reset, *args, **kwargs)

def sep(): puts("-----------------------------------", is_bold=True)
parser = argparse.ArgumentParser()
parser.add_argument("--address", "-a", type=str , required=False, help='Address of firegex backend', default="http://127.0.0.1:5000/")
parser.add_argument("--service_port", "-P", type=int , required=False, help='Port of the Benchmark service', default=1337)
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

s = Session()
#Connect to Firegex
req = s.post(f"{args.address}api/login", json={"password":args.password})
assert req.json()["status"] == "ok", f"Benchmark Failed: Unknown response or wrong passowrd {req.text}"
puts(f"Sucessfully logged in ✔", color=colors.green)

#Create new Service
req = s.post(f"{args.address}api/services/add" , json={"name":args.service_name,"port":args.service_port})
assert req.json()["status"] == "ok", f"Benchmark Failed: Couldn't create service {req.text} ✔"
puts(f"Sucessfully created service {args.service_name} with public port {args.service_port} ✔", color=colors.green)

#Find the Service
req = s.get(f"{args.address}api/services")
internal_port = service_id = None
try:
    for service in req.json():
        if service["name"] == args.service_name:
            service_id = service["id"]
            internal_port = service["internal_port"]
            puts(f"Sucessfully received the internal port {internal_port} ✔", color=colors.green)
            break
except Exception:
    puts(f"Benchmark Failed: Coulnd't get the service internal port {req.text}", color=colors.red)
    exit(1)

#Start iperf3
def startServer():
    server = iperf3.Server()
    server.bind_address = '127.0.0.1'
    server.port = internal_port
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
print(f"{getReading(internal_port)} MB/s")

#Start firewall
req = s.get(f"{args.address}api/service/{service_id}/start")
assert req.json()["status"] == "ok", f"Benchmark Failed: Couldn't start the service {req.text}"
puts(f"Sucessfully started service with id {service_id} ✔", color=colors.green)

#Hacky solution - wait a bit for the server to start
sleep(1)

#Get no regexs reading 
results = []
puts(f"Performance with no regexes: ", color=colors.yellow , end='')
results.append(getReading(args.service_port))
print(f"{results[0]} MB/s")

#Add all the regexs
for i in range(1,args.num_of_regexes+1):
    regex = base64.b64encode(bytes(secrets.token_hex(16).encode())).decode()
    req = s.post(f"{args.address}api/regexes/add", 
                json={"is_blacklist":True,"is_case_sensitive":True,"service_id":service_id,"mode":"B","regex":regex})
    assert req.json()["status"] == "ok", f"Test Failed: Couldn't add regex {req.text}"
    puts(f"Performance with {i} regex(s): ", color=colors.red, end='')
    results.append(getReading(args.service_port))
    print(f"{results[i]} MB/s")

with open(args.output_file,'w') as f:
    writer = csv.writer(f)
    for i,result in enumerate(results):
        writer.writerow([i,result])

puts(f"Sucessfully written results to {args.output_file} ✔", color=colors.magenta)

#Delete the Service 
req = s.get(f"{args.address}api/service/{service_id}/delete")
assert req.json()["status"] == "ok", f"Benchmark Failed: Couldn't delete service {req.text}"
puts(f"Sucessfully delete service with id {service_id} ✔", color=colors.green)

server.terminate()