#!/usr/bin/env python3
from utils.colors import *
from utils.firegexapi import *
from utils.tcpserver import *
import argparse, secrets, base64,time

parser = argparse.ArgumentParser()
parser.add_argument("--address", "-a", type=str , required=False, help='Address of firegex backend', default="http://127.0.0.1:4444/")
parser.add_argument("--password", "-p", type=str, required=True, help='Firegex password')
parser.add_argument("--service_name", "-n", type=str , required=False, help='Name of the test service', default="Test Service")
parser.add_argument("--port", "-P", type=int , required=False, help='Port of the test service', default=1337)

args = parser.parse_args()
sep()
puts(f"Testing will start on ", color=colors.cyan, end="")
puts(f"{args.address}", color=colors.yellow)

firegex = FiregexAPI(args.address)

#Login
if (firegex.login(args.password)): puts(f"Sucessfully logged in ✔", color=colors.green)
else: puts(f"Test Failed: Unknown response or wrong passowrd ✗", color=colors.red); exit(1)

#TCP tests
server = TcpServer(args.port)

def exit_test(code):
    if service_id:
        server.stop()
        firegex.nf_delete_service(service_id)
    exit(code)

service_id = firegex.nf_add_service(args.service_name, args.port, "tcp", "127.0.0.1/24")
if service_id: puts(f"Sucessfully created service {service_id} ✔", color=colors.green)
else: puts(f"Test Failed: Failed to create service ✗", color=colors.red); exit(1)

if(firegex.nf_start_service(service_id)): puts(f"Sucessfully started service ✔", color=colors.green)
else: puts(f"Test Failed: Failed to start service ✗", color=colors.red); exit_test(1)

server.start()

if server.sendCheckData(secrets.token_bytes(200)):
    puts(f"Successfully tested first proxy with no regex ✔", color=colors.green)
else:
    puts(f"Test Failed: Data was corrupted ", color=colors.red); exit_test(1)

#Add new regex
secret = bytes(secrets.token_hex(16).encode())
regex = base64.b64encode(secret).decode()
if(firegex.nf_add_regex(service_id,regex,"B",active=True,is_blacklist=True,is_case_sensitive=True)): 
    puts(f"Sucessfully added regex {regex} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't add the regex {secret} ✗", color=colors.red); exit_test(1)

#Check if regex is present in the service
n_blocked = 0

def checkRegex(regex):
    global n_blocked
    for r in firegex.nf_get_service_regexes(service_id):
        if r["regex"] == regex:
            #Test the regex
            if not server.sendCheckData(secrets.token_bytes(200) + secret +  secrets.token_bytes(200)):
                puts(f"The malicious request was successfully blocked ✔", color=colors.green)
                n_blocked += 1
                if firegex.nf_get_regex(r["id"])["n_packets"] == n_blocked:
                    puts(f"The packed was reported as blocked ✔", color=colors.green)
                else:
                    puts(f"Test Failed: The packed wasn't reported as blocked ✗", color=colors.red); exit_test(1)
            else:
                puts(f"Test Failed: The request wasn't blocked ✗", color=colors.red);exit_test(1)
            return
    puts(f"Test Failed: The regex wasn't found ✗", color=colors.red); exit_test(1)

checkRegex(regex)

#Pause the proxy
if(firegex.nf_stop_service(service_id)): puts(f"Sucessfully paused service with id {service_id} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't pause the service ✗", color=colors.red); exit_test(1)

#Check if it's actually paused
if server.sendCheckData(secrets.token_bytes(200) + secret +  secrets.token_bytes(200)):
    puts(f"The request wasn't blocked ✔", color=colors.green)
else:
    puts(f"Test Failed: The request was blocked when it shouldn't have", color=colors.red)

#Start firewall
if(firegex.nf_start_service(service_id)): puts(f"Sucessfully started service with id {service_id} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't start the service ✗", color=colors.red); exit_test(1)

checkRegex(regex)

#TODO: test whitelist, enable/disable regex, and UDP

exit_test(0)