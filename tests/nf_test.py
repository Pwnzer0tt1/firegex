#!/usr/bin/env python3
from utils.colors import colors, puts, sep
from utils.firegexapi import FiregexAPI
from utils.tcpserver import TcpServer
from utils.udpserver import UdpServer
import argparse
import secrets
import base64
import time

parser = argparse.ArgumentParser()
parser.add_argument("--address", "-a", type=str , required=False, help='Address of firegex backend', default="http://127.0.0.1:4444/")
parser.add_argument("--password", "-p", type=str, required=True, help='Firegex password')
parser.add_argument("--service_name", "-n", type=str , required=False, help='Name of the test service', default="Test Service")
parser.add_argument("--port", "-P", type=int , required=False, help='Port of the test service', default=1337)
parser.add_argument("--ipv6", "-6" , action="store_true", help='Test Ipv6', default=False)
parser.add_argument("--proto", "-m" , type=str, required=False, choices=["tcp","udp"], help='Select the protocol', default="tcp")

args = parser.parse_args()
sep()
puts("Testing will start on ", color=colors.cyan, end="")
puts(f"{args.address}", color=colors.yellow)

firegex = FiregexAPI(args.address)

#Login
if (firegex.login(args.password)):
    puts("Sucessfully logged in ✔", color=colors.green)
else:
    puts("Test Failed: Unknown response or wrong passowrd ✗", color=colors.red)
    exit(1)

#Create server
server = (TcpServer if args.proto == "tcp" else UdpServer)(args.port,ipv6=args.ipv6)

def exit_test(code):
    if service_id:
        server.stop()
        if(firegex.nf_delete_service(service_id)):
            puts("Sucessfully deleted service ✔", color=colors.green)
        else:
            puts("Test Failed: Coulnd't delete serivce ✗", color=colors.red)
            exit_test(1)        
    exit(code)

service_id = firegex.nf_add_service(args.service_name, args.port, args.proto , "::1" if args.ipv6 else "127.0.0.1" )
if service_id:
    puts("Sucessfully created service {service_id} ✔", color=colors.green)
else:
    puts("Test Failed: Failed to create service ✗", color=colors.red)
    exit(1)

if(firegex.nf_start_service(service_id)):
    puts("Sucessfully started service ✔", color=colors.green)
else:
    puts("Test Failed: Failed to start service ✗", color=colors.red)
    exit_test(1)

server.start()
time.sleep(0.5)
if server.sendCheckData(secrets.token_bytes(432)):
    puts("Successfully tested first proxy with no regex ✔", color=colors.green)
else:
    puts("Test Failed: Data was corrupted ", color=colors.red)
    exit_test(1)

#Add new regex
secret = bytes(secrets.token_hex(16).encode())
regex = base64.b64encode(secret).decode()
if firegex.nf_add_regex(service_id,regex,"B",active=True,is_case_sensitive=True): 
    puts(f"Sucessfully added regex {str(secret)} ✔", color=colors.green)
else:
    puts("Test Failed: Coulnd't add the regex {str(secret)} ✗", color=colors.red)
    exit_test(1)

#Check if regex is present in the service
n_blocked = 0

def checkRegex(regex, should_work=True, upper=False):
    if should_work:
        global n_blocked
        for r in firegex.nf_get_service_regexes(service_id):
            if r["regex"] == regex:
                #Test the regex
                s = base64.b64decode(regex).upper() if upper else base64.b64decode(regex)
                if not server.sendCheckData(secrets.token_bytes(200) + s +  secrets.token_bytes(200)):
                    puts("The malicious request was successfully blocked ✔", color=colors.green)
                    n_blocked += 1
                    time.sleep(1)
                    if firegex.nf_get_regex(r["id"])["n_packets"] == n_blocked:
                        puts("The packed was reported as blocked ✔", color=colors.green)
                    else:
                        puts("Test Failed: The packed wasn't reported as blocked ✗", color=colors.red)
                        exit_test(1)
                else:
                    puts("Test Failed: The request wasn't blocked ✗", color=colors.red)
                    exit_test(1)
                return
        puts("Test Failed: The regex wasn't found ✗", color=colors.red)
        exit_test(1)
    else:
        if server.sendCheckData(secrets.token_bytes(200) + base64.b64decode(regex) +  secrets.token_bytes(200)):
            puts("The request wasn't blocked ✔", color=colors.green)
        else:
            puts("Test Failed: The request was blocked when it shouldn't have", color=colors.red)
            exit_test(1)

checkRegex(regex)

#Pause the proxy
if(firegex.nf_stop_service(service_id)):
    puts(f"Sucessfully paused service with id {service_id} ✔", color=colors.green)
else:
    puts("Test Failed: Coulnd't pause the service ✗", color=colors.red)
    exit_test(1)

#Check if it's actually paused
checkRegex(regex,should_work=False)

#Start firewall
if(firegex.nf_start_service(service_id)):
    puts(f"Sucessfully started service with id {service_id} ✔", color=colors.green)
else:
    puts("Test Failed: Coulnd't start the service ✗", color=colors.red)
    exit_test(1)

checkRegex(regex)

#Disable regex 
for r in firegex.nf_get_service_regexes(service_id):
        if r["regex"] == regex:
            if(firegex.nf_disable_regex(r["id"])): 
                puts(f"Sucessfully disabled regex with id {r['id']} ✔", color=colors.green)
            else: 
                puts("Test Failed: Coulnd't disable the regex ✗", color=colors.red)
                exit_test(1)
            break

#Check if it's actually disabled
checkRegex(regex,should_work=False)

#Enable regex
for r in firegex.nf_get_service_regexes(service_id):
        if r["regex"] == regex:
            if(firegex.nf_enable_regex(r["id"])): 
                puts(f"Sucessfully enabled regex with id {r['id']} ✔", color=colors.green)
            else: 
                puts("Test Failed: Coulnd't enable the regex ✗", color=colors.red)
                exit_test(1)
            break

checkRegex(regex)

#Delete regex
n_blocked = 0
for r in firegex.nf_get_service_regexes(service_id):
        if r["regex"] == regex:
            if(firegex.nf_delete_regex(r["id"])): 
                puts(f"Sucessfully deleted regex with id {r['id']} ✔", color=colors.green)
            else: 
                puts("Test Failed: Coulnd't delete the regex ✗", color=colors.red)
                exit_test(1)
            break

#Check if it's actually deleted
checkRegex(regex,should_work=False)

#Add case insensitive regex
if(firegex.nf_add_regex(service_id,regex,"B",active=True, is_case_sensitive=False)): 
    puts(f"Sucessfully added case insensitive regex {str(secret)} ✔", color=colors.green)
else:
    puts(f"Test Failed: Coulnd't add the case insensitive regex {str(secret)} ✗", color=colors.red)
    exit_test(1)

checkRegex(regex,upper=True)
checkRegex(regex)

#Delete regex
n_blocked = 0
for r in firegex.nf_get_service_regexes(service_id):
        if r["regex"] == regex:
            if(firegex.nf_delete_regex(r["id"])): 
                puts(f"Sucessfully deleted regex with id {r['id']} ✔", color=colors.green)
            else: 
                puts("Test Failed: Coulnd't delete the regex ✗", color=colors.red)
                exit_test(1)
            break

#Rename service
if(firegex.nf_rename_service(service_id,f"{args.service_name}2")):
    puts(f"Sucessfully renamed service to {args.service_name}2 ✔", color=colors.green)
else:
    puts("Test Failed: Coulnd't rename service ✗", color=colors.red)
    exit_test(1)

#Check if service was renamed correctly
for services in firegex.nf_get_services():
    if services["name"] == f"{args.service_name}2":
        puts("Checked that service was renamed correctly  ✔", color=colors.green)
        exit_test(0)

puts("Test Failed: Service wasn't renamed correctly ✗", color=colors.red)
exit_test(1)
