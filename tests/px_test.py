#!/usr/bin/env python3
from utils.colors import *
from utils.firegexapi import *
from utils.tcpserver import TcpServer
import argparse, secrets, base64,time,random

parser = argparse.ArgumentParser()
parser.add_argument("--address", "-a", type=str , required=False, help='Address of firegex backend', default="http://127.0.0.1:4444/")
parser.add_argument("--password", "-p", type=str, required=True, help='Firegex password')
parser.add_argument("--service_name", "-n", type=str , required=False, help='Name of the test service', default="Test Service")
parser.add_argument("--port", "-P", type=int , required=False, help='Port of the test service', default=1337)
args = parser.parse_args()
sep()
puts(f"Testing will start on ", color=colors.cyan, end="")
puts(f"{args.address}", color=colors.yellow)

#Create and start server
server = TcpServer(args.port,ipv6=False)
server.start()
time.sleep(0.5)

firegex = FiregexAPI(args.address)

#Login
if (firegex.login(args.password)): puts(f"Sucessfully logged in ✔", color=colors.green)
else: puts(f"Test Failed: Unknown response or wrong passowrd ✗", color=colors.red); exit(1)

def exit_test(code):
    if service_id:
        server.stop()
        if(firegex.px_delete_service(service_id)):  puts(f"Sucessfully deleted service ✔", color=colors.green)
        else: puts(f"Test Failed: Coulnd't deleted serivce ✗", color=colors.red); exit_test(1)        
    exit(code)

#Create service
service_id = firegex.px_add_service(args.service_name, args.port, 6140)
if service_id: puts(f"Sucessfully created service {service_id} ✔", color=colors.green)
else: puts(f"Test Failed: Failed to create service ✗", color=colors.red); exit(1)

if(firegex.px_start_service(service_id)): puts(f"Sucessfully started service ✔", color=colors.green)
else: puts(f"Test Failed: Failed to start service ✗", color=colors.red); exit_test(1)

#Check if service is in wait mode 
if(firegex.px_get_service(service_id)["status"] == "wait"): puts(f"Sucessfully started service in WAIT mode ✔", color=colors.green)
else: puts(f"Test Failed: Service not in WAIT mode ✗", color=colors.red); exit_test(1)

#Get inernal_port
internal_port = firegex.px_get_service(service_id)["internal_port"]
if (internal_port): puts(f"Sucessfully got internal port {internal_port} ✔", color=colors.green)
else: puts(f"Test Failed: Coundn't get internal_port ✗", color=colors.red); exit_test(1)

server.stop()
server = TcpServer(internal_port,ipv6=False, proxy_port=args.port)
server.start()
time.sleep(1)

if(firegex.px_get_service(service_id)["status"] == "active"): puts(f"Service went in ACTIVE mode ✔", color=colors.green)
else: puts(f"Test Failed: Service not in ACTIVE mode ✗", color=colors.red); exit_test(1)

if server.sendCheckData(secrets.token_bytes(432)):
    puts(f"Successfully tested first proxy with no regex ✔", color=colors.green)
else:
    puts(f"Test Failed: Data was corrupted ", color=colors.red); exit_test(1)

#Add new regex
secret = bytes(secrets.token_hex(16).encode())
regex = base64.b64encode(secret).decode()
if(firegex.px_add_regex(service_id,regex,"B",active=True,is_blacklist=True,is_case_sensitive=True)): 
    puts(f"Sucessfully added regex {str(secret)} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't add the regex {str(secret)} ✗", color=colors.red); exit_test(1)

#Check if regex is present in the service
n_blocked = 0

def checkRegex(regex, should_work=True, upper=False):
    if should_work:
        global n_blocked
        for r in firegex.px_get_service_regexes(service_id):
            if r["regex"] == regex:
                #Test the regex
                s = base64.b64decode(regex).upper() if upper else base64.b64decode(regex)
                if not server.sendCheckData(secrets.token_bytes(200) + s +  secrets.token_bytes(200)):
                    puts(f"The malicious request was successfully blocked ✔", color=colors.green)
                    n_blocked += 1
                    if firegex.px_get_regex(r["id"])["n_packets"] == n_blocked:
                        puts(f"The packed was reported as blocked ✔", color=colors.green)
                    else:
                        puts(f"Test Failed: The packed wasn't reported as blocked ✗", color=colors.red); exit_test(1)
                else:
                    puts(f"Test Failed: The request wasn't blocked ✗", color=colors.red);exit_test(1)
                return
        puts(f"Test Failed: The regex wasn't found ✗", color=colors.red); exit_test(1)
    else:
        if server.sendCheckData(secrets.token_bytes(200) + base64.b64decode(regex) +  secrets.token_bytes(200)):
            puts(f"The request wasn't blocked ✔", color=colors.green)
        else:
            puts(f"Test Failed: The request was blocked when it shouldn't have", color=colors.red)

checkRegex(regex)

#Pause the proxy
if(firegex.px_pause_service(service_id)): puts(f"Sucessfully paused service with id {service_id} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't pause the service ✗", color=colors.red); exit_test(1)

#Check if it's actually paused
checkRegex(regex,should_work=False)

#Start firewall
if(firegex.px_start_service(service_id)): puts(f"Sucessfully started service with id {service_id} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't start the service ✗", color=colors.red); exit_test(1)

checkRegex(regex)

#Stop firewall
if(firegex.px_stop_service(service_id)): puts(f"Sucessfully stopped service with id {service_id} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't stop the service ✗", color=colors.red); exit_test(1)

try:
    checkRegex(regex)
    puts(f"Test Failed: The service was still active ✗", color=colors.red); exit_test(1)
except Exception:
    puts(f"Service was correctly stopped ✔", color=colors.green)

#Start firewall in pause
if(firegex.px_pause_service(service_id)): puts(f"Sucessfully started service in pause mode with id {service_id} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't start the service ✗", color=colors.red); exit_test(1)

time.sleep(0.5)
#Check if it's actually paused
checkRegex(regex,should_work=False)

#Start firewall
if(firegex.px_start_service(service_id)): puts(f"Sucessfully started service with id {service_id} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't start the service ✗", color=colors.red); exit_test(1)

checkRegex(regex)

#Disable regex 
for r in firegex.px_get_service_regexes(service_id):
        if r["regex"] == regex:
            if(firegex.px_disable_regex(r["id"])): 
                puts(f"Sucessfully disabled regex with id {r['id']} ✔", color=colors.green)
            else: 
                puts(f"Test Failed: Coulnd't disable the regex ✗", color=colors.red); exit_test(1)
            break

#Check if it's actually disabled
checkRegex(regex,should_work=False)

#Enable regex
for r in firegex.px_get_service_regexes(service_id):
        if r["regex"] == regex:
            if(firegex.px_enable_regex(r["id"])): 
                puts(f"Sucessfully enabled regex with id {r['id']} ✔", color=colors.green)
            else: 
                puts(f"Test Failed: Coulnd't enable the regex ✗", color=colors.red); exit_test(1)
            break

checkRegex(regex)

#Delete regex
n_blocked = 0
for r in firegex.px_get_service_regexes(service_id):
        if r["regex"] == regex:
            if(firegex.px_delete_regex(r["id"])): 
                puts(f"Sucessfully deleted regex with id {r['id']} ✔", color=colors.green)
            else: 
                puts(f"Test Failed: Coulnd't delete the regex ✗", color=colors.red); exit_test(1)
            break

#Check if it's actually deleted
checkRegex(regex,should_work=False)

#Add case insensitive regex
if(firegex.px_add_regex(service_id,regex,"B",active=True,is_blacklist=True,is_case_sensitive=False)): 
    puts(f"Sucessfully added case insensitive regex {str(secret)} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't add the case insensitive regex {str(secret)} ✗", color=colors.red); exit_test(1)

checkRegex(regex,upper=True)
checkRegex(regex)

#Delete regex
n_blocked = 0
for r in firegex.px_get_service_regexes(service_id):
        if r["regex"] == regex:
            if(firegex.px_delete_regex(r["id"])): 
                puts(f"Sucessfully deleted regex with id {r['id']} ✔", color=colors.green)
            else: 
                puts(f"Test Failed: Coulnd't delete the regex ✗", color=colors.red); exit_test(1)
            break

#Add whitelist regex
if(firegex.px_add_regex(service_id,regex,"B",active=True,is_blacklist=False,is_case_sensitive=True)): 
    puts(f"Sucessfully added case whitelist regex {str(secret)} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't add the case whiteblist regex {str(secret)} ✗", color=colors.red); exit_test(1)

checkRegex(regex,should_work=False)
checkRegex(regex,upper=True) #Dirty way to test the whitelist :p

#Delete regex
n_blocked = 0
for r in firegex.px_get_service_regexes(service_id):
        if r["regex"] == regex:
            if(firegex.px_delete_regex(r["id"])): 
                puts(f"Sucessfully deleted regex with id {r['id']} ✔", color=colors.green)
            else: 
                puts(f"Test Failed: Coulnd't delete the regex ✗", color=colors.red); exit_test(1)
            break

#Rename service
if(firegex.px_rename_service(service_id,f"{args.service_name}2")): puts(f"Sucessfully renamed service to {args.service_name}2 ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't rename service ✗", color=colors.red); exit_test(1)

#Check if service was renamed correctly
found = False
for services in firegex.px_get_services():
    if services["name"] == f"{args.service_name}2":
        puts(f"Checked that service was renamed correctly  ✔", color=colors.green)
        found = True
        break

if not found: 
    puts(f"Test Failed: Service wasn't renamed correctly ✗", color=colors.red); exit_test(1)
    exit(1)

#Change service port
new_internal_port = random.randrange(6000,9000)
if(firegex.px_change_service_port(service_id,internalPort=new_internal_port)): 
    puts(f"Sucessfully changed internal_port to {new_internal_port} ✔", color=colors.green)
else: 
    puts(f"Test Failed: Coulnd't change intenral port ✗", color=colors.red); exit_test(1)

#Get inernal_port
internal_port = firegex.px_get_service(service_id)["internal_port"]
if (internal_port == new_internal_port): puts(f"Sucessfully got internal port {internal_port} ✔", color=colors.green)
else: puts(f"Test Failed: Coundn't get internal_port or port changed incorrectly ✗", color=colors.red); exit_test(1)

if(firegex.px_regen_service_port(service_id)): 
    puts(f"Sucessfully changed internal_port to {new_internal_port} ✔", color=colors.green)
else: 
    puts(f"Test Failed: Coulnd't change internal port ✗", color=colors.red); exit_test(1)

#Get regenerated inernal_port
new_internal_port = firegex.px_get_service(service_id)["internal_port"]
if (internal_port != new_internal_port): puts(f"Sucessfully got regenerated port {new_internal_port} ✔", color=colors.green)
else: puts(f"Test Failed: Coundn't get internal port, or it was the same as previous ✗", color=colors.red); exit_test(1)

exit_test(0)