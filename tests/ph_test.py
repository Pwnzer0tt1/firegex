#!/usr/bin/env python3
from utils.colors import *
from utils.firegexapi import *
from utils.tcpserver import TcpServer
from utils.udpserver import UdpServer
import argparse, secrets, base64,time

parser = argparse.ArgumentParser()
parser.add_argument("--address", "-a", type=str , required=False, help='Address of firegex backend', default="http://127.0.0.1:4444/")
parser.add_argument("--password", "-p", type=str, required=True, help='Firegex password')
parser.add_argument("--service_name", "-n", type=str , required=False, help='Name of the test service', default="Test Service")
parser.add_argument("--port", "-P", type=int , required=False, help='Port of the test service', default=1337)
parser.add_argument("--ipv6", "-6" , action="store_true", help='Test Ipv6', default=False)
parser.add_argument("--proto", "-m" , type=str, required=False, choices=["tcp","udp"], help='Select the protocol', default="tcp")

args = parser.parse_args()
sep()
puts(f"Testing will start on ", color=colors.cyan, end="")
puts(f"{args.address}", color=colors.yellow)

firegex = FiregexAPI(args.address)

#Login
if (firegex.login(args.password)): puts(f"Sucessfully logged in ✔", color=colors.green)
else: puts(f"Test Failed: Unknown response or wrong passowrd ✗", color=colors.red); exit(1)

#Create server
server = (TcpServer if args.proto == "tcp" else UdpServer)(args.port+1,ipv6=args.ipv6,proxy_port=args.port)

def exit_test(code):
    if service_id:
        server.stop()
        if(firegex.ph_delete_service(service_id)):  puts(f"Sucessfully deleted service ✔", color=colors.green)
        else: puts(f"Test Failed: Coulnd't delete serivce ✗", color=colors.red); exit_test(1)        
    exit(code)

#Create and start serivce
service_id = firegex.ph_add_service(args.service_name, args.port, args.port+1, args.proto , "::1" if args.ipv6 else "127.0.0.1",  "::1" if args.ipv6 else "127.0.0.1")
if service_id: puts(f"Sucessfully created service {service_id} ✔", color=colors.green)
else: puts(f"Test Failed: Failed to create service ✗", color=colors.red); exit(1)

if(firegex.ph_start_service(service_id)): puts(f"Sucessfully started service ✔", color=colors.green)
else: puts(f"Test Failed: Failed to start service ✗", color=colors.red); exit_test(1)

server.start()
time.sleep(0.5)

#Check if it started
def checkData(should_work):
    res = None
    try: res = server.sendCheckData(secrets.token_bytes(432))
    except (ConnectionRefusedError, TimeoutError): res = None
    if res:
        if should_work: puts(f"Successfully received data ✔", color=colors.green)
        else: puts("Test Failed: Connection wasn't blocked ✗", color=colors.red); exit_test(1)
    else:
        if should_work: puts(f"Test Failed: Data wans't received ✗", color=colors.red); exit_test(1)
        else: puts(f"Successfully blocked connection ✔", color=colors.green)

checkData(True)

#Pause the proxy
if(firegex.ph_stop_service(service_id)): puts(f"Sucessfully paused service with id {service_id} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't pause the service ✗", color=colors.red); exit_test(1)

checkData(False)

#Start firewall
if(firegex.ph_start_service(service_id)): puts(f"Sucessfully started service with id {service_id} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't start the service ✗", color=colors.red); exit_test(1)

checkData(True)

#Change port
if(firegex.ph_change_destination(service_id, "::1" if args.ipv6 else "127.0.0.1", args.port+2)): 
    puts(f"Sucessfully changed port ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't change destination ✗", color=colors.red); exit_test(1)

checkData(False)

server.stop()
server = (TcpServer if args.proto == "tcp" else UdpServer)(args.port+2,ipv6=args.ipv6,proxy_port=args.port)
server.start()
time.sleep(0.5)

checkData(True)

#Rename service
if(firegex.ph_rename_service(service_id,f"{args.service_name}2")): puts(f"Sucessfully renamed service to {args.service_name}2 ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't rename service ✗", color=colors.red); exit_test(1)

#Check if service was renamed correctly
for services in firegex.ph_get_services():
    if services["name"] == f"{args.service_name}2":
        puts(f"Checked that service was renamed correctly  ✔", color=colors.green)
        exit_test(0)

puts(f"Test Failed: Service wasn't renamed correctly ✗", color=colors.red); exit_test(1)
exit_test(1)
