#!/usr/bin/env python3
import argparse, socket,secrets, base64
from time import sleep
from multiprocessing  import Process
from firegexapi import FiregexAPI

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
parser.add_argument("--address", "-a", type=str , required=False, help='Address of firegex backend', default="http://127.0.0.1:4444/")
parser.add_argument("--service_port", "-P", type=int , required=False, help='Port of the test service', default=1337)
parser.add_argument("--service_name", "-n", type=str , required=False, help='Name of the test service', default="Test Service")
parser.add_argument("--password", "-p", type=str, required=True, help='Firegex password')
args = parser.parse_args()
sep()
puts(f"Testing will start on ", color=colors.cyan, end="")
puts(f"{args.address}", color=colors.yellow)

        
firegex = FiregexAPI(args.address)
service_created = False

#Connect to Firegex
if (firegex.login(args.password)): puts(f"Sucessfully logged in ✔", color=colors.green)
else: puts(f"Test Failed: Unknown response or wrong passowrd ✗", color=colors.red); exit(1)

#Change password
new_password = secrets.token_hex(10)
if (firegex.change_password(new_password,True)): puts(f"Sucessfully changed password to {new_password} ✔", color=colors.green)
else: puts(f"Test Failed: Coundl't change the password ✗", color=colors.red); exit(1)
#Changed it back
if (firegex.change_password(args.password,True)): puts(f"Sucessfully restored the password ✔", color=colors.green)
else: puts(f"Test Failed: Coundl't change the password ✗", color=colors.red); exit(1)


#Create new Service
service = firegex.create_service(args.service_name,args.service_port,"tcp","127.0.0.1/24")
if service:
     puts(f"Sucessfully created service {args.service_name} with public port {args.service_port} ✔", color=colors.green)
     service_created = True
else: puts(f"Test Failed: Couldn't create service ✗", color=colors.red); exit(1)

#Delete the Service and exit
def exit_test(status_code=0):
    if service_created:
        if(firegex.delete(service)):
            puts(f"Sucessfully delete service with id {service} ✔", color=colors.green)
        else:
            puts(f"Test Failed: Couldn't delete service ✗", color=colors.red); exit(1)
    sep()
    server.terminate()
    exit(status_code)

#Start listener
def startServer(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(8)
    while True:  
        connection,address = sock.accept()  
        buf = connection.recv(4096)  
        connection.send(buf)    		
        connection.close()

server = Process(target=startServer,args=[args.service_port])
server.start()

#Start firewall
if(firegex.start(service)): puts(f"Sucessfully started service with id {service} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't start the service ✗", color=colors.red); exit_test(1)

#Hacky solution - wait a bit for the server to start
sleep(1)

#Send data via the proxy, and validate it
def sendCheckData(data):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', args.service_port))
    s.sendall(data)
    received_data = s.recv(4096)
    s.close()
    return received_data == data

if sendCheckData(secrets.token_bytes(200)):
    puts(f"Successfully tested first proxy with no regex ✔", color=colors.green)
else:
    puts(f"Test Failed: Data was corrupted ", color=colors.red)

#Add new regex
secret = bytes(secrets.token_hex(16).encode())
regex = base64.b64encode(secret).decode()
if(firegex.add_regex(service,regex)): puts(f"Sucessfully added regex {secret} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't add the regex {secret} ✗", color=colors.red); exit_test(1)

#Check if regex is present in the service
n_blocked = 0

def checkRegex(regex):
    global n_blocked
    for r in firegex.get_service_regexes(service):
        if r["regex"] == regex:
            #Test the regex
            if not sendCheckData(secrets.token_bytes(200) + secret +  secrets.token_bytes(200)):
                puts(f"The malicious request was successfully blocked ✔", color=colors.green)
                n_blocked += 1
                sleep(10)
                if firegex.get_regex(r["id"])["n_packets"] == n_blocked:
                    puts(f"The packed was reported as blocked ✔", color=colors.green)
                else:
                    puts(f"Test Failed: The packed wasn't reported as blocked ✗", color=colors.red); exit_test(1)
            else:
                puts(f"Test Failed: The request wasn't blocked ✗", color=colors.red);exit_test(1)
            return
    puts(f"Test Failed: The regex wasn't found ✗", color=colors.red); exit_test(1)

checkRegex(regex)

#Pause the proxy
if(firegex.stop(service)): puts(f"Sucessfully paused service with id {service} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't pause the service ✗", color=colors.red); exit_test(1)

#Check if it's actually paused
if sendCheckData(secrets.token_bytes(200) + secret +  secrets.token_bytes(200)):
    puts(f"The request wasn't blocked ✔", color=colors.green)
else:
    puts(f"Test Failed: The request was blocked when it shouldn't have", color=colors.red)

#Start firewall
if(firegex.start(service)): puts(f"Sucessfully started service with id {service} ✔", color=colors.green)
else: puts(f"Test Failed: Coulnd't start the service ✗", color=colors.red); exit_test(1)

checkRegex(regex)

#Delete the regex
def removeRegex(regex):
    for r in firegex.get_service_regexes(service):
        if r["regex"] == regex:
            if(firegex.delete_regex(r["id"])): puts(f"Sucessfully deleted regex ✔", color=colors.green)
            else: puts(f"Test Failed: Coulnd't deleted the regex ✗", color=colors.red); exit_test(1)
            return
    puts(f"Test Failed: The regex wasn't found ✗", color=colors.red)

removeRegex(regex)

if sendCheckData(secrets.token_bytes(200) + secret +  secrets.token_bytes(200)):
    puts(f"The request wasn't blocked ✔", color=colors.green)
else:
    puts(f"Test Failed: The request was blocked when it shouldn't have", color=colors.red)

exit_test()
