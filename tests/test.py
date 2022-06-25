#!/usr/bin/env python3
import argparse, socket,secrets, base64
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
parser.add_argument("--service_port", "-P", type=int , required=False, help='Port of the test service', default=1337)
parser.add_argument("--service_name", "-n", type=str , required=False, help='Name of the test service', default="Test Service")
parser.add_argument("--password", "-p", type=str, required=True, help='Firegex passowrd')
args = parser.parse_args()
sep()
puts(f"Testing will start on ", color=colors.cyan, end="")
puts(f"{args.address}", color=colors.yellow)

s = Session()
#Connect to Firegex
req = s.post(f"{args.address}api/login", json={"password":args.password})
assert req.json()["status"] == "ok", f"Test Failed: Unknown response or wrong passowrd {req.text}"
puts(f"Sucessfully logged in ✔", color=colors.green)

#Create new Service
req = s.post(f"{args.address}api/services/add" , json={"name":args.service_name,"port":args.service_port})
assert req.json()["status"] == "ok", f"Test Failed: Couldn't create service {req.text} ✔"
puts(f"Sucessfully created service {args.service_name} on with public port {args.service_port} ✔", color=colors.green)

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
    puts(f"Test Failed: Coulnd't get the service internal port {req.text}", color=colors.red)
    exit(1)

#Start listener
def startServer():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', internal_port))
    sock.listen(8)
    while True:  
        connection,address = sock.accept()  
        buf = connection.recv(4096)  
        connection.send(buf)    		
        connection.close()

server = Process(target=startServer)
server.start()

#Start firewall
req = s.get(f"{args.address}api/service/{service_id}/start")
assert req.json()["status"] == "ok", f"Test Failed: Couldn't start the service {req.text}"
puts(f"Sucessfully started service with id {service_id} ✔", color=colors.green)

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

if sendCheckData(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'):
    puts(f"Successfully tested first proxy with no regex ✔", color=colors.green)
else:
    puts(f"Test Failed: Data was corrupted", color=colors.red)

#Add new regex
secret = bytes(secrets.token_hex(16).encode())
regex = base64.b64encode(secret).decode()
req = s.post(f"{args.address}api/regexes/add", 
            json={"is_blacklist":True,"is_case_sensitive":True,"service_id":service_id,"mode":"B","regex":regex})
puts(f"Sucessfully added regex to service with id {service_id} ✔", color=colors.green)

#Test the regex
if not sendCheckData(b'AAAAAAAAAAAAAAAA' + secret +  b'AAAAAAAAAAAAAAAAA'):
    puts(f"The malicious request was successfully blocked ✔", color=colors.green)
else:
    puts(f"Test Failed: The request wasn't blocked", color=colors.red)

#Pause the proxy
req = s.get(f"{args.address}api/service/{service_id}/pause")
assert req.json()["status"] == "ok", f"Test Failed: Couldn't delete service {req.text}"
puts(f"Sucessfully stopped service with id {service_id} ✔", color=colors.green)

#Check if it's actually paused
if sendCheckData(b'AAAAAAAAAAAAAAAA' + secret +  b'AAAAAAAAAAAAAAAAA'):
    puts(f"The request wasn't blocked ✔", color=colors.green)
else:
    puts(f"Test Failed: The request was blocked when it shouldn't have", color=colors.red)

#Delete the Service 
req = s.get(f"{args.address}api/service/{service_id}/delete")
assert req.json()["status"] == "ok", f"Test Failed: Couldn't delete service {req.text}"
puts(f"Sucessfully delete service with id {service_id} ✔", color=colors.green)

server.terminate()