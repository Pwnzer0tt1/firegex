#!/usr/bin/env python3
from utils.colors import colors, puts, sep
from utils.firegexapi import FiregexAPI
from utils.tcpserver import TcpServer
import argparse
import secrets
import time

parser = argparse.ArgumentParser()
parser.add_argument("--address", "-a", type=str , required=False, help='Address of firegex backend', default="http://127.0.0.1:4444/")
parser.add_argument("--password", "-p", type=str, required=True, help='Firegex password')
parser.add_argument("--service_name", "-n", type=str , required=False, help='Name of the test service', default="Test Service")
parser.add_argument("--port", "-P", type=int , required=False, help='Port of the test service', default=1337)
parser.add_argument("--ipv6", "-6" , action="store_true", help='Test Ipv6', default=False)
parser.add_argument("--verbose", "-V" , action="store_true", help='Verbose output', default=False)

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
server = TcpServer(args.port,ipv6=args.ipv6, verbose=args.verbose)

srvs = firegex.nfproxy_get_services()
for ele in srvs:
    if ele['name'] == args.service_name:
        firegex.nfproxy_delete_service(ele['service_id'])

service_id = firegex.nfproxy_add_service(args.service_name, args.port, "http" , "::1" if args.ipv6 else "127.0.0.1" )
if service_id:
    puts(f"Sucessfully created service {service_id} ✔", color=colors.green)
else:
    puts("Test Failed: Failed to create service ✗", color=colors.red)
    exit(1)

def exit_test(code):
    if service_id:
        server.stop()
        """
        if firegex.nfproxy_delete_service(service_id):
            puts("Sucessfully deleted service ✔", color=colors.green)
        else:
            puts("Test Failed: Coulnd't delete serivce ✗", color=colors.red)  
        """    
    exit(code)

if(firegex.nfproxy_start_service(service_id)):
    puts("Sucessfully started service ✔", color=colors.green)
else:
    puts("Test Failed: Failed to start service ✗", color=colors.red)
    exit_test(1)

server.start()
time.sleep(0.5)
try:
    if server.sendCheckData(secrets.token_bytes(432)):
        puts("Successfully tested first proxy with no filters ✔", color=colors.green)
    else:
        puts("Test Failed: Data was corrupted ", color=colors.red)
        exit_test(1)
except Exception:
    puts("Test Failed: Couldn't send data to the server ", color=colors.red)
    exit_test(1)

BASE_FILTER_VERDICT_TEST = """
from firegex.nfproxy.models import RawPacket
from firegex.nfproxy import pyfilter, ACCEPT, UNSTABLE_MANGLE, DROP, REJECT

@pyfilter
def verdict_test(packet:RawPacket):
    if b"%%TEST%%" in packet.data:
        packet.l4_data = packet.l4_data.replace(b"%%TEST%%", b"%%MANGLE%%")
        return %%ACTION%%
"""

BASE_FILTER_VERDICT_NAME = "verdict_test"

def get_vedict_test(to_match:str, action:str, mangle_to:str="REDACTED"):
    return BASE_FILTER_VERDICT_TEST.replace("%%TEST%%", to_match).replace("%%ACTION%%", action).replace("%%MANGLE%%", mangle_to)


#Check if filter is present in the service
n_blocked = 0
n_mangled = 0

def checkFilter(match_bytes, filter_name, should_work=True, mangle_with=None):
    if mangle_with:
        if should_work:
            global n_mangled
            for r in firegex.nfproxy_get_service_pyfilters(service_id):
                if r["name"] == filter_name:
                    #Test the filter
                    pre_packet = secrets.token_bytes(40)
                    post_packet = secrets.token_bytes(40)
                    server.connect_client()
                    server.send_packet(pre_packet + match_bytes + post_packet)
                    real_response = server.recv_packet()
                    expected_response = pre_packet + mangle_with + post_packet
                    if real_response == expected_response:
                        puts("The malicious request was successfully mangled ✔", color=colors.green)
                        n_mangled += 1
                        time.sleep(1)
                        if firegex.nfproxy_get_pyfilter(service_id, filter_name)["edited_packets"] == n_mangled:
                            puts("The packet was reported as mangled in the API ✔", color=colors.green)
                        else:
                            puts("Test Failed: The packet wasn't reported as mangled in the API ✗", color=colors.red)
                            exit_test(1)
                        server.send_packet(pre_packet)
                        if server.recv_packet() == pre_packet:
                            puts("Is able to communicate after mangle ✔", color=colors.green)
                        else:
                            puts("Test Failed: Couldn't communicate after mangle ✗", color=colors.red)
                            exit_test(1)
                    else:
                        puts("Test Failed: The request wasn't mangled ✗", color=colors.red)
                        exit_test(1)
                    server.close_client()
                    return
            puts("Test Failed: The filter wasn't found ✗", color=colors.red)
        else:
            if server.sendCheckData(secrets.token_bytes(40) + match_bytes + secrets.token_bytes(40)):
                puts("The request wasn't mangled ✔", color=colors.green)
            else:
                puts("Test Failed: The request was mangled when it shouldn't have", color=colors.red)
                exit_test(1)
    else:
        if should_work:
            global n_blocked
            for r in firegex.nfproxy_get_service_pyfilters(service_id):
                if r["name"] == filter_name:
                    #Test the filter
                    if not server.sendCheckData(secrets.token_bytes(40) + match_bytes + secrets.token_bytes(40)):
                        puts("The malicious request was successfully blocked ✔", color=colors.green)
                        n_blocked += 1
                        time.sleep(1)
                        if firegex.nfproxy_get_pyfilter(service_id, filter_name)["blocked_packets"] == n_blocked:
                            puts("The packet was reported as blocked in the API ✔", color=colors.green)
                        else:
                            puts("Test Failed: The packet wasn't reported as blocked in the API ✗", color=colors.red)
                            exit_test(1)
                    else:
                        puts("Test Failed: The request wasn't blocked ✗", color=colors.red)
                        exit_test(1)
                    return
            puts("Test Failed: The filter wasn't found ✗", color=colors.red)
            exit_test(1)
        else:
            if server.sendCheckData(secrets.token_bytes(40) + match_bytes + secrets.token_bytes(40)):
                puts("The request wasn't blocked ✔", color=colors.green)
            else:
                puts("Test Failed: The request was blocked when it shouldn't have", color=colors.red)
                exit_test(1)

#Add new filter
secret = bytes(secrets.token_hex(16).encode())

if firegex.nfproxy_set_code(service_id,get_vedict_test(secret.decode(), "REJECT")): 
    puts(f"Sucessfully added filter for {str(secret)} in REJECT mode ✔", color=colors.green)
else:
    puts(f"Test Failed: Couldn't add the filter {str(secret)} ✗", color=colors.red)
    exit_test(1)

checkFilter(secret, BASE_FILTER_VERDICT_NAME)

#Pause the proxy
if firegex.nfproxy_stop_service(service_id):
    puts(f"Sucessfully paused service with id {service_id} ✔", color=colors.green)
else:
    puts("Test Failed: Coulnd't pause the service ✗", color=colors.red)
    exit_test(1)

#Check if it's actually paused
checkFilter(secret, BASE_FILTER_VERDICT_NAME, should_work=False)

#Start firewall
if firegex.nfproxy_start_service(service_id):
    puts(f"Sucessfully started service with id {service_id} ✔", color=colors.green)
else:
    puts("Test Failed: Coulnd't start the service ✗", color=colors.red)
    exit_test(1)

checkFilter(secret, BASE_FILTER_VERDICT_NAME)

#Disable filter 
if firegex.nfproxy_disable_pyfilter(service_id, BASE_FILTER_VERDICT_NAME):
    puts(f"Sucessfully disabled filter {BASE_FILTER_VERDICT_NAME} ✔", color=colors.green)
else: 
    puts("Test Failed: Coulnd't disable the filter ✗", color=colors.red)
    exit_test(1)

#Check if it's actually disabled
checkFilter(secret, BASE_FILTER_VERDICT_NAME, should_work=False)

#Enable filter
if firegex.nfproxy_enable_pyfilter(service_id, BASE_FILTER_VERDICT_NAME):
    puts(f"Sucessfully enabled filter {BASE_FILTER_VERDICT_NAME} ✔", color=colors.green)
else: 
    puts("Test Failed: Coulnd't enable the regex ✗", color=colors.red)
    exit_test(1)

checkFilter(secret, BASE_FILTER_VERDICT_NAME)

def remove_filters():
    global n_blocked, n_mangled
    server.stop()
    server.start()
    if not firegex.nfproxy_set_code(service_id, ""):
        puts("Test Failed: Couldn't remove the filter ✗", color=colors.red)
        exit_test(1)
    n_blocked = 0
    n_mangled = 0

remove_filters()

#Check if it's actually deleted
checkFilter(secret, BASE_FILTER_VERDICT_NAME, should_work=False)

#Check if DROP works
if firegex.nfproxy_set_code(service_id,get_vedict_test(secret.decode(), "DROP")): 
    puts(f"Sucessfully added filter for {str(secret)} in DROP mode ✔", color=colors.green)
else:
    puts(f"Test Failed: Couldn't add the filter {str(secret)} ✗", color=colors.red)
    exit_test(1)

checkFilter(secret, BASE_FILTER_VERDICT_NAME)

remove_filters()

#Check if UNSTABLE_MANGLE works
mangle_result = secrets.token_hex(4).encode() # Mangle to a smaller packet
if firegex.nfproxy_set_code(service_id, get_vedict_test(secret.decode(), "UNSTABLE_MANGLE", mangle_result.decode())):
    puts(f"Sucessfully added filter for {str(secret)} in UNSTABLE_MANGLE mode to a smaller packet size ✔", color=colors.green)
else:
    puts(f"Test Failed: Couldn't add the filter {str(secret)} ✗", color=colors.red)
    exit_test(1)

checkFilter(secret, BASE_FILTER_VERDICT_NAME, mangle_with=mangle_result)

remove_filters()

#Check if UNSTABLE_MANGLE works
mangle_result = secrets.token_hex(60).encode() # Mangle to a bigger packet
if firegex.nfproxy_set_code(service_id, get_vedict_test(secret.decode(), "UNSTABLE_MANGLE", mangle_result.decode())):
    puts(f"Sucessfully added filter for {str(secret)} in UNSTABLE_MANGLE mode to a bigger packet size ✔", color=colors.green)
else:
    puts(f"Test Failed: Couldn't add the filter {str(secret)} ✗", color=colors.red)
    exit_test(1)

checkFilter(secret, BASE_FILTER_VERDICT_NAME, mangle_with=mangle_result)

remove_filters()

secret = b"8331ee1bf75893dd7fa3d34f29bac7fc8935aa3ef6c565fe8b395ef7f485"
TCP_INPUT_STREAM_TEST = f"""
from firegex.nfproxy.models import TCPInputStream
from firegex.nfproxy import pyfilter, ACCEPT, UNSTABLE_MANGLE, DROP, REJECT

@pyfilter
def data_type_test(packet:TCPInputStream):
    if {repr(secret)} in packet.data:
        return REJECT

"""

if firegex.nfproxy_set_code(service_id, TCP_INPUT_STREAM_TEST):
    puts(f"Sucessfully added filter for {str(secret)} for TCPInputStream ✔", color=colors.green)
else:
    puts(f"Test Failed: Couldn't add the filter {str(secret)} ✗", color=colors.red)
    exit_test(1)

data_split = len(secret)//2
server.connect_client()
server.send_packet(secret[:data_split])
if server.recv_packet() == secret[:data_split]:
    puts("The half-packet was successfully sent and received ✔", color=colors.green)
else:
    puts("Test Failed: The half-packet wasn't received ✗", color=colors.red)
    exit_test(1)
server.send_packet(secret[data_split:])
if not server.recv_packet():
    puts("The malicious request was successfully blocked ✔", color=colors.green)
else:
    puts("Test Failed: The request wasn't blocked ✗", color=colors.red)
    exit_test(1)
server.close_client()

remove_filters()

secret = b"8331ee1bf75893dd7fa3d34f29bac7fc8935aa3ef6c565fe8b395ef7f485"
TCP_OUTPUT_STREAM_TEST = f"""
from firegex.nfproxy.models import TCPOutputStream
from firegex.nfproxy import pyfilter, ACCEPT, UNSTABLE_MANGLE, DROP, REJECT

@pyfilter
def data_type_test(packet:TCPOutputStream):
    if {repr(secret)} in packet.data:
        return REJECT

"""

if firegex.nfproxy_set_code(service_id, TCP_OUTPUT_STREAM_TEST):
    puts(f"Sucessfully added filter for {str(secret)} for TCPOutputStream ✔", color=colors.green)
else:
    puts(f"Test Failed: Couldn't add the filter {str(secret)} ✗", color=colors.red)
    exit_test(1)

data_split = len(secret)//2
server.connect_client()
server.send_packet(secret[:data_split])
if server.recv_packet() == secret[:data_split]:
    puts("The half-packet was successfully sent and received ✔", color=colors.green)
else:
    puts("Test Failed: The half-packet wasn't received ✗", color=colors.red)
    exit_test(1)
server.send_packet(secret[data_split:])
if not server.recv_packet():
    puts("The malicious request was successfully blocked ✔", color=colors.green)
else:
    puts("Test Failed: The request wasn't blocked ✗", color=colors.red)
    exit_test(1)
server.close_client()

remove_filters()

secret = b"8331ee1bf75893dd7fa3d34f29bac7fc8935aa3ef6c565fe8b395ef7f485"

REQUEST_HEADER_TEST = f"""POST / HTTP/1.1
Host: localhost
X-TeSt: {secret.decode()}
Content-Length: 15

A Friendly Body""".replace("\n", "\r\n")

REQUEST_BODY_TEST = f"""POST / HTTP/1.1
Host: localhost
X-TeSt: NotTheSecret
Content-Length: {len(secret.decode())}

{secret.decode()}""".replace("\n", "\r\n")

HTTP_REQUEST_STREAM_TEST = f"""
from firegex.nfproxy.models import HttpRequest
from firegex.nfproxy import pyfilter, ACCEPT, UNSTABLE_MANGLE, DROP, REJECT

@pyfilter
def data_type_test(req:HttpRequest):
    if {repr(secret.decode())} in req.get_header("x-test"):
        return REJECT
    if req.body:
        if {repr(secret)} in req.body:
            return REJECT

"""

if firegex.nfproxy_set_code(service_id, HTTP_REQUEST_STREAM_TEST):
    puts(f"Sucessfully added filter for {str(secret)} for HttpRequest ✔", color=colors.green)
else:
    puts(f"Test Failed: Couldn't add the filter {str(secret)} ✗", color=colors.red)
    exit_test(1)

server.connect_client()
server.send_packet(REQUEST_HEADER_TEST.encode())
if not server.recv_packet():
    puts("The malicious HTTP request with the malicious header was successfully blocked ✔", color=colors.green)
else:
    puts("Test Failed: The HTTP request with the malicious header wasn't blocked ✗", color=colors.red)
    exit_test(1)
server.close_client()

server.connect_client()
server.send_packet(REQUEST_BODY_TEST.encode())
if not server.recv_packet():
    puts("The malicious HTTP request with the malicious body was successfully blocked ✔", color=colors.green)
else:
    puts("Test Failed: The HTTP request with the malicious body wasn't blocked ✗", color=colors.red)
    exit_test(1)
server.close_client()

remove_filters()

HTTP_REQUEST_HEADER_STREAM_TEST = f"""
from firegex.nfproxy.models import HttpRequestHeader
from firegex.nfproxy import pyfilter, ACCEPT, UNSTABLE_MANGLE, DROP, REJECT

@pyfilter
def data_type_test(req:HttpRequestHeader):
    if {repr(secret.decode())} in req.get_header("x-test"):
        return REJECT

"""

if firegex.nfproxy_set_code(service_id, HTTP_REQUEST_HEADER_STREAM_TEST):
    puts(f"Sucessfully added filter for {str(secret)} for HttpRequestHeader ✔", color=colors.green)
else:
    puts(f"Test Failed: Couldn't add the filter {str(secret)} ✗", color=colors.red)
    exit_test(1)

server.connect_client()
server.send_packet(REQUEST_HEADER_TEST.encode())
if not server.recv_packet():
    puts("The malicious HTTP request with the malicious header was successfully blocked ✔", color=colors.green)
else:
    puts("Test Failed: The HTTP request with the malicious header wasn't blocked ✗", color=colors.red)
    exit_test(1)
server.close_client()

remove_filters()

secret = b"8331ee1bf75893dd7fa3d34f29bac7fc8935aa3ef6c565fe8b395ef7f485"

RESPONSE_HEADER_TEST = f"""HTTP/1.1 200 OK
Host: localhost
X-TeSt: {secret.decode()}
Content-Length: 15

A Friendly Body""".replace("\n", "\r\n")

RESPONSE_BODY_TEST = f"""HTTP/1.1 200 OK
Host: localhost
X-TeSt: NotTheSecret
Content-Length: {len(secret.decode())}

{secret.decode()}""".replace("\n", "\r\n")

HTTP_RESPONSE_STREAM_TEST = f"""
from firegex.nfproxy.models import HttpResponse
from firegex.nfproxy import pyfilter, ACCEPT, UNSTABLE_MANGLE, DROP, REJECT

@pyfilter
def data_type_test(req:HttpResponse):
    if {repr(secret.decode())} in req.get_header("x-test"):
        return REJECT
    if req.body:
        if {repr(secret)} in req.body:
            return REJECT

"""

if firegex.nfproxy_set_code(service_id, HTTP_RESPONSE_STREAM_TEST):
    puts(f"Sucessfully added filter for {str(secret)} for HttpResponse ✔", color=colors.green)
else:
    puts(f"Test Failed: Couldn't add the filter {str(secret)} ✗", color=colors.red)
    exit_test(1)

server.connect_client()
server.send_packet(RESPONSE_HEADER_TEST.encode())
if not server.recv_packet():
    puts("The malicious HTTP request with the malicious header was successfully blocked ✔", color=colors.green)
else:
    puts("Test Failed: The HTTP request with the malicious header wasn't blocked ✗", color=colors.red)
    exit_test(1)
server.close_client()

server.connect_client()
server.send_packet(RESPONSE_BODY_TEST.encode())
if not server.recv_packet():
    puts("The malicious HTTP request with the malicious body was successfully blocked ✔", color=colors.green)
else:
    puts("Test Failed: The HTTP request with the malicious body wasn't blocked ✗", color=colors.red)
    exit_test(1)
server.close_client()

remove_filters()

HTTP_RESPONSE_HEADER_STREAM_TEST = f"""
from firegex.nfproxy.models import HttpResponseHeader
from firegex.nfproxy import pyfilter, ACCEPT, UNSTABLE_MANGLE, DROP, REJECT

@pyfilter
def data_type_test(req:HttpResponseHeader):
    if {repr(secret.decode())} in req.get_header("x-test"):
        return REJECT

"""

if firegex.nfproxy_set_code(service_id, HTTP_RESPONSE_HEADER_STREAM_TEST):
    puts(f"Sucessfully added filter for {str(secret)} for HttpResponseHeader ✔", color=colors.green)
else:
    puts(f"Test Failed: Couldn't add the filter {str(secret)} ✗", color=colors.red)
    exit_test(1)

server.connect_client()
server.send_packet(RESPONSE_HEADER_TEST.encode())
if not server.recv_packet():
    puts("The malicious HTTP request with the malicious header was successfully blocked ✔", color=colors.green)
else:
    puts("Test Failed: The HTTP request with the malicious header wasn't blocked ✗", color=colors.red)
    exit_test(1)
server.close_client()

remove_filters()

#Simulating requests is more complex due to websocket extensions handshake 

WS_REQUEST_PARSING_TEST = b'GET /sock/?EIO=4&transport=websocket HTTP/1.1\r\nHost: localhost:8080\r\nConnection: Upgrade\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\xac AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36\r\nUpgrade: websocket\r\nOrigin: http://localhost:8080\r\nSec-WebSocket-Version: 13\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6,zh;q=0.5\r\nCookie: cookie-consent=true; _iub_cs-86405163=%7B%22timestamp%22%3A%222024-09-12T18%3A20%3A18.627Z%22%2C%22version%22%3A%221.65.1%22%2C%22purposes%22%3A%7B%221%22%3Atrue%2C%224%22%3Atrue%7D%2C%22id%22%3A86405163%2C%22cons%22%3A%7B%22rand%22%3A%222b09e6%22%7D%7D\r\nSec-WebSocket-Key: eE01O3/ZShPKsrykACLAaA==\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n\xc1\x84#\x8a\xb2\xbb\x11\xbb\xb2\xbb'
WS_RESPONSE_PARSING_TEST = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: eGnJqUSoSKE3wOfKD2M3G82RsS8=\r\nSec-WebSocket-Extensions: permessage-deflate\r\ndate: Sat, 15 Mar 2025 12:04:19 GMT\r\nserver: uvicorn\r\n\r\n\xc1_2\xa8V*\xceLQ\xb2Rr1\xb4\xc8\xf6r\x0c\xf3\xaf\xd25\xf7\x8e\xf4\xb3LsttrW\xd2Q*-H/JLI-V\xb2\x8a\x8e\xd5Q*\xc8\xccK\x0f\xc9\xccM\xcd/-Q\xb222\x00\x02\x88\x98g^IjQYb\x0eP\xd0\x14,\x98\x9bX\x11\x90X\x99\x93\x9f\x084\xda\xd0\x00\x0cj\x01\x00\xc1\x1b21\x80\xd9e\xe1n\x19\x9e\xe3RP\x9a[Z\x99\x93j\xea\x15\x00\xb4\xcbC\xa9\x16\x00'

HTTP_REQUEST_WS_PARSING_TEST = """
from firegex.nfproxy.models import HttpRequest, HttpResponse
from firegex.nfproxy import pyfilter, ACCEPT, UNSTABLE_MANGLE, DROP, REJECT

@pyfilter
def data_type_test(req:HttpRequest):
    print(req)

@pyfilter
def data_type_test(req:HttpResponse):
    print(req)

"""

if firegex.nfproxy_set_code(service_id, HTTP_REQUEST_WS_PARSING_TEST):
    puts("Sucessfully added filter websocket parsing with HttpRequest and HttpResponse ✔", color=colors.green)
else:
    puts("Test Failed: Couldn't add the websocket parsing filter ✗", color=colors.red)
    exit_test(1)

server.connect_client()
server.send_packet(WS_REQUEST_PARSING_TEST, server_reply=WS_RESPONSE_PARSING_TEST)
if server.recv_packet():
    puts("The HTTP websocket upgrade request was successfully parsed ✔", color=colors.green)
else:
    puts("Test Failed: The HTTP websocket upgrade request wasn't parsed (an error occurred) ✗", color=colors.red)
    exit_test(1)
server.close_client()

remove_filters()

#Rename service
if firegex.nfproxy_rename_service(service_id,f"{args.service_name}2"):
    puts(f"Sucessfully renamed service to {args.service_name}2 ✔", color=colors.green)
else:
    puts("Test Failed: Coulnd't rename service ✗", color=colors.red)
    exit_test(1)

#Check if service was renamed correctly
service = firegex.nfproxy_get_service(service_id)
if service["name"] == f"{args.service_name}2":
    puts("Checked that service was renamed correctly  ✔", color=colors.green)
else:
    puts("Test Failed: Service wasn't renamed correctly ✗", color=colors.red)
    exit_test(1)
    
#Rename back service
if(firegex.nfproxy_rename_service(service_id,f"{args.service_name}")):
    puts(f"Sucessfully renamed service to {args.service_name} ✔", color=colors.green)
else:
    puts("Test Failed: Coulnd't rename service ✗", color=colors.red)
    exit_test(1)

#Change settings
if(firegex.nfproxy_settings_service(service_id, 1338, "::dead:beef" if args.ipv6 else "123.123.123.123", True)):
    srv_updated = firegex.nfproxy_get_service(service_id)
    if srv_updated["port"] == 1338 and ("::dead:beef" if args.ipv6 else "123.123.123.123") in srv_updated["ip_int"] and srv_updated["fail_open"]:
        puts("Sucessfully changed service settings ✔", color=colors.green)
    else:
        puts("Test Failed: Service settings weren't updated correctly ✗", color=colors.red)
        exit_test(1)
else:
    puts("Test Failed: Coulnd't change service settings ✗", color=colors.red)
    exit_test(1)

exit_test(0)
