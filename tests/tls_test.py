#!/usr/bin/env python3
from utils.colors import colors, puts, sep
from utils.firegexapi import FiregexAPI
from utils.tcpserver import TcpServer
from utils.tls_helpers import generate_self_signed_cert_key, tls_connect_send_recv
import argparse
import secrets
import time

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--address", "-a", type=str, required=False,
        help="Address of firegex backend", default="http://127.0.0.1:4444/",
    )
    parser.add_argument(
        "--password", "-p", type=str, required=True, help="Firegex password"
    )
    parser.add_argument(
        "--ipv6", "-6", action="store_true", help="Test Ipv6", default=False
    )
    parser.add_argument(
        "--port", "-P", type=int, required=False,
        help="Base port of the test stream", default=15443,
    )

    args = parser.parse_args()
    sep()
    puts("Testing TLS stream CRUD/edit/cascade will start on ", color=colors.cyan, end="")
    puts(f"{args.address}", color=colors.yellow)

    firegex = FiregexAPI(args.address)

    if firegex.login(args.password):
        puts("Sucessfully logged in ✔", color=colors.green)
    else:
        puts("Test Failed: Unknown response or wrong password ✗", color=colors.red)
        exit(1)

    def exit_test(code):
        exit(code)

    host = "::1" if args.ipv6 else "127.0.0.1"
    port_a = args.port
    port_b = args.port + 1
    service_name = "TLS CRUD Test Service"

    # Cleanup leftovers from a previous failed run
    for ele in firegex.nfregex_get_services():
        if ele["name"] == service_name:
            firegex.nfregex_delete_service(ele["service_id"])
    for s in firegex.tls_get_streams():
        if s["port"] in (port_a, port_b):
            firegex.tls_stop_stream(s["id"])
            firegex.tls_delete_stream(s["id"])

    # 1. Create
    cert_a, key_a = generate_self_signed_cert_key("localhost")
    stream_id = firegex.tls_add_stream("TLS CRUD Stream", host, port_a, cert_a, key_a)
    if stream_id:
        puts(f"Sucessfully created TLS stream {stream_id} ✔", color=colors.green)
    else:
        puts("Test Failed: Couldn't create TLS stream ✗", color=colors.red)
        exit_test(1)

    # 2. List / Get
    stream = firegex.tls_get_stream(stream_id)
    if stream and stream["ip_int"] and stream["port"] == port_a:
        puts("Sucessfully fetched the stream via GET /tls/streams ✔", color=colors.green)
    else:
        puts("Test Failed: Stream not found in listing ✗", color=colors.red)
        firegex.tls_delete_stream(stream_id)
        exit_test(1)

    # 3. Start + a real TLS handshake against the public ssl_port. The backend behind the
    # stream must itself speak TLS since nginx's clear_port leg always re-encrypts to it.
    backend_cert, backend_key = generate_self_signed_cert_key("127.0.0.1")
    backend = TcpServer(port_a, ipv6=args.ipv6, tls_cert=backend_cert, tls_key=backend_key)
    backend.start()
    time.sleep(0.5)

    if firegex.tls_start_stream(stream_id):
        puts("Sucessfully started TLS stream ✔", color=colors.green)
    else:
        puts("Test Failed: Couldn't start TLS stream ✗", color=colors.red)
        backend.stop()
        firegex.tls_delete_stream(stream_id)
        exit_test(1)

    ssl_port = firegex.tls_get_stream(stream_id)["ssl_port"]
    data = secrets.token_bytes(64)
    if tls_connect_send_recv(ssl_port, args.ipv6, data) == data:
        puts("Successfully performed a real TLS handshake and got the decrypted echo back ✔", color=colors.green)
    else:
        puts("Test Failed: TLS handshake / decrypt round-trip failed ✗", color=colors.red)
        backend.stop()
        firegex.tls_stop_stream(stream_id)
        firegex.tls_delete_stream(stream_id)
        exit_test(1)

    # 4. Create a dependent nfregex service linked to the stream
    service_id = firegex.nfregex_add_service(
        service_name, port_a, "tcp", host, target_type="tls", tls_stream_id=stream_id
    )
    if service_id:
        puts(f"Sucessfully created dependent nfregex service {service_id} ✔", color=colors.green)
    else:
        puts("Test Failed: Couldn't create dependent service ✗", color=colors.red)
        backend.stop()
        firegex.tls_stop_stream(stream_id)
        firegex.tls_delete_stream(stream_id)
        exit_test(1)

    # 5. The (fixed) delete-guard must now correctly reject deletion while in use
    if not firegex.tls_delete_stream(stream_id):
        puts("Correctly rejected deletion of a TLS stream still in use ✔", color=colors.green)
    else:
        puts("Test Failed: Deleting an in-use TLS stream should have failed ✗", color=colors.red)
        exit_test(1)

    # 6. Edit: move the stream to a new ip/port/cert and confirm the dependent service follows
    backend.stop()
    backend = TcpServer(port_b, ipv6=args.ipv6, tls_cert=backend_cert, tls_key=backend_key)
    backend.start()
    time.sleep(0.5)

    cert_b, key_b = generate_self_signed_cert_key("localhost")
    if firegex.tls_edit_stream(stream_id, ip_int=host, port=port_b, cert=cert_b, key=key_b):
        puts("Sucessfully edited the TLS stream's address/cert ✔", color=colors.green)
    else:
        puts("Test Failed: Couldn't edit the TLS stream ✗", color=colors.red)
        backend.stop()
        exit_test(1)

    time.sleep(1)
    updated_stream = firegex.tls_get_stream(stream_id)
    updated_service = firegex.nfregex_get_service(service_id)
    if updated_stream["port"] == port_b and updated_service["port"] == port_b:
        puts("The dependent service's mirrored ip/port followed the stream edit ✔", color=colors.green)
    else:
        puts("Test Failed: The dependent service wasn't kept in sync with the stream edit ✗", color=colors.red)
        exit_test(1)

    new_ssl_port = updated_stream["ssl_port"]
    data2 = secrets.token_bytes(64)
    if tls_connect_send_recv(new_ssl_port, args.ipv6, data2) == data2:
        puts("TLS decryption still works correctly at the new address/port after the edit ✔", color=colors.green)
    else:
        puts("Test Failed: TLS decryption broke after editing the stream's address ✗", color=colors.red)
        exit_test(1)

    # 7. Cascade: stopping the stream should stop the dependent service
    if firegex.tls_stop_stream(stream_id):
        time.sleep(1)
        if firegex.nfregex_get_service(service_id)["status"] == "stop":
            puts("Stopping the stream correctly cascaded to stop the dependent service ✔", color=colors.green)
        else:
            puts("Test Failed: Dependent service wasn't cascade-stopped ✗", color=colors.red)
            exit_test(1)
    else:
        puts("Test Failed: Couldn't stop the TLS stream ✗", color=colors.red)
        exit_test(1)

    # 8. Cascade: starting the dependent service should reactivate the stream
    if firegex.nfregex_start_service(service_id):
        time.sleep(1)
        if firegex.tls_get_stream(stream_id)["status"] == "active":
            puts("Starting the service correctly cascaded to reactivate the TLS stream ✔", color=colors.green)
        else:
            puts("Test Failed: TLS stream wasn't cascade-reactivated ✗", color=colors.red)
            exit_test(1)
    else:
        puts("Test Failed: Couldn't start the dependent service ✗", color=colors.red)
        exit_test(1)

    # Cleanup
    firegex.nfregex_delete_service(service_id)
    backend.stop()
    firegex.tls_stop_stream(stream_id)
    if firegex.tls_delete_stream(stream_id):
        puts("Sucessfully cleaned up TLS CRUD test ✔", color=colors.green)
    else:
        puts("Test Failed: Couldn't delete the TLS stream during cleanup ✗", color=colors.red)
        exit_test(1)

    exit_test(0)
