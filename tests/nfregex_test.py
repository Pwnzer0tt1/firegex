#!/usr/bin/env python3
from utils.colors import colors, puts, sep
from utils.firegexapi import FiregexAPI
from utils.tcpserver import TcpServer
from utils.udpserver import UdpServer
from utils.tls_helpers import generate_self_signed_cert_key, tls_connect_send_recv
import argparse
import secrets
import base64
import time

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--address",
        "-a",
        type=str,
        required=False,
        help="Address of firegex backend",
        default="http://127.0.0.1:4444/",
    )
    parser.add_argument(
        "--password", "-p", type=str, required=True, help="Firegex password"
    )
    parser.add_argument(
        "--service_name",
        "-n",
        type=str,
        required=False,
        help="Name of the test service",
        default="Test Service",
    )
    parser.add_argument(
        "--port",
        "-P",
        type=int,
        required=False,
        help="Port of the test service",
        default=1337,
    )
    parser.add_argument(
        "--ipv6", "-6", action="store_true", help="Test Ipv6", default=False
    )
    parser.add_argument(
        "--proto",
        "-m",
        type=str,
        required=False,
        choices=["tcp", "udp"],
        help="Select the protocol",
        default="tcp",
    )
    parser.add_argument(
        "--tls", "-t", action="store_true", help="Test TLS Decrypt", default=False
    )

    args = parser.parse_args()
    if args.tls and args.proto != "tcp":
        puts("TLS is only supported with TCP protocol.", color=colors.red)
        exit(1)
        
    sep()
    puts("Testing will start on ", color=colors.cyan, end="")
    puts(f"{args.address}", color=colors.yellow)

    firegex = FiregexAPI(args.address)

    status = firegex.status()
    if status.get("status") == "init":
        firegex.set_password(args.password)

    # Login
    if firegex.login(args.password):
        puts("Sucessfully logged in ✔", color=colors.green)
    else:
        puts("Test Failed: Unknown response or wrong passowrd ✗", color=colors.red)
        exit(1)

    # Create server. When testing TLS, the backend itself must also speak TLS: nginx's
    # loopback clear_port leg always re-encrypts before forwarding to the real destination
    # (this mirrors a CTF challenge service that natively speaks TLS).
    backend_cert, backend_key = generate_self_signed_cert_key("127.0.0.1") if args.tls else (None, None)
    server = (TcpServer if args.proto == "tcp" else UdpServer)(
        args.port, ipv6=args.ipv6, **({"tls_cert": backend_cert, "tls_key": backend_key} if args.tls else {})
    )

    tls_stream_id = None
    tls_ssl_port = None
    service_id = None
    def exit_test(code):
        if service_id:
            server.stop()
            if firegex.nfregex_delete_service(service_id):
                puts("Sucessfully deleted service ✔", color=colors.green)
            else:
                puts("Test Failed: Coulnd't delete serivce ✗", color=colors.red)
                exit(1)
        if tls_stream_id:
            firegex.tls_stop_stream(tls_stream_id)
            if firegex.tls_delete_stream(tls_stream_id):
                puts("Sucessfully deleted TLS stream ✔", color=colors.green)
            else:
                puts("Test Failed: Couldn't delete TLS stream ✗", color=colors.red)
                exit(1)
        exit(code)

    srvs = firegex.nfregex_get_services()
    for ele in srvs:
        if ele["name"] == args.service_name:
            firegex.nfregex_delete_service(ele["service_id"])

    if args.tls:
        streams = firegex.tls_get_streams()
        for s in streams:
            if s["port"] == args.port:
                firegex.tls_stop_stream(s["id"])
                firegex.tls_delete_stream(s["id"])

        cert, key = generate_self_signed_cert_key("localhost")
        tls_stream_id = firegex.tls_add_stream("TLS Stream", "::1" if args.ipv6 else "127.0.0.1", args.port, cert, key)
        if tls_stream_id:
            puts(f"Sucessfully created TLS stream {tls_stream_id} ✔", color=colors.green)
        else:
            puts("Test Failed: Failed to create TLS stream ✗", color=colors.red)
            exit_test(1)

        if firegex.tls_start_stream(tls_stream_id):
            puts("Sucessfully started TLS stream ✔", color=colors.green)
        else:
            puts("Test Failed: Failed to start TLS stream ✗", color=colors.red)
            exit_test(1)

        tls_ssl_port = firegex.tls_get_stream(tls_stream_id)["ssl_port"]

    service_id = firegex.nfregex_add_service(
        args.service_name, args.port, args.proto, "::1" if args.ipv6 else "127.0.0.1",
        target_type="tls" if args.tls else "flow",
        tls_stream_id=tls_stream_id if args.tls else None
    )
    if service_id:
        puts(f"Sucessfully created service {service_id} ✔", color=colors.green)
    else:
        puts("Test Failed: Failed to create service ✗", color=colors.red)
        exit(1)

    if firegex.nfregex_start_service(service_id):
        puts("Sucessfully started service ✔", color=colors.green)
    else:
        puts("Test Failed: Failed to start service ✗", color=colors.red)
        exit_test(1)

    server.start()
    time.sleep(0.5)

    def send_check(data):
        """Sends data and checks it was echoed back unmodified. When testing TLS,
        routes through a real TLS handshake against the stream's public ssl_port
        (so the check actually exercises decrypt -> filter -> re-encrypt), instead
        of talking to the backend directly."""
        if args.tls:
            return tls_connect_send_recv(tls_ssl_port, args.ipv6, data) == data
        return server.sendCheckData(data)

    try:
        if send_check(secrets.token_bytes(432)):
            puts("Successfully tested first proxy with no regex ✔", color=colors.green)
        else:
            puts("Test Failed: Data was corrupted ", color=colors.red)
            exit_test(1)
    except Exception:
        puts("Test Failed: Couldn't send data to the server ", color=colors.red)
        exit_test(1)
    # Add new regex
    secret = bytes(secrets.token_hex(16).encode())

    if firegex.nfregex_add_regex(
        service_id, secret, "B", active=True, is_case_sensitive=True
    ):
        puts(f"Sucessfully added regex {str(secret)} ✔", color=colors.green)
    else:
        puts(f"Test Failed: Couldn't add the regex {str(secret)} ✗", color=colors.red)
        exit_test(1)



    # Check if regex is present in the service
    n_blocked = 0

    def getMetric(metric_name, regex):
        for metric in firegex.nfregex_get_metrics().split("\n"):
            if metric.startswith(metric_name + "{") and f'regex="{regex}"' in metric:
                return int(metric.split(" ")[-1])

    def checkRegex(regex, should_work=True, upper=False, deleted=False):
        if should_work:
            global n_blocked
            for r in firegex.nfregex_get_service_regexes(service_id):
                if r["regex"] == secret:
                    # Test the regex
                    s = regex.upper() if upper else regex
                    if not send_check(
                        secrets.token_bytes(40) + s + secrets.token_bytes(40)
                    ):
                        puts(
                            "The malicious request was successfully blocked ✔",
                            color=colors.green,
                        )
                        n_blocked += 1
                        time.sleep(1)
                        if firegex.nfregex_get_regex(r["id"])["n_packets"] == n_blocked:
                            puts(
                                "The packet was reported as blocked in the API ✔",
                                color=colors.green,
                            )
                        else:
                            puts(
                                "Test Failed: The packet wasn't reported as blocked in the API ✗",
                                color=colors.red,
                            )
                            exit_test(1)
                        if (
                            getMetric("firegex_blocked_packets", secret.decode())
                            == n_blocked
                        ):
                            puts(
                                "The packet was reported as blocked in the metrics ✔",
                                color=colors.green,
                            )
                        else:
                            puts(
                                "Test Failed: The packet wasn't reported as blocked in the metrics ✗",
                                color=colors.red,
                            )
                            exit_test(1)
                        if getMetric("firegex_active", secret.decode()) == 1:
                            puts(
                                "The regex was reported as active in the metrics ✔",
                                color=colors.green,
                            )
                        else:
                            puts(
                                "Test Failed: The regex wasn't reported as active in the metrics ✗",
                                color=colors.red,
                            )
                            exit_test(1)
                    else:
                        puts(
                            "Test Failed: The request wasn't blocked ✗",
                            color=colors.red,
                        )
                        exit_test(1)
                    return
            puts("Test Failed: The regex wasn't found ✗", color=colors.red)
            exit_test(1)
        else:
            if send_check(
                secrets.token_bytes(40)
                + base64.b64decode(regex)
                + secrets.token_bytes(40)
            ):
                puts("The request wasn't blocked ✔", color=colors.green)
            else:
                puts(
                    "Test Failed: The request was blocked when it shouldn't have",
                    color=colors.red,
                )
                exit_test(1)
            if not deleted:
                if getMetric("firegex_active", secret.decode()) == 0:
                    puts(
                        "The regex was reported as inactive in the metrics ✔",
                        color=colors.green,
                    )
                else:
                    puts(
                        "Test Failed: The regex wasn't reported as inactive in the metrics ✗",
                        color=colors.red,
                    )
                    exit_test(1)

    def clear_regexes():
        global n_blocked
        n_blocked = 0
        for r in firegex.nfregex_get_service_regexes(service_id):
            if r["regex"] == secret:
                if firegex.nfregex_delete_regex(r["id"]):
                    puts(
                        f"Sucessfully deleted regex with id {r['id']} ✔",
                        color=colors.green,
                    )
                else:
                    puts("Test Failed: Coulnd't delete the regex ✗", color=colors.red)
                    exit_test(1)
                break
        if f'regex="{secret.decode()}"' not in firegex.nfregex_get_metrics():
            puts("No regex metrics after deletion ✔", color=colors.green)
        else:
            puts(
                "Test Failed: Metrics found after deleting the regex ✗",
                color=colors.red,
            )
            exit_test(1)

    checkRegex(secret)

    # Pause the proxy
    if firegex.nfregex_stop_service(service_id):
        puts(f"Sucessfully paused service with id {service_id} ✔", color=colors.green)
    else:
        puts("Test Failed: Coulnd't pause the service ✗", color=colors.red)
        exit_test(1)

    # Check if it's actually paused
    checkRegex(secret, should_work=False)

    # Start firewall
    if firegex.nfregex_start_service(service_id):
        puts(f"Sucessfully started service with id {service_id} ✔", color=colors.green)
    else:
        puts("Test Failed: Coulnd't start the service ✗", color=colors.red)
        exit_test(1)

    checkRegex(secret)

    # Disable regex
    for r in firegex.nfregex_get_service_regexes(service_id):
        if r["regex"] == secret:
            if firegex.nfregex_disable_regex(r["id"]):
                puts(
                    f"Sucessfully disabled regex with id {r['id']} ✔",
                    color=colors.green,
                )
            else:
                puts("Test Failed: Coulnd't disable the regex ✗", color=colors.red)
                exit_test(1)
            break

    # Check if it's actually disabled
    checkRegex(secret, should_work=False)

    # Enable regex
    for r in firegex.nfregex_get_service_regexes(service_id):
        if r["regex"] == secret:
            if firegex.nfregex_enable_regex(r["id"]):
                puts(
                    f"Sucessfully enabled regex with id {r['id']} ✔", color=colors.green
                )
            else:
                puts("Test Failed: Coulnd't enable the regex ✗", color=colors.red)
                exit_test(1)
            break

    checkRegex(secret)

    # Delete regex
    clear_regexes()

    # Check if it's actually deleted
    checkRegex(secret, should_work=False, deleted=True)

    # Add case insensitive regex
    if firegex.nfregex_add_regex(
        service_id, secret, "B", active=True, is_case_sensitive=False
    ):
        puts(
            f"Sucessfully added case insensitive regex {str(secret)} ✔",
            color=colors.green,
        )
    else:
        puts(
            f"Test Failed: Coulnd't add the case insensitive regex {str(secret)} ✗",
            color=colors.red,
        )
        exit_test(1)

    checkRegex(secret, upper=True)
    checkRegex(secret)

    clear_regexes()

    # Rename service
    if firegex.nfregex_rename_service(service_id, f"{args.service_name}2"):
        puts(
            f"Sucessfully renamed service to {args.service_name}2 ✔", color=colors.green
        )
    else:
        puts("Test Failed: Coulnd't rename service ✗", color=colors.red)
        exit_test(1)

    # Check if service was renamed correctly
    service = firegex.nfregex_get_service(service_id)
    if service["name"] == f"{args.service_name}2":
        puts("Checked that service was renamed correctly  ✔", color=colors.green)
    else:
        puts("Test Failed: Service wasn't renamed correctly ✗", color=colors.red)
        exit_test(1)

    # Rename back service
    if firegex.nfregex_rename_service(service_id, f"{args.service_name}"):
        puts(
            f"Sucessfully renamed service to {args.service_name} ✔", color=colors.green
        )
    else:
        puts("Test Failed: Coulnd't rename service ✗", color=colors.red)
        exit_test(1)

    # Change settings (skipped in --tls mode: the service's own port/ip/proto no longer
    # drive traffic interception once linked to a TLS stream, see resolve_target())
    if not args.tls:
        opposite_proto = "udp" if args.proto == "tcp" else "tcp"
        if firegex.nfregex_settings_service(
            service_id,
            1338,
            "::dead:beef" if args.ipv6 else "123.123.123.123",
            True,
            proto=opposite_proto,
        ):
            srv_updated = firegex.nfregex_get_service(service_id)
            if (
                srv_updated["port"] == 1338
                and srv_updated["proto"] == opposite_proto
                and ("::dead:beef" if args.ipv6 else "123.123.123.123")
                in srv_updated["ip_int"]
                and srv_updated["fail_open"]
            ):
                puts("Sucessfully changed service settings ✔", color=colors.green)
            else:
                puts(
                    "Test Failed: Service settings weren't updated correctly ✗",
                    color=colors.red,
                )
                exit_test(1)
        else:
            puts("Test Failed: Coulnd't change service settings ✗", color=colors.red)
            exit_test(1)

    if args.tls:
        # Stopping the TLS stream should cascade-stop the dependent service
        if firegex.tls_stop_stream(tls_stream_id):
            time.sleep(1)
            srv_after_stop = firegex.nfregex_get_service(service_id)
            if srv_after_stop["status"] == "stop":
                puts("TLS stream stop correctly cascaded to stop the dependent service ✔", color=colors.green)
            else:
                puts("Test Failed: Dependent service wasn't cascade-stopped ✗", color=colors.red)
                exit_test(1)
        else:
            puts("Test Failed: Coulnd't stop the TLS stream ✗", color=colors.red)
            exit_test(1)

        # Starting the dependent service should cascade-reactivate the TLS stream
        if firegex.nfregex_start_service(service_id):
            time.sleep(1)
            stream_after_start = firegex.tls_get_stream(tls_stream_id)
            if stream_after_start["status"] == "active":
                puts("Starting the service correctly cascaded to reactivate the TLS stream ✔", color=colors.green)
            else:
                puts("Test Failed: TLS stream wasn't cascade-reactivated ✗", color=colors.red)
                exit_test(1)
        else:
            puts("Test Failed: Coulnd't start the service ✗", color=colors.red)
            exit_test(1)

        if send_check(secrets.token_bytes(64)):
            puts("Traffic flows correctly after the cascade reactivation ✔", color=colors.green)
        else:
            puts("Test Failed: Traffic didn't flow correctly after the cascade reactivation ✗", color=colors.red)
            exit_test(1)

        # Deleting a still-referenced TLS stream must be rejected
        if not firegex.tls_delete_stream(tls_stream_id):
            puts("Correctly rejected deletion of a TLS stream still in use ✔", color=colors.green)
        else:
            puts("Test Failed: Deleting an in-use TLS stream should have failed ✗", color=colors.red)
            exit_test(1)

    exit_test(0)
