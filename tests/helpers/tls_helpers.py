"""Talking to a service firegex is decrypting.

Certificates are minted in `helpers.certs`; this is only the client side.
"""

import socket
import ssl
import subprocess
import time


def tls_connect_send_recv(port: int, ipv6: bool, data: bytes, timeout: float = 3.0,
                          weak_ciphers: bool = False, then: bytes | None = None,
                          pause: float = 0.0) -> bytes | None:
    """Performs a real TLS handshake against a stream's public ssl_port (trusting any
    self-signed cert), sends raw bytes and returns the raw response, or None if the
    connection was refused/reset/timed out (e.g. because a filter blocked it).

    `weak_ciphers` lowers the *client's* security level, which is needed to talk to a
    service presenting an under-2048-bit key: the distribution's crypto policy applies to
    this side of the connection too.

    `then` sends a second payload after `pause` seconds on the same session, which is two
    TLS records rather than one — the way to split a pattern across two writes through a
    connection that is being decrypted.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if weak_ciphers:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    host = "::1" if ipv6 else "127.0.0.1"
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock) as tls_sock:
                tls_sock.sendall(data)
                if then is not None:
                    time.sleep(pause)
                    tls_sock.sendall(then)
                tls_sock.settimeout(timeout)
                try:
                    return tls_sock.recv(65536)
                except socket.timeout:
                    return b""
    except (OSError, ssl.SSLError):
        return None


def capture_device_present() -> bool:
    """Whether the capture interface exists to be read.

    Firegex puts it there for as long as it is running, and leaves the traffic alone
    where it cannot — on a host that will not grant `CAP_NET_RAW`, or one where these
    tests are pointed at an instance somewhere else. So a test for it has to be able to
    say "not here" rather than fail.
    """
    return subprocess.run(["ip", "link", "show", "firegex0"],
                          capture_output=True).returncode == 0


def capture_on(device: str, seconds: float, during) -> bytes:
    """Run `during` while capturing `device`, and hand back what was seen."""
    cap = subprocess.Popen(["tcpdump", "-i", device, "-A", "-l", "-n", "-s", "0"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    time.sleep(seconds / 2)
    try:
        during()
    finally:
        time.sleep(seconds / 2)
        cap.terminate()
    return cap.stdout.read() or b""


def tls_alpn_choice(port: int, ipv6: bool, offer: list[str], timeout: float = 5.0):
    """What protocol a client offering `offer` ends up speaking, or `None`.

    The interesting answer is often `None`: firegex reports what the *service* chose, so
    a client asking for something the service does not speak is told nothing rather than
    being told yes by the thing in the middle.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(offer)
    host = "::1" if ipv6 else "127.0.0.1"
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw) as tls:
                return tls.selected_alpn_protocol()
    except (OSError, ssl.SSLError) as e:
        return f"failed: {type(e).__name__}: {e}"
