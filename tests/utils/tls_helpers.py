import datetime
import ipaddress
import socket
import ssl
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_self_signed_cert_key(common_name: str = "127.0.0.1") -> tuple[str, str]:
    """Generates a self-signed X.509 certificate and RSA private key in 100% pure Python using cryptography."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode("utf-8")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return cert_pem, key_pem

def send_decrypted_http_request(port: int, ipv6: bool, path: str = "/secret-tls-check") -> bytes | None:
    """Sends a sample HTTP request to a target port and returns received response bytes."""
    sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect(("::1" if ipv6 else "127.0.0.1", port))
        http_payload = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Firegex-TLSTest\r\n\r\n".encode()
        sock.sendall(http_payload)
        data = sock.recv(4096)
        sock.close()
        return data
    except Exception:
        return None

def tls_connect_send_recv(port: int, ipv6: bool, data: bytes, timeout: float = 3.0) -> bytes | None:
    """Performs a real TLS handshake against a stream's public ssl_port (trusting any
    self-signed cert), sends raw bytes and returns the raw response, or None if the
    connection was refused/reset/timed out (e.g. because a filter blocked it)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    host = "::1" if ipv6 else "127.0.0.1"
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock) as tls_sock:
                tls_sock.sendall(data)
                tls_sock.settimeout(timeout)
                try:
                    return tls_sock.recv(65536)
                except socket.timeout:
                    return b""
    except (OSError, ssl.SSLError):
        return None
