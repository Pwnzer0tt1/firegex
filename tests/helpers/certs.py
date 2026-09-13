"""Certificates for the TLS tests, generated in-process.

No `openssl` shelling out and no fixture files: a checked-in certificate expires, and the
morning it does every TLS test fails for a reason that has nothing to do with firegex.

`key_size` and the non-RSA generators are parameters rather than conveniences. The engine
refuses a key its signing backend will not sign with — RSA under 2048 bits — and that
refusal is something to test, so the suite has to be able to produce one. The others are
here because rustls accepts them and an operator will eventually bring one.
"""

import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID


def _build(key, hash_algorithm, common_name: str) -> tuple[str, str]:
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        # A day of slack at the front: a container whose clock is a little behind the
        # host would otherwise reject a certificate minted a moment ago.
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    # The SAN has to name the address the test actually dials. It used to be hardcoded
    # to 127.0.0.1, so an IPv6 run presented a certificate for an address nobody in that
    # run was talking to.
    try:
        alt = x509.IPAddress(ipaddress.ip_address(common_name))
    except ValueError:
        alt = x509.DNSName(common_name)
    builder = builder.add_extension(x509.SubjectAlternativeName([alt]), critical=False)
    cert = builder.sign(key, hash_algorithm)
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


def rsa_cert(common_name: str = "127.0.0.1", key_size: int = 2048) -> tuple[str, str]:
    return _build(rsa.generate_private_key(public_exponent=65537, key_size=key_size),
                  hashes.SHA256(), common_name)


def ecdsa_cert(common_name: str = "127.0.0.1", curve: str = "secp256r1") -> tuple[str, str]:
    chosen = ec.SECP384R1() if curve == "secp384r1" else ec.SECP256R1()
    return _build(ec.generate_private_key(chosen), hashes.SHA256(), common_name)


def ed25519_cert(common_name: str = "127.0.0.1") -> tuple[str, str]:
    return _build(ed25519.Ed25519PrivateKey.generate(), None, common_name)


#: Material whose envelope is right and whose body will not parse. The only way to get
#: a service past the backend's own check and as far as the engine, which is where the
#: refusal being tested comes from.
UNPARSEABLE_CERT = "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"
UNPARSEABLE_KEY = "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n"
