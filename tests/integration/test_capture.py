"""The interface the decrypted traffic is written to.

Terminating TLS in-process means the plaintext is never a packet, so the engine frames it
as the TCP stream it was and sends it to `firegex0`: one interface carrying every TLS
service's plaintext and nothing else, which is what a capture tool wants pointed at it.

**These are reconstructed packets.** The bytes are real — what the filters saw and what
was forwarded — but the framing is invented, because the framing on the wire was
encrypted. Sequence numbers start at zero, there are no retransmissions, and the
segmentation is the engine's read sizes.
"""

import secrets
import subprocess

import pytest

from integration.conftest import start_and_settle
from helpers.tls_helpers import capture_device_present, capture_on, tls_connect_send_recv

pytestmark = [pytest.mark.instance, pytest.mark.root]


@pytest.fixture(autouse=True)
def needs_the_device():
    if not capture_device_present():
        pytest.skip("firegex0 is not here: either this instance is running elsewhere, or "
                    "the host would not grant CAP_NET_RAW — in which case the capture is "
                    "lost and the firewall is not")


def test_the_capture_interface_is_up_for_a_tool_to_be_pointed_at(needs_the_device):
    """It is the instance's device, not each TLS service's.

    It used to come and go with the services, on the argument that an interface present
    while nothing is decrypting is one somebody watches stay empty. But a capture tool is
    attached once, for a round, and Zeek and Suricata exit rather than wait when the
    interface under them disappears — which restarting a single TLS service was enough to
    cause. Watching it stay empty is the better failure.
    """
    shown = subprocess.run(["ip", "link", "show", "firegex0"],
                           capture_output=True, text=True)
    assert shown.returncode == 0
    assert "UP" in shown.stdout, shown.stdout


def test_the_decrypted_stream_reaches_it(api, protected, certificate):
    from integration.conftest import Layer

    layer = Layer("proxy", tls=True)
    service_id, _, port = protected(layer, name="capture")
    start_and_settle(api, service_id)

    secret = f"PLAINTEXT_SECRET_{secrets.token_hex(6)}".encode()
    seen = capture_on("firegex0", 4.0,
                      lambda: tls_connect_send_recv(port, False, secret))
    assert secret in seen, repr(seen[-300:])
