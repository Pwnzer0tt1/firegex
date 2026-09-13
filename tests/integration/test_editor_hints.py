"""What the filter editor is allowed to suggest.

Introspected from the library rather than written down, so a model that gains a property
gains a hint. A second, hand-written description would be wrong the first time a model
changed, and autocompletion that lies is worse than none.
"""

import pytest

pytestmark = pytest.mark.instance


@pytest.fixture(scope="module")
def described(api):
    return api.services_pyfilter_api()


def test_the_library_describes_its_own_models(described):
    names = {model["name"] for model in described["models"]}
    assert {"RawPacket", "HttpRequest", "TCPInputStream"} <= names, str(sorted(names))


def test_a_raw_packet_offers_the_metadata_a_filter_may_read(described):
    raw = [m for m in described["models"] if m["name"] == "RawPacket"][0]
    members = {m["name"] for m in raw["members"]}
    assert {"client_ip", "server_port", "is_tcp", "is_input"} <= members, str(sorted(members))


def test_only_the_payload_is_writable(described):
    """Nothing below the application layer crosses into a filter.

    The two layers cannot honestly offer the same thing underneath it — NFQUEUE has a
    real header whose rewriting desynchronises the stream, while the proxy terminated the
    connection and writes its own — so metadata in, payload out is the one contract both
    keep. The old model papered over that by handing the proxy a literal
    `FAKE:IP:TCP:HEADERS:` prefix, so the same filter did different things depending on
    where it was attached.
    """
    raw = [m for m in described["models"] if m["name"] == "RawPacket"][0]
    members = {m["name"]: m for m in raw["members"]}
    assert members["data"]["writable"] is True
    assert members["client_ip"]["writable"] is False
    writable = [name for name, member in members.items() if member["writable"]]
    assert writable == ["data"], str(writable)


def test_each_model_says_which_protocols_it_belongs_to(described):
    """`type_annotations_associations` is the single place a protocol is defined, and this
    endpoint reads that same table back — a second list of names would be one more thing
    to keep in step, and the day it fell behind the symptom would be a filter that
    silently never runs."""
    http_request = [m for m in described["models"] if m["name"] == "HttpRequest"][0]
    raw = [m for m in described["models"] if m["name"] == "RawPacket"][0]
    assert http_request["protocols"] == ["http"], str(http_request["protocols"])
    assert len(raw["protocols"]) > 1, str(raw["protocols"])


def test_the_verdicts_are_described_too(described):
    assert {v["name"] for v in described["verdicts"]} == {"ACCEPT", "REJECT", "DROP"}, \
        str(described["verdicts"])
