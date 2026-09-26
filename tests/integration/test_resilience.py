"""What happens when a filter misbehaves, and who pays for it.

The trade is stated once and differs by layer. NFQUEUE has a kernel-guaranteed fail-open:
`NFQA_CFG_F_FAIL_OPEN` plus `bypass` on the nft rule mean the kernel keeps forwarding if
the filter process dies, with nothing in userspace involved in that decision. The proxy
rebuilds the same guarantee by hand — `catch_unwind`, a deadline on `spawn_blocking`, and
a filter that misbehaves losing its say rather than the traffic being held.
"""

import os
import signal
import subprocess
import time

import pytest

from integration import filter_code
from integration.conftest import add_python_filter, add_regex_filter, start_and_settle
from helpers.host import as_root, ruleset
from helpers.traffic import Channel

pytestmark = pytest.mark.instance


def test_an_exception_in_a_filter_fails_open(api, protected, inspecting_layer):
    """A filter that raises loses its say; the traffic is forwarded unfiltered.

    Holding the traffic instead would mean one bad filter taking a service off the air,
    which is the failure the whole fail-open design exists to avoid.
    """
    service_id, server, port = protected(inspecting_layer, name="raises")
    add_python_filter(api, service_id, filter_code.RAISES)
    start_and_settle(api, service_id)
    channel = Channel(server, port, inspecting_layer.ipv6)

    assert channel.gets_through(b"trigger CRASH_EXCEPTION here"), \
        "the traffic was dropped instead of failing open"


def test_an_exception_in_a_filter_says_the_traffic_went_through_unfiltered(
        api, protected, inspecting_layer):
    """Failing open silently would be the worse failure of the two.

    **The same sentence on both network layers**, which is the point of this test rather
    than a detail of it. NFQUEUE learns of the exception directly — the interpreter is
    embedded in the binary, which sends an `EXCEPTION` line. The proxy's worker is a
    separate process that catches the exception and answers with an ordinary ACCEPT, so
    nothing crosses the frame boundary to tell the engine apart from a filter that
    agreed; it marks the diagnostics channel instead and `_pump_stderr` turns that back
    into the same `_on_exception`.

    Without it the proxy said only what a traceback says — that a filter broke, and
    where. What an operator needs at three in the morning is the other half: that the
    connection went through unchecked.
    """
    service_id, server, port = protected(inspecting_layer, name="raiselog")
    add_python_filter(api, service_id, filter_code.RAISES)
    start_and_settle(api, service_id)
    channel = Channel(server, port, inspecting_layer.ipv6)

    channel.echo(b"trigger CRASH_EXCEPTION here")
    time.sleep(1.0)
    entries = api.services_logs(service_id)
    assert any("a filter raised" in e["text"] for e in entries), \
        f"no layer-independent report of the fail-open: {[e['text'] for e in entries[-6:]]}"


def test_the_log_still_carries_the_traceback_that_names_the_line(api, protected,
                                                                 proxy_layer):
    """The sentence says what happened to the traffic; the traceback says what to fix.

    Both, not one — the marker was added beside the traceback rather than instead of it.
    """
    service_id, server, port = protected(proxy_layer, name="raisetb")
    add_python_filter(api, service_id, filter_code.RAISES)
    start_and_settle(api, service_id)
    channel = Channel(server, port, proxy_layer.ipv6)

    channel.echo(b"trigger CRASH_EXCEPTION here")
    time.sleep(1.0)
    said = " ".join(e["text"] for e in api.services_logs(service_id)
                    if e["level"] == "error")
    assert "ZeroDivisionError" in said, said[-400:]
    assert "buggy" in said, "the traceback does not name the function that raised"


def test_a_filter_raising_on_every_packet_does_not_flush_the_log(api, protected,
                                                                 inspecting_layer):
    """The log is a bounded ring, so an unthrottled fault does not merely repeat itself.

    It evicts everything else — the first traceback, which was the one worth reading, and
    whatever was in the log before the filter broke. Both the traceback and the sentence
    beside it are rate-limited, and the suppressed ones are counted rather than dropped:
    "it is still happening, N more since" is what says whether this is one odd request or
    every request.
    """
    service_id, server, port = protected(inspecting_layer, name="flood")
    add_python_filter(api, service_id, filter_code.RAISES_ALWAYS)
    start_and_settle(api, service_id)
    channel = Channel(server, port, inspecting_layer.ipv6)

    for _ in range(25):
        channel.echo(b"make it raise again")
    time.sleep(1.5)

    entries = api.services_logs(service_id)
    raised = [e for e in entries if "a filter" in e["text"] and "rais" in e["text"]]
    assert raised, "25 exceptions and not one report of them"
    assert len(raised) <= 3, \
        f"the report was not rate-limited: {len(raised)} lines for 25 exceptions"

    tracebacks = [e for e in entries if "ValueError" in e["text"]]
    assert tracebacks, "the operator was never shown what went wrong"
    assert len(tracebacks) <= 3, \
        f"the traceback was not rate-limited: {len(tracebacks)} copies"

    assert any("started on the" in e["text"] for e in entries), \
        "the flood pushed the start of the service out of the log"


@pytest.mark.slow
def test_a_filter_that_hangs_is_cut_off_and_the_worker_comes_back(api, protected,
                                                                  proxy_layer):
    """The deadline on `spawn_blocking` is why a `while True:` in a filter cannot stall
    the datapath. What has to hold afterwards is that the *next* connection is filtered
    normally — a worker that is killed and not replaced is a service that has quietly
    stopped inspecting anything."""
    service_id, server, port = protected(proxy_layer, name="hangs")
    add_python_filter(api, service_id, filter_code.HANGS)
    start_and_settle(api, service_id)
    channel = Channel(server, port, proxy_layer.ipv6)

    channel.echo(b"trigger HANG_ME now")
    time.sleep(1.0)
    assert channel.gets_through(b"NORMAL_BENIGN_DATA"), \
        "the worker did not recover after a filter hung"


def test_a_filter_that_takes_the_interpreter_down_does_not_take_the_engine(
        api, protected, proxy_layer):
    """The worker is a separate process for exactly this.

    `panic = "unwind"` in Cargo.toml is load-bearing rather than tuning, and the worker
    dying is a worker being replaced rather than a datapath going away.
    """
    service_id, server, port = protected(proxy_layer, name="segv")
    add_python_filter(api, service_id, filter_code.SEGFAULTS)
    start_and_settle(api, service_id)
    channel = Channel(server, port, proxy_layer.ipv6)

    channel.echo(b"trigger SEGFAULT_TRIGGER")
    time.sleep(1.0)
    assert channel.gets_through(b"POST_SEGV_PING"), \
        "the proxy datapath died with its worker"


@pytest.mark.root
def test_the_kernel_keeps_forwarding_when_a_queued_filter_dies(api, protected,
                                                               inspecting_layer):
    """The NFQUEUE layer's one distinguishing property, and the reason to choose it.

    Nothing in userspace decides this: `NFQA_CFG_F_FAIL_OPEN` plus `bypass` on the rule
    mean that a queue with nobody reading it is a queue the kernel walks past. Killing the
    binary is the only honest way to test it.
    """
    if inspecting_layer.transport != "nfqueue":
        pytest.skip("this is the queued layer's guarantee")

    service_id, server, port = protected(inspecting_layer, name="failopen")
    add_regex_filter(api, service_id, "BLOCK_ME_NFQ")
    start_and_settle(api, service_id)
    channel = Channel(server, port, inspecting_layer.ipv6)
    assert channel.gets_through(b"harmless"), "the service was not working to begin with"
    assert channel.is_blocked(b"carrying BLOCK_ME_NFQ"), "it was not filtering to begin with"

    found = subprocess.run(["pgrep", "-f", "cppregex"], capture_output=True, text=True)
    pids = [int(p) for p in found.stdout.split() if p.isdigit()]
    if not pids:
        pytest.skip("no cppregex process to kill; is this instance running elsewhere?")
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    time.sleep(1.0)

    assert channel.gets_through(b"traffic after the binary was killed"), \
        "the kernel stopped forwarding when the filter died"


@pytest.mark.root
def test_rules_removed_from_under_firegex_are_put_back_and_said(api, protected,
                                                                 inspecting_layer):
    """Something else managing the host's nftables must not quietly switch firegex off.

    `nft -f /etc/nftables.conf` begins with `flush ruleset` on Debian, and so does
    restarting its unit. Every service went on reading ACTIVE with nothing reaching a
    filter, and nothing said so. They are put back within a few seconds now — the
    datapath never stopped, so nothing restarts — and the service's log says what
    happened, as an error, because traffic went through unfiltered in between.
    """
    service_id, server, port = protected(inspecting_layer, name="flushed")
    add_regex_filter(api, service_id, "BLOCKME")
    start_and_settle(api, service_id)
    channel = Channel(server, port, inspecting_layer.ipv6)
    assert channel.is_blocked(b"carrying BLOCKME"), "it was not filtering to begin with"

    if as_root("nft", "delete", "table", "inet", "fgex") is None:
        pytest.skip("cannot remove the table from here")
    deadline = time.time() + 10
    while f"dport {port}" not in (ruleset() or "") and time.time() < deadline:
        time.sleep(0.5)

    assert channel.gets_through(b"harmless"), "the service stopped answering"
    assert channel.is_blocked(b"carrying BLOCKME"), "the rules were not put back"
    said = [e for e in api.services_logs(service_id)
            if e["level"] == "error" and "removed from the kernel" in e["text"]]
    assert said, "the rules were put back without a word about the gap"
