"""The rules firegex installs, and that it takes all of them back.

Every nftables object firegex creates is named `fgex_` and lives in a table firegex owns,
so one `grep fgex_` over the ruleset is the whole footprint. That matters because of what
it replaced: the firewall module used to write into the tables called `filter` and
`mangle` — the ones `iptables-nft` claims — which broke `iptables` on the host outright,
and whose `reset()` re-added `filter INPUT` with `policy accept`, silently removing an
administrator's default-deny.
"""

import time

import pytest

from integration.conftest import start_and_settle
from helpers.host import ruleset as _ruleset

pytestmark = [pytest.mark.instance, pytest.mark.root]


@pytest.fixture(autouse=True)
def needs_the_ruleset():
    if _ruleset() is None:
        pytest.skip("cannot read the nftables ruleset from here: not Linux, no root and no "
                    "passwordless sudo, or the instance under test is on another host")


def test_starting_a_service_installs_rules_and_stopping_takes_every_one_back(
        api, protected, inspecting_layer):
    """A rule left behind is not untidiness.

    It points traffic at a datapath that is no longer there, so the next service to want
    that port fails for a reason belonging to a service that was deleted.
    """
    service_id, _, port = protected(inspecting_layer, name="clean")

    before = [line for line in _ruleset().splitlines() if str(port) in line]
    assert before == [], f"a rule already mentioned port {port}: {before}"

    start_and_settle(api, service_id)
    during = [line for line in _ruleset().splitlines() if str(port) in line]
    assert during, f"starting the service installed no rule for port {port}"

    assert api.services_stop(service_id)
    time.sleep(0.8)
    after = [line for line in _ruleset().splitlines() if str(port) in line]
    assert after == [], f"rules leaked after the service stopped: {after}"


def test_everything_firegex_installs_is_named_for_it(api, protected, inspecting_layer):
    """One `grep fgex_` is the whole footprint, which is what makes it removable."""
    service_id, _, _ = protected(inspecting_layer, name="named")
    start_and_settle(api, service_id)

    chains = [line.strip() for line in _ruleset().splitlines()
              if line.strip().startswith("chain ")]
    assert chains, "the table has no chains at all"
    assert all(chain.split()[1].startswith("fgex_") for chain in chains), str(chains)


def test_stopping_a_hand_off_takes_back_its_return_rule_too(api, protected,
                                                            external_layer):
    """The hand-off installs two rules on two different ports, and both have to go.

    The inbound one matches the service's address and port; the return one matches the
    operator's proxy and **its** port, to put the original port back on the way out.
    Only the first was ever recognised again — the port was compared against the
    service's before the proxy's identity was considered — so every hand-off left its
    return rule installed when it stopped, rewriting the source of anything leaving that
    endpoint for a service that was no longer protected, and gained a second copy on the
    next start.
    """
    service_id, server, port = protected(external_layer, name="handoff-clean")
    proxy_port = server.external.port

    start_and_settle(api, service_id)
    during = [line for line in _ruleset().splitlines() if str(proxy_port) in line]
    assert during, f"starting the hand-off installed no return rule for port {proxy_port}"

    assert api.services_stop(service_id)
    time.sleep(0.8)
    for label, number in (("the service", port), ("the proxy endpoint", proxy_port)):
        left = [line for line in _ruleset().splitlines() if str(number) in line]
        assert left == [], f"rules for {label} ({number}) leaked after the stop: {left}"


def test_a_hand_off_restarted_does_not_accumulate_rules(api, protected, external_layer):
    """The other half of the same failure: a rule that is never taken back is installed
    again on the next start, so the ruleset grows by one on every restart."""
    service_id, server, _ = protected(external_layer, name="handoff-twice")
    proxy_port = server.external.port

    start_and_settle(api, service_id)
    first = len([line for line in _ruleset().splitlines() if str(proxy_port) in line])
    assert first, "no return rule was installed at all"

    assert api.services_stop(service_id)
    time.sleep(0.8)
    start_and_settle(api, service_id)
    second = len([line for line in _ruleset().splitlines() if str(proxy_port) in line])
    assert second == first, f"the ruleset grew from {first} to {second} rules on a restart"
