"""The rules firegex installs, and that it takes all of them back.

Every nftables object firegex creates is named `fgex_` and lives in a table firegex owns,
so one `grep fgex_` over the ruleset is the whole footprint. That matters because of what
it replaced: the firewall module used to write into the tables called `filter` and
`mangle` — the ones `iptables-nft` claims — which broke `iptables` on the host outright,
and whose `reset()` re-added `filter INPUT` with `policy accept`, silently removing an
administrator's default-deny.
"""

import subprocess
import time

import pytest

from integration.conftest import start_and_settle

pytestmark = [pytest.mark.instance, pytest.mark.root]


def _ruleset() -> str | None:
    """The services module's table, or `None` where it cannot be read from here.

    Tried directly and then through `sudo -n`, because reading the ruleset needs root and
    the suite does not: a developer with passwordless sudo gets these checks, and one
    without gets a skip rather than a failure about a permission the tests never asked
    anyone for.
    """
    for command in (["nft"], ["sudo", "-n", "nft"]):
        try:
            shown = subprocess.run(command + ["list", "table", "inet", "fgex"],
                                   capture_output=True, text=True)
        except FileNotFoundError:
            return None
        if shown.returncode == 0:
            return shown.stdout
    return None


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
