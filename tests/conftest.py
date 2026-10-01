"""One place that knows where the instance under test is, and what may be asked of it.

Before this, four scripts each grew their own `--address`/`--password` argparse block, a
fifth read the same two things out of the environment, and a shell script held the list
of which combinations to run. The combinations are the interesting part of this suite —
the same filters on both network layers, over IPv4 and IPv6, with and without TLS — and
they belong in the test code as parameters rather than in a shell loop, where nothing can
skip one that this host cannot carry.

Selection is by command line, so a developer can narrow to the case they are fixing:

    pytest                                    # everything this host can run
    pytest tests/unit                         # no instance needed
    pytest -m "not slow"                      # skip the ones that wait on timeouts
    pytest --layer proxy --no-ipv6            # one layer, one family
    pytest --fg-address http://box:4444/      # somewhere other than localhost
"""

import os
import sys

import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(TESTS_DIR, "..", "backend"))
LIB_DIR = os.path.abspath(os.path.join(TESTS_DIR, "..", "fgex-lib"))

# `tests/` first so `helpers` resolves here, and the backend after it. The two used to
# collide outright: this directory's package was called `utils`, which is also the name
# of the backend's, so whichever imported first won and the other module failed to
# collect. That is why these could not be run in one pytest process at all.
for path in (TESTS_DIR, LIB_DIR, BACKEND_DIR):
    if path not in sys.path:
        sys.path.append(path)
sys.path.insert(0, TESTS_DIR)

from helpers.firegexapi import FiregexAPI  # noqa: E402
from helpers.net import supports_ipv6  # noqa: E402


def pytest_addoption(parser):
    group = parser.getgroup("firegex")
    group.addoption("--fg-address", action="store",
                    default=os.getenv("FIREGEX_ADDRESS", "http://127.0.0.1:4444/"),
                    help="Where the instance under test is")
    group.addoption("--fg-password", action="store",
                    default=os.getenv("FIREGEX_PASSWORD", "testpassword"),
                    help="Its password")
    group.addoption("--layer", action="append", default=[],
                    choices=["proxy", "nfqueue", "external"],
                    help="Only these network layers (repeatable; default: all of them)")
    group.addoption("--no-ipv6", action="store_true", default=False,
                    help="Skip the IPv6 half of every parametrised case")
    group.addoption("--no-tls", action="store_true", default=False,
                    help="Skip the TLS cases")


def pytest_configure(config):
    for marker in (
        "instance: needs a running firegex to talk to",
        "root: needs root and a Linux kernel with nftables",
        "slow: waits on a real timeout and takes seconds to do it",
        "ipv6: exercises the IPv6 half",
        "tls: exercises TLS termination",
    ):
        config.addinivalue_line("markers", marker)


def pytest_collection_modifyitems(config, items):
    """Skip what this host or this invocation cannot carry, rather than failing it.

    A skip with a reason beats a red test nobody can act on: a laptop without IPv6 on
    loopback is not a firegex bug, and saying so in the summary line is more useful than
    a connection error inside an assertion.
    """
    wanted_layers = set(config.getoption("--layer"))
    no_ipv6 = config.getoption("--no-ipv6") or not supports_ipv6()
    no_ipv6_reason = ("--no-ipv6 was given" if config.getoption("--no-ipv6")
                      else "this host has no IPv6 loopback")
    no_tls = config.getoption("--no-tls")

    for item in items:
        if wanted_layers:
            layer = item.callspec.params.get("layer") if hasattr(item, "callspec") else None
            name = getattr(layer, "transport", None)
            if name and name not in wanted_layers:
                item.add_marker(pytest.mark.skip(reason=f"--layer did not ask for {name}"))
        if no_ipv6 and "ipv6" in item.keywords:
            item.add_marker(pytest.mark.skip(reason=no_ipv6_reason))
        if no_tls and "tls" in item.keywords:
            item.add_marker(pytest.mark.skip(reason="--no-tls was given"))


@pytest.fixture(scope="session")
def fg_address(pytestconfig) -> str:
    address = pytestconfig.getoption("--fg-address")
    return address if address.endswith("/") else address + "/"


@pytest.fixture(scope="session")
def fg_password(pytestconfig) -> str:
    return pytestconfig.getoption("--fg-password")


@pytest.fixture(scope="session")
def api(fg_address, fg_password) -> FiregexAPI:
    """A logged-in client, shared by everything that needs an instance.

    An instance started with `--unsafe-disable-auth` answers 403 to the login endpoint
    and accepts every request without a token — `login()` reads that as "there is nothing
    to log in to" rather than as a failure, which is what lets the whole suite run
    against the one configuration where every request is already allowed.
    """
    client = FiregexAPI(fg_address)
    if not client.login(fg_password):
        pytest.fail(
            f"Could not reach or authenticate to firegex at {fg_address}. "
            f"Start one with `python3 run.py start -P {fg_password}`, or point the suite "
            f"elsewhere with --fg-address."
        )
    return client


@pytest.fixture(scope="session")
def auth_enabled(api) -> bool:
    """Whether this instance asks for a password at all."""
    return not api.status().get("auth_disabled", False)
