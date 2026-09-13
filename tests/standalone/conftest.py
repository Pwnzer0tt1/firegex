"""Tests that restart the instance they are testing.

Some settings are read **once**, at process startup — the IP allowlist, the proxy header
it trusts, whether authentication is asked for at boot — so there is no way to exercise
them against a running instance. These drive `run.py stop`/`start` themselves for each
scenario, which is why they are not collected by default (`pytest.ini`'s `testpaths` does
not include this directory) and have to be asked for by name:

    pytest standalone

Expect them to bounce whatever firegex you have running, and to leave an unrestricted one
behind at the end. They have to run on the same host firegex runs on, with whatever
`run.py` itself needs.
"""

import os
import subprocess
import time

import pytest
import requests

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BASE = "http://127.0.0.1:4444/"
PASSWORD = "testpassword"


def run_py(*args, timeout=180) -> int:
    return subprocess.run(["python3", "run.py", *args], cwd=REPO_ROOT,
                          timeout=timeout).returncode


def wait_ready(timeout: float = 90) -> bool:
    """A 403 counts as ready: it means the app answered, unlike a connection error.

    `/api/status` is the endpoint being probed, and under a restrictive allowlist the
    correct answer to it *is* a refusal.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(BASE + "api/status", timeout=2).status_code in (200, 403):
                return True
        except requests.RequestException:
            pass
        time.sleep(1)
    return False


@pytest.fixture(scope="module")
def restart():
    """Bring firegex up with a given configuration, and leave an unrestricted one behind.

    The cleanup is not tidiness: every other test module in this suite assumes it can
    reach the instance from loopback with a password, and a run that stopped halfway
    through a restrictive scenario would break all of them.
    """
    def _restart(allowed_ips=None, proxy_ip_header=None, unsafe_disable_auth=None):
        run_py("stop")
        args = ["start", "-P", PASSWORD]
        # An empty string still has to be passed explicitly, to clear a previous value.
        if allowed_ips is not None:
            args += ["--allowed-ips", allowed_ips]
        if proxy_ip_header is not None:
            args += ["--proxy-ip-header", proxy_ip_header]
        if unsafe_disable_auth is not None:
            args += ["--unsafe-disable-auth" if unsafe_disable_auth
                     else "--no-unsafe-disable-auth"]
        run_py(*args)
        assert wait_ready(), "firegex did not come back up after the restart"

    yield _restart

    _restart(allowed_ips="", unsafe_disable_auth=False)


@pytest.fixture(scope="session", autouse=True)
def only_on_the_host_that_runs_it():
    if not os.path.isfile(os.path.join(REPO_ROOT, "run.py")):
        pytest.skip("these have to run from a clone, on the host firegex runs on")
