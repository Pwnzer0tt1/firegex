"""`pyworker.py --check`, which is what decides whether a filter can be saved.

The contract is one JSON object on stdout and nothing else, so that the backend never
has to guess which part of the output was the answer. Checking a file means *running* its
module body, though, and a filter that prints while it loads used to break exactly that:
the stray line made the output unparseable and the operator was told `the check produced
no answer` about a file whose only sin was a `print()`.
"""

import json
import os
import subprocess
import sys

import pytest

BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend"))
WORKER = os.path.join(BACKEND, "modules", "services", "pyworker.py")

GOOD = """from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import RawPacket


@pyfilter
def quiet(packet: RawPacket):
    return ACCEPT
"""

#: The same file, plus the most natural thing in the world to reach for while writing a
#: filter. It has no business changing the answer.
NOISY = 'print("loading, and saying so")\n' + GOOD

BROKEN = "def broken(:\n    pass\n"


def run_check(tmp_path, source: str) -> dict:
    path = tmp_path / "filter.py"
    path.write_text(source)
    done = subprocess.run([sys.executable, WORKER, "--check", str(path)],
                          capture_output=True, text=True, cwd=BACKEND, timeout=60)
    assert done.stdout.strip(), f"nothing on stdout; stderr was:\n{done.stderr[-500:]}"
    return json.loads(done.stdout)


@pytest.fixture(autouse=True)
def needs_the_library():
    try:
        import firegex.pyfilters  # noqa: F401
    except ImportError:
        pytest.skip("the filter library is not importable here")


def test_a_filter_that_loads_is_accepted(tmp_path):
    answer = run_check(tmp_path, GOOD)
    assert answer["ok"] is True, answer
    assert answer["filters"] == ["quiet"]


def test_a_filter_that_prints_while_loading_still_gets_an_answer(tmp_path):
    """The output of the user's code goes to the diagnostics channel, not into the answer."""
    answer = run_check(tmp_path, NOISY)
    assert answer["ok"] is True, answer
    assert answer["filters"] == ["quiet"], answer


def test_what_the_filter_printed_does_not_reach_stdout(tmp_path):
    path = tmp_path / "filter.py"
    path.write_text(NOISY)
    done = subprocess.run([sys.executable, WORKER, "--check", str(path)],
                          capture_output=True, text=True, cwd=BACKEND, timeout=60)
    assert "loading, and saying so" not in done.stdout, \
        "the filter's own output landed in the answer"
    assert "loading, and saying so" in done.stderr, \
        "the filter's output was swallowed entirely instead of being diverted"


#: What every filter written before 5.0.0 starts with. The alias that made it resolve was
#: removed there, and the error Python raises for it is accurate and useless.
RENAMED = """from firegex.nfproxy import pyfilter, ACCEPT
from firegex.nfproxy.models import RawPacket


@pyfilter
def quiet(packet: RawPacket):
    return ACCEPT
"""


def test_an_old_filter_is_told_what_to_write_instead(tmp_path):
    """`No module named 'firegex.nfproxy'` is true and says nothing about the fix.

    The operator meets this in the editor, with the line already marked, rather than at
    the first start after an upgrade — which at a competition is the start of a round.
    """
    answer = run_check(tmp_path, RENAMED)
    assert answer["ok"] is False, answer
    assert answer["error"]["type"] == "ModuleNotFoundError", answer
    assert answer["error"]["line"] == 1, answer
    message = answer["error"]["message"]
    assert "firegex.pyfilters" in message, message
    assert "renamed" in message, message


def test_an_unrelated_missing_module_is_not_given_that_advice(tmp_path):
    """The hint is about one rename, not about imports in general.

    A filter importing something the operator simply has not installed has nothing to do
    with the rename, and being told to change `firegex.nfproxy` would send them looking
    for a line that is not there.
    """
    answer = run_check(tmp_path, "import a_module_nobody_has\n" + GOOD)
    assert answer["ok"] is False, answer
    assert "firegex.pyfilters" not in answer["error"]["message"], answer["error"]["message"]


def test_a_filter_that_cannot_load_is_refused_with_a_position(tmp_path):
    """A refusal is a result, not a failure: the editor wants a line to mark."""
    answer = run_check(tmp_path, BROKEN)
    assert answer["ok"] is False, answer
    assert answer["error"]["type"] == "SyntaxError", answer
    assert answer["error"]["line"] == 1, answer
