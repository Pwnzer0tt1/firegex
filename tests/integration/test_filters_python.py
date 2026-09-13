"""Python filters: what they see, what decides when they run, and the switches over them.

The same file on both network layers, because there is one Python API — `cpproxy` embeds
it, `pyworker.py` runs it out of process, and a filter written from the documentation has
to load on either. An earlier version of that worker defined a look-alike `@pyfilter`
taking `(data, direction)`, so a filter written from the docs worked on one transport and
failed on the other.
"""

import time

import pytest

from integration import filter_code
from integration.conftest import (RELOAD, add_python_filter, add_regex_filter,
                                  start_and_settle)
from helpers.traffic import Channel

pytestmark = pytest.mark.instance

HTTP_TRAVERSAL = b"GET /../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"
HTTP_BENIGN = b"GET /shop HTTP/1.1\r\nHost: x\r\n\r\n"


def test_a_python_filter_blocks_on_either_layer(api, protected, inspecting_layer):
    service_id, server, port = protected(inspecting_layer, name="py")
    add_python_filter(api, service_id, filter_code.BLOCK_MARKER)
    start_and_settle(api, service_id)
    channel = Channel(server, port, inspecting_layer.ipv6)
    assert channel.gets_through(b"harmless traffic")
    assert channel.is_blocked(b"carrying PYBLOCK")


def test_patterns_and_python_coexist_in_one_ordered_chain(api, protected, inspecting_layer):
    """Both layers host a chain of both kinds.

    They get there very differently — the proxy walks a list inside one process, NFQUEUE
    chains one process per filter by base-chain priority — and the point of testing them
    identically is that the difference does not reach the operator.
    """
    service_id, server, port = protected(inspecting_layer, name="mixed")
    add_regex_filter(api, service_id, "BLOCKME")
    add_python_filter(api, service_id, filter_code.BLOCK_MARKER)
    chain = api.services_filters(service_id)
    assert [link["kind"] for link in chain] == ["regex", "pyfilter"], str(chain)

    start_and_settle(api, service_id)
    channel = Channel(server, port, inspecting_layer.ipv6)
    assert channel.gets_through(b"harmless traffic")
    assert channel.is_blocked(b"carrying BLOCKME"), "the pattern in the chain stopped deciding"
    assert channel.is_blocked(b"carrying PYBLOCK"), "the pyfilter in the chain stopped deciding"


# --- a filter file's protocol is read off the file, never declared --------------------


def test_code_asking_for_parsed_http_is_accepted_on_a_plain_tcp_service(
        api, protected, inspecting_layer):
    """What the *file* asks for and what the *service* speaks are different questions.

    Confusing them is what used to make this a 500: the service's protocol was sent to
    the datapath, so an HTTP filter on a TCP service was refused for asking for an
    `HttpRequest` — which is the only thing an HTTP filter does.
    """
    service_id, _, _ = protected(inspecting_layer, name="proto")
    filter_id = add_python_filter(api, service_id, filter_code.HTTP, name="http")
    detected = [f for f in api.services_filters(service_id)
                if f["filter_id"] == filter_id][0]
    assert detected["proto"] == "http", str(detected)


def test_an_http_filter_decides_on_parsed_requests(api, protected, inspecting_layer):
    service_id, server, port = protected(inspecting_layer, name="http")
    add_python_filter(api, service_id, filter_code.HTTP, name="http")
    start_and_settle(api, service_id)
    channel = Channel(server, port, inspecting_layer.ipv6)
    assert channel.is_blocked(HTTP_TRAVERSAL)
    assert channel.gets_through(HTTP_BENIGN)


# --- the code is checked by the process that will run it ------------------------------


def test_code_that_cannot_load_is_refused_with_the_line_it_fails_on(api, protected,
                                                                    inspecting_layer):
    """The editor wants a position to mark, not a string to print.

    User code used to be `exec`ed inside the backend's own event loop to detect its
    protocol, so a `while True:` at module level took the interface down. It runs in a
    subprocess with a deadline now, and answers 200 even when the answer is no — a
    refusal is the result.
    """
    service_id, _, _ = protected(inspecting_layer, name="check")
    filter_id = add_python_filter(api, service_id, filter_code.BLOCK_MARKER)

    broken = api.services_check_code(service_id, filter_id, filter_code.NO_ANNOTATION)
    assert broken["ok"] is False, str(broken)
    assert broken["error"]["line"] == 5, str(broken)
    assert "annotation" in broken["error"]["message"], str(broken)


def test_a_syntax_error_is_reported_where_it_is(api, protected, inspecting_layer):
    service_id, _, _ = protected(inspecting_layer, name="syntax")
    filter_id = add_python_filter(api, service_id, filter_code.BLOCK_MARKER)

    syntax = api.services_check_code(service_id, filter_id, filter_code.SYNTAX_ERROR)
    assert syntax["ok"] is False
    assert syntax["error"]["type"] == "SyntaxError", str(syntax)
    assert syntax["error"]["line"] == 1, str(syntax)


def test_saving_code_that_will_not_load_is_refused_saying_why(api, protected,
                                                              inspecting_layer):
    """Not "the filter code did not load: worker exited".

    Saving goes through the same check as the editor's, so the operator is never handed
    a symptom and left to find the traceback in the service log.
    """
    service_id, _, _ = protected(inspecting_layer, name="save")
    filter_id = add_python_filter(api, service_id, filter_code.BLOCK_MARKER)

    why = api.services_set_code_error(service_id, filter_id, filter_code.SYNTAX_ERROR)
    assert why is not None, "code that cannot load was saved"
    assert "SyntaxError" in why and "line 1" in why, why


def test_code_that_loads_says_what_it_defines_and_what_it_speaks(api, protected,
                                                                 inspecting_layer):
    service_id, _, _ = protected(inspecting_layer, name="good")
    filter_id = add_python_filter(api, service_id, filter_code.BLOCK_MARKER)

    good = api.services_check_code(service_id, filter_id, filter_code.HTTP)
    assert good["ok"] is True, str(good)
    assert good["proto"] == "http"
    assert set(good["filters"]) == {"refuse_traversal", "look_at_the_bytes"}, str(good)


# --- the functions inside that file, one at a time ------------------------------------
# A file holds several @pyfilter functions. The code says which exist; the operator says
# which run. Deleting a function to silence it and pasting it back to resume is exactly
# what these switches replace, and it is the one that loses code mid-round.


@pytest.fixture
def http_filter(api, protected, inspecting_layer):
    service_id, server, port = protected(inspecting_layer, name="fns")
    filter_id = add_python_filter(api, service_id, filter_code.HTTP, name="http")
    start_and_settle(api, service_id)
    channel = Channel(server, port, inspecting_layer.ipv6)
    return service_id, filter_id, channel


def test_every_function_the_file_defines_is_listed_and_active(api, http_filter):
    service_id, filter_id, _ = http_filter
    functions = api.services_functions(service_id, filter_id)
    assert {f["name"] for f in functions} == {"refuse_traversal", "look_at_the_bytes"}
    assert all(f["active"] for f in functions), str(functions)


def test_functions_are_listed_in_the_order_the_file_defines_them(api, http_filter):
    """Which is the order they run in, and the first to refuse ends the packet.

    The list used to be sorted by name, over a run order that was a *set's* iteration
    order — so neither the operator nor the file could say which function saw a chunk
    first, and that decides which one gets credited with a block.
    """
    service_id, filter_id, _ = http_filter
    defined = [line.split("def ", 1)[1].split("(", 1)[0]
               for line in filter_code.HTTP.splitlines() if line.startswith("def ")]
    listed = [f["name"] for f in api.services_functions(service_id, filter_id)]
    assert listed == defined, f"{listed} against {defined}"


def test_a_block_is_counted_against_the_function_that_made_it(api, http_filter):
    """A file with ten functions blocking 900 connections is not an answer to
    "which of them is doing it"."""
    service_id, filter_id, channel = http_filter
    assert channel.is_blocked(HTTP_TRAVERSAL)
    time.sleep(0.6)
    functions = api.services_functions(service_id, filter_id)
    assert any(f["name"] == "refuse_traversal" and f["blocked"] >= 1 for f in functions), \
        str(functions)


def test_switching_one_function_off_stops_it_deciding_without_touching_the_code(
        api, http_filter):
    service_id, filter_id, channel = http_filter
    assert channel.is_blocked(HTTP_TRAVERSAL)

    assert api.services_edit_function(service_id, filter_id, "refuse_traversal", False)
    card = [f for f in api.services_filters(service_id) if f["filter_id"] == filter_id][0]
    assert card["n_functions"] == 2 and card["n_functions_active"] == 1, str(card)
    time.sleep(1.0)
    assert channel.gets_through(HTTP_TRAVERSAL), "a switched-off function still refused"

    assert api.services_edit_function(service_id, filter_id, "refuse_traversal", True)
    time.sleep(1.0)
    assert channel.is_blocked(HTTP_TRAVERSAL), "it did not start deciding again"

    stored = api.services_get_code(service_id, filter_id)
    assert "refuse_traversal" in stored, "the code was edited to switch a function off"


def test_saving_different_code_reconciles_the_list_of_functions(api, http_filter):
    """The code is what decides which functions exist.

    Functions that have gone are dropped, new ones arrive active, and survivors keep what
    the operator set.
    """
    service_id, filter_id, _ = http_filter
    api.services_edit_function(service_id, filter_id, "look_at_the_bytes", False)
    assert api.services_set_code(service_id, filter_id, filter_code.BLOCK_MARKER)
    functions = api.services_functions(service_id, filter_id)
    assert {f["name"] for f in functions} == {"refuse_marker"}, str(functions)


def test_functions_run_in_the_order_the_file_defines_them(api, protected, proxy_layer):
    """Not merely listed in that order — actually run in it.

    The second function only refuses if the first has already seen this payload, so a
    block proves the order rather than describing it.
    """
    service_id, server, port = protected(proxy_layer, name="order")
    add_python_filter(api, service_id, filter_code.ORDERED)
    start_and_settle(api, service_id)
    channel = Channel(server, port, proxy_layer.ipv6)
    assert channel.is_blocked(b"ORDER_TRIGGER"), "the file's functions ran out of order"


def test_module_globals_are_private_to_one_connection(api, protected, proxy_layer):
    """One client's bytes deciding another client's verdict is both a false positive and
    a way to smuggle a pattern past a filter by splitting it across two connections."""
    service_id, server, port = protected(proxy_layer, name="iso")
    add_python_filter(api, service_id, filter_code.ISOLATED_STATE)
    start_and_settle(api, service_id)
    channel = Channel(server, port, proxy_layer.ipv6)

    assert channel.gets_through(b"SET_STATE")
    time.sleep(0.3)
    assert channel.gets_through(b"CHECK_STATE"), \
        "state from one connection was visible to the next"


def test_what_a_filter_prints_reaches_the_service_log(api, protected, proxy_layer):
    """And nothing else.

    stdout is the length-prefixed protocol channel between worker and engine; a `print()`
    landing in the middle of a frame gets the worker killed on every packet, with nothing
    in the log to explain it.
    """
    service_id, server, port = protected(proxy_layer, name="print")
    add_python_filter(api, service_id, filter_code.PRINTS)
    start_and_settle(api, service_id)
    channel = Channel(server, port, proxy_layer.ipv6)

    assert channel.gets_through(b"SAY_SOMETHING"), "printing broke the worker's framing"
    time.sleep(RELOAD)
    entries = api.services_logs(service_id)
    assert any("the filter said this" in entry["text"] for entry in entries), \
        str(entries[-5:])


def test_removing_a_filter_leaves_the_rest_of_the_chain_running(api, protected,
                                                                inspecting_layer):
    service_id, server, port = protected(inspecting_layer, name="rm")
    add_regex_filter(api, service_id, "BLOCKME")
    python_id = add_python_filter(api, service_id, filter_code.BLOCK_MARKER)
    start_and_settle(api, service_id)
    channel = Channel(server, port, inspecting_layer.ipv6)
    assert channel.is_blocked(b"carrying PYBLOCK")

    assert api.services_delete_filter(service_id, python_id)
    time.sleep(1.0)
    assert channel.gets_through(b"carrying PYBLOCK"), "the removed filter still decides"
    assert channel.is_blocked(b"carrying BLOCKME"), "the rest of the chain stopped"
