from firegex.pyfilters import pyfilter, ACCEPT, ExceptionAction, collect_pyfilters
from firegex.pyfilters.models import (
    HttpRequest,
    HttpResponse,
    HttpFullRequest,
    HttpFullResponse,
    HttpHistory,
    HttpStreamHistory,
)
from firegex.pyfilters.internals import compile, handle_packet


def create_packet_info(payload: bytes, is_input: bool):
    return {
        "data": payload,
        "is_input": is_input,
        "is_ipv6": False,
        "is_tcp": True,
        "src_ip": "10.0.0.9" if is_input else "10.0.0.1",
        "src_port": 51000 if is_input else 80,
        "dst_ip": "10.0.0.1" if is_input else "10.0.0.9",
        "dst_port": 80 if is_input else 51000,
    }


def test_http_history_model():
    req1 = None
    res1 = None
    history_obj = HttpHistory(requests=[req1], responses=[res1])
    assert history_obj.requests == [req1]
    assert history_obj.responses == [res1]
    assert "HttpHistory" in repr(history_obj)


def test_http_history_stream_execution():
    glob = {}

    code = """
from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import HttpFullRequest, HttpFullResponse, HttpHistory

recorded_history = []

@pyfilter
def filter_req(req: HttpFullRequest, history: HttpHistory):
    req_urls = [r.url for r in history.requests]
    resp_statuses = [r.status_code for r in history.responses]
    recorded_history.append(("req", req.url, req_urls, resp_statuses))
    return ACCEPT

@pyfilter
def filter_resp(resp: HttpFullResponse, history: HttpHistory):
    req_urls = [r.url for r in history.requests]
    resp_statuses = [r.status_code for r in history.responses]
    recorded_history.append(("resp", resp.status_code, req_urls, resp_statuses))
    return ACCEPT
"""

    glob["__firegex_pyfilter_enabled"] = ["filter_req", "filter_resp"]
    exec(code, glob, glob)
    compile(glob)

    # 1. First Request
    req1_data = b"GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n"
    glob["__firegex_packet_info"] = create_packet_info(req1_data, is_input=True)
    handle_packet(glob)

    # 2. First Response
    resp1_data = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    glob["__firegex_packet_info"] = create_packet_info(resp1_data, is_input=False)
    handle_packet(glob)

    # 3. Second Request
    req2_data = b"GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n"
    glob["__firegex_packet_info"] = create_packet_info(req2_data, is_input=True)
    handle_packet(glob)

    # 4. Second Response
    resp2_data = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    glob["__firegex_packet_info"] = create_packet_info(resp2_data, is_input=False)
    handle_packet(glob)

    recorded = glob["recorded_history"]

    # 1. First Request: history is empty
    assert recorded[0] == ("req", "/first", [], [])

    # 2. First Response: past requests contains /first
    assert recorded[1] == ("resp", "OK", ["/first"], [])

    # 3. Second Request: past requests contains [/first], past responses contains [OK]
    assert recorded[2] == ("req", "/second", ["/first"], ["OK"])

    # 4. Second Response: past requests contains [/first, /second], past responses contains [OK]
    assert recorded[3] == ("resp", "Not Found", ["/first", "/second"], ["OK"])


def test_http_history_attribute_on_request():
    glob = {}

    code = """
from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import HttpFullRequest, HttpFullResponse

history_lengths = []

@pyfilter
def filter_req(req: HttpFullRequest):
    history_lengths.append((len(req.history.requests), len(req.history.responses)))
    return ACCEPT

@pyfilter
def filter_resp(resp: HttpFullResponse):
    history_lengths.append((len(resp.history.requests), len(resp.history.responses)))
    return ACCEPT
"""

    glob["__firegex_pyfilter_enabled"] = ["filter_req", "filter_resp"]
    exec(code, glob, glob)
    compile(glob)

    # Req 1
    glob["__firegex_packet_info"] = create_packet_info(b"GET /a HTTP/1.1\r\nHost: a\r\n\r\n", is_input=True)
    handle_packet(glob)

    # Resp 1
    glob["__firegex_packet_info"] = create_packet_info(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", is_input=False)
    handle_packet(glob)

    # Req 2
    glob["__firegex_packet_info"] = create_packet_info(b"GET /b HTTP/1.1\r\nHost: b\r\n\r\n", is_input=True)
    handle_packet(glob)

    lengths = glob["history_lengths"]
    assert lengths[0] == (0, 0)
    assert lengths[1] == (1, 0)
    assert lengths[2] == (1, 1)


def test_http_history_invalid_max_size():
    glob = {}

    code = """
from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import HttpFullRequest

@pyfilter
def filter_req(req: HttpFullRequest):
    return ACCEPT
"""

    glob["__firegex_pyfilter_enabled"] = ["filter_req"]
    glob["FGEX_MAX_HISTORY_SIZE"] = "invalid_number"
    exec(code, glob, glob)
    compile(glob)

    glob["__firegex_packet_info"] = create_packet_info(b"GET /test HTTP/1.1\r\nHost: test\r\n\r\n", is_input=True)
    # Should not raise ValueError, should default to 100
    handle_packet(glob)


def test_http_history_parameter_order():
    glob = {}

    code = """
from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import HttpFullRequest, HttpHistory

calls_log = []

@pyfilter
def filter_history_first(history: HttpHistory, req: HttpFullRequest):
    calls_log.append(("history_first", req.url, len(history.requests)))
    return ACCEPT
"""

    glob["__firegex_pyfilter_enabled"] = ["filter_history_first"]
    exec(code, glob, glob)
    compile(glob)

    glob["__firegex_packet_info"] = create_packet_info(b"GET /first HTTP/1.1\r\nHost: test\r\n\r\n", is_input=True)
    handle_packet(glob)

    calls = glob["calls_log"]
    # Must be called EXACTLY ONCE with 0 history elements for the first request
    assert len(calls) == 1
    assert calls[0] == ("history_first", "/first", 0)


def test_http_history_property_immutability():
    glob = {}
    immutability_log = []

    code = """
from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import HttpFullRequest, HttpHistory

@pyfilter
def filter_req(req: HttpFullRequest, history: HttpHistory):
    if len(history.requests) > 0:
        past = history.requests[0]
        immutability_log.append({
            "past_size": past.total_size,
            "past_url": past.url,
            "curr_size": req.total_size,
            "curr_url": req.url,
        })
    return ACCEPT
"""

    glob["__firegex_pyfilter_enabled"] = ["filter_req"]
    glob["immutability_log"] = immutability_log
    exec(code, glob, glob)
    compile(glob)

    # 1. First short request
    req1_data = b"GET /short HTTP/1.1\r\nHost: test\r\n\r\n"
    glob["__firegex_packet_info"] = create_packet_info(req1_data, is_input=True)
    handle_packet(glob)

    # 2. Second longer request
    req2_data = b"POST /large_path HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n\r\nHELLO"
    glob["__firegex_packet_info"] = create_packet_info(req2_data, is_input=True)
    handle_packet(glob)

    entries = glob["immutability_log"]
    assert len(entries) == 1
    # Historical request 1 size must equal 14 (/short), current size 39 (/large_path)
    assert entries[0]["past_size"] == 14
    assert entries[0]["past_url"] == "/short"
    assert entries[0]["curr_size"] == 39
    assert entries[0]["curr_url"] == "/large_path"


def test_http_history_negative_max_size():
    glob = {}

    code = """
from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import HttpFullRequest

@pyfilter
def filter_req(req: HttpFullRequest):
    return ACCEPT
"""

    glob["__firegex_pyfilter_enabled"] = ["filter_req"]
    glob["FGEX_MAX_HISTORY_SIZE"] = "-5"
    exec(code, glob, glob)
    compile(glob)

    glob["__firegex_packet_info"] = create_packet_info(b"GET /test HTTP/1.1\r\nHost: test\r\n\r\n", is_input=True)
    # Should not raise ValueError for maxlen=-5, should clamp to 0
    handle_packet(glob)


def test_http_history_pyfilters_import():
    from firegex.pyfilters import HttpHistory as HH1, HttpStreamHistory as HH2
    assert HH1 is HttpHistory
    assert HH2 is HttpStreamHistory


def test_http_history_list_mutation():
    history_obj = HttpHistory(requests=["dummy_req"], responses=["dummy_resp"])
    reqs = history_obj.requests
    reqs.clear()
    assert len(history_obj.requests) == 1
    assert history_obj.requests == ["dummy_req"]

    resps = history_obj.responses
    resps.append("extra_resp")
    assert len(history_obj.responses) == 1
    assert history_obj.responses == ["dummy_resp"]


if __name__ == "__main__":
    test_http_history_model()
    test_http_history_stream_execution()
    test_http_history_attribute_on_request()
    test_http_history_invalid_max_size()
    test_http_history_parameter_order()
    test_http_history_property_immutability()
    test_http_history_negative_max_size()
    test_http_history_pyfilters_import()
    test_http_history_list_mutation()
    print("All HTTP history unit tests passed successfully!")





def test_invalid_encoding_action_is_settable():
    """The documented knob has to actually be reachable.

    `FGEX_INVALID_ENCODING_ACTION` is documented as taking an `ExceptionAction`, and the
    property that stores it accepts nothing else — but the gate that read it out of the
    module checked `Action`, a different enum. So the documented value was silently
    ignored and the only value that got past the gate raised in the setter: the knob
    could not be set at all, in either direction, and the symptom was a service that
    kept rejecting connections its filter had been told to let through.
    """
    from firegex.pyfilters.internals.data import DataStreamCtx

    glob = {}
    code = """
from firegex.pyfilters import pyfilter, ACCEPT, ExceptionAction
from firegex.pyfilters.models import HttpRequest

FGEX_INVALID_ENCODING_ACTION = ExceptionAction.ACCEPT

@pyfilter
def anything(req: HttpRequest):
    return ACCEPT
"""
    glob["__firegex_pyfilter_enabled"] = ["anything"]
    exec(code, glob, glob)
    compile(glob)
    assert DataStreamCtx(glob, init_pkt=False).invalid_encoding_action is ExceptionAction.ACCEPT


def test_filters_are_collected_in_definition_order():
    """The order a file defines its filters in is the order they run in.

    They used to be registered by name into a `set` on the decorator, so the order was
    whatever hashing produced — and since the first filter to answer anything but ACCEPT
    ends the packet, that decided which function got the block and whether an earlier
    rewrite survived. Nothing about the file could tell you which.

    The names below are deliberately not in alphabetical order, and deliberately not in
    an order a hash would be likely to reproduce.
    """
    from firegex.pyfilters.internals import get_filter_names

    names = ["zulu", "alpha", "mike", "bravo", "yankee", "charlie", "xray", "delta"]
    code = "from firegex.pyfilters import pyfilter, ACCEPT\n" \
           "from firegex.pyfilters.models import RawPacket\n" + "".join(
               f"@pyfilter\ndef {n}(p: RawPacket):\n    return ACCEPT\n" for n in names
           )
    assert get_filter_names(code) == names

    namespace = {}
    exec(code, namespace, namespace)
    assert collect_pyfilters(namespace) == names


def test_a_filter_is_the_function_itself():
    """`@pyfilter` marks and returns the function, it does not wrap it.

    The wrapper it used to return forwarded `*args` and did nothing else, at the cost of
    a frame in every traceback an operator has to read to find their own mistake.
    """
    def original(p):
        return ACCEPT

    assert pyfilter(original) is original
