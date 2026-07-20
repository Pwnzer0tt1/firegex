from firegex.nfproxy import pyfilter, ACCEPT, clear_pyfilter_registry
from firegex.nfproxy.models import (
    HttpRequest,
    HttpResponse,
    HttpFullRequest,
    HttpFullResponse,
    HttpHistory,
    HttpStreamHistory,
)
from firegex.nfproxy.internals import compile, handle_packet


def create_packet_info(payload: bytes, is_input: bool):
    return {
        "data": payload,
        "raw_packet": b"\x00" * 40 + payload,
        "is_input": is_input,
        "is_ipv6": False,
        "is_tcp": True,
        "l4_size": len(payload),
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
    clear_pyfilter_registry()

    code = """
from firegex.nfproxy import pyfilter, ACCEPT
from firegex.nfproxy.models import HttpFullRequest, HttpFullResponse, HttpHistory

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
    glob["__firegex_proto"] = "http"
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
    clear_pyfilter_registry()

    code = """
from firegex.nfproxy import pyfilter, ACCEPT
from firegex.nfproxy.models import HttpFullRequest, HttpFullResponse

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
    glob["__firegex_proto"] = "http"
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


if __name__ == "__main__":
    test_http_history_model()
    test_http_history_stream_execution()
    test_http_history_attribute_on_request()
    print("All HTTP history unit tests passed successfully!")
