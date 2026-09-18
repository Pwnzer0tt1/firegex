"""Fixtures for everything that needs a live firegex.

**The combinations are the suite.** A service is two independent choices — a network
layer that says how traffic is intercepted, and a chain of filters that says what happens
to it — and the property worth testing is that they really are independent: the same
filters block on either layer, over either address family, with or without TLS. That used
to be a shell script running one monolithic program eight times with different flags,
which meant the first failure in a run ended it and the seven other combinations were
never reached. Here it is a parameter, so each case is a test with a name, each failure
names its own combination, and a case this host cannot carry is skipped rather than red.

Services are created through a factory fixture that remembers what it made and takes it
away afterwards. A leaked service is not a tidy-up problem: it holds a port and an
nftables rule, so the next test to want that port fails for a reason that has nothing to
do with it.
"""

import time
from dataclasses import dataclass

import pytest

from helpers.certs import rsa_cert
from helpers.net import free_port, loopback
from helpers.tcpserver import TcpServer
from helpers.udpserver import UdpEcho

#: How long to give the datapath after it is told to start. Generous on purpose: a test
#: that is flaky because a process was still binding teaches nobody anything.
SETTLE = 1.0
#: And after a change is pushed to a chain that is already running.
RELOAD = 0.6


@dataclass(frozen=True)
class Layer:
    """One combination of the choices a service is made of."""

    transport: str
    ipv6: bool = False
    tls: bool = False

    @property
    def ip(self) -> str:
        return loopback(self.ipv6)

    @property
    def proto(self) -> str:
        return "tls" if self.tls else "tcp"

    @property
    def inspects(self) -> bool:
        """Whether a filter attached here would ever run."""
        return self.transport in ("proxy", "nfqueue")

    def __str__(self) -> str:
        return (f"{self.transport}"
                f"{'+tls' if self.tls else ''}"
                f"{'-ipv6' if self.ipv6 else '-ipv4'}")


def _ids(layers):
    return [str(layer) for layer in layers]


def _marks(layer: Layer):
    marks = [pytest.mark.instance]
    if layer.ipv6:
        marks.append(pytest.mark.ipv6)
    if layer.tls:
        marks.append(pytest.mark.tls)
    return marks


def _param(layer: Layer):
    return pytest.param(layer, id=str(layer), marks=_marks(layer))


#: Every layer a filter can be attached to, over both families. What most of the suite
#: runs against, because "the same filters work on both" is the claim being tested.
INSPECTING = [Layer("proxy", ipv6=False), Layer("proxy", ipv6=True),
              Layer("nfqueue", ipv6=False), Layer("nfqueue", ipv6=True)]
#: TLS belongs to the proxy layer alone: decrypting means terminating the connection, and
#: terminating is what that layer does.
TLS_LAYERS = [Layer("proxy", ipv6=False, tls=True), Layer("proxy", ipv6=True, tls=True)]
#: The proxy layer on its own, for what only it has — connection limits, deadlines, TLS.
PROXY_ONLY = [Layer("proxy", ipv6=False), Layer("proxy", ipv6=True)]
#: The hand-off, which runs nothing of firegex and therefore hosts no filter.
EXTERNAL = [Layer("external", ipv6=False), Layer("external", ipv6=True)]

ALL_LAYERS = INSPECTING + TLS_LAYERS + EXTERNAL


@pytest.fixture(params=[_param(item) for item in INSPECTING])
def inspecting_layer(request) -> Layer:
    return request.param


@pytest.fixture(params=[_param(item) for item in INSPECTING + TLS_LAYERS])
def filtering_layer(request) -> Layer:
    """Every layer that inspects traffic, TLS included."""
    return request.param


@pytest.fixture(params=[_param(item) for item in PROXY_ONLY])
def proxy_layer(request) -> Layer:
    return request.param


@pytest.fixture(params=[_param(item) for item in TLS_LAYERS])
def tls_layer(request) -> Layer:
    return request.param


@pytest.fixture(params=[_param(item) for item in EXTERNAL])
def external_layer(request) -> Layer:
    return request.param


@pytest.fixture(params=[_param(item) for item in ALL_LAYERS])
def any_layer(request) -> Layer:
    return request.param


#: Fixtures that only mean anything if the datapath is actually in this process's path.
#: A test that asks for none of them — checking a refusal, a validation message, the
#: shape of a statistics reply — is testing the API and works from anywhere.
NEEDS_INTERCEPTION = {"protected", "stand_in", "udp_stand_in", "quic_stand_in"}


@pytest.fixture(scope="session")
def datapath_in_our_path(api, pytestconfig) -> bool:
    """Is the firegex under test actually in front of *our* loopback?

    It is perfectly possible to reach the API of an instance whose datapath protects a
    different machine — a container without host networking, a VM with the port
    forwarded, a box across the network. Every rule installs, every service starts, every
    call returns `ok`, and not one packet of ours goes near any of it. What that looks
    like without this check is dozens of "the filter did not block" failures, which reads
    as a broken firewall rather than as a suite pointed somewhere it cannot reach.

    So it is asked once, plainly: put a pattern in front of a local stand-in and see
    whether a payload carrying it is actually refused.
    """
    from helpers.tcpserver import TcpServer

    port = free_port()
    server = TcpServer(port, False)
    server.start()
    service_id = None
    try:
        service_id = api.services_add(f"fgex-canary-{port}", "127.0.0.1", port, "proxy")
        if service_id is None:
            return False
        if not api.services_add_filter(service_id, "regex", "canary"):
            return False
        filter_id = api.services_filters(service_id)[0]["filter_id"]
        api.services_add_regex(service_id, filter_id, "CANARY_BLOCK", mode="B")
        if not api.services_start(service_id):
            return False
        time.sleep(SETTLE)
        # Reaching the service at all is the other half: if the stand-in cannot be
        # dialled the answer here is about the test host, not about interception.
        if server.sendCheckData(b"canary reachable") is not True:
            return False
        return server.sendCheckData(b"carrying CANARY_BLOCK") is not True
    finally:
        if service_id:
            api.services_stop(service_id)
            api.services_delete(service_id)
        server.stop()


#: Said once per session rather than once per skipped test: the summary repeats a skip
#: reason for every test it applies to, and this one needs a paragraph.
_EXPLAINED = []


@pytest.fixture(autouse=True)
def _skip_when_the_datapath_cannot_reach_us(request):
    """Skip the tests that need interception, and explain why exactly once."""
    if not (NEEDS_INTERCEPTION & set(request.fixturenames)):
        return
    if request.getfixturevalue("datapath_in_our_path"):
        return
    if not _EXPLAINED:
        _EXPLAINED.append(True)
        print(
            "\n"
            "  The firegex under test is not in front of this machine's loopback: a\n"
            "  service with a blocking pattern refused nothing. Its API is reachable, so\n"
            "  it is running somewhere its datapath cannot see traffic between a client\n"
            "  and a server on this host — a container without host networking, or a VM\n"
            "  with only the port forwarded. Everything needing interception is skipped;\n"
            "  run the suite on the host firegex itself runs on to exercise it.\n"
        )
    pytest.skip("firegex's datapath is not in front of this host's loopback")


@pytest.fixture
def service(api):
    """Create services, and take them away however the test ends.

    Returns the service id, which is what every other call wants. Stopping before
    deleting is deliberate: a deleted-but-running service would leave its datapath and
    its nftables rules behind, and the next test wanting that port would fail for a
    reason belonging to this one.
    """
    made = []

    def _create(name: str, ip: str, port: int, transport: str, **kwargs) -> str:
        service_id = api.services_add(name, ip, port, transport, **kwargs)
        assert service_id is not None, f"could not create the service {name!r}"
        made.append(service_id)
        return service_id

    yield _create

    for service_id in reversed(made):
        for call in (api.services_stop, api.services_delete):
            try:
                call(service_id)
            except Exception:
                pass


@pytest.fixture
def stand_in(request):
    """A TCP service for firegex to protect, on a port nothing else is using."""
    started = []

    def _serve(ipv6: bool = False, tls: tuple[str, str] | None = None,
               alpn: list[str] | None = None, port: int | None = None) -> TcpServer:
        chosen = port or free_port(ipv6)
        server = TcpServer(chosen, ipv6,
                           tls_cert=tls[0] if tls else None,
                           tls_key=tls[1] if tls else None,
                           tls_alpn=alpn)
        server.start()
        started.append(server)
        return server

    yield _serve

    for server in started:
        try:
            server.stop()
        except Exception:
            pass


@pytest.fixture
def udp_stand_in():
    """A UDP service for firegex to protect."""
    started = []

    def _serve(ipv6: bool = False, port: int | None = None) -> UdpEcho:
        echo = UdpEcho(port or free_port(ipv6, udp=True), ipv6)
        echo.start()
        started.append(echo)
        return echo

    yield _serve

    for echo in started:
        try:
            echo.stop()
        except Exception:
            pass


@pytest.fixture
def http_stand_in():
    """An HTTP/1.1 service, for the edges that are carried to one."""
    from helpers.httpserver import HttpService
    started = []

    def _serve(ipv6: bool = False, port: int | None = None) -> "HttpService":
        service = HttpService(port or free_port(ipv6), ipv6)
        service.start()
        started.append(service)
        return service

    yield _serve

    for service in started:
        try:
            service.stop()
        except Exception:
            pass


@pytest.fixture
def quic_stand_in(certificate):
    """An HTTP/3 service for firegex to protect.

    It carries its own certificate, and firegex is given the same one: the engine
    terminates QUIC from the client and opens a new QUIC connection to the service, so
    there are two handshakes and both of them need one.
    """
    from helpers.quicserver import QuicEcho
    started = []

    def _serve(ipv6: bool = False, port: int | None = None) -> "QuicEcho":
        cert, key = certificate("::1" if ipv6 else "127.0.0.1")
        # A UDP probe: this one is going to bind a QUIC endpoint, and a port free for TCP
        # says nothing about whether it is free for UDP.
        echo = QuicEcho(port or free_port(ipv6, udp=True), cert, key, ipv6)
        echo.start()
        echo.material = (cert, key)
        started.append(echo)
        return echo

    yield _serve

    for echo in started:
        try:
            echo.stop()
        except Exception:
            pass


@pytest.fixture
def certificate():
    """One certificate per test that asks for one, minted for the address it will dial."""
    cache: dict[str, tuple[str, str]] = {}

    def _cert(ip: str = "127.0.0.1", key_size: int = 2048) -> tuple[str, str]:
        key = f"{ip}/{key_size}"
        if key not in cache:
            cache[key] = rsa_cert(ip, key_size=key_size)
        return cache[key]

    return _cert


#: What the stand-in for an operator's own proxy answers with. It has to differ from an
#: echo: the real service echoes too, and two echoes cannot be told apart.
EXTERNAL_MARKER = b"answered-by-your-own-proxy"


@pytest.fixture
def protected(api, service, stand_in, certificate):
    """A service in front of a stand-in that echoes, for whichever layer. Not started.

    Hands back `(service_id, server, port)`. The commonest shape in the suite by far, and
    one place that knows the order it has to be built in: the stand-in listens first, and
    the service is created pointing at it.

    On the `external` layer a second stand-in is started to play the operator's own
    proxy, because that layer's whole job is putting one in the path — it is reachable
    from the returned service via `.external`.
    """
    def _build(layer: Layer, name: str = "svc", **kwargs):
        cert = certificate(layer.ip) if layer.tls else (None, None)
        server = stand_in(layer.ipv6, tls=cert if layer.tls else None)
        extra = {}
        if layer.transport == "external":
            # It listens on a port of its own while its client dials the service's, so
            # the rules are what has to put it in the path.
            proxy = stand_in(layer.ipv6, port=free_port(layer.ipv6))
            proxy.proxy_port = server.port
            extra = {"proxy_ip": layer.ip, "proxy_port": proxy.port}
            server.external = proxy
        service_id = service(
            f"{name}-{server.port}", layer.ip, server.port, layer.transport,
            proto=layer.proto, tls_cert=cert[0], tls_key=cert[1], **extra, **kwargs,
        )
        return service_id, server, server.port

    return _build


def start_and_settle(api, service_id: str, wait: float = SETTLE):
    """Start a service and give the datapath time to be there before traffic arrives."""
    assert api.services_start(service_id), "the service would not start"
    time.sleep(wait)


def add_regex_filter(api, service_id: str, pattern: str, name: str = "patterns",
                     mode: str = "B", **kwargs) -> tuple[str, str]:
    """Attach a regex filter holding one pattern. Returns `(filter_id, pattern_id)`."""
    assert api.services_add_filter(service_id, "regex", name)
    filter_id = [f["filter_id"] for f in api.services_filters(service_id)
                 if f["name"] == name][0]
    assert api.services_add_regex(service_id, filter_id, pattern, mode=mode, **kwargs)
    pattern_id = api.services_regexes(service_id, filter_id)[0]["regex_id"]
    return filter_id, pattern_id


def add_python_filter(api, service_id: str, code: str, name: str = "python") -> str:
    """Attach a pyfilter carrying `code`. Returns its filter id."""
    assert api.services_add_filter(service_id, "pyfilter", name)
    filter_id = [f["filter_id"] for f in api.services_filters(service_id)
                 if f["name"] == name][0]
    assert api.services_set_code(service_id, filter_id, code), \
        api.services_set_code_error(service_id, filter_id, code)
    return filter_id
