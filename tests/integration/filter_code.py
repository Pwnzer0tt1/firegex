"""The filter files the suite feeds to firegex.

Written against the documented API: parameters annotated with a model, verdicts from the
library. It is the same code the NFQUEUE binary would run, which is the property worth
testing — there is one Python API, `firegex.pyfilters`, not one per transport.
"""

#: The simplest possible filter: raw payload in, a verdict out.
BLOCK_MARKER = """from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket


@pyfilter
def refuse_marker(packet: RawPacket):
    return REJECT if b"PYBLOCK" in packet.data else ACCEPT
"""

#: One file, two functions: one that wants parsed HTTP and one that wants raw payloads.
#: Nothing declares a protocol — asking for an `HttpRequest` is what makes this an HTTP
#: filter file, and the two annotations coexist because `http` provides both. This used
#: to be impossible to save: the backend sent the *service's* protocol to the datapath,
#: so an HTTP filter on a TCP service was refused for asking for an `HttpRequest`, which
#: is the only thing an HTTP filter does.
HTTP = """from firegex.pyfilters import pyfilter, ACCEPT, REJECT, ExceptionAction
from firegex.pyfilters.models import HttpRequest, RawPacket

# The stand-in service echoes whatever it is sent, so the reply to an HTTP request is not
# itself a valid HTTP response. The default is to refuse a stream the parser cannot read;
# here that is the test's own doing rather than the filter's, so it is turned off.
# (Setting this used to be silently ignored, which is how the gate that read it was found
# to be checking the wrong enum.)
FGEX_INVALID_ENCODING_ACTION = ExceptionAction.ACCEPT


@pyfilter
def refuse_traversal(request: HttpRequest):
    return REJECT if "../" in (request.url or "") else ACCEPT


@pyfilter
def look_at_the_bytes(packet: RawPacket):
    return ACCEPT
"""

#: The order functions are defined in is the order they run in, and the first to answer
#: anything but ACCEPT ends the packet. If `first` did not run first, `second` would
#: never see the flag set and would accept.
ORDERED = """from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket

seen_first = False


@pyfilter
def first_marks(packet: RawPacket):
    global seen_first
    if b"ORDER_TRIGGER" in packet.data:
        seen_first = True
    return ACCEPT


@pyfilter
def second_refuses_only_if_first_ran(packet: RawPacket):
    if b"ORDER_TRIGGER" in packet.data and seen_first:
        return REJECT
    return ACCEPT
"""

#: A datagram filter: only `RawPacket`, which is the one model that does not need a
#: stream underneath it. Everything else — an assembled TCP stream, a parsed HTTP message
#: — declines to be built on a datagram, so a filter asking for one would sit in the
#: chain and never be called.
UDP = """from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket


@pyfilter
def refuse_marker(packet: RawPacket):
    return REJECT if b"PYDENY" in packet.data else ACCEPT
"""

#: Module globals are per connection, per direction. One client's bytes deciding another
#: client's verdict is both a false positive and a way to smuggle a pattern past a filter
#: by splitting it across two connections.
ISOLATED_STATE = """from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import RawPacket

state = []


@pyfilter
def check_leak(packet: RawPacket):
    if b"SET_STATE" in packet.data:
        state.append("token")
        return ACCEPT
    if b"CHECK_STATE" in packet.data and state:
        return REJECT  # it leaked from a previous connection
    return ACCEPT
"""

#: An unhandled exception. A filter that misbehaves loses its say rather than the traffic
#: being held, and the log has to say so — a filter that silently stops filtering is the
#: worse surprise of the two.
RAISES = """from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import RawPacket


@pyfilter
def buggy(packet: RawPacket):
    if b"CRASH_EXCEPTION" in packet.data:
        raise ZeroDivisionError("deliberately")
    return ACCEPT
"""

#: Raises on *every* packet, which is the shape user code that throws actually has —
#: a typo does not fire once. Unthrottled, that is a traceback per packet into a log
#: that holds a few hundred lines, so the flood pushes out the first traceback along
#: with everything that was there before the filter broke.
RAISES_ALWAYS = """from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import RawPacket


@pyfilter
def always_buggy(packet: RawPacket):
    raise ValueError("on every single packet")
"""

#: Code that hangs. `spawn_blocking` carries a deadline precisely so this cannot stall
#: the datapath, and the worker is replaced afterwards rather than left wedged.
HANGS = """import time
from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import RawPacket


@pyfilter
def hanging(packet: RawPacket):
    if b"HANG_ME" in packet.data:
        time.sleep(30.0)
    return ACCEPT
"""

#: Code that takes the interpreter down with it, rather than merely raising.
SEGFAULTS = """import ctypes
from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import RawPacket


@pyfilter
def segfaulting(packet: RawPacket):
    if b"SEGFAULT_TRIGGER" in packet.data:
        ctypes.string_at(0)
    return ACCEPT
"""

#: A `print()` from user code. It has to reach the service log and nothing else: stdout
#: is the length-prefixed protocol channel between the worker and the engine, and a line
#: landing in the middle of a frame gets the worker killed on every packet with nothing
#: to explain it.
PRINTS = """from firegex.pyfilters import pyfilter, ACCEPT
from firegex.pyfilters.models import RawPacket


@pyfilter
def chatty(packet: RawPacket):
    if b"SAY_SOMETHING" in packet.data:
        print("the filter said this")
    return ACCEPT
"""

#: A file with no annotation on its filter's parameter: the library has nothing to decide
#: from, so it cannot be loaded.
NO_ANNOTATION = """from firegex.pyfilters import pyfilter


@pyfilter
def no_annotation(packet):
    return None
"""

#: Not valid Python at all.
SYNTAX_ERROR = "def broken(:\n    pass\n"


#: A filter that reads gRPC messages rather than the body they arrive in.
#:
#: The same file works on a unary call and on a streaming one, because the model hands
#: over one message as each completes rather than waiting for the body to end — which on
#: a bidirectional RPC it does not do until the stream closes.
GRPC = """from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import GrpcMessage


@pyfilter
def refuse_forbidden_payload(message: GrpcMessage):
    return REJECT if b"NOT-THIS-ONE" in message.payload else ACCEPT
"""
