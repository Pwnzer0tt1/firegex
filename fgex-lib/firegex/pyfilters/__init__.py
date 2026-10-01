from firegex.pyfilters.models import (
    RawPacket,
    TCPInputStream,
    TCPOutputStream,
    TCPClientStream,
    TCPServerStream,
    HttpHistory,
    HttpStreamHistory,
)
from firegex.pyfilters.internals.models import Action, FullStreamAction, ExceptionAction

ACCEPT = Action.ACCEPT
DROP = Action.DROP
REJECT = Action.REJECT

#: Set on a function by `@pyfilter`. Marking the function *is* the registration — there
#: is no registry to keep, to clear between files, or to race two compilations against.
PYFILTER_MARK = "__firegex_pyfilter__"


def pyfilter(func):
    """Mark a function as a filter, and hand it back unchanged.

    The mark lives on the function, so the file that defines it holds the whole list:
    `collect_pyfilters` reads a module's globals in definition order. What that replaced
    was a set of *names* on a module-global attribute of this decorator, which had three
    consequences worth not having back — a set has no order, so the order filters ran in
    was whatever hashing produced; the state outlived the file, so every caller had to
    clear it before and after; and a name registered from somewhere the module globals
    could not reach (a nested `def`) was registered and then not found.

    The function is returned as it is, not wrapped. The wrapper it used to get forwarded
    `*args` and did nothing else, at the cost of a stack frame in every traceback the
    operator has to read.
    """
    setattr(func, PYFILTER_MARK, True)
    return func


def collect_pyfilters(namespace: dict) -> list[str]:
    """The filters a module defines, in the order it defines them.

    Definition order is the order they run in, which is the only order a reader of the
    file can predict.
    """
    seen, names = set(), []
    for name, obj in namespace.items():
        if callable(obj) and getattr(obj, PYFILTER_MARK, False) and id(obj) not in seen:
            seen.add(id(obj))
            names.append(name)
    return names

__all__ = [
    "ACCEPT", "DROP", "REJECT",
    "Action", "FullStreamAction", "ExceptionAction", "pyfilter", "collect_pyfilters",
    "RawPacket", "TCPInputStream", "TCPOutputStream", "TCPClientStream", "TCPServerStream",
    "HttpHistory", "HttpStreamHistory"
]