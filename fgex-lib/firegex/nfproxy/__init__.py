import functools
from firegex.nfproxy.models import RawPacket, TCPInputStream, TCPOutputStream, TCPClientStream, TCPServerStream
from firegex.nfproxy.internals.models import Action, FullStreamAction

ACCEPT = Action.ACCEPT
DROP = Action.DROP
REJECT = Action.REJECT
UNSTABLE_MANGLE = Action.MANGLE

def pyfilter(func):
    """
    Decorator to mark functions that will be used in the proxy.
    Stores the function reference in a global registry.
    """
    if not hasattr(pyfilter, "registry"):
        pyfilter.registry = set()
    
    pyfilter.registry.add(func.__name__)
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    
    return wrapper

def get_pyfilters():
    """Returns the list of functions marked with @pyfilter."""
    if hasattr(pyfilter, "registry"):
        return list(pyfilter.registry)
    return []

def clear_pyfilter_registry():
    """Clears the pyfilter registry."""
    if hasattr(pyfilter, "registry"):
        pyfilter.registry.clear()

__all__ = [
    "ACCEPT", "DROP", "REJECT", "UNSTABLE_MANGLE"
    "Action", "FullStreamAction", "pyfilter",
    "RawPacket", "TCPInputStream", "TCPOutputStream", "TCPClientStream", "TCPServerStream"
]