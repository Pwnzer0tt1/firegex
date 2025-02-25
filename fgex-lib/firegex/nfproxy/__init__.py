import functools
from firegex.nfproxy.params import RawPacket
from enum import Enum

class Action(Enum):
    ACCEPT = 0
    DROP = 1
    REJECT = 2
    MANGLE = 3

class FullStreamAction(Enum):
    FLUSH = 0
    ACCEPT = 1
    REJECT = 2
    DROP = 3

ACCEPT = Action.ACCEPT
DROP = Action.DROP
REJECT = Action.REJECT
MANGLE = Action.MANGLE

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
    return list(pyfilter.registry)

def clear_pyfilter_registry():
    """Clears the pyfilter registry."""
    if hasattr(pyfilter, "registry"):
        pyfilter.registry.clear()

__all__ = [
    "ACCEPT", "DROP", "REJECT", "MANGLE", "EXCEPTION", "INVALID",
    "Action", "FullStreamAction",
    "pyfilter",
    "RawPacket"
]