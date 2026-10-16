from dataclasses import dataclass, field
from enum import Enum

class Action(Enum):
    """Action to be taken by the filter.

    There used to be a fourth, `MANGLE` (`UNSTABLE_MANGLE` to a filter author): replace
    the payload and let the chunk carry on. It was removed because it could not keep its
    promise on a stream — a filter only ever sees one chunk, so a pattern split across
    two of them was never manglable, and the miss was silent: nothing blocked, nothing
    logged. The numbering is left as it is rather than closed up, because the value is
    the wire format between the library and the datapath and reusing 3 for something
    else is how an old filter starts meaning a new thing.
    """
    ACCEPT = 0
    DROP = 1
    REJECT = 2

class ExceptionAction(Enum):
    """Action to be taken by the filter when an exception occurs (used in some cases)"""
    ACCEPT = 0
    DROP = 1
    REJECT = 2
    NOACTION = 3

class FullStreamAction(Enum):
    """Action to be taken by the filter when the stream is full"""
    FLUSH = 0
    ACCEPT = 1
    REJECT = 2
    DROP = 3

@dataclass
class FilterHandler:
    """Filter handler"""
    func: callable
    name: str
    params: dict[type, callable]
    proto: str

@dataclass
class PacketHandlerResult:
    """Packet handler result"""
    glob: dict = field(repr=False)
    action: Action = Action.ACCEPT
    matched_by: str = None

    def set_result(self) -> None:
        self.glob["__firegex_pyfilter_result"] = {
            "action": self.action.value,
            "matched_by": self.matched_by,
        }
    
    def reset_result(self) -> None:
        self.glob["__firegex_pyfilter_result"] = None
