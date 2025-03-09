from dataclasses import dataclass, field
from enum import Enum

class Action(Enum):
    """Action to be taken by the filter"""
    ACCEPT = 0
    DROP = 1
    REJECT = 2
    MANGLE = 3

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
    mangled_packet: bytes = None        
    
    def set_result(self) -> None:
        self.glob["__firegex_pyfilter_result"] = {
            "action": self.action.value,
            "matched_by": self.matched_by,
            "mangled_packet": self.mangled_packet
        }
    
    def reset_result(self) -> None:
        self.glob["__firegex_pyfilter_result"] = None
