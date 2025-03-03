from dataclasses import dataclass, field
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

@dataclass
class FilterHandler:
    func: callable
    name: str
    params: dict[type, callable]
    proto: str

@dataclass
class PacketHandlerResult:
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


