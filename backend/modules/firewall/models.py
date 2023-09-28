from enum import Enum

class Rule:
    def __init__(self, proto: str, src:str, dst:str, port_src_from:str, port_dst_from:str, port_src_to:str, port_dst_to:str, action:str, mode:str):
        self.proto = proto
        self.src = src
        self.dst = dst
        self.port_src_from = port_src_from
        self.port_dst_from = port_dst_from
        self.port_src_to = port_src_to
        self.port_dst_to = port_dst_to
        self.action = action
        self.input_mode = mode == "in"
        self.output_mode = mode == "out"
        self.forward_mode = mode == "forward"
        
    
    @classmethod
    def from_dict(cls, var: dict):
        return cls(
            proto=var["proto"],
            src=var["src"],
            dst=var["dst"],
            port_dst_from=var["port_dst_from"],
            port_dst_to=var["port_dst_to"],
            port_src_from=var["port_src_from"],
            port_src_to=var["port_src_to"],
            action=var["action"],
            mode=var["mode"]
        )

class Protocol(str, Enum):
    TCP = "tcp",
    UDP = "udp",
    BOTH = "both",
    ANY = "any"
    
    
class Mode(str, Enum):
    IN = "in",
    OUT = "out",
    FORWARD = "forward"

class Action(str, Enum):
    ACCEPT = "accept",
    DROP = "drop",
    REJECT = "reject"