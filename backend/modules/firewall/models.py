from enum import Enum
from utils import PortType
from pydantic import BaseModel

class Rule:
    def __init__(self, proto: str, src:str, dst:str, port_src_from:str, port_dst_from:str, port_src_to:str, port_dst_to:str, action:str, mode:str, **other):
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
        return cls(**var)

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
    
class RuleModel(BaseModel):
    active: bool
    name: str
    proto: Protocol
    src: str
    dst: str
    port_src_from: PortType
    port_dst_from: PortType
    port_src_to: PortType
    port_dst_to: PortType
    action: Action
    mode:Mode

class RuleFormAdd(BaseModel):
    rules: list[RuleModel]
    policy: Action
    
class RuleInfo(BaseModel):
    rules: list[RuleModel]
    policy: Action
    enabled: bool

class RenameForm(BaseModel):
    name:str

class FirewallSettings(BaseModel):
    keep_rules: bool
    allow_loopback: bool
    allow_established: bool
    allow_icmp: bool
    multicast_dns: bool
    allow_upnp: bool