class Rule:
    def __init__(self, proto: str, ip_src:str, ip_dst:str, port_src_from:str, port_dst_from:str, port_src_to:str, port_dst_to:str, action:str, mode:str):
        self.proto = proto
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.port_src_from = port_src_from
        self.port_dst_from = port_dst_from
        self.port_src_to = port_src_to
        self.port_dst_to = port_dst_to
        self.action = action
        self.input_mode = mode in ["I"]
        self.output_mode = mode in ["O"]
        
    
    @classmethod
    def from_dict(cls, var: dict):
        return cls(
            proto=var["proto"],
            ip_src=var["ip_src"],
            ip_dst=var["ip_dst"],
            port_dst_from=var["port_dst_from"],
            port_dst_to=var["port_dst_to"],
            port_src_from=var["port_src_from"],
            port_src_to=var["port_src_to"],
            action=var["action"],
            mode=var["mode"]
        )