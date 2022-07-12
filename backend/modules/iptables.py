import os, re
from subprocess import PIPE, Popen
from typing import Dict, List, Tuple, Union

class Rule():
    def __init__(self, id, target, prot, opt, source, destination, details):
        self.id = id
        self.target = target
        self.prot = prot
        self.opt = opt
        self.source = source
        self.destination = destination
        self.details = details
    
    def __repr__(self) -> str:
        return f"Rule {self.id} : {self.target}, {self.prot}, {self.opt}, {self.source}, {self.destination}, {self.details}"

    def dport(self) -> Union[int, None]:
        port = re.findall(r"dpt:([0-9]+)", self.details)
        return int(port[0]) if port else None
    
    def sport(self) -> Union[int, None]:
        port = re.findall(r"spt:([0-9]+)", self.details)
        return int(port[0]) if port else None

    def nfqueue(self) -> Union[Tuple[int,int], None]:
        balanced = re.findall(r"NFQUEUE balance ([0-9]+):([0-9]+)", self.details)
        numbered = re.findall(r"NFQUEUE num ([0-9]+)", self.details)
        queue_num = None
        if balanced: queue_num = (int(balanced[0][0]), int(balanced[0][1]))
        if numbered: queue_num = (int(numbered[0]), int(numbered[0]))
        return queue_num

class IPTables:

    def __init__(self, ipv6=False, table="filter"):
        self.ipv6 = ipv6
        self.table = table
    
    def command(self, params) -> Tuple[bytes, bytes]:
        params = ["-t", self.table] + params
        if os.geteuid() != 0:
            exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
        return Popen(["ip6tables"]+params if self.ipv6 else ["iptables"]+params, stdout=PIPE, stderr=PIPE).communicate()

    def list(self) -> Dict[str, List[Rule]]:
        stdout, strerr = self.command(["-L", "--line-number", "-n"])
        lines = stdout.decode().split("\n")
        res: Dict[str, List[Rule]] = {}
        chain_name = ""
        for line in lines:
            if line.startswith("Chain"):
                chain_name = line.split()[1]
                res[chain_name] = []
            elif line and line.split()[0].isnumeric():
                parsed = re.findall(r"([^ ]*)[ ]{,10}([^ ]*)[ ]{,5}([^ ]*)[ ]{,5}([^ ]*)[ ]{,5}([^ ]*)[ ]+([^ ]*)[ ]+(.*)", line)
                if len(parsed) > 0:
                    parsed = parsed[0]
                    res[chain_name].append(Rule(
                        id=parsed[0].strip(),
                        target=parsed[1].strip(),
                        prot=parsed[2].strip(),
                        opt=parsed[3].strip(),
                        source=parsed[4].strip(),
                        destination=parsed[5].strip(),
                        details=" ".join(parsed[6:]).strip() if len(parsed) >= 7 else ""
                    ))
        return res

    def delete_rule(self, chain, id) -> None:
        self.command(["-D", str(chain), str(id)])
    
    def create_chain(self, name) -> None:
        self.command(["-N", str(name)])

    def flush_chain(self, name) -> None:
        self.command(["-F", str(name)])

    def insert_rule(self, chain, rule, *args, rulenum=1) -> None:
        self.command(["-I", str(chain), str(rulenum), "-j", str(rule), *args])
    
    def append_rule(self, chain, rule, *args) -> None:
        self.command(["-A", str(chain), "-j", str(rule), *args])


