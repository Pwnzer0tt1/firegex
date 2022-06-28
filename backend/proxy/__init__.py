import subprocess, re, os
from threading import Lock

#c++ -o proxy proxy.cpp

class Filter:
    def __init__(self, regex, is_case_sensitive=True, is_blacklist=True, c_to_s=False, s_to_c=False, blocked_packets=0, code=None):
        self.regex = regex
        self.is_case_sensitive = is_case_sensitive
        self.is_blacklist = is_blacklist
        if c_to_s == s_to_c: c_to_s = s_to_c = True # (False, False) == (True, True)
        self.c_to_s = c_to_s
        self.s_to_c = s_to_c
        self.blocked = blocked_packets
        self.code = code
    
    def compile(self):
        if isinstance(self.regex, str): self.regex = self.regex.encode()
        if not isinstance(self.regex, bytes): raise Exception("Invalid Regex Paramether")
        re.compile(self.regex) # raise re.error if is invalid!
        case_sensitive = "1" if self.is_case_sensitive else "0"
        if self.c_to_s:
            yield case_sensitive + "C" + self.regex.hex() if self.is_blacklist else case_sensitive + "c"+ self.regex.hex()
        if self.s_to_c:
            yield case_sensitive + "S" + self.regex.hex() if self.is_blacklist else case_sensitive + "s"+ self.regex.hex()

class Proxy:
    def __init__(self, internal_port, public_port, callback_blocked_update=None, filters=None, public_host="0.0.0.0", internal_host="127.0.0.1"):
        self.filter_map = {}
        self.filter_map_lock = Lock()
        self.update_config_lock = Lock()
        self.status_change = Lock()
        self.public_host = public_host
        self.public_port = public_port
        self.internal_host = internal_host
        self.internal_port = internal_port
        self.filters = set(filters) if filters else set([])
        self.process = None
        self.callback_blocked_update = callback_blocked_update
    
    def start(self, in_pause=False):
        self.status_change.acquire()
        if not self.isactive():
            try:
                self.filter_map = self.compile_filters()
                filters_codes = list(self.filter_map.keys()) if not in_pause else []
                proxy_binary_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),"./proxy")

                self.process = subprocess.Popen(
                    [ proxy_binary_path, str(self.public_host), str(self.public_port), str(self.internal_host), str(self.internal_port)],
                    stdout=subprocess.PIPE, stdin=subprocess.PIPE, universal_newlines=True
                )
                self.update_config(filters_codes)
            finally:
                self.status_change.release()

            for stdout_line in iter(self.process.stdout.readline, ""):
                if stdout_line.startswith("BLOCKED"):
                    regex_id = stdout_line.split()[1]
                    with self.filter_map_lock:
                        self.filter_map[regex_id].blocked+=1
                        if self.callback_blocked_update: self.callback_blocked_update(self.filter_map[regex_id])
            self.process.stdout.close()
            return self.process.wait()
        else:
            self.status_change.release()
                 

    def stop(self):
        with self.status_change:
            if self.isactive():
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except Exception:
                    self.process.kill()
                    return False
                finally:
                    self.process = None
            return True

    def restart(self, in_pause=False):
        status = self.stop()
        self.start(in_pause=in_pause)
        return status
    
    def update_config(self, filters_codes):
        with self.update_config_lock:
            if (self.isactive()):
                self.process.stdin.write(" ".join(filters_codes)+"\n")
                self.process.stdin.flush()

    def reload(self):
        if self.isactive():
            with self.filter_map_lock:
                self.filter_map = self.compile_filters()
                filters_codes = list(self.filter_map.keys())
                self.update_config(filters_codes)

    def isactive(self):
        if self.process and not self.process.poll() is None:
            self.process = None
        return True if self.process else False

    def pause(self):
        if self.isactive():
            self.update_config([])
        else:
            self.start(in_pause=True)

    def compile_filters(self):
        res = {}
        for filter_obj in self.filters:
            try:
                raw_filters = filter_obj.compile()
                for filter in raw_filters:
                    res[filter] = filter_obj
            except Exception: pass
        return res
