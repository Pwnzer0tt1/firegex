from signal import SIGUSR1
from secrets import token_urlsafe
import subprocess, re, os


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
        self.public_host = public_host
        self.public_port = public_port
        self.internal_host = internal_host
        self.internal_port = internal_port
        self.filters = set(filters) if filters else set([])
        self.process = None
        self.callback_blocked_update = callback_blocked_update
        self.config_file_path = None
        while self.config_file_path is None:
            config_file_path = os.path.join("/tmp/" + token_urlsafe(16))
            if not os.path.exists(config_file_path):
                self.config_file_path = config_file_path
    
    def start(self, in_pause=False):
        if self.process is None:
            filter_map = self.compile_filters()
            filters_codes = list(filter_map.keys()) if not in_pause else []
            proxy_binary_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),"./proxy")
            try:
                self.__write_config(filters_codes)
                
                self.process = subprocess.Popen(
                    [proxy_binary_path, str(self.public_host), str(self.public_port), str(self.internal_host), str(self.internal_port), self.config_file_path],
                    stdout=subprocess.PIPE, universal_newlines=True
                )
                for stdout_line in iter(self.process.stdout.readline, ""):
                    if stdout_line.startswith("BLOCKED"):
                        regex_id = stdout_line.split()[1]
                        filter_map[regex_id].blocked+=1
                        if self.callback_blocked_update: self.callback_blocked_update(filter_map[regex_id])
                self.process.stdout.close()
                return self.process.wait()
            finally:
                self.__delete_config()
    
    def stop(self):
        if self.process:
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
    
    def __write_config(self, filters_codes):
        with open(self.config_file_path,'w') as config_file:
            for line in filters_codes:
                config_file.write(line + '\n')
    
    def __delete_config(self):
        if os.path.exists(self.config_file_path):
            os.remove(self.config_file_path)

    def reload(self):
        if self.isactive():
            filter_map = self.compile_filters()
            filters_codes = list(filter_map.keys())
            self.__write_config(filters_codes)
            self.trigger_reload_config()

    def isactive(self):
        return True if self.process else False

    def trigger_reload_config(self):
        self.process.send_signal(SIGUSR1)


    def pause(self):
        if self.isactive():
            self.__write_config([])
            self.trigger_reload_config()
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
