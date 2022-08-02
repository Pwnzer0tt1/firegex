from requests import Session

def verify(req):
    try:
        assert(req.json()["status"] == "ok")
    except Exception:
        return False
    return True

class BearerSession():
    def __init__(self):
        self.s = Session()
        self.headers = {}

    def post(self, endpoint, json={}, data=""):
        headers = self.headers
        if data:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        return self.s.post(endpoint, json=json, data=data, headers=headers)

    def get(self, endpoint, json={}):
        return self.s.get(endpoint, json=json, headers=self.headers)
    
    def set_token(self,token):
         self.headers = {"Authorization": f"Bearer {token}"}
    
    def unset_token(self):
        self.headers = {}

class FiregexAPI:
    def __init__(self,address):
        self.s = BearerSession()
        self.address = address
    
    #General API
    def status(self):
        return self.s.get(f"{self.address}api/status").json()
    
    def login(self,password):
        req = self.s.post(f"{self.address}api/login", data=f"username=login&password={password}")
        try : 
            self.s.set_token(req.json()["access_token"])
            return True
        except Exception:
            return False

    def logout(self):
        self.s.unset_token()
        return True

    def set_password(self,password):
        req = self.s.post(f"{self.address}api/set-password", json={"password":password})
        if verify(req):
            self.s.set_token(req.json()["access_token"])
            return True
        else:
            return False

    def change_password(self,password,expire):
        req = self.s.post(f"{self.address}api/change-password", json={"password":password, "expire":expire})
        if verify(req):
            self.s.set_token(req.json()["access_token"])
            return True
        else:
            return False

    def get_interfaces(self):
        req = self.s.get(f"{self.address}api/interfaces")
        return req.json()

    def reset(self, delete):
        req = self.s.post(f"{self.address}api/reset", json={"delete":delete})

    #Netfilter regex
    def nf_get_stats():
        req = self.s.get(f"{self.address}api/nfregex/stats")
        return req.json()

    def nf_get_services(self):
        req = self.s.get(f"{self.address}api/nfregex/services")
        return req.json() 

    def nf_get_service(self,service_id):
        req = self.s.get(f"{self.address}api/nfregex/service/{service_id}")
        return req.json()

    def nf_stop_service(self,service_id):
        req = self.s.get(f"{self.address}api/nfregex/service/{service_id}/stop")
        return verify(req)
    
    def nf_start_service(self,service_id):
        req = self.s.get(f"{self.address}api/nfregex/service/{service_id}/start")
        return verify(req)

    def nf_delete_service(self,service_id):
        req = self.s.get(f"{self.address}api/nfregex/service/{service_id}/delete")
        return verify(req)

    def nf_rename_service(self,service_id,newname):
        req = self.s.post(f"{self.address}api/nfregex/service/{service_id}/rename" , json={"name":newname})
        return verify(req)

    def nf_get_service_regexes(self,service_id):
        req = self.s.get(f"{self.address}api/nfregex/service/{service_id}/regexes")
        return req.json()

    def nf_get_regex(self,regex_id):
        req = self.s.get(f"{self.address}api/nfregex/regex/{regex_id}")
        return req.json()
    
    def nf_delete_regex(self,regex_id):
        req = self.s.get(f"{self.address}api/nfregex/regex/{regex_id}/delete")
        return verify(req)
    
    def nf_enable_regex(self,regex_id):
        req = self.s.get(f"{self.address}api/nfregex/regex/{regex_id}/enable")
        return verify(req)

    def nf_disable_regex(self,regex_id):
        req = self.s.get(f"{self.address}api/nfregex/regex/{regex_id}/disable")
        return verify(req)

    def nf_add_regex(self, service_id: str, regex: str, mode: str, active: bool, is_blacklist: bool, is_case_sensitive: bool):
        req = self.s.post(f"{self.address}api/nfregex/regexes/add", 
            json={"service_id": service_id, "regex": regex, "mode": mode, "active": active, "is_blacklist": is_blacklist, "is_case_sensitive": is_case_sensitive})
        return verify(req)

    def nf_add_service(self, name: str, port: int, proto: str, ip_int: str):
        req = self.s.post(f"{self.address}api/nfregex/services/add" , 
            json={"name":name,"port":port, "proto": proto, "ip_int": ip_int})
        return req.json()["service_id"] if verify(req) else False 

    #Proxy regex
    def px_get_stats():
        req = self.s.get(f"{self.address}api/regexproxy/stats")
        return req.json() 

    def px_get_services(self):
        req = self.s.get(f"{self.address}api/regexproxy/services")
        return req.json()

    def px_get_service(self,service_id):
        req = self.s.get(f"{self.address}api/regexproxy/service/{service_id}")
        return req.json()

    def px_stop_service(self,service_id):
        req = self.s.get(f"{self.address}api/regexproxy/service/{service_id}/stop")
        return verify(req)
    
    def px_pause_service(self,service_id):
        req = self.s.get(f"{self.address}api/regexproxy/service/{service_id}/pause")
        return verify(req)

    def px_start_service(self,service_id):
        req = self.s.get(f"{self.address}api/regexproxy/service/{service_id}/start")
        return verify(req)

    def px_delete_service(self,service_id):
        req = self.s.get(f"{self.address}api/regexproxy/service/{service_id}/delete")
        return verify(req)

    def px_change_service_port(self,service_id, port, internalPort):
        payload = {}
        if port: payload["port"] = port
        if internalPort: payload["internalPort"] = internalPort
        req = self.s.post(f"{self.address}api/regexproxy/service/{service_id}/start", json=payload)
        return req.json() if verify(req) else False

    def px_get_service_regexes(self,service_id):
        req = self.s.get(f"{self.address}api/regexproxy/service/{service_id}/regexes")
        return req.json() 

    def px_get_regex(self,regex_id):
        req = self.s.get(f"{self.address}api/regexproxy/regex/{regex_id}")
        return req.json() 
    
    def px_delete_regex(self,regex_id):
        req = self.s.get(f"{self.address}api/regexproxy/regex/{regex_id}/delete")
        return verify(req)
    
    def px_enable_regex(self,regex_id):
        req = self.s.get(f"{self.address}api/regexproxy/regex/{regex_id}/enable")
        return verify(req)

    def px_disable_regex(self,regex_id):
        req = self.s.get(f"{self.address}api/regexproxy/regex/{regex_id}/disable")
        return verify(req)

    def px_add_regex(self, service_id: str, regex: str, mode: str, active: bool, is_blacklist: bool, is_case_sensitive: bool):
        req = self.s.post(f"{self.address}api/regexproxy/regexes/add", 
            json={"service_id": service_id, "regex": regex, "mode": mode, "active": active, "is_blacklist": is_blacklist, "is_case_sensitive": is_case_sensitive})
        return verify(req)

    def px_rename_service(self,service_id,newname):
        req = self.s.post(f"{self.address}api/regexproxy/service/{service_id}/rename" , json={"name":newname})
        return verify(req)

    def px_add_service(self, name: str, port: int, internalPort: [int,None]):
        req = self.s.post(f"{self.address}api/regexproxy/services/add" , 
            json={"name":name,"port":port, "internalPort": internalPort})
        return req.json()["service_id"] if verify(req) else False 