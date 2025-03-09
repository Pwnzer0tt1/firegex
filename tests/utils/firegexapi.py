import string
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

    def delete(self, endpoint, json={}):
        return self.s.delete(endpoint, json=json, headers=self.headers)
    
    def put(self, endpoint, json={}):
        return self.s.put(endpoint, json=json, headers=self.headers)

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
    
    def login(self,password: str):
        req = self.s.post(f"{self.address}api/login", data=f"username=login&password={password}")
        try : 
            self.s.set_token(req.json()["access_token"])
            return True
        except Exception:
            return False

    def logout(self):
        self.s.unset_token()
        return True

    def set_password(self,password: str):
        req = self.s.post(f"{self.address}api/set-password", json={"password":password})
        if verify(req):
            self.s.set_token(req.json()["access_token"])
            return True
        else:
            return False

    def change_password(self, password: str, expire: bool):
        req = self.s.post(f"{self.address}api/change-password", json={"password":password, "expire":expire})
        if verify(req):
            self.s.set_token(req.json()["access_token"])
            return True
        else:
            return False

    def get_interfaces(self):
        req = self.s.get(f"{self.address}api/interfaces")
        return req.json()

    def reset(self, delete: bool):
        self.s.post(f"{self.address}api/reset", json={"delete":delete})

    def nfregex_get_services(self):
        req = self.s.get(f"{self.address}api/nfregex/services")
        return req.json() 

    def nfregex_get_service(self,service_id: str):
        req = self.s.get(f"{self.address}api/nfregex/services/{service_id}")
        return req.json()

    def nfregex_stop_service(self,service_id: str):
        req = self.s.post(f"{self.address}api/nfregex/services/{service_id}/stop")
        return verify(req)
    
    def nfregex_start_service(self,service_id: str):
        req = self.s.post(f"{self.address}api/nfregex/services/{service_id}/start")
        return verify(req)

    def nfregex_delete_service(self,service_id: str):
        req = self.s.delete(f"{self.address}api/nfregex/services/{service_id}")
        return verify(req)

    def nfregex_rename_service(self,service_id: str, newname: str):
        req = self.s.put(f"{self.address}api/nfregex/services/{service_id}/rename" , json={"name":newname})
        return verify(req)
    
    def nfregex_settings_service(self,service_id: str, port: int, proto: str, ip_int: str, fail_open: bool):
        req = self.s.put(f"{self.address}api/nfregex/services/{service_id}/settings" , json={"port":port, "proto":proto, "ip_int":ip_int, "fail_open":fail_open})
        return verify(req)

    def nfregex_get_service_regexes(self,service_id: str):
        req = self.s.get(f"{self.address}api/nfregex/services/{service_id}/regexes")
        return req.json()

    def nfregex_get_regex(self,regex_id: str):
        req = self.s.get(f"{self.address}api/nfregex/regexes/{regex_id}")
        return req.json()
    
    def nfregex_delete_regex(self,regex_id: str):
        req = self.s.delete(f"{self.address}api/nfregex/regexes/{regex_id}")
        return verify(req)
    
    def nfregex_enable_regex(self,regex_id: str):
        req = self.s.post(f"{self.address}api/nfregex/regexes/{regex_id}/enable")
        return verify(req)

    def nfregex_disable_regex(self,regex_id: str):
        req = self.s.post(f"{self.address}api/nfregex/regexes/{regex_id}/disable")
        return verify(req)

    def nfregex_add_regex(self, service_id: str, regex: str, mode: str, active: bool, is_case_sensitive: bool):
        req = self.s.post(f"{self.address}api/nfregex/regexes", 
            json={"service_id": service_id, "regex": regex, "mode": mode, "active": active, "is_case_sensitive": is_case_sensitive})
        return verify(req)

    def nfregex_add_service(self, name: str, port: int, proto: str, ip_int: str, fail_open: bool = False):
        req = self.s.post(f"{self.address}api/nfregex/services" , 
            json={"name":name,"port":port, "proto": proto, "ip_int": ip_int, "fail_open": fail_open})
        return req.json()["service_id"] if verify(req) else False 

    def nfregex_get_metrics(self):
        req = self.s.get(f"{self.address}api/nfregex/metrics")
        return req.text

    #PortHijack
    def ph_get_services(self):
        req = self.s.get(f"{self.address}api/porthijack/services")
        return req.json() 

    def ph_get_service(self,service_id: str):
        req = self.s.get(f"{self.address}api/porthijack/services/{service_id}")
        return req.json()

    def ph_stop_service(self,service_id: str):
        req = self.s.post(f"{self.address}api/porthijack/services/{service_id}/stop")
        return verify(req)
    
    def ph_start_service(self,service_id: str):
        req = self.s.post(f"{self.address}api/porthijack/services/{service_id}/start")
        return verify(req)

    def ph_delete_service(self,service_id: str):
        req = self.s.delete(f"{self.address}api/porthijack/services/{service_id}")
        return verify(req)

    def ph_rename_service(self,service_id: str,newname: str):
        req = self.s.put(f"{self.address}api/porthijack/services/{service_id}/rename" , json={"name":newname})
        return verify(req)

    def ph_change_destination(self,service_id: str, ip_dst:string , proxy_port: int):
        req = self.s.put(f"{self.address}api/porthijack/services/{service_id}/change-destination", json={"ip_dst": ip_dst, "proxy_port": proxy_port})
        return verify(req)

    def ph_add_service(self, name: str, public_port: int, proxy_port: int, proto: str, ip_src: str, ip_dst: str):
        req = self.s.post(f"{self.address}api/porthijack/services" , 
            json={"name":name, "public_port": public_port, "proxy_port":proxy_port, "proto": proto, "ip_src": ip_src, "ip_dst": ip_dst})
        return req.json()["service_id"] if verify(req) else False 

    def nfproxy_get_services(self):
        req = self.s.get(f"{self.address}api/nfproxy/services")
        return req.json() 

    def nfproxy_get_service(self,service_id: str):
        req = self.s.get(f"{self.address}api/nfproxy/services/{service_id}")
        return req.json()

    def nfproxy_stop_service(self,service_id: str):
        req = self.s.post(f"{self.address}api/nfproxy/services/{service_id}/stop")
        return verify(req)
    
    def nfproxy_start_service(self,service_id: str):
        req = self.s.post(f"{self.address}api/nfproxy/services/{service_id}/start")
        return verify(req)

    def nfproxy_delete_service(self,service_id: str):
        req = self.s.delete(f"{self.address}api/nfproxy/services/{service_id}")
        return verify(req)

    def nfproxy_rename_service(self,service_id: str, newname: str):
        req = self.s.put(f"{self.address}api/nfproxy/services/{service_id}/rename" , json={"name":newname})
        return verify(req)
    
    def nfproxy_settings_service(self,service_id: str, port: int, ip_int: str, fail_open: bool):
        req = self.s.put(f"{self.address}api/nfproxy/services/{service_id}/settings" , json={"port":port, "ip_int":ip_int, "fail_open":fail_open})
        return verify(req)

    def nfproxy_get_service_pyfilters(self,service_id: str):
        req = self.s.get(f"{self.address}api/nfproxy/services/{service_id}/pyfilters")
        return req.json()

    def nfproxy_get_pyfilter(self, service_id:str, filter_name: str):
        req = self.s.get(f"{self.address}api/nfproxy/services/{service_id}/pyfilters/{filter_name}")
        return req.json()
    
    def nfproxy_enable_pyfilter(self, service_id:str, filter_name: str):
        req = self.s.post(f"{self.address}api/nfproxy/services/{service_id}/pyfilters/{filter_name}/enable")
        return verify(req)

    def nfproxy_disable_pyfilter(self, service_id:str, filter_name: str):
        req = self.s.post(f"{self.address}api/nfproxy/services/{service_id}/pyfilters/{filter_name}/disable")
        return verify(req)

    def nfproxy_add_service(self, name: str, port: int, proto: str, ip_int: str, fail_open: bool = False):
        req = self.s.post(f"{self.address}api/nfproxy/services" , 
            json={"name":name,"port":port, "proto": proto, "ip_int": ip_int, "fail_open": fail_open})
        return req.json()["service_id"] if verify(req) else False 

    def nfproxy_get_code(self, service_id: str):
        req = self.s.get(f"{self.address}api/nfproxy/services/{service_id}/code")
        return req.text
    
    def nfproxy_set_code(self, service_id: str, code: str):
        req = self.s.put(f"{self.address}api/nfproxy/services/{service_id}/code", json={"code":code})
        return verify(req)