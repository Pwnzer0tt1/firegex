from requests import Session

class ProxyAPI:
    def __init__(self,address,password):
        self.s = Session()
        self.address = address
        self.password = password
    
    def connect(self):
        req = self.s.post(f"{self.address}api/login", json={"password":self.password})
        return req.json()["status"] == "ok"

    def create_service(self,service_name,service_port):
        req = self.s.post(f"{self.address}api/services/add" , json={"name":service_name,"port":service_port})
        return req.json()["status"] == "ok"
    
    def get_service_details(self,service_name):
        req = self.s.get(f"{self.address}api/services")
        internal_port = service_id = None
        try:
            for service in req.json():
                if service["name"] == service_name:
                    service_id = service["id"]
                    internal_port = service["internal_port"]
                    break
        except Exception:
            pass
        return service_id,internal_port

    def get_service_status(self,service_id):
        req = self.s.get(f"{self.address}api/service/{service_id}")
        return req.json()["status"]

    def get_service_regexes(self,service_id):
        req = self.s.get(f"{self.address}api/service/{service_id}/regexes")
        return req.json()
        
    def start(self,service_id):
        req = self.s.get(f"{self.address}api/service/{service_id}/start")
        return req.json()["status"] == "ok"

    def pause(self,service_id):
        req = self.s.get(f"{self.address}api/service/{service_id}/pause")
        return req.json()["status"] == "ok"

    def stop(self,service_id):
        req = self.s.get(f"{self.address}api/service/{service_id}/stop")
        return req.json()["status"] == "ok"
    
    def delete(self,service_id):
        req = self.s.get(f"{self.address}api/service/{service_id}/delete")
        return req.json()["status"] == "ok"
    
    def add_regex(self,service_id,regex,is_blacklist = True, is_case_sensitive = True, mode = "B"):
        req = self.s.post(f"{self.address}api/regexes/add", 
            json={"is_blacklist":is_blacklist,"is_case_sensitive":is_case_sensitive,"service_id":service_id,"mode":mode,"regex":regex})
        return req.json()["status"] == "ok"
    
