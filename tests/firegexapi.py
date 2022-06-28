from requests import Session

class FiregexAPI:
    def __init__(self,address):
        self.s = Session()
        self.address = address
    
    def login(self,password):
        req = self.s.post(f"{self.address}api/login", json={"password":password})
        return req.json()["status"] == "ok"

    def logout(self):
        req = self.s.get(f"{self.address}api/logout")
        return req.json()["status"] == "ok"

    def create_service(self,service_name,service_port):
        req = self.s.post(f"{self.address}api/services/add" , json={"name":service_name,"port":service_port})
        return req.json()["status"] == "ok"
    
    def get_service_details(self,service_name):
        req = self.s.get(f"{self.address}api/services")
        service = None
        try:
            for service in req.json():
                if service["name"] == service_name:
                    return service
        except Exception:
            pass
        return service

    def get_service_status(self,service_id):
        req = self.s.get(f"{self.address}api/service/{service_id}")
        return req.json()["status"]

    def get_service_regexes(self,service_id):
        req = self.s.get(f"{self.address}api/service/{service_id}/regexes")
        return req.json()
    
    def get_regex(self,regex_id):
        req = self.s.get(f"{self.address}api/regex/{regex_id}")
        return req.json()

    def add_regex(self,service_id,regex,is_blacklist = True, is_case_sensitive = True, mode = "B"):
        req = self.s.post(f"{self.address}api/regexes/add", 
            json={"is_blacklist":is_blacklist,"is_case_sensitive":is_case_sensitive,"service_id":service_id,"mode":mode,"regex":regex})
        return req.json()["status"] == "ok"
    
    def delete_regex(self,regex_id):
        req = self.s.get(f"{self.address}api/regex/{regex_id}/delete")
        return req.json()["status"] == "ok"

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
    