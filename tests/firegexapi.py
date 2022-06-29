from requests import Session

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
    
    def setToken(self,token):
         self.headers = {"Authorization": f"Bearer {token}"}
    
    def unsetToken(self):
        self.headers = {}

class FiregexAPI:
    def __init__(self,address):
        self.s = BearerSession()
        self.address = address
    
    def login(self,password):
        req = self.s.post(f"{self.address}api/login", data=f"username=login&password={password}")
        try : 
            self.s.setToken(req.json()["access_token"])
            return True
        except Exception:
            return False

    def logout(self):
        self.s.unsetToken()
        return True

    def change_password(self,password,expire):
        req = self.s.post(f"{self.address}api/change-password", json={"password":password, "expire":expire})
        try: 
            self.s.setToken(req.json()["access_token"])
            return True
        except Exception:
            return False

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
    
