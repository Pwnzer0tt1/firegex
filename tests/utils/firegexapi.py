import string
from requests import Session
import base64

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
        # A copy, not the dict itself: the form Content-Type belongs to this one request,
        # and writing it into the session's headers left every later JSON post claiming
        # to be a form. It went unnoticed because a successful login replaces the header
        # dict wholesale a moment later — so the only caller it ever broke was one that
        # posts a form and does *not* then set a token.
        headers = dict(self.headers)
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
            pass
        # An instance started with authentication off answers 403 here on purpose, and
        # accepts every request without a token — there is nothing to log in to. Reading
        # that as a failed login is what used to make the whole suite unrunnable against
        # the one configuration where every request is already allowed.
        try:
            return bool(self.status().get("auth_disabled"))
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

    def set_auth_mode(self, disabled: bool):
        """Turn authentication off on a running instance, or back on."""
        req = self.s.post(f"{self.address}api/auth-mode", json={"disabled": disabled})
        return verify(req)

    def set_auth_mode_error(self, disabled: bool):
        req = self.s.post(f"{self.address}api/auth-mode", json={"disabled": disabled})
        if req.status_code < 400:
            return None
        return req.json().get("detail", "")

    def get_interfaces(self):
        req = self.s.get(f"{self.address}api/interfaces")
        return req.json()

    def reset(self, delete: bool):
        self.s.post(f"{self.address}api/reset", json={"delete":delete})

    def export_backup(self):
        req = self.s.get(f"{self.address}api/export")
        return req.json()

    def import_backup(self, backup: dict):
        req = self.s.post(f"{self.address}api/import", json=backup)
        return verify(req)

    # --- Services: the network layer -------------------------------------------
    def services_list(self):
        req = self.s.get(f"{self.address}api/services")
        return req.json()

    def services_get(self, service_id: str):
        req = self.s.get(f"{self.address}api/services/{service_id}")
        return req.json()

    def services_add(self, name: str, ip_int: str, port: int, transport: str,
                     proto: str = "tcp", fail_open: bool = True,
                     tls: bool = False, tls_cert: str | None = None, tls_key: str | None = None,
                     proxy_ip: str | None = None, proxy_port: int | None = None,
                     addresses: list | None = None,
                     max_connections: int = 0, over_limit_forwards: bool = False):
        """A service takes a list of addresses; the single-address case is the common one.

        `tls=True` is kept as a convenience for the callers that read as "and behind
        TLS": it selects the protocol, which is where TLS lives. Passing `proto` directly
        works too, and passing both means the explicit one is a `tls` that agrees.
        """
        if addresses is None:
            addresses = [{"ip_int": ip_int, "port": port,
                          "proxy_ip": proxy_ip, "proxy_port": proxy_port}]
        req = self.s.post(f"{self.address}api/services", json={
            "name": name, "transport": transport, "addresses": addresses,
            "proto": "tls" if tls else proto, "fail_open": fail_open,
            "max_connections": max_connections,
            "over_limit_forwards": over_limit_forwards,
            "tls_cert": tls_cert, "tls_key": tls_key,
        })
        res = req.json()
        if res.get("status") == "ok":
            return res.get("service_id")
        print(f"Failed to create service: {req.status_code} {req.text}")
        return None

    def services_add_error(self, **body):
        """The refusal, for the combinations that are supposed to be refused."""
        req = self.s.post(f"{self.address}api/services", json=body)
        if req.status_code >= 400:
            return req.json().get("detail", "")
        res = req.json()
        return None if res.get("status") == "ok" else res.get("status")

    # --- Services: where they are reachable ------------------------------------
    def services_addresses(self, service_id: str):
        req = self.s.get(f"{self.address}api/services/{service_id}/addresses")
        return req.json()

    def services_add_address(self, service_id: str, ip_int: str, port: int,
                             proxy_ip: str | None = None, proxy_port: int | None = None):
        req = self.s.post(f"{self.address}api/services/{service_id}/addresses", json={
            "ip_int": ip_int, "port": port, "proxy_ip": proxy_ip, "proxy_port": proxy_port,
        })
        return verify(req)

    def services_add_address_error(self, service_id: str, ip_int: str, port: int,
                                   proxy_ip: str | None = None, proxy_port: int | None = None):
        req = self.s.post(f"{self.address}api/services/{service_id}/addresses", json={
            "ip_int": ip_int, "port": port, "proxy_ip": proxy_ip, "proxy_port": proxy_port,
        })
        if req.status_code < 400:
            return None
        return req.json().get("detail", "")

    def services_delete_address(self, service_id: str, address_id: str):
        req = self.s.delete(f"{self.address}api/services/{service_id}/addresses/{address_id}")
        return verify(req)

    def services_delete_address_error(self, service_id: str, address_id: str):
        req = self.s.delete(f"{self.address}api/services/{service_id}/addresses/{address_id}")
        if req.status_code < 400:
            return None
        return req.json().get("detail", "")

    def services_stats(self, service_id: str, range_from: int | None = None,
                       range_to: int | None = None, buckets: int | None = None,
                       step: int | None = None):
        # Built by hand: the session wrapper takes a URL, not request options.
        params = "&".join(
            f"{key}={value}" for key, value in (
                ("range_from", range_from), ("range_to", range_to), ("buckets", buckets),
                ("step", step),
            ) if value is not None
        )
        url = f"{self.address}api/services/{service_id}/stats"
        req = self.s.get(f"{url}?{params}" if params else url)
        return req.json()

    def services_edit(self, service_id: str, **fields):
        req = self.s.put(f"{self.address}api/services/{service_id}", json=fields)
        return verify(req)

    def services_edit_error(self, service_id: str, **fields):
        """The refusal, for the edits that are supposed to be refused."""
        req = self.s.put(f"{self.address}api/services/{service_id}", json=fields)
        if req.status_code < 400:
            return None
        return req.json().get("detail", "")

    def services_delete(self, service_id: str):
        req = self.s.delete(f"{self.address}api/services/{service_id}")
        return verify(req)

    def services_start(self, service_id: str):
        req = self.s.post(f"{self.address}api/services/{service_id}/start")
        return verify(req)

    def services_start_error(self, service_id: str):
        """The refusal, not just the failure: the caller wants to read the reason."""
        req = self.s.post(f"{self.address}api/services/{service_id}/start")
        if req.status_code < 400:
            return None
        return req.json().get("detail", "")

    def services_stop(self, service_id: str):
        req = self.s.post(f"{self.address}api/services/{service_id}/stop")
        return verify(req)

    # --- Services: the filter chain --------------------------------------------
    def services_filters(self, service_id: str):
        req = self.s.get(f"{self.address}api/services/{service_id}/filters")
        return req.json()

    def services_add_filter(self, service_id: str, kind: str, name: str | None = None):
        """No protocol: a pyfilter's is read off its code when the code is saved."""
        req = self.s.post(f"{self.address}api/services/{service_id}/filters",
                          json={"kind": kind, "name": name})
        return verify(req)

    def services_add_filter_error(self, service_id: str, kind: str, name: str | None = None):
        """The refusal, for the cases that are supposed to be refused."""
        req = self.s.post(f"{self.address}api/services/{service_id}/filters",
                          json={"kind": kind, "name": name})
        if req.status_code < 400:
            return None
        return req.json().get("detail", "")

    def services_edit_filter(self, service_id: str, filter_id: str, **fields):
        req = self.s.put(f"{self.address}api/services/{service_id}/filters/{filter_id}",
                         json=fields)
        return verify(req)

    def services_delete_filter(self, service_id: str, filter_id: str):
        req = self.s.delete(f"{self.address}api/services/{service_id}/filters/{filter_id}")
        return verify(req)

    def services_reorder_filters(self, service_id: str, filters: list):
        req = self.s.post(f"{self.address}api/services/{service_id}/filters/order",
                          json={"filters": filters})
        return verify(req)

    # --- Services: a pyfilter's code -------------------------------------------
    def services_get_code(self, service_id: str, filter_id: str):
        req = self.s.get(f"{self.address}api/services/{service_id}/filters/{filter_id}/code")
        return req.text

    def services_set_code(self, service_id: str, filter_id: str, code: str):
        req = self.s.put(f"{self.address}api/services/{service_id}/filters/{filter_id}/code",
                         json={"code": code})
        return verify(req)

    def services_functions(self, service_id: str, filter_id: str):
        req = self.s.get(
            f"{self.address}api/services/{service_id}/filters/{filter_id}/functions")
        return req.json()

    def services_edit_function(self, service_id: str, filter_id: str, name: str, active: bool):
        req = self.s.put(
            f"{self.address}api/services/{service_id}/filters/{filter_id}/functions/{name}",
            json={"active": active})
        return verify(req)

    def services_check_code(self, service_id: str, filter_id: str, code: str):
        """Would this load? Answered without saving, so the result is the body."""
        req = self.s.post(
            f"{self.address}api/services/{service_id}/filters/{filter_id}/check",
            json={"code": code})
        return req.json()

    def services_pyfilter_api(self):
        req = self.s.get(f"{self.address}api/services/pyfilter-api")
        return req.json()

    def services_set_code_error(self, service_id: str, filter_id: str, code: str):
        req = self.s.put(f"{self.address}api/services/{service_id}/filters/{filter_id}/code",
                         json={"code": code})
        if req.status_code < 400:
            return None
        return req.json().get("detail", "")

    # --- Services: a regex filter's patterns -----------------------------------
    def services_regexes(self, service_id: str, filter_id: str):
        req = self.s.get(f"{self.address}api/services/{service_id}/filters/{filter_id}/regexes")
        return req.json()

    def services_add_regex(self, service_id: str, filter_id: str, regex: str,
                           mode: str = "B", case_sensitive: bool = True, active: bool = True):
        """`regex` is the pattern itself; it travels base64-encoded because it is bytes."""
        body = {
            "regex": base64.b64encode(regex.encode()).decode(),
            "mode": mode, "case_sensitive": case_sensitive, "active": active,
        }
        req = self.s.post(
            f"{self.address}api/services/{service_id}/filters/{filter_id}/regexes", json=body)
        return verify(req)

    def services_add_regex_full(self, service_id: str, filter_id: str, **body):
        """The raw form, for the cases that are supposed to be refused."""
        req = self.s.post(
            f"{self.address}api/services/{service_id}/filters/{filter_id}/regexes", json=body)
        if req.status_code < 400:
            return None
        return req.json().get("detail", "")

    def services_add_regex_error(self, service_id: str, filter_id: str, regex: str):
        req = self.s.post(f"{self.address}api/services/{service_id}/filters/{filter_id}/regexes",
                          json={"regex": base64.b64encode(regex.encode()).decode()})
        if req.status_code < 400:
            return None
        return req.json().get("detail", "")

    def services_edit_regex(self, service_id: str, filter_id: str, regex_id: str, **fields):
        req = self.s.put(
            f"{self.address}api/services/{service_id}/filters/{filter_id}/regexes/{regex_id}",
            json=fields)
        return verify(req)

    def services_edit_regex_error(self, service_id: str, filter_id: str, regex_id: str, **fields):
        """The raw form, for the edits that are supposed to be refused."""
        req = self.s.put(
            f"{self.address}api/services/{service_id}/filters/{filter_id}/regexes/{regex_id}",
            json=fields)
        if req.status_code < 400:
            return None
        return req.json().get("detail", "")

    def services_delete_regex(self, service_id: str, filter_id: str, regex_id: str):
        req = self.s.delete(
            f"{self.address}api/services/{service_id}/filters/{filter_id}/regexes/{regex_id}")
        return verify(req)

    # --- Services: the live log ------------------------------------------------
    def services_logs(self, service_id: str):
        req = self.s.get(f"{self.address}api/services/{service_id}/logs")
        return req.json()

    def services_clear_logs(self, service_id: str):
        req = self.s.delete(f"{self.address}api/services/{service_id}/logs")
        return verify(req)

    # --- Services: the pattern tester ------------------------------------------
    def services_debug_regex(self, patterns: list, sample: bytes):
        """`patterns` are {id, expr, case_sensitive}; the sample is raw bytes."""
        req = self.s.post(f"{self.address}api/services/debug-regex", json={
            "patterns": patterns,
            "sample": base64.b64encode(sample).decode(),
        })
        return req.json()

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

