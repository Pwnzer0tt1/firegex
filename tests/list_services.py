from utils.firegexapi import FiregexAPI
api = FiregexAPI("http://127.0.0.1:4444/")
api.login("testpassword")
print(api.s.get("http://127.0.0.1:4444/api/services").json())
