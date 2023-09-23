from pydantic import BaseModel

class StatusMessageModel(BaseModel):
    status:str
    
class StatusModel(BaseModel):
    status: str
    loggined: bool
    version: str

class PasswordForm(BaseModel):
    password: str

class PasswordChangeForm(BaseModel):
    password: str
    expire: bool

class ChangePasswordModel(BaseModel):
    status: str
    access_token: str|None = None

class IpInterface(BaseModel):
    addr: str
    name: str
    
class ResetRequest(BaseModel):
    delete:bool