from pydantic import BaseModel

class StatusMessageModel(BaseModel):
    status:str
    
class StatusModel(BaseModel):
    status: str
    loggined: bool
    version: str
    auth_disabled: bool = False

class PasswordForm(BaseModel):
    password: str

class PasswordChangeForm(BaseModel):
    password: str
    expire: bool

class AuthModeForm(BaseModel):
    #: True turns authentication off. False is only ever a no-op here: putting it back on
    #: is a decision that has to come from the host — see `set_auth_mode`.
    disabled: bool

class ChangePasswordModel(BaseModel):
    status: str
    access_token: str|None = None

class IpInterface(BaseModel):
    addr: str
    name: str
    
class ResetRequest(BaseModel):
    delete:bool