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
    #: True turns authentication off, False turns it back on. The two are **not**
    #: symmetrical and the endpoint says so rather than this form: turning it off is an
    #: administrator's deployment choice, while turning it on — asked while it is off,
    #: when every caller is already an administrator — takes a token this instance signed
    #: *before* it was turned off, and a password to ask for. See `set_auth_mode`.
    disabled: bool

class ChangePasswordModel(BaseModel):
    status: str
    access_token: str|None = None

class IpInterface(BaseModel):
    addr: str
    name: str
    
class ResetRequest(BaseModel):
    delete:bool