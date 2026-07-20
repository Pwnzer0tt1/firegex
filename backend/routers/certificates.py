from fastapi import APIRouter
from pydantic import BaseModel
from utils.models import StatusMessageModel
from utils.certs import CertsDB

app = APIRouter()

class CertificateModel(BaseModel):
    ip_int: str
    port: int
    cert: str
    key: str

class CertificateResponseModel(BaseModel):
    ip_int: str
    port: int
    cert: str | None = None
    key: str | None = None

@app.get("", response_model=CertificateResponseModel)
async def get_certificate(ip_int: str, port: int):
    """Retrieve TLS certificate and key by ip_int and port"""
    cert, key = CertsDB().get_cert_and_key(ip_int, port)
    return {"ip_int": ip_int, "port": port, "cert": cert, "key": key}

@app.post("", response_model=StatusMessageModel)
async def upsert_certificate(form: CertificateModel):
    """Create or update TLS certificate and key"""
    CertsDB().upsert_cert_and_key(form.ip_int, form.port, form.cert, form.key)
    return {"status": "ok"}

@app.delete("", response_model=StatusMessageModel)
async def delete_certificate(ip_int: str, port: int):
    """Delete TLS certificate and key by ip_int and port"""
    CertsDB().delete_cert_and_key(ip_int, port)
    return {"status": "ok"}
