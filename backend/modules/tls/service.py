from modules.tls.manager import TLSManager
from modules.tls.nginx import update_nginx
from modules.tls.nftables import tls_firewall
from utils import socketio_emit

async def reload_tls():
    update_nginx()
    tls_firewall.reload()
    await socketio_emit(["tls_streams"])

async def activate_stream(stream_id: str | None) -> bool:
    """Activate a TLS stream if it exists and isn't already active. Returns False if the stream doesn't exist."""
    if not stream_id:
        return False
    manager = TLSManager()
    stream = manager.get_stream(stream_id)
    if not stream:
        return False
    if stream["status"] != "active":
        manager.update_status(stream_id, "active")
        await reload_tls()
    return True
