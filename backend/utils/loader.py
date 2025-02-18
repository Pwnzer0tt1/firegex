
import os
import httpx
from typing import Callable
from fastapi import APIRouter
from starlette.responses import StreamingResponse
from fastapi.responses import FileResponse
from utils import DEBUG, ON_DOCKER, ROUTERS_DIR, list_files, run_func
from utils.models import ResetRequest

REACT_BUILD_DIR: str = "../frontend/build/" if not ON_DOCKER else "frontend/"
REACT_HTML_PATH: str = os.path.join(REACT_BUILD_DIR,"index.html")

async def frontend_debug_proxy(path):
    httpc = httpx.AsyncClient()
    req = httpc.build_request("GET",f"http://127.0.0.1:{os.getenv('F_PORT','5173')}/"+path)
    resp = await httpc.send(req, stream=True)
    return StreamingResponse(resp.aiter_bytes(),status_code=resp.status_code, headers=resp.headers)

async def react_deploy(path):
    file_request = os.path.join(REACT_BUILD_DIR, path)
    if not os.path.isfile(file_request):
        return FileResponse(REACT_HTML_PATH, media_type='text/html')
    else:
        return FileResponse(file_request)

def frontend_deploy(app):
    @app.get("/{full_path:path}", include_in_schema=False)
    async def catch_all(full_path:str):
        if DEBUG:
            try:
                return await frontend_debug_proxy(full_path)
            except Exception:
                return {"details":"Frontend not started at "+f"http://127.0.0.1:{os.getenv('F_PORT','5173')}"}
        else:
            return await react_deploy(full_path)
        
def list_routers():
    return [ele[:-3] for ele in list_files(ROUTERS_DIR) if ele != "__init__.py" and " " not in ele and ele.endswith(".py")]

class RouterModule():
    router: APIRouter|None = None
    reset: Callable|None = None
    startup: Callable|None = None
    shutdown: Callable|None = None
    name: str
    
    def __init__(self, router: APIRouter, reset: Callable, startup: Callable, shutdown: Callable, name:str):
        self.router = router
        self.reset = reset
        self.startup = startup
        self.shutdown = shutdown
        self.name = name
        
    def __repr__(self):
        return f"RouterModule(router={self.router}, reset={self.reset}, startup={self.startup}, shutdown={self.shutdown})"

def get_router_modules():
    res: list[RouterModule] = []
    for route in list_routers():
        try:
            module = getattr(__import__(f"routers.{route}"), route, None)
            if module:
                res.append(RouterModule(
                    router=getattr(module, "app", None),
                    reset=getattr(module, "reset", None),
                    startup=getattr(module, "startup", None),
                    shutdown=getattr(module, "shutdown", None),
                    name=route
                ))
        except Exception as e:
            print(f"Router {route} failed to load: {e}")
    return res

def load_routers(app):
    resets, startups, shutdowns = [], [], []
    for router in get_router_modules():
        if router.router:
            app.include_router(router.router, prefix=f"/{router.name}", tags=[router.name])
        else:
            print(f"Router {router.name} is not loaded")
            continue
        if router.reset:
            resets.append(router.reset)
        if router.startup:
            startups.append(router.startup)
        if router.shutdown:
            shutdowns.append(router.shutdown)
    async def reset(reset_option:ResetRequest):
        for func in resets:
            await run_func(func, reset_option)
    async def startup():
        for func in startups:
            await run_func(func)
    async def shutdown():
        for func in shutdowns:
            await run_func(func)
    return reset, startup, shutdown
