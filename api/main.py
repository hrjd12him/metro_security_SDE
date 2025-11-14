from fastapi import FastAPI
from okta_guard.api.routes import router
from okta_guard.core.config import setup_logging, SCAN_SCHEDULE_SECS
from okta_guard.tasks.scanners import start_scheduler, stop_scheduler

setup_logging()
app = FastAPI(title="OktaGuard", version="0.1.0")
app.include_router(router)

@app.on_event("startup")
def _startup():
    if SCAN_SCHEDULE_SECS > 0:
        start_scheduler()

@app.on_event("shutdown")
def _shutdown():
    stop_scheduler()
