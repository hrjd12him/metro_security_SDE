from fastapi import FastAPI
from .database import Base, engine
from .logging_config import setup_logging
from .scheduler import start_scheduler, shutdown_scheduler
from .api import router as api_router

setup_logging()
Base.metadata.create_all(bind=engine)

app = FastAPI(title="OktaGuard - Identity Risk Detection")

app.include_router(api_router, prefix="/api", tags=["oktaguard"])


@app.on_event("startup")
def on_startup():
    start_scheduler()


@app.on_event("shutdown")
def on_shutdown():
    shutdown_scheduler()
