"""Juice Guard backend.

Run from the backend/ folder:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api import devices, ingest
from .db import init_db, utcnow

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    log.info("Database ready. Waiting for stations on POST /api/ingest")
    yield


app = FastAPI(title="Juice Guard - USB charging station monitor", version="0.1.0", lifespan=lifespan)

# The React dashboard (phase 4) runs on another port during development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    # Short, readable message: the ESP32 prints this body on the Serial Monitor.
    errors = [f"{'.'.join(str(p) for p in e['loc'][1:])}: {e['msg']}" for e in exc.errors()]
    log.warning("422 from %s: %s", request.client.host if request.client else "?", errors)
    return JSONResponse(status_code=422, content={"detail": errors})


@app.get("/api/health")
def health():
    return {"status": "ok", "server_time": utcnow().isoformat() + "Z"}


app.include_router(ingest.router)
app.include_router(devices.router)
