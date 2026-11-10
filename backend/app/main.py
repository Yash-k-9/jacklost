"""Juice Guard backend.

Run from the backend/ folder:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import config
from .api import admin, devices, ingest
from .auth import routes as auth_routes
from .auth.security import new_pairing_code
from .db import SessionLocal, init_db, utcnow
from .models import ROLE_ADMIN, Device, User

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("app")


def _startup_checks() -> None:
    with SessionLocal() as db:
        # Stations registered before logins existed get a pairing code too.
        for d in db.query(Device).filter(Device.pairing_code.is_(None)):
            d.pairing_code = new_pairing_code()
        db.commit()
        if not db.query(User).filter(User.role == ROLE_ADMIN).first():
            log.warning("No admin account yet. Create one: python scripts/create_admin.py")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    _startup_checks()
    log.info("Database ready. Waiting for stations on POST /api/ingest")
    yield


app = FastAPI(title="Juice Guard - USB charging station monitor", version="0.2.0", lifespan=lifespan)

# The React portals run on another port during development. Credentials = the login cookie.
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
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
app.include_router(auth_routes.router)
app.include_router(devices.router)
app.include_router(admin.router)


# Simple status page (frontend/index.html) at http://<pc-ip>:8000/
# Mounted last so it never shadows the /api routes.
FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"
if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
