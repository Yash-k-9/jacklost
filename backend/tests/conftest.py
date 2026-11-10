import os
import tempfile
import uuid

# Throwaway database and secrets, set before the app is imported.
_tmp = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["DEVICE_API_KEY"] = "test-key"
os.environ["JWT_SECRET"] = "test-secret-not-for-production-0123456789"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.auth.security import hash_password  # noqa: E402
from app.db import SessionLocal, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import ROLE_ADMIN, LoginFailure, User  # noqa: E402

init_db()

KEY = {"X-API-Key": "test-key"}
PASSWORD = "Secret123"


def payload(**over):
    p = {
        "device_id": "station-01", "voltage_v": 5.02, "source_voltage_v": 5.10, "shunt_mv": 80.0,
        "current_ma": 800.0, "power_mw": 4016.0, "data_blocked": True, "device_alert": "NONE",
        "source": "esp32", "rssi": -60, "uptime_s": 42,
    }
    p.update(over)
    return p


def unique_email(prefix: str = "user") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def new_client():
    """Factory for extra, independent browsers (each keeps its own cookies)."""
    clients = []

    def make():
        c = TestClient(app)
        c.__enter__()
        clients.append(c)
        return c

    yield make
    for c in clients:
        c.__exit__(None, None, None)


def signup(c: TestClient, email: str | None = None, password: str = PASSWORD, name: str = "Host"):
    email = email or unique_email("host")
    r = c.post("/api/auth/signup", json={"email": email, "full_name": name, "password": password})
    assert r.status_code == 201, r.text
    return r.json()


def make_admin(email: str | None = None) -> str:
    email = email or unique_email("admin")
    with SessionLocal() as db:
        db.add(User(email=email, full_name="Admin", password_hash=hash_password(PASSWORD), role=ROLE_ADMIN))
        db.commit()
    return email


def login(c: TestClient, email: str, password: str = PASSWORD):
    return c.post("/api/auth/login", json={"email": email, "password": password})


@pytest.fixture
def admin(new_client):
    c = new_client()
    assert login(c, make_admin()).status_code == 200
    return c


@pytest.fixture(autouse=True)
def _clear_login_failures():
    with SessionLocal() as db:
        db.query(LoginFailure).delete()
        db.commit()
