"""Settings loaded from environment variables / backend/.env."""
import logging
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BACKEND_DIR / ".env")


def _float(name: str, default: float) -> float:
    return float(os.getenv(name, default))


DEVICE_API_KEY: str = os.getenv("DEVICE_API_KEY", "station-key-123")
DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./juiceguard.db")

DEFAULT_SAG_V: float = _float("DEFAULT_SAG_V", 4.50)
DEFAULT_OVER_VOLTAGE_V: float = _float("DEFAULT_OVER_VOLTAGE_V", 5.50)
CHARGING_CURRENT_MA: float = _float("CHARGING_CURRENT_MA", 50)
NO_SUPPLY_V: float = 1.0  # same as firmware: below this the charger is unplugged
OFFLINE_AFTER_S: float = _float("OFFLINE_AFTER_S", 10)

# Commands the firmware understands (see handleServerReply in the sketch).
ALLOWED_COMMANDS = {"blink_led", "sim_data_attempt"}


# ---- Portal logins ---------------------------------------------------------------------------
def _jwt_secret() -> str:
    """JWT_SECRET from .env, else a random one saved in backend/.jwt_secret (never committed)."""
    if os.getenv("JWT_SECRET"):
        return os.environ["JWT_SECRET"]
    f = BACKEND_DIR / ".jwt_secret"
    if not f.exists():
        f.write_text(secrets.token_urlsafe(48))
        logging.getLogger("config").warning("JWT_SECRET not set: generated %s", f.name)
    return f.read_text().strip()


JWT_SECRET: str = _jwt_secret()
SESSION_HOURS: float = _float("SESSION_HOURS", 12)
SESSION_COOKIE = "jg_session"
# True when served over HTTPS (production). Must stay False on plain http://localhost.
COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"

# Too many wrong passwords for one email (or from one IP) in the window -> 429.
LOGIN_MAX_FAILURES: int = int(os.getenv("LOGIN_MAX_FAILURES", 5))
LOGIN_WINDOW_MIN: float = _float("LOGIN_WINDOW_MIN", 15)

FRONTEND_ORIGINS: list[str] = os.getenv(
    "FRONTEND_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",")
