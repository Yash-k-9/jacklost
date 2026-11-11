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

# ---- Security incidents -----------------------------------------------------------------------
# Voltage jump between two consecutive readings (both above NO_SUPPLY_V) that counts as a spike.
SPIKE_JUMP_V: float = _float("SPIKE_JUMP_V", 1.0)
SPIKE_WINDOW_S: float = _float("SPIKE_WINDOW_S", 60)        # spikes this close together = one incident
REBOOT_LOOP_COUNT: int = int(os.getenv("REBOOT_LOOP_COUNT", 3))  # restarts within the window -> alert
REBOOT_WINDOW_MIN: float = _float("REBOOT_WINDOW_MIN", 60)
BAD_KEY_WINDOW_MIN: float = _float("BAD_KEY_WINDOW_MIN", 10)  # wrong-key attempts this close = one incident
OVER_CURRENT_MA: float = _float("OVER_CURRENT_MA", 2500)       # above this: short / malicious load
REVERSED_CURRENT_MA: float = _float("REVERSED_CURRENT_MA", 20)  # current below -this: wiring swapped
POWER_MISMATCH_PCT: float = _float("POWER_MISMATCH_PCT", 20)    # reported power vs V x I
# Hidden inline module: this many readings in a row, all between MIN and MAX mA, within SPREAD mA.
HIDDEN_LOAD_READINGS: int = int(os.getenv("HIDDEN_LOAD_READINGS", 8))
HIDDEN_LOAD_MIN_MA: float = _float("HIDDEN_LOAD_MIN_MA", 60)
HIDDEN_LOAD_MAX_MA: float = _float("HIDDEN_LOAD_MAX_MA", 250)
HIDDEN_LOAD_SPREAD_MA: float = _float("HIDDEN_LOAD_SPREAD_MA", 30)
# Clone: uptime ahead of real elapsed time by more than this (s), or two IPs within OFFLINE_AFTER_S.
CLONE_UPTIME_SLACK_S: float = _float("CLONE_UPTIME_SLACK_S", 10)
CLONE_WINDOW_MIN: float = _float("CLONE_WINDOW_MIN", 10)
# Dropouts: a gap of this many seconds between readings counts; DROPOUT_COUNT in the window = alert.
DROPOUT_GAP_S: float = _float("DROPOUT_GAP_S", 5)
DROPOUT_COUNT: int = int(os.getenv("DROPOUT_COUNT", 3))
DROPOUT_WINDOW_MIN: float = _float("DROPOUT_WINDOW_MIN", 5)
