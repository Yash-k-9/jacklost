"""Settings loaded from environment variables / backend/.env."""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


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
