"""Small shared helpers used by more than one router."""
from . import config
from .db import utcnow
from .models import Device
from .schemas import Thresholds


def thresholds_for(device: Device | None) -> Thresholds:
    overrides = (device.thresholds or {}) if device else {}
    return Thresholds(
        sag_v=overrides.get("sag_v", config.DEFAULT_SAG_V),
        over_voltage_v=overrides.get("over_voltage_v", config.DEFAULT_OVER_VOLTAGE_V),
    )


def compute_state(voltage_v: float, current_ma: float, device_alert: str, data_blocked: bool,
                  thresholds: Thresholds | None = None) -> str:
    """State for one reading.

    TAMPER        the station says data lines are NOT blocked (firmware modified?)
    OVER_VOLTAGE  voltage above the station's limit, or the station flags HIGH_VOLTAGE
    NO_SUPPLY     charger voltage missing
    LOW_VOLTAGE   voltage below the station's limit, or the station flags LOW_VOLTAGE
    IDLE          charger present, no phone drawing current
    CHARGING      a phone is drawing current

    The server checks the limits itself on every reading: the station only raises its own flag
    after 3 bad readings in a row, so a sudden surge would otherwise show as CHARGING.
    """
    t = thresholds or Thresholds(sag_v=config.DEFAULT_SAG_V, over_voltage_v=config.DEFAULT_OVER_VOLTAGE_V)
    if not data_blocked:
        return "TAMPER"
    if voltage_v > t.over_voltage_v or device_alert == "HIGH_VOLTAGE":
        return "OVER_VOLTAGE"
    if voltage_v < config.NO_SUPPLY_V:
        return "NO_SUPPLY"
    if voltage_v < t.sag_v or device_alert == "LOW_VOLTAGE":
        return "LOW_VOLTAGE"
    if current_ma >= config.CHARGING_CURRENT_MA:
        return "CHARGING"
    return "IDLE"


def seconds_since(device: Device) -> float | None:
    if device.last_seen is None:
        return None
    return (utcnow() - device.last_seen).total_seconds()


def is_online(device: Device) -> bool:
    s = seconds_since(device)
    return s is not None and s <= config.OFFLINE_AFTER_S
