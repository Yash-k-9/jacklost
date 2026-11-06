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


def compute_state(voltage_v: float, current_ma: float, device_alert: str, data_blocked: bool) -> str:
    """Phase-1 state for one reading. Phase 3 replaces this with the full detection engine.

    NO_SUPPLY  charger voltage missing
    IDLE       charger present, no phone drawing current
    CHARGING   a phone is drawing current
    ALERT      the station itself reports a sustained voltage problem
    TAMPER     the station says data lines are NOT blocked (firmware modified?)
    """
    if not data_blocked:
        return "TAMPER"
    if voltage_v < config.NO_SUPPLY_V:
        return "NO_SUPPLY"
    if device_alert != "NONE":
        return "ALERT"
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
