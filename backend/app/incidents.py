"""Security incident detection, run on every station reading (and every rejected API key).

Kinds
  data_exposed   station reports D+/D- connected (data_blocked = false)          critical
  over_voltage   voltage above the station's limit (or the station says so)       critical
  voltage_spike  voltage jumped >= SPIKE_JUMP_V between two readings              warning
  reboot_loop    station restarted >= REBOOT_LOOP_COUNT times within the window   warning
  bad_key        readings claiming this station were rejected for a wrong key     warning

"Condition" kinds (data_exposed, over_voltage) stay open while the condition holds and close
on the first good reading. "Event" kinds (spike, reboot, bad_key) group events that come close
together; an event incident is over once no new event arrived within its window.
"""
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config
from .models import Device, Incident, Reading
from .schemas import IngestPayload
from .services import thresholds_for

SEVERITY = {"data_exposed": "critical", "over_voltage": "critical",
            "voltage_spike": "warning", "reboot_loop": "warning", "bad_key": "warning"}


def event_window(kind: str) -> timedelta | None:
    return {"voltage_spike": timedelta(seconds=config.SPIKE_WINDOW_S),
            "reboot_loop": timedelta(minutes=config.REBOOT_WINDOW_MIN),
            "bad_key": timedelta(minutes=config.BAD_KEY_WINDOW_MIN)}.get(kind)


def is_active(inc: Incident, now: datetime) -> bool:
    if inc.ended_at is not None:
        return False
    w = event_window(inc.kind)
    return w is None or inc.last_seen_at >= now - w


def is_visible(inc: Incident) -> bool:
    """A single restart is normal (power cut); only a loop of them is an incident."""
    return inc.kind != "reboot_loop" or inc.count >= config.REBOOT_LOOP_COUNT


def _latest_open(db: Session, device_id: str, kind: str) -> Incident | None:
    return db.scalar(select(Incident).where(
        Incident.device_id == device_id, Incident.kind == kind, Incident.ended_at.is_(None)
    ).order_by(Incident.id.desc()).limit(1))


def _bump(db: Session, device_id: str, kind: str, now: datetime, peak: float | None = None,
          detail: dict | None = None) -> Incident:
    """Extend the open incident of this kind, or start a new one."""
    inc = _latest_open(db, device_id, kind)
    if inc is not None and not is_active(inc, now):   # event window ran out: that one is over
        inc.ended_at = inc.last_seen_at
        inc = None
    if inc is None:
        inc = Incident(device_id=device_id, kind=kind, started_at=now, last_seen_at=now, count=1,
                       peak=peak, detail=detail or {})
        db.add(inc)
        return inc
    inc.count += 1
    inc.last_seen_at = now
    if peak is not None:
        inc.peak = peak if inc.peak is None else max(inc.peak, peak)
    if detail:
        inc.detail = {**(inc.detail or {}), **detail}
    return inc


def _close(db: Session, device_id: str, kind: str, now: datetime) -> None:
    inc = _latest_open(db, device_id, kind)
    if inc is not None:
        inc.ended_at = now


def check_reading(db: Session, device: Device, p: IngestPayload, prev: Reading | None, now: datetime) -> None:
    # 1. data lines exposed
    if not p.data_blocked:
        _bump(db, device.id, "data_exposed", now)
    else:
        _close(db, device.id, "data_exposed", now)

    # 2a. over-voltage (server limit or the station's own HIGH_VOLTAGE flag)
    limit = thresholds_for(device).over_voltage_v
    if p.voltage_v > limit or p.device_alert == "HIGH_VOLTAGE":
        _bump(db, device.id, "over_voltage", now, peak=p.voltage_v, detail={"limit_v": limit})
    else:
        _close(db, device.id, "over_voltage", now)

    # 2b. sudden voltage jump while a charger is present (plugging in from 0 V is not a spike)
    if prev is not None and prev.voltage_v >= config.NO_SUPPLY_V and p.voltage_v >= config.NO_SUPPLY_V:
        jump = abs(p.voltage_v - prev.voltage_v)
        if jump >= config.SPIKE_JUMP_V:
            _bump(db, device.id, "voltage_spike", now, peak=round(jump, 3),
                  detail={"from_v": prev.voltage_v, "to_v": p.voltage_v})

    # 7. restarts: uptime went backwards
    if prev is not None and prev.uptime_s is not None and p.uptime_s is not None and p.uptime_s < prev.uptime_s:
        _bump(db, device.id, "reboot_loop", now)


def record_bad_key(db: Session, device_id: str, client_ip: str | None, now: datetime) -> None:
    """11. A reading claiming an existing station was rejected for a wrong API key."""
    if db.get(Device, device_id) is None:
        return  # never create stations from unauthenticated requests
    inc = _bump(db, device_id, "bad_key", now)
    ips = list((inc.detail or {}).get("ips", []))
    if client_ip and client_ip not in ips:
        ips = (ips + [client_ip])[-10:]
    inc.detail = {**(inc.detail or {}), "ips": ips}
