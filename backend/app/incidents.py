"""Security incident detection, run on every station reading (and every rejected request).

Kinds                                                                              severity
  data_exposed     station reports D+/D- connected (data_blocked = false)          critical
  over_voltage     voltage above the station's limit (or the station says so)       critical
  over_current     current above OVER_CURRENT_MA (short / malicious load)           critical
  hidden_load      steady small current with no phone pattern: an inline module    critical
  clone            two devices report as the same station (uptime / IP mismatch)   critical
  low_voltage      voltage below the station's limit (or the station says so)       warning
  reversed_current current flows backwards: sensor wiring swapped or tampered      warning
  data_mismatch    reported power does not match V x I: sensor fault or fake data   warning
  supply_lost      charger supply gone (~0 V) while the station is still online     warning
  voltage_spike    voltage jumped >= SPIKE_JUMP_V between two readings              warning
  reboot_loop      station restarted >= REBOOT_LOOP_COUNT times within the window   warning
  dropout          readings missing (gaps) >= DROPOUT_COUNT times within the window warning
  offline          station silent for more than OFFLINE_AFTER_S                     warning
  bad_key          readings claiming this station were rejected for a wrong key     warning
  invalid_data     readings with impossible values were rejected (422)              warning

"Condition" kinds stay open while the condition holds and close on the first good reading.
"Event" kinds (spike, reboot, dropout, clone, bad_key, invalid_data) group events that come
close together; an event incident is over once no new event arrived within its window.
"""
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config
from .models import Device, Incident, Reading
from .schemas import IngestPayload
from .services import thresholds_for

SEVERITY = {
    "data_exposed": "critical", "over_voltage": "critical", "over_current": "critical",
    "hidden_load": "critical", "clone": "critical",
    "low_voltage": "warning", "reversed_current": "warning", "data_mismatch": "warning",
    "supply_lost": "warning", "voltage_spike": "warning", "reboot_loop": "warning",
    "dropout": "warning", "offline": "warning", "bad_key": "warning", "invalid_data": "warning",
}


def event_window(kind: str) -> timedelta | None:
    return {"voltage_spike": timedelta(seconds=config.SPIKE_WINDOW_S),
            "reboot_loop": timedelta(minutes=config.REBOOT_WINDOW_MIN),
            "dropout": timedelta(minutes=config.DROPOUT_WINDOW_MIN),
            "clone": timedelta(minutes=config.CLONE_WINDOW_MIN),
            "bad_key": timedelta(minutes=config.BAD_KEY_WINDOW_MIN),
            "invalid_data": timedelta(minutes=config.BAD_KEY_WINDOW_MIN)}.get(kind)


def is_active(inc: Incident, now: datetime) -> bool:
    if inc.ended_at is not None:
        return False
    w = event_window(inc.kind)
    return w is None or inc.last_seen_at >= now - w


def is_visible(inc: Incident) -> bool:
    """A single restart or a single missed reading is normal; only repeats are incidents."""
    if inc.kind == "reboot_loop":
        return inc.count >= config.REBOOT_LOOP_COUNT
    if inc.kind == "dropout":
        return inc.count >= config.DROPOUT_COUNT
    return True


def _latest_open(db: Session, device_id: str, kind: str) -> Incident | None:
    return db.scalar(select(Incident).where(
        Incident.device_id == device_id, Incident.kind == kind, Incident.ended_at.is_(None)
    ).order_by(Incident.id.desc()).limit(1))


def _bump(db: Session, device_id: str, kind: str, now: datetime, peak: float | None = None,
          detail: dict | None = None, lowest: bool = False, started: datetime | None = None) -> Incident:
    """Extend the open incident of this kind, or start a new one.

    peak keeps the worst value: the highest, or the lowest when lowest=True (low voltage)."""
    inc = _latest_open(db, device_id, kind)
    if inc is not None and not is_active(inc, now):   # event window ran out: that one is over
        inc.ended_at = inc.last_seen_at
        inc = None
    if inc is None:
        inc = Incident(device_id=device_id, kind=kind, started_at=started or now, last_seen_at=now,
                       count=1, peak=peak, detail=detail or {})
        db.add(inc)
        return inc
    inc.count += 1
    inc.last_seen_at = now
    if peak is not None:
        worse = min if lowest else max
        inc.peak = peak if inc.peak is None else worse(inc.peak, peak)
    if detail:
        inc.detail = {**(inc.detail or {}), **detail}
    return inc


def _close(db: Session, device_id: str, kind: str, now: datetime) -> Incident | None:
    inc = _latest_open(db, device_id, kind)
    if inc is not None:
        inc.ended_at = now
    return inc


def _condition(db: Session, device_id: str, kind: str, holds: bool, now: datetime, **kw) -> None:
    if holds:
        _bump(db, device_id, kind, now, **kw)
    else:
        _close(db, device_id, kind, now)


def check_reading(db: Session, device: Device, p: IngestPayload, prev: Reading | None, now: datetime,
                  client_ip: str | None = None) -> None:
    th = thresholds_for(device)
    supply = p.voltage_v >= config.NO_SUPPLY_V

    # Station was silent: that offline incident is over now; record how long it lasted.
    off = _close(db, device.id, "offline", now)
    if off is not None:
        off.detail = {**(off.detail or {}), "silent_s": round((now - (device.last_seen or now)).total_seconds())}

    # 1. data lines exposed
    _condition(db, device.id, "data_exposed", not p.data_blocked, now)

    # 2. voltage out of range (server limit or the station's own sustained flag)
    _condition(db, device.id, "over_voltage", p.voltage_v > th.over_voltage_v or p.device_alert == "HIGH_VOLTAGE",
               now, peak=p.voltage_v, detail={"limit_v": th.over_voltage_v})
    _condition(db, device.id, "low_voltage", supply and (p.voltage_v < th.sag_v or p.device_alert == "LOW_VOLTAGE"),
               now, peak=p.voltage_v, lowest=True, detail={"limit_v": th.sag_v})
    _condition(db, device.id, "supply_lost", not supply, now)

    # 3. current: too much, backwards, or a steady small draw with no phone pattern
    _condition(db, device.id, "over_current", p.current_ma > config.OVER_CURRENT_MA, now,
               peak=p.current_ma, detail={"limit_ma": config.OVER_CURRENT_MA})
    _condition(db, device.id, "reversed_current", p.current_ma < -config.REVERSED_CURRENT_MA, now,
               peak=abs(p.current_ma))
    _condition(db, device.id, "hidden_load", supply and _steady_small_load(db, device.id, p), now,
               peak=p.current_ma)

    # 4. reported power must match V x I (INA219 computes it from the same two values)
    expected = p.voltage_v * p.current_ma
    mismatch = (p.current_ma >= config.CHARGING_CURRENT_MA and supply and
                abs(p.power_mw - expected) > max(config.POWER_MISMATCH_PCT / 100 * expected, 50))
    _condition(db, device.id, "data_mismatch", mismatch, now,
               peak=round(abs(p.power_mw - expected) / expected * 100, 1) if mismatch else None,
               detail={"reported_mw": p.power_mw, "expected_mw": round(expected, 1)} if mismatch else None)

    # 5. sudden voltage jump while a charger is present (plugging in from 0 V is not a spike)
    if prev is not None and prev.voltage_v >= config.NO_SUPPLY_V and supply:
        jump = abs(p.voltage_v - prev.voltage_v)
        if jump >= config.SPIKE_JUMP_V:
            _bump(db, device.id, "voltage_spike", now, peak=round(jump, 3),
                  detail={"from_v": prev.voltage_v, "to_v": p.voltage_v})

    if prev is None:
        return
    elapsed = (now - prev.ts).total_seconds()

    # 6. clone: one board's uptime can't jump ahead of real time, and it can't send from two
    #    addresses within seconds. Both mean a second device is using this station's id.
    clone_why = None
    if prev.uptime_s is not None and p.uptime_s is not None and \
            p.uptime_s > prev.uptime_s + elapsed + config.CLONE_UPTIME_SLACK_S:
        clone_why = "uptime"
    elif client_ip and prev.client_ip and client_ip != prev.client_ip and elapsed < config.OFFLINE_AFTER_S:
        clone_why = "ip"
    if clone_why:
        inc = _bump(db, device.id, "clone", now, detail={"reason": clone_why})
        ips = list((inc.detail or {}).get("ips", []))
        for ip in (prev.client_ip, client_ip):
            if ip and ip not in ips:
                ips = (ips + [ip])[-10:]
        inc.detail = {**(inc.detail or {}), "ips": ips}
    clone_active = clone_why is not None or any(
        is_active(i, now) for i in [_latest_open(db, device.id, "clone")] if i is not None)

    # 7. restarts: uptime went backwards (not counted while a clone is interleaving uptimes)
    if prev.uptime_s is not None and p.uptime_s is not None and p.uptime_s < prev.uptime_s and not clone_active:
        _bump(db, device.id, "reboot_loop", now)

    # 8. dropouts: a gap well beyond the 2 s send interval (flaky Wi-Fi, jamming, power cuts)
    if config.DROPOUT_GAP_S <= elapsed:
        _bump(db, device.id, "dropout", now, peak=round(elapsed, 1))


def _steady_small_load(db: Session, device_id: str, p: IngestPayload) -> bool:
    """A phone's charge current moves around; a hidden module draws a flat, small current."""
    n = config.HIDDEN_LOAD_READINGS
    lo, hi = config.HIDDEN_LOAD_MIN_MA, config.HIDDEN_LOAD_MAX_MA
    if not lo <= p.current_ma <= hi:
        return False
    rows = db.scalars(select(Reading.current_ma).where(Reading.device_id == device_id)
                      .order_by(Reading.id.desc()).limit(n - 1)).all()
    values = [p.current_ma, *rows]
    return len(values) >= n and all(lo <= v <= hi for v in values) and \
        max(values) - min(values) <= config.HIDDEN_LOAD_SPREAD_MA


def sweep_offline(db: Session, now: datetime) -> None:
    """Open an 'offline' incident for every station that went silent. Called when someone looks
    at stations or incidents; started_at is the moment it actually went silent."""
    cutoff = now - timedelta(seconds=config.OFFLINE_AFTER_S)
    silent = db.scalars(select(Device).where(Device.last_seen.is_not(None), Device.last_seen < cutoff)).all()
    changed = False
    for d in silent:
        if _latest_open(db, d.id, "offline") is None:
            db.add(Incident(device_id=d.id, kind="offline", count=1, detail={},
                            started_at=d.last_seen + timedelta(seconds=config.OFFLINE_AFTER_S), last_seen_at=now))
            changed = True
    if changed:
        db.commit()


def _record_rejected(db: Session, kind: str, device_id: str, client_ip: str | None, now: datetime,
                     detail: dict | None = None) -> None:
    if db.get(Device, device_id) is None:
        return  # never create stations from rejected requests
    inc = _bump(db, device_id, kind, now, detail=detail)
    ips = list((inc.detail or {}).get("ips", []))
    if client_ip and client_ip not in ips:
        ips = (ips + [client_ip])[-10:]
    inc.detail = {**(inc.detail or {}), "ips": ips}


def record_bad_key(db: Session, device_id: str, client_ip: str | None, now: datetime) -> None:
    """A reading claiming an existing station was rejected for a wrong API key."""
    _record_rejected(db, "bad_key", device_id, client_ip, now)


def record_invalid(db: Session, device_id: str, client_ip: str | None, now: datetime, errors: list[str]) -> None:
    """A reading with the right key but impossible values (422): broken sensor or forged data."""
    _record_rejected(db, "invalid_data", device_id, client_ip, now, detail={"errors": errors[:5]})
