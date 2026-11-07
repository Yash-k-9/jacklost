"""Read/manage stations. Used by the dashboard (phase 4) and for manual testing now."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..db import get_db
from ..models import Command, Device, Reading
from ..schemas import CommandIn, CommandOut, DeviceOut, DeviceUpdate, ReadingOut
from ..services import is_online, seconds_since, thresholds_for

router = APIRouter(prefix="/api/devices", tags=["devices"])


def _out(d: Device) -> DeviceOut:
    online = is_online(d)
    return DeviceOut(
        id=d.id, name=d.name, location=d.location, source=d.source,
        first_seen=d.first_seen, last_seen=d.last_seen, last_ip=d.last_ip,
        last_uptime_s=d.last_uptime_s,
        state=d.state if online else "OFFLINE",
        online=online,
        seconds_since_seen=seconds_since(d),
        thresholds=thresholds_for(d),
    )


def _get(db: Session, device_id: str) -> Device:
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, f"Unknown device {device_id}")
    return d


@router.get("", response_model=list[DeviceOut])
def list_devices(db: Session = Depends(get_db)):
    return [_out(d) for d in db.scalars(select(Device).order_by(Device.id))]


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(device_id: str, db: Session = Depends(get_db)):
    return _out(_get(db, device_id))


@router.patch("/{device_id}", response_model=DeviceOut)
def update_device(device_id: str, body: DeviceUpdate, db: Session = Depends(get_db)):
    d = _get(db, device_id)
    if body.name is not None:
        d.name = body.name
    if body.location is not None:
        d.location = body.location
    t = dict(d.thresholds or {})
    if body.sag_v is not None:
        t["sag_v"] = body.sag_v
    if body.over_voltage_v is not None:
        t["over_voltage_v"] = body.over_voltage_v
    merged = thresholds_for(Device(thresholds=t))
    if merged.sag_v >= merged.over_voltage_v:
        raise HTTPException(422, "sag_v must be lower than over_voltage_v")
    d.thresholds = t
    db.commit()
    return _out(d)


@router.get("/{device_id}/readings", response_model=list[ReadingOut])
def readings(device_id: str, limit: int = Query(100, ge=1, le=5000), db: Session = Depends(get_db)):
    _get(db, device_id)
    rows = db.scalars(
        select(Reading).where(Reading.device_id == device_id).order_by(Reading.id.desc()).limit(limit)
    ).all()
    return list(reversed(rows))  # oldest -> newest, ready for a chart


@router.post("/{device_id}/commands", response_model=CommandOut, status_code=201)
def queue_command(device_id: str, body: CommandIn, db: Session = Depends(get_db)):
    _get(db, device_id)
    if body.name not in config.ALLOWED_COMMANDS:
        raise HTTPException(422, f"Unknown command. Allowed: {sorted(config.ALLOWED_COMMANDS)}")
    cmd = Command(device_id=device_id, name=body.name)
    db.add(cmd)
    db.commit()
    return cmd


@router.get("/{device_id}/commands", response_model=list[CommandOut])
def list_commands(device_id: str, db: Session = Depends(get_db)):
    _get(db, device_id)
    return db.scalars(
        select(Command).where(Command.device_id == device_id).order_by(Command.id.desc()).limit(50)
    ).all()
