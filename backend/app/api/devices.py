"""Stations, as seen from the portals.

Admins see and control every station. End hosts see and control only the stations they
own; anything else answers 404, exactly like a station that does not exist.
"""
import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import config
from ..auth.deps import audit, current_user, get_accessible_device
from ..db import get_db, utcnow
from ..models import ROLE_ADMIN, AuditLog, Command, Device, Reading, User
from ..auth.security import new_pairing_code
from .incidents import count_active
from ..schemas import ClaimIn, CommandIn, CommandOut, DeviceOut, DeviceUpdate, ReadingOut, StationCreate
from ..services import is_online, seconds_since, thresholds_for

router = APIRouter(prefix="/api/devices", tags=["devices"])


def device_out(d: Device, viewer: User, db: Session) -> DeviceOut:
    online = is_online(d)
    admin = viewer.role == ROLE_ADMIN
    owner = db.get(User, d.owner_id) if (admin and d.owner_id) else None
    recent = db.scalars(select(Reading).where(Reading.device_id == d.id).order_by(Reading.id.desc()).limit(40)).all()
    last = recent[0] if recent else None
    return DeviceOut(
        id=d.id, name=d.name, location=d.location, source=d.source,
        first_seen=d.first_seen, last_seen=d.last_seen, last_ip=d.last_ip,
        last_uptime_s=d.last_uptime_s,
        state=d.state if online else "OFFLINE",
        online=online,
        seconds_since_seen=seconds_since(d),
        thresholds=thresholds_for(d),
        owner_id=d.owner_id,
        owner_email=owner.email if owner else None,
        pairing_code=d.pairing_code if admin else None,
        added_at=d.added_at,
        voltage_v=last.voltage_v if last else None,
        current_ma=last.current_ma if last else None,
        power_mw=last.power_mw if last else None,
        data_blocked=last.data_blocked if last else None,
        rssi=last.rssi if last else None,
        power_history=[r.power_mw for r in reversed(recent)],
        active_incidents=count_active(db, d.id),
    )


@router.get("", response_model=list[DeviceOut])
def list_devices(
    owner_id: int | None = Query(None, description="Admins: only this host's stations"),
    unclaimed: bool = Query(False, description="Admins: only stations nobody owns"),
    user: User = Depends(current_user), db: Session = Depends(get_db),
):
    q = select(Device).order_by(Device.id)
    if user.role != ROLE_ADMIN:
        q = q.where(Device.owner_id == user.id)
    elif unclaimed:
        q = q.where(Device.owner_id.is_(None))
    elif owner_id is not None:
        q = q.where(Device.owner_id == owner_id)
    return [device_out(d, user, db) for d in db.scalars(q)]


@router.post("", response_model=DeviceOut, status_code=201)
def add_station(body: StationCreate, request: Request,
                user: User = Depends(current_user), db: Session = Depends(get_db)):
    """A host adds a station by its device_id, no admin approval needed.

    New id: the station is created on the host's account and starts showing readings as soon
    as the ESP32 with that id sends one. Already sending but nobody's: it moves to this host.
    Owned by someone else: refused. The admin sees who added it (Host column + audit log).
    """
    if user.role == ROLE_ADMIN:
        raise HTTPException(403, "Admins assign stations to hosts from the Admin page")
    now = utcnow()
    d = db.get(Device, body.device_id)
    if d is not None and d.owner_id == user.id:
        raise HTTPException(409, "This station is already on your account")
    if d is not None and d.owner_id is not None:
        raise HTTPException(409, "This station ID is already used by another account")
    created = d is None
    if created:
        d = Device(id=body.device_id, first_seen=now, pairing_code=new_pairing_code())
        db.add(d)
    d.owner_id, d.added_at = user.id, now
    if body.name:
        d.name = body.name.strip()
    if body.location:
        d.location = body.location.strip()
    audit(db, request, user, "device_added", target=d.id,
          detail={"new": created, "name": d.name, "location": d.location})
    db.commit()
    return device_out(d, user, db)


@router.post("/claim", response_model=DeviceOut)
def claim_device(body: ClaimIn, request: Request,
                 user: User = Depends(current_user), db: Session = Depends(get_db)):
    """A host adds a station to their account with its id + pairing code."""
    recent_fails = db.scalar(select(func.count()).select_from(AuditLog).where(
        AuditLog.user_id == user.id, AuditLog.action == "claim_failed",
        AuditLog.ts >= utcnow() - timedelta(minutes=15)))
    if recent_fails >= 10:
        raise HTTPException(429, "Too many wrong pairing codes. Try again in 15 minutes.")
    d = db.get(Device, body.device_id.strip())
    code_ok = d is not None and bool(d.pairing_code) and secrets.compare_digest(
        d.pairing_code, body.pairing_code.strip().upper())
    if not code_ok:
        audit(db, request, user, "claim_failed", target=body.device_id)
        db.commit()
        raise HTTPException(404, "No station with this id and pairing code")
    if d.owner_id == user.id:
        return device_out(d, user, db)
    if d.owner_id is not None:
        raise HTTPException(409, "This station is already registered to another account")
    d.owner_id, d.added_at = user.id, utcnow()
    audit(db, request, user, "device_claimed", target=d.id)
    db.commit()
    return device_out(d, user, db)


@router.post("/{device_id}/release", status_code=204)
def release_device(device_id: str, request: Request,
                   user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Removes the station from its host's account (the host itself, or an admin)."""
    d = get_accessible_device(db, user, device_id)
    if d.owner_id is None:
        return
    audit(db, request, user, "device_released", target=d.id, detail={"previous_owner_id": d.owner_id})
    d.owner_id = d.added_at = None
    db.commit()


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(device_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return device_out(get_accessible_device(db, user, device_id), user, db)


@router.patch("/{device_id}", response_model=DeviceOut)
def update_device(device_id: str, body: DeviceUpdate, request: Request,
                  user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = get_accessible_device(db, user, device_id)
    changes = body.model_dump(exclude_none=True)
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
    if changes:
        audit(db, request, user, "device_updated", target=d.id, detail=changes)
    db.commit()
    return device_out(d, user, db)


@router.get("/{device_id}/readings", response_model=list[ReadingOut])
def readings(device_id: str, limit: int = Query(100, ge=1, le=5000),
             user: User = Depends(current_user), db: Session = Depends(get_db)):
    get_accessible_device(db, user, device_id)
    rows = db.scalars(
        select(Reading).where(Reading.device_id == device_id).order_by(Reading.id.desc()).limit(limit)
    ).all()
    return list(reversed(rows))  # oldest -> newest, ready for a chart


@router.post("/{device_id}/commands", response_model=CommandOut, status_code=201)
def queue_command(device_id: str, body: CommandIn, request: Request,
                  user: User = Depends(current_user), db: Session = Depends(get_db)):
    get_accessible_device(db, user, device_id)
    if body.name not in config.ALLOWED_COMMANDS:
        raise HTTPException(422, f"Unknown command. Allowed: {sorted(config.ALLOWED_COMMANDS)}")
    cmd = Command(device_id=device_id, name=body.name)
    db.add(cmd)
    audit(db, request, user, "command_sent", target=device_id, detail={"command": body.name})
    db.commit()
    return cmd


@router.get("/{device_id}/commands", response_model=list[CommandOut])
def list_commands(device_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    get_accessible_device(db, user, device_id)
    return db.scalars(
        select(Command).where(Command.device_id == device_id).order_by(Command.id.desc()).limit(50)
    ).all()
