"""Security incidents, as seen from the portals. Hosts see their own stations' incidents only."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth.deps import audit, current_user, get_accessible_device
from ..db import get_db, utcnow
from ..incidents import SEVERITY, is_active, is_visible
from ..models import ROLE_ADMIN, Device, Incident, User
from ..schemas import IncidentOut

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


def incident_out(inc: Incident, dev: Device | None, viewer: User, db: Session, now) -> IncidentOut:
    owner = db.get(User, dev.owner_id) if (viewer.role == ROLE_ADMIN and dev and dev.owner_id) else None
    return IncidentOut(
        id=inc.id, device_id=inc.device_id, device_name=dev.name if dev else None,
        owner_email=owner.email if owner else None, kind=inc.kind, severity=SEVERITY.get(inc.kind, "warning"),
        active=is_active(inc, now), started_at=inc.started_at, last_seen_at=inc.last_seen_at,
        ended_at=inc.ended_at or (None if is_active(inc, now) else inc.last_seen_at),
        count=inc.count, peak=inc.peak, detail=inc.detail, acknowledged_at=inc.acknowledged_at,
    )


def count_active(db: Session, device_id: str) -> int:
    now = utcnow()
    rows = db.scalars(select(Incident).where(Incident.device_id == device_id, Incident.ended_at.is_(None))).all()
    return sum(1 for i in rows if is_visible(i) and is_active(i, now))


@router.get("", response_model=list[IncidentOut])
def list_incidents(
    device_id: str | None = Query(None, description="Only this station"),
    active_only: bool = Query(False),
    limit: int = Query(100, ge=1, le=1000),
    user: User = Depends(current_user), db: Session = Depends(get_db),
):
    q = select(Incident, Device).join(Device, Device.id == Incident.device_id).order_by(Incident.last_seen_at.desc())
    if device_id is not None:
        get_accessible_device(db, user, device_id)  # 404 if not theirs
        q = q.where(Incident.device_id == device_id)
    elif user.role != ROLE_ADMIN:
        q = q.where(Device.owner_id == user.id)
    if active_only:
        q = q.where(Incident.ended_at.is_(None))
    now = utcnow()
    out = []
    for inc, dev in db.execute(q.limit(limit * 3)):  # extra rows: some are filtered below
        if not is_visible(inc) or (active_only and not is_active(inc, now)):
            continue
        out.append(incident_out(inc, dev, user, db, now))
        if len(out) >= limit:
            break
    return out


@router.post("/{incident_id}/ack", response_model=IncidentOut)
def acknowledge(incident_id: int, request: Request,
                user: User = Depends(current_user), db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "Incident not found")
    dev = get_accessible_device(db, user, inc.device_id)  # hosts: only their own stations
    if inc.acknowledged_at is None:
        inc.acknowledged_at, inc.acknowledged_by = utcnow(), user.id
        audit(db, request, user, "incident_acknowledged", target=inc.device_id, detail={"kind": inc.kind, "incident_id": inc.id})
        db.commit()
    return incident_out(inc, dev, user, db, utcnow())
