"""/api/admin: everything only admins may do."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth.deps import audit, require_admin
from ..auth.security import new_pairing_code
from ..db import get_db, utcnow
from ..models import ROLE_HOST, AuditLog, Device, User
from ..schemas import AdminUserOut, AdminUserUpdate, AssignIn, AuditOut, DeviceOut, UserOut
from .devices import device_out

router = APIRouter(prefix="/api/admin", tags=["admin"], dependencies=[Depends(require_admin)])


def _user_out(db: Session, u: User) -> AdminUserOut:
    count = db.scalar(select(func.count()).select_from(Device).where(Device.owner_id == u.id))
    return AdminUserOut(**UserOut.model_validate(u).model_dump(), device_count=count)


def _user(db: Session, user_id: int) -> User:
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, f"Unknown user {user_id}")
    return u


def _device(db: Session, device_id: str) -> Device:
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, f"Unknown device {device_id}")
    return d


@router.get("/users", response_model=list[AdminUserOut])
def list_users(role: str | None = Query(None, pattern="^(admin|host)$"), db: Session = Depends(get_db)):
    q = select(User).order_by(User.id)
    if role:
        q = q.where(User.role == role)
    return [_user_out(db, u) for u in db.scalars(q)]


@router.get("/users/{user_id}", response_model=AdminUserOut)
def get_user(user_id: int, db: Session = Depends(get_db)):
    return _user_out(db, _user(db, user_id))


@router.patch("/users/{user_id}", response_model=AdminUserOut)
def update_user(user_id: int, body: AdminUserUpdate, request: Request,
                admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    u = _user(db, user_id)
    if body.is_active is False and u.id == admin.id:
        raise HTTPException(400, "You can't deactivate your own account")
    if body.full_name is not None:
        u.full_name = body.full_name.strip()
    if body.is_active is not None and body.is_active != u.is_active:
        u.is_active = body.is_active
        if not body.is_active:
            u.token_version += 1  # end their sessions right away
    audit(db, request, admin, "user_updated", target=u.email, detail=body.model_dump(exclude_none=True))
    db.commit()
    return _user_out(db, u)


@router.post("/devices/{device_id}/assign", response_model=DeviceOut)
def assign_device(device_id: str, body: AssignIn, request: Request,
                  admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    d = _device(db, device_id)
    if body.user_id is not None and _user(db, body.user_id).role != ROLE_HOST:
        raise HTTPException(422, "Stations can only be assigned to end-host accounts")
    audit(db, request, admin, "device_assigned", target=d.id,
          detail={"from_user_id": d.owner_id, "to_user_id": body.user_id})
    d.owner_id = body.user_id
    d.added_at = utcnow() if body.user_id is not None else None
    db.commit()
    return device_out(d, admin, db)


@router.post("/devices/{device_id}/pairing-code", response_model=DeviceOut)
def regenerate_pairing_code(device_id: str, request: Request,
                            admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """New code, e.g. after a label leaked. Does not change who owns the station."""
    d = _device(db, device_id)
    d.pairing_code = new_pairing_code()
    audit(db, request, admin, "pairing_code_regenerated", target=d.id)
    db.commit()
    return device_out(d, admin, db)


@router.get("/audit", response_model=list[AuditOut])
def audit_log(
    user_id: int | None = None,
    action: str | None = None,
    target: str | None = None,
    limit: int = Query(200, ge=1, le=2000),
    db: Session = Depends(get_db),
):
    q = select(AuditLog, User.email).outerjoin(User, User.id == AuditLog.user_id)
    if user_id is not None:
        q = q.where(AuditLog.user_id == user_id)
    if action:
        q = q.where(AuditLog.action == action)
    if target:
        q = q.where(AuditLog.target == target)
    rows = db.execute(q.order_by(AuditLog.id.desc()).limit(limit)).all()
    return [AuditOut.model_validate(row).model_copy(update={"user_email": email}) for row, email in rows]
