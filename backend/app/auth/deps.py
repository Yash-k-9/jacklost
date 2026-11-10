"""FastAPI dependencies: who is calling, and may they touch this station?"""
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import config
from ..db import get_db
from ..models import ROLE_ADMIN, AuditLog, Device, User
from .security import decode_token

_NOT_LOGGED_IN = HTTPException(401, "Not logged in", headers={"WWW-Authenticate": "Bearer"})


def _token_from(request: Request) -> str | None:
    # Browser portals use the httpOnly cookie; /docs and scripts may send a Bearer header.
    if token := request.cookies.get(config.SESSION_COOKIE):
        return token
    auth = request.headers.get("Authorization", "")
    return auth[7:] if auth.lower().startswith("bearer ") else None


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = _token_from(request)
    claims = decode_token(token) if token else None
    if not claims:
        raise _NOT_LOGGED_IN
    user = db.get(User, int(claims["sub"]))
    if user is None or not user.is_active or claims.get("ver") != user.token_version:
        raise _NOT_LOGGED_IN
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != ROLE_ADMIN:
        raise HTTPException(403, "Admins only")
    return user


def get_accessible_device(db: Session, user: User, device_id: str) -> Device:
    """The station, if this user may see it. A host asking for someone else's station gets
    the same 404 as for a missing one, so station ids of other hosts are never confirmed."""
    d = db.get(Device, device_id)
    if d is None or (user.role != ROLE_ADMIN and d.owner_id != user.id):
        raise HTTPException(404, f"Unknown device {device_id}")
    return d


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def audit(db: Session, request: Request, user: User | None, action: str,
          target: str | None = None, detail: dict | None = None) -> None:
    """Adds an audit row to the session; the caller's commit saves it with the change."""
    db.add(AuditLog(user_id=user.id if user else None, action=action, target=target,
                    detail=detail, client_ip=client_ip(request)))
