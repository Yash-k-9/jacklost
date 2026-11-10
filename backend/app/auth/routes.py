"""/api/auth: sign up, log in, log out, who am I, change password."""
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .. import config
from ..db import get_db, utcnow
from ..models import ROLE_HOST, LoginFailure, User
from ..schemas import ChangePasswordIn, LoginIn, SignupIn, UserOut
from .deps import audit, client_ip, current_user
from .security import create_token, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _set_session(response: Response, user: User) -> None:
    response.set_cookie(
        config.SESSION_COOKIE, create_token(user),
        max_age=int(config.SESSION_HOURS * 3600),
        httponly=True,              # page scripts can't read it
        samesite="lax",             # not sent on cross-site POSTs (CSRF)
        secure=config.COOKIE_SECURE,
        path="/",
    )


def _too_many_failures(db: Session, email: str, ip: str | None) -> bool:
    since = utcnow() - timedelta(minutes=config.LOGIN_WINDOW_MIN)
    recent = select(func.count()).select_from(LoginFailure).where(LoginFailure.ts >= since)
    by_email = db.scalar(recent.where(LoginFailure.email == email))
    by_ip = db.scalar(recent.where(LoginFailure.client_ip == ip)) if ip else 0
    return by_email >= config.LOGIN_MAX_FAILURES or by_ip >= config.LOGIN_MAX_FAILURES * 4


@router.post("/signup", response_model=UserOut, status_code=201)
def signup(body: SignupIn, request: Request, response: Response, db: Session = Depends(get_db)):
    """Anyone can create an end-host account; it is active immediately. Admins are only
    made with scripts/create_admin.py."""
    if db.scalar(select(User).where(User.email == body.email)):
        raise HTTPException(409, "An account with this email already exists")
    user = User(email=body.email, full_name=body.full_name,
                password_hash=hash_password(body.password), role=ROLE_HOST, last_login_at=utcnow())
    db.add(user)
    db.flush()
    audit(db, request, user, "signup")
    db.commit()
    _set_session(response, user)
    return user


@router.post("/login", response_model=UserOut)
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = client_ip(request)
    if _too_many_failures(db, body.email, ip):
        raise HTTPException(429, f"Too many failed logins. Try again in {config.LOGIN_WINDOW_MIN:g} minutes.")

    user = db.scalar(select(User).where(User.email == body.email))
    ok = verify_password(body.password, user.password_hash if user else None)
    if not ok or not user.is_active:
        db.add(LoginFailure(email=body.email, client_ip=ip))
        audit(db, request, user, "login_failed", target=body.email)
        db.commit()
        # One message for every case: does not reveal whether the email exists.
        raise HTTPException(401, "Wrong email or password")

    user.last_login_at = utcnow()
    db.execute(delete(LoginFailure).where(LoginFailure.email == body.email))
    audit(db, request, user, "login")
    db.commit()
    _set_session(response, user)
    return user


@router.post("/logout", status_code=204)
def logout(response: Response):
    response.delete_cookie(config.SESSION_COOKIE, path="/")


@router.post("/logout-all", status_code=204)
def logout_everywhere(request: Request, response: Response,
                      user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Ends every session of this user on every browser."""
    user.token_version += 1
    audit(db, request, user, "logout_all")
    db.commit()
    response.delete_cookie(config.SESSION_COOKIE, path="/")


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@router.post("/change-password", response_model=UserOut)
def change_password(body: ChangePasswordIn, request: Request, response: Response,
                    user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "Current password is wrong")
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1  # log out other browsers
    audit(db, request, user, "password_changed")
    db.commit()
    _set_session(response, user)  # but keep this one logged in
    return user
