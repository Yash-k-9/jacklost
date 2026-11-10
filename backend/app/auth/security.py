"""Password hashing and session tokens."""
import secrets
from datetime import timedelta

import bcrypt
import jwt

from .. import config
from ..db import utcnow
from ..models import User

_ALG = "HS256"
# Checked against when the email does not exist, so a wrong email costs as long as a
# wrong password and response time does not reveal which accounts exist.
_DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt()).decode()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), (password_hash or _DUMMY_HASH).encode())
    except ValueError:
        return False


def create_token(user: User) -> str:
    now = utcnow()
    claims = {
        "sub": str(user.id),
        "role": user.role,
        "ver": user.token_version,
        "iat": now,
        "exp": now + timedelta(hours=config.SESSION_HOURS),
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(claims, config.JWT_SECRET, algorithm=_ALG)


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, config.JWT_SECRET, algorithms=[_ALG], options={"require": ["sub", "exp"]})
    except jwt.PyJWTError:
        return None


def new_pairing_code() -> str:
    """8 chars, no look-alikes (0/O, 1/I/L), easy to read off a label."""
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(8))
