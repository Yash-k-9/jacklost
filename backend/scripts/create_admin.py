"""Create an admin account, or turn an existing account into an admin with a new password.

Run from the backend folder:
    ..\\.venv\\Scripts\\python scripts\\create_admin.py

Admins can't sign up through the website. This script is the only way to make one.
"""
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pydantic import ValidationError  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.auth.security import hash_password  # noqa: E402
from app.db import SessionLocal, init_db  # noqa: E402
from app.models import ROLE_ADMIN, User  # noqa: E402
from app.schemas import SignupIn  # noqa: E402


def main() -> None:
    init_db()
    email = input("Admin email: ").strip().lower()
    name = input("Full name: ").strip() or "Administrator"
    while True:
        pw = getpass.getpass("Password (8+ chars, a letter and a digit): ")
        if pw != getpass.getpass("Repeat password: "):
            print("Passwords don't match.")
            continue
        try:
            SignupIn(email=email, full_name=name, password=pw)  # same rules as the website
            break
        except ValidationError as e:
            print("; ".join(err["msg"] for err in e.errors()))
            if any(err["loc"] == ("email",) for err in e.errors()):
                return

    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == email))
        if user:
            user.role, user.password_hash, user.is_active = ROLE_ADMIN, hash_password(pw), True
            user.token_version += 1
            print(f"Updated {email}: now an admin with the new password.")
        else:
            db.add(User(email=email, full_name=name, password_hash=hash_password(pw), role=ROLE_ADMIN))
            print(f"Created admin {email}.")
        db.commit()


if __name__ == "__main__":
    main()
