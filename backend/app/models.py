"""Database tables.

Users own stations (one host -> many stations). Alerts come in phase 3.
"""
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, utcnow


ROLE_ADMIN = "admin"
ROLE_HOST = "host"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)  # stored lowercase
    full_name: Mapped[str] = mapped_column(String(128))
    password_hash: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(16), default=ROLE_HOST)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime)
    # Bumped on password change / logout-everywhere: older tokens stop working.
    token_version: Mapped[int] = mapped_column(Integer, default=0)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. "station-01"
    name: Mapped[str | None] = mapped_column(String(128))
    location: Mapped[str | None] = mapped_column(String(128))
    source: Mapped[str | None] = mapped_column(String(32))  # "esp32" or "simulator"
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    last_ip: Mapped[str | None] = mapped_column(String(64))
    last_uptime_s: Mapped[int | None] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(32), default="UNKNOWN")
    # Per-device overrides, e.g. {"sag_v": 4.6}. Missing keys fall back to config defaults.
    thresholds: Mapped[dict | None] = mapped_column(JSON)
    # The host who monitors this station (NULL = not claimed yet).
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    # A host needs the station id AND this code to claim it (shown to admins / printed on the unit).
    pairing_code: Mapped[str | None] = mapped_column(String(16))


class Reading(Base):
    __tablename__ = "readings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)  # server time
    voltage_v: Mapped[float] = mapped_column(Float)
    source_voltage_v: Mapped[float | None] = mapped_column(Float)
    shunt_mv: Mapped[float | None] = mapped_column(Float)
    current_ma: Mapped[float] = mapped_column(Float)
    power_mw: Mapped[float] = mapped_column(Float)
    data_blocked: Mapped[bool] = mapped_column(Boolean)
    device_alert: Mapped[str] = mapped_column(String(32))
    rssi: Mapped[int | None] = mapped_column(Integer)
    uptime_s: Mapped[int | None] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(32))  # state the server computed for this reading
    client_ip: Mapped[str | None] = mapped_column(String(64))


class Command(Base):
    """Queued dashboard commands, delivered in the next /api/ingest reply."""

    __tablename__ = "commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    name: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime)


class AuthFailure(Base):
    """Every rejected API key. Phase 3 turns repeated failures into a ROGUE_DEVICE alert."""

    __tablename__ = "auth_failures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    client_ip: Mapped[str | None] = mapped_column(String(64))
    device_id_claimed: Mapped[str | None] = mapped_column(String(64))


class LoginFailure(Base):
    """Failed portal logins, used to slow down password guessing."""

    __tablename__ = "login_failures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    email: Mapped[str] = mapped_column(String(254), index=True)
    client_ip: Mapped[str | None] = mapped_column(String(64))


class AuditLog(Base):
    """Who did what in the portals: logins, commands, threshold changes, claims."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(48), index=True)
    target: Mapped[str | None] = mapped_column(String(128))
    detail: Mapped[dict | None] = mapped_column(JSON)
    client_ip: Mapped[str | None] = mapped_column(String(64))
