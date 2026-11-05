"""Database tables for phase 1.

alerts and sessions tables come in phase 3 (detection engine).
"""
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, utcnow


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
