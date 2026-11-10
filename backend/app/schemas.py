"""Request/response shapes. These must stay in sync with the ESP32 sketch."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IngestPayload(BaseModel):
    # NaN / Infinity are rejected (a broken sensor read must not reach the DB).
    model_config = ConfigDict(allow_inf_nan=False, extra="ignore")

    device_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$")
    # INA219 bus range is 0-26 V; slightly negative allowed for noise near 0.
    voltage_v: float = Field(ge=-0.5, le=26.0)
    source_voltage_v: float | None = Field(default=None, ge=-0.5, le=26.5)
    shunt_mv: float | None = Field(default=None, ge=-400, le=400)  # +/-320 mV full scale
    current_ma: float = Field(ge=-4000, le=4000)  # +/-3.2 A with the 0.1 ohm shunt
    power_mw: float = Field(ge=-1, le=100_000)
    data_blocked: bool
    device_alert: Literal["NONE", "LOW_VOLTAGE", "HIGH_VOLTAGE"] = "NONE"
    source: str = Field(default="esp32", max_length=32)
    rssi: int | None = Field(default=None, ge=-127, le=0)
    uptime_s: int | None = Field(default=None, ge=0)


class Thresholds(BaseModel):
    sag_v: float
    over_voltage_v: float


class IngestReply(BaseModel):
    state: str
    thresholds: Thresholds
    commands: list[str]


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str | None
    location: str | None
    source: str | None
    first_seen: datetime
    last_seen: datetime | None
    last_ip: str | None
    last_uptime_s: int | None
    state: str
    online: bool
    seconds_since_seen: float | None
    thresholds: Thresholds
    owner_id: int | None = None
    owner_email: str | None = None  # admins only
    pairing_code: str | None = None  # admins only
    added_at: datetime | None = None  # when its current host added it
    # Latest reading, so lists can show live numbers without a second request.
    voltage_v: float | None = None
    current_ma: float | None = None
    power_mw: float | None = None
    data_blocked: bool | None = None
    rssi: int | None = None
    power_history: list[float] = []  # last 40 readings, oldest first (sparklines)


class ReadingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    voltage_v: float
    source_voltage_v: float | None
    shunt_mv: float | None
    current_ma: float
    power_mw: float
    data_blocked: bool
    device_alert: str
    rssi: int | None
    uptime_s: int | None
    state: str


class CommandIn(BaseModel):
    name: str


class CommandOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_id: str
    name: str
    created_at: datetime
    delivered_at: datetime | None


class DeviceUpdate(BaseModel):
    name: str | None = None
    location: str | None = None
    sag_v: float | None = Field(default=None, ge=0, le=26)
    over_voltage_v: float | None = Field(default=None, ge=0, le=26)


# ---- Portal accounts -------------------------------------------------------------------------
_EMAIL = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


class _Password(BaseModel):
    @staticmethod
    def check_strength(pw: str) -> str:
        if len(pw.encode()) > 72:  # bcrypt ignores everything past 72 bytes
            raise ValueError("password is too long (max 72 bytes)")
        if not any(c.isalpha() for c in pw) or not any(c.isdigit() for c in pw):
            raise ValueError("password needs at least one letter and one digit")
        return pw


class SignupIn(BaseModel):
    email: str = Field(max_length=254, pattern=_EMAIL)
    full_name: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=8, max_length=72)

    @field_validator("email")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("full_name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("name must not be blank")
        return v.strip()

    @field_validator("password")
    @classmethod
    def _pw(cls, v: str) -> str:
        return _Password.check_strength(v)


class LoginIn(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=200)

    @field_validator("email")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()


class ChangePasswordIn(BaseModel):
    current_password: str = Field(max_length=200)
    new_password: str = Field(min_length=8, max_length=72)

    @field_validator("new_password")
    @classmethod
    def _pw(cls, v: str) -> str:
        return _Password.check_strength(v)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


class AdminUserOut(UserOut):
    device_count: int


class AdminUserUpdate(BaseModel):
    is_active: bool | None = None
    full_name: str | None = Field(default=None, min_length=1, max_length=128)


class ClaimIn(BaseModel):
    device_id: str = Field(min_length=1, max_length=64)
    pairing_code: str = Field(min_length=1, max_length=16)


class StationCreate(BaseModel):
    """A host adds a station by the device_id set in its sketch. No admin step needed."""
    device_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$")
    name: str | None = Field(default=None, max_length=128)
    location: str | None = Field(default=None, max_length=128)

    @field_validator("device_id", mode="before")
    @classmethod
    def _strip_id(cls, v):
        return v.strip() if isinstance(v, str) else v


class AssignIn(BaseModel):
    user_id: int | None  # None = take the station away from its host


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    user_id: int | None
    user_email: str | None = None
    action: str
    target: str | None
    detail: dict | None
    client_ip: str | None
