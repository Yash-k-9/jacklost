"""Request/response shapes. These must stay in sync with the ESP32 sketch."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


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
