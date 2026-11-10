"""POST /api/ingest - the only endpoint the ESP32 stations call."""
import logging
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..db import get_db, utcnow
from ..auth.security import new_pairing_code
from ..models import AuthFailure, Command, Device, Reading
from ..schemas import IngestPayload, IngestReply
from ..services import compute_state, thresholds_for

log = logging.getLogger("ingest")
router = APIRouter()


@router.post("/api/ingest", response_model=IngestReply)
def ingest(
    payload: IngestPayload,
    request: Request,
    db: Session = Depends(get_db),
    x_api_key: str | None = Header(default=None),
):
    client_ip = request.client.host if request.client else None

    if not x_api_key or not secrets.compare_digest(x_api_key, config.DEVICE_API_KEY):
        db.add(AuthFailure(client_ip=client_ip, device_id_claimed=payload.device_id))
        db.commit()
        log.warning("401 bad API key from %s claiming %s", client_ip, payload.device_id)
        raise HTTPException(status_code=401, detail="Invalid API key")

    now = utcnow()
    device = db.get(Device, payload.device_id)
    if device is None:  # auto-register new stations on first contact
        device = Device(id=payload.device_id, first_seen=now, pairing_code=new_pairing_code())
        db.add(device)
        log.info("New station registered: %s from %s", payload.device_id, client_ip)

    state = compute_state(payload.voltage_v, payload.current_ma, payload.device_alert, payload.data_blocked)

    db.add(Reading(
        device_id=payload.device_id,
        ts=now,
        voltage_v=payload.voltage_v,
        source_voltage_v=payload.source_voltage_v,
        shunt_mv=payload.shunt_mv,
        current_ma=payload.current_ma,
        power_mw=payload.power_mw,
        data_blocked=payload.data_blocked,
        device_alert=payload.device_alert,
        rssi=payload.rssi,
        uptime_s=payload.uptime_s,
        state=state,
        client_ip=client_ip,
    ))

    device.last_seen = now
    device.last_ip = client_ip
    device.last_uptime_s = payload.uptime_s
    device.source = payload.source
    device.state = state

    # Deliver every pending command once, oldest first.
    pending = db.scalars(
        select(Command)
        .where(Command.device_id == payload.device_id, Command.delivered_at.is_(None))
        .order_by(Command.id)
    ).all()
    for cmd in pending:
        cmd.delivered_at = now

    db.commit()
    return IngestReply(state=state, thresholds=thresholds_for(device), commands=[c.name for c in pending])
