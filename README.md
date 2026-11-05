# Juice Guard: USB charging station monitor

The server side of the Smart USB-C Juice Jacking Protection Station. ESP32 + INA219 stations
POST power readings every 2 s. The backend stores them, works out each station's state and
sends back thresholds and dashboard commands.

> The real protection is in hardware: D+/D- are physically cut. The INA219 measures power only,
> so this system detects **power/behaviour anomalies and signs of tampering**, not USB data.

## Status
- [x] Phase 1: ingest API, SQLite storage, API key auth, device registry, command queue
- [x] Phase 2: multi-station simulator with fault/attack scenarios
- [ ] Phase 3: detection engine (alerts, watchdog, sessions)
- [ ] Phase 4: live React dashboard
- [ ] Phases 5-8: settings UI, reports, hardening, demo

## Layout
```
backend/app/main.py          FastAPI app (health, error handling, routers)
backend/app/api/ingest.py    POST /api/ingest   (called by stations)
backend/app/api/devices.py   /api/devices...    (fleet, readings, commands, thresholds)
backend/app/models.py        devices, readings, commands, auth_failures
backend/app/schemas.py       payload validation (must match the ESP32 sketch)
backend/app/services.py      state + threshold helpers
backend/tests/               pytest suite
simulator/simulate.py        fake stations + scenarios
```

## Run it (Windows)
```bash
python -m venv .venv
.venv\Scripts\python -m pip install -r backend\requirements.txt
copy backend\.env.example backend\.env        # then edit DEVICE_API_KEY if needed
cd backend
..\.venv\Scripts\python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- API docs: http://127.0.0.1:8000/docs
- Tests: `cd backend && ..\.venv\Scripts\python -m pytest -q`

### Connecting the real ESP32
1. `ipconfig`: copy the PC's IPv4 on the Wi-Fi adapter into `SERVER_URL` in the sketch.
2. `API_KEY` in the sketch must equal `DEVICE_API_KEY` in `backend/.env`.
3. Allow inbound TCP 8000 in Windows Firewall (admin PowerShell):
   `New-NetFirewallRule -DisplayName "JuiceGuard 8000" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow`
4. Serial Monitor should show `[HTTP] 200 OK - server state: CHARGING` (or IDLE).

## Simulator
```bash
.venv\Scripts\python simulator\simulate.py --list
.venv\Scripts\python simulator\simulate.py --stations 5
.venv\Scripts\python simulator\simulate.py --scenario offline --after 15 --duration 30
```
Scenarios: normal, offline, dropout, reboot, unplug, sag, overvoltage, spike, unexpected_load,
sensor_fault, reversed, tamper, bad_key, clone, garbage. The first station (`sim-01`) is the one
that misbehaves. The rest stay normal.

## API (phase 1)
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/ingest` | station reading (header `X-API-Key`) → `{state, thresholds, commands}` |
| GET | `/api/devices` | fleet with online/OFFLINE status (offline after 10 s of silence) |
| GET | `/api/devices/{id}` | one station |
| PATCH | `/api/devices/{id}` | name, location, `sag_v`, `over_voltage_v` |
| GET | `/api/devices/{id}/readings?limit=100` | history, oldest → newest |
| POST | `/api/devices/{id}/commands` | `{"name": "blink_led" \| "sim_data_attempt"}` |
| GET | `/api/health` | liveness |

Per-reading states: `CHARGING`, `IDLE`, `NO_SUPPLY`, `ALERT` (station reports sustained
low/high voltage), `TAMPER` (`data_blocked=false`). `OFFLINE` is derived from `last_seen`.
