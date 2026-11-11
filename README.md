# Juice Guard: USB charging station monitor

The server side of the Smart USB-C Juice Jacking Protection Station. ESP32 + INA219 stations
POST power readings every 2 s. The backend stores them, works out each station's state and
sends back thresholds and dashboard commands.

> The real protection is in hardware: D+/D- are physically cut. The INA219 measures power only,
> so this system detects **power/behaviour anomalies and signs of tampering**, not USB data.

## Status
- [x] Phase 1: ingest API, SQLite storage, API key auth, device registry, command queue
- [x] Phase 2: multi-station simulator with fault/attack scenarios
- [x] Portal logins: host sign-up, admin accounts, station ownership, audit log
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
..\.venv\Scripts\python scripts\create_admin.py     # first time only: makes the admin login
..\.venv\Scripts\python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- API docs: http://127.0.0.1:8000/docs
- Web portal: http://127.0.0.1:8000/ (or http://<PC-IP>:8000/ from a phone on the same Wi-Fi)

### Web portal (`frontend/`, plain HTML, served by the backend)
| Page | Who | What |
|---|---|---|
| `login.html` | anyone | log in, or create a station host account |
| `index.html` | host / admin | live list of stations (hosts: their own + "Add station" with pairing code; admins: all, with host and pairing code) |
| `station.html?id=…` | owner / admin | is it connected, sending now, continuously active (dropouts, reboots, 5-min timeline), latest reading, test commands, name/location/voltage limits, remove |
| `account.html` | everyone | change password, log out everywhere |
| `admin.html` | admin | accounts (activate/deactivate, rename), assign stations, new pairing codes, audit log |
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

## Logins and roles
- **End hosts** sign up at `POST /api/auth/signup` (active at once, no approval). A host adds
  each of their stations themselves by its station id (the `DEVICE_ID` in the ESP32 sketch), with
  no admin step; one host can have many stations. A new id is created on their account and fills
  with readings once that ESP32 reports. An id already owned by someone else is refused. Hosts
  only ever see their own stations; anyone else's answers 404.
- Admins see every station with the host who added it and when (`added_at`), and a
  `device_added` audit entry. Claiming with an 8-character pairing code still works too.
- **Admins** are created only with `scripts/create_admin.py`. They see every host and station,
  can assign stations, see pairing codes, deactivate hosts and read the audit log.
- Sessions are an httpOnly cookie (`jg_session`, also accepted as `Authorization: Bearer`).
  Passwords are bcrypt-hashed; 5 wrong passwords in 15 min blocks that email for a while.
- Every portal endpoint needs a login. Only `/api/ingest` (station API key) and `/api/health` don't.

| Method | Path | Who | Purpose |
|---|---|---|---|
| POST | `/api/auth/signup` | anyone | new end-host account, logs in |
| POST | `/api/auth/login` / `logout` / `logout-all` | anyone / user | session |
| GET | `/api/auth/me` | user | current account |
| POST | `/api/auth/change-password` | user | also logs out other browsers |
| POST | `/api/devices` | host | `{device_id, name?, location?}` adds a station (no admin step) |
| POST | `/api/devices/claim` | host | `{device_id, pairing_code}` adds a station by pairing code |
| POST | `/api/devices/{id}/release` | owner, admin | removes it from the account |
| GET | `/api/admin/users?role=host` | admin | accounts with station counts |
| PATCH | `/api/admin/users/{id}` | admin | `is_active`, `full_name` |
| POST | `/api/admin/devices/{id}/assign` | admin | `{user_id}` or `null` |
| POST | `/api/admin/devices/{id}/pairing-code` | admin | new pairing code |
| GET | `/api/admin/audit` | admin | who did what (`user_id`, `action`, `target` filters) |

## Station API (login required, except ingest)
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/ingest` | station reading (header `X-API-Key`) → `{state, thresholds, commands}` |
| GET | `/api/devices` | host: own stations; admin: all (`?owner_id=`, `?unclaimed=true`). Online/OFFLINE status (offline after 10 s of silence) |
| GET | `/api/devices/{id}` | one station |
| PATCH | `/api/devices/{id}` | name, location, `sag_v`, `over_voltage_v` |
| GET | `/api/devices/{id}/readings?limit=100` | history, oldest → newest |
| POST | `/api/devices/{id}/commands` | `{"name": "blink_led" \| "sim_data_attempt"}` |
| GET | `/api/health` | liveness |

## Security incidents
Detected on the server from every reading, so the ESP32 sketch needs no changes. Hosts see them
on their Stations page (Security alerts), as a badge on each station card and in the station's
incident history; admins see every host's. Hosts acknowledge incidents (logged in the audit log).

| Kind | Raised when | Ends when |
|---|---|---|
| `data_exposed` (critical) | a reading has `data_blocked=false` | the next reading with `data_blocked=true` |
| `over_voltage` (critical) | voltage above the station's limit, or `device_alert=HIGH_VOLTAGE` | voltage back under the limit |
| `voltage_spike` | voltage jumps >= `SPIKE_JUMP_V` (1 V) between two readings while a charger is present | no spike for `SPIKE_WINDOW_S` (60 s) |
| `reboot_loop` | uptime drops back `REBOOT_LOOP_COUNT` (3) times, each within `REBOOT_WINDOW_MIN` (60 min) of the last | no restart for 60 min |
| `bad_key` | a reading claiming an existing station is rejected for a wrong API key (IPs recorded) | no attempt for `BAD_KEY_WINDOW_MIN` (10 min) |

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/incidents?active_only=&device_id=&limit=` | host: own stations; admin: all |
| POST | `/api/incidents/{id}/ack` | acknowledge (owner or admin) |

Per-reading states: `CHARGING`, `IDLE`, `NO_SUPPLY`, `ALERT` (station reports sustained
low/high voltage), `TAMPER` (`data_blocked=false`). `OFFLINE` is derived from `last_seen`.
