import os
import tempfile

# Use a throwaway database before the app is imported.
_tmp = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["DEVICE_API_KEY"] = "test-key"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

KEY = {"X-API-Key": "test-key"}


def payload(**over):
    p = {
        "device_id": "station-01", "voltage_v": 5.02, "source_voltage_v": 5.10, "shunt_mv": 80.0,
        "current_ma": 800.0, "power_mw": 4016.0, "data_blocked": True, "device_alert": "NONE",
        "source": "esp32", "rssi": -60, "uptime_s": 42,
    }
    p.update(over)
    return p


def test_ingest_ok_reply_matches_firmware_contract():
    with TestClient(app) as c:
        r = c.post("/api/ingest", json=payload(), headers=KEY)
        assert r.status_code == 200
        body = r.json()
        assert body["state"] == "CHARGING"
        assert body["thresholds"] == {"sag_v": 4.5, "over_voltage_v": 5.5}
        assert body["commands"] == []


def test_bad_key_is_401_and_logged():
    with TestClient(app) as c:
        assert c.post("/api/ingest", json=payload(), headers={"X-API-Key": "nope"}).status_code == 401
        assert c.post("/api/ingest", json=payload()).status_code == 401


def test_impossible_values_are_422():
    with TestClient(app) as c:
        assert c.post("/api/ingest", json=payload(voltage_v=40), headers=KEY).status_code == 422
        assert c.post("/api/ingest", json=payload(device_alert="BOGUS"), headers=KEY).status_code == 422


def test_states():
    with TestClient(app) as c:
        def state(**o):
            return c.post("/api/ingest", json=payload(**o), headers=KEY).json()["state"]

        assert state(current_ma=5) == "IDLE"
        assert state(voltage_v=0.1, current_ma=0) == "NO_SUPPLY"
        assert state(device_alert="LOW_VOLTAGE", voltage_v=4.2) == "ALERT"
        assert state(data_blocked=False) == "TAMPER"


def test_command_delivered_once():
    with TestClient(app) as c:
        c.post("/api/ingest", json=payload(), headers=KEY)
        assert c.post("/api/devices/station-01/commands", json={"name": "blink_led"}).status_code == 201
        assert c.post("/api/devices/station-01/commands", json={"name": "rm -rf"}).status_code == 422
        assert c.post("/api/ingest", json=payload(), headers=KEY).json()["commands"] == ["blink_led"]
        assert c.post("/api/ingest", json=payload(), headers=KEY).json()["commands"] == []


def test_threshold_override_sent_back():
    with TestClient(app) as c:
        c.post("/api/ingest", json=payload(), headers=KEY)
        assert c.patch("/api/devices/station-01", json={"sag_v": 4.6}).status_code == 200
        assert c.post("/api/ingest", json=payload(), headers=KEY).json()["thresholds"]["sag_v"] == 4.6
        assert c.patch("/api/devices/station-01", json={"sag_v": 6.0}).status_code == 422


def test_device_list_and_readings():
    with TestClient(app) as c:
        c.post("/api/ingest", json=payload(), headers=KEY)
        devs = c.get("/api/devices").json()
        assert any(d["id"] == "station-01" and d["online"] for d in devs)
        rows = c.get("/api/devices/station-01/readings?limit=3").json()
        assert len(rows) == 3 and rows[0]["id"] < rows[-1]["id"]
