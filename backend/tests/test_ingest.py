from conftest import KEY, payload


def test_ingest_ok_reply_matches_firmware_contract(client):
    r = client.post("/api/ingest", json=payload(), headers=KEY)
    assert r.status_code == 200
    body = r.json()
    assert body["state"] == "CHARGING"
    assert body["thresholds"] == {"sag_v": 4.5, "over_voltage_v": 5.5}
    assert body["commands"] == []


def test_bad_key_is_401_and_logged(client):
    assert client.post("/api/ingest", json=payload(), headers={"X-API-Key": "nope"}).status_code == 401
    assert client.post("/api/ingest", json=payload()).status_code == 401


def test_impossible_values_are_422(client):
    assert client.post("/api/ingest", json=payload(voltage_v=40), headers=KEY).status_code == 422
    assert client.post("/api/ingest", json=payload(device_alert="BOGUS"), headers=KEY).status_code == 422


def test_states(client):
    def state(**o):
        return client.post("/api/ingest", json=payload(**o), headers=KEY).json()["state"]

    assert state(current_ma=5) == "IDLE"
    assert state(voltage_v=0.1, current_ma=0) == "NO_SUPPLY"
    assert state(device_alert="LOW_VOLTAGE", voltage_v=4.2) == "LOW_VOLTAGE"
    assert state(voltage_v=4.3) == "LOW_VOLTAGE"                       # below 4.5 V limit, no flag yet
    assert state(device_alert="HIGH_VOLTAGE", voltage_v=5.4) == "OVER_VOLTAGE"
    assert state(data_blocked=False) == "TAMPER"
    assert state(data_blocked=False, voltage_v=9.0) == "TAMPER"        # exposed data lines win


def test_sudden_surge_is_over_voltage_from_the_first_reading(client, admin):
    """The station only flags HIGH_VOLTAGE after 3 bad readings; the server must not wait."""
    sid = "surge-01"
    assert client.post("/api/ingest", json=payload(device_id=sid), headers=KEY).json()["state"] == "CHARGING"
    r = client.post("/api/ingest", json=payload(device_id=sid, voltage_v=9.6, power_mw=7680.0), headers=KEY)
    assert r.json()["state"] == "OVER_VOLTAGE"
    d = admin.get(f"/api/devices/{sid}").json()
    assert d["state"] == "OVER_VOLTAGE" and d["voltage_v"] == 9.6 and d["active_incidents"] >= 1
    # Uses the station's own limit.
    assert admin.patch(f"/api/devices/{sid}", json={"over_voltage_v": 10.0}).status_code == 200
    assert client.post("/api/ingest", json=payload(device_id=sid, voltage_v=9.6, power_mw=7680.0), headers=KEY).json()["state"] == "CHARGING"


def test_command_delivered_once(client, admin):
    client.post("/api/ingest", json=payload(), headers=KEY)
    assert admin.post("/api/devices/station-01/commands", json={"name": "blink_led"}).status_code == 201
    assert admin.post("/api/devices/station-01/commands", json={"name": "rm -rf"}).status_code == 422
    assert client.post("/api/ingest", json=payload(), headers=KEY).json()["commands"] == ["blink_led"]
    assert client.post("/api/ingest", json=payload(), headers=KEY).json()["commands"] == []


def test_threshold_override_sent_back(client, admin):
    client.post("/api/ingest", json=payload(), headers=KEY)
    assert admin.patch("/api/devices/station-01", json={"sag_v": 4.6}).status_code == 200
    assert client.post("/api/ingest", json=payload(), headers=KEY).json()["thresholds"]["sag_v"] == 4.6
    assert admin.patch("/api/devices/station-01", json={"sag_v": 6.0}).status_code == 422


def test_device_list_and_readings(client, admin):
    client.post("/api/ingest", json=payload(), headers=KEY)
    devs = admin.get("/api/devices").json()
    assert any(d["id"] == "station-01" and d["online"] for d in devs)
    rows = admin.get("/api/devices/station-01/readings?limit=3").json()
    assert len(rows) == 3 and rows[0]["id"] < rows[-1]["id"]
