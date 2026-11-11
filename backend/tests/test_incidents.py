"""Security incidents: data lines exposed, over-voltage / spikes, restart loops, wrong-key attempts."""
import uuid

from conftest import KEY, payload, signup

from app import config


def host_with_station(new_client):
    """A logged-in host who owns a fresh station that has sent one good reading."""
    host = new_client()
    signup(host)
    sid = f"st-{uuid.uuid4().hex[:6]}"
    assert host.post("/api/devices", json={"device_id": sid}).status_code == 201
    send(host, sid)
    return host, sid


def send(c, sid, headers=KEY, **over):
    r = c.post("/api/ingest", json=payload(device_id=sid, **over), headers=headers)
    return r


def incidents(c, sid, **params):
    r = c.get("/api/incidents", params={"device_id": sid, **params})
    assert r.status_code == 200, r.text
    return r.json()


def test_data_lines_exposed_opens_extends_and_closes(new_client):
    host, sid = host_with_station(new_client)
    send(host, sid, data_blocked=False)
    send(host, sid, data_blocked=False)
    [inc] = incidents(host, sid)
    assert inc["kind"] == "data_exposed" and inc["severity"] == "critical"
    assert inc["active"] and inc["count"] == 2
    assert host.get(f"/api/devices/{sid}").json()["active_incidents"] == 1

    send(host, sid, data_blocked=True)                      # blocked again -> incident over
    [inc] = incidents(host, sid)
    assert not inc["active"] and inc["ended_at"]
    assert incidents(host, sid, active_only=True) == []
    assert host.get(f"/api/devices/{sid}").json()["active_incidents"] == 0

    send(host, sid, data_blocked=False)                     # happens again -> a new incident
    assert len(incidents(host, sid)) == 2


def test_over_voltage_tracks_peak(new_client):
    host, sid = host_with_station(new_client)
    send(host, sid, voltage_v=5.8)
    send(host, sid, voltage_v=6.4)
    send(host, sid, voltage_v=6.1)
    over = [i for i in incidents(host, sid) if i["kind"] == "over_voltage"]
    assert len(over) == 1 and over[0]["active"] and over[0]["peak"] == 6.4 and over[0]["count"] == 3
    assert over[0]["detail"]["limit_v"] == config.DEFAULT_OVER_VOLTAGE_V
    send(host, sid, voltage_v=5.0)
    assert not [i for i in incidents(host, sid) if i["kind"] == "over_voltage"][0]["active"]


def test_station_high_voltage_flag_counts_as_over_voltage(new_client):
    host, sid = host_with_station(new_client)
    send(host, sid, voltage_v=5.2, device_alert="HIGH_VOLTAGE")
    assert any(i["kind"] == "over_voltage" for i in incidents(host, sid, active_only=True))


def test_voltage_spike_but_not_plugging_in(new_client):
    host, sid = host_with_station(new_client)              # last reading 5.02 V
    send(host, sid, voltage_v=0.0)                          # charger unplugged
    send(host, sid, voltage_v=5.0)                          # plugged back in: not a spike
    assert not [i for i in incidents(host, sid) if i["kind"] == "voltage_spike"]
    send(host, sid, voltage_v=3.6)                          # 1.4 V drop with charger present
    send(host, sid, voltage_v=5.1)                          # and back up: same incident
    [spike] = [i for i in incidents(host, sid) if i["kind"] == "voltage_spike"]
    assert spike["severity"] == "warning" and spike["count"] == 2 and spike["peak"] == 1.5


def test_single_restart_is_quiet_but_a_loop_is_an_incident(new_client):
    host, sid = host_with_station(new_client)              # uptime 42
    send(host, sid, uptime_s=50)
    send(host, sid, uptime_s=3)                             # restart 1 (a power cut: fine)
    assert incidents(host, sid) == []
    send(host, sid, uptime_s=2)                             # restart 2
    send(host, sid, uptime_s=1)                             # restart 3 -> loop
    [loop] = incidents(host, sid)
    assert loop["kind"] == "reboot_loop" and loop["count"] == config.REBOOT_LOOP_COUNT and loop["active"]


def test_wrong_key_attempts_show_up_for_the_owner(new_client, client):
    host, sid = host_with_station(new_client)
    bad = {"X-API-Key": "guess"}
    assert send(client, sid, headers=bad).status_code == 401
    assert send(client, sid, headers=bad).status_code == 401
    [inc] = incidents(host, sid)
    assert inc["kind"] == "bad_key" and inc["count"] == 2 and inc["active"]
    assert inc["detail"]["ips"] == ["testclient"]

    # Unknown station ids are never created by a rejected request.
    ghost = f"ghost-{uuid.uuid4().hex[:6]}"
    assert send(client, ghost, headers=bad).status_code == 401
    assert host.get(f"/api/devices/{ghost}").status_code == 404


def test_hosts_only_see_and_ack_their_own_incidents(new_client, admin):
    asha, sid = host_with_station(new_client)
    ravi = new_client()
    signup(ravi)
    send(asha, sid, data_blocked=False)
    [inc] = incidents(asha, sid)

    assert ravi.get("/api/incidents").json() == []
    assert ravi.get("/api/incidents", params={"device_id": sid}).status_code == 404
    assert ravi.post(f"/api/incidents/{inc['id']}/ack").status_code == 404

    assert inc["id"] in {i["id"] for i in asha.get("/api/incidents", params={"active_only": True}).json()}
    r = asha.post(f"/api/incidents/{inc['id']}/ack")
    assert r.status_code == 200 and r.json()["acknowledged_at"]

    # Admins see it too, with the owner's email, and the ack is in the audit log.
    seen = {i["id"]: i for i in admin.get("/api/incidents").json()}
    assert seen[inc["id"]]["owner_email"]
    assert admin.get(f"/api/admin/audit?action=incident_acknowledged&target={sid}").json()
