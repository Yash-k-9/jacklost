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
    over.pop("device_id", None)
    return c.post("/api/ingest", json=payload(device_id=sid, **over), headers=headers)


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


# ---- one test per malpractice the simulator can play ------------------------------------------

def kinds(c, sid, **params):
    return {i["kind"] for i in incidents(c, sid, **params)}


def backdate_last_reading(sid, seconds):
    """Pretend the last reading arrived `seconds` ago (instead of waiting in the test)."""
    from datetime import timedelta

    from app.db import SessionLocal
    from app.models import Device, Reading
    with SessionLocal() as db:
        r = db.query(Reading).filter(Reading.device_id == sid).order_by(Reading.id.desc()).first()
        r.ts -= timedelta(seconds=seconds)
        d = db.get(Device, sid)
        d.last_seen -= timedelta(seconds=seconds)
        db.commit()


def test_normal_charging_raises_nothing(new_client):
    host, sid = host_with_station(new_client)
    for i, ma in enumerate([1500, 1420, 1310, 1205, 990, 870, 2.0, 1.5, 0.8, 1.2]):
        send(host, sid, current_ma=ma, power_mw=round(5.02 * ma, 1), uptime_s=44 + 2 * i)
    assert incidents(host, sid) == []


def test_low_voltage_sag(new_client):
    host, sid = host_with_station(new_client)
    send(host, sid, voltage_v=4.3, power_mw=4.3 * 800)
    send(host, sid, voltage_v=4.2, power_mw=4.2 * 800)
    [inc] = incidents(host, sid)
    assert inc["kind"] == "low_voltage" and inc["peak"] == 4.2 and inc["severity"] == "warning"
    send(host, sid)
    assert not incidents(host, sid)[0]["active"]


def test_supply_lost_but_not_low_voltage(new_client):
    host, sid = host_with_station(new_client)
    send(host, sid, voltage_v=0.02, current_ma=0, power_mw=0)
    assert kinds(host, sid, active_only=True) == {"supply_lost"}


def test_over_current(new_client):
    host, sid = host_with_station(new_client)
    send(host, sid, current_ma=2900, power_mw=5.02 * 2900)
    [inc] = incidents(host, sid)
    assert inc["kind"] == "over_current" and inc["severity"] == "critical" and inc["peak"] == 2900


def test_reversed_current(new_client):
    host, sid = host_with_station(new_client)
    send(host, sid, current_ma=-850, power_mw=0)
    assert kinds(host, sid) == {"reversed_current"}


def test_hidden_load_needs_a_flat_small_current(new_client):
    host, sid = host_with_station(new_client)
    for ma in (118, 121, 119, 124, 120, 117, 122):          # 7 flat readings: not yet
        send(host, sid, current_ma=ma, power_mw=round(5.02 * ma, 1))
    assert incidents(host, sid) == []
    send(host, sid, current_ma=120, power_mw=602.4)       # 8th -> alert
    [inc] = incidents(host, sid)
    assert inc["kind"] == "hidden_load" and inc["severity"] == "critical"


def test_phone_tapering_through_the_same_range_is_not_a_hidden_load(new_client):
    host, sid = host_with_station(new_client)
    for ma in (240, 210, 180, 150, 120, 100, 80, 65):
        send(host, sid, current_ma=ma, power_mw=round(5.02 * ma, 1))
    assert incidents(host, sid) == []


def test_power_that_does_not_match_v_times_i(new_client):
    host, sid = host_with_station(new_client)
    send(host, sid, current_ma=800, power_mw=1800)          # should be ~4016
    [inc] = incidents(host, sid)
    assert inc["kind"] == "data_mismatch" and inc["detail"]["expected_mw"] == 4016.0


def test_clone_by_uptime_and_no_false_restart_loop(new_client):
    host, sid = host_with_station(new_client)              # real board: uptime 42
    for up_real, up_clone in ((44, 5044), (46, 5046), (48, 5048)):
        send(host, sid, uptime_s=up_clone)
        send(host, sid, uptime_s=up_real)
    assert kinds(host, sid) == {"clone"}


def test_offline_opens_when_silent_and_closes_on_next_reading(new_client):
    host, sid = host_with_station(new_client)
    backdate_last_reading(sid, 30)
    [inc] = incidents(host, sid, active_only=True)
    assert inc["kind"] == "offline" and inc["active"]
    assert host.get(f"/api/devices/{sid}").json()["active_incidents"] == 1
    send(host, sid, uptime_s=72)
    [inc] = [i for i in incidents(host, sid) if i["kind"] == "offline"]
    assert not inc["active"] and inc["detail"]["silent_s"] >= 30


def test_dropouts_only_count_when_repeated(new_client):
    host, sid = host_with_station(new_client)
    for n in range(config.DROPOUT_COUNT):
        backdate_last_reading(sid, 6)                      # a 6 s gap before this reading
        send(host, sid, uptime_s=50 + 10 * n)
        if n < config.DROPOUT_COUNT - 1:
            assert "dropout" not in kinds(host, sid)
    assert "dropout" in kinds(host, sid, active_only=True)


def test_impossible_values_with_the_right_key(new_client, client):
    host, sid = host_with_station(new_client)
    assert send(client, sid, voltage_v=40).status_code == 422
    [inc] = incidents(host, sid)
    assert inc["kind"] == "invalid_data" and "voltage_v" in inc["detail"]["errors"][0]
    # Without the key it is not trusted, and unknown ids are never created.
    assert send(client, sid, headers={"X-API-Key": "nope"}, voltage_v=40).status_code == 422
    assert incidents(host, sid)[0]["count"] == 1


def test_every_simulator_attack_scenario_raises_its_alert(new_client):
    """Replays simulator/simulate.py's own readings for each scenario through the backend."""
    import argparse
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "simulator"))
    import simulate

    expected = {
        "unplug": "supply_lost", "sag": "low_voltage", "overvoltage": "over_voltage",
        "spike": "over_current", "unexpected_load": "hidden_load", "sensor_fault": "data_mismatch",
        "reversed": "reversed_current", "tamper": "data_exposed", "bad_key": "bad_key",
        "clone": "clone", "garbage": "invalid_data",
    }
    host = new_client()
    signup(host)
    for scenario, kind in expected.items():
        sid = f"st-{uuid.uuid4().hex[:6]}"
        assert host.post("/api/devices", json={"device_id": sid}).status_code == 201
        args = argparse.Namespace(scenario=scenario, after=10, duration=30, interval=2, verbose=False)
        station = simulate.Station(sid, args, is_target=True)
        clone = simulate.Station(sid, argparse.Namespace(**{**vars(args), "scenario": "normal"}), False)
        clone.boot -= 5000
        for step in range(30):
            t = step * 2.0
            bad = scenario == "bad_key" and station.active(t)
            send(host, sid, headers={"X-API-Key": "wrong"} if bad else KEY, **station.reading(t))
            if scenario == "clone" and station.active(t):
                send(host, sid, **clone.reading(t))
        assert kind in kinds(host, sid), (scenario, kinds(host, sid))
