"""Logins, roles and station ownership."""
import uuid

from conftest import KEY, PASSWORD, login, make_admin, payload, signup, unique_email

from app import config


def station(client, admin) -> tuple[str, str]:
    """A fresh station reporting in; returns (id, pairing code as admins see it)."""
    sid = f"st-{uuid.uuid4().hex[:6]}"
    assert client.post("/api/ingest", json=payload(device_id=sid), headers=KEY).status_code == 200
    code = admin.get(f"/api/devices/{sid}").json()["pairing_code"]
    assert code and len(code) == 8
    return sid, code


# ---- accounts ------------------------------------------------------------------------------

def test_portal_endpoints_need_login(client):
    for path in ("/api/devices", "/api/auth/me", "/api/admin/users", "/api/admin/audit"):
        assert client.get(path).status_code == 401, path


def test_signup_logs_in_as_host_and_cookie_is_httponly(client):
    email = unique_email()
    r = client.post("/api/auth/signup", json={"email": email.upper(), "full_name": " Asha ", "password": PASSWORD})
    assert r.status_code == 201
    assert r.json()["role"] == "host" and r.json()["email"] == email and r.json()["full_name"] == "Asha"
    cookie = r.headers["set-cookie"].lower()
    assert config.SESSION_COOKIE in cookie and "httponly" in cookie and "samesite=lax" in cookie
    assert client.get("/api/auth/me").json()["email"] == email
    assert "password_hash" not in r.json()


def test_signup_cannot_make_admin_and_rejects_duplicates_and_weak_passwords(client):
    email = unique_email()
    r = client.post("/api/auth/signup", json={"email": email, "full_name": "X", "password": PASSWORD, "role": "admin"})
    assert r.json()["role"] == "host"
    assert client.post("/api/auth/signup", json={"email": email, "full_name": "X", "password": PASSWORD}).status_code == 409
    for bad in ("short1", "lettersonly", "12345678"):
        r = client.post("/api/auth/signup", json={"email": unique_email(), "full_name": "X", "password": bad})
        assert r.status_code == 422, bad
    assert client.post("/api/auth/signup", json={"email": "not-an-email", "full_name": "X", "password": PASSWORD}).status_code == 422


def test_login_logout_and_same_error_for_unknown_email(client, new_client):
    email = signup(new_client())["email"]
    wrong_pw = login(client, email, "Wrong1234")
    no_user = login(client, unique_email(), "Wrong1234")
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json() == no_user.json()

    assert login(client, email.upper()).status_code == 200
    assert client.get("/api/auth/me").status_code == 200
    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/auth/me").status_code == 401


def test_repeated_wrong_passwords_are_blocked(client, new_client):
    email = signup(new_client())["email"]
    for _ in range(config.LOGIN_MAX_FAILURES):
        assert login(client, email, "Wrong1234").status_code == 401
    assert login(client, email).status_code == 429  # even the right password, for a while


def test_bearer_token_and_forged_token(client):
    signup(client)
    token = client.cookies.get(config.SESSION_COOKIE)
    client.cookies.clear()
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    forged = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_change_password_ends_other_sessions(new_client):
    a, b = new_client(), new_client()
    email = signup(a)["email"]
    assert login(b, email).status_code == 200
    assert a.post("/api/auth/change-password",
                  json={"current_password": "Wrong1234", "new_password": "NewPass456"}).status_code == 400
    assert a.post("/api/auth/change-password",
                  json={"current_password": PASSWORD, "new_password": "NewPass456"}).status_code == 200
    assert a.get("/api/auth/me").status_code == 200   # this browser stays in
    assert b.get("/api/auth/me").status_code == 401   # the other one is logged out
    assert login(b, email, "NewPass456").status_code == 200


# ---- stations: one host, many stations -------------------------------------------------------

def test_host_claims_several_stations_and_sees_only_their_own(client, admin, new_client):
    asha, ravi = new_client(), new_client()
    signup(asha)
    signup(ravi)
    s1, c1 = station(client, admin)
    s2, c2 = station(client, admin)
    s3, c3 = station(client, admin)

    assert asha.post("/api/devices/claim", json={"device_id": s1, "pairing_code": c1}).status_code == 200
    assert asha.post("/api/devices/claim", json={"device_id": s2, "pairing_code": c2.lower()}).status_code == 200
    assert ravi.post("/api/devices/claim", json={"device_id": s3, "pairing_code": c3}).status_code == 200

    mine = {d["id"] for d in asha.get("/api/devices").json()}
    assert mine == {s1, s2}
    assert all(d["pairing_code"] is None for d in asha.get("/api/devices").json())  # hosts never see codes

    # Ravi can't see, read, control or release Asha's stations: same 404 as a missing one.
    for method, path, body in (
        ("get", f"/api/devices/{s1}", None),
        ("get", f"/api/devices/{s1}/readings", None),
        ("get", f"/api/devices/{s1}/commands", None),
        ("post", f"/api/devices/{s1}/commands", {"name": "blink_led"}),
        ("patch", f"/api/devices/{s1}", {"name": "mine now"}),
        ("post", f"/api/devices/{s1}/release", None),
    ):
        r = getattr(ravi, method)(path, json=body) if body else getattr(ravi, method)(path)
        assert r.status_code == 404, (method, path)
    assert ravi.get("/api/devices/does-not-exist").json() == {"detail": "Unknown device does-not-exist"}

    # Asha controls her own.
    assert asha.post(f"/api/devices/{s1}/commands", json={"name": "blink_led"}).status_code == 201
    assert asha.patch(f"/api/devices/{s1}", json={"name": "Desk charger", "sag_v": 4.6}).status_code == 200
    assert len(asha.get(f"/api/devices/{s1}/readings").json()) >= 1


def test_claim_needs_the_right_code_and_an_unowned_station(client, admin, new_client):
    asha, ravi = new_client(), new_client()
    signup(asha)
    signup(ravi)
    sid, code = station(client, admin)
    assert asha.post("/api/devices/claim", json={"device_id": sid, "pairing_code": "WRONGXYZ"}).status_code == 404
    assert asha.post("/api/devices/claim", json={"device_id": "nope", "pairing_code": code}).status_code == 404
    assert asha.post("/api/devices/claim", json={"device_id": sid, "pairing_code": code}).status_code == 200
    assert ravi.post("/api/devices/claim", json={"device_id": sid, "pairing_code": code}).status_code == 409

    assert asha.post(f"/api/devices/{sid}/release").status_code == 204
    assert asha.get(f"/api/devices/{sid}").status_code == 404
    assert ravi.post("/api/devices/claim", json={"device_id": sid, "pairing_code": code}).status_code == 200


def test_pairing_code_guessing_is_blocked(client, admin, new_client):
    host = new_client()
    signup(host)
    sid, code = station(client, admin)
    for _ in range(10):
        host.post("/api/devices/claim", json={"device_id": sid, "pairing_code": "WRONGXYZ"})
    assert host.post("/api/devices/claim", json={"device_id": sid, "pairing_code": code}).status_code == 429


# ---- admin ----------------------------------------------------------------------------------

def test_hosts_cannot_use_admin_endpoints(client):
    signup(client)
    assert client.get("/api/admin/users").status_code == 403
    assert client.get("/api/admin/audit").status_code == 403
    assert client.post("/api/admin/devices/x/assign", json={"user_id": None}).status_code == 403


def test_admin_sees_everything_assigns_and_audits(client, admin, new_client):
    host = new_client()
    host_id = signup(host)["id"]
    s1, _ = station(client, admin)
    s2, _ = station(client, admin)

    assert s1 in {d["id"] for d in admin.get("/api/devices?unclaimed=true").json()}
    r = admin.post(f"/api/admin/devices/{s1}/assign", json={"user_id": host_id})
    assert r.status_code == 200 and r.json()["owner_id"] == host_id
    assert {d["id"] for d in admin.get(f"/api/devices?owner_id={host_id}").json()} == {s1}
    assert {d["id"] for d in host.get("/api/devices").json()} == {s1}

    users = {u["id"]: u for u in admin.get("/api/admin/users?role=host").json()}
    assert users[host_id]["device_count"] == 1

    # Admin can control any station; the action lands in the audit log with who did it.
    assert admin.post(f"/api/devices/{s2}/commands", json={"name": "blink_led"}).status_code == 201
    entry = admin.get(f"/api/admin/audit?action=command_sent&target={s2}").json()[0]
    assert entry["user_email"].startswith("admin-") and entry["detail"] == {"command": "blink_led"}

    old = admin.get(f"/api/devices/{s1}").json()["pairing_code"]
    assert admin.post(f"/api/admin/devices/{s1}/pairing-code").json()["pairing_code"] != old

    assert admin.post(f"/api/admin/devices/{s1}/assign", json={"user_id": None}).json()["owner_id"] is None
    assert host.get("/api/devices").json() == []


def test_admin_deactivates_host(client, admin):
    host_id = signup(client)["id"]
    email = client.get("/api/auth/me").json()["email"]
    assert admin.patch(f"/api/admin/users/{host_id}", json={"is_active": False}).status_code == 200
    assert client.get("/api/auth/me").status_code == 401          # kicked out now
    assert login(client, email).status_code == 401                # and can't log back in
    assert admin.patch(f"/api/admin/users/{host_id}", json={"is_active": True}).status_code == 200
    assert login(client, email).status_code == 200


def test_admin_cannot_deactivate_self(new_client):
    c = new_client()
    email = make_admin()
    me = login(c, email).json()
    assert c.patch(f"/api/admin/users/{me['id']}", json={"is_active": False}).status_code == 400


def test_stations_can_only_go_to_hosts(client, admin):
    sid, _ = station(client, admin)
    admin_id = admin.get("/api/auth/me").json()["id"]
    assert admin.post(f"/api/admin/devices/{sid}/assign", json={"user_id": admin_id}).status_code == 422
    assert admin.post(f"/api/admin/devices/{sid}/assign", json={"user_id": 999999}).status_code == 404


# ---- hosts add their own stations (no admin step) -------------------------------------------

def test_host_adds_new_stations_by_id_and_readings_arrive(client, admin, new_client):
    asha = new_client()
    asha_id = signup(asha)["id"]
    s1, s2 = f"st-{uuid.uuid4().hex[:6]}", f"st-{uuid.uuid4().hex[:6]}"

    r = asha.post("/api/devices", json={"device_id": f"  {s1} ", "name": "Lobby", "location": "Ground"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["id"] == s1 and body["owner_id"] == asha_id and body["name"] == "Lobby"
    assert body["added_at"] and body["last_seen"] is None and body["state"] == "OFFLINE"
    assert body["pairing_code"] is None                       # hosts never see codes
    assert asha.post("/api/devices", json={"device_id": s2}).status_code == 201   # many per host

    # The ESP32 with that id starts sending: readings land on Asha's station.
    assert client.post("/api/ingest", json=payload(device_id=s1), headers=KEY).status_code == 200
    mine = {d["id"]: d for d in asha.get("/api/devices").json()}
    assert set(mine) == {s1, s2} and mine[s1]["online"] and mine[s1]["name"] == "Lobby"
    assert len(asha.get(f"/api/devices/{s1}/readings").json()) == 1

    # The admin sees both, with who added them and when, plus an audit entry.
    seen = {d["id"]: d for d in admin.get(f"/api/devices?owner_id={asha_id}").json()}
    assert set(seen) == {s1, s2} and seen[s1]["owner_email"] and seen[s1]["added_at"]
    entry = admin.get(f"/api/admin/audit?action=device_added&target={s1}").json()[0]
    assert entry["user_id"] == asha_id and entry["detail"]["new"] is True


def test_host_adds_a_station_that_is_already_sending(client, admin, new_client):
    sid, _ = station(client, admin)                           # unowned, already reporting
    host = new_client()
    signup(host)
    r = host.post("/api/devices", json={"device_id": sid})
    assert r.status_code == 201 and r.json()["online"]
    assert admin.get(f"/api/admin/audit?action=device_added&target={sid}").json()[0]["detail"]["new"] is False


def test_add_station_refuses_taken_ids_bad_ids_and_admins(client, admin, new_client):
    asha, ravi = new_client(), new_client()
    signup(asha), signup(ravi)
    sid = f"st-{uuid.uuid4().hex[:6]}"
    assert asha.post("/api/devices", json={"device_id": sid}).status_code == 201
    assert asha.post("/api/devices", json={"device_id": sid}).status_code == 409   # already mine
    assert ravi.post("/api/devices", json={"device_id": sid}).status_code == 409   # someone else's
    assert ravi.get(f"/api/devices/{sid}").status_code == 404                     # still private
    assert asha.post("/api/devices", json={"device_id": "bad id!"}).status_code == 422
    assert admin.post("/api/devices", json={"device_id": "st-admin"}).status_code == 403

    # Once Asha removes it, anyone can add it again.
    assert asha.post(f"/api/devices/{sid}/release").status_code == 204
    assert ravi.post("/api/devices", json={"device_id": sid}).status_code == 201


def test_station_list_is_still_login_only(client):
    assert client.post("/api/devices", json={"device_id": "st-x"}).status_code == 401


def test_portal_pages_are_never_served_stale(client):
    for path in ("/", "/common.css", "/common.js"):
        r = client.get(path)
        assert r.status_code == 200 and r.headers["cache-control"] == "no-cache", path


def test_station_list_includes_latest_reading(client, admin):
    sid, _ = station(client, admin)
    client.post("/api/ingest", json=payload(device_id=sid, voltage_v=5.11, current_ma=900.0, power_mw=4599.0), headers=KEY)
    d = admin.get(f"/api/devices/{sid}").json()
    assert (d["voltage_v"], d["current_ma"], d["power_mw"]) == (5.11, 900.0, 4599.0)


def test_station_list_has_shield_signal_and_history(client, admin):
    sid, _ = station(client, admin)
    client.post("/api/ingest", json=payload(device_id=sid, power_mw=1000.0, rssi=-70, data_blocked=False), headers=KEY)
    d = admin.get(f"/api/devices/{sid}").json()
    assert d["data_blocked"] is False and d["rssi"] == -70
    assert d["power_history"][-1] == 1000.0 and len(d["power_history"]) == 2
