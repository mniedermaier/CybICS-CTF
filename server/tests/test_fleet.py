"""The fleet: devices across events, groups, enrolment codes (docs/MGMT_DESIGN.md, phase 1)."""
import pytest

from conftest import auth, enroll
from cybics_mgmt.db import MIGRATIONS, connect, get_db, migrate
from cybics_mgmt.fleet import logic as fleet

CSRF = {"csrf": "csrf-test"}
BOARD = {"kind": "physical", "device_uid": "0011aabbccdd", "hostname": "cybics", "cybics_version": "1.2.4"}
LAPTOP = {"kind": "virtual", "hostname": "laptop-7", "cybics_version": "1.2.4", "mode": "full"}


def make_code(app, label="Lab", group=None):
    with app.app_context():
        db = get_db()
        group_id = fleet.create_group(db, group)["id"] if group else None
        return dict(fleet.create_code(db, label, group_id))


def fleet_enroll(client, code, device=None, label=None, **kw):
    body = {"code": code, "device": device if device is not None else LAPTOP}
    if label is not None:
        body["label"] = label
    return client.post("/api/v1/fleet/enroll", json=body, **kw)


@pytest.fixture
def device(client, app):
    resp = fleet_enroll(client, make_code(app)["code"])
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()


def devices(app, **kw):
    with app.app_context():
        found, _ = fleet.list_devices(get_db(), 0, **kw)
        return found


# ---------- migration ----------

def test_migration_gives_every_instance_a_legacy_device(tmp_path):
    path = str(tmp_path / "v9.sqlite")
    conn = connect(path)
    for number, script in enumerate(MIGRATIONS[:9], start=1):
        conn.executescript(f"BEGIN;\n{script}\nPRAGMA user_version = {number};\nCOMMIT;")
    conn.executescript("""
        INSERT INTO events (id, slug, name, join_code, created_at) VALUES (1, 'e', 'E', 'ABC', 0);
        INSERT INTO teams (id, event_id, name, password_hash, created_at) VALUES (1, 1, 'T', 'x', 0);
        INSERT INTO instances (id, team_id, token_hash, kind, device_uid, hostname, cybics_version,
                               status_json, enrolled_at, last_seen)
            VALUES ('i-1', 1, 'h1', 'physical', '00aabbccddee', 'cybics', '1.2.4', '{"mode":"full"}', 5, 9);
    """)
    conn.close()
    migrate(path)
    conn = connect(path)
    row = conn.execute("SELECT * FROM devices").fetchone()
    assert (row["id"], row["legacy"], row["kind"], row["device_uid"], row["last_seen"]) == (
        "i-1", 1, "physical", "00aabbccddee", 9)
    assert row["token_hash"] is None and row["status_json"] == '{"mode":"full"}'
    assert conn.execute("SELECT device_id FROM instances").fetchone()["device_id"] == "i-1"
    conn.close()


# ---------- legacy devices from CTF enrolments ----------

def test_ctf_enrolment_creates_a_legacy_device(client, app, event):
    instance = enroll(client, event, **LAPTOP).get_json()
    [d] = devices(app)
    assert d["id"] == instance["instance_id"] and d["legacy"] and d["ctf"] == "Red Team · Test Event"
    assert d["state"] == "online"
    client.post("/api/v1/heartbeat", headers=auth(instance["token"]),
                json={"status": {"cybics_version": "1.2.5", "services": {"openplc": True, "fuxa": False}}})
    [d] = devices(app)
    assert d["cybics_version"] == "1.2.5" and (d["services_up"], d["services_total"]) == (1, 2)


def test_a_revoked_instance_leaves_its_legacy_device_gone(client, app, event, admin):
    instance = enroll(client, event).get_json()
    admin.post(f"/admin/events/{event['id']}/instances/{instance['instance_id']}/revoke", data=CSRF)
    assert devices(app) == []
    [d] = devices(app, include_gone=True)
    assert d["state"] == "gone"
    page = admin.get("/admin/fleet?all=1").data.decode()
    assert "gone" in page and instance["instance_id"][:8] in page


def test_a_board_reenrolling_in_its_team_keeps_its_device(client, app, event):
    first = enroll(client, event, **BOARD).get_json()
    second = enroll(client, event, **{**BOARD, "cybics_version": "1.2.5"}).get_json()
    assert first["instance_id"] != second["instance_id"]
    [d] = devices(app)
    assert d["id"] == first["instance_id"] and d["cybics_version"] == "1.2.5"
    with app.app_context():
        linked = get_db().execute("SELECT device_id FROM instances").fetchall()
    assert {r["device_id"] for r in linked} == {first["instance_id"]}


def test_a_board_uid_never_joins_a_device_across_teams(client, app, event, admin):
    enroll(client, event, team="Red Team", **BOARD)
    enroll(client, event, team="Blue Team", password="blue-pass-1", **BOARD)
    found = devices(app)
    assert len(found) == 2 and all(d["uid_devices"] == 1 for d in found)
    assert "UID on 2 devices" in admin.get("/admin/fleet").data.decode()


def test_deleting_an_event_keeps_its_devices(client, app, event, admin):
    instance = enroll(client, event).get_json()
    admin.post(f"/admin/events/{event['id']}/delete", data={**CSRF, "confirm": event["slug"]})
    [d] = devices(app, include_gone=True)
    assert d["id"] == instance["instance_id"] and d["state"] == "gone"


# ---------- fleet enrolment ----------

def test_fleet_enrolment_with_a_code(client, app):
    code = make_code(app, group="Room 2")
    resp = fleet_enroll(client, code["code"].lower(), device=BOARD, label="  Board   7 ")
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["device"] == {"id": data["device_id"], "label": "Board 7", "group": "Room 2"}
    assert data["token"] and data["heartbeat_interval"] == 30
    [d] = devices(app)
    assert not d["legacy"] and d["device_uid"] == BOARD["device_uid"] and d["ctf"] is None
    with app.app_context():
        assert get_db().execute("SELECT uses FROM enrol_codes").fetchone()["uses"] == 1
        assert get_db().execute("SELECT token_hash FROM devices").fetchone()["token_hash"] != data["token"]


def test_an_event_join_code_also_enrols_a_device(client, app, event):
    resp = fleet_enroll(client, event["join_code"])
    assert resp.status_code == 201 and resp.get_json()["device"]["group"] is None


def test_a_finished_event_code_does_not_enrol(client, app, event):
    with app.app_context():
        from cybics_mgmt.ctf import logic as ctf
        ctf.set_event_state(get_db(), event["id"], "finished")
    assert fleet_enroll(client, event["join_code"]).status_code == 404


def test_a_disabled_code_is_refused(client, app, admin):
    code = make_code(app)
    admin.post(f"/admin/fleet/codes/{code['id']}/disable", data=CSRF)
    resp = fleet_enroll(client, code["code"])
    assert resp.status_code == 403 and resp.get_json()["error"]["code"] == "code_disabled"
    admin.post(f"/admin/fleet/codes/{code['id']}/enable", data=CSRF)
    assert fleet_enroll(client, code["code"]).status_code == 201


@pytest.mark.parametrize("body", [
    {"code": "NOPE1234", "device": LAPTOP},
    {"code": 12, "device": LAPTOP},
    {"code": "", "device": LAPTOP},
    {"code": "\ud800", "device": LAPTOP},
])
def test_unknown_codes_are_refused(client, body):
    resp = client.post("/api/v1/fleet/enroll", json=body)
    assert resp.status_code == 404 and resp.get_json()["error"]["code"] == "invalid_code"


@pytest.mark.parametrize("device", [
    "laptop", {"kind": "toaster"}, {"kind": "physical"}, {"kind": "physical", "device_uid": "xyz!"},
])
def test_malformed_devices_are_refused(client, app, device):
    resp = fleet_enroll(client, make_code(app)["code"], device=device)
    assert resp.status_code == 400 and resp.get_json()["error"]["code"] == "invalid_device"


def test_device_strings_never_cause_a_500(client, app, admin):
    resp = fleet_enroll(client, make_code(app)["code"], label="\ud800" * 80,
                        device={**LAPTOP, "hostname": "\udcff" * 100, "cybics_version": ["x"]})
    assert resp.status_code == 201
    assert len(resp.get_json()["device"]["label"]) == 40
    assert admin.get("/admin/fleet").status_code == 200
    assert admin.get(f"/admin/fleet/devices/{resp.get_json()['device_id']}").status_code == 200


def test_unknown_codes_trip_a_lockout_the_organiser_sees(client, app, admin):
    app.config["RATE_LIMIT_ENROL_CODE"] = (3, 60)
    code = make_code(app)["code"]
    for _ in range(3):
        fleet_enroll(client, "WRONG123")
    resp = fleet_enroll(client, code)
    assert resp.status_code == 429
    assert "unknown fleet enrolment codes" in admin.get("/admin/").data.decode()
    admin.post("/admin/lockouts/clear", data=CSRF)
    assert fleet_enroll(client, code).status_code == 201


def test_new_devices_per_address_are_capped(client, app):
    app.config["RATE_LIMIT_NEW_DEVICES"] = (2, 600)
    code = make_code(app)["code"]
    assert [fleet_enroll(client, code).status_code for _ in range(3)] == [201, 201, 429]


# ---------- fleet heartbeat and leaving ----------

def test_fleet_heartbeat_stores_the_status(client, app, device):
    resp = client.post("/api/v1/fleet/heartbeat", headers=auth(device["token"]), json={"status": {
        "cybics_version": "1.3.0", "hostname": "renamed", "services": {"landing": True},
        "host": {"cpu_temp": 51.5}}})
    assert resp.status_code == 200
    assert resp.get_json()["device"]["id"] == device["device_id"]
    [d] = devices(app)
    assert (d["cybics_version"], d["hostname"], d["services_up"]) == ("1.3.0", "renamed", 1)
    client.post("/api/v1/fleet/heartbeat", headers=auth(device["token"]), json={})
    assert devices(app)[0]["cybics_version"] == "1.3.0"   # no status keeps the last one


def test_fleet_heartbeat_discards_hostile_statuses(client, app, device):
    deep = {}
    for _ in range(50):
        deep = {"x": deep}
    client.post("/api/v1/fleet/heartbeat", headers=auth(device["token"]), json={"status": deep})
    with app.app_context():
        stored = get_db().execute("SELECT status_json FROM devices").fetchone()[0]
    assert "too deeply nested" in stored
    client.post("/api/v1/fleet/heartbeat", headers=auth(device["token"]), json={"status": {"x": "y" * 20000}})
    with app.app_context():
        assert "too large" in get_db().execute("SELECT status_json FROM devices").fetchone()[0]


def test_fleet_heartbeat_needs_a_valid_token(client):
    for headers in ({}, auth("nope"), {"Authorization": "Bearer \ud800"}):
        resp = client.post("/api/v1/fleet/heartbeat", headers=headers, json={})
        assert resp.status_code == 401


def test_retired_devices_are_locked_out_until_brought_back(client, app, device, admin):
    admin.post(f"/admin/fleet/devices/{device['device_id']}/retire", data=CSRF)
    assert client.post("/api/v1/fleet/heartbeat", headers=auth(device["token"]), json={}).status_code == 401
    assert devices(app) == []
    admin.post(f"/admin/fleet/devices/{device['device_id']}/restore", data=CSRF)
    assert client.post("/api/v1/fleet/heartbeat", headers=auth(device["token"]), json={}).status_code == 200


def test_leaving_retires_the_device(client, app, device, admin):
    assert client.delete("/api/v1/fleet/device", headers=auth(device["token"])).status_code == 204
    assert client.post("/api/v1/fleet/heartbeat", headers=auth(device["token"]), json={}).status_code == 401
    page = admin.get(f"/admin/fleet/devices/{device['device_id']}").data.decode()
    assert "retired" in page and "by the device itself" in page


# ---------- CTF enrolment of a fleet device ----------

def test_a_fleet_device_joins_a_ctf_event_without_a_legacy_device(client, app, event, device):
    resp = client.post("/api/v1/enroll", json={
        "join_code": event["join_code"], "team_name": "Red Team", "team_password": "secret-12",
        "instance": LAPTOP, "device_token": device["token"]})
    assert resp.status_code == 201
    [d] = devices(app)
    assert d["id"] == device["device_id"] and not d["legacy"] and d["ctf"] == "Red Team · Test Event"
    # The CTF heartbeat of a native device does not overwrite its fleet status.
    client.post("/api/v1/heartbeat", headers=auth(resp.get_json()["token"]),
                json={"status": {"cybics_version": "9.9.9"}})
    assert devices(app)[0]["cybics_version"] == "1.2.4"


def test_an_unknown_device_token_at_ctf_enrolment_is_refused(client, event):
    resp = client.post("/api/v1/enroll", json={
        "join_code": event["join_code"], "team_name": "Red Team", "team_password": "secret-12",
        "instance": LAPTOP, "device_token": "nope"})
    assert resp.status_code == 403 and resp.get_json()["error"]["code"] == "invalid_device_token"


# ---------- organiser pages ----------

def test_fleet_pages_need_a_login(client, device):
    for path in ("/admin/fleet", f"/admin/fleet/devices/{device['device_id']}", "/admin/fleet/setup",
                 "/admin/fleet/log"):
        assert client.get(path).status_code == 302


def test_fleet_forms_need_the_csrf_token(admin, device):
    resp = admin.post(f"/admin/fleet/devices/{device['device_id']}/retire", data={})
    assert resp.status_code == 400


def test_device_page_and_edit(admin, app, device):
    with app.app_context():
        group = fleet.create_group(get_db(), "Room 2")
    url = f"/admin/fleet/devices/{device['device_id']}"
    assert admin.get(url).status_code == 200
    admin.post(url, data={**CSRF, "label": "Board 7", "group": str(group["id"]), "notes": "left drawer"})
    [d] = devices(app)
    assert (d["label"], d["group_name"], d["notes"]) == ("Board 7", "Room 2", "left drawer")
    resp = admin.post(url, data={**CSRF, "label": "x", "group": "999"}, follow_redirects=True)
    assert b"Unknown group" in resp.data
    assert admin.get("/admin/fleet/devices/nope").status_code == 404
    assert admin.post(f"{url}/explode", data=CSRF).status_code == 404


def test_fleet_list_filters(admin, app, client):
    code = make_code(app, group="Room 2")["code"]
    fleet_enroll(client, code, device=BOARD, label="Board 1")
    fleet_enroll(client, make_code(app, label="Other")["code"], device=LAPTOP, label="Laptop 1")
    with app.app_context():
        group_id = get_db().execute("SELECT id FROM device_groups").fetchone()["id"]
    page = admin.get(f"/admin/fleet?group={group_id}").data.decode()
    assert "Board 1" in page and "Laptop 1" not in page
    page = admin.get("/admin/fleet?kind=virtual").data.decode()
    assert "Laptop 1" in page and "Board 1" not in page
    assert admin.get("/admin/fleet?group=x&kind=toaster").status_code == 200


def test_outdated_versions_are_marked(app, client, admin):
    code = make_code(app)["code"]
    fleet_enroll(client, code, device={**LAPTOP, "cybics_version": "v1.2.3"}, label="Old")
    fleet_enroll(client, code, device={**LAPTOP, "cybics_version": "1.10.0"}, label="New")
    fleet_enroll(client, code, device={**LAPTOP, "cybics_version": "dev-build"}, label="Odd")
    found = {d["label"]: d["outdated"] for d in devices(app)}
    assert found == {"Old": True, "New": False, "Odd": False}
    assert "1.10.0" in admin.get("/admin/fleet").data.decode()


def test_version_key():
    assert fleet.version_key("v1.2.3") == (1, 2, 3)
    assert fleet.version_key("1.10") == (1, 10, 0)
    assert fleet.version_key("1.2.4-rc1") == (1, 2, 4)
    assert fleet.version_key("latest") is None and fleet.version_key(None) is None


def test_groups_and_codes(admin, app):
    admin.post("/admin/fleet/groups", data={**CSRF, "name": "Room 2"})
    resp = admin.post("/admin/fleet/groups", data={**CSRF, "name": "room 2"}, follow_redirects=True)
    assert b"exists already" in resp.data
    resp = admin.post("/admin/fleet/groups", data={**CSRF, "name": "<script>"}, follow_redirects=True)
    assert b"A group name has" in resp.data
    with app.app_context():
        group_id = get_db().execute("SELECT id FROM device_groups").fetchone()["id"]
    admin.post("/admin/fleet/codes", data={**CSRF, "label": "Lab boards", "group": str(group_id)})
    page = admin.get("/admin/fleet/setup").data.decode()
    assert "Lab boards" in page and "Room 2" in page
    admin.post(f"/admin/fleet/groups/{group_id}/delete", data=CSRF)
    with app.app_context():
        code = get_db().execute("SELECT * FROM enrol_codes").fetchone()
    assert code["group_id"] is None                       # the code stays, without a group
    assert admin.post("/admin/fleet/groups/999/delete", data=CSRF).status_code == 404
    assert admin.post("/admin/fleet/codes/999/disable", data=CSRF).status_code == 404
    assert admin.post(f"/admin/fleet/codes/{code['id']}/explode", data=CSRF).status_code == 404


def test_fleet_actions_are_audited_on_the_fleet_log_only(admin, device):
    admin.post(f"/admin/fleet/devices/{device['device_id']}/retire", data=CSRF)
    admin.post("/admin/fleet/groups", data={**CSRF, "name": "Room 2"})
    log = admin.get("/admin/fleet/log").data.decode()
    assert "fleet_device_retire" in log and "fleet_group_create" in log and "fleet_code_create" not in log
    assert "fleet_" not in admin.get("/admin/").data.decode()   # the events page lists logins only


def test_codes_never_collide_with_event_join_codes(app, event, monkeypatch):
    codes = iter([event["join_code"], "UNIQUE23"])
    monkeypatch.setattr(fleet, "new_join_code", lambda: next(codes))
    assert make_code(app)["code"] == "UNIQUE23"
