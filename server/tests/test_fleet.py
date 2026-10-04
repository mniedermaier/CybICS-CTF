"""The fleet: devices across events, groups, enrolment codes, devices joining events."""
import pytest

from conftest import auth, enroll, enroll_device, join
from cybics_mgmt.ctf import logic as ctf
from cybics_mgmt.db import get_db
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
    return client.post("/api/v1/enroll", json=body, **kw)


@pytest.fixture
def device(client, app):
    resp = fleet_enroll(client, make_code(app)["code"])
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()


def devices(app, **kw):
    with app.app_context():
        found, _ = fleet.list_devices(get_db(), 0, **kw)
        return found


# ---------- devices in events ----------

def test_a_device_joins_an_event_and_leaves_it(client, app, event):
    joined = enroll(client, event, **LAPTOP).get_json()
    [d] = devices(app)
    assert d["id"] == joined["device_id"] and d["ctf"] == "Red Team · Test Event" and d["state"] == "online"
    hb = client.post("/api/v1/heartbeat", headers=auth(joined["token"]), json={}).get_json()
    assert hb["ctf"]["instance_id"] == joined["instance_id"] and hb["device"]["id"] == joined["device_id"]
    client.delete("/api/v1/ctf/join", headers=auth(joined["token"]))
    [d] = devices(app)
    assert d["ctf"] is None and d["state"] == "online"          # still a device in the fleet


def test_a_device_is_in_one_event_at_a_time(client, app, event):
    with app.app_context():
        other = dict(ctf.create_event(get_db(), "other", "Other"))
    joined = enroll(client, event).get_json()
    moved = join(client, joined["token"], other, team="Blue Team", password="blue-pass-1")
    assert moved.status_code == 201
    with app.app_context():
        live = get_db().execute("SELECT COUNT(*) FROM instances WHERE revoked = 0").fetchone()[0]
    assert live == 1 and devices(app)[0]["ctf"] == "Blue Team · Other"


def test_the_organiser_puts_a_device_into_a_team(client, app, event, admin):
    with app.app_context():
        team = ctf.create_team(get_db(), event["id"], "Blue Team", "blue-pass-1")
        other = ctf.create_team(get_db(), event["id"], "Green Team", "green-pass-1")
    device = enroll_device(client, make_code(app)["code"], **LAPTOP).get_json()
    page = admin.get(f"/admin/fleet/devices/{device['device_id']}").data.decode()
    assert "Test Event &middot; Blue Team" in page
    admin.post(f"/admin/fleet/devices/{device['device_id']}/ctf", data={**CSRF, "team": str(team["id"])})
    hb = client.post("/api/v1/heartbeat", headers=auth(device["token"]), json={}).get_json()
    assert hb["ctf"]["team"]["name"] == "Blue Team"
    with app.app_context():
        assert get_db().execute("SELECT joined_by FROM instances").fetchone()["joined_by"] == "organiser"
    admin.post(f"/admin/fleet/devices/{device['device_id']}/ctf", data={**CSRF, "team": str(other["id"])})
    assert devices(app)[0]["ctf"] == "Green Team · Test Event"
    admin.post(f"/admin/fleet/devices/{device['device_id']}/ctf", data={**CSRF, "team": "leave"})
    assert devices(app)[0]["ctf"] is None
    log = admin.get(f"/admin/events/{event['id']}/log").data.decode()
    assert "fleet_device_assign" in log
    assert "fleet_device_leave_event" in admin.get("/admin/fleet/log").data.decode()


def test_assigning_refuses_what_joining_refuses(client, app, event, admin):
    with app.app_context():
        db = get_db()
        banned = ctf.create_team(db, event["id"], "Banned Team", "banned-pass")
        ctf.set_team_banned(db, banned["id"], True)
    device = enroll_device(client, make_code(app)["code"]).get_json()
    url = f"/admin/fleet/devices/{device['device_id']}/ctf"
    assert b"disqualified" in admin.post(url, data={**CSRF, "team": str(banned["id"])}, follow_redirects=True).data
    assert b"Choose a team" in admin.post(url, data={**CSRF, "team": ""}, follow_redirects=True).data
    assert b"Unknown team" in admin.post(url, data={**CSRF, "team": "999"}, follow_redirects=True).data
    admin.post(f"/admin/fleet/devices/{device['device_id']}/retire", data=CSRF)
    with app.app_context():
        team = ctf.create_team(get_db(), event["id"], "Blue Team", "blue-pass-1")
    assert b"retired" in admin.post(url, data={**CSRF, "team": str(team["id"])}, follow_redirects=True).data
    assert admin.post("/admin/fleet/devices/nope/ctf", data={**CSRF, "team": "leave"}).status_code == 404


def test_retiring_a_device_ends_its_participation(client, app, event, admin):
    joined = enroll(client, event).get_json()
    admin.post(f"/admin/fleet/devices/{joined['device_id']}/retire", data=CSRF)
    with app.app_context():
        assert ctf.participation(get_db(), joined["device_id"]) is None


def test_a_board_uid_never_acts_across_teams(client, app, event, admin):
    enroll(client, event, team="Red Team", **BOARD)
    enroll(client, event, team="Blue Team", password="blue-pass-1", **BOARD)
    found = devices(app)
    assert len(found) == 2 and all(d["uid_devices"] == 1 and d["ctf"] for d in found)
    assert "UID on 2 devices" in admin.get("/admin/fleet").data.decode()
    assert "UID in 2 teams" in admin.get(f"/admin/events/{event['id']}/instances").data.decode()


def test_deleting_an_event_keeps_its_devices(client, app, event, admin):
    joined = enroll(client, event).get_json()
    admin.post(f"/admin/events/{event['id']}/delete", data={**CSRF, "confirm": event["slug"]})
    [d] = devices(app)
    assert d["id"] == joined["device_id"] and d["state"] == "online" and d["ctf"] is None


# ---------- fleet enrolment ----------

def test_fleet_enrolment_with_a_code(client, app):
    code = make_code(app, group="Room 2")
    resp = fleet_enroll(client, code["code"].lower(), device=BOARD, label="  Board   7 ")
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["device"] == {"id": data["device_id"], "label": "Board 7", "group": "Room 2"}
    assert data["token"] and data["heartbeat_interval"] == 30
    [d] = devices(app)
    assert d["device_uid"] == BOARD["device_uid"] and d["ctf"] is None
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
    resp = client.post("/api/v1/enroll", json=body)
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
    assert "unknown enrolment codes" in admin.get("/admin/").data.decode()
    admin.post("/admin/lockouts/clear", data=CSRF)
    assert fleet_enroll(client, code).status_code == 201


def test_new_devices_per_address_are_capped(client, app):
    app.config["RATE_LIMIT_NEW_DEVICES"] = (2, 600)
    code = make_code(app)["code"]
    assert [fleet_enroll(client, code).status_code for _ in range(3)] == [201, 201, 429]


# ---------- fleet heartbeat and leaving ----------

def test_fleet_heartbeat_stores_the_status(client, app, device):
    resp = client.post("/api/v1/heartbeat", headers=auth(device["token"]), json={"status": {
        "cybics_version": "1.3.0", "hostname": "renamed", "services": {"landing": True},
        "host": {"cpu_temp": 51.5}}})
    assert resp.status_code == 200
    assert resp.get_json()["device"]["id"] == device["device_id"]
    [d] = devices(app)
    assert (d["cybics_version"], d["hostname"], d["services_up"]) == ("1.3.0", "renamed", 1)
    client.post("/api/v1/heartbeat", headers=auth(device["token"]), json={})
    assert devices(app)[0]["cybics_version"] == "1.3.0"   # no status keeps the last one


def test_fleet_heartbeat_discards_hostile_statuses(client, app, device):
    deep = {}
    for _ in range(50):
        deep = {"x": deep}
    client.post("/api/v1/heartbeat", headers=auth(device["token"]), json={"status": deep})
    with app.app_context():
        stored = get_db().execute("SELECT status_json FROM devices").fetchone()[0]
    assert "too deeply nested" in stored
    client.post("/api/v1/heartbeat", headers=auth(device["token"]), json={"status": {"x": "y" * 20000}})
    with app.app_context():
        assert "too large" in get_db().execute("SELECT status_json FROM devices").fetchone()[0]


def test_fleet_heartbeat_needs_a_valid_token(client):
    for headers in ({}, auth("nope"), {"Authorization": "Bearer \ud800"}):
        resp = client.post("/api/v1/heartbeat", headers=headers, json={})
        assert resp.status_code == 401


def test_retired_devices_are_locked_out_until_brought_back(client, app, device, admin):
    admin.post(f"/admin/fleet/devices/{device['device_id']}/retire", data=CSRF)
    assert client.post("/api/v1/heartbeat", headers=auth(device["token"]), json={}).status_code == 401
    assert devices(app) == []
    admin.post(f"/admin/fleet/devices/{device['device_id']}/restore", data=CSRF)
    assert client.post("/api/v1/heartbeat", headers=auth(device["token"]), json={}).status_code == 200


def test_leaving_retires_the_device(client, app, device, admin):
    assert client.delete("/api/v1/device", headers=auth(device["token"])).status_code == 204
    assert client.post("/api/v1/heartbeat", headers=auth(device["token"]), json={}).status_code == 401
    page = admin.get(f"/admin/fleet/devices/{device['device_id']}").data.decode()
    assert "retired" in page and "by the device itself" in page


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


# ---------- the default enrolment code ----------

def test_the_default_code_is_created_once_and_never_re_enabled(tmp_path, admin):
    from conftest import ADMIN_PASSWORD, SIGNING_KEY
    from cybics_mgmt import create_app
    config = {"DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / "db.sqlite"), "SECRET_KEY": "test",
              "ADMIN_PASSWORD": ADMIN_PASSWORD, "FLEET_SIGNING_KEY": SIGNING_KEY,
              "DEFAULT_ENROL_CODE": "cybics-boards"}
    app = create_app(config)
    client = app.test_client()
    assert enroll_device(client, "CYBICS-BOARDS", **BOARD).status_code == 201
    with app.app_context():
        db = get_db()
        row = db.execute("SELECT * FROM enrol_codes").fetchone()
        assert (row["code"], row["uses"]) == ("CYBICS-BOARDS", 1)
        fleet.set_code_enabled(db, row["id"], False)
    create_app(config)                                     # a restart
    with app.app_context():
        assert get_db().execute("SELECT enabled FROM enrol_codes").fetchone()["enabled"] == 0


@pytest.mark.parametrize("code", ["no", "with space", "x" * 17])
def test_a_malformed_default_code_stops_the_start(tmp_path, code):
    from conftest import ADMIN_PASSWORD
    from cybics_mgmt import create_app
    with pytest.raises(ValueError):
        create_app({"DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / "db.sqlite"), "SECRET_KEY": "test",
                    "ADMIN_PASSWORD": ADMIN_PASSWORD, "DEFAULT_ENROL_CODE": code})


def test_the_default_code_never_shadows_a_join_code(app, event):
    with app.app_context(), pytest.raises(ValueError, match="join code"):
        fleet.ensure_code(get_db(), event["join_code"], "x")
