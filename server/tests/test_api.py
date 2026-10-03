"""The device-facing API: enrolment, joining an event, heartbeat, solves, scoreboard."""
import json

import pytest

from conftest import CATALOG, FLAGS, auth, enroll, enroll_device, join
from cybics_mgmt.ctf import logic as ctf
from cybics_mgmt.db import get_db


def solve(client, token, challenge, flag=None):
    return client.post("/api/v1/solves", headers=auth(token), json={
        "challenge_id": challenge, "flag": flag if flag is not None else FLAGS[challenge],
        "solved_at": 1234.5})


def test_info_identifies_the_server(client):
    data = client.get("/api/v1/info").get_json()
    assert data["service"] == "cybics-mgmt"
    assert data["api_version"] == 1


def test_enroll_creates_team_and_returns_token_once(client, event, app):
    resp = enroll(client, event)
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["team"]["name"] == "Red Team"
    assert data["event"]["state"] == "running"
    assert len(data["token"]) > 30
    with app.app_context():
        row = get_db().execute("SELECT token_hash FROM devices").fetchone()
        assert data["token"] not in row["token_hash"], "only the hash may be stored"


def test_join_code_is_case_insensitive(client, event):
    token = enroll_device(client, event["join_code"].lower()).get_json()["token"]
    resp = join(client, token, {"join_code": event["join_code"].lower()}, team="Blue", password="pass-1234")
    assert resp.status_code == 201


def test_second_instance_joins_existing_team_with_password(client, event):
    first = enroll(client, event).get_json()
    second = enroll(client, event, team="red team").get_json()  # names are case-insensitive
    assert second["team"]["id"] == first["team"]["id"]
    assert second["instance_id"] != first["instance_id"]


def test_wrong_team_password_is_refused(client, event):
    enroll(client, event)
    resp = enroll(client, event, password="not-it")
    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "wrong_team_password"


def test_unknown_join_code(client, event):
    token = enroll_device(client, event["join_code"]).get_json()["token"]
    resp = join(client, token, {"join_code": "NOPE1234"}, team="x y", password="abcd")
    assert resp.status_code == 404
    assert resp.get_json()["error"]["code"] == "invalid_join_code"


def test_physical_instance_needs_device_uid(client, event):
    resp = enroll(client, event, kind="physical")
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "invalid_device"


def test_physical_reenrol_revokes_previous_registration(client, event):
    # A reflashed board is a new device with the same UID; in the same team it replaces the old one.
    old = enroll(client, event, kind="physical", device_uid="0042001A3133").get_json()
    new = enroll(client, event, kind="physical", device_uid="0042001a3133").get_json()
    assert client.post("/api/v1/heartbeat", headers=auth(old["token"]), json={}).get_json()["ctf"] is None
    assert client.post("/api/v1/heartbeat", headers=auth(new["token"]), json={}).get_json()["ctf"]["team"]["name"] \
        == "Red Team"


def test_registration_closed(client, event, app):
    with app.app_context():
        ctf.update_event_settings(get_db(), event["id"], "Test Event", True, False)
    resp = enroll(client, event)
    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "registration_closed"


def test_cannot_enrol_into_finished_event(client, event, app):
    token = enroll_device(client, event["join_code"]).get_json()["token"]
    with app.app_context():
        ctf.set_event_state(get_db(), event["id"], "finished")
    assert join(client, token, event).status_code == 409


def test_bad_team_names_are_refused(client, event):
    for name in ("", "x", "a" * 41, "<script>"):
        resp = enroll(client, event, team=name)
        assert resp.status_code == 400, name


def test_requests_without_token_are_unauthorized(client, event):
    assert client.post("/api/v1/heartbeat", json={}).status_code == 401
    assert client.post("/api/v1/solves", json={}).status_code == 401
    assert client.post("/api/v1/heartbeat", headers=auth("forged"), json={}).status_code == 401


def test_solve_flow_and_scoring(client, enrolled):
    token = enrolled["token"]
    resp = solve(client, token, "physical_process")
    assert resp.get_json() == {"result": "accepted", "points": 100, "bonus": 0}
    assert solve(client, token, "physical_process").get_json()["result"] == "duplicate"
    assert solve(client, token, "plc_programming").get_json()["points"] == 150

    hb = client.post("/api/v1/heartbeat", headers=auth(token), json={}).get_json()["ctf"]
    assert hb["team"]["score"] == 250
    assert hb["team"]["rank"] == 1
    assert hb["solved"] == ["physical_process", "plc_programming"]


def test_teammates_share_solves(client, event):
    a = enroll(client, event).get_json()
    b = enroll(client, event).get_json()
    assert solve(client, a["token"], "physical_process").get_json()["result"] == "accepted"
    assert solve(client, b["token"], "physical_process").get_json()["result"] == "duplicate"


def test_wrong_flag_and_unknown_challenge_are_audited(client, enrolled, app):
    token = enrolled["token"]
    assert solve(client, token, "physical_process", "CybICS(nope)").get_json()["result"] == "invalid_flag"
    assert solve(client, token, "does_not_exist", "CybICS(x)").get_json()["result"] == "unknown_challenge"
    with app.app_context():
        results = [r["result"] for r in get_db().execute("SELECT result FROM submissions ORDER BY id")]
    assert results == ["invalid_flag", "unknown_challenge"]


def test_solves_only_count_while_running(client, enrolled, event, app):
    with app.app_context():
        ctf.set_event_state(get_db(), event["id"], "paused")
    assert solve(client, enrolled["token"], "physical_process").get_json()["result"] == "event_not_running"


def test_disabled_challenge_is_unknown(client, enrolled, event, app):
    with app.app_context():
        db = get_db()
        cid = db.execute("SELECT id FROM challenges WHERE key = 'physical_process'").fetchone()["id"]
        ctf.update_challenge(db, event["id"], cid, 100, False)
    assert solve(client, enrolled["token"], "physical_process").get_json()["result"] == "unknown_challenge"


def test_banned_team_is_locked_out(client, enrolled, app):
    with app.app_context():
        ctf.set_team_banned(get_db(), enrolled["team"]["id"], True)
    # The device keeps its heartbeat (the fleet still manages it); its team cannot report.
    hb = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]), json={})
    assert hb.status_code == 200 and hb.get_json()["ctf"]["team"]["banned"] is True
    resp = solve(client, enrolled["token"], "physical_process")
    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "team_banned"


def test_leaving_the_event_keeps_the_device(client, enrolled):
    assert client.delete("/api/v1/ctf/join", headers=auth(enrolled["token"])).status_code == 204
    hb = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]), json={})
    assert hb.status_code == 200 and hb.get_json()["ctf"] is None
    resp = solve(client, enrolled["token"], "physical_process")
    assert resp.status_code == 409 and resp.get_json()["error"]["code"] == "not_in_event"
    assert client.get("/api/v1/challenges", headers=auth(enrolled["token"])).status_code == 409


def test_disconnecting_retires_the_device(client, enrolled):
    assert client.delete("/api/v1/device", headers=auth(enrolled["token"])).status_code == 204
    assert client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]), json={}).status_code == 401


def test_heartbeat_stores_status_and_delivers_announcements(client, enrolled, event, app):
    with app.app_context():
        ctf.add_announcement(get_db(), event["id"], "Hint for scanning is out")
    status = {"cybics_version": "1.2.4", "mode": "minimal", "services": {"openplc": True}}
    hb = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]),
                     json={"status": status}).get_json()["ctf"]
    assert [a["message"] for a in hb["announcements"]] == ["Hint for scanning is out"]
    last = hb["announcements"][-1]["id"]
    hb = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]),
                     json={"announcements_after": last}).get_json()["ctf"]
    assert hb["announcements"] == []
    with app.app_context():
        row = get_db().execute("SELECT cybics_version, mode, status_json FROM devices").fetchone()
    assert row["cybics_version"] == "1.2.4" and row["mode"] == "minimal"
    assert json.loads(row["status_json"])["services"] == {"openplc": True}


def test_challenges_endpoint_never_exposes_flags(client, enrolled):
    data = client.get("/api/v1/challenges", headers=auth(enrolled["token"])).get_json()
    assert {c["id"] for c in data["challenges"]} == set(FLAGS)
    assert "flag" not in json.dumps(data).lower().replace("flag_", "")
    for flag in FLAGS.values():
        assert flag not in json.dumps(data)


def test_scoreboard_ranking_and_ties(client, event):
    a = enroll(client, event, team="Alpha").get_json()
    b = enroll(client, event, team="Bravo").get_json()
    enroll(client, event, team="Charlie")
    solve(client, b["token"], "physical_process")
    solve(client, a["token"], "physical_process")
    board = client.get(f"/api/v1/events/{event['slug']}/scoreboard").get_json()["scoreboard"]
    assert [(e["name"], e["rank"], e["score"]) for e in board] == [
        ("Bravo", 1, 100), ("Alpha", 2, 100), ("Charlie", 3, 0)]
    assert "team_id" not in board[0]


def test_private_scoreboard_is_hidden(client, event, app):
    with app.app_context():
        ctf.update_event_settings(get_db(), event["id"], "Test Event", False, True)
    assert client.get(f"/api/v1/events/{event['slug']}/scoreboard").status_code == 404
    assert client.get(f"/scoreboard/{event['slug']}").status_code == 404


def test_first_blood(client, event):
    a = enroll(client, event, team="Alpha").get_json()
    b = enroll(client, event, team="Bravo").get_json()
    solve(client, a["token"], "physical_process")
    solve(client, b["token"], "physical_process")
    feed = client.get(f"/api/v1/events/{event['slug']}/scoreboard").get_json()["recent_solves"]
    assert [(s["team"], s["first_blood"]) for s in feed] == [("Bravo", False), ("Alpha", True)]


def test_solve_rate_limit(client, enrolled, app):
    app.config["RATE_LIMIT_SOLVE"] = (3, 60)
    codes = [solve(client, enrolled["token"], "physical_process").status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]


def test_reimport_keeps_solves_and_disables_removed(client, enrolled, event, app):
    solve(client, enrolled["token"], "defense_firewall")
    smaller = json.loads(json.dumps(CATALOG))
    del smaller["categories"]["defense"]
    smaller["categories"]["basic_understanding"]["challenges"][0]["points"] = 120
    with app.app_context():
        db = get_db()
        ctf.import_catalog(db, event["id"], json.dumps(smaller))
        rows = {r["key"]: r for r in ctf.list_challenges(db, event["id"])}
        assert rows["defense_firewall"]["in_catalog"] == 0
        assert rows["physical_process"]["points"] == 120
        # the removed challenge's points stay with the team
        assert ctf.scoreboard(db, event["id"])[0]["score"] == 250


def test_catalog_validation(app):
    with app.app_context():
        db = get_db()
        event = ctf.create_event(db, "cat", "Cat")
        for raw in ("not json", "{}", '{"categories": {}}',
                    '{"categories": {"a": {"challenges": [{"id": "x", "points": 1}]}}}',
                    '{"categories": {"a": {"challenges": [{"id": "x", "points": -1, "flag": "f"}]}}}'):
            try:
                ctf.import_catalog(db, event["id"], raw)
            except ctf.CTFError as exc:
                assert exc.code == "invalid_catalog"
            else:
                raise AssertionError(f"accepted {raw!r}")


def test_non_json_body(client, enrolled):
    resp = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]), data="x",
                       content_type="text/plain")
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "invalid_json"


def test_api_404_is_json(client):
    resp = client.get("/api/v1/nope")
    assert resp.status_code == 404
    assert resp.get_json()["error"]["code"] == "not_found"


def test_oversized_status_is_discarded_not_truncated(client, enrolled, app):
    big = {"services": {f"s{i}": "x" * 100 for i in range(300)}}
    assert client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]),
                       json={"status": big}).status_code == 200
    with app.app_context():
        row = get_db().execute("SELECT status_json FROM devices").fetchone()
    assert "error" in json.loads(row["status_json"])


def test_lone_surrogates_are_a_400_not_a_500(client, event, enrolled):
    # JSON allows "\ud800"; UTF-8, hashing and SQLite do not.
    bad = "\ud800"
    assert solve(client, enrolled["token"], "physical_process", flag=bad).status_code == 400
    assert solve(client, enrolled["token"], bad, flag="x").status_code == 400
    for field in ("join_code", "team_name", "team_password"):
        body = {"join_code": event["join_code"], "team_name": "Blue Team", "team_password": "secret-12",
                "instance": {"kind": "virtual"}, field: bad}
        assert client.post("/api/v1/enroll", json=body).status_code in (400, 404), field
    resp = enroll(client, event, team="Blue Team", hostname=bad, mode=bad)
    assert resp.status_code == 201
    resp = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]),
                       json={"status": {"mode": bad, "cybics_version": bad, bad: bad}})
    assert resp.status_code == 200


def test_a_password_change_during_enrolment_is_retried_not_hashed_under_the_lock(
        client, event, enrolled, app, monkeypatch):
    real_verify = ctf.verify_password

    def verify_then_change(stored, password):
        ok = real_verify(stored, password)
        db = get_db()
        db.execute("UPDATE teams SET password_hash = 'changed' WHERE name = 'Red Team'")
        db.commit()
        monkeypatch.setattr(ctf, "verify_password", lambda *a: pytest.fail("hashed under the lock"))
        return ok

    monkeypatch.setattr(ctf, "verify_password", verify_then_change)
    resp = enroll(client, event)
    assert resp.status_code == 503
    assert resp.get_json()["error"]["code"] == "busy"


def test_a_board_computed_before_an_invalidation_is_not_cached(app, event, monkeypatch):
    from cybics_mgmt.ctf import api
    real_board = ctf.scoreboard

    def solve_lands_meanwhile(db, event_id):
        board = real_board(db, event_id)
        api.invalidate_board()
        return board

    monkeypatch.setattr(ctf, "scoreboard", solve_lands_meanwhile)
    api.invalidate_board()
    with app.app_context():
        api.public_board(get_db(), event)
    assert api._board_cache == {}
