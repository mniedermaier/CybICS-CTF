"""
Moderation, input hardening and admin actions. Most cases here are regression
tests for findings from review: each one used to crash a page, lose evidence or
let a moderation action silently fail.
"""
import json
import time

import pytest

from conftest import CATALOG, FLAGS, auth, enroll, enroll_device
from cybics_mgmt import create_app
from cybics_mgmt.ctf import logic as ctf
from cybics_mgmt.db import MIGRATIONS, connect, get_db, migrate

CSRF = {"csrf": "csrf-test"}


def solve(client, token, challenge, **extra):
    return client.post("/api/v1/solves", headers=auth(token), json={
        "challenge_id": challenge, "flag": FLAGS[challenge], **extra})


# ---------- hostile input never becomes a 500 ----------

@pytest.mark.parametrize("solved_at", [1e300, -1e20, 0, "soon", True, [1], None])
def test_absurd_client_time_is_dropped_and_audit_page_renders(admin, client, enrolled, event, app,
                                                             solved_at):
    resp = solve(client, enrolled["token"], "physical_process", solved_at=solved_at)
    assert resp.get_json()["result"] == "accepted"
    with app.app_context():
        assert get_db().execute("SELECT client_time FROM solves").fetchone()["client_time"] is None
    assert admin.get(f"/admin/events/{event['id']}/solves").status_code == 200


def test_plausible_client_time_is_kept(client, enrolled, app):
    ts = time.time() - 60
    solve(client, enrolled["token"], "physical_process", solved_at=ts)
    with app.app_context():
        assert get_db().execute("SELECT client_time FROM solves").fetchone()["client_time"] == ts


def test_time_filters_survive_broken_values(app):
    time_filter, ago = app.jinja_env.filters["time"], app.jinja_env.filters["ago"]
    for value in (1e300, float("inf"), float("nan"), "x"):
        assert time_filter(value) == "-"
        assert ago(value) == "-"


@pytest.mark.parametrize("body", [
    {"join_code": 123, "team_name": "Red", "team_password": "abcd"},
    {"join_code": "X", "team_name": ["Red"], "team_password": "abcd"},
    {"join_code": "X", "team_name": "Red", "team_password": 12345},
])
def test_wrong_types_on_join_are_400(client, event, body):
    if body["join_code"] == "X":
        body["join_code"] = event["join_code"]
    token = enroll_device(client, event["join_code"]).get_json()["token"]
    resp = client.post("/api/v1/ctf/join", headers=auth(token), json=body)
    assert resp.status_code == 400, resp.get_json()


def test_wrong_device_type_on_enroll_is_400(client, event):
    resp = client.post("/api/v1/enroll", json={"code": event["join_code"], "device": ["virtual"]})
    assert resp.status_code == 400, resp.get_json()


@pytest.mark.parametrize("body", [
    {"challenge_id": 5, "flag": "CybICS(x)"},
    {"challenge_id": "physical_process", "flag": {"a": 1}},
    {"challenge_id": "physical_process"},
])
def test_wrong_types_on_solve_are_400(client, enrolled, body):
    resp = client.post("/api/v1/solves", headers=auth(enrolled["token"]), json=body)
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "invalid_input"


@pytest.mark.parametrize("after", [10**20, 1e300, "inf", -5, None, [1]])
def test_announcements_after_is_clamped(client, enrolled, after):
    resp = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]),
                       json={"announcements_after": after})
    assert resp.status_code == 200


def test_heartbeat_reports_catalog_version(client, enrolled, event, app):
    hb = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]), json={}).get_json()["ctf"]
    with app.app_context():
        db = get_db()
        cid = db.execute("SELECT id FROM challenges WHERE key = 'physical_process'").fetchone()["id"]
        ctf.update_challenge(db, event["id"], cid, 100, False)
    hb2 = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]), json={}).get_json()["ctf"]
    assert hb["catalog_version"] and hb["catalog_version"] != hb2["catalog_version"]


# ---------- event rules ----------

def test_event_cannot_start_without_catalog(app, admin):
    with app.app_context():
        event = ctf.create_event(get_db(), "empty", "Empty")
        with pytest.raises(ctf.CTFError) as exc:
            ctf.set_event_state(get_db(), event["id"], "running")
    assert exc.value.code == "empty_catalog"
    resp = admin.post(f"/admin/events/{event['id']}/state", data={**CSRF, "state": "running"},
                      follow_redirects=True)
    assert b"Import the challenge catalog" in resp.data


def test_draft_scoreboard_is_private(client, app):
    with app.app_context():
        ctf.create_event(get_db(), "drafty", "Drafty")
    assert client.get("/scoreboard/drafty").status_code == 404
    assert client.get("/api/v1/events/drafty/scoreboard").status_code == 404
    assert b"Drafty" not in client.get("/").data


# ---------- moderation ----------

def test_first_blood_ignores_banned_and_voided(client, event, app):
    cheat = enroll(client, event, team="Cheaters").get_json()
    honest = enroll(client, event, team="Honest").get_json()
    solve(client, cheat["token"], "physical_process")
    solve(client, honest["token"], "physical_process")
    with app.app_context():
        ctf.set_team_banned(get_db(), cheat["team"]["id"], True)
    feed = client.get(f"/api/v1/events/{event['slug']}/scoreboard").get_json()["recent_solves"]
    assert [(s["team"], s["first_blood"]) for s in feed] == [("Honest", True)]


def test_voided_solve_scores_nothing_and_is_not_resent(admin, client, enrolled, event, app):
    solve(client, enrolled["token"], "physical_process")
    with app.app_context():
        solve_id = get_db().execute("SELECT id FROM solves").fetchone()["id"]
    admin.post(f"/admin/events/{event['id']}/solves/{solve_id}/void", data=CSRF)

    hb = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]), json={}).get_json()["ctf"]
    assert hb["team"]["score"] == 0
    # still on record, so the client's reconciliation leaves it alone ...
    assert "physical_process" in hb["solved"]
    # ... and a direct resubmission does not bring the points back
    assert solve(client, enrolled["token"], "physical_process").get_json()["result"] == "duplicate"
    assert client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]),
                       json={}).get_json()["ctf"]["team"]["score"] == 0

    page = admin.get(f"/admin/events/{event['id']}/solves").data
    assert b"voided" in page and b"Restore" in page
    admin.post(f"/admin/events/{event['id']}/solves/{solve_id}/restore", data=CSRF)
    assert client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]),
                       json={}).get_json()["ctf"]["team"]["score"] == 100


def test_deleting_a_team_keeps_its_audit_trail(admin, client, enrolled, event, app):
    solve(client, enrolled["token"], "physical_process")
    client.post("/api/v1/solves", headers=auth(enrolled["token"]),
                json={"challenge_id": "physical_process", "flag": "CybICS(guess)"})
    team_id = enrolled["team"]["id"]

    admin.post(f"/admin/events/{event['id']}/teams/{team_id}/delete", data={**CSRF, "confirm": "nope"})
    with app.app_context():
        assert get_db().execute("SELECT 1 FROM teams WHERE id = ?", (team_id,)).fetchone()

    admin.post(f"/admin/events/{event['id']}/teams/{team_id}/delete", data={**CSRF, "confirm": "red team"})
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT 1 FROM teams WHERE id = ?", (team_id,)).fetchone() is None
        rows = db.execute("SELECT team_id, team_name, result FROM submissions").fetchall()
    assert [(r["team_id"], r["team_name"]) for r in rows] == [(None, "Red Team")] * 2
    assert b"Red Team" in admin.get(f"/admin/events/{event['id']}/solves").data


def test_wrong_flags_count_as_suspicious_unknown_ids_do_not(admin, client, enrolled, event):
    client.post("/api/v1/solves", headers=auth(enrolled["token"]),
                json={"challenge_id": "physical_process", "flag": "CybICS(guess)"})
    client.post("/api/v1/solves", headers=auth(enrolled["token"]),
                json={"challenge_id": "newer_cybics_challenge", "flag": "CybICS(x)"})
    page = admin.get(f"/admin/events/{event['id']}/solves").data.decode()
    assert "physical_process" in page and "newer_cybics_challenge" not in page


def test_team_admin_actions(admin, client, event, app):
    admin.post(f"/admin/events/{event['id']}/teams", data={**CSRF, "name": "Blue", "password": "pw12-pw12"})
    with app.app_context():
        team_id = get_db().execute("SELECT id FROM teams WHERE name = 'Blue'").fetchone()["id"]
    assert enroll(client, event, team="Blue", password="pw12-pw12").status_code == 201
    admin.post(f"/admin/events/{event['id']}/teams/{team_id}/password", data={**CSRF, "password": "new-pw-123"})
    assert enroll(client, event, team="Blue", password="pw12-pw12").status_code == 403
    assert enroll(client, event, team="Blue", password="new-pw-123").status_code == 201
    admin.post(f"/admin/events/{event['id']}/teams/{team_id}/unban", data=CSRF)
    assert admin.post(f"/admin/events/{event['id']}/teams/{team_id}/explode", data=CSRF).status_code == 404


def test_revoke_instance_from_ui(admin, client, enrolled, event):
    admin.post(f"/admin/events/{event['id']}/instances/{enrolled['instance_id']}/revoke", data=CSRF)
    hb = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]), json={})
    assert hb.status_code == 200 and hb.get_json()["ctf"] is None     # still a device, no longer in the event


def test_announcement_delete(admin, client, enrolled, event):
    admin.post(f"/admin/events/{event['id']}/announcements", data={**CSRF, "message": "hello"})
    hb = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]), json={}).get_json()["ctf"]
    aid = hb["announcements"][0]["id"]
    admin.post(f"/admin/events/{event['id']}/announcements/{aid}/delete", data=CSRF)
    hb = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]), json={}).get_json()["ctf"]
    assert hb["announcements"] == []


def test_challenge_points_and_join_code(admin, event, app):
    with app.app_context():
        cid = get_db().execute("SELECT id FROM challenges WHERE key = 'opcua' OR key = 'physical_process'"
                               ).fetchone()["id"]
    admin.post(f"/admin/events/{event['id']}/challenges/{cid}", data={**CSRF, "points": "77", "enabled": "on"})
    admin.post(f"/admin/events/{event['id']}/join-code", data=CSRF)
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT points FROM challenges WHERE id = ?", (cid,)).fetchone()["points"] == 77
        assert ctf.get_event(db, event["id"])["join_code"] != event["join_code"]
    resp = admin.post(f"/admin/events/{event['id']}/challenges/{cid}", data={**CSRF, "points": "x"},
                      follow_redirects=True)
    assert b"Points must be a number" in resp.data


# ---------- admin session ----------

def test_logout(admin):
    admin.post("/admin/logout", data=CSRF)
    assert admin.get("/admin/").status_code == 302


def test_session_ends_when_admin_password_changes(admin, app):
    assert admin.get("/admin/").status_code == 200
    app.config["ADMIN_PASSWORD"] = "rotated"
    assert admin.get("/admin/").status_code == 302


def test_session_expires(admin, app):
    with admin.session_transaction() as sess:
        sess["admin_since"] = time.time() - app.config["ADMIN_SESSION_LIFETIME"] - 1
    assert admin.get("/admin/").status_code == 302


def test_forged_session_flag_is_not_enough(client):
    with client.session_transaction() as sess:
        sess["admin"] = True
        sess["admin_since"] = time.time()
    assert client.get("/admin/").status_code == 302


def test_admin_actions_are_logged(admin, event, caplog):
    with caplog.at_level("INFO", logger="cybics_mgmt"):
        admin.post(f"/admin/events/{event['id']}/state", data={**CSRF, "state": "paused"})
    assert any("event_state" in r.getMessage() for r in caplog.records)


# ---------- configuration and storage ----------

def test_generated_secret_key_is_private_and_stable(tmp_path, monkeypatch):
    monkeypatch.delenv("MGMT_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("MGMT_SECRET_KEY", raising=False)
    first = create_app({"DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / "db.sqlite")})
    second = create_app({"DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / "db.sqlite")})
    assert first.config["SECRET_KEY"] == second.config["SECRET_KEY"]
    assert (tmp_path / "secret_key").stat().st_mode & 0o777 == 0o600
    assert first.config["ADMIN_PASSWORD"] == ""               # set in the browser instead
    assert not (tmp_path / "admin_password").exists()


def test_deleting_a_team_keeps_its_submissions(tmp_path):
    path = str(tmp_path / "db.sqlite")
    migrate(path)
    conn = connect(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
    conn.executescript("""
        INSERT INTO events (id, slug, name, join_code, created_at) VALUES (1, 'e', 'E', 'ABC', 0);
        INSERT INTO teams (id, event_id, name, password_hash, created_at) VALUES (1, 1, 'Old Team', 'x', 0);
        INSERT INTO submissions (event_id, team_id, team_name, challenge_key, result, received_at)
            VALUES (1, 1, 'Old Team', 'scanning', 'invalid_flag', 0);
    """)
    row = conn.execute("SELECT team_id, team_name FROM submissions").fetchone()
    assert (row["team_id"], row["team_name"]) == (1, "Old Team")
    conn.execute("DELETE FROM teams")
    assert conn.execute("SELECT team_id FROM submissions").fetchone()["team_id"] is None
    conn.close()


def test_backup_command(app, tmp_path, enrolled):
    target = tmp_path / "backup.sqlite"
    result = app.test_cli_runner().invoke(args=["backup", str(target)])
    assert result.exit_code == 0, result.output
    conn = connect(str(target))
    assert conn.execute("SELECT COUNT(*) FROM instances").fetchone()[0] == 1
    conn.close()
    assert app.test_cli_runner().invoke(args=["backup", str(target)]).exit_code != 0


def test_cli_set_state_errors_are_readable(app):
    result = app.test_cli_runner().invoke(args=["set-state", "nope", "running"])
    assert result.exit_code != 0
    with app.app_context():
        ctf.create_event(get_db(), "empty-cli", "Empty")
    result = app.test_cli_runner().invoke(args=["set-state", "empty-cli", "running"])
    assert result.exit_code != 0
    assert "Import the challenge catalog" in result.output


# ---------- review round 2 ----------

def test_spoofed_board_uid_cannot_revoke_another_team(client, event, admin, caplog):
    victim = enroll(client, event, team="Victims", kind="physical", device_uid="0042001a3133").get_json()
    with caplog.at_level("WARNING", logger="cybics_mgmt"):
        enroll(client, event, team="Attackers", kind="physical", device_uid="0042001a3133")
    assert client.post("/api/v1/heartbeat", headers=auth(victim["token"]), json={}).status_code == 200
    assert any("also live in team" in r.getMessage() for r in caplog.records)
    assert b"UID in 2 teams" in admin.get(f"/admin/events/{event['id']}/instances").data


def test_virtual_instance_cannot_claim_a_uid(client, event, app):
    enroll(client, event, kind="virtual", device_uid="0042001a3133")
    with app.app_context():
        assert get_db().execute("SELECT device_uid FROM devices").fetchone()["device_uid"] is None


def test_state_transitions(app):
    with app.app_context():
        db = get_db()
        event = ctf.create_event(db, "flow", "Flow")
        ctf.import_catalog(db, event["id"], json.dumps(CATALOG))
        with pytest.raises(ctf.CTFError):
            ctf.set_event_state(db, event["id"], "finished")      # draft -> finished
        for state in ("running", "paused", "running", "finished", "running"):
            ctf.set_event_state(db, event["id"], state)
        with pytest.raises(ctf.CTFError) as exc:
            ctf.set_event_state(db, event["id"], "draft")
        assert exc.value.code == "invalid_transition"


def test_deeply_nested_json_is_a_400(client):
    body = "[" * 100000 + "]" * 100000
    resp = client.post("/api/v1/enroll", data=body, content_type="application/json")
    assert resp.status_code == 400


def test_huge_points_are_refused(admin, event, app):
    with app.app_context():
        cid = get_db().execute("SELECT id FROM challenges").fetchone()["id"]
    resp = admin.post(f"/admin/events/{event['id']}/challenges/{cid}",
                      data={**CSRF, "points": "9" * 30, "enabled": "on"}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Points must be between" in resp.data


@pytest.mark.parametrize("catalog", [
    {"categories": {"a": "not a dict"}},
    {"categories": {"a": {"challenges": ["not a dict"]}}},
    {"categories": {"a": {"challenges": [{"id": "x", "points": 1, "flag": "f", "title": 5}]}}},
    {"categories": {"a": {"challenges": [{"id": "x", "points": 10**12, "flag": "f"}]}}},
])
def test_malformed_catalogs_are_refused(app, catalog):
    with app.app_context():
        event = ctf.create_event(get_db(), "bad", "Bad")
        with pytest.raises(ctf.CTFError) as exc:
            ctf.import_catalog(get_db(), event["id"], json.dumps(catalog))
    assert exc.value.code == "invalid_catalog"


def test_zero_point_solves_do_not_move_the_tie_break(client, event, app):
    with app.app_context():
        db = get_db()
        cid = db.execute("SELECT id FROM challenges WHERE key = 'plc_programming'").fetchone()["id"]
        ctf.update_challenge(db, event["id"], cid, 0, True)
    a = enroll(client, event, team="Alpha").get_json()
    b = enroll(client, event, team="Bravo").get_json()
    solve(client, a["token"], "physical_process")
    solve(client, b["token"], "physical_process")
    solve(client, a["token"], "plc_programming")      # 0 points, later
    board = client.get(f"/api/v1/events/{event['slug']}/scoreboard").get_json()["scoreboard"]
    assert [e["name"] for e in board] == ["Alpha", "Bravo"]


def test_reimport_keeps_organiser_changes(event, app):
    with app.app_context():
        db = get_db()
        rows = {r["key"]: r for r in ctf.list_challenges(db, event["id"])}
        ctf.update_challenge(db, event["id"], rows["physical_process"]["id"], 42, True)
        ctf.update_challenge(db, event["id"], rows["plc_programming"]["id"], 150, False)
        ctf.import_catalog(db, event["id"], json.dumps(CATALOG))
        rows = {r["key"]: r for r in ctf.list_challenges(db, event["id"])}
    assert rows["physical_process"]["points"] == 42
    assert rows["plc_programming"]["enabled"] == 0
    assert rows["defense_firewall"]["points"] == 250


def test_proxy_headers_only_from_the_proxy(tmp_path, monkeypatch):
    monkeypatch.setenv("MGMT_TRUST_PROXY", "1")
    monkeypatch.setenv("MGMT_FORWARDED_ALLOW_IPS", "10.0.0.0/8")
    app = create_app({"DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / "db.sqlite"),
                      "SECRET_KEY": "k", "ADMIN_PASSWORD": "p"})

    @app.get("/__ip")
    def _ip():
        from flask import request
        return request.remote_addr

    def seen(peer):
        return app.test_client().get("/__ip", headers={"X-Forwarded-For": "203.0.113.7"},
                                     environ_base={"REMOTE_ADDR": peer}).data.decode()

    assert seen("10.1.2.3") == "203.0.113.7"       # from the proxy: honoured
    assert seen("198.51.100.9") == "198.51.100.9"  # directly from a client: ignored


def test_login_needs_csrf(client):
    from conftest import ADMIN_PASSWORD
    with client.session_transaction() as sess:
        sess["csrf"] = "known"
    assert client.post("/admin/login", data={"password": ADMIN_PASSWORD}).status_code == 400
    resp = client.post("/admin/login", data={"password": ADMIN_PASSWORD, "csrf": "known"})
    assert resp.status_code == 302


def test_migrations_are_serialised(tmp_path):
    import threading as _t
    path = str(tmp_path / "race.sqlite")
    errors = []

    def run():
        try:
            migrate(path)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [_t.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    conn = connect(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
    conn.close()


def test_rate_limiter_forgets_idle_keys():
    from cybics_mgmt.security import RateLimiter
    limiter = RateLimiter()
    limiter.IDLE = 0
    limiter.PRUNE_EVERY = 1
    for i in range(50):
        limiter.hit(f"k{i}", 5, 60)
    assert len(limiter._hits) <= 1


# ---------- review round 3 ----------

def test_short_admin_password_from_env_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("MGMT_ADMIN_PASSWORD", "abc")
    with pytest.raises(RuntimeError):
        create_app({"DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / "db.sqlite")})


def test_empty_expected_password_never_matches(app):
    from cybics_mgmt.security import check_admin_password
    with app.app_context():
        app.config["ADMIN_PASSWORD"] = ""
        assert not check_admin_password("")


def test_new_team_flood_is_limited(client, event, app):
    app.config["RATE_LIMIT_NEW_TEAMS"] = (3, 600)
    codes = [enroll(client, event, team=f"Spam {i}").status_code for i in range(4)]
    assert codes == [201, 201, 201, 429]
    assert enroll(client, event, team="Spam 0").status_code == 201, "joining an existing team is fine"


def test_bad_tokens_are_rate_limited(client, event, app):
    app.config["RATE_LIMIT_BAD_TOKEN"] = (3, 60)
    codes = [client.post("/api/v1/heartbeat", headers=auth(f"guess{i}"), json={}).status_code
             for i in range(4)]
    assert codes == [401, 401, 401, 429]


def test_announcement_ids_are_never_reused(admin, client, enrolled, event):
    admin.post(f"/admin/events/{event['id']}/announcements", data={**CSRF, "message": "typo"})
    hb = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]), json={}).get_json()["ctf"]
    first = hb["announcements"][0]["id"]
    admin.post(f"/admin/events/{event['id']}/announcements/{first}/delete", data=CSRF)
    admin.post(f"/admin/events/{event['id']}/announcements", data={**CSRF, "message": "fixed"})
    hb = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]),
                     json={"announcements_after": first}).get_json()["ctf"]
    assert [a["message"] for a in hb["announcements"]] == ["fixed"]
    assert first not in hb["announcement_ids"]


def test_admin_log_records_web_and_cli_actions(admin, event, app):
    admin.post(f"/admin/events/{event['id']}/state", data={**CSRF, "state": "paused"})
    app.test_cli_runner().invoke(args=["set-state", event["slug"], "running"])
    page = admin.get(f"/admin/events/{event['id']}/log").data.decode()
    assert "event_state" in page and "cli" in page and "web " in page
    csv_text = admin.get(f"/admin/events/{event['id']}/export/log.csv").data.decode()
    assert csv_text.splitlines()[0] == "time,actor,action,details"


def test_csv_exports_neutralise_formulas(admin, client, event):
    assert enroll(client, event, team="=HYPERLINK(1)").status_code == 400   # refused outright
    team = enroll(client, event, team="+Plus Team").get_json()
    solve(client, team["token"], "physical_process")
    text = admin.get(f"/admin/events/{event['id']}/export/solves.csv").data.decode()
    assert "'+Plus Team" in text
    assert admin.get(f"/admin/events/{event['id']}/export/nope.csv").status_code == 404


def test_solves_page_filters_and_pages(admin, client, event, app, monkeypatch):
    import cybics_mgmt.ctf.admin as admin_module
    monkeypatch.setattr(admin_module, "PAGE_SIZE", 1)
    a = enroll(client, event, team="Alpha").get_json()
    b = enroll(client, event, team="Bravo").get_json()
    solve(client, a["token"], "physical_process")
    solve(client, b["token"], "physical_process")
    first = admin.get(f"/admin/events/{event['id']}/solves").data.decode()
    assert "older" in first and "Bravo" in first
    second = admin.get(f"/admin/events/{event['id']}/solves?page=1").data.decode()
    assert "newer" in second and "Alpha" in second
    filtered = admin.get(f"/admin/events/{event['id']}/solves?team={a['team']['id']}").data.decode()
    assert "Alpha" in filtered.split("All solves")[1] and "Bravo" not in filtered.split("All solves")[1]


def test_cli_import_from_stdin(app):
    runner = app.test_cli_runner()
    runner.invoke(args=["create-event", "stdin", "Stdin"])
    result = runner.invoke(args=["import-catalog", "stdin", "-"], input=json.dumps(CATALOG))
    assert "Imported 3 challenges" in result.output


# ---------- review round 4 ----------

def test_login_flood_does_not_bury_the_log(client, app, admin):
    app.config["RATE_LIMIT_LOGIN"] = (3, 300)
    from conftest import login
    flood = app.test_client()
    for _ in range(50):
        login(flood, "wrong")
    with app.app_context():
        rows = get_db().execute("SELECT action, COUNT(*) AS n FROM admin_log GROUP BY action").fetchall()
    counts = {r["action"]: r["n"] for r in rows}
    assert counts.get("login_rate_limited") == 1
    assert counts.get("login_failed") == 3   # only failures count towards the lockout


def test_new_event_does_not_inherit_a_deleted_events_log(admin, app):
    with app.app_context():
        old = ctf.create_event(get_db(), "old", "Old")
    admin.post(f"/admin/events/{old['id']}/join-code", data=CSRF)
    admin.post(f"/admin/events/{old['id']}/delete", data={**CSRF, "confirm": "old"})
    time.sleep(0.01)
    with app.app_context():
        new = ctf.create_event(get_db(), "fresh", "Fresh")
    assert new["id"] == old["id"], "SQLite reuses the id; that is the case under test"
    page = admin.get(f"/admin/events/{new['id']}/log").data.decode()
    assert "regenerate_join_code" not in page
    assert "regenerate_join_code" not in admin.get(f"/admin/events/{new['id']}/export/log.csv").data.decode()


@pytest.mark.parametrize("name", ["RED-TEAM", "Réd Team", "Red  Team!"])
def test_lookalike_team_names_are_refused(client, event, name):
    enroll(client, event, team="Red Team")
    resp = enroll(client, event, team=name)
    assert resp.status_code == 409, name
    assert resp.get_json()["error"]["code"] == "team_name_taken"


@pytest.mark.parametrize("name", ["Rеd Team", "Red Teaɱ", "Red Teɑm", "Ρed Team"])
def test_non_latin_lookalike_letters_are_not_allowed_at_all(client, event, name):
    resp = enroll(client, event, team=name)   # Cyrillic е, IPA ɱ / ɑ, Greek Ρ
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "invalid_team_name"


def test_distinct_names_are_fine(client, event):
    for name in ("Team 1", "Team 2", "Blue", "Grün"):
        assert enroll(client, event, team=name).status_code == 201, name


def test_logout_ends_a_copied_session(admin, app):
    with admin.session_transaction() as sess:
        copied = dict(sess)
    admin.post("/admin/logout", data=CSRF)
    thief = app.test_client()
    with thief.session_transaction() as sess:
        sess.update(copied)
    assert thief.get("/admin/").status_code == 302


def test_public_scoreboard_is_cached_not_limited(client, enrolled, event):
    """No per-address limit (it would let one participant blank the projector); a short cache instead."""
    for _ in range(200):
        assert client.get(f"/api/v1/events/{event['slug']}/scoreboard").status_code == 200
    assert client.get(f"/scoreboard/{event['slug']}").status_code == 200


# ---------- review round 5: shared NAT, and the rest ----------

def test_bad_tokens_from_a_shared_address_do_not_stall_valid_ones(client, enrolled, app):
    app.config["RATE_LIMIT_BAD_TOKEN"] = (3, 60)
    for i in range(10):
        client.post("/api/v1/heartbeat", headers=auth(f"garbage{i}"), json={})
    resp = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]), json={})
    assert resp.status_code == 200, "a valid token is never rate limited"


def test_failed_enrolments_do_not_use_up_the_new_team_quota(client, event, app):
    app.config["RATE_LIMIT_NEW_TEAMS"] = (2, 600)
    for i in range(5):
        assert enroll(client, event, team=f"Typo {i}", password="ab").status_code == 400
    assert enroll(client, event, team="Real One").status_code == 201
    assert enroll(client, event, team="Real Two").status_code == 201
    assert enroll(client, event, team="Real Three").status_code == 429


def test_login_link_gets_the_organiser_past_a_lockout(client, app):
    from conftest import login
    app.config["RATE_LIMIT_LOGIN"] = (2, 300)
    for _ in range(3):
        login(client, "wrong")                                  # a rival on the same address
    result = app.test_cli_runner().invoke(args=["login-link", "--minutes", "5"])
    path = "/admin/login/link/" + result.output.strip().rsplit("/", 1)[1]
    with client.session_transaction() as sess:
        sess["csrf"] = "c"
    assert client.post(path, data={"csrf": "c"}).status_code == 302
    assert client.get("/admin/").status_code == 200
    other = app.test_client()
    with other.session_transaction() as sess:
        sess["csrf"] = "c"
    other.post(path, data={"csrf": "c"})
    assert other.get("/admin/").status_code == 302, "single use"


def test_expired_login_link_is_refused(client, app):
    result = app.test_cli_runner().invoke(args=["login-link"])
    token = result.output.strip().rsplit("/", 1)[1]
    with app.app_context():
        get_db().execute("UPDATE login_links SET expires_at = 0")
    with client.session_transaction() as sess:
        sess["csrf"] = "c"
    client.post(f"/admin/login/link/{token}", data={"csrf": "c"})
    assert client.get("/admin/").status_code == 302


def test_anonymous_logout_does_not_write_the_log(client, app):
    for _ in range(20):
        with client.session_transaction() as sess:
            sess["csrf"] = "x"
        client.post("/admin/logout", data={"csrf": "x"})
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM admin_log").fetchone()[0] == 0


def test_huge_integer_client_time_is_not_a_500(client, enrolled):
    resp = client.post("/api/v1/solves", headers=auth(enrolled["token"]), json={
        "challenge_id": "physical_process", "flag": FLAGS["physical_process"], "solved_at": 10**400})
    assert resp.status_code == 200


def test_non_ascii_case_lookalike_is_refused(client, event):
    assert enroll(client, event, team="Ärger Team", password="pw-one-11").status_code == 201
    resp = enroll(client, event, team="ärger Team", password="pw-two-22")
    assert resp.status_code == 409
    # Same Ä, only ASCII letters in another case: SQLite NOCASE says it is the
    # same team, so this is a teammate joining, not an impostor.
    assert enroll(client, event, team="ÄRGER TEAM", password="pw-one-11").status_code == 201


def test_x_forwarded_host_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("MGMT_TRUST_PROXY", "1")
    monkeypatch.setenv("MGMT_FORWARDED_ALLOW_IPS", "10.0.0.0/8")
    app = create_app({"DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / "db.sqlite"),
                      "SECRET_KEY": "k", "ADMIN_PASSWORD": "p" * 16})

    @app.get("/__host")
    def _host():
        from flask import request
        return request.host

    host = app.test_client().get("/__host", headers={"Host": "ctf.local", "X-Forwarded-Host": "evil.example"},
                                 environ_base={"REMOTE_ADDR": "10.1.1.1"}).data.decode()
    assert host == "ctf.local"


def test_event_settings_route(admin, event, app):
    admin.post(f"/admin/events/{event['id']}/settings", data={**CSRF, "name": "Renamed"})
    with app.app_context():
        row = ctf.get_event(get_db(), event["id"])
    assert row["name"] == "Renamed"
    assert row["scoreboard_public"] == 0 and row["allow_team_registration"] == 0


def test_submissions_csv(admin, client, enrolled, event):
    client.post("/api/v1/solves", headers=auth(enrolled["token"]),
                json={"challenge_id": "physical_process", "flag": "CybICS(guess)"})
    text = admin.get(f"/admin/events/{event['id']}/export/submissions.csv").data.decode()
    assert text.splitlines()[0] == "received_at,team,challenge,result,address,instance_id"
    assert "invalid_flag" in text and "CybICS(guess)" not in text


def test_backup_into_a_directory_with_rotation(app, tmp_path):
    target = tmp_path / "backups"
    target.mkdir()
    runner = app.test_cli_runner()
    for name in ("cybics-mgmt-20260101-000000.sqlite", "cybics-mgmt-20260102-000000.sqlite"):
        (target / name).write_text("old")
    result = runner.invoke(args=["backup", str(target), "--keep", "2"])
    assert result.exit_code == 0, result.output
    files = sorted(p.name for p in target.iterdir())
    assert len(files) == 2 and "cybics-mgmt-20260101-000000.sqlite" not in files



# ---------- review round 6: shared addresses, depth, finish ----------

def test_wrong_team_passwords_are_audited_but_never_lock_the_team(client, event, admin):
    enroll(client, event, team="Blue", password="right-pw-1")
    for _ in range(30):      # a rival on the same address
        assert enroll(client, event, team="Blue", password="nope-nope").status_code == 403
    assert enroll(client, event, team="Blue", password="right-pw-1").status_code == 201
    assert b"wrong team password" in admin.get(f"/admin/events/{event['id']}/solves").data


def test_enrol_guard_counts_only_wrong_passwords_and_can_be_cleared(client, event, app, admin):
    app.config["RATE_LIMIT_JOIN"] = (5, 60)
    enroll(client, event, team="Fine Team")
    for _ in range(20):        # garbage costs nothing and must not lock the address
        client.post("/api/v1/enroll", data="x", content_type="application/json")
        client.post("/api/v1/enroll", json={"join_code": "WRONG000"})
    assert enroll(client, event, team="Fine Team").status_code == 201
    for _ in range(5):
        enroll(client, event, team="Fine Team", password="wrong-guess-1")
    assert enroll(client, event, team="Fine Team").status_code == 429
    assert "wrong team passwords" in admin.get("/admin/").data.decode()
    admin.post("/admin/lockouts/clear", data=CSRF)
    assert enroll(client, event, team="Fine Team").status_code == 201


def test_new_teams_need_long_passwords_existing_ones_keep_working(client, event, app):
    assert enroll(client, event, team="Short", password="short").status_code == 400
    with app.app_context():
        from cybics_mgmt.security import hash_password
        get_db().execute("INSERT INTO teams (event_id, name, password_hash, created_at) VALUES (?, ?, ?, 0)",
                         (event["id"], "Legacy", hash_password("abcd")))
    assert enroll(client, event, team="Legacy", password="abcd").status_code == 201


def test_deeply_nested_status_never_breaks_the_instances_page(admin, client, enrolled, event, app):
    deep = {"services": {}}
    node = deep["services"]
    for _ in range(900):
        node["x"] = {}
        node = node["x"]
    resp = client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]), json={"status": deep})
    assert resp.status_code in (200, 400)
    with app.app_context():   # also a row stored before the depth check existed
        get_db().execute("UPDATE devices SET status_json = ?", ("[" * 3000 + "]" * 3000,))
    assert admin.get(f"/admin/events/{event['id']}/instances").status_code == 200


def test_ordinary_status_is_kept(client, enrolled, app):
    status = {"services": {"openplc": True}, "plant": {"tank": {"pressure": 3.2}}}
    client.post("/api/v1/heartbeat", headers=auth(enrolled["token"]), json={"status": status})
    with app.app_context():
        stored = json.loads(get_db().execute("SELECT status_json FROM devices").fetchone()[0])
    assert stored == status



# ---------- review round 7: enrolment cost, redirects, catalog ----------

def test_hashing_slot_timeout_answers_busy(client, event, monkeypatch):
    import cybics_mgmt.security as security
    monkeypatch.setattr(security, "HASH_WAIT", 0.01)
    held = [security._hashing.acquire() for _ in range(2)]   # both slots busy
    try:
        resp = enroll(client, event, team="Waiting Team")
    finally:
        for _ in held:
            security._hashing.release()
    assert resp.status_code == 503
    assert resp.get_json()["error"]["code"] == "busy"


def test_instances_per_team_are_capped(client, event, monkeypatch):
    monkeypatch.setattr(ctf, "MAX_INSTANCES_PER_TEAM", 3)
    codes = [enroll(client, event, team="Cap Team").status_code for _ in range(4)]
    assert codes == [201, 201, 201, 409]
    assert enroll(client, event, team="Cap Team", kind="physical", device_uid="00aa00bb00cc").status_code == 409
    other = enroll(client, event, team="Board Team", kind="physical", device_uid="00aa00bb00dd")
    assert other.status_code == 201


def test_disqualified_team_costs_no_hashing(client, enrolled, app, monkeypatch):
    with app.app_context():
        ctf.set_team_banned(get_db(), enrolled["team"]["id"], True)
    import cybics_mgmt.security as security

    def no_hashing(*_a):
        raise AssertionError("hashed for a banned team")
    monkeypatch.setattr(security, "_with_hashing_slot", no_hashing)
    with app.app_context():
        event = {"join_code": get_db().execute("SELECT join_code FROM events").fetchone()[0]}
    resp = enroll(client, event, team="Red Team", password="secret-12")
    assert resp.status_code == 403


@pytest.mark.parametrize("password", ["password", "PASSWORD", "12345678", "aaaaaaaa", "Weak Team"])
def test_weak_new_team_passwords_are_refused(client, event, password):
    resp = enroll(client, event, team="Weak Team", password=password)
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] in ("weak_team_password", "invalid_team_password")


@pytest.mark.parametrize("target", ["/%09/evil.example/", "//evil.example/", "/\\evil.example",
                                   "https://evil.example/", "/admin/../..//evil.example", "/elsewhere"])
def test_login_never_redirects_off_site(client, target):
    from conftest import ADMIN_PASSWORD
    with client.session_transaction() as sess:
        sess["csrf"] = "c"
    resp = client.post(f"/admin/login?next={target}", data={"password": ADMIN_PASSWORD, "csrf": "c"})
    location = resp.headers["Location"]
    assert location.startswith("/admin/") and not location.startswith("//"), location
    assert "evil" not in location


def test_login_keeps_a_local_next(client):
    from conftest import ADMIN_PASSWORD
    with client.session_transaction() as sess:
        sess["csrf"] = "c"
    resp = client.post("/admin/login?next=/admin/events/1/teams", data={"password": ADMIN_PASSWORD, "csrf": "c"})
    assert resp.headers["Location"] == "/admin/events/1/teams"


def test_same_state_change_keeps_timestamps(event, app):
    with app.app_context():
        db = get_db()
        ctf.set_event_state(db, event["id"], "finished")
        first = ctf.get_event(db, event["id"])["finished_at"]
        time.sleep(0.01)
        ctf.set_event_state(db, event["id"], "finished")
        assert ctf.get_event(db, event["id"])["finished_at"] == first


def test_catalog_version_covers_flags(event, app):
    with app.app_context():
        db = get_db()
        before = ctf.catalog_version(db, event["id"])
        changed = json.loads(json.dumps(CATALOG))
        changed["categories"]["basic_understanding"]["challenges"][0]["flag"] = "CybICS(other)"
        ctf.import_catalog(db, event["id"], json.dumps(changed))
        assert ctf.catalog_version(db, event["id"]) != before


# ---------- review round 8: growth, races, config ----------

def test_instances_page_hides_revoked_by_default(admin, client, event, app):
    first = enroll(client, event, team="Loop Team").get_json()
    client.delete("/api/v1/ctf/join", headers=auth(first["token"]))
    enroll(client, event, team="Loop Team")
    page = admin.get(f"/admin/events/{event['id']}/instances").data.decode()
    assert "1 device(s) that left are hidden" in page and ">left<" not in page
    assert ">left<" in admin.get(f"/admin/events/{event['id']}/instances?all=1").data.decode()


def test_enrol_and_leave_loops_are_capped_per_team(client, event, monkeypatch):
    monkeypatch.setattr(ctf, "MAX_NEW_INSTANCES_PER_HOUR", 3)
    codes = []
    for _ in range(4):
        resp = enroll(client, event, team="Loop Team")
        codes.append(resp.status_code)
        if resp.status_code == 201:
            client.delete("/api/v1/instance", headers=auth(resp.get_json()["token"]))
    assert codes == [201, 201, 201, 429]


def test_team_deleted_mid_enrolment_is_not_recreated_silently(client, event, app, monkeypatch):
    enroll(client, event, team="Gone Team", password="gone-pass-1")
    import cybics_mgmt.ctf.logic as ctf_module
    real_verify = ctf_module.verify_password

    def verify_then_delete(*args):
        ok = real_verify(*args)
        with app.app_context():
            get_db().execute("DELETE FROM teams WHERE name = 'Gone Team'")
        return ok
    monkeypatch.setattr(ctf_module, "verify_password", verify_then_delete)
    resp = enroll(client, event, team="Gone Team", password="gone-pass-1")
    assert resp.status_code == 503 and resp.get_json()["error"]["code"] == "busy"
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM teams WHERE name = 'Gone Team'").fetchone()[0] == 0


def test_short_secret_key_from_env_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("MGMT_SECRET_KEY", "short")
    with pytest.raises(RuntimeError):
        create_app({"DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / "db.sqlite"),
                    "ADMIN_PASSWORD": "p" * 16})


def test_admin_page_indexes_exist(app):
    with app.app_context():
        names = {r[0] for r in get_db().execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert {"idx_devices_uid", "idx_instances_team_live", "idx_submissions_team"} <= names



# ---------- review round 9 ----------

def test_bulk_team_actions(admin, client, event, app):
    ids = [enroll(client, event, team=f"Junk {i}").get_json()["team"]["id"] for i in range(3)]
    keep = enroll(client, event, team="Real Team").get_json()["team"]["id"]
    admin.post(f"/admin/events/{event['id']}/teams/bulk",
               data={**CSRF, "action": "delete", "team_id": [str(i) for i in ids[:2]]})
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM teams").fetchone()[0] == 4, "DELETE not typed"
    admin.post(f"/admin/events/{event['id']}/teams/bulk",
               data={**CSRF, "action": "delete", "confirm": "DELETE", "team_id": [str(i) for i in ids[:2]]})
    admin.post(f"/admin/events/{event['id']}/teams/bulk",
               data={**CSRF, "action": "ban", "team_id": [str(ids[2])]})
    with app.app_context():
        rows = {r["name"]: r["banned"] for r in get_db().execute("SELECT name, banned FROM teams")}
    assert rows == {"Junk 2": 1, "Real Team": 0}
    assert keep


def test_login_link_page_does_not_use_up_the_link(client, app):
    result = app.test_cli_runner().invoke(args=["login-link"])
    path = "/admin/login/link/" + result.output.strip().rsplit("/", 1)[1]
    assert client.get(path).status_code == 200            # a link preview
    assert client.get(path).status_code == 200
    with client.session_transaction() as sess:
        sess["csrf"] = "c"
    assert client.post(path, data={"csrf": "c"}).status_code == 302
    assert client.get("/admin/").status_code == 200


def test_login_link_uses_public_url(app):
    app.config["PUBLIC_URL"] = "https://ctf.example.org"
    result = app.test_cli_runner().invoke(args=["login-link"])
    assert "https://ctf.example.org/admin/login/link/" in result.output


def test_weak_admin_password_needs_explicit_opt_in(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("MGMT_ADMIN_PASSWORD", "admin")
    monkeypatch.setenv("MGMT_ALLOW_WEAK_ADMIN_PASSWORD", "1")
    with caplog.at_level("WARNING", logger="cybics_mgmt"):
        app = create_app({"DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / "db.sqlite")})
    assert app.config["ADMIN_PASSWORD"] == "admin"
    assert any("Never run an event like this" in r.getMessage() for r in caplog.records)


# ---------- first blood bonus ----------

def test_first_blood_bonus_is_off_by_default(client, event):
    a = enroll(client, event, team="Alpha").get_json()
    resp = solve(client, a["token"], "physical_process").get_json()
    assert resp == {"result": "accepted", "points": 100, "bonus": 0}


def test_first_blood_bonus_scores_and_moves_with_moderation(admin, client, event, app):
    admin.post(f"/admin/events/{event['id']}/settings",
               data={**CSRF, "name": "Test Event", "scoreboard_public": "on",
                     "allow_team_registration": "on", "first_blood_bonus": "10"})
    a = enroll(client, event, team="Alpha").get_json()
    b = enroll(client, event, team="Bravo").get_json()
    first = solve(client, a["token"], "physical_process").get_json()
    assert first == {"result": "accepted", "points": 100, "bonus": 10}
    assert solve(client, b["token"], "physical_process").get_json()["bonus"] == 0
    board = client.get(f"/api/v1/events/{event['slug']}/scoreboard").get_json()
    assert {e["name"]: e["score"] for e in board["scoreboard"]} == {"Alpha": 110, "Bravo": 100}
    assert board["event"]["first_blood_bonus"] == 10
    assert [(s["team"], s["bonus"]) for s in board["recent_solves"]] == [("Bravo", 0), ("Alpha", 10)]

    with app.app_context():   # Alpha's solve voided: the bonus moves to Bravo
        sid = get_db().execute("""SELECT s.id FROM solves s JOIN teams t ON t.id = s.team_id
                                  WHERE t.name = 'Alpha'""").fetchone()["id"]
    admin.post(f"/admin/events/{event['id']}/solves/{sid}/void", data=CSRF)
    board = client.get(f"/api/v1/events/{event['slug']}/scoreboard").get_json()
    assert {e["name"]: e["score"] for e in board["scoreboard"]} == {"Bravo": 110, "Alpha": 0}


def test_first_blood_bonus_is_validated(admin, event, app):
    resp = admin.post(f"/admin/events/{event['id']}/settings",
                      data={**CSRF, "name": "Test Event", "first_blood_bonus": "250"}, follow_redirects=True)
    assert b"between 0 and 100" in resp.data
    with app.app_context():
        assert ctf.get_event(get_db(), event["id"])["first_blood_bonus"] == 0


# ---------- CodeQL findings ----------

@pytest.mark.parametrize("referrer", ["https://evil.example/phish", "//evil.example/x",
                                      "http://localhost/admin/../../evil", "",
                                      "/admin/?_external=1&_scheme=https"])
def test_error_redirects_never_follow_a_foreign_referrer(admin, event, referrer):
    resp = admin.post(f"/admin/events/{event['id']}/challenges/1", data={**CSRF, "points": "x"},
                      headers={"Referer": referrer})
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/admin/"


def test_error_redirect_returns_to_the_admin_page_it_came_from(admin, event):
    resp = admin.post(f"/admin/events/{event['id']}/challenges/1", data={**CSRF, "points": "x"},
                      headers={"Referer": f"http://localhost/admin/events/{event['id']}/challenges"})
    assert resp.headers["Location"] == f"/admin/events/{event['id']}/challenges"


def test_error_redirect_keeps_the_page_query(admin, event):
    resp = admin.post(f"/admin/events/{event['id']}/challenges/1", data={**CSRF, "points": "x"},
                      headers={"Referer": f"http://localhost/admin/events/{event['id']}/instances?all=1"})
    assert resp.headers["Location"] == f"/admin/events/{event['id']}/instances?all=1"


def test_query_keys_cannot_clash_with_url_building(client):
    from conftest import ADMIN_PASSWORD
    with client.session_transaction() as sess:
        sess["csrf"] = "c"
    resp = client.post("/admin/login?next=/admin/%3Fendpoint%3D1%26_external%3D1",
                       data={"password": ADMIN_PASSWORD, "csrf": "c"})
    assert resp.status_code == 302
    assert resp.headers["Location"].startswith("/admin/"), resp.headers["Location"]


def test_a_non_ascii_csrf_token_is_a_400(client):
    with client.session_transaction() as sess:
        sess["csrf"] = "known"
    assert client.post("/admin/login", data={"password": "x", "csrf": "\u00e9"}).status_code == 400


def test_bulk_ignores_non_ascii_digits(admin, event):
    resp = admin.post(f"/admin/events/{event['id']}/teams/bulk",
                      data={**CSRF, "action": "ban", "team_id": ["\u00b2", "\u0663"]})
    assert resp.status_code == 302


def test_csv_leaves_empty_cells_empty(admin, event):
    admin.post(f"/admin/events/{event['id']}/announcements", data={**CSRF, "message": "Hello"})
    text = admin.get(f"/admin/events/{event['id']}/export/log.csv").data.decode()
    assert ",'\r\n" not in text and ",'\n" not in text
