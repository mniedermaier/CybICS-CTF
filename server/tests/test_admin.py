"""Organiser UI: login, CSRF, and the actions that change an event."""
import io
import json

from conftest import ADMIN_PASSWORD, CATALOG, FLAGS, auth, enroll, login
from cybics_ctf import ctf
from cybics_ctf.db import get_db

CSRF = {"csrf": "csrf-test"}


def test_admin_requires_login(client):
    resp = client.get("/admin/")
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_login_with_password(client):
    assert login(client, "wrong").status_code == 200
    resp = login(client)
    assert resp.status_code == 302
    assert client.get("/admin/").status_code == 200


def test_login_does_not_redirect_off_site(client):
    with client.session_transaction() as sess:
        sess["csrf"] = "c"
    resp = client.post("/admin/login?next=//evil.example/", data={"password": ADMIN_PASSWORD, "csrf": "c"})
    assert resp.headers["Location"].endswith("/admin/")


def test_login_is_rate_limited(client, app):
    app.config["RATE_LIMIT_LOGIN"] = (2, 300)
    for _ in range(2):
        login(client, "wrong")
    resp = login(client)
    assert b"Too many failed logins" in resp.data


def test_post_without_csrf_is_rejected(admin):
    assert admin.post("/admin/events", data={"slug": "x", "name": "X"}).status_code == 400


def test_create_event_and_import_catalog(admin, app):
    resp = admin.post("/admin/events", data={**CSRF, "slug": "workshop", "name": "Workshop"})
    assert resp.status_code == 302
    with app.app_context():
        event = ctf.get_event_by_slug(get_db(), "workshop")
    upload = {**CSRF, "catalog": (io.BytesIO(json.dumps(CATALOG).encode()), "ctf_config.json")}
    resp = admin.post(f"/admin/events/{event['id']}/catalog", data=upload,
                      content_type="multipart/form-data")
    assert resp.status_code == 302
    page = admin.get(f"/admin/events/{event['id']}/challenges").data.decode()
    assert "physical_process" in page
    for flag in FLAGS.values():
        assert flag not in page, "the admin UI must not show flags"


def test_every_admin_page_renders(admin, event, client):
    resp = enroll(client, event)
    token = resp.get_json()["token"]
    client.post("/api/v1/heartbeat", headers=auth(token), json={"status": {"services": {"a": True}}})
    client.post("/api/v1/solves", headers=auth(token),
                json={"challenge_id": "physical_process", "flag": FLAGS["physical_process"]})
    client.post("/api/v1/solves", headers=auth(token),
                json={"challenge_id": "physical_process", "flag": "CybICS(guess)"})
    for page in ("", "/challenges", "/teams", "/instances", "/solves"):
        resp = admin.get(f"/admin/events/{event['id']}{page}")
        assert resp.status_code == 200, page
    page = admin.get(f"/admin/events/{event['id']}/solves").data
    assert b"Nothing suspicious so far" not in page
    assert b"CybICS(guess)" not in page, "submitted flags must not be shown"


def test_state_change(admin, event, app):
    admin.post(f"/admin/events/{event['id']}/state", data={**CSRF, "state": "finished"})
    with app.app_context():
        row = ctf.get_event(get_db(), event["id"])
    assert row["state"] == "finished" and row["finished_at"]


def test_ban_team(admin, event, client, app):
    team_id = enroll(client, event).get_json()["team"]["id"]
    admin.post(f"/admin/events/{event['id']}/teams/{team_id}/ban", data=CSRF)
    with app.app_context():
        assert ctf.scoreboard(get_db(), event["id"]) == []


def test_actions_are_scoped_to_the_event(admin, event, client, app):
    team_id = enroll(client, event).get_json()["team"]["id"]
    with app.app_context():
        other = ctf.create_event(get_db(), "other", "Other")
    resp = admin.post(f"/admin/events/{other['id']}/teams/{team_id}/delete", data=CSRF)
    assert resp.status_code == 404


def test_delete_event_needs_slug_confirmation(admin, event, app):
    admin.post(f"/admin/events/{event['id']}/delete", data={**CSRF, "confirm": "wrong"})
    with app.app_context():
        assert ctf.get_event(get_db(), event["id"]) is not None
    admin.post(f"/admin/events/{event['id']}/delete", data={**CSRF, "confirm": event["slug"]})
    with app.app_context():
        assert ctf.get_event(get_db(), event["id"]) is None


def test_public_pages(client, event):
    assert client.get("/").status_code == 200
    resp = client.get(f"/scoreboard/{event['slug']}")
    assert resp.status_code == 200
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
    assert client.get("/healthz").get_json() == {"status": "ok"}


def test_cli(app, tmp_path):
    path = tmp_path / "ctf_config.json"
    path.write_text(json.dumps(CATALOG))
    runner = app.test_cli_runner()
    result = runner.invoke(args=["create-event", "cli-event", "CLI Event"])
    assert "join code" in result.output
    result = runner.invoke(args=["import-catalog", "cli-event", str(path)])
    assert "Imported 3 challenges" in result.output
    result = runner.invoke(args=["set-state", "cli-event", "running"])
    assert result.exit_code == 0
    assert "running" in runner.invoke(args=["list-events"]).output
