"""The admin password set at the first visit, changing it, and the Raspberry Pi's pi password."""
import json
import os

import pytest

from conftest import ADMIN_PASSWORD, SIGNING_KEY
from cybics_mgmt import create_app
from cybics_mgmt.db import get_db
from cybics_mgmt.security import limiter

CSRF = {"csrf": "csrf-test"}


@pytest.fixture
def fresh(tmp_path, monkeypatch):
    """A server without MGMT_ADMIN_PASSWORD: the first visit sets the admin password."""
    monkeypatch.delenv("MGMT_ADMIN_PASSWORD", raising=False)
    limiter.reset()
    host_dir = tmp_path / "host"
    host_dir.mkdir()
    app = create_app({"TESTING": True, "DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / "db.sqlite"),
                      "SECRET_KEY": "test", "FLEET_SIGNING_KEY": SIGNING_KEY, "HOST_DIR": str(host_dir)})
    yield app
    limiter.reset()


def browser(app):
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["csrf"] = "csrf-test"
    return client


def set_up(client, password="first-admin-pw", confirm=None):
    resp = client.post("/admin/setup", data={**CSRF, "password": password, "confirm": confirm or password},
                       follow_redirects=True)
    # Logging in starts a fresh session with a new CSRF token, as a browser
    # would receive with the next page; the tests keep using the known one.
    with client.session_transaction() as sess:
        sess["csrf"] = "csrf-test"
    return resp


def test_the_first_visit_sets_the_admin_password(fresh):
    client = browser(fresh)
    assert client.get("/admin/").headers["Location"].endswith("/admin/login?next=/admin/")
    assert client.get("/admin/login").headers["Location"].endswith("/admin/setup")
    assert b"Set the admin password" in client.get("/admin/setup").data
    page = set_up(client)
    assert b"Admin password set" in page.data and client.get("/admin/").status_code == 200
    with fresh.app_context():
        stored = get_db().execute("SELECT password_hash FROM admin_credentials").fetchone()[0]
    assert "first-admin-pw" not in stored                        # a hash only
    # Afterwards the setup page is gone and the password logs in.
    other = browser(fresh)
    assert other.get("/admin/setup").headers["Location"].endswith("/admin/login")
    assert set_up(other, "takeover-pw-1").request.path == "/admin/login"
    resp = other.post("/admin/login", data={**CSRF, "password": "first-admin-pw"})
    assert resp.status_code == 302 and other.get("/admin/").status_code == 200
    assert b"admin_password_set" in other.get("/admin/").data   # on the organiser log list


@pytest.mark.parametrize("password, confirm, message", [
    ("short", "short", b"at least 8 characters"),
    ("first-admin-pw", "other-admin-pw", b"two passwords differ"),
    ("password", "password", b"too easy to guess"),
    ("aaaaaaaaaa", "aaaaaaaaaa", b"too easy to guess"),
    ("x" * 257, "x" * 257, b"at most 256"),
])
def test_weak_setup_passwords_are_refused(fresh, password, confirm, message):
    client = browser(fresh)
    page = set_up(client, password, confirm)
    assert message in page.data
    with fresh.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM admin_credentials").fetchone()[0] == 0


def test_the_first_one_to_set_it_wins(fresh):
    from cybics_mgmt.security import set_admin_password
    with fresh.test_request_context():
        assert set_admin_password("first-admin-pw", first=True) is True
        assert set_admin_password("second-admin-pw", first=True) is False


def test_an_admin_password_from_the_environment_skips_the_setup(app, client):
    assert client.get("/admin/setup").headers["Location"].endswith("/admin/login")
    assert client.get("/admin/login").status_code == 200


def test_changing_the_admin_password_ends_other_sessions(fresh):
    first, second = browser(fresh), browser(fresh)
    set_up(first)
    second.post("/admin/login", data={**CSRF, "password": "first-admin-pw"})
    with second.session_transaction() as sess:
        sess["csrf"] = "csrf-test"
    assert second.get("/admin/").status_code == 200
    page = first.post("/admin/password", data={**CSRF, "target": "admin", "current": "wrong-pw-123",
                                               "password": "next-admin-pw", "confirm": "next-admin-pw"},
                      follow_redirects=True)
    assert b"current password is wrong" in page.data
    page = first.post("/admin/password", data={**CSRF, "target": "admin", "current": "first-admin-pw",
                                               "password": "next-admin-pw", "confirm": "next-admin-pw"},
                      follow_redirects=True)
    assert b"Every other session has ended" in page.data
    with first.session_transaction() as sess:
        sess["csrf"] = "csrf-test"
    assert first.get("/admin/").status_code == 200              # the one who changed it stays in
    assert second.get("/admin/").status_code == 302             # everyone else is out
    assert second.post("/admin/login", data={**CSRF, "password": "next-admin-pw"}).status_code == 302


def test_an_environment_password_cannot_be_changed_in_the_browser(admin, app):
    page = admin.get("/admin/password").data
    assert b"MGMT_ADMIN_PASSWORD" in page and b'name="current"' not in page
    admin.post("/admin/password", data={**CSRF, "target": "admin", "current": ADMIN_PASSWORD,
                                        "password": "next-admin-pw", "confirm": "next-admin-pw"})
    assert app.config["ADMIN_PASSWORD"] == ADMIN_PASSWORD


def test_reset_from_the_command_line(fresh):
    client = browser(fresh)
    set_up(client)
    result = fresh.test_cli_runner().invoke(args=["reset-admin-password"])
    assert result.exit_code == 0 and "next visit" in result.output
    assert client.get("/admin/").status_code == 302              # the session ended with it
    assert client.get("/admin/login").headers["Location"].endswith("/admin/setup")


def test_reset_refuses_an_environment_password(app):
    result = app.test_cli_runner().invoke(args=["reset-admin-password"])
    assert result.exit_code != 0 and "MGMT_ADMIN_PASSWORD" in result.output


# ---------- the Raspberry Pi's pi password ----------

def logged_in(fresh):
    client = browser(fresh)
    set_up(client)
    return client


def test_the_pi_password_goes_to_the_host_directory(fresh):
    client = logged_in(fresh)
    host_dir = fresh.config["HOST_DIR"]
    assert b"Raspberry Pi login" in client.get("/admin/password").data
    page = client.post("/admin/password", data={**CSRF, "target": "pi", "password": "new-pi-pass",
                                                "confirm": "new-pi-pass"}, follow_redirects=True)
    assert b"Sent to the Raspberry Pi" in page.data and b"being applied" in page.data
    request = os.path.join(host_dir, "pi-password.json")
    assert os.stat(request).st_mode & 0o777 == 0o600
    with open(request) as f:
        assert json.load(f) == {"user": "pi", "password": "new-pi-pass"}
    with fresh.app_context():
        log = [r[0] for r in get_db().execute("SELECT action FROM admin_log")]
    assert "pi_password_requested" in log


@pytest.mark.parametrize("password, confirm, message", [
    ("short", "short", b"8 to 128"),
    ("new-pi-pass", "other-pass", b"two passwords differ"),
    ("raspberry", "raspberry", b"too easy to guess"),
    ("bad\npassword", "bad\npassword", b"control characters"),
])
def test_bad_pi_passwords_are_refused(fresh, password, confirm, message):
    client = logged_in(fresh)
    page = client.post("/admin/password", data={**CSRF, "target": "pi", "password": password,
                                                "confirm": confirm}, follow_redirects=True)
    assert message in page.data
    assert not os.path.exists(os.path.join(fresh.config["HOST_DIR"], "pi-password.json"))


def test_the_host_status_is_shown_and_warned_about(fresh):
    client = logged_in(fresh)
    with open(os.path.join(fresh.config["HOST_DIR"], "status.json"), "w") as f:
        json.dump({"pi_default_password": True, "last": {"state": "failed", "detail": "chpasswd: boom",
                                                        "time": 1.0}}, f)
    events = client.get("/admin/").data
    assert b"still has the default login" in events
    page = client.get("/admin/password").data
    assert b"chpasswd: boom" in page and b">failed<" in page
    with open(os.path.join(fresh.config["HOST_DIR"], "status.json"), "w") as f:
        f.write("not json")
    assert b"still has the default login" not in client.get("/admin/").data


def test_without_a_host_directory_there_is_no_pi_section(admin):
    page = admin.get("/admin/password").data
    assert b"Raspberry Pi login" not in page
    admin.post("/admin/password", data={**CSRF, "target": "pi", "password": "new-pi-pass",
                                        "confirm": "new-pi-pass"})
