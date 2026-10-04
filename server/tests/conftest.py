import json
import os
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "client"))

from cybics_mgmt import create_app  # noqa: E402
from cybics_mgmt.ctf import logic as ctf  # noqa: E402
from cybics_mgmt.db import get_db  # noqa: E402
from cybics_mgmt.security import limiter  # noqa: E402

ADMIN_PASSWORD = "test-admin-password"

# Shaped like CybICS' software/landing/ctf_config.json, with made-up flags.
CATALOG = {
    "title": "CybICS CTF Training",
    "categories": {
        "basic_understanding": {
            "name": "Basic Understanding",
            "challenges": [
                {"id": "physical_process", "title": "Understanding the Physical Process",
                 "points": 100, "tag": "analysis", "flag": "CybICS(test_one)", "hint": "",
                 "training_content": "training/physical_process/README.md"},
                {"id": "plc_programming", "title": "PLC Programming", "points": 150,
                 "type": "verify", "verify_module": "check_plc_program",
                 "flag": "CybICS(test_two)", "hint": "", "training_content": ""},
            ],
        },
        "defense": {
            "name": "Defense",
            "challenges": [
                {"id": "defense_firewall", "title": "Modbus Firewall Rules", "points": 250,
                 "type": "defense", "verify_module": "check_firewall",
                 "flag": "CybICS(test_three)", "hint": "", "training_content": ""},
            ],
        },
    },
}
FLAGS = {"physical_process": "CybICS(test_one)", "plc_programming": "CybICS(test_two)",
         "defense_firewall": "CybICS(test_three)"}


# One fleet signing key for the whole run: generating RSA-3072 takes a while.
SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=3072).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


@pytest.fixture
def app(tmp_path):
    limiter.reset()
    app = create_app({"TESTING": True, "DATA_DIR": str(tmp_path),
                      "DATABASE": str(tmp_path / "test.sqlite"),
                      "SECRET_KEY": "test", "ADMIN_PASSWORD": ADMIN_PASSWORD,
                      "FLEET_SIGNING_KEY": SIGNING_KEY})
    yield app
    limiter.reset()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def event(app):
    """A running event with the test catalog imported."""
    with app.app_context():
        db = get_db()
        event = ctf.create_event(db, "test-event", "Test Event")
        ctf.import_catalog(db, event["id"], json.dumps(CATALOG))
        ctf.set_event_state(db, event["id"], "running")
        return dict(ctf.get_event(db, event["id"]))


class Joined:
    """What enroll() returns: the join's answer, with the device's token and id added."""

    def __init__(self, resp, extra):
        self.status_code = resp.status_code
        self.data = resp.data
        self._json = {**(resp.get_json(silent=True) or {}), **extra}

    def get_json(self):
        return self._json


def enroll_device(client, code, **instance):
    info = {"kind": "virtual", "hostname": "laptop", "cybics_version": "1.2.3", "mode": "full"}
    info.update(instance)
    return client.post("/api/v1/enroll", json={"code": code, "device": info})


def join(client, token, event, team="Red Team", password="secret-12"):
    return client.post("/api/v1/ctf/join", headers=auth(token), json={
        "join_code": event["join_code"], "team_name": team, "team_password": password})


def enroll(client, event, team="Red Team", password="secret-12", token=None, **instance):
    """A new device (enrolled with the event's join code) that joins `team`; `token` reuses a device."""
    device_id = None
    if token is None:
        device = enroll_device(client, event["join_code"], **instance)
        if device.status_code != 201:
            return device
        token, device_id = device.get_json()["token"], device.get_json()["device_id"]
    return Joined(join(client, token, event, team, password), {"token": token, "device_id": device_id})


@pytest.fixture
def enrolled(client, event):
    resp = enroll(client, event)
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()


def auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin(client):
    """A client logged in through the real login form, with a known CSRF token."""
    login(client)
    with client.session_transaction() as sess:
        sess["csrf"] = "csrf-test"
    return client


def login(client, password=ADMIN_PASSWORD):
    with client.session_transaction() as sess:
        sess["csrf"] = "login-csrf"
    return client.post("/admin/login", data={"password": password, "csrf": "login-csrf"})
