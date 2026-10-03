"""Fleet jobs on the server: signed, sequenced, allow-listed actions (docs/MGMT_DESIGN.md, phase 2)."""
import gzip
import json
import os
import time

import pytest

from conftest import ADMIN_PASSWORD, auth, enroll
from cybics_mgmt import create_app
from cybics_mgmt.db import get_db
from cybics_mgmt.fleet import jobs, signing
from cybics_mgmt.fleet import logic as fleet
from cybics_mgmt_client import job_message, key_fingerprint, verify_signature

CSRF = {"csrf": "csrf-test"}
LAPTOP = {"kind": "virtual", "hostname": "laptop-7", "cybics_version": "1.2.4"}
ALL = list(jobs.ACTIONS)


def enrol_device(client, app, allowed=ALL, label="Board 7"):
    """A device with fleet support that allows `allowed` and pinned the server's key."""
    with app.app_context():
        code = fleet.create_code(get_db(), "", None)["code"]
    data = client.post("/api/v1/fleet/enroll", json={"code": code, "device": LAPTOP, "label": label}).get_json()
    key = data["signing_key"]
    data["fingerprint"] = key_fingerprint(int(key["n"], 16), key["e"])
    beat(client, data, allowed=allowed)
    return data


def beat(client, device, allowed=ALL, results=(), fingerprint=None):
    resp = client.post("/api/v1/fleet/heartbeat", headers=auth(device["token"]), json={
        "status": {"services": {"openplc": True}},
        "management": {"allowed": list(allowed), "key_fingerprint": fingerprint or device["fingerprint"],
                       "client": "1"},
        "job_results": list(results)})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()


def send(admin, device, action, **params):
    return admin.post(f"/admin/fleet/devices/{device['device_id']}/jobs",
                      data={**CSRF, "action": action, **params}, follow_redirects=True)


def job_rows(app, device):
    with app.app_context():
        return [dict(r) for r in get_db().execute("SELECT * FROM jobs WHERE device_id = ? ORDER BY seq",
                                                  (device["device_id"],))]


# ---------- the key ----------

def test_enrolment_hands_out_the_signing_key(client, app):
    device = enrol_device(client, app)
    key = device["signing_key"]
    assert key["e"] == 65537 and int(key["n"], 16).bit_length() >= 3072
    assert key["fingerprint"] == device["fingerprint"]
    with app.app_context():
        assert signing.get_signer(app).fingerprint == device["fingerprint"]


def test_the_key_is_created_once_on_first_use_and_kept(tmp_path):
    config = {"DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / "db.sqlite"), "SECRET_KEY": "test",
              "ADMIN_PASSWORD": ADMIN_PASSWORD}
    first = create_app(config)
    assert not (tmp_path / signing.KEY_FILE).exists()           # not at start
    fingerprint = signing.get_signer(first).fingerprint
    assert (tmp_path / signing.KEY_FILE).stat().st_mode & 0o777 == 0o600
    assert signing.get_signer(create_app(config)).fingerprint == fingerprint


def test_an_unreadable_key_is_never_replaced(tmp_path):
    (tmp_path / signing.KEY_FILE).write_text("garbage")
    app = create_app({"DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / "db.sqlite"), "SECRET_KEY": "test",
                      "ADMIN_PASSWORD": ADMIN_PASSWORD})
    with pytest.raises(RuntimeError, match="re-enrolling every device"):
        signing.get_signer(app)
    assert (tmp_path / signing.KEY_FILE).read_text() == "garbage"


def test_canonical_json_matches_the_client():
    job = {"id": "j", "device": "d", "seq": 3, "action": "message", "params": {"text": "Grüße"}, "extra": 1}
    assert signing.canonical(job) == job_message(job)


# ---------- management state ----------

def test_heartbeat_records_what_the_device_allows(client, app):
    device = enrol_device(client, app, allowed=["message", "identify", "shell", 7, "message"])
    with app.app_context():
        row = fleet.get_device(get_db(), device["device_id"])
    assert json.loads(row["allowed_actions"]) == ["identify", "message"]
    assert row["key_fingerprint"] == device["fingerprint"] and row["client_version"] == "1"
    beat(client, device, fingerprint="not hex")
    with app.app_context():
        assert fleet.get_device(get_db(), device["device_id"])["key_fingerprint"] is None


# ---------- creating jobs ----------

def test_a_job_is_signed_sequenced_and_delivered(client, app, admin):
    device = enrol_device(client, app)
    send(admin, device, "message", text="  Lunch at 12  ")
    send(admin, device, "identify", seconds="9999")
    answer = beat(client, device)
    first, second = answer["jobs"]
    assert (first["seq"], first["action"], first["params"]) == (1, "message", {"text": "Lunch at 12"})
    assert (second["seq"], second["params"]) == (2, {"seconds": 600})
    assert answer["signing_key_fingerprint"] == device["fingerprint"]
    n, e = int(device["signing_key"]["n"], 16), device["signing_key"]["e"]
    for job in (first, second):
        assert job["device"] == device["device_id"]
        assert verify_signature(n, e, job_message(job), job["signature"])
    assert not verify_signature(n, e, job_message({**first, "params": {"text": "other"}}), first["signature"])
    assert [r["state"] for r in job_rows(app, device)] == ["delivered", "delivered"]


def test_sequence_numbers_are_per_device(client, app, admin):
    a, b = enrol_device(client, app, label="A"), enrol_device(client, app, label="B")
    send(admin, a, "identify")
    send(admin, b, "identify")
    send(admin, a, "identify")
    assert [r["seq"] for r in job_rows(app, a)] == [1, 2]
    assert [r["seq"] for r in job_rows(app, b)] == [1]


@pytest.mark.parametrize("action, params, error", [
    ("message", {"text": "   "}, "Write the message"),
    ("restart", {"service": "rm -rf /"}, "or one service"),
    ("identify", {"seconds": "soon"}, "Seconds must be a number"),
    ("shell", {}, "unknown action"),
])
def test_bad_jobs_are_refused(client, app, admin, action, params, error):
    device = enrol_device(client, app)
    resp = send(admin, device, action, **params)
    assert error in resp.data.decode()
    assert job_rows(app, device) == []


def test_restart_takes_one_service_or_all(client, app, admin):
    device = enrol_device(client, app)
    send(admin, device, "restart", service="OpenPLC")
    send(admin, device, "restart")
    assert [json.loads(r["params_json"]) for r in job_rows(app, device)] == [{"service": "openplc"},
                                                                            {"service": "all"}]


def test_only_allowed_actions_can_be_sent(client, app, admin):
    device = enrol_device(client, app, allowed=["identify"])
    resp = send(admin, device, "restart")
    assert "does not allow this action" in resp.data.decode() and job_rows(app, device) == []


def test_no_jobs_for_legacy_retired_or_silent_devices(client, app, admin, event):
    legacy = enroll(client, event).get_json()
    resp = admin.post(f"/admin/fleet/devices/{legacy['instance_id']}/jobs", data={**CSRF, "action": "identify"},
                      follow_redirects=True)
    assert "without fleet support" in resp.data.decode()
    with app.app_context():
        code = fleet.create_code(get_db(), "", None)["code"]
    silent = client.post("/api/v1/fleet/enroll", json={"code": code, "device": LAPTOP}).get_json()
    assert "not reported its management settings" in send(admin, silent, "identify").data.decode()
    device = enrol_device(client, app)
    admin.post(f"/admin/fleet/devices/{device['device_id']}/retire", data=CSRF)
    assert "retired" in send(admin, device, "identify").data.decode()


def test_a_device_with_another_pinned_key_gets_nothing(client, app, admin):
    device = enrol_device(client, app)
    send(admin, device, "identify")
    other = "ab" * 32
    assert beat(client, device, fingerprint=other)["jobs"] == []     # pending stays pending
    assert job_rows(app, device)[0]["state"] == "pending"
    assert "pinned another signing key" in send(admin, device, "identify").data.decode()
    assert len(beat(client, device)["jobs"]) == 1                     # its own key again


def test_device_page_offers_only_allowed_actions(client, app, admin):
    device = enrol_device(client, app, allowed=["identify", "collect_logs"])
    page = admin.get(f"/admin/fleet/devices/{device['device_id']}").data.decode()
    assert 'value="identify"' in page and 'value="collect_logs"' in page
    assert 'value="restart"' not in page and 'value="reset_progress"' not in page
    assert device["fingerprint"][:16] in page
    assert "2 allowed" in admin.get("/admin/fleet").data.decode()


# ---------- results, expiry, cancelling ----------

def test_results_finish_jobs_and_are_audited(client, app, admin):
    device = enrol_device(client, app)
    send(admin, device, "identify")
    job = beat(client, device)["jobs"][0]
    assert beat(client, device)["jobs"] == [job]                       # repeated until a result arrives
    answer = beat(client, device, results=[{"id": job["id"], "seq": 1, "state": "done", "detail": "shown"}])
    assert answer["jobs"] == []
    row = job_rows(app, device)[0]
    assert (row["state"], row["detail"]) == ("done", "shown") and row["finished_at"]
    log = admin.get("/admin/fleet/log").data.decode()
    assert "fleet_job_create" in log and "fleet_job_finished" in log
    # A finished job stays finished.
    beat(client, device, results=[{"id": job["id"], "state": "failed"}])
    assert job_rows(app, device)[0]["state"] == "done"


def test_odd_results_are_handled(client, app, admin):
    device, other = enrol_device(client, app, label="A"), enrol_device(client, app, label="B")
    send(admin, device, "identify")
    send(admin, other, "identify")
    job = beat(client, device)["jobs"][0]
    other_job = beat(client, other)["jobs"][0]
    beat(client, device, results=["x", {"id": 5}, {"id": other_job["id"], "state": "done"},
                                  {"id": job["id"], "state": "exploded", "detail": "?"}])
    assert job_rows(app, device)[0]["state"] == "failed"
    assert "unknown result" in job_rows(app, device)[0]["detail"]
    assert job_rows(app, other)[0]["state"] == "delivered"             # not this device's job
    client.post("/api/v1/fleet/heartbeat", headers=auth(device["token"]), json={"job_results": "nope"})


def test_undelivered_jobs_expire(client, app, admin):
    device = enrol_device(client, app)
    send(admin, device, "identify")
    with app.app_context():
        get_db().execute("UPDATE jobs SET created_at = ?", (time.time() - jobs.JOB_TTL - 1,))
    assert beat(client, device)["jobs"] == []
    assert job_rows(app, device)[0]["state"] == "expired"


def test_cancelled_jobs_are_not_delivered_but_results_still_count(client, app, admin):
    device = enrol_device(client, app)
    send(admin, device, "identify")
    job_id = job_rows(app, device)[0]["id"]
    admin.post(f"/admin/fleet/jobs/{job_id}/cancel", data=CSRF)
    assert beat(client, device)["jobs"] == []
    resp = admin.post(f"/admin/fleet/jobs/{job_id}/cancel", data=CSRF, follow_redirects=True)
    assert b"already finished" in resp.data
    beat(client, device, results=[{"id": job_id, "state": "done"}])   # it had run anyway
    assert job_rows(app, device)[0]["state"] == "done"
    assert admin.post("/admin/fleet/jobs/nope/cancel", data=CSRF).status_code == 404


# ---------- bulk ----------

def test_bulk_sends_to_devices_that_allow_it(client, app, admin):
    yes, no = enrol_device(client, app, label="Yes"), enrol_device(client, app, allowed=["identify"], label="No")
    resp = admin.post("/admin/fleet/jobs/bulk?group=&kind=virtual", data={
        **CSRF, "action": "message", "text": "Break", "device_id": [yes["device_id"], no["device_id"], "nope"]},
        follow_redirects=True)
    assert "Sent to 1 device(s). Skipped 2" in resp.data.decode()
    assert len(job_rows(app, yes)) == 1 and job_rows(app, no) == []
    resp = admin.post("/admin/fleet/jobs/bulk", data={**CSRF, "action": "shell"}, follow_redirects=True)
    assert b"Choose an action" in resp.data
    assert "fleet_jobs_bulk" in admin.get("/admin/fleet/log").data.decode()


# ---------- log bundles ----------

def upload(client, device, job_id, data):
    return client.post(f"/api/v1/fleet/jobs/{job_id}/logs", headers={**auth(device["token"]),
                       "Content-Type": "application/gzip"}, data=data)


def test_log_bundles(client, app, admin):
    device = enrol_device(client, app)
    send(admin, device, "collect_logs")
    send(admin, device, "identify")
    collect, identify = [r["id"] for r in job_rows(app, device)]
    bundle = gzip.compress(b"openplc | started\n")
    assert upload(client, device, identify, bundle).status_code == 404      # not a collect_logs job
    assert upload(client, device, collect, b"plain text").status_code == 400
    assert upload(client, device, collect, b"\x1f\x8b" + os.urandom(jobs.LOGS_MAX)).status_code == 413
    assert upload(client, device, collect, bundle).status_code == 204
    assert upload(client, device, collect, bundle).status_code == 409
    assert upload(client, {"token": "nope"}, collect, bundle).status_code == 401
    resp = admin.get(f"/admin/fleet/jobs/{collect}/logs")
    assert resp.status_code == 200 and gzip.decompress(resp.data) == b"openplc | started\n"
    assert 'filename="Board-7-logs-' in resp.headers["Content-Disposition"]
    assert "logs (" in admin.get(f"/admin/fleet/devices/{device['device_id']}").data.decode()
    assert admin.get(f"/admin/fleet/jobs/{identify}/logs").status_code == 404


def test_only_the_newest_log_bundles_are_kept(client, app, admin):
    device = enrol_device(client, app)
    for _ in range(jobs.LOGS_KEEP + 2):
        send(admin, device, "collect_logs")
    ids = [r["id"] for r in job_rows(app, device)]
    for job_id in ids:
        assert upload(client, device, job_id, gzip.compress(job_id.encode())).status_code == 204
    with app.app_context():
        kept = [r["job_id"] for r in get_db().execute("SELECT job_id FROM job_logs ORDER BY id")]
    assert kept == ids[-jobs.LOGS_KEEP:]
