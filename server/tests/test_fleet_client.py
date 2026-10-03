"""
FleetClient (client/cybics_mgmt_client.py) against a real HTTP server: it runs
a job only when it is signed with the pinned key, newer than the last one, and
allowed on the device; it executes nothing but the handlers landing registers.
"""
import gzip
import json
import threading

import pytest
from werkzeug.serving import make_server

from conftest import SIGNING_KEY
from cybics_mgmt.db import get_db
from cybics_mgmt.fleet import jobs
from cybics_mgmt.fleet import logic as fleet
from cybics_mgmt.fleet.signing import Signer, _load, get_signer
from cybics_mgmt_client import CTFClientError, FleetClient, _pinned_key, verify_signature

LAPTOP = {"kind": "virtual", "hostname": "laptop-7", "cybics_version": "1.2.4", "mode": "full"}


@pytest.fixture
def server(app):
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture
def code(app):
    with app.app_context():
        return fleet.create_code(get_db(), "", None)["code"]


class Landing:
    """Stand-in for landing: records what the handlers were asked to do."""

    def __init__(self):
        self.calls = []

    def handler(self, action, result=None):
        def run(params):
            self.calls.append((action, params))
            if isinstance(result, Exception):
                raise result
            return result
        return run

    def client(self, path, **results):
        handlers = {a: self.handler(a, results.get(a, "ok")) for a in jobs.ACTIONS}
        return FleetClient(str(path), device_info=lambda: dict(LAPTOP),
                           status=lambda: {"cybics_version": "1.2.4", "services": {"landing": True}},
                           handlers=handlers)


def enrolled(landing, tmp_path, server, code, allowed=tuple(jobs.ACTIONS), **results):
    client = landing.client(tmp_path / "fleet.json", **results)
    client.enroll(server, code, label="Board 7")
    client.set_allowed(allowed)
    assert client.sync_once()
    return client


def create(app, client, action, **params):
    with app.app_context():
        db = get_db()
        device = fleet.get_device(db, client.state["device_id"])
        return jobs.create_job(db, get_signer(app), device, action, params, "test")["id"]


def job_state(app, job_id):
    with app.app_context():
        return dict(jobs.get_job(get_db(), job_id))


# ---------- enrolment ----------

def test_disabled_fleet_client_does_nothing(tmp_path):
    client = FleetClient(str(tmp_path / "fleet.json"))
    assert client.sync_once() is False and not client.run_next_job()
    assert not (tmp_path / "fleet.json").exists()


def test_enrolment_pins_the_key_and_allows_nothing(app, server, code, tmp_path):
    client = Landing().client(tmp_path / "fleet.json")
    client.enroll(server, code, label="Board 7")
    assert client.fingerprint() == get_signer(app).fingerprint
    view = client.snapshot()
    assert view["allowed"] == [] and "token" not in view and "signing_key" not in view
    assert view["device"]["label"] == "Board 7" and view["available"] == sorted(jobs.ACTIONS)
    assert (tmp_path / "fleet.json").stat().st_mode & 0o777 == 0o600


def test_set_allowed_keeps_only_actions_with_a_handler(tmp_path):
    client = FleetClient(str(tmp_path / "fleet.json"), handlers={"identify": lambda p: "", "shell": print})
    assert client.set_allowed(["identify", "shell", "restart"]) == ["identify"]


def test_a_weak_or_missing_key_is_refused():
    assert _pinned_key({"n": "ff" * 128, "e": 65537}) is None          # 1024 bits
    assert _pinned_key({"n": "ff" * 384, "e": 3}) is None
    assert _pinned_key({"n": "zz", "e": 65537}) is None
    assert _pinned_key(None) is None
    assert _pinned_key({"n": "ff" * 384, "e": 65537}) is not None


# ---------- running jobs ----------

def test_a_job_runs_end_to_end(app, server, code, tmp_path):
    landing = Landing()
    client = enrolled(landing, tmp_path, server, code, message="shown")
    job_id = create(app, client, "message", text="Lunch")
    assert client.sync_once()
    assert client.snapshot()["queue"] == ["message"]
    assert client.run_next_job() and not client.run_next_job()
    assert landing.calls == [("message", {"text": "Lunch"})]
    assert client.sync_once()                                   # reports the result
    assert job_state(app, job_id)["state"] == "done" and job_state(app, job_id)["detail"] == "shown"
    assert client.state["results"] == []
    assert client.snapshot()["history"][-1]["state"] == "done"


def test_a_job_is_run_once_although_the_server_repeats_it(app, server, code, tmp_path):
    landing = Landing()
    client = enrolled(landing, tmp_path, server, code)
    create(app, client, "identify")
    client.sync_once()
    client.sync_once()     # delivered again: no result yet, so the server repeats it
    while client.run_next_job():
        pass
    assert len(landing.calls) == 1


def test_a_job_the_user_did_not_allow_is_refused(app, server, code, tmp_path):
    landing = Landing()
    client = enrolled(landing, tmp_path, server, code)
    job_id = create(app, client, "restart", service="all")
    client.set_allowed(["identify"])        # switched off before the job arrived
    client.sync_once()
    assert not client.run_next_job() and landing.calls == []
    client.sync_once()
    assert job_state(app, job_id)["state"] == "refused"


def test_switching_an_action_off_drops_queued_jobs(app, server, code, tmp_path):
    landing = Landing()
    client = enrolled(landing, tmp_path, server, code)
    job_id = create(app, client, "reset_progress")
    client.sync_once()
    client.set_allowed([])
    assert not client.run_next_job() and landing.calls == []
    client.sync_once()
    assert job_state(app, job_id)["state"] == "refused"


def test_a_failing_handler_is_reported(app, server, code, tmp_path):
    client = enrolled(Landing(), tmp_path, server, code, restart=RuntimeError("docker is gone"))
    job_id = create(app, client, "restart", service="all")
    client.sync_once()
    client.run_next_job()
    client.sync_once()
    row = job_state(app, job_id)
    assert row["state"] == "failed" and "docker is gone" in row["detail"]


def test_logs_are_uploaded(app, server, code, tmp_path):
    client = enrolled(Landing(), tmp_path, server, code, collect_logs="openplc | up\n" * 10)
    job_id = create(app, client, "collect_logs")
    client.sync_once()
    client.run_next_job()
    client.sync_once()
    assert job_state(app, job_id)["state"] == "done"
    with app.app_context():
        stored = jobs.get_logs(get_db(), job_id)
    assert gzip.decompress(stored["content"]) == b"openplc | up\n" * 10


def test_huge_logs_are_cut_to_the_newest_part(app, server, code, tmp_path):
    import os
    noise = os.urandom(3 * 1024 * 1024)   # does not compress
    client = enrolled(Landing(), tmp_path, server, code, collect_logs=noise)
    job_id = create(app, client, "collect_logs")
    client.sync_once()
    client.run_next_job()
    client.sync_once()
    assert job_state(app, job_id)["state"] == "done"
    with app.app_context():
        stored = gzip.decompress(jobs.get_logs(get_db(), job_id)["content"])
    assert len(stored) <= jobs.LOGS_MAX and noise.endswith(stored)


def test_a_handler_without_logs_fails_the_job(app, server, code, tmp_path):
    client = enrolled(Landing(), tmp_path, server, code, collect_logs=None)
    job_id = create(app, client, "collect_logs")
    client.sync_once()
    client.run_next_job()
    client.sync_once()
    assert job_state(app, job_id)["state"] == "failed"


def test_a_restart_that_ends_landing_counts_as_done(app, server, code, tmp_path):
    landing = Landing()
    client = enrolled(landing, tmp_path, server, code)
    job_id = create(app, client, "restart", service="all")
    client.sync_once()
    # The handler takes landing down with it: the job never returns.
    with client._lock:
        job = client.state["queue"].pop(0)
        client.state["running"] = job
        client._save()
    restarted = landing.client(tmp_path / "fleet.json")
    assert restarted.state["running"] is None
    restarted.sync_once()
    assert job_state(app, job_id)["state"] == "done" and job_state(app, job_id)["detail"] == "landing restarted"


def test_any_other_interrupted_job_counts_as_failed(app, server, code, tmp_path):
    landing = Landing()
    client = enrolled(landing, tmp_path, server, code)
    job_id = create(app, client, "collect_logs")
    client.sync_once()
    with client._lock:
        client.state["running"] = client.state["queue"].pop(0)
        client._save()
    landing.client(tmp_path / "fleet.json").sync_once()
    assert job_state(app, job_id)["state"] == "failed"


# ---------- what the client refuses ----------

def signed(job, key=SIGNING_KEY):
    return {**job, "signature": Signer(_load(key)).sign(job)}


@pytest.fixture
def armed(app, server, code, tmp_path):
    landing = Landing()
    client = enrolled(landing, tmp_path, server, code)
    return landing, client


def offer(client, *jobs_):
    with client._lock:
        for job in jobs_:
            client._accept(job)


def test_only_correctly_signed_jobs_for_this_device_run(armed):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    landing, client = armed
    me = client.state["device_id"]
    base = {"id": "j1", "device": me, "seq": 1, "action": "identify", "params": {"seconds": 5}}
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=3072).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    offer(client,
          {**base, "signature": "00"},                                  # garbage
          signed(base, attacker),                                       # another key
          {**signed(base), "params": {"seconds": 600}},                 # tampered after signing
          signed({**base, "device": "someone-else"}),                   # another device's job
          signed({**base, "seq": True}),                                # not a number
          {**signed(base), "seq": 2})                                   # seq changed after signing
    assert client.state["queue"] == [] and client.state["last_seq"] == 0
    assert client.snapshot()["last_error"]["code"] == "bad_signature"
    offer(client, signed(base))
    assert [j["id"] for j in client.state["queue"]] == ["j1"] and client.state["last_seq"] == 1


def test_replays_and_old_jobs_are_ignored(armed):
    _, client = armed
    me = client.state["device_id"]
    job = signed({"id": "j5", "device": me, "seq": 5, "action": "identify", "params": {}})
    offer(client, job, job, signed({"id": "j3", "device": me, "seq": 3, "action": "identify", "params": {}}))
    assert [j["id"] for j in client.state["queue"]] == ["j5"]


def test_verify_signature_rejects_malformed_input():
    n = int(_load(SIGNING_KEY).public_key().public_numbers().n)
    good = Signer(_load(SIGNING_KEY)).sign({"id": "x", "device": "d", "seq": 1, "action": "a", "params": {}})
    message = json.dumps({"action": "a", "device": "d", "id": "x", "params": {}, "seq": 1}, sort_keys=True,
                         separators=(",", ":")).encode()
    assert verify_signature(n, 65537, message, good)
    for bad in (good[:-2], good + "00", "zz" * (len(good) // 2), "00" * (len(good) // 2), f"{n:x}".zfill(len(good)),
                None, 7):
        assert not verify_signature(n, 65537, message, bad)


# ---------- leaving and retirement ----------

def test_leaving_disables_and_tells_the_server(app, server, code, tmp_path):
    client = enrolled(Landing(), tmp_path, server, code)
    device_id = client.state["device_id"]
    client.leave()
    assert client.state["enabled"] is False and client.state["token"] is None
    with app.app_context():
        assert fleet.get_device(get_db(), device_id)["retired_reason"] == "left"


def test_a_retired_device_stops_until_enrolled_again(app, server, code, tmp_path):
    client = enrolled(Landing(), tmp_path, server, code)
    with app.app_context():
        fleet.set_retired(get_db(), client.state["device_id"], True)
    assert client.sync_once() is False
    assert client.state["enabled"] is False and client.state["revoked"] is True
    client.enroll(server, code)
    assert client.sync_once() and client.state["revoked"] is False


def test_an_unreachable_server_is_retried_quietly(tmp_path, code, server):
    client = Landing().client(tmp_path / "fleet.json")
    client.enroll(server, code)
    client.state["server_url"] = "http://127.0.0.1:9"
    assert client.sync_once() is False
    assert client.state["enabled"] and client.snapshot()["last_error"]["code"] == "unreachable"


def test_enrolment_errors_reach_the_user(server, tmp_path):
    client = Landing().client(tmp_path / "fleet.json")
    with pytest.raises(CTFClientError) as err:
        client.enroll(server, "WRONG123")
    assert err.value.code == "invalid_code"
    broken = FleetClient(str(tmp_path / "f.json"), device_info=lambda: 1 / 0)
    with pytest.raises(CTFClientError) as err:
        broken.enroll(server, "WRONG123")
    assert err.value.code == "device_info"


def test_the_threads_run_jobs_without_help(app, server, code, tmp_path):
    landing = Landing()
    client = enrolled(landing, tmp_path, server, code)
    create(app, client, "identify")
    client.start()
    try:
        client._wake.set()
        for _ in range(100):
            if landing.calls:
                break
            threading.Event().wait(0.05)
    finally:
        client.stop()
    assert landing.calls == [("identify", {"seconds": 60})]
