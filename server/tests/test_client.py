"""
The reference client (client/cybics_ctf_client.py) against a real HTTP server,
the way CybICS' landing page will use it.
"""
import threading

import pytest
from werkzeug.serving import make_server

from conftest import FLAGS
from cybics_ctf import ctf
from cybics_ctf.db import get_db
from cybics_ctf_client import CTFClient, CTFClientError


@pytest.fixture
def server(app, event):
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


class Landing:
    """Stand-in for the landing page's local CTF state."""

    def __init__(self, solved=()):
        self.solved = list(solved)

    def client(self, path):
        return CTFClient(str(path), local_solves=lambda: self.solved, flag_for=FLAGS.get,
                         status=lambda: {"cybics_version": "1.2.3", "services": {"openplc": True}})

    def solve(self, client, challenge):
        self.solved.append(challenge)
        client.report_solve(challenge, FLAGS[challenge])


VIRTUAL = {"kind": "virtual", "hostname": "laptop", "cybics_version": "1.2.3", "mode": "full"}


def test_disabled_client_does_nothing(tmp_path):
    client = CTFClient(str(tmp_path / "state.json"))
    client.report_solve("physical_process", "CybICS(x)")
    assert client.sync_once() is False
    assert client.snapshot()["pending"] == 0


def test_test_connection(server, tmp_path):
    client = CTFClient(str(tmp_path / "s.json"))
    assert client.test_connection(server)["api_version"] == 1
    with pytest.raises(CTFClientError) as exc:
        client.test_connection("http://127.0.0.1:1")
    assert exc.value.code == "unreachable"


def test_enroll_report_and_sync(server, event, tmp_path):
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    landing.solve(client, "physical_process")
    assert client.snapshot()["pending"] == 1
    assert client.sync_once()
    snap = client.snapshot()
    assert snap["pending"] == 0
    assert "token" not in snap
    # the score updates on the heartbeat after the flush
    client.sync_once()
    assert client.snapshot()["standing"]["score"] == 100


def test_outbox_survives_restart_and_outage(server, event, tmp_path, app):
    landing = Landing()
    path = tmp_path / "s.json"
    client = landing.client(path)
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    client.state["server_url"] = "http://127.0.0.1:1"   # server "down"
    landing.solve(client, "physical_process")
    assert client.sync_once() is False
    assert client.snapshot()["last_error"]["code"] == "unreachable"

    restarted = landing.client(path)                     # landing container restarts
    assert restarted.snapshot()["pending"] == 1
    restarted.state["server_url"] = server               # server back
    assert restarted.sync_once()
    with app.app_context():
        assert ctf.scoreboard(get_db(), event["id"])[0]["score"] == 100


def test_reconciliation_resends_lost_solves(server, event, tmp_path, app):
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    landing.solved.append("plc_programming")             # solved, but the report was lost
    client.sync_once()   # heartbeat notices the gap and queues it
    client.sync_once()
    with app.app_context():
        assert ctf.scoreboard(get_db(), event["id"])[0]["score"] == 150


def test_solves_from_before_enrolment_are_not_reported(server, event, tmp_path, app):
    landing = Landing(solved=["physical_process", "plc_programming"])  # old progress on a reused Pi
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    client.sync_once()
    client.sync_once()
    with app.app_context():
        assert ctf.scoreboard(get_db(), event["id"])[0]["score"] == 0


def test_solve_while_paused_does_not_count_later(server, event, tmp_path, app):
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    with app.app_context():
        ctf.set_event_state(get_db(), event["id"], "paused")
    client.sync_once()                         # the client learns about the pause ...
    landing.solve(client, "physical_process")  # ... and then the solve happens
    client.sync_once()
    with app.app_context():
        ctf.set_event_state(get_db(), event["id"], "running")
    client.sync_once()
    client.sync_once()
    with app.app_context():
        assert ctf.scoreboard(get_db(), event["id"])[0]["score"] == 0


def test_revoked_instance_stops_syncing(server, event, tmp_path, app):
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    with app.app_context():
        ctf.revoke_instance(get_db(), client.state["instance_id"])
    assert client.sync_once() is False
    assert client.snapshot()["enabled"] is False


def test_leave(server, event, tmp_path):
    client = Landing().client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    client.leave()
    assert client.snapshot()["enabled"] is False
    assert client.state["token"] is None


def test_enroll_error_is_readable(server, tmp_path):
    client = Landing().client(tmp_path / "s.json")
    with pytest.raises(CTFClientError) as exc:
        client.enroll(server, "WRONG123", "Red Team", "secret-12", VIRTUAL)
    assert exc.value.code == "invalid_join_code"
    assert exc.value.message == "Unknown join code."


def test_url_normalisation():
    assert CTFClient.normalize_url("10.10.0.1:8000/") == "http://10.10.0.1:8000"
    assert CTFClient.normalize_url("https://ctf.example.org") == "https://ctf.example.org"
    with pytest.raises(CTFClientError):
        CTFClient.normalize_url("ftp://x")


# ---------- regressions from review ----------

def test_stale_401_does_not_disable_a_new_enrolment(server, event, tmp_path, app, monkeypatch):
    """Leave + re-enrol while a heartbeat with the old token is in flight."""
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    real_request = client._request

    def leave_and_reenrol_mid_request(method, path, **kw):
        if path == "/heartbeat":
            monkeypatch.setattr(client, "_request", real_request)
            client.leave()                                    # old token revoked ...
            client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
        return real_request(method, path, **kw)              # ... so this answers 401

    monkeypatch.setattr(client, "_request", leave_and_reenrol_mid_request)
    assert client.sync_once() is False
    assert client.snapshot()["enabled"] is True, "the new enrolment must survive"
    assert client.sync_once() is True


def test_unknown_result_values_are_held_like_invalid_flag(server, event, tmp_path, monkeypatch):
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    landing.solve(client, "physical_process")
    real_request = client._request

    def future_server(method, path, **kw):
        if path == "/solves":
            return 200, {"result": "some_future_result", "points": 0}
        return real_request(method, path, **kw)

    monkeypatch.setattr(client, "_request", future_server)
    client.sync_once()
    snap = client.snapshot()
    assert snap["pending"] == 0
    assert "physical_process" not in snap["rejected"]
    assert "physical_process" in client.state["held"]


def test_a_non_string_result_does_not_wedge_the_outbox(server, event, tmp_path, monkeypatch):
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    landing.solve(client, "physical_process")
    real_request = client._request

    def odd_server(method, path, **kw):
        if path == "/solves":
            return 200, {"result": ["accepted"]}
        return real_request(method, path, **kw)

    monkeypatch.setattr(client, "_request", odd_server)
    client.sync_once()
    assert client.snapshot()["pending"] == 0


def test_an_unwritable_state_file_is_a_client_error(server, event, tmp_path, monkeypatch):
    client = Landing().client(tmp_path / "s.json")

    def full_disk():
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(client, "_save", full_disk)
    with pytest.raises(CTFClientError) as exc:
        client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    assert exc.value.code == "state_unwritable"
    with pytest.raises(CTFClientError) as exc:
        client.leave()
    assert exc.value.code == "state_unwritable"
    assert client.snapshot()["enabled"] is False


def test_unknown_challenge_is_retried_after_catalog_change(server, event, tmp_path, app):
    with app.app_context():
        db = get_db()
        cid = db.execute("SELECT id FROM challenges WHERE key = 'physical_process'").fetchone()["id"]
        ctf.update_challenge(db, event["id"], cid, 100, False)      # disabled for now
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    landing.solve(client, "physical_process")
    client.sync_once()
    client.sync_once()
    assert "physical_process" in client.state["held"]
    with app.app_context():
        assert ctf.scoreboard(get_db(), event["id"])[0]["score"] == 0
        ctf.update_challenge(get_db(), event["id"], cid, 100, True)  # organiser re-enables it
    client.sync_once()   # heartbeat sees the new catalog_version and requeues
    client.sync_once()
    with app.app_context():
        assert ctf.scoreboard(get_db(), event["id"])[0]["score"] == 100


def test_client_errors_on_a_solve_are_final(server, event, tmp_path):
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    client.report_solve("physical_process", None)    # the server answers 400 invalid_input
    assert client.sync_once() is True
    assert client.snapshot()["pending"] == 0


def test_enrol_fails_if_progress_is_unreadable(server, event, tmp_path, app):
    def broken():
        raise ValueError("progress file is mid-write")

    client = CTFClient(str(tmp_path / "s.json"), local_solves=broken)
    with pytest.raises(CTFClientError) as exc:
        client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    assert exc.value.code == "progress_unreadable"
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM instances").fetchone()[0] == 0


def test_banned_team_keeps_retrying_and_recovers(server, event, tmp_path, app):
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    with app.app_context():
        ctf.set_team_banned(get_db(), client.state["team"]["id"], True)
    assert client.sync_once() is False
    assert client.snapshot()["enabled"] is True
    assert client.snapshot()["last_error"]["code"] == "team_banned"
    with app.app_context():
        ctf.set_team_banned(get_db(), client.state["team"]["id"], False)
    assert client.sync_once() is True


def test_solve_in_flight_during_pause_counts_after_resume(server, event, tmp_path, app):
    """Solved while running, but the report only arrives after the organiser paused."""
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    client.sync_once()
    landing.solve(client, "physical_process")         # while running
    with app.app_context():
        ctf.set_event_state(get_db(), event["id"], "paused")
    client.sync_once()                                # delivered during the pause
    assert "physical_process" in client.state["held_paused"]
    with app.app_context():
        ctf.set_event_state(get_db(), event["id"], "running")
    client.sync_once()
    client.sync_once()
    with app.app_context():
        assert ctf.scoreboard(get_db(), event["id"])[0]["score"] == 100


@pytest.mark.parametrize("failure", ["truncated", "list_body", "html_body"])
def test_transport_failures_become_client_errors(server, event, tmp_path, monkeypatch, failure):
    import http.client
    import io
    import urllib.request

    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)

    class FakeResponse(io.BytesIO):
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, *a):
            if failure == "truncated":
                raise http.client.IncompleteRead(b'{"ev')
            return b"[1, 2]" if failure == "list_body" else b"<html>proxy error</html>"

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResponse())
    assert client.sync_once() is False
    assert client.snapshot()["last_error"]["code"] in ("unreachable", "bad_response")
    assert client.snapshot()["enabled"] is True


def test_sender_thread_survives_unexpected_errors(tmp_path, monkeypatch):
    import threading as _t

    client = CTFClient(str(tmp_path / "s.json"))
    client.state["enabled"] = True
    client.state["heartbeat_interval"] = 5
    calls = []

    def boom():
        calls.append(1)
        if len(calls) >= 2:
            client.stop()
        raise RuntimeError("bug")

    monkeypatch.setattr(client, "sync_once", boom)
    monkeypatch.setattr(client._wake, "wait", lambda timeout=None: None)
    thread = _t.Thread(target=client._run)
    thread.start()
    thread.join(5)
    assert not thread.is_alive() and len(calls) == 2, "the loop must keep going after an exception"


def test_report_solve_never_raises(server, event, tmp_path, monkeypatch):
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)

    def full_disk():
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(client, "_save", full_disk)
    client.report_solve("physical_process", FLAGS["physical_process"])   # must not raise
    assert client.snapshot()["pending"] == 1
    assert client.snapshot()["last_error"]["code"] == "storage"


def test_reenrol_after_revocation_keeps_unreported_solves(server, event, tmp_path, app):
    landing = Landing(solved=["defense_firewall"])       # old progress: baseline
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    with app.app_context():
        ctf.revoke_instance(get_db(), client.state["instance_id"])   # organiser's mistake
    client.sync_once()
    assert client.snapshot()["enabled"] is False
    landing.solve(client, "physical_process")           # solved while revoked
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    client.sync_once()
    client.sync_once()
    with app.app_context():
        assert ctf.scoreboard(get_db(), event["id"])[0]["score"] == 100, \
            "the solve made while revoked counts, the old baseline still does not"


def test_leave_and_rejoin_keeps_queue_but_not_solves_made_while_away(server, event, tmp_path, app):
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    client.state["server_url"] = "http://127.0.0.1:1"                          # offline for now
    landing.solve(client, "physical_process")                                   # queued, unsent
    client.state["server_url"] = server
    client.leave()
    landing.solved.append("plc_programming")                                    # while away
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    client.sync_once()
    client.sync_once()
    with app.app_context():
        board = {e["name"]: e["score"] for e in ctf.scoreboard(get_db(), event["id"])}
    assert board["Red Team"] == 100


def test_switching_team_does_not_carry_solves_over(server, event, tmp_path, app):
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Team Alpha", "secret-12", VIRTUAL)
    client.sync_once()
    landing.solve(client, "physical_process")
    client.sync_once()
    client.leave()
    client.enroll(server, event["join_code"], "Team Bravo", "secret-12", VIRTUAL)
    client.sync_once()
    client.sync_once()
    with app.app_context():
        board = {e["name"]: e["score"] for e in ctf.scoreboard(get_db(), event["id"])}
    assert board == {"Team Alpha": 100, "Team Bravo": 0}


def test_foreign_401_does_not_unenrol(server, event, tmp_path, monkeypatch):
    import io
    import urllib.error
    import urllib.request
    client = Landing().client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)

    def captive_portal(req, *a, **kw):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b"<html>login</html>"))
    monkeypatch.setattr(urllib.request, "urlopen", captive_portal)
    assert client.sync_once() is False
    assert client.snapshot()["enabled"] is True


def test_deleted_announcements_disappear(server, event, tmp_path, app):
    client = Landing().client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    with app.app_context():
        ctf.add_announcement(get_db(), event["id"], "oops")
    client.sync_once()
    assert [a["message"] for a in client.snapshot()["announcements"]] == ["oops"]
    with app.app_context():
        aid = get_db().execute("SELECT id FROM announcements").fetchone()["id"]
        ctf.delete_announcement(get_db(), event["id"], aid)
    client.sync_once()
    assert client.snapshot()["announcements"] == []


def test_incomplete_enrol_answer_is_a_client_error(tmp_path, monkeypatch):
    client = CTFClient(str(tmp_path / "s.json"))
    monkeypatch.setattr(client, "_request", lambda *a, **kw: (201, {"team": {}}))
    with pytest.raises(CTFClientError) as exc:
        client.enroll("http://x", "CODE", "Team", "pass", VIRTUAL)
    assert exc.value.code == "bad_response"


def test_proxy_error_pages_do_not_drop_solves(server, event, tmp_path, monkeypatch):
    import io
    import urllib.error
    import urllib.request

    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    client.sync_once()
    landing.solve(client, "physical_process")
    real = urllib.request.urlopen

    def proxy_404(req, *a, **kw):
        if req.full_url.endswith("/solves"):
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {},
                                         io.BytesIO(b"<html>404 page not found</html>"))
        return real(req, *a, **kw)

    monkeypatch.setattr(urllib.request, "urlopen", proxy_404)
    client.sync_once()
    assert client.snapshot()["pending"] == 1 and client.snapshot()["rejected"] == []
    monkeypatch.setattr(urllib.request, "urlopen", real)
    client.sync_once()
    assert client.snapshot()["pending"] == 0
    client.sync_once()
    assert client.snapshot()["standing"]["score"] == 100


def test_pause_during_flush_holds_the_solve(server, event, tmp_path, app):
    """The heartbeat still said running; the organiser pauses before the solve is posted."""
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    client.sync_once()
    landing.solve(client, "physical_process")
    client._heartbeat()                                   # sees "running"
    with app.app_context():
        ctf.set_event_state(get_db(), event["id"], "paused")
    client._flush_outbox()                                # answered event_not_running
    assert client.state["held_paused"] == ["physical_process"]
    with app.app_context():
        ctf.set_event_state(get_db(), event["id"], "running")
    client.sync_once()
    client.sync_once()
    with app.app_context():
        assert ctf.scoreboard(get_db(), event["id"])[0]["score"] == 100


def test_solves_held_at_the_end_count_if_the_event_is_reopened(server, event, tmp_path, app):
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    client.sync_once()
    landing.solve(client, "physical_process")            # while running, but stuck in the outbox
    with app.app_context():
        ctf.set_event_state(get_db(), event["id"], "finished")
    client.sync_once()
    assert client.state["held_paused"] == ["physical_process"] and client.state["rejected"] == []
    with app.app_context():
        ctf.set_event_state(get_db(), event["id"], "running")   # finished by mistake: reopened
    client.sync_once()
    client.sync_once()
    with app.app_context():
        assert ctf.scoreboard(get_db(), event["id"])[0]["score"] == 100


@pytest.mark.parametrize("value", ["30s", float("nan"), [30], None, True, -5, 10**9])
def test_garbage_heartbeat_interval_is_tamed(value):
    from cybics_ctf_client import _interval
    assert 5 <= _interval(value) <= 3600


def test_recreated_event_with_the_same_slug_starts_fresh(server, event, tmp_path, app):
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    client.state["rejected"] = ["physical_process"]          # from a dry run
    client.leave()
    with app.app_context():
        db = get_db()
        ctf.delete_event(db, event["id"])
        fresh = ctf.create_event(db, event["slug"], "Real Event")
        import json as _json

        from conftest import CATALOG
        ctf.import_catalog(db, fresh["id"], _json.dumps(CATALOG))
        ctf.set_event_state(db, fresh["id"], "running")
    landing.solve(client, "physical_process")
    client.enroll(server, fresh["join_code"], "Red Team", "secret-12", VIRTUAL)
    assert client.state["rejected"] == [], "nothing carries over from the deleted event"



def test_wrong_catalog_is_recoverable(server, event, tmp_path, app):
    """The organiser imported another CybICS version's flags; honest solves come back once fixed."""
    import json as _json

    from conftest import CATALOG
    wrong = _json.loads(_json.dumps(CATALOG))
    wrong["categories"]["basic_understanding"]["challenges"][0]["flag"] = "CybICS(other_version)"
    with app.app_context():
        ctf.import_catalog(get_db(), event["id"], _json.dumps(wrong))
    landing = Landing()
    client = landing.client(tmp_path / "s.json")
    client.enroll(server, event["join_code"], "Red Team", "secret-12", VIRTUAL)
    client.sync_once()
    landing.solve(client, "physical_process")
    client.sync_once()
    assert "physical_process" in client.state["held"]
    with app.app_context():
        ctf.import_catalog(get_db(), event["id"], _json.dumps(CATALOG))   # the right file
    client.sync_once()
    client.sync_once()
    with app.app_context():
        assert ctf.scoreboard(get_db(), event["id"])[0]["score"] == 100
