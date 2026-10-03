"""
The rename from CybICS-CTF to CybICS-mgmt must not break deployed CybICS
releases or existing installations: docs/MGMT_DESIGN.md, "Phase 0".
"""
import os
import sqlite3

import pytest

import cybics_mgmt
from cybics_mgmt import create_app, env
from cybics_mgmt.db import DATABASE_NAME, LEGACY_DATABASE_NAME, adopt_legacy


def test_info_keeps_the_service_deployed_clients_check(client):
    data = client.get("/api/v1/info").get_json()
    assert data["service"] == "cybics-ctf"
    assert data["product"] == "cybics-mgmt"
    assert data["features"] == ["ctf", "fleet"]


def test_mgmt_setting_wins_over_the_legacy_name(monkeypatch):
    monkeypatch.setenv("MGMT_SERVER_NAME", "New")
    monkeypatch.setenv("CTF_SERVER_NAME", "Old")
    assert env("SERVER_NAME") == "New"


def test_legacy_setting_is_honoured_and_reported_once(monkeypatch, caplog):
    monkeypatch.delenv("MGMT_SERVER_NAME", raising=False)
    monkeypatch.setenv("CTF_SERVER_NAME", "Old")
    monkeypatch.setattr(cybics_mgmt, "_warned_legacy", set())
    with caplog.at_level("WARNING", logger="cybics_mgmt"):
        assert env("SERVER_NAME") == "Old"
        assert env("SERVER_NAME") == "Old"
    assert [r.getMessage() for r in caplog.records].count(
        "CTF_SERVER_NAME is deprecated; rename it to MGMT_SERVER_NAME") == 1


def test_blank_settings_count_as_unset(monkeypatch):
    # docker compose passes every variable through, blank when it is not set.
    monkeypatch.setenv("MGMT_SERVER_NAME", "  ")
    monkeypatch.setenv("CTF_SERVER_NAME", "")
    assert env("SERVER_NAME", "fallback") == "fallback"


def test_legacy_admin_password_still_applies(tmp_path, monkeypatch):
    monkeypatch.delenv("MGMT_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("CTF_ADMIN_PASSWORD", "legacy-password-1")
    app = create_app({"DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / DATABASE_NAME),
                      "SECRET_KEY": "test"})
    assert app.config["ADMIN_PASSWORD"] == "legacy-password-1"
    assert not (tmp_path / "admin_password").exists()


def _legacy_db(directory, rows):
    """A pre-rename database in WAL mode; returns its path and an open connection."""
    path = directory / LEGACY_DATABASE_NAME
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("CREATE TABLE t (v TEXT)")
    conn.executemany("INSERT INTO t VALUES (?)", [(r,) for r in rows])
    return path, conn


def test_legacy_database_is_adopted_with_its_wal(tmp_path):
    # A server that crashed: its last writes are still in the WAL, never
    # checkpointed, and the -wal and -shm files are left behind.
    pid = os.fork()
    if pid == 0:   # pragma: no cover - the child never returns
        _, conn = _legacy_db(tmp_path, ["a", "b"])
        conn.execute("PRAGMA wal_autocheckpoint = 0")
        conn.execute("INSERT INTO t VALUES ('c')")
        os._exit(0)
    os.waitpid(pid, 0)
    legacy = tmp_path / LEGACY_DATABASE_NAME
    assert os.path.getsize(f"{legacy}-wal") > 0
    target = tmp_path / DATABASE_NAME
    assert adopt_legacy(str(target)) is True
    assert not legacy.exists() and not os.path.exists(f"{legacy}-wal")
    rows = sqlite3.connect(target).execute("SELECT v FROM t ORDER BY v").fetchall()
    assert rows == [("a",), ("b",), ("c",)]
    assert adopt_legacy(str(target)) is False            # only once


def test_adoption_refuses_a_legacy_database_still_in_use(tmp_path):
    legacy, conn = _legacy_db(tmp_path, ["a"])   # an old server, idle but running
    try:
        with pytest.raises(RuntimeError, match="still in use"):
            adopt_legacy(str(tmp_path / DATABASE_NAME))
        assert legacy.exists() and not (tmp_path / DATABASE_NAME).exists()
        assert conn.execute("SELECT v FROM t").fetchall() == [("a",)]   # and it is unharmed
    finally:
        conn.close()


def test_an_existing_database_is_never_replaced(tmp_path):
    legacy, conn = _legacy_db(tmp_path, ["old"])
    conn.close()
    target = tmp_path / DATABASE_NAME
    sqlite3.connect(target).execute("CREATE TABLE t (v TEXT)")
    assert adopt_legacy(str(target)) is False
    assert legacy.exists()


def test_server_starts_on_an_adopted_database(tmp_path):
    first = create_app({"DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / LEGACY_DATABASE_NAME),
                        "SECRET_KEY": "test", "ADMIN_PASSWORD": "test-admin-password"})
    with first.app_context():
        from cybics_mgmt.ctf import logic as ctf
        from cybics_mgmt.db import get_db
        ctf.create_event(get_db(), "kept", "Kept Event")
    app = create_app({"DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / DATABASE_NAME),
                      "SECRET_KEY": "test", "ADMIN_PASSWORD": "test-admin-password"})
    assert app.test_client().get("/api/v1/events/kept/scoreboard").status_code == 404   # a draft
    with app.app_context():
        from cybics_mgmt.db import get_db
        assert get_db().execute("SELECT slug FROM events").fetchone()["slug"] == "kept"


def test_legacy_package_name_still_creates_the_app():
    import cybics_ctf
    assert cybics_ctf.create_app is create_app
