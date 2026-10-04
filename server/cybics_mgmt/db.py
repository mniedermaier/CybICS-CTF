"""
SQLite storage for CybICS-mgmt.

One database file holds every event. SQLite with WAL is plenty for the load a
CTF produces (a few hundred instances sending a heartbeat every 30 s), and it
keeps the deployment a single container with a single volume.

Schema changes are applied as numbered migrations tracked in PRAGMA user_version.
Append to MIGRATIONS; never edit a migration that has shipped.
"""
import fcntl
import logging
import os
import sqlite3
import time

from flask import current_app, g

log = logging.getLogger("cybics_mgmt")

DATABASE_NAME = "cybics-mgmt.sqlite"
# The file name before the rename to CybICS-mgmt; adopted once at start.
LEGACY_DATABASE_NAME = "cybics-ctf.sqlite"

MIGRATIONS = [
    # 1: initial schema
    """
    CREATE TABLE events (
        id                      INTEGER PRIMARY KEY,
        slug                    TEXT    NOT NULL UNIQUE,
        name                    TEXT    NOT NULL,
        join_code               TEXT    NOT NULL UNIQUE,
        state                   TEXT    NOT NULL DEFAULT 'draft'
                                CHECK (state IN ('draft', 'running', 'paused', 'finished')),
        scoreboard_public       INTEGER NOT NULL DEFAULT 1,
        allow_team_registration INTEGER NOT NULL DEFAULT 1,
        started_at              REAL,
        finished_at             REAL,
        created_at              REAL    NOT NULL
    );

    CREATE TABLE challenges (
        id          INTEGER PRIMARY KEY,
        event_id    INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        key         TEXT    NOT NULL,
        category    TEXT    NOT NULL DEFAULT '',
        title       TEXT    NOT NULL,
        points      INTEGER NOT NULL CHECK (points >= 0),
        flag_hash   TEXT    NOT NULL,
        ctype       TEXT    NOT NULL DEFAULT 'offensive',
        enabled     INTEGER NOT NULL DEFAULT 1,
        position    INTEGER NOT NULL DEFAULT 0,
        UNIQUE (event_id, key)
    );

    CREATE TABLE teams (
        id            INTEGER PRIMARY KEY,
        event_id      INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        name          TEXT    NOT NULL COLLATE NOCASE,
        password_hash TEXT    NOT NULL,
        banned        INTEGER NOT NULL DEFAULT 0,
        created_at    REAL    NOT NULL,
        UNIQUE (event_id, name)
    );

    CREATE TABLE instances (
        id             TEXT    PRIMARY KEY,
        team_id        INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
        token_hash     TEXT    NOT NULL UNIQUE,
        kind           TEXT    NOT NULL CHECK (kind IN ('virtual', 'physical')),
        device_uid     TEXT,
        hostname       TEXT,
        cybics_version TEXT,
        mode           TEXT,
        remote_addr    TEXT,
        status_json    TEXT,
        revoked        INTEGER NOT NULL DEFAULT 0,
        enrolled_at    REAL    NOT NULL,
        last_seen      REAL
    );
    CREATE INDEX idx_instances_team ON instances(team_id);

    CREATE TABLE solves (
        id           INTEGER PRIMARY KEY,
        team_id      INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
        challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
        instance_id  TEXT    REFERENCES instances(id) ON DELETE SET NULL,
        client_time  REAL,
        received_at  REAL    NOT NULL,
        UNIQUE (team_id, challenge_id)
    );
    CREATE INDEX idx_solves_received ON solves(received_at);

    -- Audit log of every submission, correct or not. Wrong flags never come
    -- from an unmodified landing page (it validates locally before forwarding),
    -- so they are a strong hint that someone is talking to the API directly.
    CREATE TABLE submissions (
        id            INTEGER PRIMARY KEY,
        event_id      INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        team_id       INTEGER REFERENCES teams(id) ON DELETE CASCADE,
        instance_id   TEXT    REFERENCES instances(id) ON DELETE SET NULL,
        challenge_key TEXT    NOT NULL,
        result        TEXT    NOT NULL,
        remote_addr   TEXT,
        received_at   REAL    NOT NULL
    );
    CREATE INDEX idx_submissions_event ON submissions(event_id, received_at);

    CREATE TABLE announcements (
        id         INTEGER PRIMARY KEY,
        event_id   INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        message    TEXT    NOT NULL,
        created_at REAL    NOT NULL
    );
    """,
    # 2: moderation keeps its evidence.
    #  - A solve the organiser removes is voided, not deleted: it stays on the
    #    team's record (so the instance does not report it again) but scores 0.
    #  - Deleting a team keeps its audit trail: submissions.team_id becomes NULL
    #    and the team name is kept as a snapshot. SQLite cannot change a foreign
    #    key in place, hence the table rebuild.
    """
    ALTER TABLE solves ADD COLUMN voided INTEGER NOT NULL DEFAULT 0;

    CREATE TABLE submissions_new (
        id            INTEGER PRIMARY KEY,
        event_id      INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        team_id       INTEGER REFERENCES teams(id) ON DELETE SET NULL,
        team_name     TEXT,
        instance_id   TEXT    REFERENCES instances(id) ON DELETE SET NULL,
        challenge_key TEXT    NOT NULL,
        result        TEXT    NOT NULL,
        remote_addr   TEXT,
        received_at   REAL    NOT NULL
    );
    INSERT INTO submissions_new (id, event_id, team_id, team_name, instance_id, challenge_key,
                                 result, remote_addr, received_at)
        SELECT s.id, s.event_id, s.team_id, t.name, s.instance_id, s.challenge_key,
               s.result, s.remote_addr, s.received_at
        FROM submissions s LEFT JOIN teams t ON t.id = s.team_id;
    DROP TABLE submissions;
    ALTER TABLE submissions_new RENAME TO submissions;
    CREATE INDEX idx_submissions_event ON submissions(event_id, received_at);
    """,
    # 3: the organiser owns points and the enabled switch after the first
    # import. A re-import must not undo their changes, so "missing from the
    # imported file" (in_catalog) is tracked apart from "switched off by the
    # organiser" (enabled), and custom points are marked.
    """
    ALTER TABLE challenges ADD COLUMN in_catalog INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE challenges ADD COLUMN points_custom INTEGER NOT NULL DEFAULT 0;
    """,
    # 4: announcement ids must never be reused (clients ask for "newer than
    # the last id I saw"; SQLite reuses max(rowid)+1 without AUTOINCREMENT),
    # and organiser actions get a durable log that survives container
    # recreation. admin_log.event_id has no foreign key on purpose: the log
    # must outlive a deleted event.
    """
    CREATE TABLE announcements_new (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id   INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        message    TEXT    NOT NULL,
        created_at REAL    NOT NULL
    );
    INSERT INTO announcements_new (id, event_id, message, created_at)
        SELECT id, event_id, message, created_at FROM announcements;
    DROP TABLE announcements;
    ALTER TABLE announcements_new RENAME TO announcements;

    CREATE TABLE admin_log (
        id         INTEGER PRIMARY KEY,
        event_id   INTEGER,
        action     TEXT    NOT NULL,
        details    TEXT    NOT NULL DEFAULT '',
        actor      TEXT    NOT NULL,
        created_at REAL    NOT NULL
    );
    CREATE INDEX idx_admin_log_event ON admin_log(event_id, created_at);
    """,
    # 5: admin sessions live server side as well, so logging out ends the
    # session even if someone copied the cookie.
    """
    CREATE TABLE admin_sessions (
        id         TEXT PRIMARY KEY,
        created_at REAL NOT NULL,
        ended_at   REAL
    );
    """,
    # 6: one-time login links, created on the command line. They are the way
    # in that a login lockout cannot block (see the admin login route).
    """
    CREATE TABLE login_links (
        token_hash TEXT PRIMARY KEY,
        expires_at REAL NOT NULL,
        used_at    REAL
    );
    """,
    # 7: indexes for the admin pages, whose row counts participants can grow
    # (enrol/leave loops add instances, API calls add submissions).
    """
    CREATE INDEX idx_instances_uid ON instances(device_uid) WHERE device_uid IS NOT NULL;
    CREATE INDEX idx_instances_team_live ON instances(team_id, revoked, enrolled_at);
    CREATE INDEX idx_submissions_team ON submissions(team_id, result);
    """,
    # 8: first blood looks up the earliest solve per challenge.
    """
    CREATE INDEX idx_solves_challenge ON solves(challenge_id, received_at);
    """,
    # 9: optional first-blood bonus, in percent of the challenge's points.
    """
    ALTER TABLE events ADD COLUMN first_blood_bonus INTEGER NOT NULL DEFAULT 0
        CHECK (first_blood_bonus BETWEEN 0 AND 100);
    """,
    # 10: the fleet (docs/MGMT_DESIGN.md, phase 1). A device is one CybICS
    # installation and outlives events; every existing instance gets a legacy
    # device with the same id.
    """
    CREATE TABLE device_groups (
        id          INTEGER PRIMARY KEY,
        name        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
        created_at  REAL    NOT NULL
    );

    CREATE TABLE devices (
        id              TEXT    PRIMARY KEY,
        token_hash      TEXT    UNIQUE,
        label           TEXT    NOT NULL DEFAULT '',
        group_id        INTEGER REFERENCES device_groups(id) ON DELETE SET NULL,
        kind            TEXT    NOT NULL CHECK (kind IN ('virtual', 'physical')),
        device_uid      TEXT,
        hostname        TEXT,
        cybics_version  TEXT,
        mode            TEXT,
        remote_addr     TEXT,
        status_json     TEXT,
        legacy          INTEGER NOT NULL DEFAULT 0,
        retired         INTEGER NOT NULL DEFAULT 0,
        retired_reason  TEXT,
        notes           TEXT    NOT NULL DEFAULT '',
        enrolled_at     REAL    NOT NULL,
        last_seen       REAL
    );
    CREATE INDEX devices_uid ON devices(device_uid);
    CREATE INDEX devices_group ON devices(group_id);

    CREATE TABLE enrol_codes (
        id          INTEGER PRIMARY KEY,
        code        TEXT    NOT NULL UNIQUE,
        label       TEXT    NOT NULL DEFAULT '',
        group_id    INTEGER REFERENCES device_groups(id) ON DELETE SET NULL,
        enabled     INTEGER NOT NULL DEFAULT 1,
        uses        INTEGER NOT NULL DEFAULT 0,
        created_at  REAL    NOT NULL
    );

    ALTER TABLE instances ADD COLUMN device_id TEXT REFERENCES devices(id) ON DELETE SET NULL;
    CREATE INDEX instances_device ON instances(device_id);

    INSERT INTO devices (id, kind, device_uid, hostname, cybics_version, mode, remote_addr, status_json,
                         legacy, enrolled_at, last_seen)
        SELECT id, kind, device_uid, hostname, cybics_version, mode, remote_addr, status_json,
               1, enrolled_at, last_seen
        FROM instances;
    UPDATE instances SET device_id = id;
    """,
]


def now():
    return time.time()


def connect(path):
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def migrate(path):
    """
    Bring the schema up to date. An exclusive file lock serialises processes
    that start together (gunicorn and a `flask ...` CLI call during an
    upgrade), so each migration runs exactly once; the version is re-read
    under the lock.
    """
    with open(f"{path}.migrate-lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        conn = connect(path)
        try:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            for number, script in enumerate(MIGRATIONS[version:], start=version + 1):
                conn.executescript(f"BEGIN IMMEDIATE;\n{script}\nPRAGMA user_version = {number};\nCOMMIT;")
        finally:
            conn.close()


class transaction:
    """BEGIN IMMEDIATE ... COMMIT, so read-check-write sequences do not race."""

    def __init__(self, db):
        self.db = db

    def __enter__(self):
        self.db.execute("BEGIN IMMEDIATE")
        return self.db

    def __exit__(self, exc_type, *_):
        self.db.execute("ROLLBACK" if exc_type else "COMMIT")
        return False


def prune(path, days=30):
    """Drop admin session and login link rows nobody can use any more."""
    conn = connect(path)
    try:
        cutoff = time.time() - days * 86400
        conn.execute("DELETE FROM admin_sessions WHERE created_at < ?", (cutoff,))
        conn.execute("DELETE FROM login_links WHERE expires_at < ?", (cutoff,))
    finally:
        conn.close()


def adopt_legacy(path):
    """
    Take over the database of a server from before the rename: when only the
    old file exists next to `path`, move it into place.

    It is opened, checkpointed and closed first. SQLite removes the -wal and
    -shm files when its last connection closes, so after that the main file
    holds everything, including writes a crashed server left in the WAL. If
    they are still there, another process has the old file open (an old
    server on the same volume); then the start fails instead of splitting the
    data in two.
    """
    legacy = os.path.join(os.path.dirname(path), LEGACY_DATABASE_NAME)
    with open(f"{path}.migrate-lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if os.path.exists(path) or not os.path.exists(legacy):
            return False
        conn = sqlite3.connect(legacy, isolation_level=None)
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()
        if any(os.path.exists(legacy + suffix) for suffix in ("-wal", "-shm")):
            raise RuntimeError(f"{legacy} is still in use by another process; stop it before starting "
                               "CybICS-mgmt.")
        if os.path.exists(f"{legacy}.migrate-lock"):
            os.unlink(f"{legacy}.migrate-lock")
        os.rename(legacy, path)
    log.warning("adopted the database of CybICS-CTF: %s is now %s", legacy, path)
    return True


def init_app(app):
    adopt_legacy(app.config["DATABASE"])
    migrate(app.config["DATABASE"])
    prune(app.config["DATABASE"])
    app.teardown_appcontext(close_db)
