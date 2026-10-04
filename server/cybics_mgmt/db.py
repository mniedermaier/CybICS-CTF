"""
SQLite storage for CybICS-mgmt.

One database file holds every event. SQLite with WAL is plenty for the load a
CTF produces (a few hundred instances sending a heartbeat every 30 s), and it
keeps the deployment a single container with a single volume.

Schema changes are applied as numbered migrations tracked in PRAGMA user_version.
Append to MIGRATIONS; never edit a migration that has shipped.
"""
import fcntl
import sqlite3
import time

from flask import current_app, g

DATABASE_NAME = "cybics-mgmt.sqlite"

MIGRATIONS = [
    # 1: the schema of CybICS-mgmt.
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
        -- Optional first-blood bonus, in percent of the challenge's points.
        first_blood_bonus       INTEGER NOT NULL DEFAULT 0 CHECK (first_blood_bonus BETWEEN 0 AND 100),
        started_at              REAL,
        finished_at             REAL,
        created_at              REAL    NOT NULL
    );

    -- The organiser owns points and the enabled switch after the first import.
    -- A re-import must not undo their changes, so "missing from the imported
    -- file" (in_catalog) is tracked apart from "switched off by the organiser"
    -- (enabled), and custom points are marked.
    CREATE TABLE challenges (
        id            INTEGER PRIMARY KEY,
        event_id      INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        key           TEXT    NOT NULL,
        category      TEXT    NOT NULL DEFAULT '',
        title         TEXT    NOT NULL,
        points        INTEGER NOT NULL CHECK (points >= 0),
        flag_hash     TEXT    NOT NULL,
        ctype         TEXT    NOT NULL DEFAULT 'offensive',
        enabled       INTEGER NOT NULL DEFAULT 1,
        in_catalog    INTEGER NOT NULL DEFAULT 1,
        points_custom INTEGER NOT NULL DEFAULT 0,
        position      INTEGER NOT NULL DEFAULT 0,
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

    -- A device is one CybICS installation, a virtual stack or a board, and
    -- the only identity: its token authenticates every API call. Devices are
    -- retired, never deleted, and outlive events.
    CREATE TABLE device_groups (
        id          INTEGER PRIMARY KEY,
        name        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
        created_at  REAL    NOT NULL
    );

    CREATE TABLE devices (
        id              TEXT    PRIMARY KEY,
        token_hash      TEXT    NOT NULL UNIQUE,
        label           TEXT    NOT NULL DEFAULT '',
        group_id        INTEGER REFERENCES device_groups(id) ON DELETE SET NULL,
        kind            TEXT    NOT NULL CHECK (kind IN ('virtual', 'physical')),
        device_uid      TEXT,
        hostname        TEXT,
        cybics_version  TEXT,
        mode            TEXT,
        remote_addr     TEXT,
        status_json     TEXT,
        -- What the device last reported about its management.
        allowed_actions TEXT    NOT NULL DEFAULT '[]',
        key_fingerprint TEXT,
        client_version  TEXT,
        retired         INTEGER NOT NULL DEFAULT 0,
        retired_reason  TEXT,
        notes           TEXT    NOT NULL DEFAULT '',
        enrolled_at     REAL    NOT NULL,
        last_seen       REAL
    );
    CREATE INDEX idx_devices_uid ON devices(device_uid) WHERE device_uid IS NOT NULL;
    CREATE INDEX idx_devices_group ON devices(group_id);

    CREATE TABLE enrol_codes (
        id          INTEGER PRIMARY KEY,
        code        TEXT    NOT NULL UNIQUE,
        label       TEXT    NOT NULL DEFAULT '',
        group_id    INTEGER REFERENCES device_groups(id) ON DELETE SET NULL,
        enabled     INTEGER NOT NULL DEFAULT 1,
        uses        INTEGER NOT NULL DEFAULT 0,
        created_at  REAL    NOT NULL
    );

    -- An instance is a device's participation in an event, as a member of a
    -- team. A device has at most one live instance. joined_by tells whether
    -- the device joined with the team's password or the organiser put it there.
    CREATE TABLE instances (
        id          TEXT    PRIMARY KEY,
        team_id     INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
        device_id   TEXT    NOT NULL REFERENCES devices(id),
        joined_by   TEXT    NOT NULL DEFAULT 'device' CHECK (joined_by IN ('device', 'organiser')),
        revoked     INTEGER NOT NULL DEFAULT 0,
        joined_at   REAL    NOT NULL
    );
    CREATE INDEX idx_instances_team_live ON instances(team_id, revoked, joined_at);
    CREATE INDEX idx_instances_device ON instances(device_id, revoked);

    -- A solve the organiser removes is voided, not deleted: it stays on the
    -- team's record (so the device does not report it again) but scores 0.
    CREATE TABLE solves (
        id           INTEGER PRIMARY KEY,
        team_id      INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
        challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
        instance_id  TEXT    REFERENCES instances(id) ON DELETE SET NULL,
        client_time  REAL,
        received_at  REAL    NOT NULL,
        voided       INTEGER NOT NULL DEFAULT 0,
        UNIQUE (team_id, challenge_id)
    );
    CREATE INDEX idx_solves_received ON solves(received_at);
    CREATE INDEX idx_solves_challenge ON solves(challenge_id, received_at);

    -- Audit log of every submission, correct or not. Wrong flags never come
    -- from an unmodified landing page (it validates locally before forwarding),
    -- so they are a strong hint that someone is talking to the API directly.
    -- Deleting a team keeps its trail: team_id becomes NULL, team_name is a
    -- snapshot, and device_id still names the device.
    CREATE TABLE submissions (
        id            INTEGER PRIMARY KEY,
        event_id      INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        team_id       INTEGER REFERENCES teams(id) ON DELETE SET NULL,
        team_name     TEXT,
        instance_id   TEXT    REFERENCES instances(id) ON DELETE SET NULL,
        device_id     TEXT    REFERENCES devices(id),
        challenge_key TEXT    NOT NULL,
        result        TEXT    NOT NULL,
        remote_addr   TEXT,
        received_at   REAL    NOT NULL
    );
    CREATE INDEX idx_submissions_event ON submissions(event_id, received_at);
    CREATE INDEX idx_submissions_team ON submissions(team_id, result);

    -- Ids are never reused: clients ask for "newer than the last id I saw".
    CREATE TABLE announcements (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id   INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        message    TEXT    NOT NULL,
        created_at REAL    NOT NULL
    );

    -- Every organiser action. event_id has no foreign key on purpose: the log
    -- must outlive a deleted event.
    CREATE TABLE admin_log (
        id         INTEGER PRIMARY KEY,
        event_id   INTEGER,
        action     TEXT    NOT NULL,
        details    TEXT    NOT NULL DEFAULT '',
        actor      TEXT    NOT NULL,
        created_at REAL    NOT NULL
    );
    CREATE INDEX idx_admin_log_event ON admin_log(event_id, created_at);

    -- Admin sessions live server side as well, so logging out ends the
    -- session even if someone copied the cookie.
    CREATE TABLE admin_sessions (
        id         TEXT PRIMARY KEY,
        created_at REAL NOT NULL,
        ended_at   REAL
    );

    -- One-time login links from the command line: the way in that a login
    -- lockout cannot block.
    CREATE TABLE login_links (
        token_hash TEXT PRIMARY KEY,
        expires_at REAL NOT NULL,
        used_at    REAL
    );

    -- Signed, sequenced jobs for devices (docs/MGMT_DESIGN.md, "Jobs").
    CREATE TABLE jobs (
        id           TEXT    PRIMARY KEY,
        device_id    TEXT    NOT NULL REFERENCES devices(id),
        seq          INTEGER NOT NULL,
        action       TEXT    NOT NULL,
        params_json  TEXT    NOT NULL,
        signature    TEXT    NOT NULL,
        state        TEXT    NOT NULL DEFAULT 'pending'
                     CHECK (state IN ('pending', 'delivered', 'done', 'failed', 'refused', 'cancelled', 'expired')),
        detail       TEXT,
        created_by   TEXT    NOT NULL,
        created_at   REAL    NOT NULL,
        delivered_at REAL,
        finished_at  REAL,
        UNIQUE (device_id, seq)
    );
    CREATE INDEX idx_jobs_device_state ON jobs(device_id, state);

    CREATE TABLE job_logs (
        id          INTEGER PRIMARY KEY,
        job_id      TEXT    NOT NULL UNIQUE REFERENCES jobs(id),
        device_id   TEXT    NOT NULL REFERENCES devices(id),
        size        INTEGER NOT NULL,
        content     BLOB    NOT NULL,
        created_at  REAL    NOT NULL
    );
    """,
    # 2: the admin password set in the browser at the first visit to /admin,
    # unless MGMT_ADMIN_PASSWORD is set. One row; scrypt hash only.
    """
    CREATE TABLE admin_credentials (
        id            INTEGER PRIMARY KEY CHECK (id = 1),
        password_hash TEXT    NOT NULL,
        set_at        REAL    NOT NULL
    );
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


def init_app(app):
    migrate(app.config["DATABASE"])
    prune(app.config["DATABASE"])
    app.teardown_appcontext(close_db)
