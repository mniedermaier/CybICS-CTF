"""
Domain logic: events, the challenge catalog, teams, instances (a device's
participation in an event), solves, scoring.

Kept free of request handling so the API, the admin UI and the CLI share it.
Every function takes the connection explicitly.
"""
import hashlib
import json
import math
import re
import unicodedata
import uuid

from ..db import now, transaction
from ..device_input import encodable as _encodable
from ..errors import MgmtError
from ..security import flag_matches, hash_flag, hash_password, new_join_code, verify_password

EVENT_STATES = ("draft", "running", "paused", "finished")
# Allowed state changes. Nothing goes back to draft once started, so a click
# cannot hide a running event's scoreboard or reset its start time.
TRANSITIONS = {
    "draft": ("running",),
    "running": ("paused", "finished"),
    "paused": ("running", "finished"),
    "finished": ("running",),   # reopen, e.g. after finishing by mistake
}
# A challenge counts if the organiser has it enabled and the last imported
# catalog still contains it.
ACTIVE = "enabled = 1 AND in_catalog = 1"
# A solve counts unless it was voided or its team disqualified (aliases s, t).
COUNTING_SOLVE = "s.voided = 0 AND t.banned = 0"
POINTS_MAX = 100000
# Long enough that online guessing is impractical without any lockout (which
# a rival on the same NAT address could trigger against the team).
TEAM_PASSWORD_MIN = 8
# A re-enrolling laptop adds an instance each time; this bounds what one team
# can make the server store, and hash for.
MAX_INSTANCES_PER_TEAM = 25
# Enrol + leave in a loop would stay under that cap while piling up revoked
# rows; new instances per team per hour are capped as well.
MAX_NEW_INSTANCES_PER_HOUR = 100
# The guesses that come first in any list. With a hashing budget of roughly
# ten tries per second for the whole server, refusing these is what matters.
COMMON_PASSWORDS = frozenset("""
password passwort 12345678 123456789 1234567890 qwertyui qwertzui iloveyou sunshine princess
football baseball welcome1 password1 passwort1 abcdefgh abcd1234 11111111 00000000 87654321
letmein1 trustno1 changeme admin123 administrator cybics123 cybicsctf hackerman qwerty123
""".split())
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
# Latin script only (ASCII plus Latin-1 and Latin Extended-A letters, so
# umlauts and accents work): look-alike letters from Cyrillic, Greek or the
# IPA block cannot be used to fake another team's name on the projector.
TEAM_NAME_RE = re.compile(r"^[A-Za-z0-9\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u017F _.\-'!?()+#&@]{2,40}$")
CHALLENGE_KEY_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")

# Submission results. Every one except a transient server error is final:
# the client must drop the queued solve and not retry it.
ACCEPTED = "accepted"
DUPLICATE = "duplicate"
INVALID_FLAG = "invalid_flag"
UNKNOWN_CHALLENGE = "unknown_challenge"
EVENT_NOT_RUNNING = "event_not_running"


class CTFError(MgmtError):
    """A CTF request the caller can fix; carries an API error code and HTTP status."""


def _text(value, field, required=True):
    """
    A string field from a JSON body. Anything else is the caller's mistake and
    must be a 400: under the API contract a 5xx means "transient, retry".
    """
    if value is None or value == "":
        if required:
            raise CTFError("invalid_input", f"{field} is required.")
        return ""
    if not isinstance(value, str):
        raise CTFError("invalid_input", f"{field} must be a string.")
    if not _encodable(value):
        # JSON allows lone surrogates ("\ud800"); UTF-8, hashing and SQLite do not.
        raise CTFError("invalid_input", f"{field} must be valid Unicode.")
    return value


# Instance clocks are informational, but they end up in the admin UI; keep
# only values that are a plausible "when" (finite, not far from now).
CLIENT_TIME_PAST = 90 * 86400
CLIENT_TIME_FUTURE = 86400


def _client_time(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        value = float(value)
    except OverflowError:   # an int beyond float range, e.g. 10**400
        return None
    if not math.isfinite(value):
        return None
    ts = now()
    if not ts - CLIENT_TIME_PAST <= value <= ts + CLIENT_TIME_FUTURE:
        return None
    return value


# ---------- events ----------

def create_event(db, slug, name):
    slug = slug.strip().lower()
    if not SLUG_RE.match(slug):
        raise CTFError("invalid_slug", "Slug must be lower-case letters, digits and dashes.")
    if not name.strip():
        raise CTFError("invalid_name", "Event name must not be empty.")
    with transaction(db):
        if db.execute("SELECT 1 FROM events WHERE slug = ?", (slug,)).fetchone():
            raise CTFError("slug_taken", f"An event with slug '{slug}' already exists.", 409)
        code = _unique_join_code(db)
        cur = db.execute(
            "INSERT INTO events (slug, name, join_code, created_at) VALUES (?, ?, ?, ?)",
            (slug, name.strip(), code, now()))
    return get_event(db, cur.lastrowid)


def _unique_join_code(db):
    while True:
        code = new_join_code()
        if not db.execute("SELECT 1 FROM events WHERE join_code = ?", (code,)).fetchone():
            return code


def get_event(db, event_id):
    return db.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()


def get_event_by_slug(db, slug):
    return db.execute("SELECT * FROM events WHERE slug = ?", (slug,)).fetchone()


def get_event_by_join_code(db, code):
    return db.execute("SELECT * FROM events WHERE join_code = ?",
                      (_text(code, "join_code").strip().upper(),)).fetchone()


def list_events(db):
    return db.execute("SELECT * FROM events ORDER BY created_at DESC").fetchall()


def set_event_state(db, event_id, state):
    if state not in EVENT_STATES:
        raise CTFError("invalid_state", f"Unknown state '{state}'.")
    ts = now()
    with transaction(db):
        current = db.execute("SELECT state FROM events WHERE id = ?", (event_id,)).fetchone()
        if current is None:
            raise CTFError("not_found", "No such event.", 404)
        if state == current["state"]:
            return   # nothing to do; must not move started_at/finished_at
        if state not in TRANSITIONS[current["state"]]:
            raise CTFError("invalid_transition",
                           f"An event cannot go from {current['state']} to {state}.", 409)
        if state == "running" and not db.execute(
                f"SELECT 1 FROM challenges WHERE event_id = ? AND {ACTIVE}", (event_id,)).fetchone():
            # Solves reported against an empty catalog would all be answered
            # unknown_challenge; better to refuse the start.
            raise CTFError("empty_catalog", "Import the challenge catalog before starting the event.", 409)
        db.execute("""
            UPDATE events SET state = ?,
                started_at  = CASE WHEN ? = 'running' AND started_at IS NULL THEN ? ELSE started_at END,
                finished_at = CASE WHEN ? = 'finished' THEN ? ELSE NULL END
            WHERE id = ?""", (state, state, ts, state, ts, event_id))


def update_event_settings(db, event_id, name, scoreboard_public, allow_team_registration,
                          first_blood_bonus=None):
    """first_blood_bonus: percent of a challenge's points for its first solver (0 = off); None keeps it."""
    if not name.strip():
        raise CTFError("invalid_name", "Event name must not be empty.")
    if first_blood_bonus is not None and not 0 <= first_blood_bonus <= 100:
        raise CTFError("invalid_bonus", "The first blood bonus must be between 0 and 100 percent.")
    db.execute("""UPDATE events SET name = ?, scoreboard_public = ?, allow_team_registration = ?,
                      first_blood_bonus = COALESCE(?, first_blood_bonus)
                  WHERE id = ?""",
               (name.strip(), int(bool(scoreboard_public)), int(bool(allow_team_registration)),
                first_blood_bonus, event_id))


def first_blood_points(points, bonus_percent):
    """The extra points for a first blood (rounded down; 0 when the bonus is off)."""
    return points * bonus_percent // 100


def regenerate_join_code(db, event_id):
    with transaction(db):
        db.execute("UPDATE events SET join_code = ? WHERE id = ?", (_unique_join_code(db), event_id))


def delete_event(db, event_id):
    db.execute("DELETE FROM events WHERE id = ?", (event_id,))


# ---------- challenge catalog ----------

def parse_ctf_config(raw):
    """
    Turn CybICS' software/landing/ctf_config.json into catalog rows.

    The file is the single source of truth for challenges in CybICS, so the
    server imports it as-is instead of keeping its own copy of the flags.
    """
    try:
        config = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise CTFError("invalid_catalog", f"Not valid JSON: {exc}") from exc
    categories = config.get("categories") if isinstance(config, dict) else None
    if not isinstance(categories, dict):
        raise CTFError("invalid_catalog", "Expected a ctf_config.json with a 'categories' object.")
    rows, seen = [], set()
    for cat_key, cat in categories.items():
        challenges = cat.get("challenges", []) if isinstance(cat, dict) else None
        if not isinstance(challenges, list):
            raise CTFError("invalid_catalog", f"Category '{cat_key}' has no list of challenges.")
        for chall in challenges:
            if not isinstance(chall, dict):
                raise CTFError("invalid_catalog", f"Category '{cat_key}' contains a non-object challenge.")
            key = str(chall.get("id", ""))
            if not CHALLENGE_KEY_RE.match(key):
                raise CTFError("invalid_catalog", f"Challenge id '{key}' is not valid.")
            if key in seen:
                raise CTFError("invalid_catalog", f"Challenge id '{key}' appears twice.")
            seen.add(key)
            flag = chall.get("flag")
            points = chall.get("points")
            if not isinstance(flag, str) or not flag.strip():
                raise CTFError("invalid_catalog", f"Challenge '{key}' has no flag.")
            if isinstance(points, bool) or not isinstance(points, int) or not 0 <= points <= POINTS_MAX:
                raise CTFError("invalid_catalog", f"Challenge '{key}' has invalid points.")
            title, ctype, category = chall.get("title", key), chall.get("type", "offensive"), cat.get("name", cat_key)
            if not all(isinstance(v, str) for v in (title, ctype, category)):
                raise CTFError("invalid_catalog", f"Challenge '{key}' has a non-text title, type or category.")
            rows.append({
                "key": key,
                "category": category[:100],
                "title": title[:200],
                "points": points,
                "flag_hash": hash_flag(flag),
                "ctype": ctype[:32],
                "position": len(rows),
            })
    if not rows:
        raise CTFError("invalid_catalog", "The catalog contains no challenges.")
    return rows


def import_catalog(db, event_id, raw):
    """
    Upsert challenges by key. Existing solves survive a re-import.

    Titles, flags and types follow the file. Points follow it unless the
    organiser changed them, and the organiser's enabled switch is kept.
    Challenges missing from the file drop out of the catalog (in_catalog = 0)
    but are not deleted, so their solves stay on record; they come back if a
    later file contains them again.
    """
    rows = parse_ctf_config(raw)
    with transaction(db):
        for row in rows:
            db.execute("""
                INSERT INTO challenges (event_id, key, category, title, points, flag_hash, ctype, position)
                VALUES (:event_id, :key, :category, :title, :points, :flag_hash, :ctype, :position)
                ON CONFLICT (event_id, key) DO UPDATE SET
                    category = excluded.category, title = excluded.title,
                    points = CASE WHEN points_custom THEN points ELSE excluded.points END,
                    flag_hash = excluded.flag_hash, ctype = excluded.ctype,
                    position = excluded.position, in_catalog = 1""",
                       {**row, "event_id": event_id})
        keys = [r["key"] for r in rows]
        db.execute(f"""UPDATE challenges SET in_catalog = 0
                       WHERE event_id = ? AND key NOT IN ({','.join('?' * len(keys))})""",
                   (event_id, *keys))
    return len(rows)


def list_challenges(db, event_id, enabled_only=False):
    sql = "SELECT * FROM challenges WHERE event_id = ?"
    if enabled_only:
        sql += f" AND {ACTIVE}"
    return db.execute(sql + " ORDER BY position, key", (event_id,)).fetchall()


def catalog_version(db, event_id):
    """
    Short fingerprint of the enabled catalog, ids and flags. Clients hold back
    solves the server answered unknown_challenge or invalid_flag and retry
    them when this changes (the organiser imported the catalog late, imported
    the right CybICS version after a wrong one, or re-enabled a challenge).
    """
    rows = [f"{r['key']}:{r['flag_hash']}" for r in db.execute(
        f"SELECT key, flag_hash FROM challenges WHERE event_id = ? AND {ACTIVE} ORDER BY key", (event_id,))]
    return hashlib.sha256("\n".join(rows).encode()).hexdigest()[:16]


def update_challenge(db, event_id, challenge_id, points, enabled):
    if not 0 <= points <= POINTS_MAX:
        raise CTFError("invalid_points", f"Points must be between 0 and {POINTS_MAX}.")
    db.execute("""UPDATE challenges SET enabled = ?,
                      points_custom = points_custom OR points != ?, points = ?
                  WHERE id = ? AND event_id = ?""",
               (int(bool(enabled)), points, points, challenge_id, event_id))


# ---------- teams and instances ----------
# An instance is a device's membership in a team. The device itself, and its
# token, belong to the fleet (fleet/logic.py).

def _validate_team_name(name):
    name = unicodedata.normalize("NFC", " ".join(name.split()))
    if not TEAM_NAME_RE.match(name):
        raise CTFError("invalid_team_name",
                       "Team name must be 2-40 characters: letters, digits, spaces and . - ' ! ? ( ) + # & @")
    return name


# Latin look-alikes from Cyrillic and Greek, the usual way to fake another
# team's name on the projector ("Rеd Team" with a Cyrillic е).
_HOMOGLYPHS = str.maketrans({
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c",
    "т": "t", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ӏ": "l",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "ω": "w", "0": "o", "1": "l", "|": "l",
})


def team_name_skeleton(name):
    """What a name looks like on a projector: case, accents, spacing and homoglyphs folded away."""
    decomposed = unicodedata.normalize("NFKD", name.casefold())
    plain = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return re.sub(r"[\s._\-'!?()+#&@]+", "", plain.translate(_HOMOGLYPHS))


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _nocase(text):
    """SQLite's NOCASE comparison key: ASCII letters folded, nothing else."""
    return text.translate(_ASCII_LOWER)


def _check_lookalike(db, event_id, name):
    skeleton = team_name_skeleton(name)
    for row in db.execute("SELECT name FROM teams WHERE event_id = ?", (event_id,)):
        # Skip only what SQLite itself treats as the same name (NOCASE folds
        # ASCII only): "ärger team" next to "Ärger Team" is a look-alike.
        if _nocase(row["name"]) != _nocase(name) and team_name_skeleton(row["name"]) == skeleton:
            raise CTFError("team_name_taken",
                           f"Too similar to the existing team '{row['name']}'. Pick another name.", 409)


def _cheap_refusals(db, team, device):
    """Refusals that cost nothing, checked before any password is hashed."""
    if team["banned"]:
        raise CTFError("team_banned", "This team has been disqualified.", 403)
    live = db.execute("SELECT COUNT(*) FROM instances WHERE team_id = ? AND revoked = 0 AND device_id != ?",
                      (team["id"], device["id"])).fetchone()[0]
    # A board joining again with a UID already live in the team replaces that
    # instance (an SD card reflash makes a new device), so it does not add one.
    replaces = device["device_uid"] and db.execute(
        """SELECT 1 FROM instances i JOIN devices d ON d.id = i.device_id
           WHERE i.team_id = ? AND i.revoked = 0 AND d.device_uid = ?""",
        (team["id"], device["device_uid"])).fetchone()
    if live >= MAX_INSTANCES_PER_TEAM and not replaces:
        raise CTFError("too_many_instances",
                       f"This team already has {live} active devices. Leave on an unused one first, "
                       "or ask the organiser to revoke old ones.", 409)
    recent = db.execute("SELECT COUNT(*) FROM instances WHERE team_id = ? AND joined_at > ?",
                        (team["id"], now() - 3600)).fetchone()[0]
    if recent >= MAX_NEW_INSTANCES_PER_HOUR:
        raise CTFError("too_many_instances",
                       "This team had too many devices join in the last hour. Try again later.", 429)


def _add_instance(db, team, device, joined_by):
    """
    Make the device a member of the team (call inside a transaction). Returns
    (instance_id, uid_teams). A device has one live instance: any other one
    ends here. A board joining a team its UID is already live in replaces
    that registration too (an SD card reflash makes a new device). Only
    within the team: the UID is broadcast in the board's SSID, so anyone can
    claim it, and it must never let one team knock another team's board
    offline. uid_teams lists other teams of the event with a live instance
    claiming the same UID; the caller logs it, and the admin UI flags it.
    """
    db.execute("UPDATE instances SET revoked = 1 WHERE device_id = ? AND revoked = 0", (device["id"],))
    uid_teams = []
    if device["device_uid"]:
        db.execute("""UPDATE instances SET revoked = 1 WHERE team_id = ? AND revoked = 0 AND device_id IN
                          (SELECT id FROM devices WHERE device_uid = ?)""", (team["id"], device["device_uid"]))
        uid_teams = [r["name"] for r in db.execute("""
            SELECT DISTINCT t.name FROM instances i JOIN teams t ON t.id = i.team_id
            JOIN devices d ON d.id = i.device_id
            WHERE d.device_uid = ? AND i.revoked = 0 AND t.event_id = ? AND t.id != ?""",
                                                  (device["device_uid"], team["event_id"], team["id"]))]
    instance_id = str(uuid.uuid4())
    db.execute("INSERT INTO instances (id, team_id, device_id, joined_by, joined_at) VALUES (?, ?, ?, ?, ?)",
               (instance_id, team["id"], device["id"], joined_by, now()))
    return instance_id, uid_teams


def join(db, device, join_code, team_name, team_password):
    """
    A device joins a team of the event with this join code, creating the team
    on first use. Returns (instance_id, event, team, uid_teams).
    """
    event = get_event_by_join_code(db, join_code)
    if event is None:
        raise CTFError("invalid_join_code", "Unknown join code.", 404)
    if event["state"] == "finished":
        raise CTFError("event_finished", "This event has finished.", 409)
    team_name = _validate_team_name(_text(team_name, "team_name"))
    team_password = _text(team_password, "team_password")
    if len(team_password) > 128:
        raise CTFError("invalid_team_password", "Team password must be at most 128 characters.")

    def wrong_password(team):
        failed = CTFError("wrong_team_password", "Wrong password for this team.", 403)
        failed.team = team
        return failed

    # Password hashing is slow by design; do it before taking the write lock,
    # so joins (and guessing attempts) never stall heartbeats and solves.
    existing = db.execute("SELECT * FROM teams WHERE event_id = ? AND name = ?",
                          (event["id"], team_name)).fetchone()
    new_hash = None
    if existing is not None:
        # Cheap refusals first: a disqualified team, or one at its instance
        # cap, must not be able to make the server hash anything.
        _cheap_refusals(db, existing, device)
        if not verify_password(existing["password_hash"], team_password):
            raise wrong_password(existing)
    else:
        if not event["allow_team_registration"]:
            raise CTFError("registration_closed",
                           "Team registration is closed. Ask the organiser to create your team.", 403)
        _check_new_team_password(team_name, team_password)
        _check_lookalike(db, event["id"], team_name)
        new_hash = hash_password(team_password)

    with transaction(db):
        team = db.execute("SELECT * FROM teams WHERE event_id = ? AND name = ?",
                          (event["id"], team_name)).fetchone()
        if team is None:
            if existing is not None:
                # Deleted between the check and the lock: do not silently
                # recreate it without the new-team checks.
                raise CTFError("busy", "The team changed meanwhile. Try again.", 503)
            _check_lookalike(db, event["id"], team_name)   # again under the lock: two at once
            cur = db.execute(
                "INSERT INTO teams (event_id, name, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (event["id"], team_name, new_hash, now()))
            team = db.execute("SELECT * FROM teams WHERE id = ?", (cur.lastrowid,)).fetchone()
        elif existing is None:
            # Created by someone else between the check and the lock: that
            # path skipped the checks for joining. Let the caller retry.
            raise CTFError("busy", "The team was just created by someone else. Try again.", 503)
        elif team["password_hash"] != existing["password_hash"]:
            # Password changed between the check and the lock (rare). Verifying
            # again would hash under the write lock; let the caller retry.
            raise CTFError("busy", "The team changed meanwhile. Try again.", 503)
        if team["banned"]:
            raise CTFError("team_banned", "This team has been disqualified.", 403)
        instance_id, uid_teams = _add_instance(db, team, device, "device")
    return instance_id, event, team, uid_teams


def assign(db, device, team_id):
    """
    The organiser puts a device into a team, no password needed. Returns
    (instance_id, event, team, uid_teams).
    """
    team = db.execute("SELECT * FROM teams WHERE id = ?", (team_id,)).fetchone()
    if team is None:
        raise CTFError("not_found", "Unknown team.", 404)
    event = get_event(db, team["event_id"])
    if event["state"] == "finished":
        raise CTFError("event_finished", "This event has finished.", 409)
    if device["retired"]:
        raise CTFError("device_retired", "This device is retired. Bring it back first.", 409)
    with transaction(db):
        _cheap_refusals(db, team, device)
        instance_id, uid_teams = _add_instance(db, team, device, "organiser")
    return instance_id, event, team, uid_teams


def participation(db, device_id):
    """The device's live instance with its team and event, or None."""
    return db.execute("""
        SELECT i.id AS instance_id, i.device_id, t.id AS team_id, t.name AS team_name, t.banned,
               e.id AS event_id
        FROM instances i JOIN teams t ON t.id = i.team_id JOIN events e ON e.id = t.event_id
        WHERE i.device_id = ? AND i.revoked = 0
        ORDER BY i.joined_at DESC LIMIT 1""", (device_id,)).fetchone()


def leave(db, device_id):
    """The device leaves its event."""
    db.execute("UPDATE instances SET revoked = 1 WHERE device_id = ? AND revoked = 0", (device_id,))


def revoke_instance(db, instance_id):
    db.execute("UPDATE instances SET revoked = 1 WHERE id = ?", (instance_id,))


def set_team_banned(db, team_id, banned):
    db.execute("UPDATE teams SET banned = ? WHERE id = ?", (int(bool(banned)), team_id))


def delete_team(db, team_id):
    db.execute("DELETE FROM teams WHERE id = ?", (team_id,))


def _check_new_team_password(team_name, password):
    if not password or not TEAM_PASSWORD_MIN <= len(password) <= 128:
        raise CTFError("invalid_team_password", f"Team password must be {TEAM_PASSWORD_MIN}-128 characters.")
    folded = password.casefold()
    if folded in COMMON_PASSWORDS or folded == team_name.casefold() or len(set(folded)) < 3:
        raise CTFError("weak_team_password", "That team password is too easy to guess. Pick another one.")


def create_team(db, event_id, name, password):
    name = _validate_team_name(_text(name, "name"))
    _check_new_team_password(name, password)
    password_hash = hash_password(password)   # slow: outside the write lock
    with transaction(db):
        if db.execute("SELECT 1 FROM teams WHERE event_id = ? AND name = ?", (event_id, name)).fetchone():
            raise CTFError("team_exists", f"Team '{name}' already exists.", 409)
        _check_lookalike(db, event_id, name)
        cur = db.execute("INSERT INTO teams (event_id, name, password_hash, created_at) VALUES (?, ?, ?, ?)",
                         (event_id, name, password_hash, now()))
    return db.execute("SELECT * FROM teams WHERE id = ?", (cur.lastrowid,)).fetchone()


def set_team_password(db, team_id, password):
    name = db.execute("SELECT name FROM teams WHERE id = ?", (team_id,)).fetchone()
    _check_new_team_password(name["name"] if name else "", password)
    password_hash = hash_password(password)
    db.execute("UPDATE teams SET password_hash = ? WHERE id = ?", (password_hash, team_id))


# ---------- solves ----------

def submit_solve(db, auth, challenge_key, flag, client_time, remote_addr):
    """
    Record a solve a device reports for its team. Returns (result, points,
    first blood bonus).

    Every call lands in the submissions audit log. The score uses the server's
    receive time; the device's clock is kept for information only, since its
    owner controls it.
    """
    challenge_key = _text(challenge_key, "challenge_id")[:64]
    flag = _text(flag, "flag")[:256]
    client_time = _client_time(client_time)
    bonus = 0

    with transaction(db):
        event = get_event(db, auth["event_id"])
        challenge = db.execute(
            f"SELECT * FROM challenges WHERE event_id = ? AND key = ? AND {ACTIVE}",
            (event["id"], challenge_key)).fetchone()
        points = 0
        if event["state"] != "running":
            result = EVENT_NOT_RUNNING
        elif challenge is None:
            result = UNKNOWN_CHALLENGE
        elif not flag_matches(flag, challenge["flag_hash"]):
            result = INVALID_FLAG
        else:
            cur = db.execute("""
                INSERT INTO solves (team_id, challenge_id, instance_id, client_time, received_at)
                VALUES (?, ?, ?, ?, ?) ON CONFLICT (team_id, challenge_id) DO NOTHING""",
                             (auth["team_id"], challenge["id"], auth["instance_id"], client_time, now()))
            result = ACCEPTED if cur.rowcount else DUPLICATE
            points = challenge["points"] if result == ACCEPTED else 0
            if result == ACCEPTED and event["first_blood_bonus"] and not db.execute(f"""
                    SELECT 1 FROM solves s JOIN teams t ON t.id = s.team_id
                    WHERE s.challenge_id = ? AND s.id != ? AND {COUNTING_SOLVE}""",
                    (challenge["id"], cur.lastrowid)).fetchone():
                bonus = first_blood_points(points, event["first_blood_bonus"])
        db.execute("""
            INSERT INTO submissions (event_id, team_id, team_name, instance_id, device_id, challenge_key,
                                     result, remote_addr, received_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                   (event["id"], auth["team_id"], auth["team_name"], auth["instance_id"], auth["device_id"],
                    challenge_key, result, remote_addr, now()))
    return result, points, bonus


def record_failed_join(db, event_id, team_id, team_name, device_id, remote_addr):
    """A wrong team password goes to the audit log: repeated ones are a brute-force attempt."""
    db.execute("""
        INSERT INTO submissions (event_id, team_id, team_name, device_id, challenge_key, result, remote_addr,
                                 received_at)
        VALUES (?, ?, ?, ?, '(join)', 'wrong_team_password', ?, ?)""",
               (event_id, team_id, team_name, device_id, remote_addr, now()))


def team_solved_keys(db, team_id):
    """Every challenge on the team's record, voided ones included, so clients do not resend them."""
    return [r["key"] for r in db.execute("""
        SELECT c.key FROM solves s JOIN challenges c ON c.id = s.challenge_id
        WHERE s.team_id = ? ORDER BY s.received_at""", (team_id,))]


def set_solve_voided(db, solve_id, voided):
    """
    Void (or restore) a solve. A voided solve scores nothing but stays on the
    team's record: deleting it would only make the instance report it again.
    """
    db.execute("UPDATE solves SET voided = ? WHERE id = ?", (int(bool(voided)), solve_id))


# ---------- scoring ----------

def scoreboard(db, event_id):
    """
    Teams ranked by points, ties broken by who reached that score first
    (0-point solves do not move a team's time).

    Disabled challenges still count: disabling one mid-event must not take
    points away from teams that already solved it. Banned teams and voided
    solves are left out. With a first blood bonus, the first counting solve
    of each challenge earns that share of its points on top; if that solve is
    voided or its team disqualified, the bonus moves to the next one.
    """
    event = get_event(db, event_id)
    rows = db.execute(f"""
        WITH counting AS (
            SELECT s.id, s.team_id, s.challenge_id, s.received_at, c.points
            FROM solves s JOIN teams t ON t.id = s.team_id JOIN challenges c ON c.id = s.challenge_id
            WHERE t.event_id = :event AND {COUNTING_SOLVE}
        ), firsts AS (
            SELECT challenge_id, MIN(received_at) AS first_at FROM counting GROUP BY challenge_id
        )
        SELECT t.id, t.name,
               COALESCE(SUM(v.points + CASE WHEN v.received_at = f.first_at
                                            THEN v.points * :bonus / 100 ELSE 0 END), 0) AS score,
               COUNT(v.id) AS solves,
               MAX(CASE WHEN v.points > 0 THEN v.received_at END) AS last_solve
        FROM teams t
        LEFT JOIN counting v ON v.team_id = t.id
        LEFT JOIN firsts f ON f.challenge_id = v.challenge_id
        WHERE t.event_id = :event AND t.banned = 0
        GROUP BY t.id
        ORDER BY score DESC, last_solve IS NULL, last_solve ASC, t.name""",
                      {"event": event_id, "bonus": event["first_blood_bonus"] if event else 0}).fetchall()
    board, rank = [], 0
    for position, row in enumerate(rows, start=1):
        prev = board[-1] if board else None
        if not prev or (prev["score"], prev["last_solve"]) != (row["score"], row["last_solve"]):
            rank = position
        board.append({"rank": rank, "team_id": row["id"], "name": row["name"],
                      "score": row["score"], "solves": row["solves"], "last_solve": row["last_solve"]})
    return board


def recent_solves(db, event_id, limit=20, moderation=False, team_id=None, offset=0):
    """
    Latest solves, newest first. First blood only considers solves that count
    (no banned team, not voided). `moderation` also returns banned teams' and
    voided solves, for the admin view.
    """
    return db.execute("""
        SELECT s.id, s.received_at, s.client_time, s.voided, t.name AS team, t.id AS team_id,
               t.banned, c.key, c.title, c.points, d.kind, i.id AS instance_id, i.device_id, e.first_blood_bonus,
               s.voided = 0 AND t.banned = 0 AND s.received_at = (
                   SELECT MIN(s2.received_at) FROM solves s2 JOIN teams t2 ON t2.id = s2.team_id
                   WHERE s2.challenge_id = s.challenge_id AND s2.voided = 0 AND t2.banned = 0
               ) AS first_blood
        FROM solves s JOIN teams t ON t.id = s.team_id
        JOIN challenges c ON c.id = s.challenge_id
        JOIN events e ON e.id = t.event_id
        LEFT JOIN instances i ON i.id = s.instance_id
        LEFT JOIN devices d ON d.id = i.device_id
        WHERE t.event_id = :event AND (:moderation OR (t.banned = 0 AND s.voided = 0))
          AND (:team IS NULL OR t.id = :team)
        ORDER BY s.received_at DESC LIMIT :limit OFFSET :offset""",
                      {"event": event_id, "moderation": int(moderation), "limit": limit,
                       "team": team_id, "offset": offset}).fetchall()


# ---------- announcements ----------

def add_announcement(db, event_id, message):
    message = _text(message, "message", required=False).strip()
    if not message:
        raise CTFError("invalid_message", "Announcement must not be empty.")
    db.execute("INSERT INTO announcements (event_id, message, created_at) VALUES (?, ?, ?)",
               (event_id, message[:1000], now()))


def announcements_since(db, event_id, after_id=0):
    # Clamp to SQLite's integer range; a client sending 10**20 gets nothing new, not a 500.
    after_id = max(0, min(int(after_id), 2**63 - 1))
    return db.execute("""SELECT id, message, created_at FROM announcements
                         WHERE event_id = ? AND id > ? ORDER BY id""",
                      (event_id, after_id)).fetchall()


def announcement_ids(db, event_id):
    return [r["id"] for r in db.execute("SELECT id FROM announcements WHERE event_id = ? ORDER BY id",
                                        (event_id,))]


def delete_announcement(db, event_id, announcement_id):
    db.execute("DELETE FROM announcements WHERE id = ? AND event_id = ?", (announcement_id, event_id))
