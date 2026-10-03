"""
Fleet domain logic: devices, groups and enrolment codes.

A device is one CybICS installation, a virtual stack on a laptop or one
board, and the lasting identity in the fleet (docs/MGMT_DESIGN.md). It is
never deleted, only retired. Devices come from two places:

- the fleet API (/api/v1/fleet/enroll): a native device with its own token;
- a CTF enrolment of a client that knows nothing of the fleet: the instance
  gets a *legacy* device, which mirrors the instance's status and offers no
  actions.

Kept free of request handling, like ctf/logic.py; every function takes the
connection explicitly. Nothing here imports the CTF part.
"""
import re
import uuid

from .. import device_input
from ..db import now, transaction
from ..errors import MgmtError
from ..security import hash_token, new_join_code, new_token

GROUP_NAME_RE = re.compile(r"^[A-Za-z0-9À-ÖØ-öø-ſ _.\-'()#&@/]{1,40}$")
LABEL_MAX = 40
NOTES_MAX = 500
VERSION_RE = re.compile(r"^v?(\d{1,4})\.(\d{1,4})(?:\.(\d{1,4}))?")


class FleetError(MgmtError):
    """A fleet request the caller can fix; carries an API error code and HTTP status."""


# ---------- groups ----------

def list_groups(db):
    return db.execute("""
        SELECT g.*, (SELECT COUNT(*) FROM devices d WHERE d.group_id = g.id AND d.retired = 0) AS devices
        FROM device_groups g ORDER BY g.name""").fetchall()


def create_group(db, name):
    name = " ".join(str(name or "").split())
    if not GROUP_NAME_RE.fullmatch(name):
        raise FleetError("invalid_group", "A group name has 1 to 40 letters, digits, spaces or . _ - ' ( ) # & @ /.")
    with transaction(db):
        if db.execute("SELECT 1 FROM device_groups WHERE name = ?", (name,)).fetchone():
            raise FleetError("group_exists", "A group with this name exists already.", 409)
        cur = db.execute("INSERT INTO device_groups (name, created_at) VALUES (?, ?)", (name, now()))
    return db.execute("SELECT * FROM device_groups WHERE id = ?", (cur.lastrowid,)).fetchone()


def delete_group(db, group_id):
    """Its devices and codes stay, without a group."""
    db.execute("DELETE FROM device_groups WHERE id = ?", (group_id,))


def _group_id(db, value):
    """A group id from a form value; '' means no group."""
    if value in (None, ""):
        return None
    try:
        group_id = int(str(value)[:9])
    except ValueError:
        raise FleetError("invalid_group", "Unknown group.") from None
    if not db.execute("SELECT 1 FROM device_groups WHERE id = ?", (group_id,)).fetchone():
        raise FleetError("invalid_group", "Unknown group.")
    return group_id


# ---------- enrolment codes ----------

def list_codes(db):
    return db.execute("""SELECT c.*, g.name AS group_name FROM enrol_codes c
                         LEFT JOIN device_groups g ON g.id = c.group_id
                         ORDER BY c.enabled DESC, c.created_at DESC""").fetchall()


def create_code(db, label, group_id):
    label = device_input.opt_str(" ".join(str(label or "").split()), LABEL_MAX) or ""
    group_id = _group_id(db, group_id)
    with transaction(db):
        while True:
            code = new_join_code()
            taken = db.execute("SELECT 1 FROM enrol_codes WHERE code = ? UNION ALL "
                               "SELECT 1 FROM events WHERE join_code = ?", (code, code)).fetchone()
            if not taken:
                break
        cur = db.execute("INSERT INTO enrol_codes (code, label, group_id, created_at) VALUES (?, ?, ?, ?)",
                         (code, label, group_id, now()))
    return db.execute("SELECT * FROM enrol_codes WHERE id = ?", (cur.lastrowid,)).fetchone()


def set_code_enabled(db, code_id, enabled):
    db.execute("UPDATE enrol_codes SET enabled = ? WHERE id = ?", (int(bool(enabled)), code_id))


def resolve_code(db, code):
    """
    The group a device enrolling with `code` joins, or a FleetError. An event's
    join code works too (no group), so participants type one code for both.
    """
    if not isinstance(code, str) or not device_input.encodable(code) or not code.strip():
        raise FleetError("invalid_code", "Unknown enrolment code.", 404)
    code = code.strip().upper()[:16]
    row = db.execute("SELECT * FROM enrol_codes WHERE code = ?", (code,)).fetchone()
    if row is not None:
        if not row["enabled"]:
            raise FleetError("code_disabled", "This enrolment code is disabled. Ask the organiser.", 403)
        return {"code_id": row["id"], "group_id": row["group_id"]}
    event = db.execute("SELECT state FROM events WHERE join_code = ?", (code,)).fetchone()
    if event is not None and event["state"] != "finished":
        return {"code_id": None, "group_id": None}
    raise FleetError("invalid_code", "Unknown enrolment code.", 404)


# ---------- legacy devices (CTF instances of fleet-unaware clients) ----------

def create_legacy_device(db, device_id, info, remote_addr):
    """A device for a CTF instance whose client knows nothing of the fleet. Call inside a transaction."""
    ts = now()
    db.execute("""
        INSERT INTO devices (id, kind, device_uid, hostname, cybics_version, mode, remote_addr,
                             legacy, enrolled_at, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
               (device_id, info["kind"], info["device_uid"], info["hostname"], info["cybics_version"],
                info["mode"], remote_addr, ts, ts))
    return device_id


def legacy_device_for(db, device_id):
    """`device_id` if it names a legacy device still in service, else None."""
    if not device_id:
        return None
    row = db.execute("SELECT id FROM devices WHERE id = ? AND legacy = 1 AND retired = 0",
                     (device_id,)).fetchone()
    return row["id"] if row else None


def refresh_legacy_device(db, device_id, info, remote_addr):
    """A legacy device enrolled again (a board re-enrolling in its team): take the new identity."""
    db.execute("""UPDATE devices SET hostname = ?, cybics_version = ?, mode = ?, remote_addr = ?, last_seen = ?
                  WHERE id = ? AND legacy = 1""",
               (info["hostname"], info["cybics_version"], info["mode"], remote_addr, now(), device_id))


def mirror_legacy_status(db, device_id, status_json, version, mode, remote_addr):
    """A CTF heartbeat of a legacy device. Native devices report through the fleet API instead."""
    db.execute("""UPDATE devices SET last_seen = ?, remote_addr = ?, status_json = COALESCE(?, status_json),
                      cybics_version = COALESCE(?, cybics_version), mode = COALESCE(?, mode)
                  WHERE id = ? AND legacy = 1""",
               (now(), remote_addr, status_json, version, mode, device_id))


# ---------- native devices ----------

def enroll_device(db, code, info, label, remote_addr):
    """
    Enrol a device through the fleet API. Returns (device_id, token, device);
    the token is shown exactly once, only its hash is stored.
    """
    target = resolve_code(db, code)
    info = device_input.device_info(info, lambda message: FleetError("invalid_device", message), "device")
    label = device_input.opt_str(" ".join(str(label or "").split()), LABEL_MAX) or ""
    device_id = str(uuid.uuid4())
    token = new_token()
    ts = now()
    with transaction(db):
        db.execute("""
            INSERT INTO devices (id, token_hash, label, group_id, kind, device_uid, hostname, cybics_version,
                                 mode, remote_addr, enrolled_at, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                   (device_id, hash_token(token), label, target["group_id"], info["kind"], info["device_uid"],
                    info["hostname"], info["cybics_version"], info["mode"], remote_addr, ts, ts))
        if target["code_id"] is not None:
            db.execute("UPDATE enrol_codes SET uses = uses + 1 WHERE id = ?", (target["code_id"],))
    return device_id, token, get_device(db, device_id)


def authenticate_device(db, token):
    """Resolve a device token to the device, or None (unknown, or retired)."""
    if not isinstance(token, str) or not token or not device_input.encodable(token):
        return None
    row = db.execute("SELECT * FROM devices WHERE token_hash = ?", (hash_token(token),)).fetchone()
    if row is None or row["retired"]:
        return None
    return row


def record_device_heartbeat(db, device_id, status, remote_addr):
    """Store the device's status; a heartbeat without one keeps the previous status."""
    info, status_json = device_input.clean_status(status)
    db.execute("""UPDATE devices SET last_seen = ?, remote_addr = ?, status_json = COALESCE(?, status_json),
                      cybics_version = COALESCE(?, cybics_version), mode = COALESCE(?, mode),
                      hostname = COALESCE(?, hostname)
                  WHERE id = ?""",
               (now(), remote_addr, status_json, device_input.opt_str(info.get("cybics_version"), 32),
                device_input.opt_str(info.get("mode"), 32), device_input.opt_str(info.get("hostname"), 64),
                device_id))


def leave(db, device_id):
    """The user switched fleet management off on the device."""
    db.execute("UPDATE devices SET retired = 1, retired_reason = 'left' WHERE id = ?", (device_id,))


# ---------- organiser ----------

def get_device(db, device_id):
    return db.execute("""SELECT d.*, g.name AS group_name FROM devices d
                         LEFT JOIN device_groups g ON g.id = d.group_id WHERE d.id = ?""",
                      (device_id,)).fetchone()


def update_device(db, device_id, label, group_id, notes):
    label = device_input.opt_str(" ".join(str(label or "").split()), LABEL_MAX) or ""
    notes = device_input.opt_str(str(notes or "").strip(), NOTES_MAX) or ""
    db.execute("UPDATE devices SET label = ?, group_id = ?, notes = ? WHERE id = ?",
               (label, _group_id(db, group_id), notes, device_id))


def set_retired(db, device_id, retired):
    """Retire (its token stops working, it leaves the list) or bring back a device."""
    db.execute("UPDATE devices SET retired = ?, retired_reason = ? WHERE id = ?",
               (int(bool(retired)), "organiser" if retired else None, device_id))


def device_instances(db, device_id):
    """The device's CTF participations, newest first."""
    return db.execute("""
        SELECT i.id, i.revoked, i.enrolled_at, i.last_seen, t.id AS team_id, t.name AS team,
               e.id AS event_id, e.name AS event
        FROM instances i JOIN teams t ON t.id = i.team_id JOIN events e ON e.id = t.event_id
        WHERE i.device_id = ? ORDER BY i.enrolled_at DESC LIMIT 50""", (device_id,)).fetchall()


def version_key(version):
    """(major, minor, patch) of a CybICS version string, or None if it is not one."""
    match = VERSION_RE.match(version or "")
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())


def list_devices(db, online_since, group_id=None, kind=None, include_gone=False):
    """
    Devices for the fleet page, newest check-in first, with derived fields:

    - state: "online", "offline", or "gone" (retired, or a legacy device whose
      CTF instance was revoked or deleted);
    - ctf: "team · event" of its live CTF instance, if any;
    - uid_devices: other devices in service claiming the same board UID
      (a hint that they are the same board, never acted on);
    - outdated: its version is older than the newest one in the fleet.
    """
    rows = db.execute("""
        SELECT d.*, g.name AS group_name,
            (SELECT t.name || ' · ' || e.name FROM instances i JOIN teams t ON t.id = i.team_id
             JOIN events e ON e.id = t.event_id WHERE i.device_id = d.id AND i.revoked = 0
             ORDER BY i.enrolled_at DESC LIMIT 1) AS ctf,
            EXISTS (SELECT 1 FROM instances i WHERE i.device_id = d.id AND i.revoked = 0) AS live_instance
        FROM devices d LEFT JOIN device_groups g ON g.id = d.group_id
        WHERE (:group IS NULL OR d.group_id = :group) AND (:kind IS NULL OR d.kind = :kind)
        ORDER BY d.last_seen DESC LIMIT 2000""", {"group": group_id, "kind": kind}).fetchall()
    devices = []
    for row in rows:
        device = dict(row)
        gone = device["retired"] or (device["legacy"] and not device["live_instance"])
        device["state"] = "gone" if gone else ("online" if (device["last_seen"] or 0) >= online_since
                                              else "offline")
        status = device_input.parse_status(device["status_json"])
        services = status.get("services") if isinstance(status.get("services"), dict) else {}
        device["services_up"] = sum(1 for v in services.values() if v)
        device["services_total"] = len(services)
        devices.append(device)
    in_service = [d for d in devices if d["state"] != "gone"]
    newest = max((k for k in (version_key(d["cybics_version"]) for d in in_service) if k), default=None)
    uids = {}
    for d in in_service:
        if d["device_uid"]:
            uids[d["device_uid"]] = uids.get(d["device_uid"], 0) + 1
    for d in devices:
        key = version_key(d["cybics_version"])
        d["outdated"] = bool(newest and key and key < newest)
        d["uid_devices"] = uids.get(d["device_uid"], 0) - (d["state"] != "gone") if d["device_uid"] else 0
    if not include_gone:
        devices = [d for d in devices if d["state"] != "gone"]
    return devices, newest
