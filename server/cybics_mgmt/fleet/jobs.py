"""
Fleet jobs: one allow-listed action for one device (docs/MGMT_DESIGN.md, "Jobs").

The rules this module keeps:

- only the actions in ACTIONS exist, each with validated parameters: no
  shell, no file write, no generic command;
- a job is created only for a device that runs a client with fleet support,
  allows the action, and pinned the key the server signs with;
- every job carries a sequence number that increases per device, and the
  server's signature over it, so a device can refuse replays and forgeries;
- a job not delivered within JOB_TTL expires;
- nothing a job carries is valid beyond the device.

Kept free of request handling; every function takes the connection.
"""
import json
import re
import uuid

from .. import device_input
from ..db import now, transaction
from .logic import FleetError

JOB_TTL = 24 * 3600
OPEN = ("pending", "delivered")
FINISHED = ("done", "failed", "refused")
DELIVER_MAX = 5
DETAIL_MAX = 500
LOGS_MAX = 256 * 1024
LOGS_KEEP = 5            # log bundles kept per device
SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")


def _identify(params):
    try:
        seconds = int(str(params.get("seconds", 60))[:5])
    except ValueError:
        raise FleetError("invalid_params", "Seconds must be a number.") from None
    return {"seconds": min(600, max(5, seconds))}


def _message(params):
    text = device_input.opt_str(str(params.get("text") or "").strip(), DETAIL_MAX)
    if not text:
        raise FleetError("invalid_params", "Write the message to show.")
    return {"text": text}


def _restart(params):
    service = str(params.get("service") or "all").strip().lower()
    if service != "all" and not SERVICE_RE.fullmatch(service):
        raise FleetError("invalid_params", "Restart 'all' or one service, e.g. 'openplc'.")
    return {"service": service}


def _none(_params):
    return {}


# action -> (label for the organiser, parameter check)
ACTIONS = {
    "identify": ("Identify: show a banner with the device's label", _identify),
    "message": ("Show a message on the landing page", _message),
    "restart": ("Restart CybICS services", _restart),
    "reset_progress": ("Reset the local CTF progress", _none),
    "collect_logs": ("Collect logs", _none),
}


def allowed_actions(device):
    """The actions the device allowed, as it last reported them."""
    try:
        allowed = json.loads(device["allowed_actions"] or "[]")
    except (ValueError, RecursionError):
        return []
    return [a for a in allowed if a in ACTIONS] if isinstance(allowed, list) else []


def record_management(db, device_id, management):
    """What the device reported about its management: allowed actions, pinned key, client version."""
    if not isinstance(management, dict):
        return
    allowed = management.get("allowed")
    allowed = sorted({a for a in allowed if isinstance(a, str) and a in ACTIONS}) if isinstance(allowed, list) else []
    fingerprint = management.get("key_fingerprint")
    if not (isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-f]{64}", fingerprint)):
        fingerprint = None
    db.execute("UPDATE devices SET allowed_actions = ?, key_fingerprint = ?, client_version = ? WHERE id = ?",
               (json.dumps(allowed), fingerprint, device_input.opt_str(management.get("client"), 32), device_id))


def why_not(device, action, signer_fingerprint):
    """None if a job with `action` can be created for the device, else the reason."""
    if action not in ACTIONS:
        return "unknown action"
    reason = device_problem(device, signer_fingerprint)
    if reason:
        return reason
    if action not in allowed_actions(device):
        return "the device does not allow this action"
    return None


def device_problem(device, signer_fingerprint):
    """None if the device can take jobs at all, else the reason."""
    if device["retired"]:
        return "the device is retired"
    if not device["key_fingerprint"]:
        return "the device has not reported its management settings yet"
    if device["key_fingerprint"] != signer_fingerprint:
        return "the device pinned another signing key; enrol it again"
    return None


def create_job(db, signer, device, action, params, created_by):
    """A signed job for the device, or a FleetError saying why not."""
    reason = why_not(device, action, signer.fingerprint)
    if reason:
        raise FleetError("not_allowed", f"Cannot send this to the device: {reason}.", 409)
    params = ACTIONS[action][1](params if isinstance(params, dict) else {})
    job_id = str(uuid.uuid4())
    with transaction(db):
        seq = db.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM jobs WHERE device_id = ?",
                         (device["id"],)).fetchone()[0]
        job = {"id": job_id, "device": device["id"], "seq": seq, "action": action, "params": params}
        db.execute("""INSERT INTO jobs (id, device_id, seq, action, params_json, signature, created_by, created_at)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                   (job_id, device["id"], seq, action, json.dumps(params), signer.sign(job), created_by, now()))
    return get_job(db, job_id)


def get_job(db, job_id):
    return db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()


def expire(db):
    db.execute(f"UPDATE jobs SET state = 'expired', finished_at = ? WHERE state IN {OPEN} AND created_at < ?",
               (now(), now() - JOB_TTL))


def for_delivery(db, device, signer_fingerprint):
    """
    The open jobs to put in the device's heartbeat answer, oldest first.
    Nothing while the device's pinned key is not the server's: it would
    refuse every one of them.
    """
    if device["key_fingerprint"] != signer_fingerprint:
        return []
    expire(db)
    rows = db.execute(f"""SELECT * FROM jobs WHERE device_id = ? AND state IN {OPEN}
                          ORDER BY seq LIMIT ?""", (device["id"], DELIVER_MAX)).fetchall()
    db.execute(f"""UPDATE jobs SET state = 'delivered', delivered_at = COALESCE(delivered_at, ?)
                   WHERE device_id = ? AND state = 'pending' AND id IN ({",".join("?" * len(rows)) or "NULL"})""",
               (now(), device["id"], *[r["id"] for r in rows]))
    return [{"id": r["id"], "device": r["device_id"], "seq": r["seq"], "action": r["action"],
             "params": json.loads(r["params_json"]), "signature": r["signature"]} for r in rows]


def record_results(db, device_id, results):
    """
    Results the device reports. Returns the jobs that finished now. A result
    for a job that was cancelled or expired still counts: the device ran it.
    Anything that is not a result for one of this device's jobs is ignored.
    """
    finished = []
    if not isinstance(results, list):
        return finished
    for result in results[:50]:
        if not isinstance(result, dict) or not isinstance(result.get("id"), str):
            continue
        state = result.get("state") if result.get("state") in FINISHED else "failed"
        detail = device_input.opt_str(result.get("detail"), DETAIL_MAX)
        if result.get("state") not in FINISHED:
            detail = f"unknown result {device_input.opt_str(result.get('state'), 32)!r}"
        cur = db.execute(f"""UPDATE jobs SET state = ?, detail = ?, finished_at = ?
                             WHERE id = ? AND device_id = ? AND state NOT IN {FINISHED}""",
                         (state, detail, now(), result["id"][:64], device_id))
        if cur.rowcount:
            finished.append(get_job(db, result["id"][:64]))
    return finished


def cancel(db, job_id):
    """Stop delivering an open job. A device that already has it may still run it."""
    cur = db.execute(f"UPDATE jobs SET state = 'cancelled', finished_at = ? WHERE id = ? AND state IN {OPEN}",
                     (now(), job_id))
    return cur.rowcount == 1


def list_jobs(db, device_id, limit=50):
    expire(db)
    return db.execute("""SELECT j.*, (SELECT size FROM job_logs l WHERE l.job_id = j.id) AS logs_size
                         FROM jobs j WHERE j.device_id = ? ORDER BY j.seq DESC LIMIT ?""",
                      (device_id, limit)).fetchall()


def store_logs(db, device_id, job_id, data):
    """A gzip log bundle for a collect_logs job of this device. Keeps the newest LOGS_KEEP per device."""
    job = db.execute("SELECT * FROM jobs WHERE id = ? AND device_id = ?", (job_id[:64], device_id)).fetchone()
    if job is None or job["action"] != "collect_logs":
        raise FleetError("not_found", "No such collect_logs job for this device.", 404)
    if len(data) > LOGS_MAX:
        raise FleetError("too_large", "A log bundle may be at most 256 KB.", 413)
    if not data.startswith(b"\x1f\x8b"):
        raise FleetError("invalid_logs", "A log bundle must be gzip compressed.")
    with transaction(db):
        if db.execute("SELECT 1 FROM job_logs WHERE job_id = ?", (job["id"],)).fetchone():
            raise FleetError("duplicate", "This job's logs were uploaded already.", 409)
        db.execute("INSERT INTO job_logs (job_id, device_id, size, content, created_at) VALUES (?, ?, ?, ?, ?)",
                   (job["id"], device_id, len(data), data, now()))
        db.execute("""DELETE FROM job_logs WHERE device_id = ? AND id NOT IN
                      (SELECT id FROM job_logs WHERE device_id = ? ORDER BY id DESC LIMIT ?)""",
                   (device_id, device_id, LOGS_KEEP))


def get_logs(db, job_id):
    return db.execute("SELECT * FROM job_logs WHERE job_id = ?", (job_id,)).fetchone()
