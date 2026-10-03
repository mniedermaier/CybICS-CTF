"""
The device endpoints of /api/v1: enrolment, the heartbeat, job log uploads and
leaving. The contract is documented in docs/API.md.
"""
import logging

from flask import current_app, jsonify, request

from ..api import HEARTBEAT_PARTS, bp, json_body, rate_limit
from ..db import get_db, now
from ..security import audit, client_ip, limiter
from . import jobs
from . import logic as fleet
from .logic import FleetError
from .signing import get_signer

log = logging.getLogger("cybics_mgmt")


def _device_json(device):
    return {"id": device["id"], "label": device["label"], "group": device["group_name"]}


def authenticate():
    """The device behind the request's bearer token, or a 401."""
    header = request.headers.get("Authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    # Look the token up first: a valid token is never limited (shared NAT
    # addresses, docs/ARCHITECTURE.md).
    device = fleet.authenticate_device(get_db(), token)
    if device is None:
        limit, window = current_app.config["RATE_LIMIT_BAD_TOKEN"]
        if not limiter.hit(f"badtoken:{client_ip()}", limit, window):
            raise FleetError("rate_limited", "Too many requests with an invalid token.", 429)
        raise FleetError("unauthorized", "Unknown or retired device token.", 401)
    return device


@bp.post("/enroll")
def enroll():
    # Flood guards that count only provably bad requests and devices actually
    # created; the organiser sees and clears them (admin.LOCKOUTS).
    fail_key = f"enrolcode-fail:{client_ip()}"
    limit, window = current_app.config["RATE_LIMIT_ENROL_CODE"]
    if limiter.exceeded(fail_key, limit, window):
        raise FleetError("rate_limited", "Too many unknown enrolment codes from this address. Ask the organiser.",
                         429)
    new_key = f"newdevice:{client_ip()}"
    limit, window = current_app.config["RATE_LIMIT_NEW_DEVICES"]
    if limiter.exceeded(new_key, limit, window):
        raise FleetError("rate_limited", "Too many new devices from this address. Ask the organiser.", 429)
    data = json_body()
    db = get_db()
    try:
        device_id, token, device = fleet.enroll_device(db, data.get("code"), data.get("device"),
                                                       data.get("label"), client_ip())
    except FleetError as exc:
        if exc.code == "invalid_code":
            limiter.record(fail_key)
            if limiter.hit(f"audit-enrolcode:{client_ip()}", 1, 60):
                log.warning("enrol: unknown code from %s", client_ip())
        raise
    limiter.record(new_key)
    log.info("enrol: %s device %s from %s", device["kind"], device_id[:8], client_ip())
    # The device pins this key and runs only jobs signed with it.
    return jsonify({"device_id": device_id, "token": token, "device": _device_json(device),
                    "signing_key": get_signer(current_app).public,
                    "heartbeat_interval": current_app.config["HEARTBEAT_INTERVAL"]}), 201


@bp.post("/heartbeat")
def heartbeat():
    """
    Periodic check-in: stores the status and what the device allows, takes
    job results, and answers with open jobs and whatever the other parts add
    (the CTF part: the device's event, team and standing).
    """
    device = authenticate()
    rate_limit(f"hb:{device['id']}", "RATE_LIMIT_HEARTBEAT")
    data = json_body()
    db = get_db()
    fleet.record_device_heartbeat(db, device["id"], data.get("status"), client_ip())
    jobs.record_management(db, device["id"], data.get("management"))
    for job in jobs.record_results(db, device["id"], data.get("job_results")):
        audit("fleet_job_finished", actor=f"device {device['id'][:8]}", job=job["id"], job_action=job["action"],
              state=job["state"], detail=job["detail"])
    device = fleet.get_device(db, device["id"])
    signer = get_signer(current_app)
    answer = {"device": _device_json(device),
              "jobs": jobs.for_delivery(db, device, signer.fingerprint),
              "signing_key_fingerprint": signer.fingerprint,
              "heartbeat_interval": current_app.config["HEARTBEAT_INTERVAL"],
              "server_time": now()}
    for part in HEARTBEAT_PARTS:
        answer.update(part(db, device, data))
    return jsonify(answer)


@bp.post("/jobs/<job_id>/logs")
def job_logs(job_id):
    """The gzip log bundle of a collect_logs job, as the raw request body."""
    device = authenticate()
    rate_limit(f"fleet-logs:{device['id']}", "RATE_LIMIT_HEARTBEAT")
    jobs.store_logs(get_db(), device["id"], job_id, request.get_data(cache=False))
    return "", 204


@bp.delete("/device")
def leave():
    """The user disconnected the device from the server. It is retired, and leaves its event."""
    device = authenticate()
    fleet.leave(get_db(), device["id"])
    log.info("device %s left", device["id"][:8])
    return "", 204
