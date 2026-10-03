"""
The fleet endpoints of /api/v1: device enrolment, heartbeat and leaving.
The contract is documented in docs/API.md.
"""
import logging

from flask import current_app, jsonify, request

from ..api import bp, json_body, rate_limit
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


@bp.post("/fleet/enroll")
def fleet_enroll():
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
                log.warning("fleet enrol: unknown code from %s", client_ip())
        raise
    limiter.record(new_key)
    log.info("fleet enrol: %s device %s from %s", device["kind"], device_id[:8], client_ip())
    # The device pins this key and runs only jobs signed with it.
    return jsonify({"device_id": device_id, "token": token, "device": _device_json(device),
                    "signing_key": get_signer(current_app).public,
                    "heartbeat_interval": current_app.config["HEARTBEAT_INTERVAL"]}), 201


@bp.post("/fleet/heartbeat")
def fleet_heartbeat():
    device = authenticate()
    rate_limit(f"fleet-hb:{device['id']}", "RATE_LIMIT_HEARTBEAT")
    data = json_body()
    db = get_db()
    fleet.record_device_heartbeat(db, device["id"], data.get("status"), client_ip())
    jobs.record_management(db, device["id"], data.get("management"))
    for job in jobs.record_results(db, device["id"], data.get("job_results")):
        audit("fleet_job_finished", actor=f"device {device['id'][:8]}", job=job["id"], job_action=job["action"],
              state=job["state"], detail=job["detail"])
    device = fleet.get_device(db, device["id"])
    signer = get_signer(current_app)
    return jsonify({"device": _device_json(device),
                    "jobs": jobs.for_delivery(db, device, signer.fingerprint),
                    "signing_key_fingerprint": signer.fingerprint,
                    "heartbeat_interval": current_app.config["HEARTBEAT_INTERVAL"],
                    "server_time": now()})


@bp.post("/fleet/jobs/<job_id>/logs")
def fleet_job_logs(job_id):
    """The gzip log bundle of a collect_logs job, as the raw request body."""
    device = authenticate()
    rate_limit(f"fleet-logs:{device['id']}", "RATE_LIMIT_HEARTBEAT")
    jobs.store_logs(get_db(), device["id"], job_id, request.get_data(cache=False))
    return "", 204


@bp.delete("/fleet/device")
def fleet_leave():
    """The user switched fleet management off on the device."""
    device = authenticate()
    fleet.leave(get_db(), device["id"])
    log.info("fleet: device %s left", device["id"][:8])
    return "", 204
