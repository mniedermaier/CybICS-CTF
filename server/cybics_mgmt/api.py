"""
JSON API for CybICS installations (/api/v1). The contract is documented in
docs/API.md. This module holds the blueprint and what every endpoint shares;
the device endpoints live in fleet/api.py, the CTF ones in ctf/api.py.

Devices authenticate with the bearer token they receive at enrolment. All
errors come back as {"error": {"code": ..., "message": ...}} so the landing
page can show the message to the user unchanged.
"""
from flask import Blueprint, current_app, jsonify, request

from . import __version__
from .db import now
from .errors import MgmtError
from .security import limiter

API_VERSION = 1

bp = Blueprint("api", __name__, url_prefix="/api/v1")

# Parts of the heartbeat answer that other parts of the server add: each is a
# callable (db, device, request body) -> dict merged into the answer. The CTF
# part adds "ctf" this way, so the fleet code never imports it.
HEARTBEAT_PARTS = []


@bp.errorhandler(MgmtError)
def _mgmt_error(exc):
    return error_response(exc.code, exc.message, exc.status)


def error_response(code, message, status):
    return jsonify({"error": {"code": code, "message": message}}), status


def json_body():
    try:
        data = request.get_json(silent=True)
    except RecursionError:   # absurdly nested JSON; silent=True only covers ValueError
        data = None
    if not isinstance(data, dict):
        raise MgmtError("invalid_json", "Request body must be a JSON object.")
    return data


def rate_limit(key, limit_name):
    limit, window = current_app.config[limit_name]
    if not limiter.hit(key, limit, window):
        raise MgmtError("rate_limited", "Too many requests, slow down.", 429)


@bp.get("/info")
def info():
    """Unauthenticated; the landing page's 'Test connection' button calls this."""
    return jsonify({"service": "cybics-mgmt", "name": current_app.config["SERVER_NAME_DISPLAY"],
                    "version": __version__, "api_version": API_VERSION, "server_time": now()})
