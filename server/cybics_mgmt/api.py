"""
JSON API for CybICS installations (/api/v1). The contract is documented in
docs/API.md. This module holds the blueprint and what every endpoint shares;
the CTF endpoints live in ctf/api.py.

Instances authenticate with the bearer token they receive at enrolment. All
errors come back as {"error": {"code": ..., "message": ...}} so the landing
page can show the message to the user unchanged.
"""
from flask import Blueprint, current_app, jsonify, request

from . import __version__
from .db import now
from .errors import MgmtError
from .security import limiter

API_VERSION = 1
# What this server offers, for clients that can use more than the CTF.
FEATURES = ("ctf",)

bp = Blueprint("api", __name__, url_prefix="/api/v1")


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
    """
    Unauthenticated; the landing page's 'Test connection' button calls this.
    Deployed clients check service == "cybics-ctf": it never changes in v1.
    """
    return jsonify({"service": "cybics-ctf", "product": "cybics-mgmt", "features": list(FEATURES),
                    "name": current_app.config["SERVER_NAME_DISPLAY"],
                    "version": __version__, "api_version": API_VERSION, "server_time": now()})
