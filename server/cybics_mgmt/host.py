"""
Requests to the machine the server runs on, for the CybICS-mgmt Raspberry Pi
image only: setting the password of its "pi" account from the admin UI.

The server runs as a non-root user in a read-only container and cannot change
anything on the host itself. With MGMT_HOST_DIR set (the image mounts the
host's /run/cybics-mgmt there, a tmpfs, so a password never reaches the SD
card), it writes a request file; a root service on the host
(cybics-mgmt-host, started by a systemd path unit) applies it with chpasswd,
deletes it and answers in status.json. Without MGMT_HOST_DIR none of this
exists.
"""
import json
import os
import re

from flask import current_app

REQUEST = "pi-password.json"
STATUS = "status.json"
PI_PASSWORD_MIN = 8
PI_PASSWORD_MAX = 128


def directory():
    path = current_app.config.get("HOST_DIR") or ""
    return path if path and os.path.isdir(path) else None


def status():
    """What the host last reported: {"pi_default_password": bool|None, "last": {...}|None, "pending": bool}."""
    path = directory()
    result = {"pi_default_password": None, "last": None, "pending": False}
    if path is None:
        return result
    try:
        with open(os.path.join(path, STATUS), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError, RecursionError):
        data = {}
    if isinstance(data, dict):
        if isinstance(data.get("pi_default_password"), bool):
            result["pi_default_password"] = data["pi_default_password"]
        last = data.get("last")
        if isinstance(last, dict) and last.get("state") in ("done", "failed"):
            result["last"] = {"state": last["state"], "detail": str(last.get("detail") or "")[:200],
                              "time": last.get("time") if isinstance(last.get("time"), (int, float)) else None}
    result["pending"] = os.path.exists(os.path.join(path, REQUEST))
    return result


def pi_password_problem(password, confirm):
    """Why `password` cannot become the pi account's password, or None."""
    if password != confirm:
        return "The two passwords differ."
    if not PI_PASSWORD_MIN <= len(password) <= PI_PASSWORD_MAX:
        return f"The password needs {PI_PASSWORD_MIN} to {PI_PASSWORD_MAX} characters."
    if re.search(r"[\x00-\x1f\x7f]", password):
        return "The password may not contain control characters."
    if password == "raspberry" or len(set(password)) == 1:  # noqa: S105 (the image's published default)
        return "This password is too easy to guess."
    return None


def request_pi_password(password):
    """Hand the new password to the host. The file is private and appears atomically."""
    path = directory()
    if path is None:
        raise RuntimeError("No host directory: this server does not run on the CybICS-mgmt Raspberry Pi image.")
    tmp = os.path.join(path, f".{REQUEST}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"user": "pi", "password": password}, f)
    os.replace(tmp, os.path.join(path, REQUEST))
