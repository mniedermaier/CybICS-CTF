"""Public pages: the start page, /healthz and /favicon.ico. The scoreboard is in ctf/public.py."""
from flask import Blueprint, current_app, render_template, send_from_directory

from .ctf import logic as ctf
from .ctf.api import public_scoreboard
from .db import get_db

bp = Blueprint("public", __name__)


@bp.get("/")
def index():
    events = [e for e in ctf.list_events(get_db()) if public_scoreboard(e)]
    return render_template("index.html", events=events)


@bp.get("/favicon.ico")
def favicon():
    return send_from_directory(current_app.static_folder, "img/favicon.ico",
                               mimetype="image/vnd.microsoft.icon", max_age=86400)


@bp.get("/healthz")
def healthz():
    get_db().execute("SELECT 1").fetchone()
    return {"status": "ok"}
