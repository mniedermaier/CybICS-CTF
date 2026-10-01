"""Public pages: the event list and the projector-friendly scoreboard."""
from flask import Blueprint, abort, current_app, render_template, send_from_directory

from . import ctf
from .api import public_board, public_scoreboard
from .db import get_db

bp = Blueprint("public", __name__)


@bp.get("/")
def index():
    events = [e for e in ctf.list_events(get_db()) if public_scoreboard(e)]
    return render_template("index.html", events=events)


@bp.get("/scoreboard/<slug>")
def scoreboard(slug):
    db = get_db()
    event = ctf.get_event_by_slug(db, slug)
    if not public_scoreboard(event):
        abort(404)
    board, recent = public_board(db, event)
    return render_template("scoreboard.html", event=event, board=board, recent=recent)


@bp.get("/favicon.ico")
def favicon():
    return send_from_directory(current_app.static_folder, "img/favicon.ico",
                               mimetype="image/vnd.microsoft.icon", max_age=86400)


@bp.get("/healthz")
def healthz():
    get_db().execute("SELECT 1").fetchone()
    return {"status": "ok"}
