"""The projector-friendly public scoreboard page."""
from flask import abort, render_template

from ..db import get_db
from ..public import bp
from . import logic as ctf
from .api import public_board, public_scoreboard


@bp.get("/scoreboard/<slug>")
def scoreboard(slug):
    db = get_db()
    event = ctf.get_event_by_slug(db, slug)
    if not public_scoreboard(event):
        abort(404)
    board, recent = public_board(db, event)
    return render_template("scoreboard.html", event=event, board=board, recent=recent)
