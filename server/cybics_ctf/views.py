"""Template helpers, error pages and response headers shared by all HTML views."""
import datetime

from flask import render_template, request

from . import __version__
from .db import now
from .security import csrf_token, is_admin

# Both filters render values that may come from instances; a broken value must
# show as "-", never take the page down.

def _fmt_time(ts):
    try:
        return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return "-"


def _ago(ts):
    if ts is None:
        return "never"
    try:
        delta = int(now() - ts)
    except (TypeError, ValueError, OverflowError):
        return "-"
    if delta < -60:   # in the future: a broken clock, not "just now"
        return "-"
    delta = max(0, delta)
    for unit, size in (("d", 86400), ("h", 3600), ("min", 60)):
        if delta >= size:
            return f"{delta // size} {unit} ago"
    return f"{delta} s ago"


def init_app(app):
    app.jinja_env.filters["time"] = _fmt_time
    app.jinja_env.filters["ago"] = _ago

    @app.context_processor
    def _globals():
        return {"csrf_token": csrf_token, "app_version": __version__, "is_admin": is_admin,
                "server_name": app.config["SERVER_NAME_DISPLAY"]}

    @app.after_request
    def _headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        if response.mimetype == "text/html":
            # The scoreboard is meant to be embedded nowhere but a projector tab.
            response.headers.setdefault("X-Frame-Options", "DENY")
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
                "form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'")
        return response

    def _error_page(code, title):
        def handler(exc):
            if request.path.startswith("/api/"):
                from flask import jsonify
                return jsonify({"error": {"code": title.lower().replace(" ", "_"),
                                          "message": getattr(exc, "description", title)}}), code
            return render_template("error.html", code=code, title=title,
                                   message=getattr(exc, "description", "")), code
        return handler

    for code, title in ((400, "Bad Request"), (404, "Not Found"), (405, "Method Not Allowed"),
                        (413, "Payload Too Large"), (500, "Internal Server Error")):
        app.register_error_handler(code, _error_page(code, title))
