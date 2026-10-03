"""
Organiser UI (/admin). One shared admin password (MGMT_ADMIN_PASSWORD); every
form that changes state carries a CSRF token. This module holds the blueprint,
login and what every admin page shares; the CTF pages live in ctf/admin.py.
"""
import csv
import io
from urllib.parse import parse_qsl, urlsplit

from flask import Blueprint, Response, current_app, flash, redirect, render_template, request, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.routing import RequestRedirect as RoutingRequestRedirect

from .db import get_db, now, transaction
from .errors import MgmtError
from .security import (
    HashingBusy,
    admin_required,
    audit,
    check_admin_password,
    check_csrf,
    client_ip,
    end_admin_session,
    hash_token,
    is_admin,
    limiter,
    start_admin_session,
)

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.before_request
def _csrf():
    # The login form carries a token too (from the anonymous session), so a
    # third-party page cannot log the organiser's browser into this server.
    if request.method == "POST":
        check_csrf()


@bp.errorhandler(HashingBusy)
def _busy(_exc):
    flash("The server is busy hashing passwords. Try again in a few seconds.", "error")
    return _back_here()


@bp.errorhandler(MgmtError)
def _mgmt_error(exc):
    flash(exc.message, "error")
    return _back_here()


# ---------- login ----------

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Only failures count. A lockout still blocks a correct password, or it
        # would tell a guesser when they got it right; an organiser locked out
        # by a participant on the same address gets in with a one-time link
        # from `flask --app cybics_mgmt login-link` instead.
        limit, window = current_app.config["RATE_LIMIT_LOGIN"]
        key = f"login:{client_ip()}"
        if limiter.exceeded(key, limit, window):
            # Log the lockout once per address and window, not every attempt:
            # a flood must not bury the organiser log.
            if limiter.hit(f"audit-lockout:{client_ip()}", 1, window):
                audit("login_rate_limited")
            flash("Too many failed logins from this address. Wait a few minutes, or use a one-time "
                  "login link (see the README).", "error")
        elif check_admin_password(request.form.get("password", "")):
            start_admin_session()
            audit("login")
            return redirect(_safe_next(request.args.get("next", "")))
        else:
            limiter.record(key)
            audit("login_failed")
            flash("Wrong password.", "error")
    return render_template("admin/login.html")


def _safe_next(target):
    """
    A redirect target inside the admin area, rebuilt from our own routing
    table: the result is always a URL that url_for() generated for an admin
    page, never the client's string, whatever a browser would make of it.
    """
    fallback = url_for("admin.events")
    if not isinstance(target, str) or any(ord(c) < 0x21 or c == "\\" for c in target):
        return fallback
    parts = urlsplit(target)
    if parts.scheme or parts.netloc or not parts.path.startswith("/admin/"):
        return fallback
    try:
        endpoint, values = current_app.url_map.bind("localhost").match(parts.path, method="GET")
    except (HTTPException, RoutingRequestRedirect):
        return fallback
    if not endpoint.startswith("admin.") or endpoint in ("admin.login", "admin.login_link_page"):
        return fallback
    # Built from a dict, not url_for(**kwargs): a query key such as "endpoint"
    # would otherwise be read as one of url_for's own arguments. No admin page
    # uses "_" keys, so those are dropped rather than carried along.
    query = {k: v for k, v in parse_qsl(parts.query) if not k.startswith("_")}
    return current_app.create_url_adapter(request).build(endpoint, {**query, **values})


def _back_here():
    """Back to the admin page the form came from (same site only), else the event list."""
    parts = urlsplit(request.referrer or "")
    return redirect(_safe_next(parts.path + ("?" + parts.query if parts.query else "")))


@bp.get("/login/link/<token>")
def login_link_page(token):
    """
    Confirmation page for a login link. Opening it changes nothing, so a chat
    or mail link preview cannot use the link up before the organiser does.
    """
    return render_template("admin/login_link.html", token=token)


@bp.post("/login/link/<token>")
def login_link(token):
    """Single-use login from `flask --app cybics_mgmt login-link`. Not rate limited: 256-bit tokens."""
    db = get_db()
    with transaction(db):
        cur = db.execute("""UPDATE login_links SET used_at = ?
                            WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?""",
                         (now(), hash_token(token), now()))
    if cur.rowcount != 1:
        flash("This login link is invalid, expired or already used.", "error")
        return redirect(url_for("admin.login"))
    start_admin_session()
    audit("login_link")
    return redirect(url_for("admin.events"))


@bp.post("/logout")
def logout():
    if is_admin():   # anonymous POSTs must not be able to write the log
        audit("logout")
    end_admin_session()
    return redirect(url_for("public.index"))


# Per-address limits that can lock people out. Shown to the organiser, who can
# clear them: behind a shared NAT address, one participant can trip them for
# the whole room (docs/ARCHITECTURE.md, "Shared addresses").
LOCKOUTS = (
    ("join-fail:", "RATE_LIMIT_JOIN", "wrong team passwords"),
    ("newteam:", "RATE_LIMIT_NEW_TEAMS", "new teams"),
    ("badtoken:", "RATE_LIMIT_BAD_TOKEN", "unknown device tokens"),
    ("enrolcode-fail:", "RATE_LIMIT_ENROL_CODE", "unknown enrolment codes"),
    ("newdevice:", "RATE_LIMIT_NEW_DEVICES", "new devices"),
    ("login:", "RATE_LIMIT_LOGIN", "failed admin logins"),
)


def lockouts():
    found = []
    for prefix, setting, what in LOCKOUTS:
        limit, window = current_app.config[setting]
        found += [{"address": addr, "what": what} for addr in limiter.tripped(prefix, limit, window)]
    return found


@bp.post("/lockouts/clear")
@admin_required
def clear_lockouts():
    cleared = lockouts()
    limiter.clear_prefixes([prefix for prefix, _, _ in LOCKOUTS])
    audit("clear_lockouts", lockouts=len(cleared))
    flash(f"Cleared {len(cleared)} lockout(s).", "ok")
    return redirect(url_for("admin.events"))


def csv_response(filename, header, rows):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(header)
    for row in rows:
        # Neutralise spreadsheet formulas: team names come from participants.
        writer.writerow(["'" + v if isinstance(v, str) and v and v[0] in "=+-@\t\r" else v for v in row])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})
