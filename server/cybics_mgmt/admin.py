"""
Organiser UI (/admin). One shared admin password: MGMT_ADMIN_PASSWORD, or, if
that is not set, the one the first visit sets in the browser (stored as a
hash). Every form that changes state carries a CSRF token. This module holds the blueprint,
login and what every admin page shares; the CTF pages live in ctf/admin.py.
"""
import csv
import io
from urllib.parse import parse_qsl, urlsplit

from flask import Blueprint, Response, current_app, flash, redirect, render_template, request, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.routing import RequestRedirect as RoutingRequestRedirect

from . import host
from .db import get_db, now, transaction
from .errors import MgmtError
from .security import (
    ADMIN_PASSWORD_MIN,
    HashingBusy,
    admin_required,
    admin_setup_needed,
    audit,
    check_admin_password,
    check_csrf,
    client_ip,
    end_admin_session,
    hash_token,
    is_admin,
    limiter,
    set_admin_password,
    start_admin_session,
)

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.context_processor
def _host_warning():
    # On the Raspberry Pi image: every admin page warns while pi / raspberry still works.
    return {"pi_default_password": bool(host.directory()) and host.status()["pi_default_password"] is True}


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
    if admin_setup_needed():
        return redirect(url_for("admin.setup"))
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
    if not endpoint.startswith("admin.") or endpoint in ("admin.login", "admin.login_link_page", "admin.setup"):
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


def _password_problem(password, confirm):
    """Why a new admin password is not acceptable, or None."""
    from .ctf.logic import COMMON_PASSWORDS
    if password != confirm:
        return "The two passwords differ."
    if len(password) < ADMIN_PASSWORD_MIN:
        return f"The admin password needs at least {ADMIN_PASSWORD_MIN} characters."
    if len(password) > 256:
        return "The admin password may have at most 256 characters."
    if password.lower() in COMMON_PASSWORDS or len(set(password)) == 1:
        return "This password is too easy to guess."
    return None


@bp.route("/setup", methods=["GET", "POST"])
def setup():
    """
    The first visit sets the admin password, unless MGMT_ADMIN_PASSWORD is set.
    Whoever comes first decides: set it before participants join the network,
    or set MGMT_ADMIN_PASSWORD (ADMIN_PASSWORD in the Pi's cybics-mgmt.txt).
    """
    if not admin_setup_needed():
        return redirect(url_for("admin.login"))
    if request.method == "POST":
        password = request.form.get("password", "")
        problem = _password_problem(password, request.form.get("confirm", ""))
        if problem:
            flash(problem, "error")
        elif not set_admin_password(password, first=True):
            flash("Somebody set the admin password a moment ago. Log in with it.", "error")
            return redirect(url_for("admin.login"))
        else:
            start_admin_session()
            audit("admin_password_set")
            flash("Admin password set. You are logged in.", "ok")
            return redirect(url_for("admin.events"))
    return render_template("admin/setup.html", minimum=ADMIN_PASSWORD_MIN)


@bp.route("/password", methods=["GET", "POST"])
@admin_required
def password():
    """
    The admin password (when set in the browser; every other session ends on a
    change) and, on the Raspberry Pi image, the password of its pi account.
    """
    from_env = bool(current_app.config.get("ADMIN_PASSWORD"))
    if request.method == "POST":
        target = request.form.get("target")
        new, confirm = request.form.get("password", ""), request.form.get("confirm", "")
        if target == "admin" and not from_env:
            problem = _password_problem(new, confirm)
            if not check_admin_password(request.form.get("current", "")):
                flash("The current password is wrong.", "error")
            elif problem:
                flash(problem, "error")
            else:
                set_admin_password(new)
                start_admin_session()   # the old fingerprint ended every session, this one included
                audit("admin_password_changed")
                flash("Admin password changed. Every other session has ended.", "ok")
        elif target == "pi" and host.directory():
            problem = host.pi_password_problem(new, confirm)
            if problem:
                flash(problem, "error")
            else:
                host.request_pi_password(new)
                audit("pi_password_requested")
                flash("Sent to the Raspberry Pi; it applies the new password in a moment.", "ok")
        return redirect(url_for("admin.password"))
    return render_template("admin/password.html", from_env=from_env, minimum=ADMIN_PASSWORD_MIN,
                           host=host.status() if host.directory() else None, pi_minimum=host.PI_PASSWORD_MIN)


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
