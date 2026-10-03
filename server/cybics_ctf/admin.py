"""
Organiser UI (/admin). One shared admin password (CTF_ADMIN_PASSWORD); every
form that changes state carries a CSRF token.
"""
import csv
import io
import json
from urllib.parse import parse_qsl, urlsplit

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.routing import RequestRedirect as RoutingRequestRedirect

from . import ctf
from .api import invalidate_board
from .ctf import CTFError
from .db import get_db, now, transaction
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


@bp.after_request
def _fresh_board(response):
    # Any organiser change (void, ban, points, state, ...) may move the board;
    # admin writes are rare, so simply drop the scoreboard cache after each.
    if request.method == "POST":
        invalidate_board()
    return response


def _event_or_404(event_id):
    event = ctf.get_event(get_db(), event_id)
    if event is None:
        abort(404)
    return event


def _owned(table, row_id, event_id):
    """Make sure a team/instance/solve id posted to an event page belongs to that event."""
    queries = {
        "teams": "SELECT 1 FROM teams WHERE id = ? AND event_id = ?",
        "instances": """SELECT 1 FROM instances i JOIN teams t ON t.id = i.team_id
                        WHERE i.id = ? AND t.event_id = ?""",
        "solves": """SELECT 1 FROM solves s JOIN teams t ON t.id = s.team_id
                     WHERE s.id = ? AND t.event_id = ?""",
    }
    if not get_db().execute(queries[table], (row_id, event_id)).fetchone():
        abort(404)


def _back(event_id, page="event"):
    return redirect(url_for(f"admin.{page}", event_id=event_id))


@bp.errorhandler(HashingBusy)
def _busy(_exc):
    flash("The server is busy hashing passwords. Try again in a few seconds.", "error")
    return _back_here()


@bp.errorhandler(CTFError)
def _ctf_error(exc):
    flash(exc.message, "error")
    return _back_here()


# ---------- login ----------

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Only failures count. A lockout still blocks a correct password, or it
        # would tell a guesser when they got it right; an organiser locked out
        # by a participant on the same address gets in with a one-time link
        # from `flask --app cybics_ctf login-link` instead.
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
    """Single-use login from `flask --app cybics_ctf login-link`. Not rate limited: 256-bit tokens."""
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


# ---------- events ----------

@bp.get("/")
@admin_required
def events():
    db = get_db()
    rows = []
    for event in ctf.list_events(db):
        counts = db.execute(f"""
            SELECT (SELECT COUNT(*) FROM teams WHERE event_id = :e) AS teams,
                   (SELECT COUNT(*) FROM instances i JOIN teams t ON t.id = i.team_id
                    WHERE t.event_id = :e AND i.revoked = 0) AS instances,
                   (SELECT COUNT(*) FROM challenges
                    WHERE event_id = :e AND {ctf.ACTIVE}) AS challenges
        """, {"e": event["id"]}).fetchone()
        rows.append((event, counts))
    logins = db.execute("""SELECT * FROM admin_log WHERE event_id IS NULL
                           ORDER BY created_at DESC LIMIT 20""").fetchall()
    return render_template("admin/events.html", rows=rows, logins=logins, lockouts=_lockouts())


# Per-address limits that can lock people out. Shown to the organiser, who can
# clear them: behind a shared NAT address, one participant can trip them for
# the whole room (docs/ARCHITECTURE.md, "Shared addresses").
LOCKOUTS = (
    ("enroll-fail:", "RATE_LIMIT_ENROLL", "wrong team passwords"),
    ("newteam:", "RATE_LIMIT_NEW_TEAMS", "new teams"),
    ("badtoken:", "RATE_LIMIT_BAD_TOKEN", "unknown instance tokens"),
    ("login:", "RATE_LIMIT_LOGIN", "failed admin logins"),
)


def _lockouts():
    found = []
    for prefix, setting, what in LOCKOUTS:
        limit, window = current_app.config[setting]
        found += [{"address": addr, "what": what} for addr in limiter.tripped(prefix, limit, window)]
    return found


@bp.post("/lockouts/clear")
@admin_required
def clear_lockouts():
    cleared = _lockouts()
    limiter.clear_prefixes([prefix for prefix, _, _ in LOCKOUTS])
    audit("clear_lockouts", lockouts=len(cleared))
    flash(f"Cleared {len(cleared)} lockout(s).", "ok")
    return redirect(url_for("admin.events"))


@bp.post("/events")
@admin_required
def create_event():
    event = ctf.create_event(get_db(), request.form.get("slug", ""), request.form.get("name", ""))
    audit("create_event", event_id=event["id"], slug=event["slug"])
    flash(f"Event created. Join code: {event['join_code']}", "ok")
    return _back(event["id"])


@bp.get("/events/<int:event_id>")
@admin_required
def event(event_id):
    db = get_db()
    event = _event_or_404(event_id)
    online_since = now() - current_app.config["ONLINE_WINDOW"]
    stats = db.execute("""
        SELECT COUNT(*) AS total,
               SUM(i.last_seen >= :since) AS online,
               SUM(i.kind = 'physical') AS physical
        FROM instances i JOIN teams t ON t.id = i.team_id
        WHERE t.event_id = :e AND i.revoked = 0""", {"e": event_id, "since": online_since}).fetchone()
    return render_template("admin/event.html", event=event, stats=stats,
                           challenge_count=len(ctf.list_challenges(db, event_id, enabled_only=True)),
                           board=ctf.scoreboard(db, event_id)[:10],
                           announcements=ctf.announcements_since(db, event_id),
                           transitions=ctf.TRANSITIONS)


@bp.post("/events/<int:event_id>/settings")
@admin_required
def event_settings(event_id):
    _event_or_404(event_id)
    try:
        bonus = int(request.form.get("first_blood_bonus", "0")[:4] or 0)
    except ValueError:
        raise CTFError("invalid_bonus", "The first blood bonus must be a number of percent.") from None
    ctf.update_event_settings(get_db(), event_id, request.form.get("name", ""),
                              "scoreboard_public" in request.form,
                              "allow_team_registration" in request.form, bonus)
    audit("event_settings", event_id=event_id, first_blood_bonus=bonus)
    flash("Settings saved.", "ok")
    return _back(event_id)


@bp.post("/events/<int:event_id>/state")
@admin_required
def event_state(event_id):
    _event_or_404(event_id)
    state = request.form.get("state", "")
    ctf.set_event_state(get_db(), event_id, state)
    audit("event_state", event_id=event_id, state=state)
    flash(f"Event is now {state}.", "ok")
    return _back(event_id)


@bp.post("/events/<int:event_id>/join-code")
@admin_required
def event_join_code(event_id):
    _event_or_404(event_id)
    ctf.regenerate_join_code(get_db(), event_id)
    audit("regenerate_join_code", event_id=event_id)
    flash("New join code generated. Enrolled instances are not affected.", "ok")
    return _back(event_id)


@bp.post("/events/<int:event_id>/delete")
@admin_required
def event_delete(event_id):
    event = _event_or_404(event_id)
    if request.form.get("confirm") != event["slug"]:
        flash("Type the event slug to confirm deletion.", "error")
        return _back(event_id)
    ctf.delete_event(get_db(), event_id)
    audit("delete_event", event_id=event_id, slug=event["slug"])
    flash(f"Event '{event['name']}' deleted.", "ok")
    return redirect(url_for("admin.events"))


@bp.post("/events/<int:event_id>/announcements")
@admin_required
def announce(event_id):
    _event_or_404(event_id)
    ctf.add_announcement(get_db(), event_id, request.form.get("message", ""))
    audit("announce", event_id=event_id)
    flash("Announcement sent; instances pick it up at their next heartbeat.", "ok")
    return _back(event_id)


@bp.post("/events/<int:event_id>/announcements/<int:announcement_id>/delete")
@admin_required
def announcement_delete(event_id, announcement_id):
    ctf.delete_announcement(get_db(), event_id, announcement_id)
    audit("delete_announcement", event_id=event_id, announcement_id=announcement_id)
    return _back(event_id)


# ---------- challenges ----------

@bp.get("/events/<int:event_id>/challenges")
@admin_required
def challenges(event_id):
    db = get_db()
    event = _event_or_404(event_id)
    solve_counts = {r["challenge_id"]: r["n"] for r in db.execute("""
        SELECT s.challenge_id, COUNT(*) AS n FROM solves s JOIN teams t ON t.id = s.team_id
        WHERE t.event_id = ? GROUP BY s.challenge_id""", (event_id,))}
    return render_template("admin/challenges.html", event=event,
                           challenges=ctf.list_challenges(db, event_id), solve_counts=solve_counts)


@bp.post("/events/<int:event_id>/catalog")
@admin_required
def catalog(event_id):
    _event_or_404(event_id)
    upload = request.files.get("catalog")
    if upload is None or not upload.filename:
        flash("Choose CybICS' software/landing/ctf_config.json to upload.", "error")
        return _back(event_id, "challenges")
    count = ctf.import_catalog(get_db(), event_id, upload.read())
    audit("import_catalog", event_id=event_id, challenges=count)
    flash(f"Imported {count} challenges.", "ok")
    return _back(event_id, "challenges")


@bp.post("/events/<int:event_id>/challenges/<int:challenge_id>")
@admin_required
def challenge_update(event_id, challenge_id):
    try:
        points = int(request.form.get("points", "")[:9])
    except ValueError:
        raise CTFError("invalid_points", "Points must be a number.") from None
    ctf.update_challenge(get_db(), event_id, challenge_id, points, "enabled" in request.form)
    audit("update_challenge", event_id=event_id, challenge_id=challenge_id, points=points,
          enabled="enabled" in request.form)
    flash("Challenge updated.", "ok")
    return _back(event_id, "challenges")


# ---------- teams ----------

@bp.get("/events/<int:event_id>/teams")
@admin_required
def teams(event_id):
    db = get_db()
    event = _event_or_404(event_id)
    teams = db.execute("""
        SELECT t.*,
            (SELECT COUNT(*) FROM instances i WHERE i.team_id = t.id AND i.revoked = 0) AS instances,
            (SELECT COUNT(*) FROM submissions s WHERE s.team_id = t.id
                AND s.result = 'invalid_flag') AS bad_submissions,
            (SELECT COUNT(*) FROM submissions s WHERE s.team_id = t.id
                AND s.result = 'wrong_team_password') AS failed_enrolments
        FROM teams t WHERE t.event_id = ? ORDER BY t.name""", (event_id,)).fetchall()
    scores = {e["team_id"]: e for e in ctf.scoreboard(db, event_id)}
    return render_template("admin/teams.html", event=event, teams=teams, scores=scores)


@bp.post("/events/<int:event_id>/teams")
@admin_required
def team_create(event_id):
    _event_or_404(event_id)
    ctf.create_team(get_db(), event_id, request.form.get("name", ""), request.form.get("password", ""))
    audit("create_team", event_id=event_id, team=request.form.get("name", ""))
    flash("Team created.", "ok")
    return _back(event_id, "teams")


@bp.post("/events/<int:event_id>/teams/bulk")
@admin_required
def teams_bulk(event_id):
    """Disqualify or delete several teams at once, e.g. after a junk-team flood."""
    _event_or_404(event_id)
    db = get_db()
    ids = [int(t) for t in request.form.getlist("team_id") if t.isdecimal() and t.isascii()]
    teams = db.execute(f"""SELECT id, name FROM teams WHERE event_id = ?
                           AND id IN ({",".join("?" * len(ids)) or "NULL"})""", (event_id, *ids)).fetchall()
    action = request.form.get("action")
    if not teams or action not in ("ban", "delete"):
        flash("Select teams and an action.", "error")
        return _back(event_id, "teams")
    if action == "delete" and request.form.get("confirm") != "DELETE":
        flash("Type DELETE to confirm deleting the selected teams.", "error")
        return _back(event_id, "teams")
    for team in teams:
        if action == "ban":
            ctf.set_team_banned(db, team["id"], True)
        else:
            ctf.delete_team(db, team["id"])
    audit(f"teams_bulk_{action}", event_id=event_id, teams=[t["name"] for t in teams])
    flash(f"{'Disqualified' if action == 'ban' else 'Deleted'} {len(teams)} team(s).", "ok")
    return _back(event_id, "teams")


@bp.post("/events/<int:event_id>/teams/<int:team_id>/<action>")
@admin_required
def team_action(event_id, team_id, action):
    _owned("teams", team_id, event_id)
    db = get_db()
    team = db.execute("SELECT name FROM teams WHERE id = ?", (team_id,)).fetchone()
    if action == "ban":
        ctf.set_team_banned(db, team_id, True)
        flash("Team disqualified; its instances are locked out.", "ok")
    elif action == "unban":
        ctf.set_team_banned(db, team_id, False)
        flash("Team reinstated.", "ok")
    elif action == "password":
        ctf.set_team_password(db, team_id, request.form.get("password", ""))
        flash("Team password changed.", "ok")
    elif action == "delete":
        if request.form.get("confirm", "").strip().lower() != team["name"].lower():
            flash("Type the team name to confirm deletion.", "error")
            return _back(event_id, "teams")
        ctf.delete_team(db, team_id)
        flash("Team deleted with its instances and solves. Its audit trail is kept.", "ok")
    else:
        abort(404)
    audit(f"team_{action}", event_id=event_id, team=team["name"])
    return _back(event_id, "teams")


# ---------- instances ----------

@bp.get("/events/<int:event_id>/instances")
@admin_required
def instances(event_id):
    db = get_db()
    event = _event_or_404(event_id)
    show_all = request.args.get("all") == "1"
    rows = db.execute(f"""
        SELECT i.*, t.name AS team,
            (SELECT COUNT(DISTINCT i2.team_id) FROM instances i2 JOIN teams t2 ON t2.id = i2.team_id
             WHERE i.device_uid IS NOT NULL AND i2.device_uid = i.device_uid AND i2.revoked = 0
               AND t2.event_id = t.event_id) AS uid_teams
        FROM instances i JOIN teams t ON t.id = i.team_id
        WHERE t.event_id = ? {"" if show_all else "AND i.revoked = 0"}
        ORDER BY i.revoked, t.name, i.enrolled_at LIMIT 1000""", (event_id,)).fetchall()
    revoked = db.execute("""SELECT COUNT(*) FROM instances i JOIN teams t ON t.id = i.team_id
                            WHERE t.event_id = ? AND i.revoked = 1""", (event_id,)).fetchone()[0]
    online_since = now() - current_app.config["ONLINE_WINDOW"]
    instances = []
    for row in rows:
        try:
            status = json.loads(row["status_json"] or "{}")
        except (ValueError, RecursionError):
            status = {}
        if not isinstance(status, dict):
            status = {}
        services = status.get("services") if isinstance(status.get("services"), dict) else {}
        instances.append({**dict(row), "online": (row["last_seen"] or 0) >= online_since,
                          "status_pretty": _pretty(status),
                          "services_up": sum(1 for v in services.values() if v),
                          "services_total": len(services), "status": status})
    return render_template("admin/instances.html", event=event, instances=instances,
                           show_all=show_all, revoked=revoked)


def _pretty(status):
    # Stored statuses are depth-checked, but rows from before that check may
    # not be; a broken status must never take the page down.
    try:
        return json.dumps(status, indent=2, sort_keys=True)[:4000]
    except (RecursionError, TypeError, ValueError):
        return "(status cannot be displayed)"


@bp.post("/events/<int:event_id>/instances/<instance_id>/revoke")
@admin_required
def instance_revoke(event_id, instance_id):
    _owned("instances", instance_id, event_id)
    ctf.revoke_instance(get_db(), instance_id)
    audit("revoke_instance", event_id=event_id, instance=instance_id)
    flash("Instance revoked. It has to enrol again to report.", "ok")
    return _back(event_id, "instances")


# ---------- solves and audit ----------

PAGE_SIZE = 200
# An event's log. Event ids can be reused after a delete, and the log outlives
# events on purpose; entries older than the event belong to its predecessor.
EVENT_LOG = "event_id = ? AND created_at >= ?"


def _int_arg(name, default=None):
    try:
        return max(0, int(request.args.get(name, "")[:9]))
    except ValueError:
        return default


@bp.get("/events/<int:event_id>/solves")
@admin_required
def solves(event_id):
    db = get_db()
    event = _event_or_404(event_id)
    team_id = _int_arg("team")
    page = _int_arg("page", 0)
    # Only wrong flags and wrong team passwords are suspicious: unknown_challenge
    # also happens honestly (a CybICS version with challenges this event lacks).
    suspicious = db.execute("""
        SELECT * FROM submissions
        WHERE event_id = ? AND result IN ('invalid_flag', 'wrong_team_password')
          AND (? IS NULL OR team_id = ?)
        ORDER BY received_at DESC LIMIT 200""", (event_id, team_id, team_id)).fetchall()
    rows = ctf.recent_solves(db, event_id, PAGE_SIZE + 1, moderation=True, team_id=team_id,
                             offset=page * PAGE_SIZE)
    teams = db.execute("SELECT id, name FROM teams WHERE event_id = ? ORDER BY name", (event_id,)).fetchall()
    return render_template("admin/solves.html", event=event, solves=rows[:PAGE_SIZE],
                           suspicious=suspicious, teams=teams, team_id=team_id, page=page,
                           has_more=len(rows) > PAGE_SIZE)


def _csv_response(filename, header, rows):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(header)
    for row in rows:
        # Neutralise spreadsheet formulas: team names come from participants.
        writer.writerow(["'" + v if isinstance(v, str) and v and v[0] in "=+-@\t\r" else v for v in row])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@bp.get("/events/<int:event_id>/export/<kind>.csv")
@admin_required
def export(event_id, kind):
    db = get_db()
    event = _event_or_404(event_id)
    if kind == "solves":
        rows = db.execute("""
            SELECT s.received_at, t.name, c.key, c.points, s.voided, t.banned, s.instance_id, s.client_time
            FROM solves s JOIN teams t ON t.id = s.team_id JOIN challenges c ON c.id = s.challenge_id
            WHERE t.event_id = ? ORDER BY s.received_at""", (event_id,))
        header = ["received_at", "team", "challenge", "points", "voided", "team_disqualified",
                  "instance_id", "instance_clock"]
    elif kind == "submissions":
        rows = db.execute("""
            SELECT received_at, team_name, challenge_key, result, remote_addr, instance_id
            FROM submissions WHERE event_id = ? ORDER BY received_at""", (event_id,))
        header = ["received_at", "team", "challenge", "result", "address", "instance_id"]
    elif kind == "log":
        rows = db.execute(f"""SELECT created_at, actor, action, details FROM admin_log
                              WHERE {EVENT_LOG} ORDER BY created_at""", (event_id, event["created_at"]))
        header = ["time", "actor", "action", "details"]
    else:
        abort(404)
    return _csv_response(f"{event['slug']}-{kind}.csv", header, (tuple(r) for r in rows))


@bp.get("/events/<int:event_id>/log")
@admin_required
def admin_log(event_id):
    event = _event_or_404(event_id)
    entries = get_db().execute(f"""SELECT * FROM admin_log WHERE {EVENT_LOG}
                                   ORDER BY created_at DESC LIMIT 1000""",
                               (event_id, event["created_at"])).fetchall()
    return render_template("admin/log.html", event=event, entries=entries)


@bp.post("/events/<int:event_id>/solves/<int:solve_id>/<action>")
@admin_required
def solve_action(event_id, solve_id, action):
    if action not in ("void", "restore"):
        abort(404)
    _owned("solves", solve_id, event_id)
    ctf.set_solve_voided(get_db(), solve_id, action == "void")
    audit(f"solve_{action}", event_id=event_id, solve_id=solve_id)
    flash("Solve voided: it no longer scores." if action == "void" else "Solve restored.", "ok")
    return _back(event_id, "solves")
