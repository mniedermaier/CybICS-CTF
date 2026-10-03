"""
The CTF pages of the organiser UI: events, challenges, teams, instances,
solves, the audit trail and exports.
"""
from flask import abort, current_app, flash, redirect, render_template, request, url_for

from .. import device_input
from ..admin import bp, csv_response, lockouts
from ..db import get_db, now
from ..fleet import logic as fleet
from ..security import admin_required, audit
from . import logic as ctf
from .api import invalidate_board
from .logic import CTFError


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
    # Fleet actions have no event either; they are on the fleet's own log page.
    logins = db.execute("""SELECT * FROM admin_log
                           WHERE event_id IS NULL AND action NOT LIKE 'fleet\\_%' ESCAPE '\\'
                           ORDER BY created_at DESC LIMIT 20""").fetchall()
    return render_template("admin/events.html", rows=rows, logins=logins, lockouts=lockouts())


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
               SUM(d.last_seen >= :since) AS online,
               SUM(d.kind = 'physical') AS physical
        FROM instances i JOIN teams t ON t.id = i.team_id JOIN devices d ON d.id = i.device_id
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
    flash("New join code generated. Devices already in the event stay.", "ok")
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
    flash("Announcement sent; devices pick it up at their next heartbeat.", "ok")
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
        flash("Team disqualified; its devices can no longer report solves.", "ok")
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
        flash("Team deleted with its solves; its devices left the event and stay in the fleet. "
              "Its audit trail is kept.", "ok")
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
        SELECT i.id, i.revoked, i.joined_at, i.joined_by, i.device_id, t.name AS team,
               d.kind, d.device_uid, d.hostname, d.label, d.cybics_version, d.mode, d.remote_addr,
               d.status_json, d.last_seen,
            (SELECT COUNT(DISTINCT i2.team_id) FROM instances i2 JOIN teams t2 ON t2.id = i2.team_id
             JOIN devices d2 ON d2.id = i2.device_id
             WHERE d.device_uid IS NOT NULL AND d2.device_uid = d.device_uid AND i2.revoked = 0
               AND t2.event_id = t.event_id) AS uid_teams
        FROM instances i JOIN teams t ON t.id = i.team_id JOIN devices d ON d.id = i.device_id
        WHERE t.event_id = ? {"" if show_all else "AND i.revoked = 0"}
        ORDER BY i.revoked, t.name, i.joined_at LIMIT 1000""", (event_id,)).fetchall()
    revoked = db.execute("""SELECT COUNT(*) FROM instances i JOIN teams t ON t.id = i.team_id
                            WHERE t.event_id = ? AND i.revoked = 1""", (event_id,)).fetchone()[0]
    online_since = now() - current_app.config["ONLINE_WINDOW"]
    instances = []
    for row in rows:
        status = device_input.parse_status(row["status_json"])
        services = status.get("services") if isinstance(status.get("services"), dict) else {}
        instances.append({**dict(row), "online": (row["last_seen"] or 0) >= online_since,
                          "status_pretty": device_input.pretty_status(status),
                          "services_up": sum(1 for v in services.values() if v),
                          "services_total": len(services), "status": status})
    return render_template("admin/instances.html", event=event, instances=instances,
                           show_all=show_all, revoked=revoked)


@bp.post("/events/<int:event_id>/instances/<instance_id>/revoke")
@admin_required
def instance_revoke(event_id, instance_id):
    _owned("instances", instance_id, event_id)
    ctf.revoke_instance(get_db(), instance_id)
    audit("revoke_instance", event_id=event_id, instance=instance_id)
    flash("The device left the event. It has to join again to report.", "ok")
    return _back(event_id, "instances")


# ---------- putting devices into teams (from the device's fleet page) ----------

@bp.post("/fleet/devices/<device_id>/ctf")
@admin_required
def device_assign(device_id):
    """Put a device into a team, or take it out of its event; no team password needed."""
    db = get_db()
    device = fleet.get_device(db, device_id)
    if device is None:
        abort(404)
    team_id = request.form.get("team", "")
    if team_id == "leave":
        ctf.leave(db, device_id)
        audit("fleet_device_leave_event", device=device_id)
        flash("The device left its event.", "ok")
    else:
        try:
            team_id = int(team_id[:9])
        except ValueError:
            raise CTFError("not_found", "Choose a team.", 404) from None
        _, event, team, uid_teams = ctf.assign(db, device, team_id)
        audit("fleet_device_assign", event_id=event["id"], device=device_id, team=team["name"])
        flash(f"The device is now in team {team['name']} of {event['name']}."
              + (f" Its board UID is also live in {', '.join(uid_teams)}." if uid_teams else ""), "ok")
    return redirect(url_for("admin.fleet_device", device_id=device_id))


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
    return csv_response(f"{event['slug']}-{kind}.csv", header, (tuple(r) for r in rows))


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
