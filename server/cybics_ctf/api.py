"""
JSON API for CybICS instances (/api/v1). The contract is documented in docs/API.md.

Instances authenticate with the bearer token they receive at enrolment. All
errors come back as {"error": {"code": ..., "message": ...}} so the landing
page can show the message to the user unchanged.
"""
import logging
import threading
import time
import unicodedata

from flask import Blueprint, current_app, g, jsonify, request

from . import __version__, ctf
from .ctf import CTFError
from .db import get_db, now
from .security import HashingBusy, client_ip, limiter

log = logging.getLogger("cybics_ctf")

API_VERSION = 1

bp = Blueprint("api", __name__, url_prefix="/api/v1")


@bp.errorhandler(CTFError)
def _ctf_error(exc):
    return _error(exc.code, exc.message, exc.status)


def _error(code, message, status):
    return jsonify({"error": {"code": code, "message": message}}), status


def _json_body():
    try:
        data = request.get_json(silent=True)
    except RecursionError:   # absurdly nested JSON; silent=True only covers ValueError
        data = None
    if not isinstance(data, dict):
        raise CTFError("invalid_json", "Request body must be a JSON object.")
    return data


def _rate_limit(key, limit_name):
    limit, window = current_app.config[limit_name]
    if not limiter.hit(key, limit, window):
        raise CTFError("rate_limited", "Too many requests, slow down.", 429)


def _authenticate():
    header = request.headers.get("Authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    # Look the token up first (one indexed hash): a valid token is never
    # limited, so a participant spraying garbage tokens from a shared NAT
    # address cannot stall the honest instances behind the same address.
    auth = ctf.authenticate_instance(get_db(), token)
    if auth is None:
        limit, window = current_app.config["RATE_LIMIT_BAD_TOKEN"]
        if not limiter.hit(f"badtoken:{client_ip()}", limit, window):
            raise CTFError("rate_limited", "Too many requests with an invalid token.", 429)
        # 401 tells the client its enrolment is gone (revoked, event deleted)
        # and that it should stop sending until the user re-enrols.
        raise CTFError("unauthorized", "Unknown or revoked instance token.", 401)
    if auth["banned"]:
        raise CTFError("team_banned", "This team has been disqualified.", 403)
    g.auth = auth
    return auth


def public_scoreboard(event):
    """Drafts stay private even with a public scoreboard: team names should not leak before the start."""
    return event is not None and bool(event["scoreboard_public"]) and event["state"] != "draft"


def _event_json(event):
    # created_at tells a recreated event apart from an old one with the same slug.
    return {"name": event["name"], "slug": event["slug"], "state": event["state"],
            "created_at": event["created_at"],
            "started_at": event["started_at"], "finished_at": event["finished_at"],
            "scoreboard_public": bool(event["scoreboard_public"]),
            "first_blood_bonus": event["first_blood_bonus"]}


@bp.get("/info")
def info():
    """Unauthenticated; the landing page's 'Test connection' button calls this."""
    return jsonify({"service": "cybics-ctf", "name": current_app.config["SERVER_NAME_DISPLAY"],
                    "version": __version__, "api_version": API_VERSION, "server_time": now()})


@bp.post("/enroll")
def enroll():
    # Shared addresses: a whole classroom, the projector and the organiser
    # often sit behind one NAT address, so any per-address limit can be
    # tripped by one participant for everybody. The guard here only counts
    # wrong team passwords (which cost a hash), the organiser sees and clears
    # it in the admin UI, and nothing depends on it for security: team
    # passwords are at least 8 characters, and the bounded scrypt pool caps
    # guessing for the whole server.
    fail_key = f"enroll-fail:{client_ip()}"
    limit, window = current_app.config["RATE_LIMIT_ENROLL"]
    if limiter.exceeded(fail_key, limit, window):
        if limiter.hit(f"audit-enroll-lock:{client_ip()}", 1, window):
            log.warning("enrol: failure limit reached for %s", client_ip())
        raise CTFError("rate_limited", "Too many wrong team passwords from this address. Ask the organiser.", 429)
    db = get_db()
    newteam_key = f"newteam:{client_ip()}"
    creating = False
    try:
        data = _json_body()
        code, name = data.get("join_code"), data.get("team_name")
        event_row = ctf.get_event_by_join_code(db, code) if isinstance(code, str) and code.strip() else None
        norm_name = unicodedata.normalize("NFC", " ".join(name.split())) if isinstance(name, str) else ""
        # New teams per address: counted only when a team is actually created.
        creating = event_row is not None and bool(norm_name) and not db.execute(
            "SELECT 1 FROM teams WHERE event_id = ? AND name = ?", (event_row["id"], norm_name)).fetchone()
        limit, window = current_app.config["RATE_LIMIT_NEW_TEAMS"]
        if creating and limiter.exceeded(newteam_key, limit, window):
            raise CTFError("rate_limited", "Too many new teams from this address. Join an existing team "
                                           "or ask the organiser.", 429)
        instance_id, token, event, team, uid_teams = ctf.enroll(
            db, data.get("join_code"), data.get("team_name"), data.get("team_password"),
            data.get("instance"), client_ip())
    except HashingBusy:
        raise CTFError("busy", "The server is busy with other enrolments. Try again in a few seconds.",
                       503) from None
    except CTFError as exc:
        # Only wrong team passwords count: they cost a hash. Malformed requests
        # and unknown join codes cost nothing, and counting them would let
        # anyone switch off enrolment for a whole NAT address with garbage.
        if exc.code == "wrong_team_password":
            limiter.record(fail_key)
            ctf.record_failed_enrolment(db, exc.team["event_id"], exc.team["id"], exc.team["name"],
                                        client_ip())
            log.warning("enrol: wrong password for team %r from %s", exc.team["name"], client_ip())
        elif exc.code == "invalid_join_code":
            # Once per address and minute: enough to spot someone probing
            # codes or tripping the guard, without letting them flood the log.
            if limiter.hit(f"audit-joincode:{client_ip()}", 1, 60):
                log.warning("enrol: unknown join code from %s", client_ip())
        elif exc.code != "rate_limited":
            log.info("enrol refused (%s) from %s", exc.code, client_ip())
        raise
    if creating:
        limiter.record(newteam_key)
    log.info("enrol: %s instance %s joined team %r in %s from %s", (data.get("instance") or {}).get("kind"),
             instance_id[:8], team["name"], event["slug"], client_ip())
    if uid_teams:
        log.warning("enrol: board UID claimed by team %r is also live in team(s) %s",
                    team["name"], ", ".join(repr(t) for t in uid_teams))
    return jsonify({
        "instance_id": instance_id,
        "token": token,
        "team": {"id": team["id"], "name": team["name"]},
        "event": _event_json(event),
        "heartbeat_interval": current_app.config["HEARTBEAT_INTERVAL"],
    }), 201


@bp.post("/heartbeat")
def heartbeat():
    """
    Periodic check-in. Stores the instance status and answers with everything
    the landing page needs to display: event state, team score and rank, the
    challenges the server has on record for the team (the client resends any
    local solve missing from that list) and new announcements.
    """
    auth = _authenticate()
    _rate_limit(f"hb:{auth['instance_id']}", "RATE_LIMIT_HEARTBEAT")
    data = _json_body()
    db = get_db()
    ctf.record_heartbeat(db, auth["instance_id"], data.get("status"), client_ip())
    event = ctf.get_event(db, auth["event_id"])
    try:
        after = int(data.get("announcements_after") or 0)
    except (TypeError, ValueError, OverflowError):
        after = 0
    board, _ = public_board(db, event)   # at most BOARD_TTL old; fine for a rank display
    standing = next((e for e in board if e["team_id"] == auth["team_id"]), {})
    return jsonify({
        "event": _event_json(event),
        "team": {"id": auth["team_id"], "name": auth["team_name"],
                 "score": standing.get("score", 0), "rank": standing.get("rank"),
                 "teams": len(board)},
        "solved": ctf.team_solved_keys(db, auth["team_id"]),
        "catalog_version": ctf.catalog_version(db, event["id"]),
        "announcements": [dict(a) for a in ctf.announcements_since(db, event["id"], after)],
        # Ids still current, so clients can drop announcements the organiser deleted.
        "announcement_ids": ctf.announcement_ids(db, event["id"]),
        "heartbeat_interval": current_app.config["HEARTBEAT_INTERVAL"],
        "server_time": now(),
    })


@bp.post("/solves")
def submit_solve():
    auth = _authenticate()
    _rate_limit(f"solve:{auth['instance_id']}", "RATE_LIMIT_SOLVE")
    data = _json_body()
    result, points, bonus = ctf.submit_solve(get_db(), auth, data.get("challenge_id"), data.get("flag"),
                                             data.get("solved_at"), client_ip())
    if result == ctf.ACCEPTED:
        invalidate_board()
    if result == ctf.INVALID_FLAG:
        log.warning("solve: wrong flag for %r from team %r (%s)", data.get("challenge_id"),
                    auth["team_name"], client_ip())
    # Always 200: the result is the answer, and every result is final for the
    # client. Only transport errors and 5xx mean "keep it queued, retry later".
    # points: the challenge's value; bonus: first blood extra (0 when off or not first).
    return jsonify({"result": result, "points": points, "bonus": bonus})


@bp.get("/challenges")
def challenges():
    """The event's catalog without flags, so a client can tell which challenges count."""
    auth = _authenticate()
    rows = ctf.list_challenges(get_db(), auth["event_id"], enabled_only=True)
    return jsonify({"challenges": [
        {"id": r["key"], "title": r["title"], "category": r["category"], "points": r["points"],
         "type": r["ctype"]} for r in rows]})


@bp.delete("/instance")
def leave():
    """The user switched the central server off in the landing page."""
    auth = _authenticate()
    ctf.revoke_instance(get_db(), auth["instance_id"])
    return "", 204


# The public scoreboard is the one endpoint anyone may poll. It is served
# from a short cache instead of being rate limited per address: a limit would
# let one participant behind the projector's NAT address blank the projector,
# while the cache makes any poll rate cheap. Heartbeats read it too.
_board_cache = {}
_board_lock = threading.Lock()
BOARD_TTL = 2.0


def invalidate_board():
    """Call after anything that changes scores or ranks, so nobody sees a stale board."""
    with _board_lock:
        _board_cache.clear()


def public_board(db, event):
    """(scoreboard, recent solves) for the public views, at most BOARD_TTL seconds old."""
    key = (event["id"], event["created_at"])
    with _board_lock:
        hit = _board_cache.get(key)
        if hit and time.monotonic() - hit[0] < BOARD_TTL:
            return hit[1]
    data = (ctf.scoreboard(db, event["id"]),
            [dict(r) for r in ctf.recent_solves(db, event["id"], 15)])
    with _board_lock:
        if len(_board_cache) > 256:
            _board_cache.clear()
        _board_cache[key] = (time.monotonic(), data)
    return data


@bp.get("/events/<slug>/scoreboard")
def event_scoreboard(slug):
    db = get_db()
    event = ctf.get_event_by_slug(db, slug)
    if not public_scoreboard(event):
        raise CTFError("not_found", "No public scoreboard for this event.", 404)
    board, recent = public_board(db, event)
    return jsonify({
        "event": _event_json(event),
        "scoreboard": [{k: v for k, v in e.items() if k != "team_id"} for e in board],
        "recent_solves": [{"team": r["team"], "challenge": r["title"], "points": r["points"],
                           "first_blood": bool(r["first_blood"]),
                           "bonus": ctf.first_blood_points(r["points"], r["first_blood_bonus"])
                                    if r["first_blood"] else 0,
                           "time": r["received_at"]}
                          for r in recent],
        "server_time": now(),
    })
