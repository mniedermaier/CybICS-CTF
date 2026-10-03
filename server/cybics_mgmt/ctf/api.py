"""
The CTF endpoints of /api/v1: joining and leaving an event, solves, the
catalog, the device's CTF state in the heartbeat answer, and the public
scoreboard. The contract is documented in docs/API.md.

Every call authenticates the device (fleet/api.py); the device's live
instance names its team and event.
"""
import logging
import threading
import time
import unicodedata

from flask import current_app, jsonify

from ..api import HEARTBEAT_PARTS, bp, json_body, rate_limit
from ..db import get_db, now
from ..fleet.api import authenticate
from ..security import HashingBusy, client_ip, limiter
from . import logic as ctf
from .logic import CTFError

log = logging.getLogger("cybics_mgmt")


def _participation(device):
    """The device's team and event, or the error that says why it cannot act in the CTF."""
    auth = ctf.participation(get_db(), device["id"])
    if auth is None:
        # Revoked by the organiser, the team or event deleted, or never
        # joined: the client keeps its queue and stops sending solves.
        raise CTFError("not_in_event", "This device is not in an event. Join one first.", 409)
    if auth["banned"]:
        raise CTFError("team_banned", "This team has been disqualified.", 403)
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


def _usable(value):
    return isinstance(value, str) and ctf._encodable(value)


@bp.post("/ctf/join")
def ctf_join():
    # Shared addresses: a whole classroom, the projector and the organiser
    # often sit behind one NAT address, so any per-address limit can be
    # tripped by one participant for everybody. The guard here only counts
    # wrong team passwords (which cost a hash), the organiser sees and clears
    # it in the admin UI, and nothing depends on it for security: team
    # passwords are at least 8 characters, and the bounded scrypt pool caps
    # guessing for the whole server.
    device = authenticate()
    fail_key = f"join-fail:{client_ip()}"
    limit, window = current_app.config["RATE_LIMIT_JOIN"]
    if limiter.exceeded(fail_key, limit, window):
        if limiter.hit(f"audit-join-lock:{client_ip()}", 1, window):
            log.warning("join: failure limit reached for %s", client_ip())
        raise CTFError("rate_limited", "Too many wrong team passwords from this address. Ask the organiser.", 429)
    db = get_db()
    newteam_key = f"newteam:{client_ip()}"
    creating = False
    try:
        data = json_body()
        code, name = data.get("join_code"), data.get("team_name")
        # Only well-formed strings reach SQLite here; join() turns the rest into a 400.
        event_row = ctf.get_event_by_join_code(db, code) if _usable(code) and code.strip() else None
        norm_name = unicodedata.normalize("NFC", " ".join(name.split())) if _usable(name) else ""
        # New teams per address: counted only when a team is actually created.
        creating = event_row is not None and bool(norm_name) and not db.execute(
            "SELECT 1 FROM teams WHERE event_id = ? AND name = ?", (event_row["id"], norm_name)).fetchone()
        limit, window = current_app.config["RATE_LIMIT_NEW_TEAMS"]
        if creating and limiter.exceeded(newteam_key, limit, window):
            raise CTFError("rate_limited", "Too many new teams from this address. Join an existing team "
                                           "or ask the organiser.", 429)
        instance_id, event, team, uid_teams = ctf.join(db, device, data.get("join_code"), data.get("team_name"),
                                                       data.get("team_password"))
    except HashingBusy:
        raise CTFError("busy", "The server is busy with other devices joining. Try again in a few seconds.",
                       503) from None
    except CTFError as exc:
        # Only wrong team passwords count: they cost a hash. Malformed requests
        # and unknown join codes cost nothing, and counting them would let
        # anyone switch off joining for a whole NAT address with garbage.
        if exc.code == "wrong_team_password":
            limiter.record(fail_key)
            ctf.record_failed_join(db, exc.team["event_id"], exc.team["id"], exc.team["name"], device["id"],
                                   client_ip())
            log.warning("join: wrong password for team %r from %s", exc.team["name"], client_ip())
        elif exc.code == "invalid_join_code":
            # Once per address and minute: enough to spot someone probing
            # codes or tripping the guard, without letting them flood the log.
            if limiter.hit(f"audit-joincode:{client_ip()}", 1, 60):
                log.warning("join: unknown join code from %s", client_ip())
        elif exc.code != "rate_limited":
            log.info("join refused (%s) from %s", exc.code, client_ip())
        raise
    if creating:
        limiter.record(newteam_key)
    log.info("join: %s device %s joined team %r in %s from %s", device["kind"], device["id"][:8], team["name"],
             event["slug"], client_ip())
    if uid_teams:
        log.warning("join: board UID claimed by team %r is also live in team(s) %s",
                    team["name"], ", ".join(repr(t) for t in uid_teams))
    return jsonify({"instance_id": instance_id, "team": {"id": team["id"], "name": team["name"]},
                    "event": _event_json(event)}), 201


@bp.delete("/ctf/join")
def ctf_leave():
    """The user left the event in the landing page. The device stays enrolled."""
    device = authenticate()
    ctf.leave(get_db(), device["id"])
    return "", 204


def heartbeat_part(db, device, data):
    """
    The device's CTF state for the heartbeat answer: its event state, team
    score and rank, the challenges the server has on record for the team (the
    client resends any local solve missing from that list) and new
    announcements. "ctf" is null while the device is in no event.
    """
    auth = ctf.participation(db, device["id"])
    if auth is None:
        return {"ctf": None}
    event = ctf.get_event(db, auth["event_id"])
    try:
        after = int(data.get("announcements_after") or 0)
    except (TypeError, ValueError, OverflowError):
        after = 0
    board, _ = public_board(db, event)   # at most BOARD_TTL old; fine for a rank display
    standing = next((e for e in board if e["team_id"] == auth["team_id"]), {})
    return {"ctf": {
        "instance_id": auth["instance_id"],
        "event": _event_json(event),
        "team": {"id": auth["team_id"], "name": auth["team_name"], "banned": bool(auth["banned"]),
                 "score": standing.get("score", 0), "rank": standing.get("rank"), "teams": len(board)},
        "solved": ctf.team_solved_keys(db, auth["team_id"]),
        "catalog_version": ctf.catalog_version(db, event["id"]),
        "announcements": [dict(a) for a in ctf.announcements_since(db, event["id"], after)],
        # Ids still current, so clients can drop announcements the organiser deleted.
        "announcement_ids": ctf.announcement_ids(db, event["id"]),
    }}


HEARTBEAT_PARTS.append(heartbeat_part)


@bp.post("/solves")
def submit_solve():
    device = authenticate()
    rate_limit(f"solve:{device['id']}", "RATE_LIMIT_SOLVE")
    auth = _participation(device)
    data = json_body()
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
    auth = _participation(authenticate())
    rows = ctf.list_challenges(get_db(), auth["event_id"], enabled_only=True)
    return jsonify({"challenges": [
        {"id": r["key"], "title": r["title"], "category": r["category"], "points": r["points"],
         "type": r["ctype"]} for r in rows]})


# The public scoreboard is the one endpoint anyone may poll. It is served
# from a short cache instead of being rate limited per address: a limit would
# let one participant behind the projector's NAT address blank the projector,
# while the cache makes any poll rate cheap. Heartbeats read it too.
_board_cache = {}
_board_lock = threading.Lock()
_board_generation = 0   # bumped by invalidate_board(); a board computed before that is not stored
BOARD_TTL = 2.0


def invalidate_board():
    """Call after anything that changes scores or ranks, so nobody sees a stale board."""
    global _board_generation
    with _board_lock:
        _board_generation += 1
        _board_cache.clear()


def public_board(db, event):
    """(scoreboard, recent solves) for the public views, at most BOARD_TTL seconds old."""
    key = (event["id"], event["created_at"])
    with _board_lock:
        hit = _board_cache.get(key)
        if hit and time.monotonic() - hit[0] < BOARD_TTL:
            return hit[1]
        generation = _board_generation
    data = (ctf.scoreboard(db, event["id"]),
            [dict(r) for r in ctf.recent_solves(db, event["id"], 15)])
    with _board_lock:
        if generation != _board_generation:
            return data   # invalidated while computing: this one may already be stale
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
