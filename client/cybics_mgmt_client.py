"""
Reference client for CybICS-mgmt, the optional central server for CybICS.

Meant to be vendored into CybICS' landing service (software/landing/modules/)
as a single file: standard library only, Python 3.9+. CybICS v1.2.4 ships it
as modules/central_ctf.py.

Design rules, all following from "the central server is optional":

* Nothing happens until the user enrols from the landing page. A fresh or
  disabled client makes no network calls at all.
* The landing page keeps validating flags locally. The client only *reports*
  local solves; a server that is down, slow or gone never blocks or fails a
  local submission.
* Reports survive outages. Solves sit in a persistent outbox until the server
  answers with a final result, and every heartbeat reconciles the local solve
  list with the server's, so nothing is lost if the outbox file is.
* Solves that existed locally before enrolment (old progress on a reused Pi)
  are not reported: the client snapshots them as a baseline at enrolment.

Typical wiring in landing:

    client = CTFClient(state_path="data/central_ctf.json",
                       local_solves=lambda: ctf_manager.load_progress()["solved_challenges"],
                       flag_for=lambda cid: (ctf_manager.get_challenge(cid)[0] or {}).get("flag"),
                       status=collect_status)
    client.start()                         # background heartbeat if enrolled
    ...
    # after a successful local /ctf/submit or /ctf/verify:
    client.report_solve(challenge_id, flag)

FleetClient, further down, enrols the installation in CybICS-mgmt's fleet:
telemetry, and jobs the server signs. It runs only jobs that verify against
the key pinned at enrolment, carry a higher sequence number than the last one,
and name an action the user allowed on this device. It executes nothing
itself: landing registers one handler per action.
"""
import gzip
import hashlib
import hmac
import http.client
import json
import logging
import os
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("central_ctf")

API_PREFIX = "/api/v1"
DEFAULT_INTERVAL = 30
TIMEOUT = 8
# Enrolment may queue briefly at the proxy when a whole class joins at once.
ENROLL_TIMEOUT = 30

# Results that mean "counted, or already on record". Every other result is
# final too (the solve leaves the outbox); see _settle() for which ones are
# held and retried later. Unknown future result values are treated like
# invalid_flag, as docs/API.md requires.
DONE_RESULTS = {"accepted", "duplicate"}
KNOWN_RESULTS = DONE_RESULTS | {"invalid_flag", "unknown_challenge", "event_not_running"}


class CTFClientError(Exception):
    """
    An error to show the user: `code` is the server's error code or a transport
    code. `from_server` is True only when the answer carried this server's JSON
    error shape; a 4xx page from a reverse proxy in between does not count.
    """

    def __init__(self, code, message, status=None, from_server=False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.from_server = from_server


def _http(ssl_context, base, method, path, body=None, token=None, timeout=TIMEOUT, raw=None,
          content_type=None):
    """
    One request to the server: returns (status, JSON object) or raises
    CTFClientError. `raw` sends bytes as they are, with `content_type`.
    """
    req = urllib.request.Request((base or "").rstrip("/") + API_PREFIX + path, method=method)  # noqa: S310
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "cybics-landing")
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    elif raw is not None:
        data = raw
        req.add_header("Content-Type", content_type or "application/octet-stream")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        # The scheme is http(s) only: every server_url passes normalize_url().
        with urllib.request.urlopen(req, data=data, timeout=timeout, context=ssl_context) as resp:  # noqa: S310
            raw_answer = resp.read()
            answer = json.loads(raw_answer) if raw_answer else {}
            if not isinstance(answer, dict):
                raise ValueError("not a JSON object")
            return resp.status, answer
    except urllib.error.HTTPError as exc:
        try:
            err = json.loads(exc.read()).get("error")
        except (ValueError, AttributeError, OSError, http.client.HTTPException):
            err = None
        ours = isinstance(err, dict) and isinstance(err.get("code"), str)
        err = err if ours else {}
        raise CTFClientError(err.get("code", f"http_{exc.code}"),
                             err.get("message", f"Server answered HTTP {exc.code}."),
                             exc.code, from_server=ours) from None
    except (OSError, http.client.HTTPException) as exc:
        # URLError, timeouts, resets, TLS errors (all OSError) and a body
        # cut off mid-transfer (IncompleteRead) on flaky Wi-Fi.
        reason = getattr(exc, "reason", None) or exc.__class__.__name__
        raise CTFClientError("unreachable", f"Cannot reach the CTF server: {reason}") from None
    except ValueError:   # includes JSONDecodeError and UnicodeDecodeError
        raise CTFClientError("bad_response", "The server did not answer with a JSON object.") from None


def _write_state(path, state, prefix):
    """Write a state file atomically, fsynced, readable by its owner only (it holds a token)."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=prefix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
            f.flush()
            os.fsync(f.fileno())   # a Pi may lose power at any moment
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_state(path, empty):
    state = empty
    try:
        with open(path, encoding="utf-8") as f:
            saved = json.load(f)
        if isinstance(saved, dict):
            state.update({k: v for k, v in saved.items() if k in state})
    except (OSError, ValueError):
        pass
    return state


def _interval(value):
    """The server's heartbeat interval, defended: it decides how often a thread wakes up."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
        return DEFAULT_INTERVAL
    return int(min(3600, max(5, value)))


def _empty_state():
    return {
        "enabled": False,
        "server_url": None,
        "instance_id": None,
        "token": None,
        "team": None,
        "event": None,
        "baseline": [],          # local solves that predate enrolment, never reported
        "outbox": [],            # [{challenge_id, flag, solved_at}]
        "rejected": [],          # challenge ids the server refused for good
        "held": {},              # challenge id -> catalog_version it was unknown in
        "held_paused": [],       # solved while running, delivered during a pause
        "catalog_version": None,
        "server_solved": [],
        "standing": None,        # {score, rank, teams}
        "announcements": [],
        "last_announcement_id": 0,
        "last_contact": None,
        "last_error": None,
        "heartbeat_interval": DEFAULT_INTERVAL,
        "revoked": False,        # disabled by a 401, not by the user: keep queuing
        "left_local": None,      # local solves when the user left; see enroll()
    }


# Carried over when the instance enrols again with the same server and event,
# so nothing that was queued, held or decided is lost by re-enrolling.
CARRY_OVER = ("baseline", "outbox", "rejected", "held", "held_paused", "server_solved",
              "announcements", "last_announcement_id", "catalog_version")


class CTFClient:
    def __init__(self, state_path, local_solves=lambda: [], flag_for=lambda _cid: None,
                 status=lambda: {}, ca_file=None):
        """
        state_path   JSON file holding enrolment and outbox (put it on a volume)
        local_solves callable returning the challenge ids solved locally
        flag_for     callable mapping a challenge id to its flag (from ctf_config.json)
        status       callable returning the status dict sent with each heartbeat
        ca_file      optional CA bundle for a server with a private certificate
        """
        self.state_path = state_path
        self.local_solves = local_solves
        self.flag_for = flag_for
        self.status = status
        self._ssl = ssl.create_default_context(cafile=ca_file) if ca_file else None
        self._lock = threading.RLock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = None
        self.state = self._load()

    # ---------- persistence ----------

    def _load(self):
        return _read_state(self.state_path, _empty_state())

    def _save_or_raise(self):
        """_save() for user actions: a full or read-only disk becomes a CTFClientError."""
        try:
            self._save()
        except OSError as exc:
            raise CTFClientError("state_unwritable", f"Cannot save the central CTF settings: {exc}") from None

    def _save(self):
        _write_state(self.state_path, self.state, ".central_ctf.")

    # ---------- HTTP ----------

    def _request(self, method, path, body=None, token=None, server_url=None, timeout=TIMEOUT):
        return _http(self._ssl, server_url or self.state["server_url"], method, path, body=body, token=token,
                     timeout=timeout)

    @staticmethod
    def normalize_url(url):
        url = (url or "").strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise CTFClientError("invalid_url", "Enter a server address like http://10.10.0.1:8000.")
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

    # ---------- user actions (landing settings page) ----------

    def test_connection(self, server_url):
        """GET /info; returns the server's info dict or raises CTFClientError."""
        _, info = self._request("GET", "/info", server_url=self.normalize_url(server_url))
        if info.get("service") != "cybics-ctf":
            raise CTFClientError("not_a_ctf_server", "That address is not a CybICS-mgmt server.")
        return info

    def enroll(self, server_url, join_code, team_name, team_password, instance):
        """
        instance: {"kind": "virtual"|"physical", "device_uid": <STM32 UID hex, physical only>,
                   "hostname": ..., "cybics_version": ..., "mode": ...}
        """
        server_url = self.normalize_url(server_url)
        # Read the baseline strictly, before talking to the server: enrolling
        # with an empty baseline because the progress file was unreadable would
        # report all old progress as new solves.
        try:
            baseline = sorted(set(self.local_solves() or []))
        except Exception as exc:
            raise CTFClientError("progress_unreadable",
                                 f"Cannot read the local CTF progress, try again: {exc}") from None
        _, resp = self._request("POST", "/enroll", server_url=server_url, timeout=ENROLL_TIMEOUT, body={
            "join_code": join_code, "team_name": team_name, "team_password": team_password,
            "instance": instance})
        if not (isinstance(resp.get("token"), str) and isinstance(resp.get("instance_id"), str)
                and isinstance(resp.get("event"), dict)):
            raise CTFClientError("bad_response", "The server's enrolment answer is incomplete.")
        with self._lock:
            prev = self.state
            # Same server and the same event: the slug alone is not enough, an
            # organiser may delete an event and recreate it under its old slug.
            prev_event = prev.get("event") or {}
            # And the same team: solves made for one team are not reported
            # again for another after a leave and join (that starts fresh,
            # with every current local solve as the baseline).
            same = (prev.get("server_url") == server_url
                    and prev_event.get("slug") == resp["event"].get("slug")
                    and prev_event.get("created_at") == resp["event"].get("created_at")
                    and (prev.get("team") or {}).get("id") == (resp.get("team") or {}).get("id"))
            self.state = _empty_state()
            if same:
                # Re-enrolling after a revocation, or leave + join to fix the
                # team name: keep what was queued, held or decided. Solves made
                # while the user had left stay unreported, like any solve from
                # before enrolment.
                self.state.update({k: prev[k] for k in CARRY_OVER if k in prev})
                if prev.get("left_local") is not None:
                    made_while_left = set(baseline) - set(prev["left_local"])
                    self.state["baseline"] = sorted(set(prev["baseline"]) | made_while_left)
            else:
                self.state["baseline"] = baseline
            self.state.update({
                "enabled": True, "server_url": server_url,
                "instance_id": resp["instance_id"], "token": resp["token"],
                "team": resp.get("team"), "event": resp["event"],
                "heartbeat_interval": _interval(resp.get("heartbeat_interval")),
            })
            self._save_or_raise()
        self._wake.set()
        return resp

    def leave(self):
        """
        Switch the central server off. Best effort towards the server; always
        disables locally. The token is dropped; the sync bookkeeping is kept in
        case the user joins the same event again (see enroll()).
        """
        with self._lock:
            token, url = self.state.get("token"), self.state.get("server_url")
            kept = {k: self.state[k] for k in CARRY_OVER if k in self.state}
            event, team = self.state.get("event"), self.state.get("team")
            self.state = _empty_state()
            self.state.update(kept)
            self.state.update({"server_url": url, "event": event, "team": team,
                               "left_local": sorted(set(self._safe_local_solves()))})
            try:
                self._save_or_raise()
            except CTFClientError as exc:
                unsaved = exc
            else:
                unsaved = None
        if token and url:
            try:
                self._request("DELETE", "/instance", token=token, server_url=url)
            except CTFClientError:
                pass
        if unsaved:
            raise unsaved

    def report_solve(self, challenge_id, flag):
        """
        Queue a locally verified solve and nudge the sender. Never raises, never
        blocks: landing calls this in the middle of a local submission, which
        must succeed whatever happens to the central server or this file.
        """
        try:
            with self._lock:
                # After a revocation, keep queuing: the user will most likely
                # enrol again, and these solves must not be lost.
                if not (self.state["enabled"] or self.state["revoked"]):
                    return
                if any(item["challenge_id"] == challenge_id for item in self.state["outbox"]):
                    return
                running = (self.state.get("event") or {}).get("state") == "running"
                self.state["outbox"].append({"challenge_id": challenge_id, "flag": flag,
                                             "solved_at": time.time(), "while_running": running})
                try:
                    self._save()
                except OSError as exc:   # full SD card, read-only volume: keep it in memory
                    log.warning("central CTF: cannot save the outbox: %s", exc)
                    self.state["last_error"] = {"code": "storage", "time": time.time(),
                                                "message": f"Cannot save pending reports: {exc}"}
            self._wake.set()
        except Exception:
            log.exception("central CTF: report_solve failed")

    def snapshot(self):
        """State for the landing page, without the token."""
        with self._lock:
            view = {k: v for k, v in self.state.items() if k not in ("token", "baseline", "left_local")}
            view["pending"] = len(self.state["outbox"])
            view["outbox"] = [item["challenge_id"] for item in self.state["outbox"]]
            return view

    # ---------- sync ----------

    def _safe_local_solves(self):
        try:
            return list(self.local_solves() or [])
        except Exception:  # landing's progress file may be mid-write; try again next round
            return []

    def _current(self, token):
        """True if `token` still belongs to the active enrolment (call with the lock held)."""
        return self.state["enabled"] and self.state["token"] == token

    def _settle(self, item, result, refused=False):
        """
        Take a solve out of the outbox for good (call with the lock held).
        `refused` means `result` is the error code of a 4xx, not a `result` value.
        """
        cid = item["challenge_id"]
        self.state["outbox"] = [i for i in self.state["outbox"] if i["challenge_id"] != cid]
        if result in DONE_RESULTS:
            return
        if not refused and result not in KNOWN_RESULTS:
            result = "invalid_flag"
        if result == "event_not_running" and item.get("while_running"):
            # Solved while the event ran, but the report only arrived after the
            # organiser paused or finished (the outbox may back off for
            # minutes, or the change came mid-flush). Hold it until a
            # heartbeat shows the event running again. A solve made while the
            # event was not running is not held.
            self.state["held_paused"] = sorted(set(self.state["held_paused"]) | {cid})
        elif result in ("unknown_challenge", "invalid_flag"):
            # This landing page checked the solve locally, so the server's
            # catalog disagrees: imported late, a challenge disabled for a
            # while, or the organiser imported another CybICS version's flags.
            # Hold it, and retry once the server's catalog (ids and flags)
            # changes. A cheater gains nothing: every retry is audited.
            self.state["held"][cid] = self.state["catalog_version"]
        else:
            # event_not_running (solved before the start or in a pause), or
            # a client error.
            self.state["rejected"] = sorted(set(self.state["rejected"]) | {cid})

    def _flush_outbox(self):
        with self._lock:
            pending = list(self.state["outbox"])
            token = self.state["token"]
        for item in pending:
            try:
                _, resp = self._request("POST", "/solves", body=item, token=token)
                result, refused = resp.get("result"), False
                if not isinstance(result, str) or not result:
                    result = "unknown_result"   # a list would break the set lookups in _settle()
            except CTFClientError as exc:
                # 401/403/429 concern the instance, not this solve; 5xx and
                # transport errors are transient; and a 4xx that is not this
                # server's JSON (a proxy's 404/408/413 page while the backend
                # restarts) says nothing about the solve. Keep it queued.
                if (exc.status is None or exc.status >= 500 or exc.status in (401, 403, 429)
                        or not exc.from_server):
                    raise
                result, refused = exc.code, True   # this server refused this solve: it never will accept it
            with self._lock:
                if not self._current(token):
                    return   # the user left or re-enrolled meanwhile
                self._settle(item, result, refused)
                self._save()

    def _heartbeat(self):
        with self._lock:
            token = self.state["token"]
            after = self.state["last_announcement_id"]
        try:
            status = dict(self.status() or {})
        except Exception:
            status = {}
        status.setdefault("local_solved", self._safe_local_solves())
        _, resp = self._request("POST", "/heartbeat", token=token,
                                body={"status": status, "announcements_after": after})
        with self._lock:
            if not self._current(token):
                return   # an answer for an enrolment that no longer exists
            self.state["event"] = resp.get("event")
            self.state["team"] = {k: resp["team"][k] for k in ("id", "name") if k in resp.get("team", {})}
            self.state["standing"] = {k: resp.get("team", {}).get(k) for k in ("score", "rank", "teams")}
            self.state["server_solved"] = resp.get("solved", [])
            self.state["heartbeat_interval"] = _interval(resp.get("heartbeat_interval"))
            if (resp.get("event") or {}).get("state") == "running":
                # Running (again): give held solves another try. They stay held
                # through a pause and after the end, because an organiser can
                # reopen an event that was finished by mistake.
                self.state["held_paused"] = []
            version = resp.get("catalog_version")
            if version != self.state["catalog_version"]:
                self.state["catalog_version"] = version
                self.state["held"] = {}   # the catalog changed: give held solves another try
            live = resp.get("announcement_ids")
            if isinstance(live, list):   # the organiser deleted some
                self.state["announcements"] = [a for a in self.state["announcements"] if a.get("id") in live]
            news = resp.get("announcements", [])
            if news:
                self.state["announcements"] = (self.state["announcements"] + news)[-20:]
                self.state["last_announcement_id"] = max(a["id"] for a in news)
            # Reconcile: a local solve the server does not know about (lost
            # outbox, removed by the organiser, solved while offline) is queued
            # again. Only while running, otherwise it would just bounce.
            if (resp.get("event") or {}).get("state") == "running":
                known = (set(self.state["server_solved"]) | set(self.state["baseline"])
                         | set(self.state["rejected"]) | set(self.state["held"])
                         | set(self.state["held_paused"])
                         | {i["challenge_id"] for i in self.state["outbox"]})
                for cid in self._safe_local_solves():
                    if cid in known:
                        continue
                    flag = None
                    try:
                        flag = self.flag_for(cid)
                    except Exception:
                        pass
                    if flag:
                        self.state["outbox"].append({"challenge_id": cid, "flag": flag,
                                                     "solved_at": None, "while_running": True})
            self._save()

    def sync_once(self):
        """One heartbeat plus outbox flush. Returns True on success."""
        with self._lock:
            if not self.state["enabled"]:
                return False
            token = self.state["token"]
        try:
            self._heartbeat()
            self._flush_outbox()
        except CTFClientError as exc:
            with self._lock:
                if not self._current(token):
                    return False   # stale failure from before a leave/re-enrol
                self.state["last_error"] = {"code": exc.code, "message": exc.message, "time": time.time()}
                if exc.status == 401 and exc.from_server:
                    # (A 401 page from some proxy in between says nothing about
                    # the enrolment; it is retried like any transport error.)
                    # Revoked by the organiser or the event was deleted: stop
                    # talking to the server until the user enrols again.
                    # (403 team_banned is not final: the organiser can reinstate
                    # the team, so the client keeps trying with backoff.)
                    self.state["enabled"] = False
                    self.state["revoked"] = True
                self._save()
            return False
        with self._lock:
            if not self._current(token):
                return False
            self.state["last_contact"] = time.time()
            self.state["last_error"] = None
            self._save()
        return True

    # ---------- background loop ----------

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="central-ctf", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()

    def _run(self):
        failures = 0
        while not self._stop.is_set():
            try:
                ok = self.sync_once()
            except Exception:
                # Never let the sender thread die: a bug or an unexpected
                # answer would otherwise stop all reporting until landing
                # restarts. Log it and back off like for a network error.
                log.exception("central CTF: sync failed")
                ok = False
            failures = 0 if ok else failures + 1
            with self._lock:
                interval = _interval(self.state.get("heartbeat_interval"))
                enabled = self.state["enabled"]
            # Back off up to 5 minutes while the server is unreachable.
            delay = interval if ok or not enabled else min(300, interval * (2 ** min(failures, 4)))
            self._wake.wait(delay if enabled else 3600)
            self._wake.clear()


# ---------- fleet ----------

FLEET_ACTIONS = ("identify", "message", "restart", "reset_progress", "collect_logs")
FLEET_CLIENT_VERSION = "1"
MIN_KEY_BITS = 3072
LOGS_MAX = 256 * 1024          # compressed, as the server accepts it
LOGS_RAW_MAX = 4 * 1024 * 1024  # what is compressed at most: the newest part of the logs
HISTORY_MAX = 50
# DER prefix of a SHA-256 DigestInfo (RFC 8017, section 9.2, note 1).
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def key_fingerprint(n, e):
    """SHA-256 of "<e>:<n in hex>", the value the organiser sees on the device page."""
    return hashlib.sha256(f"{e}:{n:x}".encode()).hexdigest()


def job_message(job):
    """The bytes the server signed for a job (canonical JSON of its fields)."""
    return json.dumps({k: job[k] for k in ("action", "device", "id", "params", "seq")}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True).encode()


def verify_signature(n, e, message, signature_hex):
    """
    RSA PKCS#1 v1.5 with SHA-256, in plain Python: the signature is raised to
    the public exponent and compared, in constant time, with the encoding the
    signature must have. Nothing of the decrypted block is parsed, so there is
    no padding parser to fool.
    """
    size = (n.bit_length() + 7) // 8
    if not isinstance(signature_hex, str) or len(signature_hex) != 2 * size:
        return False
    try:
        signature = int(signature_hex, 16)
    except ValueError:
        return False
    if not 0 < signature < n:
        return False
    digest_info = _SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    expected = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    return hmac.compare_digest(pow(signature, e, n).to_bytes(size, "big"), expected)


def _pinned_key(value):
    """(n, e) from an enrolment answer's signing_key, or None if it is not a key to trust."""
    if not isinstance(value, dict) or not isinstance(value.get("n"), str) or value.get("e") != 65537:
        return None
    try:
        n = int(value["n"], 16)
    except ValueError:
        return None
    if n.bit_length() < MIN_KEY_BITS:
        return None
    return n, 65537


def _empty_fleet_state():
    return {
        "enabled": False,
        "server_url": None,
        "device_id": None,
        "token": None,
        "device": None,          # {id, label, group} as the server last named them
        "signing_key": None,     # {"n": hex, "e": 65537}, pinned at enrolment
        "allowed": [],           # actions the user allowed on this device; none by default
        "last_seq": 0,           # highest job sequence number accepted
        "queue": [],             # verified jobs waiting to run
        "running": None,         # the job running right now, saved before it starts
        "results": [],           # results not yet reported to the server
        "history": [],           # the last HISTORY_MAX jobs, for the landing page
        "last_contact": None,
        "last_error": None,
        "heartbeat_interval": DEFAULT_INTERVAL,
        "revoked": False,
    }


class FleetClient:
    def __init__(self, state_path, device_info=lambda: {}, status=lambda: {}, handlers=None, ca_file=None):
        """
        state_path   JSON file holding the fleet enrolment (put it on a volume)
        device_info  callable returning {kind, device_uid, hostname, cybics_version, mode}
        status       callable returning the status dict sent with each heartbeat
        handlers     {action: callable(params) -> str | bytes | None}; collect_logs
                     returns the log text or bytes, the others a short result
        ca_file      optional CA bundle for a server with a private certificate
        """
        self.state_path = state_path
        self.device_info = device_info
        self.status = status
        self.handlers = {k: v for k, v in (handlers or {}).items() if k in FLEET_ACTIONS and callable(v)}
        self._ssl = ssl.create_default_context(cafile=ca_file) if ca_file else None
        self._lock = threading.RLock()
        self._wake = threading.Event()
        self._work = threading.Event()
        self._stop = threading.Event()
        self._threads = []
        self.state = _read_state(state_path, _empty_fleet_state())
        self._finish_interrupted()

    normalize_url = staticmethod(CTFClient.normalize_url)

    # ---------- persistence ----------

    def _save(self):
        _write_state(self.state_path, self.state, ".central_fleet.")

    def _save_or_raise(self):
        try:
            self._save()
        except OSError as exc:
            raise CTFClientError("state_unwritable", f"Cannot save the fleet settings: {exc}") from None

    def _try_save(self):
        try:
            self._save()
        except OSError as exc:   # full SD card, read-only volume: keep going in memory
            log.warning("fleet: cannot save the state: %s", exc)

    def _request(self, method, path, body=None, token=None, server_url=None, timeout=TIMEOUT, raw=None,
                 content_type=None):
        return _http(self._ssl, server_url or self.state["server_url"], method, path, body=body, token=token,
                     timeout=timeout, raw=raw, content_type=content_type)

    def _finish_interrupted(self):
        """A job that was running when landing stopped; a restart takes landing down with it."""
        running = self.state.get("running")
        if not isinstance(running, dict):
            self.state["running"] = None
            return
        if running.get("action") == "restart":
            self._finish(running, "done", "landing restarted")
        else:
            self._finish(running, "failed", "interrupted: landing stopped while the job ran")
        self.state["running"] = None
        self._try_save()

    # ---------- user actions (landing settings page) ----------

    def fingerprint(self):
        key = _pinned_key(self.state.get("signing_key"))
        return key_fingerprint(*key) if key else None

    def enroll(self, server_url, code, label=None):
        """Join the fleet with an enrolment code (or an event's join code). Starts with no action allowed."""
        server_url = self.normalize_url(server_url)
        try:
            device = dict(self.device_info() or {})
        except Exception as exc:
            raise CTFClientError("device_info", f"Cannot read this installation's details: {exc}") from None
        _, resp = self._request("POST", "/fleet/enroll", server_url=server_url, timeout=ENROLL_TIMEOUT,
                                body={"code": code, "label": label, "device": device})
        key = _pinned_key(resp.get("signing_key"))
        if not (isinstance(resp.get("token"), str) and isinstance(resp.get("device_id"), str)):
            raise CTFClientError("bad_response", "The server's enrolment answer is incomplete.")
        if key is None:
            raise CTFClientError("bad_key", "The server sent no usable signing key (RSA, at least 3072 bits).")
        with self._lock:
            history = self.state.get("history", [])
            self.state = _empty_fleet_state()
            self.state.update({
                "enabled": True, "server_url": server_url, "device_id": resp["device_id"],
                "token": resp["token"], "device": resp.get("device") if isinstance(resp.get("device"), dict) else None,
                "signing_key": {"n": format(key[0], "x"), "e": key[1]}, "history": history,
                "heartbeat_interval": _interval(resp.get("heartbeat_interval")),
            })
            self._save_or_raise()
        self._wake.set()
        return resp

    def leave(self):
        """Switch fleet management off. Best effort towards the server; always disables locally."""
        with self._lock:
            token, url = self.state.get("token"), self.state.get("server_url")
            history = self.state.get("history", [])
            self.state = _empty_fleet_state()
            self.state.update({"server_url": url, "history": history})
            try:
                self._save_or_raise()
            except CTFClientError as exc:
                unsaved = exc
            else:
                unsaved = None
        if token and url:
            try:
                self._request("DELETE", "/fleet/device", token=token, server_url=url)
            except CTFClientError:
                pass
        if unsaved:
            raise unsaved

    def set_allowed(self, actions):
        """The actions the server may ask for. Only known actions with a handler can be allowed."""
        allowed = sorted({a for a in (actions or []) if a in self.handlers})
        with self._lock:
            self.state["allowed"] = allowed
            if self.state["enabled"]:
                # Jobs already queued for an action that is no longer allowed do not run.
                for job in [j for j in self.state["queue"] if j["action"] not in allowed]:
                    self.state["queue"].remove(job)
                    self._finish(job, "refused", "no longer allowed on this device")
            self._save_or_raise()
        self._wake.set()
        return allowed

    def snapshot(self):
        """State for the landing page, without the token or the key."""
        with self._lock:
            view = {k: v for k, v in self.state.items() if k not in ("token", "signing_key", "results")}
            view["queue"] = [j["action"] for j in self.state["queue"]]
            view["key_fingerprint"] = self.fingerprint()
            view["available"] = sorted(self.handlers)
            return view

    # ---------- jobs ----------

    def _finish(self, job, state, detail=""):
        """Record a job's result for the server and the landing page (call with the lock held)."""
        detail = str(detail or "")[:500]
        self.state["results"].append({"id": job.get("id"), "seq": job.get("seq"), "state": state,
                                      "detail": detail})
        self.state["history"] = (self.state["history"] + [{
            "id": job.get("id"), "seq": job.get("seq"), "action": job.get("action"),
            "params": job.get("params"), "state": state, "detail": detail, "time": time.time()}])[-HISTORY_MAX:]

    def _accept(self, job):
        """
        Check one job from a heartbeat answer (call with the lock held). Only a
        job with a valid signature over this device and a new sequence number
        counts at all; anything else is dropped without an answer.
        """
        if not isinstance(job, dict):
            return
        seq = job.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= self.state["last_seq"]:
            return   # seen before (the server repeats a job until its result arrives) or a replay
        if (job.get("device") != self.state["device_id"] or not isinstance(job.get("id"), str)
                or not isinstance(job.get("action"), str) or not isinstance(job.get("params"), dict)):
            return
        key = _pinned_key(self.state.get("signing_key"))
        try:
            valid = key is not None and verify_signature(key[0], key[1], job_message(job), job.get("signature"))
        except (TypeError, ValueError):
            valid = False
        if not valid:
            log.warning("fleet: dropped job %r: the signature does not match the pinned key", job.get("id"))
            self.state["last_error"] = {"code": "bad_signature", "time": time.time(),
                                        "message": "A job with an invalid signature was ignored."}
            return
        self.state["last_seq"] = seq
        job = {k: job[k] for k in ("id", "seq", "action", "params")}
        if job["action"] not in self.state["allowed"] or job["action"] not in self.handlers:
            self._finish(job, "refused", "not allowed on this device")
        else:
            self.state["queue"].append(job)

    def run_next_job(self):
        """Run the oldest queued job. Returns False if there was none."""
        with self._lock:
            if not self.state["enabled"] or not self.state["queue"]:
                return False
            job = self.state["queue"].pop(0)
            device_id = self.state["device_id"]
            self.state["running"] = job
            self._try_save()   # before it runs: a restart may end this process
        try:
            result = self.handlers[job["action"]](dict(job["params"]))
            if job["action"] == "collect_logs":
                state, detail = "done", self._upload_logs(job, result)
            else:
                state, detail = "done", result if isinstance(result, str) else ""
        except CTFClientError as exc:
            state, detail = "failed", exc.message
        except Exception as exc:
            log.exception("fleet: job %s (%s) failed", job["id"], job["action"])
            state, detail = "failed", f"{exc.__class__.__name__}: {exc}"
        with self._lock:
            if self.state["device_id"] == device_id:   # not after a leave or a new enrolment
                self.state["running"] = None
                self._finish(job, state, detail)
                self._try_save()
        self._wake.set()   # report the result soon
        return True

    def _upload_logs(self, job, logs):
        if isinstance(logs, str):
            logs = logs.encode("utf-8", "replace")
        if not isinstance(logs, (bytes, bytearray)):
            raise CTFClientError("bad_logs", "The log handler returned no logs.")
        data = gzip.compress(bytes(logs[-LOGS_RAW_MAX:]))
        while len(data) > LOGS_MAX and len(logs) > 1024:
            logs = logs[len(logs) // 2:]   # keep the newest half until it fits
            data = gzip.compress(bytes(logs))
        with self._lock:
            token = self.state["token"]
        self._request("POST", f"/fleet/jobs/{urllib.parse.quote(job['id'], safe='')}/logs", token=token,
                      raw=data, content_type="application/gzip", timeout=30)
        return f"{len(data) / 1024:.1f} KB uploaded"

    # ---------- sync ----------

    def _heartbeat(self):
        with self._lock:
            token = self.state["token"]
            results = list(self.state["results"])
            management = {"allowed": list(self.state["allowed"]), "key_fingerprint": self.fingerprint(),
                          "client": FLEET_CLIENT_VERSION}
        try:
            status = dict(self.status() or {})
        except Exception:
            status = {}
        _, resp = self._request("POST", "/fleet/heartbeat", token=token,
                                body={"status": status, "management": management, "job_results": results})
        with self._lock:
            if not (self.state["enabled"] and self.state["token"] == token):
                return   # an answer for an enrolment that no longer exists
            sent = {r["id"] for r in results}
            self.state["results"] = [r for r in self.state["results"] if r["id"] not in sent]
            if isinstance(resp.get("device"), dict):
                self.state["device"] = {k: resp["device"].get(k) for k in ("id", "label", "group")}
            self.state["heartbeat_interval"] = _interval(resp.get("heartbeat_interval"))
            jobs = resp.get("jobs")
            if isinstance(jobs, list):
                for job in sorted((j for j in jobs if isinstance(j, dict) and isinstance(j.get("seq"), int)),
                                  key=lambda j: j["seq"]):
                    self._accept(job)
            self._save()
        if self.state["queue"]:
            self._work.set()

    def sync_once(self):
        """One heartbeat. Returns True on success."""
        with self._lock:
            if not self.state["enabled"]:
                return False
            token = self.state["token"]
        try:
            self._heartbeat()
        except CTFClientError as exc:
            with self._lock:
                if not (self.state["enabled"] and self.state["token"] == token):
                    return False
                self.state["last_error"] = {"code": exc.code, "message": exc.message, "time": time.time()}
                if exc.status == 401 and exc.from_server:
                    # Retired by the organiser: stop until the user enrols again.
                    self.state["enabled"] = False
                    self.state["revoked"] = True
                    self.state["queue"] = []
                self._try_save()
            return False
        with self._lock:
            if self.state["token"] == token:
                self.state["last_contact"] = time.time()
                if (self.state["last_error"] or {}).get("code") != "bad_signature":
                    self.state["last_error"] = None
                self._try_save()
        return True

    # ---------- background loops ----------

    def start(self):
        if any(t.is_alive() for t in self._threads):
            return
        self._stop.clear()
        self._threads = [threading.Thread(target=self._run, name="central-fleet", daemon=True),
                         threading.Thread(target=self._run_jobs, name="central-fleet-jobs", daemon=True)]
        for thread in self._threads:
            thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        self._work.set()

    def _run(self):
        failures = 0
        while not self._stop.is_set():
            try:
                ok = self.sync_once()
            except Exception:
                log.exception("fleet: sync failed")
                ok = False
            failures = 0 if ok else failures + 1
            with self._lock:
                interval = _interval(self.state.get("heartbeat_interval"))
                enabled = self.state["enabled"]
            delay = interval if ok or not enabled else min(300, interval * (2 ** min(failures, 4)))
            self._wake.wait(delay if enabled else 3600)
            self._wake.clear()

    def _run_jobs(self):
        """Jobs run one at a time on their own thread, so heartbeats keep going meanwhile."""
        while not self._stop.is_set():
            try:
                while self.run_next_job():
                    pass
            except Exception:
                log.exception("fleet: job runner failed")
            self._work.wait(60)
            self._work.clear()
