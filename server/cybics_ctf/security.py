"""
Credentials, hashing and rate limiting.

Threat model, in short: CybICS flags are identical in every installation and
printed in the training READMEs, and a participant fully controls a virtual
instance. The server therefore cannot prove that a team solved a challenge,
only that an enrolled instance reported a correct flag. What it can do is make
the honest path the easy one, keep an audit trail (wrong submissions, timing,
platform), and give the organiser the tools to act on it. See docs/ARCHITECTURE.md.
"""
import functools
import hashlib
import hmac
import ipaddress
import logging
import secrets
import threading
import time
from collections import defaultdict, deque

from flask import abort, current_app, redirect, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

log = logging.getLogger("cybics_ctf")


def new_token():
    return secrets.token_urlsafe(32)


def hash_token(token):
    # Tokens are 256 bits of randomness; a fast hash is the right tool and
    # allows an indexed lookup. Passwords are a different matter (see teams).
    return hashlib.sha256(token.encode()).hexdigest()


def hash_flag(flag):
    """Flags are public anyway; hashing only keeps them out of DB dumps and the UI."""
    return hashlib.sha256(flag.strip().encode()).hexdigest()


def flag_matches(flag, flag_hash):
    return hmac.compare_digest(hash_flag(flag), flag_hash)


def new_join_code():
    # Readable over a projector: no 0/O, 1/I/L.
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(8))


class RateLimiter:
    """
    Sliding-window limiter kept in process memory.

    Good enough for the single-process deployment the Dockerfile uses (one
    gunicorn worker with threads, which SQLite wants anyway). With several
    workers each one counts separately, which loosens but does not break it.
    """

    # Keys idle for longer than this are dropped, so a long event with many
    # client addresses does not grow the table forever.
    IDLE = 3600
    PRUNE_EVERY = 1000

    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()
        self._calls = 0

    def _window(self, key, window, now):
        hits = self._hits[key]
        while hits and hits[0] <= now - window:
            hits.popleft()
        return hits

    def _prune(self, now):
        self._calls += 1
        if self._calls % self.PRUNE_EVERY:
            return
        for key in [k for k, hits in self._hits.items() if not hits or hits[-1] <= now - self.IDLE]:
            del self._hits[key]

    def hit(self, key, limit, window):
        """Record one hit; return False if the key is over `limit` per `window` seconds."""
        if limit <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            hits = self._window(key, window, now)
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    def exceeded(self, key, limit, window):
        """True if `key` already has `limit` hits in the window; records nothing."""
        if limit <= 0:
            return False
        with self._lock:
            return len(self._window(key, window, time.monotonic())) >= limit

    def record(self, key):
        with self._lock:
            self._hits[key].append(time.monotonic())

    def tripped(self, prefix, limit, window):
        """Key suffixes under `prefix` that are currently at or over `limit`."""
        now = time.monotonic()
        with self._lock:
            return sorted(key[len(prefix):] for key in list(self._hits)
                          if key.startswith(prefix) and len(self._window(key, window, now)) >= limit)

    def clear_prefixes(self, prefixes):
        with self._lock:
            for key in [k for k in self._hits if k.startswith(tuple(prefixes))]:
                del self._hits[key]

    def reset(self):
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()


def client_ip():
    return request.remote_addr or "unknown"


class TrustedProxyFix:
    """
    Apply X-Forwarded-* only to requests whose direct peer is a configured
    proxy. Plain ProxyFix trusts the header from anyone who can reach the
    port, which would let a client pick its own address and walk around every
    per-IP rate limit.
    """

    def __init__(self, app, trusted, hops=1):
        self.app = app
        # Host is not taken from headers: nginx passes the client's
        # X-Forwarded-Host through untouched, and nothing needs it.
        self.fixed = ProxyFix(app, x_for=hops, x_proto=1, x_host=0)
        self.networks = [ipaddress.ip_network(n.strip(), strict=False)
                         for n in trusted.split(",") if n.strip()]

    def _trusted(self, addr):
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        return any(ip in net for net in self.networks)

    def __call__(self, environ, start_response):
        if self._trusted(environ.get("REMOTE_ADDR", "")):
            return self.fixed(environ, start_response)
        return self.app(environ, start_response)


# ---------- admin session ----------

def check_admin_password(password):
    expected = current_app.config.get("ADMIN_PASSWORD") or ""
    if not expected or not password:   # never let an empty password match an empty one
        return False
    return hmac.compare_digest(password.encode(), expected.encode())


# scrypt costs ~0.25 s of CPU and a chunk of memory per call. Bound how many
# run at once, so a burst of enrolments cannot starve heartbeats of CPU.
_hashing = threading.BoundedSemaphore(2)
# How long a request may wait for a hashing slot. Waiting holds a gunicorn
# thread; past this, the request gets "busy, retry" instead, so a flood of
# enrolments can never pile up enough waiters to stall heartbeats and solves.
HASH_WAIT = 2.0


class HashingBusy(Exception):
    pass


def _with_hashing_slot(fn, *args):
    if not _hashing.acquire(timeout=HASH_WAIT):
        raise HashingBusy()
    try:
        return fn(*args)
    finally:
        _hashing.release()


def hash_password(password):
    from werkzeug.security import generate_password_hash
    return _with_hashing_slot(generate_password_hash, password)


def verify_password(password_hash, password):
    from werkzeug.security import check_password_hash
    return _with_hashing_slot(check_password_hash, password_hash, password)


_fingerprints = {}
_fingerprint_lock = threading.Lock()


def _password_fingerprint():
    """
    Ties a session to the current admin password: changing it logs everyone
    out. Derived with scrypt (salted with the secret key), computed once per
    password and cached, so the password never meets a fast hash.
    """
    key = current_app.config["SECRET_KEY"]
    key = key.encode() if isinstance(key, str) else key
    password = current_app.config["ADMIN_PASSWORD"].encode()
    cache_key = (key, password)
    with _fingerprint_lock:
        fingerprint = _fingerprints.get(cache_key)
        if fingerprint is None:
            fingerprint = hashlib.scrypt(password, salt=key, n=2**14, r=8, p=1, dklen=16).hex()
            _fingerprints.clear()   # only the current password matters
            _fingerprints[cache_key] = fingerprint
    return fingerprint


def start_admin_session():
    from .db import get_db
    session.clear()
    sid = secrets.token_urlsafe(24)
    get_db().execute("INSERT INTO admin_sessions (id, created_at) VALUES (?, ?)", (sid, time.time()))
    session["admin"] = _password_fingerprint()
    session["admin_since"] = time.time()
    session["admin_sid"] = sid


def end_admin_session():
    """Log out for real: the session id is ended server side, a copied cookie stops working too."""
    from .db import get_db
    sid = session.get("admin_sid")
    if isinstance(sid, str):
        get_db().execute("UPDATE admin_sessions SET ended_at = ? WHERE id = ? AND ended_at IS NULL",
                         (time.time(), sid))
    session.clear()


def is_admin():
    from .db import get_db
    fingerprint = session.get("admin")
    since = session.get("admin_since") or 0
    sid = session.get("admin_sid")
    if not isinstance(fingerprint, str) or not hmac.compare_digest(fingerprint, _password_fingerprint()):
        return False
    if time.time() - since >= current_app.config["ADMIN_SESSION_LIFETIME"]:
        return False
    if not isinstance(sid, str):
        return False
    row = get_db().execute("SELECT ended_at FROM admin_sessions WHERE id = ?", (sid,)).fetchone()
    return row is not None and row["ended_at"] is None


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not is_admin():
            session.pop("admin", None)
            return redirect(url_for("admin.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def audit(action, event_id=None, actor=None, **details):
    """
    Record an organiser action: a row in admin_log (shown on the event's Log
    page, survives container recreation) and a log line. Logged at WARNING so
    raising CTF_LOG_LEVEL never hides it.
    """
    from .db import get_db, now
    actor = actor or f"web {client_ip()}"
    extra = " ".join(f"{k}={v!r}" for k, v in details.items())
    get_db().execute("INSERT INTO admin_log (event_id, action, details, actor, created_at) VALUES (?, ?, ?, ?, ?)",
                     (event_id, action, extra, actor, now()))
    log.warning("admin %s by %s event=%s %s", action, actor, event_id, extra)


def csrf_token():
    token = session.get("csrf")
    if not token:
        token = session["csrf"] = secrets.token_urlsafe(32)
    return token


def check_csrf():
    """Every state-changing admin form posts the session's CSRF token."""
    sent = request.form.get("csrf", "")
    # As bytes: compare_digest raises TypeError on non-ASCII str.
    if not sent or not hmac.compare_digest(sent.encode("utf-8", "replace"),
                                           str(session.get("csrf", "")).encode("utf-8", "replace")):
        abort(400, "CSRF token missing or invalid")
