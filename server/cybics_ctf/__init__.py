"""
CybICS CTF central server.

An optional companion to CybICS (https://github.com/mniedermaier/CybICS):
virtual and physical CybICS instances that the user enrols from the landing
page report their team, status and solves here, and the organiser runs a
shared scoreboard. A CybICS instance never needs this server to work.
"""
import logging
import os
import secrets
import tempfile
from pathlib import Path

from flask import Flask

__version__ = "0.1.0"

log = logging.getLogger("cybics_ctf")


def _env_int(name, default):
    return int(os.environ.get(name, default))


SECRET_MIN_LENGTH = 16


def _persistent_secret(data_dir, name):
    """
    Read a secret from the data volume, creating it on first start. Returns
    (value, created).

    The file appears atomically with its full content (written to a temporary
    file, fsynced, then hard-linked into place), so a second process starting
    at the same moment never reads it half-written. An empty or truncated file
    (emptied by hand, disk full, power loss) is replaced, never used: an empty
    admin password would let any login through.
    """
    path = Path(data_dir) / name
    while True:
        try:
            value = path.read_text().strip()
        except FileNotFoundError:
            value = None
        if value is not None and len(value) >= SECRET_MIN_LENGTH:
            return value, False
        value = secrets.token_urlsafe(32)
        fd, tmp = tempfile.mkstemp(dir=data_dir, prefix=f".{name}.")
        try:
            with os.fdopen(fd, "w") as f:   # mkstemp creates the file 0600
                f.write(value)
                f.flush()
                os.fsync(f.fileno())
            if path.exists():
                os.replace(tmp, path)       # unusable file: replace it
                log.warning("%s was empty or too short; generated a new one", path)
                return value, True
            try:
                os.link(tmp, path)          # fails if another process won the race
            except FileExistsError:
                continue                    # read the winner's value
            return value, True
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


def _configure_logging():
    """Log to stderr (gunicorn and docker logs pick it up), once per process."""
    if not log.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        log.addHandler(handler)
        log.setLevel(os.environ.get("CTF_LOG_LEVEL", "INFO").upper())
        log.propagate = False


def create_app(test_config=None):
    _configure_logging()
    app = Flask(__name__)
    data_dir = os.environ.get("CTF_DATA_DIR", os.path.join(os.getcwd(), "data"))

    app.config.update(
        DATA_DIR=data_dir,
        DATABASE=os.path.join(data_dir, "cybics-ctf.sqlite"),
        SERVER_NAME_DISPLAY=os.environ.get("CTF_SERVER_NAME", "CybICS CTF"),
        HEARTBEAT_INTERVAL=_env_int("CTF_HEARTBEAT_INTERVAL", 30),
        # Where organisers reach the server, for links the CLI prints.
        PUBLIC_URL=os.environ.get("CTF_PUBLIC_URL", "").rstrip("/"),
        # An instance counts as online if it checked in within this many seconds.
        ONLINE_WINDOW=_env_int("CTF_ONLINE_WINDOW", 90),
        # (hits, seconds) per key. All per-address limits count failures only;
        # see "Shared addresses" in docs/ARCHITECTURE.md.
        # Wrong team passwords per address per minute; 0 switches it off.
        RATE_LIMIT_ENROLL=(_env_int("CTF_RATE_ENROLL", 60), 60),
        RATE_LIMIT_HEARTBEAT=(_env_int("CTF_RATE_HEARTBEAT", 30), 60),
        RATE_LIMIT_SOLVE=(_env_int("CTF_RATE_SOLVE", 30), 60),
        RATE_LIMIT_LOGIN=(_env_int("CTF_RATE_LOGIN", 10), 300),
        # New teams per client address: keeps one person with the join code
        # from flooding the projector with junk teams.
        RATE_LIMIT_NEW_TEAMS=(_env_int("CTF_RATE_NEW_TEAMS", 100), 600),
        # Requests with an unknown or revoked token, per address. Valid tokens
        # are never limited by this.
        RATE_LIMIT_BAD_TOKEN=(60, 60),
        ADMIN_SESSION_LIFETIME=_env_int("CTF_ADMIN_SESSION_HOURS", 12) * 3600,
        MAX_CONTENT_LENGTH=1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("CTF_SECURE_COOKIES", "0") == "1",
    )
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.config["DATA_DIR"], exist_ok=True)
    if not app.config.get("SECRET_KEY"):
        key = (os.environ.get("CTF_SECRET_KEY") or "").strip()
        if key and len(key) < SECRET_MIN_LENGTH:
            raise RuntimeError(f"CTF_SECRET_KEY must be at least {SECRET_MIN_LENGTH} characters.")
        app.config["SECRET_KEY"] = key or _persistent_secret(app.config["DATA_DIR"], "secret_key")[0]
    if not app.config.get("ADMIN_PASSWORD"):
        password = (os.environ.get("CTF_ADMIN_PASSWORD") or "").strip()
        if password and len(password) < 8:
            # Local testing only: an explicit opt-in, and loud about it.
            if os.environ.get("CTF_ALLOW_WEAK_ADMIN_PASSWORD") != "1":
                raise RuntimeError("CTF_ADMIN_PASSWORD must be at least 8 characters "
                                   "(set CTF_ALLOW_WEAK_ADMIN_PASSWORD=1 for a local test setup).")
            log.warning("CTF_ALLOW_WEAK_ADMIN_PASSWORD=1: the admin password is shorter than 8 characters. "
                        "Never run an event like this.")
        if not password:
            password, created = _persistent_secret(app.config["DATA_DIR"], "admin_password")
            if created:
                log.warning("CTF_ADMIN_PASSWORD not set; generated an admin password in %s/admin_password",
                            app.config["DATA_DIR"])
        app.config["ADMIN_PASSWORD"] = password

    # Behind a reverse proxy (Caddy/nginx/Traefik), take the client address
    # from X-Forwarded-For, so rate limits and the audit log see the real
    # client. Only for requests that come from the proxy itself.
    if os.environ.get("CTF_TRUST_PROXY", "0") == "1":
        from .security import TrustedProxyFix
        app.wsgi_app = TrustedProxyFix(app.wsgi_app,
                                       os.environ.get("CTF_FORWARDED_ALLOW_IPS", "127.0.0.1"),
                                       hops=max(1, _env_int("CTF_PROXY_HOPS", 1)))

    from . import admin, api, cli, db, public, views
    db.init_app(app)
    app.register_blueprint(api.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(public.bp)
    views.init_app(app)
    cli.init_app(app)
    return app
