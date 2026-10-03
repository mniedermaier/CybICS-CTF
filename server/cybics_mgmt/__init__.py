"""
CybICS-mgmt: the optional central server for CybICS.

An optional companion to CybICS (https://github.com/mniedermaier/CybICS).
CybICS installations, virtual and physical, enrol as devices from their
landing page. The organiser sees and manages them in the fleet, and runs CTF
events in which devices report their team's solves to a shared scoreboard. A
CybICS installation never needs this server to work.
"""
import logging
import os
import secrets
import tempfile
from pathlib import Path

from flask import Flask

from . import db

__version__ = "0.1.0"

log = logging.getLogger("cybics_mgmt")

ENV_PREFIX = "MGMT_"


def env(name, default=None):
    """
    The setting MGMT_<name>, else `default`. Blank values count as unset, as
    they do in docker compose files that pass every variable through.
    """
    value = os.environ.get(ENV_PREFIX + name)
    return value if value is not None and value.strip() else default


def _env_int(name, default):
    return int(env(name, default))


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
        log.setLevel(env("LOG_LEVEL", "INFO").upper())
        log.propagate = False


def _ensure_default_code(app):
    from .fleet import logic as fleet
    conn = db.connect(app.config["DATABASE"])
    try:
        if fleet.ensure_code(conn, app.config["DEFAULT_ENROL_CODE"], "Default for CybICS boards"):
            log.warning("created the default enrolment code %s", app.config["DEFAULT_ENROL_CODE"].upper())
    finally:
        conn.close()


def create_app(test_config=None):
    _configure_logging()
    app = Flask(__name__)
    data_dir = env("DATA_DIR", os.path.join(os.getcwd(), "data"))

    app.config.update(
        DATA_DIR=data_dir,
        DATABASE=os.path.join(data_dir, db.DATABASE_NAME),
        SERVER_NAME_DISPLAY=env("SERVER_NAME", "CybICS-mgmt"),
        HEARTBEAT_INTERVAL=_env_int("HEARTBEAT_INTERVAL", 30),
        # Where organisers reach the server, for links the CLI prints.
        PUBLIC_URL=env("PUBLIC_URL", "").rstrip("/"),
        # An instance counts as online if it checked in within this many seconds.
        ONLINE_WINDOW=_env_int("ONLINE_WINDOW", 90),
        # (hits, seconds) per key. All per-address limits count failures only;
        # see "Shared addresses" in docs/ARCHITECTURE.md.
        # Wrong team passwords per address per minute; 0 switches it off.
        RATE_LIMIT_JOIN=(_env_int("RATE_JOIN", 60), 60),
        RATE_LIMIT_HEARTBEAT=(_env_int("RATE_HEARTBEAT", 30), 60),
        RATE_LIMIT_SOLVE=(_env_int("RATE_SOLVE", 30), 60),
        RATE_LIMIT_LOGIN=(_env_int("RATE_LOGIN", 10), 300),
        # New teams per client address: keeps one person with the join code
        # from flooding the projector with junk teams.
        RATE_LIMIT_NEW_TEAMS=(_env_int("RATE_NEW_TEAMS", 100), 600),
        # Unknown fleet enrolment codes per address per minute, and new
        # devices one address may enrol per 10 minutes.
        RATE_LIMIT_ENROL_CODE=(_env_int("RATE_ENROL_CODE", 60), 60),
        RATE_LIMIT_NEW_DEVICES=(_env_int("RATE_NEW_DEVICES", 100), 600),
        # An enrolment code created at start if missing: the code CybICS
        # boards use to enrol on their own on the default network.
        DEFAULT_ENROL_CODE=(env("DEFAULT_ENROL_CODE") or "").strip(),
        # Requests with an unknown or revoked token, per address. Valid tokens
        # are never limited by this.
        RATE_LIMIT_BAD_TOKEN=(60, 60),
        ADMIN_SESSION_LIFETIME=_env_int("ADMIN_SESSION_HOURS", 12) * 3600,
        MAX_CONTENT_LENGTH=1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=env("SECURE_COOKIES", "0") == "1",
    )
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.config["DATA_DIR"], exist_ok=True)
    if not app.config.get("SECRET_KEY"):
        key = (env("SECRET_KEY") or "").strip()
        if key and len(key) < SECRET_MIN_LENGTH:
            raise RuntimeError(f"MGMT_SECRET_KEY must be at least {SECRET_MIN_LENGTH} characters.")
        app.config["SECRET_KEY"] = key or _persistent_secret(app.config["DATA_DIR"], "secret_key")[0]
    if not app.config.get("ADMIN_PASSWORD"):
        password = (env("ADMIN_PASSWORD") or "").strip()
        if password and len(password) < 8:
            # Local testing only: an explicit opt-in, and loud about it.
            if env("ALLOW_WEAK_ADMIN_PASSWORD") != "1":
                raise RuntimeError("MGMT_ADMIN_PASSWORD must be at least 8 characters "
                                   "(set MGMT_ALLOW_WEAK_ADMIN_PASSWORD=1 for a local test setup).")
            log.warning("MGMT_ALLOW_WEAK_ADMIN_PASSWORD=1: the admin password is shorter than 8 characters. "
                        "Never run an event like this.")
        if not password:
            password, created = _persistent_secret(app.config["DATA_DIR"], "admin_password")
            if created:
                log.warning("MGMT_ADMIN_PASSWORD not set; generated an admin password in %s/admin_password",
                            app.config["DATA_DIR"])
        app.config["ADMIN_PASSWORD"] = password

    # Behind a reverse proxy (Caddy/nginx/Traefik), take the client address
    # from X-Forwarded-For, so rate limits and the audit log see the real
    # client. Only for requests that come from the proxy itself.
    if env("TRUST_PROXY", "0") == "1":
        from .security import TrustedProxyFix
        app.wsgi_app = TrustedProxyFix(app.wsgi_app,
                                       env("FORWARDED_ALLOW_IPS", "127.0.0.1"),
                                       hops=max(1, _env_int("PROXY_HOPS", 1)))

    # The CTF and fleet modules attach their routes to the shared blueprints
    # on import, so they are imported before the blueprints are registered.
    from . import admin, api, cli, public, views
    from .ctf import admin as _ctf_admin  # noqa: F401
    from .ctf import api as _ctf_api  # noqa: F401
    from .ctf import public as _ctf_public  # noqa: F401
    from .fleet import admin as _fleet_admin  # noqa: F401
    from .fleet import api as _fleet_api  # noqa: F401
    db.init_app(app)
    if app.config.get("DEFAULT_ENROL_CODE"):
        _ensure_default_code(app)
    app.register_blueprint(api.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(public.bp)
    views.init_app(app)
    cli.init_app(app)
    return app
