"""
Command-line administration, for scripted setups:

    flask --app cybics_mgmt create-event workshop-2026 "CybICS Workshop 2026"
    flask --app cybics_mgmt import-catalog workshop-2026 path/to/ctf_config.json
    flask --app cybics_mgmt set-state workshop-2026 running
    flask --app cybics_mgmt list-events
    flask --app cybics_mgmt backup /data/backup-$(date +%F).sqlite
    flask --app cybics_mgmt login-link

The event commands live in ctf/cli.py.
"""
import os
import secrets
import time

import click
from flask import current_app

from .ctf import cli as ctf_cli
from .db import get_db, now
from .security import audit, hash_token

BACKUP_PREFIX = "cybics-mgmt-"


def init_app(app):
    ctf_cli.init_app(app)

    @app.cli.command("backup")
    @click.argument("path", type=click.Path())
    @click.option("--keep", type=int, default=0,
                  help="With a directory: keep only the newest N backups in it (0 keeps all).")
    def backup(path, keep):
        """
        Write a consistent copy of the database (safe while the server runs).

        PATH is a new file, or a directory that gets a timestamped file; with
        --keep, older backups in that directory are pruned (for a cron job).
        """
        directory = path if os.path.isdir(path) else None
        if directory:
            path = os.path.join(directory, time.strftime(f"{BACKUP_PREFIX}%Y%m%d-%H%M%S.sqlite"))
        if os.path.exists(path):
            raise click.ClickException(f"{path} already exists.")
        # VACUUM INTO reads a consistent snapshot, including what still sits in
        # the WAL; copying the .sqlite file alone can miss recent writes.
        get_db().execute("VACUUM INTO ?", (path,))
        click.echo(f"Backup written to {path}.")
        if directory and keep > 0:
            old = sorted(f for f in os.listdir(directory)
                         if f.startswith(BACKUP_PREFIX) and f.endswith(".sqlite"))[:-keep]
            for name in old:
                os.unlink(os.path.join(directory, name))
                click.echo(f"Removed old backup {name}.")

    @app.cli.command("login-link")
    @click.option("--minutes", type=int, default=10, help="How long the link stays valid.")
    def login_link(minutes):
        """Print a one-time admin login link (works even while logins are rate limited)."""
        minutes = max(1, minutes)
        token = secrets.token_urlsafe(32)
        get_db().execute("INSERT INTO login_links (token_hash, expires_at) VALUES (?, ?)",
                         (hash_token(token), now() + minutes * 60))
        audit("login_link_created", actor="cli", minutes=minutes)
        base = current_app.config["PUBLIC_URL"] or "http://<server>:8000"
        click.echo(f"Open within {minutes} min, once: {base}/admin/login/link/{token}")
