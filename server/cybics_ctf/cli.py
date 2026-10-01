"""
Command-line administration, for scripted setups:

    flask --app cybics_ctf create-event workshop-2026 "CybICS Workshop 2026"
    flask --app cybics_ctf import-catalog workshop-2026 path/to/ctf_config.json
    flask --app cybics_ctf set-state workshop-2026 running
    flask --app cybics_ctf list-events
    flask --app cybics_ctf backup /data/backup-$(date +%F).sqlite
"""
import os
import secrets
import time

import click
from flask import current_app

from . import ctf
from .ctf import CTFError
from .db import get_db, now
from .security import audit, hash_token


def _event(slug):
    event = ctf.get_event_by_slug(get_db(), slug)
    if event is None:
        raise click.ClickException(f"No event with slug '{slug}'.")
    return event


def init_app(app):
    @app.cli.command("create-event")
    @click.argument("slug")
    @click.argument("name")
    def create_event(slug, name):
        """Create an event and print its join code."""
        try:
            event = ctf.create_event(get_db(), slug, name)
        except CTFError as exc:
            raise click.ClickException(exc.message) from exc
        audit("create_event", event_id=event["id"], actor="cli", slug=event["slug"])
        click.echo(f"Created '{event['name']}' ({event['slug']}), join code {event['join_code']}")

    @app.cli.command("import-catalog")
    @click.argument("slug")
    @click.argument("path", type=click.File("rb"))
    def import_catalog(slug, path):
        """Import challenges from CybICS' software/landing/ctf_config.json ('-' reads stdin)."""
        event = _event(slug)
        try:
            count = ctf.import_catalog(get_db(), event["id"], path.read())
        except CTFError as exc:
            raise click.ClickException(exc.message) from exc
        audit("import_catalog", event_id=event["id"], actor="cli", challenges=count)
        click.echo(f"Imported {count} challenges into '{slug}'.")

    @app.cli.command("set-state")
    @click.argument("slug")
    @click.argument("state", type=click.Choice(ctf.EVENT_STATES))
    def set_state(slug, state):
        """Move an event to draft, running, paused or finished."""
        event = _event(slug)
        try:
            ctf.set_event_state(get_db(), event["id"], state)
        except CTFError as exc:
            raise click.ClickException(exc.message) from exc
        audit("event_state", event_id=event["id"], actor="cli", state=state)
        click.echo(f"'{slug}' is now {state}.")

    @app.cli.command("list-events")
    def list_events():
        """List events with their state and join code."""
        for event in ctf.list_events(get_db()):
            click.echo(f"{event['slug']:24} {event['state']:9} {event['join_code']}  {event['name']}")

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
            path = os.path.join(directory, time.strftime("cybics-ctf-%Y%m%d-%H%M%S.sqlite"))
        if os.path.exists(path):
            raise click.ClickException(f"{path} already exists.")
        # VACUUM INTO reads a consistent snapshot, including what still sits in
        # the WAL; copying the .sqlite file alone can miss recent writes.
        get_db().execute("VACUUM INTO ?", (path,))
        click.echo(f"Backup written to {path}.")
        if directory and keep > 0:
            old = sorted(f for f in os.listdir(directory)
                         if f.startswith("cybics-ctf-") and f.endswith(".sqlite"))[:-keep]
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
