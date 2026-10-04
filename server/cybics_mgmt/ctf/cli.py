"""Event commands: create-event, import-catalog, set-state, list-events."""
import click

from ..db import get_db
from ..security import audit
from . import logic as ctf
from .logic import CTFError


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
