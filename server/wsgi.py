"""gunicorn entry point: gunicorn wsgi:app"""
from cybics_mgmt import create_app

app = create_app()
