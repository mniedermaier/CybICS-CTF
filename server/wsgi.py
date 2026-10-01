"""gunicorn entry point: gunicorn wsgi:app"""
from cybics_ctf import create_app

app = create_app()
