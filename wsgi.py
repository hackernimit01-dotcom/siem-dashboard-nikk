"""WSGI entrypoint for production servers."""

from app import app, bootstrap_application

bootstrap_application()
application = app
