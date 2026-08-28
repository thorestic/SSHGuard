"""Read-only HTTP API for SSHGuard security telemetry."""

from .app import app, create_app

__all__ = ["app", "create_app"]

