"""Structured JSON logging pipeline for attacker interactions.

All attacker data (connections, logins, commands, session ends) is
written here — never to stdout in production (CLAUDE.md Rule 6).

Named ``event_logging`` rather than ``logging`` to avoid shadowing
Python's stdlib ``logging`` package (which would break pytest and any
third-party dependency that imports stdlib logging at import time).
"""

from event_logging.session_logger import SessionLogger  # noqa: F401

__all__ = ["SessionLogger"]
