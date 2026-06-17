"""Structured JSON session logger (Sprint 1 deliverable).

Emits one JSON line per attacker event to a daily-rotated log file. The
log schema follows CLAUDE.md §5 Module 1 logging design:

    timestamp        ISO-8601 UTC, ms precision
    event_type       session_start | login_attempt | command |
                     persona_switch | session_end
    session_id       Cowrie session id (stable per connection)
    attacker_ip      source IP
    attacker_port    source port

Per-event extras:

    login_attempt    username, password, success (bool)
    command          command, cwd, threat_score_after, persona,
                     response_source ("dict" | "llm")
    persona_switch   from_persona, to_persona, trigger_score
    session_end      duration_s, command_count, final_threat_score

Note on package naming
----------------------
This module lives in ``event_logging/`` rather than the ``logging/``
path suggested in CLAUDE.md §8. A top-level package named ``logging``
shadows Python's stdlib ``logging`` package and breaks pytest and any
third-party library that does ``from logging import ...`` at import
time. ``event_logging`` also reads more precisely — attacker event
logging, not general-purpose logging.
"""
from __future__ import annotations

import logging as _stdlog
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional, Union

from pythonjsonlogger import jsonlogger


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

_VALID_RESPONSE_SOURCES = {"dict", "llm"}
_VALID_EVENT_TYPES = {
    "session_start",
    "login_attempt",
    "command",
    "persona_switch",
    "session_end",
}


def _iso(ts: datetime) -> str:
    """Serialize a datetime as ISO-8601 UTC with millisecond precision."""
    return (
        ts.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _coerce_time(ts: Union[datetime, str, None]) -> datetime:
    if ts is None:
        return datetime.now(timezone.utc)
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, str):
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    raise TypeError(f"unsupported timestamp type: {type(ts).__name__}")


@dataclass
class _SessionState:
    """In-memory per-session rollup used by ``get_session_summary``."""

    session_id: str
    attacker_ip: str
    attacker_port: int
    start_time: datetime
    command_count: int = 0
    login_attempts: int = 0
    successful_logins: int = 0
    last_threat_score: int = 0
    active_persona: Optional[str] = None
    persona_switch_count: int = 0
    end_time: Optional[datetime] = None


class _EventJsonFormatter(jsonlogger.JsonFormatter):
    """JsonFormatter that drops the default ``message`` key.

    We pass the full event dict via ``extra=`` and don't want the stdlib
    logging ``message`` field duplicating ``event_type``.
    """

    def add_fields(self, log_record, record, message_dict):  # type: ignore[override]
        super().add_fields(log_record, record, message_dict)
        log_record.pop("message", None)
        log_record.pop("taskName", None)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class SessionLogger:
    """Append-only JSON-lines logger for attacker sessions.

    Writes to ``<log_dir>/<filename>`` using a
    :class:`logging.handlers.TimedRotatingFileHandler` that rotates at
    UTC midnight. Rotated files are suffixed by date (e.g.
    ``honeypot.jsonl.2026-04-12``) and up to ``backup_count`` kept.

    Also maintains an in-memory rollup per ``session_id`` exposed via
    :meth:`get_session_summary`. The rollup is updated on every event
    and frozen when :meth:`log_session_end` is called.

    Thread-safe: summary updates are guarded by an instance lock;
    file writes are serialized by the stdlib handler lock.
    """

    def __init__(
        self,
        log_dir: Union[str, Path] = "event_logging/logs",
        filename: str = "honeypot.jsonl",
        backup_count: int = 30,
        logger_name: Optional[str] = None,
    ) -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.filepath = self.log_dir / filename

        name = logger_name or f"honeypot.session.{id(self)}"
        self._logger = _stdlog.getLogger(name)
        self._logger.setLevel(_stdlog.INFO)
        self._logger.propagate = False

        # Clean any handlers from a prior instance with the same name
        # (common in tests that build many SessionLogger objects).
        for h in list(self._logger.handlers):
            self._logger.removeHandler(h)
            try:
                h.close()
            except Exception:
                pass

        handler = TimedRotatingFileHandler(
            filename=str(self.filepath),
            when="midnight",
            interval=1,
            backupCount=backup_count,
            utc=True,
            encoding="utf-8",
        )
        handler.setFormatter(_EventJsonFormatter("%(message)s", json_ensure_ascii=False))
        self._logger.addHandler(handler)
        self._handler = handler

        self._sessions: Dict[str, _SessionState] = {}
        self._lock = threading.Lock()

    # -- session lifecycle -------------------------------------------------

    def log_session_start(
        self,
        session_id: str,
        attacker_ip: str,
        attacker_port: int,
        timestamp: Union[datetime, str, None] = None,
    ) -> None:
        """Record a new SSH connection. Creates the session rollup."""
        now = _coerce_time(timestamp)
        with self._lock:
            self._sessions[session_id] = _SessionState(
                session_id=session_id,
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                start_time=now,
            )
        self._emit(
            {
                "timestamp": _iso(now),
                "event_type": "session_start",
                "session_id": session_id,
                "attacker_ip": attacker_ip,
                "attacker_port": attacker_port,
            }
        )

    def log_login_attempt(
        self,
        session_id: str,
        username: str,
        password: str,
        success: bool,
        timestamp: Union[datetime, str, None] = None,
    ) -> None:
        """Record an SSH auth attempt (successful or not)."""
        now = _coerce_time(timestamp)
        with self._lock:
            st = self._sessions.get(session_id)
            if st is not None:
                st.login_attempts += 1
                if success:
                    st.successful_logins += 1
            ip = st.attacker_ip if st else None
            port = st.attacker_port if st else None
        self._emit(
            {
                "timestamp": _iso(now),
                "event_type": "login_attempt",
                "session_id": session_id,
                "attacker_ip": ip,
                "attacker_port": port,
                "username": username,
                "password": password,
                "success": bool(success),
            }
        )

    def log_command(
        self,
        session_id: str,
        command: str,
        cwd: str,
        threat_score_after: int,
        persona: str,
        response_source: str,
        timestamp: Union[datetime, str, None] = None,
        threat_category: Optional[str] = None,
        threat_score_delta: int = 0,
        threat_level: Optional[str] = None,
        patterns_detected: Optional[list] = None,
    ) -> None:
        """Record a command executed inside a session.

        ``response_source`` must be ``"dict"`` (fast path) or ``"llm"``
        (slow path) — matches the two Response Engine paths in
        CLAUDE.md §5 Module 3.
        """
        if response_source not in _VALID_RESPONSE_SOURCES:
            raise ValueError(
                f"response_source must be one of {_VALID_RESPONSE_SOURCES}, "
                f"got {response_source!r}"
            )
        now = _coerce_time(timestamp)
        with self._lock:
            st = self._sessions.get(session_id)
            if st is not None:
                if st.active_persona is not None and st.active_persona != persona:
                    st.persona_switch_count += 1
                st.command_count += 1
                st.last_threat_score = int(threat_score_after)
                st.active_persona = persona
            ip = st.attacker_ip if st else None
            port = st.attacker_port if st else None
        payload: Dict[str, Any] = {
            "timestamp": _iso(now),
            "event_type": "command",
            "session_id": session_id,
            "attacker_ip": ip,
            "attacker_port": port,
            "command": command,
            "cwd": cwd,
            "threat_score_after": int(threat_score_after),
            "persona": persona,
            "response_source": response_source,
        }
        if threat_category is not None:
            payload["threat_category"] = threat_category
        if threat_score_delta:
            payload["threat_score_delta"] = threat_score_delta
        if threat_level is not None:
            payload["threat_level"] = threat_level
        if patterns_detected:
            payload["patterns_detected"] = patterns_detected
        self._emit(payload)

    def log_session_end(
        self,
        session_id: str,
        timestamp: Union[datetime, str, None] = None,
    ) -> None:
        """Close a session. Emits duration, command count, final score."""
        now = _coerce_time(timestamp)
        with self._lock:
            st = self._sessions.get(session_id)
            if st is None:
                duration_s = 0.0
                command_count = 0
                final_score = 0
                persona = None
                ip: Optional[str] = None
                port: Optional[int] = None
            else:
                st.end_time = now
                duration_s = (now - st.start_time).total_seconds()
                command_count = st.command_count
                final_score = st.last_threat_score
                persona = st.active_persona
                ip = st.attacker_ip
                port = st.attacker_port
        self._emit(
            {
                "timestamp": _iso(now),
                "event_type": "session_end",
                "session_id": session_id,
                "attacker_ip": ip,
                "attacker_port": port,
                "duration_s": duration_s,
                "command_count": command_count,
                "final_threat_score": final_score,
                "active_persona": persona,
            }
        )

    # -- introspection -----------------------------------------------------

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """Return the current in-memory rollup for ``session_id``.

        Raises ``KeyError`` if no ``log_session_start`` has been recorded
        for that id.
        """
        with self._lock:
            st = self._sessions.get(session_id)
            if st is None:
                raise KeyError(session_id)
            end = st.end_time or datetime.now(timezone.utc)
            return {
                "session_id": st.session_id,
                "attacker_ip": st.attacker_ip,
                "attacker_port": st.attacker_port,
                "start_time": _iso(st.start_time),
                "end_time": _iso(st.end_time) if st.end_time else None,
                "duration_s": (end - st.start_time).total_seconds(),
                "command_count": st.command_count,
                "login_attempts": st.login_attempts,
                "successful_logins": st.successful_logins,
                "final_threat_score": st.last_threat_score,
                "active_persona": st.active_persona,
                "persona_switch_count": st.persona_switch_count,
                "is_closed": st.end_time is not None,
            }

    def close(self) -> None:
        """Detach and close the rotating file handler. Safe to call twice."""
        for h in list(self._logger.handlers):
            self._logger.removeHandler(h)
            try:
                h.close()
            except Exception:
                pass

    # -- internals ---------------------------------------------------------

    def _emit(self, payload: Dict[str, Any]) -> None:
        # Validate defensively — cheap, catches programmer error early.
        et = payload.get("event_type")
        if et not in _VALID_EVENT_TYPES:
            raise ValueError(f"invalid event_type {et!r}")
        self._logger.info(et, extra=payload)
