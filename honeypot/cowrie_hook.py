"""Cowrie glue layer (Sprint 3).

Hooks our system into Cowrie's command handler so that commands are
intercepted BEFORE Cowrie's default processing, routed through our
Response Engine, and our output returned to the attacker in place of
Cowrie's.

Two public entry points:

    ``HoneypotCommandDispatcher``
        Drop-in replacement for Cowrie's ``HoneyPotCommand.call()`` loop.
        Instantiated once per SSH session by ``create_dispatcher()``.

    ``create_dispatcher(session_id, attacker_ip, persona_name)``
        Factory used by the Cowrie session-setup hook.

Touch points in Cowrie (per CLAUDE.md §5 Module 1):
    cowrie/shell/command.py — import ``create_dispatcher``, call
        ``dispatcher.dispatch(cmd)`` instead of Cowrie's built-in handler.

Do NOT modify Cowrie's SSH handshake, auth flow, or session tracking —
keep this hook as small as possible (§12 risk table).

Sprint target: Sprint 3.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from dictionary.command_handlers import SimpleSession
from event_logging.session_logger import SessionLogger
from honeypot.fakefs import FakeFS
from honeypot.persona_switcher import PersonaSwitcher
from honeypot.response_engine import ResponseEngine

logger = logging.getLogger(__name__)

_SOURCE_TO_LOG_SOURCE = {
    "fast_path": "dict",
    "llm": "llm",
    "fallback": "dict",
}


def _notify_dashboard(endpoint: str, payload: dict) -> None:
    """Best-effort HTTP push to the live dashboard endpoints."""
    try:
        url = f"http://127.0.0.1:8080{endpoint}"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=1)
    except Exception:
        pass



class HoneypotCommandDispatcher:
    """Per-session command dispatcher bridging Cowrie to our Response Engine.

    Owns the session's FakeFS instance, SimpleSession state, ResponseEngine,
    and SessionLogger reference. Each SSH connection gets one dispatcher via
    ``create_dispatcher()``.

    Args:
        session_id: Unique session identifier (from Cowrie or auto-generated).
        attacker_ip: Source IP of the SSH connection.
        attacker_port: Source port of the SSH connection.
        persona_name: Initial persona to load (default ``"generic_linux"``).
        session_logger: Shared logger instance (created if not provided).
    """

    def __init__(
        self,
        session_id: str,
        attacker_ip: str,
        attacker_port: int = 0,
        persona_name: str = "generic_linux",
        session_logger: Optional[SessionLogger] = None,
        login_user: Optional[str] = None,
    ) -> None:
        self._session_id = session_id
        self._attacker_ip = attacker_ip
        self._attacker_port = attacker_port

        self._fakefs = FakeFS(persona_name)
        self._engine = ResponseEngine(self._fakefs)

        if login_user:
            user_info = self._fakefs.get_user(login_user)
            if user_info is None:
                user_info = self._pick_primary_user()
        else:
            user_info = self._pick_primary_user()

        env = self._fakefs.get_environment(user_info.username)
        self._session = SimpleSession(
            current_directory=user_info.home,
            current_user=user_info.username,
            command_history=[],
            environment=dict(env),
        )

        self._persona_name = persona_name
        self._threat_score = 0
        self._persona_switch_count = 0
        self._switcher = PersonaSwitcher(transition_steps=5)
        self._start_time = time.monotonic()

        self._logger = session_logger or SessionLogger()
        self._logger.log_session_start(
            session_id=session_id,
            attacker_ip=attacker_ip,
            attacker_port=attacker_port,
        )
        _notify_dashboard(
            "/api/session/start",
            {
                "session_id": session_id,
                "attacker_ip": attacker_ip,
                "persona": persona_name,
            },
        )

    def _pick_primary_user(self):
        """Select the first interactive (non-system) non-root user."""
        for u in self._fakefs.persona.users:
            if (
                not u.shell.endswith("nologin")
                and not u.shell.endswith("false")
                and u.username != "root"
            ):
                return u
        return self._fakefs.persona.users[0]

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def session(self) -> SimpleSession:
        return self._session

    @property
    def fakefs(self) -> FakeFS:
        return self._fakefs

    @property
    def persona_name(self) -> str:
        return self._persona_name

    @property
    def prompt(self) -> str:
        """Current shell prompt string (PS1-style)."""
        user = self._session.current_user
        host = self._fakefs.hostname
        cwd = self._session.current_directory
        home = None
        u = self._fakefs.get_user(user)
        if u:
            home = u.home
        if home and cwd == home:
            cwd_display = "~"
        elif home and cwd.startswith(home + "/"):
            cwd_display = "~" + cwd[len(home):]
        else:
            cwd_display = cwd
        prefix = "#" if user == "root" else "$"
        return f"{user}@{host}:{cwd_display}{prefix} "

    def dispatch(self, raw_input: str) -> Tuple[str, str]:
        """Synchronous entry point Cowrie calls for each command line.

        Args:
            raw_input: Exactly what the attacker typed.

        Returns:
            A ``(response_text, source)`` tuple. ``source`` is one of
            ``"fast_path"``, ``"llm"``, or ``"fallback"``.
        """
        loop = _get_or_create_event_loop()
        return loop.run_until_complete(self.dispatch_async(raw_input))

    async def dispatch_async(self, raw_input: str) -> Tuple[str, str]:
        """Async entry point for environments with a running event loop.

        Pipeline per command:
            1. ResponseEngine produces (response, source, threat_decision)
            2. If a persona transition is in progress, apply next changes
            3. If threat_decision says switch AND no transition running, start one
            4. Update session state (history, score, patterns)
            5. Log the command with threat data
            6. Return response to attacker

        Args:
            raw_input: Exactly what the attacker typed.

        Returns:
            A ``(response_text, source)`` tuple.
        """
        # 1. Get response + threat assessment
        response, source, decision = await self._engine.handle_command(
            raw_input, self._session,
        )

        # 2. If transition in progress, drip next changes into overlay
        if self._switcher.is_transitioning():
            applied = self._switcher.apply_next_changes(self._session.overlay)
            for event in applied:
                if event.change_type == "add_process":
                    self._fakefs.add_session_process({"command": event.path})

        # 3. If scorer says switch and no transition running, start one
        if (
            decision.trigger_persona_switch
            and decision.switch_to_persona
            and not self._switcher.is_transitioning()
        ):
            from_p = self._persona_name
            started = self._switcher.initiate_switch(
                self._session_id,
                self._persona_name,
                decision.switch_to_persona,
                decision.switch_reason or "threat threshold",
            )
            if started:
                self._persona_switch_count += 1
                logger.info(
                    "Session %s: persona transition started %s -> %s (reason: %s)",
                    self._session_id,
                    self._persona_name,
                    decision.switch_to_persona,
                    decision.switch_reason,
                )
                _notify_dashboard(
                    "/api/session/switch",
                    {
                        "session_id": self._session_id,
                        "from_persona": from_p,
                        "to_persona": decision.switch_to_persona,
                        "trigger_score": self._threat_score,
                    },
                )
            self._persona_name = decision.switch_to_persona

        # 4. Update session state
        self._threat_score = max(self._threat_score, decision.new_total_score)

        self._session.command_history.append({
            "raw": raw_input.strip(),
            "output": response[:200],
            "source": source,
            "cwd": self._session.current_directory,
            "category": decision.command_category.value,
            "score_delta": decision.score_delta,
        })

        for p in decision.patterns_detected:
            self._session.patterns_detected.add(p)
        self._session.threat_score = self._threat_score

        # 5. Log & Notify Dashboard
        log_source = _SOURCE_TO_LOG_SOURCE.get(source, "dict")
        self._logger.log_command(
            session_id=self._session_id,
            command=raw_input.strip(),
            cwd=self._session.current_directory,
            threat_score_after=self._threat_score,
            persona=self._persona_name,
            response_source=log_source,
            threat_category=decision.command_category.value,
            threat_score_delta=decision.score_delta,
            threat_level=decision.threat_level.value,
            patterns_detected=decision.patterns_detected or None,
        )
        _notify_dashboard(
            "/api/session/command",
            {
                "session_id": self._session_id,
                "command": raw_input.strip(),
                "score_after": self._threat_score,
                "score_delta": decision.score_delta,
                "category": decision.command_category.value,
                "threat_level": decision.threat_level.value,
                "persona": self._persona_name,
                "response_source": log_source,
            },
        )

        return response, source

    def close(self) -> None:
        """End this session. Emits a session_end log event."""
        self._logger.log_session_end(session_id=self._session_id)
        _notify_dashboard("/api/session/end", {"session_id": self._session_id})


    def get_summary(self) -> dict:
        """Return the session logger's summary for this session."""
        return self._logger.get_session_summary(self._session_id)


def create_dispatcher(
    session_id: Optional[str] = None,
    attacker_ip: str = "0.0.0.0",
    attacker_port: int = 0,
    persona_name: str = "generic_linux",
    session_logger: Optional[SessionLogger] = None,
    login_user: Optional[str] = None,
) -> HoneypotCommandDispatcher:
    """Factory: create a per-session dispatcher.

    Args:
        session_id: Unique id (auto-generated UUID4 if omitted).
        attacker_ip: Attacker's source IP.
        attacker_port: Attacker's source port.
        persona_name: Initial persona (default ``"generic_linux"``).
        session_logger: Shared SessionLogger (created if omitted).
        login_user: SSH login username. If this user exists in FakeFS,
            the session will use it; otherwise falls back to the
            persona's primary interactive user.

    Returns:
        A ready-to-use ``HoneypotCommandDispatcher``.
    """
    if session_id is None:
        session_id = uuid.uuid4().hex[:12]
    return HoneypotCommandDispatcher(
        session_id=session_id,
        attacker_ip=attacker_ip,
        attacker_port=attacker_port,
        persona_name=persona_name,
        session_logger=session_logger,
        login_user=login_user,
    )


def _get_or_create_event_loop() -> asyncio.AbstractEventLoop:
    """Get the current event loop or create one if none exists."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop
