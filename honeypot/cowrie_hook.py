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
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from dictionary.command_handlers import SimpleSession
from event_logging.session_logger import SessionLogger
from honeypot.command_parser import parse_command
from honeypot.fakefs import FakeFS
from honeypot.persona_switcher import PersonaSwitcher
from honeypot.response_engine import ResponseEngine

logger = logging.getLogger(__name__)

_FILE_READ_COMMANDS = {"cat", "head", "tail", "less", "more"}
_DECOY_CHECK_COMMANDS = {"cat", "less", "head", "tail", "ls", "find", "grep", "strings"}

_SOURCE_TO_LOG_SOURCE = {
    "fast_path": "dict",
    "llm": "llm_primary",
    "fallback": "llm_fallback",
    "error": "error",
}




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
        self._planted_paths: set = set()

        self._logger = session_logger or SessionLogger()
        self._logger.log_session_start(
            session_id=session_id,
            attacker_ip=attacker_ip,
            attacker_port=attacker_port,
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
        # 1. Get response + threat assessment (with latency timing)
        t0 = time.monotonic()
        response, source, decision = await self._engine.handle_command(
            raw_input, self._session,
        )
        latency_ms = round((time.monotonic() - t0) * 1000)

        # 2. If transition in progress, drip next changes into overlay
        if self._switcher.is_transitioning():
            applied = self._switcher.apply_next_changes(self._session.overlay)
            transition_paths: list = []
            for event in applied:
                if event.change_type == "add_process":
                    self._fakefs.add_session_process({"command": event.path})
                if event.change_type in ("add_file", "update_file"):
                    self._planted_paths.add(event.path)
                transition_paths.append(event.path)

            if applied and self._switcher.state:
                self._logger.log_persona_transition(
                    session_id=self._session_id,
                    from_stage=self._switcher.state.from_persona,
                    to_stage=self._switcher.state.to_persona,
                    phase=self._switcher.state.phase.value,
                    paths_added=transition_paths,
                )

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
            self._persona_name = decision.switch_to_persona

        # 4. Update session state
        self._threat_score = max(self._threat_score, decision.new_total_score)

        # Keep session object in sync so ThreatScorer's guards work
        self._session.active_persona = self._persona_name
        self._session.persona_switch_count = self._persona_switch_count

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

        # 5. Map finer-grained log source
        parsed = parse_command(raw_input.strip())
        log_source = _SOURCE_TO_LOG_SOURCE.get(source, "error")
        if source == "fast_path" and parsed.binary in _FILE_READ_COMMANDS:
            log_source = "fakefs"

        # 6. Log command with latency
        self._logger.log_command(
            session_id=self._session_id,
            command=raw_input.strip(),
            cwd=self._session.current_directory,
            threat_score_after=self._threat_score,
            persona=self._persona_name,
            response_source=log_source,
            latency_ms=latency_ms,
            threat_category=decision.command_category.value,
            threat_score_delta=decision.score_delta,
            threat_level=decision.threat_level.value,
            patterns_detected=decision.patterns_detected or None,
        )

        # 7. Detect decoy access
        if self._planted_paths and parsed.binary in _DECOY_CHECK_COMMANDS:
            decoy_hit = self._check_decoy_access(parsed)
            if decoy_hit:
                self._logger.log_decoy_access(
                    session_id=self._session_id,
                    path=decoy_hit,
                    command=raw_input.strip(),
                )

        return response, source

    def _check_decoy_access(self, parsed) -> Optional[str]:
        """Return the planted path accessed by this command, or None."""
        for arg in parsed.args:
            if arg.startswith("-"):
                continue
            resolved = self._fakefs.resolve_path(
                self._session.current_directory, arg,
            )
            if resolved in self._planted_paths:
                return resolved
            if parsed.binary in ("ls", "find"):
                prefix = resolved.rstrip("/") + "/"
                for pp in self._planted_paths:
                    if pp.startswith(prefix):
                        return pp
        return None

    def close(self) -> None:
        """End this session. Emits a session_end log event."""
        self._logger.log_session_end(session_id=self._session_id)


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

    # Profile mode: use profile persona if available and requested
    if persona_name == "generic_linux":
        profile_json = Path(__file__).resolve().parent.parent / "personas" / "profile.json"
        if os.environ.get("HONEYPOT_PROFILE", "").strip() == "1" and profile_json.exists():
            persona_name = "profile"

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
