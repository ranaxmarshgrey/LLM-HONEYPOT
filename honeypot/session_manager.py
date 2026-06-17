"""Module 2 -- Session Manager (Sprint 4).

Tracks per-session state for every attacker connection: current directory,
command history, running threat score, active persona, IP reputation, and
shell environment variables.  The Response Engine and Threat Scorer both
read from (and update) sessions via this module.

Design rules (per CLAUDE.md):
    - ``threat_score`` NEVER decreases.
    - ``command_history`` is append-only.
    - ``patterns_detected`` is a cumulative set.
    - Persona switches never reset session state -- they merge.
    - ``close_session`` removes the session from the store and returns a
      summary dict suitable for logging / dashboard consumption.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field, field_validator

from honeypot.ip_reputation import IPReputationResult, check_ip_reputation
from honeypot.session_overlay import SessionOverlay
from honeypot.threat_scorer import (
    CommandCategory,
    ThreatDecision,
    ThreatLevel,
    ThreatScorer,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SessionState -- the Pydantic model that IS the session
# ---------------------------------------------------------------------------

class SessionState(BaseModel):
    """Full mutable state for a single attacker session.

    This is the authoritative record every module reads from and writes to.
    """

    model_config = {"arbitrary_types_allowed": True}

    session_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    attacker_ip: str = "0.0.0.0"
    attacker_port: int = 0
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    current_directory: str = "/home/ubuntu"
    current_user: str = "ubuntu"
    command_history: List[dict] = Field(default_factory=list)
    environment: Dict[str, str] = Field(default_factory=dict)

    threat_score: int = Field(ge=0, le=100, default=0)
    threat_level: ThreatLevel = ThreatLevel.LOW
    active_persona: str = "generic_linux"
    persona_switch_count: int = 0
    persona_transition_in_progress: bool = False
    persona_transition_target: Optional[str] = None
    persona_transition_steps_remaining: int = 0

    ip_reputation: Optional[IPReputationResult] = None
    patterns_detected: Set[str] = Field(default_factory=set)
    categories_seen: Set[str] = Field(default_factory=set)

    overlay: SessionOverlay = Field(default_factory=SessionOverlay)
    total_commands: int = 0

    @field_validator("threat_score", mode="before")
    @classmethod
    def _clamp_score(cls, v: int) -> int:
        return max(0, min(100, v))


# ---------------------------------------------------------------------------
# SessionManager -- the store + business logic
# ---------------------------------------------------------------------------

class SessionManager:
    """In-memory session store with threat-scoring integration.

    Owns all active ``SessionState`` objects and exposes methods that
    enforce the append-only / monotonic-score invariants.
    """

    def __init__(self) -> None:
        self._sessions: Dict[str, SessionState] = {}
        self._scorer = ThreatScorer()

    # -- lifecycle ----------------------------------------------------------

    async def create_session(
        self,
        attacker_ip: str,
        attacker_port: int = 0,
        persona_name: str = "generic_linux",
        login_user: str = "ubuntu",
        home_directory: str = "/home/ubuntu",
        environment: Optional[Dict[str, str]] = None,
        session_id: Optional[str] = None,
    ) -> SessionState:
        """Create and register a new session.

        Performs an async IP reputation check (never blocks on failure).
        Applies any ``initial_score_bonus`` from reputation data.
        """
        sid = session_id or uuid.uuid4().hex[:12]

        ip_rep = await check_ip_reputation(attacker_ip)

        initial_score = min(ip_rep.initial_score_bonus, 100)

        session = SessionState(
            session_id=sid,
            attacker_ip=attacker_ip,
            attacker_port=attacker_port,
            current_user=login_user,
            current_directory=home_directory,
            environment=environment or {},
            active_persona=persona_name,
            threat_score=initial_score,
            threat_level=self._level_from_score(initial_score),
            ip_reputation=ip_rep,
            overlay=SessionOverlay(
                default_owner=login_user,
                default_group=login_user,
            ),
        )

        self._sessions[sid] = session
        logger.info(
            "Session %s created for %s (reputation bonus=%d)",
            sid, attacker_ip, ip_rep.initial_score_bonus,
        )
        return session

    def get_session(self, session_id: str) -> Optional[SessionState]:
        """Return the session or ``None`` if not found."""
        return self._sessions.get(session_id)

    # -- command processing -------------------------------------------------

    def update_after_command(
        self,
        session_id: str,
        raw_command: str,
        response: str,
        response_source: str,
    ) -> ThreatDecision:
        """Score a command, update session state, and return the decision.

        Enforces:
            - threat_score never decreases
            - command_history is append-only
            - patterns_detected is cumulative
        """
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"No active session with id {session_id!r}")

        decision = self._scorer.score_command(raw_command, session)

        new_score = max(session.threat_score, decision.new_total_score)
        session.threat_score = min(new_score, 100)
        session.threat_level = self._level_from_score(session.threat_score)

        session.command_history.append({
            "raw": raw_command.strip(),
            "output": response[:200],
            "source": response_source,
            "cwd": session.current_directory,
            "category": decision.command_category.value,
            "score_delta": decision.score_delta,
        })
        session.total_commands += 1

        if decision.command_category != CommandCategory.BENIGN:
            session.categories_seen.add(decision.command_category.value)

        for pattern_name in decision.patterns_detected:
            session.patterns_detected.add(pattern_name)

        return decision

    # -- persona switching --------------------------------------------------

    def record_persona_switch(
        self,
        session_id: str,
        target_persona: str,
        transition_steps: int = 3,
    ) -> None:
        """Begin a gradual persona transition.

        Does NOT reset session state (CLAUDE.md Rule 5).
        """
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"No active session with id {session_id!r}")

        if session.persona_transition_in_progress:
            return

        session.persona_switch_count += 1
        session.persona_transition_in_progress = True
        session.persona_transition_target = target_persona
        session.persona_transition_steps_remaining = transition_steps

        logger.info(
            "Session %s: persona switch started %s -> %s (%d steps)",
            session_id, session.active_persona, target_persona, transition_steps,
        )

    def complete_transition(self, session_id: str) -> None:
        """Finalise the current persona transition.

        Sets ``active_persona`` to the target and clears transition flags.
        Only call this after all gradual steps have been applied.
        """
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"No active session with id {session_id!r}")

        if not session.persona_transition_in_progress:
            return

        session.active_persona = session.persona_transition_target  # type: ignore[assignment]
        session.persona_transition_in_progress = False
        session.persona_transition_target = None
        session.persona_transition_steps_remaining = 0

        logger.info(
            "Session %s: persona transition complete -> %s",
            session_id, session.active_persona,
        )

    # -- teardown -----------------------------------------------------------

    def close_session(self, session_id: str) -> Dict[str, Any]:
        """Remove the session from the store and return a summary dict.

        The summary is suitable for logging, dashboard display, or
        post-session analysis.
        """
        session = self._sessions.pop(session_id, None)
        if session is None:
            raise KeyError(f"No active session with id {session_id!r}")

        now = datetime.now(timezone.utc)
        duration = (now - session.start_time).total_seconds()

        summary: Dict[str, Any] = {
            "session_id": session.session_id,
            "attacker_ip": session.attacker_ip,
            "attacker_port": session.attacker_port,
            "start_time": session.start_time.isoformat(),
            "end_time": now.isoformat(),
            "duration_seconds": round(duration, 2),
            "total_commands": session.total_commands,
            "final_threat_score": session.threat_score,
            "final_threat_level": session.threat_level.value,
            "final_persona": session.active_persona,
            "persona_switch_count": session.persona_switch_count,
            "patterns_detected": sorted(session.patterns_detected),
            "categories_seen": sorted(session.categories_seen),
            "ip_reputation": {
                "abuse_confidence_score": session.ip_reputation.abuse_confidence_score,
                "is_tor": session.ip_reputation.is_tor,
                "country_code": session.ip_reputation.country_code,
                "initial_score_bonus": session.ip_reputation.initial_score_bonus,
            } if session.ip_reputation else None,
            "command_history": session.command_history,
        }

        logger.info(
            "Session %s closed: %d commands, score=%d, level=%s, duration=%.1fs",
            session_id, session.total_commands, session.threat_score,
            session.threat_level.value, duration,
        )
        return summary

    # -- queries ------------------------------------------------------------

    def get_all_active(self) -> Dict[str, SessionState]:
        """Return a dict of all currently active sessions."""
        return dict(self._sessions)

    def active_count(self) -> int:
        """Return the number of active sessions."""
        return len(self._sessions)

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _level_from_score(score: int) -> ThreatLevel:
        if score <= 20:
            return ThreatLevel.LOW
        if score <= 50:
            return ThreatLevel.MEDIUM
        if score <= 80:
            return ThreatLevel.HIGH
        return ThreatLevel.CRITICAL
