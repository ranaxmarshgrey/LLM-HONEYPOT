"""Module 5b -- Persona Switcher (Sprint 5).

Manages gradual persona transitions so the attacker experiences
environmental *drift* rather than a jarring identity reset.

The mental model: over 5-6 commands after a switch is triggered,
subtle changes appear one or two at a time -- a new user in /home,
a background process, a config file -- until the new persona is fully
in place.  The attacker should feel they *discovered* something, not
that the system changed around them.

Design rules:
    - Changes are applied to the session overlay, NOT directly to FakeFS.
    - Session history, cwd, threat score are never touched.
    - Each apply_next_changes() call emits 1-2 ChangeEvents.
    - The full queue drains over exactly ``transition_steps`` calls.
    - No double-switching: a new switch while one is in progress is
      queued and starts only after the current one completes.
"""
from __future__ import annotations

import json
import logging
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from honeypot.session_overlay import SessionOverlay

logger = logging.getLogger(__name__)

_PERSONA_DIR = Path(__file__).resolve().parent.parent / "personas"


# ---------------------------------------------------------------------------
# Enums and models
# ---------------------------------------------------------------------------

class TransitionPhase(str, Enum):
    """Phases of a gradual persona transition."""
    IDLE = "idle"
    SEEDING = "seeding"
    BUILDING = "building"
    COMPLETING = "completing"
    DONE = "done"


class ChangeEvent(BaseModel):
    """A single atomic change applied during persona transition."""
    change_type: str
    path: str
    description: str
    content: Optional[str] = None
    phase: TransitionPhase


class TransitionState(BaseModel):
    """Tracks the progress of a persona transition."""
    session_id: str
    from_persona: str
    to_persona: str
    reason: str
    phase: TransitionPhase = TransitionPhase.IDLE
    change_queue: List[ChangeEvent] = Field(default_factory=list)
    changes_applied: List[ChangeEvent] = Field(default_factory=list)
    total_steps: int = 5
    steps_completed: int = 0


# ---------------------------------------------------------------------------
# Change queue builders -- the heart of the gradual drift
# ---------------------------------------------------------------------------

def _load_persona_fs(name: str) -> dict:
    """Load raw persona JSON for extracting file contents."""
    path = _PERSONA_DIR / f"{name}.json"
    with open(path) as f:
        return json.load(f)


def _build_generic_to_dev() -> List[ChangeEvent]:
    """Changes for generic_linux -> dev_workstation.

    Ordered subtle-to-obvious:
      1. (seeding)     /home/john.dev directory
      2. (seeding)     .gitconfig -- subtle developer hint
      3. (building)    node process in background
      4. (building)    projects/webapp with .env credentials
      5. (completing)  .ssh/id_rsa private key -- high-value bait
      6. (completing)  docker daemon -- full dev stack visible
    """
    dev = _load_persona_fs("dev_workstation")
    fs = dev["filesystem"]

    events: List[ChangeEvent] = []

    events.append(ChangeEvent(
        change_type="add_directory",
        path="/home/john.dev",
        description="New user home directory appears",
        phase=TransitionPhase.SEEDING,
    ))

    gitconfig = fs.get("/home/john.dev/.gitconfig", {})
    events.append(ChangeEvent(
        change_type="add_file",
        path="/home/john.dev/.gitconfig",
        description="Developer git config hints at dev activity",
        content=gitconfig.get("content", "[user]\n\tname = John Dev\n\temail = john.dev@acmecorp.net\n"),
        phase=TransitionPhase.SEEDING,
    ))

    events.append(ChangeEvent(
        change_type="add_process",
        path="node --watch server.js",
        description="Node.js process appears in process list",
        phase=TransitionPhase.BUILDING,
    ))

    events.append(ChangeEvent(
        change_type="add_directory",
        path="/home/john.dev/projects/webapp",
        description="Web project directory appears",
        phase=TransitionPhase.BUILDING,
    ))

    env_entry = fs.get("/home/john.dev/projects/webapp/.env", {})
    events.append(ChangeEvent(
        change_type="add_file",
        path="/home/john.dev/projects/webapp/.env",
        description=".env file with database credentials visible",
        content=env_entry.get("content", "DB_PASSWORD=S3cret-P@ssw0rd\n"),
        phase=TransitionPhase.BUILDING,
    ))

    events.append(ChangeEvent(
        change_type="add_directory",
        path="/home/john.dev/.ssh",
        description="SSH directory appears",
        phase=TransitionPhase.COMPLETING,
    ))

    ssh_key = fs.get("/home/john.dev/.ssh/id_rsa", {})
    events.append(ChangeEvent(
        change_type="add_file",
        path="/home/john.dev/.ssh/id_rsa",
        description="Private SSH key -- high-value target",
        content=ssh_key.get("content", "-----BEGIN OPENSSH PRIVATE KEY-----\n...fake...\n-----END OPENSSH PRIVATE KEY-----\n"),
        phase=TransitionPhase.COMPLETING,
    ))

    events.append(ChangeEvent(
        change_type="add_process",
        path="/usr/bin/dockerd -H fd:// --containerd=/",
        description="Docker daemon visible -- full dev stack",
        phase=TransitionPhase.COMPLETING,
    ))

    return events


def _build_to_finance() -> List[ChangeEvent]:
    """Changes for * -> finance_server.

    Ordered subtle-to-obvious:
      1. (seeding)     /home/finapp directory
      2. (seeding)     postgres process appears
      3. (building)    config/database.yml with DB creds
      4. (building)    reports directory with transaction CSV
      5. (completing)  audit.log compliance trail
      6. (completing)  Java Spring Boot process
    """
    fin = _load_persona_fs("finance_server")
    fs = fin["filesystem"]

    events: List[ChangeEvent] = []

    events.append(ChangeEvent(
        change_type="add_directory",
        path="/home/finapp",
        description="Finance application user home appears",
        phase=TransitionPhase.SEEDING,
    ))

    events.append(ChangeEvent(
        change_type="add_process",
        path="/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main",
        description="PostgreSQL process appears",
        phase=TransitionPhase.SEEDING,
    ))

    events.append(ChangeEvent(
        change_type="add_directory",
        path="/home/finapp/config",
        description="Configuration directory appears",
        phase=TransitionPhase.BUILDING,
    ))

    db_yml = fs.get("/home/finapp/config/database.yml", {})
    events.append(ChangeEvent(
        change_type="add_file",
        path="/home/finapp/config/database.yml",
        description="Database config with production credentials",
        content=db_yml.get("content", "host: fin-db-prod-01\npassword: F1n@nc3-Pr0d!\n"),
        phase=TransitionPhase.BUILDING,
    ))

    events.append(ChangeEvent(
        change_type="add_directory",
        path="/home/finapp/reports",
        description="Financial reports directory",
        phase=TransitionPhase.BUILDING,
    ))

    txn_csv = fs.get("/home/finapp/reports/q1-2026-transactions.csv", {})
    events.append(ChangeEvent(
        change_type="add_file",
        path="/home/finapp/reports/q1-2026-transactions.csv",
        description="Transaction data CSV",
        content=txn_csv.get("content", "date,amount,account\n2026-01-15,50000.00,ACC-7821\n"),
        phase=TransitionPhase.BUILDING,
    ))

    events.append(ChangeEvent(
        change_type="add_directory",
        path="/home/finapp/logs",
        description="Application log directory",
        phase=TransitionPhase.COMPLETING,
    ))

    audit = fs.get("/home/finapp/logs/audit.log", {})
    events.append(ChangeEvent(
        change_type="add_file",
        path="/home/finapp/logs/audit.log",
        description="Compliance audit trail",
        content=audit.get("content", "2026-04-01 INFO audit: system startup\n"),
        phase=TransitionPhase.COMPLETING,
    ))

    events.append(ChangeEvent(
        change_type="add_process",
        path="java -jar /opt/finapp/finapp-service-2.3.1.jar --spring.profiles.active=prod",
        description="Spring Boot finance service",
        phase=TransitionPhase.COMPLETING,
    ))

    return events


# ---------------------------------------------------------------------------
# PersonaSwitcher -- the state machine
# ---------------------------------------------------------------------------

class PersonaSwitcher:
    """Manages gradual persona transitions for a single session.

    Instantiate one per session.  After the ThreatDecision says to switch,
    call ``initiate_switch()`` once, then call ``apply_next_changes()``
    after every subsequent command until the transition drains.
    """

    def __init__(self, transition_steps: int = 5) -> None:
        self._state: Optional[TransitionState] = None
        self._queued: Optional[Tuple[str, str, str, str]] = None
        self._transition_steps = transition_steps

    @property
    def state(self) -> Optional[TransitionState]:
        """Current transition state, or None if never initiated."""
        return self._state

    def is_transitioning(self) -> bool:
        """True if a transition is currently in progress."""
        if self._state is None:
            return False
        return self._state.phase not in (TransitionPhase.IDLE, TransitionPhase.DONE)

    def has_queued(self) -> bool:
        """True if a switch is waiting for the current one to finish."""
        return self._queued is not None

    def initiate_switch(
        self,
        session_id: str,
        from_persona: str,
        to_persona: str,
        reason: str,
    ) -> bool:
        """Start a gradual persona transition.

        If a transition is already in progress, the new switch is
        queued and will start automatically when the current one finishes.

        Returns:
            True if the switch started immediately, False if queued.
        """
        if self.is_transitioning():
            self._queued = (session_id, from_persona, to_persona, reason)
            logger.info(
                "Transition queued: %s -> %s (current in progress)",
                from_persona, to_persona,
            )
            return False

        change_queue = self._build_change_queue(from_persona, to_persona)
        self._state = TransitionState(
            session_id=session_id,
            from_persona=from_persona,
            to_persona=to_persona,
            reason=reason,
            phase=TransitionPhase.SEEDING,
            change_queue=change_queue,
            total_steps=self._transition_steps,
        )
        logger.info(
            "Transition started: %s -> %s (%d changes over %d steps)",
            from_persona, to_persona, len(change_queue), self._transition_steps,
        )
        return True

    def apply_next_changes(self, overlay: SessionOverlay) -> List[ChangeEvent]:
        """Apply the next batch of changes to the session overlay.

        Called once per command.  Returns the ChangeEvents applied this
        round (typically 1-2).  When the queue is drained, moves to
        DONE and starts any queued switch.
        """
        if self._state is None or self._state.phase in (TransitionPhase.IDLE, TransitionPhase.DONE):
            return []

        queue = self._state.change_queue
        if not queue:
            self._finish_transition()
            return []

        steps_remaining = self._transition_steps - self._state.steps_completed
        changes_remaining = len(queue)

        if steps_remaining <= 1:
            batch = queue[:]
            queue.clear()
        else:
            per_step = changes_remaining / steps_remaining
            batch_size = max(1, min(2, round(per_step)))
            batch = queue[:batch_size]
            del queue[:batch_size]

        applied: List[ChangeEvent] = []
        for event in batch:
            self._apply_change(event, overlay)
            applied.append(event)
            self._state.changes_applied.append(event)

        self._state.steps_completed += 1
        self._advance_phase()

        if not queue:
            self._finish_transition()

        return applied

    def _advance_phase(self) -> None:
        """Update the phase based on fraction of steps completed."""
        if self._state is None:
            return

        total = self._state.total_steps
        completed = self._state.steps_completed
        ratio = completed / total if total > 0 else 1.0

        if ratio < 0.4:
            self._state.phase = TransitionPhase.SEEDING
        elif ratio < 0.75:
            self._state.phase = TransitionPhase.BUILDING
        else:
            self._state.phase = TransitionPhase.COMPLETING

    def _finish_transition(self) -> None:
        """Mark transition as DONE and start queued switch if any."""
        if self._state is not None:
            self._state.phase = TransitionPhase.DONE
            logger.info(
                "Transition complete: %s -> %s (%d changes applied)",
                self._state.from_persona,
                self._state.to_persona,
                len(self._state.changes_applied),
            )

        if self._queued is not None:
            sid, from_p, to_p, reason = self._queued
            self._queued = None
            self.initiate_switch(sid, from_p, to_p, reason)

    def _build_change_queue(
        self, from_persona: str, to_persona: str,
    ) -> List[ChangeEvent]:
        """Select the appropriate change list for a transition pair."""
        if to_persona == "dev_workstation":
            return _build_generic_to_dev()
        if to_persona == "finance_server":
            return _build_to_finance()
        return []

    @staticmethod
    def _apply_change(event: ChangeEvent, overlay: SessionOverlay) -> None:
        """Apply a single ChangeEvent to the session overlay."""
        if event.change_type == "add_directory":
            overlay.mkdir(event.path)
        elif event.change_type in ("add_file", "update_file"):
            overlay.write_file(event.path, event.content or "")
        elif event.change_type in ("add_process", "add_user"):
            pass
