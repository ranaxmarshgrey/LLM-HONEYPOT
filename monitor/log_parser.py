"""Event log parser and session state tracker for the live monitor.

Reads JSON-lines from honeypot.jsonl and maintains per-session state
that the TUI panels consume. Stateless — feed it lines one at a time.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class CommandEntry:
    """One command in the feed."""
    timestamp: str
    command: str
    response_source: str
    latency_ms: int
    score_delta: int
    threat_score_after: int
    threat_level: str
    cwd: str


@dataclass
class TransitionEntry:
    """One persona transition step."""
    timestamp: str
    from_stage: str
    to_stage: str
    phase: str
    paths_added: list


@dataclass
class DecoyEntry:
    """One decoy access event."""
    timestamp: str
    path: str
    command: str


@dataclass
class SessionState:
    """Accumulated state for a single attacker session."""
    session_id: str
    attacker_ip: str = ""
    attacker_port: int = 0
    start_time: str = ""
    persona: str = ""
    hostname: str = ""
    username: str = ""
    role: str = ""
    threat_score: int = 0
    threat_level: str = "low"
    patterns_detected: list = field(default_factory=list)
    commands: List[CommandEntry] = field(default_factory=list)
    transitions: List[TransitionEntry] = field(default_factory=list)
    decoy_accesses: List[DecoyEntry] = field(default_factory=list)
    planted_paths: list = field(default_factory=list)
    current_stage: str = ""
    transition_phase: str = ""
    is_ended: bool = False
    end_time: str = ""
    command_count: int = 0


class LogParser:
    """Parses JSON-lines events and maintains per-session state."""

    def __init__(self) -> None:
        self.sessions: Dict[str, SessionState] = {}
        self._latest_session_id: Optional[str] = None

    @property
    def latest_session_id(self) -> Optional[str]:
        return self._latest_session_id

    def feed_line(self, line: str) -> Optional[str]:
        """Parse one JSON line and update state.

        Returns the event_type, or None if the line is invalid.
        """
        line = line.strip()
        if not line:
            return None
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return None

        return self.feed_event(event)

    def feed_event(self, event: dict) -> Optional[str]:
        """Process a parsed event dict and update state."""
        event_type = event.get("event_type")
        session_id = event.get("session_id")
        if not event_type or not session_id:
            return None

        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState(session_id=session_id)

        sess = self.sessions[session_id]

        if event_type == "session_start":
            sess.attacker_ip = event.get("attacker_ip", "")
            sess.attacker_port = event.get("attacker_port", 0)
            sess.start_time = event.get("timestamp", "")
            self._latest_session_id = session_id

        elif event_type == "command":
            sess.persona = event.get("persona", sess.persona)
            sess.threat_score = event.get("threat_score_after", sess.threat_score)
            sess.threat_level = event.get("threat_level", sess.threat_level)
            sess.command_count += 1

            if event.get("patterns_detected"):
                for p in event["patterns_detected"]:
                    if p not in sess.patterns_detected:
                        sess.patterns_detected.append(p)

            sess.commands.append(CommandEntry(
                timestamp=event.get("timestamp", ""),
                command=event.get("command", ""),
                response_source=event.get("response_source", "dict"),
                latency_ms=event.get("latency_ms", 0),
                score_delta=event.get("threat_score_delta", 0),
                threat_score_after=event.get("threat_score_after", 0),
                threat_level=event.get("threat_level", "low"),
                cwd=event.get("cwd", ""),
            ))

            self._latest_session_id = session_id

        elif event_type == "persona_transition":
            sess.current_stage = event.get("to_stage", "")
            sess.transition_phase = event.get("phase", "")
            paths = event.get("paths_added", [])
            for p in paths:
                if p not in sess.planted_paths:
                    sess.planted_paths.append(p)

            sess.transitions.append(TransitionEntry(
                timestamp=event.get("timestamp", ""),
                from_stage=event.get("from_stage", ""),
                to_stage=event.get("to_stage", ""),
                phase=event.get("phase", ""),
                paths_added=paths,
            ))

        elif event_type == "decoy_access":
            sess.decoy_accesses.append(DecoyEntry(
                timestamp=event.get("timestamp", ""),
                path=event.get("path", ""),
                command=event.get("command", ""),
            ))

        elif event_type == "session_end":
            sess.is_ended = True
            sess.end_time = event.get("timestamp", "")

        return event_type

    def get_session(self, session_id: Optional[str] = None) -> Optional[SessionState]:
        """Get a session by id, or the most recent one."""
        sid = session_id or self._latest_session_id
        if sid is None:
            return None
        return self.sessions.get(sid)

    def active_session_count(self) -> int:
        return sum(1 for s in self.sessions.values() if not s.is_ended)
