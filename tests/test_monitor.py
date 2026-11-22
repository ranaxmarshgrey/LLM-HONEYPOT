"""Tests for monitor/log_parser.py and live_monitor panel state.

Feeds sample event JSON lines into the parser and asserts the
SessionState fields are correct. No real log files needed.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from monitor.log_parser import LogParser, SessionState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(event_type: str, session_id: str = "sess-1", **kw) -> dict:
    base = {
        "timestamp": "2026-11-22T14:00:00.000Z",
        "event_type": event_type,
        "session_id": session_id,
        "attacker_ip": "192.0.2.50",
        "attacker_port": 55555,
    }
    base.update(kw)
    return base


def _feed(parser: LogParser, event: dict) -> str | None:
    return parser.feed_line(json.dumps(event))


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------

class TestSessionLifecycle:

    def test_session_start_creates_state(self):
        p = LogParser()
        et = _feed(p, _event("session_start"))
        assert et == "session_start"
        sess = p.get_session("sess-1")
        assert sess is not None
        assert sess.attacker_ip == "192.0.2.50"
        assert sess.attacker_port == 55555

    def test_latest_session_tracked(self):
        p = LogParser()
        _feed(p, _event("session_start", session_id="a"))
        _feed(p, _event("session_start", session_id="b"))
        assert p.latest_session_id == "b"

    def test_session_end_marks_ended(self):
        p = LogParser()
        _feed(p, _event("session_start"))
        _feed(p, _event("session_end", duration_s=120, command_count=5, final_threat_score=45))
        sess = p.get_session("sess-1")
        assert sess.is_ended is True

    def test_active_session_count(self):
        p = LogParser()
        _feed(p, _event("session_start", session_id="a"))
        _feed(p, _event("session_start", session_id="b"))
        assert p.active_session_count() == 2
        _feed(p, _event("session_end", session_id="a"))
        assert p.active_session_count() == 1

    def test_get_session_default_latest(self):
        p = LogParser()
        _feed(p, _event("session_start", session_id="a"))
        _feed(p, _event("session_start", session_id="b"))
        sess = p.get_session()
        assert sess.session_id == "b"


# ---------------------------------------------------------------------------
# Command events
# ---------------------------------------------------------------------------

class TestCommandEvents:

    def test_command_adds_entry(self):
        p = LogParser()
        _feed(p, _event("session_start"))
        _feed(p, _event("command",
            command="whoami",
            cwd="/home/ubuntu",
            response_source="dict",
            latency_ms=5,
            threat_score_after=1,
            threat_score_delta=1,
            threat_level="low",
            persona="generic_linux",
        ))
        sess = p.get_session("sess-1")
        assert sess.command_count == 1
        assert len(sess.commands) == 1
        assert sess.commands[0].command == "whoami"
        assert sess.commands[0].response_source == "dict"
        assert sess.commands[0].latency_ms == 5

    def test_threat_score_updates(self):
        p = LogParser()
        _feed(p, _event("session_start"))
        _feed(p, _event("command", command="ls", threat_score_after=1,
                         response_source="dict", latency_ms=2,
                         threat_score_delta=1, threat_level="low",
                         cwd="/", persona="generic_linux"))
        _feed(p, _event("command", command="cat /etc/shadow",
                         threat_score_after=15, response_source="fakefs",
                         latency_ms=3, threat_score_delta=14,
                         threat_level="low", cwd="/", persona="generic_linux"))
        sess = p.get_session("sess-1")
        assert sess.threat_score == 15

    def test_patterns_accumulated(self):
        p = LogParser()
        _feed(p, _event("session_start"))
        _feed(p, _event("command", command="x", response_source="dict",
                         latency_ms=1, threat_score_after=10,
                         threat_level="low", cwd="/",
                         persona="g", patterns_detected=["shadow_access"]))
        _feed(p, _event("command", command="y", response_source="dict",
                         latency_ms=1, threat_score_after=20,
                         threat_level="medium", cwd="/",
                         persona="g", patterns_detected=["sudo_attempt", "shadow_access"]))
        sess = p.get_session("sess-1")
        assert "shadow_access" in sess.patterns_detected
        assert "sudo_attempt" in sess.patterns_detected
        assert sess.patterns_detected.count("shadow_access") == 1

    def test_persona_updates_on_command(self):
        p = LogParser()
        _feed(p, _event("session_start"))
        _feed(p, _event("command", command="ls", persona="dev_workstation",
                         response_source="dict", latency_ms=1,
                         threat_score_after=55, threat_level="high", cwd="/"))
        sess = p.get_session("sess-1")
        assert sess.persona == "dev_workstation"


# ---------------------------------------------------------------------------
# Persona transition events
# ---------------------------------------------------------------------------

class TestTransitionEvents:

    def test_transition_updates_state(self):
        p = LogParser()
        _feed(p, _event("session_start"))
        _feed(p, _event("persona_transition",
            from_stage="generic_linux",
            to_stage="dev_workstation",
            phase="seeding",
            paths_added=["/home/john.dev", "/home/john.dev/.gitconfig"],
        ))
        sess = p.get_session("sess-1")
        assert sess.current_stage == "dev_workstation"
        assert sess.transition_phase == "seeding"
        assert len(sess.transitions) == 1
        assert "/home/john.dev" in sess.planted_paths
        assert "/home/john.dev/.gitconfig" in sess.planted_paths

    def test_multiple_transitions_accumulate_paths(self):
        p = LogParser()
        _feed(p, _event("session_start"))
        _feed(p, _event("persona_transition",
            from_stage="a", to_stage="b", phase="seeding",
            paths_added=["/x/file1"],
        ))
        _feed(p, _event("persona_transition",
            from_stage="a", to_stage="b", phase="building",
            paths_added=["/x/file2"],
        ))
        sess = p.get_session("sess-1")
        assert len(sess.planted_paths) == 2
        assert sess.transition_phase == "building"

    def test_duplicate_paths_not_repeated(self):
        p = LogParser()
        _feed(p, _event("session_start"))
        _feed(p, _event("persona_transition",
            from_stage="a", to_stage="b", phase="seeding",
            paths_added=["/x"],
        ))
        _feed(p, _event("persona_transition",
            from_stage="a", to_stage="b", phase="building",
            paths_added=["/x", "/y"],
        ))
        sess = p.get_session("sess-1")
        assert sess.planted_paths.count("/x") == 1


# ---------------------------------------------------------------------------
# Decoy access events
# ---------------------------------------------------------------------------

class TestDecoyAccessEvents:

    def test_decoy_access_recorded(self):
        p = LogParser()
        _feed(p, _event("session_start"))
        _feed(p, _event("decoy_access",
            path="/home/john.dev/.env",
            command="cat /home/john.dev/.env",
        ))
        sess = p.get_session("sess-1")
        assert len(sess.decoy_accesses) == 1
        assert sess.decoy_accesses[0].path == "/home/john.dev/.env"
        assert "cat" in sess.decoy_accesses[0].command

    def test_multiple_decoy_accesses(self):
        p = LogParser()
        _feed(p, _event("session_start"))
        _feed(p, _event("decoy_access", path="/a", command="cat /a"))
        _feed(p, _event("decoy_access", path="/b", command="cat /b"))
        sess = p.get_session("sess-1")
        assert len(sess.decoy_accesses) == 2


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_empty_line_ignored(self):
        p = LogParser()
        assert p.feed_line("") is None
        assert p.feed_line("   ") is None

    def test_invalid_json_ignored(self):
        p = LogParser()
        assert p.feed_line("not json at all") is None

    def test_missing_event_type_ignored(self):
        p = LogParser()
        result = p.feed_line(json.dumps({"session_id": "x"}))
        assert result is None

    def test_missing_session_id_ignored(self):
        p = LogParser()
        result = p.feed_line(json.dumps({"event_type": "command"}))
        assert result is None

    def test_command_before_session_start(self):
        """Command for unknown session creates skeleton state."""
        p = LogParser()
        _feed(p, _event("command", command="ls", response_source="dict",
                         latency_ms=1, threat_score_after=1,
                         threat_level="low", cwd="/", persona="g"))
        sess = p.get_session("sess-1")
        assert sess is not None
        assert sess.command_count == 1

    def test_get_nonexistent_session(self):
        p = LogParser()
        assert p.get_session("nope") is None

    def test_get_session_no_sessions(self):
        p = LogParser()
        assert p.get_session() is None


# ---------------------------------------------------------------------------
# Panel renderers (smoke tests — ensure they don't crash)
# ---------------------------------------------------------------------------

class TestPanelRenderers:

    def test_all_panels_render_empty(self):
        from monitor.live_monitor import (
            _render_header, _render_command_feed,
            _render_threat_gauge, _render_escalation, _render_decoy,
        )
        p = LogParser()
        _render_header(None, p, replay=False)
        _render_command_feed(None)
        _render_threat_gauge(None)
        _render_escalation(None)
        _render_decoy(None)

    def test_all_panels_render_with_data(self):
        from monitor.live_monitor import (
            _render_header, _render_command_feed,
            _render_threat_gauge, _render_escalation, _render_decoy,
        )
        p = LogParser()
        _feed(p, _event("session_start"))
        _feed(p, _event("command", command="whoami", response_source="dict",
                         latency_ms=5, threat_score_after=1,
                         threat_score_delta=1, threat_level="low",
                         cwd="/home/ubuntu", persona="generic_linux"))
        _feed(p, _event("persona_transition", from_stage="a", to_stage="b",
                         phase="seeding", paths_added=["/x"]))
        _feed(p, _event("decoy_access", path="/x", command="cat /x"))

        sess = p.get_session("sess-1")
        _render_header(sess, p, replay=False)
        _render_header(sess, p, replay=True)
        _render_command_feed(sess)
        _render_threat_gauge(sess)
        _render_escalation(sess)
        _render_decoy(sess)

    def test_replay_banner_shown(self):
        from monitor.live_monitor import _render_header
        p = LogParser()
        _feed(p, _event("session_start"))
        sess = p.get_session("sess-1")
        panel = _render_header(sess, p, replay=True)
        assert "REPLAY" in str(panel.title)


# ---------------------------------------------------------------------------
# LogTailer
# ---------------------------------------------------------------------------

class TestLogTailer:

    def test_reads_new_lines(self, tmp_path):
        from monitor.live_monitor import LogTailer
        fp = tmp_path / "test.jsonl"
        fp.write_text("", encoding="utf-8")

        tailer = LogTailer(fp)
        assert tailer.read_new_lines() == []

        fp.write_text('{"event_type":"session_start","session_id":"s1"}\n', encoding="utf-8")
        lines = tailer.read_new_lines()
        assert len(lines) == 1

    def test_handles_append(self, tmp_path):
        from monitor.live_monitor import LogTailer
        fp = tmp_path / "test.jsonl"
        fp.write_text('{"a":1}\n', encoding="utf-8")

        tailer = LogTailer(fp)
        tailer.read_new_lines()

        with open(fp, "a", encoding="utf-8") as f:
            f.write('{"b":2}\n')

        lines = tailer.read_new_lines()
        assert len(lines) == 1
        assert '"b"' in lines[0]

    def test_handles_missing_file(self, tmp_path):
        from monitor.live_monitor import LogTailer
        fp = tmp_path / "nonexistent.jsonl"
        tailer = LogTailer(fp)
        assert tailer.read_new_lines() == []

    def test_handles_truncation(self, tmp_path):
        from monitor.live_monitor import LogTailer
        fp = tmp_path / "test.jsonl"
        fp.write_text('{"a":1}\n' * 100, encoding="utf-8")

        tailer = LogTailer(fp)
        tailer.read_new_lines()

        fp.write_text('{"b":2}\n', encoding="utf-8")
        lines = tailer.read_new_lines()
        assert len(lines) == 1
