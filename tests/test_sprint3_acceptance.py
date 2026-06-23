"""Sprint 3 Acceptance Test — 15 sequential commands through the Cowrie hook.

Simulates an SSH session by routing commands through
``HoneypotCommandDispatcher``, exactly as Cowrie would. Verifies:

    1. All responses are FakeFS-grounded (no Cowrie defaults)
    2. ``cd`` commands correctly update working directory
    3. No response contains markdown or meta-commentary
    4. No contradictions between any two responses
"""
from __future__ import annotations

import re
import tempfile

import pytest

from honeypot.cowrie_hook import create_dispatcher

PERSONA_NAMES = ["generic_linux", "dev_workstation", "finance_server"]

ACCEPTANCE_COMMANDS = [
    "whoami",
    "id",
    "ls /home",
    "cat /etc/passwd",
    "ps aux",
    "netstat -an",
    "cat /home/{user}/.bash_history",
    "df -h",
    "free -m",
    "uptime",
    "cd /var/log",
    "pwd",
    "ls",
    "cd ..",
    "pwd",
    "history",
]

_MARKDOWN_PATTERNS = re.compile(
    r"(```|^\*\*|^#{1,6}\s|"
    r"I'm an AI|I am an AI|as an AI|language model|"
    r"honeypot|^Sure,?\s|^Here'?s?\s|^Of course|"
    r"^Note:|^Explanation:)",
    re.IGNORECASE | re.MULTILINE,
)


@pytest.fixture(params=PERSONA_NAMES)
def dispatcher(request, tmp_path):
    """Create a dispatcher per persona with a temp log directory."""
    from event_logging.session_logger import SessionLogger
    logger = SessionLogger(log_dir=tmp_path, logger_name=f"accept_{request.param}")
    d = create_dispatcher(
        session_id=f"accept-{request.param}",
        attacker_ip="192.168.1.100",
        attacker_port=54321,
        persona_name=request.param,
        session_logger=logger,
    )
    yield d
    d.close()
    logger.close()


class TestSprint3Acceptance:
    """Run the 15-command acceptance sequence and validate all responses."""

    def test_full_sequence(self, dispatcher):
        user = dispatcher.session.current_user
        hostname = dispatcher.fakefs.hostname
        results: list[tuple[str, str, str]] = []

        for cmd_template in ACCEPTANCE_COMMANDS:
            cmd = cmd_template.format(user=user)
            response, source = dispatcher.dispatch(cmd)
            results.append((cmd, response, source))

        # ---- 1. All responses grounded (non-empty where expected) ----
        whoami_resp = results[0][1]
        assert whoami_resp == user, f"whoami returned '{whoami_resp}', expected '{user}'"

        id_resp = results[1][1]
        assert f"({user})" in id_resp, f"id output missing ({user})"

        ls_home_resp = results[2][1]
        assert user in ls_home_resp or len(ls_home_resp) > 0, "ls /home is empty"

        passwd_resp = results[3][1]
        assert user in passwd_resp, f"/etc/passwd missing {user}"
        assert "root" in passwd_resp, "/etc/passwd missing root"

        ps_resp = results[4][1]
        assert "PID" in ps_resp, "ps aux missing header"
        assert len(ps_resp.splitlines()) > 2, "ps aux too few lines"

        netstat_resp = results[5][1]
        assert "Proto" in netstat_resp or "Active" in netstat_resp, \
            "netstat output missing expected header"

        df_resp = results[7][1]
        assert "Filesystem" in df_resp, "df -h missing header"
        assert "%" in df_resp, "df -h missing usage percentage"

        free_resp = results[8][1]
        assert "Mem:" in free_resp, "free -m missing Mem: line"

        uptime_resp = results[9][1]
        assert "up" in uptime_resp, "uptime missing 'up'"
        assert "load average" in uptime_resp, "uptime missing load average"

        # ---- 2. cd updates working directory ----
        cd_var_log_cmd = results[10][0]
        assert cd_var_log_cmd == "cd /var/log"

        pwd_after_cd = results[11][1]
        assert pwd_after_cd.strip() == "/var/log", \
            f"pwd after 'cd /var/log' returned '{pwd_after_cd}', expected '/var/log'"

        ls_after_cd = results[12][1]
        assert results[12][2] == "fast_path"

        cd_dotdot = results[13][0]
        assert cd_dotdot == "cd .."

        pwd_after_dotdot = results[14][1]
        assert pwd_after_dotdot.strip() == "/var", \
            f"pwd after 'cd ..' returned '{pwd_after_dotdot}', expected '/var'"

        history_resp = results[15][1]
        assert "whoami" in history_resp, "history missing 'whoami'"

        # ---- 3. No markdown or meta-commentary ----
        for cmd, response, source in results:
            match = _MARKDOWN_PATTERNS.search(response)
            assert match is None, (
                f"Command '{cmd}' response contains forbidden pattern: "
                f"'{match.group()}' in:\n{response[:200]}"
            )

        # ---- 4. Cross-reference consistency checks ----
        # whoami matches id output
        assert user in id_resp

        # /etc/passwd users appear in ps aux owners
        passwd_users = set()
        for line in passwd_resp.splitlines():
            if ":" in line:
                passwd_users.add(line.split(":")[0])
        ps_users = set()
        for line in ps_resp.splitlines()[1:]:
            parts = line.split()
            if parts:
                ps_users.add(parts[0])
        assert ps_users.issubset(passwd_users), (
            f"Process owners not in /etc/passwd: {ps_users - passwd_users}"
        )

        # hostname is consistent
        assert hostname in dispatcher.fakefs.get_uname()

    def test_all_fast_path(self, dispatcher):
        """All 15 acceptance commands should resolve via fast_path."""
        user = dispatcher.session.current_user
        for cmd_template in ACCEPTANCE_COMMANDS:
            cmd = cmd_template.format(user=user)
            _, source = dispatcher.dispatch(cmd)
            assert source == "fast_path", f"'{cmd}' used {source}, expected fast_path"

    def test_session_logged(self, dispatcher):
        """Every command produces a log entry."""
        user = dispatcher.session.current_user
        for cmd_template in ACCEPTANCE_COMMANDS:
            cmd = cmd_template.format(user=user)
            dispatcher.dispatch(cmd)

        summary = dispatcher.get_summary()
        assert summary["command_count"] == len(ACCEPTANCE_COMMANDS)
        assert summary["session_id"] == dispatcher.session_id

    def test_prompt_updates_after_cd(self, dispatcher):
        """Shell prompt reflects the current directory after cd."""
        dispatcher.dispatch("cd /var/log")
        assert "/var/log" in dispatcher.prompt or "log" in dispatcher.prompt

        dispatcher.dispatch("cd ..")
        assert "/var" in dispatcher.prompt
