"""Sprint 3 acceptance demo — simulates an SSH session and prints every response."""
from __future__ import annotations

import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from event_logging.session_logger import SessionLogger
from honeypot.cowrie_hook import create_dispatcher

COMMANDS = [
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


def run_demo(persona: str = "generic_linux") -> None:
    tmpdir = tempfile.mkdtemp()
    logger = SessionLogger(log_dir=tmpdir, logger_name=f"demo_{persona}")
    d = create_dispatcher(
        session_id=f"demo-{persona}",
        attacker_ip="192.168.1.100",
        attacker_port=54321,
        persona_name=persona,
        session_logger=logger,
    )

    user = d.session.current_user
    print(f"\n{'='*70}")
    print(f"  SPRINT 3 ACCEPTANCE — persona: {persona}")
    print(f"  User: {user} | Hostname: {d.fakefs.hostname}")
    print(f"{'='*70}\n")

    issues = []

    for cmd_template in COMMANDS:
        cmd = cmd_template.format(user=user)
        prompt = d.prompt
        response, source = d.dispatch(cmd)

        print(f"{prompt}{cmd}")
        if response:
            print(response)
        print()

        # Check for markdown/meta-commentary
        import re
        bad = re.search(
            r"(```|^\*\*|^#{1,6}\s|I'm an AI|honeypot|^Sure,?\s|^Note:|^Explanation:)",
            response, re.IGNORECASE | re.MULTILINE,
        )
        if bad:
            issues.append(f"  FAIL: '{cmd}' contains forbidden pattern: '{bad.group()}'")

    d.close()
    logger.close()

    if issues:
        print("\n--- ISSUES FOUND ---")
        for i in issues:
            print(i)
    else:
        print("--- ALL CHECKS PASSED ---")


if __name__ == "__main__":
    persona = sys.argv[1] if len(sys.argv) > 1 else "generic_linux"
    run_demo(persona)
