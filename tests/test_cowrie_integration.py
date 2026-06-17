"""Sprint 1 acceptance test — end-to-end Cowrie SSH capture.

SSHes into the honeypot on localhost:2222, runs five reconnaissance
commands, disconnects, then parses Cowrie's JSON log to verify every
command was captured with the correct session binding.

The test is gated on reachability: if nothing is listening on
``HONEYPOT_HOST:HONEYPOT_PORT`` the test is *skipped* (not failed), so
the suite stays green on developer laptops without a VM. To run the
acceptance test, point it at a live deployment:

    HONEYPOT_HOST=<vm-ip> pytest tests/test_cowrie_integration.py -v

Environment overrides:
    HONEYPOT_HOST              default: 127.0.0.1
    HONEYPOT_PORT              default: 2222
    HONEYPOT_SSH_USER          default: testuser
    HONEYPOT_SSH_PASSWORD      default: testpass
    COWRIE_LOG_PATH            default: /opt/cowrie/var/log/cowrie/cowrie.json
    COWRIE_LOG_WAIT_SECONDS    default: 5  (time to wait for log flush)
"""
from __future__ import annotations

import json
import os
import socket
import time
import uuid
from pathlib import Path
from typing import List, Optional

import pytest

paramiko = pytest.importorskip("paramiko")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

HOST = os.environ.get("HONEYPOT_HOST", "127.0.0.1")
PORT = int(os.environ.get("HONEYPOT_PORT", "2222"))
USERNAME = os.environ.get("HONEYPOT_SSH_USER", "testuser")
PASSWORD = os.environ.get("HONEYPOT_SSH_PASSWORD", "testpass")
LOG_PATH = Path(
    os.environ.get("COWRIE_LOG_PATH", "/opt/cowrie/var/log/cowrie/cowrie.json")
)
LOG_WAIT = float(os.environ.get("COWRIE_LOG_WAIT_SECONDS", "5"))

COMMANDS: List[str] = [
    "whoami",
    "ls",
    "id",
    "pwd",
    "cat /etc/passwd",
]

# A probe string we'll inject into a harmless command so we can uniquely
# identify this test run's session in the shared cowrie.json log.
PROBE_TAG = f"sprint1-probe-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Reachability gate
# ---------------------------------------------------------------------------

def _port_is_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _port_is_open(HOST, PORT),
    reason=f"honeypot not reachable at {HOST}:{PORT} — skipping acceptance test",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _drain(channel, deadline: float, want_prompt: bool = True) -> str:
    """Read from a paramiko channel until idle or deadline hits."""
    buf = bytearray()
    while time.time() < deadline:
        if channel.recv_ready():
            buf.extend(channel.recv(4096))
            # Heuristic: Cowrie shell prompts typically end with '# ' or '$ '.
            if want_prompt and buf.endswith((b"# ", b"$ ")):
                break
        else:
            time.sleep(0.1)
    return buf.decode(errors="replace")


def _run_session(commands: List[str], probe_command: str) -> None:
    """Open an SSH session, run probe + commands, close cleanly."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Honeypots present non-standard kex/host keys; relax timeouts/policies.
    client.connect(
        hostname=HOST,
        port=PORT,
        username=USERNAME,
        password=PASSWORD,
        look_for_keys=False,
        allow_agent=False,
        timeout=10,
        banner_timeout=10,
        auth_timeout=10,
    )
    try:
        channel = client.invoke_shell(term="xterm", width=120, height=40)
        channel.settimeout(10)

        # Wait for the initial prompt.
        _drain(channel, deadline=time.time() + 5)

        # Inject the probe first so we can find this exact session in logs.
        channel.send((probe_command + "\n").encode())
        _drain(channel, deadline=time.time() + 3)

        for cmd in commands:
            channel.send((cmd + "\n").encode())
            _drain(channel, deadline=time.time() + 5)

        channel.send(b"exit\n")
        time.sleep(0.5)
        channel.close()
    finally:
        client.close()


def _load_log_events() -> List[dict]:
    if not LOG_PATH.exists():
        pytest.fail(
            f"cowrie log not found at {LOG_PATH}. "
            "Set COWRIE_LOG_PATH if your install uses a different location."
        )
    events: List[dict] = []
    with LOG_PATH.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def _find_our_session_id(events: List[dict], probe_tag: str) -> Optional[str]:
    """Locate the session that saw our unique probe command."""
    for ev in events:
        if ev.get("eventid") == "cowrie.command.input" and probe_tag in ev.get(
            "input", ""
        ):
            return ev.get("session")
    return None


# ---------------------------------------------------------------------------
# Acceptance test
# ---------------------------------------------------------------------------

def test_sprint1_acceptance_five_commands_captured():
    """Sprint 1 done-when: SSH in, run 5 commands, see them all in the log."""
    probe_cmd = f"echo {PROBE_TAG}"

    # 1. Drive the honeypot.
    _run_session(COMMANDS, probe_command=probe_cmd)

    # 2. Give Cowrie time to flush the log.
    time.sleep(LOG_WAIT)

    # 3. Parse and locate our session.
    events = _load_log_events()
    assert events, f"{LOG_PATH} is empty — Cowrie isn't logging"

    session_id = _find_our_session_id(events, PROBE_TAG)
    assert session_id, (
        f"could not find probe tag {PROBE_TAG!r} in cowrie.command.input events — "
        "the SSH session may not have reached Cowrie's command handler"
    )

    session_events = [e for e in events if e.get("session") == session_id]

    # 4. Session lifecycle landmarks.
    event_ids = [e.get("eventid") for e in session_events]
    assert "cowrie.session.connect" in event_ids, (
        f"missing cowrie.session.connect for session {session_id}"
    )
    # login.success OR login.failed is acceptable — Cowrie varies by config.
    assert any(
        e.startswith("cowrie.login.") for e in event_ids
    ), f"missing cowrie.login.* for session {session_id}"

    # 5. Every one of our five commands is present, in order.
    captured_inputs = [
        e.get("input", "")
        for e in session_events
        if e.get("eventid") == "cowrie.command.input"
    ]

    # Drop the probe echo we injected first.
    captured_commands = [c for c in captured_inputs if PROBE_TAG not in c]

    missing = [c for c in COMMANDS if c not in captured_commands]
    assert not missing, (
        f"commands missing from log: {missing}\n"
        f"captured: {captured_commands}"
    )

    # Order check: the indices of our commands in captured_commands must be
    # strictly increasing (Cowrie may log extras like 'exit', which is fine).
    indices = [captured_commands.index(c) for c in COMMANDS]
    assert indices == sorted(indices), (
        f"commands captured out of order: {captured_commands}"
    )

    # 6. Each command event has the expected metadata.
    for ev in session_events:
        if ev.get("eventid") != "cowrie.command.input":
            continue
        assert "timestamp" in ev, f"command event missing timestamp: {ev}"
        assert ev.get("session") == session_id
        assert "src_ip" in ev, f"command event missing src_ip: {ev}"
