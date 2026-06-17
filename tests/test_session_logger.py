"""Tests for event_logging/session_logger.py."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# Ensure project root is on sys.path so `event_logging` is importable
# whether pytest is invoked from the root or from tests/.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from event_logging.session_logger import SessionLogger  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def log_path(tmp_path):
    return tmp_path


@pytest.fixture
def logger(log_path):
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


# ---------------------------------------------------------------------------
# log_session_start
# ---------------------------------------------------------------------------

def test_log_session_start_writes_one_json_line(logger, log_path):
    logger.log_session_start("sess-1", "1.2.3.4", 55555)
    events = _read_events(log_path)
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "session_start"
    assert ev["session_id"] == "sess-1"
    assert ev["attacker_ip"] == "1.2.3.4"
    assert ev["attacker_port"] == 55555
    assert ev["timestamp"].endswith("Z")
    # No stdlib-logging noise leaks into the record.
    assert "message" not in ev


def test_log_session_start_accepts_explicit_timestamp(logger, log_path):
    ts = datetime(2026, 4, 12, 10, 0, 0, tzinfo=timezone.utc)
    logger.log_session_start("sess-1", "1.2.3.4", 22, timestamp=ts)
    ev = _read_events(log_path)[0]
    assert ev["timestamp"].startswith("2026-04-12T10:00:00")


# ---------------------------------------------------------------------------
# log_login_attempt
# ---------------------------------------------------------------------------

def test_log_login_attempt_records_both_outcomes(logger, log_path):
    logger.log_session_start("sess-1", "1.2.3.4", 55555)
    logger.log_login_attempt("sess-1", "root", "toor", success=False)
    logger.log_login_attempt("sess-1", "admin", "letmein", success=True)

    logins = [e for e in _read_events(log_path) if e["event_type"] == "login_attempt"]
    assert len(logins) == 2
    assert logins[0]["username"] == "root"
    assert logins[0]["password"] == "toor"
    assert logins[0]["success"] is False
    assert logins[1]["username"] == "admin"
    assert logins[1]["success"] is True
    assert logins[0]["attacker_ip"] == "1.2.3.4"
    assert logins[0]["attacker_port"] == 55555


def test_log_login_attempt_updates_summary(logger):
    logger.log_session_start("sess-1", "1.2.3.4", 55555)
    logger.log_login_attempt("sess-1", "root", "x", success=False)
    logger.log_login_attempt("sess-1", "root", "y", success=False)
    logger.log_login_attempt("sess-1", "root", "z", success=True)
    s = logger.get_session_summary("sess-1")
    assert s["login_attempts"] == 3
    assert s["successful_logins"] == 1


# ---------------------------------------------------------------------------
# log_command
# ---------------------------------------------------------------------------

def test_log_command_writes_all_fields(logger, log_path):
    logger.log_session_start("sess-1", "1.2.3.4", 55555)
    logger.log_command(
        "sess-1",
        command="ls -la /home",
        cwd="/home/ubuntu",
        threat_score_after=5,
        persona="generic_linux",
        response_source="dict",
    )
    cmd = next(e for e in _read_events(log_path) if e["event_type"] == "command")
    assert cmd["command"] == "ls -la /home"
    assert cmd["cwd"] == "/home/ubuntu"
    assert cmd["threat_score_after"] == 5
    assert cmd["persona"] == "generic_linux"
    assert cmd["response_source"] == "dict"


def test_log_command_rejects_invalid_response_source(logger):
    logger.log_session_start("sess-1", "1.2.3.4", 55555)
    with pytest.raises(ValueError):
        logger.log_command(
            "sess-1", "ls", "/", 0, "generic_linux", response_source="bogus"
        )


def test_log_command_counts_persona_switches(logger):
    logger.log_session_start("sess-1", "1.2.3.4", 55555)
    logger.log_command("sess-1", "ls", "/", 5, "generic_linux", "dict")
    logger.log_command("sess-1", "whoami", "/", 8, "generic_linux", "dict")
    logger.log_command("sess-1", "sudo -l", "/", 25, "dev_workstation", "llm")
    s = logger.get_session_summary("sess-1")
    assert s["command_count"] == 3
    assert s["active_persona"] == "dev_workstation"
    assert s["persona_switch_count"] == 1
    assert s["final_threat_score"] == 25


# ---------------------------------------------------------------------------
# log_session_end
# ---------------------------------------------------------------------------

def test_log_session_end_computes_duration_and_rollup(logger, log_path):
    start = datetime(2026, 4, 12, 10, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(seconds=42)
    logger.log_session_start("sess-1", "1.2.3.4", 55555, timestamp=start)
    logger.log_command(
        "sess-1", "ls", "/", 2, "generic_linux", "dict",
        timestamp=start + timedelta(seconds=5),
    )
    logger.log_command(
        "sess-1", "whoami", "/", 4, "generic_linux", "dict",
        timestamp=start + timedelta(seconds=10),
    )
    logger.log_session_end("sess-1", timestamp=end)

    end_ev = next(e for e in _read_events(log_path) if e["event_type"] == "session_end")
    assert end_ev["duration_s"] == pytest.approx(42.0)
    assert end_ev["command_count"] == 2
    assert end_ev["final_threat_score"] == 4
    assert end_ev["active_persona"] == "generic_linux"

    s = logger.get_session_summary("sess-1")
    assert s["is_closed"] is True
    assert s["duration_s"] == pytest.approx(42.0)


def test_log_session_end_without_start_still_emits(logger, log_path):
    # Defensive: if session_start was missed (e.g. restart mid-session),
    # session_end should still emit cleanly rather than crash.
    logger.log_session_end("unknown-sess")
    ev = next(e for e in _read_events(log_path) if e["event_type"] == "session_end")
    assert ev["session_id"] == "unknown-sess"
    assert ev["command_count"] == 0
    assert ev["duration_s"] == 0.0


# ---------------------------------------------------------------------------
# get_session_summary
# ---------------------------------------------------------------------------

def test_get_session_summary_live_values(logger):
    start = datetime(2026, 4, 12, 10, 0, 0, tzinfo=timezone.utc)
    logger.log_session_start("sess-1", "1.2.3.4", 55555, timestamp=start)
    logger.log_login_attempt("sess-1", "root", "x", success=False)
    logger.log_command(
        "sess-1", "ls", "/", 5, "generic_linux", "dict",
        timestamp=start + timedelta(seconds=2),
    )
    s = logger.get_session_summary("sess-1")
    assert s["session_id"] == "sess-1"
    assert s["attacker_ip"] == "1.2.3.4"
    assert s["attacker_port"] == 55555
    assert s["command_count"] == 1
    assert s["login_attempts"] == 1
    assert s["successful_logins"] == 0
    assert s["final_threat_score"] == 5
    assert s["active_persona"] == "generic_linux"
    assert s["is_closed"] is False


def test_get_session_summary_unknown_session_raises(logger):
    with pytest.raises(KeyError):
        logger.get_session_summary("does-not-exist")


# ---------------------------------------------------------------------------
# Rotation configuration
# ---------------------------------------------------------------------------

def test_handler_configured_for_daily_utc_rotation(logger):
    handlers = logger._logger.handlers
    assert len(handlers) == 1
    h = handlers[0]
    assert type(h).__name__ == "TimedRotatingFileHandler"
    assert h.when == "MIDNIGHT"
    assert h.utc is True
    assert h.backupCount >= 1


def test_rotation_produces_dated_suffix(tmp_path):
    inst = SessionLogger(log_dir=tmp_path, filename="rot.jsonl")
    try:
        inst.log_session_start("s", "1.1.1.1", 1)
        inst._handler.doRollover()
        inst.log_session_start("s2", "2.2.2.2", 2)
    finally:
        inst.close()
    files = sorted(p.name for p in tmp_path.iterdir())
    assert "rot.jsonl" in files
    assert any(f.startswith("rot.jsonl.") for f in files)
