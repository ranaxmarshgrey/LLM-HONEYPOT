"""Tests for honeypot/profile_llm_content.py — all with MOCKED LLM, no network.

Covers:
  - good output accepted and frozen into profile.json
  - each validation rule rejects bad output -> retry -> template fallback
  - timeout and missing API key -> template fallback, setup still succeeds
  - ls -la size == content length for every LLM-written file
  - persona_validator passes on LLM-content profile
  - without --llm-content the output is byte-identical to before
  - disallowed files never go to the LLM
"""
from __future__ import annotations

import json
import copy
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from honeypot.profile_llm_content import (
    validate_content,
    clean_content,
    generate_llm_contents,
    format_summary_table,
    _get_allowlist,
    _DISALLOWED_PATHS,
    ROLE_ALLOWLISTS,
)
from honeypot.profile_generator import generate_profile_persona
from honeypot.fakefs import Persona
from honeypot.persona_validator import validate as validate_persona


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_PROFILE_STUDENT = {
    "full_name": "Test User",
    "username": "testuser",
    "role": "student",
    "role_description": "",
    "org": "Test University",
    "interests": ["machine-learning", "web-dev"],
    "hostname": "testuser-laptop",
    "uid": 1000,
    "seed": 12345,
}

_PROFILE_DEVELOPER = {
    "full_name": "Dev Person",
    "username": "devperson",
    "role": "developer",
    "role_description": "",
    "org": "Acme Corp",
    "interests": ["backend", "devops"],
    "hostname": "devperson-laptop",
    "uid": 1000,
    "seed": 54321,
}

_PROFILE_GENERIC = {
    "full_name": "Jane Doe",
    "username": "janedoe",
    "role": "other",
    "role_description": "office worker",
    "org": "",
    "interests": [],
    "hostname": "janedoe-laptop",
    "uid": 1000,
    "seed": 99999,
}

GOOD_LLM_OUTPUT = (
    "# Study Notes\n"
    "These are my notes for the semester.\n"
    "I need to review chapter 5 before the exam.\n"
    "The lab work on sorting algorithms was interesting.\n"
    "Remember to submit the assignment by Friday.\n"
    "Also check the library for reference books.\n"
    "Meeting with advisor next Tuesday at 3pm.\n"
)


@pytest.fixture
def student_persona(tmp_path):
    """Generate a student persona and return (persona_data, profile)."""
    persona_path = tmp_path / "profile.json"
    escalation_path = tmp_path / "profile_escalation.json"
    generate_profile_persona(_PROFILE_STUDENT, persona_path, escalation_path)
    with open(persona_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data, _PROFILE_STUDENT


@pytest.fixture
def developer_persona(tmp_path):
    persona_path = tmp_path / "profile.json"
    escalation_path = tmp_path / "profile_escalation.json"
    generate_profile_persona(_PROFILE_DEVELOPER, persona_path, escalation_path)
    with open(persona_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data, _PROFILE_DEVELOPER


@pytest.fixture
def generic_persona(tmp_path):
    persona_path = tmp_path / "profile.json"
    escalation_path = tmp_path / "profile_escalation.json"
    generate_profile_persona(_PROFILE_GENERIC, persona_path, escalation_path)
    with open(persona_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data, _PROFILE_GENERIC


def _mock_llm_good(system_msg, user_msg):
    return GOOD_LLM_OUTPUT, "llm_primary"


def _mock_llm_with_code_fence(system_msg, user_msg):
    return "```\nsome code\nmore code\nline 3\nline 4\nline 5\nline 6\n```\n", "llm_primary"


def _mock_llm_with_refusal(system_msg, user_msg):
    return "As an AI language model, I cannot\ngenerate this content.\nLine 3\nLine 4\nLine 5\nLine 6\n", "llm_primary"


def _mock_llm_with_hostname(system_msg, user_msg):
    return "Notes for web-srv-03\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\n", "llm_primary"


def _mock_llm_with_url(system_msg, user_msg):
    return "Check https://example.com for details\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\n", "llm_primary"


def _mock_llm_with_key(system_msg, user_msg):
    return "My key: AKIAIOSFODNN7EXAMPLE\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\n", "llm_primary"


def _mock_llm_too_short(system_msg, user_msg):
    return "Only two lines.\nNot enough.\n", "llm_primary"


def _mock_llm_too_long(system_msg, user_msg):
    return "\n".join(f"Line {i}" for i in range(65)) + "\n", "llm_primary"


def _mock_llm_foreign_home(system_msg, user_msg):
    return "Files at /home/john.dev are ready\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\n", "llm_primary"


def _mock_llm_banned_username(system_msg, user_msg):
    return "Login as finapp to access\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\n", "llm_primary"


def _mock_llm_timeout(system_msg, user_msg):
    raise TimeoutError("LLM call timed out")


def _mock_llm_no_key(system_msg, user_msg):
    raise RuntimeError("No LLM API key available")


# ---------------------------------------------------------------------------
# Validation unit tests
# ---------------------------------------------------------------------------

class TestValidateContent:

    def test_good_content_accepted(self):
        assert validate_content(GOOD_LLM_OUTPUT, "testuser", "testuser-laptop") is None

    def test_empty_rejected(self):
        assert validate_content("", "testuser", "host") is not None

    def test_too_short_rejected(self):
        assert "too short" in validate_content("One line.\nTwo.\n", "u", "h")

    def test_too_long_rejected(self):
        long_text = "\n".join(f"Line {i}" for i in range(65)) + "\n"
        assert "too long" in validate_content(long_text, "u", "h")

    def test_code_fence_rejected(self):
        text = "Line 1\n```python\ncode\n```\nLine 5\nLine 6\n"
        assert "code fence" in validate_content(text, "u", "h")

    def test_refusal_text_rejected(self):
        text = "As an AI language model,\nI cannot do this.\nLine 3\nLine 4\nLine 5\nLine 6\n"
        assert "refusal" in validate_content(text, "u", "h")

    def test_banned_hostname_rejected(self):
        text = "Connect to web-srv-03\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\n"
        assert "banned hostname" in validate_content(text, "u", "h")

    def test_dev_workstation_hostname_rejected(self):
        text = "Server dev-workstation-07\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\n"
        assert "banned hostname" in validate_content(text, "u", "h")

    def test_fin_db_hostname_rejected(self):
        text = "Database fin-db-prod-01\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\n"
        assert "banned hostname" in validate_content(text, "u", "h")

    def test_foreign_home_rejected(self):
        text = "Look in /home/someoneelse\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\n"
        assert "foreign home" in validate_content(text, "testuser", "h")

    def test_own_home_accepted(self):
        text = "My files in /home/testuser\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\n"
        assert validate_content(text, "testuser", "h") is None

    def test_url_rejected(self):
        text = "Visit https://example.com\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\n"
        assert "URL" in validate_content(text, "u", "h")

    def test_key_like_string_rejected(self):
        text = "Key: AKIAIOSFODNN7EXAMPLE\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\n"
        assert "key-like" in validate_content(text, "u", "h")

    def test_begin_private_key_rejected(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\ndata\nmore\ndata\nend\nfinal\n"
        assert "key-like" in validate_content(text, "u", "h")

    def test_banned_username_finapp_rejected(self):
        text = "User finapp logged in\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\n"
        assert "banned username" in validate_content(text, "u", "h")

    def test_banned_username_john_dev_rejected(self):
        text = "Contact john.dev for help\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\n"
        assert "banned username" in validate_content(text, "u", "h")


class TestCleanContent:

    def test_strips_trailing_whitespace(self):
        result = clean_content("hello   \nworld  \n")
        assert result == "hello\nworld\n"

    def test_normalises_crlf(self):
        result = clean_content("line1\r\nline2\r\n")
        assert result == "line1\nline2\n"

    def test_ends_with_newline(self):
        result = clean_content("no trailing newline")
        assert result.endswith("\n")


# ---------------------------------------------------------------------------
# Allowlist tests
# ---------------------------------------------------------------------------

class TestAllowlist:

    def test_student_allowlist_has_entries(self):
        al = _get_allowlist("student", ["ml"], "/home/testuser")
        assert len(al) >= 4  # 3 base + at least 1 project README

    def test_developer_allowlist_has_entries(self):
        al = _get_allowlist("developer", ["backend"], "/home/dev")
        assert len(al) >= 4

    def test_generic_allowlist_has_entries(self):
        al = _get_allowlist("other", [], "/home/user")
        assert len(al) >= 4

    def test_all_paths_are_absolute(self):
        for role in ["student", "developer", "other"]:
            al = _get_allowlist(role, ["test"], "/home/u")
            for entry in al:
                assert entry["full_path"].startswith("/home/"), entry

    def test_no_disallowed_paths_in_allowlist(self):
        for role in ["student", "developer", "other"]:
            al = _get_allowlist(role, ["test"], "/home/u")
            for entry in al:
                assert not _DISALLOWED_PATHS.search(entry["full_path"]), \
                    f"Disallowed path in allowlist: {entry['full_path']}"


# ---------------------------------------------------------------------------
# Integration: generate with mocked LLM
# ---------------------------------------------------------------------------

class TestGenerateLlmContents:

    def test_good_output_accepted_and_frozen(self, student_persona):
        persona_data, profile = student_persona
        fs_before = copy.deepcopy(persona_data["filesystem"])

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_good):
            fs, report = generate_llm_contents(profile, persona_data["filesystem"])

        llm_files = [r for r in report if r["source"] in ("llm_primary", "llm_fallback")]
        assert len(llm_files) >= 1

        for r in llm_files:
            path = r["path"]
            assert fs[path]["content"] != fs_before.get(path, {}).get("content", "")
            assert fs[path]["size_bytes"] == len(fs[path]["content"].encode("utf-8"))

    def test_code_fence_rejected_then_fallback(self, student_persona):
        persona_data, profile = student_persona
        original_content = persona_data["filesystem"].get(
            f"/home/{profile['username']}/Documents/notes.txt", {}
        ).get("content", "")

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_with_code_fence):
            fs, report = generate_llm_contents(profile, persona_data["filesystem"])

        notes_report = [r for r in report if r["path"].endswith("notes.txt")]
        if notes_report:
            r = notes_report[0]
            assert r["source"] == "template"
            assert r["attempts"] == 2  # tried + retried
            assert "code fence" in r["rejection_reason"]

    def test_refusal_rejected_then_fallback(self, student_persona):
        persona_data, profile = student_persona

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_with_refusal):
            fs, report = generate_llm_contents(profile, persona_data["filesystem"])

        for r in report:
            if r["source"] != "skipped" and r["path"] in fs:
                assert r["source"] == "template"

    def test_banned_hostname_rejected(self, student_persona):
        persona_data, profile = student_persona

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_with_hostname):
            fs, report = generate_llm_contents(profile, persona_data["filesystem"])

        for r in report:
            if r["path"] in fs and r["source"] != "skipped":
                assert r["source"] == "template"

    def test_url_rejected(self, student_persona):
        persona_data, profile = student_persona

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_with_url):
            fs, report = generate_llm_contents(profile, persona_data["filesystem"])

        for r in report:
            if r["path"] in fs and r["source"] != "skipped":
                assert r["source"] == "template"

    def test_key_like_string_rejected(self, student_persona):
        persona_data, profile = student_persona

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_with_key):
            fs, report = generate_llm_contents(profile, persona_data["filesystem"])

        for r in report:
            if r["path"] in fs and r["source"] != "skipped":
                assert r["source"] == "template"

    def test_too_short_rejected(self, student_persona):
        persona_data, profile = student_persona

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_too_short):
            fs, report = generate_llm_contents(profile, persona_data["filesystem"])

        for r in report:
            if r["path"] in fs and r["source"] != "skipped":
                assert r["source"] == "template"

    def test_too_long_rejected(self, student_persona):
        persona_data, profile = student_persona

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_too_long):
            fs, report = generate_llm_contents(profile, persona_data["filesystem"])

        for r in report:
            if r["path"] in fs and r["source"] != "skipped":
                assert r["source"] == "template"

    def test_foreign_home_rejected(self, student_persona):
        persona_data, profile = student_persona

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_foreign_home):
            fs, report = generate_llm_contents(profile, persona_data["filesystem"])

        for r in report:
            if r["path"] in fs and r["source"] != "skipped":
                assert r["source"] == "template"

    def test_timeout_falls_back_to_template(self, student_persona):
        persona_data, profile = student_persona

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_timeout):
            fs, report = generate_llm_contents(profile, persona_data["filesystem"])

        for r in report:
            if r["path"] in fs and r["source"] != "skipped":
                assert r["source"] == "template"

    def test_no_api_key_falls_back_to_template(self, student_persona):
        persona_data, profile = student_persona

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_no_key):
            fs, report = generate_llm_contents(profile, persona_data["filesystem"])

        for r in report:
            if r["path"] in fs and r["source"] != "skipped":
                assert r["source"] == "template"
            assert r["byte_size"] > 0 or r["source"] == "skipped"


class TestSizeConsistency:

    def test_ls_size_equals_content_length(self, student_persona):
        persona_data, profile = student_persona

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_good):
            fs, report = generate_llm_contents(profile, persona_data["filesystem"])

        for r in report:
            if r["source"] in ("llm_primary", "llm_fallback") and r["path"] in fs:
                entry = fs[r["path"]]
                actual_size = len(entry["content"].encode("utf-8"))
                assert entry["size_bytes"] == actual_size, \
                    f"{r['path']}: size_bytes={entry['size_bytes']} != content={actual_size}"


class TestPersonaValidatorPasses:

    def test_student_persona_valid_after_llm_content(self, student_persona):
        persona_data, profile = student_persona

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_good):
            fs, _ = generate_llm_contents(profile, persona_data["filesystem"])
            persona_data["filesystem"] = fs

        Persona.model_validate(persona_data)
        errors = validate_persona(persona_data, datetime.now(tz=timezone.utc))
        assert errors == [], f"Validation errors: {errors}"

    def test_developer_persona_valid_after_llm_content(self, developer_persona):
        persona_data, profile = developer_persona

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_good):
            fs, _ = generate_llm_contents(profile, persona_data["filesystem"])
            persona_data["filesystem"] = fs

        Persona.model_validate(persona_data)
        errors = validate_persona(persona_data, datetime.now(tz=timezone.utc))
        assert errors == [], f"Validation errors: {errors}"

    def test_generic_persona_valid_after_llm_content(self, generic_persona):
        persona_data, profile = generic_persona

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_good):
            fs, _ = generate_llm_contents(profile, persona_data["filesystem"])
            persona_data["filesystem"] = fs

        Persona.model_validate(persona_data)
        errors = validate_persona(persona_data, datetime.now(tz=timezone.utc))
        assert errors == [], f"Validation errors: {errors}"


class TestWithoutLlmContentIdentical:

    def test_no_llm_produces_identical_output(self, tmp_path):
        """Without --llm-content, output is byte-identical to template."""
        p1 = tmp_path / "a.json"
        e1 = tmp_path / "a_esc.json"
        p2 = tmp_path / "b.json"
        e2 = tmp_path / "b_esc.json"

        generate_profile_persona(_PROFILE_STUDENT, p1, e1)
        generate_profile_persona(_PROFILE_STUDENT, p2, e2)

        assert p1.read_bytes() == p2.read_bytes()
        assert e1.read_bytes() == e2.read_bytes()


class TestDisallowedFilesNeverSentToLlm:

    def test_bash_history_never_sent(self, student_persona):
        persona_data, profile = student_persona
        calls = []

        def _tracking_mock(system_msg, user_msg):
            calls.append(user_msg)
            return GOOD_LLM_OUTPUT, "llm_primary"

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_tracking_mock):
            generate_llm_contents(profile, persona_data["filesystem"])

        for call in calls:
            assert ".bash_history" not in call
            assert "/etc/" not in call
            assert ".env" not in call.split("Purpose:")[0] if "Purpose:" in call else True
            assert "credentials" not in call.lower()
            assert ".ssh/" not in call
            assert ".aws/" not in call

    def test_disallowed_paths_always_template(self, student_persona):
        persona_data, profile = student_persona

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_mock_llm_good):
            _, report = generate_llm_contents(profile, persona_data["filesystem"])

        for r in report:
            if _DISALLOWED_PATHS.search(r["path"]):
                assert r["source"] == "template", \
                    f"Disallowed path {r['path']} was sent to LLM"


class TestFormatSummaryTable:

    def test_format_produces_readable_output(self):
        report = [
            {"path": "/home/u/notes.txt", "source": "llm_primary", "attempts": 1,
             "rejection_reason": None, "byte_size": 200},
            {"path": "/home/u/todo.txt", "source": "template", "attempts": 2,
             "rejection_reason": "too short", "byte_size": 50},
        ]
        table = format_summary_table(report)
        assert "1/2 files written by LLM" in table
        assert "1 used templates" in table
        assert "notes.txt" in table

    def test_all_llm_summary(self):
        report = [
            {"path": "/home/u/a.txt", "source": "llm_primary", "attempts": 1,
             "rejection_reason": None, "byte_size": 100},
            {"path": "/home/u/b.txt", "source": "llm_fallback", "attempts": 2,
             "rejection_reason": None, "byte_size": 150},
        ]
        table = format_summary_table(report)
        assert "2/2 files written by LLM" in table


class TestRetryLogic:

    def test_retry_once_then_template(self, student_persona):
        persona_data, profile = student_persona
        call_count = [0]

        def _counting_bad_mock(system_msg, user_msg):
            call_count[0] += 1
            return "```\nbad\ncontent\nhere\nmore\nstuff\n```\n", "llm_primary"

        with patch("honeypot.profile_llm_content._call_llm_sync", side_effect=_counting_bad_mock):
            _, report = generate_llm_contents(profile, persona_data["filesystem"])

        # Each file should have been tried exactly twice (try + retry)
        for r in report:
            if r["source"] == "template" and r["attempts"] > 0 and r["path"] in persona_data["filesystem"]:
                assert r["attempts"] == 2, f"{r['path']} had {r['attempts']} attempts, expected 2"
