"""LLM-written file contents for profile personas (setup-time only).

Generates realistic prose/notes for a fixed allowlist of files using
the existing LLM provider chain (Gemini primary, Claude fallback).
Results are frozen into personas/profile.json so no LLM calls happen
at attack time.

Never fails setup: missing API key / network error / timeout -> template
content for that file.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowlist per role — only prose/notes files, never system/cred files
# ---------------------------------------------------------------------------

_DISALLOWED_PATHS = re.compile(
    r"(\.bash_history|/etc/|\.env|\.git-credentials|\.aws/|\.ssh/|"
    r"\.kube/|\.npmrc|credentials|passwords\.txt|portal-creds|"
    r"config\.py|id_rsa|id_ed25519|authorized_keys|shadow|sudoers)"
)

ROLE_ALLOWLISTS: dict[str, list[dict[str, str]]] = {
    "student": [
        {"path_suffix": "Documents/notes.txt",
         "purpose": "personal study notes and reminders"},
        {"path_suffix": "semester-6/README.md",
         "purpose": "semester coursework overview and status"},
        {"path_suffix": "Documents/todo.txt",
         "purpose": "a personal to-do list with tasks and deadlines"},
    ],
    "developer": [
        {"path_suffix": "notes.md",
         "purpose": "developer working notes — current tasks, blockers, ideas"},
        {"path_suffix": "Documents/meeting-notes.txt",
         "purpose": "rough notes from a recent team meeting"},
        {"path_suffix": "Documents/design-notes.txt",
         "purpose": "short design document for a feature being built"},
    ],
    "generic": [
        {"path_suffix": "Documents/notes.txt",
         "purpose": "personal notes and reminders"},
        {"path_suffix": "Documents/todo.txt",
         "purpose": "a personal to-do list"},
        {"path_suffix": "Documents/draft.txt",
         "purpose": "a draft letter or document in progress"},
    ],
}


def _get_allowlist(role: str, interests: list[str], home: str) -> list[dict[str, str]]:
    """Return the allowlist for the given role, with interest-based README(s)."""
    effective_role = role if role in ROLE_ALLOWLISTS else "generic"
    base = [dict(e) for e in ROLE_ALLOWLISTS[effective_role]]

    # Add interest-based project READMEs
    slugged = [_slug(i) for i in interests[:2]] if interests else []
    if effective_role == "student" and slugged:
        for pname in slugged:
            base.append({
                "path_suffix": f"projects/{pname}/README.md",
                "purpose": f"project README describing a {pname} project",
            })
    elif effective_role == "developer" and slugged:
        for pname in slugged:
            base.append({
                "path_suffix": f"projects/{pname}/README.md",
                "purpose": f"project README for a {pname} codebase",
            })
    elif effective_role == "generic":
        base.append({
            "path_suffix": "Documents/shopping-list.txt",
            "purpose": "a casual shopping or errands list",
        })

    # Resolve full paths
    for entry in base:
        entry["full_path"] = f"{home}/{entry['path_suffix']}"

    return base


def _slug(text: str) -> str:
    s = text.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")[:30] or "misc"


# ---------------------------------------------------------------------------
# Validation (Step 3)
# ---------------------------------------------------------------------------

_BANNED_HOSTNAMES = {"web-srv-03", "dev-workstation-07", "fin-db-prod-01"}
_BANNED_USERNAMES = {"john.dev", "finapp", "ubuntu"}
_KEY_PATTERN = re.compile(r"(AKIA[A-Z0-9]{12,}|-----BEGIN |sk-[a-zA-Z0-9]{20,})")
_URL_PATTERN = re.compile(r"https?://")
_REFUSAL_PATTERNS = re.compile(
    r"(As an AI|I cannot|I can't|language model|I'm an AI|I am an AI)",
    re.IGNORECASE,
)
_CODE_FENCE = re.compile(r"```")

MIN_LINES = 5
MAX_LINES = 60


def validate_content(
    text: str,
    profile_username: str,
    profile_hostname: str,
) -> str | None:
    """Validate LLM-generated content. Returns rejection reason or None if OK."""
    if not text or not text.strip():
        return "empty content"

    lines = text.strip().splitlines()
    if len(lines) < MIN_LINES:
        return f"too short ({len(lines)} lines, min {MIN_LINES})"
    if len(lines) > MAX_LINES:
        return f"too long ({len(lines)} lines, max {MAX_LINES})"

    # Must be printable UTF-8 (no control chars except newline/tab)
    for ch in text:
        if ch not in ('\n', '\t', '\r') and ord(ch) < 32:
            return f"non-printable character: U+{ord(ch):04X}"

    if _CODE_FENCE.search(text):
        return "contains code fence (```)"

    if _REFUSAL_PATTERNS.search(text):
        return "contains AI refusal text"

    for banned in _BANNED_HOSTNAMES:
        if banned in text:
            return f"contains banned hostname: {banned}"

    for banned in _BANNED_USERNAMES:
        if banned in text:
            return f"contains banned username: {banned}"

    # Check for /home/<someone_else>
    home_refs = re.findall(r"/home/([a-z_][a-z0-9_-]*)", text)
    for user in home_refs:
        if user != profile_username:
            return f"references foreign home: /home/{user}"

    if _KEY_PATTERN.search(text):
        return "contains key-like string"

    if _URL_PATTERN.search(text):
        return "contains URL"

    return None


def clean_content(text: str) -> str:
    """Strip trailing whitespace per line and normalise newlines."""
    lines = text.replace('\r\n', '\n').replace('\r', '\n').splitlines()
    cleaned = [line.rstrip() for line in lines]
    return "\n".join(cleaned) + "\n"


# ---------------------------------------------------------------------------
# LLM caller (setup-time, not runtime)
# ---------------------------------------------------------------------------

_PER_CALL_TIMEOUT = 15.0
_TOTAL_BUDGET = 180.0  # 3 minutes


def _build_prompt(
    profile: dict,
    file_path: str,
    purpose: str,
) -> tuple[str, str]:
    """Build system + user messages for a single file generation call."""
    system_msg = (
        "You are writing the content of a file that belongs to a real person's "
        "Linux home directory. Write ONLY the file content — no explanations, "
        "no markdown code fences, no commentary before or after.\n\n"
        "Constraints:\n"
        "- Plain text only, no code fences\n"
        "- Between 5 and 60 lines\n"
        "- No real URLs (no http:// or https://)\n"
        "- No real people's names other than the owner's name\n"
        "- No hostnames other than the machine's hostname\n"
        "- No usernames other than the owner's username\n"
        "- No passwords, API keys, or secrets\n"
        "- Write naturally as the file owner would write it\n"
        "- Include some personality and specifics based on their role/interests"
    )

    user_msg = (
        f"File: {file_path}\n"
        f"Purpose: {purpose}\n\n"
        f"Owner profile:\n"
        f"- Name: {profile['full_name']}\n"
        f"- Username: {profile['username']}\n"
        f"- Role: {profile['role']}\n"
        f"- Organization: {profile.get('org', 'N/A')}\n"
        f"- Interests: {', '.join(profile.get('interests', [])) or 'general'}\n"
        f"- Hostname: {profile['hostname']}\n\n"
        f"Write the file content now."
    )

    return system_msg, user_msg


def _call_llm_sync(
    system_msg: str,
    user_msg: str,
) -> tuple[str, str]:
    """Call the best available LLM synchronously. Returns (text, provider)."""
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")

    if gemini_key:
        try:
            text = _call_gemini_sync(system_msg, user_msg, gemini_key)
            return text, "llm_primary"
        except Exception as exc:
            logger.warning("Gemini call failed: %s", exc)
            if anthropic_key:
                try:
                    text = _call_anthropic_sync(system_msg, user_msg, anthropic_key)
                    return text, "llm_fallback"
                except Exception as exc2:
                    logger.warning("Anthropic fallback failed: %s", exc2)
            raise

    if anthropic_key:
        text = _call_anthropic_sync(system_msg, user_msg, anthropic_key)
        return text, "llm_primary"

    raise RuntimeError("No LLM API key available")


def _call_gemini_sync(system_msg: str, user_msg: str, api_key: str) -> str:
    """Synchronous Gemini call with timeout."""
    import concurrent.futures
    from google import genai

    client = genai.Client(api_key=api_key)
    model_name = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")

    def _do():
        resp = client.models.generate_content(
            model=model_name,
            contents=user_msg,
            config=genai.types.GenerateContentConfig(
                system_instruction=system_msg,
                temperature=0.3,
            ),
        )
        return resp.text if resp.text else ""

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_do)
        return future.result(timeout=_PER_CALL_TIMEOUT)


def _call_anthropic_sync(system_msg: str, user_msg: str, api_key: str) -> str:
    """Synchronous Anthropic call with timeout."""
    import concurrent.futures
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)

    def _do():
        resp = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system=system_msg,
            messages=[{"role": "user", "content": user_msg}],
        )
        return resp.content[0].text if resp.content else ""

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_do)
        return future.result(timeout=_PER_CALL_TIMEOUT)


# ---------------------------------------------------------------------------
# Main generation entry point
# ---------------------------------------------------------------------------

def generate_llm_contents(
    profile: dict,
    filesystem: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Generate LLM-written content for allowlisted files.

    Args:
        profile: The profile dict (from setup_profile.py).
        filesystem: The filesystem dict from the persona being built.

    Returns:
        (updated_filesystem, generation_report) where generation_report
        is a list of per-file dicts.
    """
    username = profile["username"]
    hostname = profile["hostname"]
    home = f"/home/{username}"
    role = profile["role"]
    interests = profile.get("interests", [])

    allowlist = _get_allowlist(role, interests, home)
    report: list[dict[str, Any]] = []
    start_time = time.monotonic()

    for entry in allowlist:
        full_path = entry["full_path"]
        purpose = entry["purpose"]

        # Safety: never generate for disallowed paths
        if _DISALLOWED_PATHS.search(full_path):
            report.append({
                "path": full_path,
                "source": "template",
                "attempts": 0,
                "rejection_reason": "disallowed path",
                "byte_size": len(filesystem.get(full_path, {}).get("content", "").encode("utf-8")),
            })
            continue

        # Skip if file doesn't exist in template filesystem
        if full_path not in filesystem:
            report.append({
                "path": full_path,
                "source": "skipped",
                "attempts": 0,
                "rejection_reason": "not in template filesystem",
                "byte_size": 0,
            })
            continue

        # Check total time budget
        elapsed = time.monotonic() - start_time
        if elapsed >= _TOTAL_BUDGET:
            report.append({
                "path": full_path,
                "source": "template",
                "attempts": 0,
                "rejection_reason": "time budget exceeded",
                "byte_size": len(filesystem[full_path].get("content", "").encode("utf-8")),
            })
            continue

        system_msg, user_msg = _build_prompt(profile, full_path, purpose)

        source = "template"
        attempts = 0
        rejection_reason = None

        for attempt in range(2):  # try once, retry once
            attempts += 1
            try:
                raw_text, provider = _call_llm_sync(system_msg, user_msg)
                cleaned = clean_content(raw_text)
                reason = validate_content(cleaned, username, hostname)
                if reason is None:
                    # Accepted — update filesystem
                    filesystem[full_path]["content"] = cleaned
                    filesystem[full_path]["size_bytes"] = len(cleaned.encode("utf-8"))
                    source = provider
                    rejection_reason = None
                    break
                else:
                    rejection_reason = reason
                    logger.info(
                        "LLM content for %s rejected (attempt %d): %s",
                        full_path, attempt + 1, reason,
                    )
            except Exception as exc:
                rejection_reason = str(exc)
                logger.warning(
                    "LLM call for %s failed (attempt %d): %s",
                    full_path, attempt + 1, exc,
                )
                break  # don't retry on API errors

        report.append({
            "path": full_path,
            "source": source,
            "attempts": attempts,
            "rejection_reason": rejection_reason,
            "byte_size": len(filesystem[full_path].get("content", "").encode("utf-8")),
        })

    return filesystem, report


def format_summary_table(report: list[dict[str, Any]]) -> str:
    """Format a human-readable summary table."""
    lines = []
    llm_count = sum(1 for r in report if r["source"] in ("llm_primary", "llm_fallback"))
    template_count = sum(1 for r in report if r["source"] == "template")
    total = len(report)

    lines.append(f"  {'File':<50} {'Source':<15} {'Bytes':>6}")
    lines.append(f"  {'-'*50} {'-'*15} {'-'*6}")
    for r in report:
        name = r["path"].split("/")[-1] if "/" in r["path"] else r["path"]
        path_short = r["path"]
        if len(path_short) > 48:
            path_short = "..." + path_short[-45:]
        source_display = r["source"]
        if r["rejection_reason"] and r["source"] == "template":
            source_display = f"template ({r['rejection_reason'][:20]})"
        lines.append(f"  {path_short:<50} {source_display:<15} {r['byte_size']:>6}")

    lines.append(f"\n  {llm_count}/{total} files written by LLM, {template_count} used templates")
    return "\n".join(lines)
