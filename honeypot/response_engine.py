"""Module 3 — Response Engine.

Produces the shell output returned to the attacker. Two paths:

    Fast path — dictionary lookup for ~40 common commands, < 50 ms, all
                output generated from FakeFS state (never hardcoded).
    Slow path — LLM API call (Claude primary) using the grounded prompt
                template in CLAUDE.md §5 Module 3, with a strict 3-second
                timeout and FakeFS-based fallback response.

Sprint target: Sprint 3.
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import re
import time
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from dotenv import load_dotenv

from dictionary.command_registry import lookup
from honeypot.command_parser import ParsedCommand, parse_command
from honeypot.threat_scorer import ThreatDecision, ThreatScorer

if TYPE_CHECKING:
    from dictionary.command_handlers import SessionProtocol
    from honeypot.fakefs import FakeFS

load_dotenv()

logger = logging.getLogger(__name__)

LLM_TIMEOUT_SECONDS = 3.0

_FORBIDDEN_PATTERNS = re.compile(
    r"(```|^\*\*|^#{1,6}\s|"
    r"I'm an AI|I am an AI|as an AI|language model|"
    r"honeypot|I cannot|I can't help|"
    r"^Sure,?\s|^Here'?s?\s|^Of course|"
    r"^Note:|^Explanation:)",
    re.IGNORECASE | re.MULTILINE,
)

_MARKDOWN_CODE_FENCE = re.compile(r"```[\w]*\n?|```")
_MARKDOWN_BOLD = re.compile(r"\*\*(.*?)\*\*")
_MARKDOWN_HEADER = re.compile(r"^#{1,6}\s+", re.MULTILINE)
_LEADING_COMMENTARY = re.compile(
    r"^(Sure|Here|Of course|Certainly|The output)[^\n]*\n+",
    re.IGNORECASE,
)
_TRAILING_COMMENTARY = re.compile(
    r"\n+(Note:|Explanation:|This (shows|displays|output)|"
    r"The above|As you can see)[^\n]*$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Prompt builder — uses exact CLAUDE.md §5 Module 3 template
# ---------------------------------------------------------------------------

def build_llm_prompt(
    fakefs: FakeFS,
    session: SessionProtocol,
    command: str,
) -> Tuple[str, str]:
    """Build the system and user messages for the LLM call.

    Args:
        fakefs: The FakeFS instance (single source of truth).
        session: Current attacker session state.
        command: The raw command string the attacker typed.

    Returns:
        A ``(system_message, user_message)`` tuple.
    """
    ctx = fakefs.get_llm_context_summary()
    user_list = ", ".join(ctx["current_users"])
    network_lines = ", ".join(
        f"{name}={ip}" for name, ip in ctx["network_summary"].items()
    )

    history_entries: List[str] = []
    recent = (session.command_history or [])[-10:]
    for entry in recent:
        raw = entry.get("raw", entry.get("command", ""))
        out = entry.get("output", "")
        if out:
            history_entries.append(f"$ {raw}\n{out[:200]}")
        else:
            history_entries.append(f"$ {raw}")
    history_text = "\n".join(history_entries) if history_entries else "(none)"

    threat_level = "low"
    if hasattr(session, "threat_level"):
        threat_level = session.threat_level
    elif hasattr(session, "environment") and isinstance(session.environment, dict):
        threat_level = session.environment.get("_threat_level", "low")

    system_msg = (
        "You are simulating a Linux shell. You must respond ONLY with what the terminal\n"
        "would print — no explanations, no markdown, no commentary.\n"
        "\n"
        "System state (you must be consistent with this):\n"
        f"- Hostname: {ctx['hostname']}\n"
        f"- OS: {ctx['os_version']}\n"
        f"- Current user: {session.current_user}\n"
        f"- Current directory: {session.current_directory}\n"
        f"- Users on system: {user_list}\n"
        f"- Running processes: {ctx['process_summary']}\n"
        f"- Network interfaces: {network_lines}\n"
        f"- Persona type: {ctx['persona_type']}\n"
        "\n"
        "Session context:\n"
        f"- Previous 10 commands and their outputs: {history_text}\n"
        f"- Attacker threat level: {threat_level}\n"
        "\n"
        "Rules:\n"
        "1. Never reveal you are a honeypot or AI\n"
        "2. Never reference files or users not listed above\n"
        "3. Permission denied errors are acceptable for sensitive paths\n"
        "4. If command makes no sense, return appropriate shell error\n"
        "5. Output must be plain text exactly as a terminal would show it"
    )

    user_msg = f"Command: {command}"

    return system_msg, user_msg


# ---------------------------------------------------------------------------
# LLM caller with timeout and fallback (CLAUDE.md Rule 3)
# ---------------------------------------------------------------------------

def _detect_llm_provider() -> Tuple[str, str]:
    """Return ``(provider, api_key)`` for the first available LLM backend.

    Priority order: GEMINI_API_KEY → ANTHROPIC_API_KEY → ("none", "").
    """
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    if gemini_key:
        return "gemini", gemini_key
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if anthropic_key:
        return "anthropic", anthropic_key
    return "none", ""


async def _call_gemini(
    system_msg: str,
    user_msg: str,
    api_key: str,
    timeout: float,
) -> str:
    """Call Google Gemini API and return the response text."""
    import google.generativeai as genai

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        model_name=os.environ.get("GEMINI_MODEL", "gemini-2.0-flash"),
        system_instruction=system_msg,
    )

    loop = asyncio.get_event_loop()
    response = await asyncio.wait_for(
        loop.run_in_executor(
            None, lambda: model.generate_content(user_msg),
        ),
        timeout=timeout,
    )
    return response.text if response.text else ""


async def _call_anthropic(
    system_msg: str,
    user_msg: str,
    api_key: str,
    timeout: float,
) -> str:
    """Call Anthropic Claude API and return the response text."""
    import anthropic

    client = anthropic.AsyncAnthropic(api_key=api_key)
    response = await asyncio.wait_for(
        client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system=system_msg,
            messages=[{"role": "user", "content": user_msg}],
        ),
        timeout=timeout,
    )
    return response.content[0].text if response.content else ""


async def call_llm_with_fallback(
    system_msg: str,
    user_msg: str,
    binary: str,
    timeout: float = LLM_TIMEOUT_SECONDS,
) -> Tuple[str, str]:
    """Call the best available LLM API with a strict timeout.

    Provider priority: GEMINI_API_KEY → ANTHROPIC_API_KEY.
    If neither key is set, returns a fallback bash error immediately.

    Args:
        system_msg: The system prompt.
        user_msg: The user message (command).
        binary: The command binary, used for fallback error.
        timeout: Maximum seconds to wait (default 3.0).

    Returns:
        A ``(response_text, source)`` tuple where source is
        ``"llm"`` on success or ``"fallback"`` on timeout/error.
    """
    provider, api_key = _detect_llm_provider()

    if provider == "none":
        logger.warning("No LLM API key set (GEMINI_API_KEY or ANTHROPIC_API_KEY) — using fallback")
        return _fallback_response(binary), "fallback"

    try:
        if provider == "gemini":
            text = await _call_gemini(system_msg, user_msg, api_key, timeout)
        else:
            text = await _call_anthropic(system_msg, user_msg, api_key, timeout)

        return text, "llm"

    except asyncio.TimeoutError:
        logger.warning("LLM call (%s) timed out after %.1fs", provider, timeout)
        return _fallback_response(binary), "fallback"
    except Exception as exc:
        logger.error("LLM call (%s) failed: %s", provider, exc)
        return _fallback_response(binary), "fallback"


def _fallback_response(binary: str) -> str:
    """Generate a realistic bash error when the LLM is unavailable."""
    if binary:
        return f"-bash: {binary}: command not found"
    return ""


# ---------------------------------------------------------------------------
# Post-processor — strip LLM artifacts
# ---------------------------------------------------------------------------

def post_process_response(text: str) -> str:
    """Strip markdown formatting, commentary, and forbidden patterns.

    Args:
        text: Raw LLM response text.

    Returns:
        Cleaned plain-text output suitable for a terminal.
    """
    result = _MARKDOWN_CODE_FENCE.sub("", text)
    result = _MARKDOWN_BOLD.sub(r"\1", result)
    result = _MARKDOWN_HEADER.sub("", result)
    result = _LEADING_COMMENTARY.sub("", result)
    result = _TRAILING_COMMENTARY.sub("", result)

    lines = result.splitlines()
    cleaned: List[str] = []
    for line in lines:
        if _FORBIDDEN_PATTERNS.search(line):
            continue
        cleaned.append(line)

    result = "\n".join(cleaned).strip()
    return result


# ---------------------------------------------------------------------------
# Timing jitter — make responses feel like a real shell
# ---------------------------------------------------------------------------

async def apply_timing_jitter(source: str, binary: str) -> None:
    """Add realistic delay to simulate actual command execution time.

    Args:
        source: ``"fast_path"``, ``"llm"``, or ``"fallback"``.
        binary: The command name, used to pick an appropriate delay.
    """
    if source == "fast_path":
        delay = random.uniform(0.01, 0.05)
    elif source == "llm":
        return
    else:
        delay = random.uniform(0.05, 0.15)

    slow_commands = {"find", "grep", "ps", "netstat", "df", "du", "top"}
    if binary in slow_commands and source == "fast_path":
        delay = random.uniform(0.05, 0.20)

    await asyncio.sleep(delay)


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class ResponseEngine:
    """Orchestrates fast-path and LLM-path command handling.

    Args:
        fakefs: The FakeFS instance backing all system state.
        threat_scorer: Optional ThreatScorer instance. If not provided,
            one is created automatically.
    """

    def __init__(
        self,
        fakefs: FakeFS,
        threat_scorer: Optional[ThreatScorer] = None,
    ) -> None:
        self._fakefs = fakefs
        self._threat_scorer = threat_scorer or ThreatScorer()

    async def handle_command(
        self,
        raw_input: str,
        session: SessionProtocol,
    ) -> Tuple[str, str, ThreatDecision]:
        """Process a raw command string and return the simulated output.

        This is the single entry point for the entire Response Engine.
        It parses the command, tries the fast path (dictionary handlers),
        and falls back to the LLM path if no handler is registered.

        Args:
            raw_input: Exactly what the attacker typed.
            session: The current session state object.

        Returns:
            A ``(response, source, threat_decision)`` tuple where
            ``source`` is one of ``"fast_path"``, ``"llm"``, or
            ``"fallback"``, and ``threat_decision`` is the scorer's
            assessment of this command.
        """
        stripped = raw_input.strip()
        if not stripped:
            return "", "fast_path", self._empty_decision(stripped, session)

        parsed = parse_command(stripped)

        if not parsed.binary:
            return "", "fast_path", self._empty_decision(stripped, session)

        if parsed.is_chained:
            response, source = await self._handle_chained(parsed, session)
        else:
            response, source = await self._dispatch_single(parsed, session)

            if parsed.is_piped:
                response = self._apply_pipe(response, parsed.pipe_target or "")

            if parsed.redirects:
                response = self._apply_redirect(
                    response, parsed.redirects, session,
                )

        await apply_timing_jitter(source, parsed.binary)

        decision = self._threat_scorer.score_command(stripped, session)

        return response, source, decision

    def _empty_decision(
        self,
        raw: str,
        session: SessionProtocol,
    ) -> ThreatDecision:
        """Return a benign no-op decision for empty/blank input."""
        from honeypot.threat_scorer import CommandCategory, ThreatLevel

        score = getattr(session, "threat_score", 0)
        return ThreatDecision(
            command_raw=raw,
            command_category=CommandCategory.BENIGN,
            score_delta=0,
            previous_score=score,
            new_total_score=score,
            threat_level=ThreatLevel.LOW if score <= 20 else
                         ThreatLevel.MEDIUM if score <= 50 else
                         ThreatLevel.HIGH if score <= 80 else
                         ThreatLevel.CRITICAL,
        )

    async def _dispatch_single(
        self,
        parsed: ParsedCommand,
        session: SessionProtocol,
    ) -> Tuple[str, str]:
        """Dispatch a single (non-chained) command."""
        binary = parsed.subcommand if parsed.binary in ("sudo", "su") else parsed.binary

        handler = lookup(parsed.binary)
        if handler is not None:
            try:
                result = handler(self._fakefs, session, parsed)
                return result, "fast_path"
            except Exception as exc:
                logger.error("fast-path handler error for '%s': %s", parsed.binary, exc)
                return f"-bash: {parsed.binary}: error", "fallback"

        system_msg, user_msg = build_llm_prompt(
            self._fakefs, session, parsed.raw,
        )
        raw_response, source = await call_llm_with_fallback(
            system_msg, user_msg, parsed.binary,
        )

        if source == "llm":
            raw_response = post_process_response(raw_response)

        return raw_response, source

    async def _handle_chained(
        self,
        parsed: ParsedCommand,
        session: SessionProtocol,
    ) -> Tuple[str, str]:
        """Execute semicolon/&&/|| chained commands sequentially."""
        outputs: List[str] = []
        sources: List[str] = []

        for sub_raw in parsed.chained_commands:
            sub_parsed = parse_command(sub_raw)
            if not sub_parsed.binary:
                continue
            resp, src = await self._dispatch_single(sub_parsed, session)
            outputs.append(resp)
            sources.append(src)

        combined = "\n".join(o for o in outputs if o)
        source = "llm" if "llm" in sources else "fast_path"
        return combined, source

    @staticmethod
    def _apply_pipe(output: str, pipe_cmd: str) -> str:
        """Apply basic pipe transformations client-side."""
        pipe_parts = pipe_cmd.strip().split()
        if not pipe_parts:
            return output

        cmd = pipe_parts[0]
        args = pipe_parts[1:]
        lines = output.splitlines()

        if cmd == "head":
            n = 10
            if args and args[0].startswith("-") and args[0][1:].isdigit():
                n = int(args[0][1:])
            elif len(args) >= 2 and args[0] == "-n":
                try:
                    n = int(args[1])
                except ValueError:
                    pass
            return "\n".join(lines[:n])

        if cmd == "tail":
            n = 10
            if args and args[0].startswith("-") and args[0][1:].isdigit():
                n = int(args[0][1:])
            elif len(args) >= 2 and args[0] == "-n":
                try:
                    n = int(args[1])
                except ValueError:
                    pass
            return "\n".join(lines[-n:])

        if cmd == "wc":
            if "-l" in args:
                return str(len(lines))
            chars = sum(len(l) + 1 for l in lines)
            words = sum(len(l.split()) for l in lines)
            return f"  {len(lines)}  {words}  {chars}"

        if cmd == "grep":
            if not args:
                return output
            pattern = args[0]
            ignore_case = "-i" in args
            matched: List[str] = []
            for line in lines:
                text = line.lower() if ignore_case else line
                pat = pattern.lower() if ignore_case else pattern
                if pat in text:
                    matched.append(line)
            return "\n".join(matched)

        if cmd == "sort":
            reverse = "-r" in args
            return "\n".join(sorted(lines, reverse=reverse))

        if cmd == "uniq":
            seen: List[str] = []
            prev = None
            for line in lines:
                if line != prev:
                    seen.append(line)
                prev = line
            return "\n".join(seen)

        return output

    def _apply_redirect(
        self,
        output: str,
        redirects: List[str],
        session: SessionProtocol,
    ) -> str:
        """Write command output to the overlay when ``>`` or ``>>`` is used."""
        for redir in redirects:
            if redir.startswith(">>"):
                filename = redir[2:].strip()
                append = True
            elif redir.startswith("> "):
                filename = redir[2:].strip()
                append = False
            elif redir.startswith(">"):
                filename = redir[1:].strip()
                append = False
            else:
                continue

            if not filename:
                continue

            path = self._fakefs.resolve_path(
                session.current_directory, filename,
            )
            if append:
                existing = session.overlay.get_content(path, self._fakefs) or ""
                session.overlay.write_file(path, existing + output + "\n")
            else:
                session.overlay.write_file(path, output)
            return ""
        return output
