"""Shell command parser for the Response Engine (Sprint 3).

Tokenises raw attacker input into a structured ``ParsedCommand`` that the
command registry and handlers can dispatch on. Handles the patterns real
attackers actually type — flags, pipes, redirects, quoting, environment
variable references, semicolon-chained commands, and ``sudo``/``su``
subcommands — without pulling in any external parsing library.

This is intentionally *not* a full POSIX shell parser. It covers the
common surface that matters for honeypot deception; truly exotic syntax
falls through to the LLM path, which is fine.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ParsedCommand:
    """Structured representation of a single shell command."""

    raw: str
    binary: str = ""
    args: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    redirects: List[str] = field(default_factory=list)
    is_piped: bool = False
    pipe_target: Optional[str] = None
    subcommand: Optional[str] = None
    env_refs: List[str] = field(default_factory=list)
    is_chained: bool = False
    chained_commands: List[str] = field(default_factory=list)


_REDIRECT_RE = re.compile(
    r"(>>|>|2>>|2>|&>>|&>|<)"
)

_ENV_VAR_RE = re.compile(
    r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"
)

_ESCALATION_BINARIES = frozenset({"sudo", "su"})


def _safe_split(raw: str) -> List[str]:
    """Split respecting quotes; fall back to whitespace on malformed input."""
    try:
        return shlex.split(raw)
    except ValueError:
        return raw.split()


def _split_chains(raw: str) -> List[str]:
    """Split on ``;``, ``&&``, ``||`` while respecting quotes."""
    parts: List[str] = []
    current: List[str] = []
    in_single = False
    in_double = False

    i = 0
    chars = raw
    while i < len(chars):
        c = chars[i]

        if c == "'" and not in_double:
            in_single = not in_single
            current.append(c)
        elif c == '"' and not in_single:
            in_double = not in_double
            current.append(c)
        elif not in_single and not in_double:
            if c == ";":
                parts.append("".join(current).strip())
                current = []
            elif c == "&" and i + 1 < len(chars) and chars[i + 1] == "&":
                parts.append("".join(current).strip())
                current = []
                i += 1
            elif c == "|" and i + 1 < len(chars) and chars[i + 1] == "|":
                parts.append("".join(current).strip())
                current = []
                i += 1
            else:
                current.append(c)
        else:
            current.append(c)
        i += 1

    tail = "".join(current).strip()
    if tail:
        parts.append(tail)

    return [p for p in parts if p]


def _split_pipe(raw: str) -> tuple[str, Optional[str]]:
    """Split on the first un-quoted ``|`` (but not ``||``).

    Returns ``(left, right_or_None)``.
    """
    in_single = False
    in_double = False

    i = 0
    while i < len(raw):
        c = raw[i]
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif c == "|" and not in_single and not in_double:
            if i + 1 < len(raw) and raw[i + 1] == "|":
                i += 2
                continue
            return raw[:i].strip(), raw[i + 1:].strip()
        i += 1

    return raw, None


def _extract_redirects(tokens: List[str]) -> tuple[List[str], List[str]]:
    """Separate redirect operators + targets from normal tokens."""
    clean: List[str] = []
    redirects: List[str] = []
    skip_next = False

    for idx, tok in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue

        if _REDIRECT_RE.fullmatch(tok):
            if idx + 1 < len(tokens):
                redirects.append(f"{tok} {tokens[idx + 1]}")
                skip_next = True
            else:
                redirects.append(tok)
        elif tok.startswith(">") or tok.startswith(">>"):
            redirects.append(tok)
        else:
            match = _REDIRECT_RE.search(tok)
            if match and not tok.startswith("-"):
                redirects.append(tok)
            else:
                clean.append(tok)

    return clean, redirects


def _classify_token(tok: str) -> str:
    """Return ``'flag'`` or ``'arg'``."""
    if tok.startswith("-") and len(tok) > 1:
        if tok[1:].lstrip("-") == "":
            return "arg"
        return "flag"
    return "arg"


def parse_command(raw: str, env: Optional[Dict[str, str]] = None) -> ParsedCommand:
    """Parse a raw shell input string into a ``ParsedCommand``.

    Args:
        raw: Exactly what the attacker typed.
        env: Optional environment dict for ``$VAR`` expansion. When *None*,
             variable references are recorded in ``env_refs`` but left
             un-expanded in ``args``.

    Returns:
        A fully populated ``ParsedCommand`` instance. For empty or
        whitespace-only input the ``binary`` field is ``""``.
    """
    result = ParsedCommand(raw=raw)

    stripped = raw.strip()
    if not stripped:
        return result

    # ---- env var references ----
    result.env_refs = _ENV_VAR_RE.findall(stripped)

    # ---- chained commands (;, &&, ||) ----
    chains = _split_chains(stripped)
    if not chains:
        return result
    if len(chains) > 1:
        result.is_chained = True
        result.chained_commands = chains
    stripped = chains[0]

    # ---- pipes ----
    left, pipe_right = _split_pipe(stripped)
    if pipe_right is not None:
        result.is_piped = True
        result.pipe_target = pipe_right
        stripped = left

    # ---- expand env vars if env provided ----
    working = stripped
    if env:
        def _replace(m: re.Match) -> str:
            name = m.group(1)
            return env.get(name, m.group(0))
        working = _ENV_VAR_RE.sub(_replace, working)

    # ---- tokenise ----
    tokens = _safe_split(working)
    if not tokens:
        return result

    # ---- redirects ----
    tokens, result.redirects = _extract_redirects(tokens)
    if not tokens:
        return result

    # ---- binary ----
    result.binary = tokens[0]
    rest = tokens[1:]

    # ---- sudo / su subcommand ----
    if result.binary in _ESCALATION_BINARIES and rest:
        sudo_flags: List[str] = []
        sub_start = 0
        for idx, tok in enumerate(rest):
            if _classify_token(tok) == "flag":
                sudo_flags.append(tok)
            else:
                sub_start = idx
                break
        else:
            sub_start = len(rest)

        result.flags = sudo_flags
        if sub_start < len(rest):
            result.subcommand = rest[sub_start]
            rest = rest[sub_start + 1:]
        else:
            rest = []

    # ---- flags vs args ----
    for tok in rest:
        if _classify_token(tok) == "flag":
            result.flags.append(tok)
        else:
            result.args.append(tok)

    return result
