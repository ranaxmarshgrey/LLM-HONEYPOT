"""Command registry — maps command names to fast-path handlers (Sprint 3).

The registry covers all 40 Tier 1 + Tier 2 commands plus common aliases
(``ll`` → ``ls``, ``dir`` → ``ls``, etc.). The ``lookup()`` function is
the single entry point the Response Engine uses to decide fast-path vs
LLM-path.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Dict, List, Optional

from dictionary.command_handlers import (
    handle_cat,
    handle_cd,
    handle_chmod,
    handle_chown,
    handle_cp,
    handle_curl,
    handle_date,
    handle_df,
    handle_echo,
    handle_env,
    handle_find,
    handle_free,
    handle_grep,
    handle_groups,
    handle_head,
    handle_history,
    handle_hostname,
    handle_id,
    handle_ifconfig,
    handle_ip,
    handle_last,
    handle_ls,
    handle_mkdir,
    handle_mv,
    handle_netstat,
    handle_printenv,
    handle_ps,
    handle_pwd,
    handle_rm,
    handle_ssh,
    handle_su,
    handle_sudo,
    handle_tail,
    handle_touch,
    handle_uname,
    handle_uptime,
    handle_w,
    handle_wget,
    handle_which,
    handle_whoami,
)

if TYPE_CHECKING:
    from honeypot.command_parser import ParsedCommand
    from honeypot.fakefs import FakeFS
    from dictionary.command_handlers import SessionProtocol

HandlerFunc = Callable[["FakeFS", "SessionProtocol", "ParsedCommand"], str]

COMMAND_HANDLERS: Dict[str, HandlerFunc] = {
    # Tier 1 — 20 core commands
    "ls": handle_ls,
    "pwd": handle_pwd,
    "whoami": handle_whoami,
    "id": handle_id,
    "uname": handle_uname,
    "hostname": handle_hostname,
    "cat": handle_cat,
    "echo": handle_echo,
    "ps": handle_ps,
    "netstat": handle_netstat,
    "ifconfig": handle_ifconfig,
    "ip": handle_ip,
    "history": handle_history,
    "env": handle_env,
    "printenv": handle_printenv,
    "cd": handle_cd,
    "date": handle_date,
    "uptime": handle_uptime,
    "df": handle_df,
    "free": handle_free,

    # Tier 2 — 20 additional commands
    "find": handle_find,
    "grep": handle_grep,
    "which": handle_which,
    "w": handle_w,
    "last": handle_last,
    "groups": handle_groups,
    "sudo": handle_sudo,
    "su": handle_su,
    "ssh": handle_ssh,
    "wget": handle_wget,
    "curl": handle_curl,
    "chmod": handle_chmod,
    "chown": handle_chown,
    "mkdir": handle_mkdir,
    "touch": handle_touch,
    "rm": handle_rm,
    "cp": handle_cp,
    "mv": handle_mv,
    "head": handle_head,
    "tail": handle_tail,

    # Aliases
    "ll": handle_ls,
    "dir": handle_ls,
    "ss": handle_netstat,
    "export": handle_env,
    "set": handle_env,
    "type": handle_which,
    "command": handle_which,
}


def lookup(binary: str) -> Optional[HandlerFunc]:
    """Return the handler for a command binary, or None for LLM path.

    Args:
        binary: The command name (e.g. ``"ls"``, ``"cat"``).

    Returns:
        The handler callable if the command is in the fast-path registry,
        otherwise ``None`` (indicating the Response Engine should use the
        LLM slow path).
    """
    return COMMAND_HANDLERS.get(binary)


def is_fast_path(binary: str) -> bool:
    """Check whether a command has a fast-path handler."""
    return binary in COMMAND_HANDLERS


def list_commands() -> List[str]:
    """Return all registered command names (including aliases)."""
    return sorted(COMMAND_HANDLERS.keys())
