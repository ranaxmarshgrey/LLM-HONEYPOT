"""Tests for dictionary/command_registry.py (Sprint 3).

Validates that:
  - All 40 commands have registered handlers
  - Aliases map to the correct underlying handler
  - lookup() returns None for unknown commands
  - is_fast_path() works correctly
"""
from __future__ import annotations

import pytest

from dictionary.command_registry import (
    COMMAND_HANDLERS,
    is_fast_path,
    list_commands,
    lookup,
)
from dictionary.command_handlers import (
    SimpleSession,
    handle_ls,
    handle_netstat,
    handle_env,
    handle_which,
)
from honeypot.command_parser import parse_command
from honeypot.fakefs import FakeFS


TIER_1_COMMANDS = [
    "ls", "pwd", "whoami", "id", "uname", "hostname", "cat", "echo",
    "ps", "netstat", "ifconfig", "ip", "history", "env", "printenv",
    "cd", "date", "uptime", "df", "free",
]

TIER_2_COMMANDS = [
    "find", "grep", "which", "w", "last", "groups", "sudo", "su",
    "ssh", "wget", "curl", "chmod", "chown", "mkdir", "touch", "rm",
    "cp", "mv", "head", "tail",
]

ALIASES = {
    "ll": "ls",
    "dir": "ls",
    "ss": "netstat",
    "export": "env",
    "set": "env",
    "type": "which",
    "command": "which",
}


class TestRegistryCompleteness:
    @pytest.mark.parametrize("cmd", TIER_1_COMMANDS)
    def test_tier1_registered(self, cmd):
        assert lookup(cmd) is not None, f"Tier 1 command '{cmd}' not in registry"

    @pytest.mark.parametrize("cmd", TIER_2_COMMANDS)
    def test_tier2_registered(self, cmd):
        assert lookup(cmd) is not None, f"Tier 2 command '{cmd}' not in registry"

    def test_total_handler_count(self):
        unique_cmds = TIER_1_COMMANDS + TIER_2_COMMANDS + list(ALIASES.keys())
        for cmd in unique_cmds:
            assert cmd in COMMAND_HANDLERS
        assert len(COMMAND_HANDLERS) >= 40 + len(ALIASES)


class TestAliases:
    @pytest.mark.parametrize("alias,target", ALIASES.items())
    def test_alias_maps_to_correct_handler(self, alias, target):
        assert lookup(alias) is lookup(target)

    def test_ll_is_ls(self):
        assert lookup("ll") is handle_ls

    def test_ss_is_netstat(self):
        assert lookup("ss") is handle_netstat


class TestLookup:
    def test_known_command(self):
        assert lookup("ls") is not None

    def test_unknown_command(self):
        assert lookup("nonexistentcmd") is None

    def test_empty_string(self):
        assert lookup("") is None


class TestIsFastPath:
    def test_fast_path_true(self):
        assert is_fast_path("cat") is True

    def test_fast_path_false(self):
        assert is_fast_path("vim") is False

    def test_alias_is_fast_path(self):
        assert is_fast_path("ll") is True


class TestListCommands:
    def test_returns_sorted(self):
        cmds = list_commands()
        assert cmds == sorted(cmds)

    def test_includes_all(self):
        cmds = list_commands()
        for c in TIER_1_COMMANDS + TIER_2_COMMANDS:
            assert c in cmds


class TestRegistryIntegration:
    """End-to-end: parse a command, look up its handler, execute it."""

    def test_ls_via_registry(self):
        fs = FakeFS("generic_linux")
        sess = SimpleSession(current_user="root", current_directory="/root")
        parsed = parse_command("ls /")
        handler = lookup(parsed.binary)
        assert handler is not None
        out = handler(fs, sess, parsed)
        assert "etc" in out
        assert "home" in out

    def test_alias_ll_via_registry(self):
        fs = FakeFS("generic_linux")
        sess = SimpleSession(current_user="root", current_directory="/root")
        parsed = parse_command("ll /etc")
        handler = lookup(parsed.binary)
        assert handler is not None
        out = handler(fs, sess, parsed)
        assert "passwd" in out

    def test_unknown_falls_through(self):
        parsed = parse_command("nmap -sV 10.0.0.1")
        handler = lookup(parsed.binary)
        assert handler is None
