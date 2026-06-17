"""Tests for session overlay — the write layer that makes mkdir/cd/touch work.

Validates that:
  - mkdir then cd works (overlay directory exists)
  - touch then cat returns content
  - rm then ls doesn't show the file
  - Overlay items appear in ls alongside FakeFS items
  - Deleted FakeFS items don't appear in ls
  - cp, mv work through the overlay
  - find includes overlay entries
  - Session state survives write operations
"""
from __future__ import annotations

import asyncio

import pytest

from dictionary.command_handlers import SimpleSession
from honeypot.fakefs import FakeFS
from honeypot.response_engine import ResponseEngine
from honeypot.session_overlay import SessionOverlay

PERSONA_NAMES = ["generic_linux", "dev_workstation", "finance_server"]


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture(params=PERSONA_NAMES)
def ctx(request):
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


class TestMkdirThenCd:
    def test_mkdir_then_cd_works(self, ctx):
        engine, fs, sess = ctx
        resp, _, _td = _run(engine.handle_command("mkdir testdir", sess))
        assert resp == ""
        resp, _, _td = _run(engine.handle_command("cd testdir", sess))
        assert resp == ""
        assert sess.current_directory.endswith("/testdir")

    def test_mkdir_then_pwd(self, ctx):
        engine, fs, sess = ctx
        home = sess.current_directory
        _run(engine.handle_command("mkdir mydir", sess))
        _run(engine.handle_command("cd mydir", sess))
        resp, _, _td = _run(engine.handle_command("pwd", sess))
        assert resp == f"{home.rstrip('/')}/mydir"

    def test_mkdir_p_nested(self, ctx):
        engine, fs, sess = ctx
        _run(engine.handle_command("mkdir -p a/b/c", sess))
        _run(engine.handle_command("cd a", sess))
        assert sess.current_directory.endswith("/a")
        _run(engine.handle_command("cd b", sess))
        assert sess.current_directory.endswith("/b")
        _run(engine.handle_command("cd c", sess))
        assert sess.current_directory.endswith("/c")

    def test_mkdir_shows_in_ls(self, ctx):
        engine, fs, sess = ctx
        _run(engine.handle_command("mkdir visible_dir", sess))
        resp, _, _td = _run(engine.handle_command("ls", sess))
        assert "visible_dir" in resp


class TestTouchThenCat:
    def test_touch_then_ls_shows_file(self, ctx):
        engine, fs, sess = ctx
        _run(engine.handle_command("touch newfile.txt", sess))
        resp, _, _td = _run(engine.handle_command("ls", sess))
        assert "newfile.txt" in resp

    def test_touch_then_cat_empty(self, ctx):
        engine, fs, sess = ctx
        _run(engine.handle_command("touch empty.txt", sess))
        resp, _, _td = _run(engine.handle_command("cat empty.txt", sess))
        assert resp == ""

    def test_overlay_write_then_cat(self, ctx):
        engine, fs, sess = ctx
        sess.overlay.write_file(
            f"{sess.current_directory.rstrip('/')}/secret.txt",
            "my secret content",
        )
        resp, _, _td = _run(engine.handle_command("cat secret.txt", sess))
        assert resp == "my secret content"


class TestRmHidesFiles:
    def test_rm_overlay_file(self, ctx):
        engine, fs, sess = ctx
        _run(engine.handle_command("touch deleteme.txt", sess))
        resp, _, _td = _run(engine.handle_command("ls", sess))
        assert "deleteme.txt" in resp

        _run(engine.handle_command("rm deleteme.txt", sess))
        resp, _, _td = _run(engine.handle_command("ls", sess))
        assert "deleteme.txt" not in resp

    def test_rm_fakefs_file(self, ctx):
        engine, fs, sess = ctx
        _run(engine.handle_command("cd /etc", sess))
        resp_before, _, _td = _run(engine.handle_command("ls", sess))
        assert "hostname" in resp_before

        _run(engine.handle_command("rm hostname", sess))
        resp_after, _, _td = _run(engine.handle_command("ls", sess))
        assert "hostname" not in resp_after

    def test_rm_nonexistent_fails(self, ctx):
        engine, fs, sess = ctx
        resp, _, _td = _run(engine.handle_command("rm nonexistent_xyz", sess))
        assert "No such file or directory" in resp

    def test_rm_dir_without_r_fails(self, ctx):
        engine, fs, sess = ctx
        _run(engine.handle_command("mkdir somedir", sess))
        resp, _, _td = _run(engine.handle_command("rm somedir", sess))
        assert "Is a directory" in resp

    def test_rm_rf_dir_works(self, ctx):
        engine, fs, sess = ctx
        _run(engine.handle_command("mkdir somedir", sess))
        resp, _, _td = _run(engine.handle_command("rm -rf somedir", sess))
        assert resp == ""
        resp, _, _td = _run(engine.handle_command("cd somedir", sess))
        assert "No such file or directory" in resp


class TestOverlayMergedWithFakeFS:
    def test_ls_shows_both(self, ctx):
        engine, fs, sess = ctx
        _run(engine.handle_command("cd /etc", sess))
        _run(engine.handle_command("touch my_custom_file", sess))
        resp, _, _td = _run(engine.handle_command("ls", sess))
        assert "passwd" in resp
        assert "my_custom_file" in resp

    def test_cat_fakefs_still_works(self, ctx):
        engine, fs, sess = ctx
        resp, _, _td = _run(engine.handle_command("cat /etc/hostname", sess))
        assert fs.hostname in resp

    def test_cd_fakefs_still_works(self, ctx):
        engine, fs, sess = ctx
        _run(engine.handle_command("cd /var/log", sess))
        assert sess.current_directory == "/var/log"


class TestCpMv:
    def test_cp_fakefs_file(self, ctx):
        engine, fs, sess = ctx
        _run(engine.handle_command("cp /etc/hostname /tmp/hostname_copy", sess))
        resp, _, _td = _run(engine.handle_command("cat /tmp/hostname_copy", sess))
        assert fs.hostname in resp

    def test_mv_overlay_file(self, ctx):
        engine, fs, sess = ctx
        _run(engine.handle_command("touch original.txt", sess))
        _run(engine.handle_command("mv original.txt renamed.txt", sess))
        resp, _, _td = _run(engine.handle_command("ls", sess))
        assert "renamed.txt" in resp


class TestFindWithOverlay:
    def test_find_includes_overlay(self, ctx):
        engine, fs, sess = ctx
        _run(engine.handle_command("mkdir /tmp/testfind", sess))
        _run(engine.handle_command("touch /tmp/testfind/a.txt", sess))
        resp, _, _td = _run(engine.handle_command("find /tmp/testfind", sess))
        assert "/tmp/testfind" in resp


class TestSessionSurvival:
    def test_writes_dont_corrupt_session(self, ctx):
        engine, fs, sess = ctx
        original_user = sess.current_user
        _run(engine.handle_command("mkdir x", sess))
        _run(engine.handle_command("touch y", sess))
        _run(engine.handle_command("rm y", sess))
        assert sess.current_user == original_user
        resp, _, _td = _run(engine.handle_command("whoami", sess))
        assert resp == original_user

    def test_overlay_isolated_per_session(self):
        fs = FakeFS("generic_linux")
        s1 = SimpleSession(current_directory="/root", current_user="root")
        s2 = SimpleSession(current_directory="/root", current_user="root")
        e = ResponseEngine(fs)

        _run(e.handle_command("mkdir s1_only", s1))
        resp, _, _td = _run(e.handle_command("ls", s2))
        assert "s1_only" not in resp

        resp, _, _td = _run(e.handle_command("ls", s1))
        assert "s1_only" in resp


class TestOverlayUnit:
    """Unit tests for SessionOverlay directly."""

    def test_mkdir_exists(self):
        o = SessionOverlay()
        fs = FakeFS("generic_linux")
        o.mkdir("/root/testdir")
        assert o.exists("/root/testdir", fs)
        assert o.is_directory("/root/testdir", fs)

    def test_touch_exists(self):
        o = SessionOverlay()
        fs = FakeFS("generic_linux")
        o.touch("/root/file.txt")
        assert o.exists("/root/file.txt", fs)
        assert o.is_file("/root/file.txt", fs)

    def test_rm_deletes(self):
        o = SessionOverlay()
        fs = FakeFS("generic_linux")
        o.touch("/root/file.txt")
        o.rm("/root/file.txt")
        assert not o.exists("/root/file.txt", fs)

    def test_rm_hides_fakefs_path(self):
        o = SessionOverlay()
        fs = FakeFS("generic_linux")
        assert fs.path_exists("/etc/hostname")
        o.rm("/etc/hostname")
        assert not o.exists("/etc/hostname", fs)

    def test_write_file_content(self):
        o = SessionOverlay()
        fs = FakeFS("generic_linux")
        o.write_file("/root/data.txt", "hello world")
        assert o.get_content("/root/data.txt", fs) == "hello world"

    def test_merged_children(self):
        o = SessionOverlay()
        fs = FakeFS("generic_linux")
        o.mkdir("/etc/mydir")
        children = o.get_merged_children("/etc", fs)
        assert "mydir" in children
        assert "passwd" in children

    def test_merged_children_respects_deletion(self):
        o = SessionOverlay()
        fs = FakeFS("generic_linux")
        o.rm("/etc/hostname")
        children = o.get_merged_children("/etc", fs)
        assert "hostname" not in children
        assert "passwd" in children

    def test_deleted_then_recreated(self):
        o = SessionOverlay()
        fs = FakeFS("generic_linux")
        o.rm("/etc/hostname")
        assert not o.exists("/etc/hostname", fs)
        o.touch("/etc/hostname")
        assert o.exists("/etc/hostname", fs)
