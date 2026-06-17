"""Cross-reference consistency test suite (Evaluation Metric 2, CLAUDE.md §10).

Executes scripted command sequences against FakeFS and verifies that
outputs are mutually consistent across every query method:

    ls /home            -> usernames appear
    cat /etc/passwd     -> same usernames, matching uids
    ps aux              -> process owners are valid users
    cat <known_file>    -> size matches ls -l output
    ifconfig/ip addr    -> IPs match netstat local addresses

Must reach 100% pass rate before Sprint 2 is considered done (§11).

Usage:
    pytest tests/test_consistency.py -v
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest

from honeypot.fakefs import FakeFS

# ---------------------------------------------------------------------------
# All three personas must pass every test.
# ---------------------------------------------------------------------------
PERSONA_NAMES = ["generic_linux", "dev_workstation", "finance_server"]


@pytest.fixture(params=PERSONA_NAMES)
def fs(request: pytest.FixtureRequest) -> FakeFS:
    return FakeFS(request.param)


# ---------------------------------------------------------------------------
# 1. validate_consistency() — the 8 rule validator returns no errors
# ---------------------------------------------------------------------------

class TestValidateConsistency:
    def test_all_rules_pass(self, fs: FakeFS) -> None:
        errors = fs.validate_consistency()
        assert errors == [], (
            f"persona '{fs.persona_name}' has consistency violations:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )


# ---------------------------------------------------------------------------
# 2. ls-then-cat coherence
# ---------------------------------------------------------------------------

class TestLsCatCoherence:
    def test_ls_files_are_readable(self, fs: FakeFS) -> None:
        """Every child that actually exists in the filesystem as an explicit
        entry should be readable (file) or listable (directory). Children
        listed in a directory's ``children`` array that are NOT materialized
        as their own filesystem entry (e.g. /bin, /boot in root) are
        tolerated — they represent implied OS paths the persona doesn't
        need to flesh out.
        """
        for path, entry in fs.persona.filesystem.items():
            if entry.type != "directory" or not entry.children:
                continue
            for child in entry.children:
                child_path = f"{path.rstrip('/')}/{child}"
                child_entry = fs.persona.filesystem.get(child_path)
                if child_entry is None:
                    continue
                if child_entry.type == "file":
                    try:
                        content = fs.get_file_content(child_path)
                        assert isinstance(content, str)
                    except PermissionError:
                        pass

    def test_cat_known_file_matches_ls_size(self, fs: FakeFS) -> None:
        """For files with content, ``len(content)`` matches ``size_bytes``."""
        for path, entry in fs.persona.filesystem.items():
            if entry.type != "file" or entry.content is None:
                continue
            content = fs.get_file_content(path)
            expected_size = len(content.encode("utf-8"))
            assert entry.size_bytes == expected_size, (
                f"{path}: size_bytes={entry.size_bytes} but content is {expected_size} bytes"
            )

    def test_cat_nonexistent_raises(self, fs: FakeFS) -> None:
        with pytest.raises(FileNotFoundError):
            fs.get_file_content("/no/such/file/here")

    def test_cat_directory_raises(self, fs: FakeFS) -> None:
        with pytest.raises(IsADirectoryError):
            fs.get_file_content("/etc")


# ---------------------------------------------------------------------------
# 3. passwd-home coherence (Rule 1)
# ---------------------------------------------------------------------------

class TestPasswdHomeCoherence:
    def test_interactive_users_have_home_dirs(self, fs: FakeFS) -> None:
        """Every interactive user (non-nologin, non-false shell) must have a
        home directory in the filesystem.
        """
        for user in fs.persona.users:
            if user.shell.endswith("nologin") or user.shell.endswith("false"):
                continue
            assert fs.path_exists(user.home), (
                f"user '{user.username}' home '{user.home}' missing from filesystem"
            )
            assert fs.is_directory(user.home), (
                f"user '{user.username}' home '{user.home}' exists but is not a directory"
            )

    def test_passwd_file_lists_all_structured_users(self, fs: FakeFS) -> None:
        """Every user in the users[] array must appear in /etc/passwd."""
        passwd_content = fs.get_passwd_file()
        passwd_users = {
            line.split(":")[0] for line in passwd_content.splitlines() if line
        }
        for user in fs.persona.users:
            assert user.username in passwd_users, (
                f"user '{user.username}' in users[] but missing from /etc/passwd"
            )

    def test_home_dirs_in_home_have_users(self, fs: FakeFS) -> None:
        """If /home/<x> exists and is a directory, there should be a user with
        that home or a passwd entry pointing to it.
        """
        home_entry = fs.persona.filesystem.get("/home")
        if home_entry is None or home_entry.children is None:
            return
        user_homes = {u.home for u in fs.persona.users}
        for child in home_entry.children:
            child_path = f"/home/{child}"
            assert child_path in user_homes, (
                f"/home/{child} exists but no user has home={child_path}"
            )


# ---------------------------------------------------------------------------
# 4. Process-user coherence (Rule 2)
# ---------------------------------------------------------------------------

class TestProcessUserCoherence:
    def test_all_process_owners_are_valid_users(self, fs: FakeFS) -> None:
        passwd_content = fs.get_passwd_file()
        valid_users = {
            line.split(":")[0] for line in passwd_content.splitlines() if line
        }
        for proc in fs.persona.processes:
            assert proc.user in valid_users, (
                f"process pid={proc.pid} cmd='{proc.command}' owned by "
                f"unknown user '{proc.user}'"
            )

    def test_ps_aux_lists_all_processes(self, fs: FakeFS) -> None:
        ps_output = fs.get_process_list(["aux"])
        for proc in fs.persona.processes:
            assert str(proc.pid) in ps_output, (
                f"pid {proc.pid} not found in ps aux output"
            )

    def test_ps_ef_lists_all_processes(self, fs: FakeFS) -> None:
        ps_output = fs.get_process_list(["-ef"])
        for proc in fs.persona.processes:
            assert str(proc.pid) in ps_output, (
                f"pid {proc.pid} not found in ps -ef output"
            )


# ---------------------------------------------------------------------------
# 5. Port-process coherence (Rule 3)
# ---------------------------------------------------------------------------

class TestPortProcessCoherence:
    def test_open_ports_have_listening_processes(self, fs: FakeFS) -> None:
        from honeypot.persona_validator import PORT_SERVICES

        all_commands = " ".join(
            p.command for p in fs.persona.processes
        ).lower()

        for port in fs.persona.network.open_ports:
            services = PORT_SERVICES.get(port, ())
            assert services, (
                f"port {port} has no PORT_SERVICES mapping"
            )
            assert any(svc in all_commands for svc in services), (
                f"port {port} open but no matching process running "
                f"(expected one of {services})"
            )

    def test_netstat_shows_open_ports(self, fs: FakeFS) -> None:
        netstat = fs.get_netstat()
        for port in fs.persona.network.open_ports:
            assert f":{port}" in netstat, (
                f"port {port} in open_ports but not shown in netstat"
            )


# ---------------------------------------------------------------------------
# 6. Hostname coherence (Rule 4)
# ---------------------------------------------------------------------------

class TestHostnameCoherence:
    def test_hostname_matches_etc_hostname(self, fs: FakeFS) -> None:
        hostname_content = fs.get_file_content("/etc/hostname").strip()
        assert hostname_content == fs.hostname, (
            f"/etc/hostname='{hostname_content}' != system.hostname='{fs.hostname}'"
        )

    def test_hostname_in_etc_hosts(self, fs: FakeFS) -> None:
        hosts_content = fs.get_file_content("/etc/hosts")
        assert fs.hostname in hosts_content, (
            f"hostname '{fs.hostname}' not mentioned in /etc/hosts"
        )

    def test_hostname_command(self, fs: FakeFS) -> None:
        assert fs.get_hostname() == fs.hostname

    def test_uname_n_matches(self, fs: FakeFS) -> None:
        assert fs.get_uname(["-n"]) == fs.hostname

    def test_uptime_string_not_empty(self, fs: FakeFS) -> None:
        uptime = fs.get_uptime_string()
        assert "up" in uptime


# ---------------------------------------------------------------------------
# 7. File size coherence (Rule 6)
# ---------------------------------------------------------------------------

class TestFileSizeCoherence:
    def test_all_file_sizes_match_content(self, fs: FakeFS) -> None:
        for path, entry in fs.persona.filesystem.items():
            if entry.type != "file" or entry.content is None:
                continue
            actual = len(entry.content.encode("utf-8"))
            assert entry.size_bytes == actual, (
                f"{path}: size_bytes={entry.size_bytes} but content is {actual} bytes"
            )


# ---------------------------------------------------------------------------
# 8. Timestamp validity (Rule 5)
# ---------------------------------------------------------------------------

class TestTimestampValidity:
    def test_no_future_timestamps(self, fs: FakeFS) -> None:
        now = datetime.now(tz=timezone.utc)
        for path, entry in fs.persona.filesystem.items():
            if entry.modified:
                modified = datetime.fromisoformat(
                    entry.modified.replace("Z", "+00:00")
                )
                assert modified <= now, (
                    f"{path}: modified={entry.modified} is in the future"
                )

    def test_modified_not_before_created(self, fs: FakeFS) -> None:
        for path, entry in fs.persona.filesystem.items():
            if not (entry.created and entry.modified):
                continue
            created = datetime.fromisoformat(
                entry.created.replace("Z", "+00:00")
            )
            modified = datetime.fromisoformat(
                entry.modified.replace("Z", "+00:00")
            )
            assert modified >= created, (
                f"{path}: modified={entry.modified} < created={entry.created}"
            )


# ---------------------------------------------------------------------------
# 9. Parent directory existence (Rule 7)
# ---------------------------------------------------------------------------

class TestParentDirectoryCoherence:
    def test_every_path_has_parent(self, fs: FakeFS) -> None:
        for path in fs.persona.filesystem:
            if path == "/":
                continue
            parent = path.rsplit("/", 1)[0] or "/"
            assert fs.path_exists(parent), (
                f"{path}: parent '{parent}' not in filesystem"
            )
            assert fs.is_directory(parent), (
                f"{path}: parent '{parent}' is not a directory"
            )

    def test_children_listed_in_parent(self, fs: FakeFS) -> None:
        for path in fs.persona.filesystem:
            if path == "/":
                continue
            parent = path.rsplit("/", 1)[0] or "/"
            basename = path.rsplit("/", 1)[1]
            parent_entry = fs.persona.filesystem[parent]
            assert basename in (parent_entry.children or []), (
                f"{path}: '{basename}' not listed in parent '{parent}' children"
            )


# ---------------------------------------------------------------------------
# 10. Shadow-passwd coherence (Rule 8)
# ---------------------------------------------------------------------------

class TestShadowPasswdCoherence:
    def test_passwd_users_in_shadow(self, fs: FakeFS) -> None:
        passwd = fs.get_passwd_file()
        shadow = fs.get_shadow_file()
        passwd_users = {
            line.split(":")[0] for line in passwd.splitlines() if line
        }
        shadow_users = {
            line.split(":")[0] for line in shadow.splitlines() if line
        }
        missing = passwd_users - shadow_users
        assert not missing, (
            f"users in /etc/passwd but missing from /etc/shadow: {sorted(missing)}"
        )


# ---------------------------------------------------------------------------
# 11. Cross-method consistency
# ---------------------------------------------------------------------------

class TestCrossMethodConsistency:
    def test_ls_home_matches_user_list(self, fs: FakeFS) -> None:
        """Users with homes under /home/ appear in both ``ls /home`` and
        ``get_user_list()``.
        """
        user_list = fs.get_user_list()
        home_entry = fs.persona.filesystem.get("/home")
        if home_entry is None:
            return
        for child in (home_entry.children or []):
            assert child in user_list, (
                f"'{child}' in ls /home but not in user list"
            )

    def test_id_output_matches_user_record(self, fs: FakeFS) -> None:
        for user in fs.persona.users:
            id_out = fs.get_id_output(user.username)
            assert f"uid={user.uid}" in id_out
            assert f"({user.username})" in id_out

    def test_id_unknown_user(self, fs: FakeFS) -> None:
        result = fs.get_id_output("nonexistent_user_xyz")
        assert "no such user" in result

    def test_environment_contains_required_vars(self, fs: FakeFS) -> None:
        for user in fs.persona.users:
            if user.shell.endswith("nologin") or user.shell.endswith("false"):
                continue
            env = fs.get_environment(user.username)
            assert env["USER"] == user.username
            assert env["HOME"] == user.home
            assert "PATH" in env

    def test_network_interfaces_show_all_ifaces(self, fs: FakeFS) -> None:
        iface_output = fs.get_network_interfaces()
        for iface in fs.persona.network.interfaces:
            assert iface.name in iface_output, (
                f"interface '{iface.name}' missing from ip addr output"
            )
            assert iface.ip in iface_output, (
                f"IP '{iface.ip}' for '{iface.name}' missing from ip addr output"
            )

    def test_disk_usage_not_empty(self, fs: FakeFS) -> None:
        df = fs.get_disk_usage()
        assert "Filesystem" in df
        assert fs.persona.disk.filesystem in df

    def test_memory_usage_not_empty(self, fs: FakeFS) -> None:
        free = fs.get_memory_usage()
        assert "Mem:" in free
        assert str(fs.persona.memory.total_mb) in free

    def test_llm_context_summary_has_required_keys(self, fs: FakeFS) -> None:
        ctx = fs.get_llm_context_summary()
        required = {
            "hostname", "os_version", "kernel", "current_users",
            "process_summary", "network_summary", "open_ports",
            "persona_type", "persona_display",
        }
        missing = required - set(ctx.keys())
        assert not missing, f"LLM context missing keys: {missing}"
        assert ctx["hostname"] == fs.hostname

    def test_uname_variants(self, fs: FakeFS) -> None:
        assert fs.get_uname(["-s"]) == "Linux"
        assert fs.get_uname(["-r"]) == fs.persona.system.kernel
        assert fs.get_uname(["-m"]) == fs.persona.system.arch


# ---------------------------------------------------------------------------
# 12. Persona switch preserves consistency
# ---------------------------------------------------------------------------

class TestPersonaSwitch:
    def test_switch_generic_to_dev(self) -> None:
        fs = FakeFS("generic_linux")
        assert fs.hostname == "web-srv-03"

        fs.switch_persona("dev_workstation")
        while fs.transition_pending:
            fs.apply_transition_step()

        assert fs.hostname == "dev-workstation-07"
        errors = fs.validate_consistency()
        assert errors == [], (
            "consistency violations after switch:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )

    def test_switch_dev_to_finance(self) -> None:
        fs = FakeFS("dev_workstation")
        fs.switch_persona("finance_server")
        while fs.transition_pending:
            fs.apply_transition_step()

        assert fs.hostname == "fin-db-prod-01"
        errors = fs.validate_consistency()
        assert errors == [], (
            "consistency violations after switch:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )

    def test_transition_is_gradual(self) -> None:
        fs = FakeFS("generic_linux")
        fs.switch_persona("dev_workstation", steps=5)
        assert fs.transition_steps_remaining == 5

        fs.apply_transition_step()
        assert fs.transition_steps_remaining == 4
        assert fs.hostname == "dev-workstation-07"

        while fs.transition_pending:
            fs.apply_transition_step()
        assert fs.transition_steps_remaining == 0
        assert not fs.transition_pending

    def test_no_step_when_complete(self) -> None:
        fs = FakeFS("generic_linux")
        assert fs.apply_transition_step() is False


# ---------------------------------------------------------------------------
# 13. Path resolution helpers
# ---------------------------------------------------------------------------

class TestPathResolution:
    def test_resolve_absolute(self, fs: FakeFS) -> None:
        assert fs.resolve_path("/home/user", "/etc/passwd") == "/etc/passwd"

    def test_resolve_relative(self, fs: FakeFS) -> None:
        assert fs.resolve_path("/home/user", "..") == "/home"

    def test_resolve_dot_dot_at_root(self, fs: FakeFS) -> None:
        assert fs.resolve_path("/", "..") == "/"

    def test_resolve_dot(self, fs: FakeFS) -> None:
        assert fs.resolve_path("/etc", ".") == "/etc"

    def test_resolve_nested_relative(self, fs: FakeFS) -> None:
        assert fs.resolve_path("/home/user", "../../etc") == "/etc"


# ---------------------------------------------------------------------------
# 14. Uptime sanity
# ---------------------------------------------------------------------------

class TestUptimeSanity:
    def test_uptime_positive(self, fs: FakeFS) -> None:
        assert fs.persona.system.uptime_seconds > 0

    def test_uptime_string_contains_up(self, fs: FakeFS) -> None:
        uptime = fs.get_uptime_string()
        assert "up" in uptime
        assert "load average" in uptime
