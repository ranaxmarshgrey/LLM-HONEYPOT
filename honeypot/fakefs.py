"""Module 4 — FakeFS (Fake File System).

The single source of truth for all simulated system state: directory tree,
file contents, process list, users/groups, network state, and the active
persona. Every other module MUST query FakeFS before responding — nothing
invents facts (CLAUDE.md §9 Rule 1).

Backed by per-persona JSON files in ``personas/``. Enforces the 8
consistency rules defined in ``honeypot/persona_validator.py`` at load time
and on every persona switch.

Sprint target: Sprint 2.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import stat as stat_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel, Field, field_validator, model_validator

from honeypot.persona_validator import validate as _validate_persona

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from honeypot.session_overlay import SessionOverlay

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic models — every JSON persona is validated against these on load.
# ---------------------------------------------------------------------------

class SystemInfo(BaseModel):
    hostname: str
    os: str
    kernel: str
    arch: str
    uptime_seconds: int
    boot_time: str
    timezone: str
    locale: str


class NetworkInterface(BaseModel):
    name: str
    ip: str
    mac: str
    netmask: str
    broadcast: Optional[str] = None
    state: str
    rx_bytes: int
    tx_bytes: int


class ActiveConnection(BaseModel):
    proto: str
    local_addr: str
    foreign_addr: str
    state: str
    pid: int
    program: str


class NetworkInfo(BaseModel):
    interfaces: List[NetworkInterface]
    open_ports: List[int]
    active_connections: List[ActiveConnection]


class UserInfo(BaseModel):
    username: str
    uid: int
    gid: int
    home: str
    shell: str
    groups: List[str]
    password_hash: str
    last_login: Optional[str] = None
    last_login_from: Optional[str] = None


class ProcessInfo(BaseModel):
    pid: int
    ppid: int
    user: str
    cpu_percent: float
    mem_percent: float
    vsz: int
    rss: int
    tty: str
    stat: str
    start: str
    time: str
    command: str


class FileEntry(BaseModel):
    type: str  # "file" or "directory"
    owner: str
    group: str
    permissions: str
    created: str
    modified: str
    size_bytes: Optional[int] = None
    content: Optional[str] = None
    children: Optional[List[str]] = None


class DiskInfo(BaseModel):
    total_gb: Union[int, float]
    used_gb: Union[int, float]
    available_gb: Union[int, float]
    use_percent: int
    filesystem: str
    mount: str


class MemoryInfo(BaseModel):
    total_mb: int
    used_mb: int
    free_mb: int
    shared_mb: int
    buff_cache_mb: int
    available_mb: int


class Persona(BaseModel):
    """Top-level Pydantic model matching the persona JSON schema."""

    persona_id: str
    display_name: str
    threat_trigger_level: str
    schema_version: int = 1

    system: SystemInfo
    network: NetworkInfo
    users: List[UserInfo]
    processes: List[ProcessInfo]
    filesystem: Dict[str, FileEntry]
    disk: DiskInfo
    memory: MemoryInfo
    environment_defaults: Dict[str, Dict[str, str]]

    model_config = {"extra": "forbid"}

    @field_validator("filesystem", mode="before")
    @classmethod
    def _parse_filesystem(cls, v: Any) -> Any:
        if isinstance(v, dict):
            return {path: FileEntry(**entry) if isinstance(entry, dict) else entry
                    for path, entry in v.items()}
        return v


# ---------------------------------------------------------------------------
# Persona directory discovery
# ---------------------------------------------------------------------------

_PERSONAS_DIR = Path(__file__).resolve().parent.parent / "personas"


def _find_persona_path(name: str) -> Path:
    path = _PERSONAS_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"persona file not found: {path}")
    return path


# ---------------------------------------------------------------------------
# FakeFS
# ---------------------------------------------------------------------------

class FakeFS:
    """Single source of truth for all simulated Linux system state.

    Constructed from a persona JSON file, validated with Pydantic on load.
    All query methods return strings formatted exactly as a real Linux
    command would — the Response Engine calls these directly.
    """

    def __init__(self, persona_name: str = "generic_linux") -> None:
        """Load and validate a persona by name.

        Args:
            persona_name: Basename (no extension) of a file under ``personas/``.

        Raises:
            FileNotFoundError: persona JSON does not exist.
            pydantic.ValidationError: JSON doesn't match the schema.
            ValueError: persona violates one or more consistency rules.
        """
        self._persona_name = persona_name
        self._persona: Persona = self._load(persona_name)
        self._raw: dict = self._load_raw(persona_name)
        self._transition_queue: List[dict] = []
        self._session_processes: List[ProcessInfo] = []
        self._session_hostname: Optional[str] = None

    # ------------------------------------------------------------------
    # Internal loaders
    # ------------------------------------------------------------------

    @staticmethod
    def _load_raw(name: str) -> dict:
        path = _find_persona_path(name)
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    @staticmethod
    def _load(name: str) -> Persona:
        raw = FakeFS._load_raw(name)
        persona = Persona.model_validate(raw)

        now = datetime.now(tz=timezone.utc)
        errors = _validate_persona(raw, now)
        if errors:
            msg = "persona consistency violations:\n" + "\n".join(f"  - {e}" for e in errors)
            raise ValueError(msg)

        return persona

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def persona_name(self) -> str:
        return self._persona_name

    @property
    def hostname(self) -> str:
        if self._session_hostname is not None:
            return self._session_hostname
        return self._persona.system.hostname

    @property
    def persona(self) -> Persona:
        return self._persona

    # ------------------------------------------------------------------
    # Query methods — all return terminal-ready strings
    # ------------------------------------------------------------------

    def get_directory_listing(
        self,
        path: str,
        flags: Optional[List[str]] = None,
        overlay: Optional[SessionOverlay] = None,
    ) -> str:
        """Simulate ``ls`` for a given path.

        Supports flags: ``-a`` (show dotfiles), ``-l`` (long format),
        ``-la``/``-al`` (both).

        Args:
            overlay: Optional session overlay. When provided, overlay
                entries are merged with FakeFS and deletions are respected.

        Raises:
            FileNotFoundError: path does not exist in the filesystem.
            PermissionError: caller would not be able to read the directory.
        """
        flags = flags or []
        flag_str = " ".join(flags)
        show_hidden = any(f in flag_str for f in ("-a", "-la", "-al", "-lah", "-alh"))
        long_fmt = any(f in flag_str for f in ("-l", "-la", "-al", "-lah", "-alh"))

        # Check overlay for deleted paths
        if overlay and path in overlay.deleted_paths:
            raise FileNotFoundError(f"ls: cannot access '{path}': No such file or directory")

        entry = self._persona.filesystem.get(path)
        overlay_entry = overlay.entries.get(path) if overlay else None

        if entry is None and overlay_entry is None:
            raise FileNotFoundError(f"ls: cannot access '{path}': No such file or directory")

        # If it's a file (overlay or FakeFS)
        if overlay_entry and overlay_entry.type == "file":
            if long_fmt:
                return self._format_long_entry(path, entry) if entry else path.rsplit("/", 1)[-1]
            return path.rsplit("/", 1)[-1]
        if entry is not None and entry.type == "file" and overlay_entry is None:
            if long_fmt:
                return self._format_long_entry(path, entry)
            return path.rsplit("/", 1)[-1]

        # Directory listing — merge overlay children if available
        if overlay:
            children = overlay.get_merged_children(path, self)
        else:
            children = list(entry.children or []) if entry else []

        if not show_hidden:
            children = [c for c in children if not c.startswith(".")]

        if not long_fmt:
            if show_hidden:
                children = [".", ".."] + children
            return "  ".join(children) if children else ""

        lines: List[str] = []
        total_blocks = 0

        listing_items: List[Tuple[str, Optional[FileEntry]]] = []
        if show_hidden:
            listing_items.append((".", entry))
            parent_path = path.rsplit("/", 1)[0] or "/"
            parent_entry = self._persona.filesystem.get(parent_path, entry)
            listing_items.append(("..", parent_entry))

        for child_name in children:
            child_path = f"{path.rstrip('/')}/{child_name}"
            child_entry = self._persona.filesystem.get(child_path)
            listing_items.append((child_name, child_entry))

        for name, ent in listing_items:
            if ent is None:
                continue
            size = ent.size_bytes if ent.size_bytes is not None else 4096
            total_blocks += (size + 1023) // 1024 * 2
            lines.append(self._format_long_line(name, ent))

        header = f"total {total_blocks}"
        return header + "\n" + "\n".join(lines) if lines else header

    def get_file_content(
        self, path: str, overlay: Optional[SessionOverlay] = None,
    ) -> str:
        """Return the content of a fake file.

        Args:
            overlay: Optional session overlay checked before FakeFS.

        Raises:
            FileNotFoundError: path does not exist.
            IsADirectoryError: path is a directory.
            PermissionError: file permissions would block the read.
        """
        if overlay:
            if path in overlay.deleted_paths:
                raise FileNotFoundError(f"cat: {path}: No such file or directory")
            if path in overlay.entries:
                oe = overlay.entries[path]
                if oe.type == "directory":
                    raise IsADirectoryError(f"cat: {path}: Is a directory")
                return oe.content

        entry = self._persona.filesystem.get(path)
        if entry is None:
            raise FileNotFoundError(f"cat: {path}: No such file or directory")
        if entry.type == "directory":
            raise IsADirectoryError(f"cat: {path}: Is a directory")
        if entry.content is None:
            raise PermissionError(f"cat: {path}: Permission denied")
        return entry.content

    def get_process_list(self, flags: Optional[List[str]] = None) -> str:
        """Simulate ``ps`` output.

        Supports ``aux`` (BSD-style full listing, the default) and ``-ef``
        (System V style).  Includes session-injected processes from
        ``add_session_process()``.
        """
        flags = flags or ["aux"]
        flag_str = " ".join(flags)
        all_procs = list(self._persona.processes) + self._session_processes

        if "-ef" in flag_str or "-e" in flag_str:
            lines = ["UID          PID    PPID  C STIME TTY          TIME CMD"]
            for p in all_procs:
                lines.append(
                    f"{p.user:<12s} {p.pid:>5d} {p.ppid:>7d}  {int(p.cpu_percent)} "
                    f"{p.start:>5s} {p.tty:<8s} {p.time:>8s} {p.command}"
                )
        else:
            lines = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
            for p in all_procs:
                lines.append(
                    f"{p.user:<12s} {p.pid:>5d} {p.cpu_percent:>4.1f} {p.mem_percent:>4.1f} "
                    f"{p.vsz:>6d} {p.rss:>5d} {p.tty:<8s} {p.stat:<4s} {p.start:>5s} "
                    f"{p.time:>6s} {p.command}"
                )
        return "\n".join(lines)

    def get_user_list(self) -> str:
        """Return a formatted list of interactive users (like ``cut -d: -f1 /etc/passwd``)."""
        passwd = self._persona.filesystem.get("/etc/passwd")
        if passwd and passwd.content:
            return "\n".join(
                line.split(":")[0] for line in passwd.content.splitlines() if line
            )
        return "\n".join(u.username for u in self._persona.users)

    def get_user(self, username: str) -> Optional[UserInfo]:
        """Look up a structured user by name."""
        for u in self._persona.users:
            if u.username == username:
                return u
        return None

    def add_session_process(self, process_dict: dict) -> None:
        """Add a process visible only in this FakeFS instance.

        Does not modify the persona JSON.  The process appears in
        ``get_process_list()`` output alongside the persona's processes.
        """
        existing_pids = {p.pid for p in self._persona.processes}
        existing_pids.update(p.pid for p in self._session_processes)
        pid = max(existing_pids, default=1000) + 1

        defaults = {
            "pid": pid,
            "ppid": 1,
            "user": "root",
            "cpu_percent": 0.1,
            "mem_percent": 0.3,
            "vsz": 256000,
            "rss": 12000,
            "tty": "?",
            "stat": "Ssl",
            "start": "Apr20",
            "time": "0:02",
            "command": "",
        }
        defaults.update(process_dict)
        self._session_processes.append(ProcessInfo(**defaults))

    def set_session_hostname(self, hostname: str) -> None:
        """Override hostname for this session only.

        Does not modify the persona JSON.  Affects ``hostname``,
        ``get_hostname()``, and the shell prompt.
        """
        self._session_hostname = hostname

    def get_environment(self, user: str) -> Dict[str, str]:
        """Return the environment variable dict for a user.

        Falls back to a minimal set derived from the user record if the
        persona does not define ``environment_defaults`` for this user.
        """
        if user in self._persona.environment_defaults:
            return dict(self._persona.environment_defaults[user])

        u = self.get_user(user)
        if u is None:
            return {
                "USER": user,
                "HOME": f"/home/{user}",
                "SHELL": "/bin/bash",
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": self._persona.system.locale,
                "PWD": f"/home/{user}",
            }
        return {
            "USER": u.username,
            "HOME": u.home,
            "SHELL": u.shell,
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": self._persona.system.locale,
            "PWD": u.home,
            "PS1": f"{u.username}@{self._persona.system.hostname}:~$ ",
        }

    def get_system_info(self) -> dict:
        """Return a dict of system facts for prompt construction."""
        s = self._persona.system
        return {
            "hostname": s.hostname,
            "os": s.os,
            "kernel": s.kernel,
            "arch": s.arch,
            "uptime_seconds": s.uptime_seconds,
            "boot_time": s.boot_time,
            "timezone": s.timezone,
            "locale": s.locale,
        }

    def get_uptime_string(self) -> str:
        """Simulate ``uptime`` output."""
        secs = self._persona.system.uptime_seconds
        days = secs // 86400
        hours = (secs % 86400) // 3600
        minutes = (secs % 3600) // 60

        if days > 0:
            up_str = f"up {days} days, {hours:2d}:{minutes:02d}"
        elif hours > 0:
            up_str = f"up {hours:2d}:{minutes:02d}"
        else:
            up_str = f"up {minutes} min"

        user_count = sum(
            1 for u in self._persona.users
            if not u.shell.endswith("nologin") and not u.shell.endswith("false")
        )
        load = "0.08, 0.03, 0.01"

        now_str = datetime.now(tz=timezone.utc).strftime("%H:%M:%S")
        return f" {now_str} {up_str},  {user_count} user,  load average: {load}"

    def get_disk_usage(self) -> str:
        """Simulate ``df -h`` output."""
        d = self._persona.disk
        return (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            f"{d.filesystem:<15s} {d.total_gb:>4.0f}G  {d.used_gb:>4.1f}G  "
            f"{d.available_gb:>5.1f}G  {d.use_percent:>3d}% {d.mount}"
        )

    def get_memory_usage(self) -> str:
        """Simulate ``free -m`` output."""
        m = self._persona.memory
        return (
            "              total        used        free      shared  buff/cache   available\n"
            f"Mem:    {m.total_mb:>10d}   {m.used_mb:>10d}   {m.free_mb:>10d}   "
            f"{m.shared_mb:>10d}   {m.buff_cache_mb:>10d}   {m.available_mb:>10d}\n"
            f"Swap:   {0:>10d}   {0:>10d}   {0:>10d}"
        )

    def get_network_interfaces(self) -> str:
        """Simulate a simplified ``ip addr`` / ``ifconfig`` output."""
        lines: List[str] = []
        for idx, iface in enumerate(self._persona.network.interfaces, 1):
            lines.append(f"{idx}: {iface.name}: <BROADCAST,MULTICAST,{iface.state}> mtu 1500")
            lines.append(f"    link/ether {iface.mac} brd ff:ff:ff:ff:ff:ff")
            brd = f" brd {iface.broadcast}" if iface.broadcast else ""
            lines.append(f"    inet {iface.ip}/{self._netmask_to_cidr(iface.netmask)}{brd} scope global {iface.name}")
        return "\n".join(lines)

    def get_network_state(self) -> str:
        """Simulate ``netstat -tlnp`` output."""
        return self.get_netstat()

    def get_netstat(self, flags: Optional[List[str]] = None) -> str:
        """Simulate ``netstat`` output.

        Default flags behave like ``-tlnp`` (TCP listening, numeric, show PID).
        """
        lines = [
            "Active Internet connections (only servers)",
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name",
        ]
        for conn in self._persona.network.active_connections:
            lines.append(
                f"{conn.proto:<6s} {0:>6d} {0:>6d} {conn.local_addr:<24s}"
                f"{conn.foreign_addr:<24s}{conn.state:<12s}{conn.pid}/{conn.program}"
            )
        return "\n".join(lines)

    def get_passwd_file(self) -> str:
        """Return the content of ``/etc/passwd``."""
        entry = self._persona.filesystem.get("/etc/passwd")
        if entry and entry.content:
            return entry.content
        return ""

    def get_shadow_file(self) -> str:
        """Return the content of ``/etc/shadow``."""
        entry = self._persona.filesystem.get("/etc/shadow")
        if entry and entry.content:
            return entry.content
        return ""

    def get_hostname(self) -> str:
        """Return the system hostname."""
        return self._persona.system.hostname

    def get_id_output(self, username: str) -> str:
        """Simulate ``id <username>`` output."""
        u = self.get_user(username)
        if u is None:
            return f"id: '{username}': no such user"
        groups_str = ",".join(f"{g}" for g in u.groups)
        return f"uid={u.uid}({u.username}) gid={u.gid}({u.username}) groups={u.gid}({u.username}),{groups_str}"

    def get_whoami(self, username: str) -> str:
        """Simulate ``whoami`` output."""
        return username

    def get_uname(self, flags: Optional[List[str]] = None) -> str:
        """Simulate ``uname`` with optional flags."""
        flags = flags or ["-a"]
        s = self._persona.system
        if "-a" in flags:
            return f"Linux {s.hostname} {s.kernel} #1 SMP {s.arch} GNU/Linux"
        if "-r" in flags:
            return s.kernel
        if "-n" in flags:
            return s.hostname
        if "-s" in flags:
            return "Linux"
        if "-m" in flags:
            return s.arch
        return "Linux"

    # ------------------------------------------------------------------
    # Consistency validation
    # ------------------------------------------------------------------

    def validate_consistency(self) -> List[str]:
        """Run all 8 consistency rules against the current persona state.

        Returns:
            Empty list if fully consistent, otherwise a list of violation
            description strings (each prefixed with ``Rule N:``).
        """
        now = datetime.now(tz=timezone.utc)
        return _validate_persona(self._raw, now)

    # ------------------------------------------------------------------
    # Persona switching — gradual merge (Sprint 5 delivery, skeleton here)
    # ------------------------------------------------------------------

    def switch_persona(self, new_persona_name: str, steps: int = 5) -> None:
        """Begin a gradual transition to a new persona.

        The switch is spread over *steps* calls to ``apply_transition_step()``
        so that the attacker sees incremental changes (new files, new processes)
        rather than a jarring full reset (CLAUDE.md §5, persona switching rules).

        Session-level state (command_history, threat_score, session_id) is NOT
        owned by FakeFS — the Session Manager preserves those independently.

        Args:
            new_persona_name: Basename of the target persona JSON.
            steps: Number of gradual steps (default 5).

        Raises:
            FileNotFoundError: target persona JSON missing.
            pydantic.ValidationError: target persona invalid.
            ValueError: target persona has consistency violations.
        """
        new_persona = self._load(new_persona_name)
        new_raw = self._load_raw(new_persona_name)

        self._transition_queue = self._plan_transition(
            self._persona, self._raw,
            new_persona, new_raw,
            steps,
        )
        logger.info(
            "persona switch queued: %s -> %s (%d steps)",
            self._persona_name, new_persona_name, len(self._transition_queue),
        )
        self._persona_name = new_persona_name

    def apply_transition_step(self) -> bool:
        """Apply the next incremental transition step.

        Returns:
            True if a step was applied, False if the transition is complete
            (queue empty).
        """
        if not self._transition_queue:
            return False

        patch = self._transition_queue.pop(0)
        self._apply_patch(patch)
        return True

    @property
    def transition_pending(self) -> bool:
        """True while gradual persona switch has unapplied steps."""
        return len(self._transition_queue) > 0

    @property
    def transition_steps_remaining(self) -> int:
        return len(self._transition_queue)

    # ------------------------------------------------------------------
    # LLM context summary — used by the Response Engine prompt builder
    # ------------------------------------------------------------------

    def get_llm_context_summary(self) -> dict:
        """Build a compact dict the Response Engine embeds into every LLM prompt.

        Covers: system facts, current user list, running processes (names
        only), network summary, and persona type. Intentionally small so it
        fits within the LLM context budget.
        """
        s = self._persona.system
        users = [u.username for u in self._persona.users]
        process_cmds = [p.command.split()[0].rsplit("/", 1)[-1] for p in self._persona.processes]
        ifaces = {i.name: i.ip for i in self._persona.network.interfaces}

        return {
            "hostname": s.hostname,
            "os_version": s.os,
            "kernel": s.kernel,
            "current_users": users,
            "process_summary": ", ".join(sorted(set(process_cmds))),
            "network_summary": ifaces,
            "open_ports": self._persona.network.open_ports,
            "persona_type": self._persona.persona_id,
            "persona_display": self._persona.display_name,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _netmask_to_cidr(netmask: str) -> int:
        parts = [int(p) for p in netmask.split(".")]
        return sum(bin(p).count("1") for p in parts)

    @staticmethod
    def _perm_string(perm_octal: str, is_dir: bool) -> str:
        mapping = {
            "0": "---", "1": "--x", "2": "-w-", "3": "-wx",
            "4": "r--", "5": "r-x", "6": "rw-", "7": "rwx",
        }
        prefix = "d" if is_dir else "-"
        digits = perm_octal.zfill(4)
        owner, group, other = digits[-3], digits[-2], digits[-1]
        special = int(digits[-4]) if len(digits) >= 4 else 0

        result = prefix + mapping[owner] + mapping[group] + mapping[other]

        r = list(result)
        if special & 4:
            r[3] = "s" if r[3] == "x" else "S"
        if special & 2:
            r[6] = "s" if r[6] == "x" else "S"
        if special & 1:
            r[9] = "t" if r[9] == "x" else "T"
        return "".join(r)

    def _format_long_line(self, name: str, entry: FileEntry) -> str:
        perm = self._perm_string(entry.permissions, entry.type == "directory")
        nlinks = 2 if entry.type == "directory" else 1
        size = entry.size_bytes if entry.size_bytes is not None else 4096
        mod = entry.modified
        try:
            dt = datetime.fromisoformat(mod.replace("Z", "+00:00"))
            date_str = dt.strftime("%b %d %H:%M")
        except (ValueError, AttributeError):
            date_str = "Jan  1 00:00"

        return (
            f"{perm} {nlinks:>2d} {entry.owner:<8s} {entry.group:<8s} "
            f"{size:>8d} {date_str} {name}"
        )

    def _format_long_entry(self, path: str, entry: FileEntry) -> str:
        name = path.rsplit("/", 1)[-1] or "/"
        return self._format_long_line(name, entry)

    # ------------------------------------------------------------------
    # Gradual transition planner + applier
    # ------------------------------------------------------------------

    def _plan_transition(
        self,
        old: Persona, old_raw: dict,
        new: Persona, new_raw: dict,
        steps: int,
    ) -> List[dict]:
        """Break a persona switch into incremental patches.

        Strategy:
          Step 1  — update system info (hostname, OS, kernel).
          Step 2  — add new users, update /etc/passwd and /etc/shadow.
          Step 3  — add new processes.
          Step 4  — merge new filesystem entries (files, directories).
          Step 5  — update network state (open ports, interfaces, connections),
                    remove old-persona–only entries.

        Each "patch" is a dict with keys that map to sections of the Persona.
        """
        patches: List[dict] = []

        patches.append({
            "type": "system",
            "system": new_raw["system"],
            "environment_defaults": new_raw.get("environment_defaults", {}),
        })

        patches.append({
            "type": "users",
            "users": new_raw["users"],
        })

        patches.append({
            "type": "processes",
            "processes": new_raw["processes"],
        })

        new_fs = new_raw["filesystem"]
        old_fs = old_raw["filesystem"]
        added_paths = {p: new_fs[p] for p in new_fs if p not in old_fs}
        updated_paths = {
            p: new_fs[p] for p in new_fs
            if p in old_fs and new_fs[p] != old_fs[p]
        }
        patches.append({
            "type": "filesystem",
            "add": added_paths,
            "update": updated_paths,
            "filesystem_full": new_fs,
        })

        patches.append({
            "type": "network",
            "network": new_raw["network"],
            "disk": new_raw["disk"],
            "memory": new_raw["memory"],
        })

        if len(patches) < steps:
            while len(patches) < steps:
                patches.append({"type": "noop"})
        elif len(patches) > steps:
            patches = patches[:steps - 1] + [self._merge_patches(patches[steps - 1:])]

        return patches

    @staticmethod
    def _merge_patches(patches: List[dict]) -> dict:
        merged: dict = {"type": "merged"}
        for p in patches:
            merged.update(p)
        merged["type"] = "merged"
        return merged

    def _apply_patch(self, patch: dict) -> None:
        ptype = patch.get("type", "noop")
        raw = self._raw

        if ptype == "noop":
            return

        if "system" in patch:
            raw["system"] = patch["system"]
        if "environment_defaults" in patch:
            raw["environment_defaults"] = patch["environment_defaults"]
        if "users" in patch:
            raw["users"] = patch["users"]
        if "processes" in patch:
            raw["processes"] = patch["processes"]
        if "network" in patch:
            raw["network"] = patch["network"]
        if "disk" in patch:
            raw["disk"] = patch["disk"]
        if "memory" in patch:
            raw["memory"] = patch["memory"]

        if "filesystem_full" in patch:
            raw["filesystem"] = patch["filesystem_full"]
        elif ptype == "filesystem":
            fs = raw["filesystem"]
            for path, entry in patch.get("add", {}).items():
                fs[path] = entry
            for path, entry in patch.get("update", {}).items():
                fs[path] = entry

        self._persona = Persona.model_validate(raw)

    # ------------------------------------------------------------------
    # Filesystem path helpers used by command handlers
    # ------------------------------------------------------------------

    def path_exists(
        self, path: str, overlay: Optional[SessionOverlay] = None,
    ) -> bool:
        if overlay:
            return overlay.exists(path, self)
        return path in self._persona.filesystem

    def is_directory(
        self, path: str, overlay: Optional[SessionOverlay] = None,
    ) -> bool:
        if overlay:
            return overlay.is_directory(path, self)
        entry = self._persona.filesystem.get(path)
        return entry is not None and entry.type == "directory"

    def is_file(
        self, path: str, overlay: Optional[SessionOverlay] = None,
    ) -> bool:
        if overlay:
            return overlay.is_file(path, self)
        entry = self._persona.filesystem.get(path)
        return entry is not None and entry.type == "file"

    def resolve_path(self, cwd: str, path: str) -> str:
        """Resolve a relative or absolute path against a working directory."""
        if path.startswith("/"):
            parts = path.split("/")
        else:
            parts = (cwd.rstrip("/") + "/" + path).split("/")

        resolved: List[str] = []
        for p in parts:
            if p == "" or p == ".":
                continue
            elif p == "..":
                if resolved:
                    resolved.pop()
            else:
                resolved.append(p)
        return "/" + "/".join(resolved) if resolved else "/"

    def find_files(
        self,
        path: str,
        name: Optional[str] = None,
        max_depth: int = 3,
        overlay: Optional[SessionOverlay] = None,
    ) -> List[str]:
        """Simulate a shallow ``find`` command.

        Args:
            overlay: Optional session overlay. Overlay entries are included
                and deleted paths are excluded from results.
        """
        results: set[str] = set()
        prefix = path.rstrip("/")
        deleted = overlay.deleted_paths if overlay else set()

        for fpath in self._persona.filesystem.keys():
            if fpath in deleted:
                continue
            if not fpath.startswith(prefix):
                continue
            depth = fpath[len(prefix):].count("/")
            if depth > max_depth:
                continue
            if name is not None:
                basename = fpath.rsplit("/", 1)[-1]
                if name.startswith("*"):
                    if not basename.endswith(name[1:]):
                        continue
                elif basename != name:
                    continue
            results.add(fpath)

        if overlay:
            for fpath in overlay.entries:
                if fpath in deleted:
                    continue
                if not fpath.startswith(prefix):
                    continue
                depth = fpath[len(prefix):].count("/")
                if depth > max_depth:
                    continue
                if name is not None:
                    basename = fpath.rsplit("/", 1)[-1]
                    if name.startswith("*"):
                        if not basename.endswith(name[1:]):
                            continue
                    elif basename != name:
                        continue
                results.add(fpath)

        return sorted(results)
