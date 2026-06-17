"""Fast-path command handler functions (Sprint 3, Tier 1 + Tier 2).

Each handler takes ``(fakefs, session, parsed_cmd)`` and returns the
stdout string a real shell would print. All output MUST be derived from
FakeFS — no hardcoded usernames, PIDs, file contents, etc. (CLAUDE.md
Rule 2).

``session`` is any object exposing the ``SessionProtocol`` interface
defined below. The real Session Manager (Sprint 4) will satisfy it; tests
can use the ``SimpleSession`` helper also defined here.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol, runtime_checkable

if TYPE_CHECKING:
    from honeypot.command_parser import ParsedCommand
    from honeypot.fakefs import FakeFS

from honeypot.session_overlay import SessionOverlay


# ---------------------------------------------------------------------------
# Session protocol — the minimum contract handlers rely on.
# ---------------------------------------------------------------------------

@runtime_checkable
class SessionProtocol(Protocol):
    current_directory: str
    current_user: str
    command_history: List[dict]
    environment: Dict[str, str]
    overlay: SessionOverlay


@dataclass
class SimpleSession:
    """Lightweight session for tests and standalone use."""

    current_directory: str = "/home/ubuntu"
    current_user: str = "ubuntu"
    command_history: List[dict] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    overlay: SessionOverlay = field(default_factory=SessionOverlay)
    threat_score: int = 0
    active_persona: str = "generic_linux"
    persona_switch_count: int = 0
    patterns_detected: set = field(default_factory=set)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve(fakefs: FakeFS, session: SessionProtocol, path: str) -> str:
    """Resolve a possibly-relative path against the session cwd."""
    if path == "~":
        user = fakefs.get_user(session.current_user)
        return user.home if user else f"/home/{session.current_user}"
    if path.startswith("~/"):
        user = fakefs.get_user(session.current_user)
        home = user.home if user else f"/home/{session.current_user}"
        return fakefs.resolve_path(home, path[2:])
    return fakefs.resolve_path(session.current_directory, path)


def _expand_vars(text: str, session: SessionProtocol, fakefs: FakeFS) -> str:
    """Expand ``$VAR`` and ``${VAR}`` references in text."""
    env = session.environment or fakefs.get_environment(session.current_user)

    def _repl(m: re.Match) -> str:
        name = m.group(1)
        return env.get(name, "")

    return re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", _repl, text)


# ---------------------------------------------------------------------------
# Tier 1 handlers — 20 commands
# ---------------------------------------------------------------------------

def handle_ls(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``ls`` with flag support and overlay awareness."""
    path = cmd.args[0] if cmd.args else session.current_directory
    path = _resolve(fakefs, session, path)
    overlay = session.overlay

    if not overlay.exists(path, fakefs):
        return f"ls: cannot access '{path}': No such file or directory"

    if overlay.is_file(path, fakefs):
        return path.rsplit("/", 1)[-1]

    flags = cmd.flags or []
    flag_str = " ".join(flags)
    show_hidden = any(f in flag_str for f in ("-a", "-la", "-al", "-lah", "-alh"))
    long_fmt = any(f in flag_str for f in ("-l", "-la", "-al", "-lah", "-alh", "-ls"))

    merged = overlay.get_merged_children(path, fakefs)
    if not show_hidden:
        merged = [c for c in merged if not c.startswith(".")]

    if not long_fmt:
        items = merged[:]
        if show_hidden:
            items = [".", ".."] + items
        return "  ".join(items) if items else ""

    try:
        base_listing = fakefs.get_directory_listing(path, flags)
    except (FileNotFoundError, PermissionError):
        base_listing = ""

    has_overlay = any(
        opath.startswith(path.rstrip("/") + "/")
        for opath in overlay.entries
    )
    has_deletions = any(
        dp.startswith(path.rstrip("/") + "/")
        for dp in overlay.deleted_paths
    )

    if not has_overlay and not has_deletions:
        return base_listing

    base_lines = base_listing.splitlines() if base_listing else []
    filtered = []
    for line in base_lines:
        parts = line.split()
        if parts and not line.startswith("total"):
            entry_name = parts[-1]
            if entry_name in (".", ".."):
                filtered.append(line)
                continue
            child_path = f"{path.rstrip('/')}/{entry_name}"
            if child_path in overlay.deleted_paths:
                continue
        filtered.append(line)

    overlay_names_in_listing = set()
    for line in filtered:
        parts = line.split()
        if parts and not line.startswith("total"):
            overlay_names_in_listing.add(parts[-1])

    extra_lines: List[str] = []
    for child_name in merged:
        if child_name in overlay_names_in_listing:
            continue
        child_path = f"{path.rstrip('/')}/{child_name}"
        meta = overlay.get_overlay_entry_for_listing(child_path)
        if meta is None:
            continue
        perm = fakefs._perm_string(meta["permissions"], meta["type"] == "directory")
        nlinks = 2 if meta["type"] == "directory" else 1
        size = meta["size_bytes"]
        try:
            dt = datetime.fromisoformat(meta["modified"].replace("Z", "+00:00"))
            date_str = dt.strftime("%b %d %H:%M")
        except (ValueError, AttributeError):
            date_str = "Jan  1 00:00"
        extra_lines.append(
            f"{perm} {nlinks:>2d} {meta['owner']:<8s} {meta['group']:<8s} "
            f"{size:>8d} {date_str} {child_name}"
        )

    if filtered:
        return "\n".join(filtered + extra_lines)

    if extra_lines:
        total = sum(8 for _ in extra_lines)
        return f"total {total}\n" + "\n".join(extra_lines)

    return ""


def handle_pwd(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    return session.current_directory


def handle_whoami(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    return fakefs.get_whoami(session.current_user)


def handle_id(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``id [username]``."""
    target = cmd.args[0] if cmd.args else session.current_user
    return fakefs.get_id_output(target)


def handle_uname(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    flags = cmd.flags if cmd.flags else ["-s"]
    return fakefs.get_uname(flags)


def handle_hostname(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    sys_info = fakefs.get_system_info()
    if "-f" in (cmd.flags or []) or "--fqdn" in (cmd.flags or []):
        return sys_info["hostname"] + ".localdomain"
    if "-i" in (cmd.flags or []):
        ifaces = fakefs.persona.network.interfaces
        for iface in ifaces:
            if iface.name != "lo":
                return iface.ip
        return "127.0.0.1"
    return sys_info["hostname"]


def handle_cat(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``cat`` — read from overlay first, then FakeFS."""
    if not cmd.args:
        return ""

    overlay = session.overlay
    parts: List[str] = []
    for arg in cmd.args:
        path = _resolve(fakefs, session, arg)
        if path in overlay.deleted_paths:
            parts.append(f"cat: {arg}: No such file or directory")
            continue
        if path in overlay.entries:
            if overlay.entries[path].type == "directory":
                parts.append(f"cat: {arg}: Is a directory")
            else:
                parts.append(overlay.entries[path].content)
            continue
        try:
            parts.append(fakefs.get_file_content(path))
        except FileNotFoundError:
            parts.append(f"cat: {arg}: No such file or directory")
        except IsADirectoryError:
            parts.append(f"cat: {arg}: Is a directory")
        except PermissionError:
            parts.append(f"cat: {arg}: Permission denied")

    return "".join(parts).rstrip("\n")


def handle_echo(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``echo`` — expand env vars, join args.

    Uses parsed args (which exclude redirects) so that
    ``echo hello > file`` echoes ``hello``, not ``hello > file``.
    """
    if not cmd.args and not cmd.flags:
        return ""
    if cmd.redirects:
        text = " ".join(cmd.args)
    else:
        raw_tail = cmd.raw.strip()
        if raw_tail.startswith("echo "):
            raw_tail = raw_tail[5:]
        elif raw_tail == "echo":
            return ""
        text = raw_tail
    return _expand_vars(text, session, fakefs)


def handle_ps(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    flags = cmd.flags if cmd.flags else ["aux"]
    all_flags = flags + cmd.args
    return fakefs.get_process_list(all_flags)


def handle_netstat(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    return fakefs.get_netstat(cmd.flags or None)


def handle_ifconfig(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``ifconfig``.

    Uses ``get_network_interfaces()`` which produces ``ip addr`` style
    output — close enough for honeypot purposes. Real ifconfig is
    deprecated on modern Linux anyway.
    """
    return fakefs.get_network_interfaces()


def handle_ip(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``ip`` subcommands (``addr``, ``route``, ``link``)."""
    sub = cmd.args[0] if cmd.args else "addr"

    if sub in ("addr", "address", "a"):
        return fakefs.get_network_interfaces()

    if sub in ("route", "r"):
        ifaces = fakefs.persona.network.interfaces
        gateway_iface = next(
            (i for i in ifaces if i.name != "lo"), ifaces[0]
        )
        gw_parts = gateway_iface.ip.rsplit(".", 1)
        gateway = gw_parts[0] + ".1"
        net = gw_parts[0] + ".0/24"
        return (
            f"default via {gateway} dev {gateway_iface.name} proto dhcp metric 100\n"
            f"{net} dev {gateway_iface.name} proto kernel scope link src {gateway_iface.ip} metric 100"
        )

    if sub in ("link", "l"):
        lines: List[str] = []
        for idx, iface in enumerate(fakefs.persona.network.interfaces, 1):
            state = iface.state
            lines.append(
                f"{idx}: {iface.name}: <BROADCAST,MULTICAST,{state}> mtu 1500 "
                f"qdisc fq_codel state {state}"
            )
            lines.append(f"    link/ether {iface.mac} brd ff:ff:ff:ff:ff:ff")
        return "\n".join(lines)

    return f"Command \"ip {sub}\" is unknown, try \"ip help\"."


def handle_history(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Return the session's live command history, NOT ``.bash_history``."""
    if not session.command_history:
        return ""
    lines: List[str] = []
    for idx, entry in enumerate(session.command_history, 1):
        raw = entry.get("raw", entry.get("command", ""))
        lines.append(f"  {idx:>4d}  {raw}")
    return "\n".join(lines)


def handle_env(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``env`` — print all environment variables."""
    env = session.environment if session.environment else fakefs.get_environment(session.current_user)
    return "\n".join(f"{k}={v}" for k, v in env.items())


def handle_printenv(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``printenv [VAR]``."""
    env = session.environment if session.environment else fakefs.get_environment(session.current_user)
    if cmd.args:
        var = cmd.args[0]
        val = env.get(var)
        if val is None:
            return ""
        return val
    return "\n".join(f"{k}={v}" for k, v in env.items())


def handle_cd(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``cd`` — updates ``session.current_directory``.

    Checks both the session overlay and FakeFS for path existence.
    """
    if not cmd.args or cmd.args[0] == "~":
        user = fakefs.get_user(session.current_user)
        target = user.home if user else f"/home/{session.current_user}"
    elif cmd.args[0] == "-":
        target = session.environment.get("OLDPWD", session.current_directory)
    else:
        target = _resolve(fakefs, session, cmd.args[0])

    overlay = session.overlay

    if not overlay.exists(target, fakefs):
        return f"-bash: cd: {cmd.args[0] if cmd.args else '~'}: No such file or directory"

    if not overlay.is_directory(target, fakefs):
        return f"-bash: cd: {cmd.args[0]}: Not a directory"

    old = session.current_directory
    session.current_directory = target

    if hasattr(session, "environment") and isinstance(session.environment, dict):
        session.environment["OLDPWD"] = old
        session.environment["PWD"] = target

    return ""


def handle_date(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``date`` — use the persona's timezone."""
    tz_name = fakefs.get_system_info().get("timezone", "UTC")
    now = datetime.now(tz=timezone.utc)
    return now.strftime("%a %b %d %H:%M:%S") + f" {tz_name} " + now.strftime("%Y")


def handle_uptime(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    return fakefs.get_uptime_string()


def handle_df(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    return fakefs.get_disk_usage()


def handle_free(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    return fakefs.get_memory_usage()


# ---------------------------------------------------------------------------
# Tier 2 handlers — 20 commands
# ---------------------------------------------------------------------------

def _retokenize_raw(cmd: ParsedCommand) -> List[str]:
    """Re-tokenize the raw command string to preserve original order."""
    import shlex
    raw = cmd.raw.strip()
    try:
        tokens = shlex.split(raw)
    except ValueError:
        tokens = raw.split()
    return tokens[1:] if tokens else []


def handle_find(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``find`` — searches FakeFS directory tree."""
    path = "."
    name_filter = None
    type_filter = None
    max_depth = 3

    tokens = _retokenize_raw(cmd)
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "-name" and i + 1 < len(tokens):
            name_filter = tokens[i + 1]
            i += 2
        elif tok == "-type" and i + 1 < len(tokens):
            type_filter = tokens[i + 1]
            i += 2
        elif tok == "-maxdepth" and i + 1 < len(tokens):
            try:
                max_depth = int(tokens[i + 1])
            except ValueError:
                pass
            i += 2
        elif tok == "-perm":
            i += 2
        elif not tok.startswith("-"):
            path = tok
            i += 1
        else:
            i += 1

    resolved = _resolve(fakefs, session, path)
    overlay = session.overlay
    if not overlay.exists(resolved, fakefs):
        return f"find: '{path}': No such file or directory"

    results = fakefs.find_files(resolved, name=name_filter, max_depth=max_depth, overlay=overlay)

    if type_filter == "f":
        results = [r for r in results if overlay.is_file(r, fakefs)]
    elif type_filter == "d":
        results = [r for r in results if overlay.is_directory(r, fakefs)]

    return "\n".join(sorted(results)) if results else ""


def handle_grep(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``grep`` — search file contents in FakeFS and overlay."""
    if len(cmd.args) < 1:
        return "Usage: grep [OPTION]... PATTERNS [FILE]..."

    pattern = cmd.args[0]
    files = cmd.args[1:] if len(cmd.args) > 1 else []
    ignore_case = "-i" in (cmd.flags or [])
    line_numbers = "-n" in (cmd.flags or [])
    recursive = "-r" in (cmd.flags or []) or "-R" in (cmd.flags or [])
    overlay = session.overlay

    if not files and not recursive:
        return ""

    if recursive and not files:
        files = [session.current_directory]

    target_files: List[str] = []
    for f in files:
        resolved = _resolve(fakefs, session, f)
        if overlay.is_directory(resolved, fakefs) and recursive:
            found = fakefs.find_files(resolved, overlay=overlay)
            target_files.extend(
                p for p in found if overlay.is_file(p, fakefs)
            )
        elif overlay.is_file(resolved, fakefs):
            target_files.append(resolved)

    output_lines: List[str] = []
    multi = len(target_files) > 1

    for fpath in target_files:
        content = overlay.get_content(fpath, fakefs)
        if content is None:
            continue

        for lineno, line in enumerate(content.splitlines(), 1):
            text = line if not ignore_case else line.lower()
            pat = pattern if not ignore_case else pattern.lower()
            if pat in text:
                prefix = f"{fpath}:" if multi else ""
                num = f"{lineno}:" if line_numbers else ""
                output_lines.append(f"{prefix}{num}{line}")

    return "\n".join(output_lines)


def handle_which(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``which`` — return plausible binary paths."""
    if not cmd.args:
        return ""

    known_paths = {
        "bash": "/usr/bin/bash", "sh": "/bin/sh",
        "ls": "/usr/bin/ls", "cat": "/usr/bin/cat",
        "grep": "/usr/bin/grep", "find": "/usr/bin/find",
        "ps": "/usr/bin/ps", "whoami": "/usr/bin/whoami",
        "id": "/usr/bin/id", "uname": "/usr/bin/uname",
        "hostname": "/usr/bin/hostname", "date": "/usr/bin/date",
        "df": "/usr/bin/df", "free": "/usr/bin/free",
        "netstat": "/usr/bin/netstat", "ifconfig": "/usr/sbin/ifconfig",
        "ip": "/usr/sbin/ip", "ssh": "/usr/bin/ssh",
        "scp": "/usr/bin/scp", "wget": "/usr/bin/wget",
        "curl": "/usr/bin/curl", "python3": "/usr/bin/python3",
        "python": "/usr/bin/python3", "node": "/usr/bin/node",
        "git": "/usr/bin/git", "docker": "/usr/bin/docker",
        "sudo": "/usr/bin/sudo", "su": "/usr/bin/su",
        "chmod": "/usr/bin/chmod", "chown": "/usr/bin/chown",
        "mkdir": "/usr/bin/mkdir", "touch": "/usr/bin/touch",
        "rm": "/usr/bin/rm", "cp": "/usr/bin/cp", "mv": "/usr/bin/mv",
        "head": "/usr/bin/head", "tail": "/usr/bin/tail",
        "less": "/usr/bin/less", "more": "/usr/bin/more",
        "vi": "/usr/bin/vi", "vim": "/usr/bin/vim",
        "nano": "/usr/bin/nano", "awk": "/usr/bin/awk",
        "sed": "/usr/bin/sed", "sort": "/usr/bin/sort",
        "wc": "/usr/bin/wc", "tar": "/usr/bin/tar",
        "gzip": "/usr/bin/gzip", "ping": "/usr/bin/ping",
    }
    lines: List[str] = []
    for binary in cmd.args:
        if binary in known_paths:
            lines.append(known_paths[binary])
        else:
            lines.append(f"which: no {binary} in (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)")
    return "\n".join(lines)


def handle_w(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``w`` — who is logged in and what they're doing."""
    now_str = datetime.now(tz=timezone.utc).strftime("%H:%M:%S")
    up_str = fakefs.get_uptime_string().strip()

    header = f" {now_str} {up_str.split(',', 1)[-1].strip() if ',' in up_str else up_str}"
    col_header = "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT"

    user = fakefs.get_user(session.current_user)
    login_time = datetime.now(tz=timezone.utc).strftime("%H:%M")
    user_line = (
        f"{session.current_user:<8s} pts/0    "
        f"{'10.0.2.2':<16s} {login_time}    0.00s  0.04s  0.00s w"
    )
    return f"{header}\n{col_header}\n{user_line}"


def handle_last(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``last`` — recent login history from FakeFS users."""
    lines: List[str] = []
    for u in fakefs.persona.users:
        if u.shell.endswith("nologin") or u.shell.endswith("false"):
            continue
        login_from = u.last_login_from or "10.0.2.2"
        login_time = u.last_login or "Mon Apr 14 08:30"
        lines.append(
            f"{u.username:<10s} pts/0        {login_from:<16s} {login_time}   still logged in"
        )

    lines.append("")
    lines.append(f"wtmp begins {fakefs.persona.system.boot_time}")
    return "\n".join(lines)


def handle_groups(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``groups [user]``."""
    target = cmd.args[0] if cmd.args else session.current_user
    user = fakefs.get_user(target)
    if user is None:
        return f"groups: '{target}': no such user"
    return f"{target} : {' '.join(user.groups)}"


def handle_sudo(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``sudo`` — never grants root, shows realistic failure."""
    if not cmd.subcommand:
        return (
            "usage: sudo -h | -K | -k | -V\n"
            "usage: sudo [-ABbEHnPS] [-C num] [-D directory] [-g group] "
            "[-h host] [-p prompt] [-R directory] [-T timeout] [-u user] "
            "[VAR=value] [-i | -s] [command [arg ...]]"
        )
    return (
        f"[sudo] password for {session.current_user}: \n"
        f"Sorry, user {session.current_user} is not allowed to execute "
        f"'{cmd.subcommand}' as root on {fakefs.hostname}."
    )


def handle_su(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``su`` — always fails authentication."""
    target = cmd.subcommand or "root"
    return f"Password: \nsu: Authentication failure"


def handle_ssh(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``ssh`` — connection timeout."""
    if not cmd.args:
        return "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] destination"
    target = cmd.args[-1]
    return f"ssh: connect to host {target} port 22: Connection timed out"


def handle_wget(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``wget`` — fake download progress, file saved to overlay."""
    if not cmd.args:
        return "wget: missing URL\nUsage: wget [OPTION]... [URL]..."

    url = cmd.args[0]
    flags = cmd.flags or []

    output_file = None
    tokens = _retokenize_raw(cmd)
    for i, tok in enumerate(tokens):
        if tok in ("-O", "--output-document") and i + 1 < len(tokens):
            output_file = tokens[i + 1]
            break
        if tok.startswith("-O") and len(tok) > 2:
            output_file = tok[2:]
            break

    if output_file is None:
        raw_name = url.split("?")[0].rsplit("/", 1)[-1]
        output_file = raw_name if raw_name else "index.html"

    try:
        host = url.split("//")[1].split("/")[0] if "//" in url else url.split("/")[0]
    except IndexError:
        host = url

    fake_ip = "93.184.216.34"
    fake_size = 1256
    now_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    fake_content = f"<!-- Downloaded from {url} -->\n<html><body>It works!</body></html>\n"

    dst_path = _resolve(fakefs, session, output_file)
    session.overlay.write_file(dst_path, fake_content)

    progress = (
        f"--{now_str}--  {url}\n"
        f"Resolving {host} ({host})... {fake_ip}\n"
        f"Connecting to {host} ({host})|{fake_ip}|:443... connected.\n"
        f"HTTP request sent, awaiting response... 200 OK\n"
        f"Length: {fake_size} (1.2K) [text/html]\n"
        f"Saving to: '{output_file}'\n"
        f"\n"
        f"{output_file}              100%[===================>]   1.23K  --.-KB/s    in 0s\n"
        f"\n"
        f"{now_str} (4.56 MB/s) - '{output_file}' saved [{fake_size}/{fake_size}]"
    )
    return progress


def handle_curl(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``curl`` — fake download, file saved to overlay with -o/-O."""
    if not cmd.args:
        return (
            "curl: try 'curl --help' or 'curl --manual' for more information"
        )

    url = cmd.args[0]
    flags = cmd.flags or []
    tokens = _retokenize_raw(cmd)

    try:
        host = url.split("//")[1].split("/")[0] if "//" in url else url.split("/")[0]
    except IndexError:
        host = url

    output_file = None
    for i, tok in enumerate(tokens):
        if tok in ("-o", "--output") and i + 1 < len(tokens):
            output_file = tokens[i + 1]
            break
        if tok == "-O" or tok == "--remote-name":
            raw_name = url.split("?")[0].rsplit("/", 1)[-1]
            output_file = raw_name if raw_name else "index.html"
            break

    fake_content = f"<!-- Downloaded from {url} -->\n<html><body>It works!</body></html>\n"
    fake_size = len(fake_content)

    if output_file:
        dst_path = _resolve(fakefs, session, output_file)
        session.overlay.write_file(dst_path, fake_content)
        return (
            f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
            f"                                 Dload  Upload   Total   Spent    Left  Speed\n"
            f"100  {fake_size}  100  {fake_size}    0     0  12345      0 --:--:-- --:--:-- --:--:-- 12345"
        )

    return fake_content.rstrip("\n")


def handle_chmod(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``chmod`` — accepts command, does NOT modify FakeFS."""
    if len(cmd.args) < 2:
        return "chmod: missing operand\nTry 'chmod --help' for more information."
    return ""


def handle_chown(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``chown`` — overlay-aware path validation."""
    if len(cmd.args) < 2:
        return "chown: missing operand\nTry 'chown --help' for more information."
    target = cmd.args[-1]
    path = _resolve(fakefs, session, target)
    if not session.overlay.exists(path, fakefs):
        return f"chown: cannot access '{target}': No such file or directory"
    return ""


def handle_mkdir(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``mkdir`` — creates directory in session overlay."""
    if not cmd.args:
        return "mkdir: missing operand\nTry 'mkdir --help' for more information."
    overlay = session.overlay
    create_parents = "-p" in (cmd.flags or [])
    for arg in cmd.args:
        path = _resolve(fakefs, session, arg)
        if overlay.exists(path, fakefs) and not create_parents:
            return f"mkdir: cannot create directory '{arg}': File exists"
        overlay.mkdir(path)
    return ""


def handle_touch(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``touch`` — creates file in session overlay."""
    if not cmd.args:
        return "touch: missing file operand\nTry 'touch --help' for more information."
    overlay = session.overlay
    for arg in cmd.args:
        path = _resolve(fakefs, session, arg)
        overlay.touch(path)
    return ""


def handle_rm(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``rm`` — marks path as deleted in session overlay."""
    if not cmd.args:
        return "rm: missing operand\nTry 'rm --help' for more information."
    overlay = session.overlay
    recursive = "-r" in (cmd.flags or []) or "-rf" in (cmd.flags or []) or "-fr" in (cmd.flags or [])
    for arg in cmd.args:
        path = _resolve(fakefs, session, arg)
        if not overlay.exists(path, fakefs):
            return f"rm: cannot remove '{arg}': No such file or directory"
        if overlay.is_directory(path, fakefs) and not recursive:
            return f"rm: cannot remove '{arg}': Is a directory"
        overlay.rm(path, recursive=recursive)
    return ""


def handle_cp(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``cp`` — copies file into session overlay."""
    if len(cmd.args) < 2:
        return "cp: missing file operand\nTry 'cp --help' for more information."
    overlay = session.overlay
    src = _resolve(fakefs, session, cmd.args[0])
    dst = _resolve(fakefs, session, cmd.args[-1])
    if not overlay.exists(src, fakefs):
        return f"cp: cannot stat '{cmd.args[0]}': No such file or directory"
    overlay.cp(src, dst, fakefs)
    return ""


def handle_mv(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``mv`` — moves file/directory in session overlay."""
    if len(cmd.args) < 2:
        return "mv: missing file operand\nTry 'mv --help' for more information."
    overlay = session.overlay
    src = _resolve(fakefs, session, cmd.args[0])
    dst = _resolve(fakefs, session, cmd.args[-1])
    if not overlay.exists(src, fakefs):
        return f"mv: cannot stat '{cmd.args[0]}': No such file or directory"
    overlay.mv(src, dst, fakefs)
    return ""


def handle_head(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``head`` — show first N lines, overlay-aware."""
    if not cmd.args:
        return ""

    n = 10
    for flag in (cmd.flags or []):
        if flag.startswith("-") and flag[1:].isdigit():
            n = int(flag[1:])

    filepath = cmd.args[-1]
    path = _resolve(fakefs, session, filepath)
    content = session.overlay.get_content(path, fakefs)
    if content is None:
        return f"head: cannot open '{filepath}' for reading: No such file or directory"

    lines = content.splitlines()
    return "\n".join(lines[:n])


def handle_tail(fakefs: FakeFS, session: SessionProtocol, cmd: ParsedCommand) -> str:
    """Simulate ``tail`` — show last N lines, overlay-aware."""
    if not cmd.args:
        return ""

    n = 10
    for flag in (cmd.flags or []):
        if flag.startswith("-") and flag[1:].isdigit():
            n = int(flag[1:])

    filepath = cmd.args[-1]
    path = _resolve(fakefs, session, filepath)
    content = session.overlay.get_content(path, fakefs)
    if content is None:
        return f"tail: cannot open '{filepath}' for reading: No such file or directory"

    lines = content.splitlines()
    return "\n".join(lines[-n:])
