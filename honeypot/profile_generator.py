"""Profile-based persona generator (Step 3).

Takes a profile dict (from setup_profile.py) and produces:
  - personas/profile.json — a full Persona that passes pydantic + validator
  - personas/profile_escalation.json — two escalation stages for persona_switcher

All identity strings (hostname, username, home, PS1, /etc/passwd, /etc/hostname,
/etc/hosts, SSH key comments, log references) are derived from the profile.

Home directory contents are themed by role + interests.
Timestamps are deterministic from the profile seed.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from honeypot.fakefs import Persona
from honeypot.persona_validator import validate as _validate_persona


def generate_profile_persona(
    profile: dict,
    persona_path: Path,
    escalation_path: Path,
) -> None:
    """Generate persona JSON and escalation JSON from a profile dict."""
    rng = random.Random(profile["seed"])
    now = datetime.now(tz=timezone.utc)

    persona_data = _build_persona(profile, rng, now)

    # Validate before writing
    Persona.model_validate(persona_data)
    errors = _validate_persona(persona_data, now)
    if errors:
        raise ValueError(
            "Generated persona failed validation:\n" +
            "\n".join(f"  - {e}" for e in errors)
        )

    with open(persona_path, "w", encoding="utf-8") as fh:
        json.dump(persona_data, fh, indent=2, ensure_ascii=False)

    escalation_data = _build_escalation(profile, rng, now)
    with open(escalation_path, "w", encoding="utf-8") as fh:
        json.dump(escalation_data, fh, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def _past_ts(rng: random.Random, now: datetime, min_days: int = 60, max_days: int = 300) -> str:
    delta = timedelta(days=rng.randint(min_days, max_days))
    dt = now - delta
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _recent_ts(rng: random.Random, now: datetime, min_days: int = 1, max_days: int = 30) -> str:
    delta = timedelta(days=rng.randint(min_days, max_days))
    dt = now - delta
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _boot_ts(rng: random.Random, now: datetime) -> str:
    delta = timedelta(hours=rng.randint(2, 72))
    return (now - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Persona builder
# ---------------------------------------------------------------------------

def _build_persona(profile: dict, rng: random.Random, now: datetime) -> dict:
    username = profile["username"]
    hostname = profile["hostname"]
    full_name = profile["full_name"]
    uid = profile.get("uid", 1000)
    role = profile["role"]
    org = profile.get("org", "")
    interests = profile.get("interests", [])

    home = f"/home/{username}"
    install_ts = _past_ts(rng, now, 90, 300)

    system = {
        "hostname": hostname,
        "os": "Ubuntu 22.04.4 LTS",
        "kernel": "5.15.0-91-generic",
        "arch": "x86_64",
        "uptime_seconds": rng.randint(7200, 259200),
        "boot_time": _boot_ts(rng, now),
        "timezone": "UTC",
        "locale": "en_US.UTF-8",
    }

    network = _build_network(rng)
    users = _build_users(username, full_name, uid, home)
    processes = _build_processes(username, role, rng)
    filesystem = _build_filesystem(
        username, full_name, hostname, home, uid, role, org, interests,
        rng, now, install_ts,
    )
    disk = {
        "total_gb": 256,
        "used_gb": rng.randint(40, 120),
        "available_gb": 0,
        "use_percent": 0,
        "filesystem": "/dev/sda1",
        "mount": "/",
    }
    disk["available_gb"] = disk["total_gb"] - disk["used_gb"]
    disk["use_percent"] = int(disk["used_gb"] / disk["total_gb"] * 100)

    memory = {
        "total_mb": 8192,
        "used_mb": rng.randint(2000, 5000),
        "free_mb": 0,
        "shared_mb": rng.randint(100, 400),
        "buff_cache_mb": rng.randint(800, 2000),
        "available_mb": 0,
    }
    memory["free_mb"] = memory["total_mb"] - memory["used_mb"] - memory["buff_cache_mb"]
    memory["available_mb"] = memory["free_mb"] + memory["buff_cache_mb"]

    environment_defaults = {
        username: {
            "HOME": home,
            "USER": username,
            "LOGNAME": username,
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin",
            "PS1": f"{username}@{hostname}:~$ ",
            "LANG": "en_US.UTF-8",
            "TERM": "xterm-256color",
        },
        "root": {
            "HOME": "/root",
            "USER": "root",
            "LOGNAME": "root",
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PS1": f"root@{hostname}:~# ",
            "LANG": "en_US.UTF-8",
            "TERM": "xterm-256color",
        },
    }

    return {
        "persona_id": "profile",
        "display_name": f"Profile: {full_name}",
        "threat_trigger_level": "low",
        "schema_version": 1,
        "system": system,
        "network": network,
        "users": users,
        "processes": processes,
        "filesystem": filesystem,
        "disk": disk,
        "memory": memory,
        "environment_defaults": environment_defaults,
    }


# ---------------------------------------------------------------------------
# Sub-builders
# ---------------------------------------------------------------------------

def _build_network(rng: random.Random) -> dict:
    local_ip = f"192.168.1.{rng.randint(100, 250)}"
    return {
        "interfaces": [
            {
                "name": "lo",
                "ip": "127.0.0.1",
                "mac": "00:00:00:00:00:00",
                "netmask": "255.0.0.0",
                "broadcast": None,
                "state": "UP",
                "rx_bytes": rng.randint(50000, 500000),
                "tx_bytes": rng.randint(50000, 500000),
            },
            {
                "name": "enp0s3",
                "ip": local_ip,
                "mac": ":".join(f"{rng.randint(0,255):02x}" for _ in range(6)),
                "netmask": "255.255.255.0",
                "broadcast": "192.168.1.255",
                "state": "UP",
                "rx_bytes": rng.randint(1000000, 90000000),
                "tx_bytes": rng.randint(500000, 50000000),
            },
        ],
        "open_ports": [22],
        "active_connections": [
            {
                "proto": "tcp",
                "local_addr": f"{local_ip}:22",
                "foreign_addr": "0.0.0.0:*",
                "state": "LISTEN",
                "pid": 842,
                "program": "sshd",
            },
        ],
    }


def _build_users(username: str, full_name: str, uid: int, home: str) -> list[dict]:
    return [
        {
            "username": "root",
            "uid": 0,
            "gid": 0,
            "home": "/root",
            "shell": "/bin/bash",
            "groups": ["root"],
            "password_hash": "!",
            "last_login": None,
            "last_login_from": None,
        },
        {
            "username": "daemon",
            "uid": 1,
            "gid": 1,
            "home": "/usr/sbin",
            "shell": "/usr/sbin/nologin",
            "groups": ["daemon"],
            "password_hash": "*",
        },
        {
            "username": "www-data",
            "uid": 33,
            "gid": 33,
            "home": "/var/www",
            "shell": "/usr/sbin/nologin",
            "groups": ["www-data"],
            "password_hash": "*",
        },
        {
            "username": "sshd",
            "uid": 110,
            "gid": 65534,
            "home": "/run/sshd",
            "shell": "/usr/sbin/nologin",
            "groups": ["nogroup"],
            "password_hash": "*",
        },
        {
            "username": "nobody",
            "uid": 65534,
            "gid": 65534,
            "home": "/nonexistent",
            "shell": "/usr/sbin/nologin",
            "groups": ["nogroup"],
            "password_hash": "*",
        },
        {
            "username": username,
            "uid": uid,
            "gid": uid,
            "home": home,
            "shell": "/bin/bash",
            "groups": [username, "sudo", "adm"],
            "password_hash": "$6$fakeprofilehash$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "last_login": None,
            "last_login_from": None,
        },
    ]


def _build_processes(username: str, role: str, rng: random.Random) -> list[dict]:
    base_pid = rng.randint(800, 1200)
    procs = [
        {"pid": 1, "ppid": 0, "user": "root", "cpu_percent": 0.0, "mem_percent": 0.4,
         "vsz": 169384, "rss": 11200, "tty": "?", "stat": "Ss", "start": "Apr10",
         "time": "0:12", "command": "/sbin/init"},
        {"pid": base_pid, "ppid": 1, "user": "root", "cpu_percent": 0.0, "mem_percent": 0.1,
         "vsz": 15424, "rss": 5600, "tty": "?", "stat": "Ss", "start": "Apr10",
         "time": "0:00", "command": "/usr/sbin/sshd -D"},
        {"pid": base_pid + 2, "ppid": 1, "user": "root", "cpu_percent": 0.0, "mem_percent": 0.1,
         "vsz": 8536, "rss": 3200, "tty": "?", "stat": "Ss", "start": "Apr10",
         "time": "0:03", "command": "/usr/sbin/cron -f"},
        {"pid": base_pid + 5, "ppid": 1, "user": "root", "cpu_percent": 0.0, "mem_percent": 0.2,
         "vsz": 109676, "rss": 4800, "tty": "?", "stat": "Ssl", "start": "Apr10",
         "time": "0:08", "command": "/usr/lib/systemd/systemd-journald"},
        {"pid": base_pid + 20, "ppid": 1, "user": username, "cpu_percent": 0.0, "mem_percent": 0.3,
         "vsz": 21372, "rss": 6400, "tty": "pts/0", "stat": "Ss", "start": "10:22",
         "time": "0:00", "command": "-bash"},
    ]

    if role == "student":
        procs.extend([
            {"pid": base_pid + 30, "ppid": 1, "user": username, "cpu_percent": 0.3, "mem_percent": 2.1,
             "vsz": 580000, "rss": 85000, "tty": "?", "stat": "Sl", "start": "10:25",
             "time": "0:14", "command": "/usr/bin/code --unity-launch"},
            {"pid": base_pid + 35, "ppid": 1, "user": username, "cpu_percent": 1.2, "mem_percent": 4.5,
             "vsz": 1200000, "rss": 180000, "tty": "?", "stat": "Sl", "start": "10:30",
             "time": "1:22", "command": "/usr/lib/firefox/firefox"},
        ])
    elif role == "developer":
        procs.extend([
            {"pid": base_pid + 30, "ppid": 1, "user": username, "cpu_percent": 0.3, "mem_percent": 2.1,
             "vsz": 580000, "rss": 85000, "tty": "?", "stat": "Sl", "start": "10:25",
             "time": "0:14", "command": "/usr/bin/code --unity-launch"},
            {"pid": base_pid + 40, "ppid": 1, "user": "root", "cpu_percent": 0.1, "mem_percent": 1.2,
             "vsz": 920000, "rss": 48000, "tty": "?", "stat": "Ssl", "start": "Apr10",
             "time": "0:45", "command": "/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock"},
            {"pid": base_pid + 50, "ppid": base_pid + 40, "user": username, "cpu_percent": 0.5, "mem_percent": 1.8,
             "vsz": 710000, "rss": 72000, "tty": "?", "stat": "Ssl", "start": "10:30",
             "time": "0:12", "command": "node server.js"},
        ])
    else:
        procs.append(
            {"pid": base_pid + 30, "ppid": 1, "user": username, "cpu_percent": 1.0, "mem_percent": 3.8,
             "vsz": 1100000, "rss": 160000, "tty": "?", "stat": "Sl", "start": "10:30",
             "time": "1:05", "command": "/usr/lib/firefox/firefox"},
        )

    return procs


def _build_filesystem(
    username: str, full_name: str, hostname: str, home: str,
    uid: int, role: str, org: str, interests: list[str],
    rng: random.Random, now: datetime, install_ts: str,
) -> dict[str, Any]:
    fs: dict[str, Any] = {}

    def _dir(path: str, children: list[str], owner: str = "root", group: str = "root",
             perms: str = "0755", created: str | None = None, modified: str | None = None) -> None:
        fs[path] = {
            "type": "directory", "owner": owner, "group": group,
            "permissions": perms,
            "created": created or install_ts,
            "modified": modified or _recent_ts(rng, now, 1, 60),
            "children": children,
        }

    def _file(path: str, content: str, owner: str = "root", group: str = "root",
              perms: str = "0644", created: str | None = None, modified: str | None = None) -> None:
        c = created or install_ts
        m = modified or _recent_ts(rng, now, 1, 60)
        # Ensure created <= modified
        if c > m:
            m = c
        fs[path] = {
            "type": "file", "owner": owner, "group": group,
            "permissions": perms,
            "created": c, "modified": m,
            "size_bytes": len(content.encode("utf-8")),
            "content": content,
        }

    # --- Root directories ---
    _dir("/", ["bin", "boot", "dev", "etc", "home", "lib", "media", "mnt",
               "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp",
               "usr", "var"])
    _dir("/etc", ["hostname", "hosts", "passwd", "group", "shadow", "sudoers",
                  "os-release", "resolv.conf", "crontab", "fstab"])
    _dir("/home", [username])
    _dir("/tmp", [], perms="1777")
    _dir("/var", ["log", "www", "lib"])
    _dir("/var/log", ["auth.log", "syslog"])
    _dir("/root", [".bashrc"], owner="root", group="root", perms="0700")

    # --- /etc files ---
    _file("/etc/hostname", f"{hostname}\n")
    _file(
        "/etc/hosts",
        f"127.0.0.1\tlocalhost\n127.0.1.1\t{hostname}\n\n"
        "::1\tlocalhost ip6-localhost ip6-loopback\n"
        "ff02::1\tip6-allnodes\nff02::2\tip6-allrouters\n",
    )

    passwd_lines = [
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
        "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin",
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
        f"{username}:x:{uid}:{uid}:{full_name}:{home}:/bin/bash",
    ]
    _file("/etc/passwd", "\n".join(passwd_lines) + "\n")

    group_lines = [
        "root:x:0:", "daemon:x:1:", "adm:x:4:",
        "sudo:x:27:", "www-data:x:33:",
        f"{username}:x:{uid}:",
    ]
    _file("/etc/group", "\n".join(group_lines) + "\n")

    shadow_lines = [
        "root:!:20070:0:99999:7:::",
        "daemon:*:20070:0:99999:7:::",
        "bin:*:20070:0:99999:7:::",
        "sys:*:20070:0:99999:7:::",
        "www-data:*:20070:0:99999:7:::",
        "sshd:*:20070:0:99999:7:::",
        "nobody:*:20070:0:99999:7:::",
        f"{username}:$6$fakeprofilehash$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:20070:0:99999:7:::",
    ]
    _file("/etc/shadow", "\n".join(shadow_lines) + "\n", perms="0640", owner="root", group="shadow")

    _file(
        "/etc/sudoers",
        "root\tALL=(ALL:ALL) ALL\n"
        f"%sudo\tALL=(ALL:ALL) ALL\n"
        f"{username}\tALL=(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/snap\n",
        perms="0440",
    )

    _file(
        "/etc/os-release",
        'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
        'NAME="Ubuntu"\nVERSION_ID="22.04"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
        'ID=ubuntu\nID_LIKE=debian\n'
        'HOME_URL="https://www.ubuntu.com/"\n'
        'SUPPORT_URL="https://help.ubuntu.com/"\n'
        'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n',
    )

    _file("/etc/resolv.conf", "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch localdomain\n")
    _file("/etc/crontab", "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
          "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
          "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n")
    _file(
        "/etc/fstab",
        "# /etc/fstab: static file system information.\n"
        "UUID=a1b2c3d4-e5f6-7890-abcd-ef1234567890 / ext4 errors=remount-ro 0 1\n",
    )

    # --- Logs ---
    log_ts = (now - timedelta(hours=rng.randint(1, 24))).strftime("%b %d %H:%M:%S")
    _file(
        "/var/log/auth.log",
        f"{log_ts} {hostname} sshd[{rng.randint(1000,9999)}]: "
        f"Accepted publickey for {username} from 192.168.1.{rng.randint(2,99)} port {rng.randint(40000,60000)} ssh2: RSA SHA256:aB3cD4eF5\n"
        f"{log_ts} {hostname} sshd[{rng.randint(1000,9999)}]: "
        f"pam_unix(sshd:session): session opened for user {username} by (uid=0)\n",
        modified=_recent_ts(rng, now, 0, 1),
    )
    _file(
        "/var/log/syslog",
        f"{log_ts} {hostname} systemd[1]: Started Daily apt download activities.\n"
        f"{log_ts} {hostname} systemd[1]: apt-daily.service: Succeeded.\n"
        f"{log_ts} {hostname} CRON[{rng.randint(10000,30000)}]: "
        f"(root) CMD (cd / && run-parts --report /etc/cron.hourly)\n",
        modified=_recent_ts(rng, now, 0, 1),
    )

    # --- /root ---
    _file("/root/.bashrc", "# ~/.bashrc: executed by bash(1) for non-login shells.\nexport PS1='root@\\h:\\w# '\n",
          owner="root", group="root")

    # --- User home ---
    home_children = [".bashrc", ".bash_history", ".profile", "Downloads"]
    if role == "student":
        home_children.extend(["Documents", "semester-6"])
        if interests:
            home_children.append("projects")
    elif role == "developer":
        home_children.extend(["projects", ".gitconfig", "notes.md"])
    else:
        home_children.extend(["Documents", "Downloads"])

    _dir(home, home_children, owner=username, group=username)
    _file(f"{home}/.bashrc",
          "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
          f"export PS1='{username}@\\h:\\w$ '\nalias ll='ls -alF'\nalias la='ls -A'\n",
          owner=username, group=username)
    _file(f"{home}/.profile",
          "# ~/.profile: executed by the command interpreter for login shells.\n"
          'if [ -d "$HOME/bin" ] ; then\n    PATH="$HOME/bin:$PATH"\nfi\n',
          owner=username, group=username)

    _build_bash_history(fs, home, username, role, interests, org, rng, now, install_ts)
    _dir(f"{home}/Downloads", [], owner=username, group=username)

    if role == "student":
        _build_student_home(fs, home, username, interests, org, rng, now, install_ts)
    elif role == "developer":
        _build_developer_home(fs, home, username, interests, org, rng, now, install_ts)
    else:
        _build_generic_home(fs, home, username, rng, now, install_ts)

    return fs


def _build_bash_history(
    fs: dict, home: str, username: str, role: str,
    interests: list[str], org: str,
    rng: random.Random, now: datetime, install_ts: str,
) -> None:
    lines: list[str] = []
    if role == "student":
        lines = [
            "sudo apt update", "sudo apt upgrade -y",
            "cd semester-6", "ls",
            "python3 assignment1.py", "gcc -o lab3 lab3.c",
            "git clone https://github.com/example/data-structures.git",
            "cd projects", "python3 -m venv venv",
            "pip install numpy pandas matplotlib",
            "jupyter notebook", "cat README.md",
        ]
        if interests:
            lines.append(f"cd ~/projects/{_slug(interests[0])}")
        if org:
            lines.append(f"ssh student@lab.{_slug(org)}.edu")
    elif role == "developer":
        lines = [
            "sudo apt update",
            "git status", "git pull origin main",
            "docker compose up -d", "docker ps",
            "npm install", "npm run dev",
            "code .", "cat .env",
            "ssh-keygen -t ed25519 -C 'dev-key'",
            "kubectl get pods", "curl localhost:3000/api/health",
        ]
        if interests:
            lines.append(f"cd ~/projects/{_slug(interests[0])}")
    else:
        lines = [
            "sudo apt update", "ls", "pwd",
            "cd Documents", "cat notes.txt",
            "firefox &", "df -h", "free -m",
        ]

    rng.shuffle(lines)
    content = "\n".join(lines[:15]) + "\n"
    fs[f"{home}/.bash_history"] = {
        "type": "file", "owner": username, "group": username,
        "permissions": "0600",
        "created": install_ts,
        "modified": _recent_ts(rng, now, 0, 3),
        "size_bytes": len(content.encode()),
        "content": content,
    }


def _build_student_home(
    fs: dict, home: str, username: str,
    interests: list[str], org: str,
    rng: random.Random, now: datetime, install_ts: str,
) -> None:
    _dir_in = lambda p, ch: fs.__setitem__(p, {
        "type": "directory", "owner": username, "group": username,
        "permissions": "0755", "created": install_ts,
        "modified": _recent_ts(rng, now, 1, 60), "children": ch,
    })
    _file_in = lambda p, c: fs.__setitem__(p, {
        "type": "file", "owner": username, "group": username,
        "permissions": "0644", "created": install_ts,
        "modified": _recent_ts(rng, now, 1, 60),
        "size_bytes": len(c.encode()), "content": c,
    })

    _dir_in(f"{home}/Documents", ["notes.txt"])
    _file_in(f"{home}/Documents/notes.txt", f"# Notes\n- {org or 'University'} semester 6\n- Capstone project due soon\n")

    _dir_in(f"{home}/semester-6", ["assignment1.py", "lab3.c", "README.md"])
    _file_in(f"{home}/semester-6/assignment1.py",
             '#!/usr/bin/env python3\n"""Assignment 1 — sorting algorithms."""\n\ndef merge_sort(arr):\n    if len(arr) <= 1:\n        return arr\n    mid = len(arr) // 2\n    return merge(merge_sort(arr[:mid]), merge_sort(arr[mid:]))\n')
    _file_in(f"{home}/semester-6/lab3.c",
             '#include <stdio.h>\n\nint main() {\n    printf("Lab 3 output\\n");\n    return 0;\n}\n')
    _file_in(f"{home}/semester-6/README.md", f"# Semester 6\n\n{org or 'University'} coursework\n")

    if interests:
        project_names = [_slug(i) for i in interests[:2]]
        _dir_in(f"{home}/projects", project_names)
        for pname in project_names:
            _dir_in(f"{home}/projects/{pname}", ["README.md", "main.py"])
            _file_in(f"{home}/projects/{pname}/README.md", f"# {pname}\n\nProject for {pname} exploration.\n")
            _file_in(f"{home}/projects/{pname}/main.py", f'"""Main module for {pname}."""\n\nprint("Hello from {pname}")\n')


def _build_developer_home(
    fs: dict, home: str, username: str,
    interests: list[str], org: str,
    rng: random.Random, now: datetime, install_ts: str,
) -> None:
    _dir_in = lambda p, ch: fs.__setitem__(p, {
        "type": "directory", "owner": username, "group": username,
        "permissions": "0755", "created": install_ts,
        "modified": _recent_ts(rng, now, 1, 60), "children": ch,
    })
    _file_in = lambda p, c, perms="0644": fs.__setitem__(p, {
        "type": "file", "owner": username, "group": username,
        "permissions": perms, "created": install_ts,
        "modified": _recent_ts(rng, now, 1, 60),
        "size_bytes": len(c.encode()), "content": c,
    })

    gitconfig_content = f"[user]\n\tname = {username}\n\temail = {username}@{_slug(org) + '.com' if org else 'example.com'}\n"
    _file_in(f"{home}/.gitconfig", gitconfig_content)

    _file_in(f"{home}/notes.md", f"# Dev Notes\n\n- TODO: finish API endpoints\n- Review PR #42\n")

    project_names = [_slug(i) for i in interests[:2]] if interests else ["webapp"]
    _dir_in(f"{home}/projects", project_names)

    for pname in project_names:
        _dir_in(f"{home}/projects/{pname}", ["README.md", "package.json", "Dockerfile", "src"])
        _file_in(f"{home}/projects/{pname}/README.md", f"# {pname}\n\nA project by {username}.\n")
        _file_in(
            f"{home}/projects/{pname}/package.json",
            f'{{"name": "{pname}", "version": "1.0.0", "scripts": {{"dev": "node server.js", "build": "tsc"}}}}\n',
        )
        _file_in(
            f"{home}/projects/{pname}/Dockerfile",
            f"FROM node:20-slim\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci\nCOPY . .\nCMD [\"node\", \"server.js\"]\n",
        )
        _dir_in(f"{home}/projects/{pname}/src", ["index.js"])
        _file_in(f"{home}/projects/{pname}/src/index.js",
                 'const express = require("express");\nconst app = express();\n\napp.get("/", (req, res) => res.send("OK"));\n\napp.listen(3000);\n')


def _build_generic_home(
    fs: dict, home: str, username: str,
    rng: random.Random, now: datetime, install_ts: str,
) -> None:
    _dir_in = lambda p, ch: fs.__setitem__(p, {
        "type": "directory", "owner": username, "group": username,
        "permissions": "0755", "created": install_ts,
        "modified": _recent_ts(rng, now, 1, 60), "children": ch,
    })
    _file_in = lambda p, c: fs.__setitem__(p, {
        "type": "file", "owner": username, "group": username,
        "permissions": "0644", "created": install_ts,
        "modified": _recent_ts(rng, now, 1, 60),
        "size_bytes": len(c.encode()), "content": c,
    })

    _dir_in(f"{home}/Documents", ["notes.txt", "todo.txt"])
    _file_in(f"{home}/Documents/notes.txt", "# Personal notes\n- Remember to update packages\n- Check backups\n")
    _file_in(f"{home}/Documents/todo.txt", "1. Clean up downloads\n2. Update system\n3. Organize photos\n")


def _slug(text: str) -> str:
    """Turn a free-text string into a filesystem-safe slug."""
    import re
    s = text.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")[:30] or "misc"


def _dir_in(fs, path, children, username, install_ts, rng, now):
    """Helper used inside build functions via lambda."""
    pass


# ---------------------------------------------------------------------------
# Escalation builder
# ---------------------------------------------------------------------------

def _build_escalation(profile: dict, rng: random.Random, now: datetime) -> dict:
    username = profile["username"]
    home = f"/home/{username}"
    role = profile["role"]
    role_desc = profile.get("role_description", "")
    org = profile.get("org", "")
    interests = profile.get("interests", [])

    effective_role = role
    if role == "other":
        desc_lower = role_desc.lower()
        if any(w in desc_lower for w in ("student", "university", "college", "academic")):
            effective_role = "student"
        elif any(w in desc_lower for w in ("developer", "engineer", "programmer", "devops")):
            effective_role = "developer"
        else:
            effective_role = "generic"

    if effective_role == "student":
        stages = _student_escalation(username, home, org, interests, rng)
    elif effective_role == "developer":
        stages = _developer_escalation(username, home, org, interests, rng)
    else:
        stages = _generic_escalation(username, home, rng)

    return {
        "profile_role": effective_role,
        "username": username,
        "home": home,
        "stages": stages,
    }


def _student_escalation(username: str, home: str, org: str, interests: list[str],
                         rng: random.Random) -> list[dict]:
    project = _slug(interests[0]) if interests else "capstone"
    college_host = f"lab.{_slug(org)}.edu" if org else "lab.university.edu"

    return [
        {
            "stage": 1,
            "events": [
                {"change_type": "add_directory", "path": f"{home}/projects/{project}/.git",
                 "description": "Git directory appears", "phase": "seeding"},
                {"change_type": "add_file", "path": f"{home}/projects/{project}/.env",
                 "description": "Project .env with API keys",
                 "content": f"# {project} config\nAPI_KEY=sk-proj-{''.join(rng.choices('abcdef0123456789', k=32))}\n"
                            f"DATABASE_URL=sqlite:///db.sqlite3\nSECRET_KEY={''.join(rng.choices('ABCDEFGHIJKLMNOP', k=24))}\n",
                 "phase": "seeding"},
                {"change_type": "add_file", "path": f"{home}/.git-credentials",
                 "description": "Stored git credentials",
                 "content": f"https://{username}:ghp_{''.join(rng.choices('abcdefABCDEF0123456789', k=36))}@github.com\n",
                 "phase": "building"},
                {"change_type": "add_file", "path": f"{home}/projects/{project}/config.py",
                 "description": "Config file with hardcoded secrets",
                 "content": f'DB_PASSWORD = "student{rng.randint(100,999)}!"\nSMTP_PASS = "mailpass{rng.randint(100,999)}"\n',
                 "phase": "completing"},
            ],
        },
        {
            "stage": 2,
            "events": [
                {"change_type": "add_directory", "path": f"{home}/.ssh",
                 "description": "SSH directory appears", "phase": "seeding"},
                {"change_type": "add_file", "path": f"{home}/.ssh/id_rsa",
                 "description": "Private SSH key",
                 "content": f"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUA{username}-key-fake-data-do-not-use\n-----END OPENSSH PRIVATE KEY-----\n",
                 "phase": "seeding"},
                {"change_type": "add_file", "path": f"{home}/.ssh/config",
                 "description": "SSH config pointing to college lab",
                 "content": f"Host lab\n  HostName {college_host}\n  User {username}\n  IdentityFile ~/.ssh/id_rsa\n\n"
                            f"Host personal\n  HostName vps.example.com\n  User {username}\n",
                 "phase": "building"},
                {"change_type": "add_file", "path": f"{home}/.ssh/authorized_keys",
                 "description": "Authorized keys file",
                 "content": f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyDataHere {username}@{college_host}\n",
                 "phase": "building"},
                {"change_type": "add_file", "path": f"{home}/Documents/portal-creds.txt",
                 "description": "Saved portal credentials",
                 "content": f"# Student Portal Login\nURL: https://portal.{_slug(org) + '.edu' if org else 'university.edu'}\n"
                            f"Username: {username}\nPassword: {username}{rng.randint(2020,2026)}!\n",
                 "phase": "completing"},
            ],
        },
    ]


def _developer_escalation(username: str, home: str, org: str, interests: list[str],
                            rng: random.Random) -> list[dict]:
    project = _slug(interests[0]) if interests else "webapp"

    return [
        {
            "stage": 1,
            "events": [
                {"change_type": "add_file", "path": f"{home}/projects/{project}/.env",
                 "description": "Project .env with database credentials",
                 "content": f"DATABASE_URL=postgres://appuser:Pr0d-P@ss-{rng.randint(1000,9999)}@db.internal:5432/appdb\n"
                            f"REDIS_URL=redis://:redis-{rng.randint(100,999)}@cache.internal:6379/0\n"
                            f"JWT_SECRET={''.join(rng.choices('abcdefghijklmnopABCDEF0123456789', k=32))}\n",
                 "phase": "seeding"},
                {"change_type": "add_file", "path": f"{home}/projects/{project}/docker-compose.yml",
                 "description": "Docker compose with DB credentials",
                 "content": f"version: '3.8'\nservices:\n  app:\n    build: .\n    ports:\n      - '3000:3000'\n"
                            f"  db:\n    image: postgres:15\n    environment:\n"
                            f"      POSTGRES_PASSWORD: Pr0d-P@ss-{rng.randint(1000,9999)}\n",
                 "phase": "building"},
                {"change_type": "add_file", "path": f"{home}/.npmrc",
                 "description": "NPM config with auth token",
                 "content": f"//registry.npmjs.org/:_authToken=npm_{''.join(rng.choices('abcdefABCDEF0123456789', k=36))}\n",
                 "phase": "completing"},
            ],
        },
        {
            "stage": 2,
            "events": [
                {"change_type": "add_directory", "path": f"{home}/.aws",
                 "description": "AWS credentials directory", "phase": "seeding"},
                {"change_type": "add_file", "path": f"{home}/.aws/credentials",
                 "description": "AWS credentials",
                 "content": f"[default]\naws_access_key_id = AKIA{''.join(rng.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}\n"
                            f"aws_secret_access_key = {''.join(rng.choices('abcdefghijklmnopABCDEFGHIJKLMNOP+/0123456789', k=40))}\n",
                 "phase": "seeding"},
                {"change_type": "add_directory", "path": f"{home}/.ssh",
                 "description": "SSH directory appears", "phase": "building"},
                {"change_type": "add_file", "path": f"{home}/.ssh/id_ed25519",
                 "description": "Private SSH key",
                 "content": f"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUA{username}-ed25519-fake-do-not-use\n-----END OPENSSH PRIVATE KEY-----\n",
                 "phase": "building"},
                {"change_type": "add_file", "path": f"{home}/.ssh/config",
                 "description": "SSH config to staging and prod",
                 "content": f"Host staging\n  HostName staging.{_slug(org) + '.io' if org else 'example.io'}\n  User deploy\n  IdentityFile ~/.ssh/id_ed25519\n\n"
                            f"Host prod\n  HostName prod.{_slug(org) + '.io' if org else 'example.io'}\n  User deploy\n  IdentityFile ~/.ssh/id_ed25519\n  ProxyJump bastion\n",
                 "phase": "completing"},
                {"change_type": "add_file", "path": f"{home}/.kube/config",
                 "description": "Kubernetes config",
                 "content": f"apiVersion: v1\nclusters:\n- cluster:\n    server: https://k8s.internal:6443\n"
                            f"    certificate-authority-data: LS0tLS1CRUd...\n  name: prod\n"
                            f"users:\n- name: {username}\n  user:\n    token: eyJhbGciOi...\n",
                 "phase": "completing"},
            ],
        },
    ]


def _generic_escalation(username: str, home: str, rng: random.Random) -> list[dict]:
    return [
        {
            "stage": 1,
            "events": [
                {"change_type": "add_file", "path": f"{home}/Documents/passwords.txt",
                 "description": "Exported password file",
                 "content": f"# Password export — {username}\n"
                            f"Gmail: {username}@gmail.com / {''.join(rng.choices('abcdefABCDEF0123!@#', k=12))}\n"
                            f"Banking: user{rng.randint(100,999)} / {''.join(rng.choices('abcdefABCDEF0123!@#', k=14))}\n"
                            f"VPN: {username} / vpn-{''.join(rng.choices('0123456789', k=6))}\n",
                 "phase": "seeding"},
                {"change_type": "add_file", "path": f"{home}/Documents/tax-2025.pdf.txt",
                 "description": "Tax document notes",
                 "content": f"Tax filing notes — {username}\nRefund: $3,{rng.randint(100,999)}\nSSN last four: {rng.randint(1000,9999)}\n",
                 "phase": "completing"},
            ],
        },
        {
            "stage": 2,
            "events": [
                {"change_type": "add_directory", "path": f"{home}/.ssh",
                 "description": "SSH directory appears", "phase": "seeding"},
                {"change_type": "add_file", "path": f"{home}/.ssh/id_rsa",
                 "description": "Private SSH key",
                 "content": f"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUA{username}-rsa-fake-do-not-use\n-----END OPENSSH PRIVATE KEY-----\n",
                 "phase": "building"},
                {"change_type": "add_file", "path": f"{home}/.ssh/config",
                 "description": "SSH config file",
                 "content": f"Host myserver\n  HostName vps.example.com\n  User {username}\n  IdentityFile ~/.ssh/id_rsa\n",
                 "phase": "completing"},
            ],
        },
    ]
