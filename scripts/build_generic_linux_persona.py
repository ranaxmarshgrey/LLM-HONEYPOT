"""Build personas/generic_linux.json deterministically.

Writing the persona by hand is fragile: size_bytes must equal
``len(content.encode('utf-8'))``, parent directories must exist for every
path, timestamps must be ordered, etc. This script constructs the data
structure in Python, computes sizes from content, and runs every
Sprint 2 consistency rule (CLAUDE.md §9 / Sprint 2 guide rules 1–8)
before writing the file. Rerun whenever the persona needs changes.

Usage:  python scripts/build_generic_linux_persona.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Time anchors — chosen so every modified timestamp is in the past relative
# to CLAUDE.md's "today" (2026-04-16) and >= its creation timestamp.
# ---------------------------------------------------------------------------
INSTALL = "2025-06-15T08:00:00Z"      # server was provisioned
LAST_UPDATE = "2026-02-10T11:24:33Z"  # last apt upgrade
LAST_BOOT = "2026-03-25T21:12:47Z"    # ~21 days uptime before 2026-04-16
RECENT_LOG = "2026-04-15T23:59:01Z"
RECENT_USER = "2026-04-14T17:43:09Z"

UPTIME_SECONDS = 1_847_293  # ~21.38 days

# ---------------------------------------------------------------------------
# File contents — sizes are computed from these, never hand-written.
# ---------------------------------------------------------------------------
HOSTNAME_TXT = "web-srv-03\n"

HOSTS_TXT = (
    "127.0.0.1\tlocalhost\n"
    "127.0.1.1\tweb-srv-03\n"
    "\n"
    "::1\tlocalhost ip6-localhost ip6-loopback\n"
    "ff02::1\tip6-allnodes\n"
    "ff02::2\tip6-allrouters\n"
)

OS_RELEASE_TXT = (
    'NAME="Ubuntu"\n'
    'VERSION="20.04.6 LTS (Focal Fossa)"\n'
    "ID=ubuntu\n"
    "ID_LIKE=debian\n"
    'PRETTY_NAME="Ubuntu 20.04.6 LTS"\n'
    'VERSION_ID="20.04"\n'
    'HOME_URL="https://www.ubuntu.com/"\n'
    'SUPPORT_URL="https://help.ubuntu.com/"\n'
    'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
    'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
    "VERSION_CODENAME=focal\n"
    "UBUNTU_CODENAME=focal\n"
)

# Every username here also goes into SHADOW_TXT (Rule 8).
PASSWD_TXT = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n"
    "messagebus:x:102:105::/nonexistent:/usr/sbin/nologin\n"
    "syslog:x:104:110::/home/syslog:/usr/sbin/nologin\n"
    "sshd:x:108:65534::/run/sshd:/usr/sbin/nologin\n"
    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
)

# Same usernames as PASSWD_TXT (Rule 8). Real-looking bcrypt stubs.
SHADOW_TXT = (
    "root:!:20070:0:99999:7:::\n"
    "daemon:*:20070:0:99999:7:::\n"
    "bin:*:20070:0:99999:7:::\n"
    "sys:*:20070:0:99999:7:::\n"
    "sync:*:20070:0:99999:7:::\n"
    "www-data:*:20070:0:99999:7:::\n"
    "nobody:*:20070:0:99999:7:::\n"
    "systemd-resolve:*:20070:0:99999:7:::\n"
    "messagebus:*:20070:0:99999:7:::\n"
    "syslog:*:20070:0:99999:7:::\n"
    "sshd:*:20070:0:99999:7:::\n"
    "ubuntu:$6$Qn7aBc9dE$3xK8vJ2mWqP5rL4nT6yU8iO0pA1sD2fG3hJ4kL5zX:20070:0:99999:7:::\n"
)

GROUP_TXT = (
    "root:x:0:\n"
    "daemon:x:1:\n"
    "bin:x:2:\n"
    "sys:x:3:\n"
    "adm:x:4:syslog,ubuntu\n"
    "tty:x:5:\n"
    "disk:x:6:\n"
    "www-data:x:33:\n"
    "sudo:x:27:ubuntu\n"
    "nogroup:x:65534:\n"
    "ubuntu:x:1000:\n"
)

BASH_HISTORY_UBUNTU = (
    "ls -la\n"
    "sudo apt update\n"
    "nginx -t\n"
    "sudo systemctl restart nginx\n"
    "tail -f /var/log/nginx/access.log\n"
    "df -h\n"
    "free -m\n"
    "whoami\n"
    "exit\n"
)

BASHRC_UBUNTU = (
    "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
    "case $- in\n"
    "    *i*) ;;\n"
    "      *) return;;\n"
    "esac\n"
    "\n"
    "HISTCONTROL=ignoreboth\n"
    "HISTSIZE=1000\n"
    "HISTFILESIZE=2000\n"
    "\n"
    "alias ll='ls -alF'\n"
    "alias la='ls -A'\n"
    "alias l='ls -CF'\n"
)

PROFILE_UBUNTU = (
    "# ~/.profile: executed by the command interpreter for login shells.\n"
    "if [ -n \"$BASH_VERSION\" ]; then\n"
    "    if [ -f \"$HOME/.bashrc\" ]; then\n"
    "        . \"$HOME/.bashrc\"\n"
    "    fi\n"
    "fi\n"
    "\n"
    'if [ -d "$HOME/bin" ] ; then\n'
    '    PATH="$HOME/bin:$PATH"\n'
    "fi\n"
)

BASH_HISTORY_ROOT = (
    "apt update && apt upgrade -y\n"
    "nginx -t\n"
    "systemctl restart nginx\n"
    "systemctl status nginx\n"
    "ufw status\n"
    "certbot renew\n"
    "tail -f /var/log/nginx/error.log\n"
    "crontab -l\n"
    "ls -la /var/www/html\n"
    "exit\n"
)

BASHRC_ROOT = (
    "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
    "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
    "alias ll='ls -alF'\n"
    "alias la='ls -A'\n"
    "alias l='ls -CF'\n"
)

AUTH_LOG = (
    "Apr 14 17:43:09 web-srv-03 sshd[2201]: Accepted publickey for ubuntu from 192.168.1.100 port 51204 ssh2: RSA SHA256:aB3cD4eF5\n"
    "Apr 14 17:43:09 web-srv-03 sshd[2201]: pam_unix(sshd:session): session opened for user ubuntu by (uid=0)\n"
    "Apr 14 23:59:01 web-srv-03 CRON[2341]: pam_unix(cron:session): session opened for user root by (uid=0)\n"
    "Apr 14 23:59:01 web-srv-03 CRON[2341]: pam_unix(cron:session): session closed for user root\n"
    "Apr 15 17:01:01 web-srv-03 CRON[3102]: pam_unix(cron:session): session opened for user root by (uid=0)\n"
    "Apr 15 17:01:01 web-srv-03 CRON[3102]: pam_unix(cron:session): session closed for user root\n"
)

SYSLOG = (
    "Apr 15 23:17:01 web-srv-03 CRON[28401]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)\n"
    "Apr 15 23:39:01 web-srv-03 systemd[1]: Starting Daily apt download activities...\n"
    "Apr 15 23:39:04 web-srv-03 systemd[1]: apt-daily.service: Succeeded.\n"
    "Apr 15 23:39:04 web-srv-03 systemd[1]: Finished Daily apt download activities.\n"
    "Apr 15 23:59:01 web-srv-03 systemd[1]: logrotate.service: Succeeded.\n"
)

NGINX_ACCESS = (
    "192.168.1.55 - - [15/Apr/2026:09:14:03 +0000] \"GET / HTTP/1.1\" 200 612 \"-\" \"Mozilla/5.0\"\n"
    "192.168.1.55 - - [15/Apr/2026:09:14:04 +0000] \"GET /favicon.ico HTTP/1.1\" 404 162 \"-\" \"Mozilla/5.0\"\n"
    "10.0.2.88 - - [15/Apr/2026:14:22:17 +0000] \"GET /health HTTP/1.1\" 200 2 \"-\" \"curl/7.68.0\"\n"
    "10.0.2.88 - - [15/Apr/2026:14:22:18 +0000] \"GET /health HTTP/1.1\" 200 2 \"-\" \"curl/7.68.0\"\n"
)

NGINX_ERROR = (
    "2026/04/10 03:14:22 [error] 1135#1135: *42 open() \"/var/www/html/robots.txt\" failed (2: No such file or directory), client: 45.77.19.12, server: _, request: \"GET /robots.txt HTTP/1.1\"\n"
    "2026/04/12 11:03:07 [error] 1135#1135: *88 open() \"/var/www/html/wp-login.php\" failed (2: No such file or directory), client: 188.40.2.7, server: _, request: \"GET /wp-login.php HTTP/1.1\"\n"
)

INDEX_HTML = (
    "<!DOCTYPE html>\n"
    "<html>\n"
    "<head><title>Welcome to nginx!</title></head>\n"
    "<body>\n"
    "<h1>Welcome to nginx!</h1>\n"
    "<p>If you see this page, the nginx web server is successfully installed and\n"
    "working. Further configuration is required.</p>\n"
    "</body>\n"
    "</html>\n"
)


# ---------------------------------------------------------------------------
# Builder helpers
# ---------------------------------------------------------------------------

def dir_entry(owner, group, perms, created, modified, children):
    return {
        "type": "directory",
        "owner": owner,
        "group": group,
        "permissions": perms,
        "created": created,
        "modified": modified,
        "children": sorted(children),
    }


def file_entry(owner, group, perms, created, modified, content):
    data = content.encode("utf-8")
    return {
        "type": "file",
        "owner": owner,
        "group": group,
        "permissions": perms,
        "created": created,
        "modified": modified,
        "size_bytes": len(data),
        "content": content,
    }


# ---------------------------------------------------------------------------
# Persona
# ---------------------------------------------------------------------------

PERSONA = {
    "persona_id": "generic_linux",
    "display_name": "Generic Linux Web Server",
    "threat_trigger_level": "default",
    "schema_version": 1,

    "system": {
        "hostname": "web-srv-03",
        "os": "Ubuntu 20.04.6 LTS",
        "kernel": "5.4.0-150-generic",
        "arch": "x86_64",
        "uptime_seconds": UPTIME_SECONDS,
        "boot_time": LAST_BOOT,
        "timezone": "UTC",
        "locale": "en_US.UTF-8",
    },

    "network": {
        "interfaces": [
            {
                "name": "eth0",
                "ip": "10.0.2.15",
                "mac": "08:00:27:4a:3b:2c",
                "netmask": "255.255.255.0",
                "broadcast": "10.0.2.255",
                "state": "UP",
                "rx_bytes": 842917,
                "tx_bytes": 1284736,
            },
            {
                "name": "lo",
                "ip": "127.0.0.1",
                "mac": "00:00:00:00:00:00",
                "netmask": "255.0.0.0",
                "broadcast": None,
                "state": "UP",
                "rx_bytes": 15234,
                "tx_bytes": 15234,
            },
        ],
        "open_ports": [22, 80, 443],
        "active_connections": [
            {"proto": "tcp",  "local_addr": "0.0.0.0:22",  "foreign_addr": "0.0.0.0:*", "state": "LISTEN", "pid": 892,  "program": "sshd"},
            {"proto": "tcp6", "local_addr": ":::22",        "foreign_addr": ":::*",     "state": "LISTEN", "pid": 892,  "program": "sshd"},
            {"proto": "tcp",  "local_addr": "0.0.0.0:80",  "foreign_addr": "0.0.0.0:*", "state": "LISTEN", "pid": 1134, "program": "nginx"},
            {"proto": "tcp",  "local_addr": "0.0.0.0:443", "foreign_addr": "0.0.0.0:*", "state": "LISTEN", "pid": 1134, "program": "nginx"},
        ],
    },

    # users[] is the *structured* user list — used for Rule 1 (home dirs) and
    # Rule 2 (process owners). /etc/passwd may legitimately contain more
    # system accounts (see PASSWD_TXT); those are covered by Rule 8.
    "users": [
        {
            "username": "root",
            "uid": 0,
            "gid": 0,
            "home": "/root",
            "shell": "/bin/bash",
            "groups": ["root"],
            "password_hash": "!",
            "last_login": "2026-04-10T09:14:22Z",
            "last_login_from": "192.168.1.100",
        },
        {
            "username": "ubuntu",
            "uid": 1000,
            "gid": 1000,
            "home": "/home/ubuntu",
            "shell": "/bin/bash",
            "groups": ["ubuntu", "sudo", "adm"],
            "password_hash": "$6$Qn7aBc9dE$3xK8vJ2mWqP5rL4nT6yU8iO0pA1sD2fG3hJ4kL5zX",
            "last_login": RECENT_USER,
            "last_login_from": "192.168.1.100",
        },
        {
            "username": "www-data",
            "uid": 33,
            "gid": 33,
            "home": "/var/www",
            "shell": "/usr/sbin/nologin",
            "groups": ["www-data"],
            "password_hash": "*",
            "last_login": None,
            "last_login_from": None,
        },
    ],

    # All process owners must appear in users[] above (Rule 2).
    "processes": [
        {"pid": 1,    "ppid": 0, "user": "root",     "cpu_percent": 0.0, "mem_percent": 0.1, "vsz": 168936, "rss": 13288, "tty": "?", "stat": "Ss", "start": "Mar25", "time": "0:03", "command": "/sbin/init"},
        {"pid": 412,  "ppid": 1, "user": "root",     "cpu_percent": 0.0, "mem_percent": 0.4, "vsz": 104168, "rss":  8432, "tty": "?", "stat": "Ss", "start": "Mar25", "time": "0:02", "command": "/lib/systemd/systemd-journald"},
        {"pid": 892,  "ppid": 1, "user": "root",     "cpu_percent": 0.0, "mem_percent": 0.1, "vsz":  72296, "rss":  6420, "tty": "?", "stat": "Ss", "start": "Mar25", "time": "0:00", "command": "sshd: /usr/sbin/sshd -D"},
        {"pid": 923,  "ppid": 1, "user": "root",     "cpu_percent": 0.0, "mem_percent": 0.0, "vsz":  25552, "rss":  1812, "tty": "?", "stat": "Ss", "start": "Mar25", "time": "0:00", "command": "/usr/sbin/cron -f"},
        {"pid": 1134, "ppid": 1, "user": "root",     "cpu_percent": 0.0, "mem_percent": 0.3, "vsz":  55380, "rss":  5876, "tty": "?", "stat": "Ss", "start": "Mar25", "time": "0:00", "command": "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"},
        {"pid": 1135, "ppid": 1134, "user": "www-data", "cpu_percent": 0.0, "mem_percent": 0.2, "vsz": 55908, "rss": 3956, "tty": "?", "stat": "S",  "start": "Mar25", "time": "0:00", "command": "nginx: worker process"},
        {"pid": 1136, "ppid": 1134, "user": "www-data", "cpu_percent": 0.0, "mem_percent": 0.2, "vsz": 55908, "rss": 3948, "tty": "?", "stat": "S",  "start": "Mar25", "time": "0:00", "command": "nginx: worker process"},
    ],

    "filesystem": {
        "/": dir_entry("root", "root", "755", INSTALL, LAST_UPDATE,
            ["bin","boot","dev","etc","home","lib","lib64","media","mnt",
             "opt","proc","root","run","sbin","srv","sys","tmp","usr","var"]),

        # /etc and its files
        "/etc": dir_entry("root", "root", "755", INSTALL, LAST_UPDATE,
            ["hostname","hosts","os-release","passwd","shadow","group","nginx","crontab","sudoers"]),
        "/etc/hostname":   file_entry("root","root","644", INSTALL, INSTALL,      HOSTNAME_TXT),
        "/etc/hosts":      file_entry("root","root","644", INSTALL, INSTALL,      HOSTS_TXT),
        "/etc/os-release": file_entry("root","root","644", INSTALL, INSTALL,      OS_RELEASE_TXT),
        "/etc/passwd":     file_entry("root","root","644", INSTALL, LAST_UPDATE,  PASSWD_TXT),
        "/etc/shadow":     file_entry("root","shadow","640", INSTALL, LAST_UPDATE, SHADOW_TXT),
        "/etc/group":      file_entry("root","root","644", INSTALL, LAST_UPDATE,  GROUP_TXT),

        # /home tree
        "/home": dir_entry("root","root","755", INSTALL, INSTALL, ["ubuntu"]),
        "/home/ubuntu": dir_entry("ubuntu","ubuntu","750", INSTALL, RECENT_USER,
            [".bash_history",".bashrc",".profile",".ssh"]),
        "/home/ubuntu/.bash_history": file_entry("ubuntu","ubuntu","600", INSTALL, RECENT_USER, BASH_HISTORY_UBUNTU),
        "/home/ubuntu/.bashrc":       file_entry("ubuntu","ubuntu","644", INSTALL, INSTALL,     BASHRC_UBUNTU),
        "/home/ubuntu/.profile":      file_entry("ubuntu","ubuntu","644", INSTALL, INSTALL,     PROFILE_UBUNTU),

        # /root tree
        "/root": dir_entry("root","root","700", INSTALL, "2026-04-10T09:14:22Z",
            [".bash_history",".bashrc",".profile",".ssh"]),
        "/root/.bash_history": file_entry("root","root","600", INSTALL, "2026-04-10T09:14:22Z", BASH_HISTORY_ROOT),
        "/root/.bashrc":       file_entry("root","root","644", INSTALL, INSTALL,                BASHRC_ROOT),

        # /tmp (empty)
        "/tmp": dir_entry("root","root","1777", INSTALL, RECENT_LOG, []),

        # /var tree
        "/var":           dir_entry("root","root","755", INSTALL, LAST_UPDATE,
                           ["log","www","lib","cache","backups","spool","tmp"]),
        "/var/log":       dir_entry("root","root","755", INSTALL, RECENT_LOG,
                           ["auth.log","syslog","dpkg.log","nginx"]),
        "/var/log/auth.log":         file_entry("root","adm","640", "2026-04-01T00:00:00Z", RECENT_LOG, AUTH_LOG),
        "/var/log/syslog":           file_entry("syslog","adm","640", "2026-04-01T00:00:00Z", RECENT_LOG, SYSLOG),
        "/var/log/nginx":            dir_entry("root","adm","755", INSTALL, RECENT_LOG, ["access.log","error.log"]),
        "/var/log/nginx/access.log": file_entry("www-data","adm","644", "2026-04-01T00:00:00Z", RECENT_LOG, NGINX_ACCESS),
        "/var/log/nginx/error.log":  file_entry("www-data","adm","644", "2026-04-01T00:00:00Z", "2026-04-12T11:03:07Z", NGINX_ERROR),

        "/var/www":            dir_entry("www-data","www-data","755", INSTALL, INSTALL, ["html"]),
        "/var/www/html":       dir_entry("www-data","www-data","755", INSTALL, INSTALL, ["index.html"]),
        "/var/www/html/index.html": file_entry("www-data","www-data","644", INSTALL, INSTALL, INDEX_HTML),
    },

    "disk": {
        "total_gb": 25,
        "used_gb": 4.2,
        "available_gb": 19.9,
        "use_percent": 18,
        "filesystem": "/dev/sda1",
        "mount": "/",
    },

    "memory": {
        "total_mb": 2048,
        "used_mb": 734,
        "free_mb": 187,
        "shared_mb": 12,
        "buff_cache_mb": 1127,
        "available_mb": 1118,
    },

    "environment_defaults": {
        "ubuntu": {
            "USER": "ubuntu",
            "HOME": "/home/ubuntu",
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "en_US.UTF-8",
            "PWD": "/home/ubuntu",
            "PS1": "ubuntu@web-srv-03:~$ ",
        },
        "root": {
            "USER": "root",
            "HOME": "/root",
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin",
            "LANG": "en_US.UTF-8",
            "PWD": "/root",
            "PS1": "root@web-srv-03:~# ",
        },
    },
}


# Consistency validator lives in honeypot/persona_validator.py so FakeFS
# and the other persona builders share it.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from honeypot.persona_validator import validate  # noqa: E402


def main() -> int:
    out = Path(__file__).resolve().parent.parent / "personas" / "generic_linux.json"
    now = datetime(2026, 4, 16, 12, 0, 0, tzinfo=timezone.utc)

    errors = validate(PERSONA, now)
    if errors:
        print("CONSISTENCY VIOLATIONS:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    out.write_text(json.dumps(PERSONA, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes, 0 consistency violations)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
