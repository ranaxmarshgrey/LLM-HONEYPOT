"""Build personas/dev_workstation.json deterministically.

Developer workstation persona: Ubuntu 22.04 desktop with node, docker,
code-server, a checked-in webapp project with a tempting .env file,
fake SSH keys, and a git repo. This is the medium-threat escalation
persona — what an attacker sees after low-level recon has bumped their
threat score past the 20-point threshold.

Usage:  python scripts/build_dev_workstation_persona.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from honeypot.persona_validator import validate  # noqa: E402


# ---------------------------------------------------------------------------
# Time anchors
# ---------------------------------------------------------------------------
INSTALL = "2025-09-01T10:00:00Z"
LAST_UPDATE = "2026-03-02T14:12:09Z"
LAST_BOOT = "2026-04-11T09:04:17Z"        # ~5 days uptime before 2026-04-16
RECENT_EDIT = "2026-04-15T18:22:14Z"
RECENT_LOG = "2026-04-15T23:59:01Z"

UPTIME_SECONDS = 432_000  # 5 days


# ---------------------------------------------------------------------------
# /etc file contents — PASSWD_TXT and SHADOW_TXT must have identical user sets
# ---------------------------------------------------------------------------

HOSTNAME_TXT = "dev-workstation-07\n"

HOSTS_TXT = (
    "127.0.0.1\tlocalhost\n"
    "127.0.1.1\tdev-workstation-07\n"
    "\n"
    "::1\tlocalhost ip6-localhost ip6-loopback\n"
    "ff02::1\tip6-allnodes\n"
    "ff02::2\tip6-allrouters\n"
)

OS_RELEASE_TXT = (
    'NAME="Ubuntu"\n'
    'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
    "ID=ubuntu\n"
    "ID_LIKE=debian\n"
    'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
    'VERSION_ID="22.04"\n'
    'HOME_URL="https://www.ubuntu.com/"\n'
    'SUPPORT_URL="https://help.ubuntu.com/"\n'
    'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
    "VERSION_CODENAME=jammy\n"
    "UBUNTU_CODENAME=jammy\n"
)

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
    "docker:x:999:999::/home/docker:/usr/sbin/nologin\n"
    "john.dev:x:1001:1001:John Developer,,,:/home/john.dev:/bin/bash\n"
)

SHADOW_TXT = (
    "root:!:20000:0:99999:7:::\n"
    "daemon:*:20000:0:99999:7:::\n"
    "bin:*:20000:0:99999:7:::\n"
    "sys:*:20000:0:99999:7:::\n"
    "sync:*:20000:0:99999:7:::\n"
    "www-data:*:20000:0:99999:7:::\n"
    "nobody:*:20000:0:99999:7:::\n"
    "systemd-resolve:*:20000:0:99999:7:::\n"
    "messagebus:*:20000:0:99999:7:::\n"
    "syslog:*:20000:0:99999:7:::\n"
    "sshd:*:20000:0:99999:7:::\n"
    "docker:*:20000:0:99999:7:::\n"
    "john.dev:$6$dV3xN8qW$kL2mP9vT7rY4sA1bC6eH5iJ3oU0zX8fG2hK4nM5wQ:20000:0:99999:7:::\n"
)

GROUP_TXT = (
    "root:x:0:\n"
    "daemon:x:1:\n"
    "bin:x:2:\n"
    "sys:x:3:\n"
    "adm:x:4:syslog,john.dev\n"
    "sudo:x:27:john.dev\n"
    "www-data:x:33:\n"
    "docker:x:999:john.dev\n"
    "nogroup:x:65534:\n"
    "john.dev:x:1001:\n"
)


# ---------------------------------------------------------------------------
# User files — a developer's home directory
# ---------------------------------------------------------------------------

BASH_HISTORY = (
    "cd projects/webapp\n"
    "git status\n"
    "npm install\n"
    "npm run dev\n"
    "docker-compose up -d\n"
    "docker ps\n"
    "code .\n"
    "git add .\n"
    "git commit -m 'fix login bug'\n"
    "git push origin develop\n"
    "psql -h staging-db.internal -U webapp\n"
    "kubectl get pods -n staging\n"
    "exit\n"
)

BASHRC = (
    "# ~/.bashrc\n"
    "case $- in\n"
    "    *i*) ;;\n"
    "      *) return;;\n"
    "esac\n"
    "\n"
    "HISTCONTROL=ignoreboth\n"
    "HISTSIZE=5000\n"
    "HISTFILESIZE=10000\n"
    "\n"
    "export NVM_DIR=\"$HOME/.nvm\"\n"
    '[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"\n'
    "\n"
    "alias ll='ls -alF'\n"
    "alias gs='git status'\n"
    "alias gp='git pull'\n"
    "alias dc='docker-compose'\n"
    "alias k='kubectl'\n"
    "\n"
    "export EDITOR=code\n"
    'export PATH="$HOME/.local/bin:$PATH"\n'
)

PROFILE = (
    "# ~/.profile\n"
    "if [ -n \"$BASH_VERSION\" ]; then\n"
    "    if [ -f \"$HOME/.bashrc\" ]; then\n"
    "        . \"$HOME/.bashrc\"\n"
    "    fi\n"
    "fi\n"
    '\nif [ -d "$HOME/bin" ] ; then\n'
    '    PATH="$HOME/bin:$PATH"\n'
    "fi\n"
)

GITCONFIG = (
    "[user]\n"
    "\tname = John Developer\n"
    "\temail = john.dev@acmecorp.internal\n"
    "[core]\n"
    "\teditor = code --wait\n"
    "[push]\n"
    "\tdefault = current\n"
    "[pull]\n"
    "\trebase = true\n"
    "[alias]\n"
    "\tst = status\n"
    "\tco = checkout\n"
    "\tbr = branch\n"
)

# --- Lure files: SSH keys (fake) ---
ID_RSA = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n"
    "NhAAAAAwEAAQAAAYEAwZKj5QnDQfakeExampleOnlyDoNotUseThisKeyAnywhereReal\n"
    "VeryLongBase64EncodedDataHereButThisIsJustAHoneypotLureForAttackersXx\n"
    "NotARealKeyDoNotTryToUseItForAnythingItDoesNotWorkThisIsFakeFakeFakeQ\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)

ID_RSA_PUB = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBkqPlCcNB9qR4TampleOnlyDoNotUse"
    "ThisKeyAnywhereRealVeryLongBase64EncodedDataHereButThisIsJustAHoneyp"
    "otLureForAttackers john.dev@dev-workstation-07\n"
)

AUTHORIZED_KEYS = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCxyz789FakeKeyExampleForHoneypot"
    "LureDoNotUseThisKeyAnywhereRealAttackersMightTryButItWillNotWorkXy "
    "john.dev@laptop\n"
)

# --- Project files ---
README_MD = (
    "# Internal WebApp\n"
    "\n"
    "Internal dashboard for the operations team.\n"
    "\n"
    "## Quick start\n"
    "\n"
    "```bash\n"
    "npm install\n"
    "cp .env.example .env   # fill in secrets\n"
    "docker-compose up -d   # start postgres + redis\n"
    "npm run dev\n"
    "```\n"
    "\n"
    "Served on http://localhost:3000 in dev.\n"
)

ENV_FILE = (
    "# WebApp development environment\n"
    "NODE_ENV=development\n"
    "PORT=3000\n"
    "\n"
    "# Database\n"
    "DB_HOST=staging-db.internal.acmecorp.net\n"
    "DB_PORT=5432\n"
    "DB_NAME=webapp_staging\n"
    "DB_USER=webapp_svc\n"
    "DB_PASSWORD=S3cret-P@ssw0rd-2026-!rotate-me\n"
    "\n"
    "# Redis\n"
    "REDIS_URL=redis://:cache-pw-8812@staging-redis.internal:6379/0\n"
    "\n"
    "# External APIs\n"
    "STRIPE_API_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dcFAKEFAKEFAKE\n"
    "SENDGRID_API_KEY=SG.fakesendgridkeyjustalurebutlookslegitimate.xxxxxxxxxxxx\n"
    "JWT_SECRET=dev-only-jwt-signing-secret-do-not-ship\n"
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    "\n"
    "# Feature flags\n"
    "FEATURE_NEW_DASHBOARD=true\n"
    "FEATURE_BETA_CHECKOUT=false\n"
)

PACKAGE_JSON = (
    "{\n"
    '  "name": "webapp",\n'
    '  "version": "1.4.2",\n'
    '  "private": true,\n'
    '  "scripts": {\n'
    '    "dev": "node --watch server.js",\n'
    '    "start": "node server.js",\n'
    '    "test": "jest",\n'
    '    "lint": "eslint ."\n'
    "  },\n"
    '  "dependencies": {\n'
    '    "express": "^4.19.2",\n'
    '    "pg": "^8.11.3",\n'
    '    "redis": "^4.6.12",\n'
    '    "dotenv": "^16.4.5",\n'
    '    "jsonwebtoken": "^9.0.2",\n'
    '    "bcrypt": "^5.1.1"\n'
    "  },\n"
    '  "devDependencies": {\n'
    '    "jest": "^29.7.0",\n'
    '    "eslint": "^8.57.0"\n'
    "  }\n"
    "}\n"
)

DOCKERFILE = (
    "FROM node:20-alpine\n"
    "\n"
    "WORKDIR /app\n"
    "COPY package*.json ./\n"
    "RUN npm ci --only=production\n"
    "\n"
    "COPY . .\n"
    "\n"
    "EXPOSE 3000\n"
    "USER node\n"
    'CMD ["node", "server.js"]\n'
)

DOCKER_COMPOSE_YML = (
    "version: '3.8'\n"
    "services:\n"
    "  postgres:\n"
    "    image: postgres:15\n"
    "    environment:\n"
    "      POSTGRES_DB: webapp_dev\n"
    "      POSTGRES_USER: webapp\n"
    "      POSTGRES_PASSWORD: dev-local-pw\n"
    "    ports:\n"
    "      - '5432:5432'\n"
    "    volumes:\n"
    "      - pg_data:/var/lib/postgresql/data\n"
    "  redis:\n"
    "    image: redis:7-alpine\n"
    "    ports:\n"
    "      - '6379:6379'\n"
    "volumes:\n"
    "  pg_data:\n"
)

SERVER_JS = (
    "const express = require('express');\n"
    "const { Pool } = require('pg');\n"
    "require('dotenv').config();\n"
    "\n"
    "const app = express();\n"
    "const pool = new Pool({\n"
    "  host: process.env.DB_HOST,\n"
    "  port: process.env.DB_PORT,\n"
    "  database: process.env.DB_NAME,\n"
    "  user: process.env.DB_USER,\n"
    "  password: process.env.DB_PASSWORD,\n"
    "});\n"
    "\n"
    "app.get('/health', (req, res) => res.send('ok'));\n"
    "\n"
    "app.get('/users/:id', async (req, res) => {\n"
    "  const { rows } = await pool.query('SELECT id, email FROM users WHERE id = $1', [req.params.id]);\n"
    "  res.json(rows[0] || null);\n"
    "});\n"
    "\n"
    "app.listen(process.env.PORT || 3000, () => {\n"
    "  console.log('webapp listening on :' + (process.env.PORT || 3000));\n"
    "});\n"
)

GIT_CONFIG_REPO = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    "\tfilemode = true\n"
    "\tbare = false\n"
    "\tlogallrefupdates = true\n"
    "[remote \"origin\"]\n"
    "\turl = git@github.acmecorp.internal:platform/webapp.git\n"
    "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
    "[branch \"develop\"]\n"
    "\tremote = origin\n"
    "\tmerge = refs/heads/develop\n"
)

BASH_HISTORY_ROOT = (
    "apt update\n"
    "apt install -y docker.io\n"
    "usermod -aG docker john.dev\n"
    "systemctl enable docker\n"
    "exit\n"
)

BASHRC_ROOT = (
    "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
    "alias ll='ls -alF'\n"
)

AUTH_LOG = (
    "Apr 15 08:12:03 dev-workstation-07 sshd[1823]: Accepted publickey for john.dev from 10.0.2.88 port 50421\n"
    "Apr 15 08:12:03 dev-workstation-07 sshd[1823]: pam_unix(sshd:session): session opened for user john.dev by (uid=0)\n"
    "Apr 15 17:01:01 dev-workstation-07 CRON[2841]: pam_unix(cron:session): session opened for user root by (uid=0)\n"
    "Apr 15 17:01:01 dev-workstation-07 CRON[2841]: pam_unix(cron:session): session closed for user root\n"
)

SYSLOG = (
    "Apr 15 09:04:17 dev-workstation-07 systemd[1]: Started Docker Application Container Engine.\n"
    "Apr 15 09:04:19 dev-workstation-07 dockerd[1023]: level=info msg=\"API listen on /run/docker.sock\"\n"
    "Apr 15 17:01:01 dev-workstation-07 CRON[2841]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)\n"
    "Apr 15 23:59:01 dev-workstation-07 systemd[1]: logrotate.service: Succeeded.\n"
)


# ---------------------------------------------------------------------------
# Builders
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
    return {
        "type": "file",
        "owner": owner,
        "group": group,
        "permissions": perms,
        "created": created,
        "modified": modified,
        "size_bytes": len(content.encode("utf-8")),
        "content": content,
    }


# ---------------------------------------------------------------------------
# Persona
# ---------------------------------------------------------------------------

PERSONA = {
    "persona_id": "dev_workstation",
    "display_name": "Developer Workstation",
    "threat_trigger_level": "medium",
    "schema_version": 1,

    "system": {
        "hostname": "dev-workstation-07",
        "os": "Ubuntu 22.04.3 LTS",
        "kernel": "5.15.0-88-generic",
        "arch": "x86_64",
        "uptime_seconds": UPTIME_SECONDS,
        "boot_time": LAST_BOOT,
        "timezone": "UTC",
        "locale": "en_US.UTF-8",
    },

    "network": {
        "interfaces": [
            {"name": "eth0", "ip": "10.0.2.88", "mac": "08:00:27:91:4e:bd",
             "netmask": "255.255.255.0", "broadcast": "10.0.2.255", "state": "UP",
             "rx_bytes": 24_834_912, "tx_bytes": 18_221_047},
            {"name": "docker0", "ip": "172.17.0.1", "mac": "02:42:a1:b2:c3:d4",
             "netmask": "255.255.0.0", "broadcast": None, "state": "UP",
             "rx_bytes": 148_272, "tx_bytes": 92_401},
            {"name": "lo", "ip": "127.0.0.1", "mac": "00:00:00:00:00:00",
             "netmask": "255.0.0.0", "broadcast": None, "state": "UP",
             "rx_bytes": 104_928, "tx_bytes": 104_928},
        ],
        "open_ports": [22, 3000, 8080],
        "active_connections": [
            {"proto": "tcp",  "local_addr": "0.0.0.0:22",   "foreign_addr": "0.0.0.0:*", "state": "LISTEN", "pid": 748,  "program": "sshd"},
            {"proto": "tcp6", "local_addr": ":::22",         "foreign_addr": ":::*",      "state": "LISTEN", "pid": 748,  "program": "sshd"},
            {"proto": "tcp",  "local_addr": "127.0.0.1:3000","foreign_addr": "0.0.0.0:*", "state": "LISTEN", "pid": 2341, "program": "node"},
            {"proto": "tcp",  "local_addr": "0.0.0.0:8080", "foreign_addr": "0.0.0.0:*", "state": "LISTEN", "pid": 3012, "program": "code-server"},
            {"proto": "tcp",  "local_addr": "10.0.2.88:50412","foreign_addr": "140.82.114.4:443", "state": "ESTABLISHED", "pid": 2890, "program": "git"},
        ],
    },

    "users": [
        {
            "username": "root", "uid": 0, "gid": 0,
            "home": "/root", "shell": "/bin/bash",
            "groups": ["root"], "password_hash": "!",
            "last_login": "2026-03-02T14:12:09Z",
            "last_login_from": None,
        },
        {
            "username": "john.dev", "uid": 1001, "gid": 1001,
            "home": "/home/john.dev", "shell": "/bin/bash",
            "groups": ["john.dev", "sudo", "docker", "adm"],
            "password_hash": "$6$dV3xN8qW$kL2mP9vT7rY4sA1bC6eH5iJ3oU0zX8fG2hK4nM5wQ",
            "last_login": "2026-04-15T08:12:03Z",
            "last_login_from": "10.0.2.88",
        },
    ],

    "processes": [
        {"pid": 1,    "ppid": 0,    "user": "root",     "cpu_percent": 0.0, "mem_percent": 0.1, "vsz": 169440, "rss": 13512, "tty": "?", "stat": "Ss", "start": "Apr11", "time": "0:04", "command": "/sbin/init splash"},
        {"pid": 412,  "ppid": 1,    "user": "root",     "cpu_percent": 0.0, "mem_percent": 0.4, "vsz": 104168, "rss":  8432, "tty": "?", "stat": "Ss", "start": "Apr11", "time": "0:02", "command": "/lib/systemd/systemd-journald"},
        {"pid": 748,  "ppid": 1,    "user": "root",     "cpu_percent": 0.0, "mem_percent": 0.1, "vsz":  72296, "rss":  6420, "tty": "?", "stat": "Ss", "start": "Apr11", "time": "0:00", "command": "sshd: /usr/sbin/sshd -D"},
        {"pid": 812,  "ppid": 1,    "user": "root",     "cpu_percent": 0.0, "mem_percent": 0.0, "vsz":  25552, "rss":  1812, "tty": "?", "stat": "Ss", "start": "Apr11", "time": "0:00", "command": "/usr/sbin/cron -f"},
        {"pid": 1023, "ppid": 1,    "user": "root",     "cpu_percent": 0.3, "mem_percent": 1.8, "vsz": 1834272, "rss": 94328, "tty": "?", "stat": "Ssl","start": "Apr11", "time": "2:41", "command": "/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock"},
        {"pid": 1045, "ppid": 1,    "user": "root",     "cpu_percent": 0.1, "mem_percent": 0.9, "vsz": 1214776, "rss": 46112, "tty": "?", "stat": "Ssl","start": "Apr11", "time": "1:12", "command": "/usr/bin/containerd"},
        {"pid": 2341, "ppid": 1890, "user": "john.dev", "cpu_percent": 0.4, "mem_percent": 2.3, "vsz":  742316, "rss":118432, "tty": "pts/0", "stat": "Sl","start": "09:14", "time": "0:08", "command": "node --watch server.js"},
        {"pid": 2890, "ppid": 1890, "user": "john.dev", "cpu_percent": 0.0, "mem_percent": 0.3, "vsz":  22914, "rss":  8120, "tty": "pts/1", "stat": "S", "start": "10:02", "time": "0:00", "command": "npm run dev"},
        {"pid": 3012, "ppid": 1,    "user": "john.dev", "cpu_percent": 0.2, "mem_percent": 3.1, "vsz":  912044, "rss":152882, "tty": "?", "stat": "Ssl","start": "Apr11", "time": "3:14", "command": "/home/john.dev/.local/bin/code-server --host 0.0.0.0 --port 8080"},
    ],

    "filesystem": {
        "/": dir_entry("root","root","755", INSTALL, LAST_UPDATE,
            ["bin","boot","dev","etc","home","lib","lib64","media","mnt",
             "opt","proc","root","run","sbin","srv","sys","tmp","usr","var"]),

        # /etc
        "/etc": dir_entry("root","root","755", INSTALL, LAST_UPDATE,
            ["hostname","hosts","os-release","passwd","shadow","group","docker","ssh"]),
        "/etc/hostname":   file_entry("root","root","644", INSTALL, INSTALL,     HOSTNAME_TXT),
        "/etc/hosts":      file_entry("root","root","644", INSTALL, INSTALL,     HOSTS_TXT),
        "/etc/os-release": file_entry("root","root","644", INSTALL, INSTALL,     OS_RELEASE_TXT),
        "/etc/passwd":     file_entry("root","root","644", INSTALL, LAST_UPDATE, PASSWD_TXT),
        "/etc/shadow":     file_entry("root","shadow","640", INSTALL, LAST_UPDATE, SHADOW_TXT),
        "/etc/group":      file_entry("root","root","644", INSTALL, LAST_UPDATE, GROUP_TXT),

        # /home/john.dev + subtree
        "/home": dir_entry("root","root","755", INSTALL, INSTALL, ["john.dev"]),
        "/home/john.dev": dir_entry("john.dev","john.dev","750", INSTALL, RECENT_EDIT,
            [".bash_history",".bashrc",".profile",".gitconfig",".ssh","projects"]),
        "/home/john.dev/.bash_history": file_entry("john.dev","john.dev","600", INSTALL, RECENT_EDIT, BASH_HISTORY),
        "/home/john.dev/.bashrc":       file_entry("john.dev","john.dev","644", INSTALL, INSTALL,     BASHRC),
        "/home/john.dev/.profile":      file_entry("john.dev","john.dev","644", INSTALL, INSTALL,     PROFILE),
        "/home/john.dev/.gitconfig":    file_entry("john.dev","john.dev","644", INSTALL, INSTALL,     GITCONFIG),

        "/home/john.dev/.ssh":             dir_entry("john.dev","john.dev","700", INSTALL, INSTALL,
            ["authorized_keys","id_rsa","id_rsa.pub","known_hosts"]),
        "/home/john.dev/.ssh/id_rsa":          file_entry("john.dev","john.dev","600", INSTALL, INSTALL, ID_RSA),
        "/home/john.dev/.ssh/id_rsa.pub":      file_entry("john.dev","john.dev","644", INSTALL, INSTALL, ID_RSA_PUB),
        "/home/john.dev/.ssh/authorized_keys": file_entry("john.dev","john.dev","600", INSTALL, INSTALL, AUTHORIZED_KEYS),

        # projects/webapp — the juicy part
        "/home/john.dev/projects": dir_entry("john.dev","john.dev","755", INSTALL, RECENT_EDIT, ["webapp"]),
        "/home/john.dev/projects/webapp": dir_entry("john.dev","john.dev","755", INSTALL, RECENT_EDIT,
            [".env",".git","Dockerfile","README.md","docker-compose.yml","package.json","server.js"]),
        "/home/john.dev/projects/webapp/.env":               file_entry("john.dev","john.dev","600", INSTALL, RECENT_EDIT, ENV_FILE),
        "/home/john.dev/projects/webapp/README.md":          file_entry("john.dev","john.dev","644", INSTALL, RECENT_EDIT, README_MD),
        "/home/john.dev/projects/webapp/package.json":       file_entry("john.dev","john.dev","644", INSTALL, RECENT_EDIT, PACKAGE_JSON),
        "/home/john.dev/projects/webapp/Dockerfile":         file_entry("john.dev","john.dev","644", INSTALL, RECENT_EDIT, DOCKERFILE),
        "/home/john.dev/projects/webapp/docker-compose.yml": file_entry("john.dev","john.dev","644", INSTALL, RECENT_EDIT, DOCKER_COMPOSE_YML),
        "/home/john.dev/projects/webapp/server.js":          file_entry("john.dev","john.dev","644", INSTALL, RECENT_EDIT, SERVER_JS),
        "/home/john.dev/projects/webapp/.git": dir_entry("john.dev","john.dev","755", INSTALL, RECENT_EDIT, ["config","HEAD"]),
        "/home/john.dev/projects/webapp/.git/config":        file_entry("john.dev","john.dev","644", INSTALL, RECENT_EDIT, GIT_CONFIG_REPO),

        # /root
        "/root": dir_entry("root","root","700", INSTALL, "2026-03-02T14:12:09Z",
            [".bash_history",".bashrc"]),
        "/root/.bash_history": file_entry("root","root","600", INSTALL, "2026-03-02T14:12:09Z", BASH_HISTORY_ROOT),
        "/root/.bashrc":       file_entry("root","root","644", INSTALL, INSTALL,                 BASHRC_ROOT),

        # /tmp
        "/tmp": dir_entry("root","root","1777", INSTALL, RECENT_LOG, []),

        # /var
        "/var": dir_entry("root","root","755", INSTALL, LAST_UPDATE, ["log","lib","cache","tmp"]),
        "/var/log": dir_entry("root","root","755", INSTALL, RECENT_LOG, ["auth.log","syslog","dpkg.log"]),
        "/var/log/auth.log": file_entry("root","adm","640", "2026-04-01T00:00:00Z", RECENT_LOG, AUTH_LOG),
        "/var/log/syslog":   file_entry("syslog","adm","640", "2026-04-01T00:00:00Z", RECENT_LOG, SYSLOG),
        "/var/lib": dir_entry("root","root","755", INSTALL, LAST_UPDATE, ["docker","dpkg"]),
        "/var/lib/docker": dir_entry("root","root","710", INSTALL, LAST_UPDATE, ["containers","image","volumes"]),
    },

    "disk": {
        "total_gb": 120,
        "used_gb": 43.7,
        "available_gb": 70.4,
        "use_percent": 37,
        "filesystem": "/dev/nvme0n1p2",
        "mount": "/",
    },

    "memory": {
        "total_mb": 8192,
        "used_mb": 3842,
        "free_mb": 921,
        "shared_mb": 288,
        "buff_cache_mb": 3429,
        "available_mb": 3847,
    },

    "environment_defaults": {
        "john.dev": {
            "USER": "john.dev",
            "HOME": "/home/john.dev",
            "SHELL": "/bin/bash",
            "PATH": "/home/john.dev/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "en_US.UTF-8",
            "PWD": "/home/john.dev/projects/webapp",
            "PS1": "john.dev@dev-workstation-07:~/projects/webapp$ ",
            "EDITOR": "code",
            "NVM_DIR": "/home/john.dev/.nvm",
        },
        "root": {
            "USER": "root",
            "HOME": "/root",
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin",
            "LANG": "en_US.UTF-8",
            "PWD": "/root",
            "PS1": "root@dev-workstation-07:~# ",
        },
    },
}


def main() -> int:
    out = Path(__file__).resolve().parent.parent / "personas" / "dev_workstation.json"
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
