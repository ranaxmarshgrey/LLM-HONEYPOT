"""Persona consistency validator (CLAUDE.md §9 + Sprint 2 rules 1–8).

Used by:
    scripts/build_*_persona.py    — fail the build if a persona violates
                                     any rule, never write a broken JSON.
    honeypot/fakefs.py            — refuse to load an inconsistent
                                     persona at runtime.

A rule is enumerated in ``Rule`` (str enum-ish constants) purely so error
messages and tests can match on a stable prefix. Every ``validate()``
error string starts with ``"Rule N: "``.

Sprint target: Sprint 2.
"""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List


# ---------------------------------------------------------------------------
# Port -> plausible service command substrings (Rule 3).
# A process whose command contains any listed substring counts as owning
# the port. Keep this table conservative — a false match is a consistency
# hole, a missing mapping just means "add the port to this table before
# exposing it in a persona".
# ---------------------------------------------------------------------------

PORT_SERVICES: Dict[int, tuple[str, ...]] = {
    22:    ("sshd",),
    80:    ("nginx", "apache", "apache2", "httpd", "caddy"),
    443:   ("nginx", "apache", "apache2", "httpd", "caddy"),
    2375:  ("dockerd", "docker"),
    2376:  ("dockerd", "docker"),
    3000:  ("node", "npm"),
    3306:  ("mysqld", "mariadb"),
    5432:  ("postgres", "postgresql"),
    6379:  ("redis",),
    8000:  ("python", "gunicorn", "uvicorn"),
    8080:  ("java", "node", "gunicorn", "tomcat", "code-server"),
    8443:  ("java", "nginx", "apache", "tomcat"),
    9000:  ("java", "php-fpm"),
}


def _iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def validate(persona: dict, now: datetime) -> List[str]:
    """Run all 8 consistency checks against a loaded persona dict.

    Returns a list of human-readable violation strings (empty list means
    fully consistent). Never raises — callers decide what to do with the
    violations.
    """
    errors: List[str] = []
    fs = persona["filesystem"]
    users = {u["username"] for u in persona["users"]}

    # Rule 1 — User-Home Coherence
    for u in persona["users"]:
        if u["shell"].endswith("nologin") or u["shell"].endswith("false"):
            continue
        home = u["home"]
        if home not in fs or fs[home].get("type") != "directory":
            errors.append(
                f"Rule 1: user '{u['username']}' home '{home}' missing or not a directory"
            )

    # Rule 2 — Process-User Coherence
    for p in persona["processes"]:
        if p["user"] not in users:
            errors.append(
                f"Rule 2: process pid={p['pid']} owned by unknown user '{p['user']}'"
            )

    # Rule 3 — Port-Process Coherence
    all_commands = " ".join(p["command"] for p in persona["processes"]).lower()
    for port in persona["network"]["open_ports"]:
        services = PORT_SERVICES.get(port, ())
        if not services:
            errors.append(
                f"Rule 3: open port {port} has no known service mapping "
                f"(add it to PORT_SERVICES)"
            )
            continue
        if not any(svc in all_commands for svc in services):
            errors.append(
                f"Rule 3: open port {port} has no matching process "
                f"(want one of {services})"
            )

    # Rule 4 — Hostname Coherence
    hn = persona["system"]["hostname"]
    hostname_file = fs.get("/etc/hostname", {}).get("content", "").strip()
    hosts_file = fs.get("/etc/hosts", {}).get("content", "")
    if hostname_file != hn:
        errors.append(
            f"Rule 4: /etc/hostname content '{hostname_file}' != system.hostname '{hn}'"
        )
    if hn not in hosts_file:
        errors.append(f"Rule 4: /etc/hosts does not mention hostname '{hn}'")

    # Rule 5 — Timestamp Coherence
    for path, entry in fs.items():
        created = entry.get("created")
        modified = entry.get("modified")
        if not (created and modified):
            continue
        c, m = _iso(created), _iso(modified)
        if m > now:
            errors.append(f"Rule 5: {path} modified={modified} is in the future")
        if m < c:
            errors.append(
                f"Rule 5: {path} modified < created ({modified} < {created})"
            )

    # Rule 6 — File Size Coherence
    for path, entry in fs.items():
        if entry.get("type") != "file":
            continue
        content = entry.get("content")
        if content is None:
            continue  # binary / opaque files may omit content
        expected = len(content.encode("utf-8"))
        if entry.get("size_bytes") != expected:
            errors.append(
                f"Rule 6: {path} size_bytes={entry.get('size_bytes')} != "
                f"len(content)={expected}"
            )

    # Rule 7 — Parent Directory Coherence
    for path in fs:
        if path == "/":
            continue
        parent = path.rsplit("/", 1)[0] or "/"
        if parent not in fs:
            errors.append(f"Rule 7: {path} parent '{parent}' not in filesystem")
            continue
        if fs[parent].get("type") != "directory":
            errors.append(f"Rule 7: {path} parent '{parent}' is not a directory")
            continue
        basename = path.rsplit("/", 1)[1]
        if basename not in fs[parent].get("children", []):
            errors.append(f"Rule 7: {path} not listed in parent '{parent}' children")

    # Rule 8 — Shadow-Passwd Coherence
    passwd_entry = fs.get("/etc/passwd", {})
    shadow_entry = fs.get("/etc/shadow", {})
    passwd_content = passwd_entry.get("content", "")
    shadow_content = shadow_entry.get("content", "")
    if not passwd_content:
        errors.append("Rule 8: /etc/passwd missing or empty")
    if not shadow_content:
        errors.append("Rule 8: /etc/shadow missing or empty")
    if passwd_content and shadow_content:
        passwd_users = {
            line.split(":", 1)[0] for line in passwd_content.splitlines() if line
        }
        shadow_users = {
            line.split(":", 1)[0] for line in shadow_content.splitlines() if line
        }
        missing = passwd_users - shadow_users
        if missing:
            errors.append(
                f"Rule 8: users in passwd but missing from shadow: {sorted(missing)}"
            )

    return errors
