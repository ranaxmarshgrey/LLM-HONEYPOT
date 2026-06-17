"""Module 5a -- Threat Scorer.

Classifies each command into a threat category, assigns a score delta,
detects multi-command attack patterns, and decides whether a persona
switch should be triggered.

Two-layer classification:
    Layer 1 -- Exact match on the full command string (fast).
    Layer 2 -- Binary name match + argument escalators (fallback).

The main entry point is ``ThreatScorer.score_command()``, which returns
a ``ThreatDecision`` consumed by the Session Manager and (in Sprint 5)
the Persona Switcher.

Sprint target: Sprint 4.
"""
from __future__ import annotations

import logging
import re
from enum import Enum
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ThreatLevel(str, Enum):
    """Session-wide threat assessment derived from cumulative score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CommandCategory(str, Enum):
    """Attack-phase classification for a single command."""

    BENIGN = "benign"
    RECONNAISSANCE = "reconnaissance"
    EXPLORATION = "exploration"
    PRIVILEGE_ESC = "privilege_escalation"
    EXFILTRATION = "exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"


# ---------------------------------------------------------------------------
# ThreatDecision -- the output contract Sprint 5 will consume
# ---------------------------------------------------------------------------

class ThreatDecision(BaseModel):
    """Result of scoring a single command within a session."""

    command_raw: str
    command_category: CommandCategory
    score_delta: int = Field(ge=0)

    previous_score: int = Field(ge=0, le=100)
    new_total_score: int = Field(ge=0, le=100)
    threat_level: ThreatLevel

    trigger_persona_switch: bool = False
    switch_to_persona: Optional[str] = None
    switch_reason: Optional[str] = None

    patterns_detected: List[str] = Field(default_factory=list)
    is_first_of_category: bool = False


# ---------------------------------------------------------------------------
# Layer 1 -- Exact match scores
# ---------------------------------------------------------------------------

_Cat = CommandCategory

EXACT_MATCH_SCORES: Dict[str, Tuple[CommandCategory, int]] = {
    # -- BENIGN (delta 0) ---------------------------------------------------
    "ls": (_Cat.BENIGN, 0),
    "pwd": (_Cat.BENIGN, 0),
    "echo": (_Cat.BENIGN, 0),
    "clear": (_Cat.BENIGN, 0),
    "exit": (_Cat.BENIGN, 0),
    "help": (_Cat.BENIGN, 0),
    "date": (_Cat.BENIGN, 0),
    "uptime": (_Cat.BENIGN, 0),
    "history": (_Cat.BENIGN, 0),
    "cd": (_Cat.BENIGN, 0),
    "touch": (_Cat.BENIGN, 0),
    "mkdir": (_Cat.BENIGN, 0),
    "cp": (_Cat.BENIGN, 0),
    "mv": (_Cat.BENIGN, 0),
    "rm": (_Cat.BENIGN, 0),
    "head": (_Cat.BENIGN, 0),
    "tail": (_Cat.BENIGN, 0),
    "less": (_Cat.BENIGN, 0),
    "more": (_Cat.BENIGN, 0),
    "man": (_Cat.BENIGN, 0),

    # -- LEVEL 1: Basic Reconnaissance (delta 1-4) -------------------------
    "whoami": (_Cat.RECONNAISSANCE, 1),
    "id": (_Cat.RECONNAISSANCE, 1),
    "uname": (_Cat.RECONNAISSANCE, 2),
    "uname -a": (_Cat.RECONNAISSANCE, 3),
    "uname -r": (_Cat.RECONNAISSANCE, 2),
    "hostname": (_Cat.RECONNAISSANCE, 1),
    "hostname -f": (_Cat.RECONNAISSANCE, 2),
    "arch": (_Cat.RECONNAISSANCE, 1),
    "cat /etc/os-release": (_Cat.RECONNAISSANCE, 3),
    "cat /proc/version": (_Cat.RECONNAISSANCE, 3),
    "env": (_Cat.RECONNAISSANCE, 3),
    "printenv": (_Cat.RECONNAISSANCE, 3),
    "w": (_Cat.RECONNAISSANCE, 2),
    "who": (_Cat.RECONNAISSANCE, 2),
    "last": (_Cat.RECONNAISSANCE, 3),
    "df": (_Cat.RECONNAISSANCE, 2),
    "df -h": (_Cat.RECONNAISSANCE, 2),
    "free": (_Cat.RECONNAISSANCE, 2),
    "free -m": (_Cat.RECONNAISSANCE, 2),
    "free -h": (_Cat.RECONNAISSANCE, 2),
    "ifconfig": (_Cat.RECONNAISSANCE, 3),
    "ip addr": (_Cat.RECONNAISSANCE, 3),
    "ip a": (_Cat.RECONNAISSANCE, 3),
    "ip route": (_Cat.RECONNAISSANCE, 3),
    "ip link": (_Cat.RECONNAISSANCE, 2),
    "netstat": (_Cat.RECONNAISSANCE, 4),
    "netstat -an": (_Cat.RECONNAISSANCE, 4),
    "netstat -tulpn": (_Cat.RECONNAISSANCE, 4),
    "ss": (_Cat.RECONNAISSANCE, 3),
    "ss -tulpn": (_Cat.RECONNAISSANCE, 4),
    "ss -an": (_Cat.RECONNAISSANCE, 4),
    "ps": (_Cat.RECONNAISSANCE, 2),
    "ps aux": (_Cat.EXPLORATION, 4),
    "ps -ef": (_Cat.EXPLORATION, 4),
    "ps -eo": (_Cat.EXPLORATION, 4),
    "mount": (_Cat.RECONNAISSANCE, 2),
    "lsblk": (_Cat.RECONNAISSANCE, 2),
    "lscpu": (_Cat.RECONNAISSANCE, 2),
    "cat /proc/cpuinfo": (_Cat.RECONNAISSANCE, 3),

    # -- LEVEL 2: System Exploration (delta 4-8) ----------------------------
    "cat /etc/passwd": (_Cat.EXPLORATION, 6),
    "cat /etc/group": (_Cat.EXPLORATION, 5),
    "cat /etc/hosts": (_Cat.EXPLORATION, 4),
    "cat /etc/hostname": (_Cat.EXPLORATION, 3),
    "cat /etc/resolv.conf": (_Cat.EXPLORATION, 4),
    "cat /etc/crontab": (_Cat.EXPLORATION, 6),
    "crontab -l": (_Cat.EXPLORATION, 5),
    "ls -la /home": (_Cat.EXPLORATION, 4),
    "ls -la /root": (_Cat.EXPLORATION, 5),
    "ls /root": (_Cat.EXPLORATION, 4),
    "ls -la /var/log": (_Cat.EXPLORATION, 4),
    "ls /var/log": (_Cat.EXPLORATION, 4),
    "cat /var/log/auth.log": (_Cat.EXPLORATION, 7),
    "cat /var/log/syslog": (_Cat.EXPLORATION, 5),
    "cat /var/log/wtmp": (_Cat.EXPLORATION, 5),
    "find / -name": (_Cat.EXPLORATION, 6),
    "find / -perm": (_Cat.EXPLORATION, 8),
    "find / -writable": (_Cat.EXPLORATION, 7),
    "find / -type f -name *.conf": (_Cat.EXPLORATION, 6),
    "locate": (_Cat.EXPLORATION, 5),
    "which": (_Cat.EXPLORATION, 2),
    "dpkg -l": (_Cat.EXPLORATION, 4),
    "rpm -qa": (_Cat.EXPLORATION, 4),
    "cat /etc/issue": (_Cat.EXPLORATION, 3),
    "cat /etc/fstab": (_Cat.EXPLORATION, 4),
    "systemctl list-units": (_Cat.EXPLORATION, 5),
    "service --status-all": (_Cat.EXPLORATION, 5),

    # -- LEVEL 3: Privilege Escalation (delta 8-15) -------------------------
    "sudo -l": (_Cat.PRIVILEGE_ESC, 10),
    "sudo su": (_Cat.PRIVILEGE_ESC, 12),
    "sudo su -": (_Cat.PRIVILEGE_ESC, 12),
    "sudo bash": (_Cat.PRIVILEGE_ESC, 12),
    "sudo sh": (_Cat.PRIVILEGE_ESC, 12),
    "sudo -i": (_Cat.PRIVILEGE_ESC, 12),
    "su": (_Cat.PRIVILEGE_ESC, 8),
    "su root": (_Cat.PRIVILEGE_ESC, 10),
    "su -": (_Cat.PRIVILEGE_ESC, 10),
    "cat /etc/shadow": (_Cat.PRIVILEGE_ESC, 12),
    "cat /etc/sudoers": (_Cat.PRIVILEGE_ESC, 12),
    "cat /etc/sudoers.d": (_Cat.PRIVILEGE_ESC, 10),
    "passwd": (_Cat.PRIVILEGE_ESC, 8),
    "chmod 777": (_Cat.PRIVILEGE_ESC, 8),
    "chmod +s": (_Cat.PRIVILEGE_ESC, 12),
    "chmod 4755": (_Cat.PRIVILEGE_ESC, 12),
    "chown root": (_Cat.PRIVILEGE_ESC, 10),
    "find / -perm -4000": (_Cat.PRIVILEGE_ESC, 12),
    "find / -perm -u=s": (_Cat.PRIVILEGE_ESC, 12),
    "find / -suid": (_Cat.PRIVILEGE_ESC, 12),
    "find / -sgid": (_Cat.PRIVILEGE_ESC, 10),
    "cat /etc/pam.d": (_Cat.PRIVILEGE_ESC, 8),
    "getcap -r /": (_Cat.PRIVILEGE_ESC, 10),

    # -- LEVEL 4: Exfiltration / Weaponisation (delta 14-25) ----------------
    "wget": (_Cat.EXFILTRATION, 15),
    "curl": (_Cat.EXFILTRATION, 15),
    "nc": (_Cat.EXFILTRATION, 20),
    "netcat": (_Cat.EXFILTRATION, 20),
    "ncat": (_Cat.EXFILTRATION, 20),
    "scp": (_Cat.EXFILTRATION, 16),
    "rsync": (_Cat.EXFILTRATION, 14),
    "ftp": (_Cat.EXFILTRATION, 14),
    "tftp": (_Cat.EXFILTRATION, 16),
    "python -c": (_Cat.EXFILTRATION, 18),
    "python3 -c": (_Cat.EXFILTRATION, 18),
    "perl -e": (_Cat.EXFILTRATION, 18),
    "ruby -e": (_Cat.EXFILTRATION, 16),
    "php -r": (_Cat.EXFILTRATION, 16),
    "bash -i": (_Cat.EXFILTRATION, 22),
    "sh -i": (_Cat.EXFILTRATION, 22),
    "/dev/tcp": (_Cat.EXFILTRATION, 25),
    "/dev/udp": (_Cat.EXFILTRATION, 25),
    "mkfifo": (_Cat.EXFILTRATION, 20),
    "base64": (_Cat.EXFILTRATION, 8),
    "xxd": (_Cat.EXFILTRATION, 6),

    # -- LATERAL MOVEMENT (delta 8-20) --------------------------------------
    "ssh": (_Cat.LATERAL_MOVEMENT, 15),
    "ssh-keygen": (_Cat.LATERAL_MOVEMENT, 10),
    "cat ~/.ssh": (_Cat.LATERAL_MOVEMENT, 12),
    "cat /root/.ssh": (_Cat.LATERAL_MOVEMENT, 15),
    "ls ~/.ssh": (_Cat.LATERAL_MOVEMENT, 10),
    "ls /root/.ssh": (_Cat.LATERAL_MOVEMENT, 12),
    "cat ~/.ssh/id_rsa": (_Cat.LATERAL_MOVEMENT, 15),
    "cat ~/.ssh/authorized_keys": (_Cat.LATERAL_MOVEMENT, 12),
    "arp": (_Cat.LATERAL_MOVEMENT, 8),
    "arp -a": (_Cat.LATERAL_MOVEMENT, 8),
    "nmap": (_Cat.LATERAL_MOVEMENT, 18),
    "masscan": (_Cat.LATERAL_MOVEMENT, 20),
    "ping": (_Cat.LATERAL_MOVEMENT, 3),
}

# ---------------------------------------------------------------------------
# Layer 2 -- Binary name fallback scores
# ---------------------------------------------------------------------------

BINARY_SCORES: Dict[str, Tuple[CommandCategory, int]] = {
    "wget": (_Cat.EXFILTRATION, 15),
    "curl": (_Cat.EXFILTRATION, 15),
    "nc": (_Cat.EXFILTRATION, 20),
    "netcat": (_Cat.EXFILTRATION, 20),
    "ncat": (_Cat.EXFILTRATION, 20),
    "nmap": (_Cat.LATERAL_MOVEMENT, 18),
    "masscan": (_Cat.LATERAL_MOVEMENT, 20),
    "python": (_Cat.EXFILTRATION, 10),
    "python3": (_Cat.EXFILTRATION, 10),
    "perl": (_Cat.EXFILTRATION, 12),
    "ruby": (_Cat.EXFILTRATION, 10),
    "php": (_Cat.EXFILTRATION, 10),
    "gcc": (_Cat.EXFILTRATION, 8),
    "cc": (_Cat.EXFILTRATION, 8),
    "make": (_Cat.EXFILTRATION, 8),
    "sudo": (_Cat.PRIVILEGE_ESC, 8),
    "su": (_Cat.PRIVILEGE_ESC, 8),
    "chmod": (_Cat.PRIVILEGE_ESC, 6),
    "chown": (_Cat.PRIVILEGE_ESC, 6),
    "chgrp": (_Cat.PRIVILEGE_ESC, 4),
    "find": (_Cat.EXPLORATION, 4),
    "locate": (_Cat.EXPLORATION, 4),
    "ssh": (_Cat.LATERAL_MOVEMENT, 12),
    "scp": (_Cat.EXFILTRATION, 16),
    "rsync": (_Cat.EXFILTRATION, 14),
    "ftp": (_Cat.EXFILTRATION, 14),
    "tftp": (_Cat.EXFILTRATION, 16),
    "ssh-keygen": (_Cat.LATERAL_MOVEMENT, 10),
    "ssh-copy-id": (_Cat.LATERAL_MOVEMENT, 12),
    "arp": (_Cat.LATERAL_MOVEMENT, 8),
    "base64": (_Cat.EXFILTRATION, 8),
    "xxd": (_Cat.EXFILTRATION, 6),
    "hexdump": (_Cat.EXFILTRATION, 5),
    "mkfifo": (_Cat.EXFILTRATION, 20),
    "passwd": (_Cat.PRIVILEGE_ESC, 8),
    "crontab": (_Cat.EXPLORATION, 5),
    "systemctl": (_Cat.EXPLORATION, 4),
    "service": (_Cat.EXPLORATION, 4),
    "ping": (_Cat.LATERAL_MOVEMENT, 3),
    "traceroute": (_Cat.LATERAL_MOVEMENT, 5),
    "dig": (_Cat.LATERAL_MOVEMENT, 4),
    "nslookup": (_Cat.LATERAL_MOVEMENT, 4),
    "tar": (_Cat.EXFILTRATION, 5),
    "zip": (_Cat.EXFILTRATION, 5),
    "gzip": (_Cat.EXFILTRATION, 4),
}

# ---------------------------------------------------------------------------
# Argument-based escalators -- substring match adds bonus
# ---------------------------------------------------------------------------

ARGUMENT_ESCALATORS: Dict[str, int] = {
    "/etc/shadow": 8,
    "/etc/sudoers": 8,
    "/etc/sudoers.d": 6,
    "/root/.ssh": 10,
    "/.ssh/id_rsa": 10,
    "/.ssh/id_ed25519": 10,
    "/.ssh/authorized_keys": 8,
    "/dev/tcp": 15,
    "/dev/udp": 15,
    "-perm -4000": 8,
    "-perm -u=s": 8,
    "-suid": 8,
    "4755": 8,
    "777": 5,
    "+s": 5,
    "+x": 3,
    "base64": 6,
    "xxd": 5,
    "hexdump": 5,
    "/etc/pam.d": 5,
    "id_rsa": 8,
    ".bash_history": 5,
    ".env": 6,
    "credentials": 6,
    "password": 5,
    "config.php": 5,
    "wp-config": 6,
    "database.yml": 5,
    ".git/config": 5,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _threat_level_from_score(score: int) -> ThreatLevel:
    """Map a cumulative score (0-100) to a threat level."""
    if score <= 20:
        return ThreatLevel.LOW
    if score <= 50:
        return ThreatLevel.MEDIUM
    if score <= 80:
        return ThreatLevel.HIGH
    return ThreatLevel.CRITICAL


_PERSONA_ORDER = ["generic_linux", "dev_workstation", "finance_server"]


# ---------------------------------------------------------------------------
# Pattern detector
# ---------------------------------------------------------------------------

class PatternDetector:
    """Detects multi-command attack patterns across session history.

    Patterns add bonus score when detected for the first time in a session.
    """

    def detect(
        self,
        command_history: List[dict],
        new_command: str,
        already_detected: set[str],
    ) -> List[Tuple[str, int]]:
        """Return ``[(pattern_name, bonus_score)]`` for newly detected patterns.

        Args:
            command_history: Previous commands (each dict has at least ``"raw"``).
            new_command: The current command being scored.
            already_detected: Patterns already fired in this session --
                each pattern fires only once.

        Returns:
            List of ``(name, bonus)`` tuples for *newly* detected patterns.
        """
        history = [c.get("raw", "") for c in command_history]
        all_cmds = history + [new_command]
        results: List[Tuple[str, int]] = []

        def _emit(name: str, bonus: int) -> None:
            if name not in already_detected:
                results.append((name, bonus))

        def _binary(cmd: str) -> str:
            parts = cmd.strip().split()
            return parts[0] if parts else ""

        # 1) Rapid recon burst: 5+ recon commands in last 10
        recent = all_cmds[-10:]
        recon_count = sum(1 for c in recent if self._is_recon(c))
        if recon_count >= 5:
            _emit("rapid_recon_burst", 8)

        # 2) Privilege escalation chain: 2+ priv-esc indicators in last 5
        priv_indicators = ("sudo", "/etc/shadow", "/etc/sudoers", "passwd")
        priv_hits = sum(
            1 for c in all_cmds[-5:]
            if any(p in c for p in priv_indicators)
            or c.strip() in ("su", "su -", "su root")
        )
        if priv_hits >= 2:
            _emit("privilege_escalation_chain", 12)

        # 3) Credential harvesting: passwd + shadow in same session
        has_passwd = any("passwd" in c for c in all_cmds)
        has_shadow = any("shadow" in c for c in all_cmds)
        if has_passwd and has_shadow:
            _emit("credential_harvesting", 15)

        # 4) SSH key theft
        if any(".ssh" in c for c in all_cmds):
            if any(k in " ".join(all_cmds) for k in ("id_rsa", "id_ed25519", "authorized_keys")):
                _emit("ssh_key_theft_attempt", 12)

        # 5) Download-and-execute
        has_download = any(_binary(c) in ("wget", "curl") for c in all_cmds)
        has_execute = any(
            any(e in c for e in ("chmod +x", "chmod 755", "bash ", "sh ", "./"))
            for c in all_cmds[-5:]
        )
        if has_download and has_execute:
            _emit("download_and_execute", 20)

        # 6) Network mapping: netstat/ss + arp
        has_net_enum = any(_binary(c) in ("netstat", "ss") for c in all_cmds)
        has_arp = any("arp" in c for c in all_cmds)
        if has_net_enum and has_arp:
            _emit("network_mapping", 10)

        # 7) Active network scan
        if any(_binary(c) in ("nmap", "masscan") for c in all_cmds):
            _emit("active_network_scan", 18)

        # 8) Persistence attempt: 2+ persistence-related commands
        persistence_kw = ("crontab", "cron.d", "rc.local", "systemd",
                          ".bashrc", ".profile", "/etc/init.d")
        p_count = sum(1 for c in all_cmds if any(k in c for k in persistence_kw))
        if p_count >= 2:
            _emit("persistence_attempt", 15)

        # 9) Data staging: find + compress
        has_find_data = any(
            _binary(c) == "find" and ("-size" in c or "-name" in c) for c in all_cmds
        )
        has_compress = any(_binary(c) in ("tar", "zip", "gzip", "bzip2") for c in all_cmds)
        if has_find_data and has_compress:
            _emit("data_staging", 15)

        return results

    @staticmethod
    def _is_recon(cmd: str) -> bool:
        """Quick check whether a command is reconnaissance-level."""
        recon_binaries = {
            "whoami", "id", "uname", "hostname", "arch", "w", "who",
            "last", "df", "free", "ifconfig", "netstat", "ss", "ps",
            "env", "printenv", "mount", "lsblk", "lscpu",
        }
        binary = cmd.strip().split()[0] if cmd.strip() else ""
        return binary in recon_binaries


# ---------------------------------------------------------------------------
# Persona switch decider
# ---------------------------------------------------------------------------

class PersonaSwitchDecider:
    """Decides whether and where to switch personas based on threat state.

    Rules:
        1. Never switch backward (finance -> dev -> generic is forbidden).
        2. Max 2 switches per session to avoid suspicion.
        3. Certain dangerous patterns force an immediate step-up.
    """

    MAX_SWITCHES = 2

    def should_switch(
        self,
        current_persona: str,
        new_score: int,
        switch_count: int,
        patterns: List[str],
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Evaluate whether a persona switch is needed.

        Args:
            current_persona: The currently active persona name.
            new_score: Cumulative threat score after the latest command.
            switch_count: How many switches have already occurred.
            patterns: Pattern names detected this command.

        Returns:
            ``(should_switch, target_persona, reason)``
        """
        if switch_count >= self.MAX_SWITCHES:
            return False, None, None

        current_idx = (
            _PERSONA_ORDER.index(current_persona)
            if current_persona in _PERSONA_ORDER
            else 0
        )

        if new_score >= 81 and current_idx < 2:
            return (
                True,
                "finance_server",
                f"Critical threat score ({new_score}) -- escalating to high-value target",
            )

        if new_score >= 51 and current_idx < 1:
            return (
                True,
                "dev_workstation",
                f"High threat score ({new_score}) -- escalating to developer environment",
            )

        force_patterns = {
            "download_and_execute",
            "credential_harvesting",
            "privilege_escalation_chain",
        }
        for p in patterns:
            if p in force_patterns and current_idx < 2:
                target = _PERSONA_ORDER[min(current_idx + 1, 2)]
                return True, target, f"Dangerous pattern detected: {p}"

        return False, None, None


# ---------------------------------------------------------------------------
# ThreatScorer -- main entry point
# ---------------------------------------------------------------------------

class ThreatScorer:
    """Scores commands and maintains threat state for a session.

    Typical usage::

        scorer = ThreatScorer()
        decision = scorer.score_command("cat /etc/shadow", session)
        # decision.new_total_score, decision.threat_level, etc.
    """

    def __init__(self) -> None:
        self._pattern_detector = PatternDetector()
        self._switch_decider = PersonaSwitchDecider()

    def score_command(
        self,
        raw_command: str,
        session: _SessionLike,
    ) -> ThreatDecision:
        """Classify and score a single command in context.

        Args:
            raw_command: The raw string the attacker typed.
            session: Any object with ``command_history`` (list[dict]),
                ``threat_score`` (int), ``active_persona`` (str),
                ``persona_switch_count`` (int), and
                ``patterns_detected`` (set[str]).

        Returns:
            A fully populated ``ThreatDecision``.
        """
        stripped = raw_command.strip()
        previous_score: int = getattr(session, "threat_score", 0)
        history: List[dict] = getattr(session, "command_history", [])
        current_persona: str = getattr(session, "active_persona", "generic_linux")
        switch_count: int = getattr(session, "persona_switch_count", 0)
        detected: set = getattr(session, "patterns_detected", set())

        category, base_delta = self._classify(stripped)

        arg_bonus = self._argument_bonus(stripped)
        raw_delta = base_delta + arg_bonus

        new_patterns = self._pattern_detector.detect(history, stripped, detected)
        pattern_bonus = sum(bonus for _, bonus in new_patterns)
        pattern_names = [name for name, _ in new_patterns]

        total_delta = raw_delta + pattern_bonus
        new_score = min(previous_score + total_delta, 100)
        threat_level = _threat_level_from_score(new_score)

        seen_categories = {
            c.get("category", "benign") for c in history
        }
        is_first = category.value not in seen_categories and category != _Cat.BENIGN

        should_switch, switch_target, switch_reason = self._switch_decider.should_switch(
            current_persona, new_score, switch_count, pattern_names,
        )

        return ThreatDecision(
            command_raw=stripped,
            command_category=category,
            score_delta=total_delta,
            previous_score=previous_score,
            new_total_score=new_score,
            threat_level=threat_level,
            trigger_persona_switch=should_switch,
            switch_to_persona=switch_target,
            switch_reason=switch_reason,
            patterns_detected=pattern_names,
            is_first_of_category=is_first,
        )

    # ---- classification layers --------------------------------------------

    @staticmethod
    def _classify(command: str) -> Tuple[CommandCategory, int]:
        """Two-layer classification: exact match then binary fallback."""

        if command in EXACT_MATCH_SCORES:
            return EXACT_MATCH_SCORES[command]

        # Try progressively shorter prefixes for partial exact matches.
        # e.g. "cat /etc/shadow" matches even if typed as
        # "cat /etc/shadow 2>/dev/null".
        for key, value in EXACT_MATCH_SCORES.items():
            if len(key) > 3 and command.startswith(key):
                return value

        binary = command.split()[0] if command else ""
        if binary in BINARY_SCORES:
            return BINARY_SCORES[binary]

        return CommandCategory.BENIGN, 0

    @staticmethod
    def _argument_bonus(command: str) -> int:
        """Sum escalator bonuses for any matching argument substrings."""
        bonus = 0
        for pattern, score in ARGUMENT_ESCALATORS.items():
            if pattern in command:
                bonus += score
        return bonus


# ---------------------------------------------------------------------------
# Typing helper -- avoids importing the real Session class
# ---------------------------------------------------------------------------

class _SessionLike:
    """Structural type hint for objects the scorer reads from."""
    command_history: List[dict]
    threat_score: int
    active_persona: str
    persona_switch_count: int
    patterns_detected: set
