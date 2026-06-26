"""Interactive Honeypot Shell — be the attacker.

Opens an interactive terminal that looks and behaves like a real Linux
shell.  Every command you type passes through the full honeypot pipeline
(FakeFS -> Dictionary/LLM -> Threat Scorer -> Persona Switcher) and the
results are pushed to the live dashboard in real time.

Usage:
    # Terminal 1 — start the backend + dashboard
    python -m uvicorn dashboard.app:app --port 8080

    # Terminal 2 — start the Next.js frontend
    npm run dev

    # Terminal 3 — be the attacker
    python scripts/interactive_honeypot.py

    Open http://localhost:3000 in a browser and watch the dashboard
    update as you type commands.

Flags:
    --ip 1.2.3.4        Spoof the attacker IP (default: random from pool)
    --persona NAME      Starting persona (default: generic_linux)
    --no-dashboard      Skip dashboard connection
    --no-score          Hide threat score after each command
"""
from __future__ import annotations

import argparse
import random
import signal
import sys
import time
from pathlib import Path

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

LEVEL_COLORS = {"low": GREEN, "medium": YELLOW, "high": ORANGE, "critical": RED}

IP_POOL = [
    "185.220.101.42", "45.137.21.9", "103.97.176.5",
    "194.26.29.118", "61.177.173.12", "212.70.149.71",
    "159.223.44.190", "92.118.39.84", "5.188.206.18",
]

# ---------------------------------------------------------------------------
# Dashboard client
# ---------------------------------------------------------------------------
DASHBOARD_URL = "http://127.0.0.1:8080"


def _post(endpoint: str, data: dict) -> bool:
    try:
        r = requests.post(f"{DASHBOARD_URL}{endpoint}", json=data, timeout=2)
        return r.status_code == 200
    except Exception:
        return False


def _dashboard_alive() -> bool:
    try:
        r = requests.get(f"{DASHBOARD_URL}/api/stats", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Threat level from score
# ---------------------------------------------------------------------------
def _level(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Interactive Honeypot Shell")
    parser.add_argument("--ip", default=None, help="Attacker IP to spoof")
    parser.add_argument("--persona", default="generic_linux", help="Starting persona")
    parser.add_argument("--no-dashboard", action="store_true", help="Skip dashboard")
    parser.add_argument("--no-score", action="store_true", help="Hide score display")
    args = parser.parse_args()

    attacker_ip = args.ip or random.choice(IP_POOL)
    use_dashboard = not args.no_dashboard
    show_score = not args.no_score

    # Banner
    print(f"\n{BOLD}{CYAN}{'=' * 64}")
    print(f"  ADAPTIVE HONEYPOT - Interactive Shell")
    print(f"  You are the attacker. Type commands. Watch the dashboard.")
    print(f"{'=' * 64}{RESET}\n")

    # Dashboard check
    dashboard_ok = False
    if use_dashboard:
        dashboard_ok = _dashboard_alive()
        if dashboard_ok:
            print(f"  {GREEN}[+] Dashboard connected at {DASHBOARD_URL}{RESET}")
            print(f"  {GREEN}[+] Open http://localhost:3000 to watch live{RESET}")
        else:
            print(f"  {YELLOW}[!] Dashboard not running — console-only mode{RESET}")
            print(f"  {DIM}    Start it: python -m uvicorn dashboard.app:app --port 8080{RESET}")

    print(f"\n  {DIM}Attacker IP : {attacker_ip}")
    print(f"  Persona    : {args.persona}")
    print(f"  Type 'exit' or Ctrl+C to quit{RESET}\n")

    # Create dispatcher
    sess_logger = SessionLogger(
        log_dir=str(PROJECT_ROOT / "event_logging" / "logs"),
        logger_name="interactive_session",
    )
    dispatcher = create_dispatcher(
        attacker_ip=attacker_ip,
        attacker_port=random.randint(30000, 60000),
        persona_name=args.persona,
        session_logger=sess_logger,
    )
    session_id = dispatcher.session_id

    # Register session with dashboard
    if dashboard_ok:
        _post("/api/dashboard/clear", {})
        _post("/api/session/start", {
            "session_id": session_id,
            "attacker_ip": attacker_ip,
            "persona": args.persona,
        })
        _post("/api/fingerprint", {"score": 19, "total": 22})

    prev_persona = args.persona
    running = True

    def handle_sigint(sig, frame):
        nonlocal running
        running = False
        print(f"\n\n{DIM}  Connection closed by remote host.{RESET}\n")

    signal.signal(signal.SIGINT, handle_sigint)

    # Interactive loop
    while running:
        try:
            prompt = dispatcher.prompt
            raw = input(f"{GREEN}{prompt}{RESET}")
        except (EOFError, KeyboardInterrupt):
            print(f"\n{DIM}  Connection closed by remote host.{RESET}\n")
            break

        raw = raw.strip()
        if not raw:
            continue
        if raw.lower() in ("exit", "logout", "quit"):
            print(f"{DIM}logout{RESET}")
            print(f"{DIM}Connection to {dispatcher.fakefs.hostname} closed.{RESET}")
            break

        # Dispatch through the full pipeline
        response, source = dispatcher.dispatch(raw)

        # Print response
        if response.strip():
            print(response)

        # Get threat info
        session = dispatcher.session
        score = session.threat_score
        level = _level(score)
        history = session.command_history
        last_entry = history[-1] if history else {}
        delta = last_entry.get("score_delta", 0)
        category = last_entry.get("category", "benign")
        persona = dispatcher.persona_name

        # Show score bar (subtle, below the output)
        if show_score:
            lc = LEVEL_COLORS.get(level, GREEN)
            filled = int(score / 100 * 20)
            bar = f"{'#' * filled}{'.' * (20 - filled)}"
            delta_str = f"+{delta}" if delta > 0 else str(delta)
            print(f"{DIM}  [{bar}] {lc}{score}/100{RESET} {DIM}({delta_str} {category}){RESET}")

        # Persona switch
        if persona != prev_persona:
            print(f"\n  {BOLD}{ORANGE}>>> PERSONA SWITCH: {prev_persona} -> {persona}{RESET}")
            print(f"  {ORANGE}    System is now presenting as a different environment{RESET}\n")
            if dashboard_ok:
                _post("/api/session/switch", {
                    "session_id": session_id,
                    "from_persona": prev_persona,
                    "to_persona": persona,
                    "trigger_score": score,
                })
            prev_persona = persona

        # Push to dashboard
        if dashboard_ok:
            _post("/api/session/command", {
                "session_id": session_id,
                "command": raw,
                "score_after": score,
                "score_delta": delta,
                "category": category,
                "threat_level": level,
                "persona": persona,
                "response_source": source,
            })

    # Cleanup
    dispatcher.close()
    if dashboard_ok:
        _post("/api/session/end", {"session_id": session_id})

    # Summary
    print(f"\n{BOLD}  Session Summary{RESET}")
    print(f"  {'-' * 40}")
    print(f"  Commands : {len(dispatcher.session.command_history)}")
    lc = LEVEL_COLORS.get(level, GREEN)
    print(f"  Score    : {lc}{score}/100 ({level.upper()}){RESET}")
    print(f"  Persona  : {persona}")
    print()


if __name__ == "__main__":
    main()
