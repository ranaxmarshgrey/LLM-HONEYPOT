"""Interactive Honeypot Shell — be the attacker.

Opens an interactive terminal that looks and behaves like a real Linux
shell.  Every command you type passes through the full honeypot pipeline
(FakeFS -> Dictionary/LLM -> Threat Scorer -> Persona Switcher).

Usage:
    python scripts/interactive_honeypot.py

Flags:
    --ip 1.2.3.4        Spoof the attacker IP (default: random from pool)
    --persona NAME      Starting persona (default: generic_linux)
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

from dotenv import load_dotenv
load_dotenv()

import os
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
def _ensure_profile() -> None:
    """If HONEYPOT_PROFILE=1 but no profile.json exists, run first-time setup."""
    if os.environ.get("HONEYPOT_PROFILE", "").strip() != "1":
        return

    profile_json = PROJECT_ROOT / "personas" / "profile.json"
    if profile_json.exists():
        return

    print(f"\n{BOLD}{MAGENTA}{'=' * 64}")
    print(f"  FIRST-TIME SETUP")
    print(f"  Your honeypot needs an identity. Answer a few questions")
    print(f"  so the system knows what to look like to attackers.")
    print(f"{'=' * 64}{RESET}\n")

    from scripts.setup_profile import collect_interactive, save_profile, _ask_llm_content
    from honeypot.profile_generator import generate_profile_persona

    profile = collect_interactive()
    use_llm = _ask_llm_content()

    profile_path = PROJECT_ROOT / "profile.yaml"
    save_profile(profile, profile_path)

    persona_path = PROJECT_ROOT / "personas" / "profile.json"
    escalation_path = PROJECT_ROOT / "personas" / "profile_escalation.json"
    generate_profile_persona(profile, persona_path, escalation_path)

    if use_llm:
        import json as _json
        from honeypot.profile_llm_content import generate_llm_contents, format_summary_table

        print(f"\n  {DIM}Generating LLM-written file contents...{RESET}")
        with open(persona_path, "r", encoding="utf-8") as fh:
            persona_data = _json.load(fh)

        filesystem, report = generate_llm_contents(profile, persona_data["filesystem"])
        persona_data["filesystem"] = filesystem

        from honeypot.fakefs import Persona
        from honeypot.persona_validator import validate as _validate_persona
        from datetime import datetime, timezone

        Persona.model_validate(persona_data)
        errors = _validate_persona(persona_data, datetime.now(tz=timezone.utc))
        if not errors:
            with open(persona_path, "w", encoding="utf-8") as fh:
                _json.dump(persona_data, fh, indent=2, ensure_ascii=False)

        report_path = PROJECT_ROOT / "personas" / "profile_generation_report.json"
        with open(report_path, "w", encoding="utf-8") as fh:
            _json.dump(report, fh, indent=2, ensure_ascii=False)

        print(format_summary_table(report))

    print(f"\n  {GREEN}Profile created!{RESET}")
    print(f"  {DIM}Honeypot will appear as: {profile['username']}@{profile['hostname']}")
    print(f"  Role: {profile['role']}{RESET}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Interactive Honeypot Shell")
    parser.add_argument("--ip", default=None, help="Attacker IP to spoof")
    parser.add_argument("--persona", default="generic_linux", help="Starting persona")
    parser.add_argument("--no-score", action="store_true", help="Hide score display")
    args = parser.parse_args()

    _ensure_profile()

    attacker_ip = args.ip or random.choice(IP_POOL)
    show_score = not args.no_score

    # Banner
    print(f"\n{BOLD}{CYAN}{'=' * 64}")
    print(f"  ADAPTIVE HONEYPOT - Interactive Shell")
    print(f"  You are the attacker. Type commands.")
    print(f"{'=' * 64}{RESET}\n")

    print(f"  {DIM}Attacker IP : {attacker_ip}")
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
            prev_persona = persona

    # Cleanup
    dispatcher.close()

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
