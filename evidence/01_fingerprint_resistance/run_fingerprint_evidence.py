"""Run the 22-check fingerprint resistance suite and produce evidence artifacts.

Outputs:
  - fingerprint_report.json   (detailed per-check results + Cowrie comparison)
  - fingerprint_summary.md    (categorised summary table)
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tests.fingerprint_tests.fingerprint_checker import FingerprintChecker

CATEGORIES = {
    "Timing Realism": [
        "timing_simple_cmd",
        "timing_complex_cmd",
        "timing_variance",
    ],
    "Filesystem Consistency": [
        "cross_ref_passwd_whoami",
        "cross_ref_hostname",
        "cross_ref_ls_cat",
        "cross_ref_home_passwd",
        "file_timestamps_past",
    ],
    "Process & Network Realism": [
        "cross_ref_ps_netstat",
        "proc_version_match",
        "pid_realistic",
        "process_count_realistic",
    ],
    "Session & Environment Realism": [
        "uptime_increases",
        "bash_history_realistic",
        "history_has_content",
        "env_vars_realistic",
    ],
    "Write-Operation Fidelity": [
        "mkdir_cd_works",
        "touch_cat_works",
        "write_persists",
    ],
    "Cowrie Signature Avoidance": [
        "no_cowrie_banner",
        "no_empty_commands",
        "shadow_permission",
    ],
}

CHECK_DESCRIPTIONS = {
    "timing_simple_cmd":        "Response to 'ls' under 200 ms",
    "timing_complex_cmd":       "Response to 'find /' has realistic jitter (>10 ms)",
    "timing_variance":          "Repeated identical commands have timing variance",
    "cross_ref_passwd_whoami":  "whoami result appears in /etc/passwd",
    "cross_ref_hostname":       "hostname == /etc/hostname == uname -n",
    "cross_ref_ps_netstat":     "ps aux processes match netstat listening ports",
    "cross_ref_ls_cat":         "Files shown by ls are readable with cat",
    "cross_ref_home_passwd":    "/etc/passwd home-dir users exist under /home",
    "proc_version_match":       "uname -r kernel matches uname -a output",
    "uptime_increases":         "uptime output contains realistic 'up' string",
    "pid_realistic":            "PIDs in ps aux have gaps (not sequential from 1)",
    "bash_history_realistic":   ".bash_history contains plausible commands",
    "file_timestamps_past":     "All file timestamps are in the past",
    "process_count_realistic":  "ps aux shows >3 processes",
    "mkdir_cd_works":           "mkdir dir && cd dir succeeds (session overlay)",
    "touch_cat_works":          "touch file && cat file succeeds (session overlay)",
    "write_persists":           "echo data > file && cat file returns data",
    "no_cowrie_banner":         "No 'cowrie' string in env or hostname",
    "no_empty_commands":        "Empty command returns empty output (not error)",
    "history_has_content":      "history returns prior session commands",
    "env_vars_realistic":       "env contains USER, PATH, HOME",
    "shadow_permission":        "cat /etc/shadow returns content or permission denied",
}


def main() -> None:
    out_dir = Path(__file__).resolve().parent
    ts = datetime.now(tz=timezone.utc)

    print("=" * 72)
    print("  Automated fingerprint-detection self-test")
    print("  (22 known Cowrie / honeypot-detection techniques)")
    print(f"  {ts.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 72)

    checker = FingerprintChecker()

    # ── Run against our system ──────────────────────────────────────────
    print("\n>>> Running 22 checks against our adaptive honeypot ...\n")
    our_results = checker.run_all_checks()
    our_map = {r.name: r for r in our_results}

    # ── Cowrie expected baseline (documented behaviour, NOT live test) ──
    cowrie_results = checker.run_against_cowrie_baseline()
    cowrie_map = {r.name: r for r in cowrie_results}

    our_passed = sum(1 for r in our_results if r.passed)
    cowrie_passed = sum(1 for r in cowrie_results if r.passed)

    # ── Console output (terminal-screenshot friendly) ───────────────────
    for cat_name, checks in CATEGORIES.items():
        cat_our = sum(1 for c in checks if our_map.get(c) and our_map[c].passed)
        cat_cow = sum(1 for c in checks if cowrie_map.get(c) and cowrie_map[c].passed)
        print(f"\n  [{cat_name}]  Our system {cat_our}/{len(checks)}  |  Cowrie {cat_cow}/{len(checks)}")
        print(f"  {'Check':<42s} {'Ours':<8s} {'Cowrie':<8s} Detail")
        print("  " + "-" * 90)
        for chk in checks:
            our = our_map.get(chk)
            cow = cowrie_map.get(chk)
            ours_s = "PASS" if (our and our.passed) else "FAIL"
            cow_s  = "PASS" if (cow and cow.passed) else "FAIL"
            detail = our.actual if our else "N/A"
            print(f"  {chk:<42s} {ours_s:<8s} {cow_s:<8s} {detail}")

    print("\n" + "=" * 72)
    print(f"  TOTAL:  Our system  {our_passed}/22   |   Cowrie expected  {cowrie_passed}/22")
    print(f"  (Cowrie scores are expected results from documented behaviour, not a live test)")
    print(f"  Improvement over expected Cowrie:  +{our_passed - cowrie_passed} checks")
    print("=" * 72)

    # ── JSON report ─────────────────────────────────────────────────────
    json_data = {
        "title": "Automated fingerprint-detection self-test (22 known Cowrie/honeypot-detection techniques)",
        "generated_at": ts.isoformat(),
        "our_system": {
            "total_checks": 22,
            "passed": our_passed,
            "failed": 22 - our_passed,
            "categories": {},
            "results": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "expected": r.expected,
                    "actual": r.actual,
                    "notes": r.notes,
                }
                for r in our_results
            ],
        },
        "cowrie_baseline": {
            "total_checks": 22,
            "passed": cowrie_passed,
            "failed": 22 - cowrie_passed,
            "results": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "expected": r.expected,
                    "actual": r.actual,
                    "notes": r.notes,
                }
                for r in cowrie_results
            ],
        },
    }

    for cat_name, checks in CATEGORIES.items():
        cat_our = sum(1 for c in checks if our_map.get(c) and our_map[c].passed)
        json_data["our_system"]["categories"][cat_name] = {
            "passed": cat_our,
            "total": len(checks),
        }

    json_path = out_dir / "fingerprint_report.json"
    json_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")
    print(f"\n  Saved: {json_path}")

    # ── Markdown summary ────────────────────────────────────────────────
    md_lines = [
        "# Fingerprint Resistance Report",
        "",
        "> **Automated fingerprint-detection self-test "
        "(22 known Cowrie / honeypot-detection techniques)**",
        ">",
        f"> Generated: {ts.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Overall Result",
        "",
        f"| System | Passed | Failed | Score |",
        f"|--------|--------|--------|-------|",
        f"| **Our Adaptive Honeypot** | {our_passed} | {22 - our_passed} | **{our_passed}/22** |",
        f"| Vanilla Cowrie (expected*) | {cowrie_passed} | {22 - cowrie_passed} | {cowrie_passed}/22 |",
        "",
        f"**Improvement over Cowrie:** +{our_passed - cowrie_passed} checks",
        "",
        "---",
        "",
        "## Results by Category",
        "",
    ]

    for cat_name, checks in CATEGORIES.items():
        cat_our = sum(1 for c in checks if our_map.get(c) and our_map[c].passed)
        cat_cow = sum(1 for c in checks if cowrie_map.get(c) and cowrie_map[c].passed)
        md_lines.append(f"### {cat_name}  ({cat_our}/{len(checks)} passed)")
        md_lines.append("")
        md_lines.append("| # | Check | Description | Ours | Cowrie | Detail |")
        md_lines.append("|---|-------|-------------|------|--------|--------|")
        for i, chk in enumerate(checks, 1):
            our = our_map.get(chk)
            cow = cowrie_map.get(chk)
            ours_s = "PASS" if (our and our.passed) else "FAIL"
            cow_s  = "PASS" if (cow and cow.passed) else "FAIL"
            desc = CHECK_DESCRIPTIONS.get(chk, "")
            detail = (our.actual if our else "N/A").replace("|", "\\|")
            md_lines.append(f"| {i} | `{chk}` | {desc} | {ours_s} | {cow_s} | {detail} |")
        md_lines.append("")

    md_lines.extend([
        "---",
        "",
        "## Methodology",
        "",
        "Each of the 22 checks targets a specific technique that real attackers or",
        "automated scanners use to detect honeypots (particularly Cowrie-based ones).",
        "The test suite runs all checks **deterministically against the local",
        "HoneypotCommandDispatcher** — no network, no SSH, no LLM API calls.",
        "(*) Cowrie scores are **expected results** based on documented Cowrie behaviour",
        "(source code analysis + Vetterl & Clayton 2018), **not** from running these",
        "checks against a live Cowrie instance. Direct measurement is Phase-3 future work.",
        "",
        "Cowrie baseline scores are based on documented vanilla Cowrie behaviour.",
        "",
        "Categories:",
        "",
        "- **Timing Realism** — honeypots often respond too fast or with zero variance",
        "- **Filesystem Consistency** — cross-referencing /etc/passwd, hostnames, file listings",
        "- **Process & Network Realism** — PID gaps, process counts, port/process agreement",
        "- **Session & Environment Realism** — uptime, bash_history, env vars, command history",
        "- **Write-Operation Fidelity** — mkdir/touch/echo persistence via session overlay",
        "- **Cowrie Signature Avoidance** — known Cowrie fingerprints (banner, empty commands, etc.)",
    ])

    md_path = out_dir / "fingerprint_summary.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    print(f"  Saved: {md_path}")


if __name__ == "__main__":
    main()
