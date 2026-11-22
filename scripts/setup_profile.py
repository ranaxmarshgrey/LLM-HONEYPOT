#!/usr/bin/env python3
"""Install-time profile personalisation.

Collects user identity (name, username, role, org, interests) and writes
``profile.yaml``. Then calls the profile generator to produce
``personas/profile.json`` and ``personas/profile_escalation.json``.

Usage:
    python scripts/setup_profile.py                 # interactive prompts
    python scripts/setup_profile.py --from profile.yaml  # non-interactive
"""
from __future__ import annotations

import argparse
import hashlib
import random
import re
import sys
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_VALID_ROLES = {"student", "developer", "other"}


def _suggest_username(full_name: str) -> str:
    """Derive a plausible Linux username from a full name."""
    parts = full_name.lower().split()
    parts = [re.sub(r"[^a-z0-9]", "", p) for p in parts]
    parts = [p for p in parts if p]
    if not parts:
        return "user"
    if len(parts) == 1:
        return parts[0][:32]
    candidate = parts[0][0] + parts[-1]
    return candidate[:32]


def _validate_username(username: str) -> str | None:
    """Return an error message if the username is invalid, else None."""
    if not _USERNAME_RE.match(username):
        return (
            f"Invalid username '{username}'. Must match ^[a-z_][a-z0-9_-]{{0,31}}$"
        )
    return None


def _make_seed(full_name: str, username: str) -> int:
    """Derive a deterministic seed from identity."""
    blob = f"{full_name}:{username}".encode()
    return int(hashlib.sha256(blob).hexdigest()[:8], 16)


def _prompt(label: str, default: str = "", required: bool = True) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"  {label}{suffix}: ").strip()
        if not value:
            value = default
        if value or not required:
            return value
        print("    (required)")


def _prompt_choice(label: str, choices: list[str], default: str = "") -> str:
    display = "/".join(
        f"[{c}]" if c == default else c for c in choices
    )
    while True:
        value = input(f"  {label} ({display}): ").strip().lower()
        if not value:
            value = default
        if value in choices:
            return value
        print(f"    Choose one of: {', '.join(choices)}")


def _prompt_list(label: str, max_items: int = 3) -> list[str]:
    raw = input(f"  {label} (comma-separated, up to {max_items}, or Enter to skip): ").strip()
    if not raw:
        return []
    items = [s.strip() for s in raw.split(",") if s.strip()]
    return items[:max_items]


def collect_interactive() -> dict:
    """Collect profile fields via interactive prompts."""
    print("\n  === Adaptive Honeypot — Profile Setup ===\n")

    full_name = _prompt("Full name")
    suggested = _suggest_username(full_name)
    username = _prompt(f"Username", default=suggested)

    err = _validate_username(username)
    while err:
        print(f"    {err}")
        username = _prompt("Username")
        err = _validate_username(username)

    role = _prompt_choice("Role", ["student", "developer", "other"], default="student")
    role_description = ""
    if role == "other":
        role_description = _prompt("Describe your role briefly", required=False)

    org = _prompt("Organization (college/company)", required=False)
    interests = _prompt_list("Interests (e.g. web-dev, ML, networking)")

    seed = _make_seed(full_name, username)

    profile = {
        "full_name": full_name,
        "username": username,
        "role": role,
        "role_description": role_description,
        "org": org,
        "interests": interests,
        "hostname": f"{username}-laptop",
        "uid": 1000,
        "seed": seed,
    }
    return profile


def load_from_file(path: str) -> dict:
    """Load a profile from a YAML file and validate required fields."""
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        raise ValueError(f"profile.yaml must be a YAML mapping, got {type(data).__name__}")

    required = ["full_name", "username", "role"]
    for field in required:
        if field not in data or not data[field]:
            raise ValueError(f"Missing required field: {field}")

    err = _validate_username(data["username"])
    if err:
        raise ValueError(err)

    if data["role"] not in _VALID_ROLES:
        raise ValueError(f"role must be one of {_VALID_ROLES}, got {data['role']!r}")

    data.setdefault("role_description", "")
    data.setdefault("org", "")
    data.setdefault("interests", [])
    data.setdefault("hostname", f"{data['username']}-laptop")
    data.setdefault("uid", 1000)

    if "seed" not in data:
        data["seed"] = _make_seed(data["full_name"], data["username"])

    return data


def save_profile(profile: dict, path: Path) -> None:
    """Write profile.yaml."""
    with open(path, "w", encoding="utf-8") as fh:
        yaml.dump(profile, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)


def _ask_llm_content() -> bool:
    """Ask the user whether to use LLM for file contents."""
    while True:
        answer = input("  Use LLM to write file contents? [Y/n]: ").strip().lower()
        if answer in ("", "y", "yes"):
            return True
        if answer in ("n", "no"):
            return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Adaptive Honeypot Profile Setup")
    parser.add_argument(
        "--from", dest="from_file", metavar="FILE",
        help="Load profile from a YAML file instead of interactive prompts",
    )
    parser.add_argument(
        "--llm-content", action="store_true", default=False,
        help="Use LLM to generate realistic file contents for the profile",
    )
    args = parser.parse_args()

    if args.from_file:
        profile = load_from_file(args.from_file)
        print(f"  Loaded profile from {args.from_file}")
    else:
        profile = collect_interactive()

    # Determine LLM content mode
    use_llm = args.llm_content
    if not args.from_file and not args.llm_content:
        use_llm = _ask_llm_content()

    profile_path = PROJECT_ROOT / "profile.yaml"
    save_profile(profile, profile_path)
    print(f"\n  Profile saved to {profile_path}")

    # Generate persona files
    from honeypot.profile_generator import generate_profile_persona

    persona_path = PROJECT_ROOT / "personas" / "profile.json"
    escalation_path = PROJECT_ROOT / "personas" / "profile_escalation.json"

    generate_profile_persona(profile, persona_path, escalation_path)
    print(f"  Generated {persona_path}")
    print(f"  Generated {escalation_path}")

    # LLM content generation (optional)
    if use_llm:
        import json
        from honeypot.profile_llm_content import generate_llm_contents, format_summary_table

        print("\n  Generating LLM-written file contents...")
        with open(persona_path, "r", encoding="utf-8") as fh:
            persona_data = json.load(fh)

        filesystem, report = generate_llm_contents(profile, persona_data["filesystem"])
        persona_data["filesystem"] = filesystem

        # Re-validate and write
        from honeypot.fakefs import Persona
        from honeypot.persona_validator import validate as _validate_persona
        from datetime import datetime, timezone

        Persona.model_validate(persona_data)
        errors = _validate_persona(persona_data, datetime.now(tz=timezone.utc))
        if errors:
            print(f"\n  WARNING: Validation errors after LLM content:")
            for e in errors:
                print(f"    - {e}")
        else:
            with open(persona_path, "w", encoding="utf-8") as fh:
                json.dump(persona_data, fh, indent=2, ensure_ascii=False)

        # Write generation report
        report_path = PROJECT_ROOT / "personas" / "profile_generation_report.json"
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)

        print(f"\n{format_summary_table(report)}")
        print(f"\n  Report saved to {report_path}")

    print("\n  Done! The honeypot will use this profile on next start.\n")


if __name__ == "__main__":
    main()
