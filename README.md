# Adaptive LLM-Powered Honeypot

**B.Tech Capstone Phase-2 (PW26\_SVM\_03)**
PES University, Bengaluru | Guide: Dr. Sapna V M

**Team:**
Kavya R Chengalath (PES1UG23CS295) | Kiran Kumar B D (PES1UG23CS306) | Keerthi A H (PES1UG23CS296) | Jayanth Gowda (PES1UG23CS263)

---

## What This System Does

A cybersecurity deception system (honeypot) that exposes an SSH server to the internet and responds to attackers like a real Linux machine. Every response is generated from a **Fake File System (FakeFS)** — the single source of truth — so the attacker sees a consistent, believable environment across every command they type.

The system scores attacker behaviour in real-time. As an attacker becomes more dangerous, the system **gradually morphs the environment** around them — from a generic web server to a developer workstation to a finance production server — planting increasingly valuable-looking fake data (credentials, API keys, SSH keys) to keep them engaged and collect intelligence.

The attacker never sees a "switch." They think they discovered something deeper.

### Core Innovation

All five components (SSH gateway, response engine, fake filesystem, threat scorer, persona switcher) work together in real-time. The LLM never invents facts — it is always grounded in FakeFS state. Persona switching is gradual over 3–5 commands, not abrupt.

---

## Architecture

```
Attacker SSH ──► Cowrie (port 2222) ──► cowrie_hook.py (per-session dispatcher)
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    │                         │                         │
              ResponseEngine           ThreatScorer           PersonaSwitcher
              (65 fast-path             (120+ exact,           (gradual 5-phase
               handlers, or             45+ binary,             transition via
               LLM slow path)           9 attack patterns)      session overlay)
                    │                         │                         │
                    └────────────┬────────────┴─────────────────────────┘
                                 │
                              FakeFS  (single source of truth)
                                 │
                          Session Overlay  (per-session write layer)
                                 │
                          Event Logger  (JSON-lines to honeypot.jsonl)
```

### How a Command Flows

1. Attacker types a command over SSH (e.g. `cat /etc/passwd`)
2. **Cowrie** captures the raw input and passes it to `cowrie_hook.py`
3. The **Command Parser** tokenizes the input, handling pipes (`|`), chains (`;`, `&&`), redirects (`>`, `>>`), and subcommands
4. The **Response Engine** tries the **fast path** first — 65 registered command handlers that query FakeFS directly (< 50ms latency)
5. If no handler exists, the **LLM slow path** fires — it builds a grounded prompt from FakeFS state + session context and calls the LLM API (Gemini → OpenRouter → Anthropic fallback chain)
6. The **Threat Scorer** classifies the command (benign / reconnaissance / privilege escalation / exfiltration) and updates the session's cumulative threat score
7. If the score crosses a threshold (51 or 81), the **Persona Switcher** begins a gradual transition — planting new files, processes, and credentials into the session overlay over 3–5 subsequent commands
8. Everything is logged to `event_logging/logs/honeypot.jsonl` with response source, latency, threat score, persona transitions, and decoy access events

### Module Map

| Module | File | Purpose |
|--------|------|---------|
| SSH Gateway | Cowrie (external) | Raw SSH protocol, authentication |
| Cowrie Hook | `honeypot/cowrie_hook.py` | Per-session dispatcher, wires everything together |
| Response Engine | `honeypot/response_engine.py` | Fast-path dictionary + LLM fallback with provider chain |
| FakeFS | `honeypot/fakefs.py` | Single source of truth for all system state |
| Session Overlay | `honeypot/session_overlay.py` | Per-session write layer (mkdir, touch, rm, cp, mv, wget) |
| Command Parser | `honeypot/command_parser.py` | Shell command tokenization, pipes, chains, redirects |
| Threat Scorer | `honeypot/threat_scorer.py` | Two-layer command classification, 9 attack patterns |
| Persona Switcher | `honeypot/persona_switcher.py` | Gradual 5-phase persona transition engine |
| IP Reputation | `honeypot/ip_reputation.py` | AbuseIPDB async integration |
| Persona Validator | `honeypot/persona_validator.py` | 8 consistency rules enforced on every persona |
| Profile Generator | `honeypot/profile_generator.py` | Generates personalised personas from user identity |
| LLM Content Gen | `honeypot/profile_llm_content.py` | LLM-written file contents at setup time |
| Session Logger | `event_logging/session_logger.py` | Enriched JSON-lines structured logging |
| Command Handlers | `dictionary/command_handlers.py` | 65 fast-path handler functions |
| Command Registry | `dictionary/command_registry.py` | Command name → handler mapping + aliases |
| Live Monitor | `monitor/live_monitor.py` | Rich TUI defender dashboard |
| Log Parser | `monitor/log_parser.py` | Event stream parser with session state tracking |

---

## Personas

The system ships with three built-in personas that represent escalating levels of value to an attacker, plus an optional personalised profile mode.

| Persona | Hostname | User | Trigger | What It Looks Like |
|---------|----------|------|---------|-------------------|
| generic\_linux | web-srv-03 | ubuntu | Default (score 0–50) | Basic cloud VM running nginx |
| dev\_workstation | dev-workstation-07 | john.dev | Score ≥ 51 | Developer machine with API keys, Docker, .env files |
| finance\_server | fin-db-prod-01 | finapp | Score ≥ 81 | Production finance DB with credentials and reports |
| **profile** (opt-in) | *your-name*-laptop | *your-username* | HONEYPOT\_PROFILE=1 | Personalised to your identity, role, and interests |

### Profile Mode

When `HONEYPOT_PROFILE=1` is set, the honeypot uses a persona generated from your identity instead of the generic defaults. On first run, it prompts for:

- **Name and username** — drives hostname, home directory, PS1 prompt, /etc/passwd
- **Role** (student / developer / other) — determines file layout, processes, bash history
- **Organization** — appears in SSH configs, git configs, lab hostnames
- **Interests** — creates themed project directories with realistic content

With `--llm-content`, the setup uses an LLM to write realistic file contents (notes, READMEs, todo lists) personalised to the profile. These are frozen into the persona JSON at setup time — no LLM calls happen during an attack session.

---

## LLM Provider Chain

The system uses LLMs in two places: runtime command handling (slow path) and setup-time file content generation. Both use the same provider fallback chain:

```
Gemini (GEMINI_API_KEY) → OpenRouter (OPENROUTER_API_KEY) → Anthropic (OPENROUTER_API_KEY)
```

| Provider | Env Var | Default Model | Notes |
|----------|---------|---------------|-------|
| Google Gemini | `GEMINI_API_KEY` | gemini-3.5-flash-lite | Free tier, fastest |
| OpenRouter | `OPENROUTER_API_KEY` | google/gemini-2.5-flash | Aggregator, many models available |
| Anthropic | `ANTHROPIC_API_KEY` | claude-sonnet-4 | Requires paid API access |

**The system works without any API key.** The 65 fast-path handlers cover virtually all commands an attacker would type. The LLM is only needed for truly exotic commands.

---

## Threat Scoring

The threat scorer uses a two-layer classification system:

**Layer 1 — Exact command matching** (120+ entries):
```
whoami: 1 | id: 1 | ls: 1 | uname: 2 | cat /etc/passwd: 6 | cat /etc/shadow: 8
sudo: 10 | cat /etc/sudoers: 12 | wget: 15 | curl: 15 | nc: 20 | bash -i: 20
```

**Layer 2 — Pattern matching** (9 attack patterns):
- Reverse shell attempts (`/dev/tcp`, `bash -i >& /dev/tcp`)
- Privilege escalation (`chmod 4755`, `find -perm -4000`)
- Credential harvesting (`cat /etc/shadow`, `.ssh/id_rsa`)
- Network reconnaissance (`nmap`, `masscan`)
- Data exfiltration (`scp`, `rsync`, `base64`)
- Persistence mechanisms (`crontab -e`, `.bashrc` modification)
- Lateral movement (`ssh`, `telnet` to internal IPs)
- C2 communication (`curl | bash`, `wget | sh`)
- Container escape (`docker.sock`, `nsenter`)

**Threat thresholds:**
| Score | Level | Action |
|-------|-------|--------|
| 0–50 | LOW | Generic Linux persona |
| 51–80 | HIGH | Transition to dev\_workstation (or profile stage 1) |
| 81–100 | CRITICAL | Transition to finance\_server (or profile stage 2) |

---

## Persona Switching (Gradual Transition)

When the threat score crosses a threshold, the persona switcher runs a **5-phase transition** over 3–5 commands:

1. **Seeding** — First new files appear in the session overlay (a directory, a config file)
2. **Building** — More files drip in (credentials, SSH keys, .env files)
3. **Completing** — Final high-value decoys planted (AWS creds, database configs)
4. **Done** — Transition complete, all decoys in place

The attacker's session state (command history, threat score, any files they created) is **fully preserved** across the transition. Files they created with `mkdir` or `touch` survive. Nothing they've seen disappears — the transition is strictly additive.

The LLM prompt is updated to reflect the new persona, so even slow-path responses match the new identity.

---

## Quick Start

### 1. Clone and Install

```bash
git clone <repo-url>
cd adaptive-honeypot
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### 2. Configure API Keys (Optional)

```bash
cp .env.example .env
# Edit .env — set at least one LLM API key:
#   GEMINI_API_KEY=...        (Google AI Studio, free tier)
#   OPENROUTER_API_KEY=...    (OpenRouter, free/paid models)
#   ANTHROPIC_API_KEY=...     (Anthropic, paid API)
#
# Without any key, the 65 fast-path handlers still work for all common commands.
```

### 3. Run the Interactive Shell (Be the Attacker)

```bash
python scripts/interactive_honeypot.py
```

This opens an interactive terminal that looks and behaves like a real SSH session. Every command passes through the full pipeline (FakeFS → Dictionary/LLM → Threat Scorer → Persona Switcher). A threat score bar shows after each command.

### 4. Profile Mode (Personalised Honeypot)

```bash
# Option A: Setup via interactive prompts
python scripts/setup_profile.py                     # template content
python scripts/setup_profile.py --llm-content       # LLM-written file contents

# Option B: Auto-setup on first run
export HONEYPOT_PROFILE=1    # or set in .env
python scripts/interactive_honeypot.py
# → prompts for name/role/org on first run, then starts the shell
```

### 5. Live Defender Monitor

```bash
# Live tail — watches the event log in real-time
python -m monitor --log event_logging/logs/honeypot.jsonl

# Replay a recorded session
python -m monitor --log event_logging/logs/honeypot.jsonl --replay --session <session-id>
```

The monitor shows 5 panels: session header, live command feed (colour-coded by source), threat gauge, escalation timeline, and decoy access alerts.

### 6. Run Tests

```bash
pytest -q                                   # full suite (1418 tests)
pytest -q --ignore=tests/test_fingerprint.py  # skip LLM-dependent fingerprint tests
pytest tests/test_consistency.py -v          # FakeFS consistency checks only
```

---

## Directory Structure

```
adaptive-honeypot/
├── honeypot/                       Core system modules
│   ├── cowrie_hook.py              Per-session dispatcher (the real session layer)
│   ├── response_engine.py          Fast path + LLM path with provider chain
│   ├── fakefs.py                   FakeFS — single source of truth
│   ├── session_overlay.py          Per-session write layer (mkdir, touch, rm, etc.)
│   ├── command_parser.py           Shell command tokenizer (pipes, chains, redirects)
│   ├── threat_scorer.py            Two-layer command classification + 9 patterns
│   ├── persona_switcher.py         Gradual 5-phase transition engine
│   ├── persona_validator.py        8 consistency rules for persona JSON
│   ├── profile_generator.py        Personalised persona generator from user identity
│   ├── profile_llm_content.py      LLM-written file contents (setup-time only)
│   ├── ip_reputation.py            AbuseIPDB async integration
│   └── session_manager.py          Session state model (spec)
│
├── dictionary/                     Fast-path command handlers
│   ├── command_handlers.py         65 handler functions (all FakeFS-grounded)
│   └── command_registry.py         Command name → handler map + aliases
│
├── personas/                       Persona JSON definitions
│   ├── generic_linux.json          Default: basic cloud VM
│   ├── dev_workstation.json        Stage 1: developer machine
│   ├── finance_server.json         Stage 2: finance production DB
│   ├── profile.json                Generated (gitignored): personalised persona
│   ├── profile_escalation.json     Generated (gitignored): personalised escalation stages
│   └── profile_generation_report.json  Generated (gitignored): LLM content report
│
├── monitor/                        Defender TUI monitor
│   ├── live_monitor.py             Rich 5-panel TUI with live tailing + replay mode
│   ├── log_parser.py               Event stream parser with session state tracking
│   ├── __main__.py                 CLI entry point (python -m monitor)
│   └── __init__.py
│
├── event_logging/                  Structured logging
│   ├── session_logger.py           Enriched JSON-lines (source, latency, transitions, decoys)
│   └── logs/                       Log output (gitignored)
│
├── scripts/
│   ├── interactive_honeypot.py     Interactive attacker shell with first-run auto-setup
│   ├── setup_profile.py            Profile setup (interactive + --from YAML + --llm-content)
│   ├── build_generic_linux_persona.py
│   ├── build_dev_workstation_persona.py
│   └── build_finance_server_persona.py
│
├── cowrie_integration/             Cowrie patching
│   ├── install_hook.sh             Patches Cowrie protocol.py
│   └── cowrie_command_patch.py     Bridge module
│
├── tests/                          Test suite (1418 tests)
│   ├── test_consistency.py         FakeFS cross-reference checks (all 3 personas)
│   ├── test_command_handlers.py    Handler correctness across all personas
│   ├── test_command_registry.py    Registry completeness + alias mapping
│   ├── test_response_engine.py     Engine integration, provider detection, post-processing
│   ├── test_threat_scorer.py       Scoring accuracy, patterns, thresholds
│   ├── test_persona_switcher.py    Transition phases, overlay preservation
│   ├── test_live_path_persona.py   End-to-end persona switching through dispatcher
│   ├── test_event_enrichment.py    Enriched event logging (sources, latency, transitions)
│   ├── test_profile_mode.py        Profile generation and validation
│   ├── test_profile_llm_content.py LLM content generation (all mocked, no network)
│   ├── test_monitor.py             Log parser, panel renderers, log tailer
│   ├── test_fingerprint.py         Honeypot fingerprint resistance checks
│   └── ...                         Session overlay, IP reputation, write commands, etc.
│
├── .env.example                    Environment variable template
├── .gitignore
├── CLAUDE.md                       Architect briefing (project spec)
├── README.md                       This file
└── requirements.txt
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| SSH | Cowrie (Python) |
| Backend | Python 3.11+ |
| Data Models | Pydantic v2 |
| FakeFS Storage | JSON (one per persona) |
| LLM APIs | Gemini / OpenRouter / Anthropic Claude |
| IP Reputation | AbuseIPDB (free tier) |
| HTTP Client | httpx (async) |
| Logging | JSON-lines, enriched events |
| Defender Monitor | Rich (TUI library) |
| Testing | pytest (1418 tests) |
| Deployment | Ubuntu 22.04 VM |

---

## Event Logging

All attacker interactions are logged to `event_logging/logs/honeypot.jsonl` with enriched fields:

```json
{
  "event_type": "command",
  "session_id": "abc123",
  "attacker_ip": "185.220.101.42",
  "command": "cat /etc/shadow",
  "response_source": "fakefs",
  "latency_ms": 12,
  "threat_score": 34,
  "persona": "generic_linux",
  "timestamp": "2026-11-23T10:15:42Z"
}
```

**Response sources:** `dict` (fast-path handler), `fakefs` (file read handler), `llm_primary` (Gemini/OpenRouter), `llm_fallback` (Anthropic fallback), `error` (handler exception)

**Special event types:**
- `persona_transition` — logged when the persona switcher advances a phase, includes `from_stage`, `to_stage`, `phase`, and `paths_added`
- `decoy_access` — logged when the attacker reads a file that was planted during persona transition

---

## Evaluation Metrics

| Metric | Method |
|--------|--------|
| **Fingerprint Resistance** | 22 known honeypot fingerprinting checks — our system vs. vanilla Cowrie |
| **FakeFS Consistency** | Cross-reference test suite: ls → cat /etc/passwd → ps aux → verify all outputs agree |
| **Command Depth** | Track how many sessions progress to Level 3+ attack commands vs. Cowrie baseline |

---

## Development Rules

1. **FakeFS is always consulted before responding** — no module invents system facts
2. **No hardcoded strings for system facts** — always query FakeFS
3. **Every LLM call has a timeout and fallback** — 3s runtime, 15s setup-time
4. **Session state is append-only** — command history is never overwritten
5. **Persona switches never reset session state** — history, score, overlay all preserved
6. **Attacker data never leaves `event_logging/`** — never printed to stdout in production
7. **All API keys from environment variables only** — never hardcoded
8. **Tests after every change** — 1418 tests, all passing
