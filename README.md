# Adaptive LLM-Powered Honeypot

B.Tech Capstone Phase-2 (PW26\_SVM\_03), PES University, Bengaluru
Guide: Dr. Sapna V M

**Team:**
Kavya R Chengalath (PES1UG23CS295) | Kiran Kumar B D (PES1UG23CS306) | Keerthi A H (PES1UG23CS296) | Jayanth Gowda (PES1UG23CS263)

---

## What This System Does

A cybersecurity deception system that exposes an SSH server to the internet and responds to attackers like a real Linux machine. Every response is generated from a Fake File System (FakeFS) — the single source of truth — so the attacker sees a consistent, believable environment.

The system scores attacker behaviour in real-time. As an attacker becomes more dangerous, the system gradually morphs the environment around them — from a generic web server to a developer workstation to a finance production server — planting increasingly valuable-looking fake data to keep them engaged and collect intelligence.

The attacker never sees a "switch." They think they discovered something deeper.

---

## Architecture

```
Attacker SSH -> Cowrie (port 2222) -> cowrie_hook.py (per-session dispatcher)
                                          |
                    +---------------------+---------------------+
                    |                     |                     |
              ResponseEngine         ThreatScorer        PersonaSwitcher
              (fast path: 40+        (120+ exact,        (gradual 5-step
               handlers, or          45+ binary,          transition via
               LLM slow path)        9 patterns)          session overlay)
                    |                     |                     |
                    +----------+----------+---------------------+
                               |
                            FakeFS  (single source of truth)
                               |
                        Session Overlay  (per-session write layer)
```

### Core Modules

| Module | File | Purpose |
|--------|------|---------|
| SSH Gateway | Cowrie (external) | Raw SSH protocol, authentication |
| Cowrie Hook | `honeypot/cowrie_hook.py` | Per-session dispatcher, wires everything together |
| Response Engine | `honeypot/response_engine.py` | Fast-path dictionary + LLM fallback |
| FakeFS | `honeypot/fakefs.py` | Single source of truth for all system state |
| Session Overlay | `honeypot/session_overlay.py` | Per-session write layer (mkdir, touch, rm, wget) |
| Command Parser | `honeypot/command_parser.py` | Shell command tokenization, pipes, chains |
| Threat Scorer | `honeypot/threat_scorer.py` | Two-layer command classification, 9 attack patterns |
| Persona Switcher | `honeypot/persona_switcher.py` | Gradual persona transition engine |
| IP Reputation | `honeypot/ip_reputation.py` | AbuseIPDB async integration |
| Session Logger | `event_logging/session_logger.py` | JSON-lines structured logging |
| Command Handlers | `dictionary/command_handlers.py` | 40+ fast-path handlers |

### Personas

| Persona | Hostname | User | Trigger | What It Looks Like |
|---------|----------|------|---------|-------------------|
| generic\_linux | web-srv-03 | ubuntu | Default | Basic cloud VM |
| dev\_workstation | dev-workstation-07 | john.dev | Score >= 51 | Developer machine with API keys |
| finance\_server | fin-db-prod-01 | finapp | Score >= 81 | Production finance server |

---

## Quick Start

```bash
# 1. Clone and install
git clone <repo-url>
cd adaptive-honeypot
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# 2. (Optional) Configure LLM API key for slow-path commands
cp .env.example .env
# Edit .env: GEMINI_API_KEY=... or ANTHROPIC_API_KEY=...
# Without a key, the fast-path (40+ commands) still works fine

# 3. Be the attacker
python scripts/interactive_honeypot.py
```

### Run Tests

```bash
pytest -q
```

### Deploy to a Linux VM (with real SSH)

See [DEPLOYMENT.md](DEPLOYMENT.md) for full instructions.

```bash
bash scripts/deploy.sh ubuntu@YOUR_VM_IP --first-run
```

---

## Directory Structure

```
adaptive-honeypot/
|-- honeypot/                    Core system modules
|   |-- cowrie_hook.py           Per-session dispatcher
|   |-- response_engine.py      Fast path + LLM path
|   |-- fakefs.py                Single source of truth
|   |-- session_overlay.py       Per-session write layer
|   |-- command_parser.py        Shell command parser
|   |-- session_manager.py       Session state tracking
|   |-- threat_scorer.py         Command classification
|   |-- persona_switcher.py      Gradual transition engine
|   |-- ip_reputation.py         AbuseIPDB integration
|   |-- persona_validator.py     8 consistency rules
|
|-- dictionary/                  Fast-path command handlers
|   |-- command_handlers.py      40+ handler functions
|   |-- command_registry.py      Command name -> handler map
|
|-- personas/                    Persona JSON definitions
|   |-- generic_linux.json
|   |-- dev_workstation.json
|   |-- finance_server.json
|
|-- event_logging/               Structured logging
|   |-- session_logger.py        JSON-lines with daily rotation
|   |-- logs/                    Log output (gitignored)
|
|-- scripts/
|   |-- interactive_honeypot.py  Interactive attacker shell
|   |-- setup.sh                 VM setup
|   |-- deploy.sh                Deployment script
|
|-- cowrie_integration/          Cowrie patching
|   |-- install_hook.sh          Patches Cowrie protocol.py
|   |-- cowrie_command_patch.py   Bridge module
|
|-- tests/                       Test suite
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| SSH | Cowrie |
| Backend | Python 3.11+ |
| Data Models | Pydantic v2 |
| FakeFS Storage | JSON (one per persona) |
| LLM API | Gemini / Anthropic Claude |
| IP Reputation | AbuseIPDB (free tier) |
| HTTP Client | httpx (async) |
| Logging | JSON-lines, daily rotation |
| Testing | pytest |
| Deployment | Ubuntu 22.04 VM |
