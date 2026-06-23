# CLAUDE.md — Adaptive LLM-Powered Honeypot
## Project Architect Briefing for Claude Code

---

## 1. PROJECT IDENTITY

**Project Name:** Adaptive LLM-Powered Honeypot with Behavioural Mimicry and Threat-Intelligence–Driven Persona Switching

**Academic Context:** B.Tech Capstone Project Phase-2, PES University, Bengaluru
- Project ID: PW26_SVM_03
- Guide: Dr. Sapna V M

**Team:**
- Kavya R Chengalath (PES1UG23CS295) — FakeFS + Persona Templates
- Kiran Kumar B D (PES1UG23CS306) — LLM Response Engine + Prompt Engineering
- Keerthi A H (PES1UG23CS296) — Threat Scoring + Session Manager
- Jayanth Gowda (PES1UG23CS263) — Cowrie Setup + Logging + Dashboard

---

## 2. WHAT THIS SYSTEM IS

A cybersecurity deception system (honeypot) that:

1. **Attracts real attackers** via an exposed SSH server
2. **Responds like a real Linux system** using LLM-generated, context-aware shell output
3. **Maintains internal consistency** through a Fake File System (FakeFS) that is the single source of truth for all responses
4. **Scores attacker threat level** in real-time based on commands executed, session behaviour, and IP reputation
5. **Switches system "personas"** gradually and seamlessly when threat thresholds are crossed — e.g., from a generic Linux host to a finance server

**The core innovation:** All five components work together in real-time. The LLM never invents facts — it is always grounded in FakeFS state. Persona switching is gradual, not abrupt.

---

## 3. WHAT THIS SYSTEM IS NOT

- NOT a real production server — it is a decoy
- NOT a system that executes real commands — all responses are simulated
- NOT built from scratch SSH — we use Cowrie as the SSH base layer
- NOT using local LLMs — we use API-based LLMs (Anthropic Claude or OpenAI GPT-4)
- NOT using Kubernetes in Phase-2 — that is future work

---

## 4. SYSTEM ARCHITECTURE — 5 MODULES

```
Internet / Real Attacker
         │
         ▼
┌─────────────────────┐
│   MODULE 1          │
│   SSH Gateway       │  ← Cowrie handles raw SSH protocol
│   (Cowrie)          │    Captures every keystroke
└────────┬────────────┘
         │ command stream
         ▼
┌─────────────────────┐
│   MODULE 2          │
│   Session Manager   │  ← Tracks: current directory, command history,
│                     │    session threat score, active persona
└────────┬────────────┘
         │ enriched command context
         ▼
┌─────────────────────┐     ┌─────────────────────┐
│   MODULE 3          │────▶│   MODULE 4          │
│   Response Engine   │     │   FakeFS            │
│                     │◀────│                     │
│  Fast path:         │     │  Single source of   │
│  dictionary lookup  │     │  truth for all      │
│                     │     │  system state:      │
│  Slow path:         │     │  - directory tree   │
│  LLM API call       │     │  - file contents    │
│  (grounded in       │     │  - process list     │
│   FakeFS state)     │     │  - users/groups     │
└────────┬────────────┘     │  - network state    │
         │                  │  - persona config   │
         │                  └──────────┬──────────┘
         │                             │
         ▼                             ▼
┌─────────────────────────────────────────────────┐
│   MODULE 5                                      │
│   Threat Scorer + Persona Switcher              │
│                                                 │
│   - Classifies each command into threat level   │
│   - Accumulates session threat score            │
│   - Checks IP reputation (AbuseIPDB API)        │
│   - Triggers persona switch at thresholds       │
│   - Updates FakeFS with new persona state       │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
            ┌─────────────────┐
            │   LOGGING +     │
            │   DASHBOARD     │
            │                 │
            │  - All sessions │
            │  - Threat scores│
            │  - Command logs │
            │  - Persona state│
            └─────────────────┘
```

---

## 5. MODULE SPECIFICATIONS

### Module 1: SSH Gateway (Cowrie)
- **Technology:** Cowrie SSH honeypot (Python)
- **Role:** Handle raw SSH protocol, authentication (always accept after N attempts), session lifecycle
- **Our customisation:** Hook into Cowrie's command handler to intercept commands BEFORE Cowrie processes them, pass to our Response Engine, return our response instead of Cowrie's default
- **Key files to modify in Cowrie:** `cowrie/shell/command.py`, `cowrie/commands/`
- **Port:** Listen on 2222 (redirect 22→2222 via iptables)
- **Do NOT modify:** Cowrie's SSH handshake, authentication flow, session tracking

### Module 2: Session Manager
- **Technology:** Python class, Redis or in-memory dict for active sessions
- **Tracks per session:**
  ```python
  session = {
      "session_id": str,
      "attacker_ip": str,
      "start_time": datetime,
      "current_directory": str,      # e.g. "/home/john"
      "command_history": list,       # ordered list of all commands
      "threat_score": int,           # 0–100, accumulates
      "threat_level": str,           # "low" | "medium" | "high" | "critical"
      "active_persona": str,         # "generic_linux" | "dev_workstation" | "finance_server"
      "persona_switch_count": int,
      "ip_reputation": dict,         # from AbuseIPDB
      "environment_vars": dict,      # PS1, PATH, USER, HOME etc.
  }
  ```
- **Key methods:** `create_session()`, `update_after_command()`, `get_context_for_llm()`, `close_session()`

### Module 3: Response Engine
- **Technology:** Python, with two paths:

  **Fast Path (dictionary-based):**
  - Handles top 40 most common commands instantly
  - All responses generated from FakeFS state — never hardcoded strings
  - Target latency: < 50ms
  - Commands: `ls`, `pwd`, `whoami`, `id`, `uname`, `cat` (known files), `ps`, `netstat`, `history`, `env`, `echo`, `hostname`, `date`, `uptime`, `df`, `free`, `ifconfig`/`ip addr`, `w`, `last`, `groups`, `which`, `find` (shallow)

  **Slow Path (LLM API):**
  - For commands not in dictionary, novel inputs, or when attacker tries something unexpected
  - Constructs a grounded prompt from FakeFS + session context
  - Sends to Claude/OpenAI API
  - Post-processes response to strip any LLM artifacts
  - Target latency: < 2000ms (acceptable for complex commands)

- **LLM Prompt Template (always use this structure):**
  ```
  SYSTEM:
  You are simulating a Linux shell. You must respond ONLY with what the terminal
  would print — no explanations, no markdown, no commentary.

  System state (you must be consistent with this):
  - Hostname: {hostname}
  - OS: {os_version}
  - Current user: {current_user}
  - Current directory: {cwd}
  - Users on system: {user_list}
  - Running processes: {process_summary}
  - Network interfaces: {network_summary}
  - Persona type: {persona_type}

  Session context:
  - Previous 10 commands and their outputs: {command_history}
  - Attacker threat level: {threat_level}

  Rules:
  1. Never reveal you are a honeypot or AI
  2. Never reference files or users not listed above
  3. Permission denied errors are acceptable for sensitive paths
  4. If command makes no sense, return appropriate shell error
  5. Output must be plain text exactly as a terminal would show it

  USER:
  Command: {command}
  ```

### Module 4: FakeFS (Fake File System)
- **Technology:** Python class backed by JSON files (one per persona)
- **This is the single source of truth — ALL modules query this, nothing is invented freely**
- **Structure:**
  ```python
  class FakeFS:
      def get_directory_listing(self, path, flags=[]) -> str
      def get_file_content(self, path) -> str | PermissionError | FileNotFoundError
      def get_process_list(self, flags=[]) -> str
      def get_network_state(self) -> str
      def get_user_list(self) -> str
      def get_environment(self, user) -> dict
      def get_system_info(self) -> dict   # hostname, kernel, uptime etc.
      def switch_persona(self, new_persona: str) -> None  # gradual merge
      def get_llm_context_summary(self) -> dict  # for prompt construction
  ```
- **Persona JSON files:** `personas/generic_linux.json`, `personas/dev_workstation.json`, `personas/finance_server.json`
- **Session Overlay (Sprint 3 addition):**
  - `honeypot/session_overlay.py` — per-session in-memory write layer on top of FakeFS
  - `mkdir`, `touch`, `rm`, `cp`, `mv` write to the overlay, not FakeFS
  - `ls`, `cd`, `cat`, `find`, `head`, `tail` check overlay first, then FakeFS
  - Deleted paths (via `rm`) are hidden from FakeFS reads
  - Overlay is discarded when the session ends — nothing persists
  - This makes `mkdir foo && cd foo` work convincingly without modifying persona JSON
  - Each session gets its own independent overlay (attacker A's changes are invisible to attacker B)

- **Consistency rules enforced by FakeFS:**
  - File modification times are always in the past
  - File sizes match file content length
  - Users in `/etc/passwd` match users in `/home/`
  - Process owners are valid users
  - PIDs are realistic (not sequential from 1)

### Module 5: Threat Scorer + Persona Switcher
- **Technology:** Python, with AbuseIPDB API integration

- **Command threat taxonomy:**
  ```python
  COMMAND_WEIGHTS = {
      # Level 1 — Basic Reconnaissance (score: 1-3)
      "whoami": 1, "id": 1, "ls": 1, "pwd": 1, "uname": 2,
      "hostname": 1, "date": 1, "uptime": 1,

      # Level 2 — System Exploration (score: 3-8)
      "cat /etc/passwd": 6, "cat /etc/shadow": 8,
      "ps aux": 3, "netstat": 4, "ss": 4,
      "find": 4, "locate": 3, "env": 3,

      # Level 3 — Privilege Escalation Attempts (score: 8-15)
      "sudo": 10, "su": 10, "chmod 777": 8,
      "chown": 7, "passwd": 9,
      "cat /etc/sudoers": 12,

      # Level 4 — Exfiltration / Weaponisation (score: 15-25)
      "wget": 15, "curl": 15, "nc": 20,
      "python -c": 18, "bash -i": 20,
      "scp": 16, "/dev/tcp": 22
  }
  ```

- **Threat thresholds:**
  ```
  0–20:   LOW      → No change, generic Linux persona
  21–50:  MEDIUM   → Begin enriching environment, hint at more value
  51–80:  HIGH     → Switch to dev_workstation persona
  81–100: CRITICAL → Switch to finance_server persona
  ```

- **Persona switching rules:**
  - NEVER switch abruptly — spread changes over 3–5 command responses
  - New files appear gradually (one or two per command response)
  - Process list updates incrementally
  - The LLM is told about the transition and instructed to hint at it naturally
  - Session history is preserved — attacker never sees a "reset"

---

## 6. PERSONA DEFINITIONS

### Persona 1: generic_linux (default)
- Hostname: `web-srv-03`
- User: `ubuntu` (uid 1000)
- Running: nginx, cron, sshd, systemd
- Files: basic web server files, some logs
- Value signal: low

### Persona 2: dev_workstation (medium threat trigger)
- Hostname: `dev-workstation-07`
- User: `john.dev` (uid 1001)
- Running: VS Code server, node processes, git, docker
- Files: source code repos, `.env` files (fake credentials), Dockerfile, package.json
- Value signal: medium — looks like a developer machine with API keys

### Persona 3: finance_server (high threat trigger)
- Hostname: `fin-db-prod-01`
- User: `finapp` (uid 1002)
- Running: PostgreSQL, Java (Spring Boot), cron jobs
- Files: financial report CSVs (fake data), DB connection configs, audit logs
- Value signal: high — looks like it contains sensitive financial data
- Purpose: Keep sophisticated attacker engaged longest, collect most intelligence

---

## 7. TECHNOLOGY STACK

```
Layer               Technology
─────────────────────────────────────────────────
SSH Layer           Cowrie (Python)
Backend             Python 3.11+
Session Store       Redis (or in-memory dict for dev)
FakeFS Storage      JSON files (one per persona)
LLM API             Anthropic Claude API (primary) / OpenAI GPT-4 (fallback)
IP Reputation       AbuseIPDB API (free tier)
Logging             Python logging → JSON files → SQLite
Dashboard           FastAPI + simple HTML/JS (or Flask)
Deployment          Ubuntu 22.04 VM (DigitalOcean/AWS)
Version Control     Git + GitHub
```

---

## 8. DIRECTORY STRUCTURE

```
adaptive-honeypot/
├── CLAUDE.md                    ← This file
├── README.md
├── .env                         ← API keys (never commit this)
├── .env.example                 ← Template for .env
├── .gitignore
│
├── cowrie/                      ← Cowrie submodule (git clone)
│   └── ...
│
├── honeypot/                    ← Our core system
│   ├── __init__.py
│   ├── session_manager.py       ← Module 2
│   ├── response_engine.py       ← Module 3
│   ├── fakefs.py                ← Module 4
│   ├── session_overlay.py       ← Per-session write layer on top of FakeFS
│   ├── threat_scorer.py         ← Module 5
│   ├── persona_switcher.py      ← Module 5 (switching logic)
│   └── cowrie_hook.py           ← Glue: hooks our system into Cowrie
│
├── personas/                    ← FakeFS persona definitions
│   ├── generic_linux.json
│   ├── dev_workstation.json
│   └── finance_server.json
│
├── dictionary/                  ← Fast-path command responses
│   ├── command_handlers.py      ← Handler functions per command
│   └── command_registry.py     ← Maps command names → handlers
│
├── event_logging/              ← NOT named `logging/` — that would shadow
│   ├── session_logger.py          Python's stdlib `logging` package and
│   └── logs/                      break pytest + many third-party deps.
│
├── dashboard/                   ← Web dashboard
│   ├── app.py                  ← FastAPI/Flask app
│   ├── templates/
│   └── static/
│
├── tests/                       ← Consistency + evaluation tests
│   ├── test_fakefs.py
│   ├── test_consistency.py      ← Cross-reference test suite
│   ├── test_threat_scorer.py
│   └── fingerprint_tests/      ← Known honeypot fingerprint probes
│
├── scripts/
│   ├── setup.sh                ← Full environment setup
│   ├── deploy.sh               ← VM deployment
│   └── run_tests.sh
│
└── requirements.txt
```

---

## 9. DEVELOPMENT RULES (Claude Code must follow these)

### Rule 1: FakeFS is always consulted before responding
No module may invent system facts. If a command requires knowing a filename, username, process, or network state — it MUST query `FakeFS` first. The LLM prompt must include FakeFS context. Write operations (`mkdir`, `touch`, `rm`, `cp`, `mv`) go through the session overlay — a per-session in-memory layer that makes attacker-created files visible within that session without modifying the persona JSON.

### Rule 2: No hardcoded strings for system facts
Wrong:
```python
return "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),27(sudo)"
```
Right:
```python
user = fakefs.get_user("ubuntu")
return f"uid={user.uid}({user.name}) gid={user.gid}({user.name}) groups={user.format_groups()}"
```

### Rule 3: Every LLM call must be wrapped with a timeout and fallback
```python
try:
    response = await llm_call(prompt, timeout=3.0)
except TimeoutError:
    response = fakefs.get_generic_error_response(command)
```

### Rule 4: Session state is append-only during a session
Never overwrite command history. Always append. This ensures consistency if we replay sessions.

### Rule 5: Persona switches never reset session state
When switching persona, merge the new persona into existing session state. The `command_history`, `threat_score`, and `session_id` are preserved.

### Rule 6: Never log real attacker data outside the `event_logging/` directory
All attacker interaction data goes to `event_logging/logs/`. Never print attacker input to stdout in production.

### Rule 7: All API keys from environment variables only
```python
import os
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]  # Never hardcode
```

### Rule 8: Test after every module is built
Run `tests/test_consistency.py` after any FakeFS change. Run `tests/test_threat_scorer.py` after any scoring change.

---

## 10. EVALUATION FRAMEWORK (How we prove this works)

### Metric 1: Fingerprint Resistance Score
- Run 22 known honeypot fingerprinting checks against our system
- Run same checks against vanilla Cowrie
- Report: `our_system_passes / 22` vs `cowrie_passes / 22`

### Metric 2: FakeFS Consistency Score
- Run scripted cross-reference test suite (in `tests/test_consistency.py`)
- Test sequence: ls → cat /etc/passwd → ps aux → cat known_file → check all outputs are mutually consistent
- Report: `consistent_responses / total_cross_references_checked`

### Metric 3: Command Depth Progression
- Classify every command in every session into Level 1/2/3/4
- Track how many sessions progress to Level 3+
- Compare against Cowrie baseline (parallel deployment)
- Report: `sessions_reaching_level3+ / total_sessions` for both systems

### Baseline: Vanilla Cowrie
- Deploy standard Cowrie alongside our system on same VM (different port)
- All three metrics measured for both systems simultaneously
- This is our comparison baseline

---

## 11. SPRINT PLAN

### Sprint 1 — Foundation (Week 1–2)
**Goal:** Working Cowrie deployment with logging
- [ ] Provision cloud VM (Ubuntu 22.04)
- [ ] Install and configure Cowrie
- [ ] Redirect port 22 → 2222 via iptables
- [ ] Verify SSH login capture works
- [ ] Set up JSON logging pipeline
- [ ] Write `scripts/setup.sh`
**Done when:** SSH in, run commands, see every keystroke in logs

### Sprint 2 — FakeFS (Week 2–3)
**Goal:** Consistent, queryable fake filesystem
- [ ] Design and implement `honeypot/fakefs.py`
- [ ] Write `personas/generic_linux.json` (first persona)
- [ ] Implement all query methods
- [ ] Write and pass `tests/test_consistency.py`
- [ ] Enforce all consistency rules (timestamps, sizes, user coherence)
**Done when:** 100% pass rate on consistency test suite

### Sprint 3 — Response Engine (Week 3–4)
**Goal:** Realistic command responses
- [ ] Build `dictionary/command_handlers.py` (top 40 commands)
- [ ] All handlers query FakeFS — no hardcoded strings
- [ ] Build LLM integration with grounded prompt template
- [ ] Implement timeout + fallback
- [ ] Hook into Cowrie via `honeypot/cowrie_hook.py`
**Done when:** 20 sequential commands return consistent responses

### Sprint 4 — Threat Scoring (Week 4–5)
**Goal:** Real-time attacker threat assessment
- [ ] Build `honeypot/threat_scorer.py` with command taxonomy
- [ ] Integrate AbuseIPDB for IP reputation
- [ ] Implement session threat score accumulation
- [ ] Define and test threshold triggers
- [ ] Integrate with Session Manager
**Done when:** Live threat score visible per session, makes intuitive sense

### Sprint 5 — Persona Switching (Week 5–6)
**Goal:** Seamless, gradual identity transitions
- [ ] Write `personas/dev_workstation.json` and `personas/finance_server.json`
- [ ] Build `honeypot/persona_switcher.py` with gradual merge logic
- [ ] Update LLM prompt to reflect new persona during transition
- [ ] Test that session history is preserved across switch
**Done when:** Persona switch undetectable across 10 post-switch commands

### Sprint 6 — Evaluation + Dashboard (Week 6–7)
**Goal:** Prove it works with data
- [ ] Build `dashboard/app.py` with live session view
- [ ] Run fingerprint resistance tests
- [ ] Deploy to internet, collect 1–2 weeks of real data
- [ ] Analyse and chart all three evaluation metrics
- [ ] Write comparison against Cowrie baseline
**Done when:** Three charts showing metrics vs. baseline

---

## 12. KNOWN RISKS AND HOW TO HANDLE THEM

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| LLM API latency > 2s | High | Dictionary fast path covers 80% of commands |
| LLM hallucinates non-FakeFS facts | High | Strict prompt + post-processing validation |
| Attacker detects persona switch | Medium | Gradual transition over 3–5 commands |
| Cowrie hook breaks Cowrie internals | Medium | Keep hook minimal, test on every Cowrie update |
| API cost overrun | Medium | Cache common LLM responses, rate limit per session |
| Real attacker uploads malware | Low | Cowrie sandbox prevents execution; log only |

---

## 13. WHAT SUCCESS LOOKS LIKE

At the end of Phase-2, you should be able to demonstrate:

1. A live SSH session where an attacker-like interaction receives realistic, consistent responses
2. A dashboard showing real attacker sessions with threat scores
3. A persona switch happening mid-session, with the evaluator unable to detect the transition point
4. Three evaluation metric charts showing improvement over Cowrie baseline
5. A consistency test suite that passes 100%

---

## 14. IMPORTANT CONSTRAINTS FOR CLAUDE CODE

- Always write Python 3.11+ compatible code
- Use `async/await` for all I/O operations (LLM calls, file reads, API calls)
- Use `pydantic` for all data models (sessions, persona configs, log entries)
- Use `pytest` for all tests
- Use `python-dotenv` for environment variable management
- FakeFS must be importable and usable independently (no circular imports)
- Every public method must have a docstring explaining inputs, outputs, and side effects
- Logging uses Python's `logging` module — never `print()` in production code
- All persona JSON files must validate against a pydantic schema before loading