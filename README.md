# Adaptive LLM-Powered Honeypot with Behavioural Mimicry and Threat-Intelligence-Driven Persona Switching

B.Tech Capstone Phase-2 (PW26\_SVM\_03), PES University, Bengaluru
Guide: Dr. Sapna V M

**Team:**
Kavya R Chengalath (PES1UG23CS295) | Kiran Kumar B D (PES1UG23CS306) | Keerthi A H (PES1UG23CS296) | Jayanth Gowda (PES1UG23CS263)

---

## What This System Does

A cybersecurity deception system that exposes an SSH server to the internet and responds to attackers like a real Linux machine. Every response is generated from a Fake File System (FakeFS) — the single source of truth — so the attacker sees a consistent, believable environment.

The system scores attacker behaviour in real-time. As an attacker becomes more dangerous, the system gradually morphs the environment around them — from a generic web server to a developer workstation to a finance production server — planting increasingly valuable-looking fake data to keep them engaged and collect intelligence.

The attacker never sees a "switch." They think they discovered something deeper. That is the core innovation.

---

## Architecture Overview

```
Internet / Real Attacker
         |
         v
+---------------------+
|   SSH Gateway        |  Cowrie handles raw SSH protocol
|   (Cowrie)           |  Captures every keystroke
+--------+------------+
         | raw command string
         v
+---------------------+     +----------------------+
|   Cowrie Hook        |---->|   Response Engine     |
|   (cowrie_hook.py)   |     |   (response_engine.py)|
|                      |     |                      |
|   Per-session:       |     |   Fast path: 40+     |
|   - FakeFS instance  |     |   command handlers   |
|   - Session overlay  |     |   (< 50ms)           |
|   - Threat scorer    |     |                      |
|   - Persona switcher |     |   Slow path: LLM API |
|   - Session logger   |     |   (Claude, < 3s)     |
+--------+------------+     +---------+------------+
         |                             |
         v                             v
+---------------------+     +----------------------+
|   Threat Scorer      |     |   FakeFS             |
|   (threat_scorer.py) |     |   (fakefs.py)        |
|                      |     |                      |
|   Two-layer          |     |   Single source of   |
|   classification     |     |   truth for:         |
|   120+ exact matches |     |   - Directory tree   |
|   45+ binary scores  |     |   - File contents    |
|   30 arg escalators  |     |   - Process list     |
|   9 attack patterns  |     |   - Users/groups     |
+--------+------------+     |   - Network state    |
         |                   |   - Persona config   |
         v                   +---------+------------+
+---------------------+               |
|   Persona Switcher   |               v
|   (persona_switcher) |     +----------------------+
|                      |     |   Session Overlay    |
|   Gradual drift:     |     |   (session_overlay)  |
|   5-step transition  |     |                      |
|   Seeding -> Building|     |   Per-session write  |
|   -> Completing      |     |   layer: mkdir, rm,  |
+---------------------+     |   touch, wget files  |
                             +----------------------+
         |
         v
+---------------------+     +----------------------+
|   Session Manager    |     |   IP Reputation      |
|   (session_manager)  |     |   (ip_reputation.py) |
|                      |     |                      |
|   Tracks all active  |     |   AbuseIPDB API      |
|   sessions with      |     |   Async, cached,     |
|   Pydantic models    |     |   never blocks       |
+---------------------+     +----------------------+
         |
         v
+---------------------+
|   Session Logger     |
|   (session_logger)   |
|                      |
|   JSON-lines log     |
|   Daily rotation     |
|   In-memory rollup   |
+---------------------+
```

---

## Full Command Flow (What Happens When an Attacker Types a Command)

```
Attacker types: cat /etc/shadow
                    |
                    v
1. Cowrie SSH layer receives the keystroke stream
                    |
                    v
2. cowrie_hook.py dispatch_async() is called
                    |
                    v
3. ResponseEngine.handle_command() parses the command
   - command_parser.py splits into binary, args, flags, pipes, redirects
                    |
                    v
4. Fast path check: is "cat" in the command registry?
   YES -> command_handlers.handle_cat() queries FakeFS
          FakeFS checks session overlay first, then persona JSON
          Returns file content (or "Permission denied")
   NO  -> LLM path: build grounded prompt from FakeFS state,
          call Claude API with 3s timeout, post-process response
                    |
                    v
5. ThreatScorer.score_command() classifies the command
   - Layer 1: exact match "cat /etc/shadow" -> (PRIVILEGE_ESC, 12)
   - Layer 2: binary fallback + argument escalators
   - PatternDetector checks for multi-command attack patterns
   - PersonaSwitchDecider evaluates if score crossed a threshold
   - Returns ThreatDecision with score delta, new total, level, patterns
                    |
                    v
6. If PersonaSwitcher.is_transitioning():
   - apply_next_changes() drips 1-2 ChangeEvents into session overlay
   - New files/directories appear gradually for attacker to discover
   - add_process events injected into FakeFS process list
                    |
                    v
7. If ThreatDecision.trigger_persona_switch AND not transitioning:
   - PersonaSwitcher.initiate_switch() starts 5-step gradual drift
   - Change queue built: subtle hints first, obvious signals last
                    |
                    v
8. Session state updated:
   - threat_score = max(old, new)  -- NEVER decreases
   - command_history.append(...)   -- append-only
   - patterns_detected |= new     -- cumulative set
                    |
                    v
9. SessionLogger.log_command() writes JSON-lines log entry
   with threat_category, score_delta, threat_level, patterns
                    |
                    v
10. Response returned to attacker via Cowrie SSH
```

---

## The Six Core Modules

### Module 1: SSH Gateway (Cowrie)

Cowrie is an open-source SSH honeypot. We use it only for the SSH protocol layer — authentication, session lifecycle, keystroke capture. Our hook (`cowrie_hook.py`) intercepts every command before Cowrie processes it, routes it through our Response Engine, and returns our output instead of Cowrie's defaults.

- Port: 2222 (iptables redirects 22 -> 2222)
- Always accepts login after N attempts
- We do NOT modify Cowrie's SSH handshake or auth flow

### Module 2: Session Manager (`honeypot/session_manager.py`)

Tracks every active attacker session with a Pydantic `SessionState` model.

**Key fields per session:**
- `session_id`, `attacker_ip`, `start_time`
- `current_directory`, `current_user`
- `command_history` (append-only list)
- `threat_score` (0-100, never decreases)
- `threat_level` (LOW / MEDIUM / HIGH / CRITICAL)
- `active_persona` (generic_linux / dev_workstation / finance_server)
- `patterns_detected` (cumulative set)
- `ip_reputation` (from AbuseIPDB)
- `overlay` (per-session SessionOverlay instance)

**Key methods:**
- `create_session()` — async, calls IP reputation check, applies initial score bonus
- `update_after_command()` — scores command, enforces monotonic score, appends history
- `record_persona_switch()` / `complete_transition()` — gradual transition lifecycle
- `close_session()` — removes from store, returns summary dict with full session data

**Invariants enforced:**
- `threat_score` NEVER decreases
- `command_history` is append-only
- `patterns_detected` only grows
- Persona switches never reset any session state

### Module 3: Response Engine (`honeypot/response_engine.py`)

Produces the terminal output returned to the attacker. Two paths:

**Fast Path (< 50ms):**
40+ command handlers in `dictionary/command_handlers.py` generate output directly from FakeFS state. Commands covered: `ls`, `pwd`, `whoami`, `id`, `uname`, `cat`, `ps`, `netstat`, `df`, `free`, `ifconfig`, `ip`, `w`, `last`, `groups`, `which`, `find`, `head`, `tail`, `grep`, `echo`, `hostname`, `date`, `uptime`, `env`, `wget`, `curl`, `mkdir`, `touch`, `rm`, `cp`, `mv`, `cd`, `history`, `chmod`, `chown`, `sudo`, `su`, and more.

Every handler queries FakeFS — no hardcoded strings for usernames, PIDs, file contents, hostnames, or any system fact.

**Slow Path (< 3s):**
For commands not in the dictionary, the engine builds a grounded LLM prompt containing the full system state from FakeFS (hostname, OS, current user, directory, process summary, network state, command history, threat level) and calls the Claude API. The response is post-processed to strip markdown, commentary, and any LLM artifacts.

**Additional features:**
- Pipe handling: `head`, `tail`, `wc`, `grep`, `sort`, `uniq`
- Redirect handling: `>` and `>>` write to session overlay
- Chained commands: `&&`, `||`, `;`
- Command substitution: `$(...)`, `` `...` ``
- Timing jitter: realistic delays per command type

**Return value:** `(response, source, threat_decision)` — the 3-tuple contract that feeds the threat scorer.

### Module 4: FakeFS (`honeypot/fakefs.py`)

The single source of truth. Every module queries FakeFS before responding. Nothing is invented freely.

**Backed by persona JSON files** in `personas/` — one per persona (generic_linux, dev_workstation, finance_server). Each JSON contains:
- System info (hostname, OS, kernel, uptime)
- Users (username, uid, home, shell, groups, password hash)
- Processes (pid, ppid, user, cpu, mem, command)
- Filesystem (full directory tree with file contents, permissions, timestamps)
- Network (interfaces, open ports, active connections)
- Disk and memory stats
- Environment variable defaults per user

**Validated on load** with Pydantic models and 8 consistency rules (timestamps in past, sizes match content, users in /etc/passwd match /home, process owners are valid users, etc.).

**Session Overlay (`honeypot/session_overlay.py`):**
A per-session in-memory write layer on top of FakeFS. When an attacker runs `mkdir`, `touch`, `rm`, `wget`, `curl -o`, or `echo > file`, changes go to the overlay — not the persona JSON. Read operations (`ls`, `cat`, `cd`, `find`) check overlay first, then FakeFS. Deletions via `rm` hide FakeFS entries. Each session has its own independent overlay, discarded on session end.

**Session-only FakeFS extensions:**
- `add_session_process(dict)` — injects a process visible only in this session's `ps` output
- `set_session_hostname(str)` — overrides hostname for this session without touching the JSON

### Module 5a: Threat Scorer (`honeypot/threat_scorer.py`)

Real-time attacker threat assessment. Classifies every command and accumulates a session-wide threat score.

**Two-layer classification:**
- **Layer 1:** Exact match on the full command string (120+ entries). Example: `"cat /etc/shadow"` -> `(PRIVILEGE_ESC, 12)`.
- **Layer 2:** Binary name fallback (45+ entries) + argument escalator substring matching (30 patterns with bonus scores). Example: `find` (base 4) + `/etc/shadow` in args (+8) = 12.

**Command categories:** BENIGN, RECONNAISSANCE, EXPLORATION, PRIVILEGE\_ESCALATION, EXFILTRATION, LATERAL\_MOVEMENT.

**Threat levels and thresholds:**
| Score | Level | Action |
|-------|-------|--------|
| 0-20 | LOW | No change, generic Linux persona |
| 21-50 | MEDIUM | Environment enriching, hint at more value |
| 51-80 | HIGH | Switch to dev\_workstation persona |
| 81-100 | CRITICAL | Switch to finance\_server persona |

**PatternDetector (9 multi-command patterns):**
Detects attack sequences across the full command history. Each pattern fires only once per session and adds a bonus score.

| Pattern | Bonus | Trigger |
|---------|-------|---------|
| rapid\_recon\_burst | +8 | 5+ recon commands in last 10 |
| privilege\_escalation\_chain | +12 | 2+ priv-esc indicators in last 5 |
| credential\_harvesting | +15 | passwd + shadow in same session |
| ssh\_key\_theft\_attempt | +12 | .ssh + key file access |
| download\_and\_execute | +20 | wget/curl + chmod/bash/sh |
| network\_mapping | +10 | netstat/ss + arp |
| active\_network\_scan | +18 | nmap or masscan |
| persistence\_attempt | +15 | 2+ crontab/rc.local/.bashrc |
| data\_staging | +15 | find + tar/zip/gzip |

**PersonaSwitchDecider:**
- Score >= 51 and on generic\_linux -> switch to dev\_workstation
- Score >= 81 and not on finance\_server -> switch to finance\_server
- Never switch backward (finance -> dev is forbidden)
- Max 2 switches per session
- Dangerous patterns (download\_and\_execute, credential\_harvesting, privilege\_escalation\_chain) force an immediate step-up

**Output:** `ThreatDecision` Pydantic model with command category, score delta, cumulative score, threat level, persona switch decision, detected patterns, and first-of-category flag.

### Module 5b: Persona Switcher (`honeypot/persona_switcher.py`)

The core innovation. Manages gradual persona transitions so the attacker experiences environmental *drift* — not a jarring reset.

**The wrong way (detectable):**
```
Command 43: ls /home       -> john.dev    (suddenly new user)
Command 44: whoami         -> finapp      (different user)
Command 45: hostname       -> fin-db-prod-01  (hostname changed)
```

**The right way (gradual drift over 5 commands):**
```
Command 43: ls /home       -> ubuntu  john.dev     (new dir appeared)
Command 44: ps aux         -> ... node --watch ... (new process)
Command 45: find / -name .env -> /home/john.dev/projects/webapp/.env
Command 46: cat that .env  -> DB_PASSWORD=S3cret-P@ssw0rd
Command 47: ls ~/.ssh      -> id_rsa (SSH key appeared)
```

The attacker thinks they discovered something. They didn't notice a switch.

**TransitionPhase state machine:** IDLE -> SEEDING -> BUILDING -> COMPLETING -> DONE

**Change queues (ordered subtle-to-obvious):**

*generic\_linux -> dev\_workstation (8 changes):*
1. (seeding) /home/john.dev directory appears
2. (seeding) .gitconfig — subtle developer hint
3. (building) Node.js process in ps output
4. (building) projects/webapp directory
5. (building) .env file with database credentials
6. (completing) .ssh directory
7. (completing) id\_rsa private SSH key
8. (completing) Docker daemon process

*\* -> finance\_server (9 changes):*
1. (seeding) /home/finapp directory
2. (seeding) PostgreSQL process appears
3. (building) config/ directory
4. (building) database.yml with production credentials
5. (building) reports/ directory
6. (building) Transaction CSV with financial data
7. (completing) logs/ directory
8. (completing) audit.log compliance trail
9. (completing) Spring Boot Java process

**Rules:**
- Each `apply_next_changes()` call emits 1-2 events (never the full dump)
- Full queue drains over exactly 5 calls
- Changes go to the session overlay, not FakeFS JSON
- No double-switching: a second switch during a transition is queued automatically
- Session history, cwd, threat score are never touched during a switch

### Module 6: IP Reputation (`honeypot/ip_reputation.py`)

Async AbuseIPDB integration that enriches sessions at connection time.

- Lookup via AbuseIPDB `/api/v2/check` endpoint
- Timeout capped at 3 seconds — never blocks session creation
- Results cached in-memory for process lifetime (saves API quota)
- Private/loopback IPs skip the API call entirely
- Any failure (missing key, network error, timeout, bad JSON) returns `unknown()` gracefully

**Initial score bonus calculation:**
| Condition | Bonus |
|-----------|-------|
| abuse\_confidence >= 80 | +20 |
| abuse\_confidence >= 50 | +10 |
| abuse\_confidence >= 25 | +5 |
| is\_tor | +15 |
| total\_reports >= 100 | +8 |

Bonuses stack. A known-malicious Tor exit node with 200+ reports gets +43 at session start.

### Logging (`event_logging/session_logger.py`)

Structured JSON-lines logger with daily rotation.

**Event types:**
- `session_start` — attacker IP, port, timestamp
- `login_attempt` — username, password, success/fail
- `command` — command string, cwd, threat score, persona, response source, threat category, score delta, threat level, patterns detected
- `persona_switch` — from/to persona, trigger score
- `session_end` — duration, command count, final threat score

---

## The Three Personas

### generic\_linux (default, LOW threat)
- **Hostname:** web-srv-03
- **User:** ubuntu (uid 1000)
- **Processes:** nginx, cron, sshd, systemd
- **Files:** Basic web server files, some logs
- **Value signal:** Low — looks like a typical cloud VM

### dev\_workstation (HIGH threat, score >= 51)
- **Hostname:** dev-workstation-07
- **User:** john.dev (uid 1001)
- **Processes:** VS Code server, Node.js, npm, git, Docker
- **Files:** Source code repos, `.env` files with fake API keys and DB passwords, Dockerfile, package.json, `.ssh/id_rsa` private key
- **Value signal:** Medium — looks like a developer machine with credentials

### finance\_server (CRITICAL threat, score >= 81)
- **Hostname:** fin-db-prod-01
- **User:** finapp (uid 1002)
- **Processes:** PostgreSQL, Java Spring Boot, cron jobs
- **Files:** Financial report CSVs with fake transaction data, DB connection configs with production credentials, audit logs
- **Value signal:** High — looks like it contains sensitive financial data. Keeps sophisticated attackers engaged longest.

---

## Directory Structure

```
adaptive-honeypot/
|-- CLAUDE.md                         # Full architect briefing
|-- README.md                         # This file
|-- .env.example                      # API key template
|-- requirements.txt
|
|-- honeypot/                         # Core system modules
|   |-- cowrie_hook.py                # Cowrie glue layer, per-session dispatcher
|   |-- response_engine.py           # Fast path + LLM path orchestrator
|   |-- fakefs.py                    # Fake File System (single source of truth)
|   |-- session_overlay.py           # Per-session write layer on FakeFS
|   |-- command_parser.py            # Shell command parser
|   |-- session_manager.py           # Session state tracking (Pydantic)
|   |-- threat_scorer.py             # Two-layer command classification
|   |-- persona_switcher.py          # Gradual persona transition engine
|   |-- ip_reputation.py             # AbuseIPDB async integration
|   |-- persona_validator.py         # 8 consistency rules for personas
|
|-- dictionary/                       # Fast-path command handlers
|   |-- command_handlers.py           # 40+ handler functions
|   |-- command_registry.py           # Maps command names -> handlers
|
|-- personas/                         # FakeFS persona definitions
|   |-- generic_linux.json            # Default: web server
|   |-- dev_workstation.json          # Developer machine
|   |-- finance_server.json           # Finance production server
|
|-- event_logging/                    # Structured logging
|   |-- session_logger.py            # JSON-lines logger with rotation
|   |-- logs/                        # Log output directory
|
|-- tests/                            # 1279 tests
|   |-- test_fakefs.py               # FakeFS query + consistency
|   |-- test_consistency.py          # Cross-reference test suite
|   |-- test_command_handlers.py     # All 40+ fast-path handlers
|   |-- test_command_parser.py       # Parser edge cases
|   |-- test_command_registry.py     # Registry lookup
|   |-- test_response_engine.py      # Fast/LLM path, pipes, redirects
|   |-- test_session_overlay.py      # Overlay CRUD + isolation
|   |-- test_write_commands_persist.py # 12-step write sequence
|   |-- test_threat_scorer.py        # 250+ scoring tests
|   |-- test_threat_integration.py   # 20-command session simulation
|   |-- test_ip_reputation.py        # Mocked HTTP tests
|   |-- test_session_manager.py      # Session lifecycle tests
|   |-- test_session_logger.py       # Logging tests
|   |-- test_persona_switcher.py     # Gradual drift verification
|   |-- test_sprint3_acceptance.py   # End-to-end acceptance
|   |-- test_cowrie_integration.py   # Live SSH integration
|
|-- scripts/
|   |-- setup.sh                     # VM setup automation
|   |-- deploy.sh                    # Deployment script
|
|-- dashboard/                        # Web dashboard (Sprint 6)
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| SSH Layer | Cowrie (Python) |
| Backend | Python 3.11+ |
| Data Models | Pydantic v2 |
| FakeFS Storage | JSON files (one per persona) |
| LLM API | Anthropic Claude API (primary) |
| IP Reputation | AbuseIPDB API (free tier) |
| HTTP Client | httpx (async) |
| Logging | Python logging -> JSON-lines -> daily rotation |
| Testing | pytest (1279 tests) |
| Environment | python-dotenv |
| Deployment | Ubuntu 22.04 VM |

---

## Quick Start

### Prerequisites
- Python 3.11+
- Cowrie SSH honeypot (for live deployment)
- Anthropic API key (for LLM slow path)
- AbuseIPDB API key (optional, for IP reputation)

### Setup

```bash
git clone <repo-url>
cd adaptive-honeypot

# Create virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux/Mac
# .venv\Scripts\activate        # Windows

# Install dependencies
pip install -r requirements.txt

# Configure API keys
cp .env.example .env
# Edit .env and add:
#   ANTHROPIC_API_KEY=sk-ant-...
#   ABUSEIPDB_API_KEY=...
```

### Run Tests

```bash
# Full suite (1279 tests)
pytest

# Specific module
pytest tests/test_threat_scorer.py -v
pytest tests/test_persona_switcher.py -v

# Integration test (20-command attack simulation)
pytest tests/test_threat_integration.py -v
```

### Deploy to VM

```bash
bash scripts/setup.sh    # On fresh Ubuntu 22.04
```

---

## Evaluation Metrics

### 1. Fingerprint Resistance Score
How many of 22 known honeypot fingerprinting checks does our system pass vs vanilla Cowrie?

### 2. FakeFS Consistency Score
Cross-reference test suite verifying `ls` -> `cat /etc/passwd` -> `ps aux` -> `cat known_file` all produce mutually consistent output.

### 3. Command Depth Progression
What percentage of sessions reach Level 3+ (privilege escalation)? Compared against Cowrie baseline deployed on the same VM.

---

## Sprint History

| Sprint | Delivered | Tests |
|--------|-----------|-------|
| Sprint 1 | Cowrie deployment, SSH capture, JSON logging | 50+ |
| Sprint 2 | FakeFS with 3 persona JSONs, consistency validator | 200+ |
| Sprint 3 | Response Engine (40+ handlers), session overlay, command parser, Cowrie hook | 800+ |
| Sprint 4 | Threat Scorer (120+ scores, 9 patterns), IP Reputation, Session Manager | 1100+ |
| Sprint 5 | Persona Switcher (gradual drift), FakeFS session extensions, full wiring | 1279 |
| Sprint 6 | Dashboard, evaluation, real-world data collection | Planned |
