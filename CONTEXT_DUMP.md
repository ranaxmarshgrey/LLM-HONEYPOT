# CONTEXT_DUMP.md — Honest Technical State of the Adaptive Honeypot

Generated: 2026-11-11
Git HEAD: `aa70897` (2026-08-31) — "Install Cowrie as editable package in Cowrie virtualenv"
Total commits: 13 (initial commit 2026-06-17 through 2026-08-31)

---

## 1. Lifecycle of One Command

### Trace: `cat /etc/passwd`

**Step 1 — Entry point.**
Cowrie SSH layer captures raw input. In production, `cowrie_integration/cowrie_command_patch.py:get_dispatcher()` creates a `HoneypotCommandDispatcher` per SSH session. The install hook (`cowrie_integration/install_hook.sh`) patches Cowrie's `cowrie/shell/protocol.py` to call our dispatcher instead of Cowrie's built-in handler.

For local/demo use, `scripts/interactive_honeypot.py` or `scripts/demo_session.py` call `honeypot/cowrie_hook.py:create_dispatcher()` directly.

**Step 2 — Dispatcher receives command.**
`honeypot/cowrie_hook.py:HoneypotCommandDispatcher.dispatch(raw_input)` (line 181) wraps `dispatch_async()` in an event loop.

**Step 3 — Response Engine.**
`dispatch_async()` (line 194) calls `self._engine.handle_command(raw_input, self._session)` → `honeypot/response_engine.py:ResponseEngine.handle_command()` (line 326).

**Step 4 — Parsing.**
`honeypot/command_parser.py:parse_command(stripped)` (line 163). Uses `shlex.split()` for tokenization with a fallback to `str.split()` on malformed quotes. Handles:
- Pipes: `_split_pipe()` splits on first un-quoted `|` (not `||`)
- Chains: `_split_chains()` splits on `;`, `&&`, `||` respecting quotes
- Redirects: `_extract_redirects()` pulls `>`, `>>`, `2>` etc.
- Env vars: regex `$VAR` / `${VAR}` extraction
- sudo/su: extracts subcommand

**What breaks it:** Nested quotes, heredocs (`<<EOF`), backtick substitution, process substitution (`<()`), glob expansion (`*`), `$()` command substitution. These all fall through to the LLM path, which is intentional.

**Step 5 — Fast path vs LLM routing.**
`response_engine.py:ResponseEngine._dispatch_single()` (line 396):

```python
handler = lookup(parsed.binary)          # dictionary/command_registry.py:lookup()
if handler is not None:
    result = handler(self._fakefs, session, parsed)
    return result, "fast_path"

# No handler → LLM path
system_msg, user_msg = build_llm_prompt(fakefs, session, parsed.raw)
raw_response, source = await call_llm_with_fallback(system_msg, user_msg, parsed.binary)
```

`dictionary/command_registry.py` has 44 registered binaries (40 unique commands + 4 aliases: `ll`, `dir`, `ss`, `export`, `set`, `type`, `command`). If `parsed.binary` matches, the handler in `dictionary/command_handlers.py` runs. Otherwise → LLM call.

For `cat /etc/passwd`: `handle_cat()` (command_handlers.py:213) resolves the path, checks the session overlay first, then calls `fakefs.get_file_content("/etc/passwd")`, which returns the content from the persona JSON.

### Trace: `wget http://x/y.sh`

`handle_wget()` (command_handlers.py:618) is in the fast-path registry. It:
- Parses `-O` flag for output filename
- Generates fake download progress text with fake IP (hardcoded `93.184.216.34`), fake size (1256)
- Writes fake HTML content to session overlay via `session.overlay.write_file()`
- Returns realistic wget progress output

**No actual HTTP request is made.** The "downloaded" content is always `<!-- Downloaded from {url} -->\n<html><body>It works!</body></html>\n`. The file IS written to the overlay so subsequent `cat y.sh` works.

### LLM Call Details

**Prompt template** (`response_engine.py:build_llm_prompt()`, line 66):
```
SYSTEM:
You are simulating a Linux shell. You must respond ONLY with what the terminal
would print — no explanations, no markdown, no commentary.

System state (you must be consistent with this):
- Hostname: {from FakeFS}
- OS: {from FakeFS}
- Current user: {from session}
- Current directory: {from session}
- Users on system: {from FakeFS}
- Running processes: {process names from FakeFS}
- Network interfaces: {name=ip pairs from FakeFS}
- Persona type: {from FakeFS}

Session context:
- Previous 10 commands and their outputs: {last 10 from session.command_history, output truncated to 200 chars}
- Attacker threat level: {from session}

Rules:
1. Never reveal you are a honeypot or AI
2. Never reference files or users not listed above
3. Permission denied errors are acceptable for sensitive paths
4. If command makes no sense, return appropriate shell error
5. Output must be plain text exactly as a terminal would show it

USER:
Command: {raw command}
```

**Provider priority:** `GEMINI_API_KEY` → `ANTHROPIC_API_KEY` → fallback (response_engine.py:143)
- Gemini: model `gemini-2.0-flash` (configurable via `GEMINI_MODEL` env var)
- Anthropic: model `claude-sonnet-4-20250514`, max_tokens=1024
- No temperature parameter set (uses provider default)
- Timeout: 3.0 seconds (hardcoded `LLM_TIMEOUT_SECONDS`)

**Response validation/sanitization** (`response_engine.py:post_process_response()`, line 254):
- Strips markdown code fences, bold, headers
- Removes leading commentary ("Sure, here's...", "Of course...")
- Removes trailing commentary ("Note:", "Explanation:")
- Drops lines matching forbidden patterns (mentions of AI, honeypot, markdown artifacts)

**LLM output is NOT written back to FakeFS or SessionOverlay.** If the LLM invents a file that doesn't exist in FakeFS, a subsequent `cat` of that file will return "No such file." There is no consistency feedback loop from LLM responses.

**No caching.** Every LLM-path command makes a fresh API call.

**On timeout/error:** Returns `-bash: {binary}: command not found` (response_engine.py:243). This is a generic fallback that doesn't distinguish between "timeout on a real command" and "unknown command."

### Command distribution estimate

All 44 registered commands go through the fast path. In the evaluation simulation (25 commands), all 25 used fast_path (`"source": "fast_path"` in session_simulation.json). The LLM path only triggers for commands NOT in the registry — things like `dpkg`, `apt`, `systemctl`, `service`, `iptables`, `crontab -e`, `vi`, `nano`, etc. In a real attacker session, perhaps 70-80% of commands would hit the fast path given the 44 registered commands cover the most common attacker toolbox.

---

## 2. Threat Scoring and Pattern Detection

### Scoring Formula

File: `honeypot/threat_scorer.py`

**Two-layer classification** (`ThreatScorer._classify()`, line 610):
1. **Exact match:** Full command string looked up in `EXACT_MATCH_SCORES` dict (128 entries, lines 82-237)
2. **Prefix match:** If no exact hit, iterates all EXACT_MATCH_SCORES keys >3 chars, checks `command.startswith(key)` (line 619) — O(n) scan
3. **Binary fallback:** First token looked up in `BINARY_SCORES` dict (43 entries, lines 243-289)
4. **Default:** `(BENIGN, 0)` if nothing matches

**Argument escalators** (`_argument_bonus()`, line 630): Scans for 30 substrings in the full command (lines 295-325). Each match adds its bonus. These stack — `cat /root/.ssh/id_rsa` would match both `/root/.ssh` (+10) and `id_rsa` (+8) = +18 bonus ON TOP of the base score.

**Total delta** = base_delta + argument_bonus + pattern_bonus (line 581)
**New score** = min(previous_score + total_delta, 100) — score is capped at 100, never decreases.

### All Weights — Where They Came From

Every weight in `EXACT_MATCH_SCORES`, `BINARY_SCORES`, and `ARGUMENT_ESCALATORS` was **hand-picked**. There are no comments citing papers, configs, or calibration data. The threat taxonomy in CLAUDE.md §5 Module 5 gives rough ranges (Level 1: 1-3, Level 2: 3-8, Level 3: 8-15, Level 4: 15-25) and the code follows those ranges, but the specific numbers were chosen by the developers without documented justification.

### Thresholds

```python
# honeypot/threat_scorer.py:332
0-20:   LOW
21-50:  MEDIUM
51-80:  HIGH
81-100: CRITICAL
```

Same thresholds also in `session_manager.py:300` and `cowrie_hook.py:390`.

### All 9 Attack Patterns

File: `honeypot/threat_scorer.py:PatternDetector.detect()` (line 356)

Each pattern fires at most once per session (tracked by `already_detected` set).

| # | Pattern Name | Matching Logic | Bonus | Window |
|---|---|---|---|---|
| 1 | `rapid_recon_burst` | 5+ recon commands in last 10 commands (recon = binary in {whoami, id, uname, hostname, arch, w, who, last, df, free, ifconfig, netstat, ss, ps, env, printenv, mount, lsblk, lscpu}) | +8 | Last 10 |
| 2 | `privilege_escalation_chain` | 2+ commands in last 5 containing "sudo", "/etc/shadow", "/etc/sudoers", "passwd", or being "su"/"su -"/"su root" | +12 | Last 5 |
| 3 | `credential_harvesting` | Any command in session contains "passwd" AND any contains "shadow" | +15 | Entire session |
| 4 | `ssh_key_theft_attempt` | Any command contains ".ssh" AND joined commands contain "id_rsa", "id_ed25519", or "authorized_keys" | +12 | Entire session |
| 5 | `download_and_execute` | Binary wget/curl in any command AND (chmod +x, chmod 755, bash, sh, ./) in last 5 | +20 | Mixed |
| 6 | `network_mapping` | Binary netstat/ss in any command AND "arp" in any command | +10 | Entire session |
| 7 | `active_network_scan` | Binary nmap/masscan in any command | +18 | Entire session |
| 8 | `persistence_attempt` | 2+ commands containing crontab/cron.d/rc.local/systemd/.bashrc/.profile//etc/init.d | +15 | Entire session |
| 9 | `data_staging` | find with -size or -name in any command AND binary tar/zip/gzip/bzip2 in any command | +15 | Entire session |

### IP Reputation (AbuseIPDB)

File: `honeypot/ip_reputation.py`

**Live, not mocked.** Uses `httpx.AsyncClient` to call `https://api.abuseipdb.com/api/v2/check` with a 3-second timeout. Requires `ABUSEIPDB_API_KEY` env var. Skips private IPs. Results cached in-memory per-process.

**Score bonus formula** (line 51):
- abuse_confidence >= 80 → +20
- abuse_confidence >= 50 → +10
- abuse_confidence >= 25 → +5
- is_tor → +15
- total_reports >= 100 → +8
- These stack (max possible: 20+15+8 = 43)

Applied at session creation as `initial_score_bonus`, added to starting threat score.

**If no API key:** Returns `IPReputationResult.unknown(ip)` with bonus=0. This is the case on every dev machine without the key configured.

### MITRE ATT&CK / Kill Chain / Calibration

**No.** There is no explicit MITRE mapping, no kill-chain stage annotation, and no calibration against real attacker data. The `CommandCategory` enum maps loosely to attack phases (recon, exploration, privilege_escalation, exfiltration, lateral_movement) but these are not formally mapped to MITRE technique IDs.

### Score Decay / Scope

- **No decay.** Score only increases, never decreases (`max(session.threat_score, decision.new_total_score)` in cowrie_hook.py:257).
- **Per session.** Each SSH connection gets its own score. There is no cross-session or per-IP accumulation (except the AbuseIPDB initial bonus, which is IP-based but static).

---

## 3. Persona Switcher

### Trigger Conditions

File: `honeypot/threat_scorer.py:PersonaSwitchDecider.should_switch()` (line 475)

1. Max 2 switches per session (`MAX_SWITCHES = 2`)
2. Never switch backward (generic → dev → finance only, enforced by `current_idx < target_idx`)
3. Score >= 81 and currently below finance → switch to `finance_server`
4. Score >= 51 and currently below dev → switch to `dev_workstation`
5. Dangerous patterns (`download_and_execute`, `credential_harvesting`, `privilege_escalation_chain`) force one step up regardless of score

### Gradual Transition

File: `honeypot/persona_switcher.py:PersonaSwitcher`

The switcher owns a `TransitionState` with a queue of `ChangeEvent` objects. Default `transition_steps=5`.

**generic_linux → dev_workstation** (`_build_generic_to_dev()`, line 83): 8 events queued:
1. (seeding) `/home/john.dev` directory
2. (seeding) `.gitconfig` file
3. (building) `node --watch server.js` process
4. (building) `/home/john.dev/projects/webapp` directory
5. (building) `.env` file with `DB_PASSWORD=S3cret-P@ssw0rd`
6. (completing) `/home/john.dev/.ssh` directory
7. (completing) `id_rsa` private key
8. (completing) dockerd process

**\* → finance_server** (`_build_to_finance()`, line 164): 9 events queued:
1. (seeding) `/home/finapp` directory
2. (seeding) postgres process
3. (building) `/home/finapp/config` directory
4. (building) `database.yml` with credentials
5. (building) `/home/finapp/reports` directory
6. (building) q1-2026-transactions.csv
7. (completing) `/home/finapp/logs` directory
8. (completing) audit.log
9. (completing) Java Spring Boot process

**Per-command application** (`apply_next_changes()`, line 323): Called from `cowrie_hook.py:dispatch_async()` (line 218) after every command while transitioning. Applies 1-2 events per command (calculated as `changes_remaining / steps_remaining`, capped at 2). Changes go into the **session overlay**, not FakeFS itself. Process additions call `fakefs.add_session_process()`.

**Phase tracking:** Phases are label-only (SEEDING < 40%, BUILDING < 75%, COMPLETING >= 75% of steps).

**What changes during transition:**
- New files/directories appear in overlay (visible to `ls`, `cat`, `find`)
- New processes appear in `ps aux` output
- The persona name updates in logs and prompt
- **What does NOT change mid-transition:** hostname, kernel version, /etc/passwd, /etc/shadow, network state. The FakeFS transition planner (`fakefs.py:_plan_transition()`) builds 5 patches that would update system/users/processes/filesystem/network, but this is **only used by `FakeFS.switch_persona()`**, which is **never called from the dispatcher.** The dispatcher only uses `PersonaSwitcher` which operates on the overlay.

**Critical gap:** The `FakeFS.switch_persona()` and `apply_transition_step()` methods exist and are tested in isolation, but the `HoneypotCommandDispatcher` uses `PersonaSwitcher` (overlay-based) instead. The FakeFS-level transition (hostname change, user list change, etc.) never actually fires in the dispatcher pipeline. Only overlay file/directory/process additions happen.

---

## 4. Observability

### Per-command Logging

File: `event_logging/session_logger.py:SessionLogger.log_command()` (line 225)

Fields logged per command (JSON-lines format):
```json
{
  "timestamp": "2026-08-31T12:00:00.000Z",
  "event_type": "command",
  "session_id": "abc123",
  "attacker_ip": "1.2.3.4",
  "attacker_port": 55555,
  "command": "cat /etc/passwd",
  "cwd": "/home/ubuntu",
  "threat_score_after": 6,
  "persona": "generic_linux",
  "response_source": "dict",
  "threat_category": "exploration",
  "threat_score_delta": 6,
  "threat_level": "low",
  "patterns_detected": []
}
```

Written to `event_logging/logs/honeypot.jsonl`, rotated daily at UTC midnight, 30 backups kept.

Other event types: `session_start`, `login_attempt`, `persona_switch`, `session_end`.

### Dashboard

File: `dashboard/app.py` — FastAPI app on port 8080.

**How it gets data:** Two mechanisms:
1. **HTTP POST push** from `cowrie_hook.py:_notify_dashboard()` (line 52) — best-effort HTTP POST to `http://127.0.0.1:8080/api/session/{start|command|switch|end}` with 1-second timeout. Fires after every command.
2. **WebSocket** at `/ws` — pushes full state to connected browser clients every 2 seconds.

**What it shows:**
- Panel 1: Active sessions (IP, score, level, persona, command count, duration)
- Panel 2: Score timeline per session
- Panel 3: Live command feed (last 50 commands across all sessions)
- Panel 4: Stats (avg duration, Level 3+ %, fingerprint score, Cowrie comparison numbers)

**The dashboard does update live** when commands flow through the dispatcher with the dashboard running.

**Script launcher:** The dashboard also has a script catalog (`SCRIPTS_CATALOG`, line 416) with 8 registered demo/scenario scripts that can be launched from the dashboard UI via subprocess.

### Decision Trace

**There is no per-command decision trace.** The closest thing is:
- The `ThreatDecision` dataclass (returned from scorer, consumed in dispatcher) contains: `command_category`, `score_delta`, `patterns_detected`, `trigger_persona_switch`, `switch_to_persona`
- This data is logged to JSON-lines and pushed to the dashboard
- But there is no trace of: parsed tokens, which routing path was chosen (fast/LLM), which handler ran, overlay changes made, or the LLM prompt/response

---

## 5. How to Run It

### Local (Windows/Linux/Mac — no Cowrie, no real SSH)

```bash
# 1. Clone and install
git clone <repo>
cd adaptive-honeypot
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# 2. Optional: create .env with API keys
cp .env.example .env
# Edit .env to set GEMINI_API_KEY or ANTHROPIC_API_KEY
# Without an API key, unknown commands return "command not found" instead of LLM output

# 3. Start the dashboard backend
python -m uvicorn dashboard.app:app --host 0.0.0.0 --port 8080

# 4. In another terminal, be the attacker
python scripts/interactive_honeypot.py

# 5. Open browser to http://localhost:8080 for dashboard
# Or http://localhost:3000 if you also run the Next.js frontend (npm run dev)
```

**Dependencies:** Python 3.11+, packages in requirements.txt (fastapi, uvicorn, pydantic, python-dotenv, httpx, python-json-logger, google-generativeai, anthropic, paramiko for tests, requests for demo scripts).

### Production (Oracle Cloud / any Linux VM — with real SSH)

```bash
# On the VM:
bash scripts/setup.sh          # Install Cowrie, Python deps, iptables
bash cowrie_integration/install_hook.sh  # Patch Cowrie to use our dispatcher
# Or from dev machine:
bash scripts/deploy.sh root@<vm-ip> --first-run
```

This patches Cowrie's `protocol.py` to intercept `lineReceived()` and route commands through our `HoneypotCommandDispatcher`. Port 22 → 2222 via iptables.

### Can another laptop SSH in right now?

**No, not on Windows.** There is no SSH server component running locally. The interactive shell (`scripts/interactive_honeypot.py`) simulates the experience in a terminal but doesn't listen on any port.

To accept real SSH connections you need:
1. A Linux VM with Cowrie installed
2. The install hook applied
3. Port 2222 (or 22 redirected) open
4. The dashboard running on port 8080

### API Key Status

**Unknown at runtime.** There is no `.env` file committed (correct — it's gitignored). The `.env.example` shows the expected keys. Without `GEMINI_API_KEY` or `ANTHROPIC_API_KEY`, the LLM path returns fallback errors. Without `ABUSEIPDB_API_KEY`, IP reputation returns zero bonus.

---

## 6. Status of Known Issues

### Cowrie dispatcher using SimpleSession instead of SessionManager

**Partly true.** The `HoneypotCommandDispatcher` (cowrie_hook.py:68) creates a `SimpleSession` (command_handlers.py:41, a dataclass) rather than using the full `SessionManager` (session_manager.py:84). `SessionManager` exists as a complete class with `create_session()`, `update_after_command()`, `record_persona_switch()`, `close_session()`, and async IP reputation lookup. But the dispatcher instantiates `SimpleSession` directly (cowrie_hook.py:107) and manages threat scoring inline. The `SessionManager` is fully implemented but **not wired into the main dispatcher pipeline.**

Evidence: `cowrie_hook.py` imports `SimpleSession` from `dictionary.command_handlers` (line 37), not `SessionManager` from `honeypot.session_manager`.

### Fingerprint resistance 22/22 headline vs actual results

**The last actual run (evaluation/fingerprint_report.json, generated 2026-10-24) shows 21/22 passed.** The one failure: `timing_simple_cmd` — `ls` took 1046.6ms, exceeding the 200ms threshold. This appears to be cold-start overhead (subsequent timing checks show ~1020-1050ms, suggesting the first FakeFS load is slow).

The `run_evaluation.py` summary table (line 329) prints `"FakeFS Consistency Score": "100% (124 assertions)"` but this is a **hardcoded string**, not computed from running `test_consistency.py` (which doesn't exist as an actual test file — `tests/test_fakefs.py` is a stub with only TODO comments).

### Cowrie 8/22 baseline being hardcoded

**Confirmed hardcoded.** `fingerprint_checker.py:run_against_cowrie_baseline()` (line 611) returns a **hardcoded list of 22 CheckResult objects** with hand-assigned pass/fail values. No actual Cowrie instance is tested. The docstring says "Returns hardcoded results based on known Cowrie weaknesses." The dashboard also hardcodes `cowrie_fingerprint: 8` (dashboard/app.py:242) and `cowrie_avg_duration: "0m 44s"` (line 234) and `cowrie_level3_pct: 11` (line 236).

### LLM latency figure

**Not measured in production.** The 3-second timeout in `response_engine.py:LLM_TIMEOUT_SECONDS` is the maximum allowed, not a measured figure. The fingerprint timing checks measure local overhead (FakeFS + dictionary handlers), not LLM round-trip time. The evaluation script (`run_evaluation.py`) sends 25 commands, all of which use the fast path — no LLM calls are made during evaluation.

### Oracle Cloud deployment / live attacker data

**No evidence of live deployment or real attacker data in the repo.** The deploy scripts exist (`scripts/deploy.sh`, `cowrie_integration/install_hook.sh`) and the git log shows Cowrie integration work (8 commits on 2026-08-31 fixing the install hook). But:
- No attacker session logs in `event_logging/logs/` are committed
- No real-IP data anywhere
- The session_simulation.json uses a hardcoded IP `185.220.101.42`
- The install_hook.sh commits suggest iteration on getting Cowrie patching working, but no commit confirms it ever ran successfully end-to-end

---

## 7. Tests and Evaluation

### Test Files

| File | What It Tests | Status |
|------|--------------|--------|
| `tests/test_fakefs.py` | FakeFS query methods | **STUB — 0 tests, only TODO comments** |
| `tests/test_session_logger.py` | SessionLogger events, rotation, summaries | **12 real tests, all appear functional** |
| `tests/test_cowrie_integration.py` | End-to-end SSH capture | **Gated on live Cowrie — skips when honeypot not reachable** |
| `tests/fingerprint_tests/fingerprint_checker.py` | 22 fingerprint resistance checks | **Runnable locally, tests our dispatcher directly** |

**Total real test count:** ~12 unit tests (session_logger) + 22 fingerprint checks + 1 gated integration test. The `test_fakefs.py` file is empty.

There are **no unit tests for:**
- Command parser
- Command handlers (all 40+)
- Threat scorer (weights, patterns, persona switch logic)
- Response engine (routing, LLM fallback, post-processing)
- Session overlay
- Persona switcher (transition logic)
- Session manager
- IP reputation

### Evaluation Scripts

| Script | Path | What It Does |
|--------|------|--------------|
| `run_evaluation.py` | `scripts/run_evaluation.py` | Runs fingerprint checks + 25-command simulation, produces summary table |
| `demo_session.py` | `scripts/demo_session.py` | 10-command presentation demo |
| `demo_session_2.py` | `scripts/demo_session_2.py` | 14-command stealth recon demo |
| `demo_session_3.py` | `scripts/demo_session_3.py` | 10-command ransomware/lateral movement demo |
| `attack_scenarios.py` | `scripts/attack_scenarios.py` | 4 scenario modes (botnet, credential, privesc, persistence) |
| `interactive_honeypot.py` | `scripts/interactive_honeypot.py` | Interactive terminal with live dashboard feed |

### Collected Data

- `evaluation/fingerprint_report.json` — last run 2026-10-24, shows 21/22 passed
- `evaluation/fingerprint_report.txt` — text version of same
- `evaluation/session_simulation.json` — 25-command simulation output with scores and transitions
- No real attacker session data exists in the repo

---

## 8. Changes Since Late September

The most recent commit is **2026-08-31**. There are **zero commits after September 2026**.

Full commit timeline:
```
2026-06-17  Initial commit
2026-06-23  Import from LLM-HONEYPOT repo, Next.js frontend, deployment config, Gemini integration
2026-06-23  Next.js frontend styles
2026-06-26  Interactive shell, attack scenarios, Next.js wiring
2026-08-31  7 commits in one day fixing Cowrie integration hook:
            - Connect live Cowrie SSH → dashboard REST endpoints
            - Fix protocol.py patching (lineReceived interception)
            - Enhance regex matching for Python type hints
            - Fix bash syntax in install_hook.sh
            - Use single-line call to eliminate IndentationErrors
            - Set PYTHONPATH for ModuleNotFoundError
            - Install Cowrie as editable package
```

The evaluation files (`fingerprint_report.json`, `session_simulation.json`) are dated 2026-10-24 but were likely generated locally (not committed as a code change — they're listed as modified in `git status`).

---

## 9. Honest Gap List

### Fake / Hardcoded

- **Cowrie 8/22 fingerprint baseline is entirely fabricated.** `fingerprint_checker.py:run_against_cowrie_baseline()` returns hardcoded pass/fail values. No Cowrie instance was tested.
- **Cowrie comparison stats in dashboard are hardcoded:** `cowrie_avg_duration: "0m 44s"`, `cowrie_level3_pct: 11`, `cowrie_fingerprint: 8` — none measured.
- **"124 assertions" consistency claim is a hardcoded string** in `run_evaluation.py:329`. No test file `test_consistency.py` exists. The persona_validator has 8 rules that run at load time, but there's no test suite counting "124 assertions."
- **`handle_wget()` fake download IP is always `93.184.216.34`** regardless of URL.
- **All wget/curl downloads produce identical HTML content** regardless of what URL was requested.
- **`handle_which()` has a hardcoded dict of 45 binary→path mappings** (command_handlers.py:510-535). This IS a hardcoded string table, though the CLAUDE.md rules specifically say "no hardcoded strings for system facts." Defense: `which` output is system config, not persona-specific. Still technically a violation.

### Half-Built / Not Wired Up

- **`SessionManager` exists but is not used.** The full Pydantic-modeled `SessionManager` with async IP reputation, proper lifecycle, and state invariants is in `session_manager.py` but the dispatcher uses `SimpleSession` (a plain dataclass) instead.
- **FakeFS gradual transition (`switch_persona()` + `apply_transition_step()`) is not used by the dispatcher.** The persona switcher operates on the overlay only. System-level changes (hostname, user list, network state, etc.) planned by `FakeFS._plan_transition()` never execute.
- **Hostname never changes during persona transition.** The overlay-based switcher adds files and processes but cannot change hostname, kernel, or /etc/passwd. After "switching" to finance_server, `hostname` still returns `web-srv-03` (generic_linux's hostname).
- **LLM responses are not fed back into FakeFS/overlay.** If the LLM says a file exists, subsequent fast-path commands won't find it.
- **No `test_consistency.py` file.** Referenced in CLAUDE.md sprint plan and evaluation script, but never created. `test_fakefs.py` is a stub with only TODO comments.
- **Redis session store** mentioned in `.env.example` (`REDIS_URL`) but never used. Everything is in-memory.

### Would Embarrass Under Examination

- **"22/22 fingerprint resistance"** was never achieved. Last actual run: 21/22. The timing check failure (1046ms for `ls`) is a real issue.
- **No real attacker data.** Every evaluation metric comes from scripted simulations, not live traffic.
- **The Cowrie integration may not work end-to-end.** The 7 rapid-fire commits on 2026-08-31 show iterating on install_hook.sh failures, but no commit message confirms success. No test proves a real SSH session flows through our dispatcher.
- **Score weights are unjustified.** If asked "why is `wget` scored 15 but `curl` also 15, and `nc` is 20?" — there's no documented rationale, paper citation, or calibration data.
- **Pattern detection uses whole-session scan for 6 of 9 patterns.** `credential_harvesting`, `ssh_key_theft_attempt`, `active_network_scan`, `network_mapping`, `persistence_attempt`, and `data_staging` check the ENTIRE command history, not a window. This means typing `cat /etc/passwd` in command 1 and `cat /etc/shadow` in command 200 still triggers `credential_harvesting`. This may be intentional but is academically questionable.
- **Pipe handling is simplistic.** `_apply_pipe()` in response_engine.py handles head, tail, wc, grep, sort, uniq as string operations on the output. Complex pipes (`ps aux | grep ssh | awk '{print $2}'`) only handle the first pipe segment; `awk` falls through.
- **The Next.js frontend** (app/, components/, lib/) exists but is a separate layer from the FastAPI dashboard — it connects via WebSocket to the same backend. Its status is unclear from the Python codebase alone.
- **`handle_sudo()` always denies.** Real attackers on honeypots often succeed with sudo after a password prompt. Our system always returns "not allowed to execute" which is a fingerprint risk.
- **No MITRE ATT&CK mapping** despite the project being an academic cybersecurity system.
