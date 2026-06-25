# System Architecture — Adaptive LLM-Powered Honeypot

## 1. High-Level System Overview

```
                            ┌─────────────────────────────────────────────────────┐
                            │                    INTERNET                         │
                            │          Real attackers / Bots / Scanners           │
                            └───────────────────────┬─────────────────────────────┘
                                                    │
                                                    │  SSH connection (port 22)
                                                    │
                            ┌───────────────────────▼─────────────────────────────┐
                            │              UBUNTU 22.04 VM                        │
                            │                                                     │
                            │   iptables NAT: port 22 ──REDIRECT──► port 2222     │
                            │                                                     │
                            │  ┌──────────────────────────────────────────────┐   │
                            │  │         MODULE 1: COWRIE SSH SERVER          │   │
                            │  │         (port 2222)                          │   │
                            │  │                                              │   │
                            │  │  • SSH-2.0-OpenSSH_8.9p1 banner             │   │
                            │  │  • Accepts login after N attempts            │   │
                            │  │  • Captures all keystrokes                   │   │
                            │  │  • Manages PTY / terminal emulation          │   │
                            │  │                                              │   │
                            │  │  cowrie/shell/protocol.py  ◄── PATCHED       │   │
                            │  │  to intercept every command and route it     │   │
                            │  │  through our Adaptive Honeypot Engine        │   │
                            │  └──────────────────┬───────────────────────────┘   │
                            │                     │                               │
                            │                     │ raw command string             │
                            │                     ▼                               │
                            │  ┌──────────────────────────────────────────────┐   │
                            │  │    COWRIE HOOK  (cowrie_hook.py)             │   │
                            │  │    Entry point: HoneypotCommandDispatcher    │   │
                            │  │                                              │   │
                            │  │  • One dispatcher per SSH session            │   │
                            │  │  • Owns: FakeFS, ResponseEngine, Session,   │   │
                            │  │          PersonaSwitcher, SessionLogger      │   │
                            │  │  • dispatch(raw_input) → (response, source)  │   │
                            │  └──────────────────┬───────────────────────────┘   │
                            │                     │                               │
                            │      ┌──────────────┼──────────────┐                │
                            │      │              │              │                │
                            │      ▼              ▼              ▼                │
                            │  ┌────────┐  ┌───────────┐  ┌──────────┐           │
                            │  │Response│  │  Threat   │  │  Event   │           │
                            │  │Engine  │  │  Scorer   │  │  Logger  │           │
                            │  └────┬───┘  └─────┬─────┘  └────┬─────┘           │
                            │       │            │              │                 │
                            │       ▼            ▼              ▼                 │
                            │   ┌───────┐  ┌──────────┐  ┌───────────┐           │
                            │   │FakeFS │  │ Persona  │  │  JSON     │           │
                            │   │       │  │ Switcher │  │  Logs     │           │
                            │   └───────┘  └──────────┘  └─────┬─────┘           │
                            │                                   │                 │
                            │                     ┌─────────────▼──────────┐      │
                            │                     │     DASHBOARD          │      │
                            │                     │   FastAPI + WebSocket  │      │
                            │                     │     (port 8080)        │      │
                            │                     └────────────────────────┘      │
                            └─────────────────────────────────────────────────────┘
```

---

## 2. Detailed Command Processing Pipeline

Every single command the attacker types flows through this exact 7-stage pipeline:

```
 ATTACKER TYPES: cat /etc/passwd
        │
        │ Stage 1: Cowrie captures raw SSH input
        ▼
┌─────────────────────────────────────────────────────────────────────┐
│  COWRIE HOOK — dispatcher.dispatch_async("cat /etc/passwd")        │
│  File: honeypot/cowrie_hook.py                                     │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
        │ Stage 2: Parse the command
        ▼
┌─────────────────────────────────────────────────────────────────────┐
│  COMMAND PARSER                                                     │
│  File: honeypot/command_parser.py                                   │
│                                                                     │
│  Input:  "cat /etc/passwd"                                          │
│  Output: ParsedCommand(                                             │
│            binary="cat",                                            │
│            args=["/etc/passwd"],                                     │
│            flags=[],                                                │
│            is_piped=False,                                          │
│            is_chained=False,                                        │
│            redirects=[],                                            │
│          )                                                          │
│                                                                     │
│  Also handles: pipes (|), redirects (>), chains (;/&&/||),          │
│  sudo/su subcommands, env var refs ($VAR), quoting                  │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
        │ Stage 3: Try fast path, else LLM
        ▼
┌─────────────────────────────────────────────────────────────────────┐
│  RESPONSE ENGINE                                                    │
│  File: honeypot/response_engine.py                                  │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  FAST PATH (dictionary lookup)          < 50ms              │    │
│  │  File: dictionary/command_registry.py                       │    │
│  │        dictionary/command_handlers.py                       │    │
│  │                                                             │    │
│  │  40+ commands: ls, cat, ps, whoami, id, uname, hostname,   │    │
│  │  cd, echo, env, find, grep, sudo, wget, curl, netstat,     │    │
│  │  ifconfig, ip, df, free, head, tail, mkdir, touch, rm,     │    │
│  │  cp, mv, chmod, chown, which, w, last, groups, ssh, su,    │    │
│  │  history, uptime, date, printenv + aliases (ll, dir, ss)   │    │
│  │                                                             │    │
│  │  Every handler queries FakeFS — NEVER hardcoded strings     │    │
│  │  Example: handle_cat(fakefs, session, parsed)               │    │
│  │    → fakefs.get_file_content("/etc/passwd")                 │    │
│  │    → returns formatted /etc/passwd from persona JSON        │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │                                       │
│              handler found? │                                       │
│             ┌───YES─────────┴────────NO───┐                        │
│             │                             │                        │
│             ▼                             ▼                        │
│  ┌──────────────────┐      ┌──────────────────────────────────┐    │
│  │ Return response  │      │  LLM PATH (Gemini / Claude)     │    │
│  │ source="fast_    │      │  Timeout: 3 seconds              │    │
│  │ path"            │      │                                  │    │
│  └──────────────────┘      │  1. build_llm_prompt()           │    │
│                            │     System msg includes:          │    │
│                            │     - hostname, OS, kernel        │    │
│                            │     - current user + cwd          │    │
│                            │     - all users on system         │    │
│                            │     - running processes           │    │
│                            │     - network interfaces          │    │
│                            │     - persona type                │    │
│                            │     - last 10 commands+outputs    │    │
│                            │     - threat level                │    │
│                            │     ALL from FakeFS (grounded)    │    │
│                            │                                  │    │
│                            │  2. Call LLM API                  │    │
│                            │     Priority: Gemini → Anthropic  │    │
│                            │                                  │    │
│                            │  3. post_process_response()       │    │
│                            │     Strip: markdown, code fences, │    │
│                            │     "Sure,", "I'm an AI",         │    │
│                            │     commentary, explanations       │    │
│                            │                                  │    │
│                            │  4. On timeout/error:             │    │
│                            │     "-bash: cmd: command not      │    │
│                            │      found"                       │    │
│                            │     source="fallback"             │    │
│                            └────────────────┬─────────────────┘    │
│                                             │                      │
│  ┌──────────────────────────────────────────┘                      │
│  │                                                                 │
│  │  Post-processing (if applicable):                               │
│  │  • Pipe: ls | grep foo → filter output client-side              │
│  │    Supported: head, tail, grep, wc, sort, uniq                  │
│  │  • Redirect: echo hi > file.txt → write to session overlay      │
│  │  • Timing jitter: 10-200ms random delay (anti-fingerprinting)   │
│  │                                                                 │
└──┼─────────────────────────────────────────────────────────────────┘
   │
   │ Stage 4: Score the command
   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  THREAT SCORER                                                      │
│  File: honeypot/threat_scorer.py                                    │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Layer 1: EXACT MATCH (fast)                                  │  │
│  │  "cat /etc/passwd" → (EXPLORATION, score_delta=6)             │  │
│  │                                                               │  │
│  │  100+ exact command-to-score mappings:                        │  │
│  │  BENIGN (0):   ls, pwd, cd, echo, clear, exit, date, touch   │  │
│  │  RECON (1-4):  whoami, id, uname, hostname, env, ifconfig    │  │
│  │  EXPLORE (4-8): cat /etc/passwd, ps aux, find, crontab -l    │  │
│  │  PRIV_ESC (8-15): sudo, su, cat /etc/shadow, chmod 777       │  │
│  │  EXFIL (14-25):  wget, curl, nc, bash -i, /dev/tcp           │  │
│  │  LATERAL (3-20):  ssh, nmap, arp, ping, cat ~/.ssh/id_rsa    │  │
│  └──────────────────────────────┬────────────────────────────────┘  │
│                                 │ no exact match?                   │
│                                 ▼                                   │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Layer 2: BINARY NAME + ARGUMENT ESCALATORS (fallback)        │  │
│  │                                                               │  │
│  │  Binary score: "find" → (EXPLORATION, base=4)                 │  │
│  │  + argument bonus: "-perm -4000" → +8                         │  │
│  │  = total delta: 12                                            │  │
│  │                                                               │  │
│  │  Escalation triggers: /etc/shadow (+8), /root/.ssh (+10),     │  │
│  │  /dev/tcp (+15), id_rsa (+8), .env (+6), 777 (+5), ...       │  │
│  └──────────────────────────────┬────────────────────────────────┘  │
│                                 │                                   │
│                                 ▼                                   │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  PATTERN DETECTOR (multi-command analysis)                    │  │
│  │                                                               │  │
│  │  Scans command history for attack sequences:                  │  │
│  │  • rapid_recon_burst:        5+ recon cmds in last 10 → +8   │  │
│  │  • privilege_escalation_chain: sudo + shadow in 5 cmds → +12 │  │
│  │  • credential_harvesting:    passwd + shadow in session → +15 │  │
│  │  • ssh_key_theft_attempt:    .ssh + id_rsa → +12             │  │
│  │  • download_and_execute:     wget + chmod +x → +20           │  │
│  │  • network_mapping:          netstat + arp → +10             │  │
│  │  • active_network_scan:      nmap/masscan → +18              │  │
│  │  • persistence_attempt:      crontab + rc.local → +15        │  │
│  │  • data_staging:             find + tar/zip → +15            │  │
│  │  Each pattern fires ONCE per session                          │  │
│  └──────────────────────────────┬────────────────────────────────┘  │
│                                 │                                   │
│                                 ▼                                   │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  PERSONA SWITCH DECIDER                                       │  │
│  │                                                               │  │
│  │  Output: ThreatDecision {                                     │  │
│  │    score_delta, new_total_score (0-100, never decreases),     │  │
│  │    threat_level (LOW/MEDIUM/HIGH/CRITICAL),                   │  │
│  │    trigger_persona_switch (bool),                             │  │
│  │    switch_to_persona, switch_reason                           │  │
│  │  }                                                            │  │
│  │                                                               │  │
│  │  Switch rules:                                                │  │
│  │   Score 0-20  (LOW):      generic_linux (stay)                │  │
│  │   Score 21-50 (MEDIUM):   enrich (no switch yet)              │  │
│  │   Score 51-80 (HIGH):     → dev_workstation                   │  │
│  │   Score 81+   (CRITICAL): → finance_server                    │  │
│  │                                                               │  │
│  │  Constraints:                                                 │  │
│  │   • Max 2 switches per session                                │  │
│  │   • Never switch backward (finance → dev forbidden)           │  │
│  │   • Certain patterns force immediate step-up                  │  │
│  └──────────────────────────────┬────────────────────────────────┘  │
└─────────────────────────────────┼───────────────────────────────────┘
                                  │
   │ Stage 5: Persona transition (if triggered)
   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PERSONA SWITCHER                                                   │
│  File: honeypot/persona_switcher.py                                 │
│                                                                     │
│  Gradual transition over 5 commands (never abrupt):                 │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  Example: generic_linux → dev_workstation                   │    │
│  │                                                             │    │
│  │  Step 1 (SEEDING):    /home/john.dev directory appears      │    │
│  │  Step 2 (SEEDING):    .gitconfig file appears               │    │
│  │  Step 3 (BUILDING):   node process in ps output             │    │
│  │  Step 4 (BUILDING):   projects/webapp/.env with creds       │    │
│  │  Step 5 (COMPLETING): .ssh/id_rsa + docker daemon           │    │
│  │                                                             │    │
│  │  All changes go to SESSION OVERLAY (not FakeFS)             │    │
│  │  Session history, cwd, threat score NEVER reset             │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  Example: dev_workstation → finance_server                  │    │
│  │                                                             │    │
│  │  Step 1 (SEEDING):    /opt/finapp directory appears         │    │
│  │  Step 2 (SEEDING):    db_config.properties file             │    │
│  │  Step 3 (BUILDING):   PostgreSQL + Java processes           │    │
│  │  Step 4 (BUILDING):   /data/reports/ with CSV files         │    │
│  │  Step 5 (COMPLETING): audit_log.csv + prod DB creds         │    │
│  └─────────────────────────────────────────────────────────────┘    │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
   │ Stage 6: Update session state + log
   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  COWRIE HOOK — back in dispatch_async()                             │
│                                                                     │
│  • Append to command_history (append-only, never overwritten)       │
│  • Update threat_score (monotonic — never decreases)                │
│  • Add detected patterns to session set                             │
│  • Log command via SessionLogger                                    │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  SESSION LOGGER  (event_logging/session_logger.py)          │    │
│  │                                                             │    │
│  │  Writes structured JSON to event_logging/logs/:             │    │
│  │  {                                                          │    │
│  │    "event": "command",                                      │    │
│  │    "session_id": "abc123",                                  │    │
│  │    "command": "cat /etc/passwd",                            │    │
│  │    "response_source": "dict",                               │    │
│  │    "threat_score_after": 6,                                 │    │
│  │    "threat_category": "exploration",                        │    │
│  │    "threat_level": "low",                                   │    │
│  │    "persona": "generic_linux",                              │    │
│  │    "timestamp": "2026-06-23T10:15:30Z"                      │    │
│  │  }                                                          │    │
│  └─────────────────────────────────────────────────────────────┘    │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
   │ Stage 7: Return response to attacker
   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  COWRIE SSH SERVER                                                  │
│                                                                     │
│  Sends our response text back over the SSH channel.                 │
│  Attacker sees:                                                     │
│                                                                     │
│  ubuntu@web-srv-03:~$ cat /etc/passwd                               │
│  root:x:0:0:root:/root:/bin/bash                                    │
│  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin                    │
│  ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash                   │
│  www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin               │
│  ...                                                                │
│                                                                     │
│  Displays our prompt: ubuntu@web-srv-03:~$                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Data Layer — FakeFS & Session Overlay

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  FAKEFS  (honeypot/fakefs.py)                                               │
│  THE SINGLE SOURCE OF TRUTH — all modules query this, nothing is invented   │
│                                                                             │
│  Backed by persona JSON files:                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  personas/generic_linux.json     (default — basic web server)          │ │
│  │  personas/dev_workstation.json   (dev machine with .env, API keys)     │ │
│  │  personas/finance_server.json    (financial DB, CSV reports)            │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  Each persona JSON validated by persona_validator.py (8 consistency rules): │
│  Rule 1: users in /etc/passwd == users in /home/                            │
│  Rule 2: file sizes match actual content length                             │
│  Rule 3: open ports have matching processes                                 │
│  Rule 4: process owners are valid users                                     │
│  Rule 5: timestamps are in the past                                         │
│  Rule 6: PIDs are realistic (non-sequential)                                │
│  Rule 7: network interfaces have valid IPs                                  │
│  Rule 8: /etc/hostname matches system_info.hostname                         │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │  What FakeFS provides (Pydantic models):                         │       │
│  │                                                                  │       │
│  │  SystemInfo:     hostname, kernel, arch, uptime, timezone        │       │
│  │  UserInfo[]:     username, uid, gid, home, shell, groups,        │       │
│  │                  password_hash, last_login                       │       │
│  │  ProcessInfo[]:  pid, ppid, user, cpu%, mem%, vsz, rss,          │       │
│  │                  tty, stat, start_time, command                  │       │
│  │  NetworkInfo:    interfaces[], open_ports[], connections[]        │       │
│  │  Filesystem:     full directory tree with contents, perms,       │       │
│  │                  owners, timestamps, sizes                       │       │
│  └──────────────────────────────────────────────────────────────────┘       │
│                                                                             │
│  Key methods:                                                               │
│  ├─ get_directory_listing(path, flags)  → ls output                         │
│  ├─ get_file_content(path)             → file text / PermissionError        │
│  ├─ get_process_list(flags)            → ps aux output                      │
│  ├─ get_network_state()                → netstat / ifconfig data            │
│  ├─ get_user(name)                     → UserInfo for whoami/id             │
│  ├─ get_environment(user)              → env vars dict                      │
│  ├─ get_system_info()                  → hostname, kernel, etc.             │
│  ├─ get_llm_context_summary()          → everything for LLM prompt         │
│  └─ resolve_path(cwd, relative)        → absolute path                     │
│                                                                             │
│  ═══════════════════════════════════════════════════════════════════════     │
│                                                                             │
│  SESSION OVERLAY  (honeypot/session_overlay.py)                             │
│  Per-session in-memory write layer ON TOP of FakeFS                         │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │                                                                  │       │
│  │  READ path:   overlay.has(path)?  →  return overlay entry        │       │
│  │               overlay.deleted(path)?  →  FileNotFoundError       │       │
│  │               else  →  fall through to FakeFS                    │       │
│  │                                                                  │       │
│  │  WRITE ops:   mkdir, touch, rm, cp, mv, echo > file              │       │
│  │               → all write to overlay dict, NOT FakeFS            │       │
│  │                                                                  │       │
│  │  Isolation:   each session gets its own overlay                  │       │
│  │               attacker A's files invisible to attacker B         │       │
│  │                                                                  │       │
│  │  Lifecycle:   created at session start                           │       │
│  │               discarded at session end (nothing persists)        │       │
│  │                                                                  │       │
│  │  Persona switcher writes new files here during transition        │       │
│  │                                                                  │       │
│  └──────────────────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Three Persona States

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          PERSONA LIFECYCLE                                   │
│                                                                             │
│  Score: 0 ─────────────── 51 ──────────────── 81 ──────────────── 100      │
│         │    LOW/MEDIUM    │      HIGH        │     CRITICAL      │         │
│         │                  │                  │                    │         │
│         ▼                  ▼                  ▼                    │         │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────┐       │         │
│  │ GENERIC     │──►│ DEV          │──►│ FINANCE          │       │         │
│  │ LINUX       │   │ WORKSTATION  │   │ SERVER           │       │         │
│  │             │   │              │   │                  │       │         │
│  │ web-srv-03  │   │ dev-wk-07   │   │ fin-db-prod-01  │       │         │
│  │ user:ubuntu │   │ user:john.dev│   │ user:finapp     │       │         │
│  │             │   │              │   │                  │       │         │
│  │ Processes:  │   │ Processes:   │   │ Processes:       │       │         │
│  │ nginx       │   │ node         │   │ postgresql       │       │         │
│  │ sshd        │   │ docker       │   │ java (Spring)    │       │         │
│  │ cron        │   │ VS Code      │   │ cron jobs        │       │         │
│  │             │   │ git          │   │                  │       │         │
│  │ Files:      │   │              │   │ Files:           │       │         │
│  │ web configs │   │ Files:       │   │ financial CSVs   │       │         │
│  │ basic logs  │   │ .env (creds) │   │ DB configs       │       │         │
│  │             │   │ source code  │   │ audit logs       │       │         │
│  │ Value: LOW  │   │ Dockerfile   │   │ prod passwords   │       │         │
│  │             │   │ SSH keys     │   │                  │       │         │
│  │             │   │              │   │ Value: HIGH      │       │         │
│  │             │   │ Value: MED   │   │ (keep attacker   │       │         │
│  │             │   │              │   │  engaged longest) │       │         │
│  └─────────────┘   └──────────────┘   └──────────────────┘       │         │
│                                                                             │
│  Transition is GRADUAL over 5 commands (seeding → building → completing)    │
│  Session history, cwd, and score are NEVER reset during a switch            │
│  Max 2 switches per session │ Never switches backward                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. External Services

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  EXTERNAL API CALLS                                                         │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  LLM API  (response_engine.py → _detect_llm_provider)                │  │
│  │                                                                       │  │
│  │  Priority: GEMINI_API_KEY → ANTHROPIC_API_KEY → fallback             │  │
│  │                                                                       │  │
│  │  ┌─────────────────────┐     ┌──────────────────────┐                │  │
│  │  │ Google Gemini API   │     │ Anthropic Claude API  │                │  │
│  │  │ Model: gemini-2.0-  │     │ Model: claude-sonnet- │                │  │
│  │  │   flash (default)   │     │   4-20250514          │                │  │
│  │  │ Free tier available │     │ Paid                   │                │  │
│  │  └─────────────────────┘     └──────────────────────┘                │  │
│  │                                                                       │  │
│  │  Timeout: 3 seconds │ Fallback: "-bash: cmd: command not found"      │  │
│  │  Used for: ~20% of commands (novel/unusual ones)                     │  │
│  │  Fast path handles: ~80% (dictionary lookup, no API needed)          │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  AbuseIPDB API  (honeypot/ip_reputation.py)                          │  │
│  │                                                                       │  │
│  │  Called ONCE per session at session start                             │  │
│  │  Returns: abuse_confidence_score, is_tor, is_vpn, country, ISP       │  │
│  │  Adds initial_score_bonus to session threat score                    │  │
│  │  Cached in-memory (same IP = no repeat API call)                     │  │
│  │  Timeout: 3 seconds │ Fallback: score_bonus=0 (never blocks)        │  │
│  │  Free tier: 1,000 checks/day                                        │  │
│  │  Optional: system works fine without it                              │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Dashboard & Monitoring

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  DASHBOARD  (dashboard/app.py)                                              │
│  FastAPI + WebSocket  │  Port 8080                                          │
│                                                                             │
│  ┌────────────────────┐  ┌────────────────────┐                            │
│  │  Panel 1:          │  │  Panel 2:          │                            │
│  │  Active Sessions   │  │  Threat Score      │                            │
│  │                    │  │  Timeline          │                            │
│  │  • Session ID      │  │                    │                            │
│  │  • Attacker IP     │  │  Line chart per    │                            │
│  │  • Threat Level    │  │  session showing   │                            │
│  │  • Current Persona │  │  score progression │                            │
│  │  • Command Count   │  │  + persona switch  │                            │
│  │  • Duration        │  │  markers           │                            │
│  └────────────────────┘  └────────────────────┘                            │
│                                                                             │
│  ┌────────────────────┐  ┌────────────────────┐                            │
│  │  Panel 3:          │  │  Panel 4:          │                            │
│  │  Live Command Feed │  │  System Stats      │                            │
│  │                    │  │                    │                            │
│  │  Real-time feed of │  │  • Total sessions  │                            │
│  │  commands across   │  │  • Unique IPs      │                            │
│  │  all sessions with │  │  • Persona switches│                            │
│  │  category + score  │  │  • Fingerprint     │                            │
│  │  color coding      │  │    resistance score│                            │
│  └────────────────────┘  └────────────────────┘                            │
│                                                                             │
│  REST endpoints:            WebSocket:                                      │
│  GET  /api/stats            /ws → pushes updates every 2s                   │
│  GET  /api/sessions                                                         │
│  POST /api/session/start                                                    │
│  POST /api/session/command                                                  │
│  POST /api/session/end                                                      │
│  POST /api/session/switch                                                   │
│  POST /api/fingerprint                                                      │
│  POST /api/dashboard/clear                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. File-Level Dependency Map

```
cowrie_hook.py ─────────┬──► response_engine.py ──┬──► command_parser.py
(entry point)           │                         ├──► command_registry.py ──► command_handlers.py
                        │                         ├──► fakefs.py ──► persona_validator.py
                        │                         │                 ├──► personas/generic_linux.json
                        │                         │                 ├──► personas/dev_workstation.json
                        │                         │                 └──► personas/finance_server.json
                        │                         └──► threat_scorer.py
                        │
                        ├──► fakefs.py (owns the FakeFS instance)
                        │
                        ├──► persona_switcher.py ──► session_overlay.py
                        │
                        └──► session_logger.py ──► event_logging/logs/*.json

session_manager.py ─────┬──► threat_scorer.py
(used by dashboard)     ├──► session_overlay.py
                        └──► ip_reputation.py ──► AbuseIPDB API

dashboard/app.py ───────── standalone FastAPI (reads from session_logger output)

cowrie_integration/ ────── install_hook.sh patches Cowrie → calls cowrie_hook.py
```

---

## 8. Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  YOUR WINDOWS MACHINE                                                       │
│                                                                             │
│  adaptive-honeypot/  (development + tests)                                  │
│  │                                                                          │
│  └──► bash scripts/deploy.sh ubuntu@VM_IP --first-run                       │
│       │                                                                     │
│       │  rsync (excludes .env, logs, .venv, __pycache__)                    │
│       ▼                                                                     │
└───────┼─────────────────────────────────────────────────────────────────────┘
        │
        │  SSH (port 2200 — your management port)
        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  UBUNTU 22.04 VM  (Oracle Cloud / DigitalOcean / AWS)                       │
│                                                                             │
│  /opt/adaptive-honeypot/         ← project code                             │
│  /opt/adaptive-honeypot/.venv/   ← Python virtualenv                        │
│  /opt/adaptive-honeypot/.env     ← API keys (never synced)                  │
│                                                                             │
│  /opt/cowrie/                    ← Cowrie SSH honeypot                       │
│  /opt/cowrie/cowrie-env/         ← Cowrie's own virtualenv                   │
│  /opt/cowrie/src/cowrie/shell/protocol.py  ← PATCHED by install_hook.sh     │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────┐                │
│  │  systemd services:                                       │                │
│  │                                                          │                │
│  │  cowrie.service              ← SSH honeypot (port 2222)  │                │
│  │  honeypot-dashboard.service  ← Dashboard (port 8080)     │                │
│  │  redis-server.service        ← Session store (optional)  │                │
│  │                                                          │                │
│  │  iptables NAT PREROUTING:                                │                │
│  │  port 22 → REDIRECT → port 2222                          │                │
│  └─────────────────────────────────────────────────────────┘                │
│                                                                             │
│  Ports:                                                                     │
│  22   → redirected to Cowrie (attackers connect here)                       │
│  2200 → your real SSH for management (restricted to your IP)                │
│  2222 → Cowrie direct (optional, for testing)                               │
│  8080 → Dashboard (restricted to your IP)                                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Evaluation Metrics Pipeline

```
┌──────────────────────────────┐
│  Metric 1:                   │      ┌──────────────────────────────┐
│  FINGERPRINT RESISTANCE      │      │  Metric 2:                   │
│                              │      │  FAKEFS CONSISTENCY          │
│  22 known honeypot checks:   │      │                              │
│  • /proc/cpuinfo entries     │      │  Cross-reference tests:      │
│  • disk size realistic?      │      │  • ls /home matches          │
│  • uptime plausible?         │      │    /etc/passwd users         │
│  • process count normal?     │      │  • ps aux owners are         │
│  • /etc/passwd realistic?    │      │    valid users               │
│  • network interfaces OK?    │      │  • file sizes match          │
│  • timezone consistent?      │      │    content length            │
│  • SSH banner credible?      │      │  • hostnames consistent      │
│  • ... etc                   │      │    across all outputs        │
│                              │      │                              │
│  Score: passes / 22          │      │  Score: consistent /         │
│  vs. vanilla Cowrie baseline │      │         total checks         │
└──────────────────────────────┘      └──────────────────────────────┘

┌──────────────────────────────┐      ┌──────────────────────────────┐
│  Metric 3:                   │      │  BASELINE:                   │
│  COMMAND DEPTH PROGRESSION   │      │  VANILLA COWRIE              │
│                              │      │                              │
│  For each attacker session:  │      │  Deployed on same VM,        │
│  classify every command:     │      │  different port.             │
│                              │      │  Same 3 metrics measured     │
│  Level 1: Basic recon        │      │  simultaneously.             │
│  Level 2: Exploration        │      │                              │
│  Level 3: Priv escalation    │      │  Comparison proves our       │
│  Level 4: Exfiltration       │      │  system keeps attackers      │
│                              │      │  engaged longer and          │
│  Score: sessions reaching    │      │  resists fingerprinting      │
│  Level 3+ / total sessions   │      │  better.                     │
│  (ours vs Cowrie)            │      │                              │
└──────────────────────────────┘      └──────────────────────────────┘
```
