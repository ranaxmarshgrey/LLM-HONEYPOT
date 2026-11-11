"""Sprint 6 — Live Threat Intelligence Dashboard.

FastAPI application with WebSocket real-time updates.
Serves a single HTML file at ``/`` that displays four panels:
    Panel 1 — Active Sessions
    Panel 2 — Threat Score Timeline
    Panel 3 — Live Command Feed
    Panel 4 — System Statistics

Also exposes REST endpoints for programmatic access and a WebSocket
endpoint (``/ws``) that pushes live updates every 2 seconds.

Usage::

    uvicorn dashboard.app:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

logger = logging.getLogger(__name__)

app = FastAPI(title="Adaptive Honeypot Dashboard", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# DashboardDataManager — the data layer the dashboard reads from
# ---------------------------------------------------------------------------

class DashboardDataManager:
    """Tracks all state needed by the dashboard.

    Fed by the dispatcher (or demo scripts) via ``record_*`` methods.
    Dashboard endpoints read from this via ``get_*`` methods.
    """

    def __init__(self) -> None:
        # Active sessions: session_id -> session dict
        self._sessions: Dict[str, Dict[str, Any]] = {}
        # Score timelines: session_id -> list of {cmd_index, score, persona}
        self._timelines: Dict[str, List[Dict[str, Any]]] = {}
        # Recent commands across all sessions (ring buffer)
        self._command_feed: deque = deque(maxlen=200)
        # Closed sessions for stats
        self._closed_sessions: List[Dict[str, Any]] = []
        # Persona switch events
        self._persona_switches: List[Dict[str, Any]] = []
        # Unique IPs seen today
        self._unique_ips: Set[str] = set()
        # Connected WebSocket clients
        self._ws_clients: Set[WebSocket] = set()
        # Fingerprint score (set by evaluation)
        self.fingerprint_score: int = 0
        self.fingerprint_total: int = 22
        # Total sessions today
        self.total_sessions_today: int = 0

    # -- Recording methods (called by dispatcher/demo) ---------------------

    def record_session_start(
        self,
        session_id: str,
        attacker_ip: str,
        persona: str = "generic_linux",
    ) -> None:
        """Register a new session."""
        self._sessions[session_id] = {
            "session_id": session_id,
            "attacker_ip": attacker_ip,
            "threat_score": 0,
            "threat_level": "low",
            "persona": persona,
            "command_count": 0,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": 0,
            "score_history": [],
        }
        self._timelines[session_id] = []
        self._unique_ips.add(attacker_ip)
        self.total_sessions_today += 1

    def record_command(
        self,
        session_id: str,
        command: str,
        score_after: int,
        score_delta: int,
        category: str,
        threat_level: str,
        persona: str,
        response_source: str = "dict",
    ) -> None:
        """Record a command for a session."""
        session = self._sessions.get(session_id)
        if session is None:
            return

        session["threat_score"] = score_after
        session["threat_level"] = threat_level
        session["persona"] = persona
        session["command_count"] = session.get("command_count", 0) + 1

        # Update duration
        start = session.get("start_time", "")
        if start:
            try:
                st = datetime.fromisoformat(start.replace("Z", "+00:00"))
                session["duration_seconds"] = (
                    datetime.now(timezone.utc) - st
                ).total_seconds()
            except (ValueError, TypeError):
                pass

        # Score history for timeline
        point = {
            "cmd_index": session["command_count"],
            "score": score_after,
            "persona": persona,
            "command": command,
        }
        session.setdefault("score_history", []).append(point)
        self._timelines.setdefault(session_id, []).append(point)

        # Command feed
        feed_entry = {
            "session_id": session_id[:8],
            "session_id_full": session_id,
            "command": command,
            "score_delta": score_delta,
            "category": category,
            "threat_level": threat_level,
            "persona": persona,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "command",
        }
        self._command_feed.append(feed_entry)

    def record_persona_switch(
        self,
        session_id: str,
        from_persona: str,
        to_persona: str,
        trigger_score: int,
    ) -> None:
        """Record a persona switch event."""
        event = {
            "session_id": session_id[:8],
            "session_id_full": session_id,
            "from_persona": from_persona,
            "to_persona": to_persona,
            "trigger_score": trigger_score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "persona_switch",
        }
        self._persona_switches.append(event)
        self._command_feed.append(event)

        # Update session persona
        session = self._sessions.get(session_id)
        if session:
            session["persona"] = to_persona

    def record_session_end(self, session_id: str) -> None:
        """Close a session."""
        session = self._sessions.pop(session_id, None)
        if session:
            self._closed_sessions.append(session)

    # -- Query methods (called by dashboard endpoints) ---------------------

    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Return all active sessions."""
        result = []
        now = datetime.now(timezone.utc)
        for sid, session in self._sessions.items():
            s = dict(session)
            start = s.get("start_time", "")
            if start:
                try:
                    st = datetime.fromisoformat(start.replace("Z", "+00:00"))
                    s["duration_seconds"] = (now - st).total_seconds()
                except (ValueError, TypeError):
                    pass
            result.append(s)
        return result

    def get_session_timeline(self, session_id: str) -> List[Dict[str, Any]]:
        """Return score timeline for a session."""
        return self._timelines.get(session_id, [])

    def get_command_feed(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the last N commands across all sessions."""
        return list(self._command_feed)[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """Return system statistics for Panel 4."""
        all_sessions = list(self._sessions.values()) + self._closed_sessions

        # Average session duration
        durations = [s.get("duration_seconds", 0) for s in all_sessions if s.get("duration_seconds", 0) > 0]
        avg_duration = sum(durations) / len(durations) if durations else 0

        # Level 3+ percentage
        level3_count = sum(
            1 for s in all_sessions
            if s.get("threat_level") in ("high", "critical")
        )
        level3_pct = (level3_count / len(all_sessions) * 100) if all_sessions else 0

        return {
            "avg_duration_seconds": round(avg_duration, 1),
            "avg_duration_display": _format_duration(avg_duration),
            "cowrie_avg_duration": "0m 44s",
            "level3_plus_pct": round(level3_pct, 1),
            "cowrie_level3_pct": 11,
            "fingerprint_score": self.fingerprint_score,
            "fingerprint_total": self.fingerprint_total,
            "cowrie_fingerprint": 8,
            "persona_switches_today": len(self._persona_switches),
            "unique_ips_today": len(self._unique_ips),
            "total_sessions_today": self.total_sessions_today,
            "active_sessions": len(self._sessions),
        }

    def get_ws_update(self) -> Dict[str, Any]:
        """Return a full data payload for WebSocket push."""
        return {
            "type": "update",
            "sessions": self.get_active_sessions(),
            "commands": self.get_command_feed(50),
            "stats": self.get_stats(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # -- WebSocket management -----------------------------------------------

    async def broadcast(self, data: Dict[str, Any]) -> None:
        """Push data to all connected WebSocket clients."""
        if not self._ws_clients:
            return
        message = json.dumps(data, default=str)
        disconnected: Set[WebSocket] = set()
        for ws in self._ws_clients:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.add(ws)
        self._ws_clients -= disconnected

    def add_ws_client(self, ws: WebSocket) -> None:
        self._ws_clients.add(ws)

    def remove_ws_client(self, ws: WebSocket) -> None:
        self._ws_clients.discard(ws)


def _format_duration(seconds: float) -> str:
    """Format seconds as Xm Ys."""
    m = int(seconds // 60)
    s = int(seconds % 60)
    return f"{m}m {s:02d}s"


# ---------------------------------------------------------------------------
# Global data manager — shared between dashboard and demo scripts
# ---------------------------------------------------------------------------

data_manager = DashboardDataManager()


# ---------------------------------------------------------------------------
# Routes — GET (read)
# ---------------------------------------------------------------------------

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the single-file dashboard."""
    html_path = TEMPLATE_DIR / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.get("/api/sessions")
async def api_sessions():
    """Return all active sessions."""
    return data_manager.get_active_sessions()


@app.get("/api/sessions/{session_id}/timeline")
async def api_session_timeline(session_id: str):
    """Return score timeline for a session."""
    return data_manager.get_session_timeline(session_id)


@app.get("/api/commands")
async def api_commands(limit: int = 50):
    """Return recent command feed."""
    return data_manager.get_command_feed(limit)


@app.get("/api/stats")
async def api_stats():
    """Return system statistics."""
    return data_manager.get_stats()


# ---------------------------------------------------------------------------
# Routes — POST (write) — used by demo_session.py / external scripts
# ---------------------------------------------------------------------------

@app.post("/api/session/start")
async def api_session_start(payload: dict):
    """Register a new session via HTTP."""
    data_manager.record_session_start(
        session_id=payload["session_id"],
        attacker_ip=payload.get("attacker_ip", "0.0.0.0"),
        persona=payload.get("persona", "generic_linux"),
    )
    # Broadcast immediately so dashboard updates
    await data_manager.broadcast(data_manager.get_ws_update())
    return {"status": "ok"}


@app.post("/api/session/command")
async def api_session_command(payload: dict):
    """Record a command via HTTP."""
    data_manager.record_command(
        session_id=payload["session_id"],
        command=payload["command"],
        score_after=payload.get("score_after", 0),
        score_delta=payload.get("score_delta", 0),
        category=payload.get("category", "benign"),
        threat_level=payload.get("threat_level", "low"),
        persona=payload.get("persona", "generic_linux"),
        response_source=payload.get("response_source", "dict"),
    )
    await data_manager.broadcast(data_manager.get_ws_update())
    return {"status": "ok"}


@app.post("/api/session/switch")
async def api_session_switch(payload: dict):
    """Record a persona switch via HTTP."""
    data_manager.record_persona_switch(
        session_id=payload["session_id"],
        from_persona=payload["from_persona"],
        to_persona=payload["to_persona"],
        trigger_score=payload.get("trigger_score", 0),
    )
    await data_manager.broadcast(data_manager.get_ws_update())
    return {"status": "ok"}


@app.post("/api/session/end")
async def api_session_end(payload: dict):
    """Close a session via HTTP."""
    data_manager.record_session_end(session_id=payload["session_id"])
    await data_manager.broadcast(data_manager.get_ws_update())
    return {"status": "ok"}


@app.post("/api/fingerprint")
async def api_fingerprint(payload: dict):
    """Set the fingerprint score."""
    data_manager.fingerprint_score = payload.get("score", 0)
    data_manager.fingerprint_total = payload.get("total", 22)
    await data_manager.broadcast(data_manager.get_ws_update())
    return {"status": "ok"}


@app.post("/api/dashboard/clear")
async def api_dashboard_clear():
    """Clear all dashboard data (for demos)."""
    data_manager._sessions.clear()
    data_manager._timelines.clear()
    data_manager._command_feed.clear()
    data_manager._closed_sessions.clear()
    data_manager._persona_switches.clear()
    data_manager._unique_ips.clear()
    data_manager.total_sessions_today = 0
    await data_manager.broadcast(data_manager.get_ws_update())
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Script Catalog & Subprocess Execution Launcher
# ---------------------------------------------------------------------------

import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SCRIPTS_CATALOG = [
    {
        "id": "demo_session",
        "title": "Panel Presentation Demo 1 (Standard)",
        "category": "Panel Presentation",
        "script": "scripts/demo_session.py",
        "args": [],
        "command_count": 10,
        "estimated_duration": "15s",
        "attack_pattern": "Reconnaissance -> Exploration -> Sensitive File Exfiltration -> Persona Switch Trigger",
        "design_patterns": ["Facade Pattern", "Observer Pattern", "Driver Test Double"],
        "description": "Standard 10-command presentation sequence. Triggers persona switch from generic_linux to dev_workstation mid-session.",
        "highlights": [
            "whoami, id, uname -a recon",
            "sudo privilege check & shadow read attempt",
            "cat /home/john.dev/.env exfiltration",
            "Live Persona Switch transition alert",
        ],
    },
    {
        "id": "demo_session_2",
        "title": "Stealth Recon & Data Exfiltration Demo",
        "category": "Panel Presentation",
        "script": "scripts/demo_session_2.py",
        "args": [],
        "command_count": 14,
        "estimated_duration": "20s",
        "attack_pattern": "Stealth Recon -> linpeas.sh Download -> Directory Compression -> HTTP Exfiltration",
        "design_patterns": ["Facade Pattern", "In-Memory Overlay Pattern", "Pipeline Pattern"],
        "description": "Simulates a stealthy attacker searching config files, downloading enumeration scripts, and exfiltrating archives.",
        "highlights": [
            "netstat & find *.conf recon",
            "wget linpeas.sh execution",
            "tar backup creation in /tmp",
            "curl POST exfiltration to attacker server",
        ],
    },
    {
        "id": "demo_session_3",
        "title": "Loud & Ransomware / Lateral Movement Demo",
        "category": "Panel Presentation",
        "script": "scripts/demo_session_3.py",
        "args": [],
        "command_count": 10,
        "estimated_duration": "15s",
        "attack_pattern": "Immediate PrivEsc -> SSH Key Theft -> Lateral Movement -> Ransomware & Log Wipe",
        "design_patterns": ["Facade Pattern", "Threat Taxonomy Classifier", "Overlay Isolation"],
        "description": "High-noise attacker stealing SSH private keys, attempting lateral movement, and executing simulated log wiping.",
        "highlights": [
            "Direct cat /etc/shadow grab",
            "cat ~/.ssh/id_rsa key theft",
            "Lateral SSH connection attempt",
            "Ransomware simulation & rm -rf /var/log/*",
        ],
    },
    {
        "id": "attack_botnet",
        "title": "Botnet Automated Probe Scenario",
        "category": "Attacker Scenarios",
        "script": "scripts/attack_scenarios.py",
        "args": ["--scenario", "botnet", "--speed", "0.5"],
        "command_count": 12,
        "estimated_duration": "10s",
        "attack_pattern": "High-Speed Automated Botnet Scan & Mass Recon",
        "design_patterns": ["Strategy Pattern", "Stochastic Timing Model"],
        "description": "Simulates an automated botnet script scanning open ports, system uptime, and user enumeration at fast speed.",
        "highlights": [
            "Automated command burst",
            "Stochastic human/bot typing intervals",
            "Fast threat accumulation",
        ],
    },
    {
        "id": "attack_credential",
        "title": "Credential Harvesting Attack Scenario",
        "category": "Attacker Scenarios",
        "script": "scripts/attack_scenarios.py",
        "args": ["--scenario", "credential", "--speed", "0.8"],
        "command_count": 10,
        "estimated_duration": "12s",
        "attack_pattern": "Targeted Key/Credential Search (.env, AWS keys, shadow)",
        "design_patterns": ["Strategy Pattern", "Threat Threshold Switcher"],
        "description": "Targeted adversary hunting for hardcoded passwords, AWS credentials, and environment config files.",
        "highlights": [
            "Targeted .env search",
            "AWS credential hunting",
            "High threat score escalation",
        ],
    },
    {
        "id": "attack_privesc",
        "title": "Privilege Escalation Attack Scenario",
        "category": "Attacker Scenarios",
        "script": "scripts/attack_scenarios.py",
        "args": ["--scenario", "privesc", "--speed", "0.8"],
        "command_count": 11,
        "estimated_duration": "15s",
        "attack_pattern": "SUID Binary Search -> Sudo Exploit Attempt -> Root Shell Escalation",
        "design_patterns": ["Strategy Pattern", "Persona Merging State Engine"],
        "description": "Exploration of SUID binaries, sudoers configuration, and kernel vulnerability checking.",
        "highlights": [
            "find / -perm -4000 SUID search",
            "cat /etc/sudoers check",
            "Triggers high persona transition",
        ],
    },
    {
        "id": "attack_persistence",
        "title": "Persistence & Backdoor Scenario",
        "category": "Attacker Scenarios",
        "script": "scripts/attack_scenarios.py",
        "args": ["--scenario", "persistence", "--speed", "0.8"],
        "command_count": 10,
        "estimated_duration": "12s",
        "attack_pattern": "Cron Injection -> SSH Authorized Keys -> Bashrc Persistence",
        "design_patterns": ["Strategy Pattern", "In-Memory Write Overlay"],
        "description": "Attacker attempting to establish persistent rootkits, backdoor users, and crontab entries.",
        "highlights": [
            "Crontab backdoor injection",
            "echo to ~/.bashrc",
            "Overlay filesystem modification",
        ],
    },
    {
        "id": "run_evaluation",
        "title": "Academic Evaluation & Fingerprint Resistance Test",
        "category": "Evaluation Suite",
        "script": "scripts/run_evaluation.py",
        "args": [],
        "command_count": 22,
        "estimated_duration": "10s",
        "attack_pattern": "22 Honeypot Fingerprint Probes + Cross-Reference Invariant Checks",
        "design_patterns": ["Automated Test Harness", "Cross-Reference Consistency Evaluator"],
        "description": "Runs 22 honeypot detection probes against the system and scores overall fingerprint resistance.",
        "highlights": [
            "22/22 Fingerprint resistance pass check",
            "Cross-reference state validation",
            "Latency fast-path vs slow-path benchmark",
        ],
    },
]

# Global process tracking
_active_process: Optional[subprocess.Popen] = None
_active_script_id: Optional[str] = None
_script_logs: List[str] = []


@app.get("/api/scripts")
async def api_get_scripts():
    """Return the catalog of executable demo & evaluation scripts."""
    global _active_process, _active_script_id
    running_id = None
    if _active_process and _active_process.poll() is None:
        running_id = _active_script_id
    return {
        "scripts": SCRIPTS_CATALOG,
        "running_script_id": running_id,
    }


@app.get("/api/scripts/status")
async def api_scripts_status():
    """Get real-time execution status of background demo script."""
    global _active_process, _active_script_id, _script_logs
    is_running = _active_process is not None and _active_process.poll() is None
    return {
        "is_running": is_running,
        "script_id": _active_script_id if is_running else None,
        "logs": _script_logs[-50:],
    }


@app.post("/api/scripts/run")
async def api_run_script(payload: dict):
    """Run a demo or scenario script in the background."""
    global _active_process, _active_script_id, _script_logs
    script_id = payload.get("script_id")
    
    # Find script definition
    item = next((s for s in SCRIPTS_CATALOG if s["id"] == script_id), None)
    if not item:
        return {"status": "error", "message": f"Script {script_id} not found"}

    # Check if a process is already running
    if _active_process and _active_process.poll() is None:
        return {"status": "error", "message": f"Script {_active_script_id} is already running."}

    _script_logs.clear()
    _script_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Starting {item['title']}...")

    cmd = [sys.executable, str(PROJECT_ROOT / item["script"])] + item["args"]

    try:
        # Note: Set stdin=subprocess.PIPE so interactive prompts won't hang!
        # If script waits for input (like input() in demo_session.py), send newline automatically
        process = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        
        # Pass a newline to stdin in case demo waits for "Press Enter"
        if process.stdin:
            try:
                process.stdin.write("\n")
                process.stdin.flush()
            except Exception:
                pass

        _active_process = process
        _active_script_id = script_id

        # Async background reader for process output
        def read_output():
            nonlocal process
            for line in iter(process.stdout.readline, ''):
                if line:
                    _script_logs.append(line.rstrip())
            process.stdout.close()
            process.wait()

        import threading
        t = threading.Thread(target=read_output, daemon=True)
        t.start()

        return {
            "status": "ok",
            "message": f"Launched {item['title']}",
            "script_id": script_id,
        }
    except Exception as e:
        logger.error(f"Failed to launch script {script_id}: {e}")
        return {"status": "error", "message": str(e)}


@app.post("/api/scripts/stop")
async def api_stop_script():
    """Stop the currently running script process."""
    global _active_process, _active_script_id
    if _active_process and _active_process.poll() is None:
        try:
            _active_process.terminate()
            _script_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Script process terminated by user.")
        except Exception as e:
            logger.error(f"Error terminating process: {e}")
        _active_process = None
        _active_script_id = None
        return {"status": "ok", "message": "Script stopped"}
    return {"status": "ok", "message": "No script running"}


# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """WebSocket endpoint for real-time dashboard updates."""
    await ws.accept()
    data_manager.add_ws_client(ws)
    try:
        # Send initial state
        await ws.send_text(json.dumps(data_manager.get_ws_update(), default=str))

        # Keep alive: push updates every 2 seconds
        while True:
            await asyncio.sleep(2)
            try:
                update = data_manager.get_ws_update()
                await ws.send_text(json.dumps(update, default=str))
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    finally:
        data_manager.remove_ws_client(ws)


# ---------------------------------------------------------------------------
# Background task for periodic broadcast
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_event():
    """Start background broadcast task."""
    asyncio.create_task(_periodic_broadcast())


async def _periodic_broadcast():
    """Broadcast updates to all clients every 2 seconds."""
    while True:
        await asyncio.sleep(2)
        if data_manager._ws_clients:
            await data_manager.broadcast(data_manager.get_ws_update())


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "dashboard.app:app",
        host="0.0.0.0",
        port=8080,
        reload=False,
        log_level="info",
    )
