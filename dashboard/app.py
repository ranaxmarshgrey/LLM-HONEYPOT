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
from fastapi.responses import HTMLResponse

logger = logging.getLogger(__name__)

app = FastAPI(title="Adaptive Honeypot Dashboard", version="1.0.0")


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
            "level3_plus_pct": round(level3_pct, 1),
            "fingerprint_score": self.fingerprint_score,
            "fingerprint_total": self.fingerprint_total,
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
