"""Live defender monitor — rich TUI that tails honeypot.jsonl.

Usage:
    python -m monitor.live_monitor                        # live tail
    python -m monitor.live_monitor --session abc123       # pin to session
    python -m monitor.live_monitor --replay backup.jsonl  # replay mode
    python -m monitor.live_monitor --replay backup.jsonl --speed 5

Reads ONLY the real event log. No hard-coded or sample data.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from monitor.log_parser import LogParser, SessionState

_DEFAULT_LOG = Path(__file__).resolve().parent.parent / "event_logging" / "logs" / "honeypot.jsonl"

_SOURCE_COLOURS = {
    "dict": "green",
    "fakefs": "cyan",
    "llm_primary": "yellow",
    "llm": "yellow",
    "llm_fallback": "red",
    "error": "bright_red",
}

_LEVEL_COLOURS = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bright_red",
}

_GAUGE_WIDTH = 30


# ---------------------------------------------------------------------------
# Panel renderers — each returns a Rich renderable
# ---------------------------------------------------------------------------

def _render_header(sess: Optional[SessionState], parser: LogParser, replay: bool) -> Panel:
    """Top banner: profile identity, active sessions, attacker IP."""
    if sess is None:
        inner = Text("Waiting for attacker...", style="dim italic")
        return Panel(inner, title="Honeypot Monitor", border_style="blue")

    parts = []
    hostname = sess.persona or "unknown"
    parts.append(f"[bold]Persona:[/bold] {hostname}")
    parts.append(f"[bold]IP:[/bold] {sess.attacker_ip}:{sess.attacker_port}")
    parts.append(f"[bold]Session:[/bold] {sess.session_id}")
    parts.append(f"[bold]Active sessions:[/bold] {parser.active_session_count()}")
    if sess.start_time:
        parts.append(f"[bold]Started:[/bold] {sess.start_time[:19]}")

    title = "[bold red] REPLAY of recorded session [/bold red]" if replay else "Honeypot Monitor"
    return Panel(
        Text.from_markup("  |  ".join(parts)),
        title=title,
        border_style="red" if replay else "blue",
    )


def _time_part(ts: str) -> str:
    """Extract HH:MM:SS from ISO timestamp."""
    if "T" in ts:
        return ts.split("T")[1][:8]
    return ts[:8] if len(ts) >= 8 else ts


def _render_command_feed(sess: Optional[SessionState], max_rows: int = 30) -> Panel:
    """Left panel: live command feed."""
    table = Table(show_header=True, expand=True, padding=(0, 1))
    table.add_column("Time", style="dim", width=8, no_wrap=True)
    table.add_column("Command", ratio=3)
    table.add_column("Source", width=12, no_wrap=True)
    table.add_column("ms", width=5, justify="right")
    table.add_column("+Δ", width=4, justify="right")

    if sess is None or not sess.commands:
        return Panel(table, title="Command Feed", border_style="green")

    recent = sess.commands[-max_rows:]
    for cmd in recent:
        colour = _SOURCE_COLOURS.get(cmd.response_source, "white")
        delta = f"+{cmd.score_delta}" if cmd.score_delta > 0 else ""
        table.add_row(
            _time_part(cmd.timestamp),
            Text(cmd.command, overflow="ellipsis", no_wrap=True),
            Text(cmd.response_source, style=colour),
            str(cmd.latency_ms),
            Text(delta, style="red" if cmd.score_delta >= 10 else "yellow" if delta else "dim"),
        )

    return Panel(table, title=f"Command Feed ({sess.command_count} total)", border_style="green")


def _render_threat_gauge(sess: Optional[SessionState]) -> Panel:
    """Right top: threat score gauge + patterns."""
    if sess is None:
        return Panel(Text("No data", style="dim"), title="Threat", border_style="yellow")

    score = min(sess.threat_score, 100)
    filled = int(score / 100 * _GAUGE_WIDTH)
    empty = _GAUGE_WIDTH - filled

    level = sess.threat_level.upper()
    colour = _LEVEL_COLOURS.get(sess.threat_level, "white")

    bar = f"[{colour}]{'█' * filled}[/{colour}][dim]{'░' * empty}[/dim]"
    gauge_line = f" {bar}  {score}/100  [{colour}]{level}[/{colour}]"

    lines = [gauge_line, ""]

    if sess.patterns_detected:
        lines.append("[bold]Patterns detected:[/bold]")
        for p in sess.patterns_detected:
            lines.append(f"  • {p}")
    else:
        lines.append("[dim]No patterns detected yet[/dim]")

    return Panel(
        Text.from_markup("\n".join(lines)),
        title="Threat Score",
        border_style="yellow",
    )


def _render_escalation(sess: Optional[SessionState]) -> Panel:
    """Right middle: escalation progress."""
    if sess is None or not sess.transitions:
        return Panel(
            Text("No escalation yet", style="dim"),
            title="Escalation",
            border_style="magenta",
        )

    latest = sess.transitions[-1]
    lines = [
        f"[bold]Current stage:[/bold] {sess.current_stage}",
        f"[bold]Phase:[/bold] {sess.transition_phase.upper()}",
        f"[bold]Transitions:[/bold] {len(sess.transitions)}",
        "",
        "[bold]Files planted:[/bold]",
    ]
    for p in sess.planted_paths[-10:]:
        lines.append(f"  [cyan]{p}[/cyan]")
    if len(sess.planted_paths) > 10:
        lines.append(f"  [dim]... and {len(sess.planted_paths) - 10} more[/dim]")

    return Panel(
        Text.from_markup("\n".join(lines)),
        title="Escalation Progress",
        border_style="magenta",
    )


def _render_decoy(sess: Optional[SessionState]) -> Panel:
    """Right bottom: decoy accesses."""
    if sess is None or not sess.decoy_accesses:
        return Panel(
            Text("No decoy accesses yet", style="dim"),
            title="Decoy Accesses",
            border_style="red",
        )

    lines = []
    for da in sess.decoy_accesses[-8:]:
        ts = _time_part(da.timestamp)
        lines.append(f"[bold red]⚠[/bold red] {ts}  [yellow]{da.command}[/yellow]")
        lines.append(f"           [dim]path: {da.path}[/dim]")

    return Panel(
        Text.from_markup("\n".join(lines)),
        title=f"Decoy Accesses ({len(sess.decoy_accesses)})",
        border_style="red",
    )


def _build_layout() -> Layout:
    """Create the monitor's panel layout."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
    )
    layout["body"].split_row(
        Layout(name="left", ratio=3),
        Layout(name="right", ratio=2),
    )
    layout["right"].split_column(
        Layout(name="threat", ratio=2),
        Layout(name="escalation", ratio=2),
        Layout(name="decoy", ratio=2),
    )
    return layout


def _update_layout(
    layout: Layout,
    parser: LogParser,
    session_id: Optional[str],
    replay: bool,
) -> None:
    """Refresh all panels from current parser state."""
    sess = parser.get_session(session_id)
    layout["header"].update(_render_header(sess, parser, replay))
    layout["left"].update(_render_command_feed(sess))
    layout["threat"].update(_render_threat_gauge(sess))
    layout["escalation"].update(_render_escalation(sess))
    layout["decoy"].update(_render_decoy(sess))


# ---------------------------------------------------------------------------
# File tailer — handles rotation
# ---------------------------------------------------------------------------

class LogTailer:
    """Tail a JSON-lines log file, handling rotation."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._pos = 0
        self._inode: Optional[int] = None
        self._init_position()

    def _init_position(self) -> None:
        if self._path.exists():
            stat = self._path.stat()
            self._inode = self._get_inode(stat)
            self._pos = stat.st_size

    @staticmethod
    def _get_inode(stat) -> int:
        return getattr(stat, "st_ino", 0) or hash(stat.st_ctime_ns)

    def read_new_lines(self) -> list[str]:
        """Read any new lines since last call. Handles rotation."""
        if not self._path.exists():
            return []

        stat = self._path.stat()
        current_inode = self._get_inode(stat)

        if self._inode is not None and current_inode != self._inode:
            self._pos = 0
            self._inode = current_inode

        if stat.st_size < self._pos:
            self._pos = 0

        if stat.st_size == self._pos:
            return []

        lines = []
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                f.seek(self._pos)
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        lines.append(stripped)
                self._pos = f.tell()
        except (IOError, OSError):
            pass

        return lines


# ---------------------------------------------------------------------------
# Main entry points
# ---------------------------------------------------------------------------

def run_live(
    log_path: Path,
    session_id: Optional[str] = None,
    refresh_rate: float = 0.5,
) -> None:
    """Tail the live log file and render the TUI."""
    console = Console()
    parser = LogParser()
    layout = _build_layout()

    if not log_path.exists():
        console.print(f"[dim]Log file {log_path} does not exist yet. Waiting...[/dim]")

    tailer = LogTailer(log_path)

    # Read existing content to populate state
    if log_path.exists():
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                parser.feed_line(line)
        tailer._pos = log_path.stat().st_size

    pin_session = session_id

    _update_layout(layout, parser, pin_session, replay=False)

    with Live(layout, console=console, refresh_per_second=4, screen=True) as live:
        try:
            while True:
                new_lines = tailer.read_new_lines()
                for line in new_lines:
                    parser.feed_line(line)
                _update_layout(layout, parser, pin_session, replay=False)
                time.sleep(refresh_rate)
        except KeyboardInterrupt:
            pass

    console.print("\n[bold]Monitor stopped.[/bold]")


def run_replay(
    replay_path: Path,
    speed: float = 1.0,
    session_id: Optional[str] = None,
) -> None:
    """Replay a log file at the given speed multiplier."""
    console = Console()
    parser = LogParser()
    layout = _build_layout()

    if not replay_path.exists():
        console.print(f"[bold red]File not found: {replay_path}[/bold red]")
        return

    lines = replay_path.read_text(encoding="utf-8").splitlines()
    events = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if not events:
        console.print("[bold red]No valid events in replay file.[/bold red]")
        return

    pin_session = session_id
    _update_layout(layout, parser, pin_session, replay=True)

    with Live(layout, console=console, refresh_per_second=10, screen=True) as live:
        try:
            prev_ts = None
            for event in events:
                ts_str = event.get("timestamp", "")
                if prev_ts and ts_str and speed > 0:
                    try:
                        cur = _parse_ts(ts_str)
                        prev = _parse_ts(prev_ts)
                        if cur and prev:
                            delta = (cur - prev).total_seconds()
                            if delta > 0:
                                time.sleep(min(delta / speed, 2.0))
                    except (ValueError, TypeError):
                        pass

                parser.feed_event(event)
                _update_layout(layout, parser, pin_session, replay=True)
                prev_ts = ts_str

            console.print("\n[bold]Replay complete. Press Ctrl+C to exit.[/bold]")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    console.print("\n[bold]Monitor stopped.[/bold]")


def _parse_ts(ts: str):
    """Parse ISO timestamp string."""
    ts = ts.replace("Z", "+00:00")
    try:
        from datetime import datetime, timezone
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Live defender monitor for the adaptive honeypot",
    )
    ap.add_argument(
        "--log",
        type=Path,
        default=_DEFAULT_LOG,
        help="Path to honeypot.jsonl (default: event_logging/logs/honeypot.jsonl)",
    )
    ap.add_argument(
        "--session",
        type=str,
        default=None,
        help="Pin to a specific session ID",
    )
    ap.add_argument(
        "--replay",
        type=Path,
        default=None,
        help="Replay a saved log file instead of tailing live",
    )
    ap.add_argument(
        "--speed",
        type=float,
        default=1.0,
        help="Replay speed multiplier (default: 1.0)",
    )

    args = ap.parse_args()

    if args.replay:
        run_replay(args.replay, speed=args.speed, session_id=args.session)
    else:
        run_live(args.log, session_id=args.session)


if __name__ == "__main__":
    main()
