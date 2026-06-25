"""Replay session_trace.json into the live dashboard and capture screenshots.

Workflow:
    1. Start the FastAPI dashboard on port 8089 (subprocess)
    2. POST session_trace.json data command-by-command via the REST API
    3. Open headless Chrome, wait for WebSocket to populate panels
    4. Screenshot each of the four panels + the full page
    5. Kill the dashboard server

Outputs saved to evidence/04_dashboard/screenshots/
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import requests

DASHBOARD_PORT = 8089
DASHBOARD_URL = f"http://127.0.0.1:{DASHBOARD_PORT}"
TRACE_PATH = PROJECT_ROOT / "evidence" / "03_simulated_session" / "session_trace.json"
SCREENSHOT_DIR = Path(__file__).resolve().parent / "screenshots"


def wait_for_dashboard(timeout: float = 15.0) -> bool:
    """Poll until the dashboard responds."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(f"{DASHBOARD_URL}/api/stats", timeout=1)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def replay_trace(trace: dict) -> None:
    """Feed trace data into the dashboard via REST API."""
    session_id = trace["session_id"]
    ip = trace.get("simulated_attacker_ip", "0.0.0.0")

    requests.post(f"{DASHBOARD_URL}/api/dashboard/clear", json={}, timeout=2)
    time.sleep(0.3)

    requests.post(f"{DASHBOARD_URL}/api/session/start", json={
        "session_id": session_id,
        "attacker_ip": ip,
        "persona": trace.get("initial_persona", "generic_linux"),
    }, timeout=2)

    requests.post(f"{DASHBOARD_URL}/api/fingerprint", json={
        "score": 22,
        "total": 22,
    }, timeout=2)

    prev_persona = trace.get("initial_persona", "generic_linux")

    for cmd in trace["commands"]:
        requests.post(f"{DASHBOARD_URL}/api/session/command", json={
            "session_id": session_id,
            "command": cmd["command"],
            "score_after": cmd["cumulative_score"],
            "score_delta": cmd["score_delta"],
            "category": cmd["category"],
            "threat_level": cmd["threat_level"],
            "persona": cmd["persona"],
            "response_source": cmd["response_source"],
        }, timeout=2)

        if cmd.get("persona_switch"):
            sw = cmd["persona_switch"]
            requests.post(f"{DASHBOARD_URL}/api/session/switch", json={
                "session_id": session_id,
                "from_persona": sw["from"],
                "to_persona": sw["to"],
                "trigger_score": sw["trigger_score"],
            }, timeout=2)

        prev_persona = cmd["persona"]
        time.sleep(0.05)


def take_screenshots() -> None:
    """Open headless Chrome and screenshot each panel."""
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC

    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument("--force-device-scale-factor=1")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")

    driver = webdriver.Chrome(options=opts)

    try:
        driver.get(DASHBOARD_URL)

        WebDriverWait(driver, 10).until(
            EC.text_to_be_present_in_element((By.ID, "ws-status-text"), "LIVE")
        )
        time.sleep(3)

        driver.execute_script("""
            const cards = document.querySelectorAll('.session-card');
            if (cards.length > 0) cards[0].click();
        """)
        time.sleep(2)

        # Full page
        driver.save_screenshot(str(SCREENSHOT_DIR / "dashboard_full.png"))
        print(f"  Saved: dashboard_full.png")

        panels = {
            "panel_sessions": "panel-sessions",
            "panel_timeline": "panel-timeline",
            "panel_feed":     "panel-feed",
            "panel_stats":    "panel-stats",
        }

        for name, element_id in panels.items():
            try:
                el = driver.find_element(By.ID, element_id)
                el.screenshot(str(SCREENSHOT_DIR / f"{name}.png"))
                print(f"  Saved: {name}.png")
            except Exception as e:
                print(f"  WARNING: Could not screenshot {name}: {e}")

        # Also screenshot just the header
        try:
            header = driver.find_element(By.ID, "dashboard-header")
            header.screenshot(str(SCREENSHOT_DIR / "header.png"))
            print(f"  Saved: header.png")
        except Exception:
            pass

    finally:
        driver.quit()


def main() -> None:
    print("=" * 70)
    print("  Dashboard Evidence Generator")
    print("  Replays session_trace.json and captures panel screenshots")
    print("=" * 70)

    if not TRACE_PATH.exists():
        print(f"\n  ERROR: {TRACE_PATH} not found.")
        print("  Run evidence/03_simulated_session/run_session_evidence.py first.")
        sys.exit(1)

    trace = json.loads(TRACE_PATH.read_text(encoding="utf-8"))

    # 1. Start dashboard
    print(f"\n  Starting dashboard on port {DASHBOARD_PORT}...")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "dashboard.app:app",
            "--host", "127.0.0.1",
            "--port", str(DASHBOARD_PORT),
            "--log-level", "warning",
        ],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )

    try:
        if not wait_for_dashboard():
            print("  ERROR: Dashboard did not start within 15s.")
            proc.kill()
            sys.exit(1)
        print("  Dashboard is up.")

        # 2. Replay trace
        print(f"\n  Replaying {len(trace['commands'])} commands from session_trace.json...")
        replay_trace(trace)
        print("  Replay complete.")

        # 3. Screenshots
        print(f"\n  Taking screenshots with headless Chrome...")
        take_screenshots()

        print(f"\n  All screenshots saved to: {SCREENSHOT_DIR}")

    finally:
        # 4. Kill dashboard
        print("\n  Stopping dashboard...")
        if sys.platform == "win32":
            proc.kill()
        else:
            os.kill(proc.pid, signal.SIGTERM)
        proc.wait(timeout=5)
        print("  Done.")

    print("=" * 70)


if __name__ == "__main__":
    main()
