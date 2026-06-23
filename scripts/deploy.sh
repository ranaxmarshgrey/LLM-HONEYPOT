#!/usr/bin/env bash
# scripts/deploy.sh
#
# Push latest code to the production VM and restart all honeypot services.
# Assumes setup.sh has already been run on the target VM.
#
# Usage:
#   bash scripts/deploy.sh <user@host>
#   bash scripts/deploy.sh root@203.0.113.10
#   bash scripts/deploy.sh root@203.0.113.10 --first-run    # also runs setup.sh
#
# What this does:
#   1. rsync the project (minus .env, logs, __pycache__, .venv) to the remote
#   2. If --first-run: run setup.sh on the remote
#   3. Install/update project Python dependencies
#   4. Apply the Cowrie integration patch
#   5. Restart Cowrie, dashboard, and ensure iptables redirect is active
#   6. Run a quick smoke test (SSH connect + dashboard HTTP check)
#
set -Eeuo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REMOTE_PROJECT_DIR="/opt/adaptive-honeypot"
COWRIE_HOME="/opt/cowrie"
DASHBOARD_PORT=8080

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
  echo "Usage: bash scripts/deploy.sh <user@host> [--first-run]"
  exit 1
fi

REMOTE="$1"
FIRST_RUN=false
if [[ "${2:-}" == "--first-run" ]]; then
  FIRST_RUN=true
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[1;34m[deploy]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[deploy]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m[deploy]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[deploy]\033[0m %s\n' "$*" >&2; exit 1; }

ssh_cmd() {
  ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "${REMOTE}" "$@"
}

# ---------------------------------------------------------------------------
# 1. rsync project to remote
# ---------------------------------------------------------------------------
log "syncing project to ${REMOTE}:${REMOTE_PROJECT_DIR}"
ssh_cmd "mkdir -p ${REMOTE_PROJECT_DIR}"

rsync -azP --delete \
  --exclude='.env' \
  --exclude='.venv/' \
  --exclude='__pycache__/' \
  --exclude='.pytest_cache/' \
  --exclude='*.pyc' \
  --exclude='event_logging/logs/*.json' \
  --exclude='event_logging/logs/*.db' \
  --exclude='.git/' \
  --exclude='.claude/' \
  "${PROJECT_DIR}/" "${REMOTE}:${REMOTE_PROJECT_DIR}/"

ok "project synced"

# ---------------------------------------------------------------------------
# 2. First-run setup (optional)
# ---------------------------------------------------------------------------
if [[ "${FIRST_RUN}" == "true" ]]; then
  log "running first-time setup (setup.sh) on remote..."
  ssh_cmd "cd ${REMOTE_PROJECT_DIR} && sudo bash scripts/setup.sh"
  ok "setup.sh completed"
fi

# ---------------------------------------------------------------------------
# 3. Install/update project Python dependencies
# ---------------------------------------------------------------------------
log "installing project Python dependencies"
ssh_cmd "cd ${REMOTE_PROJECT_DIR} && \
  if [ ! -d .venv ]; then python3.11 -m venv .venv; fi && \
  .venv/bin/pip install --quiet --upgrade pip && \
  .venv/bin/pip install --quiet -r requirements.txt"
ok "dependencies installed"

# ---------------------------------------------------------------------------
# 4. Check .env exists on remote
# ---------------------------------------------------------------------------
log "checking .env on remote"
if ! ssh_cmd "test -f ${REMOTE_PROJECT_DIR}/.env"; then
  warn ".env not found on remote! Copying .env.example as template..."
  ssh_cmd "cp ${REMOTE_PROJECT_DIR}/.env.example ${REMOTE_PROJECT_DIR}/.env"
  warn ">>> IMPORTANT: SSH into the VM and edit ${REMOTE_PROJECT_DIR}/.env with your real API keys!"
fi

# ---------------------------------------------------------------------------
# 5. Apply Cowrie integration patch
# ---------------------------------------------------------------------------
log "applying Cowrie integration patch"
ssh_cmd "cd ${REMOTE_PROJECT_DIR} && \
  if [ -f cowrie_integration/install_hook.sh ]; then \
    sudo bash cowrie_integration/install_hook.sh; \
  else \
    echo 'No Cowrie integration script found — skipping'; \
  fi"

# ---------------------------------------------------------------------------
# 6. Install and start systemd services
# ---------------------------------------------------------------------------
log "installing systemd services"
ssh_cmd "sudo cp ${REMOTE_PROJECT_DIR}/systemd/honeypot-dashboard.service /etc/systemd/system/ 2>/dev/null || true && \
  sudo systemctl daemon-reload"

log "restarting services"
ssh_cmd "sudo systemctl restart cowrie 2>/dev/null || echo 'cowrie not installed yet'"
ssh_cmd "sudo systemctl enable --now honeypot-dashboard 2>/dev/null || echo 'dashboard service not installed yet'"

# ---------------------------------------------------------------------------
# 7. Verify iptables redirect
# ---------------------------------------------------------------------------
log "verifying iptables redirect 22 -> 2222"
ssh_cmd "sudo iptables -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222 2>/dev/null || \
  (sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222 && \
   sudo mkdir -p /etc/iptables && sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null)"

# ---------------------------------------------------------------------------
# 8. Smoke test
# ---------------------------------------------------------------------------
log "running smoke tests"
REMOTE_HOST=$(echo "${REMOTE}" | cut -d@ -f2)

# Check Cowrie is listening
if ssh_cmd "ss -ltn sport = :2222 | grep -q :2222"; then
  ok "Cowrie SSH on port 2222: LISTENING"
else
  warn "Cowrie SSH on port 2222: NOT LISTENING (may still be starting)"
fi

# Check dashboard
if ssh_cmd "curl -sf http://127.0.0.1:${DASHBOARD_PORT}/api/stats >/dev/null 2>&1"; then
  ok "Dashboard on port ${DASHBOARD_PORT}: RUNNING"
else
  warn "Dashboard on port ${DASHBOARD_PORT}: NOT RESPONDING (may still be starting)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
ok "=========================================="
ok "  Deployment complete!"
ok "=========================================="
echo ""
echo "  SSH honeypot:  ssh anyuser@${REMOTE_HOST}"
echo "  Dashboard:     http://${REMOTE_HOST}:${DASHBOARD_PORT}"
echo ""
echo "  Useful commands:"
echo "    ssh ${REMOTE} 'journalctl -u cowrie -f'              # Cowrie logs"
echo "    ssh ${REMOTE} 'journalctl -u honeypot-dashboard -f'  # Dashboard logs"
echo "    ssh ${REMOTE} 'cat ${REMOTE_PROJECT_DIR}/event_logging/logs/*.json | tail -20'"
echo ""
