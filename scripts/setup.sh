#!/usr/bin/env bash
# scripts/setup.sh
#
# One-shot, idempotent setup for a fresh Ubuntu 22.04 VM.
# Running twice is safe: every step checks current state before acting.
#
# What this does (Sprint 1 Deliverable 4):
#   1. Installs system packages (python3.11, git, redis, iptables-persistent, ...)
#   2. Creates a non-root `cowrie` system user
#   3. Clones Cowrie into /opt/cowrie (or pulls if already there)
#   4. Builds Cowrie's Python virtualenv + installs its requirements
#   5. Writes a cowrie.cfg with hostname=web-srv-03, listen port=2222
#   6. Installs a systemd unit so Cowrie restarts on reboot
#   7. Adds iptables PREROUTING redirect 22 -> 2222 and persists it
#   8. Creates the project venv and installs requirements.txt
#   9. Prints a health check summary
#
# Usage:  sudo bash scripts/setup.sh
#
set -Eeuo pipefail

# ---------------------------------------------------------------------------
# Config (override via env vars if needed)
# ---------------------------------------------------------------------------
COWRIE_USER="${COWRIE_USER:-cowrie}"
COWRIE_HOME="${COWRIE_HOME:-/opt/cowrie}"
COWRIE_REPO="${COWRIE_REPO:-https://github.com/cowrie/cowrie.git}"
# Upstream renamed master -> main. Leave blank to auto-detect the remote
# HEAD; set explicitly (e.g. COWRIE_BRANCH=master) only to pin an older fork.
COWRIE_BRANCH="${COWRIE_BRANCH:-}"
COWRIE_HOSTNAME="${COWRIE_HOSTNAME:-web-srv-03}"
COWRIE_LISTEN_PORT="${COWRIE_LISTEN_PORT:-2222}"
COWRIE_SERVICE="${COWRIE_SERVICE:-cowrie}"

# Project paths — derived from this script's location.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROJECT_VENV="${PROJECT_DIR}/.venv"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[setup]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[setup]\033[0m %s\n' "$*" >&2; exit 1; }

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    die "must be run as root (try: sudo bash scripts/setup.sh)"
  fi
}

check_ubuntu_2204() {
  if [[ ! -r /etc/os-release ]]; then
    die "cannot read /etc/os-release — is this Ubuntu?"
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    warn "expected Ubuntu, got ID=${ID:-unknown} — continuing anyway"
  fi
  if [[ "${VERSION_ID:-}" != "22.04" ]]; then
    warn "expected 22.04, got ${VERSION_ID:-unknown} — continuing anyway"
  fi
}

# ---------------------------------------------------------------------------
# 1. System packages
# ---------------------------------------------------------------------------
install_apt_packages() {
  log "updating apt cache"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq

  # iptables-persistent prompts interactively unless preseeded.
  echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
  echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections

  log "installing system packages (idempotent)"
  apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential \
    python3.11 python3.11-venv python3.11-dev \
    python3-pip python3-virtualenv \
    libssl-dev libffi-dev libpython3-dev \
    authbind \
    iptables iptables-persistent netfilter-persistent \
    redis-server
}

# ---------------------------------------------------------------------------
# 2. Cowrie system user
# ---------------------------------------------------------------------------
create_cowrie_user() {
  if id -u "${COWRIE_USER}" >/dev/null 2>&1; then
    log "user ${COWRIE_USER} already exists"
  else
    log "creating system user ${COWRIE_USER}"
    adduser --system --group --home "${COWRIE_HOME}" --shell /bin/bash "${COWRIE_USER}"
  fi
  # Ensure home exists and is owned correctly (covers pre-existing users).
  mkdir -p "${COWRIE_HOME}"
  chown -R "${COWRIE_USER}:${COWRIE_USER}" "${COWRIE_HOME}"
}

# ---------------------------------------------------------------------------
# 3. Clone / update Cowrie
# ---------------------------------------------------------------------------
# Resolve the default branch from the remote (main on current Cowrie, master
# on old forks). Caller may pin by setting COWRIE_BRANCH.
resolve_cowrie_branch() {
  if [[ -n "${COWRIE_BRANCH}" ]]; then
    log "using pinned Cowrie branch: ${COWRIE_BRANCH}"
    return
  fi
  log "resolving Cowrie default branch from ${COWRIE_REPO}"
  local head_ref
  head_ref="$(git ls-remote --symref "${COWRIE_REPO}" HEAD 2>/dev/null \
              | awk '/^ref:/ {sub("refs/heads/","",$2); print $2; exit}')"
  if [[ -z "${head_ref}" ]]; then
    warn "could not resolve remote HEAD — falling back to 'main'"
    head_ref="main"
  fi
  COWRIE_BRANCH="${head_ref}"
  log "Cowrie default branch is '${COWRIE_BRANCH}'"
}

clone_or_update_cowrie() {
  resolve_cowrie_branch

  if [[ -d "${COWRIE_HOME}/.git" ]]; then
    log "Cowrie repo already present — syncing to origin/${COWRIE_BRANCH}"
    sudo -u "${COWRIE_USER}" git -C "${COWRIE_HOME}" fetch --quiet --prune origin
    # Make the local branch track origin/<branch>, creating it if missing,
    # then fast-forward. Handles the case where the local clone is stuck
    # on an old 'master' but upstream is now 'main'.
    sudo -u "${COWRIE_USER}" git -C "${COWRIE_HOME}" checkout --quiet -B \
      "${COWRIE_BRANCH}" "origin/${COWRIE_BRANCH}"
  else
    log "cloning Cowrie (${COWRIE_BRANCH}) into ${COWRIE_HOME}"
    if [[ -n "$(ls -A "${COWRIE_HOME}" 2>/dev/null || true)" ]]; then
      die "${COWRIE_HOME} is not empty and not a git repo — refusing to clobber"
    fi
    sudo -u "${COWRIE_USER}" git clone --quiet --branch "${COWRIE_BRANCH}" \
      "${COWRIE_REPO}" "${COWRIE_HOME}"
  fi

  # Sanity-check the repo layout. If upstream reshuffles things, fail loudly
  # here rather than hours later when systemd can't start the service.
  local missing=()
  [[ -x "${COWRIE_HOME}/bin/cowrie"         ]] || missing+=("bin/cowrie")
  [[ -f "${COWRIE_HOME}/etc/cowrie.cfg.dist" ]] || missing+=("etc/cowrie.cfg.dist")
  [[ -f "${COWRIE_HOME}/requirements.txt"    ]] || missing+=("requirements.txt")
  if (( ${#missing[@]} > 0 )); then
    die "Cowrie repo structure unexpected — missing: ${missing[*]}"
  fi

  # Cowrie expects these runtime dirs to exist before first start. bin/cowrie
  # creates them on demand, but pre-creating keeps systemd happy on cold boot.
  sudo -u "${COWRIE_USER}" mkdir -p \
    "${COWRIE_HOME}/var/log/cowrie" \
    "${COWRIE_HOME}/var/lib/cowrie/downloads" \
    "${COWRIE_HOME}/var/lib/cowrie/tty" \
    "${COWRIE_HOME}/var/run"
}

# ---------------------------------------------------------------------------
# 4. Cowrie virtualenv + requirements
# ---------------------------------------------------------------------------
build_cowrie_venv() {
  local venv="${COWRIE_HOME}/cowrie-env"
  if [[ ! -x "${venv}/bin/python" ]]; then
    log "creating Cowrie virtualenv"
    sudo -u "${COWRIE_USER}" python3.11 -m venv "${venv}"
  else
    log "Cowrie virtualenv already present"
  fi
  log "installing/upgrading Cowrie Python requirements"
  sudo -u "${COWRIE_USER}" "${venv}/bin/pip" install --quiet --upgrade pip setuptools wheel
  sudo -u "${COWRIE_USER}" "${venv}/bin/pip" install --quiet --upgrade \
    -r "${COWRIE_HOME}/requirements.txt"
}

# ---------------------------------------------------------------------------
# 5. cowrie.cfg — hostname web-srv-03, listen port 2222
# ---------------------------------------------------------------------------
write_cowrie_cfg() {
  local cfg="${COWRIE_HOME}/etc/cowrie.cfg"
  log "writing ${cfg} (hostname=${COWRIE_HOSTNAME}, port=${COWRIE_LISTEN_PORT})"
  # Overwriting is intentional and safe: cowrie.cfg is generated state, not
  # user-edited. For per-operator tweaks, use cowrie.cfg.local (Cowrie merges it).
  install -o "${COWRIE_USER}" -g "${COWRIE_USER}" -m 0644 /dev/null "${cfg}"
  cat > "${cfg}" <<EOF
# Managed by scripts/setup.sh — edit cowrie.cfg.local for overrides.
[honeypot]
hostname = ${COWRIE_HOSTNAME}
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
data_path = var/lib/cowrie
contents_path = honeyfs
txtcmds_path = txtcmds
ttylog = true
ttylog_path = var/lib/cowrie/tty
interactive_timeout = 180
authentication_timeout = 120
backend = shell

[ssh]
enabled = true
listen_endpoints = tcp:${COWRIE_LISTEN_PORT}:interface=0.0.0.0
version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6

[telnet]
enabled = false

[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json
epoch_timestamp = false
EOF
  chown "${COWRIE_USER}:${COWRIE_USER}" "${cfg}"
}

# ---------------------------------------------------------------------------
# 6. systemd unit
# ---------------------------------------------------------------------------
install_systemd_unit() {
  local unit="/etc/systemd/system/${COWRIE_SERVICE}.service"
  if [[ ! -x "${COWRIE_HOME}/bin/cowrie" ]]; then
    die "${COWRIE_HOME}/bin/cowrie missing or not executable — clone step failed?"
  fi
  log "installing systemd unit ${unit}"
  cat > "${unit}" <<EOF
[Unit]
Description=Cowrie SSH Honeypot
After=network.target

[Service]
Type=forking
User=${COWRIE_USER}
Group=${COWRIE_USER}
WorkingDirectory=${COWRIE_HOME}
Environment=PYTHONUNBUFFERED=1
ExecStart=${COWRIE_HOME}/bin/cowrie start
ExecStop=${COWRIE_HOME}/bin/cowrie stop
Restart=on-failure
RestartSec=5
# cowrie writes its own pidfile; let systemd track via Type=forking.
PIDFile=${COWRIE_HOME}/var/run/cowrie.pid

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "${unit}"
  systemctl daemon-reload
  systemctl enable --now "${COWRIE_SERVICE}.service"
}

# ---------------------------------------------------------------------------
# 7. iptables 22 -> 2222 redirect (persisted)
# ---------------------------------------------------------------------------
configure_iptables_redirect() {
  log "configuring iptables PREROUTING redirect 22 -> ${COWRIE_LISTEN_PORT}"
  # Idempotent: only add if rule does not already exist.
  if ! iptables -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-port "${COWRIE_LISTEN_PORT}" 2>/dev/null; then
    iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port "${COWRIE_LISTEN_PORT}"
    log "added iptables rule"
  else
    log "iptables rule already present"
  fi
  # Persist for reboot via iptables-persistent.
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4
  ip6tables-save > /etc/iptables/rules.v6 || true
  systemctl enable netfilter-persistent >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# 8. Project venv + requirements
# ---------------------------------------------------------------------------
build_project_venv() {
  if [[ ! -f "${PROJECT_DIR}/requirements.txt" ]]; then
    warn "no requirements.txt at ${PROJECT_DIR} — skipping project venv"
    return
  fi
  if [[ ! -x "${PROJECT_VENV}/bin/python" ]]; then
    log "creating project virtualenv at ${PROJECT_VENV}"
    python3.11 -m venv "${PROJECT_VENV}"
  else
    log "project virtualenv already present"
  fi
  log "installing project requirements"
  "${PROJECT_VENV}/bin/pip" install --quiet --upgrade pip setuptools wheel
  "${PROJECT_VENV}/bin/pip" install --quiet -r "${PROJECT_DIR}/requirements.txt"

  # Ensure the logging directory exists and is writable (Rule 6).
  mkdir -p "${PROJECT_DIR}/logging/logs"
  chmod 0755 "${PROJECT_DIR}/logging/logs"
}

# ---------------------------------------------------------------------------
# 9. Health check
# ---------------------------------------------------------------------------
health_check() {
  log "health check"
  local ok=1

  if systemctl is-active --quiet "${COWRIE_SERVICE}.service"; then
    log "  cowrie.service   : active"
  else
    warn "  cowrie.service   : NOT active"
    warn "  last log lines:"
    journalctl -u "${COWRIE_SERVICE}.service" -n 15 --no-pager 2>/dev/null \
      | sed 's/^/    /' >&2 || true
    ok=0
  fi

  if ss -ltn "sport = :${COWRIE_LISTEN_PORT}" | grep -q ":${COWRIE_LISTEN_PORT}"; then
    log "  port ${COWRIE_LISTEN_PORT}        : listening"
  else
    warn "  port ${COWRIE_LISTEN_PORT}        : NOT listening (service may still be starting)"
    ok=0
  fi

  if iptables -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-port "${COWRIE_LISTEN_PORT}" 2>/dev/null; then
    log "  iptables 22->${COWRIE_LISTEN_PORT} : installed"
  else
    warn "  iptables 22->${COWRIE_LISTEN_PORT} : MISSING"
    ok=0
  fi

  if systemctl is-active --quiet redis-server.service; then
    log "  redis-server     : active"
  else
    warn "  redis-server     : NOT active"
  fi

  if [[ -x "${PROJECT_VENV}/bin/python" ]]; then
    log "  project venv     : ${PROJECT_VENV}"
  fi

  if [[ ${ok} -eq 1 ]]; then
    log "setup complete — try:  ssh anyuser@<vm-ip> -p ${COWRIE_LISTEN_PORT}"
  else
    warn "setup finished with warnings — inspect messages above"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  require_root
  check_ubuntu_2204
  install_apt_packages
  create_cowrie_user
  clone_or_update_cowrie
  build_cowrie_venv
  write_cowrie_cfg
  install_systemd_unit
  configure_iptables_redirect
  build_project_venv
  health_check
}

main "$@"
