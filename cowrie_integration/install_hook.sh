#!/usr/bin/env bash
# cowrie_integration/install_hook.sh
#
# Patches Cowrie to route all commands through our adaptive honeypot.
# Safe to run multiple times (idempotent).
#
# What this does:
#   1. Adds our project directory to Cowrie's PYTHONPATH
#   2. Copies our command patch into Cowrie's source tree
#   3. Patches cowrie/shell/protocol.py to intercept commands
#   4. Restarts Cowrie to pick up changes
#
# Usage:  sudo bash cowrie_integration/install_hook.sh
#
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
COWRIE_HOME="${COWRIE_HOME:-/opt/cowrie}"
COWRIE_USER="${COWRIE_USER:-cowrie}"

log()  { printf '\033[1;34m[hook]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[hook]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m[hook]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[hook]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Validate Cowrie installation
# ---------------------------------------------------------------------------
[[ -d "${COWRIE_HOME}/src/cowrie" ]] || die "Cowrie not found at ${COWRIE_HOME}"

# ---------------------------------------------------------------------------
# 1. Set PYTHONPATH in Cowrie's environment
# ---------------------------------------------------------------------------
log "configuring Cowrie environment"

COWRIE_ENV_FILE="${COWRIE_HOME}/etc/cowrie.env"
if [[ ! -f "${COWRIE_ENV_FILE}" ]]; then
  touch "${COWRIE_ENV_FILE}"
  chown "${COWRIE_USER}:${COWRIE_USER}" "${COWRIE_ENV_FILE}"
fi

# Add our project to PYTHONPATH if not already there
if ! grep -q "HONEYPOT_PROJECT_DIR" "${COWRIE_ENV_FILE}" 2>/dev/null; then
  cat >> "${COWRIE_ENV_FILE}" <<EOF

# Adaptive Honeypot integration
HONEYPOT_PROJECT_DIR=${PROJECT_DIR}
PYTHONPATH=\${PYTHONPATH:+\$PYTHONPATH:}${PROJECT_DIR}
EOF
  log "added HONEYPOT_PROJECT_DIR to ${COWRIE_ENV_FILE}"
else
  log "HONEYPOT_PROJECT_DIR already in ${COWRIE_ENV_FILE}"
fi

# Also add to the systemd service override
SYSTEMD_OVERRIDE_DIR="/etc/systemd/system/cowrie.service.d"
mkdir -p "${SYSTEMD_OVERRIDE_DIR}"
cat > "${SYSTEMD_OVERRIDE_DIR}/honeypot.conf" <<EOF
[Service]
Environment=HONEYPOT_PROJECT_DIR=${PROJECT_DIR}
Environment=PYTHONPATH=${PROJECT_DIR}
EnvironmentFile=-${PROJECT_DIR}/.env
EOF
systemctl daemon-reload
log "systemd environment override installed"

# ---------------------------------------------------------------------------
# 2. Copy our command patch module
# ---------------------------------------------------------------------------
log "installing command patch module"
PATCH_DEST="${COWRIE_HOME}/src/cowrie/commands/adaptive_honeypot.py"
cp "${SCRIPT_DIR}/cowrie_command_patch.py" "${PATCH_DEST}"
chown "${COWRIE_USER}:${COWRIE_USER}" "${PATCH_DEST}"
ok "patch module installed at ${PATCH_DEST}"

# ---------------------------------------------------------------------------
# 3. Install our project deps into Cowrie's virtualenv
# ---------------------------------------------------------------------------
log "installing project requirements into Cowrie virtualenv"
COWRIE_VENV="${COWRIE_HOME}/cowrie-env"
if [[ -x "${COWRIE_VENV}/bin/pip" ]]; then
  "${COWRIE_VENV}/bin/pip" install --quiet \
    python-dotenv pydantic 'pydantic-settings>=2.2.0' \
    'google-generativeai>=0.8.0' \
    'anthropic>=0.25.0' 'httpx>=0.27.0'
  ok "dependencies installed"
else
  warn "Cowrie virtualenv not found at ${COWRIE_VENV} — install deps manually"
fi

# ---------------------------------------------------------------------------
# 4. Patch Cowrie's protocol to intercept commands
# ---------------------------------------------------------------------------
log "patching Cowrie command handler"

PROTOCOL_FILE="${COWRIE_HOME}/src/cowrie/shell/protocol.py"
MARKER="# ADAPTIVE_HONEYPOT_PATCH"

# Restore backup if available so we can re-patch cleanly
if [[ -f "${PROTOCOL_FILE}.bak" ]]; then
  cp "${PROTOCOL_FILE}.bak" "${PROTOCOL_FILE}"
fi

python3 - "${PROTOCOL_FILE}" "${MARKER}" "${PROJECT_DIR}" <<'PYSCRIPT'
import sys

filepath = sys.argv[1]
marker = sys.argv[2]
project_dir = sys.argv[3]

with open(filepath, "r") as f:
    content = f.read()

patch_import = f"""
{marker}
import os as _hp_os
import sys as _hp_sys
_hp_project = _hp_os.environ.get("HONEYPOT_PROJECT_DIR", "{project_dir}")
if _hp_project not in _hp_sys.path:
    _hp_sys.path.insert(0, _hp_project)

_hp_dispatchers = {{}}  # session_id -> dispatcher

def _hp_get_dispatcher(protocol):
    \"\"\"Get or create an adaptive honeypot dispatcher for this session.\"\"\"
    sid = getattr(protocol, "sessionno", id(protocol))
    session_id = str(sid)
    if session_id not in _hp_dispatchers:
        try:
            from cowrie_integration.cowrie_command_patch import get_dispatcher
            peer = protocol.transport.getPeer()
            ip = getattr(peer, "host", "0.0.0.0")
            port = getattr(peer, "port", 0)
            _hp_dispatchers[session_id] = get_dispatcher(session_id, ip, port)
        except Exception as e:
            import logging
            logging.getLogger("cowrie.adaptive").error("Failed to create dispatcher: %s", e)
            return None
    return _hp_dispatchers.get(session_id)

def _hp_handle_command(protocol, cmd_string):
    \"\"\"Route a command through the adaptive honeypot.\"\"\"
    dispatcher = _hp_get_dispatcher(protocol)
    if dispatcher is None:
        return None  # fall through to default Cowrie handling
    try:
        from cowrie_integration.cowrie_command_patch import handle_command
        output = handle_command(dispatcher, cmd_string)
        prompt = dispatcher.prompt
        return output, prompt
    except Exception as e:
        import logging
        logging.getLogger("cowrie.adaptive").error("Command handling failed: %s", e)
        return None

def _hp_close_session(protocol):
    \"\"\"Clean up when a session ends.\"\"\"
    sid = str(getattr(protocol, "sessionno", id(protocol)))
    dispatcher = _hp_dispatchers.pop(sid, None)
    if dispatcher:
        try:
            from cowrie_integration.cowrie_command_patch import close_session
            close_session(dispatcher)
        except Exception:
            pass
{marker}_END
"""

# Add imports at top
import_end = content.rfind("\nclass ")
if import_end == -1:
    import_end = content.rfind("\n\n")
content = content[:import_end] + patch_import + content[import_end:]

# Insert hook at beginning of lineReceived definition using regex
import re

hook_code = """
        # ADAPTIVE_HONEYPOT_EXEC_HOOK
        try:
            _line_str = line.decode('utf-8', errors='ignore') if isinstance(line, bytes) else str(line)
            _res = _hp_handle_command(self, _line_str)
            if _res is not None:
                _out, _prompt = _res
                if _out and not _out.endswith('\\n'):
                    _out += '\\n'
                if hasattr(self, 'terminal') and self.terminal:
                    self.terminal.write(_out.encode('utf-8'))
                    self.terminal.write(_prompt.encode('utf-8'))
                elif hasattr(self, 'sendLine'):
                    self.sendLine(_out.encode('utf-8'))
                return
        except Exception as _e:
            import logging
            logging.getLogger("cowrie.adaptive").error("Hook exec error: %s", _e)
"""

pattern = re.compile(r"(def\s+lineReceived\s*\([^)]*\)\s*(?:->\s*[^:]+)?\s*:)")
if pattern.search(content):
    content = pattern.sub(r"\1" + hook_code, content)
    print("Found and patched lineReceived with regex")
else:
    print("WARNING: lineReceived not found in protocol.py!")

with open(filepath, "w") as f:
    f.write(content)

print(f"Patched {filepath} successfully")
PYSCRIPT

ok "Cowrie command handler patched"

# ---------------------------------------------------------------------------
# 5. Restart Cowrie
# ---------------------------------------------------------------------------
log "restarting Cowrie"
systemctl restart cowrie 2>/dev/null || "${COWRIE_HOME}/bin/cowrie" restart
ok "Cowrie restarted with adaptive honeypot integration"

echo ""
ok "Cowrie integration installed successfully!"
echo "  Test: ssh anyuser@localhost -p 2222"
echo "  Logs: journalctl -u cowrie -f"
echo ""
