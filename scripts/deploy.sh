#!/usr/bin/env bash
# scripts/deploy.sh
#
# Push latest code to the production VM and restart the honeypot service.
# Assumes setup.sh has already run on the target.
#
# Usage:  bash scripts/deploy.sh <user@host>
set -euo pipefail

# TODO(Sprint 1+): rsync project (minus .env, logs, venv) to remote.
# TODO(Sprint 1+): ssh remote "systemctl restart cowrie honeypot".
# TODO(Sprint 6): hook dashboard restart in as well.
