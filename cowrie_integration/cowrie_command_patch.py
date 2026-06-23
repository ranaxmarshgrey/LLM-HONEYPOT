"""Cowrie command handler patch.

This module replaces Cowrie's default command execution with our
adaptive honeypot Response Engine. It is loaded as a Cowrie plugin
by placing it in Cowrie's custom command directory.

When a command is received from an attacker:
  1. Cowrie's SSH layer captures the raw input
  2. This patch intercepts it BEFORE Cowrie processes it
  3. Routes it through our HoneypotCommandDispatcher
  4. Returns our LLM/FakeFS-generated output to the attacker

Installation:
  Run cowrie_integration/install_hook.sh, which:
  - Copies this file into Cowrie's source tree
  - Adds our project to Cowrie's Python path
  - Creates the bridge configuration
"""
from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger(__name__)

# Add our project to the path so we can import honeypot modules
_PROJECT_DIR = os.environ.get(
    "HONEYPOT_PROJECT_DIR", "/opt/adaptive-honeypot"
)
if _PROJECT_DIR not in sys.path:
    sys.path.insert(0, _PROJECT_DIR)


def get_dispatcher(session_id: str, attacker_ip: str, attacker_port: int = 0):
    """Create a dispatcher for a new Cowrie session.

    Called once per SSH connection from Cowrie's session setup.

    Args:
        session_id: Cowrie's session identifier.
        attacker_ip: Attacker's source IP.
        attacker_port: Attacker's source port.

    Returns:
        A HoneypotCommandDispatcher instance.
    """
    from dotenv import load_dotenv
    load_dotenv(os.path.join(_PROJECT_DIR, ".env"))

    from honeypot.cowrie_hook import create_dispatcher
    from event_logging.session_logger import SessionLogger

    log_dir = os.environ.get(
        "HONEYPOT_LOG_DIR",
        os.path.join(_PROJECT_DIR, "event_logging", "logs"),
    )
    session_logger = SessionLogger(log_dir=log_dir)

    persona = os.environ.get("HONEYPOT_DEFAULT_PERSONA", "generic_linux")

    dispatcher = create_dispatcher(
        session_id=session_id,
        attacker_ip=attacker_ip,
        attacker_port=attacker_port,
        persona_name=persona,
        session_logger=session_logger,
    )

    logger.info(
        "Adaptive honeypot dispatcher created for session %s (IP: %s)",
        session_id, attacker_ip,
    )
    return dispatcher


def handle_command(dispatcher, raw_input: str) -> str:
    """Process a command through the adaptive honeypot.

    Called by the patched Cowrie command handler for every command
    the attacker types.

    Args:
        dispatcher: The HoneypotCommandDispatcher for this session.
        raw_input: Exactly what the attacker typed.

    Returns:
        The simulated terminal output to send back to the attacker.
    """
    try:
        response, source = dispatcher.dispatch(raw_input)
        logger.debug(
            "Command '%s' handled via %s (%d chars)",
            raw_input.strip()[:50], source, len(response),
        )
        return response
    except Exception as exc:
        logger.error("Dispatcher error for '%s': %s", raw_input.strip()[:50], exc)
        return ""


def close_session(dispatcher):
    """Clean up when a Cowrie session ends.

    Args:
        dispatcher: The HoneypotCommandDispatcher to close.
    """
    try:
        dispatcher.close()
        logger.info("Session %s closed", dispatcher.session_id)
    except Exception as exc:
        logger.error("Error closing session %s: %s", dispatcher.session_id, exc)
