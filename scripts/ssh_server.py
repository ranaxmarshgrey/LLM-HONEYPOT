"""Lightweight SSH honeypot server for live demos.

Runs a real SSH server (via paramiko) that accepts any login and
hands every command to the honeypot dispatcher.  The attacker sees
a fully realistic SSH session.

Usage (on the "victim" / honeypot laptop):
    python scripts/ssh_server.py                    # listens on 0.0.0.0:2222
    python scripts/ssh_server.py --port 22          # listen on port 22 (needs admin)
    python scripts/ssh_server.py --host 192.168.x.x # bind to specific interface

From the attacker laptop:
    ssh ubuntu@<victim-ip> -p 2222
    (any password works)
"""
from __future__ import annotations

import argparse
import logging
import os
import random
import socket
import sys
import threading
import time
import traceback
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv()

import paramiko

from honeypot.cowrie_hook import create_dispatcher
from event_logging.session_logger import SessionLogger

logger = logging.getLogger("ssh_server")

# ---------------------------------------------------------------------------
# Host key — generated once, reused across restarts
# ---------------------------------------------------------------------------
HOST_KEY_PATH = PROJECT_ROOT / "host_key"


def _get_host_key() -> paramiko.RSAKey:
    if HOST_KEY_PATH.exists():
        return paramiko.RSAKey(filename=str(HOST_KEY_PATH))
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(HOST_KEY_PATH))
    logger.info("Generated new host key: %s", HOST_KEY_PATH)
    return key


# ---------------------------------------------------------------------------
# SSH Server Interface — controls auth behaviour
# ---------------------------------------------------------------------------
class HoneypotSSHServer(paramiko.ServerInterface):
    """Accept any username/password after a short delay (looks realistic)."""

    def __init__(self) -> None:
        self.event = threading.Event()
        self.username: str = ""

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        time.sleep(random.uniform(0.3, 0.8))
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes,
    ) -> bool:
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        self.event.set()
        return True


# ---------------------------------------------------------------------------
# Session handler — one per attacker connection
# ---------------------------------------------------------------------------
def _handle_connection(
    client_sock: socket.socket,
    addr: tuple,
    host_key: paramiko.RSAKey,
    persona_name: str,
) -> None:
    attacker_ip = addr[0]
    attacker_port = addr[1]
    logger.info("Connection from %s:%d", attacker_ip, attacker_port)

    transport = paramiko.Transport(client_sock)
    transport.add_server_key(host_key)
    server = HoneypotSSHServer()

    try:
        transport.start_server(server=server)
    except paramiko.SSHException:
        logger.warning("SSH negotiation failed from %s", attacker_ip)
        client_sock.close()
        return

    channel = transport.accept(timeout=30)
    if channel is None:
        logger.warning("No channel opened by %s", attacker_ip)
        transport.close()
        return

    server.event.wait(10)
    if not server.event.is_set():
        logger.warning("Client %s never requested a shell", attacker_ip)
        channel.close()
        transport.close()
        return

    # Build the honeypot dispatcher for this session
    sess_logger = SessionLogger(
        log_dir=str(PROJECT_ROOT / "event_logging" / "logs"),
        logger_name="ssh_session",
    )
    dispatcher = create_dispatcher(
        attacker_ip=attacker_ip,
        attacker_port=attacker_port,
        persona_name=persona_name,
        session_logger=sess_logger,
    )

    hostname = dispatcher.fakefs.hostname
    kernel = dispatcher.fakefs.get_system_info().get(
        "kernel_version", "5.15.0-91-generic",
    )

    # Send SSH login banner
    banner = (
        f"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux {kernel} x86_64)\r\n"
        f"\r\n"
        f" * Documentation:  https://help.ubuntu.com\r\n"
        f" * Management:     https://landscape.canonical.com\r\n"
        f" * Support:        https://ubuntu.com/advantage\r\n"
        f"\r\n"
        f"Last login: {_fake_last_login()} from {_fake_login_ip()}\r\n"
    )
    channel.sendall(banner.encode("utf-8"))

    # Interactive shell loop
    buf = ""
    prompt = dispatcher.prompt
    channel.sendall(prompt.encode("utf-8"))

    try:
        while transport.is_active():
            if channel.recv_ready():
                data = channel.recv(4096)
                if not data:
                    break

                for byte in data:
                    ch = chr(byte)

                    if ch == "\r" or ch == "\n":
                        channel.sendall(b"\r\n")
                        cmd = buf.strip()
                        buf = ""

                        if not cmd:
                            channel.sendall(prompt.encode("utf-8"))
                            continue

                        if cmd.lower() in ("exit", "logout", "quit"):
                            channel.sendall(b"logout\r\n")
                            channel.sendall(
                                f"Connection to {hostname} closed.\r\n".encode("utf-8"),
                            )
                            channel.close()
                            dispatcher.close()
                            transport.close()
                            logger.info("Session ended (logout) for %s", attacker_ip)
                            return

                        response, source = dispatcher.dispatch(cmd)

                        if response.strip():
                            lines = response.replace("\n", "\r\n")
                            if not lines.endswith("\r\n"):
                                lines += "\r\n"
                            channel.sendall(lines.encode("utf-8"))

                        prompt = dispatcher.prompt
                        channel.sendall(prompt.encode("utf-8"))

                    elif ch == "\x7f" or ch == "\x08":
                        if buf:
                            buf = buf[:-1]
                            channel.sendall(b"\x08 \x08")
                    elif ch == "\x03":
                        channel.sendall(b"^C\r\n")
                        buf = ""
                        channel.sendall(prompt.encode("utf-8"))
                    elif ch == "\x04":
                        channel.sendall(b"logout\r\n")
                        channel.close()
                        dispatcher.close()
                        transport.close()
                        return
                    elif ord(ch) >= 32:
                        buf += ch
                        channel.sendall(ch.encode("utf-8"))
            else:
                time.sleep(0.05)

    except Exception:
        logger.debug("Session error for %s: %s", attacker_ip, traceback.format_exc())
    finally:
        dispatcher.close()
        try:
            channel.close()
        except Exception:
            pass
        try:
            transport.close()
        except Exception:
            pass
        logger.info("Session closed for %s", attacker_ip)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _fake_last_login() -> str:
    import datetime
    now = datetime.datetime.now()
    delta = datetime.timedelta(
        hours=random.randint(2, 48),
        minutes=random.randint(0, 59),
    )
    t = now - delta
    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    return "{} {} {:2d} {:02d}:{:02d}:{:02d} {:4d}".format(
        days[t.weekday()], months[t.month - 1], t.day,
        t.hour, t.minute, t.second, t.year,
    )


def _fake_login_ip() -> str:
    return "{}.{}.{}.{}".format(
        random.choice([10, 172, 192]),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(1, 254),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Honeypot SSH Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=2222, help="Listen port (default: 2222)")
    parser.add_argument("--persona", default="generic_linux", help="Starting persona")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    host_key = _get_host_key()
    logger.info("Host key fingerprint: %s", host_key.get_fingerprint().hex())

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(5)

    logger.info("Honeypot SSH server listening on %s:%d", args.host, args.port)
    logger.info("Attackers can connect with: ssh <any-user>@<this-ip> -p %d", args.port)
    logger.info("Any password will be accepted")
    logger.info("Press Ctrl+C to stop\n")

    try:
        while True:
            client_sock, addr = sock.accept()
            t = threading.Thread(
                target=_handle_connection,
                args=(client_sock, addr, host_key, args.persona),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        logger.info("\nShutting down...")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
