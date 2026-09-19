#!/usr/bin/env python3
"""Run a Bash payload over SSH after canonicalizing cross-platform text bytes."""
from __future__ import annotations
from pathlib import Path
import argparse, os, re, shutil, subprocess, sys

HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,253}\\Z")
USER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\\Z")

def canonical_bash_payload(raw: bytes) -> bytes:
    if raw.startswith(b"\\xef\\xbb\\xbf"):
        raw = raw[3:]
    if b"\\x00" in raw:
        raise ValueError("REMOTE_BASH_PAYLOAD_NUL")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("REMOTE_BASH_PAYLOAD_UTF8_INVALID") from exc
    text = text.replace("\\r\\n", "\\n").replace("\\r", "\\n")
    if not text.endswith("\\n"):
        text += "\\n"
    return text.encode("utf-8")

def ssh_command(*, ssh: str, identity: Path, user: str, host: str,
                connect_timeout: int, connection_attempts: int,
                alive_interval: int, alive_count: int) -> list[str]:
    if not USER_RE.fullmatch(user):
        raise ValueError("REMOTE_BASH_USER_INVALID")
    if not HOST_RE.fullmatch(host) or any(ch.isspace() for ch in host):
        raise ValueError("REMOTE_BASH_HOST_INVALID")
    if min(connect_timeout, connection_attempts, alive_interval, alive_count) < 1:
        raise ValueError("REMOTE_BASH_TIMEOUT_INVALID")
    if not identity.is_file():
        raise ValueError("REMOTE_BASH_IDENTITY_MISSING")
    resolved = shutil.which(ssh) if os.path.basename(ssh) == ssh else ssh
    if not resolved or not Path(resolved).is_file():
        raise ValueError("REMOTE_BASH_SSH_MISSING")
    return [
        resolved, "-i", str(identity),
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"ConnectTimeout={connect_timeout}",
        "-o", f"ConnectionAttempts={connection_attempts}",
        "-o", f"ServerAliveInterval={alive_interval}",
        "-o", f"ServerAliveCountMax={alive_count}",
        f"{user}@{host}", "bash", "-s",
    ]

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--script", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", default="root")
    parser.add_argument("--identity", required=True)
    parser.add_argument("--ssh", default="ssh")
    parser.add_argument("--connect-timeout", type=int, default=8)
    parser.add_argument("--connection-attempts", type=int, default=3)
    parser.add_argument("--alive-interval", type=int, default=5)
    parser.add_argument("--alive-count", type=int, default=3)
    args = parser.parse_args(argv)
    source = Path(args.script).expanduser().resolve()
    if not source.is_file():
        raise SystemExit("REMOTE_BASH_SCRIPT_MISSING")
    try:
        payload = canonical_bash_payload(source.read_bytes())
        command = ssh_command(
            ssh=args.ssh, identity=Path(args.identity).expanduser().resolve(),
            user=args.user, host=args.host, connect_timeout=args.connect_timeout,
            connection_attempts=args.connection_attempts,
            alive_interval=args.alive_interval, alive_count=args.alive_count,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    return subprocess.run(
        command, input=payload, stdout=sys.stdout.buffer, stderr=sys.stderr.buffer, check=False
    ).returncode

if __name__ == "__main__":
    raise SystemExit(main())
