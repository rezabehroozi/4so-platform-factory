#!/usr/bin/env python3
"""Exact browser-byte authority for release UI certification."""
from __future__ import annotations

from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys

AUTHORITY = "UI_BROWSER_AUTHORITY_V1"
ENV_AUTHORITY = "PLATFORM_FACTORY_UI_BROWSER_AUTHORITY"
ENV_EXECUTABLE = "PLATFORM_FACTORY_UI_BROWSER_EXECUTABLE"
SHA_RE = re.compile(r"(?:sha256:)?([0-9a-f]{64})\\Z")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_platform() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    if os.name == "nt":
        return "windows"
    return sys.platform


def normalized_arch() -> str:
    value = platform.machine().lower()
    return {"x86_64": "amd64", "x64": "amd64", "aarch64": "arm64"}.get(value, value)


def validate_ui_browser_authority(manifest_path: Path) -> tuple[Path, dict]:
    manifest_path = manifest_path.expanduser().resolve()
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("UI_BROWSER_AUTHORITY_MISSING")
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("UI_BROWSER_AUTHORITY_JSON_INVALID") from exc
    required = {"schemaVersion", "authority", "browser", "platform", "architecture", "version", "executable", "sha256", "size"}
    if not isinstance(document, dict) or set(document) != required:
        raise ValueError("UI_BROWSER_AUTHORITY_SCHEMA_INVALID")
    if document["schemaVersion"] != 1 or document["authority"] != AUTHORITY or document["browser"] != "chromium":
        raise ValueError("UI_BROWSER_AUTHORITY_IDENTITY_INVALID")
    if document["platform"] != normalized_platform() or document["architecture"] != normalized_arch():
        raise ValueError("UI_BROWSER_AUTHORITY_PLATFORM_MISMATCH")
    version = str(document["version"]).strip()
    executable_rel = str(document["executable"]).strip()
    if not version or not executable_rel or Path(executable_rel).is_absolute() or ".." in Path(executable_rel).parts:
        raise ValueError("UI_BROWSER_AUTHORITY_EXECUTABLE_INVALID")
    match = SHA_RE.fullmatch(str(document["sha256"]).strip())
    if match is None or not isinstance(document["size"], int) or isinstance(document["size"], bool) or document["size"] <= 0:
        raise ValueError("UI_BROWSER_AUTHORITY_DIGEST_INVALID")
    executable = (manifest_path.parent / executable_rel).resolve()
    try:
        info = executable.lstat()
    except OSError as exc:
        raise ValueError("UI_BROWSER_EXECUTABLE_MISSING") from exc
    if executable.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size != document["size"]:
        raise ValueError("UI_BROWSER_EXECUTABLE_IDENTITY_INVALID")
    if os.name != "nt" and info.st_mode & 0o111 == 0:
        raise ValueError("UI_BROWSER_EXECUTABLE_NOT_EXECUTABLE")
    if file_sha256(executable) != match.group(1):
        raise ValueError("UI_BROWSER_EXECUTABLE_DIGEST_MISMATCH")
    probe = subprocess.run([str(executable), "--version"], text=True, capture_output=True, timeout=15, check=False)
    observed = (probe.stdout or probe.stderr or "").strip()
    if probe.returncode != 0 or version not in observed:
        raise ValueError("UI_BROWSER_EXECUTABLE_VERSION_MISMATCH")
    return executable, document


def prepare_full_verifier_browser(environment: dict[str, str]) -> tuple[Path, dict]:
    raw = environment.get(ENV_AUTHORITY, "").strip()
    if not raw:
        raise ValueError("UI_BROWSER_AUTHORITY_MISSING: set PLATFORM_FACTORY_UI_BROWSER_AUTHORITY to an exact offline browser authority manifest")
    executable, document = validate_ui_browser_authority(Path(raw))
    environment[ENV_EXECUTABLE] = str(executable)
    return executable, document


def explicit_ui_browser() -> str | None:
    raw = os.environ.get(ENV_EXECUTABLE, "").strip()
    if not raw:
        return None
    path = Path(raw).expanduser().resolve()
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimeError("UI_BROWSER_EXECUTABLE_MISSING") from exc
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("UI_BROWSER_EXECUTABLE_IDENTITY_INVALID")
    return str(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority")
    args = parser.parse_args()
    raw = args.authority or os.environ.get(ENV_AUTHORITY, "")
    if not raw.strip():
        raise SystemExit("UI_BROWSER_AUTHORITY_MISSING")
    try:
        executable, document = validate_ui_browser_authority(Path(raw))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"UI_BROWSER_AUTHORITY_PASS authority={AUTHORITY} browser={document['browser']} version={document['version']} executable={executable}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
