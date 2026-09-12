#!/usr/bin/env python3
"""Provision and launch the optional Chrome DevTools MCP browser specialist.

This is developer/Autopilot tooling only. It never changes product runtime state.
On Windows and Linux it verifies Node/npm/npx plus a supported Google Chrome or
Chrome for Testing binary. Missing prerequisites are provisioned user-locally by
`--ensure`, avoiding a mandatory Administrator/root dependency.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile

AUTHORITY = "BROWSER_TRIAGE_PREREQUISITE_AUTHORITY_V1"
MCP_PACKAGE = "chrome-devtools-mcp"
MCP_VERSION = "1.8.0"
NODE_VERSION = "22.12.0"
CHROME_VERSION = "152.0.7977.75"

NODE_ASSETS = {
    ("linux", "x86_64"): (
        "node-v22.12.0-linux-x64.tar.xz",
        "22982235e1b71fa8850f82edd09cdae7e3f32df1764a9ec298c72d25ef2c164f",
    ),
    ("linux", "aarch64"): (
        "node-v22.12.0-linux-arm64.tar.xz",
        "8cfd5a8b9afae5a2e0bd86b0148ca31d2589c0ea669c2d0b11c132e35d90ed68",
    ),
    ("windows", "amd64"): (
        "node-v22.12.0-win-x64.zip",
        "2b8f2256382f97ad51e29ff71f702961af466c4616393f767455501e6aece9b8",
    ),
    ("windows", "arm64"): (
        "node-v22.12.0-win-arm64.zip",
        "17401720af48976e3f67c41e8968a135fb49ca1f88103a92e0e8c70605763854",
    ),
}

# Chrome for Testing is version-pinned for this 4SO release. Google publishes
# exact versioned assets over HTTPS but does not publish SHA-256 in the CfT JSON
# API. The bootstrap verifies the extracted browser reports this exact version.
CHROME_ASSETS = {
    ("linux", "x86_64"): ("linux64", "chrome-linux64", "chrome"),
    ("windows", "amd64"): ("win64", "chrome-win64", "chrome.exe"),
    ("windows", "x86_64"): ("win64", "chrome-win64", "chrome.exe"),
}


def _normalized_platform(system: str | None = None, machine: str | None = None) -> tuple[str, str]:
    raw_system = (system or platform.system()).lower()
    raw_machine = (machine or platform.machine()).lower()
    if raw_system.startswith("win"):
        os_name = "windows"
    elif raw_system == "linux":
        os_name = "linux"
    else:
        os_name = raw_system
    aliases = {"x64": "amd64", "x86-64": "x86_64", "arm64": "arm64", "aarch64": "aarch64"}
    return os_name, aliases.get(raw_machine, raw_machine)


def _cache_root() -> Path:
    override = os.environ.get("PLATFORM_FACTORY_BROWSER_TOOLCHAIN_DIR", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
        return base / "4SO" / "browser-triage"
    return Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "4so-platform-factory" / "browser-triage"


def _run_version(command: list[str]) -> str | None:
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else None


def _parse_numeric_version(raw: str | None) -> tuple[int, ...]:
    if not raw:
        return ()
    token = raw.strip().lower().replace("google chrome", "").replace("chrome for testing", "").replace("chromium", "").strip()
    if token.startswith("v"):
        token = token[1:]
    parts: list[int] = []
    for item in token.split("."):
        digits = "".join(ch for ch in item if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def _node_compatible(raw: str | None) -> bool:
    version = _parse_numeric_version(raw)
    if not version:
        return False
    major = version[0]
    minor = version[1] if len(version) > 1 else 0
    if major == 20:
        return minor >= 19
    if major == 22:
        return minor >= 12
    return major >= 23


def _chrome_compatible(raw: str | None) -> bool:
    version = _parse_numeric_version(raw)
    required = _parse_numeric_version(CHROME_VERSION)
    return bool(version and required and version >= required)


def _node_local_paths(root: Path, os_name: str, arch: str) -> tuple[Path, Path, Path] | None:
    asset = NODE_ASSETS.get((os_name, arch)) or NODE_ASSETS.get((os_name, "amd64" if arch == "x86_64" else arch))
    if asset is None:
        return None
    stem = asset[0]
    for suffix in (".tar.xz", ".zip"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    base = root / "node" / stem
    if os_name == "windows":
        return base / "node.exe", base / "npm.cmd", base / "npx.cmd"
    return base / "bin" / "node", base / "bin" / "npm", base / "bin" / "npx"


def _chrome_local_path(root: Path, os_name: str, arch: str) -> Path | None:
    asset = CHROME_ASSETS.get((os_name, arch)) or CHROME_ASSETS.get((os_name, "amd64" if arch == "x86_64" else arch))
    if asset is None:
        return None
    _, folder, executable = asset
    return root / "chrome" / CHROME_VERSION / folder / executable


def _system_chrome_candidates(os_name: str) -> list[Path]:
    result: list[Path] = []
    if os_name == "windows":
        for key in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            base = os.environ.get(key)
            if base:
                result.append(Path(base) / "Google" / "Chrome" / "Application" / "chrome.exe")
    elif os_name == "linux":
        for command in ("google-chrome-stable", "google-chrome"):
            found = shutil.which(command)
            if found:
                result.append(Path(found))
    return result


def _find_ready(root: Path) -> dict[str, object]:
    os_name, arch = _normalized_platform()
    result: dict[str, object] = {"authority": AUTHORITY, "os": os_name, "arch": arch}

    node = shutil.which("node")
    npm = shutil.which("npm")
    npx = shutil.which("npx")
    node_version = _run_version([node, "--version"]) if node else None
    if not (node and npm and npx and _node_compatible(node_version)):
        local = _node_local_paths(root, os_name, arch)
        if local and all(path.is_file() for path in local):
            node, npm, npx = map(str, local)
            node_version = _run_version([node, "--version"])
    result.update({"nodePath": node, "nodeVersion": node_version, "npmPath": npm, "npxPath": npx})
    result["nodeReady"] = bool(node and npm and npx and _node_compatible(node_version))

    chrome: str | None = None
    chrome_version: str | None = None
    local_chrome = _chrome_local_path(root, os_name, arch)
    candidates = []
    if local_chrome:
        candidates.append(local_chrome)
    candidates.extend(_system_chrome_candidates(os_name))
    for candidate in candidates:
        if not candidate.is_file():
            continue
        raw = _run_version([str(candidate), "--version"])
        if _chrome_compatible(raw):
            chrome = str(candidate)
            chrome_version = raw
            break
    result.update({"chromePath": chrome, "chromeVersion": chrome_version, "chromeReady": bool(chrome)})
    result["ready"] = bool(result["nodeReady"] and result["chromeReady"])
    return result


def _download(url: str, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "4SO-Platform-Factory-Browser-Triage/1"})
    with urllib.request.urlopen(request, timeout=120) as response, target.open("wb") as output:
        shutil.copyfileobj(response, output)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_zip_extract(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        normalized: dict[str, str] = {}
        modes: dict[str, int] = {}
        for info in infos:
            name = posixpath.normpath(info.filename.replace("\\", "/"))
            if not name or name in {".", ".."} or name.startswith("../") or name.startswith("/"):
                raise RuntimeError("BROWSER_BOOTSTRAP_ARCHIVE_PATH_TRAVERSAL")
            candidate = (destination / name).resolve(strict=False)
            if root not in candidate.parents and candidate != root:
                raise RuntimeError("BROWSER_BOOTSTRAP_ARCHIVE_PATH_TRAVERSAL")
            mode = ((info.external_attr >> 16) & 0xFFFF) if info.create_system == 3 else 0
            file_type = stat.S_IFMT(mode)
            is_dir = info.is_dir() or info.filename.endswith("/")
            if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise RuntimeError(f"BROWSER_BOOTSTRAP_ARCHIVE_SPECIAL_MEMBER_FORBIDDEN name={info.filename}")
            if (is_dir and file_type == stat.S_IFREG) or (not is_dir and file_type == stat.S_IFDIR):
                raise RuntimeError(f"BROWSER_BOOTSTRAP_ARCHIVE_SPECIAL_MEMBER_FORBIDDEN name={info.filename}")
            normalized[info.filename] = name
            modes[info.filename] = mode & 0o777
        for info in infos:
            candidate = destination / normalized[info.filename]
            if info.is_dir() or info.filename.endswith("/"):
                candidate.mkdir(parents=True, exist_ok=True)
            else:
                candidate.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as source, candidate.open("wb") as output:
                    shutil.copyfileobj(source, output)
            if modes[info.filename]:
                candidate.chmod(modes[info.filename])


def _safe_tar_extract(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with tarfile.open(archive, "r:xz") as tf:
        members = tf.getmembers()
        normalized: dict[str, str] = {}
        for member in members:
            name = posixpath.normpath(member.name.replace("\\", "/"))
            if not name or name in {".", ".."} or name.startswith("../") or name.startswith("/"):
                raise RuntimeError("BROWSER_BOOTSTRAP_ARCHIVE_PATH_TRAVERSAL")
            candidate = (destination / name).resolve(strict=False)
            if root not in candidate.parents and candidate != root:
                raise RuntimeError("BROWSER_BOOTSTRAP_ARCHIVE_PATH_TRAVERSAL")
            normalized[member.name] = name
            if member.issym():
                target = member.linkname.replace("\\", "/")
                if not target or target.startswith("/"):
                    raise RuntimeError(f"BROWSER_BOOTSTRAP_ARCHIVE_SYMLINK_TARGET_ESCAPE name={member.name}")
                resolved_target = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
                if resolved_target in {"..", "."} or resolved_target.startswith("../") or resolved_target.startswith("/"):
                    raise RuntimeError(f"BROWSER_BOOTSTRAP_ARCHIVE_SYMLINK_TARGET_ESCAPE name={member.name}")
                target_path = (destination / resolved_target).resolve(strict=False)
                if root not in target_path.parents and target_path != root:
                    raise RuntimeError(f"BROWSER_BOOTSTRAP_ARCHIVE_SYMLINK_TARGET_ESCAPE name={member.name}")
            elif member.islnk() or not (member.isdir() or member.isfile()):
                raise RuntimeError(f"BROWSER_BOOTSTRAP_ARCHIVE_SPECIAL_MEMBER_FORBIDDEN name={member.name}")
        for member in members:
            candidate = (destination / normalized[member.name]).resolve(strict=False)
            if member.isdir():
                candidate.mkdir(parents=True, exist_ok=True)
                continue
            candidate.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                if candidate.exists() or candidate.is_symlink():
                    candidate.unlink()
                os.symlink(member.linkname, candidate)
                continue
            source = tf.extractfile(member)
            if source is None:
                raise RuntimeError(f"BROWSER_BOOTSTRAP_ARCHIVE_MEMBER_UNREADABLE name={member.name}")
            with source, candidate.open("wb") as output:
                shutil.copyfileobj(source, output)
            candidate.chmod(member.mode & 0o777)


def _ensure_node(root: Path, os_name: str, arch: str) -> None:
    key = (os_name, arch)
    if key not in NODE_ASSETS and os_name == "windows" and arch == "x86_64":
        key = (os_name, "amd64")
    asset = NODE_ASSETS.get(key)
    if asset is None:
        raise RuntimeError(f"BROWSER_BOOTSTRAP_NODE_PLATFORM_UNSUPPORTED os={os_name} arch={arch}")
    filename, expected = asset
    url = f"https://nodejs.org/dist/v{NODE_VERSION}/{filename}"
    downloads = root / "downloads"
    archive = downloads / filename
    if not archive.is_file() or _sha256(archive) != expected:
        archive.unlink(missing_ok=True)
        _download(url, archive)
    actual = _sha256(archive)
    if actual != expected:
        archive.unlink(missing_ok=True)
        raise RuntimeError(f"BROWSER_BOOTSTRAP_NODE_DIGEST_MISMATCH expected={expected} actual={actual}")
    destination = root / "node"
    local = _node_local_paths(root, os_name, arch)
    assert local is not None
    if all(path.is_file() for path in local) and _node_compatible(_run_version([str(local[0]), "--version"])):
        return
    if destination.exists():
        shutil.rmtree(destination)
    if filename.endswith(".zip"):
        _safe_zip_extract(archive, destination)
    else:
        _safe_tar_extract(archive, destination)
    if not all(path.is_file() for path in local) or not _node_compatible(_run_version([str(local[0]), "--version"])):
        raise RuntimeError("BROWSER_BOOTSTRAP_NODE_INSTALL_VERIFY_FAILED")


def _ensure_chrome(root: Path, os_name: str, arch: str) -> None:
    key = (os_name, arch)
    if key not in CHROME_ASSETS and os_name == "windows" and arch == "x86_64":
        key = (os_name, "amd64")
    asset = CHROME_ASSETS.get(key)
    if asset is None:
        raise RuntimeError(f"BROWSER_BOOTSTRAP_CHROME_PLATFORM_UNSUPPORTED os={os_name} arch={arch}; install current stable Google Chrome manually")
    platform_id, folder, executable = asset
    filename = f"chrome-{platform_id}.zip"
    url = f"https://storage.googleapis.com/chrome-for-testing-public/{CHROME_VERSION}/{platform_id}/{filename}"
    archive = root / "downloads" / f"chrome-{CHROME_VERSION}-{platform_id}.zip"
    target = root / "chrome" / CHROME_VERSION / folder / executable
    if target.is_file() and _chrome_compatible(_run_version([str(target), "--version"])):
        return
    archive.unlink(missing_ok=True)
    _download(url, archive)
    destination = root / "chrome" / CHROME_VERSION
    if destination.exists():
        shutil.rmtree(destination)
    _safe_zip_extract(archive, destination)
    if os_name == "linux" and target.is_file():
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    raw = _run_version([str(target), "--version"])
    if not target.is_file() or not _chrome_compatible(raw):
        raise RuntimeError(f"BROWSER_BOOTSTRAP_CHROME_INSTALL_VERIFY_FAILED version={raw!r}")


def ensure() -> dict[str, object]:
    root = _cache_root()
    os_name, arch = _normalized_platform()
    if os_name not in {"linux", "windows"}:
        raise RuntimeError(f"BROWSER_BOOTSTRAP_OS_UNSUPPORTED os={os_name}")
    current = _find_ready(root)
    if not current["nodeReady"]:
        _ensure_node(root, os_name, arch)
    current = _find_ready(root)
    if not current["chromeReady"]:
        _ensure_chrome(root, os_name, arch)
    current = _find_ready(root)
    if not current["ready"]:
        raise RuntimeError("BROWSER_BOOTSTRAP_POST_INSTALL_NOT_READY")
    current["toolchainRoot"] = str(root)
    current["mcpPackage"] = f"{MCP_PACKAGE}@{MCP_VERSION}"
    current["provisioning"] = "user-local-pinned-fallback"
    return current


def mcp_command(ready: dict[str, object]) -> list[str]:
    npx = str(ready.get("npxPath") or "")
    chrome = str(ready.get("chromePath") or "")
    if not npx or not chrome:
        raise RuntimeError("BROWSER_BOOTSTRAP_MCP_COMMAND_NOT_READY")
    args = [
        npx,
        "-y",
        f"{MCP_PACKAGE}@{MCP_VERSION}",
        "--executablePath",
        chrome,
        "--headless",
        "--isolated",
        "--no-usage-statistics",
        "--no-performance-crux",
    ]
    if os.name == "nt":
        return ["cmd", "/d", "/s", "/c", *args]
    return args


def self_test() -> None:
    assert _node_compatible("v20.19.0")
    assert not _node_compatible("v20.18.9")
    assert _node_compatible("v22.12.0")
    assert not _node_compatible("v22.11.9")
    assert _node_compatible("v24.1.0")
    assert _chrome_compatible("Google Chrome 152.0.7977.75")
    assert not _chrome_compatible("Google Chrome 151.0.7922.174")
    assert _normalized_platform("Windows", "AMD64") == ("windows", "amd64")
    assert _normalized_platform("Linux", "x86_64") == ("linux", "x86_64")
    for key, (_, digest) in NODE_ASSETS.items():
        assert len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest), key
    assert ("linux", "x86_64") in CHROME_ASSETS
    assert ("windows", "amd64") in CHROME_ASSETS


def main() -> int:
    parser = argparse.ArgumentParser(description="4SO browser-triage prerequisite bootstrap")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="report whether Node/npm/npx and supported Chrome are ready")
    mode.add_argument("--ensure", action="store_true", help="install missing prerequisites user-locally, then verify")
    mode.add_argument("--run-mcp", action="store_true", help="ensure prerequisites and launch exact-pinned Chrome DevTools MCP")
    mode.add_argument("--self-test", action="store_true", help="validate platform/version/digest policy without network access")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("BROWSER_TRIAGE_PREREQUISITE_SELF_TEST_PASS", AUTHORITY)
        return 0
    try:
        if args.ensure or args.run_mcp:
            value = ensure()
        else:
            value = _find_ready(_cache_root())
            value["toolchainRoot"] = str(_cache_root())
            value["mcpPackage"] = f"{MCP_PACKAGE}@{MCP_VERSION}"
        if args.run_mcp:
            env = os.environ.copy()
            env.update({
                "CHROME_DEVTOOLS_MCP_NO_UPDATE_CHECKS": "1",
                "CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS": "1",
                "CI": "1",
            })
            command = mcp_command(value)
            return subprocess.call(command, env=env)
        if args.json:
            print(json.dumps(value, sort_keys=True))
        else:
            status = "PASS" if value.get("ready") else "BLOCKED"
            print(f"BROWSER_TRIAGE_PREREQUISITES_{status} os={value.get('os')} arch={value.get('arch')} node={value.get('nodeVersion')} chrome={value.get('chromeVersion')}")
        return 0 if value.get("ready") else 3
    except (RuntimeError, OSError, urllib.error.URLError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print(f"BROWSER_TRIAGE_PREREQUISITES_BLOCKED error={exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
