#!/usr/bin/env python3
"""Pinned build-time toolchain authority for S1 upstream acquisition.

The product runtime never depends on these binaries. Acquisition hosts must use the
exact tool versions in catalog/upstream-acquisition-toolchain.json. Bootstrap is
optional, downloads only exact locked assets, verifies SHA-256 before extraction,
and installs into an operator-selected directory rather than the product tree.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "catalog" / "upstream-acquisition-toolchain.json"
AUTHORITY = "UPSTREAM_ACQUISITION_TOOLCHAIN_V3"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
EXPECTED_INPUT_LIMITS = {
    "maxHelmIndexBytes": 32 * 1024 * 1024,
    "maxChartArchiveBytes": 64 * 1024 * 1024,
    "maxChartMembers": 8192,
    "maxChartUnpackedBytes": 512 * 1024 * 1024,
    "maxChartMetadataBytes": 1024 * 1024,
}


def _load(path: Path = DEFAULT_LOCK) -> dict:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("ACQUISITION_TOOLCHAIN_LOCK_NOT_REGULAR")
    doc = json.loads(path.read_text())
    if doc.get("apiVersion") != "platform.4so.io/v1alpha1" or doc.get("kind") != "UpstreamAcquisitionToolchain":
        raise RuntimeError("ACQUISITION_TOOLCHAIN_TYPE_INVALID")
    spec = doc.get("spec") or {}
    if spec.get("authority") != AUTHORITY:
        raise RuntimeError("ACQUISITION_TOOLCHAIN_AUTHORITY_INVALID")
    policy = spec.get("policy") or {}
    required = {
        "allowUnpinnedTools": False,
        "allowLatestResolution": False,
        "requireAssetDigestVerification": True,
        "bootstrapIsBuildTimeOnly": True,
        "vendoredIntoProductArtifact": False,
        "allowStagedOfflineBootstrap": True,
        "stagedArchivesMustMatchLockedFilename": True,
    }
    for key, expected in required.items():
        if policy.get(key) != expected:
            raise RuntimeError(f"ACQUISITION_TOOLCHAIN_POLICY_INVALID {key}")
    if spec.get("inputLimits") != EXPECTED_INPUT_LIMITS:
        raise RuntimeError("ACQUISITION_TOOLCHAIN_INPUT_LIMITS_INVALID")
    tools = spec.get("tools")
    if not isinstance(tools, list) or not tools:
        raise RuntimeError("ACQUISITION_TOOLCHAIN_TOOLS_INVALID")
    seen: set[str] = set()
    for tool in tools:
        if not isinstance(tool, dict):
            raise RuntimeError("ACQUISITION_TOOLCHAIN_TOOL_INVALID")
        name = str(tool.get("name") or "")
        version = str(tool.get("version") or "")
        if not NAME_RE.fullmatch(name) or name in seen or not VERSION_RE.fullmatch(version):
            raise RuntimeError(f"ACQUISITION_TOOLCHAIN_IDENTITY_INVALID {name}@{version}")
        seen.add(name)
        cmd = tool.get("versionCommand")
        if not isinstance(cmd, list) or not cmd or any(not isinstance(x, str) or not x or len(x) > 64 for x in cmd):
            raise RuntimeError(f"ACQUISITION_TOOLCHAIN_VERSION_COMMAND_INVALID {name}")
        try:
            re.compile(str(tool.get("versionRegex") or ""))
        except re.error as exc:
            raise RuntimeError(f"ACQUISITION_TOOLCHAIN_VERSION_REGEX_INVALID {name}") from exc
        platforms = tool.get("platforms")
        if not isinstance(platforms, dict) or set(platforms) != {"linux-amd64", "linux-arm64"}:
            raise RuntimeError(f"ACQUISITION_TOOLCHAIN_PLATFORMS_INVALID {name}")
        for target, asset in platforms.items():
            if not isinstance(asset, dict):
                raise RuntimeError(f"ACQUISITION_TOOLCHAIN_ASSET_INVALID {name}:{target}")
            url = str(asset.get("url") or "")
            digest = str(asset.get("sha256") or "")
            member = str(asset.get("archiveMember") or "")
            if not url.startswith("https://") or not SHA256_RE.fullmatch(digest) or not member or member.startswith("/") or ".." in Path(member).parts:
                raise RuntimeError(f"ACQUISITION_TOOLCHAIN_ASSET_INVALID {name}:{target}")
    if seen != {"helm", "crane"}:
        raise RuntimeError(f"ACQUISITION_TOOLCHAIN_REQUIRED_TOOLS_INVALID {sorted(seen)}")
    return doc


def input_limits(path: Path = DEFAULT_LOCK) -> dict[str, int]:
    return dict((_load(path).get("spec") or {})["inputLimits"])


def tool_map(path: Path = DEFAULT_LOCK) -> dict[str, dict]:
    doc = _load(path)
    return {str(x["name"]): x for x in doc["spec"]["tools"]}


def host_platform() -> str:
    if platform.system().lower() != "linux":
        raise RuntimeError("ACQUISITION_TOOLCHAIN_HOST_UNSUPPORTED")
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if not arch:
        raise RuntimeError(f"ACQUISITION_TOOLCHAIN_ARCH_UNSUPPORTED {machine}")
    return "linux-" + arch


def _run_version(binary: Path, args: list[str]) -> str:
    proc = subprocess.run([str(binary), *args], text=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    if proc.returncode:
        raise RuntimeError(f"ACQUISITION_TOOLCHAIN_VERSION_COMMAND_FAILED {binary.name} rc={proc.returncode}")
    lines = [x.strip() for x in proc.stdout.splitlines() if x.strip()]
    if not lines:
        raise RuntimeError(f"ACQUISITION_TOOLCHAIN_VERSION_EMPTY {binary.name}")
    return lines[-1]


def resolve_tool(name: str, *, tool_dir: Path | None = None, lock: Path = DEFAULT_LOCK) -> tuple[Path, str]:
    tools = tool_map(lock)
    if name not in tools:
        raise RuntimeError(f"ACQUISITION_TOOLCHAIN_TOOL_UNKNOWN {name}")
    tool = tools[name]
    candidates: list[Path] = []
    env_dir = os.environ.get("PLATFORM_FACTORY_ACQUISITION_TOOL_DIR", "").strip()
    for d in (tool_dir, Path(env_dir) if env_dir else None):
        if d:
            candidates.append(d / name)
    found = shutil.which(name)
    if found:
        candidates.append(Path(found))
    seen: set[str] = set()
    for binary in candidates:
        key = str(binary)
        if key in seen:
            continue
        seen.add(key)
        try:
            st = binary.stat()
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or not os.access(binary, os.X_OK):
            continue
        actual = _run_version(binary, list(tool["versionCommand"]))
        if re.fullmatch(str(tool["versionRegex"]), actual):
            return binary.resolve(), actual
        raise RuntimeError(f"ACQUISITION_TOOLCHAIN_VERSION_MISMATCH {name} expected={tool['version']} actual={actual}")
    raise RuntimeError(f"ACQUISITION_TOOLCHAIN_TOOL_MISSING {name}@{tool['version']}")


def require_toolchain(*, tool_dir: Path | None = None, lock: Path = DEFAULT_LOCK) -> dict[str, tuple[Path, str]]:
    return {name: resolve_tool(name, tool_dir=tool_dir, lock=lock) for name in ("helm", "crane")}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, out: Path, timeout: int) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "4so-platform-factory-acquisition-toolchain/2"})
    with urllib.request.urlopen(req, timeout=timeout) as response, out.open("wb") as fh:
        final = response.geturl()
        if not str(final).startswith("https://"):
            raise RuntimeError(f"ACQUISITION_TOOLCHAIN_HTTPS_DOWNGRADE {url}->{final}")
        remaining = 128 * 1024 * 1024
        while True:
            chunk = response.read(min(1024 * 1024, remaining + 1))
            if not chunk:
                break
            remaining -= len(chunk)
            if remaining < 0:
                raise RuntimeError("ACQUISITION_TOOLCHAIN_ASSET_TOO_LARGE")
            fh.write(chunk)


def _asset_filename(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    name = Path(parsed.path).name
    if not name or name in {".", ".."}:
        raise RuntimeError(f"ACQUISITION_TOOLCHAIN_ASSET_FILENAME_INVALID {url}")
    return name


def _install_archive(name: str, archive: Path, dest: Path, *, lock: Path = DEFAULT_LOCK) -> None:
    tools = tool_map(lock)
    target = host_platform()
    tool = tools[name]
    asset = tool["platforms"][target]
    if archive.is_symlink() or not archive.is_file():
        raise RuntimeError(f"ACQUISITION_TOOLCHAIN_STAGED_ASSET_NOT_REGULAR {name}")
    actual = sha256_file(archive)
    if actual != str(asset["sha256"]):
        raise RuntimeError(f"ACQUISITION_TOOLCHAIN_DIGEST_MISMATCH {name} expected={asset['sha256']} actual={actual}")
    member_name = str(asset["archiveMember"])
    with tarfile.open(archive, "r:gz") as tf:
        members = [m for m in tf.getmembers() if m.name == member_name]
        if len(members) != 1:
            raise RuntimeError(f"ACQUISITION_TOOLCHAIN_ARCHIVE_MEMBER_INVALID {name}")
        member = members[0]
        if not member.isfile() or member.issym() or member.islnk():
            raise RuntimeError(f"ACQUISITION_TOOLCHAIN_ARCHIVE_MEMBER_UNSAFE {name}")
        src = tf.extractfile(member)
        if src is None:
            raise RuntimeError(f"ACQUISITION_TOOLCHAIN_ARCHIVE_MEMBER_UNREADABLE {name}")
        payload = src.read(64 * 1024 * 1024 + 1)
        if len(payload) > 64 * 1024 * 1024:
            raise RuntimeError(f"ACQUISITION_TOOLCHAIN_BINARY_TOO_LARGE {name}")
    out = dest / name
    temp_out = dest / ("." + name + ".tmp")
    temp_out.write_bytes(payload)
    temp_out.chmod(0o755)
    os.replace(temp_out, out)
    resolve_tool(name, tool_dir=dest, lock=lock)


def bootstrap(dest: Path, *, timeout: int = 120, lock: Path = DEFAULT_LOCK) -> None:
    tools = tool_map(lock)
    target = host_platform()
    dest.mkdir(parents=True, exist_ok=True)
    if dest.is_symlink():
        raise RuntimeError("ACQUISITION_TOOLCHAIN_DEST_SYMLINK_DENIED")
    with tempfile.TemporaryDirectory(prefix="4so-toolchain-") as td:
        temp = Path(td)
        for name in ("helm", "crane"):
            tool = tools[name]
            asset = tool["platforms"][target]
            archive = temp / f"{name}.tar.gz"
            _download(str(asset["url"]), archive, timeout)
            _install_archive(name, archive, dest, lock=lock)


def bootstrap_staged(stage: Path, dest: Path, *, lock: Path = DEFAULT_LOCK) -> None:
    """Install the exact locked toolchain from operator-staged archives.

    This path is intentionally network-free. It exists for restricted or
    disconnected build hosts where assets are downloaded on a separate host and
    transferred through an approved channel. The staged filenames are derived
    from the canonical lock URLs and every archive is SHA-256 verified before
    extraction, so staging cannot become an alternate version/source authority.
    """
    tools = tool_map(lock)
    target = host_platform()
    if stage.is_symlink() or not stage.is_dir():
        raise RuntimeError("ACQUISITION_TOOLCHAIN_STAGE_NOT_DIRECTORY")
    dest.mkdir(parents=True, exist_ok=True)
    if dest.is_symlink():
        raise RuntimeError("ACQUISITION_TOOLCHAIN_DEST_SYMLINK_DENIED")
    for name in ("helm", "crane"):
        asset = tools[name]["platforms"][target]
        archive = stage / _asset_filename(str(asset["url"]))
        _install_archive(name, archive, dest, lock=lock)


def self_test() -> int:
    tools = tool_map()
    assert tools["helm"]["version"] == "4.2.4"
    assert tools["crane"]["version"] == "0.22.1"
    assert host_platform() in {"linux-amd64", "linux-arm64"}
    for name, tool in tools.items():
        for asset in tool["platforms"].values():
            assert asset["url"].startswith("https://") and SHA256_RE.fullmatch(asset["sha256"])

    # Offline execution controls: exact pinned binaries are accepted, while a
    # mismatched binary in the explicitly selected tool directory fails closed.
    with tempfile.TemporaryDirectory(prefix="4so-toolchain-selftest-") as td:
        tool_dir = Path(td)
        fixtures = {"helm": "v4.2.4", "crane": "0.22.1"}
        for name, version in fixtures.items():
            binary = tool_dir / name
            binary.write_text(f"#!/bin/sh\nprintf '%s\\n' '{version}'\n")
            binary.chmod(0o755)
        resolved = require_toolchain(tool_dir=tool_dir)
        assert resolved["helm"][1] == "v4.2.4" and resolved["crane"][1] == "0.22.1"

        (tool_dir / "helm").write_text("#!/bin/sh\nprintf '%s\\n' 'v4.2.3'\n")
        (tool_dir / "helm").chmod(0o755)
        try:
            resolve_tool("helm", tool_dir=tool_dir)
        except RuntimeError as exc:
            assert "ACQUISITION_TOOLCHAIN_VERSION_MISMATCH" in str(exc)
        else:
            raise AssertionError("mismatched Helm version must fail closed")

    # Staged/offline bootstrap must use the exact filenames and digests in the
    # lock and must not need network access. Use a synthetic exact lock with
    # tiny shell-script archives so the self-test remains deterministic.
    with tempfile.TemporaryDirectory(prefix="4so-toolchain-staged-selftest-") as td:
        base = Path(td)
        stage = base / "stage"
        dest = base / "dest"
        stage.mkdir()
        synthetic = _load()
        synthetic = json.loads(json.dumps(synthetic))
        target = host_platform()
        fixtures = {"helm": ("linux-amd64/helm", "v4.2.4"), "crane": ("crane", "0.22.1")}
        for name, (member_name, version) in fixtures.items():
            asset = synthetic["spec"]["tools"][[x["name"] for x in synthetic["spec"]["tools"]].index(name)]["platforms"][target]
            archive_name = _asset_filename(str(asset["url"]))
            archive = stage / archive_name
            with tarfile.open(archive, "w:gz") as tf:
                payload = f"#!/bin/sh\nprintf '%s\\n' '{version}'\n".encode()
                info = tarfile.TarInfo(member_name)
                info.mode = 0o755
                info.size = len(payload)
                import io
                tf.addfile(info, io.BytesIO(payload))
            asset["sha256"] = sha256_file(archive)
        synthetic_lock = base / "lock.json"
        synthetic_lock.write_text(json.dumps(synthetic, indent=2, sort_keys=True) + "\n")
        bootstrap_staged(stage, dest, lock=synthetic_lock)
        resolved = require_toolchain(tool_dir=dest, lock=synthetic_lock)
        assert resolved["helm"][1] == "v4.2.4" and resolved["crane"][1] == "0.22.1"

        staged_helm = stage / _asset_filename(str(tool_map(synthetic_lock)["helm"]["platforms"][target]["url"]))
        staged_helm.write_bytes(staged_helm.read_bytes() + b"tamper")
        try:
            bootstrap_staged(stage, base / "tampered-dest", lock=synthetic_lock)
        except RuntimeError as exc:
            assert "ACQUISITION_TOOLCHAIN_DIGEST_MISMATCH helm" in str(exc)
        else:
            raise AssertionError("tampered staged acquisition tool asset must fail closed")

    print(f"UPSTREAM_ACQUISITION_TOOLCHAIN_SELF_TEST_PASS authority={AUTHORITY} tools=2 platform={host_platform()} exact-version-negative-control=pass staged-offline-bootstrap=pass staged-tamper-negative-control=pass")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Validate or bootstrap the pinned S1 acquisition toolchain")
    p.add_argument("--check", action="store_true")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--bootstrap", metavar="DIR", type=Path)
    p.add_argument("--bootstrap-staged", metavar="STAGE_DIR", type=Path, help="network-free bootstrap from exact lock-named archives in STAGE_DIR")
    p.add_argument("--dest", metavar="DIR", type=Path, help="destination for --bootstrap-staged")
    p.add_argument("--timeout", type=int, default=120)
    args = p.parse_args()
    if sum(bool(x) for x in (args.check, args.self_test, args.bootstrap, args.bootstrap_staged)) != 1:
        p.error("choose exactly one of --check, --self-test, --bootstrap, --bootstrap-staged")
    if bool(args.bootstrap_staged) != bool(args.dest):
        p.error("--bootstrap-staged requires --dest and --dest is only valid with --bootstrap-staged")
    try:
        if args.self_test:
            return self_test()
        if args.bootstrap:
            bootstrap(args.bootstrap.resolve(), timeout=args.timeout)
        if args.bootstrap_staged:
            bootstrap_staged(args.bootstrap_staged.resolve(), args.dest.resolve())
        tool_dir = args.bootstrap.resolve() if args.bootstrap else (args.dest.resolve() if args.bootstrap_staged else None)
        resolved = require_toolchain(tool_dir=tool_dir)
        print("UPSTREAM_ACQUISITION_TOOLCHAIN_PASS " + " ".join(f"{name}={version}" for name, (_, version) in sorted(resolved.items())))
        return 0
    except (RuntimeError, OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(f"UPSTREAM_ACQUISITION_TOOLCHAIN_BLOCKED {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
