#!/usr/bin/env python3
"""Deterministic, exact-SHA physical lab runner for 4SO Platform Factory.

AI is failure-only: it receives a compact normalized packet after a deterministic
stage fails. It cannot decide PASS, alter evidence, or promote Physical PASS.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import hashlib
import http.client
import json
import ipaddress
import os
import posixpath
import re
import shlex
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import tarfile
import time
import urllib.error
import urllib.request
import urllib.parse
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
GUIDE_PATH = ROOT / "internal" / "labmodel" / "certification-matrix.json"
DEFAULT_PACKET_BYTES = 8 * 1024
MAX_PACKET_BYTES = 16 * 1024
DEFAULT_OUTPUT_TOKENS = 800
MAX_OUTPUT_TOKENS = 1200
MAX_RUNTIME_JSON_BYTES = 16 * 1024 * 1024
_M03_REQUIRED_TOOLS = ("psql", "pg_dump", "pg_restore", "createdb", "dropdb")
MAX_RELEASE_ARCHIVE_FILES = 20000
MAX_RELEASE_UNPACKED_BYTES = 8 * 1024 * 1024 * 1024
EXACT_RELEASE_SNAPSHOT_AUTHORITY = "LAB_EXACT_RELEASE_SNAPSHOT_AUTHORITY_V2"
RUN_STATE_BINDING_AUTHORITY = "LAB_RUN_STATE_BINDING_AUTHORITY_V2"
SSH_CREDENTIAL_SNAPSHOT_AUTHORITY = "LAB_SSH_CREDENTIAL_SNAPSHOT_AUTHORITY_V2"
AI_RUN_POSTGRES_DURABILITY_AUTHORITY = "AI_RUN_POSTGRES_DURABILITY_RUNTIME_AUTHORITY_V1"
M03_EXACT_RELEASE_EVIDENCE_AUTHORITY = "LAB_M03_EXACT_RELEASE_EVIDENCE_AUTHORITY_V1"
LAB_CONTROL_PLANE_TRANSPORT_AUTHORITY = "LAB_CONTROL_PLANE_TRANSPORT_AUTHORITY_V1"
REMOTE_BOOTSTRAP_EXPECTED_BUNDLE_AUTHORITY = "REMOTE_BOOTSTRAP_EXPECTED_BUNDLE_AUTHORITY_V1"
EXACT_RELEASE_EXECUTION_AUTHORITY = "LAB_EXACT_RELEASE_EXECUTION_AUTHORITY_V1"
INSTALLER_ACCESS_TOKEN_FILE_AUTHORITY = "LAB_INSTALLER_ACCESS_TOKEN_FILE_AUTHORITY_V1"

_OCI_IMAGE_INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
_OCI_IMAGE_MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
_OCI_DESCRIPTOR_FIELDS = {"mediaType", "digest", "size", "urls", "annotations", "data", "artifactType", "platform"}
_OCI_PLATFORM_FIELDS = {"architecture", "os", "os.version", "os.features", "variant"}

_AI_SENSITIVE_KEY = re.compile(r"(?i)(password|passphrase|secret|token|api.?key|authorization|cookie|private.?key|client.?secret|credential)")
_AI_SECRET_PATTERNS = [
    re.compile(r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(?:password|passphrase|client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization)\s*[:=]\s*[^\s,;]+"),
]


def _redact_ai_value(value: Any) -> tuple[Any, int]:
    count = 0
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if _AI_SENSITIVE_KEY.search(str(key)) and not re.search(r"(?i)(digest|fingerprint|ref|certificate.?id)$", str(key)):
                out[key] = "[REDACTED]"
                count += 1
            else:
                out[key], nested = _redact_ai_value(item)
                count += nested
        return out, count
    if isinstance(value, list):
        out = []
        for item in value:
            clean, nested = _redact_ai_value(item)
            out.append(clean); count += nested
        return out, count
    if isinstance(value, str):
        clean = value
        for pattern in _AI_SECRET_PATTERNS:
            clean, n = pattern.subn("[REDACTED]", clean)
            count += n
        return clean, count
    return value, count


def _strict_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _strict_json_value(raw: str | bytes, *, label: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_strict_json_pairs)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError(f"{label} is invalid or ambiguous JSON: {exc}") from exc


def _load_runtime_json_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} cannot be inspected: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > MAX_RUNTIME_JSON_BYTES:
        raise RuntimeError(f"{label} must be a bounded regular non-symlink file")
    flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"{label} cannot be opened safely: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise RuntimeError(f"{label} changed while opening")
        with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
            raw = stream.read(MAX_RUNTIME_JSON_BYTES + 1)
        after = os.fstat(fd)
        if len(raw) > MAX_RUNTIME_JSON_BYTES or len(raw) != opened.st_size or not _same_open_file_state(opened, after):
            raise RuntimeError(f"{label} changed while reading or exceeds the runtime JSON bound")
    finally:
        os.close(fd)
    value = _strict_json_value(raw, label=label)
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return value


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return _load_runtime_json_object(path, label=f"JSON document {path}")
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc


def guide() -> dict[str, Any]:
    value = _load_json(GUIDE_PATH)
    if value.get("authority") != "LAB_CERTIFICATION_MATRIX_V2":
        raise SystemExit("canonical lab guide authority is invalid")
    return value


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_fd(fd: int) -> str:
    h = hashlib.sha256()
    with os.fdopen(os.dup(fd), "rb", closefd=True) as f:
        f.seek(0)
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _same_open_file_state(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        os.path.samestat(before, after)
        and after.st_size == before.st_size
        and after.st_mtime_ns == before.st_mtime_ns
        and after.st_ctime_ns == before.st_ctime_ns
    )


def _tail(value: str, limit: int = 12000) -> str:
    value = value.replace("\x00", "")
    return value if len(value) <= limit else value[-limit:]


def _fingerprint(stage: str, rc: int, output: str) -> str:
    normalized = re.sub(r"\b\d{4}-\d\d-\d\d[T ][0-9:.+Z-]+\b", "<time>", output)
    normalized = re.sub(r"\b[0-9a-f]{64}\b", "<sha256>", normalized.lower())
    return hashlib.sha256(f"{stage}\n{rc}\n{normalized}".encode()).hexdigest()[:24]


def _canonical_release_zip_path(raw: str) -> str:
    if (
        not isinstance(raw, str)
        or not raw
        or raw.strip() != raw
        or "\\" in raw
        or "\x00" in raw
        or raw.startswith("/")
        or raw.endswith("/")
        or posixpath.normpath(raw) != raw
        or any(part in ("", ".", "..") for part in raw.split("/"))
    ):
        raise SystemExit(f"non-canonical release ZIP path: {raw!r}")
    return raw


def _validated_release_members(zf: zipfile.ZipFile) -> tuple[str, list[zipfile.ZipInfo]]:
    infos = zf.infolist()
    if not infos or len(infos) > MAX_RELEASE_ARCHIVE_FILES:
        raise SystemExit("release artifact file count is empty or exceeds the canonical limit")
    seen: set[str] = set()
    roots: set[str] = set()
    total_unpacked = 0
    for info in infos:
        if info.is_dir():
            raise SystemExit(f"release artifact contains non-canonical directory entry: {info.filename!r}")
        name = _canonical_release_zip_path(info.filename)
        if name in seen:
            raise SystemExit(f"release artifact contains duplicate path: {name!r}")
        seen.add(name)
        if "/" not in name:
            raise SystemExit("release artifact files must all live beneath one canonical root")
        roots.add(name.split("/", 1)[0])
        if info.flag_bits & 0x1:
            raise SystemExit(f"release artifact contains encrypted entry: {name!r}")
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(unix_mode)
        if info.create_system != 3 or file_type not in (0, stat.S_IFREG):
            raise SystemExit(f"release artifact contains non-regular entry: {name!r}")
        if stat.S_IMODE(unix_mode) == 0:
            raise SystemExit(f"release artifact entry has no Unix permissions: {name!r}")
        total_unpacked += info.file_size
        if total_unpacked > MAX_RELEASE_UNPACKED_BYTES:
            raise SystemExit("release artifact unpacked size exceeds the canonical limit")
    if len(roots) != 1:
        raise SystemExit("release artifact must contain one canonical root")
    return next(iter(roots)), infos


def _release_identity(archive: Path) -> tuple[str, str, str]:
    try:
        source_info = archive.lstat()
    except OSError as exc:
        raise SystemExit(f"releaseArtifact cannot be inspected: {exc}") from exc
    if archive.is_symlink() or not stat.S_ISREG(source_info.st_mode) or source_info.st_size <= 0:
        raise SystemExit("releaseArtifact must be a non-empty regular non-symlink ZIP file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(archive, flags)
    except OSError as exc:
        raise SystemExit(f"release artifact identity cannot be opened safely: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size <= 0 or not os.path.samestat(source_info, opened):
            raise SystemExit("release artifact changed while opening identity")
        try:
            with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
                stream.seek(0)
                with zipfile.ZipFile(stream) as zf:
                    root, _ = _validated_release_members(zf)
                    version_raw = zf.read(root + "/VERSION")
                    release_name_raw = zf.read(root + "/RELEASE-NAME")
        except (KeyError, zipfile.BadZipFile, OSError) as exc:
            raise SystemExit(f"release artifact identity is unreadable: {exc}") from exc
        digest = _sha256_fd(fd)
        after = os.fstat(fd)
        if not _same_open_file_state(opened, after):
            raise SystemExit("release artifact changed while reading identity")
    finally:
        os.close(fd)
    try:
        version = version_raw.decode("utf-8", errors="strict").strip()
        release_name = release_name_raw.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise SystemExit("release artifact identity files must be UTF-8") from exc
    if version_raw != (version + "\n").encode("utf-8") or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit("release artifact VERSION is non-canonical")
    if release_name_raw != (release_name + "\n").encode("utf-8") or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", release_name):
        raise SystemExit("release artifact RELEASE-NAME is non-canonical")
    if root != f"4so-platform-factory-{version}-{release_name}":
        raise SystemExit("release artifact root does not match VERSION/RELEASE-NAME")
    return root, version, digest


def _snapshot_release_artifact(source: Path, target: Path) -> tuple[str, str, str]:
    """Copy one exact release byte stream into private run state and certify only that copy."""
    try:
        before = source.lstat()
    except OSError as exc:
        raise SystemExit(f"releaseArtifact cannot be inspected: {exc}") from exc
    if source.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise SystemExit("releaseArtifact must be a non-empty regular non-symlink ZIP file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(source, flags)
    except OSError as exc:
        raise SystemExit(f"releaseArtifact cannot be opened safely: {exc}") from exc
    target.parent.mkdir(parents=True, exist_ok=True)
    target.parent.chmod(0o700)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=target.name + ".tmp.", dir=target.parent)
    tmp = Path(tmp_name)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size <= 0 or not os.path.samestat(before, opened):
            raise SystemExit("releaseArtifact changed while opening")
        h = hashlib.sha256()
        written = 0
        os.fchmod(tmp_fd, 0o600)
        with os.fdopen(os.dup(fd), "rb", closefd=True) as src, os.fdopen(tmp_fd, "wb", closefd=False) as out:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
                out.write(chunk)
                written += len(chunk)
            out.flush()
            os.fsync(out.fileno())
        after = os.fstat(fd)
        if (
            not os.path.samestat(opened, after)
            or written != opened.st_size
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
        ):
            raise SystemExit("releaseArtifact changed while snapshotting")
        os.fchmod(tmp_fd, 0o400)
        os.close(tmp_fd)
        tmp_fd = -1
        os.replace(tmp, target)
        dir_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        os.close(fd)
        if tmp_fd >= 0:
            os.close(tmp_fd)
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
    root, version, digest = _release_identity(target)
    if digest != h.hexdigest():
        raise SystemExit("releaseArtifact snapshot digest changed after atomic publication")
    return root, version, digest


def _spec_with_release_snapshot(spec: dict[str, Any], target: Path) -> tuple[dict[str, Any], tuple[str, str, str]]:
    body = spec.get("spec")
    if not isinstance(body, dict):
        raise SystemExit("spec is required")
    source = Path(str(body.get("releaseArtifact", ""))).expanduser().absolute()
    identity = _snapshot_release_artifact(source, target)
    cloned = json.loads(json.dumps(spec))
    cloned["spec"]["releaseArtifact"] = str(target.resolve())
    return cloned, identity


def _spec_with_persistent_release_snapshot(spec: dict[str, Any], target: Path) -> tuple[dict[str, Any], tuple[str, str, str]]:
    """Bind a run state directory to one exact release snapshot and never replace it."""
    try:
        target.lstat()
        target_exists = True
    except FileNotFoundError:
        target_exists = False
    if not target_exists:
        return _spec_with_release_snapshot(spec, target)

    existing = _release_identity(target)
    with tempfile.TemporaryDirectory(prefix=".release-candidate-", dir=target.parent) as td:
        candidate = Path(td) / "release-artifact.zip"
        _, candidate_identity = _spec_with_release_snapshot(spec, candidate)
    if candidate_identity != existing:
        raise SystemExit(
            "lab state directory is already bound to a different exact release artifact; use a new --state-dir"
        )
    cloned = json.loads(json.dumps(spec))
    cloned["spec"]["releaseArtifact"] = str(target.resolve())
    return cloned, existing


@contextlib.contextmanager
def _exclusive_run_state(state: Path):
    """Fence one mutating Lab execution per state directory."""
    state.mkdir(parents=True, exist_ok=True)
    state.chmod(0o700)
    lock_path = state / ".lab-run.lock"
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise SystemExit(f"lab run-state lock cannot be opened safely: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit("lab run-state lock must be a regular file")
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SystemExit("another Lab execution is already active for this --state-dir") from exc
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _snapshot_ssh_file(source: Path, target: Path, *, label: str, private: bool) -> dict[str, Any]:
    """Snapshot one SSH trust input as exact bytes without following a source symlink."""
    try:
        before = source.lstat()
    except OSError as exc:
        raise SystemExit(f"{label} cannot be inspected: {exc}") from exc
    if source.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise SystemExit(f"{label} must be a non-empty regular non-symlink file")
    if private and before.st_mode & 0o077:
        raise SystemExit(f"{label} permissions must not allow group/other access")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(source, flags)
    except OSError as exc:
        raise SystemExit(f"{label} cannot be opened safely: {exc}") from exc
    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    target.parent.chmod(0o700)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=target.name + ".tmp.", dir=target.parent)
    tmp = Path(tmp_name)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size <= 0 or not os.path.samestat(before, opened):
            raise SystemExit(f"{label} changed while opening")
        h = hashlib.sha256()
        written = 0
        os.fchmod(tmp_fd, 0o600)
        with os.fdopen(os.dup(fd), "rb", closefd=True) as src, os.fdopen(tmp_fd, "wb", closefd=False) as out:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
                out.write(chunk)
                written += len(chunk)
            out.flush()
            os.fsync(out.fileno())
        after = os.fstat(fd)
        if (
            not os.path.samestat(opened, after)
            or written != opened.st_size
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
        ):
            raise SystemExit(f"{label} changed while snapshotting")
        os.fchmod(tmp_fd, 0o400)
        os.close(tmp_fd)
        tmp_fd = -1
        os.replace(tmp, target)
        dir_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        os.close(fd)
        if tmp_fd >= 0:
            os.close(tmp_fd)
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
    target_info = target.lstat()
    if target.is_symlink() or not stat.S_ISREG(target_info.st_mode) or target_info.st_mode & 0o222:
        raise SystemExit(f"{label} private snapshot is not immutable")
    digest = _sha256(target)
    if digest != h.hexdigest() or target_info.st_size != written:
        raise SystemExit(f"{label} private snapshot digest changed after atomic publication")
    return {"sha256": "sha256:" + digest, "size": written}


def _spec_with_persistent_ssh_snapshots(spec: dict[str, Any], state: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Bind one run state to exact SSH key and host-trust bytes across retries."""
    body = spec.get("spec")
    if not isinstance(body, dict) or not isinstance(body.get("ssh"), dict):
        raise SystemExit("spec.ssh is required")
    ssh = body["ssh"]
    source_identity = Path(str(ssh.get("identityFile", ""))).expanduser().absolute()
    source_known = Path(str(ssh.get("knownHostsFile", ""))).expanduser().absolute()
    ssh_state = state / "ssh-authority"
    targets = {
        "identityFile": (source_identity, ssh_state / "identity", True, "ssh.identityFile"),
        "knownHostsFile": (source_known, ssh_state / "known_hosts", False, "ssh.knownHostsFile"),
    }
    identities: dict[str, dict[str, Any]] = {}
    for key, (source, target, private, label) in targets.items():
        try:
            existing_info = target.lstat()
        except FileNotFoundError:
            existing_info = None
        if existing_info is None:
            identities[key] = _snapshot_ssh_file(source, target, label=label, private=private)
        else:
            if target.is_symlink() or not stat.S_ISREG(existing_info.st_mode) or existing_info.st_mode & 0o222:
                raise SystemExit(f"{label} persistent snapshot must be an immutable regular non-symlink file")
            candidate_dir = Path(tempfile.mkdtemp(prefix=".ssh-candidate-", dir=state))
            try:
                candidate = candidate_dir / target.name
                candidate_identity = _snapshot_ssh_file(source, candidate, label=label, private=private)
                existing_identity = {"sha256": "sha256:" + _sha256(target), "size": target.stat().st_size}
                if candidate_identity != existing_identity:
                    raise SystemExit(
                        "lab state directory is already bound to different SSH credential/host-trust bytes; use a new --state-dir"
                    )
                identities[key] = existing_identity
            finally:
                shutil.rmtree(candidate_dir, ignore_errors=True)
    cloned = json.loads(json.dumps(spec))
    cloned["spec"]["ssh"]["identityFile"] = str((ssh_state / "identity").resolve())
    cloned["spec"]["ssh"]["knownHostsFile"] = str((ssh_state / "known_hosts").resolve())
    binding = {
        "authority": SSH_CREDENTIAL_SNAPSHOT_AUTHORITY,
        "schemaVersion": 1,
        "identityFile": identities["identityFile"],
        "knownHostsFile": identities["knownHostsFile"],
    }
    raw = json.dumps(binding, sort_keys=True, separators=(",", ":")).encode("utf-8")
    binding["bindingDigest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    return cloned, binding


def _execution_spec_digest(spec: dict[str, Any], artifact_sha: str) -> str:
    body = spec["spec"]
    ssh = body.get("ssh") or {}
    canonical = {
        "metadata": spec.get("metadata") or {},
        "releaseArtifactDigest": "sha256:" + artifact_sha,
        "serverInventory": _canonical_server_inventory(body),
        "ssh": {
            "user": str(ssh.get("user", "root")).strip(),
            "identityFile": str(Path(str(ssh.get("identityFile", ""))).expanduser().resolve()),
            "knownHostsFile": str(Path(str(ssh.get("knownHostsFile", ""))).expanduser().resolve()),
        },
        "management": body.get("management") or {},
        "bundleDirectory": str(Path(str(body["bundleDirectory"])).expanduser().resolve()) if body.get("bundleDirectory") else "automatic",
    }
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _run_state_binding(spec: dict[str, Any], preflight: dict[str, Any], artifact_sha: str, ssh_binding: dict[str, Any] | None = None) -> dict[str, Any]:
    body = spec["spec"]
    bundle_binding = preflight.get("bundleBinding")
    if not isinstance(bundle_binding, dict):
        raise SystemExit("successful Lab preflight did not return immutable bundle binding authority")
    base = {
        "authority": RUN_STATE_BINDING_AUTHORITY,
        "schemaVersion": 2,
        "releaseArtifactDigest": "sha256:" + artifact_sha,
        "serverInventoryDigest": _server_inventory_digest(body),
        "executionSpecDigest": _execution_spec_digest(spec, artifact_sha),
        "sshCredentialBinding": ssh_binding or {"authority": "legacy-unbound"},
        "bundleBinding": bundle_binding,
    }
    raw = json.dumps(base, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {**base, "bindingDigest": "sha256:" + hashlib.sha256(raw).hexdigest()}


def _bind_or_verify_run_state(state: Path, binding: dict[str, Any]) -> str:
    path = state / "run-authority.json"
    try:
        existing_info = path.lstat()
    except FileNotFoundError:
        existing_info = None
    if existing_info is not None:
        if path.is_symlink() or not stat.S_ISREG(existing_info.st_mode):
            raise SystemExit("lab run-state authority must be a regular non-symlink file")
        existing = _load_json(path)
        if existing != binding:
            raise SystemExit(
                "lab state directory is already bound to different release/topology/spec/ssh/bundle authority; use a new --state-dir"
            )
        return "reused"
    _write_json(path, binding, mode=0o400)
    return "created"


def _safe_extract(archive: Path, dest: Path, *, expected_sha256: str | None = None) -> Path:
    """Extract only the exact bytes opened and digest-bound for this operation."""
    try:
        before = archive.lstat()
    except OSError as exc:
        raise SystemExit(f"release artifact cannot be inspected for extraction: {exc}") from exc
    if archive.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise SystemExit("release artifact extraction source must be a non-empty regular non-symlink file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(archive, flags)
    except OSError as exc:
        raise SystemExit(f"release artifact cannot be opened safely for extraction: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size <= 0 or not os.path.samestat(before, opened):
            raise SystemExit("release artifact changed while opening for extraction")
        digest_before = _sha256_fd(fd)
        after_digest = os.fstat(fd)
        if not _same_open_file_state(opened, after_digest):
            raise SystemExit("release artifact changed while hashing for extraction")
        if expected_sha256 is not None and digest_before != expected_sha256:
            raise SystemExit("release artifact execution digest does not match exact release authority")
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True, mode=0o700)
        try:
            with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
                stream.seek(0)
                with zipfile.ZipFile(stream) as zf:
                    root, infos = _validated_release_members(zf)
                    for info in infos:
                        name = _canonical_release_zip_path(info.filename)
                        mode = stat.S_IMODE((info.external_attr >> 16) & 0xFFFF)
                        target = dest / name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(info) as src, target.open("wb") as out:
                            shutil.copyfileobj(src, out)
                        target.chmod(mode)
        except (zipfile.BadZipFile, OSError) as exc:
            raise SystemExit(f"release artifact extraction failed: {exc}") from exc
        after_extract = os.fstat(fd)
        if not _same_open_file_state(opened, after_extract):
            raise SystemExit("release artifact changed while extracting")
        digest_after = _sha256_fd(fd)
        final = os.fstat(fd)
        if not _same_open_file_state(opened, final) or digest_after != digest_before:
            raise SystemExit("release artifact changed while verifying extracted execution bytes")
    finally:
        os.close(fd)
    return dest / root



BUNDLE_ACQUISITION_AUTHORITY = "LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8"
BUNDLE_ACQUISITION_EXACT_RELEASE_AUTHORITY = "LAB_APPLIANCE_BUNDLE_ACQUISITION_EXACT_RELEASE_BINDING_V1"
BUNDLE_ACQUISITION_LOCK_REL = "lab/appliance-bundle-acquisition-lock.json"
MANAGEMENT_WORKLOAD_IMAGE_PLAN_AUTHORITY = "MANAGEMENT_WORKLOAD_IMAGE_BUILD_PLAN_V5"
MANAGEMENT_WORKLOAD_PRODUCT_IMAGE_CERTIFICATION_AUTHORITY = "MANAGEMENT_WORKLOAD_PRODUCT_IMAGE_CERTIFICATION_V1"
MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY = "MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_V1"
MANAGEMENT_WORKLOAD_IMAGE_PLAN_REL = "lab/management-workload-image-build-plan.json"
MANAGEMENT_WORKLOAD_OCI_ASSEMBLY_AUTHORITY = "MANAGEMENT_WORKLOAD_OCI_ASSEMBLY_AUTHORITY_V1"
MAX_MANAGEMENT_WORKLOAD_IMAGE_PLAN_BYTES = 256 * 1024
MAX_BUNDLE_ACQUISITION_LOCK_BYTES = 1024 * 1024
BUNDLE_SOURCE_LOCKS_BLOCKER = "LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING"
MAX_BUNDLE_INPUT_PACK_BYTES = 32 * 1024 * 1024 * 1024
MAX_BUNDLE_INPUT_PACK_UNPACKED_BYTES = 32 * 1024 * 1024 * 1024
MAX_BUNDLE_INPUT_PACK_FILES = 4096
MAX_MANAGEMENT_WORKLOAD_OCI_ENTRIES = 100000
_ZERO_DIGEST = "sha256:" + ("0" * 64)
_BUNDLE_REQUIRED_SOURCE_AUTHORITIES = frozenset({
    "rke2-installer-and-offline-artifacts",
    "management-workload-oci-archive",
    "argocd-install-manifest",
    "cloudnative-pg-install-manifest",
    "replicated-storage-install-manifest",
})
_BUNDLE_DERIVED_AUTHORITIES = frozenset({"digest-pinned-core-workload-images"})


def _safe_relative_path(value: str, *, label: str) -> str:
    raw = str(value)
    if raw != raw.strip() or "\\" in raw or "\x00" in raw:
        raise ValueError(f"{label} must be a canonical relative path")
    if not raw or raw.startswith("/") or any(part in ("", ".", "..") for part in raw.split("/")):
        raise ValueError(f"{label} must be a canonical relative path")
    return raw


def _parse_public_https_url(raw_url: str, *, label: str, allow_query: bool = False) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(raw_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or (parsed.query and not allow_query)
    ):
        suffix = "" if allow_query else "/query"
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label} must be public HTTPS without credentials{suffix}/fragment")
    host = parsed.hostname.rstrip(".")
    if not host or host.lower() == "localhost" or host.lower().endswith(".localhost"):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label} must not target localhost")
    try:
        literal = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label} must not target a non-public address")
    return parsed


def _resolve_public_https_addresses(parsed: urllib.parse.SplitResult, *, label: str) -> tuple[tuple[Any, ...], ...]:
    host = parsed.hostname.rstrip(".")
    try:
        infos = socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label} host resolution failed: {exc}") from exc
    if not infos:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label} resolved to no addresses")
    admitted: list[tuple[Any, ...]] = []
    for info in infos:
        address = str(info[4][0]).split("%", 1)[0]
        try:
            resolved = ipaddress.ip_address(address)
        except ValueError as exc:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label} resolved to an invalid address") from exc
        if not resolved.is_global:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label} resolves to a non-public address: {resolved}")
        admitted.append(tuple(info))
    return tuple(admitted)


def _validate_public_https_url(raw_url: str, *, label: str, allow_query: bool = False, resolve: bool = False) -> str:
    parsed = _parse_public_https_url(raw_url, label=label, allow_query=allow_query)
    if resolve:
        _resolve_public_https_addresses(parsed, label=label)
    return raw_url

def _validate_public_https_urls(urls: Any, *, label: str) -> list[str]:
    if not isinstance(urls, list) or not (1 <= len(urls) <= 4) or any(not isinstance(url, str) for url in urls):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label} requires 1-4 HTTPS urls")
    if len(set(urls)) != len(urls):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label} urls must not contain duplicates")
    for index, raw_url in enumerate(urls):
        _validate_public_https_url(raw_url, label=f"{label}[{index}]")
    return urls


def _pinned_socket_timeout(value: Any) -> Any:
    """Resolve an http.client timeout into a value a raw socket accepts.

    ``http.client`` passes the ``socket._GLOBAL_DEFAULT_TIMEOUT`` sentinel whenever
    the caller supplied no explicit timeout. A pinned connection dials the
    admitted address itself, so it must apply the same resolution rule as
    ``socket.create_connection`` instead of handing the sentinel to ``settimeout``.
    """
    if value is None or value is socket._GLOBAL_DEFAULT_TIMEOUT:
        return socket.getdefaulttimeout()
    return value


def _tls_server_hostname(host: str) -> str:
    """Return the SNI and certificate-verification name for a pinned connection host.

    A trailing dot is a legal DNS spelling in a URL authority but is not a valid
    TLS server name; verified public sources are spelled without it so that
    certificate hostname checking cannot be broken by an equivalent URL.
    """
    return host.rstrip(".") or host


def _pinned_socket(
    infos: tuple[tuple[Any, ...], ...],
    *,
    timeout: Any,
    source_address: Any = None,
    context: Any = None,
    server_hostname: str = "",
    nodelay: bool = False,
    failure_label: str = "any admitted address",
) -> socket.socket:
    """Open one socket to the first admitted address, optionally wrapped in TLS.

    Validation and dialing share a single resolved address set, so a rebinding DNS
    answer can never be reached. Every failure path closes its own socket, so a TLS
    handshake or parameter failure cannot leak a descriptor out of the Lab runner.
    """
    last_error: OSError | None = None
    for family, socktype, proto, _canonname, sockaddr in infos:
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(_pinned_socket_timeout(timeout))
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            if nodelay:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
            if context is not None:
                return context.wrap_socket(sock, server_hostname=server_hostname)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
        except BaseException:
            sock.close()
            raise
    raise OSError(f"unable to connect to {failure_label}: {last_error}")


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that connects only to addresses admitted by one DNS lookup."""

    def __init__(self, host: str, *, pinned_infos: tuple[tuple[Any, ...], ...], context: Any = None, **kwargs: Any):
        check_hostname = kwargs.pop("check_hostname", None)
        if context is None:
            super().__init__(host, check_hostname=check_hostname, **kwargs)
        else:
            # An acquisition context is the exact TLS policy the caller configured,
            # so it is kept verbatim. HTTPSConnection.__init__ would clone the
            # context and probe its attributes, which silently rewrites that policy
            # for a pinned connection and refuses a purpose-built context object
            # outright. The inherited HTTPConnection.connect() stays unreachable:
            # connect() below dials the admitted address set itself.
            http.client.HTTPConnection.__init__(self, host, **kwargs)
            self._context = context
            if check_hostname is not None:
                self._context.check_hostname = check_hostname
            if getattr(self._context, "check_hostname", False) and getattr(self._context, "verify_mode", ssl.CERT_REQUIRED) == ssl.CERT_NONE:
                raise ValueError("check_hostname needs a SSL context with either CERT_OPTIONAL or CERT_REQUIRED")
        self._pinned_infos = pinned_infos

    def connect(self) -> None:
        if self._tunnel_host:
            raise OSError("HTTP proxy tunnels are not permitted for automatic public-source acquisition")
        self.sock = _pinned_socket(
            self._pinned_infos,
            timeout=self.timeout,
            source_address=self.source_address,
            context=self._context,
            server_hostname=_tls_server_hostname(self.host),
            nodelay=True,
            failure_label="any admitted public HTTPS address",
        )


class _PinnedPublicHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        parsed = _parse_public_https_url(req.get_full_url(), label="acquisition request", allow_query=True)
        pinned_infos = _resolve_public_https_addresses(parsed, label="acquisition request")
        expected_host = parsed.hostname.rstrip(".")
        expected_port = parsed.port or 443

        def connection_factory(host: str, **kwargs: Any) -> _PinnedHTTPSConnection:
            conn = _PinnedHTTPSConnection(host, pinned_infos=pinned_infos, **kwargs)
            if conn.host.rstrip(".") != expected_host or conn.port != expected_port:
                raise OSError("automatic public-source acquisition cannot traverse an implicit proxy")
            return conn

        return self.do_open(connection_factory, req, context=self._context)

    https_request = urllib.request.AbstractHTTPHandler.do_request_


class _PublicHTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_public_https_url(newurl, label="acquisition redirect", allow_query=True, resolve=True)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

class _DeniedControlPlaneRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Lab control-plane redirects are denied", headers, fp)


def _control_plane_address_blocked(address: ipaddress._BaseAddress) -> bool:
    if address.is_loopback:
        return False
    if address.is_link_local or address.is_multicast or address.is_unspecified:
        return True
    if isinstance(address, ipaddress.IPv4Address) and int(str(address).split(".")[0]) == 0:
        return True
    return False


def _parse_control_plane_url(raw_url: str, *, label: str) -> urllib.parse.SplitResult:
    if not isinstance(raw_url, str) or raw_url != raw_url.strip() or not raw_url:
        raise RuntimeError(f"{label} must be a canonical absolute URL")
    parsed = urllib.parse.urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError(f"{label} must use http or https with a host")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise RuntimeError(f"{label} must not contain URL credentials or a fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError(f"{label} has an invalid port") from exc
    if port is not None and not (1 <= port <= 65535):
        raise RuntimeError(f"{label} has an invalid port")
    return parsed


def _resolve_control_plane_addresses(parsed: urllib.parse.SplitResult, *, label: str) -> tuple[tuple[Any, ...], ...]:
    host = parsed.hostname.rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        family = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
        infos = ((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (str(literal), port)),)
    else:
        try:
            infos = tuple(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except socket.gaierror as exc:
            raise RuntimeError(f"{label} DNS resolution failed: {exc}") from exc
        if not infos:
            raise RuntimeError(f"{label} resolved to no addresses")
    admitted: list[tuple[Any, ...]] = []
    seen: set[tuple[Any, ...]] = set()
    for info in infos:
        try:
            parsed_address = ipaddress.ip_address(info[4][0])
            address = parsed_address.ipv4_mapped if isinstance(parsed_address, ipaddress.IPv6Address) and parsed_address.ipv4_mapped is not None else parsed_address
        except ValueError as exc:
            raise RuntimeError(f"{label} resolved to an invalid address") from exc
        if _control_plane_address_blocked(address):
            raise RuntimeError(f"{label} resolves to an unsafe address: {address}")
        if parsed.scheme == "http" and not address.is_loopback:
            raise RuntimeError(f"{label} may use plaintext HTTP only on loopback")
        key = (info[0], info[1], info[2], info[4])
        if key not in seen:
            seen.add(key)
            admitted.append(tuple(info))
    return tuple(admitted)


class _PinnedControlPlaneHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, *, pinned_infos: tuple[tuple[Any, ...], ...], **kwargs: Any):
        super().__init__(host, **kwargs)
        self._pinned_infos = pinned_infos

    def connect(self) -> None:
        self.sock = _pinned_socket(
            self._pinned_infos,
            timeout=self.timeout,
            source_address=self.source_address,
            failure_label="admitted Lab control-plane address",
        )


class _PinnedControlPlaneHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, *, pinned_infos: tuple[tuple[Any, ...], ...], context: ssl.SSLContext, **kwargs: Any):
        # The Lab control-plane context carries the exact minimum-TLS policy, so it
        # is used verbatim rather than through the stdlib copy-on-supply behaviour.
        kwargs.pop("check_hostname", None)
        http.client.HTTPConnection.__init__(self, host, **kwargs)
        self._context = context
        self._pinned_infos = pinned_infos

    def connect(self) -> None:
        self.sock = _pinned_socket(
            self._pinned_infos,
            timeout=self.timeout,
            source_address=self.source_address,
            context=self._context,
            server_hostname=_tls_server_hostname(self.host),
            failure_label="admitted Lab control-plane address",
        )


class _PinnedControlPlaneHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        parsed = _parse_control_plane_url(req.get_full_url(), label="Lab control-plane request")
        if parsed.scheme != "http":
            raise RuntimeError("Lab HTTP handler received a non-HTTP request")
        pinned_infos = _resolve_control_plane_addresses(parsed, label="Lab control-plane request")
        expected_host = parsed.hostname.rstrip(".")
        expected_port = parsed.port or 80

        def connection_factory(host: str, **kwargs: Any) -> _PinnedControlPlaneHTTPConnection:
            conn = _PinnedControlPlaneHTTPConnection(host, pinned_infos=pinned_infos, **kwargs)
            if conn.host.rstrip(".") != expected_host or conn.port != expected_port:
                raise OSError("Lab control-plane traffic cannot traverse an implicit proxy")
            return conn

        return self.do_open(connection_factory, req)


class _PinnedControlPlaneHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        super().__init__(context=context)

    def https_open(self, req):
        parsed = _parse_control_plane_url(req.get_full_url(), label="Lab control-plane request")
        if parsed.scheme != "https":
            raise RuntimeError("Lab HTTPS handler received a non-HTTPS request")
        pinned_infos = _resolve_control_plane_addresses(parsed, label="Lab control-plane request")
        expected_host = parsed.hostname.rstrip(".")
        expected_port = parsed.port or 443

        def connection_factory(host: str, **kwargs: Any) -> _PinnedControlPlaneHTTPSConnection:
            kwargs.pop("context", None)
            conn = _PinnedControlPlaneHTTPSConnection(host, pinned_infos=pinned_infos, context=self._context, **kwargs)
            if conn.host.rstrip(".") != expected_host or conn.port != expected_port:
                raise OSError("Lab control-plane traffic cannot traverse an implicit proxy")
            return conn

        return self.do_open(connection_factory, req, context=self._context)

    https_request = urllib.request.AbstractHTTPHandler.do_request_


def _build_control_plane_opener() -> urllib.request.OpenerDirector:
    # Bearer-authenticated M00-M03 traffic is an explicit trust boundary. Never
    # inherit HTTP(S)_PROXY, never follow redirects, and resolve/dial through the
    # pinned handlers above so validation and connection use one address set.
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _DeniedControlPlaneRedirectHandler(),
        _PinnedControlPlaneHTTPHandler(),
        _PinnedControlPlaneHTTPSHandler(),
    )


_CONTROL_PLANE_OPENER = _build_control_plane_opener()


def _control_plane_open(req: urllib.request.Request, *, timeout: int):
    return _CONTROL_PLANE_OPENER.open(req, timeout=timeout)


def _validate_locked_artifact(artifact: Any, *, label: str) -> dict[str, Any]:
    allowed = {"name", "stagingPath", "urls", "sha256", "sizeBytes"}
    if not isinstance(artifact, dict) or set(artifact) != allowed:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label} has invalid fields")
    if not isinstance(artifact.get("name"), str) or not artifact["name"].strip() or "/" in artifact["name"] or "\\" in artifact["name"]:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label}.name must be a basename")
    _safe_relative_path(str(artifact.get("stagingPath", "")), label=f"{label}.stagingPath")
    _validate_public_https_urls(artifact.get("urls"), label=label)
    if not re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256", ""))):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label}.sha256 must be a lowercase hex digest")
    size = artifact.get("sizeBytes")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or size > MAX_BUNDLE_INPUT_PACK_BYTES:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label}.sizeBytes is invalid")
    return artifact


def _validate_pending_artifact(artifact: Any, *, label: str) -> dict[str, Any]:
    allowed = {"name", "stagingPath", "reason", "sourceRef", "contentAddress"}
    if not isinstance(artifact, dict) or set(artifact) != allowed:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label} has invalid fields")
    for key in ("name", "stagingPath", "reason", "sourceRef", "contentAddress"):
        if not isinstance(artifact.get(key), str) or not artifact[key].strip():
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label}.{key} is required")
    if "/" in artifact["name"] or "\\" in artifact["name"]:
        # A repository path is allowed for pending source files, but traversal is not.
        _safe_relative_path(artifact["name"], label=f"{label}.name")
    _safe_relative_path(artifact["stagingPath"], label=f"{label}.stagingPath")
    _validate_public_https_url(artifact["sourceRef"], label=f"{label}.sourceRef")
    if not re.fullmatch(r"git-sha1:[0-9a-f]{40}", artifact["contentAddress"]):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label}.contentAddress must be a git-sha1 content address")
    return artifact


def _validate_source_authority(item: Any, *, label: str, partial: bool) -> str:
    required = {"id", "kind", "provider", "version", "scope", "artifacts"}
    if partial:
        required.add("pendingArtifacts")
    if not isinstance(item, dict) or set(item) != required:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label} has invalid fields")
    authority_id = str(item.get("id", "")).strip()
    if not authority_id or authority_id not in _BUNDLE_REQUIRED_SOURCE_AUTHORITIES:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label}.id is not a recognized source authority")
    for key in ("kind", "provider", "version", "scope"):
        if not isinstance(item.get(key), str) or not str(item[key]).strip():
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label}.{key} is required")
    if item["kind"] not in {"kubernetes-manifest", "release-artifact", "release-artifact-set", "image-inventory", "oci-archive"}:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label}.kind is invalid")
    artifacts = item.get("artifacts")
    if not isinstance(artifacts, list) or (not partial and not artifacts):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label}.artifacts must be a non-empty array for resolved authorities")
    if len(artifacts) > 16:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label}.artifacts exceeds the canonical limit")
    artifact_names: list[str] = []
    for index, artifact in enumerate(artifacts):
        _validate_locked_artifact(artifact, label=f"{label}.artifacts[{index}]")
        artifact_names.append(artifact["name"])
    if len(set(artifact_names)) != len(artifact_names):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label}.artifacts names must not contain duplicates")
    if partial:
        pending = item.get("pendingArtifacts")
        if not isinstance(pending, list) or not pending or len(pending) > 16:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label}.pendingArtifacts must be a non-empty bounded array")
        pending_names: list[str] = []
        for index, artifact in enumerate(pending):
            _validate_pending_artifact(artifact, label=f"{label}.pendingArtifacts[{index}]")
            pending_names.append(artifact["name"])
        if len(set(pending_names)) != len(pending_names):
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label}.pendingArtifacts names must not contain duplicates")
        if set(artifact_names) & set(pending_names):
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label} cannot lock and pend the same artifact name")
    return authority_id


def _parse_bundle_acquisition_lock(raw: bytes, version: str) -> tuple[dict[str, Any], str]:
    if not raw or len(raw) > MAX_BUNDLE_ACQUISITION_LOCK_BYTES:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: acquisition lock byte size is invalid")
    try:
        lock = _strict_json_value(raw, label="acquisition lock")
    except RuntimeError as exc:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {exc}") from exc
    if not isinstance(lock, dict):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: acquisition lock must be an object")
    allowed = {"authority", "schemaVersion", "releaseVersion", "status", "inputPack", "resolvedAuthorities", "partialAuthorities", "missingAuthorities", "derivedAuthorities"}
    extras = sorted(set(lock) - allowed)
    if extras:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: acquisition lock has unknown fields: {extras}")
    if lock.get("authority") != BUNDLE_ACQUISITION_AUTHORITY or lock.get("schemaVersion") != 8:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: acquisition lock authority/schema is invalid")
    if str(lock.get("releaseVersion", "")).strip() != version:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: acquisition lock releaseVersion does not match exact release")
    status = str(lock.get("status", "")).strip()
    if status not in {"ready", "incomplete"}:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: acquisition lock status must be ready or incomplete")
    derived = lock.get("derivedAuthorities", [])
    if derived != sorted(_BUNDLE_DERIVED_AUTHORITIES):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: derivedAuthorities must contain exactly the canonical derived authority set")
    missing = lock.get("missingAuthorities", [])
    if not isinstance(missing, list) or any(not isinstance(item, str) or not item.strip() for item in missing):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: missingAuthorities must be an array of non-empty strings")
    missing = [item.strip() for item in missing]
    if len(set(missing)) != len(missing):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: missingAuthorities must not contain duplicates")
    if any(item not in _BUNDLE_REQUIRED_SOURCE_AUTHORITIES for item in missing):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: missingAuthorities contains an unrecognized source authority")

    resolved = lock.get("resolvedAuthorities", [])
    partial = lock.get("partialAuthorities", [])
    if not isinstance(resolved, list) or not isinstance(partial, list):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: resolvedAuthorities and partialAuthorities must be arrays")
    resolved_ids = [_validate_source_authority(item, label=f"resolvedAuthorities[{index}]", partial=False) for index, item in enumerate(resolved)]
    partial_ids = [_validate_source_authority(item, label=f"partialAuthorities[{index}]", partial=True) for index, item in enumerate(partial)]
    for label, ids in (("resolvedAuthorities", resolved_ids), ("partialAuthorities", partial_ids)):
        if len(set(ids)) != len(ids):
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {label} ids must not contain duplicates")
    partitions = [set(resolved_ids), set(partial_ids), set(missing)]
    if any(partitions[i] & partitions[j] for i in range(3) for j in range(i + 1, 3)):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: an authority cannot appear in more than one resolved/partial/missing partition")
    if set().union(*partitions) != _BUNDLE_REQUIRED_SOURCE_AUTHORITIES:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: resolvedAuthorities + partialAuthorities + missingAuthorities must cover the complete canonical source-authority set")

    staging_paths: list[str] = []
    for authority in [*resolved, *partial]:
        for artifact in authority.get("artifacts", []):
            staging_paths.append(_safe_relative_path(artifact["stagingPath"], label=f"{authority['id']}.artifacts.stagingPath"))
        for artifact in authority.get("pendingArtifacts", []):
            staging_paths.append(_safe_relative_path(artifact["stagingPath"], label=f"{authority['id']}.pendingArtifacts.stagingPath"))
    if len(staging_paths) != len(set(staging_paths)):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: source-authority stagingPath values must be globally unique")

    pack = lock.get("inputPack")
    if status == "incomplete":
        if not partial_ids and not missing:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: incomplete acquisition lock must enumerate partial or missing authorities")
        if pack is not None:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: incomplete acquisition lock must not advertise an inputPack")
    else:
        if partial_ids or missing or len(resolved_ids) != len(_BUNDLE_REQUIRED_SOURCE_AUTHORITIES):
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: ready acquisition lock requires every canonical source authority to be fully resolved")
        if not isinstance(pack, dict):
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: ready acquisition lock requires inputPack")
        pack_allowed = {"urls", "sha256", "sizeBytes", "format", "buildSpecPath", "stagingDirectory"}
        pack_extras = sorted(set(pack) - pack_allowed)
        if pack_extras:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: inputPack has unknown fields: {pack_extras}")
        _validate_public_https_urls(pack.get("urls"), label="ready inputPack")
        if not re.fullmatch(r"[0-9a-f]{64}", str(pack.get("sha256", ""))):
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: inputPack sha256 must be a lowercase hex digest")
        size = pack.get("sizeBytes")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or size > MAX_BUNDLE_INPUT_PACK_BYTES:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: inputPack sizeBytes is invalid")
        if pack.get("format") != "zip":
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: only deterministic ZIP input packs are supported")
        _safe_relative_path(str(pack.get("buildSpecPath", "")), label="inputPack.buildSpecPath")
        _safe_relative_path(str(pack.get("stagingDirectory", "")), label="inputPack.stagingDirectory")
    lock["missingAuthorities"] = missing
    return lock, "sha256:" + hashlib.sha256(raw).hexdigest()



def _parse_management_workload_image_plan(raw: bytes, version: str) -> tuple[dict[str, Any], str]:
    if not raw or len(raw) > MAX_MANAGEMENT_WORKLOAD_IMAGE_PLAN_BYTES:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: management workload image build plan byte size is invalid")
    try:
        plan = _strict_json_value(raw, label="management workload image build plan")
    except RuntimeError as exc:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {exc}") from exc
    if not isinstance(plan, dict):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: management workload image build plan must be an object")
    allowed = {"authority","schemaVersion","releaseVersion","targetPlatform","archiveStagingPath","coreImages","baseImages","derivedManifestImageSets","manifestImageResolutionAuthority","externalVersionSelectionAuthority","externalAcquisitionAuthority","assemblyAuthority","inventoryAuthority","importAddressabilityAuthority","productImageCertificationAuthority"}
    if set(plan) != allowed:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: management workload image build plan fields are invalid")
    if plan.get("authority") != MANAGEMENT_WORKLOAD_IMAGE_PLAN_AUTHORITY or plan.get("schemaVersion") != 5 or str(plan.get("releaseVersion", "")).strip() != version:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: management workload image build plan authority/version is invalid")
    if plan.get("targetPlatform") != {"os":"linux","architecture":"amd64"} or plan.get("archiveStagingPath") != "workloads/platform-workloads.oci.tar":
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: management workload image target/archive contract is invalid")
    if plan.get("manifestImageResolutionAuthority") != MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY or plan.get("externalVersionSelectionAuthority") != "MANAGEMENT_WORKLOAD_EXTERNAL_VERSION_SELECTION_V1" or plan.get("externalAcquisitionAuthority") != "MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_V2" or plan.get("assemblyAuthority") != MANAGEMENT_WORKLOAD_OCI_ASSEMBLY_AUTHORITY or plan.get("inventoryAuthority") != "MANAGEMENT_WORKLOAD_OCI_ARCHIVE_INVENTORY_V2" or plan.get("importAddressabilityAuthority") != "MANAGEMENT_WORKLOAD_OCI_IMPORT_ADDRESSABILITY_V2" or plan.get("productImageCertificationAuthority") != MANAGEMENT_WORKLOAD_PRODUCT_IMAGE_CERTIFICATION_AUTHORITY:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: management workload OCI authority chain is invalid")
    expected_external = {
        "postgresql": {"repository":"docker.io/library/postgres","registryEndpoint":"registry-1.docker.io","registryRepository":"library/postgres","version":"17.11","tag":"17.11-bookworm","selectionChannel":"postgresql-17-patch","selectionEvidenceURL":"https://www.postgresql.org/docs/17/release-17-11.html"},
        "forgejo": {"repository":"codeberg.org/forgejo/forgejo","registryEndpoint":"codeberg.org","registryRepository":"forgejo/forgejo","version":"15.0.7","tag":"15.0.7","selectionChannel":"forgejo-lts","selectionEvidenceURL":"https://forgejo.org/releases/"},
        "zot": {"repository":"ghcr.io/project-zot/zot-linux-amd64","registryEndpoint":"ghcr.io","registryRepository":"project-zot/zot-linux-amd64","version":"2.1.20","tag":"v2.1.20","selectionChannel":"zot-stable","selectionEvidenceURL":"https://github.com/project-zot/zot/releases/tag/v2.1.20"},
        "keycloak": {"repository":"quay.io/keycloak/keycloak","registryEndpoint":"quay.io","registryRepository":"keycloak/keycloak","version":"26.7.3","tag":"26.7.3","selectionChannel":"keycloak-current-security","selectionEvidenceURL":"https://www.keycloak.org/2026/08/keycloak-2673-released"},
    }
    expected_product = {
        "platform-api":("platform.4so.local/management/platform-api","bin/linux-amd64/platform-api","deploy/images/Dockerfile.api-release","api-runtime-base"),
        "maintenance":("platform.4so.local/management/maintenance",None,"deploy/images/Dockerfile.maintenance","maintenance-toolchain-base"),
        "platform-agent":("platform.4so.local/management/platform-agent","bin/linux-amd64/platform-agent","deploy/images/Dockerfile.agent-release","static-runtime-base"),
        "platform-probe":("platform.4so.local/management/platform-probe","bin/linux-amd64/platform-probe","deploy/images/Dockerfile.probe-release","static-runtime-base"),
    }
    core = plan.get("coreImages")
    if not isinstance(core, list) or len(core) != 8:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: management workload build plan must enumerate exactly eight core image roles")
    blockers: list[dict[str, str]] = []
    roles: set[str] = set()
    for index, row in enumerate(core):
        if not isinstance(row, dict):
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: coreImages[{index}] must be an object")
        role = str(row.get("role", "")).strip()
        if role in roles or role not in {*expected_external, *expected_product}:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: core image role set is invalid")
        roles.add(role)
        if row.get("state") != "pending" or not isinstance(row.get("blocker"), str) or not row["blocker"].strip():
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: core image role {role} must remain explicit pending truth until resolved outside the exact source release")
        if role in expected_external:
            expected = expected_external[role]
            required_external = {"role","ownership","repository","registryEndpoint","registryRepository","version","tag","selectionChannel","selectionEvidenceURL","state","blocker"}
            if set(row) != required_external or row.get("ownership") != "external" or any(row.get(key) != value for key, value in expected.items()):
                raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: external core image role {role} version/transport contract is invalid")
            if row.get("tag") == "latest" or not str(row.get("selectionEvidenceURL", "")).startswith("https://"):
                raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: external core image role {role} version-selection authority is invalid")
        else:
            expected_repo, source_member, recipe, base_role = expected_product[role]
            allowed_product = {"role","ownership","repository","state","containerRecipe","baseImageRole","blocker"} | ({"sourceReleaseMember"} if source_member else set())
            if set(row) != allowed_product or row.get("ownership") != "product" or row.get("repository") != expected_repo or row.get("containerRecipe") != recipe or row.get("baseImageRole") != base_role:
                raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: product core image role {role} contract is invalid")
            if source_member and row.get("sourceReleaseMember") != source_member:
                raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: product core image role {role} exact-release binary contract is invalid")
            _safe_relative_path(str(row["containerRecipe"]), label=f"coreImages[{index}].containerRecipe")
            if source_member:
                _safe_relative_path(str(row["sourceReleaseMember"]), label=f"coreImages[{index}].sourceReleaseMember")
        if role in expected_external:
            blockers.append({
                "role": role,
                "blocker": row["blocker"],
                "repository": str(row["repository"]),
                "version": str(row["version"]),
                "tag": str(row["tag"]),
                "registryEndpoint": str(row["registryEndpoint"]),
            })
        else:
            blockers.append({"role": role, "blocker": row["blocker"]})
    bases = plan.get("baseImages")
    expected_bases = {"api-runtime-base","static-runtime-base","maintenance-toolchain-base"}
    if not isinstance(bases, list) or len(bases) != 3 or {str(row.get("role", "")) for row in bases if isinstance(row, dict)} != expected_bases:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: management workload base image role set is invalid")
    for row in bases:
        if set(row) != {"role","state","blocker"} or row.get("state") != "pending" or not isinstance(row.get("blocker"), str) or not row["blocker"].strip():
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: management workload base image resolution truth is invalid")
        blockers.append({"role": row["role"], "blocker": row["blocker"]})
    expected_sets = {
        "argocd-install-manifest": ("manifests/argocd-install.yaml", "runtime-manifests/argocd-install.yaml", "runtime-manifests/argocd-install.image-lock.json"),
        "cloudnative-pg-install-manifest": ("manifests/cloudnative-pg-install.yaml", "runtime-manifests/cloudnative-pg-install.yaml", "runtime-manifests/cloudnative-pg-install.image-lock.json"),
        "replicated-storage-install-manifest": ("manifests/replicated-storage-install.yaml", "runtime-manifests/replicated-storage-install.yaml", "runtime-manifests/replicated-storage-install.image-lock.json"),
    }
    derived = plan.get("derivedManifestImageSets")
    if not isinstance(derived, list) or len(derived) != 3:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: derived manifest image-set authority is invalid")
    seen_derived: set[str] = set()
    required_fields = {"sourceAuthority","manifestPath","sourceManifestSha256","sourceManifestBytes","resolvedManifestPath","resolutionLockPath","state","blocker"}
    for index, row in enumerate(derived):
        if not isinstance(row, dict) or set(row) != required_fields:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: derived manifest image-set row {index} is invalid")
        authority = str(row.get("sourceAuthority", ""))
        expected = expected_sets.get(authority)
        if expected is None or authority in seen_derived:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: derived manifest image-set role is invalid")
        seen_derived.add(authority)
        manifest_path, resolved_path, resolution_lock = expected
        source_sha = str(row.get("sourceManifestSha256", ""))
        source_bytes = row.get("sourceManifestBytes")
        if row.get("manifestPath") != manifest_path or not re.fullmatch(r"sha256:[0-9a-f]{64}", source_sha) or not isinstance(source_bytes, int) or source_bytes <= 0 or source_bytes > 16 * 1024 * 1024 or row.get("resolvedManifestPath") != resolved_path or row.get("resolutionLockPath") != resolution_lock or row.get("state") != "pending" or row.get("blocker") != "EXACT_MANIFEST_IMAGE_DIGEST_RESOLUTION_PENDING":
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: derived manifest image-set {authority} contract is invalid")
        for field in ("manifestPath","resolvedManifestPath","resolutionLockPath"):
            _safe_relative_path(str(row[field]), label=f"derivedManifestImageSets.{field}")
        blockers.append({"role": "manifest:" + authority, "blocker": row["blocker"]})
    if seen_derived != set(expected_sets):
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: derived manifest image-set authority is incomplete")
    plan["pendingResolution"] = sorted(blockers, key=lambda row: row["role"])
    return plan, "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_management_workload_image_plan_lock_binding(plan: dict[str, Any], lock: dict[str, Any]) -> str:
    by_id = {str(row.get("id", "")): row for row in lock.get("resolvedAuthorities", []) if isinstance(row, dict)}
    proof: list[dict[str, Any]] = []
    for row in plan.get("derivedManifestImageSets", []):
        authority = row["sourceAuthority"]
        locked = by_id.get(authority)
        if not isinstance(locked, dict) or not isinstance(locked.get("artifacts"), list) or len(locked["artifacts"]) != 1:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: management image plan source authority {authority} is absent from acquisition lock")
        artifact = locked["artifacts"][0]
        if artifact.get("stagingPath") != row["manifestPath"] or "sha256:" + str(artifact.get("sha256", "")) != row["sourceManifestSha256"] or artifact.get("sizeBytes") != row["sourceManifestBytes"]:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: management image plan source authority {authority} drifts from acquisition lock")
        proof.append({"authority": authority, "path": row["manifestPath"], "sha256": row["sourceManifestSha256"], "sizeBytes": row["sourceManifestBytes"]})
    raw = json.dumps(sorted(proof, key=lambda item: item["authority"]), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load_management_workload_image_plan(release_root: Path, version: str) -> tuple[dict[str, Any], str]:
    path = release_root / MANAGEMENT_WORKLOAD_IMAGE_PLAN_REL
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: exact release is missing {MANAGEMENT_WORKLOAD_IMAGE_PLAN_REL}: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > MAX_MANAGEMENT_WORKLOAD_IMAGE_PLAN_BYTES:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: management workload image build plan must be a bounded regular non-symlink file")
    flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: management workload image build plan changed while opening")
        with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
            raw = stream.read(MAX_MANAGEMENT_WORKLOAD_IMAGE_PLAN_BYTES + 1)
        if not _same_open_file_state(opened, os.fstat(fd)) or len(raw) != opened.st_size:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: management workload image build plan changed while reading")
    finally:
        os.close(fd)
    return _parse_management_workload_image_plan(raw, version)


def _load_exact_management_workload_image_plan(archive: Path, version: str, expected_sha256: str) -> tuple[dict[str, Any], str]:
    raw = _read_exact_release_member(archive, MANAGEMENT_WORKLOAD_IMAGE_PLAN_REL, expected_sha256=expected_sha256, max_bytes=MAX_MANAGEMENT_WORKLOAD_IMAGE_PLAN_BYTES)
    return _parse_management_workload_image_plan(raw, version)


def _management_workload_image_plan_projection(artifact: Path, version: str, artifact_sha: str, lock: dict[str, Any]) -> dict[str, Any] | None:
    """Project the exact-release management workload image plan into Lab evidence.

    The projection exists only while the appliance bundle acquisition lock still
    awaits the management workload OCI archive. A source-binding digest is emitted
    only when every derived manifest source authority is already resolved in that
    same lock, so neither a plan nor a blocked acquisition result can imply
    acquisition authority that has not actually been proven. Plan and execution
    share this owner so their emitted evidence cannot drift apart.
    """
    pending = "management-workload-oci-archive" in lock.get("missingAuthorities", []) or any(
        isinstance(row, dict) and row.get("id") == "management-workload-oci-archive" for row in lock.get("partialAuthorities", [])
    )
    if not pending:
        return None
    image_plan, image_plan_digest = _load_exact_management_workload_image_plan(artifact, version, artifact_sha)
    resolved_ids = {str(row.get("id", "")) for row in lock.get("resolvedAuthorities", []) if isinstance(row, dict)}
    required_manifest_sources = {str(row["sourceAuthority"]) for row in image_plan.get("derivedManifestImageSets", [])}
    source_binding = _verify_management_workload_image_plan_lock_binding(image_plan, lock) if required_manifest_sources.issubset(resolved_ids) else ""
    return {
        "authority": image_plan["authority"],
        "digest": image_plan_digest,
        "manifestImageResolutionAuthority": image_plan["manifestImageResolutionAuthority"],
        "sourceBindingDigest": source_binding,
        "assemblyAuthority": image_plan["assemblyAuthority"],
        "pendingResolution": image_plan["pendingResolution"],
    }

def _load_bundle_acquisition_lock(release_root: Path, version: str) -> tuple[dict[str, Any], str]:
    """Load a local lock for source-tree validation/tests; physical Lab uses the exact ZIP loader below."""
    path = release_root / BUNDLE_ACQUISITION_LOCK_REL
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: exact release is missing {BUNDLE_ACQUISITION_LOCK_REL}: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > MAX_BUNDLE_ACQUISITION_LOCK_BYTES:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: acquisition lock must be a bounded regular non-symlink file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: acquisition lock cannot be opened safely: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: acquisition lock changed while opening")
        with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
            raw = stream.read(MAX_BUNDLE_ACQUISITION_LOCK_BYTES + 1)
        after = os.fstat(fd)
        if not _same_open_file_state(opened, after) or len(raw) != opened.st_size:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: acquisition lock changed while reading")
    finally:
        os.close(fd)
    return _parse_bundle_acquisition_lock(raw, version)


def _read_exact_release_member(archive: Path, member_rel: str, *, expected_sha256: str, max_bytes: int) -> bytes:
    """Read one release member from the same stable ZIP inode whose full digest matches Exact-Release authority."""
    member_rel = _safe_relative_path(member_rel, label="exact release member")
    try:
        before = archive.lstat()
    except OSError as exc:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: exact release cannot be inspected: {exc}") from exc
    if archive.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: exact release must be a non-empty regular non-symlink ZIP")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(archive, flags)
    except OSError as exc:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: exact release cannot be opened safely: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: exact release changed while opening source authority")
        digest_before = _sha256_fd(fd)
        after_digest = os.fstat(fd)
        if not _same_open_file_state(opened, after_digest) or digest_before != expected_sha256:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: source authority ZIP does not match exact release digest")
        try:
            with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
                stream.seek(0)
                with zipfile.ZipFile(stream) as zf:
                    root, infos = _validated_release_members(zf)
                    expected_name = root + "/" + member_rel
                    info = next((item for item in infos if item.filename == expected_name), None)
                    if info is None:
                        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: exact release is missing {member_rel}")
                    if info.file_size <= 0 or info.file_size > max_bytes:
                        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: {member_rel} byte size is invalid")
                    raw = zf.read(info)
        except (zipfile.BadZipFile, OSError, KeyError) as exc:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: exact release source authority is unreadable: {exc}") from exc
        after_read = os.fstat(fd)
        if not _same_open_file_state(opened, after_read):
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: exact release changed while reading source authority")
        digest_after = _sha256_fd(fd)
        final = os.fstat(fd)
        if not _same_open_file_state(opened, final) or digest_after != digest_before:
            raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: exact release changed while verifying source authority bytes")
        return raw
    finally:
        os.close(fd)


def _load_exact_bundle_acquisition_lock(archive: Path, version: str, expected_sha256: str) -> tuple[dict[str, Any], str]:
    raw = _read_exact_release_member(archive, BUNDLE_ACQUISITION_LOCK_REL, expected_sha256=expected_sha256, max_bytes=MAX_BUNDLE_ACQUISITION_LOCK_BYTES)
    return _parse_bundle_acquisition_lock(raw, version)

def _download_locked_input_pack(pack: dict[str, Any], output: Path) -> tuple[str, str]:
    expected_sha = str(pack["sha256"])
    expected_size = int(pack["sizeBytes"])
    last_error = ""
    for raw_url in pack["urls"]:
        output.parent.mkdir(parents=True, exist_ok=True)
        tmp_fd, tmp_name = tempfile.mkstemp(prefix=output.name + ".tmp.", dir=output.parent)
        os.close(tmp_fd)
        tmp = Path(tmp_name)
        try:
            _validate_public_https_url(raw_url, label="acquisition inputPack")
            request = urllib.request.Request(raw_url, headers={"User-Agent": "4SO-Platform-Factory-Lab/1", "Accept": "application/zip"})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _PublicHTTPSRedirectHandler(), _PinnedPublicHTTPSHandler())
            h = hashlib.sha256()
            total = 0
            with opener.open(request, timeout=60) as resp, tmp.open("wb") as dst:
                _validate_public_https_url(resp.geturl(), label="acquisition final URL", allow_query=True)
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > expected_size or total > MAX_BUNDLE_INPUT_PACK_BYTES:
                        raise RuntimeError("acquisition input pack exceeded locked size")
                    h.update(chunk)
                    dst.write(chunk)
            if total != expected_size:
                raise RuntimeError(f"acquisition input pack size mismatch expected={expected_size} actual={total}")
            got = h.hexdigest()
            if got != expected_sha:
                raise RuntimeError(f"acquisition input pack digest mismatch expected={expected_sha} actual={got}")
            tmp.chmod(0o600)
            os.replace(tmp, output)
            safe_url = urllib.parse.urlunsplit((urllib.parse.urlsplit(raw_url).scheme, urllib.parse.urlsplit(raw_url).netloc, urllib.parse.urlsplit(raw_url).path, "", ""))
            return safe_url, "sha256:" + got
        except Exception as exc:
            last_error = str(exc)
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
    raise RuntimeError("all immutable inputPack urls failed: " + _tail(last_error, 1000))


def _safe_extract_input_pack(archive: Path, dest: Path) -> Path:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, mode=0o700)
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if not infos or len(infos) > MAX_BUNDLE_INPUT_PACK_FILES:
            raise RuntimeError("bundle input pack file count is empty or exceeds the canonical limit")
        seen: set[str] = set()
        roots: set[str] = set()
        total_unpacked = 0
        for info in infos:
            name = info.filename
            if info.is_dir():
                raise RuntimeError(f"bundle input pack contains non-canonical directory entry: {name!r}")
            if name in seen:
                raise RuntimeError(f"bundle input pack duplicates archive path: {name!r}")
            seen.add(name)
            if name.startswith("/") or "\\" in name or any(part in ("", ".", "..") for part in name.split("/")):
                raise RuntimeError(f"bundle input pack contains non-canonical path: {name!r}")
            if "/" not in name:
                raise RuntimeError("bundle input pack files must all live beneath one canonical root")
            roots.add(name.split("/", 1)[0])
            if info.flag_bits & 0x1:
                raise RuntimeError(f"bundle input pack contains encrypted entry: {name!r}")
            file_type = (info.external_attr >> 16) & 0o170000
            if file_type not in (0, stat.S_IFREG):
                raise RuntimeError(f"bundle input pack contains non-regular entry: {name!r}")
            if info.file_size <= 0:
                raise RuntimeError(f"bundle input pack contains empty file: {name!r}")
            total_unpacked += info.file_size
            if total_unpacked > MAX_BUNDLE_INPUT_PACK_UNPACKED_BYTES:
                raise RuntimeError("bundle input pack exceeds the canonical unpacked-size limit")
        if len(roots) != 1:
            raise RuntimeError("bundle input pack must contain exactly one canonical root")
        root = next(iter(roots))
        for info in infos:
            target = dest / info.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with zf.open(info) as src, target.open("wb") as out:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
                    written += len(chunk)
            if written != info.file_size:
                raise RuntimeError(f"bundle input pack extracted size mismatch: {info.filename!r}")
            mode = (info.external_attr >> 16) & 0o777
            target.chmod(mode or 0o600)
    return dest / root


def _normalize_acquired_build_spec(pack_root: Path, pack: dict[str, Any], *, version: str, artifact_sha: str, out_path: Path, lock: dict[str, Any] | None = None, derived_manifest_resolution: dict[str, Any] | None = None) -> tuple[Path, Path]:
    spec_rel = _safe_relative_path(pack["buildSpecPath"], label="inputPack.buildSpecPath")
    staging_rel = _safe_relative_path(pack["stagingDirectory"], label="inputPack.stagingDirectory")
    spec_path = pack_root / spec_rel
    staging = pack_root / staging_rel
    if not spec_path.is_file() or spec_path.is_symlink() or not staging.is_dir() or staging.is_symlink():
        raise RuntimeError("bundle input pack buildSpecPath/stagingDirectory is missing or unsafe")
    value = _load_runtime_json_object(spec_path, label="bundle input pack build spec")
    metadata = value.get("metadata")
    if not isinstance(metadata, dict):
        raise RuntimeError("bundle input pack build spec metadata is missing")
    if str(metadata.get("version", "")).strip() != version:
        raise RuntimeError("bundle input pack build spec version does not match exact release")
    if str(metadata.get("sourceReleaseDigest", "")).strip() != _ZERO_DIGEST:
        raise RuntimeError("bundle input pack sourceReleaseDigest must use the canonical zero placeholder")
    metadata["sourceReleaseDigest"] = "sha256:" + artifact_sha
    if lock is not None:
        resolved = lock.get("resolvedAuthorities")
        if not isinstance(resolved, list):
            raise RuntimeError("ready acquisition lock source artifacts are unavailable")
        bindings: list[dict[str, Any]] = []
        derived_rows = list((derived_manifest_resolution or {}).get("rows", []))
        source_manifest_paths = {str(row.get("sourcePath", "")) for row in derived_rows if isinstance(row, dict)}
        for authority in resolved:
            if not isinstance(authority, dict) or not isinstance(authority.get("artifacts"), list):
                raise RuntimeError("ready acquisition lock source authority is invalid")
            for artifact in authority["artifacts"]:
                rel = _safe_relative_path(str(artifact.get("stagingPath", "")), label="source artifact binding path")
                if rel in source_manifest_paths:
                    continue
                bindings.append({"path": rel, "sha256": "sha256:" + str(artifact.get("sha256", "")), "sizeBytes": artifact.get("sizeBytes")})
        for row in derived_rows:
            rel = _safe_relative_path(str(row.get("resolvedPath", "")), label="resolved manifest binding path")
            digest = str(row.get("resolvedSha256", ""))
            size = row.get("resolvedBytes")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or not isinstance(size, int) or size <= 0:
                raise RuntimeError("derived resolved manifest binding is invalid")
            bindings.append({"path": rel, "sha256": digest, "sizeBytes": size})
        bindings.sort(key=lambda row: row["path"] )
        if not bindings or len({row["path"] for row in bindings}) != len(bindings):
            raise RuntimeError("ready acquisition lock source artifact bindings are empty or duplicated")
        spec = value.get("spec")
        if not isinstance(spec, dict):
            raise RuntimeError("bundle input pack build spec spec is missing")
        if "sourceArtifacts" in spec:
            raise RuntimeError("bundle input pack build spec must not self-assert sourceArtifacts; exact release lock owns those bindings")
        if derived_rows:
            workloads = spec.get("workloads")
            if not isinstance(workloads, dict):
                raise RuntimeError("bundle input pack build spec workloads are missing")
            by_authority = {row["sourceAuthority"]: row for row in derived_rows}
            mapping = {"argocd-install-manifest":"gitOpsManifest", "cloudnative-pg-install-manifest":"cloudNativePGManifest", "replicated-storage-install-manifest":"storageManifest"}
            if set(by_authority) != set(mapping):
                raise RuntimeError("derived manifest resolution authority is incomplete")
            for authority_id, field in mapping.items():
                workloads[field] = by_authority[authority_id]["resolvedPath"]
        spec["sourceArtifacts"] = bindings
    _write_json(out_path, value)
    return out_path, staging



def _locked_regular_file_digest(path: Path, *, label: str) -> tuple[int, str]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} is missing: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise RuntimeError(f"{label} must be a non-empty regular non-symlink file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"{label} cannot be opened safely: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise RuntimeError(f"{label} changed while opening")
        h = hashlib.sha256()
        total = 0
        with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(chunk)
                total += len(chunk)
        after = os.fstat(fd)
        if not os.path.samestat(opened, after) or total != opened.st_size or opened.st_size != before.st_size:
            raise RuntimeError(f"{label} changed while hashing")
        return total, h.hexdigest()
    finally:
        os.close(fd)


def _core_image_refs_from_build_spec(value: dict[str, Any]) -> list[str]:
    workloads = ((value.get("spec") or {}).get("workloads") or {})
    keys = (
        "postgresqlImage", "platformApiImage", "forgejoImage", "zotImage",
        "keycloakImage", "maintenanceImage", "fleetAgentImage", "runtimeProbeImage",
    )
    refs = [str(workloads.get(key, "")).strip() for key in keys]
    if any(not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", ref) for ref in refs):
        raise RuntimeError("bundle input pack build spec core workload images must all be digest-pinned")
    if len(set(refs)) != len(refs):
        raise RuntimeError("bundle input pack build spec core workload image references must be unique")
    return sorted(refs)


def _load_core_image_inventory(path: Path) -> list[str]:
    raw = path.read_bytes()
    value = _strict_json_value(raw, label="core workload image inventory")
    if not isinstance(value, dict) or set(value) != {"images"} or not isinstance(value["images"], list):
        raise RuntimeError("core workload image inventory must contain exactly an images array")
    refs: list[str] = []
    for index, row in enumerate(value["images"]):
        if not isinstance(row, dict) or set(row) != {"reference"}:
            raise RuntimeError(f"core workload image inventory row {index} is invalid")
        ref = str(row.get("reference", "")).strip()
        if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", ref):
            raise RuntimeError(f"core workload image inventory row {index} is not digest-pinned")
        refs.append(ref)
    if len(refs) != 8 or len(set(refs)) != len(refs):
        raise RuntimeError("core workload image inventory must contain exactly eight unique image references")
    return sorted(refs)


def _inspect_management_workload_oci_archive(path: Path) -> list[str]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0:
        raise RuntimeError("management workload OCI archive must be a non-empty regular file")
    try:
        tf = tarfile.open(path, mode="r|*")
    except (tarfile.TarError, OSError) as exc:
        raise RuntimeError(f"management workload OCI archive is invalid: {exc}") from exc
    entries: dict[str, tuple[int, bytes | None, str | None]] = {}
    total = 0
    try:
        entry_count = 0
        for member in tf:
            entry_count += 1
            if entry_count > MAX_MANAGEMENT_WORKLOAD_OCI_ENTRIES:
                raise RuntimeError("management workload OCI archive has too many entries")
            raw_name = member.name
            if not raw_name or raw_name.startswith("/") or "\\" in raw_name or raw_name.endswith("/") or any(part in ("", ".", "..") for part in raw_name.split("/")):
                raise RuntimeError(f"management workload OCI archive path {raw_name!r} is not canonical")
            if raw_name in entries:
                raise RuntimeError(f"management workload OCI archive contains duplicate path {raw_name!r}")
            if member.isdir():
                continue
            if not member.isfile() or member.issym() or member.islnk() or member.size <= 0:
                raise RuntimeError(f"management workload OCI archive path {raw_name!r} must be a non-empty regular file")
            total += member.size
            if total > 64 * 1024 * 1024 * 1024:
                raise RuntimeError("management workload OCI archive unpacked size exceeds limit")
            stream = tf.extractfile(member)
            if stream is None:
                raise RuntimeError(f"management workload OCI archive path {raw_name!r} is unreadable")
            h = hashlib.sha256()
            collected = bytearray() if (raw_name in {"oci-layout", "index.json", "4so-image-inventory.json"} or (raw_name.startswith("blobs/sha256/") and member.size <= 16 * 1024 * 1024)) else None
            read = 0
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk); read += len(chunk)
                if collected is not None:
                    collected.extend(chunk)
            if read != member.size:
                raise RuntimeError(f"management workload OCI archive path {raw_name!r} size changed while reading")
            digest = h.hexdigest()
            if raw_name.startswith("blobs/sha256/"):
                expected = raw_name.removeprefix("blobs/sha256/")
                if not re.fullmatch(r"[0-9a-f]{64}", expected) or digest != expected:
                    raise RuntimeError(f"management workload OCI blob {raw_name!r} digest mismatch")
            elif raw_name not in {"oci-layout", "index.json", "4so-image-inventory.json"}:
                raise RuntimeError(f"management workload OCI archive contains unowned path {raw_name!r}")
            entries[raw_name] = (member.size, bytes(collected) if collected is not None else None, digest)
    finally:
        tf.close()
    for required in ("oci-layout", "index.json", "4so-image-inventory.json"):
        if required not in entries or entries[required][1] is None:
            raise RuntimeError(f"management workload OCI archive requires {required}")
    layout = _strict_json_value(entries["oci-layout"][1], label="management workload OCI layout")
    if layout != {"imageLayoutVersion": "1.0.0"}:
        raise RuntimeError("management workload OCI layout must be OCI image-layout 1.0.0")
    inventory = _strict_json_value(entries["4so-image-inventory.json"][1], label="management workload OCI inventory")
    if not isinstance(inventory, dict) or set(inventory) != {"authority", "schemaVersion", "importAddressabilityAuthority", "images"} or inventory.get("authority") != "MANAGEMENT_WORKLOAD_OCI_ARCHIVE_INVENTORY_V2" or inventory.get("schemaVersion") != 2 or inventory.get("importAddressabilityAuthority") != "MANAGEMENT_WORKLOAD_OCI_IMPORT_ADDRESSABILITY_V2":
        raise RuntimeError("management workload OCI inventory authority is invalid")
    images = inventory.get("images")
    if not isinstance(images, list) or not images or images != sorted(images) or len(images) != len(set(images)) or any(not isinstance(ref, str) or not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", ref) for ref in images):
        raise RuntimeError("management workload OCI inventory images must be sorted unique digest-pinned references")
    index = _strict_json_value(entries["index.json"][1], label="management workload OCI index")
    if (
        not isinstance(index, dict)
        or set(index) - {"schemaVersion", "mediaType", "artifactType", "subject", "manifests", "annotations"}
        or index.get("schemaVersion") != 2
        or (index.get("mediaType") not in (None, "", "application/vnd.oci.image.index.v1+json"))
        or index.get("artifactType") not in (None, "")
        or index.get("subject") is not None
        or not isinstance(index.get("manifests"), list)
        or not index["manifests"]
        or ("annotations" in index and (not isinstance(index["annotations"], dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in index["annotations"].items())))
    ):
        raise RuntimeError("management workload OCI index is invalid")
    blobs = {"sha256:" + name.removeprefix("blobs/sha256/"): row for name, row in entries.items() if name.startswith("blobs/sha256/")}
    reachable: set[str] = set()

    def validate_descriptor_shape(desc: Any) -> None:
        if (
            not isinstance(desc, dict)
            or set(desc) - _OCI_DESCRIPTOR_FIELDS
            or not isinstance(desc.get("mediaType"), str)
            or not isinstance(desc.get("digest"), str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", desc["digest"])
            or not isinstance(desc.get("size"), int)
            or isinstance(desc.get("size"), bool)
            or desc["size"] <= 0
            or ("urls" in desc and (not isinstance(desc["urls"], list) or any(not isinstance(v, str) for v in desc["urls"])))
            or ("annotations" in desc and (not isinstance(desc["annotations"], dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in desc["annotations"].items())))
            or ("data" in desc and not isinstance(desc["data"], str))
            or ("artifactType" in desc and not isinstance(desc["artifactType"], str))
        ):
            raise RuntimeError("management workload OCI descriptor is invalid")
        platform = desc.get("platform")
        if platform is not None and (
            not isinstance(platform, dict)
            or set(platform) - _OCI_PLATFORM_FIELDS
            or any(key in platform and not isinstance(platform[key], str) for key in ("architecture", "os", "os.version", "variant"))
            or ("os.features" in platform and (not isinstance(platform["os.features"], list) or any(not isinstance(v, str) for v in platform["os.features"])))
        ):
            raise RuntimeError("management workload OCI descriptor platform is invalid")

    def verify_descriptor(desc: Any, *, parse_document: bool) -> None:
        validate_descriptor_shape(desc)
        digest = desc["digest"]
        row = blobs.get(digest)
        if row is None or row[0] != desc["size"]:
            raise RuntimeError(f"management workload OCI descriptor {digest} is missing or has wrong size")
        reachable.add(digest)
        if not parse_document:
            return
        raw = row[1]
        if raw is None:
            raise RuntimeError(f"management workload OCI descriptor {digest} exceeds verification limit")
        value = _strict_json_value(raw, label=f"management workload OCI descriptor {digest}")
        media = desc["mediaType"]
        if media in _OCI_IMAGE_INDEX_MEDIA_TYPES:
            if (
                not isinstance(value, dict)
                or set(value) - {"schemaVersion", "mediaType", "artifactType", "subject", "manifests", "annotations"}
                or value.get("schemaVersion") != 2
                or value.get("artifactType") not in (None, "")
                or value.get("subject") is not None
                or value.get("mediaType") not in (None, "", media)
                or not isinstance(value.get("manifests"), list)
                or not value["manifests"]
                or ("annotations" in value and (not isinstance(value["annotations"], dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value["annotations"].items())))
            ):
                raise RuntimeError(f"management workload OCI nested index {digest} is invalid")
            for child in value["manifests"]:
                verify_descriptor(child, parse_document=True)
            return
        if media in _OCI_IMAGE_MANIFEST_MEDIA_TYPES:
            if (
                not isinstance(value, dict)
                or set(value) - {"schemaVersion", "mediaType", "artifactType", "config", "subject", "layers", "annotations"}
                or value.get("schemaVersion") != 2
                or value.get("artifactType") not in (None, "")
                or value.get("subject") is not None
                or value.get("mediaType") not in (None, "", media)
                or not isinstance(value.get("config"), dict)
                or not isinstance(value.get("layers"), list)
                or ("annotations" in value and (not isinstance(value["annotations"], dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value["annotations"].items())))
            ):
                raise RuntimeError(f"management workload OCI image manifest {digest} is invalid")
            verify_descriptor(value["config"], parse_document=False)
            for layer in value["layers"]:
                verify_descriptor(layer, parse_document=False)
            return
        raise RuntimeError(f"management workload OCI descriptor {digest} has unsupported mediaType {media!r}")
    expected_by_digest: dict[str, str] = {}
    for ref in images:
        digest = "sha256:" + ref.rsplit("@sha256:", 1)[1]
        if digest in expected_by_digest:
            raise RuntimeError("management workload OCI inventory manifest digests must be unique for import addressability")
        expected_by_digest[digest] = ref
    manifests = index["manifests"]
    top_digests = [str(row.get("digest", "")) for row in manifests if isinstance(row, dict)]
    if len(top_digests) != len(set(top_digests)) or set(top_digests) != set(expected_by_digest):
        raise RuntimeError("management workload OCI inventory/index image set mismatch")
    for desc in manifests:
        digest = str(desc.get("digest", "")) if isinstance(desc, dict) else ""
        ref = expected_by_digest.get(digest)
        annotations = desc.get("annotations") if isinstance(desc, dict) else None
        if ref is None or not isinstance(annotations, dict) or annotations.get("io.containerd.image.name") != ref or annotations.get("org.opencontainers.image.ref.name") != ref:
            raise RuntimeError(f"management workload OCI descriptor {digest!r} is not import-addressable as inventory reference {ref!r}")
        verify_descriptor(desc, parse_document=True)
    if set(blobs) != reachable:
        raise RuntimeError(f"management workload OCI archive contains unreferenced blobs: {sorted(set(blobs) - reachable)}")
    return list(images)




def _image_repository(ref: str) -> str:
    ref = str(ref).strip()
    if not ref or re.search(r"\s", ref):
        raise RuntimeError(f"image reference {ref!r} is not canonical")
    if "@sha256:" in ref:
        prefix, digest = ref.rsplit("@sha256:", 1)
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError(f"image reference {ref!r} digest is invalid")
        ref = prefix
    if "/" not in ref:
        raise RuntimeError(f"image reference {ref!r} must use an explicit registry")
    host = ref.split("/", 1)[0]
    if "." not in host and ":" not in host and host != "localhost":
        raise RuntimeError(f"image reference {ref!r} must use an explicit registry")
    slash = ref.rfind("/")
    tail = ref[slash + 1:]
    if ":" in tail:
        tail = tail.rsplit(":", 1)[0]
        ref = ref[:slash + 1] + tail
    if not ref or ref.endswith("/") or "@" in ref:
        raise RuntimeError(f"image reference repository {ref!r} is invalid")
    return ref


def _parse_platformctl_json(result: dict[str, Any], *, label: str) -> dict[str, Any]:
    if result.get("status") != "PASS":
        raise RuntimeError(f"{label} failed: {_tail(str(result.get('outputTail', '')), 1200)}")
    value = _strict_json_value(str(result.get("outputTail", "")).encode("utf-8"), label=label)
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} output must be a JSON object")
    return value


def _resolve_acquired_manifest_images(pack_root: Path, pack: dict[str, Any], lock: dict[str, Any], image_plan: dict[str, Any], platformctl: Path, *, cwd: Path) -> dict[str, Any]:
    if image_plan.get("manifestImageResolutionAuthority") != MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY:
        raise RuntimeError(f"{BUNDLE_SOURCE_LOCKS_BLOCKER}: manifest image resolution authority is unavailable")
    binding_digest = _verify_management_workload_image_plan_lock_binding(image_plan, lock)
    staging_rel = _safe_relative_path(pack["stagingDirectory"], label="inputPack.stagingDirectory")
    staging = pack_root / staging_rel
    if not staging.is_dir() or staging.is_symlink():
        raise RuntimeError("bundle input pack stagingDirectory is missing or unsafe")

    by_id = {str(item.get("id", "")): item for item in lock.get("resolvedAuthorities", []) if isinstance(item, dict)}
    workload = by_id.get("management-workload-oci-archive")
    if not isinstance(workload, dict) or not isinstance(workload.get("artifacts"), list) or not workload["artifacts"]:
        raise RuntimeError("management workload OCI archive authority is unavailable for manifest image resolution")
    archive_refs: list[str] = []
    for index, artifact in enumerate(workload["artifacts"]):
        rel = _safe_relative_path(str(artifact.get("stagingPath", "")), label=f"management-workload-oci-archive.artifacts[{index}].stagingPath")
        archive_refs.extend(_inspect_management_workload_oci_archive(staging / rel))
    if len(archive_refs) != len(set(archive_refs)):
        raise RuntimeError("management workload OCI archive contains duplicate exact image references")
    exact_by_repo: dict[str, str] = {}
    for ref in archive_refs:
        repo = _image_repository(ref)
        if repo in exact_by_repo and exact_by_repo[repo] != ref:
            raise RuntimeError(f"management workload OCI archive contains multiple exact images for repository {repo}")
        exact_by_repo[repo] = ref

    rows: list[dict[str, Any]] = []
    for item in image_plan.get("derivedManifestImageSets", []):
        source_rel = _safe_relative_path(str(item["manifestPath"]), label="manifest image source path")
        resolved_rel = _safe_relative_path(str(item["resolvedManifestPath"]), label="resolved manifest path")
        lock_rel = _safe_relative_path(str(item["resolutionLockPath"]), label="manifest resolution lock path")
        source = staging / source_rel
        source_size, source_sha = _locked_regular_file_digest(source, label=f"manifest source {source_rel}")
        if source_size != item["sourceManifestBytes"] or "sha256:" + source_sha != item["sourceManifestSha256"]:
            raise RuntimeError(f"manifest source {source_rel} does not match management workload image plan")

        inspect = _run("bundle-manifest-image-inspect", [str(platformctl), "workload-oci", "inspect-manifest", "--manifest", str(source)], cwd=cwd, timeout=120)
        inspected = _parse_platformctl_json(inspect, label=f"manifest image inspection {source_rel}")
        if inspected.get("authority") != MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY or not isinstance(inspected.get("images"), list) or not inspected["images"]:
            raise RuntimeError(f"manifest image inspection {source_rel} returned invalid authority")
        mappings: list[tuple[str, str]] = []
        for source_ref in inspected["images"]:
            source_ref = str(source_ref).strip()
            repo = _image_repository(source_ref)
            exact = exact_by_repo.get(repo)
            if exact is None:
                raise RuntimeError(f"manifest image {source_ref} is absent from the exact management workload OCI archive")
            if "@sha256:" in source_ref:
                source_digest = source_ref.rsplit("@sha256:", 1)[1]
                exact_digest = exact.rsplit("@sha256:", 1)[1]
                if source_digest != exact_digest:
                    raise RuntimeError(f"digest-pinned manifest image {source_ref} does not match the exact OCI archive image {exact}")
            else:
                mappings.append((source_ref, exact))

        out_manifest = staging / resolved_rel
        out_lock = staging / lock_rel
        out_manifest.parent.mkdir(parents=True, exist_ok=True)
        out_lock.parent.mkdir(parents=True, exist_ok=True)
        command = [str(platformctl), "workload-oci", "resolve-manifest", "--manifest", str(source)]
        for source_ref, exact in sorted(mappings):
            command.extend(["--resolution", source_ref + "=" + exact])
        command.extend(["--out-manifest", str(out_manifest), "--out-lock", str(out_lock)])
        resolve = _run("bundle-manifest-image-resolve", command, cwd=cwd, timeout=180)
        resolved = _parse_platformctl_json(resolve, label=f"manifest image resolution {source_rel}")
        if resolved.get("authority") != MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY or resolved.get("sourceManifestSha256") != item["sourceManifestSha256"]:
            raise RuntimeError(f"manifest image resolution {source_rel} returned invalid source binding")
        resolved_size, resolved_sha = _locked_regular_file_digest(out_manifest, label=f"resolved manifest {resolved_rel}")
        lock_size, lock_sha = _locked_regular_file_digest(out_lock, label=f"manifest resolution lock {lock_rel}")
        lock_value = _load_runtime_json_object(out_lock, label=f"manifest resolution lock {lock_rel}")
        if lock_value.get("authority") != MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY or lock_value.get("sourceManifestSha256") != item["sourceManifestSha256"] or lock_value.get("sourceManifestBytes") != item["sourceManifestBytes"] or lock_value.get("resolvedManifestSha256") != "sha256:" + resolved_sha or lock_value.get("resolvedManifestBytes") != resolved_size:
            raise RuntimeError(f"manifest resolution lock {lock_rel} does not bind source/resolved bytes")
        exact_images = [str(row.get("exact", "")) for row in lock_value.get("images", []) if isinstance(row, dict)]
        if not exact_images or any(ref not in archive_refs for ref in exact_images):
            raise RuntimeError(f"manifest resolution lock {lock_rel} contains an image outside the exact OCI archive")
        rows.append({
            "sourceAuthority": item["sourceAuthority"], "sourcePath": source_rel,
            "sourceSha256": "sha256:" + source_sha, "sourceBytes": source_size,
            "resolvedPath": resolved_rel, "resolvedSha256": "sha256:" + resolved_sha, "resolvedBytes": resolved_size,
            "lockPath": lock_rel, "lockSha256": "sha256:" + lock_sha, "lockBytes": lock_size,
            "images": sorted(exact_images),
        })
    proof_raw = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"authority": MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY, "sourceBindingDigest": binding_digest, "rows": rows, "digest": "sha256:" + hashlib.sha256(proof_raw).hexdigest()}

def _verify_locked_authority_bytes(staging: Path, by_id: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, list[str]], list[Path]]:
    """Prove every canonical source authority byte-for-byte inside the staged pack.

    Returns the immutable proof rows, the staging paths bound per authority, and the
    workload archive files that must later be opened directly. A size or digest
    mismatch is a hard failure: a bundle is never partially admitted."""
    proof_rows: list[dict[str, Any]] = []
    bound_paths: dict[str, list[str]] = {}
    workload_archive_paths: list[Path] = []
    for authority_id in sorted(by_id):
        authority = by_id[authority_id]
        paths: list[str] = []
        for index, artifact in enumerate(authority.get("artifacts", [])):
            rel = _safe_relative_path(artifact["stagingPath"], label=f"{authority_id}.artifacts[{index}].stagingPath")
            target = staging / rel
            size, digest = _locked_regular_file_digest(target, label=f"source authority {authority_id}:{rel}")
            if size != artifact["sizeBytes"]:
                raise RuntimeError(f"source authority {authority_id}:{rel} size mismatch expected={artifact['sizeBytes']} actual={size}")
            if digest != artifact["sha256"]:
                raise RuntimeError(f"source authority {authority_id}:{rel} sha256 mismatch expected={artifact['sha256']} actual={digest}")
            paths.append(rel)
            proof_rows.append({"authority": authority_id, "stagingPath": rel, "sizeBytes": size, "sha256": digest})
            if authority_id == "management-workload-oci-archive":
                workload_archive_paths.append(target)
        bound_paths[authority_id] = sorted(paths)
    return proof_rows, bound_paths, workload_archive_paths


def _verify_derived_manifest_resolution_rows(staging: Path, derived_rows: list[Any]) -> list[str]:
    """Prove each derived manifest resolution row against its own resolution lock.

    Returns the exact image references those locks admitted, so a resolved manifest
    can never claim an image the management workload archive does not contain."""
    validated_derived_images: list[str] = []
    for index, row in enumerate(derived_rows):
        if not isinstance(row, dict):
            raise RuntimeError(f"manifest image resolution row {index} must be an object")
        # The source manifest path is validated even though only the resolved/lock
        # paths are opened: a non-canonical evidence path must fail the batch.
        _safe_relative_path(str(row.get("sourcePath", "")), label=f"manifestImageResolution.rows[{index}].sourcePath")
        resolved_rel = _safe_relative_path(str(row.get("resolvedPath", "")), label=f"manifestImageResolution.rows[{index}].resolvedPath")
        lock_rel = _safe_relative_path(str(row.get("lockPath", "")), label=f"manifestImageResolution.rows[{index}].lockPath")
        resolved_size, resolved_sha = _locked_regular_file_digest(staging / resolved_rel, label=f"derived resolved manifest {resolved_rel}")
        lock_size, lock_sha = _locked_regular_file_digest(staging / lock_rel, label=f"derived manifest resolution lock {lock_rel}")
        if resolved_size != row.get("resolvedBytes") or "sha256:" + resolved_sha != row.get("resolvedSha256"):
            raise RuntimeError(f"derived resolved manifest {resolved_rel} changed after manifest image resolution")
        if lock_size != row.get("lockBytes") or "sha256:" + lock_sha != row.get("lockSha256"):
            raise RuntimeError(f"derived manifest resolution lock {lock_rel} changed after manifest image resolution")
        lock_value = _load_runtime_json_object(staging / lock_rel, label=f"derived manifest resolution lock {lock_rel}")
        if lock_value.get("authority") != MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY:
            raise RuntimeError(f"derived manifest resolution lock {lock_rel} has an invalid authority")
        if lock_value.get("sourceManifestSha256") != row.get("sourceSha256") or lock_value.get("sourceManifestBytes") != row.get("sourceBytes"):
            raise RuntimeError(f"derived manifest resolution lock {lock_rel} does not bind the exact source manifest")
        if lock_value.get("resolvedManifestSha256") != row.get("resolvedSha256") or lock_value.get("resolvedManifestBytes") != row.get("resolvedBytes"):
            raise RuntimeError(f"derived manifest resolution lock {lock_rel} does not bind the exact resolved manifest")
        exact_images = sorted(str(item.get("exact", "")).strip() for item in lock_value.get("images", []) if isinstance(item, dict))
        if not exact_images or exact_images != sorted(str(value).strip() for value in row.get("images", [])):
            raise RuntimeError(f"derived manifest resolution lock {lock_rel} image set differs from manifest image resolution evidence")
        validated_derived_images.extend(exact_images)
    return validated_derived_images


def _verify_build_spec_source_roles(spec: dict[str, Any], bound_paths: dict[str, list[str]], derived_rows: list[Any]) -> None:
    """Bind every build-spec source role to the exact locked or derived staging paths.

    A role naming a file the canonical authority set never produced, or dropping one
    it did, fails the batch here instead of being reconciled during the build."""
    rke2 = spec.get("rke2") or {}
    workloads = spec.get("workloads") or {}
    if not isinstance(spec, dict) or not isinstance(rke2, dict) or not isinstance(workloads, dict):
        raise RuntimeError("bundle input pack build spec source sections must be objects")
    if str(workloads.get("ocmManifest", "")).strip():
        raise RuntimeError("bundle input pack build spec ocmManifest is not admitted by the canonical source-authority set")
    for field, value in (("rke2.installArtifacts", rke2.get("installArtifacts")), ("rke2.imageArchives", rke2.get("imageArchives")), ("workloads.imageArchives", workloads.get("imageArchives"))):
        if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item.strip() for item in value):
            raise RuntimeError(f"bundle input pack build spec {field} must be a non-empty path array")
    role_paths = {
        "rke2-installer-and-offline-artifacts": [str(rke2.get("installer", "")).strip(), *[str(v).strip() for v in (rke2.get("installArtifacts") or [])], *[str(v).strip() for v in (rke2.get("imageArchives") or [])]],
        "management-workload-oci-archive": [str(v).strip() for v in (workloads.get("imageArchives") or [])],
        "argocd-install-manifest": [str(workloads.get("gitOpsManifest", "")).strip()],
        "cloudnative-pg-install-manifest": [str(workloads.get("cloudNativePGManifest", "")).strip()],
        "replicated-storage-install-manifest": [str(workloads.get("storageManifest", "")).strip()],
    }
    derived_by_authority = {str(row.get("sourceAuthority", "")): row for row in derived_rows if isinstance(row, dict)}
    for authority_id, actual in role_paths.items():
        try:
            canonical = sorted(_safe_relative_path(value, label=f"buildSpec.{authority_id}") for value in actual)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
        if len(canonical) != len(set(canonical)):
            raise RuntimeError(f"build spec source role {authority_id} contains duplicate staging paths")
        expected_paths = bound_paths[authority_id]
        if authority_id in derived_by_authority:
            expected_paths = [_safe_relative_path(str(derived_by_authority[authority_id]["resolvedPath"]), label=f"derived.{authority_id}.resolvedPath")]
        if canonical != expected_paths:
            raise RuntimeError(f"build spec source role {authority_id} does not exactly match locked/derived staging paths")


def _verify_management_workload_oci_content(workload_archive_paths: list[Path], validated_derived_images: list[str], build_spec: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Open each admitted workload archive and cross-check its image references.

    Returns the archive image references and the derived core workload references
    the caller seals into durable evidence."""
    if not workload_archive_paths:
        raise RuntimeError("management workload OCI archive authority must resolve to at least one archive artifact")
    archive_refs: list[str] = []
    for archive_path in workload_archive_paths:
        archive_refs.extend(_inspect_management_workload_oci_archive(archive_path))
    if len(archive_refs) != len(set(archive_refs)):
        raise RuntimeError("management workload OCI archives contain duplicate image references")
    if any(ref not in archive_refs for ref in validated_derived_images):
        raise RuntimeError("derived manifest image resolution contains an image outside the exact management workload OCI archive")
    spec_refs = _core_image_refs_from_build_spec(build_spec)
    if not set(spec_refs).issubset(set(archive_refs)):
        raise RuntimeError("derived core workload image authority does not match OCI archive content")
    return archive_refs, spec_refs


def _verify_pack_file_closure(pack_root: Path, staging_rel: str, pack: dict[str, Any], proof_rows: list[dict[str, Any]], derived_rows: list[Any]) -> None:
    """Require the extracted pack to hold exactly the files its own evidence names.

    Extra or missing files mean the archive was assembled outside the canonical
    acquisition path, so the batch is rejected before any build starts."""
    build_spec_rel = _safe_relative_path(pack["buildSpecPath"], label="inputPack.buildSpecPath")
    expected_pack_files = {build_spec_rel}
    expected_pack_files.update(f"{staging_rel}/{row['stagingPath']}" for row in proof_rows)
    for row in derived_rows:
        expected_pack_files.add(f"{staging_rel}/{_safe_relative_path(str(row['resolvedPath']), label='derived resolved path')}")
        expected_pack_files.add(f"{staging_rel}/{_safe_relative_path(str(row['lockPath']), label='derived resolution lock path')}")
    actual_pack_files: set[str] = set()
    for candidate in pack_root.rglob("*"):
        if candidate.is_symlink():
            raise RuntimeError("bundle input pack contains a symlink after extraction")
        if candidate.is_file():
            actual_pack_files.add(candidate.relative_to(pack_root).as_posix())
    if actual_pack_files != expected_pack_files:
        extra = sorted(actual_pack_files - expected_pack_files)
        missing = sorted(expected_pack_files - actual_pack_files)
        raise RuntimeError(f"bundle input pack file ownership mismatch extra={extra} missing={missing}")


def _verify_input_pack_source_bindings(pack_root: Path, pack: dict[str, Any], lock: dict[str, Any], build_spec_path: Path, derived_manifest_resolution: dict[str, Any] | None = None) -> dict[str, Any]:
    staging_rel = _safe_relative_path(pack["stagingDirectory"], label="inputPack.stagingDirectory")
    staging = pack_root / staging_rel
    if not staging.is_dir() or staging.is_symlink():
        raise RuntimeError("bundle input pack stagingDirectory is missing or unsafe")
    build_spec = _load_runtime_json_object(build_spec_path, label="normalized bundle input pack build spec")
    if not isinstance(build_spec, dict):
        raise RuntimeError("bundle input pack build spec must be an object")

    by_id = {item["id"]: item for item in lock.get("resolvedAuthorities", [])}
    if set(by_id) != _BUNDLE_REQUIRED_SOURCE_AUTHORITIES:
        raise RuntimeError("ready bundle source binding requires all canonical source authorities")

    proof_rows, bound_paths, workload_archive_paths = _verify_locked_authority_bytes(staging, by_id)

    spec = build_spec.get("spec") or {}
    source_artifacts = spec.get("sourceArtifacts") if isinstance(spec, dict) else None
    derived_rows = list((derived_manifest_resolution or {}).get("rows", []))
    source_manifest_paths = {str(row.get("sourcePath", "")) for row in derived_rows if isinstance(row, dict)}
    validated_derived_images = _verify_derived_manifest_resolution_rows(staging, derived_rows)
    if source_artifacts is not None:
        expected_bindings = [{"path": row["stagingPath"], "sha256": "sha256:" + row["sha256"], "sizeBytes": row["sizeBytes"]} for row in proof_rows if row["stagingPath"] not in source_manifest_paths]
        for row in derived_rows:
            expected_bindings.append({"path": row["resolvedPath"], "sha256": row["resolvedSha256"], "sizeBytes": row["resolvedBytes"]})
        expected_bindings = sorted(expected_bindings, key=lambda row: row["path"] )
        if source_artifacts != expected_bindings:
            raise RuntimeError("normalized bundle build spec sourceArtifacts do not exactly match locked and derived source authority bytes")
    _verify_build_spec_source_roles(spec, bound_paths, derived_rows)

    archive_refs, spec_refs = _verify_management_workload_oci_content(workload_archive_paths, validated_derived_images, build_spec)

    _verify_pack_file_closure(pack_root, staging_rel, pack, proof_rows, derived_rows)

    derived_proof = {"authority": "digest-pinned-core-workload-images", "images": spec_refs, "derivedFrom": "management-workload-oci-archive"}
    manifest_proof = None
    if derived_rows:
        manifest_proof = {"authority": MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY, "digest": derived_manifest_resolution.get("digest"), "sourceBindingDigest": derived_manifest_resolution.get("sourceBindingDigest"), "rows": derived_rows}
    canonical_proof = json.dumps({"artifacts": proof_rows, "derived": derived_proof, "manifestImageResolution": manifest_proof}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"artifactCount": len(proof_rows), "derivedAuthorityCount": 2 if manifest_proof else 1, "bindingDigest": "sha256:" + hashlib.sha256(canonical_proof).hexdigest(), "manifestImageResolution": manifest_proof}


def _bundle_verify_details(result: dict[str, Any]) -> dict[str, Any]:
    try:
        value = _strict_json_value(str(result.get("outputTail", "")), label="bundle verifier output")
    except RuntimeError as exc:
        raise ValueError(str(exc)) from exc
    if not isinstance(value, dict):
        raise ValueError("bundle verifier output must be a JSON object")
    return value


def _bundle_verify_binding(result: dict[str, Any], *, version: str, artifact_sha: str) -> tuple[bool, str]:
    if result.get("status") != "PASS":
        return False, "bundle verifier did not pass"
    try:
        value = _bundle_verify_details(result)
    except ValueError as exc:
        return False, f"bundle verifier output is not canonical JSON: {exc}"
    expected_release = "sha256:" + artifact_sha
    if value.get("verified") is not True or value.get("lockRequired") is not True:
        return False, "bundle verifier did not prove a required immutable lock"
    if str(value.get("version", "")).strip() != version:
        return False, "bundle version does not match exact release version"
    if str(value.get("sourceReleaseDigest", "")).strip() != expected_release:
        return False, "bundle sourceReleaseDigest does not match exact release ZIP"
    for key in ("bundleDigest", "lockDigest"):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(value.get(key, ""))):
            return False, f"bundle verifier did not return canonical {key}"
    return True, "exact release version/SHA and immutable bundle lock are bound"

def _auto_acquire_bundle(body: dict[str, Any], artifact: Path, release_root: Path, state_dir: Path) -> tuple[Path | None, dict[str, Any]]:
    _, version, artifact_sha = _release_identity(artifact)
    lock, lock_digest = _load_exact_bundle_acquisition_lock(artifact, version, artifact_sha)
    if lock["status"] != "ready":
        image_plan_projection = _management_workload_image_plan_projection(artifact, version, artifact_sha, lock)
        return None, {
            "stage": "bundle-auto-acquisition-authority",
            "command": [BUNDLE_ACQUISITION_AUTHORITY],
            "exactReleaseBindingAuthority": BUNDLE_ACQUISITION_EXACT_RELEASE_AUTHORITY,
            "returnCode": 3,
            "durationSeconds": 0,
            "outputTail": "incomplete production bundle source authorities: " + ",".join([item["id"] for item in lock.get("partialAuthorities", [])] + lock["missingAuthorities"]),
            "fingerprint": _fingerprint("bundle-auto-acquisition-authority", 4, lock_digest + ":" + ",".join([item["id"] for item in lock.get("partialAuthorities", [])] + lock["missingAuthorities"])),
            "status": "BLOCKED",
            "blocker": BUNDLE_SOURCE_LOCKS_BLOCKER,
            "resolvedAuthorities": list(lock.get("resolvedAuthorities", [])),
            "partialAuthorities": list(lock.get("partialAuthorities", [])),
            "missingAuthorities": list(lock["missingAuthorities"]),
            "acquisitionLockDigest": lock_digest,
            "managementWorkloadImagePlan": image_plan_projection,
        }
    pack = lock["inputPack"]
    state_dir.mkdir(parents=True, exist_ok=True)
    archive = state_dir / "bundle-input-pack.zip"
    started = time.monotonic()
    try:
        source_url, pack_digest = _download_locked_input_pack(pack, archive)
        pack_root = _safe_extract_input_pack(archive, state_dir / "input-pack")
        platformctl = release_root / "bin" / "linux-amd64" / "platformctl"
        image_plan, _image_plan_digest = _load_exact_management_workload_image_plan(artifact, version, artifact_sha)
        derived_manifest_resolution = _resolve_acquired_manifest_images(pack_root, pack, lock, image_plan, platformctl, cwd=release_root)
        generated_spec, staging = _normalize_acquired_build_spec(pack_root, pack, version=version, artifact_sha=artifact_sha, out_path=state_dir / "bundle-build.json", lock=lock, derived_manifest_resolution=derived_manifest_resolution)
        source_binding = _verify_input_pack_source_bindings(pack_root, pack, lock, generated_spec, derived_manifest_resolution=derived_manifest_resolution)
        bundle = state_dir / "bundle"
        if bundle.exists():
            shutil.rmtree(bundle)
        build_result = _run("bundle-auto-build", [str(platformctl), "appliance-bundle", "build", "--spec", str(generated_spec), "--staging", str(staging), "--out", str(bundle), "--release-artifact", str(artifact)], cwd=release_root, timeout=1800)
        if build_result["status"] != "PASS":
            return None, {**build_result, "blocker": "LAB_BUNDLE_AUTO_BUILD_FAILED", "acquisitionLockDigest": lock_digest, "inputPackDigest": pack_digest}
        verify = _run("bundle-auto-verify", [str(platformctl), "appliance-bundle", "verify", "--dir", str(bundle)], cwd=release_root, timeout=300)
        binding_ok, binding_detail = _bundle_verify_binding(verify, version=version, artifact_sha=artifact_sha)
        if verify["status"] != "PASS" or not binding_ok:
            failed = {**verify, "status": "FAIL", "returnCode": verify.get("returnCode", 2) or 2, "outputTail": _tail(str(verify.get("outputTail", "")) + "\n" + binding_detail)}
            return None, {**failed, "blocker": "LAB_BUNDLE_AUTO_VERIFY_FAILED", "acquisitionLockDigest": lock_digest, "inputPackDigest": pack_digest}
        try:
            archive.unlink()
        except FileNotFoundError:
            pass
        shutil.rmtree(state_dir / "input-pack", ignore_errors=True)
        verify_details = _bundle_verify_details(verify)
        return bundle, {
            "stage": "bundle-auto-acquisition",
            "command": [BUNDLE_ACQUISITION_AUTHORITY],
            "exactReleaseBindingAuthority": BUNDLE_ACQUISITION_EXACT_RELEASE_AUTHORITY,
            "returnCode": 0,
            "durationSeconds": round(time.monotonic() - started, 3),
            "outputTail": f"immutable input pack acquired from {source_url}; exact-release-bound appliance bundle built and verified",
            "fingerprint": _fingerprint("bundle-auto-acquisition", 0, lock_digest + ":" + pack_digest + ":" + artifact_sha + ":" + source_binding["bindingDigest"]),
            "status": "PASS",
            "acquisitionLockDigest": lock_digest,
            "inputPackDigest": pack_digest,
            "sourceBindingDigest": source_binding["bindingDigest"],
            "sourceBindingArtifactCount": source_binding["artifactCount"],
            "sourceBindingDerivedAuthorityCount": source_binding.get("derivedAuthorityCount", 0),
            "manifestImageResolutionAuthority": derived_manifest_resolution["authority"],
            "manifestImageResolutionDigest": derived_manifest_resolution["digest"],
            "releaseArtifactDigest": "sha256:" + artifact_sha,
            "bundleDigest": str(verify_details["bundleDigest"]),
            "bundleLockDigest": str(verify_details["lockDigest"]),
        }
    except Exception as exc:
        safe = _tail(str(exc), 2000)
        return None, {
            "stage": "bundle-auto-acquisition",
            "command": [BUNDLE_ACQUISITION_AUTHORITY],
            "exactReleaseBindingAuthority": BUNDLE_ACQUISITION_EXACT_RELEASE_AUTHORITY,
            "returnCode": 4,
            "durationSeconds": round(time.monotonic() - started, 3),
            "outputTail": safe,
            "fingerprint": _fingerprint("bundle-auto-acquisition", 4, safe),
            "status": "BLOCKED",
            "blocker": "LAB_BUNDLE_IMMUTABLE_ACQUISITION_FAILED",
            "acquisitionLockDigest": lock_digest,
        }

def _roles_for_tier(tier: str) -> list[str]:
    for row in guide()["serverTiers"]:
        if row["id"] == tier:
            return list(row["roles"])
    raise SystemExit(f"unknown server tier: {tier}")


def validate_spec(spec: dict[str, Any], *, require_bundle: bool = False) -> dict[str, Any]:
    if spec.get("apiVersion") != "platform.4so.io/v1alpha1" or spec.get("kind") != "LabExecution":
        raise SystemExit("lab spec must be platform.4so.io/v1alpha1 LabExecution")
    body = spec.get("spec")
    if not isinstance(body, dict):
        raise SystemExit("spec is required")
    tier = str(body.get("serverTier", "")).strip()
    required = _roles_for_tier(tier)
    servers = body.get("servers")
    if not isinstance(servers, list):
        raise SystemExit("spec.servers must be an array")
    role_map: dict[str, str] = {}
    for item in servers:
        if not isinstance(item, dict):
            raise SystemExit("each server must be an object")
        role, host = str(item.get("role", "")).strip(), str(item.get("host", "")).strip()
        if not role or not host or role in role_map:
            raise SystemExit("each server needs a unique non-empty role and host")
        role_map[role] = host
    missing = [role for role in required if role not in role_map]
    extras = [role for role in role_map if role not in required]
    if missing or extras:
        raise SystemExit(f"server inventory does not match tier {tier}; missing={missing} extras={extras}")
    canonical_hosts = [host.strip().lower() for host in role_map.values()]
    if len(set(canonical_hosts)) != len(canonical_hosts):
        raise SystemExit("lab server inventory must map every physical role to a distinct host; duplicate hosts would invalidate topology evidence")
    ssh = body.get("ssh")
    if not isinstance(ssh, dict) or str(ssh.get("user", "root")).strip() != "root":
        raise SystemExit("lab SSH user must be root")
    for key in ("identityFile", "knownHostsFile"):
        p = Path(str(ssh.get(key, ""))).expanduser()
        if not p.is_file() or p.is_symlink():
            raise SystemExit(f"ssh.{key} must be an existing regular non-symlink file")
        if key == "identityFile" and p.stat().st_mode & 0o077:
            raise SystemExit("SSH identityFile permissions must not allow group/other access")
    artifact = Path(str(body.get("releaseArtifact", ""))).expanduser()
    _release_identity(artifact)
    if require_bundle and body.get("bundleDirectory"):
        bundle = Path(str(body.get("bundleDirectory", ""))).expanduser()
        if not bundle.is_dir() or bundle.is_symlink():
            raise SystemExit("bundleDirectory must be an existing non-symlink directory when explicitly provided")
    _validate_management_install_inputs(body)
    return body


def _server_map(body: dict[str, Any]) -> dict[str, str]:
    return {str(v["role"]): str(v["host"]) for v in body["servers"]}


def _canonical_server_inventory(body: dict[str, Any]) -> dict[str, Any]:
    servers = sorted(
        ({"role": str(item["role"]).strip(), "host": str(item["host"]).strip().lower()} for item in body["servers"]),
        key=lambda item: item["role"],
    )
    return {"serverTier": str(body["serverTier"]).strip(), "servers": servers}


def _server_inventory_digest(body: dict[str, Any]) -> str:
    raw = json.dumps(_canonical_server_inventory(body), sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _valid_lab_dns_subdomain(value: str) -> bool:
    value = value.strip().rstrip(".")
    if not value or len(value) > 253:
        return False
    for label in value.split("."):
        if not label or len(label) > 63 or label[0] == "-" or label[-1] == "-":
            return False
        if any(not (ch.isdigit() or "a" <= ch <= "z" or ch == "-") for ch in label):
            return False
    return True


def _valid_https_endpoint(value: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(value.strip())
    except ValueError:
        return False
    return parsed.scheme == "https" and bool(parsed.hostname) and parsed.username is None and parsed.password is None and not parsed.fragment


def _validate_management_install_inputs(body: dict[str, Any]) -> None:
    management = body.get("management")
    if not isinstance(management, dict):
        raise SystemExit("spec.management is required for server-driven management installation")
    admin_email = str(management.get("adminEmail", "")).strip()
    if not admin_email or any(ch.isspace() for ch in admin_email) or admin_email.count("@") != 1:
        raise SystemExit("spec.management.adminEmail is required for managed identity bootstrap")
    dns_zone = str(management.get("dnsZone", "")).strip().rstrip(".")
    if not _valid_lab_dns_subdomain(dns_zone):
        raise SystemExit("server-driven management certification requires a valid lowercase spec.management.dnsZone")
    management_roles = _management_roles(str(body.get("serverTier", "")))
    if len(management_roles) != 3:
        return
    public_endpoint = str(management.get("publicEndpoint", "")).strip()
    if not _valid_https_endpoint(public_endpoint):
        raise SystemExit("three-node management certification requires an explicit valid HTTPS spec.management.publicEndpoint")
    storage_class = str(management.get("storageClass", "replicated-rwx")).strip()
    if not _valid_lab_dns_subdomain(storage_class):
        raise SystemExit("three-node management certification requires a valid lowercase spec.management.storageClass")
    object_storage = management.get("objectStorage")
    if not isinstance(object_storage, dict):
        raise SystemExit("three-node management certification requires spec.management.objectStorage")
    if not _valid_https_endpoint(str(object_storage.get("url", ""))):
        raise SystemExit("three-node management certification requires an HTTPS object-storage URL")
    if not str(object_storage.get("bucket", "")).strip():
        raise SystemExit("three-node management certification requires a non-empty object-storage bucket")
    credential_ref = str(object_storage.get("credentialRef", "")).strip()
    prefix = "external-secret://platform-system/"
    if not credential_ref.startswith(prefix) or not _valid_lab_dns_subdomain(credential_ref[len(prefix):]):
        raise SystemExit("three-node management certification requires object-storage credentialRef external-secret://platform-system/<secret>")


def plan_document(spec: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="4so-lab-plan-") as td:
        scratch = Path(td)
        snapshot_spec, (_, version, artifact_sha) = _spec_with_release_snapshot(spec, scratch / "release-artifact.zip")
        body = validate_spec(snapshot_spec)
        tier = body["serverTier"]
        program_guide = guide()
        bundle_acquisition: dict[str, Any]
        if body.get("bundleDirectory"):
            bundle_acquisition = {"authority": "operator-provided-bundle", "status": "provided", "missingAuthorities": []}
        else:
            artifact = Path(body["releaseArtifact"])
            try:
                acquisition_lock, lock_digest = _load_exact_bundle_acquisition_lock(artifact, version, artifact_sha)
                bundle_acquisition = {
                    "authority": BUNDLE_ACQUISITION_AUTHORITY,
                    "exactReleaseBindingAuthority": BUNDLE_ACQUISITION_EXACT_RELEASE_AUTHORITY,
                    "status": acquisition_lock["status"],
                    "resolvedAuthorities": list(acquisition_lock.get("resolvedAuthorities", [])),
                    "partialAuthorities": list(acquisition_lock.get("partialAuthorities", [])),
                    "missingAuthorities": list(acquisition_lock.get("missingAuthorities", [])),
                    "lockDigest": lock_digest,
                    "managementWorkloadImagePlan": _management_workload_image_plan_projection(artifact, version, artifact_sha, acquisition_lock),
                }
            except RuntimeError as exc:
                bundle_acquisition = {"authority": BUNDLE_ACQUISITION_AUTHORITY, "status": "invalid", "missingAuthorities": [BUNDLE_SOURCE_LOCKS_BLOCKER], "error": _tail(str(exc), 1000)}
        management_roles = [r for r in _roles_for_tier(tier) if r.startswith("management")]
        active_install_row = "M01" if len(management_roles) == 1 else "M02"
        active_rows = {"M00", active_install_row}
        if tier == "production-ha":
            active_rows.add("M03")
        matrix = [row for row in program_guide["matrix"] if row["id"] in active_rows]
        return {
            "authority": "LAB_EXECUTION_PLAN_V1",
            "releaseArtifactAuthority": EXACT_RELEASE_SNAPSHOT_AUTHORITY,
            "releaseExecutionAuthority": EXACT_RELEASE_EXECUTION_AUTHORITY,
            "serverTier": tier,
            "releaseSha256": artifact_sha,
            "serverInventoryDigest": _server_inventory_digest(body),
            "servers": _server_map(body),
            "managementRoles": management_roles,
            "matrixRows": matrix,
            "fullProgramMatrix": program_guide["matrix"],
            "runnerCoverage": program_guide.get("runner", {}),
            "deterministicRunner": True,
            "ai": {"mode": "failure-only", "canDecidePass": False, "canDecidePhysicalPass": False},
            "bundleAuthority": "provided-and-verified" if body.get("bundleDirectory") else BUNDLE_ACQUISITION_AUTHORITY,
            "bundleAcquisition": bundle_acquisition,
        }


def _ssh_command(body: dict[str, Any], host: str, remote: str) -> list[str]:
    ssh = body["ssh"]
    return [
        "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={Path(ssh['knownHostsFile']).expanduser()}",
        "-o", "ConnectTimeout=10", "-i", str(Path(ssh["identityFile"]).expanduser()),
        "--", f"root@{host}", "sh", "-ceu", shlex.quote(remote),
    ]


def _run(stage: str, command: list[str], *, cwd: Path, timeout: int, env: dict[str, str] | None = None, input_text: str | None = None) -> dict[str, Any]:
    started = time.monotonic()
    try:
        proc = subprocess.run(command, cwd=cwd, text=True, input=input_text, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=env)
        output = proc.stdout or ""
        rc = proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + "\nTIMEOUT"
        rc = 124
    except OSError as exc:
        output, rc = str(exc), 127
    return {
        "stage": stage, "command": command, "returnCode": rc, "durationSeconds": round(time.monotonic() - started, 3),
        "outputTail": _tail(output), "fingerprint": _fingerprint(stage, rc, output), "status": "PASS" if rc == 0 else "FAIL",
    }


def failure_packet(result: dict[str, Any], *, artifact_sha: str, server_role: str = "", facts: list[str] | None = None, byte_limit: int = DEFAULT_PACKET_BYTES) -> dict[str, Any]:
    packet = {
        "schemaVersion": 1, "artifactSha256": artifact_sha, "stage": result["stage"], "returnCode": result["returnCode"],
        "fingerprint": result["fingerprint"], "serverRole": server_role, "command": result["command"],
        "outputTail": result["outputTail"], "facts": facts or [],
        "constraints": ["AI does not decide PASS", "AI does not decide Physical PASS", "recommend owner-layer checks; do not invent evidence"],
    }
    packet, redaction_count = _redact_ai_value(packet)
    packet["redactionCount"] = redaction_count
    byte_limit = max(2048, min(int(byte_limit), MAX_PACKET_BYTES))
    while len(json.dumps(packet, separators=(",", ":")).encode()) > byte_limit and len(packet["outputTail"]) > 512:
        packet["outputTail"] = packet["outputTail"][len(packet["outputTail"]) // 4 :]
    return packet


def _platformctl_for_ai(cwd: Path) -> Path:
    candidates = [cwd / "bin" / "linux-amd64" / "platformctl", ROOT / "bin" / "linux-amd64" / "platformctl"]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError("platformctl AI runtime binary is unavailable")


def _diagnosis_prompt(packet: dict[str, Any]) -> str:
    return (
        "Diagnose this deterministic 4SO Platform Factory lab failure. Return ONLY one JSON object with keys "
        "classification (product-defect|test-defect|environment|supply-chain|unknown), summary, owner, recommendedChecks (array max 5), "
        "recommendedFix, confidence (0-100). Do not claim PASS or Physical PASS. Packet:\n" + json.dumps(packet, separators=(",", ":"))
    )


def _diagnosis_schema() -> dict[str, Any]:
    return {
        "type": "object", "additionalProperties": False,
        "required": ["classification", "summary", "owner", "recommendedChecks", "recommendedFix", "confidence"],
        "properties": {
            "classification": {"enum": ["product-defect", "test-defect", "environment", "supply-chain", "unknown"]},
            "summary": {"type": "string"}, "owner": {"type": "string"},
            "recommendedChecks": {"type": "array", "maxItems": 5, "items": {"type": "string"}},
            "recommendedFix": {"type": "string"},
            "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
        },
    }


def _validate_diagnosis(raw: str) -> dict[str, Any]:
    raw = raw.strip()
    if raw.startswith("```"):
        raise ValueError("AI output must be strict JSON without markdown")
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("classification") not in {"product-defect", "test-defect", "environment", "supply-chain", "unknown"}:
        raise ValueError("invalid diagnosis classification")
    checks = value.get("recommendedChecks", [])
    if not isinstance(checks, list) or len(checks) > 5:
        raise ValueError("recommendedChecks must contain at most five entries")
    if not isinstance(value.get("confidence"), int) or not 0 <= value["confidence"] <= 100:
        raise ValueError("confidence must be 0-100")
    return value


def diagnose(packet: dict[str, Any], config: dict[str, Any] | None, *, cwd: Path) -> dict[str, Any]:
    config = config or {}
    provider = str(config.get("provider", "none")).strip() or "none"
    if provider == "none":
        return {"status": "SKIPPED", "provider": "none"}
    packet, additional_redactions = _redact_ai_value(packet)
    if additional_redactions:
        packet["redactionCount"] = int(packet.get("redactionCount", 0)) + additional_redactions
    prompt = _diagnosis_prompt(packet)
    max_tokens = min(int(config.get("maxOutputTokens", DEFAULT_OUTPUT_TOKENS)), MAX_OUTPUT_TOKENS)
    try:
        if provider == "codex-cli":
            command = os.environ.get("PLATFORM_FACTORY_CODEX_COMMAND", "").strip()
            argv = shlex.split(command) if command else ["codex", "exec", "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only"]
            proc = subprocess.run(argv + [prompt], cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
            if proc.returncode:
                raise RuntimeError(_tail(proc.stdout or ""))
            parsed = _validate_diagnosis(proc.stdout)
        elif provider == "claude-code":
            schema = _diagnosis_schema()
            argv = ["claude", "-p", "--bare", "--no-session-persistence", "--output-format", "json", "--json-schema", json.dumps(schema), "--max-turns", str(min(int(config.get("maxTurns",2)),4))]
            budget = float(config.get("maxBudgetUSD", 1.0))
            if budget > 0:
                argv += ["--max-budget-usd", str(min(budget,20.0))]
            proc = subprocess.run(argv + [prompt], cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
            if proc.returncode:
                raise RuntimeError(_tail(proc.stdout or ""))
            envelope = json.loads(proc.stdout)
            candidate = envelope.get("structured_output") or envelope.get("result") or envelope
            parsed = candidate if isinstance(candidate, dict) else _validate_diagnosis(str(candidate))
            parsed = _validate_diagnosis(json.dumps(parsed))
        elif provider in {"openai-responses", "openai-compatible-chat"}:
            endpoint = str(config.get("endpoint", "")).strip()
            api_env = str(config.get("apiKeyEnv", "PLATFORM_FACTORY_AI_API_KEY"))
            api_key = os.environ.get(api_env, "").strip()
            model = str(config.get("model", "")).strip() or os.environ.get("PLATFORM_FACTORY_AI_MODEL", "").strip()
            if not model:
                raise RuntimeError("AI model is not configured")
            env = os.environ.copy()
            env["PLATFORM_FACTORY_AI_PROVIDER"] = provider
            env["PLATFORM_FACTORY_AI_MODEL"] = model
            env["PLATFORM_FACTORY_AI_MAX_OUTPUT_TOKENS"] = str(max_tokens)
            env["PLATFORM_FACTORY_AI_MAX_INPUT_BYTES"] = str(min(MAX_PACKET_BYTES, max(DEFAULT_PACKET_BYTES, int(config.get("maxInputBytes", MAX_PACKET_BYTES)))))
            if endpoint:
                env["PLATFORM_FACTORY_AI_ENDPOINT"] = endpoint
            if api_key:
                env["PLATFORM_FACTORY_AI_API_KEY"] = api_key
            with tempfile.TemporaryDirectory(prefix="4so-ai-packet-") as td:
                packet_path = Path(td) / "failure-packet.json"
                packet_path.write_text(json.dumps(packet, separators=(",", ":")), encoding="utf-8")
                packet_path.chmod(0o600)
                platformctl = _platformctl_for_ai(cwd)
                proc = subprocess.run([str(platformctl), "ai", "diagnose", "-f", str(packet_path)], cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            if proc.returncode:
                raise RuntimeError(_tail(proc.stdout or ""))
            envelope = json.loads(proc.stdout)
            parsed = envelope.get("diagnosis")
            if not isinstance(parsed, dict):
                raise RuntimeError("platformctl AI runtime did not return a diagnosis")
            parsed = _validate_diagnosis(json.dumps(parsed))
            return {"status": "OK", "provider": provider, "diagnosis": parsed, "runtime": envelope.get("runtime", {})}
        elif provider == "antigravity-command":
            command = str(config.get("command", "")).strip() or os.environ.get("PLATFORM_FACTORY_ANTIGRAVITY_COMMAND", "").strip()
            if not command:
                raise RuntimeError("Antigravity command adapter is not configured")
            proc = subprocess.run(shlex.split(command), cwd=cwd, input=prompt, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
            if proc.returncode:
                raise RuntimeError(_tail(proc.stdout or ""))
            parsed = _validate_diagnosis(proc.stdout)
        else:
            raise RuntimeError(f"unsupported AI provider: {provider}")
        return {"status": "OK", "provider": provider, "diagnosis": parsed}
    except Exception as exc:
        return {"status": "BLOCKED", "provider": provider, "error": _tail(str(exc), 2000)}


def _write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".tmp.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as out:
            out.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
            out.flush()
            os.fsync(out.fileno())
        os.close(fd)
        fd = -1
        os.replace(tmp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _sanitize_private_stage_output(output: str) -> str:
    output = re.sub(r"(?m)^M03_PASSWORD=.*$", "M03_PASSWORD=[REDACTED]", output)
    output = re.sub(r"(?m)^M03_CA_B64=.*$", "M03_CA_B64=[OMITTED]", output)
    clean, _ = _redact_ai_value(output)
    return _tail(str(clean))


def _run_private_ssh(stage: str, body: dict[str, Any], host: str, remote: str, *, timeout: int) -> tuple[subprocess.CompletedProcess[str] | None, dict[str, Any]]:
    command = _ssh_command(body, host, remote)
    started = time.monotonic()
    try:
        proc = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
        safe = _sanitize_private_stage_output(proc.stdout or "")
        result = {"stage":stage,"command":["credential-private-ssh",f"root@{host}"],"returnCode":proc.returncode,"durationSeconds":round(time.monotonic()-started,3),"outputTail":safe,"fingerprint":_fingerprint(stage,proc.returncode,safe),"status":"PASS" if proc.returncode == 0 else "FAIL"}
        return proc, result
    except subprocess.TimeoutExpired as exc:
        raw = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        safe = _sanitize_private_stage_output(raw + "\nTIMEOUT")
        return None, {"stage":stage,"command":["credential-private-ssh",f"root@{host}"],"returnCode":124,"durationSeconds":round(time.monotonic()-started,3),"outputTail":safe,"fingerprint":_fingerprint(stage,124,safe),"status":"FAIL"}
    except OSError as exc:
        safe = _tail(str(exc))
        return None, {"stage":stage,"command":["credential-private-ssh",f"root@{host}"],"returnCode":127,"durationSeconds":round(time.monotonic()-started,3),"outputTail":safe,"fingerprint":_fingerprint(stage,127,safe),"status":"FAIL"}


def _parse_m03_bootstrap_output(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if not line.startswith("M03_") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip()
    required = {"M03_ROLE", "M03_DATABASE", "M03_PASSWORD", "M03_SERVICE_IP", "M03_CA_B64"}
    missing = sorted(required - set(values))
    if missing:
        raise ValueError("M03 private bootstrap output is incomplete: " + ",".join(missing))
    if not re.fullmatch(r"pf_cert_[0-9a-f]{16}", values["M03_ROLE"]):
        raise ValueError("M03 generated role identity is invalid")
    if values["M03_DATABASE"] != values["M03_ROLE"]:
        raise ValueError("M03 generated database must be owned under the same unique certification identity")
    if not re.fullmatch(r"[0-9a-f]{48}", values["M03_PASSWORD"]):
        raise ValueError("M03 generated password shape is invalid")
    try:
        ipaddress.ip_address(values["M03_SERVICE_IP"])
    except ValueError as exc:
        raise ValueError("M03 PostgreSQL service did not expose a routable ClusterIP") from exc
    try:
        ca = base64.b64decode(values["M03_CA_B64"], validate=True)
    except Exception as exc:
        raise ValueError("M03 PostgreSQL CA payload is not valid base64") from exc
    if b"-----BEGIN CERTIFICATE-----" not in ca or b"-----END CERTIFICATE-----" not in ca:
        raise ValueError("M03 PostgreSQL CA payload is not a PEM certificate")
    return values


def _read_stable_m03_evidence(path: Path) -> tuple[dict[str, Any], str]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"M03 evidence is missing: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > 2 * 1024 * 1024:
        raise RuntimeError("M03 evidence must be a non-empty regular non-symlink file no larger than 2 MiB")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise RuntimeError("M03 evidence changed while opening")
        with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
            raw = stream.read(2 * 1024 * 1024 + 1)
        after = os.fstat(fd)
        if len(raw) > 2 * 1024 * 1024 or len(raw) != opened.st_size or not _same_open_file_state(opened, after):
            raise RuntimeError("M03 evidence changed while reading")
    finally:
        os.close(fd)
    value = _strict_json_value(raw, label="M03 PostgreSQL runtime evidence")
    if not isinstance(value, dict):
        raise RuntimeError("M03 PostgreSQL runtime evidence must be a JSON object")
    return value, "sha256:" + hashlib.sha256(raw).hexdigest()


def _validate_m03_evidence(path: Path, artifact_sha: str) -> tuple[bool, str, str]:
    try:
        evidence, file_digest = _read_stable_m03_evidence(path)
    except (OSError, RuntimeError) as exc:
        return False, f"invalid M03 evidence: {exc}", ""
    supplied = str(evidence.get("evidenceDigest", ""))
    unsigned = dict(evidence)
    unsigned.pop("evidenceDigest", None)
    calculated = "sha256:" + hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    checks = evidence.get("checks") if isinstance(evidence.get("checks"), list) else []
    failed = [str(item.get("name", "unknown")) for item in checks if isinstance(item, dict) and item.get("status") != "PASS"]
    expected_release_digest = "sha256:" + artifact_sha
    if evidence.get("schemaVersion") != 2 or evidence.get("releaseEvidenceAuthority") != M03_EXACT_RELEASE_EVIDENCE_AUTHORITY or evidence.get("releaseArtifactDigest") != expected_release_digest:
        return False, "M03 evidence is not bound to the exact release artifact", file_digest
    if evidence.get("mode") != "runtime" or evidence.get("status") != "PASS" or evidence.get("runtimeCertified") is not True:
        return False, f"M03 evidence did not certify runtime; status={evidence.get('status')} runtimeCertified={evidence.get('runtimeCertified')} failed={failed}", file_digest
    if evidence.get("aiRunPostgresDurabilityAuthority") != AI_RUN_POSTGRES_DURABILITY_AUTHORITY or evidence.get("aiRunPostgresDurabilityCertified") is not True:
        return False, "M03 evidence did not certify durable PostgreSQL AI run/dispatch authority", file_digest
    required_ai_checks = {"ai-run-atomic-result-commit", "ai-run-post-restart-durability", "ai-run-post-restore-durability"}
    passed_ai_checks = {str(item.get("name")) for item in checks if isinstance(item, dict) and item.get("status") == "PASS"}
    if not required_ai_checks.issubset(passed_ai_checks):
        return False, "M03 evidence is missing mandatory AI PostgreSQL durability checks", file_digest
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", supplied) or supplied != calculated:
        return False, "M03 evidence digest mismatch", file_digest
    encoded = json.dumps(evidence, sort_keys=True)
    if re.search(r"postgres(?:ql)?://[^:/\s]+:[^*@/\s]+@", encoded, flags=re.I) or re.search(r"(?i)password\s*=\s*(?!\*\*\*)[^\s\"']+", encoded):
        return False, "M03 evidence contains an unredacted PostgreSQL credential", file_digest
    mandatory = [item for item in checks if isinstance(item, dict)]
    if not mandatory or any(item.get("status") != "PASS" for item in mandatory):
        return False, "M03 runtime evidence contains a non-PASS check", file_digest
    return True, f"runtimeCertified=true evidenceDigest={supplied} fileDigest={file_digest} checks={len(mandatory)}", file_digest


def _m03_certifier_private_transport(base_env: dict[str, str], dsn: str, admin_dsn: str) -> tuple[dict[str, str], str]:
    env = dict(base_env)
    env.pop("POSTGRES_CERT_DSN", None)
    env.pop("POSTGRES_CERT_ADMIN_DSN", None)
    payload = json.dumps({"dsn": dsn, "adminDsn": admin_dsn}, sort_keys=True, separators=(",", ":"))
    return env, payload


def _m03_remote_cleanup(body: dict[str, Any], host: str, role: str) -> dict[str, Any]:
    if not re.fullmatch(r"pf_cert_[0-9a-f]{16}", role):
        detail = "refusing M03 cleanup for an unbound role identity"
        return {"stage":"M03-postgresql-cleanup","command":["owned-certification-resource-cleanup"],"returnCode":4,"durationSeconds":0,"outputTail":detail,"fingerprint":_fingerprint("M03-postgresql-cleanup",4,detail),"status":"FAIL"}
    remote = rf'''K=/var/lib/rancher/rke2/bin/kubectl
KC=/etc/rancher/rke2/rke2.yaml
pod="$($K --kubeconfig "$KC" -n platform-system get cluster.postgresql.cnpg.io/platform-postgresql -o jsonpath='{{.status.currentPrimary}}')"
test -n "$pod"
$K --kubeconfig "$KC" -n platform-system exec -i "$pod" -- psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres -v role={shlex.quote(role)} <<'SQL'
SELECT pg_terminate_backend(a.pid)
FROM pg_stat_activity a
WHERE a.pid <> pg_backend_pid()
  AND a.datname IN (
    SELECT d.datname FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE r.rolname=:'role'
  );
SELECT format('DROP DATABASE %I WITH (FORCE)', d.datname)
FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba
WHERE r.rolname=:'role'
ORDER BY d.datname
\gexec
SELECT format('DROP ROLE %I', rolname) FROM pg_roles WHERE rolname=:'role'
\gexec
SQL
'''
    _, result = _run_private_ssh("M03-postgresql-cleanup", body, host, remote, timeout=180)
    if result["status"] == "PASS":
        result["command"] = ["owned-certification-resource-cleanup"]
        result["outputTail"] = "ephemeral M03 databases and role removed by unique owner identity"
        result["fingerprint"] = _fingerprint(result["stage"], 0, result["outputTail"])
    return result


def _execute_m03_postgresql(body: dict[str, Any], release_root: Path, state_dir: Path, artifact_sha: str, primary_role: str, primary_host: str) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    missing_tools = [tool for tool in _M03_REQUIRED_TOOLS if shutil.which(tool) is None]
    if missing_tools:
        detail = "M03 blocked: missing local PostgreSQL client tools: " + ",".join(missing_tools)
        result = {"stage":"M03-postgresql-client-preflight","command":["postgresql-client-tool-check"],"returnCode":2,"durationSeconds":0,"outputTail":detail,"fingerprint":_fingerprint("M03-postgresql-client-preflight",2,detail),"status":"BLOCKED"}
        return {"status":"BLOCKED","results":[result],"evidence":"","runtimeCertified":False}

    remote = r'''K=/var/lib/rancher/rke2/bin/kubectl
KC=/etc/rancher/rke2/rke2.yaml
pod="$($K --kubeconfig "$KC" -n platform-system get cluster.postgresql.cnpg.io/platform-postgresql -o jsonpath='{.status.currentPrimary}')"
test -n "$pod"
service_ip="$($K --kubeconfig "$KC" -n platform-system get svc/platform-postgresql-rw -o jsonpath='{.spec.clusterIP}')"
server_ca_secret="$($K --kubeconfig "$KC" -n platform-system get cluster.postgresql.cnpg.io/platform-postgresql -o jsonpath='{.status.certificates.serverCASecret}')"
test -n "$server_ca_secret"
ca_b64="$($K --kubeconfig "$KC" -n platform-system get secret/"$server_ca_secret" -o jsonpath='{.data.ca\.crt}')"
suffix="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
role="pf_cert_${suffix}"
database="$role"
password="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
$K --kubeconfig "$KC" -n platform-system exec -i "$pod" -- psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres -v role="$role" -v database="$database" -v password="$password" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN CREATEDB PASSWORD %L', :'role', :'password')
\gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'database', :'role')
\gexec
SQL
printf 'M03_ROLE=%s\nM03_DATABASE=%s\nM03_PASSWORD=%s\nM03_SERVICE_IP=%s\nM03_CA_B64=%s\n' "$role" "$database" "$password" "$service_ip" "$ca_b64"
'''
    proc, bootstrap = _run_private_ssh("M03-postgresql-credential-bootstrap", body, primary_host, remote, timeout=180)
    results.append(bootstrap)
    if proc is None or bootstrap["status"] != "PASS":
        return {"status":"FAIL","results":results,"evidence":"","runtimeCertified":False}

    private: dict[str, str] = {}
    role = ""
    try:
        private = _parse_m03_bootstrap_output(proc.stdout or "")
        role = private["M03_ROLE"]
    except ValueError as exc:
        detail = str(exc)
        parse_result = {"stage":"M03-postgresql-private-bootstrap-verify","command":["verify-private-bootstrap-contract"],"returnCode":4,"durationSeconds":0,"outputTail":detail,"fingerprint":_fingerprint("M03-postgresql-private-bootstrap-verify",4,detail),"status":"FAIL"}
        results.append(parse_result)
        for line in (proc.stdout or "").splitlines():
            if line.startswith("M03_ROLE="):
                candidate = line.split("=",1)[1].strip()
                if re.fullmatch(r"pf_cert_[0-9a-f]{16}", candidate):
                    role = candidate
                    break
        if role:
            results.append(_m03_remote_cleanup(body, primary_host, role))
        return {"status":"FAIL","results":results,"evidence":"","runtimeCertified":False}

    ca_path = state_dir / "m03-postgresql-ca.crt"
    ca_path.write_bytes(base64.b64decode(private["M03_CA_B64"], validate=True))
    ca_path.chmod(0o600)
    local_port = _find_free_port()
    ssh = body["ssh"]
    tunnel_cmd = ["ssh","-N","-o","ExitOnForwardFailure=yes","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o",f"UserKnownHostsFile={Path(ssh['knownHostsFile']).expanduser()}","-i",str(Path(ssh["identityFile"]).expanduser()),"-L",f"127.0.0.1:{local_port}:{private['M03_SERVICE_IP']}:5432",f"root@{primary_host}"]
    tunnel = subprocess.Popen(tunnel_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    evidence_path = state_dir / "m03-postgresql-runtime-certification.json"
    runtime_ok = False
    try:
        tunnel_ready = False
        deadline = time.time() + 30
        while time.time() < deadline:
            if tunnel.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", local_port), timeout=1):
                    tunnel_ready = True
                    detail = f"credential-private SSH tunnel established to installed platform-postgresql-rw service via {primary_role}"
                    results.append({"stage":"M03-postgresql-tunnel","command":["credential-private-ssh-tunnel",f"root@{primary_host}"],"returnCode":0,"durationSeconds":0,"outputTail":detail,"fingerprint":_fingerprint("M03-postgresql-tunnel",0,detail),"status":"PASS"})
                    break
            except OSError:
                time.sleep(.25)
        if not tunnel_ready:
            raw = tunnel.stdout.read() if tunnel.stdout and tunnel.poll() is not None else ""
            safe = _sanitize_private_stage_output(raw)
            failed = {"stage":"M03-postgresql-tunnel","command":["credential-private-ssh-tunnel",f"root@{primary_host}"],"returnCode":1,"durationSeconds":30,"outputTail":safe or "SSH PostgreSQL tunnel did not become reachable","fingerprint":_fingerprint("M03-postgresql-tunnel",1,safe),"status":"FAIL"}
            results.append(failed)
            return {"status":"FAIL","results":results,"evidence":"","runtimeCertified":False}

        host = "platform-postgresql-rw.platform-system.svc"
        user = urllib.parse.quote(private["M03_ROLE"], safe="")
        password = urllib.parse.quote(private["M03_PASSWORD"], safe="")
        database = urllib.parse.quote(private["M03_DATABASE"], safe="")
        ca_query = urllib.parse.quote(str(ca_path), safe="/")
        dsn = f"postgresql://{user}:{password}@{host}:{local_port}/{database}?sslmode=verify-full&sslrootcert={ca_query}"
        admin_dsn = f"postgresql://{user}:{password}@{host}:{local_port}/postgres?sslmode=verify-full&sslrootcert={ca_query}"
        restart_remote = r'''K=/var/lib/rancher/rke2/bin/kubectl
KC=/etc/rancher/rke2/rke2.yaml
pod="$($K --kubeconfig "$KC" -n platform-system get cluster.postgresql.cnpg.io/platform-postgresql -o jsonpath='{.status.currentPrimary}')"
test -n "$pod"
$K --kubeconfig "$KC" -n platform-system delete pod "$pod" --wait=false
'''
        restart_command = shlex.join(_ssh_command(body, primary_host, restart_remote))
        env, private_connection = _m03_certifier_private_transport(os.environ, dsn, admin_dsn)
        env["ALLOW_DESTRUCTIVE_POSTGRES_CERTIFICATION"] = "1"
        env["POSTGRES_CERT_RESTART_COMMAND"] = restart_command
        env["PGHOSTADDR"] = "127.0.0.1"
        cert = _run(
            "M03-postgresql-runtime-certification",
            [sys.executable, str(release_root / "scripts" / "postgresql_runtime_certify.py"), "--connection-json-stdin", "--evidence", str(evidence_path), "--release-artifact-digest", "sha256:" + artifact_sha],
            cwd=release_root, timeout=1800, env=env, input_text=private_connection,
        )
        results.append(cert)
        if cert["status"] != "PASS":
            return {"status":"FAIL","results":results,"evidence":str(evidence_path) if evidence_path.is_file() else "","runtimeCertified":False}
        valid, detail, evidence_file_digest = _validate_m03_evidence(evidence_path, artifact_sha)
        evidence_result = {"stage":"M03-postgresql-runtime-evidence-verify","command":["verify-sealed-runtime-evidence"],"returnCode":0 if valid else 4,"durationSeconds":0,"outputTail":detail,"fingerprint":_fingerprint("M03-postgresql-runtime-evidence-verify",0 if valid else 4,detail),"status":"PASS" if valid else "FAIL"}
        results.append(evidence_result)
        if not valid:
            return {"status":"FAIL","results":results,"evidence":str(evidence_path),"evidenceFileDigest":evidence_file_digest,"releaseEvidenceAuthority":M03_EXACT_RELEASE_EVIDENCE_AUTHORITY,"runtimeCertified":False}
        recovery = _ha_runtime_probe(body, primary_role, primary_host, minimum_nodes=3, require_full_recovery=True, timeout=600)
        recovery["stage"] = "M03-postgresql-api-runtime-recovery"
        results.append(recovery)
        if recovery["status"] != "PASS":
            return {"status":"FAIL","results":results,"evidence":str(evidence_path),"evidenceFileDigest":evidence_file_digest,"releaseEvidenceAuthority":M03_EXACT_RELEASE_EVIDENCE_AUTHORITY,"runtimeCertified":False}
        runtime_ok = True
    finally:
        cleanup = _m03_remote_cleanup(body, primary_host, role)
        results.append(cleanup)
        tunnel.terminate()
        try:
            tunnel.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tunnel.kill()
        private.clear()
    if results[-1]["status"] != "PASS":
        runtime_ok = False
    return {"status":"PASS" if runtime_ok else "FAIL","results":results,"evidence":str(evidence_path) if evidence_path.is_file() else "","evidenceFileDigest":evidence_file_digest if evidence_path.is_file() else "","releaseEvidenceAuthority":M03_EXACT_RELEASE_EVIDENCE_AUTHORITY,"runtimeCertified":runtime_ok}


def _preflight(spec: dict[str, Any], *, require_bundle: bool, bundle_state_dir: Path | None = None) -> dict[str, Any]:
    body = validate_spec(spec, require_bundle=require_bundle)
    artifact = Path(body["releaseArtifact"]).expanduser().resolve()
    _, version, artifact_sha = _release_identity(artifact)
    results = []
    verify = _run("M00-release-verify", [sys.executable, str(ROOT / "scripts" / "verify_release.py"), str(artifact)], cwd=ROOT, timeout=900)
    results.append(verify)
    if verify["status"] != "PASS":
        return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(verify, artifact_sha=artifact_sha), body.get("ai"), cwd=ROOT)}
    resolved_bundle: Path | None = None
    bundle_binding: dict[str, Any] | None = None
    if require_bundle:
        extracted = Path(tempfile.mkdtemp(prefix="4so-lab-preflight-"))
        ephemeral_acquisition = bundle_state_dir is None
        acquisition_state = bundle_state_dir or Path(tempfile.mkdtemp(prefix="4so-lab-bundle-acquisition-"))
        try:
            release_root = _safe_extract(artifact, extracted, expected_sha256=artifact_sha)
            platformctl = release_root / "bin" / "linux-amd64" / "platformctl"
            if body.get("bundleDirectory"):
                resolved_bundle = Path(body["bundleDirectory"]).expanduser().resolve()
                bundle_result = _run("bundle-verify", [str(platformctl), "appliance-bundle", "verify", "--dir", str(resolved_bundle)], cwd=release_root, timeout=300)
                results.append(bundle_result)
                binding_ok, binding_detail = _bundle_verify_binding(bundle_result, version=version, artifact_sha=artifact_sha)
                if bundle_result["status"] != "PASS" or not binding_ok:
                    binding_result = {"stage":"bundle-release-binding","command":["exact-release-bundle-binding"],"returnCode":2,"durationSeconds":0,"outputTail":binding_detail,"fingerprint":_fingerprint("bundle-release-binding",2,binding_detail),"status":"FAIL"}
                    results.append(binding_result)
                    return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(binding_result, artifact_sha=artifact_sha, facts=["bundle must be immutable, digest locked and bound to this exact release version/SHA"]), body.get("ai"), cwd=release_root)}
                details = _bundle_verify_details(bundle_result)
                bundle_binding = {
                    "mode": "provided",
                    "bundleDigest": str(details["bundleDigest"]),
                    "bundleLockDigest": str(details["lockDigest"]),
                }
            else:
                resolved_bundle, acquisition = _auto_acquire_bundle(body, artifact, release_root, acquisition_state)
                results.append(acquisition)
                if resolved_bundle is None:
                    return {"status":acquisition.get("status","BLOCKED"),"version":version,"artifactSha256":artifact_sha,"serverInventoryDigest":_server_inventory_digest(body),"results":results,"blocker":acquisition.get("blocker",BUNDLE_SOURCE_LOCKS_BLOCKER),"missingAuthorities":list(acquisition.get("missingAuthorities",[])),"physicalPass":False}
                bundle_binding = {
                    "mode": "automatic",
                    "bundleDigest": str(acquisition["bundleDigest"]),
                    "bundleLockDigest": str(acquisition["bundleLockDigest"]),
                    "acquisitionLockDigest": str(acquisition["acquisitionLockDigest"]),
                    "inputPackDigest": str(acquisition["inputPackDigest"]),
                    "sourceBindingDigest": str(acquisition["sourceBindingDigest"]),
                }
        finally:
            shutil.rmtree(extracted, ignore_errors=True)
            if ephemeral_acquisition:
                shutil.rmtree(acquisition_state, ignore_errors=True)
    management_roles = _management_roles(body["serverTier"])
    server_map = _server_map(body)
    for role in management_roles:
        host = server_map[role]
        remote = r'''test "$(id -u)" -eq 0
command -v systemctl >/dev/null
command -v awk >/dev/null
command -v df >/dev/null
arch=$(uname -m)
cpu=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc)
mem_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
disk_kib=$(df -Pk /var/lib | awk 'NR==2 {print $4}')
printf 'LAB_HOST_FACTS arch=%s cpu=%s mem_kib=%s disk_kib=%s\n' "$arch" "$cpu" "$mem_kib" "$disk_kib"
test -w /var/lib'''
        result = _run(f"ssh-preflight:{role}", _ssh_command(body, host, remote), cwd=ROOT, timeout=30)
        results.append(result)
        if result["status"] != "PASS":
            return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(result, artifact_sha=artifact_sha, server_role=role), body.get("ai"), cwd=ROOT)}
        match = re.search(r"LAB_HOST_FACTS arch=(\S+) cpu=(\d+) mem_kib=(\d+) disk_kib=(\d+)", result["outputTail"])
        if not match:
            resource_result = {**result, "stage": f"resource-preflight:{role}", "returnCode": 2, "status": "FAIL", "outputTail": _tail(result["outputTail"] + "\nmissing parseable LAB_HOST_FACTS")}
            return {"status":"FAIL","artifactSha256":artifact_sha,"results":results+[resource_result],"ai":diagnose(failure_packet(resource_result, artifact_sha=artifact_sha, server_role=role), body.get("ai"), cwd=ROOT)}
        arch, cpu, mem_kib, disk_kib = match.group(1), int(match.group(2)), int(match.group(3)), int(match.group(4))
        minimums = {"cpu": 4, "memKiB": 16 * 1024 * 1024, "diskKiB": 100 * 1024 * 1024}
        resource_status = "PASS" if arch in {"x86_64", "aarch64", "arm64"} and cpu >= minimums["cpu"] and mem_kib >= minimums["memKiB"] and disk_kib >= minimums["diskKiB"] else "FAIL"
        resource_result = {"stage": f"resource-preflight:{role}", "command": ["deterministic-host-facts"], "returnCode": 0 if resource_status == "PASS" else 3, "durationSeconds": 0, "outputTail": f"arch={arch} cpu={cpu} memKiB={mem_kib} freeDiskKiB={disk_kib}; required cpu>=4 memGiB>=16 freeDiskGiB>=100", "fingerprint": _fingerprint(f"resource-preflight:{role}", 0 if resource_status == "PASS" else 3, f"{arch}:{cpu}:{mem_kib}:{disk_kib}"), "status": resource_status}
        results.append(resource_result)
        if resource_status != "PASS":
            return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(resource_result, artifact_sha=artifact_sha, server_role=role), body.get("ai"), cwd=ROOT)}
    if body["serverTier"] == "production-ha":
        missing_tools = [tool for tool in _M03_REQUIRED_TOOLS if shutil.which(tool) is None]
        detail = "M03 local PostgreSQL clients available: " + ",".join(_M03_REQUIRED_TOOLS) if not missing_tools else "M03 blocked: missing local PostgreSQL clients: " + ",".join(missing_tools)
        client_result = {"stage":"M03-postgresql-client-preflight","command":["postgresql-client-tool-check"],"returnCode":0 if not missing_tools else 2,"durationSeconds":0,"outputTail":detail,"fingerprint":_fingerprint("M03-postgresql-client-preflight",0 if not missing_tools else 2,detail),"status":"PASS" if not missing_tools else "BLOCKED"}
        results.append(client_result)
        if missing_tools:
            return {"status":"BLOCKED","version":version,"artifactSha256":artifact_sha,"serverInventoryDigest":_server_inventory_digest(body),"results":results,"blocker":"M03_POSTGRESQL_CLIENT_TOOLS_MISSING","physicalPass":False}
    deferred_roles = [role for role in _roles_for_tier(body["serverTier"]) if role not in management_roles]
    response = {"status":"PASS","version":version,"artifactSha256":artifact_sha,"releaseArtifactAuthority":EXACT_RELEASE_SNAPSHOT_AUTHORITY,"releaseExecutionAuthority":EXACT_RELEASE_EXECUTION_AUTHORITY,"serverInventoryDigest":_server_inventory_digest(body),"results":results,"preflightCoverage":"MANAGEMENT_HOSTS_EXACT_ARTIFACT_AND_APPLICABLE_PHASE_C_RUNTIME","deferredTargetRoles":deferred_roles,"physicalPass":False}
    if require_bundle and resolved_bundle is not None and bundle_state_dir is not None:
        response["resolvedBundleDirectory"] = str(resolved_bundle)
        response["bundleAuthority"] = "provided-and-verified" if body.get("bundleDirectory") else BUNDLE_ACQUISITION_AUTHORITY
        if bundle_binding is None:
            raise SystemExit("successful Lab preflight did not retain immutable bundle binding")
        response["bundleBinding"] = bundle_binding
        response["bundleExecutionAuthority"] = REMOTE_BOOTSTRAP_EXPECTED_BUNDLE_AUTHORITY
    return response


def _management_roles(tier: str) -> list[str]:
    return [r for r in _roles_for_tier(tier) if r.startswith("management")]


def _install_request(body: dict[str, Any]) -> dict[str, Any]:
    roles = _management_roles(body["serverTier"])
    hosts = [_server_map(body)[r] for r in roles]
    mgmt = body.get("management") or {}
    ha = len(hosts) == 3
    public = str(mgmt.get("publicEndpoint", "")).strip() or f"https://{hosts[0]}"
    req: dict[str, Any] = {
        "profileId": "production-standard-ha" if ha else "evaluation-single-node",
        # Phase D certifies installation from the exact verified appliance bundle.
        # Keep the executable request disconnected so M01/M02 cannot silently
        # substitute unbound upstream bytes during the physical run.
        "connectivity": "disconnected",
        "infrastructure": {"provider":"existing-hosts","existingCluster":False,"nodeAddresses":hosts,"credentialRef":"secret://installer/ssh-private-key","sshUser":"root"},
        "network": {"publicEndpoint":public,"dnsZone":str(mgmt.get("dnsZone", "")).strip().rstrip("."),"tlsMode":"managed-private-ca" if ha else "bootstrap-self-signed"},
        "services": {"git":{},"registry":{},"database":{},"objectStorage":{},"identity":{"adminEmail":str(mgmt.get("adminEmail", "")).strip()}},
        "acceptRisk": True,
    }
    if ha:
        req["infrastructure"]["storageClass"] = str(mgmt.get("storageClass", "replicated-rwx"))
        obj = mgmt.get("objectStorage") or {}
        req["services"]["objectStorage"] = {"mode":"external","provider":"s3-compatible", **{k:v for k,v in obj.items() if v not in (None,"")}}
    return req


def _read_private_installer_token(path: Path, *, require_read_only: bool) -> tuple[str, str]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"installer access token is unavailable: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size < 32 or before.st_size > 4096:
        raise RuntimeError("installer access token must be a bounded regular non-symlink file")
    if before.st_mode & 0o077:
        raise RuntimeError("installer access token permissions must not allow group/other access")
    if require_read_only and before.st_mode & 0o222:
        raise RuntimeError("sealed installer access token must not remain writable")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise RuntimeError("installer access token changed while opening")
        with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
            raw = stream.read(4097)
        after = os.fstat(fd)
        if len(raw) > 4096 or len(raw) != opened.st_size or not _same_open_file_state(opened, after):
            raise RuntimeError("installer access token changed while reading")
    finally:
        os.close(fd)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("installer access token must be UTF-8 text") from exc
    token = text.strip()
    if len(token) < 32 or any(ch.isspace() for ch in token) or text not in {token, token + "\n", token + "\r\n"}:
        raise RuntimeError("installer access token must be one bounded trimmed value")
    return token, "sha256:" + hashlib.sha256(token.encode()).hexdigest()


def _promote_installer_token_export(export_path: Path, canonical_path: Path) -> tuple[str, str]:
    token, fingerprint = _read_private_installer_token(export_path, require_read_only=False)
    os.chmod(export_path, 0o400, follow_symlinks=False)
    _token2, fingerprint2 = _read_private_installer_token(export_path, require_read_only=True)
    if fingerprint2 != fingerprint:
        raise RuntimeError("installer access token changed while sealing")
    canonical_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    canonical_path.parent.chmod(0o700)
    os.replace(export_path, canonical_path)
    dir_fd = os.open(canonical_path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    token3, fingerprint3 = _read_private_installer_token(canonical_path, require_read_only=True)
    if fingerprint3 != fingerprint:
        raise RuntimeError("installer access token changed while publishing")
    return token3, fingerprint3


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _post_json(url: str, token: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    req = urllib.request.Request(url + path, data=json.dumps(payload).encode(), headers={"Content-Type":"application/json","Authorization":"Bearer "+token}, method="POST")
    with _control_plane_open(req, timeout=20) as resp:
        return json.loads(resp.read(1 << 20))


def _get_json(url: str, token: str, path: str, *, timeout: int = 20) -> dict[str, Any]:
    req = urllib.request.Request(url + path, headers={"Authorization":"Bearer "+token})
    with _control_plane_open(req, timeout=timeout) as resp:
        value = json.loads(resp.read(1 << 20))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object from {path}")
    return value


def _wait_for_installer_health(url: str, token: str, *, timeout: int = 120) -> None:
    deadline = time.time() + timeout
    last_error = ""
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url + "/healthz", headers={"Authorization":"Bearer "+token})
            with _control_plane_open(req, timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception as exc:
            last_error = str(exc)
        time.sleep(.5)
    raise RuntimeError("installer health did not recover before timeout" + (f": {last_error}" if last_error else ""))


_M02_SAFE_INTERRUPT_STEPS = {
    "deploy-replicated-storage",
    "deploy-postgresql-operator",
    "deploy-foundation",
    "deploy-internal-git",
    "deploy-oci-registry",
    "seed-offline-registry",
    "deploy-identity",
    "configure-secure-exposure",
    "bootstrap-repository",
    "deploy-gitops-controller",
    "publish-signed-revision",
    "verify-gitops-handover",
    "deploy-fleet-hub",
    "verify-fleet-hub",
    "configure-off-node-backup",
    "verify-embedded-services",
    "verify-runtime",
    "verify-ha-services",
    "revoke-bootstrap-credential",
}


def _active_bootstrap_step(status: dict[str, Any]) -> str:
    if status.get("bootstrapActive") is not True:
        return ""
    run = status.get("run")
    if not isinstance(run, dict) or str(run.get("state", "")).upper() != "RUNNING":
        return ""
    steps = run.get("steps")
    if not isinstance(steps, list):
        return ""
    for step in steps:
        if not isinstance(step, dict):
            continue
        key = str(step.get("key", "")).strip()
        state = str(step.get("state", "")).upper()
        if key in _M02_SAFE_INTERRUPT_STEPS and state == "RUNNING":
            return key
    return ""


def _wait_for_m02_interrupt_point(url: str, token: str, *, timeout: int = 3600) -> tuple[str, dict[str, Any]]:
    deadline = time.time() + timeout
    last: dict[str, Any] = {}
    while time.time() < deadline:
        last = _get_json(url, token, "/api/v1/status")
        step = _active_bootstrap_step(last)
        if step:
            return step, last
        run = last.get("run") if isinstance(last.get("run"), dict) else {}
        if str(run.get("state", "")).upper() in {"FAILED", "SUCCEEDED"}:
            raise RuntimeError(f"bootstrap reached terminal state before M02 interruption point: {run.get('state')}")
        time.sleep(2)
    raise RuntimeError("no replay-safe post-quorum bootstrap step became active before M02 interruption timeout")


def _ha_runtime_probe(body: dict[str, Any], primary_role: str, primary_host: str, *, minimum_nodes: int, require_full_recovery: bool, timeout: int = 300) -> dict[str, Any]:
    mode = "full" if require_full_recovery else "degraded-quorum"
    full_flag = 1 if require_full_recovery else 0
    script = f'''set -eu
K=/var/lib/rancher/rke2/bin/kubectl
KC=/etc/rancher/rke2/rke2.yaml
test -x "$K"
test -s "$KC"
deadline=$(( $(date +%s) + {int(timeout)} ))
while :; do
  ready_nodes=$("$K" --kubeconfig "$KC" get nodes --no-headers 2>/dev/null | awk '$2=="Ready"{{n++}} END{{print n+0}}')
  api_ready=$("$K" --kubeconfig "$KC" -n platform-system get pods -l app=platform-api -o jsonpath='{{range .items[*]}}{{range .status.containerStatuses[*]}}{{.ready}}{{"\\n"}}{{end}}{{end}}' 2>/dev/null | grep -c '^true$' || true)
  pg_ready=$("$K" --kubeconfig "$KC" -n platform-system get pods -l cnpg.io/cluster=platform-postgresql -o jsonpath='{{range .items[*]}}{{range .status.containerStatuses[*]}}{{.ready}}{{"\\n"}}{{end}}{{end}}' 2>/dev/null | grep -c '^true$' || true)
  if "$K" --kubeconfig "$KC" get --raw=/readyz >/dev/null 2>&1 && [ "$ready_nodes" -ge {minimum_nodes} ] && [ "$api_ready" -ge 2 ] && [ "$pg_ready" -ge 2 ]; then
    if [ "{full_flag}" -eq 0 ] || {{ [ "$api_ready" -ge 3 ] && [ "$pg_ready" -ge 3 ]; }}; then
      printf 'LAB_HA_PROBE mode={mode} ready_nodes=%s api_ready=%s pg_ready=%s\n' "$ready_nodes" "$api_ready" "$pg_ready"
      exit 0
    fi
  fi
  [ "$(date +%s)" -lt "$deadline" ] || {{ printf 'LAB_HA_PROBE_TIMEOUT mode={mode} ready_nodes=%s api_ready=%s pg_ready=%s\n' "$ready_nodes" "$api_ready" "$pg_ready"; exit 4; }}
  sleep 3
done'''
    return _run(f"m02-ha-probe-{mode}:{primary_role}", _ssh_command(body, primary_host, script), cwd=ROOT, timeout=timeout + 30)


def _restart_ha_peer_service(body: dict[str, Any], role: str, host: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for stage, script in [
        (f"m02-rke2-restart:{role}", "systemctl restart rke2-server.service"),
        (f"m02-rke2-active:{role}", "systemctl is-active --quiet rke2-server.service && systemctl is-enabled --quiet rke2-server.service"),
    ]:
        result = _run(stage, _ssh_command(body, host, script), cwd=ROOT, timeout=180)
        results.append(result)
        if result["status"] != "PASS":
            break
    return results


def _reboot_ha_peer(body: dict[str, Any], role: str, host: str, primary_role: str, primary_host: str, *, timeout: int = 600) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    before = _run(f"m02-boot-id-before:{role}", _ssh_command(body, host, "cat /proc/sys/kernel/random/boot_id"), cwd=ROOT, timeout=30)
    results.append(before)
    before_id = _boot_id_from_result(before)
    if not before_id:
        results[-1] = {**before, "status":"FAIL", "returnCode": before.get("returnCode", 2) or 2, "outputTail": _tail(str(before.get("outputTail", "")) + "\nmissing parseable boot_id before reboot")}
        return results
    trigger_script = "nohup sh -c 'sleep 1; systemctl reboot' >/dev/null 2>&1 & echo LAB_REBOOT_SCHEDULED"
    trigger = _run(f"m02-reboot-trigger:{role}", _ssh_command(body, host, trigger_script), cwd=ROOT, timeout=30)
    results.append(trigger)
    if trigger["status"] != "PASS":
        return results
    outage_deadline = time.time() + 60
    outage_proven = False
    while time.time() < outage_deadline:
        time.sleep(2)
        down = _run(f"m02-reboot-outage:{role}", _ssh_command(body, host, "true"), cwd=ROOT, timeout=10)
        if down["status"] != "PASS":
            outage_proven = True
            results.append({**down, "status":"PASS", "returnCode":0, "outputTail":"peer became unreachable after reboot trigger; outage observed"})
            break
    if not outage_proven:
        results.append({"stage":f"m02-reboot-outage:{role}","command":["prove-peer-outage"],"returnCode":4,"durationSeconds":60,"outputTail":"peer never became unreachable after reboot trigger","fingerprint":_fingerprint(f"m02-reboot-outage:{role}",4,"no outage"),"status":"FAIL"})
        return results
    degraded = _ha_runtime_probe(body, primary_role, primary_host, minimum_nodes=2, require_full_recovery=False, timeout=180)
    results.append(degraded)
    if degraded["status"] != "PASS":
        return results
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(3)
        probe = _run(f"m02-boot-id-after:{role}", _ssh_command(body, host, "cat /proc/sys/kernel/random/boot_id"), cwd=ROOT, timeout=20)
        after_id = _boot_id_from_result(probe)
        if probe["status"] == "PASS" and after_id and after_id != before_id:
            results.append(probe)
            service = _run(f"m02-service-after-reboot:{role}", _ssh_command(body, host, "systemctl is-active --quiet rke2-server.service && systemctl is-enabled --quiet rke2-server.service"), cwd=ROOT, timeout=60)
            results.append(service)
            if service["status"] != "PASS":
                return results
            full = _ha_runtime_probe(body, primary_role, primary_host, minimum_nodes=3, require_full_recovery=True, timeout=300)
            results.append(full)
            return results
    results.append({"stage":f"m02-reboot-wait:{role}","command":["deterministic-boot-id-change"],"returnCode":4,"durationSeconds":timeout,"outputTail":"peer did not return with a different boot_id before timeout","fingerprint":_fingerprint(f"m02-reboot-wait:{role}",4,"boot timeout"),"status":"FAIL"})
    return results


def _boot_id_from_result(result: dict[str, Any]) -> str:
    if result.get("status") != "PASS":
        return ""
    matches = re.findall(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b", str(result.get("outputTail", "")))
    return matches[-1].lower() if matches else ""


def _reboot_management_host(body: dict[str, Any], role: str, host: str, *, timeout: int = 600) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    before = _run(f"m01-boot-id-before:{role}", _ssh_command(body, host, "cat /proc/sys/kernel/random/boot_id"), cwd=ROOT, timeout=30)
    results.append(before)
    before_id = _boot_id_from_result(before)
    if not before_id:
        before = {**before, "status": "FAIL", "returnCode": before.get("returnCode", 2) or 2, "outputTail": _tail(str(before.get("outputTail", "")) + "\nmissing parseable boot_id before reboot")}
        results[-1] = before
        return results
    trigger_script = r'''before=$(cat /proc/sys/kernel/random/boot_id)
printf 'LAB_REBOOT_SCHEDULED boot_id=%s\n' "$before"
nohup sh -c 'sleep 1; systemctl reboot' >/dev/null 2>&1 &
'''
    trigger = _run(f"m01-reboot-trigger:{role}", _ssh_command(body, host, trigger_script), cwd=ROOT, timeout=30)
    results.append(trigger)
    if trigger["status"] != "PASS":
        return results
    deadline = time.time() + timeout
    last_probe: dict[str, Any] | None = None
    while time.time() < deadline:
        time.sleep(3)
        probe = _run(f"m01-boot-id-after:{role}", _ssh_command(body, host, "cat /proc/sys/kernel/random/boot_id"), cwd=ROOT, timeout=20)
        last_probe = probe
        after_id = _boot_id_from_result(probe)
        if probe["status"] == "PASS" and after_id and after_id != before_id:
            results.append(probe)
            service = _run(
                f"m01-service-after-reboot:{role}",
                _ssh_command(body, host, "systemctl is-active --quiet 4so-platform-installer.service && systemctl is-enabled --quiet 4so-platform-installer.service"),
                cwd=ROOT,
                timeout=30,
            )
            results.append(service)
            return results
    detail = "host did not return with a different boot_id before reboot timeout"
    if last_probe and last_probe.get("outputTail"):
        detail += "; last probe: " + _tail(str(last_probe["outputTail"]), 1200)
    timeout_result = {
        "stage": f"m01-reboot-wait:{role}", "command": ["deterministic-boot-id-change"], "returnCode": 4,
        "durationSeconds": timeout, "outputTail": detail,
        "fingerprint": _fingerprint(f"m01-reboot-wait:{role}", 4, detail), "status": "FAIL",
    }
    results.append(timeout_result)
    return results


def _execute_management_install(
    spec: dict[str, Any],
    state_dir: Path,
    resolved_bundle: Path | None = None,
    expected_bundle_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = validate_spec(spec, require_bundle=True)
    artifact = Path(body["releaseArtifact"]).expanduser().resolve()
    root_name, version, artifact_sha = _release_identity(artifact)
    inventory_digest = _server_inventory_digest(body)
    release_root = _safe_extract(artifact, state_dir / "artifact", expected_sha256=artifact_sha)
    bundle = resolved_bundle.resolve() if resolved_bundle is not None else Path(body["bundleDirectory"]).expanduser().resolve()
    if not isinstance(expected_bundle_binding, dict):
        raise SystemExit("Lab execution requires the preflight-sealed expected bundle binding")
    expected_bundle_digest = str(expected_bundle_binding.get("bundleDigest", ""))
    expected_bundle_lock_digest = str(expected_bundle_binding.get("bundleLockDigest", ""))
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_bundle_digest) or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_bundle_lock_digest):
        raise SystemExit("Lab execution received an invalid preflight bundle binding")
    platformctl = release_root / "bin" / "linux-amd64" / "platformctl"
    installer = release_root / "bin" / "linux-amd64" / "platform-installer"
    mgmt_roles = _management_roles(body["serverTier"])
    primary_role = mgmt_roles[0]
    primary = _server_map(body)[primary_role]
    generated = state_dir / "generated"
    host_spec = {
        "apiVersion":"platform.4so.io/v1alpha1","kind":"InstallerHostDeployment","metadata":{"name":"lab-installer","version":version},
        "spec":{"installerBinary":str(installer),"bundleDirectory":str(bundle),"listen":"127.0.0.1:9443","executionEnabled":True,"allowInsecureHttp":False,"tls":{},"health":{"path":"/healthz","timeoutSeconds":120,"intervalMilliseconds":500},"service":{"enable":True,"start":True},"admission":{"allowDowngrade":False}}
    }
    host_spec_path = generated / "installer-host.json"; _write_json(host_spec_path, host_spec)
    remote_spec = {
        "apiVersion":"platform.4so.io/v1alpha1","kind":"InstallerRemoteBootstrap","metadata":{"name":"lab-installer","version":version},
        "spec":{
            "target":{"host":primary,"user":"root","identityFile":str(Path(body["ssh"]["identityFile"]).expanduser().resolve()),"knownHostsFile":str(Path(body["ssh"]["knownHostsFile"]).expanduser().resolve()),"root":"/"},
            "platformctlBinary":str(platformctl),
            "deploymentSpec":str(host_spec_path),
            "expectedBundle":{"bundleDigest":expected_bundle_digest,"lockDigest":expected_bundle_lock_digest},
        }
    }
    remote_spec_path = generated / "remote-bootstrap.json"; _write_json(remote_spec_path, remote_spec)
    install_req_path = generated / "installation-request.json"; _write_json(install_req_path, _install_request(body))
    token_file = state_dir / "installer.token"
    token_export = state_dir / f"installer.token.export.{os.getpid()}.{time.time_ns()}"
    campaign = state_dir / "campaign.json"
    evidence = state_dir / "field-evidence.json"
    results: list[dict[str, Any]] = []
    try:
        for stage, command, timeout in [
            ("installer-remote-preflight", [str(platformctl),"installer-remote","preflight","--spec",str(remote_spec_path)], 300),
            ("installer-remote-plan", [str(platformctl),"installer-remote","plan","--spec",str(remote_spec_path)], 300),
            ("installer-remote-apply", [str(platformctl),"installer-remote","apply","--spec",str(remote_spec_path),"--confirmation","DEPLOY"], 1800),
            ("installer-remote-verify", [str(platformctl),"installer-remote","verify","--spec",str(remote_spec_path)], 300),
            ("installer-export-access", [str(platformctl),"installer-remote","export-access","--spec",str(remote_spec_path),"--out-token-file",str(token_export),"--confirmation","EXPORT"], 300),
        ]:
            r = _run(stage, command, cwd=release_root, timeout=timeout); results.append(r)
            if r["status"] != "PASS":
                return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(r, artifact_sha=artifact_sha, server_role=primary_role), body.get("ai"), cwd=release_root)}
        token, token_fingerprint = _promote_installer_token_export(token_export, token_file)
        results.append({"stage":"installer-access-token-seal","command":[INSTALLER_ACCESS_TOKEN_FILE_AUTHORITY],"returnCode":0,"durationSeconds":0,"outputTail":"installer access token exported to a private pending file, validated without symlink following, sealed read-only and atomically published for campaign continuation","fingerprint":_fingerprint("installer-access-token-seal",0,token_fingerprint),"status":"PASS","tokenAuthority":INSTALLER_ACCESS_TOKEN_FILE_AUTHORITY,"tokenFingerprint":token_fingerprint})
    finally:
        try:
            token_export.unlink()
        except FileNotFoundError:
            pass
    local_port = _find_free_port()
    ssh = body["ssh"]
    tunnel_cmd = ["ssh","-N","-o","ExitOnForwardFailure=yes","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o",f"UserKnownHostsFile={Path(ssh['knownHostsFile']).expanduser()}","-i",str(Path(ssh["identityFile"]).expanduser()),"-L",f"127.0.0.1:{local_port}:127.0.0.1:9443",f"root@{primary}"]
    tunnel = subprocess.Popen(tunnel_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        url = f"http://127.0.0.1:{local_port}"
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                req = urllib.request.Request(url+"/healthz", headers={"Authorization":"Bearer "+token})
                with _control_plane_open(req, timeout=2) as resp:
                    if resp.status == 200: break
            except Exception: time.sleep(.3)
        else:
            out = tunnel.stdout.read() if tunnel.stdout else ""
            r={"stage":"installer-ssh-tunnel","command":tunnel_cmd,"returnCode":1,"durationSeconds":20,"outputTail":_tail(out),"fingerprint":_fingerprint("installer-ssh-tunnel",1,out),"status":"FAIL"}
            results.append(r); return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(r, artifact_sha=artifact_sha, server_role=primary_role), body.get("ai"), cwd=release_root)}
        private_key = Path(ssh["identityFile"]).expanduser().read_text()
        known_hosts = Path(ssh["knownHostsFile"]).expanduser().read_text()
        _post_json(url, token, "/api/v1/secrets/ssh-private-key", {"privateKey":private_key.strip()})
        _post_json(url, token, "/api/v1/secrets/ssh-known-hosts", {"knownHosts":known_hosts.strip()})
        def run_campaign_stage(stage: str, command: list[str], timeout: int) -> dict[str, Any]:
            result = _run(stage, command, cwd=release_root, timeout=timeout)
            results.append(result)
            return result

        base_commands = [
            ("field-campaign-prepare", [str(platformctl),"field-campaign","prepare","--installer-url",url,"--request",str(install_req_path),"--state",str(campaign),"--release-artifact",str(artifact),"--token-file",str(token_file)], 300),
            ("field-campaign-start", [str(platformctl),"field-campaign","start","--state",str(campaign),"--confirmation","INSTALL","--token-file",str(token_file)], 300),
        ]
        for stage, command, timeout in base_commands:
            r = run_campaign_stage(stage, command, timeout)
            if r["status"] != "PASS":
                diag_path=state_dir/"field-diagnostic.json"
                diag=_run("field-campaign-diagnose",[str(platformctl),"field-campaign","diagnose","--state",str(campaign),"--out",str(diag_path),"--token-file",str(token_file)],cwd=release_root,timeout=300)
                results.append(diag)
                facts=[]
                if diag_path.is_file(): facts=[_tail(diag_path.read_text(errors="replace"),4000)]
                return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(r,artifact_sha=artifact_sha,server_role=primary_role,facts=facts),body.get("ai"),cwd=release_root)}

        if len(mgmt_roles) == 3:
            started = time.time()
            try:
                interrupt_step, interrupt_status = _wait_for_m02_interrupt_point(url, token)
                run = interrupt_status.get("run") if isinstance(interrupt_status.get("run"), dict) else {}
                detail = f"safeStep={interrupt_step} runId={run.get('id','')} state={run.get('state','')}"
                results.append({"stage":"m02-durable-interrupt-point","command":["observe-replay-safe-post-quorum-step"],"returnCode":0,"durationSeconds":round(time.time()-started,3),"outputTail":detail,"fingerprint":_fingerprint("m02-durable-interrupt-point",0,detail),"status":"PASS"})
            except Exception as exc:
                detail = str(exc)
                r={"stage":"m02-durable-interrupt-point","command":["observe-replay-safe-post-quorum-step"],"returnCode":4,"durationSeconds":round(time.time()-started,3),"outputTail":detail,"fingerprint":_fingerprint("m02-durable-interrupt-point",4,detail),"status":"FAIL"}
                results.append(r)
                return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(r,artifact_sha=artifact_sha,server_role=primary_role),body.get("ai"),cwd=release_root)}

            restart = _run("m02-installer-service-interrupt", _ssh_command(body, primary, "systemctl restart 4so-platform-installer.service && systemctl is-active --quiet 4so-platform-installer.service"), cwd=ROOT, timeout=180)
            results.append(restart)
            if restart["status"] != "PASS":
                return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(restart,artifact_sha=artifact_sha,server_role=primary_role),body.get("ai"),cwd=release_root)}
            try:
                _wait_for_installer_health(url, token, timeout=120)
                detail = "installer health recovered after deliberate service interruption"
                results.append({"stage":"m02-installer-health-after-interrupt","command":["poll-healthz"],"returnCode":0,"durationSeconds":0,"outputTail":detail,"fingerprint":_fingerprint("m02-installer-health-after-interrupt",0,detail),"status":"PASS"})
            except Exception as exc:
                detail = str(exc)
                r={"stage":"m02-installer-health-after-interrupt","command":["poll-healthz"],"returnCode":4,"durationSeconds":120,"outputTail":detail,"fingerprint":_fingerprint("m02-installer-health-after-interrupt",4,detail),"status":"FAIL"}
                results.append(r)
                return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(r,artifact_sha=artifact_sha,server_role=primary_role),body.get("ai"),cwd=release_root)}

            interrupted_watch = run_campaign_stage("m02-field-campaign-watch-interrupted", [str(platformctl),"field-campaign","watch","--state",str(campaign),"--poll-interval","1s","--timeout","5m","--token-file",str(token_file)], 330)
            if interrupted_watch["status"] != "PASS":
                return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(interrupted_watch,artifact_sha=artifact_sha,server_role=primary_role),body.get("ai"),cwd=release_root)}
            campaign_state = _load_json(campaign)
            if campaign_state.get("state") != "INTERRUPTED" or str(campaign_state.get("runState", "")).upper() != "RUNNING":
                detail = f"expected INTERRUPTED/RUNNING after service restart, got state={campaign_state.get('state')} runState={campaign_state.get('runState')}"
                r={"stage":"m02-durable-interruption-proof","command":["verify-campaign-interruption-state"],"returnCode":4,"durationSeconds":0,"outputTail":detail,"fingerprint":_fingerprint("m02-durable-interruption-proof",4,detail),"status":"FAIL"}
                results.append(r)
                return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(r,artifact_sha=artifact_sha,server_role=primary_role),body.get("ai"),cwd=release_root)}
            detail = f"campaign={campaign_state.get('state')} durableRun={campaign_state.get('runState')} runId={campaign_state.get('runId','')}"
            results.append({"stage":"m02-durable-interruption-proof","command":["verify-campaign-interruption-state"],"returnCode":0,"durationSeconds":0,"outputTail":detail,"fingerprint":_fingerprint("m02-durable-interruption-proof",0,detail),"status":"PASS"})
            resume = run_campaign_stage("m02-field-campaign-resume", [str(platformctl),"field-campaign","resume","--state",str(campaign),"--confirmation","RESUME","--token-file",str(token_file)], 300)
            if resume["status"] != "PASS":
                return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(resume,artifact_sha=artifact_sha,server_role=primary_role),body.get("ai"),cwd=release_root)}
            final_commands = [
                ("m02-field-campaign-watch-after-resume", [str(platformctl),"field-campaign","watch","--state",str(campaign),"--poll-interval","5s","--timeout","2h","--token-file",str(token_file)], 7500),
                ("field-campaign-collect", [str(platformctl),"field-campaign","collect","--state",str(campaign),"--out",str(evidence),"--release-artifact",str(artifact),"--token-file",str(token_file)], 300),
            ]
        else:
            final_commands = [
                ("field-campaign-watch", [str(platformctl),"field-campaign","watch","--state",str(campaign),"--poll-interval","5s","--timeout","2h","--token-file",str(token_file)], 7500),
                ("field-campaign-collect", [str(platformctl),"field-campaign","collect","--state",str(campaign),"--out",str(evidence),"--release-artifact",str(artifact),"--token-file",str(token_file)], 300),
            ]
        for stage, command, timeout in final_commands:
            r = run_campaign_stage(stage, command, timeout)
            if r["status"] != "PASS":
                diag_path=state_dir/"field-diagnostic.json"
                diag=_run("field-campaign-diagnose",[str(platformctl),"field-campaign","diagnose","--state",str(campaign),"--out",str(diag_path),"--token-file",str(token_file)],cwd=release_root,timeout=300)
                results.append(diag)
                facts=[]
                if diag_path.is_file(): facts=[_tail(diag_path.read_text(errors="replace"),4000)]
                return {"status":"FAIL","artifactSha256":artifact_sha,"results":results,"ai":diagnose(failure_packet(r,artifact_sha=artifact_sha,server_role=primary_role,facts=facts),body.get("ai"),cwd=release_root)}
    finally:
        tunnel.terminate()
        try: tunnel.wait(timeout=5)
        except subprocess.TimeoutExpired: tunnel.kill()

    post_restart_evidence = ""
    m01_restart_certified = False
    m02_durable_resume_certified = False
    m02_ha_recovery_certified = False
    if len(mgmt_roles) == 1:
        reboot_results = _reboot_management_host(body, primary_role, primary)
        results.extend(reboot_results)
        failed_reboot = next((item for item in reboot_results if item.get("status") != "PASS"), None)
        if failed_reboot is not None:
            return {"status":"FAIL","artifactSha256":artifact_sha,"serverInventoryDigest":inventory_digest,"results":results,"ai":diagnose(failure_packet(failed_reboot, artifact_sha=artifact_sha, server_role=primary_role, facts=["M01 requires a real boot_id change and installer service recovery"]), body.get("ai"), cwd=release_root)}
        verify_after = _run("m01-installer-verify-after-reboot", [str(platformctl),"installer-remote","verify","--spec",str(remote_spec_path)], cwd=release_root, timeout=300)
        results.append(verify_after)
        if verify_after["status"] != "PASS":
            return {"status":"FAIL","artifactSha256":artifact_sha,"serverInventoryDigest":inventory_digest,"results":results,"ai":diagnose(failure_packet(verify_after, artifact_sha=artifact_sha, server_role=primary_role, facts=["M01 post-reboot installer verification failed"]), body.get("ai"), cwd=release_root)}
        # Reuse the same local port because campaign state binds InstallerURL to it.
        tunnel = subprocess.Popen(tunnel_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.time() + 30
            while time.time() < deadline:
                try:
                    req = urllib.request.Request(url+"/healthz", headers={"Authorization":"Bearer "+token})
                    with _control_plane_open(req, timeout=2) as resp:
                        if resp.status == 200:
                            break
                except Exception:
                    time.sleep(.5)
            else:
                out = tunnel.stdout.read() if tunnel.stdout else ""
                tunnel_failure={"stage":"m01-installer-tunnel-after-reboot","command":tunnel_cmd,"returnCode":1,"durationSeconds":30,"outputTail":_tail(out),"fingerprint":_fingerprint("m01-installer-tunnel-after-reboot",1,out),"status":"FAIL"}
                results.append(tunnel_failure)
                return {"status":"FAIL","artifactSha256":artifact_sha,"serverInventoryDigest":inventory_digest,"results":results,"ai":diagnose(failure_packet(tunnel_failure,artifact_sha=artifact_sha,server_role=primary_role),body.get("ai"),cwd=release_root)}
            post_path = state_dir / "field-evidence-post-restart.json"
            post_collect = _run("m01-field-campaign-collect-after-reboot", [str(platformctl),"field-campaign","collect","--state",str(campaign),"--out",str(post_path),"--release-artifact",str(artifact),"--token-file",str(token_file)], cwd=release_root, timeout=300)
            results.append(post_collect)
            if post_collect["status"] != "PASS":
                return {"status":"FAIL","artifactSha256":artifact_sha,"serverInventoryDigest":inventory_digest,"results":results,"ai":diagnose(failure_packet(post_collect,artifact_sha=artifact_sha,server_role=primary_role,facts=["M01 exact-SHA field evidence must remain collectable after host reboot"]),body.get("ai"),cwd=release_root)}
            post_restart_evidence = str(post_path)
            m01_restart_certified = True
        finally:
            tunnel.terminate()
            try: tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired: tunnel.kill()
    elif len(mgmt_roles) == 3:
        # The campaign above deliberately killed/restarted the installer while a replay-safe
        # post-quorum step was active, observed durable INTERRUPTED state and resumed the
        # exact same run. At this point successful field evidence proves that resume completed.
        m02_durable_resume_certified = True
        full_before = _ha_runtime_probe(body, primary_role, primary, minimum_nodes=3, require_full_recovery=True, timeout=300)
        results.append(full_before)
        if full_before["status"] != "PASS":
            return {"status":"FAIL","artifactSha256":artifact_sha,"serverInventoryDigest":inventory_digest,"results":results,"ai":diagnose(failure_packet(full_before,artifact_sha=artifact_sha,server_role=primary_role,facts=["M02 requires full three-node management quorum before fault injection"]),body.get("ai"),cwd=release_root)}

        peer_restart_role = mgmt_roles[1]
        peer_restart_host = _server_map(body)[peer_restart_role]
        restart_results = _restart_ha_peer_service(body, peer_restart_role, peer_restart_host)
        results.extend(restart_results)
        failed_restart = next((item for item in restart_results if item.get("status") != "PASS"), None)
        if failed_restart is not None:
            return {"status":"FAIL","artifactSha256":artifact_sha,"serverInventoryDigest":inventory_digest,"results":results,"ai":diagnose(failure_packet(failed_restart,artifact_sha=artifact_sha,server_role=peer_restart_role,facts=["M02 requires a real rke2-server service restart on one HA peer"]),body.get("ai"),cwd=release_root)}
        full_after_restart = _ha_runtime_probe(body, primary_role, primary, minimum_nodes=3, require_full_recovery=True, timeout=300)
        results.append(full_after_restart)
        if full_after_restart["status"] != "PASS":
            return {"status":"FAIL","artifactSha256":artifact_sha,"serverInventoryDigest":inventory_digest,"results":results,"ai":diagnose(failure_packet(full_after_restart,artifact_sha=artifact_sha,server_role=primary_role,facts=["M02 management quorum did not fully recover after rke2-server restart"]),body.get("ai"),cwd=release_root)}

        reboot_role = mgmt_roles[2]
        reboot_host = _server_map(body)[reboot_role]
        reboot_results = _reboot_ha_peer(body, reboot_role, reboot_host, primary_role, primary)
        results.extend(reboot_results)
        failed_reboot = next((item for item in reboot_results if item.get("status") != "PASS"), None)
        if failed_reboot is not None:
            return {"status":"FAIL","artifactSha256":artifact_sha,"serverInventoryDigest":inventory_digest,"results":results,"ai":diagnose(failure_packet(failed_reboot,artifact_sha=artifact_sha,server_role=reboot_role,facts=["M02 requires observed peer outage, degraded two-node quorum and full three-node recovery after boot_id change"]),body.get("ai"),cwd=release_root)}
        m02_ha_recovery_certified = True

    m03_runtime_certified = False
    m03_evidence = ""
    m03_evidence_digest = ""
    if body["serverTier"] == "production-ha":
        m03 = _execute_m03_postgresql(body, release_root, state_dir, artifact_sha, primary_role, primary)
        results.extend(m03["results"])
        m03_evidence = str(m03.get("evidence", ""))
        m03_evidence_digest = str(m03.get("evidenceFileDigest", ""))
        if m03["status"] != "PASS":
            failure = next((item for item in reversed(m03["results"]) if item.get("status") != "PASS"), m03["results"][-1])
            return {"status":m03["status"],"artifactSha256":artifact_sha,"serverInventoryDigest":inventory_digest,"releaseRoot":root_name,"results":results,"m03Evidence":m03_evidence,"m03EvidenceDigest":m03_evidence_digest,"m03EvidenceAuthority":M03_EXACT_RELEASE_EVIDENCE_AUTHORITY,"ai":diagnose(failure_packet(failure,artifact_sha=artifact_sha,server_role=primary_role,facts=["M03 must certify the PostgreSQL runtime installed by the same M02 run; BLOCKED or failed cleanup never count as PASS"]),body.get("ai"),cwd=release_root),"physicalPass":False}
        m03_runtime_certified = True

    return {"status":"PASS","artifactSha256":artifact_sha,"releaseArtifactAuthority":EXACT_RELEASE_SNAPSHOT_AUTHORITY,"releaseExecutionAuthority":EXACT_RELEASE_EXECUTION_AUTHORITY,"bundleExecutionAuthority":REMOTE_BOOTSTRAP_EXPECTED_BUNDLE_AUTHORITY,"serverInventoryDigest":inventory_digest,"releaseRoot":root_name,"results":results,"evidence":post_restart_evidence or str(evidence),"preRestartEvidence":str(evidence),"m01RestartCertified":m01_restart_certified,"m02DurableResumeCertified":m02_durable_resume_certified,"m02HARecoveryCertified":m02_ha_recovery_certified,"m03RuntimeCertified":m03_runtime_certified,"m03Evidence":m03_evidence,"m03EvidenceDigest":m03_evidence_digest,"m03EvidenceAuthority":M03_EXACT_RELEASE_EVIDENCE_AUTHORITY,"physicalPass":False,"physicalPassReason":"row-level M00-M03 success is not the independent four-layer release Physical PASS"}


def self_test() -> int:
    g=guide()
    assert len(g["serverTiers"])==4 and len(g["matrix"])==14
    fake={"stage":"x","command":["false"],"returnCode":1,"durationSeconds":0,"outputTail":"x"*50000,"fingerprint":"abc","status":"FAIL"}
    p=failure_packet(fake,artifact_sha="0"*64)
    assert len(json.dumps(p,separators=(",",":")).encode()) <= MAX_PACKET_BYTES
    assert diagnose(p,{"provider":"none"},cwd=ROOT)["status"]=="SKIPPED"
    print("LAB_RUNNER_SELF_TEST_PASS")
    return 0


def main() -> int:
    ap=argparse.ArgumentParser(description="4SO Platform Factory deterministic physical lab runner")
    sub=ap.add_subparsers(dest="command",required=True)
    sub.add_parser("guide")
    sub.add_parser("self-test")
    for name in ("plan","preflight","run"):
        p=sub.add_parser(name); p.add_argument("--spec",required=True)
        if name=="run":
            p.add_argument("--state-dir",required=True); p.add_argument("--confirmation",required=True)
    args=ap.parse_args()
    if args.command=="guide": print(json.dumps(guide(),indent=2)); return 0
    if args.command=="self-test": return self_test()
    spec=_load_json(Path(args.spec).expanduser())
    if args.command=="plan": print(json.dumps(plan_document(spec),indent=2)); return 0
    if args.command=="preflight":
        with tempfile.TemporaryDirectory(prefix="4so-lab-preflight-release-") as td:
            snapshot_spec, _ = _spec_with_release_snapshot(spec, Path(td)/"release-artifact.zip")
            result=_preflight(snapshot_spec,require_bundle=False)
        print(json.dumps(result,indent=2)); return 0 if result["status"]=="PASS" else 2
    if args.confirmation!="RUN_LAB": raise SystemExit("confirmation must be exactly RUN_LAB")
    requested_state = Path(args.state_dir).expanduser().absolute()
    try:
        requested_info = requested_state.lstat()
    except FileNotFoundError:
        requested_info = None
    if requested_info is not None and (requested_state.is_symlink() or not stat.S_ISDIR(requested_info.st_mode)):
        raise SystemExit("--state-dir must be a real directory, not a symlink or non-directory")
    state=requested_state.resolve(); state.mkdir(parents=True,exist_ok=True); state.chmod(0o700)
    with _exclusive_run_state(state):
        snapshot_spec, (_, _, snapshot_sha) = _spec_with_persistent_release_snapshot(spec, state/"release-artifact.zip")
        snapshot_spec, ssh_binding = _spec_with_persistent_ssh_snapshots(snapshot_spec, state)
        pre=_preflight(snapshot_spec,require_bundle=True,bundle_state_dir=state/"bundle-acquisition")
        if pre["status"]=="PASS":
            if pre.get("artifactSha256") != snapshot_sha:
                raise SystemExit("preflight exact-release digest does not match the private run snapshot")
            binding = _run_state_binding(snapshot_spec, pre, snapshot_sha, ssh_binding)
            binding_status = _bind_or_verify_run_state(state, binding)
            pre["sshCredentialAuthority"] = SSH_CREDENTIAL_SNAPSHOT_AUTHORITY
            pre["sshCredentialBindingDigest"] = ssh_binding["bindingDigest"]
            pre["runStateAuthority"] = RUN_STATE_BINDING_AUTHORITY
            pre["runStateBindingDigest"] = binding["bindingDigest"]
            pre["runStateBindingStatus"] = binding_status
        _write_json(state/"preflight.json",pre)
        if pre["status"]!="PASS": print(json.dumps(pre,indent=2)); return 2
        resolved_bundle = Path(str(pre.get("resolvedBundleDirectory", ""))).resolve() if pre.get("resolvedBundleDirectory") else None
        result=_execute_management_install(snapshot_spec,state,resolved_bundle,pre.get("bundleBinding"))
        if result.get("artifactSha256") != snapshot_sha:
            raise SystemExit("execution exact-release digest does not match the private run snapshot")
        result["sshCredentialAuthority"] = SSH_CREDENTIAL_SNAPSHOT_AUTHORITY
        result["sshCredentialBindingDigest"] = ssh_binding["bindingDigest"]
        result["runStateAuthority"] = RUN_STATE_BINDING_AUTHORITY
        result["runStateBindingDigest"] = binding["bindingDigest"]
        _write_json(state/"result.json",result)
        print(json.dumps(result,indent=2)); return 0 if result["status"]=="PASS" else 3


if __name__=="__main__": raise SystemExit(main())
