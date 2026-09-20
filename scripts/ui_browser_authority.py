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
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from urllib.parse import urlsplit

AUTHORITY = "UI_BROWSER_AUTHORITY_V1"
ACQUISITION_AUTHORITY = "UI_BROWSER_ACQUISITION_LOCK_V1"
ENV_AUTHORITY = "PLATFORM_FACTORY_UI_BROWSER_AUTHORITY"
ENV_EXECUTABLE = "PLATFORM_FACTORY_UI_BROWSER_EXECUTABLE"
SHA_RE = re.compile(r"(?:sha256:)?([0-9a-f]{64})")
MAX_BROWSER_ARCHIVE_MEMBERS = 200000
MAX_BROWSER_EXTRACTED_BYTES = 4 * 1024 * 1024 * 1024


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



def validate_ui_browser_acquisition_lock(lock_path: Path) -> dict:
    lock_path = lock_path.expanduser().resolve()
    if not lock_path.is_file() or lock_path.is_symlink():
        raise ValueError("UI_BROWSER_ACQUISITION_LOCK_MISSING")
    try:
        document = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("UI_BROWSER_ACQUISITION_LOCK_JSON_INVALID") from exc
    required = {"schemaVersion", "authority", "browser", "platform", "architecture", "version", "source", "executable"}
    if not isinstance(document, dict) or set(document) != required:
        raise ValueError("UI_BROWSER_ACQUISITION_LOCK_SCHEMA_INVALID")
    if document["schemaVersion"] != 1 or document["authority"] != ACQUISITION_AUTHORITY or document["browser"] != "chromium":
        raise ValueError("UI_BROWSER_ACQUISITION_LOCK_IDENTITY_INVALID")
    if document["platform"] != normalized_platform() or document["architecture"] != normalized_arch():
        raise ValueError("UI_BROWSER_ACQUISITION_LOCK_PLATFORM_MISMATCH")
    if not str(document["version"]).strip():
        raise ValueError("UI_BROWSER_ACQUISITION_LOCK_VERSION_INVALID")
    executable = str(document["executable"]).strip()
    if not executable or Path(executable).is_absolute() or ".." in Path(executable).parts:
        raise ValueError("UI_BROWSER_ACQUISITION_LOCK_EXECUTABLE_INVALID")
    source = document["source"]
    if not isinstance(source, dict) or set(source) != {"url", "sha256", "size"}:
        raise ValueError("UI_BROWSER_ACQUISITION_LOCK_SOURCE_INVALID")
    parsed = urlsplit(str(source["url"]).strip())
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("UI_BROWSER_ACQUISITION_LOCK_URL_INVALID")
    match = SHA_RE.fullmatch(str(source["sha256"]).strip())
    size = source["size"]
    if match is None or not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ValueError("UI_BROWSER_ACQUISITION_LOCK_DIGEST_INVALID")
    return document


def verify_ui_browser_acquisition_archive(lock_path: Path, archive_path: Path) -> dict:
    document = validate_ui_browser_acquisition_lock(lock_path)
    archive_path = archive_path.expanduser().resolve()
    try:
        info = archive_path.lstat()
    except OSError as exc:
        raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_MISSING") from exc
    if archive_path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_IDENTITY_INVALID")
    source = document["source"]
    if info.st_size != source["size"]:
        raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_SIZE_MISMATCH")
    match = SHA_RE.fullmatch(str(source["sha256"]).strip())
    if match is None or file_sha256(archive_path) != match.group(1):
        raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_DIGEST_MISMATCH")
    return document

def _browser_archive_member(name: str) -> tuple[Path, bool]:
    if not isinstance(name, str) or not name or chr(0) in name or chr(92) in name or name.startswith("/"):
        raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_PATH_INVALID")
    directory = name.endswith("/")
    raw = name[:-1] if directory else name
    parts = raw.split("/")
    if not raw or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_PATH_INVALID")
    if re.fullmatch(r"[A-Za-z]:.*", parts[0]):
        raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_PATH_INVALID")
    relative = Path(*parts)
    if relative.is_absolute() or relative.drive:
        raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_PATH_INVALID")
    return relative, directory


def materialize_ui_browser_authority(lock_path: Path, archive_path: Path, output_dir: Path) -> tuple[Path, dict]:
    document = verify_ui_browser_acquisition_archive(lock_path, archive_path)
    output_dir = output_dir.expanduser().resolve()
    parent = output_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError("UI_BROWSER_MATERIALIZATION_TARGET_EXISTS")

    archive_path = archive_path.expanduser().resolve()
    staging = Path(tempfile.mkdtemp(prefix=".4so-ui-browser-", dir=parent))
    published = False
    try:
        seen: set[str] = set()
        extracted_bytes = 0
        try:
            with zipfile.ZipFile(archive_path) as bundle:
                infos = bundle.infolist()
                if len(infos) > MAX_BROWSER_ARCHIVE_MEMBERS:
                    raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_MEMBER_LIMIT")
                for info in infos:
                    relative, directory = _browser_archive_member(info.filename)
                    identity = relative.as_posix()
                    if identity in seen:
                        raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_DUPLICATE_PATH")
                    seen.add(identity)
                    unix_mode = (info.external_attr >> 16) & 0xFFFF
                    file_type = stat.S_IFMT(unix_mode)
                    if file_type == stat.S_IFLNK:
                        raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_SYMLINK_FORBIDDEN")
                    if directory:
                        if file_type not in (0, stat.S_IFDIR):
                            raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_ENTRY_TYPE_INVALID")
                        (staging / relative).mkdir(parents=True, exist_ok=True)
                        continue
                    if file_type not in (0, stat.S_IFREG):
                        raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_ENTRY_TYPE_INVALID")
                    if info.file_size < 0:
                        raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_ENTRY_SIZE_INVALID")
                    extracted_bytes += info.file_size
                    if extracted_bytes > MAX_BROWSER_EXTRACTED_BYTES:
                        raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_EXTRACTED_SIZE_LIMIT")
                    target = staging / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.open(info, "r") as source, target.open("xb") as sink:
                        shutil.copyfileobj(source, sink, length=1024 * 1024)
                    if target.stat().st_size != info.file_size:
                        raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_ENTRY_SIZE_MISMATCH")
                    permissions = stat.S_IMODE(unix_mode) if file_type == stat.S_IFREG else 0
                    if permissions:
                        target.chmod(permissions)
        except zipfile.BadZipFile as exc:
            raise ValueError("UI_BROWSER_ACQUISITION_ARCHIVE_FORMAT_INVALID") from exc

        executable_rel = Path(str(document["executable"]))
        executable = staging / executable_rel
        try:
            info = executable.lstat()
        except OSError as exc:
            raise ValueError("UI_BROWSER_ACQUISITION_EXECUTABLE_MISSING") from exc
        if executable.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise ValueError("UI_BROWSER_ACQUISITION_EXECUTABLE_IDENTITY_INVALID")
        if os.name != "nt" and info.st_mode & 0o111 == 0:
            executable.chmod(stat.S_IMODE(info.st_mode) | 0o111)
            info = executable.lstat()

        manifest = {
            "schemaVersion": 1,
            "authority": AUTHORITY,
            "browser": "chromium",
            "platform": document["platform"],
            "architecture": document["architecture"],
            "version": document["version"],
            "executable": executable_rel.as_posix(),
            "sha256": "sha256:" + file_sha256(executable),
            "size": info.st_size,
        }
        manifest_path = staging / "authority.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        validate_ui_browser_authority(manifest_path)
        staging.rename(output_dir)
        published = True
        return validate_ui_browser_authority(output_dir / "authority.json")
    finally:
        if not published:
            shutil.rmtree(staging, ignore_errors=True)


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
    authority_root = manifest_path.parent.resolve()
    candidate = manifest_path.parent
    relative = Path(executable_rel)
    try:
        for component in relative.parts:
            candidate = candidate / component
            info = candidate.lstat()
            if candidate.is_symlink():
                raise ValueError("UI_BROWSER_EXECUTABLE_IDENTITY_INVALID")
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError("UI_BROWSER_EXECUTABLE_MISSING") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size != document["size"]:
        raise ValueError("UI_BROWSER_EXECUTABLE_IDENTITY_INVALID")
    executable = candidate.resolve()
    try:
        executable.relative_to(authority_root)
    except ValueError as exc:
        raise ValueError("UI_BROWSER_EXECUTABLE_OUTSIDE_AUTHORITY") from exc
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
    parser.add_argument("--acquisition-lock")
    parser.add_argument("--archive")
    parser.add_argument("--materialize-dir")
    args = parser.parse_args()
    if args.acquisition_lock or args.archive or args.materialize_dir:
        if not args.acquisition_lock or not args.archive:
            raise SystemExit("UI_BROWSER_ACQUISITION_ARGUMENTS_INCOMPLETE")
        try:
            document = verify_ui_browser_acquisition_archive(Path(args.acquisition_lock), Path(args.archive))
            if args.materialize_dir:
                executable, authority = materialize_ui_browser_authority(
                    Path(args.acquisition_lock), Path(args.archive), Path(args.materialize_dir)
                )
                print(
                    f"UI_BROWSER_OFFLINE_MATERIALIZATION_PASS authority={AUTHORITY} "
                    f"browser={authority['browser']} version={authority['version']} executable={executable}"
                )
                return 0
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        print(
            f"UI_BROWSER_ACQUISITION_ARCHIVE_PASS authority={ACQUISITION_AUTHORITY} "
            f"browser={document['browser']} version={document['version']} archive={Path(args.archive).expanduser().resolve()}"
        )
        return 0
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
