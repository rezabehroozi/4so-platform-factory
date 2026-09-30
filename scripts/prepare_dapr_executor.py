#!/usr/bin/env python3
"""Prepare an offline-only BuildKit context for the Dapr target executor."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
import zipfile

import upstream_acquisition_toolchain as toolchain
from acquire_dapr_runtime import IMAGE_TAG, VERSION
from seal_dapr_runtime import load_json, validate_acquisition

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = "DAPR_EXECUTOR_CONTEXT_AUTHORITY_V1"
BINARY_MEMBER = "bin/linux-amd64/dapr-runtime"
DOCKERFILE = ROOT / "deploy" / "images" / "Dockerfile.dapr-runtime-release"
MAX_RELEASE_BYTES = 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024


def digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def digest_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def canonical_member(name: str) -> str:
    if not isinstance(name, str) or not name or name.startswith("/") or "\\" in name or "\x00" in name or name.endswith("/"):
        raise RuntimeError("DAPR_EXECUTOR_ARCHIVE_PATH_INVALID")
    parts = PurePosixPath(name).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise RuntimeError("DAPR_EXECUTOR_ARCHIVE_PATH_INVALID")
    return "/".join(parts)


def release_binary(release: Path) -> tuple[bytes, str, str]:
    info = release.lstat()
    if release.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > MAX_RELEASE_BYTES:
        raise RuntimeError("DAPR_EXECUTOR_RELEASE_INVALID")
    try:
        archive = zipfile.ZipFile(release, "r")
    except zipfile.BadZipFile as exc:
        raise RuntimeError("DAPR_EXECUTOR_RELEASE_FORMAT_INVALID") from exc
    try:
        rows = {}
        total = 0
        for row in archive.infolist():
            name = canonical_member(row.filename)
            if name in rows or row.is_dir():
                raise RuntimeError("DAPR_EXECUTOR_RELEASE_ENTRY_INVALID")
            mode = (row.external_attr >> 16) & 0xFFFF
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                raise RuntimeError("DAPR_EXECUTOR_RELEASE_ENTRY_INVALID")
            total += row.file_size
            if total > MAX_RELEASE_BYTES:
                raise RuntimeError("DAPR_EXECUTOR_RELEASE_UNPACKED_LIMIT")
            rows[name] = row
        roots = {name.split("/", 1)[0] for name in rows}
        if len(roots) != 1:
            raise RuntimeError("DAPR_EXECUTOR_RELEASE_ROOT_INVALID")
        root = next(iter(roots))
        manifest_name = root + "/ARTIFACT-MANIFEST.json"
        binary_name = root + "/" + BINARY_MEMBER
        if manifest_name not in rows or binary_name not in rows:
            raise RuntimeError("DAPR_EXECUTOR_RELEASE_MEMBER_MISSING")
        manifest_raw = archive.read(rows[manifest_name])
        if len(manifest_raw) > MAX_JSON_BYTES:
            raise RuntimeError("DAPR_EXECUTOR_RELEASE_MANIFEST_TOO_LARGE")
        manifest = json.loads(manifest_raw)
        if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2 or manifest.get("product") != "4SO Platform Factory":
            raise RuntimeError("DAPR_EXECUTOR_RELEASE_IDENTITY_INVALID")
        matches = [x for x in manifest.get("files", []) if isinstance(x, dict) and x.get("path") == BINARY_MEMBER]
        if len(matches) != 1:
            raise RuntimeError("DAPR_EXECUTOR_BINARY_MANIFEST_INVALID")
        binary = archive.read(rows[binary_name])
        if len(binary) <= 0 or len(binary) > MAX_MEMBER_BYTES:
            raise RuntimeError("DAPR_EXECUTOR_BINARY_SIZE_INVALID")
        actual = digest_bytes(binary)
        row = matches[0]
        if row.get("sha256") != actual.removeprefix("sha256:") or row.get("size") != len(binary) or str(row.get("mode")) != "0o755":
            raise RuntimeError("DAPR_EXECUTOR_BINARY_DIGEST_MISMATCH")
        version = str(manifest.get("version") or "").strip()
        if not version:
            raise RuntimeError("DAPR_EXECUTOR_RELEASE_VERSION_INVALID")
        return binary, actual, version
    finally:
        archive.close()


def validate_chart(chart: Path, acquisition: dict) -> bytes:
    info = chart.lstat()
    if chart.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > 64 * 1024 * 1024:
        raise RuntimeError("DAPR_EXECUTOR_CHART_INVALID")
    if chart.name != acquisition.get("helmPackageName"):
        raise RuntimeError("DAPR_EXECUTOR_CHART_NAME_MISMATCH")
    raw = chart.read_bytes()
    if digest_bytes(raw) != acquisition.get("helmPackageDigest"):
        raise RuntimeError("DAPR_EXECUTOR_CHART_DIGEST_MISMATCH")
    return raw


def prepare(release: Path, acquisition_path: Path, chart: Path, toolchain_stage: Path, out: Path) -> dict:
    release = Path(os.path.abspath(os.fspath(release.expanduser())))
    acquisition_path = Path(os.path.abspath(os.fspath(acquisition_path.expanduser())))
    chart = Path(os.path.abspath(os.fspath(chart.expanduser())))
    toolchain_stage = Path(os.path.abspath(os.fspath(toolchain_stage.expanduser())))
    out = Path(os.path.abspath(os.fspath(out.expanduser())))
    if out.exists() or out.is_symlink():
        raise RuntimeError("DAPR_EXECUTOR_CONTEXT_OUTPUT_EXISTS")
    if not DOCKERFILE.is_file() or DOCKERFILE.is_symlink():
        raise RuntimeError("DAPR_EXECUTOR_DOCKERFILE_INVALID")

    binary, binary_digest, release_version = release_binary(release)
    acquisition, acquisition_digest = load_json(acquisition_path, "DAPR_ACQUISITION")
    validate_acquisition(acquisition)
    chart_raw = validate_chart(chart, acquisition)

    out.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".4so-dapr-executor-", dir=out.parent))
    published = False
    try:
        tools_dir = stage / ".tools"
        toolchain.bootstrap_staged(toolchain_stage, tools_dir)
        resolved = toolchain.require_toolchain(tool_dir=tools_dir)
        helm_path, helm_version = resolved["helm"]
        helm_raw = helm_path.read_bytes()
        files = {
            "helm": (helm_raw, 0o555),
            "dapr-runtime": (binary, 0o555),
            f"dapr-{IMAGE_TAG}.tgz": (chart_raw, 0o444),
            "Dockerfile": (DOCKERFILE.read_bytes(), 0o444),
        }
        for name, (raw, mode) in files.items():
            target = stage / name
            target.write_bytes(raw)
            target.chmod(mode)
        lock = {
            "apiVersion": "platform.4so.io/v1alpha1",
            "kind": "DaprExecutorContext",
            "authority": AUTHORITY,
            "sourceRelease": {
                "version": release_version,
                "sha256": digest_path(release),
                "binarySha256": binary_digest,
            },
            "runtimeAcquisition": {
                "sha256": acquisition_digest,
                "authority": acquisition["authority"],
                "version": VERSION,
                "helmPackageSha256": acquisition["helmPackageDigest"],
            },
            "toolchain": {
                "authority": toolchain.AUTHORITY,
                "helmVersion": helm_version,
                "helmBinarySha256": digest_bytes(helm_raw),
            },
            "build": {
                "authority": "buildkit",
                "networkRequired": False,
                "baseImageRequired": False,
                "dockerfileSha256": digest_bytes(files["Dockerfile"][0]),
            },
            "output": {
                "repository": "dapr-runtime",
                "ociDigestKnown": False,
                "zotMirrorRequired": True,
            },
        }
        (stage / "executor-context.lock.json").write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        shutil.rmtree(tools_dir)
        stage.rename(out)
        published = True
        return lock
    finally:
        if not published:
            shutil.rmtree(stage, ignore_errors=True)


def self_test() -> int:
    if BINARY_MEMBER != "bin/linux-amd64/dapr-runtime" or VERSION != "v1.18.4":
        raise RuntimeError("DAPR_EXECUTOR_CONTEXT_IDENTITY_DRIFT")
    if DOCKERFILE.name != "Dockerfile.dapr-runtime-release":
        raise RuntimeError("DAPR_EXECUTOR_DOCKERFILE_IDENTITY_DRIFT")
    print("DAPR_EXECUTOR_CONTEXT_SELF_TEST_PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--release", type=Path)
    parser.add_argument("--acquisition", type=Path)
    parser.add_argument("--chart", type=Path)
    parser.add_argument("--toolchain-stage", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        if args.self_test:
            return self_test()
        if not all((args.release, args.acquisition, args.chart, args.toolchain_stage, args.out)):
            parser.error("--release, --acquisition, --chart, --toolchain-stage and --out are required")
        result = prepare(args.release, args.acquisition, args.chart, args.toolchain_stage, args.out)
    except (RuntimeError, OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        print(f"DAPR_EXECUTOR_CONTEXT_BLOCKED {exc}", file=__import__("sys").stderr)
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
