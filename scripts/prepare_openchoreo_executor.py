#!/usr/bin/env python3
"""Prepare an offline-only OpenChoreo runtime executor BuildKit context.

Inputs are immutable evidence: one exact 4SO FULL release, one exact OpenChoreo
acquisition bundle, and the staged pinned Helm toolchain. This command never
pulls charts/images and never claims an OCI digest.
"""
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
from openchoreo_runtime_contract import ACQUISITION_AUTHORITY, UPSTREAM_COMMIT, VERSION

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = "OPENCHOREO_EXECUTOR_CONTEXT_AUTHORITY_V1"
BINARY_MEMBER = "bin/linux-amd64/openchoreo-runtime"
DOCKERFILE = ROOT / "deploy" / "images" / "Dockerfile.openchoreo-runtime-release"
MAX_RELEASE_BYTES = 1024 * 1024 * 1024
MAX_ACQUISITION_BYTES = 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024
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
        raise RuntimeError("OPENCHOREO_EXECUTOR_ARCHIVE_PATH_INVALID")
    parts = PurePosixPath(name).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise RuntimeError("OPENCHOREO_EXECUTOR_ARCHIVE_PATH_INVALID")
    return "/".join(parts)

def zip_rows(path: Path, max_bytes: int) -> tuple[zipfile.ZipFile, dict[str, zipfile.ZipInfo]]:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > max_bytes:
        raise RuntimeError("OPENCHOREO_EXECUTOR_ARCHIVE_INVALID")
    try:
        bundle = zipfile.ZipFile(path, "r")
    except zipfile.BadZipFile as exc:
        raise RuntimeError("OPENCHOREO_EXECUTOR_ARCHIVE_FORMAT_INVALID") from exc
    rows: dict[str, zipfile.ZipInfo] = {}
    total = 0
    for row in bundle.infolist():
        name = canonical_member(row.filename)
        if name in rows:
            bundle.close()
            raise RuntimeError("OPENCHOREO_EXECUTOR_ARCHIVE_DUPLICATE_PATH")
        mode = (row.external_attr >> 16) & 0xFFFF
        if row.is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG):
            bundle.close()
            raise RuntimeError("OPENCHOREO_EXECUTOR_ARCHIVE_ENTRY_TYPE_INVALID")
        total += row.file_size
        if total > max_bytes:
            bundle.close()
            raise RuntimeError("OPENCHOREO_EXECUTOR_ARCHIVE_UNPACKED_LIMIT")
        rows[name] = row
    return bundle, rows

def read_member(bundle: zipfile.ZipFile, row: zipfile.ZipInfo, limit: int = MAX_MEMBER_BYTES) -> bytes:
    if row.file_size < 0 or row.file_size > limit:
        raise RuntimeError("OPENCHOREO_EXECUTOR_ARCHIVE_MEMBER_SIZE_INVALID")
    with bundle.open(row, "r") as fh:
        raw = fh.read(limit + 1)
    if len(raw) != row.file_size or len(raw) > limit:
        raise RuntimeError("OPENCHOREO_EXECUTOR_ARCHIVE_MEMBER_SIZE_MISMATCH")
    return raw

def strict_json(raw: bytes, label: str) -> dict:
    if len(raw) > MAX_JSON_BYTES:
        raise RuntimeError(f"{label}_TOO_LARGE")
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise RuntimeError(f"{label}_DUPLICATE_KEY")
            out[key] = value
        return out
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"{label}_INVALID") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{label}_INVALID")
    return value

def release_binary(release: Path) -> tuple[bytes, str, str]:
    bundle, rows = zip_rows(release, MAX_RELEASE_BYTES)
    try:
        roots = {name.split("/", 1)[0] for name in rows}
        if len(roots) != 1:
            raise RuntimeError("OPENCHOREO_EXECUTOR_RELEASE_ROOT_INVALID")
        root = next(iter(roots))
        manifest_name = root + "/ARTIFACT-MANIFEST.json"
        binary_name = root + "/" + BINARY_MEMBER
        if manifest_name not in rows or binary_name not in rows:
            raise RuntimeError("OPENCHOREO_EXECUTOR_RELEASE_MEMBER_MISSING")
        manifest = strict_json(read_member(bundle, rows[manifest_name], MAX_JSON_BYTES), "OPENCHOREO_EXECUTOR_RELEASE_MANIFEST")
        if manifest.get("schemaVersion") != 2 or manifest.get("product") != "4SO Platform Factory":
            raise RuntimeError("OPENCHOREO_EXECUTOR_RELEASE_IDENTITY_INVALID")
        matches = [x for x in manifest.get("files", []) if isinstance(x, dict) and x.get("path") == BINARY_MEMBER]
        if len(matches) != 1:
            raise RuntimeError("OPENCHOREO_EXECUTOR_BINARY_MANIFEST_INVALID")
        raw = read_member(bundle, rows[binary_name], 128 * 1024 * 1024)
        actual = digest_bytes(raw)
        row = matches[0]
        if row.get("sha256") != actual.removeprefix("sha256:") or row.get("size") != len(raw) or str(row.get("mode")) != "0o755":
            raise RuntimeError("OPENCHOREO_EXECUTOR_BINARY_DIGEST_MISMATCH")
        version = str(manifest.get("version") or "").strip()
        if not version:
            raise RuntimeError("OPENCHOREO_EXECUTOR_RELEASE_VERSION_INVALID")
        return raw, actual, version
    finally:
        bundle.close()

def acquisition_payload(acquisition: Path) -> tuple[dict, dict[str, bytes]]:
    bundle, rows = zip_rows(acquisition, MAX_ACQUISITION_BYTES)
    source_name = f"source/openchoreo-{UPSTREAM_COMMIT}.tar.gz"
    required = {
        "acquisition.json", "image-inventory.json", "source-selection.json", source_name,
        f"charts/openchoreo-control-plane-{VERSION}.tgz",
        f"charts/openchoreo-data-plane-{VERSION}.tgz",
        "render/control-plane-render.json", "render/data-plane-render.json",
        "values/control-plane-values.yaml", "values/data-plane-values.yaml",
    }
    try:
        if set(rows) != required:
            raise RuntimeError("OPENCHOREO_EXECUTOR_ACQUISITION_MEMBER_SET_INVALID")
        lock = strict_json(read_member(bundle, rows["acquisition.json"], MAX_JSON_BYTES), "OPENCHOREO_EXECUTOR_ACQUISITION_LOCK")
        expected = {
            "authority": ACQUISITION_AUTHORITY, "version": VERSION, "upstreamCommit": UPSTREAM_COMMIT,
            "sourceResolved": True, "imageBytesIncluded": False, "zotMirrorRequired": True, "executionReady": False,
            "buildAuthority": "buildkit", "registryAuthority": "zot",
        }
        for key, value in expected.items():
            if lock.get(key) != value:
                raise RuntimeError(f"OPENCHOREO_EXECUTOR_ACQUISITION_LOCK_INVALID {key}")
        plane_by_name = {p.get("name"): p for p in lock.get("planes", []) if isinstance(p, dict)}
        if set(plane_by_name) != {"control-plane", "data-plane"}:
            raise RuntimeError("OPENCHOREO_EXECUTOR_PLANE_INVENTORY_INVALID")
        payload: dict[str, bytes] = {}
        for name in ("control-plane", "data-plane"):
            plane = plane_by_name[name]
            chart_member = f"charts/openchoreo-{name}-{VERSION}.tgz"
            values_member = f"values/{name}-values.yaml"
            render_member = f"render/{name}-render.json"
            for member, digest_key in ((chart_member, "chartSha256"), (values_member, "valuesSha256"), (render_member, "renderManifestSha256")):
                raw = read_member(bundle, rows[member])
                if digest_bytes(raw) != plane.get(digest_key):
                    raise RuntimeError(f"OPENCHOREO_EXECUTOR_ACQUISITION_DIGEST_MISMATCH {member}")
                payload[member] = raw
        source_raw = read_member(bundle, rows[source_name])
        if digest_bytes(source_raw) != lock.get("sourceArchiveSha256"):
            raise RuntimeError("OPENCHOREO_EXECUTOR_SOURCE_ARCHIVE_DIGEST_MISMATCH")
        return lock, payload
    finally:
        bundle.close()

def prepare(release: Path, acquisition: Path, toolchain_stage: Path, out: Path) -> dict:
    # Do not resolve immutable evidence inputs before their lstat checks.
    # resolve() follows a symlink and would erase the very fact we need to reject.
    release = Path(os.path.abspath(release.expanduser()))
    acquisition = Path(os.path.abspath(acquisition.expanduser()))
    toolchain_stage = Path(os.path.abspath(toolchain_stage.expanduser()))
    out = out.expanduser().resolve()
    if out.exists() or out.is_symlink():
        raise RuntimeError("OPENCHOREO_EXECUTOR_CONTEXT_OUTPUT_EXISTS")
    if not DOCKERFILE.is_file() or DOCKERFILE.is_symlink():
        raise RuntimeError("OPENCHOREO_EXECUTOR_DOCKERFILE_INVALID")
    binary, binary_digest, release_version = release_binary(release)
    lock, payload = acquisition_payload(acquisition)
    out.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".4so-openchoreo-executor-", dir=out.parent))
    published = False
    try:
        tools_dir = stage / ".tools"
        toolchain.bootstrap_staged(toolchain_stage, tools_dir)
        resolved = toolchain.require_toolchain(tool_dir=tools_dir)
        helm_path, helm_version = resolved["helm"]
        helm_raw = helm_path.read_bytes()
        files = {
            "helm": (helm_raw, 0o555),
            "openchoreo-runtime": (binary, 0o555),
            "openchoreo-control-plane.tgz": (payload[f"charts/openchoreo-control-plane-{VERSION}.tgz"], 0o444),
            "openchoreo-data-plane.tgz": (payload[f"charts/openchoreo-data-plane-{VERSION}.tgz"], 0o444),
            "control-plane-values.yaml": (payload["values/control-plane-values.yaml"], 0o444),
            "data-plane-values.yaml": (payload["values/data-plane-values.yaml"], 0o444),
            "control-plane-render.json": (payload["render/control-plane-render.json"], 0o444),
            "data-plane-render.json": (payload["render/data-plane-render.json"], 0o444),
            "Dockerfile": (DOCKERFILE.read_bytes(), 0o444),
        }
        for name, (raw, mode) in files.items():
            path = stage / name
            path.write_bytes(raw)
            path.chmod(mode)
        context_lock = {
            "apiVersion": "platform.4so.io/v1alpha1", "kind": "OpenChoreoExecutorContext",
            "authority": AUTHORITY,
            "sourceRelease": {"version": release_version, "sha256": digest_path(release), "binarySha256": binary_digest},
            "runtimeAcquisition": {"sha256": digest_path(acquisition), "authority": ACQUISITION_AUTHORITY, "version": VERSION},
            "toolchain": {"authority": toolchain.AUTHORITY, "helmVersion": helm_version, "helmBinarySha256": digest_bytes(helm_raw)},
            "build": {"authority": "buildkit", "networkRequired": False, "baseImageRequired": False, "dockerfileSha256": digest_bytes(files["Dockerfile"][0])},
            "output": {"repository": "openchoreo-runtime", "ociDigestKnown": False, "zotMirrorRequired": True},
        }
        (stage / "executor-context.lock.json").write_text(json.dumps(context_lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        shutil.rmtree(tools_dir)
        stage.rename(out)
        published = True
        return context_lock
    finally:
        if not published:
            shutil.rmtree(stage, ignore_errors=True)

def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="4so-openchoreo-context-test-") as td:
        root = Path(td)
        bad = root / "bad.zip"
        with zipfile.ZipFile(bad, "w") as zf:
            info = zipfile.ZipInfo("../escape")
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            zf.writestr(info, b"x")
        try:
            acquisition_payload(bad)
        except RuntimeError as exc:
            if "ARCHIVE_PATH_INVALID" not in str(exc):
                raise
        else:
            raise RuntimeError("OPENCHOREO_EXECUTOR_PATH_TRAVERSAL_NEGATIVE_CONTROL_FAILED")
    print("OPENCHOREO_EXECUTOR_CONTEXT_SELF_TEST_PASS")
    return 0

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--release", type=Path)
    p.add_argument("--acquisition", type=Path)
    p.add_argument("--toolchain-stage", type=Path)
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    if args.self_test:
        return self_test()
    if not all((args.release, args.acquisition, args.toolchain_stage, args.out)):
        p.error("--release, --acquisition, --toolchain-stage and --out are required")
    try:
        result = prepare(args.release, args.acquisition, args.toolchain_stage, args.out)
    except (RuntimeError, OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"OPENCHOREO_EXECUTOR_CONTEXT_BLOCKED {exc}", file=os.sys.stderr)
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
