#!/usr/bin/env python3
"""Prepare an offline-only virtual-cluster executor image build context.

The output is a build context, not an image and never claims an OCI digest.
It accepts only:
* an exact FULL release ZIP containing virtual-cluster-renderer;
* an exact vCluster acquisition ZIP produced by acquire_virtual_cluster_runtime.py;
* the exact staged Helm archive named and SHA-256-locked by the canonical
  upstream acquisition toolchain.

No network access is performed. The resulting Dockerfile is FROM scratch and
contains only the exact Helm binary, product renderer, chart and values bytes.
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

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = "VIRTUAL_CLUSTER_EXECUTOR_CONTEXT_AUTHORITY_V1"
ACQUISITION_AUTHORITY = "VIRTUAL_CLUSTER_RUNTIME_ACQUISITION_AUTHORITY_V1"
RENDERER_MEMBER = "bin/linux-amd64/virtual-cluster-renderer"
DOCKERFILE = ROOT / "deploy" / "images" / "Dockerfile.virtual-cluster-runtime-release"
MAX_RELEASE_BYTES = 1024 * 1024 * 1024
MAX_ACQUISITION_BYTES = 256 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _regular(path: Path, label: str, max_bytes: int | None = None) -> os.stat_result:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"{label}_NOT_REGULAR")
    if info.st_size <= 0 or (max_bytes is not None and info.st_size > max_bytes):
        raise RuntimeError(f"{label}_SIZE_INVALID")
    return info


def _canonical_member(name: str) -> str:
    if not isinstance(name, str) or not name or name.startswith("/") or "\\" in name or "\x00" in name or name.endswith("/"):
        raise RuntimeError("EXECUTOR_CONTEXT_ARCHIVE_PATH_INVALID")
    parts = PurePosixPath(name).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise RuntimeError("EXECUTOR_CONTEXT_ARCHIVE_PATH_INVALID")
    return "/".join(parts)


def _zip_rows(path: Path, *, max_bytes: int) -> tuple[zipfile.ZipFile, dict[str, zipfile.ZipInfo]]:
    _regular(path, "EXECUTOR_CONTEXT_ARCHIVE", max_bytes)
    try:
        bundle = zipfile.ZipFile(path, "r")
    except zipfile.BadZipFile as exc:
        raise RuntimeError("EXECUTOR_CONTEXT_ARCHIVE_FORMAT_INVALID") from exc
    rows: dict[str, zipfile.ZipInfo] = {}
    total = 0
    for info in bundle.infolist():
        name = _canonical_member(info.filename)
        if name in rows:
            bundle.close()
            raise RuntimeError("EXECUTOR_CONTEXT_ARCHIVE_DUPLICATE_PATH")
        mode = (info.external_attr >> 16) & 0xFFFF
        kind = stat.S_IFMT(mode)
        if info.is_dir() or kind not in (0, stat.S_IFREG):
            bundle.close()
            raise RuntimeError("EXECUTOR_CONTEXT_ARCHIVE_ENTRY_TYPE_INVALID")
        if info.file_size < 0:
            bundle.close()
            raise RuntimeError("EXECUTOR_CONTEXT_ARCHIVE_ENTRY_SIZE_INVALID")
        total += info.file_size
        if total > max_bytes:
            bundle.close()
            raise RuntimeError("EXECUTOR_CONTEXT_ARCHIVE_UNPACKED_LIMIT")
        rows[name] = info
    return bundle, rows


def _read_member(bundle: zipfile.ZipFile, info: zipfile.ZipInfo, *, limit: int) -> bytes:
    if info.file_size > limit:
        raise RuntimeError("EXECUTOR_CONTEXT_ARCHIVE_MEMBER_TOO_LARGE")
    with bundle.open(info, "r") as fh:
        raw = fh.read(limit + 1)
    if len(raw) != info.file_size or len(raw) > limit:
        raise RuntimeError("EXECUTOR_CONTEXT_ARCHIVE_MEMBER_SIZE_MISMATCH")
    return raw


def _strict_json(raw: bytes, label: str) -> dict:
    if len(raw) > MAX_JSON_BYTES:
        raise RuntimeError(f"{label}_TOO_LARGE")
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise RuntimeError(f"{label}_DUPLICATE_JSON_KEY")
            out[key] = value
        return out
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"{label}_INVALID_JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{label}_INVALID_JSON")
    return value


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def release_renderer(release: Path) -> tuple[bytes, str, str]:
    bundle, rows = _zip_rows(release, max_bytes=MAX_RELEASE_BYTES)
    try:
        roots = {name.split("/", 1)[0] for name in rows}
        if len(roots) != 1:
            raise RuntimeError("EXECUTOR_RELEASE_ROOT_INVALID")
        root = next(iter(roots))
        manifest_name = root + "/ARTIFACT-MANIFEST.json"
        renderer_name = root + "/" + RENDERER_MEMBER
        if manifest_name not in rows or renderer_name not in rows:
            raise RuntimeError("EXECUTOR_RELEASE_REQUIRED_MEMBER_MISSING")
        manifest = _strict_json(_read_member(bundle, rows[manifest_name], limit=MAX_JSON_BYTES), "EXECUTOR_RELEASE_MANIFEST")
        if manifest.get("schemaVersion") != 2 or manifest.get("product") != "4SO Platform Factory":
            raise RuntimeError("EXECUTOR_RELEASE_MANIFEST_IDENTITY_INVALID")
        records = manifest.get("files")
        if not isinstance(records, list):
            raise RuntimeError("EXECUTOR_RELEASE_MANIFEST_FILES_INVALID")
        matches = [row for row in records if isinstance(row, dict) and row.get("path") == RENDERER_MEMBER]
        if len(matches) != 1:
            raise RuntimeError("EXECUTOR_RELEASE_RENDERER_MANIFEST_INVALID")
        raw = _read_member(bundle, rows[renderer_name], limit=128 * 1024 * 1024)
        actual = _digest(raw)
        if matches[0].get("sha256") != actual.removeprefix("sha256:") or int(matches[0].get("size", -1)) != len(raw):
            raise RuntimeError("EXECUTOR_RELEASE_RENDERER_DIGEST_MISMATCH")
        if str(matches[0].get("mode")) != "0o755":
            raise RuntimeError("EXECUTOR_RELEASE_RENDERER_MODE_INVALID")
        version = str(manifest.get("version") or "")
        if not version:
            raise RuntimeError("EXECUTOR_RELEASE_VERSION_INVALID")
        return raw, actual, version
    finally:
        bundle.close()


def acquisition_payload(acquisition: Path) -> tuple[dict, bytes, bytes]:
    bundle, rows = _zip_rows(acquisition, max_bytes=MAX_ACQUISITION_BYTES)
    try:
        required = {
            "acquisition.json",
            "chart/vcluster-0.37.1.tgz",
            "values/vcluster-oss-values.yaml",
            "render-manifest.json",
            "image-inventory.json",
            "source-selection.json",
        }
        if set(rows) != required:
            raise RuntimeError("EXECUTOR_ACQUISITION_MEMBER_SET_INVALID")
        lock = _strict_json(_read_member(bundle, rows["acquisition.json"], limit=MAX_JSON_BYTES), "EXECUTOR_ACQUISITION_LOCK")
        expected = {
            "authority": ACQUISITION_AUTHORITY,
            "engine": "vcluster-oss",
            "version": "0.37.1",
            "sourceResolved": True,
            "imageBytesIncluded": False,
            "zotMirrorRequired": True,
            "executionReady": False,
        }
        for key, value in expected.items():
            if lock.get(key) != value:
                raise RuntimeError(f"EXECUTOR_ACQUISITION_LOCK_INVALID {key}")
        chart = _read_member(bundle, rows["chart/vcluster-0.37.1.tgz"], limit=64 * 1024 * 1024)
        values = _read_member(bundle, rows["values/vcluster-oss-values.yaml"], limit=4 * 1024 * 1024)
        if _digest(chart) != lock.get("chartSha256"):
            raise RuntimeError("EXECUTOR_ACQUISITION_CHART_DIGEST_MISMATCH")
        if _digest(values) != lock.get("valuesSha256"):
            raise RuntimeError("EXECUTOR_ACQUISITION_VALUES_DIGEST_MISMATCH")
        if lock.get("chartArtifactPath") != "runtime/virtualcluster/chart/vcluster-0.37.1.tgz":
            raise RuntimeError("EXECUTOR_ACQUISITION_CHART_PATH_INVALID")
        return lock, chart, values
    finally:
        bundle.close()


def prepare(release: Path, acquisition: Path, toolchain_stage: Path, out: Path) -> dict:
    release = release.expanduser().resolve()
    acquisition = acquisition.expanduser().resolve()
    toolchain_stage = toolchain_stage.expanduser().resolve()
    out = out.expanduser().resolve()
    if out.exists() or out.is_symlink():
        raise RuntimeError("EXECUTOR_CONTEXT_OUTPUT_EXISTS")
    if not DOCKERFILE.is_file() or DOCKERFILE.is_symlink():
        raise RuntimeError("EXECUTOR_CONTEXT_DOCKERFILE_INVALID")
    renderer, renderer_digest, release_version = release_renderer(release)
    acquisition_lock, chart, values = acquisition_payload(acquisition)

    parent = out.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".4so-vcluster-executor-", dir=parent))
    tools = staging / ".tools"
    published = False
    try:
        toolchain.bootstrap_staged(toolchain_stage, tools)
        resolved = toolchain.require_toolchain(tool_dir=tools)
        helm_path, helm_version = resolved["helm"]
        helm_raw = helm_path.read_bytes()
        files = {
            "helm": (helm_raw, 0o555),
            "virtual-cluster-renderer": (renderer, 0o555),
            "vcluster.tgz": (chart, 0o444),
            "execution-values.yaml": (values, 0o444),
            "Dockerfile": (DOCKERFILE.read_bytes(), 0o444),
        }
        for name, (raw, mode) in files.items():
            target = staging / name
            target.write_bytes(raw)
            target.chmod(mode)

        lock = {
            "apiVersion": "platform.4so.io/v1alpha1",
            "kind": "VirtualClusterExecutorContext",
            "authority": AUTHORITY,
            "sourceRelease": {
                "version": release_version,
                "sha256": sha256_path(release),
                "rendererSha256": renderer_digest,
            },
            "runtimeAcquisition": {
                "sha256": sha256_path(acquisition),
                "chartSha256": acquisition_lock["chartSha256"],
                "valuesSha256": acquisition_lock["valuesSha256"],
            },
            "toolchain": {
                "authority": toolchain.AUTHORITY,
                "helmVersion": helm_version,
                "helmBinarySha256": _digest(helm_raw),
            },
            "build": {
                "dockerfileSha256": _digest(files["Dockerfile"][0]),
                "networkRequired": False,
                "baseImageRequired": False,
                "expectedEntrypoint": ["/usr/local/bin/helm"],
                "expectedPostRenderer": "/usr/local/bin/4so-vcluster-post-renderer",
            },
            "output": {
                "ociDigestKnown": False,
                "mirrorRequired": True,
            },
        }
        (staging / "executor-context.lock.json").write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        shutil.rmtree(tools)
        staging.rename(out)
        published = True
        return lock
    finally:
        if not published:
            shutil.rmtree(staging, ignore_errors=True)


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="4so-vcluster-context-selftest-") as td:
        root = Path(td)
        # Acquisition validation is exercised without network or external tools.
        chart = b"exact-chart-bytes"
        values = b"controlPlane:\n  statefulSet:\n    image:\n      repository: loft-sh/vcluster-oss\n"
        lock = {
            "authority": ACQUISITION_AUTHORITY,
            "engine": "vcluster-oss",
            "version": "0.37.1",
            "sourceResolved": True,
            "imageBytesIncluded": False,
            "zotMirrorRequired": True,
            "executionReady": False,
            "chartSha256": _digest(chart),
            "valuesSha256": _digest(values),
            "chartArtifactPath": "runtime/virtualcluster/chart/vcluster-0.37.1.tgz",
        }
        acquisition = root / "acquisition.zip"
        members = {
            "acquisition.json": json.dumps(lock, sort_keys=True).encode(),
            "chart/vcluster-0.37.1.tgz": chart,
            "values/vcluster-oss-values.yaml": values,
            "render-manifest.json": b"[]\n",
            "image-inventory.json": b'{"images":[]}\n',
            "source-selection.json": b"{}\n",
        }
        with zipfile.ZipFile(acquisition, "w") as zf:
            for name, raw in members.items():
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                zf.writestr(info, raw)
        parsed, actual_chart, actual_values = acquisition_payload(acquisition)
        assert parsed["chartSha256"] == _digest(actual_chart)
        assert parsed["valuesSha256"] == _digest(actual_values)

        bad = root / "bad.zip"
        with zipfile.ZipFile(bad, "w") as zf:
            info = zipfile.ZipInfo("../escape")
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            zf.writestr(info, b"x")
        try:
            acquisition_payload(bad)
        except RuntimeError as exc:
            assert "ARCHIVE_PATH_INVALID" in str(exc)
        else:
            raise AssertionError("path traversal acquisition entry must fail closed")

    print(f"VIRTUAL_CLUSTER_EXECUTOR_CONTEXT_SELF_TEST_PASS authority={AUTHORITY}")
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
        if any((args.release, args.acquisition, args.toolchain_stage, args.out)):
            p.error("--self-test does not accept build inputs")
        return self_test()
    if not all((args.release, args.acquisition, args.toolchain_stage, args.out)):
        p.error("--release, --acquisition, --toolchain-stage and --out are required")
    try:
        lock = prepare(args.release, args.acquisition, args.toolchain_stage, args.out)
    except (RuntimeError, OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"VIRTUAL_CLUSTER_EXECUTOR_CONTEXT_BLOCKED {exc}", file=os.sys.stderr)
        return 3
    print(json.dumps(lock, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
