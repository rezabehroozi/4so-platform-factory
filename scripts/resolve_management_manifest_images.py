#!/usr/bin/env python3
"""Resolve management manifest runtime images to immutable digests using pinned tooling."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
from upstream_acquisition_toolchain import require_toolchain

AUTHORITY = "MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RECEIPT_V1"
RESOLUTION_AUTHORITY = "MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_V1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TARGET_PLATFORM = "linux/amd64"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def regular_file(path: Path, label: str) -> Path:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size <= 0:
        raise RuntimeError(f"{label}_NOT_REGULAR {path}")
    return path


def run(cmd: list[str], *, timeout: int = 900) -> str:
    proc = subprocess.run(cmd, cwd=ROOT, stdin=subprocess.DEVNULL, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if proc.returncode:
        raise RuntimeError(f"COMMAND_FAILED rc={proc.returncode} cmd={cmd!r}\n{proc.stdout[-8000:]}")
    return proc.stdout.strip()


def run_json(cmd: list[str], *, timeout: int = 900) -> dict:
    raw = run(cmd, timeout=timeout)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"COMMAND_JSON_INVALID {cmd!r}: {raw[-2000:]!r}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("COMMAND_JSON_OBJECT_REQUIRED")
    return value


def resolve_platform_digest(crane: Path, source_ref: str) -> str:
    """Resolve the exact linux/amd64 image manifest, never a multi-arch index."""
    digest = run([str(crane), "digest", "--platform", TARGET_PLATFORM, source_ref], timeout=600).splitlines()[-1].strip()
    if not DIGEST_RE.fullmatch(digest):
        raise RuntimeError(f"MANIFEST_IMAGE_DIGEST_INVALID {source_ref}:{digest}")
    return digest


def canonical_repository(ref: str) -> str:
    raw = ref
    ref = ref.strip()
    if ref != raw or not ref or any(ch.isspace() for ch in ref):
        raise RuntimeError(f"IMAGE_REFERENCE_INVALID {ref!r}")
    if "@sha256:" in ref:
        ref = ref.split("@sha256:", 1)[0]
    slash = ref.rfind("/")
    if slash <= 0:
        raise RuntimeError(f"IMAGE_REFERENCE_REGISTRY_REQUIRED {ref}")
    colon = ref.rfind(":")
    if colon > slash:
        ref = ref[:colon]
    if not ref or ref.endswith("/") or "@" in ref:
        raise RuntimeError(f"IMAGE_REPOSITORY_INVALID {ref}")
    return ref


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise



def _exact_manifest_authorities(plan: dict) -> dict[str, dict]:
    lock_path = regular_file(ROOT / "lab" / "appliance-bundle-acquisition-lock.json", "BUNDLE_ACQUISITION_LOCK")
    lock = json.loads(lock_path.read_text())
    if lock.get("authority") != "LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8":
        raise RuntimeError("BUNDLE_ACQUISITION_LOCK_AUTHORITY_INVALID")
    by_id = {
        str(row.get("id") or ""): row
        for row in (lock.get("resolvedAuthorities") or [])
        if isinstance(row, dict)
    }
    expected: dict[str, dict] = {}
    for row in plan.get("derivedManifestImageSets") or []:
        authority = str(row.get("sourceAuthority") or "")
        source = by_id.get(authority)
        if source is None:
            raise RuntimeError(f"SOURCE_MANIFEST_AUTHORITY_MISSING {authority}")
        artifacts = source.get("artifacts") or []
        if not isinstance(artifacts, list) or len(artifacts) != 1 or not isinstance(artifacts[0], dict):
            raise RuntimeError(f"SOURCE_MANIFEST_ARTIFACT_SET_INVALID {authority}")
        artifact = artifacts[0]
        urls = artifact.get("urls") or []
        if (
            artifact.get("stagingPath") != row.get("manifestPath")
            or int(artifact.get("sizeBytes") or -1) != int(row.get("sourceManifestBytes") or -2)
            or "sha256:" + str(artifact.get("sha256") or "") != str(row.get("sourceManifestSha256") or "")
            or not isinstance(urls, list)
            or len(urls) != 1
            or not isinstance(urls[0], str)
        ):
            raise RuntimeError(f"SOURCE_MANIFEST_AUTHORITY_DRIFT {authority}")
        parsed = urllib.parse.urlsplit(urls[0])
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise RuntimeError(f"SOURCE_MANIFEST_URL_INVALID {authority}")
        expected[authority] = artifact
    if len(expected) != 4:
        raise RuntimeError("SOURCE_MANIFEST_AUTHORITY_COVERAGE_INVALID")
    return expected


def _materialize_exact_file(url: str, out: Path, expected_bytes: int, expected_sha: str, label: str) -> None:
    if out.exists() or out.is_symlink():
        regular_file(out, label)
        if out.stat().st_size != expected_bytes or sha256_file(out) != expected_sha:
            raise RuntimeError(f"{label}_EXISTING_IDENTITY_DRIFT")
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "4so-platform-factory-management-manifest/1"})
    with urllib.request.urlopen(req, timeout=120) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme != "https" or not final.hostname or final.username or final.password:
            raise RuntimeError(f"{label}_HTTPS_DOWNGRADE")
        payload = response.read(expected_bytes + 1)
        if len(payload) != expected_bytes or response.read(1):
            raise RuntimeError(f"{label}_SIZE_MISMATCH")
    actual_sha = "sha256:" + hashlib.sha256(payload).hexdigest()
    if actual_sha != expected_sha:
        raise RuntimeError(f"{label}_DIGEST_MISMATCH expected={expected_sha} actual={actual_sha}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(out, flags, 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        try:
            out.unlink()
        except OSError:
            pass
        raise


def replace_generated_file(staged: Path, target: Path, label: str) -> None:
    regular_file(staged, label + "_STAGED")
    if target.exists() or target.is_symlink():
        regular_file(target, label + "_EXISTING")
    target.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(staged, 0o644)
    os.replace(staged, target)


def _materialize_source_manifests(plan: dict) -> None:
    authorities = _exact_manifest_authorities(plan)
    for row in plan.get("derivedManifestImageSets") or []:
        authority = str(row.get("sourceAuthority") or "")
        artifact = authorities[authority]
        _materialize_exact_file(
            str((artifact.get("urls") or [])[0]),
            ROOT / str(row.get("manifestPath") or ""),
            int(row.get("sourceManifestBytes") or 0),
            str(row.get("sourceManifestSha256") or ""),
            "SOURCE_MANIFEST_" + authority.upper().replace("-", "_"),
        )

def resolve_all(platformctl: Path, receipt_out: Path, run_id: str) -> dict:
    regular_file(platformctl, "PLATFORMCTL")
    if not os.access(platformctl, os.X_OK):
        raise RuntimeError("PLATFORMCTL_NOT_EXECUTABLE")
    plan_path = regular_file(ROOT / "lab" / "management-workload-image-build-plan.json", "MANAGEMENT_IMAGE_PLAN")
    plan = json.loads(plan_path.read_text())
    if plan.get("authority") != "MANAGEMENT_WORKLOAD_IMAGE_BUILD_PLAN_V5" or plan.get("manifestImageResolutionAuthority") != RESOLUTION_AUTHORITY:
        raise RuntimeError("MANAGEMENT_IMAGE_PLAN_AUTHORITY_INVALID")
    rows = plan.get("derivedManifestImageSets") or []
    if not isinstance(rows, list) or len(rows) != 4:
        raise RuntimeError("MANAGEMENT_MANIFEST_SET_COVERAGE_INVALID")
    if not str(run_id).isdigit():
        raise RuntimeError("RUN_ID_INVALID")

    _materialize_source_manifests(plan)
    tools = require_toolchain()
    crane = Path(str(tools["crane"][0]))
    regular_file(crane, "PINNED_CRANE")
    sets = []
    for row in sorted(rows, key=lambda item: str(item.get("sourceAuthority") or "")):
        authority = str(row.get("sourceAuthority") or "")
        source = regular_file(ROOT / str(row.get("manifestPath") or ""), "SOURCE_MANIFEST")
        if source.stat().st_size != int(row.get("sourceManifestBytes") or -1) or sha256_file(source) != str(row.get("sourceManifestSha256") or ""):
            raise RuntimeError(f"SOURCE_MANIFEST_IDENTITY_DRIFT {authority}")
        inspected = run_json([str(platformctl), "workload-oci", "inspect-manifest", "--manifest", str(source)])
        if inspected.get("authority") != RESOLUTION_AUTHORITY:
            raise RuntimeError(f"MANIFEST_INSPECTION_AUTHORITY_INVALID {authority}")
        mutable = inspected.get("resolutionRequired") or []
        if not isinstance(mutable, list):
            raise RuntimeError(f"MANIFEST_INSPECTION_SHAPE_INVALID {authority}")
        resolutions: list[str] = []
        for source_ref in sorted(str(x) for x in mutable):
            digest = resolve_platform_digest(crane, source_ref)
            resolutions.extend(["--resolution", source_ref + "=" + canonical_repository(source_ref) + "@" + digest])

        out_manifest = ROOT / str(row.get("resolvedManifestPath") or "")
        out_lock = ROOT / str(row.get("resolutionLockPath") or "")
        with tempfile.TemporaryDirectory(prefix=".management-manifest-", dir=ROOT) as td:
            temp_root = Path(td)
            staged_manifest = temp_root / "resolved.yaml"
            staged_lock = temp_root / "resolution-lock.json"
            result = run_json([
                str(platformctl), "workload-oci", "resolve-manifest",
                "--manifest", str(source), *resolutions,
                "--out-manifest", str(staged_manifest), "--out-lock", str(staged_lock),
            ])
            if result.get("authority") != RESOLUTION_AUTHORITY or result.get("resolved") is not True:
                raise RuntimeError(f"MANIFEST_RESOLUTION_RESULT_INVALID {authority}")
            verify = run_json([str(platformctl), "workload-oci", "inspect-manifest", "--manifest", str(staged_manifest)])
            if verify.get("resolutionRequiredCount") != 0:
                raise RuntimeError(f"MANIFEST_RESOLUTION_MUTABLE_IMAGE_REMAINS {authority}")
            lock = json.loads(regular_file(staged_lock, "MANIFEST_RESOLUTION_LOCK").read_text())
            if lock.get("authority") != RESOLUTION_AUTHORITY or lock.get("sourceManifestSha256") != row.get("sourceManifestSha256"):
                raise RuntimeError(f"MANIFEST_RESOLUTION_LOCK_INVALID {authority}")
            resolved_sha = sha256_file(staged_manifest)
            lock_sha = sha256_file(staged_lock)
            exact_images = sorted(str(x) for x in (verify.get("images") or []))
            image_count = int(verify.get("imageCount") or 0)
            replace_generated_file(staged_manifest, out_manifest, "RESOLVED_MANIFEST")
            replace_generated_file(staged_lock, out_lock, "MANIFEST_RESOLUTION_LOCK")
        sets.append({
            "sourceAuthority": authority,
            "sourceManifestPath": str(row["manifestPath"]),
            "sourceManifestSha256": str(row["sourceManifestSha256"]),
            "resolvedManifestPath": str(row["resolvedManifestPath"]),
            "resolvedManifestSha256": resolved_sha,
            "resolutionLockPath": str(row["resolutionLockPath"]),
            "resolutionLockSha256": lock_sha,
            "imageCount": image_count,
            "exactImages": exact_images,
        })

    receipt = {
        "authority": AUTHORITY,
        "schemaVersion": 1,
        "releaseVersion": str(plan.get("releaseVersion") or ""),
        "planDigest": sha256_file(plan_path),
        "sourceRunId": str(run_id),
        "resolved": True,
        "runtimeCertified": False,
        "physicalCertified": False,
        "sets": sets,
    }
    atomic_json(receipt_out, receipt)
    return receipt


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--platformctl", required=True)
    ap.add_argument("--receipt", default="lab/management-workload-manifest-image-receipt.json")
    ap.add_argument("--run-id", required=True)
    args = ap.parse_args()
    receipt = resolve_all(Path(args.platformctl), ROOT / args.receipt, args.run_id)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
