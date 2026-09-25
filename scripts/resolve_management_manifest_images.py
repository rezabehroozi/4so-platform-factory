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

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
from upstream_acquisition_toolchain import require_toolchain

AUTHORITY = "MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RECEIPT_V1"
RESOLUTION_AUTHORITY = "MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_V1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


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


def canonical_repository(ref: str) -> str:
    ref = ref.strip()
    if not ref or any(ch.isspace() for ch in ref):
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
            digest = run([str(crane), "digest", source_ref], timeout=600).splitlines()[-1].strip()
            if not DIGEST_RE.fullmatch(digest):
                raise RuntimeError(f"MANIFEST_IMAGE_DIGEST_INVALID {source_ref}:{digest}")
            resolutions.extend(["--resolution", source_ref + "=" + canonical_repository(source_ref) + "@" + digest])

        out_manifest = ROOT / str(row.get("resolvedManifestPath") or "")
        out_lock = ROOT / str(row.get("resolutionLockPath") or "")
        if out_manifest.exists() or out_manifest.is_symlink() or out_lock.exists() or out_lock.is_symlink():
            raise RuntimeError(f"MANIFEST_RESOLUTION_OUTPUT_ALREADY_EXISTS {authority}")
        result = run_json([
            str(platformctl), "workload-oci", "resolve-manifest",
            "--manifest", str(source), *resolutions,
            "--out-manifest", str(out_manifest), "--out-lock", str(out_lock),
        ])
        if result.get("authority") != RESOLUTION_AUTHORITY or result.get("resolved") is not True:
            raise RuntimeError(f"MANIFEST_RESOLUTION_RESULT_INVALID {authority}")
        verify = run_json([str(platformctl), "workload-oci", "inspect-manifest", "--manifest", str(out_manifest)])
        if verify.get("resolutionRequiredCount") != 0:
            raise RuntimeError(f"MANIFEST_RESOLUTION_MUTABLE_IMAGE_REMAINS {authority}")
        lock = json.loads(regular_file(out_lock, "MANIFEST_RESOLUTION_LOCK").read_text())
        if lock.get("authority") != RESOLUTION_AUTHORITY or lock.get("sourceManifestSha256") != row.get("sourceManifestSha256"):
            raise RuntimeError(f"MANIFEST_RESOLUTION_LOCK_INVALID {authority}")
        sets.append({
            "sourceAuthority": authority,
            "sourceManifestPath": str(row["manifestPath"]),
            "sourceManifestSha256": str(row["sourceManifestSha256"]),
            "resolvedManifestPath": str(row["resolvedManifestPath"]),
            "resolvedManifestSha256": sha256_file(out_manifest),
            "resolutionLockPath": str(row["resolutionLockPath"]),
            "resolutionLockSha256": sha256_file(out_lock),
            "imageCount": int(verify.get("imageCount") or 0),
            "exactImages": sorted(str(x) for x in (verify.get("images") or [])),
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
