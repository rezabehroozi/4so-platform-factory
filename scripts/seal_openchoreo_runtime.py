#!/usr/bin/env python3
"""Seal exact OpenChoreo acquisition + zot mirror + executor image evidence.

The output is the direct OPENCHOREO_RUNTIME_SOURCE_AUTHORITY_V1 JSON consumed by
Platform API. No source bytes, mirror state or executor digest are inferred.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from openchoreo_runtime_contract import (
    ACQUISITION_AUTHORITY,
    SOURCE_AUTHORITY,
    UPSTREAM_COMMIT,
    UPSTREAM_REPOSITORY,
    VERSION,
    admit_output_path,
)
from prepare_openchoreo_executor import acquisition_payload, digest_path, strict_json

MIRROR_AUTHORITY = "OPENCHOREO_ZOT_MIRROR_EVIDENCE_V1"
EXECUTOR_AUTHORITY = "OPENCHOREO_EXECUTOR_IMAGE_EVIDENCE_V1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

def load_json(path: Path, label: str) -> dict:
    path = path.expanduser()
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_size <= 0 or info.st_size > 16 * 1024 * 1024:
        raise RuntimeError(f"{label}_FILE_INVALID")
    path = path.resolve()
    return strict_json(path.read_bytes(), label)

def validate_exact_ref(ref: str, digest: str, label: str) -> None:
    if not DIGEST_RE.fullmatch(digest) or not ref.endswith("@" + digest) or any(c.isspace() for c in ref):
        raise RuntimeError(f"{label}_REFERENCE_INVALID")

def seal(acquisition: Path, mirror_path: Path, executor_path: Path, out: Path) -> dict:
    acquisition = acquisition.expanduser()
    acquisition_lock, _ = acquisition_payload(acquisition)
    acquisition_digest = digest_path(acquisition)
    mirror = load_json(mirror_path, "OPENCHOREO_MIRROR_EVIDENCE")
    executor = load_json(executor_path, "OPENCHOREO_EXECUTOR_EVIDENCE")

    if mirror.get("authority") != MIRROR_AUTHORITY or mirror.get("registryAuthority") != "zot" or mirror.get("mirrorReady") is not True:
        raise RuntimeError("OPENCHOREO_MIRROR_EVIDENCE_AUTHORITY_INVALID")
    if mirror.get("acquisitionBundleSha256") != acquisition_digest or mirror.get("version") != VERSION or mirror.get("upstreamCommit") != UPSTREAM_COMMIT:
        raise RuntimeError("OPENCHOREO_MIRROR_EVIDENCE_SOURCE_MISMATCH")
    mirror_registry = str(mirror.get("registryIdentity") or "").strip().lower()
    if not mirror_registry or "/" in mirror_registry or "://" in mirror_registry:
        raise RuntimeError("OPENCHOREO_MIRROR_REGISTRY_IDENTITY_INVALID")

    acquired = {}
    for row in acquisition_lock.get("images") or []:
        source = str(row.get("sourceReference") or "")
        digest = str(row.get("digest") or "").lower()
        validate_exact_ref(source, digest, "OPENCHOREO_ACQUIRED_IMAGE")
        if source in acquired:
            raise RuntimeError("OPENCHOREO_ACQUIRED_IMAGE_DUPLICATE")
        acquired[source] = digest

    mirrored = {}
    runtime_images = []
    for row in mirror.get("images") or []:
        source = str(row.get("sourceReference") or "")
        digest = str(row.get("digest") or "").lower()
        mirror_ref = str(row.get("mirrorReference") or "")
        validate_exact_ref(source, digest, "OPENCHOREO_MIRROR_SOURCE")
        validate_exact_ref(mirror_ref, digest, "OPENCHOREO_MIRROR_TARGET")
        if source not in acquired or acquired[source] != digest or source in mirrored:
            raise RuntimeError("OPENCHOREO_MIRROR_INVENTORY_MISMATCH")
        mirrored[source] = digest
        runtime_images.append({"sourceReference": source, "digest": digest, "mirrorReference": mirror_ref})
    if mirrored != acquired:
        raise RuntimeError("OPENCHOREO_MIRROR_INVENTORY_INCOMPLETE")

    if executor.get("authority") != EXECUTOR_AUTHORITY or executor.get("buildAuthority") != "buildkit" or executor.get("registryAuthority") != "zot":
        raise RuntimeError("OPENCHOREO_EXECUTOR_EVIDENCE_AUTHORITY_INVALID")
    if executor.get("acquisitionBundleSha256") != acquisition_digest or executor.get("registryReadback") is not True or executor.get("mirrorReady") is not True:
        raise RuntimeError("OPENCHOREO_EXECUTOR_EVIDENCE_SOURCE_MISMATCH")
    executor_registry = str(executor.get("registryIdentity") or "").strip().lower()
    if executor_registry != mirror_registry:
        raise RuntimeError("OPENCHOREO_RUNTIME_REGISTRY_IDENTITY_MISMATCH")
    executor_ref = str(executor.get("imageReference") or "")
    executor_digest = str(executor.get("imageDigest") or "").lower()
    validate_exact_ref(executor_ref, executor_digest, "OPENCHOREO_EXECUTOR_IMAGE")
    if "/openchoreo-runtime@" not in executor_ref:
        raise RuntimeError("OPENCHOREO_EXECUTOR_IMAGE_REPOSITORY_INVALID")

    planes = acquisition_lock.get("planes") or []
    if {p.get("name") for p in planes if isinstance(p, dict)} != {"control-plane", "data-plane"}:
        raise RuntimeError("OPENCHOREO_RUNTIME_PLANE_INVENTORY_INVALID")
    for plane in planes:
        for key in ("chartSha256", "valuesSha256", "renderManifestSha256"):
            if not DIGEST_RE.fullmatch(str(plane.get(key) or "")):
                raise RuntimeError(f"OPENCHOREO_RUNTIME_PLANE_DIGEST_INVALID {plane.get('name')} {key}")

    source_archive_digest = str(acquisition_lock.get("sourceArchiveSha256") or "")
    if not DIGEST_RE.fullmatch(source_archive_digest):
        raise RuntimeError("OPENCHOREO_RUNTIME_SOURCE_ARCHIVE_DIGEST_INVALID")

    runtime = {
        "authority": SOURCE_AUTHORITY,
        "version": VERSION,
        "upstreamRepository": UPSTREAM_REPOSITORY,
        "upstreamCommit": UPSTREAM_COMMIT,
        "sourceArchiveSha256": source_archive_digest,
        "planes": sorted(planes, key=lambda p: p["name"]),
        "images": sorted(runtime_images, key=lambda row: (row["digest"], row["sourceReference"])),
        "executorImageReference": executor_ref,
        "executorImageDigest": executor_digest,
        "resolved": True,
        "mirrorReady": True,
        "backstageEnabled": False,
        "workflowPlaneEnabled": False,
        "observabilityPlaneEnabled": False,
        "openChoreoMcpEnabled": False,
        "externalOidcRequired": True,
        "buildAuthority": "buildkit",
        "registryAuthority": "zot",
        "registryIdentity": mirror_registry,
    }
    out = admit_output_path(out, "OPENCHOREO_RUNTIME_SEAL_OUTPUT")
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(runtime, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(out)
    return runtime

def self_test() -> int:
    digest = "sha256:" + "a" * 64
    validate_exact_ref("zot.internal/openchoreo/api@" + digest, digest, "SELF_TEST")
    try:
        validate_exact_ref("zot.internal/openchoreo/api:latest", digest, "SELF_TEST")
    except RuntimeError:
        pass
    else:
        raise RuntimeError("OPENCHOREO_RUNTIME_SEAL_MUTABLE_REFERENCE_NEGATIVE_CONTROL_FAILED")
    print("OPENCHOREO_RUNTIME_SEAL_SELF_TEST_PASS")
    return 0

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--acquisition", type=Path)
    p.add_argument("--mirror-evidence", type=Path)
    p.add_argument("--executor-evidence", type=Path)
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    if args.self_test:
        return self_test()
    if not all((args.acquisition, args.mirror_evidence, args.executor_evidence, args.out)):
        p.error("--acquisition, --mirror-evidence, --executor-evidence and --out are required")
    try:
        runtime = seal(args.acquisition, args.mirror_evidence, args.executor_evidence, args.out)
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"OPENCHOREO_RUNTIME_SEAL_BLOCKED {exc}", file=__import__("sys").stderr)
        return 3
    print(json.dumps(runtime, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
