#!/usr/bin/env python3
"""Validate the Git-safe external management image receipt against its exact plan."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat

from management_product_image_evidence import verify as verify_product_image_receipt

AUTHORITY = "MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_RECEIPT_V1"
MANIFEST_AUTHORITY = "MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RECEIPT_V1"
MANIFEST_RESOLUTION_AUTHORITY = "MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_V1"
PRODUCT_AUTHORITY = "MANAGEMENT_WORKLOAD_PRODUCT_IMAGE_RECEIPT_V1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _regular(path: Path, label: str) -> Path:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise RuntimeError(f"{label}_NOT_REGULAR")
    return path


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def external_receipt_evidence(root: Path, plan: dict) -> dict:
    """Return exact external-image evidence without promoting final archive/runtime state."""
    plan_path = _regular(root / "lab" / "management-workload-image-build-plan.json", "MANAGEMENT_IMAGE_PLAN")
    receipt_path = _regular(root / "lab" / "management-workload-external-image-receipt.json", "MANAGEMENT_EXTERNAL_RECEIPT")
    try:
        receipt = json.loads(receipt_path.read_text())
    except json.JSONDecodeError as exc:
        raise RuntimeError("MANAGEMENT_EXTERNAL_RECEIPT_JSON_INVALID") from exc
    if not isinstance(receipt, dict) or receipt.get("authority") != AUTHORITY or receipt.get("schemaVersion") != 1:
        raise RuntimeError("MANAGEMENT_EXTERNAL_RECEIPT_AUTHORITY_INVALID")
    if receipt.get("offlineVerified") is not True:
        raise RuntimeError("MANAGEMENT_EXTERNAL_RECEIPT_OFFLINE_VERIFY_REQUIRED")
    if receipt.get("archiveReady") is not False or receipt.get("runtimeCertified") is not False or receipt.get("physicalCertified") is not False:
        raise RuntimeError("MANAGEMENT_EXTERNAL_RECEIPT_SCOPE_INFLATION")
    if receipt.get("planDigest") != _sha256(plan_path):
        raise RuntimeError("MANAGEMENT_EXTERNAL_RECEIPT_PLAN_DIGEST_DRIFT")
    if not DIGEST_RE.fullmatch(str(receipt.get("releaseArtifactDigest") or "")):
        raise RuntimeError("MANAGEMENT_EXTERNAL_RECEIPT_RELEASE_DIGEST_INVALID")
    run_id = str(receipt.get("sourceRunId") or "")
    if not run_id.isdigit():
        raise RuntimeError("MANAGEMENT_EXTERNAL_RECEIPT_RUN_ID_INVALID")

    expected = {
        str(row.get("role") or ""): row
        for row in (plan.get("coreImages") or [])
        if isinstance(row, dict) and row.get("ownership") == "external"
    }
    images = receipt.get("images") or []
    if not expected or not isinstance(images, list) or len(images) != len(expected):
        raise RuntimeError("MANAGEMENT_EXTERNAL_RECEIPT_COVERAGE_INVALID")

    by_role: dict[str, dict] = {}
    for row in images:
        if not isinstance(row, dict):
            raise RuntimeError("MANAGEMENT_EXTERNAL_RECEIPT_IMAGE_INVALID")
        role = str(row.get("role") or "")
        plan_row = expected.get(role)
        if plan_row is None or role in by_role:
            raise RuntimeError("MANAGEMENT_EXTERNAL_RECEIPT_ROLE_INVALID")
        for receipt_key, plan_key in (
            ("sourceRepository", "repository"),
            ("sourceTag", "tag"),
            ("selectedVersion", "version"),
        ):
            if str(row.get(receipt_key) or "") != str(plan_row.get(plan_key) or ""):
                raise RuntimeError(f"MANAGEMENT_EXTERNAL_RECEIPT_PLAN_DRIFT {role}:{receipt_key}")
        manifest = str(row.get("manifestDigest") or "")
        exact = str(row.get("exactReference") or "")
        if not DIGEST_RE.fullmatch(manifest) or exact != str(plan_row.get("repository") or "") + "@" + manifest:
            raise RuntimeError(f"MANAGEMENT_EXTERNAL_RECEIPT_REFERENCE_INVALID {role}")
        for key in ("tagRootDigest", "lockSha256"):
            if not DIGEST_RE.fullmatch(str(row.get(key) or "")):
                raise RuntimeError(f"MANAGEMENT_EXTERNAL_RECEIPT_DIGEST_INVALID {role}:{key}")
        reachable = row.get("reachableBytes")
        if not isinstance(reachable, int) or reachable <= 0:
            raise RuntimeError(f"MANAGEMENT_EXTERNAL_RECEIPT_BYTES_INVALID {role}")
        by_role[role] = {
            "exactReference": exact,
            "manifestDigest": manifest,
            "tagRootDigest": str(row["tagRootDigest"]),
            "lockSha256": str(row["lockSha256"]),
            "reachableBytes": reachable,
        }
    if set(by_role) != set(expected):
        raise RuntimeError("MANAGEMENT_EXTERNAL_RECEIPT_COVERAGE_INVALID")

    return {
        "authority": AUTHORITY,
        "sourceRunId": run_id,
        "offlineVerified": True,
        "archiveReady": False,
        "runtimeCertified": False,
        "physicalCertified": False,
        "releaseArtifactDigest": str(receipt["releaseArtifactDigest"]),
        "planDigest": str(receipt["planDigest"]),
        "byRole": by_role,
    }

def manifest_receipt_evidence(root: Path, plan: dict) -> dict:
    """Return exact manifest-resolution evidence without promoting archive/runtime/physical state."""
    plan_path = _regular(root / "lab" / "management-workload-image-build-plan.json", "MANAGEMENT_IMAGE_PLAN")
    receipt_path = _regular(root / "lab" / "management-workload-manifest-image-receipt.json", "MANAGEMENT_MANIFEST_RECEIPT")
    try:
        receipt = json.loads(receipt_path.read_text())
    except json.JSONDecodeError as exc:
        raise RuntimeError("MANAGEMENT_MANIFEST_RECEIPT_JSON_INVALID") from exc
    if not isinstance(receipt, dict) or receipt.get("authority") != MANIFEST_AUTHORITY or receipt.get("schemaVersion") != 1:
        raise RuntimeError("MANAGEMENT_MANIFEST_RECEIPT_AUTHORITY_INVALID")
    if receipt.get("resolved") is not True:
        raise RuntimeError("MANAGEMENT_MANIFEST_RECEIPT_RESOLUTION_REQUIRED")
    if receipt.get("runtimeCertified") is not False or receipt.get("physicalCertified") is not False:
        raise RuntimeError("MANAGEMENT_MANIFEST_RECEIPT_SCOPE_INFLATION")
    if receipt.get("releaseVersion") != plan.get("releaseVersion"):
        raise RuntimeError("MANAGEMENT_MANIFEST_RECEIPT_RELEASE_DRIFT")
    if receipt.get("planDigest") != _sha256(plan_path):
        raise RuntimeError("MANAGEMENT_MANIFEST_RECEIPT_PLAN_DIGEST_DRIFT")
    run_id = str(receipt.get("sourceRunId") or "")
    if not run_id.isdigit():
        raise RuntimeError("MANAGEMENT_MANIFEST_RECEIPT_RUN_ID_INVALID")

    expected = {
        str(row.get("sourceAuthority") or ""): row
        for row in (plan.get("derivedManifestImageSets") or [])
        if isinstance(row, dict)
    }
    sets = receipt.get("sets") or []
    if not expected or not isinstance(sets, list) or len(sets) != len(expected):
        raise RuntimeError("MANAGEMENT_MANIFEST_RECEIPT_COVERAGE_INVALID")

    by_authority: dict[str, dict] = {}
    for row in sets:
        if not isinstance(row, dict):
            raise RuntimeError("MANAGEMENT_MANIFEST_RECEIPT_SET_INVALID")
        authority = str(row.get("sourceAuthority") or "")
        plan_row = expected.get(authority)
        if plan_row is None or authority in by_authority:
            raise RuntimeError(f"MANAGEMENT_MANIFEST_RECEIPT_SET_AUTHORITY_INVALID {authority}")
        for receipt_key, plan_key in (
            ("sourceManifestPath", "manifestPath"),
            ("sourceManifestSha256", "sourceManifestSha256"),
            ("resolvedManifestPath", "resolvedManifestPath"),
            ("resolutionLockPath", "resolutionLockPath"),
        ):
            if str(row.get(receipt_key) or "") != str(plan_row.get(plan_key) or ""):
                raise RuntimeError(f"MANAGEMENT_MANIFEST_RECEIPT_PLAN_DRIFT {authority}:{receipt_key}")
        for key in ("resolvedManifestSha256", "resolutionLockSha256"):
            if not DIGEST_RE.fullmatch(str(row.get(key) or "")):
                raise RuntimeError(f"MANAGEMENT_MANIFEST_RECEIPT_DIGEST_INVALID {authority}:{key}")

        resolved_path = _regular(root / str(row["resolvedManifestPath"]), "MANAGEMENT_RESOLVED_MANIFEST")
        lock_path = _regular(root / str(row["resolutionLockPath"]), "MANAGEMENT_MANIFEST_RESOLUTION_LOCK")
        if _sha256(resolved_path) != row["resolvedManifestSha256"] or _sha256(lock_path) != row["resolutionLockSha256"]:
            raise RuntimeError(f"MANAGEMENT_MANIFEST_RECEIPT_FILE_DIGEST_DRIFT {authority}")
        try:
            lock = json.loads(lock_path.read_text())
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"MANAGEMENT_MANIFEST_RESOLUTION_LOCK_JSON_INVALID {authority}") from exc
        if lock.get("authority") != MANIFEST_RESOLUTION_AUTHORITY or lock.get("sourceManifestSha256") != plan_row.get("sourceManifestSha256"):
            raise RuntimeError(f"MANAGEMENT_MANIFEST_RESOLUTION_LOCK_INVALID {authority}")

        exact_images = row.get("exactImages") or []
        image_count = row.get("imageCount")
        if not isinstance(exact_images, list) or not exact_images or image_count != len(exact_images):
            raise RuntimeError(f"MANAGEMENT_MANIFEST_RECEIPT_IMAGE_COVERAGE_INVALID {authority}")
        for ref in exact_images:
            if not isinstance(ref, str) or ref.count("@sha256:") != 1:
                raise RuntimeError(f"MANAGEMENT_MANIFEST_RECEIPT_IMAGE_REFERENCE_INVALID {authority}")
            digest = "sha256:" + ref.rsplit("@sha256:", 1)[1]
            if not DIGEST_RE.fullmatch(digest):
                raise RuntimeError(f"MANAGEMENT_MANIFEST_RECEIPT_IMAGE_REFERENCE_INVALID {authority}")

        by_authority[authority] = {
            "resolvedManifestSha256": str(row["resolvedManifestSha256"]),
            "resolutionLockSha256": str(row["resolutionLockSha256"]),
            "imageCount": int(image_count),
            "exactImages": list(exact_images),
        }

    if set(by_authority) != set(expected):
        raise RuntimeError("MANAGEMENT_MANIFEST_RECEIPT_COVERAGE_INVALID")
    return {
        "authority": MANIFEST_AUTHORITY,
        "sourceRunId": run_id,
        "resolved": True,
        "runtimeCertified": False,
        "physicalCertified": False,
        "planDigest": str(receipt["planDigest"]),
        "byAuthority": by_authority,
    }



def product_receipt_evidence(root: Path, plan: dict) -> dict:
    """Return exact base/product image evidence without promoting final archive/physical state."""
    receipt_path = _regular(root / "lab" / "management-workload-product-image-receipt.json", "MANAGEMENT_PRODUCT_RECEIPT")
    receipt = verify_product_image_receipt(root, receipt_path)
    if receipt.get("authority") != PRODUCT_AUTHORITY or receipt.get("schemaVersion") != 1:
        raise RuntimeError("MANAGEMENT_PRODUCT_RECEIPT_AUTHORITY_INVALID")
    if receipt.get("releaseVersion") != plan.get("releaseVersion"):
        raise RuntimeError("MANAGEMENT_PRODUCT_RECEIPT_RELEASE_DRIFT")
    if receipt.get("runtimeRealismVerified") is not True:
        raise RuntimeError("MANAGEMENT_PRODUCT_RECEIPT_RUNTIME_REALISM_REQUIRED")
    if receipt.get("archiveReady") is not False or receipt.get("runtimeCertified") is not False or receipt.get("physicalCertified") is not False:
        raise RuntimeError("MANAGEMENT_PRODUCT_RECEIPT_SCOPE_INFLATION")

    expected_products = {
        str(row.get("role") or ""): row
        for row in (plan.get("coreImages") or [])
        if isinstance(row, dict) and row.get("ownership") == "product"
    }
    expected_bases = {
        str(row.get("role") or ""): row
        for row in (plan.get("baseImages") or [])
        if isinstance(row, dict)
    }
    products = receipt.get("productImages") or []
    bases = receipt.get("baseImages") or []
    if not expected_products or {str(row.get("role") or "") for row in products if isinstance(row, dict)} != set(expected_products):
        raise RuntimeError("MANAGEMENT_PRODUCT_RECEIPT_PRODUCT_COVERAGE_INVALID")
    if not expected_bases or {str(row.get("role") or "") for row in bases if isinstance(row, dict)} != set(expected_bases):
        raise RuntimeError("MANAGEMENT_PRODUCT_RECEIPT_BASE_COVERAGE_INVALID")

    by_role: dict[str, dict] = {}
    for row in products:
        role = str(row["role"])
        plan_row = expected_products[role]
        exact = str(row.get("exactReference") or "")
        if not exact.startswith(str(plan_row.get("repository") or "") + "@sha256:"):
            raise RuntimeError(f"MANAGEMENT_PRODUCT_RECEIPT_PLAN_DRIFT {role}:repository")
        cert = row.get("certification") or {}
        result = cert.get("result") or {}
        if cert.get("certified") is not True or result.get("exactPayloadBound") is not True:
            raise RuntimeError(f"MANAGEMENT_PRODUCT_RECEIPT_CERTIFICATION_INVALID {role}")
        probe = row.get("runtimeRealismProbe") or {}
        if probe.get("execution") is not True:
            raise RuntimeError(f"MANAGEMENT_PRODUCT_RECEIPT_EXECUTION_PROBE_MISSING {role}")
        by_role[role] = {
            "exactReference": exact,
            "certificationAuthority": str(result.get("authority") or ""),
            "releaseArtifactDigest": str(cert.get("releaseArtifactDigest") or ""),
            "runtimeRealismProbe": dict(probe),
        }

    by_base_role: dict[str, dict] = {}
    for row in bases:
        role = str(row["role"])
        exact = str(row.get("exactReference") or "")
        if exact.count("@sha256:") != 1:
            raise RuntimeError(f"MANAGEMENT_PRODUCT_RECEIPT_BASE_REFERENCE_INVALID {role}")
        probe = row.get("compatibilityProbe") or {}
        if not isinstance(probe, dict) or not probe or any(value is not True for value in probe.values()):
            raise RuntimeError(f"MANAGEMENT_PRODUCT_RECEIPT_BASE_PROBE_INVALID {role}")
        by_base_role[role] = {
            "exactReference": exact,
            "compatibilityProbe": dict(probe),
            **({"composition": dict(row["composition"])} if isinstance(row.get("composition"), dict) else {}),
        }

    return {
        "authority": PRODUCT_AUTHORITY,
        "sourceRunId": str(receipt["sourceRunId"]),
        "sourceCommitSHA": str(receipt["sourceCommitSHA"]),
        "releaseArtifactDigest": str(receipt["releaseArtifactDigest"]),
        "planDigest": str(receipt["planDigest"]),
        "runtimeRealismVerified": True,
        "archiveReady": False,
        "runtimeCertified": False,
        "physicalCertified": False,
        "byRole": by_role,
        "byBaseRole": by_base_role,
    }
