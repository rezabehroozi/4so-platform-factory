#!/usr/bin/env python3
"""Seal exact management workload OCI archive build evidence.

The archive receipt proves deterministic OCI assembly and exact image coverage.
It does not make the appliance input pack public/distribution-ready and never
promotes runtime or Exact-SHA Physical certification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path

from management_workload_evidence import (
    external_receipt_evidence,
    manifest_receipt_evidence,
    product_receipt_evidence,
)

AUTHORITY = "MANAGEMENT_WORKLOAD_OCI_ARCHIVE_RECEIPT_V1"
ASSEMBLY_AUTHORITY = "MANAGEMENT_WORKLOAD_OCI_ASSEMBLY_AUTHORITY_V1"
INVENTORY_AUTHORITY = "MANAGEMENT_WORKLOAD_OCI_ARCHIVE_INVENTORY_V2"
ADDRESSABILITY_AUTHORITY = "MANAGEMENT_WORKLOAD_OCI_IMPORT_ADDRESSABILITY_V2"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REF_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")


def regular(path: Path, label: str) -> Path:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size <= 0:
        raise RuntimeError(f"{label}_NOT_REGULAR")
    return path


def load(path: Path, label: str) -> dict:
    value = json.loads(regular(path, label).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{label}_NOT_OBJECT")
    return value


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with regular(path, "ARCHIVE_DIGEST_INPUT").open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def canonical_receipt_digest(path: Path, label: str) -> str:
    regular(path, label)
    return digest(path)


def expected_images(root: Path) -> tuple[dict, dict, dict, list[str]]:
    plan = load(root / "lab" / "management-workload-image-build-plan.json", "MANAGEMENT_IMAGE_PLAN")
    external = external_receipt_evidence(root, plan)
    manifest = manifest_receipt_evidence(root, plan)
    product = product_receipt_evidence(root, plan)

    refs: list[str] = []
    refs.extend(row["exactReference"] for row in external["byRole"].values())
    refs.extend(row["exactReference"] for row in product["byRole"].values())
    for row in manifest["byAuthority"].values():
        refs.extend(row["exactImages"])
    unique = sorted(set(refs))
    if len(unique) != 20 or len(refs) < len(unique):
        # The four manifest sets intentionally overlap; only the final unique
        # archive inventory must contain one addressable copy of each image.
        manifest_refs = {
            ref
            for row in manifest["byAuthority"].values()
            for ref in row["exactImages"]
        }
        expected_count = len(external["byRole"]) + len(product["byRole"]) + len(manifest_refs)
        if len(unique) != expected_count:
            raise RuntimeError(
                f"MANAGEMENT_ARCHIVE_EXPECTED_IMAGE_COVERAGE_INVALID unique={len(unique)} expected={expected_count}"
            )
    if len(unique) != 20 or any(not REF_RE.fullmatch(ref) for ref in unique):
        raise RuntimeError("MANAGEMENT_ARCHIVE_EXPECTED_IMAGE_SET_INVALID")
    return external, manifest, product, unique


def validate_assembly_result(result: dict, archive: Path, expected: list[str]) -> None:
    if result.get("assembled") is not True or result.get("authority") != ASSEMBLY_AUTHORITY:
        raise RuntimeError("MANAGEMENT_ARCHIVE_ASSEMBLY_AUTHORITY_INVALID")
    if result.get("inventoryAuthority") != INVENTORY_AUTHORITY:
        raise RuntimeError("MANAGEMENT_ARCHIVE_INVENTORY_AUTHORITY_INVALID")
    if result.get("importAddressabilityAuthority") != ADDRESSABILITY_AUTHORITY:
        raise RuntimeError("MANAGEMENT_ARCHIVE_ADDRESSABILITY_AUTHORITY_INVALID")
    if result.get("imageCount") != len(expected) or result.get("images") != expected:
        raise RuntimeError("MANAGEMENT_ARCHIVE_IMAGE_COVERAGE_INVALID")
    actual_digest = digest(archive)
    actual_bytes = regular(archive, "MANAGEMENT_ARCHIVE").stat().st_size
    if result.get("archiveSha256") != actual_digest or result.get("archiveBytes") != actual_bytes:
        raise RuntimeError("MANAGEMENT_ARCHIVE_BYTE_IDENTITY_INVALID")
    blob_count = result.get("blobCount")
    if not isinstance(blob_count, int) or isinstance(blob_count, bool) or blob_count <= 0:
        raise RuntimeError("MANAGEMENT_ARCHIVE_BLOB_COUNT_INVALID")


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


def seal(root: Path, archive: Path, assembly_result: Path, out: Path, run_id: str, source_sha: str) -> dict:
    if not str(run_id).isdigit():
        raise RuntimeError("MANAGEMENT_ARCHIVE_RUN_ID_INVALID")
    source_sha = str(source_sha).strip().lower()
    if not COMMIT_RE.fullmatch(source_sha):
        raise RuntimeError("MANAGEMENT_ARCHIVE_SOURCE_SHA_INVALID")

    external, manifest, product, expected = expected_images(root)
    result = load(assembly_result, "MANAGEMENT_ARCHIVE_ASSEMBLY_RESULT")
    validate_assembly_result(result, archive, expected)

    receipt = {
        "apiVersion": "platform.4so.io/v1alpha1",
        "kind": "ManagementWorkloadOCIArchiveReceipt",
        "authority": AUTHORITY,
        "schemaVersion": 1,
        "releaseVersion": load(root / "lab" / "management-workload-image-build-plan.json", "MANAGEMENT_IMAGE_PLAN")["releaseVersion"],
        "sourceRunId": str(run_id),
        "sourceCommitSHA": source_sha,
        "archiveSha256": digest(archive),
        "archiveBytes": regular(archive, "MANAGEMENT_ARCHIVE").stat().st_size,
        "imageCount": len(expected),
        "blobCount": int(result["blobCount"]),
        "images": expected,
        "assemblyAuthority": ASSEMBLY_AUTHORITY,
        "inventoryAuthority": INVENTORY_AUTHORITY,
        "importAddressabilityAuthority": ADDRESSABILITY_AUTHORITY,
        "sourceEvidence": {
            "externalReceiptSha256": canonical_receipt_digest(root / "lab" / "management-workload-external-image-receipt.json", "MANAGEMENT_EXTERNAL_RECEIPT"),
            "manifestReceiptSha256": canonical_receipt_digest(root / "lab" / "management-workload-manifest-image-receipt.json", "MANAGEMENT_MANIFEST_RECEIPT"),
            "productReceiptSha256": canonical_receipt_digest(root / "lab" / "management-workload-product-image-receipt.json", "MANAGEMENT_PRODUCT_RECEIPT"),
            "productSourceRunId": product["sourceRunId"],
            "productSourceCommitSHA": product["sourceCommitSHA"],
            "externalSourceRunId": external["sourceRunId"],
            "manifestSourceRunId": manifest["sourceRunId"],
        },
        "archiveBuilt": True,
        "distributionReady": False,
        "runtimeCertified": False,
        "physicalCertified": False,
    }
    atomic_json(out, receipt)
    return receipt


def verify_structure(receipt_path: Path) -> dict:
    """Validate a historical archive receipt without claiming it matches current image inputs."""
    receipt = load(receipt_path, "MANAGEMENT_ARCHIVE_RECEIPT")
    if receipt.get("authority") != AUTHORITY or receipt.get("schemaVersion") != 1 or receipt.get("kind") != "ManagementWorkloadOCIArchiveReceipt":
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_AUTHORITY_INVALID")
    if not COMMIT_RE.fullmatch(str(receipt.get("sourceCommitSHA") or "")) or not str(receipt.get("sourceRunId") or "").isdigit():
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_SOURCE_IDENTITY_INVALID")
    if not DIGEST_RE.fullmatch(str(receipt.get("archiveSha256") or "")):
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_DIGEST_INVALID")
    if receipt.get("assemblyAuthority") != ASSEMBLY_AUTHORITY or receipt.get("inventoryAuthority") != INVENTORY_AUTHORITY or receipt.get("importAddressabilityAuthority") != ADDRESSABILITY_AUTHORITY:
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_AUTHORITY_CHAIN_INVALID")
    if receipt.get("archiveBuilt") is not True or receipt.get("distributionReady") is not False or receipt.get("runtimeCertified") is not False or receipt.get("physicalCertified") is not False:
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_SCOPE_INFLATION")
    if not isinstance(receipt.get("archiveBytes"), int) or receipt["archiveBytes"] <= 0 or not isinstance(receipt.get("blobCount"), int) or receipt["blobCount"] <= 0:
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_SIZE_INVALID")
    images = receipt.get("images")
    if not isinstance(images, list) or receipt.get("imageCount") != len(images) or not images or images != sorted(set(images)) or any(not REF_RE.fullmatch(str(ref)) for ref in images):
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_IMAGE_SET_INVALID")
    source = receipt.get("sourceEvidence")
    required = {"externalReceiptSha256","manifestReceiptSha256","productReceiptSha256","productSourceRunId","productSourceCommitSHA","externalSourceRunId","manifestSourceRunId"}
    if not isinstance(source, dict) or set(source) != required:
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_SOURCE_EVIDENCE_INVALID")
    for key in ("externalReceiptSha256","manifestReceiptSha256","productReceiptSha256"):
        if not DIGEST_RE.fullmatch(str(source.get(key) or "")):
            raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_SOURCE_EVIDENCE_INVALID")
    if not COMMIT_RE.fullmatch(str(source.get("productSourceCommitSHA") or "")) or any(not str(source.get(key) or "").isdigit() for key in ("productSourceRunId","externalSourceRunId","manifestSourceRunId")):
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_SOURCE_EVIDENCE_INVALID")
    return receipt


def verify(root: Path, receipt_path: Path) -> dict:
    receipt = verify_structure(receipt_path)
    external, manifest, product, expected = expected_images(root)
    if receipt.get("authority") != AUTHORITY or receipt.get("schemaVersion") != 1 or receipt.get("kind") != "ManagementWorkloadOCIArchiveReceipt":
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_AUTHORITY_INVALID")
    if not COMMIT_RE.fullmatch(str(receipt.get("sourceCommitSHA") or "")) or not str(receipt.get("sourceRunId") or "").isdigit():
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_SOURCE_IDENTITY_INVALID")
    if not DIGEST_RE.fullmatch(str(receipt.get("archiveSha256") or "")):
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_DIGEST_INVALID")
    if receipt.get("imageCount") != len(expected) or receipt.get("images") != expected:
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_IMAGE_COVERAGE_INVALID")
    if receipt.get("assemblyAuthority") != ASSEMBLY_AUTHORITY or receipt.get("inventoryAuthority") != INVENTORY_AUTHORITY or receipt.get("importAddressabilityAuthority") != ADDRESSABILITY_AUTHORITY:
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_AUTHORITY_CHAIN_INVALID")
    if receipt.get("archiveBuilt") is not True or receipt.get("distributionReady") is not False or receipt.get("runtimeCertified") is not False or receipt.get("physicalCertified") is not False:
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_SCOPE_INFLATION")
    if not isinstance(receipt.get("archiveBytes"), int) or receipt["archiveBytes"] <= 0 or not isinstance(receipt.get("blobCount"), int) or receipt["blobCount"] <= 0:
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_SIZE_INVALID")
    source = receipt.get("sourceEvidence")
    expected_source = {
        "externalReceiptSha256": canonical_receipt_digest(root / "lab" / "management-workload-external-image-receipt.json", "MANAGEMENT_EXTERNAL_RECEIPT"),
        "manifestReceiptSha256": canonical_receipt_digest(root / "lab" / "management-workload-manifest-image-receipt.json", "MANAGEMENT_MANIFEST_RECEIPT"),
        "productReceiptSha256": canonical_receipt_digest(root / "lab" / "management-workload-product-image-receipt.json", "MANAGEMENT_PRODUCT_RECEIPT"),
        "productSourceRunId": product["sourceRunId"],
        "productSourceCommitSHA": product["sourceCommitSHA"],
        "externalSourceRunId": external["sourceRunId"],
        "manifestSourceRunId": manifest["sourceRunId"],
    }
    if source != expected_source:
        raise RuntimeError("MANAGEMENT_ARCHIVE_RECEIPT_SOURCE_EVIDENCE_DRIFT")
    return receipt


def self_test() -> int:
    good = "registry.example.test/repo/image@sha256:" + "a" * 64
    if not REF_RE.fullmatch(good):
        raise RuntimeError("MANAGEMENT_ARCHIVE_SELF_TEST_EXACT_REF_FAILED")
    if REF_RE.fullmatch("registry.example.test/repo/image:latest"):
        raise RuntimeError("MANAGEMENT_ARCHIVE_SELF_TEST_MUTABLE_REF_ACCEPTED")
    if not COMMIT_RE.fullmatch("b" * 40):
        raise RuntimeError("MANAGEMENT_ARCHIVE_SELF_TEST_COMMIT_FAILED")
    print("MANAGEMENT_WORKLOAD_OCI_ARCHIVE_RECEIPT_SELF_TEST_PASS")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument("--archive", type=Path)
    ap.add_argument("--assembly-result", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--run-id", default="")
    ap.add_argument("--source-sha", default="")
    ap.add_argument("--verify", type=Path)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    if args.verify:
        print(json.dumps(verify(root, args.verify), sort_keys=True))
        return 0
    if not args.archive or not args.assembly_result or not args.out or not args.run_id or not args.source_sha:
        ap.error("--archive, --assembly-result, --out, --run-id and --source-sha are required")
    print(json.dumps(seal(root, args.archive, args.assembly_result, args.out, args.run_id, args.source_sha), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
