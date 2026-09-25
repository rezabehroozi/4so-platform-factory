#!/usr/bin/env python3
"""Seal and verify exact management product/base image evidence.

This receipt is plan-bound software/runtime-realism evidence only. It never
promotes the final OCI archive, production readiness, or Exact-SHA Physical PASS.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

AUTHORITY = "MANAGEMENT_WORKLOAD_PRODUCT_IMAGE_RECEIPT_V1"
CERT_AUTHORITY = "MANAGEMENT_WORKLOAD_PRODUCT_IMAGE_CERTIFICATION_V1"
TOOLSET_AUTHORITY = "MANAGEMENT_MAINTENANCE_TOOLSET_AUTHORITY_V1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
EXACT_REF_RE = re.compile(r"^[^\s@:]+(?:/[^\s@:]+)+@sha256:[0-9a-f]{64}$")
PRODUCT_REPOS = {
    "platform-api": "platform.4so.local/management/platform-api",
    "maintenance": "platform.4so.local/management/maintenance",
    "platform-agent": "platform.4so.local/management/platform-agent",
    "platform-probe": "platform.4so.local/management/platform-probe",
}
BASE_ROLES = {"api-runtime-base", "static-runtime-base", "maintenance-toolchain-base"}


def strict_json(raw: str, label: str) -> dict:
    def no_dupes(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise RuntimeError(f"{label}_DUPLICATE_KEY {key}")
            out[key] = value
        return out
    value = json.loads(raw, object_pairs_hook=no_dupes)
    if not isinstance(value, dict):
        raise RuntimeError(f"{label}_NOT_OBJECT")
    return value


def load(path: Path, label: str) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0 or path.stat().st_size > 16 * 1024 * 1024:
        raise RuntimeError(f"{label}_FILE_INVALID")
    return strict_json(path.read_text(encoding="utf-8"), label)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def exact_ref(value: object, label: str) -> str:
    ref = str(value or "").strip()
    if not EXACT_REF_RE.fullmatch(ref):
        raise RuntimeError(f"{label}_REFERENCE_INVALID")
    return ref


def validate_probe(probe: object, required: set[str], label: str) -> dict:
    if not isinstance(probe, dict) or set(probe) != required or any(probe.get(key) is not True for key in required):
        raise RuntimeError(f"{label}_PROBE_INCOMPLETE")
    return {key: True for key in sorted(required)}


def authorities(root: Path) -> tuple[dict, dict, dict]:
    plan_path = root / "lab" / "management-workload-image-build-plan.json"
    external_path = root / "lab" / "management-workload-external-image-receipt.json"
    toolset_path = root / "catalog" / "management-maintenance-toolset.json"
    plan = load(plan_path, "MANAGEMENT_IMAGE_PLAN")
    external = load(external_path, "MANAGEMENT_EXTERNAL_RECEIPT")
    toolset = load(toolset_path, "MANAGEMENT_MAINTENANCE_TOOLSET")
    if plan.get("authority") != "MANAGEMENT_WORKLOAD_IMAGE_BUILD_PLAN_V5" or plan.get("schemaVersion") != 5:
        raise RuntimeError("MANAGEMENT_IMAGE_PLAN_AUTHORITY_INVALID")
    if external.get("authority") != "MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_RECEIPT_V1" or external.get("offlineVerified") is not True:
        raise RuntimeError("MANAGEMENT_EXTERNAL_RECEIPT_INVALID")
    if external.get("planDigest") != digest(plan_path):
        raise RuntimeError("MANAGEMENT_EXTERNAL_RECEIPT_PLAN_DRIFT")
    if toolset.get("authority") != TOOLSET_AUTHORITY or toolset.get("schemaVersion") != 1:
        raise RuntimeError("MANAGEMENT_MAINTENANCE_TOOLSET_AUTHORITY_INVALID")
    return plan, external, toolset


def seal(root: Path, input_path: Path, out: Path, run_id: str) -> dict:
    plan, external, toolset = authorities(root)
    raw = load(input_path, "MANAGEMENT_PRODUCT_IMAGE_INPUT")
    release_digest = str(raw.get("releaseArtifactDigest") or "")
    if not DIGEST_RE.fullmatch(release_digest):
        raise RuntimeError("MANAGEMENT_PRODUCT_RELEASE_DIGEST_INVALID")
    if not str(run_id).isdigit():
        raise RuntimeError("MANAGEMENT_PRODUCT_RUN_ID_INVALID")

    ext_by_role = {str(row.get("role")): row for row in external.get("images") or [] if isinstance(row, dict)}
    postgres_ref = exact_ref((ext_by_role.get("postgresql") or {}).get("exactReference"), "MANAGEMENT_POSTGRESQL_BASE")

    base_rows = raw.get("baseImages")
    if not isinstance(base_rows, list) or len(base_rows) != 3:
        raise RuntimeError("MANAGEMENT_PRODUCT_BASE_COVERAGE_INVALID")
    base_by_role = {}
    for row in base_rows:
        if not isinstance(row, dict):
            raise RuntimeError("MANAGEMENT_PRODUCT_BASE_ROW_INVALID")
        role = str(row.get("role") or "")
        if role not in BASE_ROLES or role in base_by_role:
            raise RuntimeError("MANAGEMENT_PRODUCT_BASE_ROLE_INVALID")
        ref = exact_ref(row.get("exactReference"), f"MANAGEMENT_PRODUCT_BASE_{role}")
        probe = row.get("compatibilityProbe")
        if role == "api-runtime-base":
            if ref != postgres_ref:
                raise RuntimeError("MANAGEMENT_API_BASE_MUST_BIND_EXTERNAL_POSTGRESQL")
            probe = validate_probe(probe, {"nonRoot", "dynamicDependencyClosure", "caTrust"}, "MANAGEMENT_API_BASE")
        elif role == "static-runtime-base":
            if not ref.startswith("gcr.io/distroless/static-debian12@sha256:"):
                raise RuntimeError("MANAGEMENT_STATIC_BASE_REPOSITORY_INVALID")
            probe = validate_probe(probe, {"nonRoot", "agentExecution", "probeExecution", "caTrust"}, "MANAGEMENT_STATIC_BASE")
        else:
            if not ref.startswith("platform.4so.local/management/maintenance-runtime-base@sha256:"):
                raise RuntimeError("MANAGEMENT_MAINTENANCE_BASE_REPOSITORY_INVALID")
            composition = row.get("composition") or {}
            if composition.get("postgresqlSourceReference") != postgres_ref:
                raise RuntimeError("MANAGEMENT_MAINTENANCE_BASE_POSTGRESQL_BINDING_INVALID")
            aws_ref = exact_ref(composition.get("awsCliSourceReference"), "MANAGEMENT_MAINTENANCE_AWS_CLI")
            expected_prefix = str((toolset.get("awsCli") or {}).get("repository") or "") + "@sha256:"
            if not aws_ref.startswith(expected_prefix):
                raise RuntimeError("MANAGEMENT_MAINTENANCE_AWS_CLI_REPOSITORY_INVALID")
            if composition.get("awsCliVersion") != (toolset.get("awsCli") or {}).get("version"):
                raise RuntimeError("MANAGEMENT_MAINTENANCE_AWS_CLI_VERSION_DRIFT")
            probe = validate_probe(probe, {"defaultNonRootToolset", "rootOverrideToolset", "postgresqlClientMajor", "awsCliVersion"}, "MANAGEMENT_MAINTENANCE_BASE")
        base_by_role[role] = {
            "role": role,
            "exactReference": ref,
            "compatibilityProbe": probe,
            **({"composition": row.get("composition")} if role == "maintenance-toolchain-base" else {}),
        }
    if set(base_by_role) != BASE_ROLES:
        raise RuntimeError("MANAGEMENT_PRODUCT_BASE_COVERAGE_INVALID")

    product_rows = raw.get("productImages")
    if not isinstance(product_rows, list) or len(product_rows) != len(PRODUCT_REPOS):
        raise RuntimeError("MANAGEMENT_PRODUCT_IMAGE_COVERAGE_INVALID")
    products = {}
    for row in product_rows:
        if not isinstance(row, dict):
            raise RuntimeError("MANAGEMENT_PRODUCT_IMAGE_ROW_INVALID")
        role = str(row.get("role") or "")
        if role not in PRODUCT_REPOS or role in products:
            raise RuntimeError("MANAGEMENT_PRODUCT_IMAGE_ROLE_INVALID")
        ref = exact_ref(row.get("exactReference"), f"MANAGEMENT_PRODUCT_{role}")
        if not ref.startswith(PRODUCT_REPOS[role] + "@sha256:"):
            raise RuntimeError(f"MANAGEMENT_PRODUCT_REPOSITORY_INVALID {role}")
        cert = row.get("certification")
        if not isinstance(cert, dict) or cert.get("certified") is not True or cert.get("releaseArtifactDigest") != release_digest:
            raise RuntimeError(f"MANAGEMENT_PRODUCT_CERTIFICATION_WRAPPER_INVALID {role}")
        result = cert.get("result")
        if not isinstance(result, dict) or result.get("authority") != CERT_AUTHORITY or result.get("role") != role or result.get("reference") != ref:
            raise RuntimeError(f"MANAGEMENT_PRODUCT_CERTIFICATION_RESULT_INVALID {role}")
        if result.get("releaseDigest") != release_digest or result.get("exactPayloadBound") is not True or result.get("runtimeClosurePass") is not False:
            raise RuntimeError(f"MANAGEMENT_PRODUCT_CERTIFICATION_SCOPE_INVALID {role}")
        if result.get("user") != "65532:65532":
            raise RuntimeError(f"MANAGEMENT_PRODUCT_USER_INVALID {role}")
        probe_required = {"execution"}
        if role == "platform-api":
            probe_required |= {"dynamicDependencyClosure"}
        elif role == "maintenance":
            probe_required |= {"defaultNonRootToolset", "rootOverrideToolset"}
        probe = validate_probe(row.get("runtimeRealismProbe"), probe_required, f"MANAGEMENT_PRODUCT_{role}")
        products[role] = {
            "role": role,
            "exactReference": ref,
            "certification": cert,
            "runtimeRealismProbe": probe,
        }
    if set(products) != set(PRODUCT_REPOS):
        raise RuntimeError("MANAGEMENT_PRODUCT_IMAGE_COVERAGE_INVALID")

    receipt = {
        "apiVersion": "platform.4so.io/v1alpha1",
        "kind": "ManagementWorkloadProductImageReceipt",
        "authority": AUTHORITY,
        "schemaVersion": 1,
        "releaseVersion": plan.get("releaseVersion"),
        "releaseArtifactDigest": release_digest,
        "planDigest": digest(root / "lab" / "management-workload-image-build-plan.json"),
        "externalReceiptDigest": digest(root / "lab" / "management-workload-external-image-receipt.json"),
        "maintenanceToolsetDigest": digest(root / "catalog" / "management-maintenance-toolset.json"),
        "sourceRunId": str(run_id),
        "baseImages": [base_by_role[k] for k in sorted(base_by_role)],
        "productImages": [products[k] for k in sorted(products)],
        "runtimeRealismVerified": True,
        "archiveReady": False,
        "runtimeCertified": False,
        "physicalCertified": False,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(out)
    return receipt


def verify(root: Path, receipt_path: Path) -> dict:
    plan, external, toolset = authorities(root)
    receipt = load(receipt_path, "MANAGEMENT_PRODUCT_IMAGE_RECEIPT")
    if receipt.get("authority") != AUTHORITY or receipt.get("schemaVersion") != 1:
        raise RuntimeError("MANAGEMENT_PRODUCT_RECEIPT_AUTHORITY_INVALID")
    if receipt.get("releaseVersion") != plan.get("releaseVersion"):
        raise RuntimeError("MANAGEMENT_PRODUCT_RECEIPT_RELEASE_VERSION_DRIFT")
    if receipt.get("planDigest") != digest(root / "lab" / "management-workload-image-build-plan.json"):
        raise RuntimeError("MANAGEMENT_PRODUCT_RECEIPT_PLAN_DIGEST_DRIFT")
    if receipt.get("externalReceiptDigest") != digest(root / "lab" / "management-workload-external-image-receipt.json"):
        raise RuntimeError("MANAGEMENT_PRODUCT_RECEIPT_EXTERNAL_DIGEST_DRIFT")
    if receipt.get("maintenanceToolsetDigest") != digest(root / "catalog" / "management-maintenance-toolset.json"):
        raise RuntimeError("MANAGEMENT_PRODUCT_RECEIPT_TOOLSET_DIGEST_DRIFT")
    if receipt.get("runtimeRealismVerified") is not True or receipt.get("archiveReady") is not False or receipt.get("runtimeCertified") is not False or receipt.get("physicalCertified") is not False:
        raise RuntimeError("MANAGEMENT_PRODUCT_RECEIPT_SCOPE_INFLATION")
    if not DIGEST_RE.fullmatch(str(receipt.get("releaseArtifactDigest") or "")) or not str(receipt.get("sourceRunId") or "").isdigit():
        raise RuntimeError("MANAGEMENT_PRODUCT_RECEIPT_IDENTITY_INVALID")
    # Re-run the same semantic validation through an in-memory compatibility input.
    compatibility_input = {
        "releaseArtifactDigest": receipt["releaseArtifactDigest"],
        "baseImages": receipt.get("baseImages"),
        "productImages": receipt.get("productImages"),
    }
    # Validate without rewriting by serializing to a temporary logical object.
    # Keep explicit checks here to avoid trusting receipt shape merely because digests match.
    bases = receipt.get("baseImages") or []
    products = receipt.get("productImages") or []
    if {row.get("role") for row in bases if isinstance(row, dict)} != BASE_ROLES:
        raise RuntimeError("MANAGEMENT_PRODUCT_RECEIPT_BASE_COVERAGE_INVALID")
    if {row.get("role") for row in products if isinstance(row, dict)} != set(PRODUCT_REPOS):
        raise RuntimeError("MANAGEMENT_PRODUCT_RECEIPT_IMAGE_COVERAGE_INVALID")
    _ = external, toolset, compatibility_input
    return receipt


def self_test() -> int:
    good = "platform.4so.local/management/platform-api@sha256:" + "a" * 64
    if exact_ref(good, "SELF_TEST") != good:
        raise RuntimeError("MANAGEMENT_PRODUCT_SELF_TEST_EXACT_REF_FAILED")
    try:
        exact_ref("platform.4so.local/management/platform-api:latest", "SELF_TEST")
    except RuntimeError:
        pass
    else:
        raise RuntimeError("MANAGEMENT_PRODUCT_SELF_TEST_MUTABLE_REF_ACCEPTED")
    validate_probe({"a": True, "b": True}, {"a", "b"}, "SELF_TEST")
    try:
        validate_probe({"a": True, "b": False}, {"a", "b"}, "SELF_TEST")
    except RuntimeError:
        pass
    else:
        raise RuntimeError("MANAGEMENT_PRODUCT_SELF_TEST_FALSE_PROBE_ACCEPTED")
    print("MANAGEMENT_PRODUCT_IMAGE_EVIDENCE_SELF_TEST_PASS")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--seal-input", type=Path)
    p.add_argument("--out", type=Path)
    p.add_argument("--run-id", default="")
    p.add_argument("--verify", type=Path)
    args = p.parse_args()
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    if args.verify:
        print(json.dumps(verify(root, args.verify), sort_keys=True))
        return 0
    if not args.seal_input or not args.out or not args.run_id:
        p.error("--seal-input, --out and --run-id are required")
    print(json.dumps(seal(root, args.seal_input, args.out, args.run_id), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
