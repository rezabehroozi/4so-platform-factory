#!/usr/bin/env python3
"""Prove that the Cilium/Gateway API/KGateway transition is ready for runtime execution.

This is preparation evidence only. It does not mutate the current Gateway API
catalog release and cannot certify Cilium, KGateway, Runtime or Physical PASS.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

AUTHORITY = "RUNTIME_DEPENDENCY_TRANSITION_READINESS_V1"
TRANSITION_AUTHORITY = "RUNTIME_DEPENDENCY_TRANSITION_V1"
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def load(path: Path, label: str) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0:
        raise RuntimeError(f"{label}_FILE_INVALID")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{label}_NOT_OBJECT")
    return value


def source_lock(root: Path, component: str, release: str) -> tuple[dict, str]:
    path = root / "catalog" / "runtime" / component / release / "source-lock.json"
    value = load(path, f"{component.upper()}_SOURCE_LOCK")
    if value.get("component") != component or str(value.get("version") or "") != release:
        raise RuntimeError(f"{component.upper()}_SOURCE_LOCK_IDENTITY_INVALID")
    if value.get("networkFetchRequired") is not False or value.get("upstreamVerification") != "sha256-pinned-offline":
        raise RuntimeError(f"{component.upper()}_SOURCE_LOCK_OFFLINE_INVALID")
    digest = sha256(path)
    return value, digest


def verify(root: Path) -> dict:
    transition_path = root / "catalog" / "runtime-dependency-transition.json"
    transition = load(transition_path, "RUNTIME_DEPENDENCY_TRANSITION")
    spec = transition.get("spec") or {}
    if transition.get("kind") != "RuntimeDependencyTransition" or spec.get("authority") != TRANSITION_AUTHORITY:
        raise RuntimeError("RUNTIME_DEPENDENCY_TRANSITION_AUTHORITY_INVALID")
    if spec.get("status") != "runtime-certification-pending":
        raise RuntimeError("RUNTIME_DEPENDENCY_TRANSITION_STATUS_INVALID")
    policy = spec.get("policy") or {}
    expected_policy = {
        "mutationBeforeSourceResolution": False,
        "physicalPassInference": False,
        "runtimeCertificationRequired": True,
        "sourceAcquisitionIndependentOfRuntimeSuitability": True,
    }
    if policy != expected_policy:
        raise RuntimeError("RUNTIME_DEPENDENCY_TRANSITION_POLICY_INVALID")

    ga = spec.get("gatewayApi") or {}
    kg = spec.get("kgateway") or {}
    ci = spec.get("cilium") or {}
    if ga.get("currentRelease") != "1.5.1" or ga.get("targetRelease") != "1.6.1" or ga.get("sourceStatus") != "source-acquired":
        raise RuntimeError("GATEWAY_API_TRANSITION_INVALID")
    if kg.get("targetRelease") != "2.4.1" or kg.get("sourceStatus") != "source-acquired" or kg.get("gatewayApiCompatibility") != "1.4-1.6":
        raise RuntimeError("KGATEWAY_TRANSITION_INVALID")
    if ci.get("targetRelease") != "1.20.1" or ci.get("requiredGatewayApiRelease") != "1.6.1" or ci.get("sourceStatus") != "source-acquired":
        raise RuntimeError("CILIUM_TRANSITION_INVALID")
    if ci.get("runtimeStatus") != "dependency-transition-required":
        raise RuntimeError("CILIUM_RUNTIME_HOLD_MUST_REMAIN")

    current_gateway, current_gateway_digest = source_lock(root, "gateway-api", "1.5.1")
    kgateway, kgateway_digest = source_lock(root, "kgateway", "2.4.1")
    cilium, cilium_digest = source_lock(root, "cilium", "1.20.1")

    if kgateway.get("upstreamArtifactDigest") != "sha256:95e193ec629e31efb8a9046ba399457fd2332c321bb9a6b0c6a3c35215e3f1f8":
        raise RuntimeError("KGATEWAY_ARTIFACT_DIGEST_DRIFT")
    if cilium.get("upstreamArtifactDigest") != "sha256:06210eef7c23d15f7699c79e2fe3a1ec9c389024c5c5c006ea04022d322449a2":
        raise RuntimeError("CILIUM_ARTIFACT_DIGEST_DRIFT")

    assets = ga.get("assets")
    if not isinstance(assets, list) or len(assets) != 2:
        raise RuntimeError("GATEWAY_API_TARGET_ASSET_COVERAGE_INVALID")
    target_assets = []
    for row in assets:
        name = str(row.get("name") or "")
        path = root / "catalog" / "runtime-dependencies" / "gateway-api" / "1.6.1" / name
        expected = "sha256:" + str(row.get("sha256") or "")
        if not SHA_RE.fullmatch(expected) or path.is_symlink() or not path.is_file():
            raise RuntimeError(f"GATEWAY_API_TARGET_ASSET_INVALID {name}")
        if path.stat().st_size != row.get("size") or sha256(path) != expected:
            raise RuntimeError(f"GATEWAY_API_TARGET_ASSET_DIGEST_DRIFT {name}")
        target_assets.append({"name": name, "sha256": expected, "sizeBytes": path.stat().st_size})

    order = spec.get("ordering") or []
    expected_order = [
        "acquire-and-verify-gateway-api-1.6.1",
        "acquire-and-verify-kgateway-2.4.1",
        "acquire-and-verify-cilium-1.20.1",
        "certify-gateway-api-upgrade-1.5.1-to-1.6.1",
        "certify-kgateway-2.4.1-on-gateway-api-1.6.1",
        "certify-cilium-1.20.1-on-gateway-api-1.6.1",
    ]
    if order != expected_order:
        raise RuntimeError("RUNTIME_DEPENDENCY_TRANSITION_ORDER_INVALID")

    registry = load(root / "catalog" / "component-runtime-certification.json", "COMPONENT_RUNTIME_CERTIFICATION")
    holds = {row.get("component"): row for row in (registry.get("spec") or {}).get("runtimeSuitabilityHolds") or [] if isinstance(row, dict)}
    if set(holds) != {"cilium", "kyverno", "metallb"}:
        raise RuntimeError("RUNTIME_SUITABILITY_HOLD_SET_INVALID")
    if holds["cilium"].get("authority") != TRANSITION_AUTHORITY or holds["cilium"].get("status") != "dependency-transition-required":
        raise RuntimeError("CILIUM_RUNTIME_SUITABILITY_HOLD_INVALID")

    receipt = {
        "apiVersion": "platform.4so.io/v1alpha1",
        "kind": "RuntimeDependencyTransitionReadiness",
        "authority": AUTHORITY,
        "transitionAuthority": TRANSITION_AUTHORITY,
        "transitionDigest": sha256(transition_path),
        "currentGatewayApi": {
            "release": "1.5.1",
            "sourceLockSha256": current_gateway_digest,
            "artifactDigest": current_gateway.get("upstreamArtifactDigest"),
        },
        "targetGatewayApi": {
            "release": "1.6.1",
            "assets": sorted(target_assets, key=lambda row: row["name"]),
        },
        "kgateway": {
            "release": "2.4.1",
            "sourceLockSha256": kgateway_digest,
            "artifactDigest": kgateway.get("upstreamArtifactDigest"),
        },
        "cilium": {
            "release": "1.20.1",
            "sourceLockSha256": cilium_digest,
            "artifactDigest": cilium.get("upstreamArtifactDigest"),
        },
        "executionOrder": expected_order,
        "sourceClosureReady": True,
        "transitionExecutionReady": True,
        "currentGatewayApiMutationPerformed": False,
        "ciliumReleased": False,
        "runtimeCertified": False,
        "physicalCertified": False,
        "remainingRuntimeSuitabilityHolds": ["cilium", "kyverno", "metallb"],
    }
    return receipt


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--out", type=Path)
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    if args.self_test:
        receipt = verify(args.root.resolve())
        assert receipt["transitionExecutionReady"] is True
        assert receipt["runtimeCertified"] is False and receipt["physicalCertified"] is False
        assert receipt["remainingRuntimeSuitabilityHolds"] == ["cilium", "kyverno", "metallb"]
        print("RUNTIME_DEPENDENCY_TRANSITION_READINESS_SELF_TEST_PASS")
        return 0
    receipt = verify(args.root.resolve())
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
