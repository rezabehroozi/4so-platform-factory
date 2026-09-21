#!/usr/bin/env python3
"""Acquire the selected vCluster OSS chart into a sealed source bundle.

This reuses the repository's pinned Helm/Crane acquisition toolchain. It resolves
real chart/image digests from upstream and emits source evidence only. It never
claims execution readiness: exact image bytes still have to be mirrored into the
product-owned zot authority and sealed into the runtime source lock.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

import acquire_upstream_helm as helm

ROOT = Path(__file__).resolve().parents[1]
SELECTION_PATH = ROOT / "runtime" / "virtualcluster" / "source-selection.json"
AUTHORITY = "VIRTUAL_CLUSTER_RUNTIME_ACQUISITION_AUTHORITY_V1"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)

def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()

def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())

def load_selection() -> dict:
    doc = json.loads(SELECTION_PATH.read_text())
    spec = doc.get("spec") or {}
    required = {
        "authority": "VIRTUAL_CLUSTER_RUNTIME_SOURCE_AUTHORITY_V1",
        "engine": "vcluster-oss",
        "version": "0.37.1",
        "releaseUrl": "https://github.com/loft-sh/vcluster/releases/tag/v0.37.1",
        "valuesFile": "runtime/virtualcluster/vcluster-oss-values.yaml",
    }
    for key, expected in required.items():
        if spec.get(key) != expected:
            raise RuntimeError(f"VIRTUAL_CLUSTER_SOURCE_SELECTION_DRIFT {key}")
    chart = spec.get("chart") or {}
    if chart != {"repository": "https://charts.loft.sh", "name": "vcluster"}:
        raise RuntimeError("VIRTUAL_CLUSTER_CHART_SELECTION_DRIFT")
    image = spec.get("requiredControlPlaneImage") or {}
    if image != {"registry": "ghcr.io", "repository": "loft-sh/vcluster-oss", "tag": "0.37.1"}:
        raise RuntimeError("VIRTUAL_CLUSTER_OSS_IMAGE_SELECTION_DRIFT")
    resolution = spec.get("resolution") or {}
    if resolution.get("resolved") is not False or resolution.get("chartSha256") or resolution.get("imageDigests"):
        raise RuntimeError("VIRTUAL_CLUSTER_SOURCE_SELECTION_MUST_REMAIN_UNRESOLVED_IN_GIT")
    return doc

def validate_values(path: Path) -> None:
    raw = path.read_text()
    required = [
        "registry: ghcr.io",
        "repository: loft-sh/vcluster-oss",
        'tag: "0.37.1"',
    ]
    for token in required:
        if token not in raw:
            raise RuntimeError(f"VIRTUAL_CLUSTER_OSS_VALUES_MISSING {token}")
    for forbidden in ("loft-sh/vcluster-pro", "vcluster-platform"):
        if forbidden in raw:
            raise RuntimeError(f"VIRTUAL_CLUSTER_PLATFORM_DEPENDENCY_FORBIDDEN {forbidden}")

def validate_images(images: list[str]) -> tuple[list[str], list[str]]:
    exact = sorted(str(v).strip() for v in images if str(v).strip())
    if not exact:
        raise RuntimeError("VIRTUAL_CLUSTER_IMAGE_INVENTORY_EMPTY")
    digests: list[str] = []
    seen = set()
    oss = False
    for ref in exact:
        if "@sha256:" not in ref or len(ref.rsplit("@sha256:", 1)[1]) != 64:
            raise RuntimeError(f"VIRTUAL_CLUSTER_IMAGE_NOT_DIGEST_PINNED {ref}")
        if "vcluster-pro" in ref or "vcluster-platform" in ref:
            raise RuntimeError(f"VIRTUAL_CLUSTER_PLATFORM_IMAGE_FORBIDDEN {ref}")
        if "loft-sh/vcluster-oss@sha256:" in ref:
            oss = True
        digest = "sha256:" + ref.rsplit("@sha256:", 1)[1]
        if digest not in seen:
            seen.add(digest)
            digests.append(digest)
    if not oss:
        raise RuntimeError("VIRTUAL_CLUSTER_OSS_IMAGE_MISSING")
    return exact, sorted(digests)

def write_deterministic_zip(out: Path, files: list[tuple[str, Path]]) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    if tmp.exists():
        tmp.unlink()
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, path in sorted(files):
            info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, path.read_bytes())
    tmp.replace(out)

def acquire(out: Path, network_timeout: int) -> dict:
    global_selection = load_selection()
    spec = global_selection["spec"]
    values = (ROOT / spec["valuesFile"]).resolve()
    if not values.is_file() or ROOT not in values.parents:
        raise RuntimeError("VIRTUAL_CLUSTER_VALUES_FILE_OUTSIDE_REPOSITORY")
    validate_values(values)

    pinned = helm.require_toolchain()
    helm.HELM_BIN = str(pinned["helm"][0])
    helm.CRANE_BIN = str(pinned["crane"][0])
    helm_version = helm.tool_version([helm.HELM_BIN, "version", "--short"], "HELM")
    crane_version = helm.tool_version([helm.CRANE_BIN, "version"], "CRANE")

    version = spec["version"]
    chart_repo = spec["chart"]["repository"]
    chart_name = spec["chart"]["name"]
    with tempfile.TemporaryDirectory(prefix="4so-vcluster-acquire-") as td:
        tmp = Path(td)
        env = helm.helm_env(tmp / "helm")
        expected_digest, upstream_version = helm.http_index_metadata(chart_repo, chart_name, version, network_timeout)
        artifact = helm.pull_chart(chart_repo, chart_name, upstream_version, tmp, env)
        if sha256_path(artifact) != expected_digest:
            raise RuntimeError("VIRTUAL_CLUSTER_CHART_DIGEST_MISMATCH")
        metadata = helm.chart_metadata(artifact)
        if metadata.get("apiVersion") != "v2" or metadata.get("name") != chart_name or helm.normalized_version(str(metadata.get("version") or "")) != version:
            raise RuntimeError("VIRTUAL_CLUSTER_CHART_IDENTITY_MISMATCH")

        rendered = helm.render_chart(artifact, "virtual-cluster-placeholder", "1.34.0", [values], env)
        resources = copy.deepcopy(rendered)
        images = sorted(helm.pin_images(resources, helm.crane_digest))
        image_refs, image_digests = validate_images(images)

        render_path = tmp / "render-manifest.json"
        render_path.write_text(json.dumps(resources, indent=2, sort_keys=True) + "\n")
        inventory_path = tmp / "image-inventory.json"
        inventory_path.write_text(json.dumps({"images": [{"reference": ref} for ref in image_refs]}, indent=2, sort_keys=True) + "\n")
        selection_copy = tmp / "source-selection.json"
        shutil.copy2(SELECTION_PATH, selection_copy)
        values_copy = tmp / "vcluster-oss-values.yaml"
        shutil.copy2(values, values_copy)
        chart_copy = tmp / f"vcluster-{version}.tgz"
        shutil.copy2(artifact, chart_copy)

        lock = {
            "apiVersion": "platform.4so.io/v1alpha1",
            "kind": "VirtualClusterRuntimeAcquisition",
            "authority": AUTHORITY,
            "engine": spec["engine"],
            "version": version,
            "releaseUrl": spec["releaseUrl"],
            "chartRepository": chart_repo,
            "chartName": chart_name,
            "chartSha256": expected_digest,
            "valuesSha256": sha256_path(values),
            "renderManifestSha256": sha256_path(render_path),
            "imageReferences": image_refs,
            "imageDigests": image_digests,
            "chartArtifactPath": f"runtime/virtualcluster/chart/vcluster-{version}.tgz",
            "toolchain": {"helm": helm_version, "crane": crane_version},
            "sourceResolved": True,
            "imageBytesIncluded": False,
            "zotMirrorRequired": True,
            "executionReady": False,
        }
        lock_path = tmp / "acquisition.json"
        lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
        write_deterministic_zip(out, [
            ("acquisition.json", lock_path),
            ("chart/" + chart_copy.name, chart_copy),
            ("image-inventory.json", inventory_path),
            ("render-manifest.json", render_path),
            ("source-selection.json", selection_copy),
            ("values/vcluster-oss-values.yaml", values_copy),
        ])
        return {"authority": AUTHORITY, "bundle": str(out), "bundleSha256": sha256_path(out), **lock}

def self_test() -> int:
    load_selection()
    values = ROOT / "runtime" / "virtualcluster" / "vcluster-oss-values.yaml"
    validate_values(values)
    refs, digests = validate_images([
        "ghcr.io/loft-sh/vcluster-oss@sha256:" + "a" * 64,
        "registry.k8s.io/pause@sha256:" + "b" * 64,
    ])
    if len(refs) != 2 or digests != ["sha256:" + "a" * 64, "sha256:" + "b" * 64]:
        raise RuntimeError("VIRTUAL_CLUSTER_ACQUISITION_SELF_TEST_DIGEST_DRIFT")
    for bad in (
        ["ghcr.io/loft-sh/vcluster-pro@sha256:" + "a" * 64],
        ["ghcr.io/loft-sh/vcluster-oss:0.37.1"],
    ):
        try:
            validate_images(bad)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("VIRTUAL_CLUSTER_ACQUISITION_SELF_TEST_NEGATIVE_CONTROL_FAILED")
    print("VIRTUAL_CLUSTER_RUNTIME_ACQUISITION_SELF_TEST_PASS")
    return 0

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--out", default=str(ROOT / "dist" / "virtualcluster" / "vcluster-oss-0.37.1-runtime-source.zip"))
    parser.add_argument("--network-timeout", type=int, default=60)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.preflight:
        load_selection()
        validate_values(ROOT / "runtime" / "virtualcluster" / "vcluster-oss-values.yaml")
        helm.require_toolchain()
        print("VIRTUAL_CLUSTER_RUNTIME_ACQUISITION_PREFLIGHT_PASS")
        return 0
    result = acquire(Path(args.out).resolve(), args.network_timeout)
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
