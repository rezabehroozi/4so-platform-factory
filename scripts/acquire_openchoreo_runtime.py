#!/usr/bin/env python3
"""Acquire the exact OpenChoreo v1.3.0 Control/Data target source.

The result is acquisition evidence, not runtime admission. It intentionally
excludes Workflow/Observability planes, Backstage and upstream MCP from the 4SO
profile. Image bytes must still be mirrored into zot and the bounded executor
image must be sealed before OPENCHOREO_RUNTIME_SOURCE_AUTHORITY_V1 can admit it.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path

import acquire_upstream_helm as helm
from openchoreo_runtime_contract import (
    ACQUISITION_AUTHORITY as AUTHORITY,
    OCI_BASE,
    SOURCE_AUTHORITY,
    UPSTREAM_COMMIT,
    UPSTREAM_REPOSITORY,
    VERSION,
)

ROOT = Path(__file__).resolve().parents[1]
SELECTION_PATH = ROOT / "runtime" / "openchoreo" / "source-selection.json"
VALUES = {
    "control-plane": ROOT / "runtime" / "openchoreo" / "control-plane-values.yaml",
    "data-plane": ROOT / "runtime" / "openchoreo" / "data-plane-values.yaml",
}
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)

def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()

def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())

def load_selection() -> dict:
    doc = json.loads(SELECTION_PATH.read_text())
    spec = doc.get("spec") or {}
    if spec.get("authority") != SOURCE_AUTHORITY or spec.get("version") != VERSION:
        raise RuntimeError("OPENCHOREO_SOURCE_SELECTION_IDENTITY_DRIFT")
    if spec.get("upstreamRepository") != UPSTREAM_REPOSITORY or spec.get("upstreamCommit") != UPSTREAM_COMMIT:
        raise RuntimeError("OPENCHOREO_UPSTREAM_COMMIT_DRIFT")
    planes = {v.get("name"): v for v in spec.get("planes") or []}
    expected = {"control-plane": "openchoreo-control-plane", "data-plane": "openchoreo-data-plane"}
    if set(planes) != set(expected):
        raise RuntimeError("OPENCHOREO_PLANES_MUST_BE_CONTROL_AND_DATA_ONLY")
    for name, chart in expected.items():
        p = planes[name]
        if p.get("chartRepository") != OCI_BASE or p.get("chartName") != chart or p.get("chartVersion") != VERSION:
            raise RuntimeError(f"OPENCHOREO_CHART_SELECTION_DRIFT {name}")
    for forbidden in ("backstageEnabled", "workflowPlaneEnabled", "observabilityPlaneEnabled", "openChoreoMcpEnabled"):
        if spec.get(forbidden) is not False:
            raise RuntimeError(f"OPENCHOREO_DUPLICATE_PLANE_MUST_BE_DISABLED {forbidden}")
    if spec.get("externalOidcRequired") is not True or spec.get("buildAuthority") != "buildkit" or spec.get("registryAuthority") != "zot":
        raise RuntimeError("OPENCHOREO_FACTORY_AUTHORITY_BOUNDARY_DRIFT")
    if spec.get("resolved") is not False or spec.get("mirrorReady") is not False or spec.get("images") or spec.get("executorImageReference"):
        raise RuntimeError("OPENCHOREO_GIT_SOURCE_SELECTION_MUST_REMAIN_UNRESOLVED")
    return doc

def validate_values() -> None:
    cp = VALUES["control-plane"].read_text()
    dp = VALUES["data-plane"].read_text()
    for token in ("backstage:", "enabled: false", "mcp:"):
        if token not in cp:
            raise RuntimeError(f"OPENCHOREO_CONTROL_VALUES_MISSING {token}")
    if "kube-prometheus-stack:" not in dp or "enabled: false" not in dp:
        raise RuntimeError("OPENCHOREO_DATA_MONITORING_SUPPRESSION_MISSING")
    if "gateway:\n  enabled: false" not in cp or "gateway:\n  enabled: false" not in dp:
        raise RuntimeError("OPENCHOREO_GATEWAY_DUPLICATE_STACK_SUPPRESSION_MISSING")
    combined = cp + "\n" + dp
    for forbidden in ("openchoreo-workflow-plane", "openchoreo-observability-plane", "thunderid"):
        if forbidden in combined.lower():
            raise RuntimeError(f"OPENCHOREO_FORBIDDEN_DEFAULT_DEPENDENCY {forbidden}")

def source_archive(tmp: Path, timeout: int) -> Path:
    url = f"{UPSTREAM_REPOSITORY}/archive/{UPSTREAM_COMMIT}.tar.gz"
    out = tmp / f"openchoreo-{UPSTREAM_COMMIT}.tar.gz"
    req = urllib.request.Request(url, headers={"User-Agent": "4so-platform-factory-openchoreo-acquirer/1"})
    with urllib.request.urlopen(req, timeout=timeout) as response, out.open("wb") as target:
        shutil.copyfileobj(response, target)
    if out.stat().st_size < 1024:
        raise RuntimeError("OPENCHOREO_SOURCE_ARCHIVE_TOO_SMALL")
    return out

def pull_oci_chart(chart: str, tmp: Path, env: dict[str, str]) -> Path:
    ref = f"{OCI_BASE}/{chart}"
    helm.run([helm.HELM_BIN, "pull", ref, "--version", VERSION, "--destination", str(tmp)], env=env, timeout=300)
    path = tmp / f"{chart}-{VERSION}.tgz"
    if not path.is_file():
        raise RuntimeError(f"OPENCHOREO_CHART_PULL_MISSING {chart}")
    meta = helm.chart_metadata(path)
    if meta.get("apiVersion") != "v2" or meta.get("name") != chart or helm.normalized_version(str(meta.get("version") or "")) != VERSION:
        raise RuntimeError(f"OPENCHOREO_CHART_IDENTITY_MISMATCH {chart}")
    return path

def validate_pinned_images(refs: list[str]) -> list[dict]:
    if not refs:
        raise RuntimeError("OPENCHOREO_IMAGE_INVENTORY_EMPTY")
    rows = []
    seen = set()
    for ref in sorted(refs):
        if "@sha256:" not in ref:
            raise RuntimeError(f"OPENCHOREO_IMAGE_NOT_DIGEST_PINNED {ref}")
        digest = "sha256:" + ref.rsplit("@sha256:", 1)[1].lower()
        if len(digest) != 71 or digest in seen:
            if digest in seen:
                continue
            raise RuntimeError(f"OPENCHOREO_IMAGE_DIGEST_INVALID {ref}")
        seen.add(digest)
        rows.append({"sourceReference": ref, "digest": digest})
    return rows

def write_zip(out: Path, files: list[tuple[str, Path]]) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    if tmp.exists():
        tmp.unlink()
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, path in sorted(files):
            info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            z.writestr(info, path.read_bytes())
    tmp.replace(out)

def acquire(out: Path, timeout: int) -> dict:
    load_selection()
    validate_values()
    pinned = helm.require_toolchain()
    helm.HELM_BIN = str(pinned["helm"][0])
    helm.CRANE_BIN = str(pinned["crane"][0])
    with tempfile.TemporaryDirectory(prefix="4so-openchoreo-acquire-") as td:
        tmp = Path(td)
        env = helm.helm_env(tmp / "helm")
        archive = source_archive(tmp, timeout)
        planes = []
        all_images: set[str] = set()
        files: list[tuple[str, Path]] = [("source/" + archive.name, archive)]
        for name, chart in (("control-plane", "openchoreo-control-plane"), ("data-plane", "openchoreo-data-plane")):
            artifact = pull_oci_chart(chart, tmp, env)
            rendered = helm.render_chart(artifact, f"4so-openchoreo-{name}", "1.34.0", [VALUES[name]], env)
            resources = copy.deepcopy(rendered)
            all_images.update(helm.pin_images(resources, helm.crane_digest))
            render = tmp / f"{name}-render.json"
            render.write_text(json.dumps(resources, indent=2, sort_keys=True) + "\n")
            planes.append({
                "name": name, "chartRepository": OCI_BASE, "chartName": chart, "chartVersion": VERSION,
                "chartSha256": sha256_path(artifact), "valuesSha256": sha256_path(VALUES[name]),
                "renderManifestSha256": sha256_path(render),
            })
            files.extend([
                (f"charts/{artifact.name}", artifact),
                (f"render/{render.name}", render),
                (f"values/{VALUES[name].name}", VALUES[name]),
            ])
        images = validate_pinned_images(sorted(all_images))
        inventory = tmp / "image-inventory.json"
        inventory.write_text(json.dumps({"images": images}, indent=2, sort_keys=True) + "\n")
        lock = {
            "apiVersion": "platform.4so.io/v1alpha1", "kind": "OpenChoreoRuntimeAcquisition",
            "authority": AUTHORITY, "sourceAuthority": SOURCE_AUTHORITY, "version": VERSION,
            "upstreamRepository": UPSTREAM_REPOSITORY, "upstreamCommit": UPSTREAM_COMMIT,
            "sourceArchiveSha256": sha256_path(archive), "planes": planes, "images": images,
            "excludedPlanes": ["workflow-plane", "observability-plane"], "backstageEnabled": False,
            "openChoreoMcpEnabled": False, "externalOidcRequired": True,
            "buildAuthority": "buildkit", "registryAuthority": "zot",
            "sourceResolved": True, "imageBytesIncluded": False, "zotMirrorRequired": True, "executionReady": False,
        }
        lock_path = tmp / "acquisition.json"
        lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
        files.extend([("acquisition.json", lock_path), ("image-inventory.json", inventory), ("source-selection.json", SELECTION_PATH)])
        write_zip(out, files)
        return {"bundle": str(out), "bundleSha256": sha256_path(out), **lock}

def self_test() -> int:
    load_selection()
    validate_values()
    rows = validate_pinned_images([
        "ghcr.io/openchoreo/controller@sha256:" + "a" * 64,
        "ghcr.io/openchoreo/cluster-agent@sha256:" + "b" * 64,
    ])
    if len(rows) != 2:
        raise RuntimeError("OPENCHOREO_ACQUISITION_SELF_TEST_INVENTORY_DRIFT")
    try:
        validate_pinned_images(["ghcr.io/openchoreo/controller:1.3.0"])
    except RuntimeError:
        pass
    else:
        raise RuntimeError("OPENCHOREO_ACQUISITION_NEGATIVE_CONTROL_FAILED")
    print("OPENCHOREO_RUNTIME_ACQUISITION_SELF_TEST_PASS")
    return 0

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--network-timeout", type=int, default=60)
    parser.add_argument("--out", default=str(ROOT / "dist" / "openchoreo" / "openchoreo-1.3.0-source.zip"))
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.preflight:
        load_selection(); validate_values(); helm.require_toolchain()
        print("OPENCHOREO_RUNTIME_ACQUISITION_PREFLIGHT_PASS")
        return 0
    print(json.dumps(acquire(Path(args.out).resolve(), args.network_timeout), sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
