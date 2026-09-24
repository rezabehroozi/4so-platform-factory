#!/usr/bin/env python3
"""Validate and expose the product-owned upstream admission queue for unresolved Helm components.

This authority selects exact candidates and official sources before network acquisition.  It
never resolves a source, manufactures a digest/source lock, or claims runtime certification.
Those remain separate fail-closed gates owned by acquire_upstream_helm.py and runtime
certification respectively.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import shlex
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUTHORITY = ROOT / "catalog" / "upstream-admission.json"
EXACT = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
SPDX_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,127}$")
ALLOWED_STATUS = {
    "ready-for-acquisition",
    "architecture-review-required",
    "dependency-review-required",
    "version-selection-required",
    "version-review-required",
}
ALLOWED_RUNTIME_STATUS = {
    "eligible-after-source-resolution",
    "dependency-transition-required",
    "review-required",
}


def normalized(v: str | None) -> str:
    return str(v or "").strip().removeprefix("v")


def constraint_matches(constraint: str, version: str) -> bool:
    c, v = normalized(constraint).lower(), normalized(version)
    if not EXACT.fullmatch(v):
        return False
    if EXACT.fullmatch(c):
        return c == v
    cp, vp = c.split("."), v.split(".")
    return len(cp) == 3 and cp[2] == "x" and cp[:2] == vp[:2]


def _absolute_no_follow(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def require_real_repo_file(root: Path, path: Path, label: str) -> Path:
    root_abs = _absolute_no_follow(root)
    path_abs = _absolute_no_follow(path)
    try:
        rel = path_abs.relative_to(root_abs)
    except ValueError:
        rel = None
    if rel is not None:
        current = root_abs
        for part in rel.parts[:-1]:
            current /= part
            st = current.lstat()
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise RuntimeError(f"{label.upper().replace(' ', '_')}_PATH_INVALID {current}")
    st = path_abs.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise RuntimeError(f"{label.upper().replace(' ', '_')}_PATH_INVALID {path_abs}")
    return path_abs


def require_real_repo_directory(root: Path, path: Path, label: str) -> Path:
    root_abs = _absolute_no_follow(root)
    path_abs = _absolute_no_follow(path)
    rel = path_abs.relative_to(root_abs)
    current = root_abs
    for part in rel.parts:
        current /= part
        st = current.lstat()
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise RuntimeError(f"{label.upper().replace(' ', '_')}_PATH_INVALID {current}")
    return path_abs


def unresolved_helm_components(root: Path) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    components_dir = require_real_repo_directory(root, root / "catalog" / "components", "catalog components")
    for path in sorted(components_dir.glob("*.json")):
        require_real_repo_file(root, path, "catalog component")
        doc = json.loads(path.read_text())
        spec = doc.get("spec") or {}
        src = spec.get("source") or {}
        if src.get("type") == "helm-chart" and not src.get("resolved"):
            rows[str((doc.get("metadata") or {}).get("name") or path.stem)] = doc
    return rows


def load_authority(path: Path = DEFAULT_AUTHORITY, root: Path = ROOT) -> dict:
    path = require_real_repo_file(root, path, "upstream admission authority")
    doc = json.loads(path.read_text())
    if doc.get("apiVersion") != "platform.4so.io/v1alpha1" or doc.get("kind") != "CatalogUpstreamAdmission":
        raise RuntimeError("UPSTREAM_ADMISSION_TYPE_INVALID")
    policy = (doc.get("spec") or {}).get("policy") or {}
    required_policy = {
        "sourceAuthority": "official-upstream-only",
        "versionSelection": "exact-semver-no-prerelease",
        "sourceResolution": "separate-immutable-acquisition-required",
        "runtimeCertification": "separate-runtime-evidence-required",
        "candidateAcquisition": "exact-source-may-be-acquired-before-runtime-clearance",
        "autoWidenCatalogConstraint": False,
        "allowLatestResolution": False,
    }
    for key, expected in required_policy.items():
        if policy.get(key) != expected:
            raise RuntimeError(f"UPSTREAM_ADMISSION_POLICY_INVALID {key}")
    return doc


def validate(root: Path = ROOT, authority_path: Path = DEFAULT_AUTHORITY) -> tuple[dict, list[dict]]:
    doc = load_authority(authority_path, root)
    catalog = unresolved_helm_components(root)
    entries = (doc.get("spec") or {}).get("components") or []
    if not isinstance(entries, list):
        raise RuntimeError("UPSTREAM_ADMISSION_COMPONENTS_INVALID")
    by_name: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuntimeError("UPSTREAM_ADMISSION_ENTRY_INVALID")
        name = str(entry.get("component") or "")
        if not NAME.fullmatch(name) or name in by_name:
            raise RuntimeError(f"UPSTREAM_ADMISSION_IDENTITY_INVALID {name}")
        by_name[name] = entry
    if set(by_name) != set(catalog):
        missing = sorted(set(catalog) - set(by_name))
        extra = sorted(set(by_name) - set(catalog))
        raise RuntimeError(f"UPSTREAM_ADMISSION_COVERAGE_INVALID missing={missing} extra={extra}")

    for name in sorted(by_name):
        entry = by_name[name]
        spec = catalog[name]["spec"]
        status = str(entry.get("status") or "")
        if status not in ALLOWED_STATUS:
            raise RuntimeError(f"UPSTREAM_ADMISSION_STATUS_INVALID {name}:{status}")
        runtime_status = str(entry.get("runtimeStatus") or "")
        if runtime_status not in ALLOWED_RUNTIME_STATUS:
            raise RuntimeError(f"UPSTREAM_ADMISSION_RUNTIME_STATUS_INVALID {name}:{runtime_status}")
        constraint = str(entry.get("catalogConstraint") or "")
        if not constraint or not (EXACT.fullmatch(normalized(constraint)) or re.fullmatch(r"[0-9]+\.[0-9]+\.x", normalized(constraint))):
            raise RuntimeError(f"UPSTREAM_ADMISSION_CONSTRAINT_INVALID {name}:{constraint}")
        chart = str(entry.get("chart") or "")
        if chart != str((spec.get("delivery") or {}).get("chart") or ""):
            raise RuntimeError(f"UPSTREAM_ADMISSION_CHART_MISMATCH {name}:{chart}")
        source = str(entry.get("source") or "")
        if not (source.startswith("https://") or source.startswith("oci://")):
            raise RuntimeError(f"UPSTREAM_ADMISSION_SOURCE_INVALID {name}:{source}")
        values_files = entry.get("valuesFiles") or []
        if not isinstance(values_files, list) or any(not isinstance(v, str) or not v or v.startswith("/") or "\\" in v or ".." in pathlib.PurePosixPath(v).parts for v in values_files):
            raise RuntimeError(f"UPSTREAM_ADMISSION_VALUES_FILES_INVALID {name}")
        if len(values_files) != len(set(values_files)):
            raise RuntimeError(f"UPSTREAM_ADMISSION_VALUES_FILES_DUPLICATE {name}")
        for value in values_files:
            path = require_real_repo_file(root, root / value, f"upstream values file {name}")
            try:
                path.resolve().relative_to(root.resolve())
            except ValueError as exc:
                raise RuntimeError(f"UPSTREAM_ADMISSION_VALUES_FILE_OUTSIDE_REPOSITORY {name}:{value}") from exc
        license_spdx = str(entry.get("licenseSPDX") or "").strip()
        if status == "ready-for-acquisition" and not license_spdx:
            raise RuntimeError(f"UPSTREAM_ADMISSION_LICENSE_SPDX_MISSING {name}")
        if license_spdx and not SPDX_ID.fullmatch(license_spdx):
            raise RuntimeError(f"UPSTREAM_ADMISSION_LICENSE_SPDX_INVALID {name}:{license_spdx}")
        if not str(entry.get("rationale") or "").strip():
            raise RuntimeError(f"UPSTREAM_ADMISSION_RATIONALE_MISSING {name}")
        evidence = entry.get("reviewEvidence") or []
        if not isinstance(evidence, list):
            raise RuntimeError(f"UPSTREAM_ADMISSION_REVIEW_EVIDENCE_INVALID {name}")
        for index, item in enumerate(evidence):
            if not isinstance(item, dict):
                raise RuntimeError(f"UPSTREAM_ADMISSION_REVIEW_EVIDENCE_INVALID {name}:{index}")
            if item.get("kind") not in {"release", "blocker", "source-migration"} or not str(item.get("url") or "").startswith("https://") or not str(item.get("summary") or "").strip():
                raise RuntimeError(f"UPSTREAM_ADMISSION_REVIEW_EVIDENCE_INVALID {name}:{index}")
        if runtime_status != "eligible-after-source-resolution" and not any(item.get("kind") == "blocker" for item in evidence):
            raise RuntimeError(f"UPSTREAM_ADMISSION_RUNTIME_BLOCKER_EVIDENCE_MISSING {name}")
        selected = entry.get("selectedVersion")
        upstream = entry.get("upstreamVersion")
        if selected is not None:
            selected = normalized(str(selected))
            if not EXACT.fullmatch(selected) or not constraint_matches(constraint, selected):
                raise RuntimeError(f"UPSTREAM_ADMISSION_VERSION_INVALID {name}:{selected} not-in {constraint}")
            if not upstream or normalized(str(upstream)) != selected:
                raise RuntimeError(f"UPSTREAM_ADMISSION_UPSTREAM_VERSION_INVALID {name}:{upstream}")
        if status == "version-review-required" and (selected is None or not evidence):
            raise RuntimeError(f"UPSTREAM_ADMISSION_VERSION_REVIEW_EVIDENCE_MISSING {name}")
        if status == "ready-for-acquisition":
            if selected is None:
                raise RuntimeError(f"UPSTREAM_ADMISSION_READY_VERSION_MISSING {name}")
            if str(spec.get("release") or "") != selected:
                raise RuntimeError(f"UPSTREAM_ADMISSION_CATALOG_PIN_MISMATCH {name}:{spec.get('release')}!={selected}")
            if spec.get("versionPolicy") != "exact-upstream-admitted-pending-source-acquisition":
                raise RuntimeError(f"UPSTREAM_ADMISSION_VERSION_POLICY_INVALID {name}")
        elif selected is not None:
            # Review state is a policy decision blocker, not permission to keep
            # runtime identity mutable. Once an exact candidate is selected, the
            # catalog must bind to that exact candidate while source.resolved
            # remains false and acquisition stays forbidden until review clears.
            if str(spec.get("release") or "") != selected:
                raise RuntimeError(f"UPSTREAM_ADMISSION_REVIEW_CANDIDATE_PIN_MISMATCH {name}:{spec.get('release')}!={selected}")
            if spec.get("versionPolicy") != "exact-upstream-review-candidate-pending-decision":
                raise RuntimeError(f"UPSTREAM_ADMISSION_REVIEW_VERSION_POLICY_INVALID {name}")
        elif str(spec.get("release") or "") != constraint:
            raise RuntimeError(f"UPSTREAM_ADMISSION_REVIEW_COMPONENT_MUTATED {name}:{spec.get('release')}!={constraint}")
        if (spec.get("source") or {}).get("resolved"):
            raise RuntimeError(f"UPSTREAM_ADMISSION_CONTAINS_RESOLVED_COMPONENT {name}")

    # Source acquisition is intentionally independent from runtime suitability.
    # Exact bytes may be acquired for inspection/evidence while installation and
    # certification remain blocked by runtimeStatus. Cilium 1.20 must stay
    # dependency-transition-required until Gateway API 1.6.1 is both current and
    # immutably resolved.
    gateway_path = require_real_repo_file(root, root / "catalog" / "components" / "gateway-api.json", "gateway api component")
    gateway = json.loads(gateway_path.read_text()).get("spec") or {}
    gateway_release = normalized(str(gateway.get("release") or ""))
    gateway_resolved = bool((gateway.get("source") or {}).get("resolved"))
    cilium = by_name.get("cilium") or {}
    cilium_selected = normalized(str(cilium.get("selectedVersion") or ""))
    if cilium_selected.startswith("1.20.") and (gateway_release != "1.6.1" or not gateway_resolved):
        if cilium.get("runtimeStatus") != "dependency-transition-required":
            raise RuntimeError(
                f"UPSTREAM_ADMISSION_RUNTIME_DEPENDENCY_STATUS_INVALID cilium:{cilium_selected} must remain dependency-transition-required until resolved gateway-api:1.6.1; current={gateway_release}:resolved={str(gateway_resolved).lower()}"
            )

    return doc, [by_name[n] for n in sorted(by_name)]


def acquisition_command(entry: dict) -> str:
    if entry.get("status") != "ready-for-acquisition":
        raise RuntimeError(f"UPSTREAM_ADMISSION_NOT_READY {entry.get('component')}:{entry.get('status')}")
    parts = [
        "python3", "scripts/acquire_upstream_helm.py", "--from-admission",
        "--component", str(entry["component"]), "--install",
    ]
    return " ".join(shlex.quote(p) for p in parts)


def summary(entries: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for e in entries:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    runtime_counts: dict[str, int] = {}
    for e in entries:
        runtime_counts[e["runtimeStatus"]] = runtime_counts.get(e["runtimeStatus"], 0) + 1
    return {
        "components": len(entries),
        "readyForAcquisition": counts.get("ready-for-acquisition", 0),
        "reviewRequired": len(entries) - counts.get("ready-for-acquisition", 0),
        "runtimeBlocked": sum(v for k, v in runtime_counts.items() if k != "eligible-after-source-resolution"),
        "statusCounts": dict(sorted(counts.items())),
        "runtimeStatusCounts": dict(sorted(runtime_counts.items())),
    }


def main() -> int:
    p = argparse.ArgumentParser(description="Validate/print the product-owned upstream Helm admission authority")
    p.add_argument("--authority", default=str(DEFAULT_AUTHORITY))
    p.add_argument("--json", action="store_true")
    p.add_argument("--commands", action="store_true", help="print deterministic acquisition commands for admitted entries")
    a = p.parse_args()
    try:
        _, entries = validate(ROOT, _absolute_no_follow(Path(a.authority)))
        out = summary(entries)
        if a.json:
            print(json.dumps({"status": "PASS", **out, "entries": entries}, indent=2, sort_keys=True))
        else:
            print("UPSTREAM_ADMISSION_PASS components=%d ready=%d review=%d runtime_blocked=%d statuses=%s runtime=%s" % (
                out["components"], out["readyForAcquisition"], out["reviewRequired"], out["runtimeBlocked"],
                ",".join(f"{k}:{v}" for k, v in out["statusCounts"].items()),
                ",".join(f"{k}:{v}" for k, v in out["runtimeStatusCounts"].items()),
            ))
        if a.commands:
            for e in entries:
                if e["status"] == "ready-for-acquisition":
                    print(acquisition_command(e))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"UPSTREAM_ADMISSION_BLOCKED {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
