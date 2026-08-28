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
ALLOWED_STATUS = {
    "ready-for-acquisition",
    "architecture-review-required",
    "dependency-review-required",
    "version-selection-required",
    "version-review-required",
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
        constraint = str(entry.get("catalogConstraint") or "")
        if not constraint or not (EXACT.fullmatch(normalized(constraint)) or re.fullmatch(r"[0-9]+\.[0-9]+\.x", normalized(constraint))):
            raise RuntimeError(f"UPSTREAM_ADMISSION_CONSTRAINT_INVALID {name}:{constraint}")
        chart = str(entry.get("chart") or "")
        if chart != str((spec.get("delivery") or {}).get("chart") or ""):
            raise RuntimeError(f"UPSTREAM_ADMISSION_CHART_MISMATCH {name}:{chart}")
        source = str(entry.get("source") or "")
        if not (source.startswith("https://") or source.startswith("oci://")):
            raise RuntimeError(f"UPSTREAM_ADMISSION_SOURCE_INVALID {name}:{source}")
        if not str(entry.get("rationale") or "").strip():
            raise RuntimeError(f"UPSTREAM_ADMISSION_RATIONALE_MISSING {name}")
        selected = entry.get("selectedVersion")
        upstream = entry.get("upstreamVersion")
        if selected is not None:
            selected = normalized(str(selected))
            if not EXACT.fullmatch(selected) or not constraint_matches(constraint, selected):
                raise RuntimeError(f"UPSTREAM_ADMISSION_VERSION_INVALID {name}:{selected} not-in {constraint}")
            if not upstream or normalized(str(upstream)) != selected:
                raise RuntimeError(f"UPSTREAM_ADMISSION_UPSTREAM_VERSION_INVALID {name}:{upstream}")
        if status == "ready-for-acquisition":
            if selected is None:
                raise RuntimeError(f"UPSTREAM_ADMISSION_READY_VERSION_MISSING {name}")
            if str(spec.get("release") or "") != selected:
                raise RuntimeError(f"UPSTREAM_ADMISSION_CATALOG_PIN_MISMATCH {name}:{spec.get('release')}!={selected}")
            if spec.get("versionPolicy") != "exact-upstream-admitted-pending-source-acquisition":
                raise RuntimeError(f"UPSTREAM_ADMISSION_VERSION_POLICY_INVALID {name}")
        elif str(spec.get("release") or "") != constraint:
            raise RuntimeError(f"UPSTREAM_ADMISSION_REVIEW_COMPONENT_MUTATED {name}:{spec.get('release')}!={constraint}")
        if (spec.get("source") or {}).get("resolved"):
            raise RuntimeError(f"UPSTREAM_ADMISSION_CONTAINS_RESOLVED_COMPONENT {name}")
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
    return {
        "components": len(entries),
        "readyForAcquisition": counts.get("ready-for-acquisition", 0),
        "reviewRequired": len(entries) - counts.get("ready-for-acquisition", 0),
        "statusCounts": dict(sorted(counts.items())),
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
            print("UPSTREAM_ADMISSION_PASS components=%d ready=%d review=%d statuses=%s" % (
                out["components"], out["readyForAcquisition"], out["reviewRequired"],
                ",".join(f"{k}:{v}" for k, v in out["statusCounts"].items()),
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
