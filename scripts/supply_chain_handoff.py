#!/usr/bin/env python3
"""Unified, derived S1/S2 connected-to-offline supply-chain handoff contract.

This file does not select versions or promote source/runtime state. It derives one
transport/execution plan from the canonical authorities already owned by the
product: catalog component/source state, upstream admission, management workload
image plan, and release build-toolchain lock. A connected runner can fill the
staging tree; an offline build host can then audit/verify the same tree without
turning staging metadata into a second source of truth.
"""
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
AUTHORITY = "SUPPLY_CHAIN_HANDOFF_V1"
SEAL_AUTHORITY = "SUPPLY_CHAIN_HANDOFF_SEAL_V1"
SEAL_FILE = "supply-chain-stage-seal.json"
MAX_STAGE_FILES = 200000
MAX_STAGE_BYTES = 50 * 1024 * 1024 * 1024
KIND = "SupplyChainHandoffPlan"
API_VERSION = "platform.4so.io/v1alpha1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXACT_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def _json(path: Path) -> dict:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"AUTHORITY_NOT_REGULAR_FILE {path}")
    raw = path.read_bytes()
    after = path.lstat()
    if before.st_ino != after.st_ino or before.st_dev != after.st_dev or before.st_size != after.st_size:
        raise RuntimeError(f"AUTHORITY_CHANGED_WHILE_READING {path}")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError(f"AUTHORITY_NOT_OBJECT {path}")
    return value


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _component_docs(root: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for path in sorted((root / "catalog" / "components").glob("*.json")):
        doc = _json(path)
        name = str((doc.get("metadata") or {}).get("name") or "")
        if not name or name in out:
            raise RuntimeError(f"COMPONENT_IDENTITY_INVALID {path}")
        out[name] = doc
    return out


def _source_lock(root: Path, component: str, release: str) -> dict | None:
    path = root / "catalog" / "runtime" / component / release / "source-lock.json"
    if not path.exists():
        return None
    lock = _json(path)
    if str(lock.get("component") or "") != component or str(lock.get("version") or "") != release:
        raise RuntimeError(f"SOURCE_LOCK_IDENTITY_INVALID {component}:{release}")
    return {"path": path.relative_to(root).as_posix(), "sha256": _sha256(path)}


def _previous_locks(root: Path, component: str, target: str) -> list[dict]:
    base = root / "catalog" / "runtime" / component
    rows: list[dict] = []
    if not base.exists():
        return rows
    target_key = tuple(map(int, target.split("."))) if EXACT_RE.fullmatch(target) else None
    for child in sorted(base.iterdir(), key=lambda p: p.name):
        if not child.is_dir() or child.name == target or not EXACT_RE.fullmatch(child.name):
            continue
        prev_key = tuple(map(int, child.name.split(".")))
        if target_key is None or prev_key >= target_key:
            continue
        lock = _source_lock(root, component, child.name)
        if lock:
            rows.append({"release": child.name, **lock})
    return rows


def build(root: Path = ROOT) -> dict:
    version = (root / "VERSION").read_text().strip()
    admission = _json(root / "catalog" / "upstream-admission.json")
    image_plan = _json(root / "lab" / "management-workload-image-build-plan.json")
    toolchain = _json(root / "lab" / "release-build-toolchain-lock.json")
    upgrade_admission = _json(root / "catalog" / "component-upgrade-source-admission.json")
    runtime_transition = _json(root / "catalog" / "runtime-dependency-transition.json")
    components = _component_docs(root)

    rows = (admission.get("spec") or {}).get("components") or []
    if not isinstance(rows, list):
        raise RuntimeError("UPSTREAM_ADMISSION_ROWS_INVALID")
    ready, review, runtime_holds = [], [], []
    for row in rows:
        name = str(row.get("component") or "")
        selected = str(row.get("selectedVersion") or "").lstrip("v")
        if name not in components or not EXACT_RE.fullmatch(selected):
            raise RuntimeError(f"UPSTREAM_ADMISSION_ROW_INVALID {name}:{selected}")
        entry = {
            "component": name,
            "selectedVersion": selected,
            "source": str(row.get("source") or ""),
            "upstreamVersion": str(row.get("upstreamVersion") or row.get("selectedVersion") or ""),
            "status": str(row.get("status") or ""),
            "runtimeStatus": str(row.get("runtimeStatus") or ""),
        }
        (ready if row.get("status") == "ready-for-acquisition" else review).append(entry)
        if row.get("runtimeStatus") != "eligible-after-source-resolution":
            runtime_holds.append(entry)

    upgrade_admission_by_name = {str(r.get("component") or ""): r for r in (upgrade_admission.get("components") or [])}
    resolved = []
    upgrade = []
    for name, doc in sorted(components.items()):
        spec = doc.get("spec") or {}
        release = str(spec.get("release") or "").lstrip("v")
        lock = _source_lock(root, name, release)
        if lock:
            resolved.append({"component": name, "release": release, **lock})
        previous = _previous_locks(root, name, release)
        admission_row = upgrade_admission_by_name.get(name) or {}
        install_only = admission_row.get("status") == "install-only-first-product-release"
        upgrade.append({
            "component": name,
            "targetRelease": release,
            "targetSourceLockPresent": lock is not None,
            "previousExactSourceLocks": previous,
            "pairState": "install-only-first-product-release" if install_only else ("pair-present" if lock and previous else ("target-only" if lock else "target-source-pending")),
            "previousReleaseSelectionPolicy": "historical-version-fabrication-forbidden" if install_only else "explicit-reviewed-exact-version-required",
        })

    external = []
    product_images = []
    for row in image_plan.get("coreImages") or []:
        ownership = row.get("ownership")
        if ownership == "external":
            external.append({
                "role": row["role"],
                "repository": row["repository"],
                "tag": row["tag"],
                "version": row["version"],
                "selectionChannel": row["selectionChannel"],
                "selectionEvidenceURL": row["selectionEvidenceURL"],
                "layoutPath": f"management/external/{row['role']}/layout",
                "lockPath": f"management/external/{row['role']}/acquisition-lock.json",
            })
        elif ownership == "product":
            product_images.append({
                "role": row["role"],
                "repository": row["repository"],
                "containerRecipe": row["containerRecipe"],
                "baseImageRole": row["baseImageRole"],
                "sourceReleaseMember": row.get("sourceReleaseMember", ""),
                "state": row.get("state"),
            })

    manifest_sets = []
    for row in image_plan.get("derivedManifestImageSets") or []:
        manifest_sets.append({
            "sourceAuthority": row["sourceAuthority"],
            "manifestPath": row["manifestPath"],
            "sourceManifestSha256": row["sourceManifestSha256"],
            "sourceManifestBytes": row["sourceManifestBytes"],
            "resolvedManifestPath": row["resolvedManifestPath"],
            "resolutionLockPath": row["resolutionLockPath"],
            "stagedResolutionPath": f"management/manifests/{row['sourceAuthority']}.resolution.json",
        })

    tc_spec = toolchain.get("spec") or {}
    candidate = tc_spec.get("candidateExactCompiler") or tc_spec.get("exactCompiler") or {}
    toolchain_row = {
        "admissionStatus": tc_spec.get("admissionStatus"),
        "version": candidate.get("version"),
        "goos": candidate.get("goos"),
        "goarch": candidate.get("goarch"),
        "archiveFile": candidate.get("archiveFile"),
        "archiveURL": candidate.get("archiveURL", ""),
        "archiveSha256": candidate.get("archiveSha256"),
        "archiveSize": candidate.get("archiveSize"),
        "stagePath": f"toolchain/{candidate.get('archiveFile','')}",
        "installPath": candidate.get("localArchivePath"),
    }

    upgrade_admitted = []
    upgrade_review = []
    upgrade_install_only = []
    for row in upgrade_admission.get("components") or []:
        item = {
            "component": str(row.get("component") or ""),
            "targetRelease": str(row.get("targetRelease") or ""),
            "status": str(row.get("status") or ""),
            "previousVersion": str(row.get("previousVersion") or ""),
            "source": str(row.get("source") or ""),
        }
        if item["status"] == "admitted-for-acquisition":
            upgrade_admitted.append(item)
        elif item["status"] == "install-only-first-product-release":
            upgrade_install_only.append(item)
        else:
            upgrade_review.append(item)

    historical = {
        "authority": "HISTORICAL_UPGRADE_STAGED_BATCH_V1",
        "stageManifestPath": "historical/stage-manifest.json",
        "helmReady": [],
        "taggedSourceSetReady": [],
        "waitingCurrentSource": [],
        "alreadyHistoricalSourceLocked": [],
        "installOnlyFirstProductRelease": [],
    }
    for row in upgrade_admission.get("components") or []:
        name = str(row.get("component") or "")
        status = str(row.get("status") or "")
        if status == "install-only-first-product-release":
            historical["installOnlyFirstProductRelease"].append({"component": name, "targetRelease": str(row.get("targetRelease") or "")})
            continue
        if status != "admitted-for-acquisition":
            continue
        previous = str(row.get("previousVersion") or "")
        target = str(row.get("targetRelease") or "")
        item = {"component": name, "targetRelease": target, "previousVersion": previous, "source": str(row.get("source") or "")}
        prev_lock = _source_lock(root, name, previous) if EXACT_RE.fullmatch(previous) else None
        if prev_lock:
            historical["alreadyHistoricalSourceLocked"].append({**item, **prev_lock})
            continue
        cdoc = components.get(name) or {}
        cspec = cdoc.get("spec") or {}
        if (cspec.get("source") or {}).get("resolved") is not True:
            historical["waitingCurrentSource"].append(item)
            continue
        if (cspec.get("source") or {}).get("type") == "external-tagged-source-set":
            recipe_path = root / "catalog" / "tagged-source-recipes" / name / f"{previous}.json"
            if recipe_path.is_file():
                recipe = _json(recipe_path)
                item["recipePath"] = recipe_path.relative_to(root).as_posix()
                item["recipeCommitSHA"] = str((recipe.get("spec") or {}).get("commitSHA") or "")
            historical["taggedSourceSetReady"].append(item)
        else:
            historical["helmReady"].append(item)
    for key in ("helmReady","taggedSourceSetReady","waitingCurrentSource","alreadyHistoricalSourceLocked","installOnlyFirstProductRelease"):
        historical[key] = sorted(historical[key], key=lambda r: r["component"])

    blockers = []
    if review:
        blockers.append("UPSTREAM_SOURCE_SELECTION_REVIEWS_PENDING")
    if runtime_holds:
        blockers.append("UPSTREAM_RUNTIME_SUITABILITY_HOLDS_PENDING")
    if ready:
        blockers += ["COMPONENT_SOURCE_ACQUISITION_PENDING", "SOURCE_LOCKS_PENDING"]
    if tc_spec.get("admissionStatus") != "admitted":
        blockers.append("RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING")
    if external or manifest_sets or product_images:
        blockers += ["MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING", "MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING"]
    if any(row["pairState"] not in {"pair-present", "install-only-first-product-release"} for row in upgrade):
        blockers.append("COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING")
    if any(row.get("status") == "admitted-for-acquisition" and not _previous_locks(root, row.get("component", ""), row.get("targetRelease", "")) for row in (upgrade_admission.get("components") or [])):
        blockers.append("COMPONENT_HISTORICAL_SOURCE_ACQUISITION_PENDING")

    return {
        "apiVersion": API_VERSION,
        "kind": KIND,
        "metadata": {"name": "platform-factory-pre-certification-supply-chain-handoff"},
        "spec": {
            "authority": AUTHORITY,
            "schemaVersion": 1,
            "releaseVersion": version,
            "truthModel": {
                "derivedEvidenceOnly": True,
                "canonicalAuthorities": [
                    "catalog/components/*",
                    "catalog/upstream-admission.json",
                    "catalog/runtime/*/*/source-lock.json",
                    "lab/management-workload-image-build-plan.json",
                    "lab/release-build-toolchain-lock.json",
                    "catalog/component-upgrade-source-admission.json",
                    "catalog/tagged-source-recipes/*",
                    "catalog/runtime-dependency-transition.json",
                ],
                "stagingNeverPromotesSourceResolution": True,
                "stagingNeverPromotesRuntimeCertification": True,
                "physicalPassInferenceForbidden": True,
            },
            "componentAcquisition": {
                "stageManifestPath": "components/stage-manifest.json",
                "ready": sorted(ready, key=lambda r: r["component"]),
                "reviewBlocked": sorted(review, key=lambda r: r["component"]),
                "runtimeHolds": sorted(runtime_holds, key=lambda r: r["component"]),
                "alreadySourceLocked": sorted(resolved, key=lambda r: r["component"]),
            },
            "managementWorkloads": {
                "externalImages": sorted(external, key=lambda r: r["role"]),
                "manifestImageResolution": sorted(manifest_sets, key=lambda r: r["sourceAuthority"]),
                "productImages": sorted(product_images, key=lambda r: r["role"]),
                "archiveStagingPath": image_plan.get("archiveStagingPath"),
            },
            "releaseToolchain": toolchain_row,
            "runtimeDependencyTransition": {
                "authority": str((runtime_transition.get("spec") or {}).get("authority") or ""),
                "status": str((runtime_transition.get("spec") or {}).get("status") or ""),
                "gatewayTargetRelease": str(((runtime_transition.get("spec") or {}).get("gatewayApi") or {}).get("targetRelease") or ""),
                "kgatewayTargetRelease": str(((runtime_transition.get("spec") or {}).get("kgateway") or {}).get("targetRelease") or ""),
                "ciliumTargetRelease": str(((runtime_transition.get("spec") or {}).get("cilium") or {}).get("targetRelease") or ""),
            },
            "historicalComponentAcquisition": historical,
            "componentUpgradeSourceAdmission": {
                "authority": str(upgrade_admission.get("authority") or ""),
                "admitted": sorted(upgrade_admitted, key=lambda r: r["component"]),
                "reviewRequired": sorted(upgrade_review, key=lambda r: r["component"]),
                "installOnlyFirstProductRelease": sorted(upgrade_install_only, key=lambda r: r["component"]),
            },
            "componentUpgradePairRequirements": upgrade,
            "openBlockers": sorted(set(blockers)),
        },
    }


def validate(plan: dict, root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    if plan.get("apiVersion") != API_VERSION or plan.get("kind") != KIND:
        errors.append("type identity invalid")
    spec = plan.get("spec") or {}
    if spec.get("authority") != AUTHORITY or spec.get("schemaVersion") != 1:
        errors.append("authority invalid")
    if spec.get("releaseVersion") != (root / "VERSION").read_text().strip():
        errors.append("release version drift")
    truth = spec.get("truthModel") or {}
    for key in ("derivedEvidenceOnly", "stagingNeverPromotesSourceResolution", "stagingNeverPromotesRuntimeCertification", "physicalPassInferenceForbidden"):
        if truth.get(key) is not True:
            errors.append(f"truth model missing {key}")
    tc = spec.get("releaseToolchain") or {}
    if not tc.get("archiveFile") or not SHA256_RE.fullmatch(str(tc.get("archiveSha256") or "")) or not isinstance(tc.get("archiveSize"), int) or tc.get("archiveSize") <= 0:
        errors.append("release toolchain exact archive contract invalid")
    if tc.get("stagePath") != f"toolchain/{tc.get('archiveFile','')}":
        errors.append("release toolchain stage path invalid")
    comp = spec.get("componentAcquisition") or {}
    ready = comp.get("ready") or []
    review = comp.get("reviewBlocked") or []
    runtime_holds = comp.get("runtimeHolds") or []
    if set(r.get("component") for r in ready) & set(r.get("component") for r in review):
        errors.append("component ready/review sets overlap")
    for row in ready + review:
        if not EXACT_RE.fullmatch(str(row.get("selectedVersion") or "")):
            errors.append(f"component candidate not exact: {row.get('component')}")
    if any(r.get("status") != "ready-for-acquisition" for r in runtime_holds):
        errors.append("runtime hold incorrectly blocks source acquisition")
    transition = spec.get("runtimeDependencyTransition") or {}
    if transition.get("authority") != "RUNTIME_DEPENDENCY_TRANSITION_V1" or transition.get("status") != "acquisition-pending":
        errors.append("runtime dependency transition authority invalid")
    upgrade_adm = spec.get("componentUpgradeSourceAdmission") or {}
    if upgrade_adm.get("authority") != "COMPONENT_UPGRADE_SOURCE_ADMISSION_V1":
        errors.append("upgrade source admission authority invalid")
    if len((upgrade_adm.get("admitted") or [])) + len((upgrade_adm.get("reviewRequired") or [])) + len((upgrade_adm.get("installOnlyFirstProductRelease") or [])) != len(_component_docs(root)):
        errors.append("upgrade source admission coverage invalid")
    hist = spec.get("historicalComponentAcquisition") or {}
    if hist.get("authority") != "HISTORICAL_UPGRADE_STAGED_BATCH_V1" or hist.get("stageManifestPath") != "historical/stage-manifest.json":
        errors.append("historical component acquisition authority invalid")
    hist_rows = sum((hist.get(k) or [] for k in ("helmReady","taggedSourceSetReady","waitingCurrentSource","alreadyHistoricalSourceLocked","installOnlyFirstProductRelease")), [])
    if len(hist_rows) != len(_component_docs(root)):
        errors.append("historical component acquisition coverage invalid")
    for row in hist.get("taggedSourceSetReady") or []:
        if not str(row.get("recipePath") or "").startswith("catalog/tagged-source-recipes/") or not re.fullmatch(r"[0-9a-f]{40}", str(row.get("recipeCommitSHA") or "")):
            errors.append(f"historical tagged recipe binding invalid: {row.get('component')}")
    upgrades = spec.get("componentUpgradePairRequirements") or []
    if len(upgrades) != len(_component_docs(root)):
        errors.append("upgrade pair coverage invalid")
    for row in upgrades:
        if row.get("pairState") not in {"pair-present", "target-only", "target-source-pending", "install-only-first-product-release"}:
            errors.append(f"upgrade pair state invalid: {row.get('component')}")
        expected_policy = "historical-version-fabrication-forbidden" if row.get("pairState") == "install-only-first-product-release" else "explicit-reviewed-exact-version-required"
        if row.get("previousReleaseSelectionPolicy") != expected_policy:
            errors.append(f"upgrade previous release policy invalid: {row.get('component')}")
    expected = build(root)
    if json.dumps(plan, sort_keys=True, separators=(",", ":")) != json.dumps(expected, sort_keys=True, separators=(",", ":")):
        errors.append("handoff plan drift: regenerate from canonical authorities")
    return errors


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    fd, tmp_name = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def stage_audit(stage: Path, plan: dict, *, strict: bool = False) -> tuple[list[str], list[str]]:
    """Audit transport presence and byte identity where authority supplies a digest.

    OCI layouts and manifest-resolution locks are owner-verified later because their
    internal identity is bound to the exact release/platformctl transaction; this audit
    intentionally does not duplicate those domain validators.
    """
    missing: list[str] = []
    invalid: list[str] = []
    if not stage.exists() or stage.is_symlink() or not stage.is_dir():
        return ["stage-directory"], []
    spec = plan["spec"]
    tc = spec["releaseToolchain"]
    tc_path = stage / tc["stagePath"]
    if not tc_path.exists():
        missing.append(tc["stagePath"])
    else:
        st = tc_path.lstat()
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            invalid.append(tc["stagePath"] + ":not-regular")
        elif st.st_size != tc["archiveSize"]:
            invalid.append(tc["stagePath"] + ":size")
        elif _sha256(tc_path) != tc["archiveSha256"]:
            invalid.append(tc["stagePath"] + ":sha256")
    comp_manifest = stage / spec["componentAcquisition"]["stageManifestPath"]
    if not comp_manifest.exists():
        missing.append(comp_manifest.relative_to(stage).as_posix())
    elif comp_manifest.is_symlink() or not comp_manifest.is_file():
        invalid.append(comp_manifest.relative_to(stage).as_posix() + ":not-regular")
    historical = spec.get("historicalComponentAcquisition") or {}
    if (historical.get("helmReady") or []) or (historical.get("taggedSourceSetReady") or []):
        hist_manifest = stage / str(historical.get("stageManifestPath") or "historical/stage-manifest.json")
        if not hist_manifest.exists():
            missing.append(hist_manifest.relative_to(stage).as_posix())
        elif hist_manifest.is_symlink() or not hist_manifest.is_file():
            invalid.append(hist_manifest.relative_to(stage).as_posix() + ":not-regular")
    for row in spec["managementWorkloads"]["externalImages"]:
        for key in ("layoutPath", "lockPath"):
            p = stage / row[key]
            if not p.exists():
                missing.append(row[key])
            elif p.is_symlink() or (key == "layoutPath" and not p.is_dir()) or (key == "lockPath" and not p.is_file()):
                invalid.append(row[key] + ":type")
    for row in spec["managementWorkloads"]["manifestImageResolution"]:
        p = stage / row["stagedResolutionPath"]
        if not p.exists():
            missing.append(row["stagedResolutionPath"])
        elif p.is_symlink() or not p.is_file():
            invalid.append(row["stagedResolutionPath"] + ":type")
    if strict and missing:
        invalid.extend("missing:" + item for item in missing)
    return sorted(missing), sorted(invalid)



def _stage_inventory(stage: Path) -> tuple[list[dict], int]:
    """Return deterministic regular-file inventory; reject links/special files.

    The seal is transport evidence only. It intentionally excludes itself and never
    promotes staged bytes into product authority.
    """
    if not stage.exists() or stage.is_symlink() or not stage.is_dir():
        raise RuntimeError("STAGE_ROOT_INVALID")
    rows: list[dict] = []
    total = 0
    for path in sorted(stage.rglob("*"), key=lambda p: p.as_posix()):
        rel = path.relative_to(stage).as_posix()
        if rel == SEAL_FILE:
            continue
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode):
            raise RuntimeError(f"STAGE_SYMLINK_FORBIDDEN {rel}")
        if stat.S_ISDIR(st.st_mode):
            continue
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"STAGE_SPECIAL_FILE_FORBIDDEN {rel}")
        total += st.st_size
        if len(rows) >= MAX_STAGE_FILES:
            raise RuntimeError("STAGE_FILE_LIMIT_EXCEEDED")
        if total > MAX_STAGE_BYTES:
            raise RuntimeError("STAGE_BYTE_LIMIT_EXCEEDED")
        rows.append({"path": rel, "sizeBytes": st.st_size, "sha256": _sha256(path)})
    return rows, total


def build_stage_seal(stage: Path, plan: dict) -> dict:
    rows, total = _stage_inventory(stage)
    plan_digest = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    inventory_digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "apiVersion": API_VERSION,
        "kind": "SupplyChainHandoffStageSeal",
        "metadata": {"name": "platform-factory-pre-certification-stage"},
        "spec": {
            "authority": SEAL_AUTHORITY,
            "schemaVersion": 1,
            "releaseVersion": plan["spec"]["releaseVersion"],
            "handoffAuthority": AUTHORITY,
            "handoffPlanSha256": plan_digest,
            "inventorySha256": inventory_digest,
            "fileCount": len(rows),
            "totalBytes": total,
            "files": rows,
            "truthModel": {
                "transportEvidenceOnly": True,
                "sealNeverPromotesSourceResolution": True,
                "sealNeverPromotesRuntimeCertification": True,
                "physicalPassInferenceForbidden": True,
            },
        },
    }


def verify_stage_seal(stage: Path, plan: dict) -> list[str]:
    errors: list[str] = []
    seal_path = stage / SEAL_FILE
    try:
        actual = _json(seal_path)
        expected = build_stage_seal(stage, plan)
    except Exception as exc:
        return [str(exc)]
    spec = actual.get("spec") or {}
    truth = spec.get("truthModel") or {}
    if spec.get("authority") != SEAL_AUTHORITY or spec.get("schemaVersion") != 1:
        errors.append("stage seal authority invalid")
    for key in ("transportEvidenceOnly", "sealNeverPromotesSourceResolution", "sealNeverPromotesRuntimeCertification", "physicalPassInferenceForbidden"):
        if truth.get(key) is not True:
            errors.append(f"stage seal truth model missing {key}")
    if json.dumps(actual, sort_keys=True, separators=(",", ":")) != json.dumps(expected, sort_keys=True, separators=(",", ":")):
        errors.append("stage seal drift or byte tamper")
    return errors

def command_plan(plan: dict) -> dict:
    spec = plan["spec"]
    connected = [
        "python3 scripts/acquire_upstream_batch.py --stage-out STAGE/components",
        "python3 scripts/acquire_historical_upgrade_batch.py --stage-out STAGE/historical",
        "# acquire each management external image with exact release-bound platformctl workload-oci acquire-external",
        f"# stage exact compiler byte at STAGE/{spec['releaseToolchain']['stagePath']}",
        "# resolve every mutable image reference from the three source manifests to exact digest references",
    ]
    offline = [
        "python3 scripts/component_upgrade_source_admission.py --check",
        "python3 scripts/supply_chain_handoff.py --check --plan lab/supply-chain-handoff-plan.json",
        "python3 scripts/supply_chain_handoff.py --verify-stage-seal STAGE",
        "python3 scripts/supply_chain_handoff.py --audit-stage STAGE --strict",
        "python3 scripts/acquire_upstream_batch.py --install-staged STAGE/components",
        "python3 scripts/acquire_historical_upgrade_batch.py --install-staged STAGE/historical",
        f"python3 scripts/acquire_release_build_toolchain.py --install STAGE/{spec['releaseToolchain']['stagePath']}",
        "# verify every management external image with exact release-bound platformctl workload-oci verify-external before OCI assembly",
        "python3 scripts/component_runtime_upgrade_matrix.py --write --check",
    ]
    return {"authority": AUTHORITY, "connected": connected, "offline": offline}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--plan", default="lab/supply-chain-handoff-plan.json")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--commands", action="store_true")
    ap.add_argument("--audit-stage")
    ap.add_argument("--seal-stage")
    ap.add_argument("--verify-stage-seal")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()
    out = ROOT / args.plan
    current = build(ROOT)
    if args.write:
        _atomic_json(out, current)
    if args.check:
        if not out.exists():
            print("SUPPLY_CHAIN_HANDOFF_FAIL missing-plan")
            return 1
        errors = validate(_json(out), ROOT)
        if errors:
            print("SUPPLY_CHAIN_HANDOFF_FAIL " + "; ".join(errors))
            return 1
    if args.status:
        spec = current["spec"]
        ca = spec["componentAcquisition"]
        pairs = spec["componentUpgradePairRequirements"]
        pair_present = sum(1 for row in pairs if row["pairState"] == "pair-present")
        install_only = sum(1 for row in pairs if row["pairState"] == "install-only-first-product-release")
        hist = spec.get("historicalComponentAcquisition") or {}
        print(f"SUPPLY_CHAIN_HANDOFF_STATUS ready={len(ca['ready'])} review={len(ca['reviewBlocked'])} source_locked={len(ca['alreadySourceLocked'])} historical_tagged_ready={len(hist.get('taggedSourceSetReady') or [])} historical_helm_ready={len(hist.get('helmReady') or [])} historical_waiting_current={len(hist.get('waitingCurrentSource') or [])} external_images={len(spec['managementWorkloads']['externalImages'])} manifest_sets={len(spec['managementWorkloads']['manifestImageResolution'])} upgrade_pairs={pair_present}/{len(pairs)-install_only} install_only={install_only} toolchain={spec['releaseToolchain']['admissionStatus']}")
    if args.commands:
        print(json.dumps(command_plan(current), indent=2))
    if args.seal_stage:
        stage = Path(args.seal_stage).resolve()
        missing, invalid = stage_audit(stage, current, strict=True)
        if invalid or missing:
            print("SUPPLY_CHAIN_HANDOFF_SEAL_FAIL stage-not-complete invalid=" + ",".join(invalid) + (" missing=" + ",".join(missing) if missing else ""))
            return 1
        _atomic_json(stage / SEAL_FILE, build_stage_seal(stage, current))
        print(f"SUPPLY_CHAIN_HANDOFF_SEAL_PASS file={stage / SEAL_FILE}")
    if args.verify_stage_seal:
        stage = Path(args.verify_stage_seal).resolve()
        errors = verify_stage_seal(stage, current)
        if errors:
            print("SUPPLY_CHAIN_HANDOFF_SEAL_VERIFY_FAIL " + "; ".join(errors))
            return 1
        print("SUPPLY_CHAIN_HANDOFF_SEAL_VERIFY_PASS")
    if args.audit_stage:
        missing, invalid = stage_audit(Path(args.audit_stage).resolve(), current, strict=args.strict)
        if invalid:
            print("SUPPLY_CHAIN_HANDOFF_STAGE_FAIL invalid=" + ",".join(invalid) + (" missing=" + ",".join(missing) if missing else ""))
            return 1
        if missing:
            print("SUPPLY_CHAIN_HANDOFF_STAGE_PENDING missing=" + ",".join(missing))
            return 2
        print("SUPPLY_CHAIN_HANDOFF_STAGE_PASS")
    if not any((args.write, args.check, args.status, args.commands, args.audit_stage, args.seal_stage, args.verify_stage_seal)):
        ap.error("choose --write/--check/--status/--commands/--audit-stage/--seal-stage/--verify-stage-seal")
    if args.check:
        print("SUPPLY_CHAIN_HANDOFF_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
