#!/usr/bin/env python3
"""Exact-release-bound connected staging and offline verification for management images."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
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
AUTHORITY = "MANAGEMENT_WORKLOAD_STAGED_BATCH_V1"
DIAGNOSTIC_AUTHORITY = "MANAGEMENT_WORKLOAD_ACQUISITION_DIAGNOSTIC_V1"
ACQUISITION_LOCK_AUTHORITY = "LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8"
MANAGEMENT_WORKLOAD_SOURCE_AUTHORITY = "management-workload-oci-archive"
MANIFEST = "stage-manifest.json"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ROLE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def regular_dir(path: Path, label: str, create: bool = False) -> Path:
    if create:
        path.mkdir(parents=True, exist_ok=True)
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f"{label}_NOT_REAL_DIRECTORY {path}")
    return path


def regular_file(path: Path, label: str) -> Path:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise RuntimeError(f"{label}_NOT_REAL_FILE {path}")
    return path


def tree_digest(path: Path) -> tuple[str, int, int]:
    """Digest a transferred OCI layout by relative path + size + file digest."""
    regular_dir(path, "MANAGEMENT_STAGE_LAYOUT")
    h = hashlib.sha256()
    count = 0
    total = 0
    for p in sorted(path.rglob("*"), key=lambda x: x.as_posix()):
        rel = p.relative_to(path).as_posix()
        st = p.lstat()
        if stat.S_ISLNK(st.st_mode):
            raise RuntimeError(f"MANAGEMENT_STAGE_LAYOUT_SYMLINK {rel}")
        if stat.S_ISDIR(st.st_mode):
            continue
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"MANAGEMENT_STAGE_LAYOUT_NONREGULAR {rel}")
        dg = sha256_file(p)
        h.update(rel.encode() + b"\0" + str(st.st_size).encode() + b"\0" + dg.encode() + b"\n")
        count += 1
        total += st.st_size
    if not count:
        raise RuntimeError("MANAGEMENT_STAGE_LAYOUT_EMPTY")
    return "sha256:" + h.hexdigest(), count, total


def load_plan(root: Path = ROOT) -> tuple[dict, list[dict]]:
    p = root / "lab" / "management-workload-image-build-plan.json"
    plan = json.loads(regular_file(p, "MANAGEMENT_IMAGE_PLAN").read_text())
    if plan.get("authority") != "MANAGEMENT_WORKLOAD_IMAGE_BUILD_PLAN_V5":
        raise RuntimeError("MANAGEMENT_IMAGE_PLAN_AUTHORITY_INVALID")
    rows = []
    for row in plan.get("coreImages") or []:
        if row.get("ownership") != "external":
            continue
        role = str(row.get("role") or "")
        if not ROLE_RE.fullmatch(role):
            raise RuntimeError(f"MANAGEMENT_IMAGE_ROLE_INVALID {role}")
        rows.append({
            "role": role,
            "repository": str(row.get("repository") or ""),
            "tag": str(row.get("tag") or ""),
            "version": str(row.get("version") or ""),
            "selectionChannel": str(row.get("selectionChannel") or ""),
            "selectionEvidenceURL": str(row.get("selectionEvidenceURL") or ""),
        })
    return plan, sorted(rows, key=lambda r: r["role"])


def diagnose(root: Path = ROOT) -> dict:
    """Return a read-only, fail-closed acquisition diagnosis without network or build mutation."""
    plan, external_rows = load_plan(root)
    version = regular_file(root / "VERSION", "VERSION").read_text().strip()
    lock = json.loads(regular_file(root / "lab" / "appliance-bundle-acquisition-lock.json", "BUNDLE_ACQUISITION_LOCK").read_text())
    if lock.get("authority") != ACQUISITION_LOCK_AUTHORITY or lock.get("schemaVersion") != 8:
        raise RuntimeError("MANAGEMENT_ACQUISITION_LOCK_AUTHORITY_INVALID")
    if plan.get("releaseVersion") != version or lock.get("releaseVersion") != version:
        raise RuntimeError("MANAGEMENT_ACQUISITION_RELEASE_VERSION_DRIFT")
    status = str(lock.get("status") or "")
    if status not in {"ready", "incomplete"}:
        raise RuntimeError("MANAGEMENT_ACQUISITION_LOCK_STATUS_INVALID")
    missing = lock.get("missingAuthorities") or []
    if not isinstance(missing, list) or any(not isinstance(item, str) or not item.strip() for item in missing):
        raise RuntimeError("MANAGEMENT_ACQUISITION_MISSING_AUTHORITIES_INVALID")
    missing = sorted(item.strip() for item in missing)
    resolved = sorted(str(row.get("id") or "") for row in (lock.get("resolvedAuthorities") or []) if isinstance(row, dict))
    partial = sorted(str(row.get("id") or "") for row in (lock.get("partialAuthorities") or []) if isinstance(row, dict))

    pending_external = sorted(row["role"] for row in external_rows if any(not row[key] for key in ("repository", "tag", "version", "selectionChannel", "selectionEvidenceURL")) or next((src.get("state") for src in plan.get("coreImages", []) if src.get("role") == row["role"]), "pending") != "ready")
    pending_base = sorted(str(row.get("role") or "") for row in (plan.get("baseImages") or []) if row.get("state") != "ready")
    pending_product = sorted(str(row.get("role") or "") for row in (plan.get("coreImages") or []) if row.get("ownership") == "product" and row.get("state") != "ready")
    pending_manifests = sorted(str(row.get("manifestPath") or "") for row in (plan.get("derivedManifestImageSets") or []) if row.get("state") != "ready")

    blockers = []
    for row in plan.get("baseImages") or []:
        if row.get("state") != "ready":
            blockers.append({"stage": "base-image", "subject": str(row.get("role") or ""), "blocker": str(row.get("blocker") or "UNSPECIFIED")})
    for row in plan.get("coreImages") or []:
        if row.get("state") != "ready":
            blockers.append({"stage": "external-image" if row.get("ownership") == "external" else "product-image", "subject": str(row.get("role") or ""), "blocker": str(row.get("blocker") or "UNSPECIFIED")})
    for row in plan.get("derivedManifestImageSets") or []:
        if row.get("state") != "ready":
            blockers.append({"stage": "manifest-resolution", "subject": str(row.get("manifestPath") or ""), "blocker": str(row.get("blocker") or "UNSPECIFIED")})
    blockers.sort(key=lambda row: (row["stage"], row["subject"], row["blocker"]))

    authoritative_ready = status == "ready" and not missing and not partial and MANAGEMENT_WORKLOAD_SOURCE_AUTHORITY in resolved
    return {
        "authority": DIAGNOSTIC_AUTHORITY,
        "releaseVersion": version,
        "status": "READY" if authoritative_ready else "BLOCKED",
        "acquisitionLockStatus": status,
        "missingAuthorities": missing,
        "partialAuthorities": partial,
        "resolvedAuthorities": resolved,
        "managementWorkloadArchiveResolved": MANAGEMENT_WORKLOAD_SOURCE_AUTHORITY in resolved,
        "canStartExternalAcquisition": bool(external_rows) and all(all(row[key] for key in ("repository", "tag", "version", "selectionChannel", "selectionEvidenceURL")) for row in external_rows),
        "pending": {
            "externalImages": pending_external,
            "baseImages": pending_base,
            "productImages": pending_product,
            "manifestResolutions": pending_manifests,
        },
        "blockers": blockers,
        "nextAction": "seal-and-verify-management-workload-oci-archive" if not authoritative_ready else "bundle-source-authority-ready",
    }


def platformctl(path: str) -> Path:
    p = Path(path).resolve()
    regular_file(p, "PLATFORMCTL")
    if not os.access(p, os.X_OK):
        raise RuntimeError(f"PLATFORMCTL_NOT_EXECUTABLE {p}")
    return p


def run_json(cmd: list[str], timeout: int = 1800) -> dict:
    proc = subprocess.run(cmd, cwd=ROOT, stdin=subprocess.DEVNULL, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if proc.returncode:
        raise RuntimeError(f"COMMAND_FAILED rc={proc.returncode} cmd={cmd!r}\n{proc.stdout[-8000:]}")
    try:
        value = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"COMMAND_JSON_INVALID {cmd!r}: {proc.stdout[-2000:]!r}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("COMMAND_JSON_OBJECT_REQUIRED")
    return value


def atomic_json(path: Path, value: dict) -> None:
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw); fh.flush(); os.fsync(fh.fileno())
        os.chmod(tmp, 0o644); os.replace(tmp, path)
        # Directory fsync is a POSIX durability boundary. Windows cannot open a
        # directory with os.open() for fsync, and ReplaceFile/MoveFileEx semantics
        # are already handled by os.replace(). Never turn that platform difference
        # into a false acquisition failure on the canonical Windows control host.
        if os.name != "nt":
            dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try: os.fsync(dfd)
            finally: os.close(dfd)
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise


def verified_exact_reference(doc: dict) -> str:
    if doc.get("verified") is not True:
        return ""
    direct = str(doc.get("exactReference") or "")
    if direct:
        return direct
    nested = doc.get("result") or {}
    return str(nested.get("exactReference") or "")


def stage_entry(role_row: dict, role_dir: Path, verified: dict) -> dict:
    layout = role_dir / "layout"
    lock = regular_file(role_dir / "acquisition-lock.json", "MANAGEMENT_STAGE_LOCK")
    lock_doc = json.loads(lock.read_text())
    if lock_doc.get("authority") != "MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_V2":
        raise RuntimeError(f"MANAGEMENT_STAGE_LOCK_AUTHORITY_INVALID {role_row['role']}")
    for key, expected in (("role", role_row["role"]), ("sourceRepository", role_row["repository"]), ("selectedVersion", role_row["version"]), ("sourceTag", role_row["tag"]), ("selectionChannel", role_row["selectionChannel"])):
        if lock_doc.get(key) != expected:
            raise RuntimeError(f"MANAGEMENT_STAGE_LOCK_PLAN_DRIFT {role_row['role']}:{key}")
    exact = str(lock_doc.get("exactReference") or "")
    manifest_digest = str(lock_doc.get("manifestDigest") or "")
    if not DIGEST_RE.fullmatch(manifest_digest) or exact != role_row["repository"] + "@" + manifest_digest:
        raise RuntimeError(f"MANAGEMENT_STAGE_EXACT_REFERENCE_INVALID {role_row['role']}")
    if verified_exact_reference(verified) != exact:
        raise RuntimeError(f"MANAGEMENT_STAGE_OWNER_VERIFY_INVALID {role_row['role']}")
    td, files, total = tree_digest(layout)
    return {
        **role_row,
        "layoutPath": f"{role_row['role']}/layout",
        "lockPath": f"{role_row['role']}/acquisition-lock.json",
        "lockDigest": sha256_file(lock),
        "layoutTreeDigest": td,
        "layoutFileCount": files,
        "layoutBytes": total,
        "exactReference": exact,
        "manifestDigest": manifest_digest,
    }


def manifest(entries: list[dict], release: Path) -> dict:
    return {
        "apiVersion": "platform.4so.io/v1alpha1",
        "kind": "StagedManagementWorkloadBatch",
        "metadata": {"name": "management-external-images"},
        "spec": {
            "authority": AUTHORITY,
            "canonicalAuthority": "lab/management-workload-image-build-plan.json+exact-release-artifact",
            "releaseFileSha256": sha256_file(release),
            "networkFetchRequiredForOfflineVerify": False,
            "entries": sorted(entries, key=lambda r: r["role"]),
        },
    }


def validate_manifest(stage: Path, doc: dict, release: Path, rows: list[dict]) -> list[dict]:
    if doc.get("apiVersion") != "platform.4so.io/v1alpha1" or doc.get("kind") != "StagedManagementWorkloadBatch":
        raise RuntimeError("MANAGEMENT_STAGE_TYPE_INVALID")
    spec = doc.get("spec") or {}
    if spec.get("authority") != AUTHORITY or spec.get("canonicalAuthority") != "lab/management-workload-image-build-plan.json+exact-release-artifact" or spec.get("networkFetchRequiredForOfflineVerify") is not False:
        raise RuntimeError("MANAGEMENT_STAGE_AUTHORITY_INVALID")
    if spec.get("releaseFileSha256") != sha256_file(release):
        raise RuntimeError("MANAGEMENT_STAGE_RELEASE_DRIFT")
    entries = spec.get("entries") or []
    by_role = {str(r.get("role") or ""): r for r in entries if isinstance(r, dict)}
    expected = {r["role"]: r for r in rows}
    if set(by_role) != set(expected) or len(by_role) != len(entries):
        raise RuntimeError("MANAGEMENT_STAGE_COVERAGE_INVALID")
    for role, row in expected.items():
        entry = by_role[role]
        for key in ("repository", "tag", "version", "selectionChannel", "selectionEvidenceURL"):
            if entry.get(key) != row[key]:
                raise RuntimeError(f"MANAGEMENT_STAGE_PLAN_DRIFT {role}:{key}")
        if entry.get("layoutPath") != f"{role}/layout" or entry.get("lockPath") != f"{role}/acquisition-lock.json":
            raise RuntimeError(f"MANAGEMENT_STAGE_PATH_INVALID {role}")
        for key in ("lockDigest", "layoutTreeDigest", "manifestDigest"):
            if not DIGEST_RE.fullmatch(str(entry.get(key) or "")):
                raise RuntimeError(f"MANAGEMENT_STAGE_DIGEST_INVALID {role}:{key}")
        if entry.get("exactReference") != row["repository"] + "@" + entry["manifestDigest"]:
            raise RuntimeError(f"MANAGEMENT_STAGE_EXACT_REFERENCE_INVALID {role}")
        lock = regular_file(stage / entry["lockPath"], "MANAGEMENT_STAGE_LOCK")
        if sha256_file(lock) != entry["lockDigest"]:
            raise RuntimeError(f"MANAGEMENT_STAGE_LOCK_DIGEST_MISMATCH {role}")
        td, count, total = tree_digest(stage / entry["layoutPath"])
        if td != entry["layoutTreeDigest"] or count != entry["layoutFileCount"] or total != entry["layoutBytes"]:
            raise RuntimeError(f"MANAGEMENT_STAGE_LAYOUT_DIGEST_MISMATCH {role}")
    return [by_role[role] for role in sorted(by_role)]


def prepare_role_stage_dir(role_dir: Path) -> None:
    if role_dir.exists():
        st = role_dir.lstat()
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise RuntimeError(f"MANAGEMENT_STAGE_ROLE_ALREADY_EXISTS {role_dir.name}")
        names = {child.name for child in role_dir.iterdir()}
        if names == {".layout.partial"}:
            partial = role_dir / ".layout.partial"
            pst = partial.lstat()
            if stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
                raise RuntimeError(f"MANAGEMENT_STAGE_ROLE_ALREADY_EXISTS {role_dir.name}")
            return
        if names:
            raise RuntimeError(f"MANAGEMENT_STAGE_ROLE_ALREADY_EXISTS {role_dir.name}")
        role_dir.rmdir()
    role_dir.mkdir(mode=0o755)


def acquire(stage: Path, release: Path, ctl: Path) -> None:
    regular_dir(stage, "MANAGEMENT_STAGE", create=True)
    _, rows = load_plan(ROOT)
    plan_path = ROOT / "lab" / "management-workload-image-build-plan.json"

    def verify_role(row: dict, role_dir: Path) -> dict:
        layout, lock = role_dir / "layout", role_dir / "acquisition-lock.json"
        verified = run_json([str(ctl), "workload-oci", "verify-external", "--release", str(release), "--plan", str(plan_path), "--role", row["role"], "--layout", str(layout), "--lock", str(lock)])
        return stage_entry(row, role_dir, verified)

    def acquire_role(row: dict) -> dict:
        role_dir = stage / row["role"]
        prepare_role_stage_dir(role_dir)
        layout, lock = role_dir / "layout", role_dir / "acquisition-lock.json"
        run_json([str(ctl), "workload-oci", "acquire-external", "--release", str(release), "--plan", str(plan_path), "--role", row["role"], "--out-layout", str(layout), "--out-lock", str(lock)])
        return verify_role(row, role_dir)

    entries = []
    pending = []
    for row in rows:
        role_dir = stage / row["role"]
        if role_dir.exists():
            st = role_dir.lstat()
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise RuntimeError(f"MANAGEMENT_STAGE_ROLE_ALREADY_EXISTS {row['role']}")
            names = {child.name for child in role_dir.iterdir()}
            if names == {"layout", "acquisition-lock.json"}:
                entries.append(verify_role(row, role_dir))
                continue
            if names == {".layout.partial"}:
                pending.append(row)
                continue
            if names:
                raise RuntimeError(f"MANAGEMENT_STAGE_ROLE_ALREADY_EXISTS {row['role']}")
        pending.append(row)

    if pending:
        with ThreadPoolExecutor(max_workers=min(4, len(pending))) as pool:
            futures = {pool.submit(acquire_role, row): row["role"] for row in pending}
            for future in as_completed(futures):
                entries.append(future.result())

    atomic_json(stage / MANIFEST, manifest(entries, release))


def verify(stage: Path, release: Path, ctl: Path) -> list[dict]:
    regular_dir(stage, "MANAGEMENT_STAGE")
    _, rows = load_plan(ROOT)
    doc = json.loads(regular_file(stage / MANIFEST, "MANAGEMENT_STAGE_MANIFEST").read_text())
    entries = validate_manifest(stage, doc, release, rows)
    for entry in entries:
        result = run_json([str(ctl), "workload-oci", "verify-external", "--release", str(release), "--plan", str(ROOT / "lab" / "management-workload-image-build-plan.json"), "--role", entry["role"], "--layout", str(stage / entry["layoutPath"]), "--lock", str(stage / entry["lockPath"])])
        if verified_exact_reference(result) != entry["exactReference"]:
            raise RuntimeError(f"MANAGEMENT_STAGE_OFFLINE_OWNER_VERIFY_INVALID {entry['role']}")
    return entries


def assemble(stage: Path, release: Path, ctl: Path, out: Path) -> None:
    entries = verify(stage, release, ctl)
    cmd = [str(ctl), "workload-oci", "assemble"]
    for entry in entries:
        cmd += ["--source", entry["exactReference"] + "=" + str(stage / entry["layoutPath"])]
    cmd += ["--out", str(out)]
    result = run_json(cmd)
    print(json.dumps(result, sort_keys=True))


def main() -> int:
    ap = argparse.ArgumentParser()
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--diagnose", action="store_true")
    group.add_argument("--stage-out")
    group.add_argument("--verify-staged")
    group.add_argument("--assemble-staged")
    ap.add_argument("--release")
    ap.add_argument("--platformctl")
    ap.add_argument("--out")
    args = ap.parse_args()
    try:
        if args.diagnose:
            print(json.dumps(diagnose(ROOT), sort_keys=True))
            return 0
        if not args.release or not args.platformctl:
            raise RuntimeError("--release and --platformctl are required for staging, verification and assembly")
        release = Path(args.release).resolve(); regular_file(release, "EXACT_RELEASE")
        ctl = platformctl(args.platformctl)
        if args.stage_out:
            stage = Path(args.stage_out).resolve(); acquire(stage, release, ctl)
            print(f"MANAGEMENT_WORKLOAD_BATCH_STAGE_PASS roles=4 stage={stage}")
        elif args.verify_staged:
            rows = verify(Path(args.verify_staged).resolve(), release, ctl)
            print(f"MANAGEMENT_WORKLOAD_BATCH_VERIFY_PASS roles={len(rows)}")
        else:
            if not args.out: raise RuntimeError("--assemble-staged requires --out")
            assemble(Path(args.assemble_staged).resolve(), release, ctl, Path(args.out).resolve())
        return 0
    except Exception as exc:
        print(f"MANAGEMENT_WORKLOAD_BATCH_FAIL {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
