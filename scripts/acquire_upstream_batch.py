#!/usr/bin/env python3
"""Checkpoint-safe S1 batch runner for admitted upstream Helm components.

Canonical authority remains catalog/upstream-admission.json plus component source state.
This runner supports two execution shapes:

1. connected acquire+install in the source tree (legacy --execute), and
2. connected stage -> controlled transfer -> offline verify/install.

The staged manifest is derived evidence only. It never becomes a second source of truth:
every offline install is re-bound to the current component contract and, while unresolved,
the canonical admission row. catalog-bundle install remains the only mutation path.
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

from catalog_upstream_admission import DEFAULT_AUTHORITY, ROOT, normalized, validate

STAGE_AUTHORITY = "UPSTREAM_STAGED_BATCH_V1"
STAGE_MANIFEST = "stage-manifest.json"
EXACT_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SAFE_BUNDLE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}-[0-9]+\.[0-9]+\.[0-9]+\.zip$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def queue(root: Path = ROOT) -> tuple[list[str], list[tuple[str, str]]]:
    _, rows = validate(root, root / "catalog" / "upstream-admission.json")
    ready = sorted(str(r["component"]) for r in rows if r.get("status") == "ready-for-acquisition")
    review = sorted((str(r["component"]), str(r.get("status") or "")) for r in rows if r.get("status") != "ready-for-acquisition")
    return ready, review


def admission_map(root: Path = ROOT) -> dict[str, dict]:
    _, rows = validate(root, root / "catalog" / "upstream-admission.json")
    return {str(row["component"]): row for row in rows}


def acquisition_cmd(component: str, *, platformctl: str | None = None, install: bool = True, out: Path | None = None) -> list[str]:
    cmd = [
        sys.executable,
        "scripts/acquire_upstream_helm.py",
        "--from-admission",
        "--component",
        component,
    ]
    if install:
        cmd.append("--install")
    if out is not None:
        cmd += ["--out", str(out)]
    if platformctl:
        cmd += ["--platformctl", platformctl]
    return cmd


def _absolute_no_follow(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def platformctl_prefix(path: str | None) -> list[str]:
    if path:
        resolved = _absolute_no_follow(Path(path))
        if resolved.is_symlink() or not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise RuntimeError(f"PLATFORMCTL_NOT_EXECUTABLE {resolved}")
        return [str(resolved)]
    built = ROOT / "bin" / "platformctl"
    if built.is_file() and not built.is_symlink() and os.access(built, os.X_OK):
        return [str(built)]
    return ["go", "run", "./cmd/platformctl"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _regular_directory(path: Path, label: str, *, create: bool = False) -> Path:
    if create:
        path.mkdir(parents=True, exist_ok=True)
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f"{label}_NOT_REAL_DIRECTORY {path}")
    return path


def _regular_file(path: Path, label: str) -> Path:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise RuntimeError(f"{label}_NOT_REAL_FILE {path}")
    return path


def _atomic_json(path: Path, payload: dict) -> None:
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    fd, temp_name = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, path)
        if os.name != "nt":
            dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _run_json(cmd: list[str], *, cwd: Path = ROOT, timeout: int = 240) -> dict:
    proc = subprocess.run(cmd, cwd=cwd, text=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if proc.returncode:
        raise RuntimeError(f"COMMAND_FAILED rc={proc.returncode} cmd={cmd!r}\n{proc.stdout[-8000:]}")
    text = proc.stdout.strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"COMMAND_JSON_INVALID cmd={cmd!r} output={text[-2000:]!r}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"COMMAND_JSON_OBJECT_REQUIRED cmd={cmd!r}")
    return value


def _stage_entry(row: dict, bundle_path: Path, verified: dict) -> dict:
    component = str(row.get("component") or "")
    version = normalized(str(row.get("selectedVersion") or ""))
    source = str(row.get("source") or "")
    upstream_version = str(row.get("upstreamVersion") or row.get("selectedVersion") or "")
    filename = bundle_path.name
    if row.get("status") != "ready-for-acquisition":
        raise RuntimeError(f"STAGED_BATCH_ROW_NOT_READY {component}:{row.get('status')}")
    if not EXACT_VERSION_RE.fullmatch(version):
        raise RuntimeError(f"STAGED_BATCH_VERSION_INVALID {component}:{version}")
    expected_name = f"{component}-{version}.zip"
    if filename != expected_name or not SAFE_BUNDLE_RE.fullmatch(filename):
        raise RuntimeError(f"STAGED_BATCH_FILENAME_INVALID {filename} expected={expected_name}")
    if verified.get("valid") is not True or verified.get("component") != component or normalized(str(verified.get("version") or "")) != version:
        raise RuntimeError(f"STAGED_BATCH_BUNDLE_IDENTITY_MISMATCH {component}")
    if str(verified.get("upstreamUrl") or "") != source:
        raise RuntimeError(f"STAGED_BATCH_SOURCE_MISMATCH {component}")
    bundle_digest = str(verified.get("bundleDigest") or "")
    file_digest = sha256_file(bundle_path)
    if not SHA256_RE.fullmatch(bundle_digest) or bundle_digest != file_digest:
        raise RuntimeError(f"STAGED_BATCH_BUNDLE_DIGEST_MISMATCH {component} verified={bundle_digest} file={file_digest}")
    upstream_artifact_digest = str(verified.get("upstreamArtifactDigest") or "")
    if not SHA256_RE.fullmatch(upstream_artifact_digest):
        raise RuntimeError(f"STAGED_BATCH_UPSTREAM_DIGEST_INVALID {component}")
    return {
        "component": component,
        "version": version,
        "source": source,
        "upstreamVersion": upstream_version,
        "bundleFile": filename,
        "bundleDigest": bundle_digest,
        "upstreamArtifactDigest": upstream_artifact_digest,
        "bundleKey": f"{component}/{version}",
    }


def stage_manifest(entries: list[dict]) -> dict:
    ordered = sorted(entries, key=lambda row: row["component"])
    return {
        "apiVersion": "platform.4so.io/v1alpha1",
        "kind": "StagedUpstreamCatalogBatch",
        "metadata": {"name": "s1-ready-upstream-bundles"},
        "spec": {
            "authority": STAGE_AUTHORITY,
            "canonicalAuthority": "catalog/upstream-admission.json+catalog/components/*/spec.source.resolved",
            "networkFetchRequiredForInstall": False,
            "entries": ordered,
        },
    }


def validate_stage_manifest(stage_dir: Path, manifest: dict, *, root: Path = ROOT) -> list[dict]:
    if manifest.get("apiVersion") != "platform.4so.io/v1alpha1" or manifest.get("kind") != "StagedUpstreamCatalogBatch":
        raise RuntimeError("STAGED_BATCH_TYPE_INVALID")
    spec = manifest.get("spec") or {}
    if spec.get("authority") != STAGE_AUTHORITY or spec.get("canonicalAuthority") != "catalog/upstream-admission.json+catalog/components/*/spec.source.resolved" or spec.get("networkFetchRequiredForInstall") is not False:
        raise RuntimeError("STAGED_BATCH_AUTHORITY_INVALID")
    entries = spec.get("entries")
    if not isinstance(entries, list) or not entries:
        raise RuntimeError("STAGED_BATCH_ENTRIES_INVALID")
    seen_components: set[str] = set()
    seen_files: set[str] = set()
    admission = admission_map(root)
    normalized_entries: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuntimeError("STAGED_BATCH_ENTRY_INVALID")
        required = {"component", "version", "source", "upstreamVersion", "bundleFile", "bundleDigest", "upstreamArtifactDigest", "bundleKey"}
        if set(entry) != required:
            raise RuntimeError(f"STAGED_BATCH_ENTRY_FIELDS_INVALID {sorted(entry)}")
        component = str(entry["component"])
        version = normalized(str(entry["version"]))
        bundle_file = str(entry["bundleFile"])
        if component in seen_components or bundle_file in seen_files:
            raise RuntimeError(f"STAGED_BATCH_DUPLICATE {component}:{bundle_file}")
        seen_components.add(component)
        seen_files.add(bundle_file)
        if not EXACT_VERSION_RE.fullmatch(version) or bundle_file != f"{component}-{version}.zip" or not SAFE_BUNDLE_RE.fullmatch(bundle_file):
            raise RuntimeError(f"STAGED_BATCH_ENTRY_IDENTITY_INVALID {component}:{version}:{bundle_file}")
        if entry["bundleKey"] != f"{component}/{version}" or not SHA256_RE.fullmatch(str(entry["bundleDigest"])) or not SHA256_RE.fullmatch(str(entry["upstreamArtifactDigest"])):
            raise RuntimeError(f"STAGED_BATCH_ENTRY_DIGEST_OR_KEY_INVALID {component}")
        component_path = root / "catalog" / "components" / f"{component}.json"
        _regular_file(component_path, "STAGED_BATCH_COMPONENT")
        component_doc = json.loads(component_path.read_text())
        current_release = normalized(str((component_doc.get("spec") or {}).get("release") or ""))
        source_state = (component_doc.get("spec") or {}).get("source") or {}
        if current_release != version:
            raise RuntimeError(f"STAGED_BATCH_COMPONENT_RELEASE_DRIFT {component}:{current_release}!={version}")
        if not source_state.get("resolved"):
            row = admission.get(component)
            if row is None or row.get("status") != "ready-for-acquisition":
                raise RuntimeError(f"STAGED_BATCH_ADMISSION_NOT_READY {component}")
            if normalized(str(row.get("selectedVersion") or "")) != version or str(row.get("source") or "") != entry["source"] or str(row.get("upstreamVersion") or row.get("selectedVersion") or "") != entry["upstreamVersion"]:
                raise RuntimeError(f"STAGED_BATCH_ADMISSION_DRIFT {component}")
        bundle_path = stage_dir / bundle_file
        _regular_file(bundle_path, "STAGED_BATCH_BUNDLE")
        if sha256_file(bundle_path) != entry["bundleDigest"]:
            raise RuntimeError(f"STAGED_BATCH_FILE_DIGEST_MISMATCH {component}")
        normalized_entries.append(entry)
    return sorted(normalized_entries, key=lambda row: row["component"])


def emit_plan(as_json: bool) -> int:
    ready, review = queue()
    payload = {
        "ready": ready,
        "review": [{"component": name, "status": status} for name, status in review],
        "readyCount": len(ready),
        "reviewCount": len(review),
        "checkpointAuthority": "catalog/upstream-admission.json+catalog/components/*/spec.source.resolved",
        "stagedOfflineHandoffAuthority": STAGE_AUTHORITY,
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            "UPSTREAM_BATCH_PLAN ready=%d review=%d readyComponents=%s reviewComponents=%s stagedAuthority=%s"
            % (len(ready), len(review), ",".join(ready), ",".join(f"{name}:{status}" for name, status in review), STAGE_AUTHORITY)
        )
    return 0


def execute(limit: int, platformctl: str | None) -> int:
    initial_ready, initial_review = queue()
    selected = initial_ready[:limit] if limit > 0 else initial_ready
    if not selected:
        if initial_review:
            print("UPSTREAM_BATCH_BLOCKED no-ready-components review=%s" % ",".join(f"{name}:{status}" for name, status in initial_review), file=sys.stderr)
            return 3
        print("UPSTREAM_BATCH_PASS acquired=0 remainingReady=0 review=0")
        return 0
    completed: list[str] = []
    for component in selected:
        proc = subprocess.run(acquisition_cmd(component, platformctl=platformctl), cwd=ROOT, text=True)
        if proc.returncode != 0:
            remaining_ready, review = queue()
            print(
                "UPSTREAM_BATCH_CHECKPOINT component=%s rc=%d completed=%s remainingReady=%s review=%s"
                % (component, proc.returncode, ",".join(completed), ",".join(remaining_ready), ",".join(f"{name}:{status}" for name, status in review)),
                file=sys.stderr,
            )
            return proc.returncode
        completed.append(component)
    remaining_ready, review = queue()
    status = "PASS" if not remaining_ready and not review else "CHECKPOINT_PASS"
    print("UPSTREAM_BATCH_%s acquired=%d completed=%s remainingReady=%d review=%d" % (status, len(completed), ",".join(completed), len(remaining_ready), len(review)))
    return 0


def stage(limit: int, stage_dir: Path, platformctl: str | None) -> int:
    stage_dir = _regular_directory(_absolute_no_follow(stage_dir), "STAGED_BATCH_DIRECTORY", create=True)
    manifest_path = stage_dir / STAGE_MANIFEST
    if manifest_path.exists():
        _regular_file(manifest_path, "STAGED_BATCH_MANIFEST")
        existing = json.loads(manifest_path.read_text())
        existing_entries = validate_stage_manifest(stage_dir, existing)
    else:
        existing_entries = []
    completed = {str(row["component"]): row for row in existing_entries}
    ready, review = queue()
    selected = [name for name in ready if name not in completed]
    if limit > 0:
        selected = selected[:limit]
    admission = admission_map()
    ctl = platformctl_prefix(platformctl)
    for component in selected:
        row = admission[component]
        version = normalized(str(row["selectedVersion"]))
        out = stage_dir / f"{component}-{version}.zip"
        if out.exists() or out.is_symlink():
            _regular_file(out, "STAGED_BATCH_ORPHAN_BUNDLE")
            verified = _run_json(ctl + ["catalog-bundle", "verify", "-f", str(out)])
        else:
            proc = subprocess.run(acquisition_cmd(component, platformctl=platformctl, install=False, out=out), cwd=ROOT, text=True)
            if proc.returncode != 0:
                print("UPSTREAM_BATCH_STAGE_CHECKPOINT component=%s rc=%d completed=%s" % (component, proc.returncode, ",".join(sorted(completed))), file=sys.stderr)
                return proc.returncode
            verified = _run_json(ctl + ["catalog-bundle", "verify", "-f", str(out)])
        completed[component] = _stage_entry(row, out, verified)
        _atomic_json(manifest_path, stage_manifest(list(completed.values())))
    if not completed:
        if review:
            print("UPSTREAM_BATCH_STAGE_BLOCKED no-ready-components review=%s" % ",".join(f"{name}:{status}" for name, status in review), file=sys.stderr)
            return 3
        print("UPSTREAM_BATCH_STAGE_PASS staged=0")
        return 0
    validate_stage_manifest(stage_dir, json.loads(manifest_path.read_text()))
    remaining = [name for name in ready if name not in completed]
    status = "PASS" if not remaining else "CHECKPOINT_PASS"
    print("UPSTREAM_BATCH_STAGE_%s staged=%d remainingReady=%d review=%d manifest=%s" % (status, len(completed), len(remaining), len(review), manifest_path))
    return 0


def refresh_derived_handoff() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/supply_chain_handoff.py", "--write", "--plan", "lab/supply-chain-handoff-plan.json"],
        cwd=ROOT, text=True,
    )
    if proc.returncode:
        raise RuntimeError(f"SUPPLY_CHAIN_HANDOFF_REFRESH_FAILED rc={proc.returncode}")


def install_staged(stage_dir: Path, platformctl: str | None) -> int:
    stage_dir = _regular_directory(_absolute_no_follow(stage_dir), "STAGED_BATCH_DIRECTORY")
    manifest_path = _regular_file(stage_dir / STAGE_MANIFEST, "STAGED_BATCH_MANIFEST")
    entries = validate_stage_manifest(stage_dir, json.loads(manifest_path.read_text()))
    ctl = platformctl_prefix(platformctl)
    completed: list[str] = []
    for entry in entries:
        component = str(entry["component"])
        bundle = stage_dir / str(entry["bundleFile"])
        verified = _run_json(ctl + ["catalog-bundle", "verify", "-f", str(bundle)])
        if verified.get("component") != component or normalized(str(verified.get("version") or "")) != entry["version"] or verified.get("bundleDigest") != entry["bundleDigest"] or verified.get("upstreamArtifactDigest") != entry["upstreamArtifactDigest"] or verified.get("upstreamUrl") != entry["source"]:
            raise RuntimeError(f"STAGED_BATCH_VERIFY_DRIFT {component}")
        _run_json(ctl + ["catalog-bundle", "install", "-f", str(bundle), "--repo-root", str(ROOT), "--confirmation", "IMPORT"])
        completed.append(component)
        # Repository validation after each authoritative mutation makes resume
        # semantics explicit. Refresh only the derived handoff first so successful
        # source acquisition is not rejected by a stale transport snapshot.
        refresh_derived_handoff()
        proc = subprocess.run([sys.executable, "scripts/validate_repository.py", "."], cwd=ROOT, text=True)
        if proc.returncode != 0:
            print("UPSTREAM_BATCH_INSTALL_CHECKPOINT component=%s validationRc=%d completed=%s" % (component, proc.returncode, ",".join(completed)), file=sys.stderr)
            return proc.returncode
    remaining_ready, review = queue()
    status = "PASS" if not remaining_ready and not review else "CHECKPOINT_PASS"
    print("UPSTREAM_BATCH_INSTALL_%s installed=%d completed=%s remainingReady=%d review=%d" % (status, len(completed), ",".join(completed), len(remaining_ready), len(review)))
    return 0


def self_test() -> int:
    ready, review = queue()
    assert ready == sorted(ready)
    assert all(name for name in ready)
    assert all(name and status != "ready-for-acquisition" for name, status in review)
    assert not set(ready) & {name for name, _ in review}
    if ready:
        cmd = acquisition_cmd(ready[0])
        assert "--from-admission" in cmd and "--install" in cmd and ready[0] in cmd
        stage_cmd = acquisition_cmd(ready[0], install=False, out=Path("/tmp/example.zip"))
        assert "--install" not in stage_cmd and "--out" in stage_cmd
    fixture_entry = {
        "component": "alloy",
        "version": "1.11.0",
        "source": "https://grafana.github.io/helm-charts",
        "upstreamVersion": "1.11.0",
        "bundleFile": "alloy-1.11.0.zip",
        "bundleDigest": "sha256:" + "a" * 64,
        "upstreamArtifactDigest": "sha256:" + "b" * 64,
        "bundleKey": "alloy/1.11.0",
    }
    manifest = stage_manifest([fixture_entry])
    assert manifest["spec"]["authority"] == STAGE_AUTHORITY
    assert manifest["spec"]["networkFetchRequiredForInstall"] is False
    assert manifest["spec"]["entries"][0]["bundleFile"] == "alloy-1.11.0.zip"
    print("UPSTREAM_BATCH_SELF_TEST_PASS ready=%d review=%d staged-offline-handoff=pass" % (len(ready), len(review)))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Checkpoint-safe S1 admitted Helm acquisition/staging runner")
    parser.add_argument("--plan", action="store_true", help="print the canonical ready/review queue without network/tool use")
    parser.add_argument("--json", action="store_true", help="with --plan, emit machine-readable JSON")
    parser.add_argument("--execute", action="store_true", help="connected acquire+install canonical ready rows sequentially")
    parser.add_argument("--stage-out", type=Path, help="connected acquisition into verified offline bundles plus derived stage manifest")
    parser.add_argument("--install-staged", type=Path, help="network-free verify/install of a staged bundle directory")
    parser.add_argument("--limit", type=int, default=0, help="maximum new ready components for --execute/--stage-out; 0 means all")
    parser.add_argument("--platformctl", help="optional exact platformctl path")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.limit < 0:
        parser.error("--limit must be >= 0")
    modes = sum(bool(x) for x in (args.plan, args.execute, args.stage_out, args.install_staged, args.self_test))
    if modes != 1:
        parser.error("choose exactly one of --plan, --execute, --stage-out, --install-staged, --self-test")
    if args.json and not args.plan:
        parser.error("--json is only valid with --plan")
    try:
        if args.self_test:
            return self_test()
        if args.plan:
            return emit_plan(args.json)
        if args.execute:
            return execute(args.limit, args.platformctl)
        if args.stage_out:
            return stage(args.limit, args.stage_out, args.platformctl)
        return install_staged(args.install_staged, args.platformctl)
    except (RuntimeError, OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(f"UPSTREAM_BATCH_BLOCKED {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
