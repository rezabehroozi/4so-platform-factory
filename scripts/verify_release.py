#!/usr/bin/env python3
"""Verify release integrity, independence and extracted-source behavior."""
from __future__ import annotations

from pathlib import Path
import argparse
import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

RELEASE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
MANIFEST_KEYS = {"schemaVersion", "product", "version", "releaseName", "fileCount", "files"}
MANIFEST_FILE_KEYS = {"path", "sha256", "size", "mode"}

FORBIDDEN = (
    bytes((107, 117, 98, 97, 114, 97)),
    bytes((104, 111, 115, 116, 105, 114, 97, 110)),
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()





def snapshot_archive(source: Path, target: Path) -> str:
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or source.is_symlink() or info.st_size <= 0:
        raise SystemExit("ARCHIVE_SOURCE_INVALID")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(source, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size <= 0 or (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
            raise SystemExit("ARCHIVE_SOURCE_CHANGED_WHILE_OPENING")
        h = hashlib.sha256()
        written = 0
        with os.fdopen(os.dup(fd), "rb", closefd=True) as src, target.open("wb") as out:
            os.chmod(target, 0o600)
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                h.update(chunk)
                written += len(chunk)
            out.flush()
            os.fsync(out.fileno())
        if written != opened.st_size:
            raise SystemExit("ARCHIVE_SOURCE_CHANGED_SIZE_WHILE_SNAPSHOTTING")
        return h.hexdigest()
    finally:
        os.close(fd)



def strict_json_loads(raw: str | bytes, *, label: str) -> object:
    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=no_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise SystemExit(f"{label}_JSON_INVALID {exc}") from exc


def canonical_archive_path(raw: str) -> str:
    if (
        not isinstance(raw, str)
        or not raw
        or raw.strip() != raw
        or "\\" in raw
        or "\x00" in raw
        or raw.startswith("/")
        or raw.endswith("/")
        or posixpath.normpath(raw) != raw
        or any(part in {"", ".", ".."} for part in raw.split("/"))
    ):
        raise SystemExit(f"ARCHIVE_PATH_NON_CANONICAL {raw!r}")
    return raw


def validate_manifest_identity(root: Path, manifest: object) -> tuple[str, str, list[dict[str, object]]]:
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_KEYS:
        raise SystemExit("MANIFEST_SCHEMA_INVALID")
    version_path = root / "VERSION"
    release_name_path = root / "RELEASE-NAME"
    if not version_path.is_file() or not release_name_path.is_file():
        raise SystemExit("RELEASE_IDENTITY_FILE_MISSING")
    version_raw = version_path.read_bytes()
    release_name_raw = release_name_path.read_bytes()
    version = version_raw.decode("utf-8", errors="strict").strip()
    release_name = release_name_raw.decode("utf-8", errors="strict").strip()
    if version_raw != (version + "\n").encode("utf-8") or release_name_raw != (release_name + "\n").encode("utf-8"):
        raise SystemExit("RELEASE_IDENTITY_FILE_NON_CANONICAL")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit("RELEASE_VERSION_INVALID")
    if not RELEASE_NAME_RE.fullmatch(release_name):
        raise SystemExit("RELEASE_NAME_INVALID")
    if manifest.get("schemaVersion") != 2 or manifest.get("product") != "4SO Platform Factory":
        raise SystemExit("MANIFEST_IDENTITY_INVALID")
    if manifest.get("version") != version or manifest.get("releaseName") != release_name:
        raise SystemExit("MANIFEST_RELEASE_IDENTITY_MISMATCH")
    expected_root = f"4so-platform-factory-{version}-{release_name}"
    if root.name != expected_root:
        raise SystemExit(f"ARCHIVE_ROOT_IDENTITY_MISMATCH expected={expected_root} actual={root.name}")
    rows = manifest.get("files")
    file_count = manifest.get("fileCount")
    if not isinstance(file_count, int) or isinstance(file_count, bool) or file_count < 0 or not isinstance(rows, list) or file_count != len(rows):
        raise SystemExit("MANIFEST_FILE_COUNT_INVALID")
    validated: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != MANIFEST_FILE_KEYS:
            raise SystemExit("MANIFEST_FILE_SCHEMA_INVALID")
        path = canonical_archive_path(row.get("path"))
        if path == "ARTIFACT-MANIFEST.json":
            raise SystemExit("MANIFEST_SELF_REFERENCE_INVALID")
        sha256 = row.get("sha256")
        mode = row.get("mode")
        size = row.get("size")
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise SystemExit(f"MANIFEST_SHA256_INVALID {path}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise SystemExit(f"MANIFEST_SIZE_INVALID {path}")
        if not isinstance(mode, str) or not re.fullmatch(r"0o[0-7]{3}", mode):
            raise SystemExit(f"MANIFEST_MODE_INVALID {path}")
        validated.append(row)
    return version, release_name, validated


def elf_metadata(path: Path) -> tuple[str, list[str]]:
    notes = subprocess.run(["readelf", "-n", str(path)], capture_output=True, text=True, check=False)
    dynamic = subprocess.run(["readelf", "-d", str(path)], capture_output=True, text=True, check=False)
    if notes.returncode != 0 or dynamic.returncode != 0:
        raise SystemExit(f"ELF_METADATA_FAILED {path}")
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", notes.stdout)
    build_id = match.group(1).lower() if match else ""
    needed = sorted(set(re.findall(r"Shared library: \[(.*?)\]", dynamic.stdout)))
    return build_id, needed


def validate_generated_metadata(root: Path, version: str, release_name: str) -> None:
    provenance_path = root / "BUILD-PROVENANCE.json"
    sbom_path = root / "SBOM.spdx.json"
    if not provenance_path.is_file():
        raise SystemExit("BUILD_PROVENANCE_MISSING")
    if not sbom_path.is_file():
        raise SystemExit("SBOM_MISSING")
    provenance = strict_json_loads(provenance_path.read_text(encoding="utf-8"), label="PROVENANCE")
    if (
        provenance.get("schemaVersion") != 1
        or provenance.get("product") != "4SO Platform Factory"
        or provenance.get("version") != version
        or provenance.get("releaseName") != release_name
        or provenance.get("module") != "platform.4so.io/factory"
    ):
        raise SystemExit("PROVENANCE_IDENTITY_INVALID")
    binaries = provenance.get("binaries", [])
    if len(binaries) != 5:
        raise SystemExit("PROVENANCE_BINARY_MATRIX_INVALID")
    runtime_needed = set()
    for row in binaries:
        file = root / "bin" / row["target"] / row["name"]
        if not file.is_file() or sha(file) != row["sha256"]:
            raise SystemExit(f"PROVENANCE_BINARY_INVALID {file}")
        build_id, needed = elf_metadata(file)
        if row.get("gnuBuildID", "") != build_id or sorted(row.get("runtimeNeeded", [])) != needed:
            raise SystemExit(f"PROVENANCE_ELF_METADATA_INVALID {file}")
        runtime_needed.update(needed)
    sbom = strict_json_loads(sbom_path.read_text(encoding="utf-8"), label="SBOM")
    if sbom.get("spdxVersion") != "SPDX-2.3":
        raise SystemExit("SBOM_FORMAT_INVALID")
    if sbom.get("name") != f"4so-platform-factory-{version}-{release_name}":
        raise SystemExit("SBOM_RELEASE_IDENTITY_INVALID")
    packages = sbom.get("packages", [])
    package_names = {row.get("name") for row in packages if isinstance(row, dict)}
    product_packages = [row for row in packages if isinstance(row, dict) and row.get("name") == "4SO Platform Factory"]
    if len(product_packages) != 1 or product_packages[0].get("versionInfo") != version:
        raise SystemExit("SBOM_PRODUCT_IDENTITY_INVALID")
    if "4SO Platform Factory" not in package_names or not runtime_needed.issubset(package_names):
        raise SystemExit("SBOM_RUNTIME_DEPENDENCY_INVENTORY_INCOMPLETE")
    if len(packages) < 1 + len(runtime_needed):
        raise SystemExit("SBOM_PACKAGE_MATRIX_INVALID")
    print("PROVENANCE_AND_SBOM_GATE_PASS", len(binaries), len(packages), len(sbom.get("files", [])))


def validate_brand_independence(root: Path) -> None:
    for file in sorted(path for path in root.rglob("*") if path.is_file()):
        data = file.read_bytes().lower()
        for term in FORBIDDEN:
            if term in data:
                raise SystemExit(f"FORBIDDEN_BRAND_LITERAL {file.relative_to(root)}")
    print("FULL_ARTIFACT_BRAND_INDEPENDENCE_GATE_PASS")


def extract_archive_preserving_modes(archive: Path, dest: Path) -> None:
    """Extract a release ZIP while enforcing safe paths and Unix file modes."""
    with zipfile.ZipFile(archive) as zip_file:
        seen_members: set[str] = set()
        for info in zip_file.infolist():
            if info.is_dir():
                raise SystemExit(f"ARCHIVE_DIRECTORY_ENTRY_NON_CANONICAL {info.filename}")
            normalized = canonical_archive_path(info.filename)
            if normalized in seen_members:
                raise SystemExit(f"ARCHIVE_DUPLICATE_PATH {info.filename}")
            seen_members.add(normalized)
            member = Path(*normalized.split("/"))
            target = dest / member
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(unix_mode)
            if info.create_system != 3 or file_type not in (0, stat.S_IFREG):
                raise SystemExit(f"ARCHIVE_FILE_MODE_INVALID {info.filename}")
            permission = stat.S_IMODE(unix_mode)
            if permission == 0:
                raise SystemExit(f"ARCHIVE_PERMISSION_MISSING {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zip_file.open(info, "r") as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
            os.chmod(target, permission)


def validate_archive_executable_modes(archive: Path) -> None:
    required = {
        "platform-api",
        "platform-installer",
        "platform-agent",
        "platform-probe",
        "platformctl",
    }
    seen = set()
    with zipfile.ZipFile(archive) as zip_file:
        for info in zip_file.infolist():
            if info.is_dir():
                raise SystemExit(f"ARCHIVE_DIRECTORY_ENTRY_NON_CANONICAL {info.filename}")
            name = canonical_archive_path(info.filename)
            parts = tuple(name.split("/"))
            if len(parts) >= 4 and parts[-3:-1] == ("bin", "linux-amd64") and parts[-1] in required:
                mode = (info.external_attr >> 16) & 0xFFFF
                if info.create_system != 3 or stat.S_IFMT(mode) != stat.S_IFREG:
                    raise SystemExit(f"ARCHIVE_BINARY_TYPE_INVALID {info.filename}")
                if stat.S_IMODE(mode) & 0o111 == 0:
                    raise SystemExit(f"ARCHIVE_BINARY_NOT_EXECUTABLE {info.filename}")
                seen.add(parts[-1])
    missing = sorted(required - seen)
    if missing:
        raise SystemExit(f"ARCHIVE_BINARY_MODE_ENTRY_MISSING {missing}")
    print("ARCHIVE_EXECUTABLE_MODE_GATE_PASS", len(seen))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()
    archive = Path(os.path.abspath(os.path.expanduser(args.archive)))
    if not archive.is_file():
        raise SystemExit("ARCHIVE_NOT_FOUND")

    with tempfile.TemporaryDirectory() as directory:
        workspace = Path(directory)
        snapshot = workspace / "release-snapshot.zip"
        archive_digest = snapshot_archive(archive, snapshot)
        dest = workspace / "extracted"
        dest.mkdir()
        validate_archive_executable_modes(snapshot)
        extract_archive_preserving_modes(snapshot, dest)
        top_level = list(dest.iterdir())
        if len(top_level) != 1 or not top_level[0].is_dir():
            raise SystemExit("ARCHIVE_ROOT_INVALID")
        root = top_level[0]
        manifest_path = root / "ARTIFACT-MANIFEST.json"
        if not manifest_path.is_file():
            raise SystemExit("MANIFEST_MISSING")
        manifest = strict_json_loads(manifest_path.read_text(encoding="utf-8"), label="MANIFEST")
        version, release_name, rows = validate_manifest_identity(root, manifest)
        indexed = {str(row["path"]): row for row in rows}
        if len(indexed) != len(rows):
            raise SystemExit("MANIFEST_DUPLICATE_PATH")
        actual = {
            path.relative_to(root).as_posix(): path
            for path in root.rglob("*")
            if path.is_file() and path.name != "ARTIFACT-MANIFEST.json"
        }
        if set(indexed) != set(actual):
            print(
                "MANIFEST_PATH_MISMATCH",
                "missing",
                sorted(set(actual) - set(indexed)),
                "stale",
                sorted(set(indexed) - set(actual)),
            )
            return 1
        for path, file in actual.items():
            row = indexed[path]
            if sha(file) != row["sha256"] or file.stat().st_size != row["size"]:
                print("MANIFEST_HASH_MISMATCH", path)
                return 1
            expected_mode = int(str(row.get("mode", "0")), 8)
            actual_mode = stat.S_IMODE(file.stat().st_mode)
            if expected_mode != actual_mode:
                print("MANIFEST_MODE_MISMATCH", path, oct(expected_mode), oct(actual_mode))
                return 1
        if manifest.get("fileCount") != len(actual):
            raise SystemExit("MANIFEST_FILE_COUNT_INVALID")
        print("ARTIFACT_INTEGRITY_GATE_PASS", len(actual) + 1, archive_digest)
        validate_generated_metadata(root, version, release_name)
        validate_brand_independence(root)

        if args.full:
            build_ldflags = f"-s -w -buildid= -X platform.4so.io/factory/internal/buildinfo.Version={version}"
            verify_binary = Path(tempfile.gettempdir()) / f"platform-api-verify-{os.getpid()}"
            installer_binary = Path(tempfile.gettempdir()) / f"platform-installer-verify-{os.getpid()}"
            agent_binary = Path(tempfile.gettempdir()) / f"platform-agent-verify-{os.getpid()}"
            probe_binary = Path(tempfile.gettempdir()) / f"platform-probe-verify-{os.getpid()}"
            ctl_binary = Path(tempfile.gettempdir()) / f"platformctl-verify-{os.getpid()}"
            package_result = subprocess.run(
                ["go", "list", "./..."], cwd=root, text=True, capture_output=True, check=False
            )
            if package_result.returncode:
                sys.stderr.write(package_result.stderr)
                return package_result.returncode
            go_packages = [line.strip() for line in package_result.stdout.splitlines() if line.strip()]
            unit_commands = [["go", "test", "-count=1", package] for package in go_packages]
            vet_commands = [["go", "vet", package] for package in go_packages]
            race_commands = [["go", "test", "-race", "-count=1", package] for package in go_packages]
            commands = [
                ["python3", "scripts/validate_repository.py", "."],
                *unit_commands,
                *vet_commands,
                *race_commands,
                ["python3", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"],
                ["go", "build", "-trimpath", "-ldflags", build_ldflags, "-o", str(verify_binary), "./cmd/platform-api"],
                ["go", "build", "-trimpath", "-ldflags", build_ldflags, "-o", str(installer_binary), "./cmd/platform-installer"],
                ["go", "build", "-trimpath", "-ldflags", build_ldflags, "-o", str(agent_binary), "./cmd/platform-agent"],
                ["go", "build", "-trimpath", "-ldflags", build_ldflags, "-o", str(probe_binary), "./cmd/platform-probe"],
                ["go", "build", "-trimpath", "-ldflags", build_ldflags, "-o", str(ctl_binary), "./cmd/platformctl"],
                [str(ctl_binary), "runtime-closure", "verify-report", "--help"],
                [str(ctl_binary), "field-evidence", "verify-report", "--help"],
                [str(ctl_binary), "field-diagnostics", "verify-report", "--help"],
                [str(ctl_binary), "field-campaign", "prepare", "--help"],
                [str(ctl_binary), "field-campaign", "watch", "--help"],
                [str(ctl_binary), "field-campaign", "diagnose", "--help"],
                [str(ctl_binary), "installer-host", "plan", "--help"],
                [str(ctl_binary), "installer-host", "apply", "--help"],
                [str(ctl_binary), "installer-host", "status", "--help"],
                [str(ctl_binary), "installer-host", "verify", "--help"],
                [str(ctl_binary), "installer-host", "rollback", "--help"],
                [str(ctl_binary), "installer-host", "recover", "--help"],
                [str(ctl_binary), "installer-remote", "preflight", "--help"],
                [str(ctl_binary), "installer-remote", "apply", "--help"],
                [str(ctl_binary), "zero-to-ha", "handoff", "--help"],
                [str(ctl_binary), "catalog-bundle", "verify", "--help"],
                [str(ctl_binary), "image-bundle", "assemble", "--help"],
                [str(ctl_binary), "image-bundle", "verify", "--help"],
                [str(ctl_binary), "image-bundle", "push", "--help"],
                ["python3", "scripts/smoke_api.py", str(verify_binary)],
                ["python3", "scripts/smoke_blueprint_lifecycle.py", str(verify_binary)],
                ["python3", "scripts/smoke_blueprint_overlay_ownership.py", str(verify_binary)],
                ["python3", "scripts/smoke_blueprint_authoring_parity.py", str(verify_binary)],
                ["python3", "scripts/smoke_compatibility_matrix.py", str(verify_binary)],
                ["python3", "scripts/smoke_catalog_governance.py", str(verify_binary)],
                ["python3", "scripts/smoke_plan_safety.py", str(verify_binary)],
                ["python3", "scripts/smoke_planning_impact.py", str(verify_binary)],
                ["python3", "scripts/smoke_evidence_collection_completion.py", str(verify_binary)],
                ["python3", "scripts/smoke_rollback_feasibility.py"],
                ["python3", "scripts/smoke_operation_retry_recovery.py", str(verify_binary)],
                ["python3", "scripts/smoke_operation_step_trace_authority.py", str(verify_binary)],
                ["python3", "scripts/smoke_compensation_orchestration.py", str(verify_binary)],
                ["python3", "scripts/smoke_owner_destructive_recovery.py", str(verify_binary)],
                ["python3", "scripts/smoke_tenant_resize_protected_delete.py", str(verify_binary)],
                ["python3", "scripts/smoke_cluster_maintenance.py", str(verify_binary)],
                ["python3", "scripts/smoke_oidc_group_authz_audit.py", str(verify_binary)],
                ["python3", "scripts/smoke_git_credential_reference.py", str(verify_binary)],
                ["python3", "scripts/smoke_git_pull_request_lkg.py", str(verify_binary)],
                ["python3", "scripts/smoke_git_three_way_drift.py", str(verify_binary)],
                ["python3", "scripts/smoke_upgrade_control.py", str(verify_binary)],
                ["python3", "scripts/smoke_notification_routing.py", str(verify_binary)],
                ["python3", "scripts/smoke_executable_catalog.py", str(verify_binary)],
                ["python3", "scripts/smoke_external_catalog_bundle.py", str(ctl_binary)],
                ["python3", "scripts/smoke_canonical_gateway_api.py", str(verify_binary)],
                ["python3", "scripts/smoke_canonical_snapshot_controller.py", str(verify_binary)],
                ["python3", "scripts/smoke_image_mirror_runtime.py", str(verify_binary), str(ctl_binary)],
                ["python3", "scripts/smoke_runtime_certification.py", str(verify_binary)],
                ["python3", "scripts/smoke_service_account_token.py", str(verify_binary)],
                ["python3", "scripts/smoke_agent_mtls.py", str(verify_binary), str(ctl_binary)],
                ["python3", "scripts/smoke_fleet_support.py", str(verify_binary), str(ctl_binary)],
                ["python3", "scripts/smoke_installer.py", str(installer_binary), str(root / "bin" / "linux-amd64" / "platformctl")],
                ["python3", "scripts/smoke_installer_host.py", str(ctl_binary), str(installer_binary)],
                ["python3", "scripts/smoke_installer_remote.py", str(ctl_binary), str(installer_binary)],
                ["python3", "scripts/smoke_ui_live.py", str(verify_binary), "."],
                ["python3", "scripts/smoke_ui.py", "."],
            ]
            smoke_environment = os.environ.copy()
            # Full extracted-artifact verification owns the same local smoke
            # contract as `make smoke`. Preserve production fail-closed defaults
            # in the binaries while explicitly enabling development-mode auth
            # only for the isolated smoke processes.
            smoke_environment["PLATFORM_FACTORY_DEVELOPMENT_MODE"] = "true"
            try:
                for command in commands:
                    result = subprocess.run(command, cwd=root, env=smoke_environment, text=True, check=False)
                    if result.returncode:
                        return result.returncode
            finally:
                verify_binary.unlink(missing_ok=True)
                installer_binary.unlink(missing_ok=True)
                agent_binary.unlink(missing_ok=True)
                probe_binary.unlink(missing_ok=True)
                ctl_binary.unlink(missing_ok=True)
            print("EXTRACTED_SOURCE_VERIFICATION_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
