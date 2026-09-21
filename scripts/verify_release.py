#!/usr/bin/env python3
"""Verify release integrity, independence and extracted-source behavior."""
from __future__ import annotations

from pathlib import Path
import argparse
import concurrent.futures
import hashlib
import json
import os
import posixpath
import re
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from ui_browser_authority import prepare_full_verifier_browser

RELEASE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
MANIFEST_KEYS = {"schemaVersion", "product", "version", "releaseName", "fileCount", "files"}
MANIFEST_FILE_KEYS = {"path", "sha256", "size", "mode"}

FORBIDDEN = (
    bytes((107, 117, 98, 97, 114, 97)),
    bytes((104, 111, 115, 116, 105, 114, 97, 110)),
)

FULL_VERIFIER_AUTHORITY = "CHECKPOINT_SAFE_FULL_VERIFIER_V2"
SHARD_AUTHORITY = "AUTOPILOT_STAGE_SHARD_AUTHORITY_V2"


def run_bounded_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: int,
) -> tuple[int, str, str]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        start_new_session=(os.name == "posix"),
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        return process.returncode, stdout or "", stderr or ""
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        else:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            stdout, stderr = process.communicate()
        stderr = (stderr or "") + (
            f"\nCOMMAND_TIMEOUT timeout={timeout_seconds} command={' '.join(command)}\n"
        )
        return 124, stdout or "", stderr


def run_parallel_commands(
    label: str,
    commands: list[list[str]],
    *,
    cwd: Path,
    env: dict[str, str],
    workers: int,
    timeout_seconds: int,
) -> int:
    """Run replayable independent gates concurrently without reducing coverage."""
    workers = max(1, min(workers, len(commands) or 1))

    def execute(command: list[str]) -> tuple[int, str, str]:
        return run_bounded_command(
            command,
            cwd=cwd,
            env=env,
            timeout_seconds=timeout_seconds,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(execute, command) for command in commands]
        results = [future.result() for future in futures]

    # strict=True keeps a shrunken result list from silently skipping the remaining
    # release gates: every submitted command must be reported.
    for command, (returncode, stdout, stderr) in zip(commands, results, strict=True):
        print("+", " ".join(command), flush=True)
        if stdout:
            sys.stdout.write(stdout)
        if stderr:
            sys.stderr.write(stderr)
        if returncode:
            print(
                f"{label}_FAILED rc={returncode} command={' '.join(command)}",
                file=sys.stderr,
            )
            return returncode
    print(
        f"{label}_PASS authority={FULL_VERIFIER_AUTHORITY} "
        f"commands={len(commands)} workers={workers}"
    )
    return 0


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
        after = os.fstat(fd)
        if (
            (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
        ):
            raise SystemExit("ARCHIVE_SOURCE_CHANGED_WHILE_SNAPSHOTTING")
        if hashlib.sha256(target.read_bytes()).hexdigest() != h.hexdigest():
            raise SystemExit("ARCHIVE_SNAPSHOT_DIGEST_CHANGED_AFTER_PUBLICATION")
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
        "virtual-cluster-renderer",
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
            print(
                f"FULL_VERIFIER_START authority={FULL_VERIFIER_AUTHORITY} shardAuthority={SHARD_AUTHORITY} version={version}",
                flush=True,
            )
            verify_environment = os.environ.copy()
            verify_environment["PLATFORM_FACTORY_DEVELOPMENT_MODE"] = "true"
            try:
                browser_executable, browser_authority = prepare_full_verifier_browser(verify_environment)
            except ValueError as exc:
                raise SystemExit(str(exc)) from exc
            print(
                "UI_BROWSER_AUTHORITY_GATE_PASS",
                browser_authority["version"],
                browser_authority["sha256"],
                browser_executable,
                flush=True,
            )

            # Checkpoint-safe package execution: all packages are still covered,
            # but each package has its own Go timeout and each shard is an
            # independently replayable Autopilot checkpoint.
            unit_shards = [
                ["python3", "scripts/run_go_package_shard.py", "--shard", str(shard)]
                for shard in range(1, 5)
            ]
            vet_shards = [
                ["python3", "scripts/run_go_package_shard.py", "--vet", "--shard", str(shard)]
                for shard in range(1, 5)
            ]
            race_shards = [
                ["python3", "scripts/run_go_package_shard.py", "--race", "--shard", str(shard)]
                for shard in range(1, 5)
            ]

            source_gate_commands: list[tuple[list[str], int]] = [
                (["python3", "scripts/validate_repository.py", "."], 240),
                (["python3", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"], 420),
                (["python3", "scripts/test_lab_runner.py"], 300),
                (["python3", "scripts/lab_runner.py", "self-test"], 300),
                (["python3", "scripts/catalog_upstream_admission.py"], 180),
                (["python3", "scripts/acquire_upstream_helm.py", "--self-test"], 180),
                (["python3", "scripts/acquire_virtual_cluster_runtime.py", "--self-test"], 180),
                (["python3", "scripts/acquire_upstream_tagged_source.py", "--self-test"], 180),
                (["python3", "scripts/acquire_historical_upgrade_batch.py", "--self-test"], 180),
                (["python3", "scripts/generate_agent_knowledge.py", "--check"], 180),
                (["python3", "scripts/browser_triage_profile.py", "--check"], 120),
                (["python3", "scripts/browser_triage_bootstrap.py", "--self-test"], 120),
            ]
            for command, timeout_seconds in source_gate_commands:
                print("+", " ".join(command), flush=True)
                returncode, stdout, stderr = run_bounded_command(
                    command, cwd=root, env=verify_environment, timeout_seconds=timeout_seconds
                )
                if stdout:
                    sys.stdout.write(stdout)
                if stderr:
                    sys.stderr.write(stderr)
                if returncode:
                    return returncode

            for label, shard_commands, workers, timeout_seconds in (
                ("GO_UNIT_SHARD_GATE", unit_shards, 4, 900),
                ("GO_VET_SHARD_GATE", vet_shards, 4, 900),
                ("GO_RACE_SHARD_GATE", race_shards, 2, 1200),
            ):
                rc = run_parallel_commands(
                    label,
                    shard_commands,
                    cwd=root,
                    env=verify_environment,
                    workers=workers,
                    timeout_seconds=timeout_seconds,
                )
                if rc:
                    return rc

            # Build host binaries from the extracted source. The packaged
            # linux-amd64 binaries have already been checked byte-for-byte by
            # provenance/SBOM validation above; these builds prove source
            # rebuildability and feed the same smoke matrix as `make smoke`.
            build_command = ["make", "build"]
            print("+", " ".join(build_command), flush=True)
            returncode, stdout, stderr = run_bounded_command(
                build_command, cwd=root, env=verify_environment, timeout_seconds=1200
            )
            if stdout:
                sys.stdout.write(stdout)
            if stderr:
                sys.stderr.write(stderr)
            if returncode:
                return returncode

            for name in ("platform-api", "platformctl", "platform-installer", "platform-agent", "platform-probe"):
                binary = root / "bin" / name
                version_probe = subprocess.run(
                    [str(binary), "version"], cwd=root, env=verify_environment, text=True, capture_output=True, check=False
                )
                if version_probe.returncode != 0 or version_probe.stdout.strip() != version:
                    print(
                        "EXTRACTED_BINARY_VERSION_MISMATCH",
                        name,
                        "expected",
                        version,
                        "actual",
                        version_probe.stdout.strip() or version_probe.stderr.strip(),
                        file=sys.stderr,
                    )
                    return 1
            print("EXTRACTED_BINARY_VERSION_GATE_PASS", version, 5)

            ctl_binary = root / "bin" / "platformctl"
            cli_help_commands = [
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
            ]
            rc = run_parallel_commands(
                "CLI_HELP_GATE",
                cli_help_commands,
                cwd=root,
                env=verify_environment,
                workers=4,
                timeout_seconds=120,
            )
            if rc:
                return rc

            # Backend smoke parity with `make smoke`. The first three shards are
            # independent API/control-plane smoke; installer lifecycle remains a
            # separate checkpoint because it owns destructive/recovery semantics.
            regular_smoke_shards = [
                ["python3", "scripts/run_smoke_shard.py", "--shard", str(shard)]
                for shard in range(1, 4)
            ]
            rc = run_parallel_commands(
                "BACKEND_SMOKE_SHARD_GATE",
                regular_smoke_shards,
                cwd=root,
                env=verify_environment,
                workers=3,
                timeout_seconds=1800,
            )
            if rc:
                return rc
            installer_smoke = ["python3", "scripts/run_smoke_shard.py", "--shard", "4"]
            print("+", " ".join(installer_smoke), flush=True)
            returncode, stdout, stderr = run_bounded_command(
                installer_smoke, cwd=root, env=verify_environment, timeout_seconds=1800
            )
            if stdout:
                sys.stdout.write(stdout)
            if stderr:
                sys.stderr.write(stderr)
            if returncode:
                return returncode

            # UI/full-product parity: rendered/headless, quality/accessibility,
            # Persian coverage, live API authority and the C4 workflow E2E.
            ui_commands: list[tuple[list[str], int]] = [
                (["python3", "scripts/smoke_ui.py", "."], 900),
                (["python3", "scripts/smoke_ui_quality.py"], 900),
                (["python3", "scripts/persian_ui_lint.py", "--root", "."], 180),
                (["python3", "scripts/console_localization_coverage.py", "--root", "."], 180),
                (["python3", "scripts/smoke_ui_localization_runtime.py", "."], 300),
                (["python3", "scripts/smoke_ui_live.py", "./bin/platform-api", "."], 900),
                (
                    ["python3", "scripts/smoke_ui_workflow_e2e.py", "./bin/platform-api", "./bin/platform-installer"],
                    1200,
                ),
            ]
            for command, timeout_seconds in ui_commands:
                print("+", " ".join(command), flush=True)
                returncode, stdout, stderr = run_bounded_command(
                    command, cwd=root, env=verify_environment, timeout_seconds=timeout_seconds
                )
                if stdout:
                    sys.stdout.write(stdout)
                if stderr:
                    sys.stderr.write(stderr)
                if returncode:
                    return returncode

            print(f"EXTRACTED_SOURCE_VERIFICATION_PASS authority={FULL_VERIFIER_AUTHORITY}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
