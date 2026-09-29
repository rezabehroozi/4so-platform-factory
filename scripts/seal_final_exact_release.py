#!/usr/bin/env python3
"""Build, fully verify and seal the final pre-physical Exact Release locally.

This is the C9 execution owner. It does not use CI/run IDs and never claims
Physical PASS. The seal is emitted only when:
- current Git source is clean and bound to one exact HEAD,
- S1 + C7W final admission is READY,
- the admitted offline release toolchain is used,
- a deterministic release is rebuilt from that source,
- the exact archive passes the full verifier,
- source HEAD remains unchanged through verification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

try:
    import final_exact_release_admission as admission
except ModuleNotFoundError:
    from scripts import final_exact_release_admission as admission

AUTHORITY = "FINAL_EXACT_RELEASE_SEAL_V1"
EXECUTION_AUTHORITY = "LOCAL_EXACT_RELEASE_SEAL_V1"
FULL_VERIFIER_AUTHORITY = "CHECKPOINT_SAFE_FULL_VERIFIER_V2"
TOOLCHAIN_AUTHORITY = "RELEASE_BUILD_TOOLCHAIN_AUTHORITY_V1"


def sha256(path: Path) -> str:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_size <= 0:
        raise RuntimeError(f"FINAL_EXACT_RELEASE_FILE_INVALID {path}")
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return "sha256:" + h.hexdigest()


def run(command: list[str], *, root: Path, env: dict[str, str]) -> str:
    proc = subprocess.run(
        command,
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.returncode != 0:
        raise RuntimeError(
            f"FINAL_EXACT_RELEASE_COMMAND_FAILED rc={proc.returncode} command={' '.join(command)}"
        )
    return (proc.stdout or "").strip()


def git_source(root: Path) -> str:
    top = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if top.returncode != 0 or Path(top.stdout.strip()).resolve() != root:
        raise RuntimeError("FINAL_EXACT_RELEASE_GIT_ROOT_INVALID")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if head.returncode != 0 or len(head.stdout.strip()) != 40:
        raise RuntimeError("FINAL_EXACT_RELEASE_GIT_HEAD_INVALID")
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if dirty.returncode != 0 or dirty.stdout.strip():
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_NOT_EXACT_HEAD")
    return head.stdout.strip()


def safe_toolchain_archive(root: Path, lock: dict) -> tuple[Path, dict]:
    if lock.get("authority") != TOOLCHAIN_AUTHORITY:
        raise RuntimeError("FINAL_EXACT_RELEASE_TOOLCHAIN_AUTHORITY_INVALID")
    spec = lock.get("spec") or {}
    if spec.get("admissionStatus") != "admitted":
        raise RuntimeError("FINAL_EXACT_RELEASE_TOOLCHAIN_NOT_ADMITTED")
    exact = spec.get("exactCompiler") or {}
    rel = str(exact.get("localArchivePath") or "")
    pure = PurePosixPath(rel)
    if (
        not rel
        or pure.is_absolute()
        or ".." in pure.parts
        or not rel.startswith("vendor/toolchains/")
    ):
        raise RuntimeError("FINAL_EXACT_RELEASE_TOOLCHAIN_PATH_INVALID")
    archive = root.joinpath(*pure.parts)
    try:
        info = archive.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_TOOLCHAIN_ARCHIVE_MISSING") from exc
    if not stat.S_ISREG(info.st_mode) or archive.is_symlink():
        raise RuntimeError("FINAL_EXACT_RELEASE_TOOLCHAIN_ARCHIVE_INVALID")
    wanted_size = int(exact.get("archiveSize") or 0)
    wanted_sha = str(exact.get("archiveSha256") or "")
    got_sha = sha256(archive).removeprefix("sha256:")
    if info.st_size != wanted_size or got_sha != wanted_sha:
        raise RuntimeError("FINAL_EXACT_RELEASE_TOOLCHAIN_ARCHIVE_MISMATCH")
    return archive, exact


def extract_toolchain(archive: Path, exact: dict, workspace: Path) -> Path:
    with tarfile.open(archive, mode="r:gz") as tf:
        for member in tf.getmembers():
            pure = PurePosixPath(member.name)
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or not pure.parts
                or pure.parts[0] != "go"
                or not (member.isdir() or member.isreg())
            ):
                raise RuntimeError(
                    f"FINAL_EXACT_RELEASE_TOOLCHAIN_MEMBER_INVALID {member.name}"
                )
            target = workspace.joinpath(*pure.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tf.extractfile(member)
            if source is None:
                raise RuntimeError(
                    f"FINAL_EXACT_RELEASE_TOOLCHAIN_MEMBER_UNREADABLE {member.name}"
                )
            with source, target.open("xb") as out:
                shutil.copyfileobj(source, out, length=1024 * 1024)
            target.chmod(member.mode & 0o777)

    go = workspace / "go" / "bin" / "go"
    info = go.lstat()
    if not stat.S_ISREG(info.st_mode) or go.is_symlink():
        raise RuntimeError("FINAL_EXACT_RELEASE_GO_BINARY_INVALID")
    probe = subprocess.run(
        [str(go), "version"], text=True, capture_output=True, check=False
    )
    expected = (
        f"go version {exact.get('version')} "
        f"{exact.get('goos')}/{exact.get('goarch')}"
    )
    if probe.returncode != 0 or probe.stdout.strip() != expected:
        raise RuntimeError(
            f"FINAL_EXACT_RELEASE_GO_VERSION_MISMATCH expected={expected} "
            f"actual={(probe.stdout or probe.stderr).strip()}"
        )
    return go


def expected_release(root: Path) -> tuple[Path, Path, str, str]:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    release_name = (root / "RELEASE-NAME").read_text(encoding="utf-8").strip()
    if not version or not release_name:
        raise RuntimeError("FINAL_EXACT_RELEASE_IDENTITY_INVALID")
    name = f"4so-platform-factory-{version}-{release_name}"
    return root / "release" / f"{name}.zip", root / "release" / name, version, release_name


def build_evidence(
    root: Path,
    release: Path,
    stage: Path,
    admission_row: dict,
    source_sha: str,
    version: str,
    release_name: str,
) -> dict:
    if admission_row.get("authority") != admission.AUTHORITY or admission_row.get("admitted") is not True:
        raise RuntimeError("FINAL_EXACT_RELEASE_ADMISSION_INVALID")
    if admission_row.get("physicalCertified") is not False:
        raise RuntimeError("FINAL_EXACT_RELEASE_ADMISSION_SCOPE_INFLATED")
    if release.parent != root / "release" or stage.parent != root / "release":
        raise RuntimeError("FINAL_EXACT_RELEASE_PATH_INVALID")
    for required in (
        stage / "ARTIFACT-MANIFEST.json",
        stage / "BUILD-PROVENANCE.json",
        stage / "SBOM.spdx.json",
    ):
        sha256(required)
    return {
        "apiVersion": "platform.4so.io/v1alpha1",
        "kind": "FinalExactReleaseEvidence",
        "authority": AUTHORITY,
        "sourceExecutionAuthority": EXECUTION_AUTHORITY,
        "sourceCommitSHA": source_sha,
        "version": version,
        "releaseName": release_name,
        "releaseArchive": release.name,
        "releaseArchiveSha256": sha256(release),
        "releaseArchiveBytes": release.stat().st_size,
        "artifactManifestSha256": sha256(stage / "ARTIFACT-MANIFEST.json"),
        "buildProvenanceSha256": sha256(stage / "BUILD-PROVENANCE.json"),
        "sbomSha256": sha256(stage / "SBOM.spdx.json"),
        "admissionAuthority": admission_row["authority"],
        "applianceDistributionSha256": admission_row["applianceDistributionSha256"],
        "mcpExternalInteropSha256": admission_row["mcpExternalInteropSha256"],
        "fullVerifierAuthority": FULL_VERIFIER_AUTHORITY,
        "fullVerifierPass": True,
        "physicalCertified": False,
    }


def atomic_write_json(path: Path, value: dict) -> None:
    if path.exists() or path.is_symlink():
        raise RuntimeError("FINAL_EXACT_RELEASE_ALREADY_SEALED")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name("." + path.name + ".tmp")
    if temp.exists():
        if temp.is_symlink() or not temp.is_file():
            raise RuntimeError("FINAL_EXACT_RELEASE_OUTPUT_TEMP_INVALID")
        temp.unlink()
    try:
        with temp.open("x", encoding="utf-8") as fh:
            fh.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(temp, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise RuntimeError("FINAL_EXACT_RELEASE_ALREADY_SEALED") from exc
        directory_fd=os.open(path.parent,os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temp.exists():
            temp.unlink()


def admit_output_path(root: Path, out: Path) -> Path:
    candidate = out if out.is_absolute() else root / out
    candidate = Path(os.path.abspath(candidate))
    try:
        rel = candidate.relative_to(root)
    except ValueError as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_OUTPUT_OUTSIDE_ROOT") from exc
    cursor = root
    for part in rel.parts[:-1]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise RuntimeError("FINAL_EXACT_RELEASE_OUTPUT_PARENT_SYMLINK_FORBIDDEN")
        if cursor.exists() and not cursor.is_dir():
            raise RuntimeError("FINAL_EXACT_RELEASE_OUTPUT_PARENT_INVALID")
    if candidate.is_symlink():
        raise RuntimeError("FINAL_EXACT_RELEASE_OUTPUT_SYMLINK_FORBIDDEN")
    return candidate


def execute(root: Path, out: Path) -> dict:
    root = root.resolve()
    out = admit_output_path(root,out)
    if out.exists():
        raise RuntimeError("FINAL_EXACT_RELEASE_ALREADY_SEALED")

    source_sha = git_source(root)
    admitted = admission.verify(root)

    lock = json.loads(
        (root / "lab" / "release-build-toolchain-lock.json").read_text(
            encoding="utf-8"
        )
    )
    archive, exact = safe_toolchain_archive(root, lock)

    with tempfile.TemporaryDirectory(prefix="4so-final-release-toolchain-") as td:
        go = extract_toolchain(archive, exact, Path(td))
        env = os.environ.copy()
        env["GO"] = str(go)
        env["GOTOOLCHAIN"] = "local"
        env["PYTHON"] = sys.executable

        run(
            [sys.executable, "scripts/verify_release_build_toolchain.py", "--require-admitted"],
            root=root,
            env=env,
        )
        run(["make", "build-release", f"GO={go}", f"PYTHON={sys.executable}"], root=root, env=env)
        run([sys.executable, "scripts/build_release.py", "."], root=root, env=env)

        release, stage, version, release_name = expected_release(root)
        sha256(release)
        if not stage.is_dir() or stage.is_symlink():
            raise RuntimeError("FINAL_EXACT_RELEASE_STAGE_INVALID")

        run(
            [sys.executable, "scripts/verify_release.py", str(release), "--full"],
            root=root,
            env=env,
        )

    if git_source(root) != source_sha:
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_CHANGED_DURING_BUILD")

    evidence = build_evidence(
        root, release, stage, admitted, source_sha, version, release_name
    )
    atomic_write_json(out, evidence)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("lab/final-exact-release-evidence.json"),
    )
    args = parser.parse_args()
    evidence = execute(args.root, args.out)
    print(
        json.dumps(
            {
                "authority": evidence["authority"],
                "sourceCommitSHA": evidence["sourceCommitSHA"],
                "releaseArchive": evidence["releaseArchive"],
                "releaseArchiveSha256": evidence["releaseArchiveSha256"],
                "fullVerifierPass": evidence["fullVerifierPass"],
                "physicalCertified": evidence["physicalCertified"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
