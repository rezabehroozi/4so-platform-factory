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
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

try:
    import final_exact_release_admission as admission
except ModuleNotFoundError:
    from scripts import final_exact_release_admission as admission

AUTHORITY = "FINAL_EXACT_RELEASE_SEAL_V1"
EXECUTION_AUTHORITY = "LOCAL_EXACT_RELEASE_SEAL_V1"
FULL_VERIFIER_AUTHORITY = "CHECKPOINT_SAFE_FULL_VERIFIER_V2"
TOOLCHAIN_AUTHORITY = "RELEASE_BUILD_TOOLCHAIN_AUTHORITY_V1"
SOURCE_WORKSPACE_AUTHORITY = "GIT_DETACHED_EXACT_SHA_WORKTREE_V1"
FINAL_EVIDENCE_KEYS = {
    "apiVersion","kind","authority","sourceExecutionAuthority","sourceWorkspaceAuthority",
    "sourceCommitSHA","version","releaseName","releaseArchive","releaseArchivePath",
    "releaseArchiveSha256","releaseArchiveBytes","artifactManifestSha256",
    "buildProvenanceSha256","sbomSha256","admissionAuthority",
    "applianceDistributionSha256","mcpExternalInteropSha256","fullVerifierAuthority",
    "fullVerifierPass","physicalCertified",
}


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
    branch = subprocess.run(
        ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if branch.returncode != 0 or branch.stdout.strip() != "main":
        raise RuntimeError("FINAL_EXACT_RELEASE_BRANCH_NOT_MAIN")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if head.returncode != 0 or len(head.stdout.strip()) != 40:
        raise RuntimeError("FINAL_EXACT_RELEASE_GIT_HEAD_INVALID")
    indexed = subprocess.run(
        ["git", "ls-files", "-v", "-z"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if indexed.returncode != 0:
        raise RuntimeError("FINAL_EXACT_RELEASE_GIT_INDEX_UNAVAILABLE")
    for raw in indexed.stdout.split(b"\x00"):
        if raw and not raw.startswith(b"H "):
            raise RuntimeError("FINAL_EXACT_RELEASE_GIT_INDEX_FLAGS_FORBIDDEN")
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
    admitted_archive_size=int(exact.get("archiveSize") or 0)
    if admitted_archive_size<=0:
        raise RuntimeError("FINAL_EXACT_RELEASE_TOOLCHAIN_LOCK_INVALID")
    max_members=65536
    max_member_size=256*1024*1024
    max_total_size=max(512*1024*1024,admitted_archive_size*8)
    with tarfile.open(archive, mode="r:gz") as tf:
        members=tf.getmembers()
        if not members or len(members)>max_members:
            raise RuntimeError("FINAL_EXACT_RELEASE_TOOLCHAIN_MEMBER_COUNT_INVALID")
        seen=set()
        total_size=0
        for member in members:
            pure = PurePosixPath(member.name)
            canonical=pure.as_posix()
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or not pure.parts
                or pure.parts[0] != "go"
                or len(canonical.encode("utf-8"))>1024
                or not (member.isdir() or member.isreg())
                or canonical in seen
            ):
                raise RuntimeError(
                    f"FINAL_EXACT_RELEASE_TOOLCHAIN_MEMBER_INVALID {member.name}"
                )
            seen.add(canonical)
            if member.isreg():
                if member.size<0 or member.size>max_member_size:
                    raise RuntimeError(f"FINAL_EXACT_RELEASE_TOOLCHAIN_MEMBER_SIZE_INVALID {member.name}")
                total_size+=member.size
                if total_size>max_total_size:
                    raise RuntimeError("FINAL_EXACT_RELEASE_TOOLCHAIN_UNCOMPRESSED_SIZE_INVALID")
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
                out.flush()
                os.fsync(out.fileno())
            if target.stat().st_size!=member.size:
                raise RuntimeError(f"FINAL_EXACT_RELEASE_TOOLCHAIN_MEMBER_SIZE_DRIFT {member.name}")
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


def prepare_exact_worktree(root: Path, source_sha: str, parent: Path) -> Path:
    target = parent / "source"
    proc = subprocess.run(
        ["git", "worktree", "add", "--detach", str(target), source_sha],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"FINAL_EXACT_RELEASE_WORKTREE_CREATE_FAILED {proc.stdout.strip()}")
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=target,
            text=True,
            capture_output=True,
            check=False,
        )
        indexed = subprocess.run(
            ["git", "ls-files", "-v", "-z"],
            cwd=target,
            capture_output=True,
            check=False,
        )
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=target,
            text=True,
            capture_output=True,
            check=False,
        )
        if head.returncode != 0 or head.stdout.strip() != source_sha:
            raise RuntimeError("FINAL_EXACT_RELEASE_WORKTREE_HEAD_MISMATCH")
        if indexed.returncode != 0 or any(raw and not raw.startswith(b"H ") for raw in indexed.stdout.split(b"\x00")):
            raise RuntimeError("FINAL_EXACT_RELEASE_WORKTREE_INDEX_INVALID")
        if dirty.returncode != 0 or dirty.stdout.strip():
            raise RuntimeError("FINAL_EXACT_RELEASE_WORKTREE_NOT_CLEAN")
        return target
    except Exception:
        subprocess.run(["git", "worktree", "remove", "--force", str(target)], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        raise


def remove_exact_worktree(root: Path, target: Path) -> None:
    proc = subprocess.run(
        ["git", "worktree", "remove", "--force", str(target)],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"FINAL_EXACT_RELEASE_WORKTREE_CLEANUP_FAILED {proc.stdout.strip()}")
    subprocess.run(["git", "worktree", "prune"], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def stage_toolchain_archive(archive: Path, exact: dict, worktree: Path) -> Path:
    rel = PurePosixPath(str(exact.get("localArchivePath") or ""))
    target = worktree.joinpath(*rel.parts)
    if target.exists() or target.is_symlink():
        raise RuntimeError("FINAL_EXACT_RELEASE_WORKTREE_TOOLCHAIN_CONFLICT")
    wanted_size=int(exact.get("archiveSize") or 0)
    wanted_sha=str(exact.get("archiveSha256") or "")
    if wanted_size<=0 or not re.fullmatch(r"[0-9a-f]{64}",wanted_sha):
        raise RuntimeError("FINAL_EXACT_RELEASE_TOOLCHAIN_LOCK_INVALID")
    target.parent.mkdir(parents=True, exist_ok=True)
    with archive.open("rb") as source, target.open("xb") as output:
        shutil.copyfileobj(source, output, length=1024 * 1024)
        output.flush()
        os.fsync(output.fileno())
    if target.stat().st_size!=wanted_size or sha256(target)!="sha256:"+wanted_sha:
        raise RuntimeError("FINAL_EXACT_RELEASE_WORKTREE_TOOLCHAIN_MISMATCH")
    return target


def verify_worktree_source_unchanged(worktree: Path, source_sha: str, allowed_untracked: set[str] | None = None) -> None:
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=worktree, text=True, capture_output=True, check=False)
    indexed = subprocess.run(["git", "ls-files", "-v", "-z"], cwd=worktree, capture_output=True, check=False)
    tracked_raw = subprocess.run(["git", "ls-files", "-z"], cwd=worktree, capture_output=True, check=False)
    status = subprocess.run(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=worktree, capture_output=True, check=False)
    index_valid = indexed.returncode == 0 and all(not raw or raw.startswith(b"H ") for raw in indexed.stdout.split(b"\x00"))
    allowed=set(allowed_untracked or ())
    status_valid=status.returncode==0 and tracked_raw.returncode==0
    tracked=set()
    if status_valid:
        try:
            tracked={raw.decode("utf-8",errors="strict") for raw in tracked_raw.stdout.split(b"\x00") if raw}
        except UnicodeDecodeError:
            status_valid=False
    if status_valid:
        for raw in status.stdout.split(b"\x00"):
            if not raw:
                continue
            if len(raw)>=4 and raw[:2]==b"??" and raw[2:3]==b" ":
                try:
                    rel=raw[3:].decode("utf-8",errors="strict")
                except UnicodeDecodeError:
                    status_valid=False
                    break
                if rel in allowed:
                    continue
            status_valid=False
            break
    if status_valid:
        generated_prefixes=("bin/","release/",".state/")
        for candidate in worktree.rglob("*"):
            if candidate==worktree/".git" or not (candidate.is_file() or candidate.is_symlink()):
                continue
            rel=candidate.relative_to(worktree).as_posix()
            if rel in tracked or rel in allowed or any(rel.startswith(prefix) for prefix in generated_prefixes):
                continue
            status_valid=False
            break
    if head.returncode != 0 or head.stdout.strip() != source_sha or not index_valid or not status_valid:
        raise RuntimeError("FINAL_EXACT_RELEASE_WORKTREE_SOURCE_CHANGED")


def publish_verified_file(source: Path, target: Path) -> Path:
    try:
        source_info=source.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"FINAL_EXACT_RELEASE_ARTIFACT_SOURCE_MISSING {source}") from exc
    if not stat.S_ISREG(source_info.st_mode) or source.is_symlink() or source_info.st_size<=0:
        raise RuntimeError(f"FINAL_EXACT_RELEASE_ARTIFACT_SOURCE_INVALID {source}")
    wanted_size=source_info.st_size
    wanted=sha256(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_file() or target.stat().st_size!=wanted_size or sha256(target)!=wanted:
            raise RuntimeError(f"FINAL_EXACT_RELEASE_ARTIFACT_CONFLICT {target}")
        return target

    fd,temp_name=tempfile.mkstemp(prefix="."+target.name+".publish.",dir=target.parent)
    temp=Path(temp_name)
    try:
        with source.open("rb") as input_fh, os.fdopen(fd,"wb") as output_fh:
            shutil.copyfileobj(input_fh,output_fh,length=1024*1024)
            output_fh.flush()
            os.fsync(output_fh.fileno())
        if temp.stat().st_size!=wanted_size or sha256(temp)!=wanted:
            raise RuntimeError(f"FINAL_EXACT_RELEASE_ARTIFACT_SOURCE_CHANGED {source}")
        temp.chmod(0o444)
        try:
            os.link(temp,target,follow_symlinks=False)
        except FileExistsError:
            if target.is_symlink() or not target.is_file() or target.stat().st_size!=wanted_size or sha256(target)!=wanted:
                raise RuntimeError(f"FINAL_EXACT_RELEASE_ARTIFACT_CONFLICT {target}")
        if target.stat().st_size!=wanted_size or sha256(target)!=wanted:
            raise RuntimeError(f"FINAL_EXACT_RELEASE_ARTIFACT_PUBLICATION_DRIFT {target}")
        directory_fd=os.open(target.parent,os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return target
    finally:
        if temp.exists():
            temp.unlink()


def verify_release_checksum(release:Path,checksum:Path,label:str)->None:
    digest=sha256(release)
    try:
        checksum_info=checksum.lstat()
        checksum_text=checksum.read_text(encoding="utf-8")
    except (FileNotFoundError,UnicodeDecodeError,OSError) as exc:
        raise RuntimeError(f"{label}_CHECKSUM_INVALID") from exc
    wanted=f"{digest.removeprefix('sha256:')}  {release.name}\n"
    if not stat.S_ISREG(checksum_info.st_mode) or checksum.is_symlink() or checksum_text!=wanted:
        raise RuntimeError(f"{label}_CHECKSUM_INVALID")


def exact_release_publication_path(root: Path, source_sha: str, filename: str) -> Path:
    if len(source_sha) != 40 or any(ch not in "0123456789abcdef" for ch in source_sha):
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_SHA_INVALID")
    if not filename or "/" in filename or "\\" in filename or filename in {".", ".."}:
        raise RuntimeError("FINAL_EXACT_RELEASE_ARTIFACT_NAME_INVALID")
    return admit_output_path(root, root / "release" / "exact-sha" / source_sha / filename)


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
    expected_name = f"4so-platform-factory-{version}-{release_name}"
    expected_parent=root/"release"/"exact-sha"/source_sha
    if release.parent!=expected_parent or release.name!=expected_name+".zip" or stage.name!=expected_name:
        raise RuntimeError("FINAL_EXACT_RELEASE_PATH_INVALID")
    prefix=expected_name+"/"
    metadata_files=("ARTIFACT-MANIFEST.json","BUILD-PROVENANCE.json","SBOM.spdx.json")
    stage_digests={name:sha256(stage/name) for name in metadata_files}
    try:
        with zipfile.ZipFile(release,"r") as archive:
            names=archive.namelist()
            embedded={}
            for name in metadata_files:
                member=prefix+name
                if names.count(member)!=1:
                    raise RuntimeError(f"FINAL_EXACT_RELEASE_METADATA_MEMBER_INVALID {member}")
                embedded[name]="sha256:"+hashlib.sha256(archive.read(member)).hexdigest()
    except (zipfile.BadZipFile,KeyError,OSError) as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_ARCHIVE_METADATA_INVALID") from exc
    if embedded!=stage_digests:
        raise RuntimeError("FINAL_EXACT_RELEASE_STAGE_ARCHIVE_METADATA_DRIFT")
    return {
        "apiVersion": "platform.4so.io/v1alpha1",
        "kind": "FinalExactReleaseEvidence",
        "authority": AUTHORITY,
        "sourceExecutionAuthority": EXECUTION_AUTHORITY,
        "sourceWorkspaceAuthority": SOURCE_WORKSPACE_AUTHORITY,
        "sourceCommitSHA": source_sha,
        "version": version,
        "releaseName": release_name,
        "releaseArchive": release.name,
        "releaseArchivePath": release.relative_to(root).as_posix(),
        "releaseArchiveSha256": sha256(release),
        "releaseArchiveBytes": release.stat().st_size,
        "artifactManifestSha256": embedded["ARTIFACT-MANIFEST.json"],
        "buildProvenanceSha256": embedded["BUILD-PROVENANCE.json"],
        "sbomSha256": embedded["SBOM.spdx.json"],
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


def git_source_for_resume(root: Path, out: Path) -> str:
    top = subprocess.run(["git","rev-parse","--show-toplevel"],cwd=root,text=True,capture_output=True,check=False)
    branch = subprocess.run(["git","symbolic-ref","--quiet","--short","HEAD"],cwd=root,text=True,capture_output=True,check=False)
    if branch.returncode!=0 or branch.stdout.strip()!="main":
        raise RuntimeError("FINAL_EXACT_RELEASE_BRANCH_NOT_MAIN")
    head = subprocess.run(["git","rev-parse","HEAD"],cwd=root,text=True,capture_output=True,check=False)
    indexed = subprocess.run(["git","ls-files","-v","-z"],cwd=root,capture_output=True,check=False)
    status = subprocess.run(["git","status","--porcelain=v1","-z","--untracked-files=all"],cwd=root,capture_output=True,check=False)
    if top.returncode!=0 or Path(top.stdout.strip()).resolve()!=root or head.returncode!=0 or len(head.stdout.strip())!=40 or indexed.returncode!=0 or status.returncode!=0:
        raise RuntimeError("FINAL_EXACT_RELEASE_RESUME_GIT_STATE_INVALID")
    if any(raw and not raw.startswith(b"H ") for raw in indexed.stdout.split(b"\x00")):
        raise RuntimeError("FINAL_EXACT_RELEASE_GIT_INDEX_FLAGS_FORBIDDEN")
    allowed=os.fsencode(out.relative_to(root).as_posix())
    for record in status.stdout.split(b"\x00"):
        if not record:
            continue
        status_code=record[:2]
        if len(record)>=4 and record[2:3]==b" " and record[3:]==allowed and b"R" not in status_code and b"C" not in status_code:
            continue
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_NOT_EXACT_HEAD")
    return head.stdout.strip()


def validate_final_evidence_lineage(root:Path,sealed_sha:str,current_sha:str,out:Path)->None:
    sealed_sha=str(sealed_sha or "").strip().lower()
    current_sha=str(current_sha or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}",sealed_sha) or not re.fullmatch(r"[0-9a-f]{40}",current_sha):
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_SOURCE_IDENTITY_INVALID")
    if sealed_sha==current_sha:
        return
    ancestor=subprocess.run(["git","merge-base","--is-ancestor",sealed_sha,current_sha],cwd=root,capture_output=True,check=False)
    if ancestor.returncode!=0:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_SOURCE_NOT_ANCESTOR")
    try:
        allowed=out.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_PATH_INVALID") from exc
    diff=subprocess.run(["git","diff","--name-only","-z",sealed_sha+".."+current_sha],cwd=root,capture_output=True,check=False)
    if diff.returncode!=0:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_SOURCE_DELTA_UNAVAILABLE")
    try:
        changed={raw.decode("utf-8",errors="strict") for raw in diff.stdout.split(b"\x00") if raw}
    except UnicodeDecodeError as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_SOURCE_DELTA_INVALID") from exc
    if changed!={allowed}:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_SOURCE_DELTA_NOT_EVIDENCE_ONLY")


def final_git_handoff(root:Path,out:Path,evidence:dict)->dict:
    root=root.resolve()
    current_sha=git_source_for_resume(root,out)
    sealed_sha=str(evidence.get("sourceCommitSHA") or "").strip().lower()
    validate_final_evidence_lineage(root,sealed_sha,current_sha,out)
    rel=out.resolve().relative_to(root).as_posix()
    tracked=subprocess.run(["git","ls-files","--error-unmatch",rel],cwd=root,text=True,capture_output=True,check=False)
    status=subprocess.run(["git","status","--porcelain=v1","--",rel],cwd=root,text=True,capture_output=True,check=False)
    if status.returncode!=0:
        return {
            "nextActionCode":"INSPECT_C9_EVIDENCE_GIT_STATE",
            "nextCommand":["git","status","--short","--",rel],
        }
    if tracked.returncode!=0 or status.stdout.strip():
        return {
            "nextActionCode":"COMMIT_C9_EVIDENCE",
            "nextCommand":["git","add",rel],
            "followupCommand":["git","commit","-m","evidence: seal final exact pre-certification release"],
            "releaseSourceCommitSHA":sealed_sha,
            "detail":"final exact release is sealed; persist only the final evidence file as the post-seal evidence commit",
        }
    return {
        "nextActionCode":"C9_SEALED",
        "nextCommand":[],
        "releaseSourceCommitSHA":sealed_sha,
        "evidenceCommitSHA":current_sha,
        "detail":"final exact release evidence is committed with evidence-only lineage from the sealed release SHA",
    }


def exact_source_admission(root: Path, source_sha: str) -> dict:
    state_dir=root/".state"
    if state_dir.is_symlink() or (state_dir.exists() and not state_dir.is_dir()):
        raise RuntimeError("FINAL_EXACT_RELEASE_STATE_DIR_INVALID")
    state_dir.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="4so-final-release-admission-source-",dir=state_dir) as source_td:
        worktree=prepare_exact_worktree(root,source_sha,Path(source_td))
        try:
            return admission.verify(worktree,expected_source_sha=source_sha)
        finally:
            remove_exact_worktree(root,worktree)


def verify_existing_release_full(root: Path, source_sha: str, release: Path) -> None:
    state_dir=root/".state"
    if state_dir.is_symlink() or (state_dir.exists() and not state_dir.is_dir()):
        raise RuntimeError("FINAL_EXACT_RELEASE_STATE_DIR_INVALID")
    state_dir.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="4so-final-release-resume-toolchain-",dir=state_dir) as tool_td, tempfile.TemporaryDirectory(prefix="4so-final-release-resume-source-",dir=state_dir) as source_td:
        worktree=prepare_exact_worktree(root,source_sha,Path(source_td))
        try:
            lock=json.loads((worktree/"lab"/"release-build-toolchain-lock.json").read_text(encoding="utf-8"))
            archive,exact=safe_toolchain_archive(root,lock)
            staged_archive=stage_toolchain_archive(archive,exact,worktree)
            go=extract_toolchain(staged_archive,exact,Path(tool_td))
            env=os.environ.copy()
            env["GO"]=str(go)
            env["GOTOOLCHAIN"]="local"
            env["PYTHON"]=sys.executable
            env["PYTHONDONTWRITEBYTECODE"]="1"
            run([sys.executable,"scripts/verify_release_build_toolchain.py","--require-admitted","--archive",str(staged_archive)],root=worktree,env=env)
            run([sys.executable,"scripts/verify_release.py",str(release),"--full"],root=worktree,env=env)
            verify_worktree_source_unchanged(worktree,source_sha,{staged_archive.relative_to(worktree).as_posix()})
        finally:
            remove_exact_worktree(root,worktree)


def resume_existing_evidence(root: Path, out: Path) -> dict:
    if out.is_symlink() or not out.is_file() or out.stat().st_size<=0 or out.stat().st_size>1024*1024:
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_INVALID")
    current_sha=git_source_for_resume(root,out)
    try:
        evidence=json.loads(out.read_text(encoding="utf-8"))
    except (UnicodeDecodeError,json.JSONDecodeError) as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_INVALID") from exc
    if not isinstance(evidence,dict) or set(evidence)!=FINAL_EVIDENCE_KEYS:
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_FIELDS_INVALID")
    source_sha=str(evidence.get("sourceCommitSHA") or "").strip().lower()
    validate_final_evidence_lineage(root,source_sha,current_sha,out)
    version=(root/"VERSION").read_text(encoding="utf-8").strip()
    release_name=(root/"RELEASE-NAME").read_text(encoding="utf-8").strip()
    expected_name=f"4so-platform-factory-{version}-{release_name}.zip"
    expected_rel=PurePosixPath("release")/"exact-sha"/source_sha/expected_name
    fixed={
        "apiVersion":"platform.4so.io/v1alpha1","kind":"FinalExactReleaseEvidence","authority":AUTHORITY,
        "sourceExecutionAuthority":EXECUTION_AUTHORITY,"sourceWorkspaceAuthority":SOURCE_WORKSPACE_AUTHORITY,
        "sourceCommitSHA":source_sha,"version":version,"releaseName":release_name,
        "releaseArchive":expected_name,"releaseArchivePath":expected_rel.as_posix(),
        "admissionAuthority":admission.AUTHORITY,"fullVerifierAuthority":FULL_VERIFIER_AUTHORITY,
        "fullVerifierPass":True,"physicalCertified":False,
    }
    if any(evidence.get(k)!=v for k,v in fixed.items()):
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_DRIFT")
    admitted=exact_source_admission(root,source_sha)
    if admitted.get("admitted") is not True or admitted.get("physicalCertified") is not False:
        raise RuntimeError("FINAL_EXACT_RELEASE_ADMISSION_INVALID")
    for key in ("applianceDistributionSha256","mcpExternalInteropSha256"):
        if evidence.get(key)!=admitted.get(key):
            raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_ADMISSION_DRIFT")
    for key in ("releaseArchiveSha256","artifactManifestSha256","buildProvenanceSha256","sbomSha256","applianceDistributionSha256","mcpExternalInteropSha256"):
        value=evidence.get(key)
        if not isinstance(value,str) or len(value)!=71 or not value.startswith("sha256:") or any(ch not in "0123456789abcdef" for ch in value[7:]):
            raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_DIGEST_INVALID")
    if type(evidence.get("releaseArchiveBytes")) is not int or evidence["releaseArchiveBytes"]<=0:
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_ARCHIVE_SIZE_INVALID")
    release=root.joinpath(*expected_rel.parts)
    digest=sha256(release)
    if evidence.get("releaseArchiveSha256")!=digest or evidence.get("releaseArchiveBytes")!=release.stat().st_size:
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_ARCHIVE_DRIFT")
    checksum=release.with_name(release.name+".sha256")
    try:
        verify_release_checksum(release,checksum,"FINAL_EXACT_RELEASE_EXISTING")
    except RuntimeError as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_CHECKSUM_DRIFT") from exc
    prefix=f"4so-platform-factory-{version}-{release_name}/"
    expected_embedded={
        prefix+"ARTIFACT-MANIFEST.json":evidence.get("artifactManifestSha256"),
        prefix+"BUILD-PROVENANCE.json":evidence.get("buildProvenanceSha256"),
        prefix+"SBOM.spdx.json":evidence.get("sbomSha256"),
    }
    try:
        with zipfile.ZipFile(release,"r") as archive:
            names=set(archive.namelist())
            for name,wanted in expected_embedded.items():
                if name not in names or not isinstance(wanted,str) or not wanted.startswith("sha256:"):
                    raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_METADATA_DRIFT")
                got="sha256:"+hashlib.sha256(archive.read(name)).hexdigest()
                if got!=wanted:
                    raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_METADATA_DRIFT")
    except (zipfile.BadZipFile,KeyError,OSError) as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_ARCHIVE_INVALID") from exc
    verify_existing_release_full(root,source_sha,release)
    if git_source_for_resume(root,out)!=current_sha:
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_CHANGED_DURING_RESUME")
    validate_final_evidence_lineage(root,source_sha,current_sha,out)
    return evidence


def execute(root: Path, out: Path) -> dict:
    root = root.resolve()
    out = admit_output_path(root,out)
    if out.exists():
        return resume_existing_evidence(root,out)

    source_sha = git_source(root)

    state_dir = root / ".state"
    if state_dir.is_symlink() or (state_dir.exists() and not state_dir.is_dir()):
        raise RuntimeError("FINAL_EXACT_RELEASE_STATE_DIR_INVALID")
    state_dir.mkdir(exist_ok=True)

    evidence = None
    with tempfile.TemporaryDirectory(prefix="4so-final-release-toolchain-", dir=state_dir) as tool_td, tempfile.TemporaryDirectory(prefix="4so-final-release-source-", dir=state_dir) as source_td:
        worktree = prepare_exact_worktree(root, source_sha, Path(source_td))
        try:
            lock = json.loads(
                (worktree / "lab" / "release-build-toolchain-lock.json").read_text(
                    encoding="utf-8"
                )
            )
            archive, exact = safe_toolchain_archive(root, lock)
            staged_archive = stage_toolchain_archive(archive, exact, worktree)
            go = extract_toolchain(staged_archive, exact, Path(tool_td))
            admitted = admission.verify(worktree,expected_source_sha=source_sha)
            env = os.environ.copy()
            env["GO"] = str(go)
            env["GOTOOLCHAIN"] = "local"
            env["PYTHON"] = sys.executable
            env["PYTHONDONTWRITEBYTECODE"] = "1"

            run(
                [sys.executable, "scripts/verify_release_build_toolchain.py", "--require-admitted", "--archive", str(staged_archive)],
                root=worktree,
                env=env,
            )
            run(["make", "build-release", f"GO={go}", f"PYTHON={sys.executable}"], root=worktree, env=env)
            run([sys.executable, "scripts/build_release.py", "."], root=worktree, env=env)

            release, stage, version, release_name = expected_release(worktree)
            sha256(release)
            if not stage.is_dir() or stage.is_symlink():
                raise RuntimeError("FINAL_EXACT_RELEASE_STAGE_INVALID")

            run(
                [sys.executable, "scripts/verify_release.py", str(release), "--full"],
                root=worktree,
                env=env,
            )
            verify_worktree_source_unchanged(worktree, source_sha, {staged_archive.relative_to(worktree).as_posix()})
            if git_source(root) != source_sha:
                raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_CHANGED_DURING_BUILD")

            published_release_path = exact_release_publication_path(root, source_sha, release.name)
            published_checksum_path = exact_release_publication_path(root, source_sha, release.name + ".sha256")
            published_release = publish_verified_file(release, published_release_path)
            published_checksum=publish_verified_file(release.with_name(release.name + ".sha256"), published_checksum_path)
            verify_release_checksum(published_release,published_checksum,"FINAL_EXACT_RELEASE_PUBLISHED")
            evidence = build_evidence(
                root, published_release, stage, admitted, source_sha, version, release_name
            )
        finally:
            remove_exact_worktree(root, worktree)

    if git_source(root) != source_sha:
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_CHANGED_DURING_BUILD")
    if evidence is None:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_NOT_BUILT")
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
    result={
        "authority": evidence["authority"],
        "sourceCommitSHA": evidence["sourceCommitSHA"],
        "releaseArchive": evidence["releaseArchive"],
        "releaseArchiveSha256": evidence["releaseArchiveSha256"],
        "fullVerifierPass": evidence["fullVerifierPass"],
        "physicalCertified": evidence["physicalCertified"],
    }
    result.update(final_git_handoff(args.root.resolve(),admit_output_path(args.root.resolve(),args.out),evidence))
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
