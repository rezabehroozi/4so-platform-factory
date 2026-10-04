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
import platform
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
    import ui_browser_authority as browser_authority
    import c9_stable_snapshot as stable_snapshot
except ModuleNotFoundError:
    from scripts import final_exact_release_admission as admission
    from scripts import ui_browser_authority as browser_authority
    from scripts import c9_stable_snapshot as stable_snapshot

AUTHORITY = "FINAL_EXACT_RELEASE_SEAL_V1"
EXECUTION_AUTHORITY = "LOCAL_EXACT_RELEASE_SEAL_V1"
FULL_VERIFIER_AUTHORITY = "CHECKPOINT_SAFE_FULL_VERIFIER_V2"
TOOLCHAIN_AUTHORITY = "RELEASE_BUILD_TOOLCHAIN_AUTHORITY_V1"
SOURCE_WORKSPACE_AUTHORITY = "GIT_DETACHED_EXACT_SHA_WORKTREE_V1"
ENVIRONMENT_PREFLIGHT_AUTHORITY = "FINAL_EXACT_RELEASE_ENVIRONMENT_PREFLIGHT_V1"
FINAL_EVIDENCE_KEYS = {
    "apiVersion","kind","authority","sourceExecutionAuthority","sourceWorkspaceAuthority",
    "sourceCommitSHA","version","releaseName","releaseArchive","releaseArchivePath",
    "releaseArchiveSha256","releaseArchiveBytes","artifactManifestSha256",
    "buildProvenanceSha256","sbomSha256","admissionAuthority",
    "applianceDistributionSha256","mcpExternalInteropSha256","fullVerifierAuthority",
    "fullVerifierPass","physicalCertified",
}


def normalized_machine()->str:
    raw=str(platform.machine() or "").strip().lower()
    if raw in {"x86_64","amd64"}:
        return "amd64"
    if raw in {"aarch64","arm64"}:
        return "arm64"
    return raw or "unknown"


def require_exact_release_host()->None:
    if not sys.platform.startswith("linux") or normalized_machine()!="amd64":
        raise RuntimeError("FINAL_EXACT_RELEASE_LINUX_AMD64_HOST_REQUIRED")


def exact_release_environment(go: Path) -> dict[str, str]:
    env=os.environ.copy()
    dangerous_exact={
        "CC","CXX","GCCGO","GOROOT","GOTOOLDIR",
        "LD_PRELOAD","LD_LIBRARY_PATH","LIBRARY_PATH","COMPILER_PATH",
        "CPATH","C_INCLUDE_PATH","CPLUS_INCLUDE_PATH",
        "PKG_CONFIG","PKG_CONFIG_PATH","PKG_CONFIG_LIBDIR","PKG_CONFIG_SYSROOT_DIR",
        "PYTHONHOME","PYTHONPATH","PYTHONSTARTUP","PYTHONINSPECT",
        "BASH_ENV","ENV","MAKEFLAGS","MFLAGS","MAKELEVEL","MAKEFILES","MAKEOVERRIDES",
        "SOURCE_COMMIT","AR","NM","RANLIB","STRIP","GCC_EXEC_PREFIX","DEPENDENCIES_OUTPUT",
    }
    for key in list(env):
        if key in dangerous_exact or key.startswith("CGO_") or key.startswith("DYLD_") or key.startswith("GO") or key.startswith("GIT_"):
            env.pop(key,None)
    env["PATH"]="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    env["LANG"]="C"
    env["LC_ALL"]="C"
    env["TZ"]="UTC"
    env["GO"]=str(go)
    env["GOTOOLCHAIN"]="local"
    env["GOENV"]="off"
    env["GOWORK"]="off"
    env["GOFLAGS"]=""
    env["GOPROXY"]="off"
    env["GOSUMDB"]="off"
    env["GOPRIVATE"]=""
    env["GONOPROXY"]=""
    env["GONOSUMDB"]=""
    env["PYTHON"]=sys.executable
    env["PYTHONDONTWRITEBYTECODE"]="1"
    env["PYTHONNOUSERSITE"]="1"
    return env


def clean_git_env()->dict[str,str]:
    env=os.environ.copy()
    for key in list(env):
        if key.startswith("GIT_"):
            env.pop(key,None)
    return env


def stable_file_fingerprint(path:Path,label:str)->tuple[str,int]:
    return stable_snapshot.stable_file_fingerprint(path,label)


def verify_release_archive_exact_source(
    root:Path,
    release:Path,
    source_sha:str,
    *,
    expected_digest:str,
    expected_size:int,
)->None:
    stable_snapshot.verify_release_archive_exact_source(
        root,
        release,
        source_sha,
        expected_digest=expected_digest,
        expected_size=expected_size,
    )


def sha256(path: Path) -> str:
    return stable_file_fingerprint(path,"FINAL_EXACT_RELEASE")[0]


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
    git_env=clean_git_env()
    top = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=root,
        env=git_env,
        text=True,
        capture_output=True,
        check=False,
    )
    if top.returncode != 0 or Path(top.stdout.strip()).resolve() != root:
        raise RuntimeError("FINAL_EXACT_RELEASE_GIT_ROOT_INVALID")
    branch = subprocess.run(
        ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
        cwd=root,
        env=git_env,
        text=True,
        capture_output=True,
        check=False,
    )
    if branch.returncode != 0 or branch.stdout.strip() != "main":
        raise RuntimeError("FINAL_EXACT_RELEASE_BRANCH_NOT_MAIN")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        env=git_env,
        text=True,
        capture_output=True,
        check=False,
    )
    if head.returncode != 0 or len(head.stdout.strip()) != 40:
        raise RuntimeError("FINAL_EXACT_RELEASE_GIT_HEAD_INVALID")
    indexed = subprocess.run(
        ["git", "ls-files", "-v", "-z"],
        cwd=root,
        env=git_env,
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
        env=git_env,
        text=True,
        capture_output=True,
        check=False,
    )
    if dirty.returncode != 0 or dirty.stdout.strip():
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_NOT_EXACT_HEAD")
    return head.stdout.strip()


def exact_source_json(root:Path,source_sha:str,relpath:str,label:str,*,max_bytes:int=1024*1024)->tuple[dict,str]:
    root=root.resolve()
    source_sha=str(source_sha or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}",source_sha):
        raise RuntimeError(f"{label}_SOURCE_SHA_INVALID")
    pure=PurePosixPath(str(relpath or ""))
    if pure.is_absolute() or not pure.parts or ".." in pure.parts or any(part in {"","."} for part in pure.parts):
        raise RuntimeError(f"{label}_SOURCE_PATH_INVALID")
    git_env=clean_git_env()
    top=subprocess.run(["git","rev-parse","--show-toplevel"],cwd=root,env=git_env,text=True,capture_output=True,check=False)
    if top.returncode!=0 or Path(top.stdout.strip()).resolve()!=root:
        raise RuntimeError(f"{label}_SOURCE_REPOSITORY_INVALID")
    proc=subprocess.run(
        ["git","cat-file","blob",f"{source_sha}:{pure.as_posix()}"],
        cwd=root,
        env=git_env,
        capture_output=True,
        check=False,
    )
    raw=proc.stdout if proc.returncode==0 else b""
    if proc.returncode!=0 or not raw or len(raw)>max_bytes:
        raise RuntimeError(f"{label}_SOURCE_OBJECT_INVALID")
    try:
        value=json.loads(raw.decode("utf-8",errors="strict"))
    except (UnicodeDecodeError,json.JSONDecodeError) as exc:
        raise RuntimeError(f"{label}_SOURCE_OBJECT_INVALID") from exc
    if not isinstance(value,dict):
        raise RuntimeError(f"{label}_SOURCE_OBJECT_INVALID")
    return value,"sha256:"+hashlib.sha256(raw).hexdigest()


def exact_source_toolchain_lock(root:Path,source_sha:str)->tuple[dict,str]:
    source_sha=str(source_sha or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}",source_sha):
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_SHA_INVALID")
    return exact_source_json(
        root,
        source_sha,
        "lab/release-build-toolchain-lock.json",
        "FINAL_EXACT_RELEASE_TOOLCHAIN_LOCK",
    )


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
    got_digest,got_size=stable_file_fingerprint(archive,"FINAL_EXACT_RELEASE_TOOLCHAIN_ARCHIVE")
    if got_size != wanted_size or got_digest.removeprefix("sha256:") != wanted_sha:
        raise RuntimeError("FINAL_EXACT_RELEASE_TOOLCHAIN_ARCHIVE_MISMATCH")
    return archive, exact


def exact_release_environment_preflight(root:Path,toolchain_lock:dict|None=None)->dict:
    root=root.resolve()
    blockers=[]
    required_host="linux-amd64-exact-toolchain"
    observed_architecture=normalized_machine()
    required_architecture="amd64"
    if not sys.platform.startswith("linux") or observed_architecture!=required_architecture:
        blockers.append("FINAL_EXACT_RELEASE_LINUX_AMD64_HOST_REQUIRED")

    lock_path=root/"lab"/"release-build-toolchain-lock.json"
    archive_path=""
    archive_ready=False
    try:
        lock=toolchain_lock if toolchain_lock is not None else json.loads(lock_path.read_text(encoding="utf-8"))
        archive,_=safe_toolchain_archive(root,lock)
        archive_path=str(archive)
        archive_ready=True
    except (OSError,UnicodeDecodeError,json.JSONDecodeError,RuntimeError,ValueError) as exc:
        blockers.append(str(exc).split()[0] if str(exc).strip() else "FINAL_EXACT_RELEASE_TOOLCHAIN_PREFLIGHT_FAILED")

    browser_manifest=str(os.environ.get(browser_authority.ENV_AUTHORITY) or "").strip()
    browser_ready=False
    browser_version=""
    if not browser_manifest:
        blockers.append("UI_BROWSER_AUTHORITY_MISSING")
    else:
        try:
            _,browser_doc=browser_authority.validate_ui_browser_authority(Path(browser_manifest))
            browser_ready=True
            browser_version=str(browser_doc.get("version") or "")
        except (OSError,ValueError) as exc:
            blockers.append(str(exc).split(":")[0].split()[0] if str(exc).strip() else "UI_BROWSER_AUTHORITY_INVALID")

    exact_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    missing_tools=[name for name in ("gcc","ld","ldd","readelf") if shutil.which(name,path=exact_path) is None]
    for name in missing_tools:
        blockers.append("FINAL_EXACT_RELEASE_HOST_TOOL_MISSING_"+name.upper().replace("-","_"))

    blockers=list(dict.fromkeys(blockers))
    return {
        "authority":ENVIRONMENT_PREFLIGHT_AUTHORITY,
        "ready":not blockers,
        "requiredHost":required_host,
        "observedArchitecture":observed_architecture,
        "requiredArchitecture":required_architecture,
        "toolchainArchiveReady":archive_ready,
        "toolchainArchivePath":archive_path,
        "browserAuthorityReady":browser_ready,
        "browserAuthorityPath":browser_manifest,
        "browserVersion":browser_version,
        "missingHostTools":missing_tools,
        "blockers":blockers,
        "physicalCertified":False,
    }


def require_exact_release_environment(root:Path,toolchain_lock:dict|None=None)->dict:
    result=exact_release_environment_preflight(root,toolchain_lock=toolchain_lock)
    if not result["ready"]:
        raise RuntimeError("FINAL_EXACT_RELEASE_ENVIRONMENT_BLOCKED "+",".join(result["blockers"]))
    return result


def extract_toolchain(archive: Path, exact: dict, workspace: Path) -> Path:
    admitted_archive_size=int(exact.get("archiveSize") or 0)
    admitted_archive_sha=str(exact.get("archiveSha256") or "")
    if admitted_archive_size<=0 or not re.fullmatch(r"[0-9a-f]{64}",admitted_archive_sha):
        raise RuntimeError("FINAL_EXACT_RELEASE_TOOLCHAIN_LOCK_INVALID")
    max_members=65536
    max_member_size=256*1024*1024
    max_total_size=max(512*1024*1024,admitted_archive_size*8)
    try:
        verified=stable_snapshot.verified_open(
            archive,
            "FINAL_EXACT_RELEASE_TOOLCHAIN_EXTRACTION_ARCHIVE",
            expected_digest="sha256:"+admitted_archive_sha,
            expected_size=admitted_archive_size,
        )
        with verified as archive_file, tarfile.open(fileobj=archive_file,mode="r:gz") as tf:
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
    except RuntimeError:
        raise
    except (OSError,tarfile.TarError) as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_TOOLCHAIN_ARCHIVE_INVALID") from exc

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
    git_env=clean_git_env()
    target = parent / "source"
    proc = subprocess.run(
        ["git", "worktree", "add", "--detach", str(target), source_sha],
        cwd=root,
        env=git_env,
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
            env=git_env,
            text=True,
            capture_output=True,
            check=False,
        )
        indexed = subprocess.run(
            ["git", "ls-files", "-v", "-z"],
            cwd=target,
            env=git_env,
            capture_output=True,
            check=False,
        )
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=target,
            env=git_env,
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
        subprocess.run(["git", "worktree", "remove", "--force", str(target)], cwd=root,env=git_env,stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        raise


def remove_exact_worktree(root: Path, target: Path) -> None:
    git_env=clean_git_env()
    proc = subprocess.run(
        ["git", "worktree", "remove", "--force", str(target)],
        cwd=root,
        env=git_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"FINAL_EXACT_RELEASE_WORKTREE_CLEANUP_FAILED {proc.stdout.strip()}")
    subprocess.run(["git", "worktree", "prune"], cwd=root,env=git_env,stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


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
    stable_snapshot.publish_verified_file(
        archive,
        target,
        expected_digest="sha256:"+wanted_sha,
        expected_size=wanted_size,
    )
    target.chmod(0o644)
    target_digest,target_size=stable_file_fingerprint(target,"FINAL_EXACT_RELEASE_WORKTREE_TOOLCHAIN")
    if target_size!=wanted_size or target_digest!="sha256:"+wanted_sha:
        raise RuntimeError("FINAL_EXACT_RELEASE_WORKTREE_TOOLCHAIN_MISMATCH")
    return target


def verify_worktree_source_unchanged(worktree: Path, source_sha: str, allowed_untracked: set[str] | None = None) -> None:
    git_env=clean_git_env()
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=worktree,env=git_env,text=True,capture_output=True,check=False)
    indexed = subprocess.run(["git", "ls-files", "-v", "-z"], cwd=worktree,env=git_env,capture_output=True,check=False)
    tracked_raw = subprocess.run(["git", "ls-files", "-z"], cwd=worktree,env=git_env,capture_output=True,check=False)
    status = subprocess.run(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=worktree,env=git_env,capture_output=True,check=False)
    index_valid = indexed.returncode == 0 and all(not raw or raw.startswith(b"H ") for raw in indexed.stdout.split(b"\x00"))
    allowed=set(allowed_untracked or ())
    try:
        tracked={raw.decode("utf-8",errors="strict") for raw in tracked_raw.stdout.split(b"\x00") if raw}
        dirty=set()
        for raw in status.stdout.split(b"\x00"):
            if not raw:
                continue
            if len(raw)<4 or raw[2:3]!=b" ":
                dirty.add("<invalid-status>")
                continue
            dirty.add(raw[3:].decode("utf-8",errors="strict"))
    except UnicodeDecodeError:
        dirty={"<invalid-utf8-status>"}
    unexpected={path for path in dirty if path not in allowed}
    allowed_valid=all(path not in tracked for path in allowed)
    if (
        head.returncode != 0
        or head.stdout.strip() != source_sha
        or not index_valid
        or tracked_raw.returncode != 0
        or status.returncode != 0
        or unexpected
        or not allowed_valid
    ):
        raise RuntimeError("FINAL_EXACT_RELEASE_WORKTREE_SOURCE_CHANGED")


def exact_release_publication_path(root: Path, source_sha: str, filename: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{40}",source_sha):
        raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_SOURCE_SHA_INVALID")
    if not filename or Path(filename).name!=filename:
        raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_FILENAME_INVALID")
    return root/"release"/"exact-sha"/source_sha/filename


def publish_verified_file(
    source:Path,
    target:Path,
    *,
    expected_digest:str|None=None,
    expected_size:int|None=None,
)->Path:
    return stable_snapshot.publish_verified_file(
        source,
        target,
        expected_digest=expected_digest,
        expected_size=expected_size,
    )


def seal_publication_directory(path:Path)->None:
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_DIRECTORY_INVALID")
    path.chmod(0o555)
    if path.stat().st_mode&0o222:
        raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_DIRECTORY_WRITABLE")


def require_publication_directory_read_only(path:Path,label:str)->None:
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError(f"{label}_INVALID")
    if path.stat().st_mode&0o222:
        raise RuntimeError(f"{label}_WRITABLE")


def require_published_read_only(path:Path,label:str)->None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size<=0:
        raise RuntimeError(f"{label}_INVALID")
    if path.stat().st_mode&0o222:
        raise RuntimeError(f"{label}_WRITABLE")


def verify_release_checksum(release:Path,checksum:Path,label:str)->None:
    if checksum.is_symlink() or not checksum.is_file():
        raise RuntimeError(f"{label}_CHECKSUM_INVALID")
    try:
        raw=stable_snapshot.stable_file_bytes(checksum,label+"_CHECKSUM",max_bytes=4096).decode("utf-8",errors="strict")
    except (RuntimeError,UnicodeDecodeError) as exc:
        raise RuntimeError(f"{label}_CHECKSUM_INVALID") from exc
    expected=sha256(release).removeprefix("sha256:")
    if raw!=f"{expected}  {release.name}\n":
        raise RuntimeError(f"{label}_CHECKSUM_INVALID")


def build_evidence(root: Path, release: Path, stage: Path, admitted: dict, source_sha: str, version: str, release_name: str) -> dict:
    manifest = stage / "ARTIFACT-MANIFEST.json"
    provenance = stage / "BUILD-PROVENANCE.json"
    sbom = stage / "SBOM.spdx.json"
    for path in (manifest, provenance, sbom):
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"FINAL_EXACT_RELEASE_METADATA_MISSING {path.name}")
    published=exact_release_publication_path(root,source_sha,release.name)
    if release.resolve()!=published.resolve():
        raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_PATH_INVALID")
    require_published_read_only(release,"FINAL_EXACT_RELEASE_ARTIFACT")
    require_publication_directory_read_only(release.parent,"FINAL_EXACT_RELEASE_PUBLICATION_DIRECTORY")
    release_digest,release_size=stable_file_fingerprint(release,"FINAL_EXACT_RELEASE_ARTIFACT")
    prefix=f"4so-platform-factory-{version}-{release_name}/"
    expected_embedded={
        prefix+"ARTIFACT-MANIFEST.json":sha256(manifest),
        prefix+"BUILD-PROVENANCE.json":sha256(provenance),
        prefix+"SBOM.spdx.json":sha256(sbom),
    }
    try:
        with zipfile.ZipFile(release,"r") as archive:
            names=set(archive.namelist())
            for name,wanted in expected_embedded.items():
                if name not in names:
                    raise RuntimeError("FINAL_EXACT_RELEASE_ARCHIVE_METADATA_MISSING")
                got="sha256:"+hashlib.sha256(archive.read(name)).hexdigest()
                if got!=wanted:
                    raise RuntimeError("FINAL_EXACT_RELEASE_ARCHIVE_METADATA_DRIFT")
    except (zipfile.BadZipFile,KeyError,OSError) as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_ARCHIVE_INVALID") from exc
    release_after_digest,release_after_size=stable_file_fingerprint(release,"FINAL_EXACT_RELEASE_ARTIFACT")
    if (release_after_digest,release_after_size)!=(release_digest,release_size):
        raise RuntimeError("FINAL_EXACT_RELEASE_ARCHIVE_CHANGED_DURING_EVIDENCE")
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
        "releaseArchiveSha256": release_digest,
        "releaseArchiveBytes": release_size,
        "artifactManifestSha256": expected_embedded[prefix+"ARTIFACT-MANIFEST.json"],
        "buildProvenanceSha256": expected_embedded[prefix+"BUILD-PROVENANCE.json"],
        "sbomSha256": expected_embedded[prefix+"SBOM.spdx.json"],
        "admissionAuthority": admission.AUTHORITY,
        "applianceDistributionSha256": admitted["applianceDistributionSha256"],
        "mcpExternalInteropSha256": admitted["mcpExternalInteropSha256"],
        "fullVerifierAuthority": FULL_VERIFIER_AUTHORITY,
        "fullVerifierPass": True,
        "physicalCertified": False,
    }


def verify_evidence_publication_binding(root:Path,evidence:dict)->Path:
    root=root.resolve()
    source_sha=str(evidence.get("sourceCommitSHA") or "").strip().lower()
    archive_name=str(evidence.get("releaseArchive") or "").strip()
    if not re.fullmatch(r"[0-9a-f]{40}",source_sha) or not archive_name or Path(archive_name).name!=archive_name:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_PUBLICATION_PATH_INVALID")
    expected_rel=PurePosixPath("release")/"exact-sha"/source_sha/archive_name
    if evidence.get("releaseArchivePath")!=expected_rel.as_posix():
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_PUBLICATION_PATH_INVALID")
    release=root.joinpath(*expected_rel.parts)
    require_publication_directory_read_only(release.parent,"FINAL_EXACT_RELEASE_EVIDENCE_PUBLICATION_DIRECTORY")
    require_published_read_only(release,"FINAL_EXACT_RELEASE_EVIDENCE_PUBLICATION_ARCHIVE")
    digest,size=stable_file_fingerprint(release,"FINAL_EXACT_RELEASE_EVIDENCE_PUBLICATION_ARCHIVE")
    if evidence.get("releaseArchiveSha256")!=digest or evidence.get("releaseArchiveBytes")!=size:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_PUBLICATION_DRIFT")
    checksum=release.with_name(release.name+".sha256")
    require_published_read_only(checksum,"FINAL_EXACT_RELEASE_EVIDENCE_PUBLICATION_CHECKSUM")
    try:
        verify_release_checksum(release,checksum,"FINAL_EXACT_RELEASE_EVIDENCE_PUBLICATION")
    except RuntimeError as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_PUBLICATION_DRIFT") from exc
    return release


def admit_output_path(root:Path,out:Path)->Path:
    root=root.resolve(); raw=out if out.is_absolute() else root/out
    raw=Path(os.path.abspath(raw))
    for parent in reversed(raw.parents):
        if parent.exists() and (parent.is_symlink() or not parent.is_dir()):
            raise RuntimeError("FINAL_EXACT_RELEASE_OUTPUT_PARENT_SYMLINK_FORBIDDEN")
    if raw.exists() and raw.is_symlink():
        raise RuntimeError("FINAL_EXACT_RELEASE_OUTPUT_SYMLINK_FORBIDDEN")
    raw.parent.mkdir(parents=True,exist_ok=True)
    if raw.parent.is_symlink() or not raw.parent.is_dir():
        raise RuntimeError("FINAL_EXACT_RELEASE_OUTPUT_PARENT_INVALID")
    return raw


def atomic_write_json(path: Path, value: dict) -> None:
    path=admit_output_path(path.parent.resolve(),path.name)
    if path.exists() or path.is_symlink():
        raise RuntimeError("FINAL_EXACT_RELEASE_ALREADY_SEALED")
    raw=(json.dumps(value,indent=2,sort_keys=True)+"\n").encode("utf-8")
    fd,temp_name=tempfile.mkstemp(prefix="."+path.name+".tmp.",dir=path.parent)
    temp=Path(temp_name)
    try:
        with os.fdopen(fd,"wb") as fh:
            fh.write(raw); fh.flush(); os.fsync(fh.fileno())
        try:
            os.link(temp,path,follow_symlinks=False)
        except FileExistsError as exc:
            raise RuntimeError("FINAL_EXACT_RELEASE_ALREADY_SEALED") from exc
        directory_fd=os.open(path.parent,os.O_RDONLY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    finally:
        if temp.exists(): temp.unlink()


def validate_final_evidence_lineage(root:Path,sealed_sha:str,current_sha:str,out:Path)->None:
    sealed_sha=str(sealed_sha or "").strip().lower(); current_sha=str(current_sha or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}",sealed_sha) or not re.fullmatch(r"[0-9a-f]{40}",current_sha):
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_SOURCE_INVALID")
    if sealed_sha==current_sha:
        return
    git_env=clean_git_env()
    ancestor=subprocess.run(["git","merge-base","--is-ancestor",sealed_sha,current_sha],cwd=root,env=git_env,capture_output=True,check=False)
    if ancestor.returncode!=0:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_SOURCE_NOT_ANCESTOR")
    diff=subprocess.run(["git","diff","--name-only","-z",sealed_sha+".."+current_sha],cwd=root,env=git_env,capture_output=True,check=False)
    if diff.returncode!=0:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_SOURCE_DELTA_UNAVAILABLE")
    changed={raw.decode("utf-8",errors="strict") for raw in diff.stdout.split(b"\x00") if raw}
    try:
        rel=out.resolve().relative_to(root).as_posix()
    except ValueError as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_PATH_OUTSIDE_REPOSITORY") from exc
    if changed!={rel}:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_SOURCE_DELTA_NOT_EVIDENCE_ONLY")


def git_source_for_resume(root: Path, out: Path) -> str:
    git_env=clean_git_env()
    top = subprocess.run(["git","rev-parse","--show-toplevel"],cwd=root,env=git_env,text=True,capture_output=True,check=False)
    branch = subprocess.run(["git","symbolic-ref","--quiet","--short","HEAD"],cwd=root,env=git_env,text=True,capture_output=True,check=False)
    head = subprocess.run(["git","rev-parse","HEAD"],cwd=root,env=git_env,text=True,capture_output=True,check=False)
    indexed = subprocess.run(["git","ls-files","-v","-z"],cwd=root,env=git_env,capture_output=True,check=False)
    if top.returncode!=0 or Path(top.stdout.strip()).resolve()!=root or branch.returncode!=0 or branch.stdout.strip()!="main" or head.returncode!=0 or not re.fullmatch(r"[0-9a-f]{40}",head.stdout.strip()):
        raise RuntimeError("FINAL_EXACT_RELEASE_GIT_SOURCE_INVALID")
    if indexed.returncode!=0 or any(raw and not raw.startswith(b"H ") for raw in indexed.stdout.split(b"\x00")):
        raise RuntimeError("FINAL_EXACT_RELEASE_GIT_INDEX_FLAGS_FORBIDDEN")
    try:
        out_rel=out.resolve().relative_to(root).as_posix()
    except ValueError as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_OUTPUT_OUTSIDE_REPOSITORY") from exc
    status=subprocess.run(["git","status","--porcelain=v1","-z","--untracked-files=all"],cwd=root,env=git_env,capture_output=True,check=False)
    if status.returncode!=0:
        raise RuntimeError("FINAL_EXACT_RELEASE_GIT_STATUS_UNAVAILABLE")
    dirty=[]
    for raw in status.stdout.split(b"\x00"):
        if not raw: continue
        if len(raw)<4 or raw[2:3]!=b" ":
            raise RuntimeError("FINAL_EXACT_RELEASE_GIT_STATUS_INVALID")
        dirty.append(raw[3:].decode("utf-8",errors="strict"))
    if set(dirty)-{out_rel}:
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_NOT_EXACT_HEAD")
    return head.stdout.strip()


def final_git_handoff(root:Path,out:Path,evidence:dict)->dict:
    root=root.resolve()
    try:
        persisted,_=admission.mcp_contract.load_with_sha256(out,"FINAL_EXACT_RELEASE_EXISTING_EVIDENCE",max_bytes=1024*1024)
    except RuntimeError as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_HANDOFF_INVALID") from exc
    if persisted!=evidence:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_HANDOFF_DRIFT")
    verify_evidence_publication_binding(root,evidence)
    current_sha=git_source_for_resume(root,out)
    sealed_sha=str(evidence.get("sourceCommitSHA") or "").strip().lower()
    validate_final_evidence_lineage(root,sealed_sha,current_sha,out)
    rel=out.resolve().relative_to(root).as_posix()
    git_env=clean_git_env()
    tracked=subprocess.run(["git","ls-files","--error-unmatch",rel],cwd=root,env=git_env,text=True,capture_output=True,check=False)
    status=subprocess.run(["git","status","--porcelain=v1","--",rel],cwd=root,env=git_env,text=True,capture_output=True,check=False)
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


def require_valid_final_admission(admitted:dict)->dict:
    if (
        not isinstance(admitted,dict)
        or admitted.get("authority")!=admission.AUTHORITY
        or admitted.get("admitted") is not True
        or admitted.get("physicalCertified") is not False
    ):
        raise RuntimeError("FINAL_EXACT_RELEASE_ADMISSION_INVALID")
    return admitted


def verify_existing_release_full(root: Path, source_sha: str, release: Path) -> None:
    state_dir=root/".state"
    if state_dir.is_symlink() or (state_dir.exists() and not state_dir.is_dir()):
        raise RuntimeError("FINAL_EXACT_RELEASE_STATE_DIR_INVALID")
    state_dir.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="4so-final-release-resume-toolchain-",dir=state_dir) as tool_td, tempfile.TemporaryDirectory(prefix="4so-final-release-resume-source-",dir=state_dir) as source_td:
        worktree=prepare_exact_worktree(root,source_sha,Path(source_td))
        try:
            lock,_=exact_source_toolchain_lock(root,source_sha)
            archive,exact=safe_toolchain_archive(root,lock)
            staged_archive=stage_toolchain_archive(archive,exact,worktree)
            go=extract_toolchain(staged_archive,exact,Path(tool_td))
            env=exact_release_environment(go)
            release_snapshot=stable_file_fingerprint(release,"FINAL_EXACT_RELEASE_RESUME_SOURCE_ARCHIVE")
            verify_release_archive_exact_source(
                worktree,
                release,
                source_sha,
                expected_digest=release_snapshot[0],
                expected_size=release_snapshot[1],
            )
            run([sys.executable,"scripts/verify_release_build_toolchain.py","--require-admitted","--archive",str(staged_archive)],root=worktree,env=env)
            run([sys.executable,"scripts/verify_release.py",str(release),"--full"],root=worktree,env=env)
            release_after=stable_file_fingerprint(release,"FINAL_EXACT_RELEASE_RESUME_SOURCE_ARCHIVE")
            if release_after!=release_snapshot:
                raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_ARCHIVE_CHANGED_DURING_FULL_VERIFY")
            verify_worktree_source_unchanged(worktree,source_sha,{staged_archive.relative_to(worktree).as_posix()})
        finally:
            remove_exact_worktree(root,worktree)


def resume_existing_evidence(root: Path, out: Path) -> dict:
    if out.is_symlink() or not out.is_file() or out.stat().st_size<=0 or out.stat().st_size>1024*1024:
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_INVALID")
    current_sha=git_source_for_resume(root,out)
    try:
        evidence,evidence_snapshot_sha256=admission.mcp_contract.load_with_sha256(out,"FINAL_EXACT_RELEASE_EXISTING_EVIDENCE",max_bytes=1024*1024)
    except RuntimeError as exc:
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
    admitted=require_valid_final_admission(exact_source_admission(root,source_sha))
    for key in ("applianceDistributionSha256","mcpExternalInteropSha256"):
        if evidence.get(key)!=admitted.get(key):
            raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_ADMISSION_DRIFT")
    toolchain_lock,_=exact_source_toolchain_lock(root,source_sha)
    require_exact_release_host()
    require_exact_release_environment(root,toolchain_lock=toolchain_lock)
    for key in ("releaseArchiveSha256","artifactManifestSha256","buildProvenanceSha256","sbomSha256","applianceDistributionSha256","mcpExternalInteropSha256"):
        value=evidence.get(key)
        if not isinstance(value,str) or len(value)!=71 or not value.startswith("sha256:") or any(ch not in "0123456789abcdef" for ch in value[7:]):
            raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_DIGEST_INVALID")
    if type(evidence.get("releaseArchiveBytes")) is not int or evidence["releaseArchiveBytes"]<=0:
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_ARCHIVE_SIZE_INVALID")
    release=root.joinpath(*expected_rel.parts)
    require_publication_directory_read_only(release.parent,"FINAL_EXACT_RELEASE_EXISTING_PUBLICATION_DIRECTORY")
    require_published_read_only(release,"FINAL_EXACT_RELEASE_EXISTING_ARCHIVE")
    digest,size=stable_file_fingerprint(release,"FINAL_EXACT_RELEASE_EXISTING_ARCHIVE")
    if evidence.get("releaseArchiveSha256")!=digest or evidence.get("releaseArchiveBytes")!=size:
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_ARCHIVE_DRIFT")
    checksum=release.with_name(release.name+".sha256")
    require_published_read_only(checksum,"FINAL_EXACT_RELEASE_EXISTING_CHECKSUM")
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
    digest_after,size_after=stable_file_fingerprint(release,"FINAL_EXACT_RELEASE_EXISTING_ARCHIVE")
    if (digest_after,size_after)!=(digest,size):
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_ARCHIVE_CHANGED_DURING_RESUME")
    try:
        verify_release_checksum(release,checksum,"FINAL_EXACT_RELEASE_EXISTING")
    except RuntimeError as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_CHECKSUM_DRIFT") from exc
    try:
        _,evidence_after_sha256=admission.mcp_contract.load_with_sha256(out,"FINAL_EXACT_RELEASE_EXISTING_EVIDENCE",max_bytes=1024*1024)
    except RuntimeError as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_CHANGED_DURING_RESUME") from exc
    if evidence_after_sha256!=evidence_snapshot_sha256:
        raise RuntimeError("FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_CHANGED_DURING_RESUME")
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
    initial_admitted=require_valid_final_admission(exact_source_admission(root,source_sha))
    toolchain_lock,_=exact_source_toolchain_lock(root,source_sha)
    require_exact_release_host()
    require_exact_release_environment(root,toolchain_lock=toolchain_lock)

    state_dir = root / ".state"
    if state_dir.is_symlink() or (state_dir.exists() and not state_dir.is_dir()):
        raise RuntimeError("FINAL_EXACT_RELEASE_STATE_DIR_INVALID")
    state_dir.mkdir(exist_ok=True)

    evidence = None
    with tempfile.TemporaryDirectory(prefix="4so-final-release-toolchain-", dir=state_dir) as tool_td, tempfile.TemporaryDirectory(prefix="4so-final-release-source-", dir=state_dir) as source_td:
        worktree = prepare_exact_worktree(root, source_sha, Path(source_td))
        try:
            admitted=require_valid_final_admission(admission.verify(worktree,expected_source_sha=source_sha))
            if admitted!=initial_admitted:
                raise RuntimeError("FINAL_EXACT_RELEASE_ADMISSION_DRIFT")
            lock=toolchain_lock
            archive, exact = safe_toolchain_archive(root, lock)
            staged_archive = stage_toolchain_archive(archive, exact, worktree)
            go = extract_toolchain(staged_archive, exact, Path(tool_td))
            env = exact_release_environment(go)

            run(
                [sys.executable, "scripts/verify_release_build_toolchain.py", "--require-admitted", "--archive", str(staged_archive)],
                root=worktree,
                env=env,
            )
            run(
                [
                    sys.executable,
                    "scripts/build_release_binaries.py",
                    "--root",
                    ".",
                    "--go",
                    str(go),
                    "--source-commit",
                    source_sha,
                ],
                root=worktree,
                env=env,
            )
            run([sys.executable, "scripts/package_release_exact.py", "--root", "."], root=worktree, env=env)

            release, stage, version, release_name = expected_release(worktree)
            packaged_snapshot=stable_file_fingerprint(release,"FINAL_EXACT_RELEASE_PACKAGED_SOURCE_ARCHIVE")
            verify_release_archive_exact_source(
                worktree,
                release,
                source_sha,
                expected_digest=packaged_snapshot[0],
                expected_size=packaged_snapshot[1],
            )
            if not stage.is_dir() or stage.is_symlink():
                raise RuntimeError("FINAL_EXACT_RELEASE_STAGE_INVALID")

            run(
                [sys.executable, "scripts/verify_release.py", str(release), "--full"],
                root=worktree,
                env=env,
            )
            verified_release_digest,verified_release_size=stable_file_fingerprint(release,"FINAL_EXACT_RELEASE_VERIFIED_ARCHIVE")
            if (verified_release_digest,verified_release_size)!=packaged_snapshot:
                raise RuntimeError("FINAL_EXACT_RELEASE_ARCHIVE_CHANGED_DURING_FULL_VERIFY")
            checksum_source=release.with_name(release.name+".sha256")
            verify_release_checksum(release,checksum_source,"FINAL_EXACT_RELEASE_VERIFIED")
            verified_checksum_digest,verified_checksum_size=stable_file_fingerprint(checksum_source,"FINAL_EXACT_RELEASE_VERIFIED_CHECKSUM")
            verify_worktree_source_unchanged(worktree, source_sha, {staged_archive.relative_to(worktree).as_posix()})
            if git_source(root) != source_sha:
                raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_CHANGED_DURING_BUILD")

            published_release_path = exact_release_publication_path(root, source_sha, release.name)
            published_checksum_path = exact_release_publication_path(root, source_sha, release.name + ".sha256")
            published_release = publish_verified_file(
                release,
                published_release_path,
                expected_digest=verified_release_digest,
                expected_size=verified_release_size,
            )
            published_checksum=publish_verified_file(
                checksum_source,
                published_checksum_path,
                expected_digest=verified_checksum_digest,
                expected_size=verified_checksum_size,
            )
            published_before=stable_file_fingerprint(published_release,"FINAL_EXACT_RELEASE_PUBLISHED_ARCHIVE")
            if published_before!=(verified_release_digest,verified_release_size):
                raise RuntimeError("FINAL_EXACT_RELEASE_PUBLISHED_ARCHIVE_DRIFT")
            verify_release_checksum(published_release,published_checksum,"FINAL_EXACT_RELEASE_PUBLISHED")
            run(
                [sys.executable,"scripts/verify_release.py",str(published_release),"--full"],
                root=worktree,
                env=env,
            )
            published_after=stable_file_fingerprint(published_release,"FINAL_EXACT_RELEASE_PUBLISHED_ARCHIVE")
            if published_after!=published_before:
                raise RuntimeError("FINAL_EXACT_RELEASE_PUBLISHED_ARCHIVE_CHANGED_DURING_VERIFY")
            verify_release_checksum(published_release,published_checksum,"FINAL_EXACT_RELEASE_PUBLISHED")
            seal_publication_directory(published_release.parent)
            evidence = build_evidence(
                root, published_release, stage, admitted, source_sha, version, release_name
            )
        finally:
            remove_exact_worktree(root, worktree)

    if git_source(root) != source_sha:
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_CHANGED_DURING_BUILD")
    if evidence is None:
        raise RuntimeError("FINAL_EXACT_RELEASE_EVIDENCE_NOT_BUILT")
    verify_evidence_publication_binding(root,evidence)
    atomic_write_json(out, evidence)
    return evidence


def canonical_preflight_exit_code(root:Path)->int:
    root=root.resolve()
    canonical=Path(__file__).resolve().with_name("c9_preflight.py")
    proc=subprocess.run(
        [sys.executable,str(canonical),"--root",str(root),"--preflight"],
        cwd=root,
        env=clean_git_env(),
        stdout=None,
        stderr=None,
        check=False,
    )
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("lab/final-exact-release-evidence.json"),
    )
    parser.add_argument("--preflight",action="store_true")
    args=parser.parse_args()
    if args.preflight:
        return canonical_preflight_exit_code(args.root)
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
    result["workingDirectory"]=str(args.root.resolve())
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
