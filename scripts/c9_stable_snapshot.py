#!/usr/bin/env python3
"""Stable file snapshot primitives for the C9 exact-release owner."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tempfile
import zipfile

C9_SOURCE_EXCLUDE=frozenset({".git","bin","dist","release","__pycache__",".pytest_cache",".state",".tmpbin"})
C9_GENERATED_METADATA=frozenset({"ARTIFACT-MANIFEST.json","BUILD-PROVENANCE.json","SBOM.spdx.json","DERIVED-AGENT-KNOWLEDGE.json"})
C9_RELEASE_BINARIES=frozenset({
    "platform-api","platformctl","platform-installer","platform-agent","platform-probe",
    "virtual-cluster-renderer","openchoreo-runtime","dapr-runtime",
})
C9_EXACT_PUBLICATION_LABELS=frozenset({
    "FINAL_EXACT_RELEASE_EXISTING_ARCHIVE",
    "FINAL_EXACT_RELEASE_EVIDENCE_PUBLICATION_ARCHIVE",
    "FINAL_EXACT_RELEASE_PUBLISHED_ARCHIVE",
    "FINAL_EXACT_RELEASE_ARTIFACT",
})


def _open_no_symlink_chain(absolute:Path,flags:int)->int:
    secure=(
        os.name=="posix"
        and hasattr(os,"O_DIRECTORY")
        and hasattr(os,"O_NOFOLLOW")
        and os.open in os.supports_dir_fd
    )
    if not secure:
        return os.open(absolute,flags)
    parts=absolute.parts
    if len(parts)<2 or not absolute.is_absolute():
        return os.open(absolute,flags)
    directory_flags=os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|os.O_DIRECTORY|os.O_NOFOLLOW
    directory_fd=os.open(parts[0],directory_flags)
    try:
        for part in parts[1:-1]:
            next_fd=os.open(part,directory_flags,dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd=next_fd
        return os.open(parts[-1],flags,dir_fd=directory_fd)
    finally:
        os.close(directory_fd)


def _open_stable_regular(path:Path,label:str)->tuple[Path,int,os.stat_result]:
    absolute=Path(os.path.abspath(path))
    flags=os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_BINARY",0)|getattr(os,"O_NOFOLLOW",0)
    try:
        fd=_open_no_symlink_chain(absolute,flags)
    except (OSError,TypeError,NotImplementedError) as exc:
        raise RuntimeError(f"{label}_FILE_INVALID") from exc
    try:
        before=os.fstat(fd)
        named=os.stat(absolute,follow_symlinks=False)
    except OSError as exc:
        os.close(fd)
        raise RuntimeError(f"{label}_FILE_INVALID") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or before.st_size<=0
        or not os.path.samestat(before,named)
    ):
        os.close(fd)
        raise RuntimeError(f"{label}_FILE_INVALID")
    return absolute,fd,before


def _require_same_file(absolute:Path,fd:int,before:os.stat_result,label:str)->os.stat_result:
    try:
        after=os.fstat(fd)
        named=os.stat(absolute,follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError(f"{label}_FILE_CHANGED_DURING_READ") from exc
    before_meta=(before.st_size,before.st_mtime_ns,before.st_ctime_ns)
    after_meta=(after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    named_meta=(named.st_size,named.st_mtime_ns,named.st_ctime_ns)
    if (
        not stat.S_ISREG(after.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or not os.path.samestat(before,after)
        or not os.path.samestat(after,named)
        or before_meta!=after_meta
        or after_meta!=named_meta
    ):
        raise RuntimeError(f"{label}_FILE_CHANGED_DURING_READ")
    return after


def _fingerprint_fd(fd:int)->tuple[str,int]:
    os.lseek(fd,0,os.SEEK_SET)
    h=hashlib.sha256(); total=0
    while True:
        block=os.read(fd,1024*1024)
        if not block:
            break
        total+=len(block); h.update(block)
    return "sha256:"+h.hexdigest(),total


def stable_file_fingerprint(path:Path,label:str)->tuple[str,int]:
    absolute,fd,before=_open_stable_regular(path,label)
    try:
        digest,total=_fingerprint_fd(fd)
        _require_same_file(absolute,fd,before,label)
        if total!=before.st_size:
            raise RuntimeError(f"{label}_FILE_CHANGED_DURING_READ")
    finally:
        os.close(fd)
    _maybe_verify_exact_publication(path,label,digest,total)
    return digest,total


@contextmanager
def verified_open(
    path:Path,
    label:str,
    *,
    expected_digest:str,
    expected_size:int,
):
    absolute,fd,before=_open_stable_regular(path,label)
    raw=None
    try:
        digest,size=_fingerprint_fd(fd)
        _require_same_file(absolute,fd,before,label)
        if digest!=expected_digest or size!=expected_size:
            raise RuntimeError(f"{label}_SNAPSHOT_MISMATCH")
        os.lseek(fd,0,os.SEEK_SET)
        raw=os.fdopen(fd,"rb",buffering=0,closefd=False)
        yield raw
        raw.seek(0)
        after_digest,after_size=_fingerprint_fd(fd)
        _require_same_file(absolute,fd,before,label)
        if after_digest!=expected_digest or after_size!=expected_size:
            raise RuntimeError(f"{label}_SNAPSHOT_MISMATCH")
        os.lseek(fd,0,os.SEEK_SET)
    finally:
        if raw is not None:
            raw.close()
        os.close(fd)


def stable_file_bytes(path:Path,label:str,*,max_bytes:int)->bytes:
    absolute,fd,before=_open_stable_regular(path,label)
    if before.st_size>max_bytes:
        os.close(fd)
        raise RuntimeError(f"{label}_FILE_INVALID")
    chunks=[]; total=0
    try:
        while True:
            block=os.read(fd,min(1024*1024,max_bytes+1-total))
            if not block:
                break
            chunks.append(block); total+=len(block)
            if total>max_bytes:
                raise RuntimeError(f"{label}_FILE_INVALID")
        _require_same_file(absolute,fd,before,label)
        if total!=before.st_size:
            raise RuntimeError(f"{label}_FILE_CHANGED_DURING_READ")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _clean_git_env()->dict[str,str]:
    env=os.environ.copy()
    for key in list(env):
        if key.startswith("GIT_"):
            env.pop(key,None)
    return env


def _exact_git_tree(root:Path,source_sha:str)->tuple[dict[str,tuple[str,str]],str]:
    root=root.resolve(); source_sha=str(source_sha or "").strip().lower()
    if len(source_sha)!=40 or any(ch not in "0123456789abcdef" for ch in source_sha):
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_SHA_INVALID")
    env=_clean_git_env()
    top=subprocess.run(["git","rev-parse","--show-toplevel"],cwd=root,env=env,text=True,capture_output=True,check=False)
    fmt=subprocess.run(["git","rev-parse","--show-object-format"],cwd=root,env=env,text=True,capture_output=True,check=False)
    tree=subprocess.run(["git","ls-tree","-r","-z","--full-tree",source_sha],cwd=root,env=env,capture_output=True,check=False)
    if top.returncode!=0 or Path(top.stdout.strip()).resolve()!=root or fmt.returncode!=0 or tree.returncode!=0:
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_TREE_UNAVAILABLE")
    object_format=fmt.stdout.strip().lower()
    if object_format not in {"sha1","sha256"}:
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_OBJECT_FORMAT_INVALID")
    rows={}
    for raw in tree.stdout.split(b"\x00"):
        if not raw:
            continue
        try:
            meta,path_raw=raw.split(b"\t",1)
            mode,obj_type,oid=meta.decode("ascii",errors="strict").split(" ")
            path_text=path_raw.decode("utf-8",errors="strict")
        except (ValueError,UnicodeDecodeError) as exc:
            raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_TREE_ENTRY_INVALID") from exc
        pure=PurePosixPath(path_text)
        if pure.is_absolute() or not pure.parts or ".." in pure.parts or any(part in {"","."} for part in pure.parts):
            raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_TREE_ENTRY_INVALID")
        if any(part in C9_SOURCE_EXCLUDE for part in pure.parts) or path_text in C9_GENERATED_METADATA:
            continue
        if pure.name.startswith(".durable-"):
            raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_TREE_ENTRY_INVALID")
        if obj_type!="blob" or mode not in {"100644","100755"}:
            raise RuntimeError(f"FINAL_EXACT_RELEASE_SOURCE_TREE_ENTRY_INVALID {path_text}")
        if path_text in rows:
            raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_TREE_DUPLICATE")
        rows[path_text]=(oid,mode)
    if not rows:
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_TREE_EMPTY")
    return rows,object_format


def _git_blob_oid(raw:bytes,object_format:str)->str:
    h=hashlib.new(object_format)
    h.update(f"blob {len(raw)}\0".encode("ascii")); h.update(raw)
    return h.hexdigest()


def verify_release_archive_exact_source(
    root:Path,
    release:Path,
    source_sha:str,
    *,
    expected_digest:str,
    expected_size:int,
)->None:
    tree,object_format=_exact_git_tree(root,source_sha)
    try:
        with verified_open(
            release,
            "FINAL_EXACT_RELEASE_SOURCE_ARCHIVE",
            expected_digest=expected_digest,
            expected_size=expected_size,
        ) as raw, zipfile.ZipFile(raw,"r") as archive:
            raw_names=archive.namelist()
            if len(raw_names)!=len(set(raw_names)):
                raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_ARCHIVE_DUPLICATE_PATH")
            names=set(raw_names)
            roots={name.split("/",1)[0] for name in names if "/" in name and name.split("/",1)[0]}
            if len(roots)!=1:
                raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_ARCHIVE_ROOT_INVALID")
            prefix=next(iter(roots))+"/"
            expected_source_names={prefix+rel for rel in tree}
            allowed_generated={prefix+name for name in C9_GENERATED_METADATA}
            allowed_binaries={prefix+"bin/linux-amd64/"+name for name in C9_RELEASE_BINARIES}
            unexpected=sorted(names-expected_source_names-allowed_generated-allowed_binaries)
            if unexpected:
                raise RuntimeError(f"FINAL_EXACT_RELEASE_SOURCE_EXTRA_FILE {unexpected[0]}")
            for rel,(wanted_oid,wanted_mode) in tree.items():
                archive_name=prefix+rel
                if archive_name not in names:
                    raise RuntimeError(f"FINAL_EXACT_RELEASE_SOURCE_FILE_MISSING {rel}")
                info=archive.getinfo(archive_name)
                payload=archive.read(archive_name)
                if _git_blob_oid(payload,object_format)!=wanted_oid:
                    raise RuntimeError(f"FINAL_EXACT_RELEASE_SOURCE_BLOB_DRIFT {rel}")
                unix_mode=(info.external_attr>>16)&0xFFFF
                if info.create_system!=3 or stat.S_IFMT(unix_mode) not in (0,stat.S_IFREG):
                    raise RuntimeError(f"FINAL_EXACT_RELEASE_SOURCE_TYPE_DRIFT {rel}")
                actual_mode=stat.S_IMODE(unix_mode)
                expected_mode=0o755 if wanted_mode=="100755" else 0o644
                if actual_mode!=expected_mode:
                    raise RuntimeError(f"FINAL_EXACT_RELEASE_SOURCE_MODE_DRIFT {rel}")
    except RuntimeError:
        raise
    except (zipfile.BadZipFile,KeyError,OSError) as exc:
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_ARCHIVE_INVALID") from exc


def _exact_publication_context(path:Path)->tuple[Path,str]|None:
    absolute=Path(os.path.abspath(path))
    if absolute.suffix!=".zip":
        return None
    source_dir=absolute.parent
    exact_dir=source_dir.parent
    release_dir=exact_dir.parent
    if exact_dir.name!="exact-sha" or release_dir.name!="release":
        return None
    source_sha=source_dir.name.lower()
    if len(source_sha)!=40 or any(ch not in "0123456789abcdef" for ch in source_sha):
        return None
    return release_dir.parent.resolve(),source_sha


def _maybe_verify_exact_publication(path:Path,label:str,digest:str,size:int)->None:
    if label not in C9_EXACT_PUBLICATION_LABELS:
        return
    context=_exact_publication_context(path)
    if context is None:
        return
    root,source_sha=context
    verify_release_archive_exact_source(
        root,
        Path(path),
        source_sha,
        expected_digest=digest,
        expected_size=size,
    )


def _source_drift_error(target:Path)->str:
    target_posix=target.as_posix()
    if "/vendor/toolchains/" in "/"+target_posix.lstrip("/"):
        return "FINAL_EXACT_RELEASE_WORKTREE_TOOLCHAIN_MISMATCH"
    return "FINAL_EXACT_RELEASE_PUBLICATION_SOURCE_DRIFT"


def publish_verified_file(
    source:Path,
    target:Path,
    *,
    expected_digest:str|None=None,
    expected_size:int|None=None,
)->Path:
    source_digest,source_size=stable_file_fingerprint(source,"FINAL_EXACT_RELEASE_PUBLICATION_SOURCE")
    if (expected_digest is None)!=(expected_size is None):
        raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_EXPECTED_SNAPSHOT_INVALID")
    if expected_digest is not None:
        if expected_digest!=source_digest or expected_size!=source_size:
            raise RuntimeError(_source_drift_error(target))
    wanted_digest=source_digest
    wanted_size=source_size

    target_parent=target.parent
    for parent in reversed(target_parent.parents):
        if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
            raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_PARENT_INVALID")
    if target_parent.is_symlink() or (target_parent.exists() and not target_parent.is_dir()):
        raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_PARENT_INVALID")
    target_parent.mkdir(parents=True,exist_ok=True)
    if target_parent.is_symlink() or not target_parent.is_dir():
        raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_PARENT_INVALID")

    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_file():
            raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_TARGET_INVALID")
        if target.stat().st_mode&0o222:
            raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_ARTIFACT_WRITABLE")
        target_digest,target_size=stable_file_fingerprint(target,"FINAL_EXACT_RELEASE_PUBLICATION_TARGET")
        if target_digest!=wanted_digest or target_size!=wanted_size:
            raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_ARTIFACT_CONFLICT")
        return target

    absolute,source_fd,before=_open_stable_regular(source,"FINAL_EXACT_RELEASE_PUBLICATION_SOURCE")
    try:
        fd,temp_name=tempfile.mkstemp(prefix="."+target.name+".tmp.",dir=target_parent)
        temp=Path(temp_name)
        try:
            h=hashlib.sha256(); copied=0
            with os.fdopen(fd,"wb") as out:
                while True:
                    block=os.read(source_fd,1024*1024)
                    if not block:
                        break
                    copied+=len(block); h.update(block); out.write(block)
                out.flush(); os.fsync(out.fileno())
            _require_same_file(absolute,source_fd,before,"FINAL_EXACT_RELEASE_PUBLICATION_SOURCE")
            copied_digest="sha256:"+h.hexdigest()
            if copied!=wanted_size or copied_digest!=wanted_digest:
                raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_COPY_DRIFT")
            temp_digest,temp_size=stable_file_fingerprint(temp,"FINAL_EXACT_RELEASE_PUBLICATION_TEMP")
            if temp_digest!=wanted_digest or temp_size!=wanted_size:
                raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_COPY_DRIFT")
            temp.chmod(0o444)
            try:
                os.link(temp,target,follow_symlinks=False)
            except FileExistsError:
                if target.is_symlink() or not target.is_file() or target.stat().st_mode&0o222:
                    raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_ARTIFACT_CONFLICT")
                target_digest,target_size=stable_file_fingerprint(target,"FINAL_EXACT_RELEASE_PUBLICATION_TARGET")
                if target_digest!=wanted_digest or target_size!=wanted_size:
                    raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_ARTIFACT_CONFLICT")
            directory_fd=os.open(target_parent,os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return target
        finally:
            if temp.exists():
                temp.unlink()
    finally:
        os.close(source_fd)
