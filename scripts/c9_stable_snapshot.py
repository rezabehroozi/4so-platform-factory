#!/usr/bin/env python3
"""Stable file snapshot primitives for the C9 exact-release owner."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile


def _open_stable_regular(path:Path,label:str)->tuple[Path,int,os.stat_result]:
    absolute=Path(os.path.abspath(path))
    flags=os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_BINARY",0)|getattr(os,"O_NOFOLLOW",0)
    try:
        fd=os.open(absolute,flags)
    except OSError as exc:
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


def stable_file_fingerprint(path:Path,label:str)->tuple[str,int]:
    absolute,fd,before=_open_stable_regular(path,label)
    h=hashlib.sha256(); total=0
    try:
        while True:
            block=os.read(fd,1024*1024)
            if not block:
                break
            total+=len(block); h.update(block)
        _require_same_file(absolute,fd,before,label)
        if total!=before.st_size:
            raise RuntimeError(f"{label}_FILE_CHANGED_DURING_READ")
        return "sha256:"+h.hexdigest(),total
    finally:
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
            raise RuntimeError("FINAL_EXACT_RELEASE_PUBLICATION_SOURCE_DRIFT")
    wanted_digest=source_digest
    wanted_size=source_size

    target_parent=target.parent
    for parent in reversed(target_parent.parents):
        if parent.exists() and (parent.is_symlink() or not parent.is_dir()):
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

    fd,temp_name=tempfile.mkstemp(prefix="."+target.name+".tmp.",dir=target_parent)
    temp=Path(temp_name)
    try:
        h=hashlib.sha256(); copied=0
        absolute,source_fd,before=_open_stable_regular(source,"FINAL_EXACT_RELEASE_PUBLICATION_SOURCE")
        try:
            with os.fdopen(fd,"wb") as out:
                while True:
                    block=os.read(source_fd,1024*1024)
                    if not block:
                        break
                    copied+=len(block); h.update(block); out.write(block)
                out.flush(); os.fsync(out.fileno())
            _require_same_file(absolute,source_fd,before,"FINAL_EXACT_RELEASE_PUBLICATION_SOURCE")
        finally:
            os.close(source_fd)
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
