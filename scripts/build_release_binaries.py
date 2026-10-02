#!/usr/bin/env python3
"""Build the exact Linux/amd64 release binary set without Make or shell semantics."""
from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

AUTHORITY="NATIVE_RELEASE_BINARY_BUILD_AUTHORITY_V1"
COMMIT=re.compile(r"^[0-9a-f]{40}$")
VERSION=re.compile(r"^\d+\.\d+\.\d+$")
TARGETS=(
    ("platform-api","./cmd/platform-api","1"),
    ("platformctl","./cmd/platformctl","0"),
    ("platform-installer","./cmd/platform-installer","0"),
    ("platform-agent","./cmd/platform-agent","0"),
    ("platform-probe","./cmd/platform-probe","0"),
    ("virtual-cluster-renderer","./cmd/virtual-cluster-renderer","0"),
    ("openchoreo-runtime","./cmd/openchoreo-runtime","0"),
    ("dapr-runtime","./cmd/dapr-runtime","0"),
)

def git_head(root:Path)->str:
    p=subprocess.run(["git","rev-parse","HEAD"],cwd=root,text=True,capture_output=True,check=False)
    value=p.stdout.strip().lower() if p.returncode==0 else ""
    if not COMMIT.fullmatch(value):
        raise RuntimeError("RELEASE_BINARY_BUILD_SOURCE_SHA_UNAVAILABLE")
    return value

def release_identity(root:Path,source_commit:str="",version:str="")->tuple[str,str]:
    observed_sha=git_head(root)
    wanted_sha=str(source_commit or observed_sha).strip().lower()
    if not COMMIT.fullmatch(wanted_sha) or wanted_sha!=observed_sha:
        raise RuntimeError("RELEASE_BINARY_BUILD_SOURCE_SHA_MISMATCH")
    observed_version=(root/"VERSION").read_text(encoding="utf-8").strip()
    wanted_version=str(version or observed_version).strip()
    if not VERSION.fullmatch(wanted_version) or wanted_version!=observed_version:
        raise RuntimeError("RELEASE_BINARY_BUILD_VERSION_MISMATCH")
    return wanted_sha,wanted_version

def build_plan(root:Path,go_binary:str,source_commit:str,version:str)->list[tuple[str,dict[str,str],list[str]]]:
    ldflags=(
        "-s -w -buildid= "
        f"-X platform.4so.io/factory/internal/buildinfo.Version={version} "
        f"-X platform.4so.io/factory/internal/buildinfo.SourceCommit={source_commit}"
    )
    out_dir=root/"bin"/"linux-amd64"
    plan=[]
    for name,package,cgo in TARGETS:
        env={"GOOS":"linux","GOARCH":"amd64","CGO_ENABLED":cgo}
        argv=[
            go_binary,"build","-trimpath","-buildvcs=false","-ldflags",ldflags,
            "-o",str(out_dir/name),package,
        ]
        plan.append((name,env,argv))
    return plan

def build(root:Path,go_binary:str,source_commit:str="",version:str="")->dict:
    root=root.resolve()
    if not sys.platform.startswith("linux"):
        raise RuntimeError("RELEASE_BINARY_BUILD_LINUX_HOST_REQUIRED")
    source_commit,version=release_identity(root,source_commit,version)
    go_binary=str(go_binary or "").strip()
    if not go_binary:
        raise RuntimeError("RELEASE_BINARY_BUILD_GO_INVALID")
    out_dir=root/"bin"/"linux-amd64"
    if out_dir.is_symlink() or (out_dir.exists() and not out_dir.is_dir()):
        raise RuntimeError("RELEASE_BINARY_BUILD_OUTPUT_DIR_INVALID")
    out_dir.mkdir(parents=True,exist_ok=True)
    for name,extra_env,argv in build_plan(root,go_binary,source_commit,version):
        target=out_dir/name
        if target.is_symlink():
            raise RuntimeError(f"RELEASE_BINARY_BUILD_OUTPUT_SYMLINK {name}")
        env=os.environ.copy(); env.update(extra_env)
        proc=subprocess.run(argv,cwd=root,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=False)
        if proc.returncode!=0:
            raise RuntimeError(f"RELEASE_BINARY_BUILD_FAILED {name} rc={proc.returncode} {(proc.stdout or '').strip()}")
        try:
            info=target.lstat()
        except OSError as exc:
            raise RuntimeError(f"RELEASE_BINARY_BUILD_OUTPUT_MISSING {name}") from exc
        if not stat.S_ISREG(info.st_mode) or target.is_symlink() or info.st_size<=0:
            raise RuntimeError(f"RELEASE_BINARY_BUILD_OUTPUT_INVALID {name}")
    return {
        "authority":AUTHORITY,
        "sourceCommitSHA":source_commit,
        "version":version,
        "target":"linux-amd64",
        "binaryCount":len(TARGETS),
        "binaries":[name for name,_,_ in TARGETS],
    }

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,default=Path("."))
    p.add_argument("--go",default=os.environ.get("GO","go"))
    p.add_argument("--source-commit",default=os.environ.get("SOURCE_COMMIT",""))
    p.add_argument("--version",default="")
    args=p.parse_args()
    result=build(args.root,args.go,args.source_commit,args.version)
    print(
        f"RELEASE_BINARY_BUILD_PASS authority={result['authority']} "
        f"source={result['sourceCommitSHA']} version={result['version']} "
        f"target={result['target']} binaries={result['binaryCount']}"
    )
    return 0

if __name__=="__main__":
    raise SystemExit(main())
