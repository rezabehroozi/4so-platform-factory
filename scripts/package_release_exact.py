#!/usr/bin/env python3
"""Run the release packager inside the exact native release tool environment."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

try:
    import build_release_binaries as release_binary_builder
except ModuleNotFoundError:
    from scripts import build_release_binaries as release_binary_builder

AUTHORITY="EXACT_RELEASE_PACKAGER_EXECUTION_V1"


def require_exact_toolchain(root:Path)->tuple[str,dict[str,str]]:
    root=root.resolve()
    release_binary_builder.require_release_build_host()
    go_binary=str(os.environ.get("GO") or "go").strip() or "go"
    env=release_binary_builder.release_build_environment()
    toolchain_spec=release_binary_builder.admitted_toolchain_spec(root)
    release_binary_builder.require_go_binary_identity(root,go_binary,env,toolchain_spec)
    release_binary_builder.require_cgo_toolchain_identity(root,env,toolchain_spec)
    env["GO"]=go_binary
    return go_binary,env


def release_tool_authority(root:Path)->tuple[str,dict[str,str]]:
    return require_exact_toolchain(root)


def run_packager(root:Path)->int:
    root=root.resolve()
    _,env=release_tool_authority(root)
    proc=subprocess.run(
        [sys.executable,"scripts/build_release.py","."],
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.returncode:
        raise RuntimeError(f"EXACT_RELEASE_PACKAGER_FAILED rc={proc.returncode}")
    return 0


def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,default=Path("."))
    args=parser.parse_args()
    rc=run_packager(args.root)
    print(f"EXACT_RELEASE_PACKAGER_PASS authority={AUTHORITY}")
    return rc


if __name__=="__main__":
    raise SystemExit(main())
