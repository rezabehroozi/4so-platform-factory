#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import signal
import shutil
import subprocess
import sys

AUTHORITY = "AUTOPILOT_STAGE_SHARD_AUTHORITY_V2"
OWNER_DEDUP_AUTHORITY = "AUTOPILOT_OWNER_UNIT_DEDUP_V1"
INSTALLER_OWNER_PACKAGES = frozenset({
    "platform.4so.io/factory/cmd/platformctl",
    "platform.4so.io/factory/cmd/platform-installer",
    "platform.4so.io/factory/internal/bootstrap",
    "platform.4so.io/factory/internal/hostdeployment",
    "platform.4so.io/factory/internal/remotebootstrap",
})


def _process_group_kwargs() -> dict:
    if os.name=="nt":
        return {"creationflags":getattr(subprocess,"CREATE_NEW_PROCESS_GROUP",0)}
    return {"start_new_session":True}


def _terminate_tree(process: subprocess.Popen[str], *, force: bool) -> None:
    if process.poll() is not None:
        return
    if os.name=="posix":
        try:
            os.killpg(process.pid,signal.SIGKILL if force else signal.SIGTERM)
        except ProcessLookupError:
            pass
        return
    taskkill=shutil.which("taskkill")
    if taskkill:
        args=[taskkill,"/PID",str(process.pid),"/T"]
        if force:
            args.append("/F")
        subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
    if process.poll() is None:
        try:
            process.kill() if force else process.terminate()
        except OSError:
            pass


def run_bounded(command: list[str], *, env: dict[str, str], timeout: int) -> int:
    process = subprocess.Popen(
        command,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        **_process_group_kwargs(),
    )
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_tree(process,force=False)
        try:
            output, _ = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            _terminate_tree(process,force=True)
            output, _ = process.communicate()
        if output:
            sys.stdout.write(output)
        print(f"GO_PACKAGE_COMMAND_TIMEOUT timeout={timeout} command={' '.join(command)}", flush=True)
        return 124
    if output:
        sys.stdout.write(output)
    return process.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a deterministic bounded shard of go list ./...")
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shards", type=int, default=4)
    parser.add_argument("--race", action="store_true")
    parser.add_argument("--vet", action="store_true")
    parser.add_argument("--command-timeout", type=int, default=240)
    parser.add_argument("--exclude-installer-owner", action="store_true", help="unit mode only: skip packages already proven by installer-go-owner-tests")
    args = parser.parse_args()
    if args.shards < 1 or args.shard < 1 or args.shard > args.shards:
        raise SystemExit("invalid shard")
    if args.race and args.vet:
        raise SystemExit("--race and --vet are mutually exclusive")
    if args.exclude_installer_owner and (args.race or args.vet):
        raise SystemExit("--exclude-installer-owner is unit-mode only; vet/race remain exhaustive")
    go_command = str(os.environ.get("GO") or "go").strip() or "go"
    packages = subprocess.check_output([go_command, "list", "./..."], text=True).splitlines()
    excluded = INSTALLER_OWNER_PACKAGES if args.exclude_installer_owner else frozenset()
    candidates = [pkg for pkg in packages if pkg not in excluded]
    selected = [pkg for i, pkg in enumerate(candidates) if i % args.shards == args.shard - 1]
    mode = "race" if args.race else "vet" if args.vet else "unit"
    print(
        f"GO_PACKAGE_SHARD authority={AUTHORITY} mode={mode} shard={args.shard}/{args.shards} packages={len(selected)} "
        f"ownerDedupAuthority={OWNER_DEDUP_AUTHORITY if args.exclude_installer_owner else 'none'} ownerExcluded={len(excluded)}",
        flush=True,
    )
    env = os.environ.copy()
    env["CGO_ENABLED"] = "1"
    for pkg in selected:
        if args.vet:
            command = [go_command, "vet", pkg]
        else:
            go_timeout = "180s" if args.race else "120s"
            command = [go_command, "test"] + (["-race"] if args.race else []) + ["-count=1", f"-timeout={go_timeout}", pkg]
        print("+", " ".join(command), flush=True)
        rc = run_bounded(command, env=env, timeout=args.command_timeout)
        if rc:
            return rc
    print(f"GO_PACKAGE_SHARD_PASS authority={AUTHORITY} mode={mode} shard={args.shard}/{args.shards}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
