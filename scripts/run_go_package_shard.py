#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys

AUTHORITY = "AUTOPILOT_STAGE_SHARD_AUTHORITY_V2"


def run_bounded(command: list[str], *, env: dict[str, str], timeout: int) -> int:
    process = subprocess.Popen(
        command,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        start_new_session=(os.name == "posix"),
    )
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        else:
            process.terminate()
        try:
            output, _ = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
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
    args = parser.parse_args()
    if args.shards < 1 or args.shard < 1 or args.shard > args.shards:
        raise SystemExit("invalid shard")
    if args.race and args.vet:
        raise SystemExit("--race and --vet are mutually exclusive")
    packages = subprocess.check_output(["go", "list", "./..."], text=True).splitlines()
    selected = [pkg for i, pkg in enumerate(packages) if i % args.shards == args.shard - 1]
    mode = "race" if args.race else "vet" if args.vet else "unit"
    print(
        f"GO_PACKAGE_SHARD authority={AUTHORITY} mode={mode} shard={args.shard}/{args.shards} packages={len(selected)}",
        flush=True,
    )
    env = os.environ.copy()
    env["CGO_ENABLED"] = "1"
    for pkg in selected:
        if args.vet:
            command = ["go", "vet", pkg]
        else:
            go_timeout = "180s" if args.race else "120s"
            command = ["go", "test"] + (["-race"] if args.race else []) + ["-count=1", f"-timeout={go_timeout}", pkg]
        print("+", " ".join(command), flush=True)
        rc = run_bounded(command, env=env, timeout=args.command_timeout)
        if rc:
            return rc
    print(f"GO_PACKAGE_SHARD_PASS authority={AUTHORITY} mode={mode} shard={args.shard}/{args.shards}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
