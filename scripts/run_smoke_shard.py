#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys

AUTHORITY = "AUTOPILOT_STAGE_SHARD_AUTHORITY_V2"

SMOKES = [
    ("smoke_api.py", ["./bin/platform-api"]),
    ("smoke_ai_control_plane.py", ["./bin/platform-api"]),
    ("smoke_blueprint_lifecycle.py", ["./bin/platform-api"]),
    ("smoke_blueprint_overlay_ownership.py", ["./bin/platform-api"]),
    ("smoke_blueprint_authoring_parity.py", ["./bin/platform-api"]),
    ("smoke_compatibility_matrix.py", ["./bin/platform-api"]),
    ("smoke_catalog_governance.py", ["./bin/platform-api"]),
    ("smoke_plan_safety.py", ["./bin/platform-api"]),
    ("smoke_planning_impact.py", ["./bin/platform-api"]),
    ("smoke_evidence_collection_completion.py", ["./bin/platform-api"]),
    ("smoke_rollback_feasibility.py", []),
    ("smoke_operation_retry_recovery.py", ["./bin/platform-api"]),
    ("smoke_operation_step_trace_authority.py", ["./bin/platform-api"]),
    ("smoke_compensation_orchestration.py", ["./bin/platform-api"]),
    ("smoke_owner_destructive_recovery.py", ["./bin/platform-api"]),
    ("smoke_tenant_resize_protected_delete.py", ["./bin/platform-api"]),
    ("smoke_cluster_maintenance.py", ["./bin/platform-api"]),
    ("smoke_target_node_lifecycle.py", ["./bin/platform-api"]),
    ("smoke_oidc_group_authz_audit.py", ["./bin/platform-api"]),
    ("smoke_git_credential_reference.py", ["./bin/platform-api"]),
    ("smoke_git_pull_request_lkg.py", ["./bin/platform-api"]),
    ("smoke_git_three_way_drift.py", ["./bin/platform-api"]),
    ("smoke_upgrade_control.py", ["./bin/platform-api"]),
    ("smoke_notification_routing.py", ["./bin/platform-api"]),
    ("smoke_executable_catalog.py", ["./bin/platform-api"]),
    ("smoke_external_catalog_bundle.py", ["./bin/platformctl"]),
    ("smoke_canonical_gateway_api.py", ["./bin/platform-api"]),
    ("smoke_canonical_snapshot_controller.py", ["./bin/platform-api"]),
    ("smoke_image_mirror_runtime.py", ["./bin/platform-api", "./bin/platformctl"]),
    ("smoke_runtime_certification.py", ["./bin/platform-api"]),
    ("smoke_service_account_token.py", ["./bin/platform-api"]),
    ("smoke_agent_mtls.py", ["./bin/platform-api", "./bin/platformctl"]),
    ("smoke_fleet_support.py", ["./bin/platform-api", "./bin/platformctl"]),
    ("smoke_workload_logs.py", ["./bin/platform-api"]),
    ("smoke_installer.py", ["./bin/platform-installer", "./bin/platformctl"]),
    ("smoke_installer_host.py", ["./bin/platformctl", "./bin/platform-installer"]),
    ("smoke_installer_remote.py", ["./bin/platformctl", "./bin/platform-installer"]),
]


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
        print(f"SMOKE_COMMAND_TIMEOUT timeout={timeout} command={' '.join(command)}", flush=True)
        return 124
    if output:
        sys.stdout.write(output)
    return process.returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shards", type=int, default=4)
    parser.add_argument("--command-timeout", type=int, default=600)
    args = parser.parse_args()
    if args.shards < 1 or args.shard < 1 or args.shard > args.shards:
        raise SystemExit("invalid shard")

    if args.shards != 4:
        selected = [row for i, row in enumerate(SMOKES) if i % args.shards == args.shard - 1]
    else:
        installer = [row for row in SMOKES if row[0].startswith("smoke_installer")]
        regular = [row for row in SMOKES if not row[0].startswith("smoke_installer")]
        selected = installer if args.shard == 4 else [row for i, row in enumerate(regular) if i % 3 == args.shard - 1]

    env = os.environ.copy()
    env.setdefault("PLATFORM_FACTORY_DEVELOPMENT_MODE", "true")
    print(
        f"SMOKE_SHARD authority={AUTHORITY} shard={args.shard}/{args.shards} tests={len(selected)}",
        flush=True,
    )
    for script, script_args in selected:
        command = ["python3", str(Path("scripts") / script), *script_args]
        print("+", " ".join(command), flush=True)
        rc = run_bounded(command, env=env, timeout=args.command_timeout)
        if rc:
            return rc
    print(f"SMOKE_SHARD_PASS authority={AUTHORITY} shard={args.shard}/{args.shards}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
