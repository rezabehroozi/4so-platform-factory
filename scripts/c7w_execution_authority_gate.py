#!/usr/bin/env python3
"""Fail closed if the local C7W execution/reconciliation owner graph drifts."""
from __future__ import annotations

import argparse
from pathlib import Path

AUTHORITY="C7W_EXECUTION_AUTHORITY_GATE_V1"
REQUIRED_FILES=(
    "scripts/c7w_preflight.py",
    "scripts/prepare_c7w_oauth_bindings.py",
    "scripts/reconcile_c7w_trusted_clients.py",
    "scripts/run_mcp_external_interop.py",
    "scripts/prepare_mcp_external_client_execution.py",
)


def read(root:Path,rel:str,errors:list[tuple[str,str]])->str:
    path=root/rel
    if path.is_symlink() or not path.is_file():
        errors.append(("C7W_EXECUTION_OWNER_MISSING",rel))
        return ""
    try:
        return path.read_text(encoding="utf-8",errors="strict")
    except (OSError,UnicodeDecodeError) as exc:
        errors.append(("C7W_EXECUTION_OWNER_INVALID",f"{rel}:{exc}"))
        return ""


def validate(root:Path)->list[tuple[str,str]]:
    root=root.resolve(); errors:list[tuple[str,str]]=[]
    source={rel:read(root,rel,errors) for rel in REQUIRED_FILES}
    preflight=source["scripts/c7w_preflight.py"]
    materializer=source["scripts/prepare_c7w_oauth_bindings.py"]
    reconciler=source["scripts/reconcile_c7w_trusted_clients.py"]
    runner=source["scripts/run_mcp_external_interop.py"]
    packet=source["scripts/prepare_mcp_external_client_execution.py"]

    reconciliation_markers=(
        'AUTHORITY="MCP_EXTERNAL_TRUSTED_CLIENT_RECONCILIATION_V1"',
        "def reconcile_plan",
        "def reconcile(",
        "before=fetch_rows",
        "create_row(",
        "after=fetch_rows",
        '"status=409"',
        "def preflight_command",
    )
    missing=[marker for marker in reconciliation_markers if marker not in reconciler]
    if missing:
        errors.append(("C7W_RECONCILIATION_OWNER_INVALID",",".join(missing)))

    if (
        "def trusted_client_reconcile_command" not in preflight
        or "scripts/reconcile_c7w_trusted_clients.py" not in preflight
        or '"RECONCILE_C7W_TRUSTED_CLIENTS"' not in preflight
    ):
        errors.append(("C7W_RECONCILIATION_WIRING_INVALID","scripts/c7w_preflight.py"))

    if (
        ".state/private/c7w-oauth-client-bindings.json" not in materializer
        or "followup_preflight_command" not in materializer
    ):
        errors.append(("C7W_OAUTH_MATERIALIZER_OWNER_INVALID","scripts/prepare_c7w_oauth_bindings.py"))

    if (
        'AUTHORITY="MCP_EXTERNAL_LOCAL_EXECUTION_RUNNER_V1"' not in runner
        or "def runner_command" not in runner
    ):
        errors.append(("C7W_LOCAL_RUNNER_OWNER_INVALID","scripts/run_mcp_external_interop.py"))

    if 'AUTHORITY="MCP_EXTERNAL_CLIENT_EXECUTION_PACKET_V1"' not in packet:
        errors.append(("C7W_EXECUTION_PACKET_OWNER_INVALID","scripts/prepare_mcp_external_client_execution.py"))

    return errors


def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--root",type=Path,default=Path(".")); args=p.parse_args()
    errors=validate(args.root)
    if errors:
        for code,detail in errors:
            print(f"{code} {detail}")
        return 1
    print(f"C7W_EXECUTION_AUTHORITY_GATE_PASS authority={AUTHORITY}")
    return 0


if __name__=="__main__": raise SystemExit(main())
