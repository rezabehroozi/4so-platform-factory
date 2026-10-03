#!/usr/bin/env python3
"""Fail closed if the local C7W execution/reconciliation owner graph drifts."""
from __future__ import annotations

import argparse
import ast
from pathlib import Path

AUTHORITY="C7W_EXECUTION_AUTHORITY_GATE_V1"
REQUIRED_FILES=(
    "scripts/c7w_preflight.py",
    "scripts/prepare_c7w_oauth_bindings.py",
    "scripts/reconcile_c7w_trusted_clients.py",
    "scripts/c7w_execution_bindings.py",
    "scripts/c7w_credential_profiles.py",
    "scripts/run_mcp_external_interop.py",
    "scripts/prepare_mcp_external_interop_campaign.py",
    "scripts/seal_mcp_external_interop.py",
    "scripts/prepare_mcp_external_client_execution.py",
    "scripts/finalize_mcp_external_client_receipt.py",
)
PLACEHOLDERS=("<foreign-project-id>","<same-project-operation-id>","<request-created-by-same-subject>")


def read(root:Path,rel:str,errors:list[tuple[str,str]])->str:
    path=root/rel
    if path.is_symlink() or not path.is_file():
        errors.append(("C7W_EXECUTION_OWNER_MISSING",rel)); return ""
    try: return path.read_text(encoding="utf-8",errors="strict")
    except (OSError,UnicodeDecodeError) as exc:
        errors.append(("C7W_EXECUTION_OWNER_INVALID",f"{rel}:{exc}")); return ""


def direct_git_calls_without_env(source:str)->list[int]:
    try:
        tree=ast.parse(source)
    except (SyntaxError,ValueError):
        return [0]
    missing=[]
    for node in ast.walk(tree):
        if not isinstance(node,ast.Call) or not node.args:
            continue
        func=node.func
        command=node.args[0]
        if not (
            isinstance(func,ast.Attribute)
            and func.attr=="run"
            and isinstance(func.value,ast.Name)
            and func.value.id=="subprocess"
            and isinstance(command,ast.List)
            and command.elts
            and isinstance(command.elts[0],ast.Constant)
            and command.elts[0].value=="git"
        ):
            continue
        if not any(keyword.arg=="env" for keyword in node.keywords):
            missing.append(getattr(node,"lineno",0))
    return missing


def validate(root:Path)->list[tuple[str,str]]:
    root=root.resolve(); errors:list[tuple[str,str]]=[]
    source={rel:read(root,rel,errors) for rel in REQUIRED_FILES}
    preflight=source["scripts/c7w_preflight.py"]
    materializer=source["scripts/prepare_c7w_oauth_bindings.py"]
    reconciler=source["scripts/reconcile_c7w_trusted_clients.py"]
    execution=source["scripts/c7w_execution_bindings.py"]
    profiles=source["scripts/c7w_credential_profiles.py"]
    runner=source["scripts/run_mcp_external_interop.py"]
    campaign=source["scripts/prepare_mcp_external_interop_campaign.py"]
    seal=source["scripts/seal_mcp_external_interop.py"]
    packet=source["scripts/prepare_mcp_external_client_execution.py"]
    finalizer=source["scripts/finalize_mcp_external_client_receipt.py"]

    for rel,text in (
        ("scripts/c7w_preflight.py",preflight),
        ("scripts/c7w_execution_bindings.py",execution),
        ("scripts/run_mcp_external_interop.py",runner),
        ("scripts/prepare_mcp_external_interop_campaign.py",campaign),
        ("scripts/seal_mcp_external_interop.py",seal),
    ):
        missing_env=direct_git_calls_without_env(text)
        if missing_env:
            errors.append(("C7W_GIT_ENVIRONMENT_AUTHORITY_INVALID",f"{rel}:lines={','.join(str(x) for x in missing_env)}"))

    reconciliation_markers=(
        'AUTHORITY="MCP_EXTERNAL_TRUSTED_CLIENT_RECONCILIATION_V1"',"def reconcile_plan","def reconcile(","before=fetch_rows","create_row(","after=fetch_rows",'"status=409"',"def preflight_command",
    )
    missing=[marker for marker in reconciliation_markers if marker not in reconciler]
    if missing: errors.append(("C7W_RECONCILIATION_OWNER_INVALID",",".join(missing)))
    if "def trusted_client_reconcile_command" not in preflight or "scripts/reconcile_c7w_trusted_clients.py" not in preflight or '"RECONCILE_C7W_TRUSTED_CLIENTS"' not in preflight:
        errors.append(("C7W_RECONCILIATION_WIRING_INVALID","scripts/c7w_preflight.py"))
    if ".state/private/c7w-oauth-client-bindings.json" not in materializer or "followup_preflight_command" not in materializer:
        errors.append(("C7W_OAUTH_MATERIALIZER_OWNER_INVALID","scripts/prepare_c7w_oauth_bindings.py"))

    execution_markers=(
        'AUTHORITY="MCP_EXTERNAL_EXECUTION_BINDINGS_V1"',
        'DEFAULT_OUTPUT=Path(".state/private/c7w-execution-bindings.json")',
        "def validate_document",
        "def canonical_output_path",
        "def materialize",
        "credentialProfileContractSha256",
    )
    missing=[marker for marker in execution_markers if marker not in execution]
    if missing: errors.append(("C7W_EXECUTION_BINDINGS_OWNER_INVALID",",".join(missing)))
    if 'AUTHORITY="MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1"' not in profiles or "def contract" not in profiles:
        errors.append(("C7W_CREDENTIAL_PROFILE_OWNER_INVALID","scripts/c7w_credential_profiles.py"))
    if (
        "PREPARE_C7W_EXECUTION_BINDINGS" not in preflight
        or "scripts/c7w_execution_bindings.py" not in preflight
        or "executionBindingsSha256" not in preflight
        or "DEFAULT_EXECUTION_BINDING_REL" not in preflight
        or "MCP_EXTERNAL_EXECUTION_BINDINGS_PATH_INVALID" not in preflight
    ):
        errors.append(("C7W_EXECUTION_BINDINGS_WIRING_INVALID","scripts/c7w_preflight.py"))
    if 'AUTHORITY="MCP_EXTERNAL_LOCAL_EXECUTION_RUNNER_V1"' not in runner or "def runner_command" not in runner:
        errors.append(("C7W_LOCAL_RUNNER_OWNER_INVALID","scripts/run_mcp_external_interop.py"))
    if 'AUTHORITY=core.CAMPAIGN_AUTHORITY' not in campaign or "def source_commit_sha" not in campaign:
        errors.append(("C7W_CAMPAIGN_OWNER_INVALID","scripts/prepare_mcp_external_interop_campaign.py"))
    if 'AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROPERABILITY_EVIDENCE_V1"' not in seal or "def validate_evidence_only_source_lineage" not in seal:
        errors.append(("C7W_SEAL_OWNER_INVALID","scripts/seal_mcp_external_interop.py"))
    if (
        'AUTHORITY="MCP_EXTERNAL_CLIENT_EXECUTION_PACKET_V1"' not in packet
        or "executionBindingsSha256" not in packet
        or "credentialProfileContract" not in packet
        or "_binding_snapshot" not in packet
    ):
        errors.append(("C7W_EXECUTION_PACKET_OWNER_INVALID","scripts/prepare_mcp_external_client_execution.py"))
    if "_packet_execution_bindings" not in finalizer or "credentialProfileContractSha256" not in finalizer or "executionBindingsSha256" not in finalizer:
        errors.append(("C7W_RECEIPT_FINALIZER_OWNER_INVALID","scripts/finalize_mcp_external_client_receipt.py"))
    for rel,text in (("scripts/prepare_mcp_external_client_execution.py",packet),("scripts/finalize_mcp_external_client_receipt.py",finalizer)):
        for placeholder in PLACEHOLDERS:
            if placeholder in text:
                errors.append(("C7W_EXECUTION_PLACEHOLDER_FORBIDDEN",f"{rel}:{placeholder}"))
    return errors


def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--root",type=Path,default=Path(".")); args=p.parse_args(); errors=validate(args.root)
    if errors:
        for code,detail in errors: print(f"{code} {detail}")
        return 1
    print(f"C7W_EXECUTION_AUTHORITY_GATE_PASS authority={AUTHORITY}")
    return 0

if __name__=="__main__": raise SystemExit(main())