#!/usr/bin/env python3
"""Read-only, machine-actionable preflight for real C7W named-client execution."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

try:
    import prepare_mcp_external_interop_campaign as campaign
    import run_mcp_external_interop as runner
    import seal_mcp_external_interop as core
except ModuleNotFoundError:
    from scripts import prepare_mcp_external_interop_campaign as campaign
    from scripts import run_mcp_external_interop as runner
    from scripts import seal_mcp_external_interop as core

AUTHORITY="MCP_EXTERNAL_PREFLIGHT_HANDOFF_V1"


def git_source_commit(root:Path)->str:
    root=Path(os.path.abspath(root))
    proc=subprocess.run(["git","rev-parse","HEAD"],cwd=root,text=True,capture_output=True,check=False)
    value=proc.stdout.strip().lower() if proc.returncode==0 else ""
    if not core.COMMIT.fullmatch(value):
        raise RuntimeError("MCP_EXTERNAL_SOURCE_COMMIT_UNAVAILABLE")
    return value


def root_input_path(root:Path,path:Path)->Path:
    root=Path(os.path.abspath(root))
    raw=Path(path)
    absolute=Path(os.path.abspath(raw if raw.is_absolute() else root/raw))
    try:
        absolute.relative_to(root)
    except ValueError as exc:
        raise RuntimeError("MCP_EXTERNAL_PREFLIGHT_INPUT_PATH_OUTSIDE_ROOT") from exc
    return absolute


def _missing_inputs(endpoint:str,oauth_client_map:Path|None,token_env:str)->list[str]:
    missing=[]
    if not str(endpoint or "").strip():
        missing.append("C7W_MCP_ENDPOINT")
    if oauth_client_map is None:
        missing.append("C7W_OAUTH_CLIENT_MAP")
    token=str(os.getenv(str(token_env or "")) or "").strip()
    if not token or any(ch in token for ch in "\r\n"):
        missing.append(str(token_env or "C7W_PLATFORM_ADMIN_TOKEN"))
    return missing


def _base(*,ready:bool,blockers:list[str])->dict:
    return {
        "authority":AUTHORITY,
        "ready":ready,
        "blockers":blockers,
        "requiredInputs":[],
        "nextActionCode":"",
        "nextCommand":[],
        "physicalCertified":False,
    }


def _failure(code:str,source_sha:str="")->dict:
    out=_base(ready=False,blockers=[code])
    if code.startswith("MCP_EXTERNAL_LOCAL_"):
        out.update({
            "nextActionCode":"RESTORE_C7W_SOURCE_FREEZE",
            "nextCommand":["git","status","--short"],
            "detail":"restore canonical main, repository-root authority and the C7W canonical matrix/evidence-only source boundary before live interoperability work",
        })
    elif code.startswith("MCP_EXTERNAL_PREFLIGHT_INPUT_PATH_"):
        out.update({
            "nextActionCode":"REPAIR_C7W_INPUT_PATHS",
            "detail":"keep private OAuth binding inputs inside the explicit repository root",
        })
    elif code.startswith("MCP_EXTERNAL_OAUTH_BINDINGS_"):
        out.update({
            "nextActionCode":"REPAIR_C7W_OAUTH_BINDINGS",
            "detail":"repair the private four-client OAuth binding document, then rerun C7W preflight",
        })
    elif code=="MCP_EXTERNAL_RUNTIME_SOURCE_DRIFT":
        out.update({
            "nextActionCode":"DEPLOY_C7W_CURRENT_SOURCE",
            "requiredSourceCommitSHA":source_sha,
            "detail":"deploy the exact current main source before external named-client execution",
        })
    elif code.startswith("MCP_EXTERNAL_TRUSTED_CLIENT_"):
        out.update({
            "nextActionCode":"RECONCILE_C7W_TRUSTED_CLIENTS",
            "detail":"make all four Product trusted-client registrations ACTIVE with provider/client identity matching the private OAuth binding document",
        })
    else:
        out.update({
            "nextActionCode":"INSPECT_C7W_LIVE_ENDPOINT",
            "detail":"repair the HTTPS MCP/Product API endpoint or its runtime identity/challenge contract, then rerun C7W preflight",
        })
    return out


def preflight(root:Path,matrix:Path,endpoint:str,oauth_client_map:Path|None,token_env:str)->dict:
    root=Path(os.path.abspath(root))
    missing=_missing_inputs(endpoint,oauth_client_map,token_env)
    if missing:
        out=_base(ready=False,blockers=["MCP_EXTERNAL_PREFLIGHT_INPUTS_MISSING"])
        out.update({
            "nextActionCode":"PROVIDE_C7W_INPUTS",
            "requiredInputs":missing,
            "detail":"provide only the missing C7W endpoint/OAuth/admin-token inputs; token values are never emitted",
        })
        return out

    source_sha=""
    try:
        runner.require_c7w_source_freeze(root)
        matrix_path=runner.require_canonical_matrix(root,matrix)
        oauth_path=root_input_path(root,oauth_client_map)
        source_sha=git_source_commit(root)
        endpoint_value=campaign.endpoint(endpoint)
        matrix_doc=core.load(matrix_path,"MATRIX")
        core.validate_matrix_contract(matrix_doc,"MCP_EXTERNAL_MATRIX")
        bindings,binding_sha=campaign.load_oauth_bindings(oauth_path)
        live=campaign.live_preflight(endpoint_value)
        runtime=campaign.runtime_identity_readback(endpoint_value,token_env,source_sha)
        trusted=campaign.trusted_client_readback(endpoint_value,bindings,token_env)
    except RuntimeError as exc:
        code=str(exc).split()[0] if str(exc).strip() else "MCP_EXTERNAL_PREFLIGHT_UNKNOWN"
        return _failure(code,source_sha)

    state=Path(f".state/c7w-external-interop-{source_sha[:12]}")
    command=[
        sys.executable,
        "scripts/run_mcp_external_interop.py",
        "--matrix",
        str(matrix_path),
        "--state-dir",
        str(state),
        "prepare",
        "--endpoint",
        endpoint_value,
        "--oauth-client-map",
        str(oauth_path),
        "--token-env",
        str(token_env),
        "--source-commit-sha",
        source_sha,
    ]
    out=_base(ready=True,blockers=[])
    out.update({
        "sourceCommitSHA":source_sha,
        "runtimeVersion":runtime["version"],
        "endpoint":endpoint_value,
        "matrixPath":str(matrix_path),
        "oauthClientMapPath":str(oauth_path),
        "oauthClientBindingsSha256":binding_sha,
        "trustedClientCount":len(trusted),
        "livePreflightAuthority":live.get("authority"),
        "stateDir":str(state),
        "workingDirectory":str(root),
        "nextActionCode":"RUN_C7W_PREPARE",
        "nextCommand":command,
        "detail":"C7W exact source, canonical matrix, live endpoint, runtime identity and four trusted-client bindings are ready; create the source-bound campaign from workingDirectory",
    })
    return out


def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,default=Path("."))
    parser.add_argument("--matrix",type=Path,default=runner.CANONICAL_MATRIX_REL)
    parser.add_argument("--endpoint",default=os.environ.get("C7W_MCP_ENDPOINT",""))
    raw_map=os.environ.get("C7W_OAUTH_CLIENT_MAP","").strip()
    parser.add_argument("--oauth-client-map",type=Path,default=Path(raw_map) if raw_map else None)
    parser.add_argument("--token-env",default=os.environ.get("C7W_PLATFORM_ADMIN_TOKEN_ENV","C7W_PLATFORM_ADMIN_TOKEN"))
    args=parser.parse_args()
    result=preflight(args.root,args.matrix,args.endpoint,args.oauth_client_map,args.token_env)
    print(json.dumps(result,sort_keys=True))
    return 0 if result.get("ready") is True else 2


if __name__=="__main__":
    raise SystemExit(main())
