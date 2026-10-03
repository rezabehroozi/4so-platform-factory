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
PRIVATE_INPUT_REL=Path(".state/private")
DEFAULT_OAUTH_BINDING_REL=PRIVATE_INPUT_REL/"c7w-oauth-client-bindings.json"
OAUTH_CLIENT_ID_INPUTS=[f"C7W_{client.upper()}_OAUTH_CLIENT_ID" for client in core.CLIENTS]
PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")
EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")


def git_source_commit(root:Path)->str:
    root=Path(os.path.abspath(root))
    proc=subprocess.run(["git","rev-parse","HEAD"],cwd=root,text=True,capture_output=True,check=False)
    value=proc.stdout.strip().lower() if proc.returncode==0 else ""
    if not core.COMMIT.fullmatch(value):
        raise RuntimeError("MCP_EXTERNAL_SOURCE_COMMIT_UNAVAILABLE")
    return value


def private_input_path(root:Path,path:Path)->Path:
    root=Path(os.path.abspath(root))
    boundary=Path(os.path.abspath(root/PRIVATE_INPUT_REL))
    raw=Path(path)
    absolute=Path(os.path.abspath(raw if raw.is_absolute() else root/raw))
    try:
        absolute.relative_to(boundary)
    except ValueError as exc:
        raise RuntimeError("MCP_EXTERNAL_PRIVATE_INPUT_PATH_INVALID") from exc
    for candidate in (absolute,*absolute.parents):
        if candidate==root:
            break
        if candidate.exists() and candidate.is_symlink():
            raise RuntimeError("MCP_EXTERNAL_PRIVATE_INPUT_PATH_INVALID")
        if candidate==boundary:
            break
    if absolute.is_symlink() or not absolute.is_file():
        raise RuntimeError("MCP_EXTERNAL_PRIVATE_INPUT_PATH_INVALID")
    return absolute


def oauth_binding_materializer_command()->list[str]:
    return [
        sys.executable,
        "scripts/prepare_c7w_oauth_bindings.py",
        "--root",
        ".",
        "--out",
        str(DEFAULT_OAUTH_BINDING_REL),
    ]


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


def _existing_state_handoff(root:Path)->dict|None:
    try:
        source_sha=git_source_commit(root)
    except RuntimeError:
        return None
    progress=root/PROGRESS_REL
    evidence=root/EVIDENCE_REL

    if evidence.exists() or evidence.is_symlink():
        if evidence.is_symlink() or not evidence.is_file():
            out=_base(ready=False,blockers=["MCP_EXTERNAL_CANONICAL_EVIDENCE_INVALID"])
            out.update({
                "sourceCommitSHA":source_sha,
                "workingDirectory":str(root),
                "nextActionCode":"INSPECT_C7W_CANONICAL_EVIDENCE",
                "nextCommand":["git","status","--short","--",str(PROGRESS_REL),str(EVIDENCE_REL)],
                "detail":"canonical final C7W evidence exists at an unsafe path; restore that evidence before any state recovery or new campaign",
            })
            return out
        try:
            handoff=runner.git_handoff(root,evidence,progress)
        except RuntimeError as exc:
            code=str(exc).split()[0] if str(exc).strip() else "MCP_EXTERNAL_CANONICAL_EVIDENCE_INVALID"
            out=_base(ready=False,blockers=[code])
            out.update({
                "sourceCommitSHA":source_sha,
                "workingDirectory":str(root),
                "nextActionCode":"INSPECT_C7W_CANONICAL_EVIDENCE",
                "nextCommand":["git","status","--short","--",str(PROGRESS_REL),str(EVIDENCE_REL)],
                "detail":f"{code}; final C7W evidence exists but cannot produce a safe Git/C9 handoff",
            })
            return out
        action=str(handoff.get("nextActionCode") or "")
        ready=action in {"RUN_C9_SEAL","RUN_C9_ON_EXACT_LINUX_HOST","C9_SEALED"}
        out=_base(ready=ready,blockers=[] if ready else ["MCP_EXTERNAL_CANONICAL_EVIDENCE_REQUIRES_HANDOFF"])
        out.update(handoff)
        out.setdefault("sourceCommitSHA",source_sha)
        out["workingDirectory"]=str(root)
        out["physicalCertified"]=False
        return out

    state=Path(f".state/c7w-external-interop-{source_sha[:12]}")
    absolute=Path(os.path.abspath(root/state))
    artifacts=[rel for rel,path in ((PROGRESS_REL,progress),) if path.exists() or path.is_symlink()]
    if not absolute.exists() and not absolute.is_symlink():
        if not artifacts:
            return None
        out=_base(ready=False,blockers=["MCP_EXTERNAL_LOCAL_STATE_MISSING_WITH_CANONICAL_EVIDENCE"])
        out.update({
            "sourceCommitSHA":source_sha,
            "stateDir":str(state),
            "workingDirectory":str(root),
            "nextActionCode":"RESTORE_C7W_LOCAL_STATE",
            "nextCommand":["git","status","--short","--",*[str(rel) for rel in artifacts]],
            "detail":"canonical C7W progress exists but the source-bound private state directory is missing; restore or inspect local state before any new campaign",
        })
        return out
    if absolute.is_symlink() or not absolute.is_dir():
        out=_base(ready=False,blockers=["MCP_EXTERNAL_LOCAL_STATE_DIR_INVALID"])
        out.update({
            "sourceCommitSHA":source_sha,
            "stateDir":str(state),
            "workingDirectory":str(root),
            "nextActionCode":"INSPECT_C7W_LOCAL_STATE",
            "nextCommand":[],
            "detail":"the source-bound C7W state path exists but is not a safe directory; repair the local state path before campaign recovery",
        })
        return out
    out=_base(ready=False,blockers=["MCP_EXTERNAL_EXISTING_STATE_REQUIRES_STATUS"])
    out.update({
        "sourceCommitSHA":source_sha,
        "stateDir":str(state),
        "workingDirectory":str(root),
        "nextActionCode":"RUN_C7W_STATUS",
        "nextCommand":runner.runner_command(state,"status"),
        "detail":"source-bound C7W state already exists; inspect canonical status/recovery first without re-requesting endpoint, OAuth or token inputs",
    })
    return out


def _failure(code:str,source_sha:str="")->dict:
    out=_base(ready=False,blockers=[code])
    if code.startswith("MCP_EXTERNAL_LOCAL_"):
        out.update({
            "nextActionCode":"RESTORE_C7W_SOURCE_FREEZE",
            "nextCommand":["git","status","--short"],
            "detail":"restore canonical main, repository-root authority and the C7W canonical matrix/evidence-only source boundary before live interoperability work",
        })
    elif code.startswith("MCP_EXTERNAL_PRIVATE_INPUT_"):
        out.update({
            "nextActionCode":"REPAIR_C7W_INPUT_PATHS",
            "requiredInputs":["C7W_OAUTH_CLIENT_MAP"],
            "detail":"place the private OAuth binding file under .state/private inside the exact repository root; never track it in Git",
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
    existing=_existing_state_handoff(root)
    if existing is not None:
        return existing

    missing=_missing_inputs(endpoint,oauth_client_map,token_env)
    if missing:
        if missing==["C7W_OAUTH_CLIENT_MAP"]:
            out=_base(ready=False,blockers=["MCP_EXTERNAL_PREFLIGHT_OAUTH_BINDINGS_MISSING"])
            out.update({
                "nextActionCode":"PREPARE_C7W_OAUTH_BINDINGS",
                "requiredInputs":list(OAUTH_CLIENT_ID_INPUTS),
                "nextCommand":oauth_binding_materializer_command(),
                "outputPath":str(DEFAULT_OAUTH_BINDING_REL),
                "detail":"materialize the private four-client OAuth binding document from the already-provisioned client IDs; values stay in environment/private state and are never emitted",
            })
            return out
        out=_base(ready=False,blockers=["MCP_EXTERNAL_PREFLIGHT_INPUTS_MISSING"])
        out.update({
            "nextActionCode":"PROVIDE_C7W_INPUTS",
            "requiredInputs":missing,
            "detail":"provide only the missing C7W endpoint/OAuth/admin-token inputs; token values are never emitted",
        })
        return out

    source_sha=""
    try:
        matrix_path=runner.require_canonical_matrix(root,matrix)
        oauth_path=private_input_path(root,oauth_client_map)
        runner.require_c7w_source_freeze(root)
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
        "detail":"C7W exact source, canonical matrix, private OAuth bindings, live endpoint, runtime identity and four trusted-client registrations are ready; create the source-bound campaign from workingDirectory",
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
