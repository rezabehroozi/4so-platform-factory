#!/usr/bin/env python3
"""Read-only, machine-actionable preflight for real C7W named-client execution."""
from __future__ import annotations

import argparse,json,os,subprocess,sys
from pathlib import Path

try:
    import c7w_execution_bindings as execution_bindings
    import prepare_mcp_external_interop_campaign as campaign
    import run_mcp_external_interop as runner
    import seal_mcp_external_interop as core
except ModuleNotFoundError:
    from scripts import c7w_execution_bindings as execution_bindings
    from scripts import prepare_mcp_external_interop_campaign as campaign
    from scripts import run_mcp_external_interop as runner
    from scripts import seal_mcp_external_interop as core

AUTHORITY="MCP_EXTERNAL_PREFLIGHT_HANDOFF_V1"
PRIVATE_INPUT_REL=Path(".state/private")
DEFAULT_OAUTH_BINDING_REL=PRIVATE_INPUT_REL/"c7w-oauth-client-bindings.json"
DEFAULT_EXECUTION_BINDING_REL=execution_bindings.DEFAULT_OUTPUT
OAUTH_CLIENT_ID_INPUTS=[f"C7W_{client.upper()}_OAUTH_CLIENT_ID" for client in core.CLIENTS]
EXECUTION_BINDING_INPUTS=[execution_bindings.ENV_RESOURCES[key] for key in execution_bindings.RESOURCE_KEYS]
PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")
EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")


def git_source_commit(root:Path)->str:
    root=Path(os.path.abspath(root))
    proc=subprocess.run(["git","rev-parse","HEAD"],cwd=root,env=runner.clean_git_env(),text=True,capture_output=True,check=False)
    value=proc.stdout.strip().lower() if proc.returncode==0 else ""
    if not core.COMMIT.fullmatch(value): raise RuntimeError("MCP_EXTERNAL_SOURCE_COMMIT_UNAVAILABLE")
    return value


def private_path(root:Path,path:Path,*,require_file:bool)->Path:
    root=Path(os.path.abspath(root)); boundary=Path(os.path.abspath(root/PRIVATE_INPUT_REL)); raw=Path(path)
    absolute=Path(os.path.abspath(raw if raw.is_absolute() else root/raw))
    try: absolute.relative_to(boundary)
    except ValueError as exc: raise RuntimeError("MCP_EXTERNAL_PRIVATE_INPUT_PATH_INVALID") from exc
    for candidate in (absolute,*absolute.parents):
        if candidate==root: break
        if candidate.is_symlink(): raise RuntimeError("MCP_EXTERNAL_PRIVATE_INPUT_PATH_INVALID")
        if candidate==boundary: break
    if absolute.is_symlink() or (require_file and not absolute.is_file()): raise RuntimeError("MCP_EXTERNAL_PRIVATE_INPUT_PATH_INVALID")
    return absolute


def private_input_path(root:Path,path:Path)->Path:
    return private_path(root,path,require_file=True)


def oauth_binding_materializer_command(root:Path,endpoint:str,token_env:str)->list[str]:
    root=Path(root).resolve()
    return [sys.executable,"scripts/prepare_c7w_oauth_bindings.py","--root",str(root),"--out",str(DEFAULT_OAUTH_BINDING_REL),"--preflight-endpoint",str(endpoint),"--preflight-token-env",str(token_env)]


def execution_binding_materializer_command(root:Path,source_sha:str,endpoint:str,oauth_client_map:Path,token_env:str,output:Path=DEFAULT_EXECUTION_BINDING_REL)->list[str]:
    return [
        sys.executable,"scripts/c7w_execution_bindings.py","--root",str(root),"--out",str(output),
        "--source-commit",source_sha,"--preflight-endpoint",str(endpoint),"--preflight-oauth-client-map",str(oauth_client_map),"--preflight-token-env",str(token_env),
    ]


def trusted_client_reconcile_command(root:Path,endpoint:str,oauth_client_map:Path,token_env:str)->list[str]:
    return [sys.executable,"scripts/reconcile_c7w_trusted_clients.py","--root",str(Path(root).resolve()),"--endpoint",str(endpoint),"--oauth-client-map",str(oauth_client_map),"--token-env",str(token_env)]


def _missing_inputs(endpoint:str,oauth_client_map:Path|None,token_env:str)->list[str]:
    missing=[]
    if not str(endpoint or "").strip(): missing.append("C7W_MCP_ENDPOINT")
    if oauth_client_map is None: missing.append("C7W_OAUTH_CLIENT_MAP")
    token=str(os.getenv(str(token_env or "")) or "").strip()
    if not token or any(ch in token for ch in "\r\n"): missing.append(str(token_env or "C7W_PLATFORM_ADMIN_TOKEN"))
    return missing


def _base(*,ready:bool,blockers:list[str])->dict:
    return {"authority":AUTHORITY,"ready":ready,"blockers":blockers,"requiredInputs":[],"nextActionCode":"","nextCommand":[],"physicalCertified":False}


def canonical_artifact_source_sha(root:Path,path:Path,current_sha:str,label:str)->str:
    value=core.load(path,label)
    source_sha=str(value.get("sourceCommitSHA") or "").strip().lower() if isinstance(value,dict) else ""
    if not core.COMMIT.fullmatch(source_sha):
        raise RuntimeError(label+"_SOURCE_INVALID")
    core.validate_evidence_only_source_lineage(root,source_sha,current_sha,label)
    return source_sha


def _existing_state_handoff(root:Path)->dict|None:
    try: current_sha=git_source_commit(root)
    except RuntimeError: return None
    progress=root/PROGRESS_REL; evidence=root/EVIDENCE_REL
    progress_present=progress.exists() or progress.is_symlink()
    evidence_present=evidence.exists() or evidence.is_symlink()
    certified_sha=current_sha

    if evidence_present:
        if evidence.is_symlink() or not evidence.is_file():
            out=_base(ready=False,blockers=["MCP_EXTERNAL_CANONICAL_EVIDENCE_INVALID"]); out.update({"sourceCommitSHA":current_sha,"workingDirectory":str(root),"nextActionCode":"INSPECT_C7W_CANONICAL_EVIDENCE","nextCommand":["git","status","--short","--",str(PROGRESS_REL),str(EVIDENCE_REL)],"detail":"canonical final C7W evidence exists at an unsafe path; restore that evidence before any state recovery or new campaign"}); return out
        try:
            certified_sha=canonical_artifact_source_sha(root,evidence,current_sha,"MCP_EXTERNAL_PREFLIGHT_EVIDENCE")
        except RuntimeError as exc:
            out=_base(ready=False,blockers=[str(exc).split()[0] if str(exc).strip() else "MCP_EXTERNAL_CANONICAL_EVIDENCE_INVALID"]); out.update({"sourceCommitSHA":current_sha,"workingDirectory":str(root),"nextActionCode":"INSPECT_C7W_CANONICAL_EVIDENCE","nextCommand":["git","status","--short","--",str(PROGRESS_REL),str(EVIDENCE_REL)],"detail":"canonical final C7W evidence source lineage is invalid; restore exact evidence before any Git/C9 handoff"}); return out
    elif progress_present:
        if progress.is_symlink() or not progress.is_file():
            out=_base(ready=False,blockers=["MCP_EXTERNAL_CANONICAL_PROGRESS_INVALID"]); out.update({"sourceCommitSHA":current_sha,"workingDirectory":str(root),"nextActionCode":"INSPECT_C7W_CANONICAL_PROGRESS","nextCommand":["git","status","--short","--",str(PROGRESS_REL)],"detail":"canonical C7W progress exists at an unsafe path; restore that progress before campaign recovery"}); return out
        try:
            certified_sha=canonical_artifact_source_sha(root,progress,current_sha,"MCP_EXTERNAL_PREFLIGHT_PROGRESS")
        except RuntimeError as exc:
            out=_base(ready=False,blockers=[str(exc).split()[0] if str(exc).strip() else "MCP_EXTERNAL_CANONICAL_PROGRESS_INVALID"]); out.update({"sourceCommitSHA":current_sha,"workingDirectory":str(root),"nextActionCode":"INSPECT_C7W_CANONICAL_PROGRESS","nextCommand":["git","status","--short","--",str(PROGRESS_REL)],"detail":"canonical C7W progress source lineage is invalid; restore source-bound progress before campaign recovery"}); return out

    state=Path(f".state/c7w-external-interop-{certified_sha[:12]}"); absolute=Path(os.path.abspath(root/state))
    identity={"sourceCommitSHA":current_sha}
    if certified_sha!=current_sha:
        identity["certifiedSourceCommitSHA"]=certified_sha

    if evidence_present:
        if not progress_present or progress.is_symlink() or not progress.is_file():
            out=_base(ready=False,blockers=["MCP_EXTERNAL_CANONICAL_EVIDENCE_WITHOUT_PROGRESS"]); out.update({**identity,"workingDirectory":str(root),"nextActionCode":"INSPECT_C7W_CANONICAL_EVIDENCE","nextCommand":["git","status","--short","--",str(PROGRESS_REL),str(EVIDENCE_REL)],"detail":"canonical final C7W evidence exists without a safe canonical progress snapshot; restore both artifacts before any C9 handoff"}); return out
        if not absolute.exists() and not absolute.is_symlink():
            out=_base(ready=False,blockers=["MCP_EXTERNAL_LOCAL_STATE_MISSING_WITH_CANONICAL_EVIDENCE"]); out.update({**identity,"stateDir":str(state),"workingDirectory":str(root),"nextActionCode":"RESTORE_C7W_LOCAL_STATE","nextCommand":["git","status","--short","--",str(PROGRESS_REL),str(EVIDENCE_REL)],"detail":"canonical C7W final evidence exists but the certified-source private state is missing; bulk receipt/audit revalidation is required before Git/C9 handoff"}); return out
        if absolute.is_symlink() or not absolute.is_dir():
            out=_base(ready=False,blockers=["MCP_EXTERNAL_LOCAL_STATE_DIR_INVALID"]); out.update({**identity,"stateDir":str(state),"workingDirectory":str(root),"nextActionCode":"INSPECT_C7W_LOCAL_STATE","nextCommand":[],"detail":"the certified-source C7W state path exists but is not a safe directory; repair local state before final evidence revalidation"}); return out
        out=_base(ready=False,blockers=["MCP_EXTERNAL_CANONICAL_EVIDENCE_REVALIDATION_REQUIRED"]); out.update({**identity,"stateDir":str(state),"workingDirectory":str(root),"nextActionCode":"RUN_C7W_STATUS","nextCommand":runner.runner_command(state,"status"),"detail":"canonical final C7W evidence exists; run status against the certified-source state to rebuild the independent bulk seal and compare it with persisted evidence before any Git/C9 handoff"}); return out

    artifacts=[rel for rel,path in ((PROGRESS_REL,progress),) if path.exists() or path.is_symlink()]
    if not absolute.exists() and not absolute.is_symlink():
        if not artifacts: return None
        out=_base(ready=False,blockers=["MCP_EXTERNAL_LOCAL_STATE_MISSING_WITH_CANONICAL_EVIDENCE"]); out.update({**identity,"stateDir":str(state),"workingDirectory":str(root),"nextActionCode":"RESTORE_C7W_LOCAL_STATE","nextCommand":["git","status","--short","--",*[str(rel) for rel in artifacts]],"detail":"canonical C7W progress exists but the certified-source private state directory is missing; restore or inspect local state before any new campaign"}); return out
    if absolute.is_symlink() or not absolute.is_dir():
        out=_base(ready=False,blockers=["MCP_EXTERNAL_LOCAL_STATE_DIR_INVALID"]); out.update({**identity,"stateDir":str(state),"workingDirectory":str(root),"nextActionCode":"INSPECT_C7W_LOCAL_STATE","nextCommand":[],"detail":"the certified-source C7W state path exists but is not a safe directory; repair the local state path before campaign recovery"}); return out
    out=_base(ready=False,blockers=["MCP_EXTERNAL_EXISTING_STATE_REQUIRES_STATUS"]); out.update({**identity,"stateDir":str(state),"workingDirectory":str(root),"nextActionCode":"RUN_C7W_STATUS","nextCommand":runner.runner_command(state,"status"),"detail":"source-bound C7W state already exists; inspect canonical status/recovery first without re-requesting endpoint, OAuth or token inputs"}); return out


def _failure(code:str,source_sha:str="")->dict:
    out=_base(ready=False,blockers=[code])
    if code.startswith("MCP_EXTERNAL_LOCAL_"): out.update({"nextActionCode":"RESTORE_C7W_SOURCE_FREEZE","nextCommand":["git","status","--short"],"detail":"restore canonical main, repository-root authority and the C7W canonical matrix/evidence-only source boundary before live interoperability work"})
    elif code.startswith("MCP_EXTERNAL_PRIVATE_INPUT_"): out.update({"nextActionCode":"REPAIR_C7W_INPUT_PATHS","requiredInputs":["C7W_OAUTH_CLIENT_MAP"],"detail":"place private C7W inputs under .state/private inside the exact repository root; never track them in Git"})
    elif code.startswith("MCP_EXTERNAL_OAUTH_BINDINGS_"): out.update({"nextActionCode":"REPAIR_C7W_OAUTH_BINDINGS","detail":"repair the private four-client OAuth binding document, then rerun C7W preflight"})
    elif code.startswith("MCP_EXTERNAL_EXECUTION_BINDINGS_"): out.update({"nextActionCode":"REPAIR_C7W_EXECUTION_BINDINGS","requiredInputs":list(EXECUTION_BINDING_INPUTS),"detail":"repair the source-bound non-secret C7W execution binding document under .state/private, then rerun preflight"})
    elif code=="MCP_EXTERNAL_RUNTIME_SOURCE_DRIFT": out.update({"nextActionCode":"DEPLOY_C7W_CURRENT_SOURCE","requiredSourceCommitSHA":source_sha,"detail":"deploy the exact current main source before external named-client execution"})
    elif code.startswith("MCP_EXTERNAL_TRUSTED_CLIENT_"): out.update({"nextActionCode":"RECONCILE_C7W_TRUSTED_CLIENTS","detail":"make all four Product trusted-client registrations ACTIVE with provider/client identity matching the private OAuth binding document"})
    else: out.update({"nextActionCode":"INSPECT_C7W_LIVE_ENDPOINT","detail":"repair the HTTPS MCP/Product API endpoint or its runtime identity/challenge contract, then rerun C7W preflight"})
    return out


def preflight(root:Path,matrix:Path,endpoint:str,oauth_client_map:Path|None,token_env:str,execution_binding_path:Path|None=None)->dict:
    root=Path(os.path.abspath(root)); existing=_existing_state_handoff(root)
    if existing is not None: return existing
    missing=_missing_inputs(endpoint,oauth_client_map,token_env)
    if missing:
        if missing==["C7W_OAUTH_CLIENT_MAP"]:
            out=_base(ready=False,blockers=["MCP_EXTERNAL_PREFLIGHT_OAUTH_BINDINGS_MISSING"]); out.update({"workingDirectory":str(root),"nextActionCode":"PREPARE_C7W_OAUTH_BINDINGS","requiredInputs":list(OAUTH_CLIENT_ID_INPUTS),"nextCommand":oauth_binding_materializer_command(root,endpoint,token_env),"outputPath":str(DEFAULT_OAUTH_BINDING_REL),"detail":"materialize the private four-client OAuth binding document from the already-provisioned client IDs; values stay in environment/private state and are never emitted"}); return out
        out=_base(ready=False,blockers=["MCP_EXTERNAL_PREFLIGHT_INPUTS_MISSING"]); out.update({"nextActionCode":"PROVIDE_C7W_INPUTS","requiredInputs":missing,"detail":"provide only the missing C7W endpoint/OAuth/admin-token inputs; token values are never emitted"}); return out
    source_sha=""; endpoint_value=""; oauth_path=None
    execution_raw=Path(execution_binding_path or DEFAULT_EXECUTION_BINDING_REL)
    try:
        execution_path=private_path(root,execution_raw,require_file=False)
        canonical_execution_path=Path(os.path.abspath(root/DEFAULT_EXECUTION_BINDING_REL))
        if execution_path!=canonical_execution_path:
            raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_PATH_INVALID")
        matrix_path=runner.require_canonical_matrix(root,matrix); oauth_path=private_input_path(root,oauth_client_map); runner.require_c7w_source_freeze(root); source_sha=git_source_commit(root); endpoint_value=campaign.endpoint(endpoint)
        matrix_doc=core.load(matrix_path,"MATRIX"); core.validate_matrix_contract(matrix_doc,"MCP_EXTERNAL_MATRIX"); bindings,binding_sha=campaign.load_oauth_bindings(oauth_path)
    except RuntimeError as exc:
        code=str(exc).split()[0] if str(exc).strip() else "MCP_EXTERNAL_PREFLIGHT_UNKNOWN"; return _failure(code,source_sha)
    if not execution_path.exists() and not execution_path.is_symlink():
        out=_base(ready=False,blockers=["MCP_EXTERNAL_PREFLIGHT_EXECUTION_BINDINGS_MISSING"]); out.update({"sourceCommitSHA":source_sha,"workingDirectory":str(root),"nextActionCode":"PREPARE_C7W_EXECUTION_BINDINGS","requiredInputs":list(EXECUTION_BINDING_INPUTS),"nextCommand":execution_binding_materializer_command(root,source_sha,endpoint_value,oauth_path,token_env,execution_path),"outputPath":str(execution_path),"detail":"materialize the three non-secret runtime resource IDs at the canonical private authority path required before any live endpoint execution"}); return out
    try:
        execution_path=private_input_path(root,execution_path)
        execution_doc,execution_sha=execution_bindings.load(execution_path,source_sha)
    except RuntimeError as exc:
        code=str(exc).split()[0] if str(exc).strip() else "MCP_EXTERNAL_EXECUTION_BINDINGS_INVALID"; out=_failure(code,source_sha); out.update({"workingDirectory":str(root),"nextCommand":execution_binding_materializer_command(root,source_sha,endpoint_value,oauth_path,token_env,Path(os.path.abspath(root/DEFAULT_EXECUTION_BINDING_REL))),"outputPath":str(Path(os.path.abspath(root/DEFAULT_EXECUTION_BINDING_REL)))}); return out
    try:
        live=campaign.live_preflight(endpoint_value); runtime=campaign.runtime_identity_readback(endpoint_value,token_env,source_sha); trusted=campaign.trusted_client_readback(endpoint_value,bindings,token_env)
    except RuntimeError as exc:
        code=str(exc).split()[0] if str(exc).strip() else "MCP_EXTERNAL_PREFLIGHT_UNKNOWN"; out=_failure(code,source_sha)
        if code.startswith("MCP_EXTERNAL_TRUSTED_CLIENT_") and endpoint_value and oauth_path is not None: out.update({"workingDirectory":str(root),"nextCommand":trusted_client_reconcile_command(root,endpoint_value,oauth_path,token_env)})
        return out
    state=Path(f".state/c7w-external-interop-{source_sha[:12]}")
    command=[sys.executable,"scripts/run_mcp_external_interop.py","--matrix",str(matrix_path),"--state-dir",str(state),"prepare","--endpoint",endpoint_value,"--oauth-client-map",str(oauth_path),"--token-env",str(token_env),"--source-commit-sha",source_sha]
    out=_base(ready=True,blockers=[]); out.update({"sourceCommitSHA":source_sha,"runtimeVersion":runtime["version"],"endpoint":endpoint_value,"matrixPath":str(matrix_path),"oauthClientMapPath":str(oauth_path),"oauthClientBindingsSha256":binding_sha,"executionBindingsPath":str(execution_path),"executionBindingsSha256":execution_sha,"credentialProfileContractAuthority":execution_doc["credentialProfileContractAuthority"],"credentialProfileContractSha256":execution_doc["credentialProfileContractSha256"],"trustedClientCount":len(trusted),"livePreflightAuthority":live.get("authority"),"stateDir":str(state),"workingDirectory":str(root),"nextActionCode":"RUN_C7W_PREPARE","nextCommand":command,"detail":"C7W exact source, canonical matrix, private OAuth bindings, canonical source-bound execution resources, credential-profile contract, live endpoint, runtime identity and four trusted-client registrations are ready; create the source-bound campaign from workingDirectory"}); return out


def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("--root",type=Path,default=Path(".")); parser.add_argument("--matrix",type=Path,default=runner.CANONICAL_MATRIX_REL); parser.add_argument("--endpoint",default=os.environ.get("C7W_MCP_ENDPOINT","")); raw_map=os.environ.get("C7W_OAUTH_CLIENT_MAP","").strip(); parser.add_argument("--oauth-client-map",type=Path,default=Path(raw_map) if raw_map else None); parser.add_argument("--execution-bindings",type=Path); parser.add_argument("--token-env",default=os.environ.get("C7W_PLATFORM_ADMIN_TOKEN_ENV","C7W_PLATFORM_ADMIN_TOKEN")); args=parser.parse_args(); result=preflight(args.root,args.matrix,args.endpoint,args.oauth_client_map,args.token_env,args.execution_bindings); print(json.dumps(result,sort_keys=True)); return 0 if result.get("ready") is True else 2

if __name__=="__main__": raise SystemExit(main())
