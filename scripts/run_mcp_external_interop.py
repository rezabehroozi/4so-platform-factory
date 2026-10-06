#!/usr/bin/env python3
"""Canonical local-only orchestrator for real C7W named-client interoperability.

The runner never executes or emulates ChatGPT, Claude, Gemini or Grok. It only
prepares replay-fenced packets, validates independently produced captures,
fetches authoritative Product API audit evidence, and advances canonical C7W
progress using the owner validators.
"""
from __future__ import annotations

import argparse
import json
import os
import hashlib
from pathlib import Path
import subprocess
import sys

import admit_mcp_external_receipt as admission
import fetch_mcp_external_audit_window as audit_fetch
import finalize_mcp_external_client_receipt as finalizer
import prepare_mcp_external_client_execution as packet_builder
import prepare_mcp_external_interop_campaign as campaign_builder
import seal_mcp_external_interop as core

AUTHORITY="MCP_EXTERNAL_LOCAL_EXECUTION_RUNNER_V1"
DEFAULT_STATE=Path(".state/c7w-external-interop")
CANONICAL_MATRIX_REL=Path("lab/mcp-external-client-interop-matrix.json")
CANONICAL_PROGRESS_REL=Path("lab/mcp-external-client-interop-progress.json")
CANONICAL_EVIDENCE_REL=Path("lab/mcp-external-client-interoperability-evidence.json")


def clean_git_env()->dict[str,str]:
    env=os.environ.copy()
    for key in list(env):
        if key.startswith("GIT_"):
            env.pop(key,None)
    return env


def secure_state_dir(path:Path)->Path:
    path=Path(os.path.abspath(path))
    for parent in reversed(path.parents):
        if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
            raise RuntimeError("MCP_EXTERNAL_LOCAL_STATE_PARENT_INVALID")
    path.mkdir(parents=True,exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError("MCP_EXTERNAL_LOCAL_STATE_DIR_INVALID")
    path.chmod(0o700)
    for name in ("packets","capture-templates","captures","receipts","audits"):
        child=path/name
        if child.is_symlink() or (child.exists() and not child.is_dir()):
            raise RuntimeError(f"MCP_EXTERNAL_LOCAL_STATE_CHILD_INVALID {name}")
        child.mkdir(exist_ok=True)
        if child.is_symlink() or not child.is_dir():
            raise RuntimeError(f"MCP_EXTERNAL_LOCAL_STATE_CHILD_INVALID {name}")
        child.chmod(0o700)
    return path


def paths(state:Path)->dict[str,Path]:
    return {
        "campaign":state/"campaign.json",
        "packets":state/"packets",
        "templates":state/"capture-templates",
        "captures":state/"captures",
        "receipts":state/"receipts",
        "audits":state/"audits",
    }


def complete_bulk_artifacts_present(state:Path)->bool:
    p=paths(state)
    for client in core.CLIENTS:
        for parent in (p["receipts"],p["audits"]):
            path=parent/(client+".json")
            if path.is_symlink() or not path.is_file():
                return False
    return True


def captured_artifact_recovery_handoff(value:dict,state:Path)->dict:
    out=dict(value)
    out.update({
        "authority":AUTHORITY,
        "action":"STATUS",
        "stateDir":str(state),
        "recoveryRequired":True,
        "recoveryReason":"CAPTURED_ARTIFACT_PROGRESS_RECONCILIATION",
        "nextActionCode":"RUN_C7W_SEAL",
        "nextCommand":runner_command(state,"seal"),
        "detail":"all four receipt/audit artifact pairs already exist; reconcile canonical progress from independently verified captured evidence instead of repeating external client execution",
        "physicalCertified":False,
    })
    return out


def require_canonical_matrix(root:Path,candidate:Path)->Path:
    root=root.resolve()
    raw=Path(candidate)
    actual=Path(os.path.abspath(raw if raw.is_absolute() else root/raw))
    expected=Path(os.path.abspath(root/CANONICAL_MATRIX_REL))
    if actual!=expected or actual.is_symlink() or expected.is_symlink() or not expected.is_file():
        raise RuntimeError("MCP_EXTERNAL_LOCAL_MATRIX_PATH_INVALID")
    return expected


def require_canonical_artifact_path(root:Path,candidate:Path,expected_rel:Path,label:str)->Path:
    root=root.resolve()
    raw=Path(candidate)
    actual=Path(os.path.abspath(raw if raw.is_absolute() else root/raw))
    expected=Path(os.path.abspath(root/expected_rel))
    code=f"MCP_EXTERNAL_LOCAL_{label}_PATH_INVALID"
    if actual!=expected:
        raise RuntimeError(code)
    for current in (expected,*expected.parents):
        if current==root:
            break
        if current.is_symlink():
            raise RuntimeError(code)
    try:
        expected.relative_to(root)
    except ValueError as exc:
        raise RuntimeError(code) from exc
    return expected


def require_c7w_source_freeze(root:Path)->None:
    root=root.resolve()
    git_env=clean_git_env()
    top=subprocess.run(["git","rev-parse","--show-toplevel"],cwd=root,env=git_env,text=True,capture_output=True,check=False)
    if top.returncode!=0 or Path(top.stdout.strip()).resolve()!=root:
        raise RuntimeError("MCP_EXTERNAL_LOCAL_GIT_ROOT_INVALID")
    branch=subprocess.run(["git","symbolic-ref","--quiet","--short","HEAD"],cwd=root,env=git_env,text=True,capture_output=True,check=False)
    if branch.returncode!=0 or branch.stdout.strip()!="main":
        raise RuntimeError("MCP_EXTERNAL_LOCAL_BRANCH_NOT_MAIN")
    indexed=subprocess.run(["git","ls-files","-v","-z"],cwd=root,env=git_env,capture_output=True,check=False)
    if indexed.returncode!=0 or any(raw and not raw.startswith(b"H ") for raw in indexed.stdout.split(b"\x00")):
        raise RuntimeError("MCP_EXTERNAL_LOCAL_GIT_INDEX_FLAGS_FORBIDDEN")
    allowed=sorted(core.C7W_EVIDENCE_ONLY_PATHS)
    command=["git","status","--porcelain=v1","-z","--untracked-files=all"]
    all_status=subprocess.run(command,cwd=root,env=git_env,capture_output=True,check=False)
    allowed_status=subprocess.run(command+["--",*allowed],cwd=root,env=git_env,capture_output=True,check=False)
    if all_status.returncode!=0 or allowed_status.returncode!=0:
        raise RuntimeError("MCP_EXTERNAL_LOCAL_GIT_STATUS_UNAVAILABLE")
    all_records={row for row in all_status.stdout.split(b"\x00") if row}
    allowed_records={row for row in allowed_status.stdout.split(b"\x00") if row}
    forbidden=all_records-allowed_records
    if forbidden:
        raise RuntimeError("MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN")


def require_active_campaign_source(root:Path,campaign:dict)->str:
    root=root.resolve()
    require_c7w_source_freeze(root)
    head=subprocess.run(["git","rev-parse","HEAD"],cwd=root,env=clean_git_env(),text=True,capture_output=True,check=False)
    current_sha=head.stdout.strip().lower() if head.returncode==0 else ""
    certified_sha=str((campaign or {}).get("sourceCommitSHA") or "").strip().lower()
    if not core.COMMIT.fullmatch(current_sha) or not core.COMMIT.fullmatch(certified_sha):
        raise RuntimeError("MCP_EXTERNAL_LOCAL_ACTIVE_CAMPAIGN_SOURCE_INVALID")
    core.validate_evidence_only_source_lineage(root,certified_sha,current_sha,"MCP_EXTERNAL_LOCAL_ACTIVE_CAMPAIGN")
    return current_sha


def git_handoff(root:Path,evidence_path:Path,progress_path:Path)->dict:
    root=root.resolve()
    git_env=clean_git_env()
    def run_git(*args:str)->subprocess.CompletedProcess:
        return subprocess.run(["git",*args],cwd=root,env=git_env,text=True,capture_output=True,check=False)
    try:
        require_c7w_source_freeze(root)
    except RuntimeError as exc:
        return {
            "nextActionCode":"RESTORE_C7W_SOURCE_FREEZE",
            "nextCommand":["git","status","--short"],
            "detail":str(exc)+"; C9 handoff is forbidden until the worktree returns to the C7W evidence-only source boundary",
        }
    head=run_git("rev-parse","HEAD")
    if head.returncode!=0 or not core.COMMIT.fullmatch(head.stdout.strip().lower()):
        return {
            "nextActionCode":"INSPECT_GIT_SOURCE_AUTHORITY",
            "nextCommand":["git","status","--short"],
            "detail":"canonical Git HEAD is unavailable; do not run C9 until C7W evidence is committed to an exact source SHA",
        }
    rels=[]
    for path in (progress_path,evidence_path):
        try:
            rel=path.resolve().relative_to(root).as_posix()
        except ValueError:
            return {
                "nextActionCode":"PERSIST_C7W_EVIDENCE_IN_REPOSITORY",
                "nextCommand":["git","status","--short"],
                "detail":"canonical C7W progress/evidence is outside the repository; copy it into the configured tracked paths before C9",
            }
        rels.append(rel)
    tracked=run_git("ls-files","--error-unmatch",*rels)
    diff=run_git("status","--porcelain=v1","--",*rels)
    if diff.returncode!=0:
        return {
            "nextActionCode":"INSPECT_C7W_EVIDENCE_GIT_STATE",
            "nextCommand":["git","status","--short","--",*rels],
            "detail":"unable to establish Git state for canonical C7W evidence",
        }
    if tracked.returncode!=0 or diff.stdout.strip():
        return {
            "nextActionCode":"COMMIT_C7W_EVIDENCE",
            "nextCommand":["git","add",*rels],
            "followupCommand":["git","commit","-m","evidence: seal external MCP interoperability"],
            "detail":"C7W is complete but evidence is not yet part of the exact Git SHA required by C9",
        }
    current_sha=head.stdout.strip().lower()
    evidence=core.load(evidence_path,"C7W_EVIDENCE")
    certified_sha=str(evidence.get("sourceCommitSHA") or "").strip().lower()
    try:
        core.validate_evidence_only_source_lineage(root,certified_sha,current_sha,"MCP_EXTERNAL_LOCAL_HANDOFF")
    except RuntimeError as exc:
        return {
            "nextActionCode":"RERUN_C7W_ON_CURRENT_SOURCE",
            "nextCommand":runner_command(Path(f".state/c7w-external-interop-{current_sha[:12]}"),"prepare"),
            "requiredInputs":["C7W_MCP_ENDPOINT","C7W_OAUTH_CLIENT_MAP","C7W_PLATFORM_ADMIN_TOKEN"],
            "certifiedSourceCommitSHA":certified_sha,
            "currentSourceCommitSHA":current_sha,
            "detail":str(exc)+"; source changed beyond evidence-only C7W files, so C9 must not use the stale external certification",
        }
    handoff=c9_handoff(current_sha,root)
    handoff.update({
        "sourceCommitSHA":current_sha,
        "certifiedSourceCommitSHA":certified_sha,
    })
    if handoff["nextActionCode"]=="RUN_C9_SEAL":
        handoff["detail"]="C7W evidence is committed and source lineage is evidence-only; C9 may run on this exact Linux build host"
    return handoff


def runner_command(state:Path,command:str,*args:str)->list[str]:
    return [sys.executable,"scripts/run_mcp_external_interop.py","--state-dir",str(state),command,*args]


def c9_seal_command(root:Path|None=None)->list[str]:
    root_text=str(Path(root).resolve()) if root is not None else "."
    return [sys.executable,"scripts/seal_final_exact_release.py","--root",root_text,"--out","lab/final-exact-release-evidence.json"]
def c9_preflight_command(root:Path|None=None)->list[str]:
    root_text=str(Path(root).resolve()) if root is not None else "."
    return [sys.executable,"scripts/c9_preflight.py","--root",root_text,"--preflight"]
def c9_handoff(source_sha:str,root:Path|None=None)->dict:
    if sys.platform.startswith("linux"):
        checkout_root=Path(root or Path.cwd()).resolve()
        return {
            "nextActionCode":"RUN_C9_SEAL",
            "nextCommand":c9_seal_command(),
            "preflightCommand":c9_preflight_command(),
            "workingDirectory":str(checkout_root),
            "requiredHost":"linux-amd64-exact-toolchain",
        }
    checkout_placeholder="<exact-source-checkout-root>"
    return {
        "nextActionCode":"RUN_C9_ON_EXACT_LINUX_HOST",
        "nextCommand":[],
        "preflightCommandTemplate":["<python>","scripts/c9_preflight.py","--root",checkout_placeholder,"--preflight"],
        "nextCommandTemplate":["<python>","scripts/seal_final_exact_release.py","--root",checkout_placeholder,"--out","lab/final-exact-release-evidence.json"],
        "requiredWorkingDirectory":checkout_placeholder,
        "requiredHost":"linux-amd64-exact-toolchain",
        "requiredSourceCommitSHA":source_sha,
        "detail":"C9 is source-ready after C7W, but its admitted Go/CGO lock is Linux/amd64; run the exact committed SHA on a Linux host with the admitted offline toolchain archive rather than weakening the release boundary",
    }


def client_execution_handoff(state:Path,client:str)->dict:
    client=str(client or "").strip().lower()
    if client not in core.CLIENTS:
        raise RuntimeError("MCP_EXTERNAL_LOCAL_CLIENT_HANDOFF_INVALID")
    p=paths(state)
    capture=str(p["captures"]/(client+".capture.json"))
    return {
        "clientId":client,
        "packetPath":str(p["packets"]/(client+".json")),
        "captureTemplatePath":str(p["templates"]/(client+".json")),
        "expectedCapturePath":capture,
        "requiredCaptureAuthority":"MCP_EXTERNAL_CLIENT_CAPTURE_V1",
        "admitCommand":runner_command(state,"admit","--client",client,"--capture",capture),
    }


def external_client_action(state:Path,client:str)->dict:
    handoff=client_execution_handoff(state,client)
    return {
        "nextActionCode":"RUN_EXTERNAL_CLIENT",
        "nextCommand":[],
        "nextClientHandoff":handoff,
        "postExternalExecutionCommand":handoff["admitCommand"],
        "detail":"execute the named external client with its exact prepared packet and capture template; only after the capture is complete run postExternalExecutionCommand",
    }


def capture_template(packet:dict)->dict:
    requirements=packet.get("receiptRequirements") or {}
    if requirements.get("structuredResponseObservationRequired") is not True:
        raise RuntimeError("MCP_EXTERNAL_LOCAL_PACKET_RESPONSE_OBSERVATION_REQUIRED")
    audited=set(requirements.get("requestIds") or [])
    checks={}
    for row in packet.get("checks") or []:
        check_id=str(row.get("id") or "")
        if not check_id:
            raise RuntimeError("MCP_EXTERNAL_LOCAL_PACKET_CHECK_INVALID")
        checks[check_id]={"observed":finalizer.observation_template(row),**({"requestId":""} if check_id in audited else {})}
    if list(checks)!=list(core.REQUIRED_CHECKS):
        raise RuntimeError("MCP_EXTERNAL_LOCAL_PACKET_CHECK_SET_INVALID")
    return {
        "authority":"MCP_EXTERNAL_CLIENT_CAPTURE_V1",
        "clientId":packet["clientId"],
        "clientSurface":packet["clientSurface"],
        "campaignId":packet["campaignId"],
        "challengeSha256":packet["challengeSha256"],
        "endpoint":packet["endpoint"],
        "sourceCommitSHA":packet["sourceCommitSHA"],
        "runtimeVersion":packet["runtimeVersion"],
        "executionId":"",
        "executedAt":"",
        "externalExecution":False,
        "credentialedExecution":False,
        "checks":checks,
        "providerExecutionRef":"",
    }


def prepare(args:argparse.Namespace)->dict:
    root=Path.cwd().resolve()
    require_c7w_source_freeze(root)
    args.matrix=require_canonical_matrix(root,args.matrix)
    state=secure_state_dir(args.state_dir)
    p=paths(state)
    source_sha=campaign_builder.source_commit_sha(args.source_commit_sha)
    matrix=core.load(args.matrix,"MATRIX")
    core.validate_matrix_contract(matrix,"MCP_EXTERNAL_MATRIX")
    if p["campaign"].exists() or p["campaign"].is_symlink():
        campaign=campaign_builder.resume_existing(args.matrix,args.endpoint,p["campaign"],source_sha)
        resumed=True
    else:
        if args.oauth_client_map is None:
            raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_REQUIRED")
        bindings,binding_sha=campaign_builder.load_oauth_bindings(args.oauth_client_map)
        runtime_identity=campaign_builder.runtime_identity_readback(args.endpoint,args.token_env,source_sha)
        trusted=campaign_builder.trusted_client_readback(args.endpoint,bindings,args.token_env)
        preflight=campaign_builder.live_preflight(args.endpoint)
        campaign=campaign_builder.prepare(args.matrix,args.endpoint,preflight,binding_sha,trusted,runtime_identity)
        core.write_json_once_or_identical(p["campaign"],campaign,"MCP_EXTERNAL_CAMPAIGN")
        resumed=False
    for client in core.CLIENTS:
        packet=packet_builder.packet(args.matrix,p["campaign"],client)
        packet_path=p["packets"]/(client+".json")
        core.write_json_once_or_identical(packet_path,packet,"MCP_EXTERNAL_EXECUTION_PACKET")
        template_path=p["templates"]/(client+".json")
        core.write_json_once_or_identical(template_path,capture_template(packet),"MCP_EXTERNAL_CAPTURE_TEMPLATE")
    if resumed:
        current=progress_status(args.matrix,state,args.progress_out)
        certified=current["certified"]
        missing=current["missing"]
        complete=current["complete"]
        next_client=current["nextClient"]
    else:
        certified=[]
        missing=list(core.CLIENTS)
        complete=False
        next_client=core.CLIENTS[0]
    client_handoff={client:client_execution_handoff(state,client) for client in core.CLIENTS}
    result={
        "authority":AUTHORITY,
        "action":"PREPARED",
        "resumed":resumed,
        "campaignId":campaign["campaignId"],
        "sourceCommitSHA":campaign["sourceCommitSHA"],
        "runtimeVersion":campaign["runtimeVersion"],
        "stateDir":str(state),
        "externalExecutionRequired":True,
        "clients":list(core.CLIENTS),
        "clientHandoff":client_handoff,
        "certified":certified,
        "missing":missing,
        "complete":complete,
        "nextClient":next_client,
        "physicalCertified":False,
    }
    if complete:
        result.update({"nextActionCode":"RUN_C7W_SEAL","nextCommand":runner_command(state,"seal")})
    else:
        result.update(external_client_action(state,next_client))
    return result


def progress_status(matrix:Path,state:Path,progress_path:Path,*,require_live:bool=True)->dict:
    matrix=require_canonical_matrix(Path.cwd(),matrix)
    p=paths(state)
    if not p["campaign"].is_file() or p["campaign"].is_symlink():
        if progress_path.exists() or progress_path.is_symlink():
            raise RuntimeError("MCP_EXTERNAL_LOCAL_CAMPAIGN_MISSING_WITH_CANONICAL_PROGRESS")
        return {"certified":[],"missing":list(core.CLIENTS),"complete":False,"nextClient":core.CLIENTS[0],"campaignPrepared":False}
    if require_live:
        spec,_,campaign=admission.matrix_contract(matrix,p["campaign"])
    else:
        matrix_value=core.load(matrix,"MATRIX")
        spec=core.validate_matrix_contract(matrix_value,"MCP_EXTERNAL_MATRIX")
        campaign=core.verify_campaign(p["campaign"],matrix,spec,require_live=False)
    expected=admission.base_progress(matrix,p["campaign"],campaign,spec)
    if not progress_path.exists():
        certified=[]
    else:
        existing=core.load(progress_path,"PROGRESS")
        by_id=admission.validate_existing(existing,expected)
        admission.validate_existing_campaign_rows(by_id,expected,campaign,spec)
        certified=[name for name in core.CLIENTS if name in by_id]
    missing=[name for name in core.CLIENTS if name not in certified]
    return {
        "certified":certified,
        "missing":missing,
        "complete":not missing,
        "nextClient":missing[0] if missing else None,
        "campaignPrepared":True,
        "campaignId":campaign["campaignId"],
        "sourceCommitSHA":campaign["sourceCommitSHA"],
        "runtimeVersion":campaign["runtimeVersion"],
    }


def recover_complete_progress_from_bulk(matrix:Path,campaign_path:Path,bulk:dict,progress_path:Path)->dict:
    if bulk.get("authority")!=core.AUTHORITY or bulk.get("certifiedClientCount")!=len(core.CLIENTS) or bulk.get("externalCertificationPass") is not True:
        raise RuntimeError("MCP_EXTERNAL_LOCAL_RECOVERY_BULK_EVIDENCE_INVALID")
    rows=bulk.get("clients")
    if not isinstance(rows,list) or [row.get("clientId") for row in rows if isinstance(row,dict)]!=list(core.CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_LOCAL_RECOVERY_BULK_CLIENT_SET_INVALID")
    matrix_value=core.load(matrix,"MATRIX")
    spec=core.validate_matrix_contract(matrix_value,"MCP_EXTERNAL_MATRIX")
    campaign=core.verify_campaign(campaign_path,matrix,spec,require_live=False)
    expected=admission.base_progress(matrix,campaign_path,campaign,spec)
    bulk_by={row["clientId"]:row for row in rows}
    if progress_path.exists():
        existing=core.load(progress_path,"PROGRESS")
        existing_by=admission.validate_existing(existing,expected)
        admission.validate_existing_campaign_rows(existing_by,expected,campaign,spec)
        for client,row in existing_by.items():
            if bulk_by.get(client)!=row:
                raise RuntimeError(f"MCP_EXTERNAL_LOCAL_RECOVERY_PROGRESS_BULK_DRIFT {client}")
    expected["clients"]=rows
    expected["certifiedClientCount"]=len(core.CLIENTS)
    expected["complete"]=True
    expected["externalCertificationPass"]=True
    expected["serverAuditWitnessPass"]=True
    validated=admission.validate_existing(expected,expected)
    admission.validate_existing_campaign_rows(validated,expected,campaign,spec)
    if list(validated)!=list(core.CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_LOCAL_RECOVERY_PROGRESS_INVALID")
    return expected


def admit(args:argparse.Namespace)->dict:
    root=Path.cwd().resolve()
    args.matrix=require_canonical_matrix(root,args.matrix)
    state=secure_state_dir(args.state_dir)
    p=paths(state)
    campaign=core.load(p["campaign"],"ACTIVE_CAMPAIGN")
    require_active_campaign_source(root,campaign)
    client=str(args.client).strip().lower()
    packet_path=p["packets"]/(client+".json")
    if not packet_path.is_file() or packet_path.is_symlink():
        raise RuntimeError("MCP_EXTERNAL_LOCAL_PACKET_MISSING")
    receipt_path=p["receipts"]/(client+".json")
    receipt=finalizer.finalize(packet_path,args.capture)
    core.write_json_once_or_identical(receipt_path,receipt,"MCP_EXTERNAL_CLIENT_RECEIPT")

    spec,required,campaign=admission.matrix_contract(args.matrix,p["campaign"])
    normalized_receipt=core.verify_receipt(receipt_path,client,required,str(spec["protocol"]),campaign)
    audit_path=p["audits"]/(client+".json")
    if audit_path.exists() or audit_path.is_symlink():
        core.verify_server_audit(audit_path,normalized_receipt,client)
    else:
        audit_fetch.fetch(args.matrix,p["campaign"],receipt_path,client,args.token_env,audit_path,args.attempts,args.interval_seconds)

    with admission.progress_lock(args.progress_out):
        merged=admission.merge(args.matrix,p["campaign"],receipt_path,audit_path,client,args.progress_out,allow_campaign_supersede=args.allow_campaign_supersede)
        core.write_json_atomic_replace(args.progress_out,merged,"MCP_EXTERNAL_INTEROP_PROGRESS")
    status=progress_status(args.matrix,state,args.progress_out)
    result={
        "authority":AUTHORITY,
        "action":"ADMITTED",
        "clientId":client,
        "certifiedClientCount":len(status["certified"]),
        "complete":status["complete"],
        "nextClient":status["nextClient"],
        "evidencePath":None,
        "physicalCertified":False,
    }
    if status["complete"]:
        result.update({
            "nextActionCode":"RUN_C7W_SEAL",
            "nextCommand":runner_command(state,"seal"),
            "detail":"all four named clients are admitted; run the independent bulk seal before Git/C9 handoff",
        })
    else:
        next_client=status["nextClient"]
        result.update(external_client_action(state,next_client))
    return result


def seal(args:argparse.Namespace)->dict:
    root=Path.cwd().resolve()
    args.matrix=require_canonical_matrix(root,args.matrix)
    state=secure_state_dir(args.state_dir)
    p=paths(state)
    campaign=core.load(p["campaign"],"ACTIVE_CAMPAIGN")
    require_active_campaign_source(root,campaign)
    progress=progress_status(args.matrix,state,args.progress_out,require_live=False)
    value=None
    if not progress["complete"]:
        if not complete_bulk_artifacts_present(state):
            raise RuntimeError(f"MCP_EXTERNAL_LOCAL_SEAL_PROGRESS_INCOMPLETE next={progress.get('nextClient') or 'unknown'}")
        value=core.seal(args.matrix,p["campaign"],p["receipts"],p["audits"])
        with admission.progress_lock(args.progress_out):
            current=progress_status(args.matrix,state,args.progress_out,require_live=False)
            if not current["complete"]:
                recovered=recover_complete_progress_from_bulk(args.matrix,p["campaign"],value,args.progress_out)
                revalidated=core.seal(args.matrix,p["campaign"],p["receipts"],p["audits"])
                if revalidated!=value:
                    raise RuntimeError("MCP_EXTERNAL_LOCAL_RECOVERY_BULK_CHANGED_DURING_RECONCILIATION")
                value=revalidated
                core.write_json_atomic_replace(args.progress_out,recovered,"MCP_EXTERNAL_INTEROP_PROGRESS")
        progress=progress_status(args.matrix,state,args.progress_out,require_live=False)
        if not progress["complete"]:
            raise RuntimeError("MCP_EXTERNAL_LOCAL_RECOVERY_PROGRESS_INCOMPLETE")
    persisted_progress=core.load(args.progress_out,"PROGRESS")
    projected=admission.final_evidence(persisted_progress,args.progress_out)
    if value is None:
        value=core.seal(args.matrix,p["campaign"],p["receipts"],p["audits"])
    if value!=projected:
        raise RuntimeError("MCP_EXTERNAL_LOCAL_SEAL_PROGRESS_BULK_DRIFT")
    core.write_json_once_or_identical(args.evidence_out,value,"MCP_EXTERNAL_INTEROP_EVIDENCE")
    out={
        "authority":AUTHORITY,
        "action":"SEALED",
        "campaignId":value["campaignId"],
        "sourceCommitSHA":value["sourceCommitSHA"],
        "certifiedClientCount":value["certifiedClientCount"],
        "evidencePath":str(args.evidence_out),
        "externalCertificationPass":value["externalCertificationPass"],
        "physicalCertified":False,
    }
    out.update(git_handoff(root,args.evidence_out,args.progress_out))
    return out


def status(args:argparse.Namespace)->dict:
    root=Path.cwd().resolve()
    args.matrix=require_canonical_matrix(root,args.matrix)
    state=Path(os.path.abspath(args.state_dir))
    if state.exists() or state.is_symlink():
        if state.is_symlink() or not state.is_dir():
            raise RuntimeError("MCP_EXTERNAL_LOCAL_STATE_DIR_INVALID")
        if (args.evidence_out.exists() or args.evidence_out.is_symlink()) and not args.progress_out.exists():
            raise RuntimeError("MCP_EXTERNAL_LOCAL_EVIDENCE_WITHOUT_PROGRESS")
        try:
            value=progress_status(args.matrix,state,args.progress_out)
        except RuntimeError as exc:
            if "MCP_EXTERNAL_CAMPAIGN_EXPIRED" not in str(exc):
                raise
            try:
                historical=progress_status(args.matrix,state,args.progress_out,require_live=False)
            except RuntimeError as historical_exc:
                if "MCP_EXTERNAL_CAMPAIGN_EXPIRED" not in str(historical_exc):
                    raise
                historical={"complete":False}
            if historical["complete"]:
                value=historical
            elif complete_bulk_artifacts_present(state):
                return captured_artifact_recovery_handoff(historical,state)
            else:
                p=paths(state)
                campaign=core.load(p["campaign"],"EXPIRED_CAMPAIGN")
                campaign_id=str(campaign.get("campaignId") or "").strip()
                suffix=hashlib.sha256(campaign_id.encode("utf-8")).hexdigest()[:12] if campaign_id else "expired"
                replacement=f".state/c7w-external-interop-replacement-{suffix}"
                return {
                    "authority":AUTHORITY,
                    "action":"STATUS",
                    "stateDir":str(state),
                    "campaignPrepared":False,
                    "complete":False,
                    "recoveryRequired":True,
                    "recoveryReason":"CAMPAIGN_EXPIRED",
                    "nextActionCode":"PREPARE_REPLACEMENT_C7W_CAMPAIGN",
                    "nextCommand":runner_command(Path(replacement),"prepare"),
                    "replacementStateDir":replacement,
                    "replacementAdmitRequiresCampaignSupersede":args.progress_out.exists(),
                    "followupAdmitEnvironment":{"C7W_ALLOW_CAMPAIGN_SUPERSEDE":"true"} if args.progress_out.exists() else {},
                    "detail":"the source-bound C7W campaign expired; prepare a fresh campaign and explicitly supersede only the incomplete canonical progress on the first admission",
                    "physicalCertified":False,
                }
        if (args.evidence_out.exists() or args.evidence_out.is_symlink()) and not value["complete"]:
            raise RuntimeError("MCP_EXTERNAL_LOCAL_EVIDENCE_WITH_INCOMPLETE_PROGRESS")
    else:
        if args.progress_out.exists() or args.progress_out.is_symlink() or args.evidence_out.exists() or args.evidence_out.is_symlink():
            raise RuntimeError("MCP_EXTERNAL_LOCAL_STATE_MISSING_WITH_CANONICAL_EVIDENCE")
        value={"certified":[],"missing":list(core.CLIENTS),"complete":False,"nextClient":core.CLIENTS[0],"campaignPrepared":False}
    value.update({"authority":AUTHORITY,"action":"STATUS","stateDir":str(state),"physicalCertified":False})
    if value["complete"]:
        p=paths(state)
        if not args.evidence_out.exists():
            value.update({
                "nextActionCode":"RUN_C7W_SEAL",
                "nextCommand":runner_command(state,"seal"),
                "detail":"all four named clients are admitted; resume the independent bulk seal to reconstruct or persist final C7W evidence",
            })
            return value
        if not args.evidence_out.is_file() or args.evidence_out.is_symlink():
            raise RuntimeError("MCP_EXTERNAL_LOCAL_COMPLETE_EVIDENCE_INVALID")
        rebuilt=core.seal(args.matrix,p["campaign"],p["receipts"],p["audits"])
        persisted=core.load(args.evidence_out,"EVIDENCE")
        if rebuilt!=persisted:
            raise RuntimeError("MCP_EXTERNAL_LOCAL_EVIDENCE_DRIFT")
        value.update(git_handoff(root,args.evidence_out,args.progress_out))
    else:
        if complete_bulk_artifacts_present(state):
            return captured_artifact_recovery_handoff(value,state)
        if value.get("campaignPrepared"):
            p=paths(state)
            campaign=core.load(p["campaign"],"ACTIVE_CAMPAIGN")
            try:
                require_active_campaign_source(root,campaign)
            except RuntimeError as exc:
                head=subprocess.run(["git","rev-parse","HEAD"],cwd=root,env=clean_git_env(),text=True,capture_output=True,check=False)
                current_sha=head.stdout.strip().lower() if head.returncode==0 else ""
                value.update({
                    "nextActionCode":"RERUN_C7W_ON_CURRENT_SOURCE",
                    "nextCommand":runner_command(Path(f".state/c7w-external-interop-{current_sha[:12] or 'current'}"),"prepare"),
                    "requiredInputs":["C7W_MCP_ENDPOINT","C7W_OAUTH_CLIENT_MAP","C7W_PLATFORM_ADMIN_TOKEN"],
                    "detail":str(exc)+"; active campaign source is stale before the next external client execution",
                })
                return value
            next_client=value.get("nextClient")
            value.update(external_client_action(state,next_client))
        else:
            value.update({
                "nextActionCode":"PREPARE_C7W_CAMPAIGN",
                "nextCommand":runner_command(state,"prepare"),
                "requiredInputs":["C7W_MCP_ENDPOINT","C7W_OAUTH_CLIENT_MAP","C7W_PLATFORM_ADMIN_TOKEN"],
                "detail":"prepare a live source-bound C7W campaign before external client execution",
            })
    return value


def parser()->argparse.ArgumentParser:
    p=argparse.ArgumentParser()
    p.add_argument("--matrix",type=Path,default=CANONICAL_MATRIX_REL)
    p.add_argument("--state-dir",type=Path,default=Path(os.environ.get("C7W_STATE_DIR",str(DEFAULT_STATE))))
    p.add_argument("--progress-out",type=Path,default=CANONICAL_PROGRESS_REL)
    p.add_argument("--evidence-out",type=Path,default=CANONICAL_EVIDENCE_REL)
    sub=p.add_subparsers(dest="command",required=True)

    prepare_p=sub.add_parser("prepare")
    prepare_p.add_argument("--endpoint",default=os.environ.get("C7W_MCP_ENDPOINT",""))
    _oauth_map=os.environ.get("C7W_OAUTH_CLIENT_MAP","").strip()
    prepare_p.add_argument("--oauth-client-map",type=Path,default=Path(_oauth_map) if _oauth_map else None)
    prepare_p.add_argument("--token-env",default=os.environ.get("C7W_PLATFORM_ADMIN_TOKEN_ENV","C7W_PLATFORM_ADMIN_TOKEN"))
    prepare_p.add_argument("--source-commit-sha",default="")

    admit_p=sub.add_parser("admit")
    admit_p.add_argument("--client",choices=core.CLIENTS,required=True)
    admit_p.add_argument("--capture",type=Path,required=True)
    admit_p.add_argument("--token-env",default=os.environ.get("C7W_PLATFORM_ADMIN_TOKEN_ENV","C7W_PLATFORM_ADMIN_TOKEN"))
    admit_p.add_argument("--attempts",type=int,default=15)
    admit_p.add_argument("--interval-seconds",type=float,default=2.0)
    admit_p.add_argument("--allow-campaign-supersede",action="store_true")

    sub.add_parser("status")
    sub.add_parser("seal")
    return p


def main()->int:
    args=parser().parse_args()
    root=Path.cwd().resolve()
    args.progress_out=require_canonical_artifact_path(root,args.progress_out,CANONICAL_PROGRESS_REL,"PROGRESS")
    args.evidence_out=require_canonical_artifact_path(root,args.evidence_out,CANONICAL_EVIDENCE_REL,"EVIDENCE")
    if args.command=="prepare":
        result=prepare(args)
    elif args.command=="admit":
        result=admit(args)
    elif args.command=="seal":
        result=seal(args)
    else:
        result=status(args)
    result["workingDirectory"]=str(root)
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
