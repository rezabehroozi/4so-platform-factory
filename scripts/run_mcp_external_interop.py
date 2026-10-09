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
import platform
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
SOURCE_FREEZE_FAILURES={
    "MCP_EXTERNAL_LOCAL_GIT_ROOT_INVALID",
    "MCP_EXTERNAL_LOCAL_BRANCH_NOT_MAIN",
    "MCP_EXTERNAL_LOCAL_GIT_HEAD_INVALID",
    "MCP_EXTERNAL_LOCAL_GIT_INDEX_FLAGS_FORBIDDEN",
    "MCP_EXTERNAL_LOCAL_GIT_STATUS_UNAVAILABLE",
    "MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN",
}


def clean_git_env()->dict[str,str]:
    env=os.environ.copy()
    for key in list(env):
        if key.startswith("GIT_"):
            env.pop(key,None)
    return env


def require_safe_state_parent_chain(path:Path)->Path:
    path=Path(os.path.abspath(path))
    for parent in reversed(path.parents):
        if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
            raise RuntimeError("MCP_EXTERNAL_LOCAL_STATE_PARENT_INVALID")
    return path


def secure_state_dir(path:Path)->Path:
    path=require_safe_state_parent_chain(path)
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise RuntimeError("MCP_EXTERNAL_LOCAL_STATE_DIR_INVALID")
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
    parents=(p["receipts"],p["audits"])
    if any(parent.is_symlink() or not parent.is_dir() for parent in parents):
        return False
    for client in core.CLIENTS:
        for parent in parents:
            path=parent/(client+".json")
            if path.is_symlink() or not path.is_file():
                return False
    return True


def execution_artifacts_present(state:Path)->bool:
    p=paths(state)
    for key in ("packets","templates","captures","receipts","audits"):
        parent=p[key]
        if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
            return True
        if not parent.is_dir():
            continue
        try:
            next(parent.iterdir())
        except StopIteration:
            continue
        except OSError:
            return True
        return True
    return False


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


def source_freeze_failure(exc:BaseException)->bool:
    code=str(exc).split()[0] if str(exc).strip() else ""
    return code in SOURCE_FREEZE_FAILURES


def source_freeze_recovery_handoff(value:dict,state:Path,exc:BaseException)->dict:
    out=dict(value)
    out.update({
        "authority":AUTHORITY,
        "action":"STATUS",
        "stateDir":str(state),
        "recoveryRequired":True,
        "recoveryReason":"SOURCE_FREEZE_REQUIRED",
        "nextActionCode":"RESTORE_C7W_SOURCE_FREEZE",
        "nextCommand":["git","status","--short"],
        "requiredInputs":[],
        "detail":str(exc)+"; restore canonical clean main at the C7W evidence-only source boundary before resuming, replacing, or sealing any campaign state",
        "physicalCertified":False,
    })
    return out


def stale_campaign_source_handoff(root:Path,state:Path,progress_path:Path,value:dict,exc:BaseException)->dict:
    if source_freeze_failure(exc):
        return source_freeze_recovery_handoff(value,state,exc)
    head=subprocess.run(["git","rev-parse","HEAD"],cwd=root,env=clean_git_env(),text=True,capture_output=True,check=False)
    current_sha=head.stdout.strip().lower() if head.returncode==0 else ""
    replacement=Path(f".state/c7w-external-interop-{current_sha[:12] or 'current'}")
    supersede=progress_path.exists()
    out=dict(value)
    out.update({
        "authority":AUTHORITY,
        "action":"STATUS",
        "stateDir":str(state),
        "recoveryRequired":True,
        "recoveryReason":"CAMPAIGN_SOURCE_DRIFT",
        "nextActionCode":"RERUN_C7W_ON_CURRENT_SOURCE",
        "nextCommand":runner_command(replacement,"prepare"),
        "requiredInputs":["C7W_MCP_ENDPOINT","C7W_OAUTH_CLIENT_MAP","C7W_PLATFORM_ADMIN_TOKEN"],
        "replacementStateDir":str(replacement),
        "replacementAdmitRequiresCampaignSupersede":supersede,
        "followupAdmitEnvironment":{"C7W_ALLOW_CAMPAIGN_SUPERSEDE":"true"} if supersede else {},
        "historicalStateDir":str(state),
        "detail":str(exc)+"; active campaign source is stale, so preserve the historical state and prepare a fresh source-bound campaign before any seal or external client continuation",
        "physicalCertified":False,
    })
    return out


def orphan_execution_state_handoff(value:dict,state:Path)->dict:
    campaign_path=paths(state)["campaign"]
    out=dict(value)
    out.update({
        "authority":AUTHORITY,
        "action":"STATUS",
        "stateDir":str(state),
        "recoveryRequired":True,
        "recoveryReason":"EXECUTION_ARTIFACT_CAMPAIGN_STATE_MISSING",
        "nextActionCode":"RESTORE_C7W_CAMPAIGN_STATE",
        "nextCommand":[],
        "requiredStatePath":str(campaign_path),
        "detail":"C7W execution artifacts exist without their campaign authority; restore the exact historical campaign state before reconciliation, and do not seal or overwrite this state with a new campaign",
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
    head=subprocess.run(["git","rev-parse","--verify","HEAD"],cwd=root,env=git_env,text=True,capture_output=True,check=False)
    head_sha=head.stdout.strip().lower() if head.returncode==0 else ""
    if not core.COMMIT.fullmatch(head_sha):
        raise RuntimeError("MCP_EXTERNAL_LOCAL_GIT_HEAD_INVALID")
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


def require_prepare_source_snapshot(root:Path,expected_sha:str)->None:
    require_c7w_source_freeze(root)
    current_sha=campaign_builder.source_commit_sha()
    if current_sha!=expected_sha:
        raise RuntimeError("MCP_EXTERNAL_LOCAL_SOURCE_CHANGED_DURING_PREPARE")


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
    if diff.returncode!=0 or tracked.returncode not in (0,1):
        return {
            "nextActionCode":"INSPECT_C7W_EVIDENCE_GIT_STATE",
            "nextCommand":["git","status","--short","--",*rels],
            "detail":"unable to establish Git state for canonical C7W evidence",
        }
    current_sha=head.stdout.strip().lower()
    evidence=core.load(evidence_path,"C7W_EVIDENCE")
    certified_sha=str(evidence.get("sourceCommitSHA") or "").strip().lower()
    try:
        core.validate_evidence_only_source_lineage(root,certified_sha,current_sha,"MCP_EXTERNAL_LOCAL_HANDOFF")
    except RuntimeError as exc:
        if tracked.returncode!=0 or diff.stdout.strip():
            return {
                "nextActionCode":"INSPECT_STALE_C7W_EVIDENCE_GIT_STATE",
                "nextCommand":["git","status","--short","--",*rels],
                "certifiedSourceCommitSHA":certified_sha,
                "currentSourceCommitSHA":current_sha,
                "detail":str(exc)+"; canonical C7W evidence is stale and not cleanly committed; do not commit stale evidence into the current source lineage, inspect/retire only the canonical C7W evidence paths and then rerun preflight",
            }
        return {
            "nextActionCode":"RETIRE_STALE_C7W_EVIDENCE",
            "nextCommand":["git","rm","--",*rels],
            "followupCommand":["git","commit","-m","evidence: retire stale external MCP interoperability"],
            "rerunCommand":[sys.executable,"scripts/c7w_preflight.py","--root",str(root)],
            "requiredInputs":["C7W_MCP_ENDPOINT","C7W_OAUTH_CLIENT_MAP","C7W_PLATFORM_ADMIN_TOKEN"],
            "certifiedSourceCommitSHA":certified_sha,
            "currentSourceCommitSHA":current_sha,
            "detail":str(exc)+"; source changed beyond evidence-only C7W files, so retire the stale canonical certification in a dedicated evidence-only commit, then rerun C7W preflight on the new exact HEAD; the prior complete certification remains preserved in Git history",
        }
    if tracked.returncode!=0 or diff.stdout.strip():
        return {
            "nextActionCode":"COMMIT_C7W_EVIDENCE",
            "nextCommand":["git","add",*rels],
            "followupCommand":["git","commit","-m","evidence: seal external MCP interoperability"],
            "detail":"C7W is complete, source lineage is still valid, and evidence is not yet part of the exact Git SHA required by C9",
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
    if sys.platform.startswith("linux") and str(platform.machine() or "").strip().lower() in {"x86_64","amd64"}:
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
    code="MCP_EXTERNAL_LOCAL_CLIENT_HANDOFF_PATH_INVALID"
    if state.is_symlink() or not state.is_dir():
        raise RuntimeError(code)
    for parent in (p["packets"],p["templates"],p["captures"]):
        if parent.is_symlink() or not parent.is_dir():
            raise RuntimeError(code)
    packet_path=p["packets"]/(client+".json")
    template_path=p["templates"]/(client+".json")
    capture_path=p["captures"]/(client+".capture.json")
    for required in (packet_path,template_path):
        if required.is_symlink() or not required.is_file():
            raise RuntimeError(code)
    if capture_path.is_symlink() or (capture_path.exists() and not capture_path.is_file()):
        raise RuntimeError(code)
    capture=str(capture_path)
    return {
        "clientId":client,
        "packetPath":str(packet_path),
        "captureTemplatePath":str(template_path),
        "expectedCapturePath":capture,
        "requiredCaptureAuthority":"MCP_EXTERNAL_CLIENT_CAPTURE_V1",
        "admitCommand":runner_command(state,"admit","--client",client,"--capture",capture),
    }


def require_client_capture_path(state:Path,client:str,candidate:Path)->Path:
    client=str(client or "").strip().lower()
    code="MCP_EXTERNAL_LOCAL_CAPTURE_PATH_INVALID"
    if client not in core.CLIENTS:
        raise RuntimeError(code)
    state=Path(os.path.abspath(state))
    p=paths(state)
    capture_parent=p["captures"]
    raw=Path(candidate)
    actual=Path(os.path.abspath(raw if raw.is_absolute() else Path.cwd()/raw))
    expected=capture_parent/(client+".capture.json")
    if state.is_symlink() or not state.is_dir() or capture_parent.is_symlink() or not capture_parent.is_dir():
        raise RuntimeError(code)
    if actual!=expected or expected.is_symlink() or not expected.is_file():
        raise RuntimeError(code)
    return expected


def external_client_action(state:Path,client:str)->dict:
    handoff=client_execution_handoff(state,client)
    return {
        "nextActionCode":"RUN_EXTERNAL_CLIENT",
        "nextCommand":[],
        "nextClientHandoff":handoff,
        "postExternalExecutionCommand":handoff["admitCommand"],
        "detail":"execute the named external client with its exact prepared packet and capture template; only after the capture is complete run postExternalExecutionCommand",
    }


def replacement_campaign_supersede_handoff(progress_path:Path,campaign:dict,*,resumed:bool)->dict:
    if resumed or not progress_path.exists():
        return {}
    if progress_path.is_symlink() or not progress_path.is_file():
        raise RuntimeError("MCP_EXTERNAL_LOCAL_REPLACEMENT_PROGRESS_INVALID")
    existing=core.load(progress_path,"REPLACEMENT_PROGRESS")
    old_campaign=str(existing.get("campaignId") or "").strip() if isinstance(existing,dict) else ""
    new_campaign=str((campaign or {}).get("campaignId") or "").strip()
    if not old_campaign or not new_campaign:
        raise RuntimeError("MCP_EXTERNAL_LOCAL_REPLACEMENT_PROGRESS_INVALID")
    if old_campaign==new_campaign:
        return {}
    clients=existing.get("clients") if isinstance(existing,dict) else None
    certified_count=existing.get("certifiedClientCount") if isinstance(existing,dict) else None
    if type(certified_count) is not int or certified_count<0 or certified_count>len(core.CLIENTS) or not isinstance(clients,list) or len(clients)!=certified_count:
        raise RuntimeError("MCP_EXTERNAL_LOCAL_REPLACEMENT_PROGRESS_INVALID")
    if existing.get("complete") is True or certified_count>=len(core.CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_LOCAL_REPLACEMENT_PROGRESS_COMPLETE_FORBIDDEN")
    environment={"C7W_ALLOW_CAMPAIGN_SUPERSEDE":"true"}
    return {
        "replacementAdmitRequiresCampaignSupersede":True,
        "followupAdmitEnvironment":environment,
        "postExternalExecutionEnvironment":environment,
    }


def apply_replacement_campaign_supersede_command(result:dict,supersede_handoff:dict)->None:
    if supersede_handoff.get("replacementAdmitRequiresCampaignSupersede") is not True:
        return
    handoff=result.get("nextClientHandoff")
    command=handoff.get("admitCommand") if isinstance(handoff,dict) else None
    post=result.get("postExternalExecutionCommand")
    if not isinstance(command,list) or not command or post!=command or "--allow-campaign-supersede" in command:
        raise RuntimeError("MCP_EXTERNAL_LOCAL_REPLACEMENT_ADMIT_COMMAND_INVALID")
    fenced=[*command,"--allow-campaign-supersede"]
    handoff["admitCommand"]=fenced
    result["postExternalExecutionCommand"]=list(fenced)


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
    campaign_present=p["campaign"].exists() or p["campaign"].is_symlink()
    if not campaign_present and execution_artifacts_present(state):
        raise RuntimeError("MCP_EXTERNAL_LOCAL_ORPHAN_STATE_REQUIRES_RECOVERY")
    source_sha=campaign_builder.source_commit_sha(args.source_commit_sha)
    matrix=core.load(args.matrix,"MATRIX")
    core.validate_matrix_contract(matrix,"MCP_EXTERNAL_MATRIX")
    if campaign_present:
        campaign=campaign_builder.resume_existing(args.matrix,args.endpoint,p["campaign"],source_sha)
        resumed=True
    else:
        if args.oauth_client_map is None:
            raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_REQUIRED")
        bindings,binding_sha=campaign_builder.load_oauth_bindings(args.oauth_client_map)
        runtime_identity=campaign_builder.runtime_identity_readback(args.endpoint,args.token_env,source_sha)
        trusted=campaign_builder.trusted_client_readback(args.endpoint,bindings,args.token_env)
        preflight=campaign_builder.live_preflight(args.endpoint)
        require_prepare_source_snapshot(root,source_sha)
        campaign=campaign_builder.prepare(args.matrix,args.endpoint,preflight,binding_sha,trusted,runtime_identity)
        core.write_json_once_or_identical(p["campaign"],campaign,"MCP_EXTERNAL_CAMPAIGN")
        resumed=False
    supersede_handoff=replacement_campaign_supersede_handoff(args.progress_out,campaign,resumed=resumed)
    for client in core.CLIENTS:
        packet=packet_builder.packet(args.matrix,p["campaign"],client)
        packet_path=p["packets"]/(client+".json")
        core.write_json_once_or_identical(packet_path,packet,"MCP_EXTERNAL_EXECUTION_PACKET")
        template_path=p["templates"]/(client+".json")
        core.write_json_once_or_identical(template_path,capture_template(packet),"MCP_EXTERNAL_CAPTURE_TEMPLATE")
    require_prepare_source_snapshot(root,source_sha)
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
        result.update(supersede_handoff)
        apply_replacement_campaign_supersede_command(result,supersede_handoff)
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
    args.capture=require_client_capture_path(state,client,args.capture)
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
    state=require_safe_state_parent_chain(args.state_dir)
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
                p=paths(state)
                campaign=core.load(p["campaign"],"EXPIRED_CAMPAIGN")
                try:
                    require_active_campaign_source(root,campaign)
                except RuntimeError as source_exc:
                    return stale_campaign_source_handoff(root,state,args.progress_out,historical,source_exc)
                return captured_artifact_recovery_handoff(historical,state)
            else:
                try:
                    require_c7w_source_freeze(root)
                except RuntimeError as source_exc:
                    return source_freeze_recovery_handoff(historical,state,source_exc)
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
                    "requiredInputs":["C7W_MCP_ENDPOINT","C7W_OAUTH_CLIENT_MAP","C7W_PLATFORM_ADMIN_TOKEN"],
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
            campaign=core.load(p["campaign"],"ACTIVE_CAMPAIGN")
            try:
                require_active_campaign_source(root,campaign)
            except RuntimeError as exc:
                if source_freeze_failure(exc):
                    return source_freeze_recovery_handoff(value,state,exc)
                if "SOURCE_DELTA_NOT_EVIDENCE_ONLY" not in str(exc):
                    raise
                if not complete_bulk_artifacts_present(state):
                    value.update({
                        "recoveryRequired":True,
                        "recoveryReason":"COMPLETE_PROGRESS_SOURCE_DRIFT",
                        "nextActionCode":"RESTORE_C7W_BULK_STATE",
                        "nextCommand":[],
                        "detail":str(exc)+"; canonical progress is complete but the source-bound receipt/audit set is incomplete, so restore the historical bulk state before retiring progress or rerunning C7W",
                    })
                    return value
                try:
                    progress_rel=args.progress_out.resolve().relative_to(root).as_posix()
                except ValueError as path_exc:
                    raise RuntimeError("MCP_EXTERNAL_LOCAL_PROGRESS_PATH_INVALID") from path_exc
                tracked=subprocess.run(
                    ["git","ls-files","--error-unmatch",progress_rel],
                    cwd=root,env=clean_git_env(),text=True,capture_output=True,check=False,
                )
                if tracked.returncode not in (0,1):
                    value.update({
                        "recoveryRequired":True,
                        "recoveryReason":"COMPLETE_PROGRESS_SOURCE_DRIFT",
                        "nextActionCode":"INSPECT_C7W_PROGRESS_GIT_STATE",
                        "nextCommand":["git","status","--short","--",progress_rel],
                        "detail":"unable to establish whether the stale complete canonical progress is tracked; inspect its Git state before retirement",
                    })
                    return value
                value.update({
                    "recoveryRequired":True,
                    "recoveryReason":"COMPLETE_PROGRESS_SOURCE_DRIFT",
                    "nextActionCode":"RETIRE_STALE_C7W_PROGRESS",
                    "nextCommand":["git","rm","-f","--",progress_rel] if tracked.returncode==0 else ["git","clean","-f","--",progress_rel],
                    "rerunCommand":[sys.executable,"scripts/c7w_preflight.py","--root",str(root)],
                    "requiredInputs":["C7W_MCP_ENDPOINT","C7W_OAUTH_CLIENT_MAP","C7W_PLATFORM_ADMIN_TOKEN"],
                    "historicalStateDir":str(state),
                    "detail":str(exc)+"; all four historical receipt/audit pairs remain preserved in the source-bound private state, so retire only the stale canonical progress and rerun preflight on the current source",
                })
                if tracked.returncode==0:
                    value["followupCommand"]=["git","commit","-m","evidence: retire stale complete MCP interoperability progress"]
                return value
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
        if value.get("campaignPrepared"):
            p=paths(state)
            campaign=core.load(p["campaign"],"ACTIVE_CAMPAIGN")
            try:
                require_active_campaign_source(root,campaign)
            except RuntimeError as exc:
                return stale_campaign_source_handoff(root,state,args.progress_out,value,exc)
            if complete_bulk_artifacts_present(state):
                return captured_artifact_recovery_handoff(value,state)
            next_client=value.get("nextClient")
            value.update(external_client_action(state,next_client))
        elif execution_artifacts_present(state):
            return orphan_execution_state_handoff(value,state)
        else:
            try:
                require_c7w_source_freeze(root)
            except RuntimeError as exc:
                return source_freeze_recovery_handoff(value,state,exc)
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
    admit_p.add_argument("--allow-campaign-supersede",action="store_true",default=str(os.environ.get("C7W_ALLOW_CAMPAIGN_SUPERSEDE","false")).strip().lower() in {"1","true","yes"})

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
