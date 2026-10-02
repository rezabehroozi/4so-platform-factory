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
from pathlib import Path
import subprocess

import admit_mcp_external_receipt as admission
import fetch_mcp_external_audit_window as audit_fetch
import finalize_mcp_external_client_receipt as finalizer
import prepare_mcp_external_client_execution as packet_builder
import prepare_mcp_external_interop_campaign as campaign_builder
import seal_mcp_external_interop as core

AUTHORITY="MCP_EXTERNAL_LOCAL_EXECUTION_RUNNER_V1"
DEFAULT_STATE=Path(".state/c7w-external-interop")


def secure_state_dir(path:Path)->Path:
    path=Path(os.path.abspath(path))
    for parent in reversed(path.parents):
        if parent.exists() and (parent.is_symlink() or not parent.is_dir()):
            raise RuntimeError("MCP_EXTERNAL_LOCAL_STATE_PARENT_INVALID")
    path.mkdir(parents=True,exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError("MCP_EXTERNAL_LOCAL_STATE_DIR_INVALID")
    path.chmod(0o700)
    for name in ("packets","capture-templates","receipts","audits"):
        child=path/name
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
        "receipts":state/"receipts",
        "audits":state/"audits",
    }


def git_handoff(root:Path,evidence_path:Path,progress_path:Path)->dict:
    root=root.resolve()
    def run_git(*args:str)->subprocess.CompletedProcess:
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=False)
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
            "nextCommand":["env",f"C7W_STATE_DIR=.state/c7w-external-interop-{current_sha[:12]}","make","c7w-prepare"],
            "requiredInputs":["C7W_MCP_ENDPOINT","C7W_OAUTH_CLIENT_MAP","C7W_PLATFORM_ADMIN_TOKEN"],
            "certifiedSourceCommitSHA":certified_sha,
            "currentSourceCommitSHA":current_sha,
            "detail":str(exc)+"; source changed beyond evidence-only C7W files, so C9 must not use the stale external certification",
        }
    return {
        "nextActionCode":"RUN_C9_SEAL",
        "nextCommand":["make","c9-seal"],
        "sourceCommitSHA":current_sha,
        "certifiedSourceCommitSHA":certified_sha,
        "detail":"C7W evidence is committed and source lineage is evidence-only; C9 may run",
    }


def capture_template(packet:dict)->dict:
    requirements=packet.get("receiptRequirements") or {}
    audited=set(requirements.get("requestIds") or [])
    checks={}
    for row in packet.get("checks") or []:
        check_id=str(row.get("id") or "")
        if not check_id:
            raise RuntimeError("MCP_EXTERNAL_LOCAL_PACKET_CHECK_INVALID")
        checks[check_id]={"passed":False,**({"requestId":""} if check_id in audited else {})}
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
    return {
        "authority":AUTHORITY,
        "action":"PREPARED",
        "resumed":resumed,
        "campaignId":campaign["campaignId"],
        "sourceCommitSHA":campaign["sourceCommitSHA"],
        "runtimeVersion":campaign["runtimeVersion"],
        "stateDir":str(state),
        "externalExecutionRequired":True,
        "clients":list(core.CLIENTS),
        "physicalCertified":False,
    }


def progress_status(matrix:Path,state:Path,progress_path:Path)->dict:
    p=paths(state)
    if not p["campaign"].is_file() or p["campaign"].is_symlink():
        if progress_path.exists() or progress_path.is_symlink():
            raise RuntimeError("MCP_EXTERNAL_LOCAL_CAMPAIGN_MISSING_WITH_CANONICAL_PROGRESS")
        return {"certified":[],"missing":list(core.CLIENTS),"complete":False,"nextClient":core.CLIENTS[0],"campaignPrepared":False}
    spec,_,campaign=admission.matrix_contract(matrix,p["campaign"])
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


def admit(args:argparse.Namespace)->dict:
    state=secure_state_dir(args.state_dir)
    p=paths(state)
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
        merged=admission.merge(args.matrix,p["campaign"],receipt_path,audit_path,client,args.progress_out,allow_campaign_supersede=False)
        core.write_json_atomic_replace(args.progress_out,merged,"MCP_EXTERNAL_INTEROP_PROGRESS")
        if merged["complete"]:
            evidence=admission.final_evidence(merged,args.progress_out)
            core.write_json_once_or_identical(args.evidence_out,evidence,"MCP_EXTERNAL_INTEROP_EVIDENCE")
    status=progress_status(args.matrix,state,args.progress_out)
    return {
        "authority":AUTHORITY,
        "action":"ADMITTED",
        "clientId":client,
        "certifiedClientCount":len(status["certified"]),
        "complete":status["complete"],
        "nextClient":status["nextClient"],
        "evidencePath":str(args.evidence_out) if status["complete"] else None,
        "physicalCertified":False,
    }


def seal(args:argparse.Namespace)->dict:
    state=secure_state_dir(args.state_dir)
    p=paths(state)
    progress=progress_status(args.matrix,state,args.progress_out)
    if not progress["complete"]:
        raise RuntimeError(f"MCP_EXTERNAL_LOCAL_SEAL_PROGRESS_INCOMPLETE next={progress.get('nextClient') or 'unknown'}")
    persisted_progress=core.load(args.progress_out,"PROGRESS")
    projected=admission.final_evidence(persisted_progress,args.progress_out)
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
    out.update(git_handoff(Path.cwd(),args.evidence_out,args.progress_out))
    return out


def status(args:argparse.Namespace)->dict:
    state=Path(os.path.abspath(args.state_dir))
    if state.exists() or state.is_symlink():
        if state.is_symlink() or not state.is_dir():
            raise RuntimeError("MCP_EXTERNAL_LOCAL_STATE_DIR_INVALID")
        if (args.evidence_out.exists() or args.evidence_out.is_symlink()) and not args.progress_out.exists():
            raise RuntimeError("MCP_EXTERNAL_LOCAL_EVIDENCE_WITHOUT_PROGRESS")
        value=progress_status(args.matrix,state,args.progress_out)
        if (args.evidence_out.exists() or args.evidence_out.is_symlink()) and not value["complete"]:
            raise RuntimeError("MCP_EXTERNAL_LOCAL_EVIDENCE_WITH_INCOMPLETE_PROGRESS")
    else:
        if args.progress_out.exists() or args.progress_out.is_symlink() or args.evidence_out.exists() or args.evidence_out.is_symlink():
            raise RuntimeError("MCP_EXTERNAL_LOCAL_STATE_MISSING_WITH_CANONICAL_EVIDENCE")
        value={"certified":[],"missing":list(core.CLIENTS),"complete":False,"nextClient":core.CLIENTS[0],"campaignPrepared":False}
    value.update({"authority":AUTHORITY,"action":"STATUS","stateDir":str(state),"physicalCertified":False})
    if value["complete"]:
        p=paths(state)
        if not args.evidence_out.is_file() or args.evidence_out.is_symlink():
            raise RuntimeError("MCP_EXTERNAL_LOCAL_COMPLETE_WITHOUT_EVIDENCE")
        rebuilt=core.seal(args.matrix,p["campaign"],p["receipts"],p["audits"])
        persisted=core.load(args.evidence_out,"EVIDENCE")
        if rebuilt!=persisted:
            raise RuntimeError("MCP_EXTERNAL_LOCAL_EVIDENCE_DRIFT")
        value.update(git_handoff(Path.cwd(),args.evidence_out,args.progress_out))
    else:
        if value.get("campaignPrepared"):
            next_client=value.get("nextClient")
            value.update({
                "nextActionCode":"RUN_EXTERNAL_CLIENT",
                "nextCommand":["env",f"C7W_CLIENT={next_client}","C7W_CAPTURE=/secure/"+str(next_client)+".capture.json","make","c7w-admit"],
                "detail":"execute the named external client with its prepared packet, then admit the resulting capture",
            })
        else:
            value.update({
                "nextActionCode":"PREPARE_C7W_CAMPAIGN",
                "nextCommand":["make","c7w-prepare"],
                "detail":"prepare a live source-bound C7W campaign before external client execution",
            })
    return value


def parser()->argparse.ArgumentParser:
    p=argparse.ArgumentParser()
    p.add_argument("--matrix",type=Path,default=Path("lab/mcp-external-client-interop-matrix.json"))
    p.add_argument("--state-dir",type=Path,default=DEFAULT_STATE)
    p.add_argument("--progress-out",type=Path,default=Path("lab/mcp-external-client-interop-progress.json"))
    p.add_argument("--evidence-out",type=Path,default=Path("lab/mcp-external-client-interoperability-evidence.json"))
    sub=p.add_subparsers(dest="command",required=True)

    prepare_p=sub.add_parser("prepare")
    prepare_p.add_argument("--endpoint",required=True)
    prepare_p.add_argument("--oauth-client-map",type=Path)
    prepare_p.add_argument("--token-env",default="C7W_PLATFORM_ADMIN_TOKEN")
    prepare_p.add_argument("--source-commit-sha",default="")

    admit_p=sub.add_parser("admit")
    admit_p.add_argument("--client",choices=core.CLIENTS,required=True)
    admit_p.add_argument("--capture",type=Path,required=True)
    admit_p.add_argument("--token-env",default="C7W_PLATFORM_ADMIN_TOKEN")
    admit_p.add_argument("--attempts",type=int,default=15)
    admit_p.add_argument("--interval-seconds",type=float,default=2.0)

    sub.add_parser("status")
    sub.add_parser("seal")
    return p


def main()->int:
    args=parser().parse_args()
    if args.command=="prepare":
        result=prepare(args)
    elif args.command=="admit":
        result=admit(args)
    elif args.command=="seal":
        result=seal(args)
    else:
        result=status(args)
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
