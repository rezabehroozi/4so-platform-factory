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
        "progress":state/"progress.json",
        "evidence":state/"mcp-external-client-interoperability-evidence.json",
        "packets":state/"packets",
        "templates":state/"capture-templates",
        "receipts":state/"receipts",
        "audits":state/"audits",
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


def progress_status(matrix:Path,state:Path)->dict:
    p=paths(state)
    if not p["campaign"].is_file() or p["campaign"].is_symlink():
        return {"certified":[],"missing":list(core.CLIENTS),"complete":False,"nextClient":core.CLIENTS[0],"campaignPrepared":False}
    spec,_,campaign=admission.matrix_contract(matrix,p["campaign"])
    expected=admission.base_progress(matrix,p["campaign"],campaign,spec)
    if not p["progress"].exists():
        certified=[]
    else:
        existing=core.load(p["progress"],"PROGRESS")
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

    audit_path=p["audits"]/(client+".json")
    if audit_path.exists() or audit_path.is_symlink():
        core.verify_server_audit(audit_path,receipt,client)
    else:
        audit_fetch.fetch(args.matrix,p["campaign"],receipt_path,client,args.token_env,audit_path,args.attempts,args.interval_seconds)

    with admission.progress_lock(p["progress"]):
        merged=admission.merge(args.matrix,p["campaign"],receipt_path,audit_path,client,p["progress"],allow_campaign_supersede=False)
        core.write_json_atomic_replace(p["progress"],merged,"MCP_EXTERNAL_INTEROP_PROGRESS")
        if merged["complete"]:
            evidence=admission.final_evidence(merged,p["progress"])
            core.write_json_once_or_identical(p["evidence"],evidence,"MCP_EXTERNAL_INTEROP_EVIDENCE")
    status=progress_status(args.matrix,state)
    return {
        "authority":AUTHORITY,
        "action":"ADMITTED",
        "clientId":client,
        "certifiedClientCount":len(status["certified"]),
        "complete":status["complete"],
        "nextClient":status["nextClient"],
        "evidencePath":str(p["evidence"]) if status["complete"] else None,
        "physicalCertified":False,
    }


def seal(args:argparse.Namespace)->dict:
    state=secure_state_dir(args.state_dir)
    p=paths(state)
    value=core.seal(args.matrix,p["campaign"],p["receipts"],p["audits"])
    core.write_json_once_or_identical(p["evidence"],value,"MCP_EXTERNAL_INTEROP_EVIDENCE")
    return {
        "authority":AUTHORITY,
        "action":"SEALED",
        "campaignId":value["campaignId"],
        "sourceCommitSHA":value["sourceCommitSHA"],
        "certifiedClientCount":value["certifiedClientCount"],
        "evidencePath":str(p["evidence"]),
        "externalCertificationPass":value["externalCertificationPass"],
        "physicalCertified":False,
    }


def status(args:argparse.Namespace)->dict:
    state=secure_state_dir(args.state_dir)
    value=progress_status(args.matrix,state)
    value.update({"authority":AUTHORITY,"action":"STATUS","stateDir":str(state),"physicalCertified":False})
    if value["complete"]:
        p=paths(state)
        if not p["evidence"].is_file() or p["evidence"].is_symlink():
            raise RuntimeError("MCP_EXTERNAL_LOCAL_COMPLETE_WITHOUT_EVIDENCE")
        rebuilt=core.seal(args.matrix,p["campaign"],p["receipts"],p["audits"])
        persisted=core.load(p["evidence"],"EVIDENCE")
        if rebuilt!=persisted:
            raise RuntimeError("MCP_EXTERNAL_LOCAL_EVIDENCE_DRIFT")
    return value


def parser()->argparse.ArgumentParser:
    p=argparse.ArgumentParser()
    p.add_argument("--matrix",type=Path,default=Path("lab/mcp-external-client-interop-matrix.json"))
    p.add_argument("--state-dir",type=Path,default=DEFAULT_STATE)
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
