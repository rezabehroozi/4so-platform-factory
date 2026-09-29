#!/usr/bin/env python3
"""Incrementally admit one server-audit-witnessed named MCP client receipt."""
from __future__ import annotations
import argparse, json
from pathlib import Path
import seal_mcp_external_interop as core

AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1"

def matrix_contract(matrix_path:Path,campaign_path:Path):
    matrix=core.load(matrix_path,"MATRIX"); spec=matrix.get("spec") or {}
    if matrix.get("authority")!=core.MATRIX_AUTHORITY or spec.get("externalCertificationStatus")!="pending":
        raise RuntimeError("MCP_EXTERNAL_MATRIX_STATE_INVALID")
    protocol=str(spec.get("protocol") or ""); required=list(spec.get("sharedRequiredChecks") or [])
    declared=[r.get("id") for r in spec.get("clients") or [] if isinstance(r,dict)]
    surfaces={r.get("id"):r.get("displayName") for r in spec.get("clients") or [] if isinstance(r,dict)}
    if protocol!="2026-07-28" or required!=list(core.REQUIRED_CHECKS) or declared!=list(core.CLIENTS) or surfaces!=core.CLIENT_SURFACES:
        raise RuntimeError("MCP_EXTERNAL_MATRIX_CONTRACT_INVALID")
    return spec,required,core.verify_campaign(campaign_path,matrix_path,spec)

def base_progress(matrix_path:Path,campaign_path:Path,campaign:dict,spec:dict)->dict:
    return {"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress","authority":AUTHORITY,
      "matrixAuthority":core.MATRIX_AUTHORITY,"matrixSha256":core.sha256(matrix_path),
      "campaignAuthority":core.CAMPAIGN_AUTHORITY,"campaignId":campaign["campaignId"],"campaignSha256":core.sha256(campaign_path),
      "protocol":spec["protocol"],"transport":spec["transport"],"endpoint":campaign["endpoint"],"clients":[],
      "certifiedClientCount":0,"complete":False,"allAdmittedReceiptsPass":True,"serverAuditWitnessPass":False,
      "externalCertificationPass":False,"runtimeCertified":False,"physicalCertified":False}

def validate_existing(existing:dict,expected:dict)->dict[str,dict]:
    if existing.get("authority")!=AUTHORITY or existing.get("kind")!="MCPExternalClientInteropProgress":
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_AUTHORITY_INVALID")
    for key in ("matrixAuthority","matrixSha256","campaignAuthority","campaignId","campaignSha256","protocol","transport","endpoint"):
        if existing.get(key)!=expected.get(key): raise RuntimeError(f"MCP_EXTERNAL_PROGRESS_CAMPAIGN_DRIFT {key}")
    if existing.get("runtimeCertified") is not False or existing.get("physicalCertified") is not False:
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_SCOPE_INFLATED")
    rows=existing.get("clients")
    if not isinstance(rows,list): raise RuntimeError("MCP_EXTERNAL_PROGRESS_CLIENTS_INVALID")
    by_id={}; order={name:i for i,name in enumerate(core.CLIENTS)}; last=-1
    provider_refs={}; execution_ids={}; evidence_digests={}; receipt_digests={}; challenge_digests={}; request_id_owners={}
    for row in rows:
        if not isinstance(row,dict) or row.get("clientId") not in order or row["clientId"] in by_id: raise RuntimeError("MCP_EXTERNAL_PROGRESS_CLIENT_IDENTITY_INVALID")
        if row.get("clientSurface")!=core.CLIENT_SURFACES[row["clientId"]]: raise RuntimeError("MCP_EXTERNAL_PROGRESS_CLIENT_SURFACE_INVALID")
        idx=order[row["clientId"]]
        if idx<=last: raise RuntimeError("MCP_EXTERNAL_PROGRESS_CLIENT_ORDER_INVALID")
        last=idx
        row_client=row["clientId"]
        execution_id=str(row.get("executionId") or "").strip()
        if not execution_id or len(execution_id)>160 or execution_id in execution_ids: raise RuntimeError("MCP_EXTERNAL_PROGRESS_EXECUTION_ID_INVALID")
        execution_ids[execution_id]=row_client
        provider_ref=str(row.get("providerExecutionRef") or "").strip()
        if len(provider_ref)<8 or len(provider_ref)>500 or any(ord(ch)<0x21 or ord(ch)>0x7e for ch in provider_ref): raise RuntimeError("MCP_EXTERNAL_PROGRESS_PROVIDER_EXECUTION_REF_INVALID")
        owner=provider_refs.get(provider_ref)
        if owner is not None: raise RuntimeError(f"MCP_EXTERNAL_PROGRESS_PROVIDER_EXECUTION_REUSE {row_client}:{owner}")
        provider_refs[provider_ref]=row_client
        checks=row.get("checks")
        if not isinstance(checks,dict) or set(checks)!=set(core.REQUIRED_CHECKS) or any(v is not True for v in checks.values()): raise RuntimeError("MCP_EXTERNAL_PROGRESS_CHECKS_INVALID")
        request_ids=row.get("requestIds")
        if not isinstance(request_ids,dict) or set(request_ids)!=set(core.AUDITED_CHECKS):
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_REQUEST_IDS_INVALID")
        if len(set(str(v or "").strip() for v in request_ids.values()))!=len(core.AUDITED_CHECKS):
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_REQUEST_IDS_INVALID")
        for check,rid_raw in request_ids.items():
            rid=str(rid_raw or "").strip()
            if not core.REQUEST_ID.fullmatch(rid): raise RuntimeError("MCP_EXTERNAL_PROGRESS_REQUEST_IDS_INVALID")
            previous=request_id_owners.get(rid)
            if previous is not None: raise RuntimeError(f"MCP_EXTERNAL_PROGRESS_REQUEST_ID_REUSE {row_client}:{check}:{previous}")
            request_id_owners[rid]=f"{row_client}:{check}"
        evidence_digest=str(row.get("evidenceDigest") or "")
        receipt_digest=str(row.get("externalReceiptSha256") or "")
        challenge_digest=str(row.get("challengeSha256") or "")
        if not core.SHA.fullmatch(evidence_digest) or not core.SHA.fullmatch(receipt_digest) or not core.SHA.fullmatch(challenge_digest):
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_RECEIPT_BINDING_INVALID")
        if evidence_digest in evidence_digests or receipt_digest in receipt_digests or challenge_digest in challenge_digests:
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_EVIDENCE_REUSE")
        evidence_digests[evidence_digest]=row_client; receipt_digests[receipt_digest]=row_client; challenge_digests[challenge_digest]=row_client
        witness=row.get("serverAuditWitness") or {}
        start_seq=witness.get("auditWindowStartSequence"); start_prev=str(witness.get("auditWindowPreviousDigest") or ""); head_seq=witness.get("auditHeadSequence")
        start_valid=type(start_seq) is int and start_seq>0 and type(head_seq) is int and head_seq>=start_seq and ((start_seq==1 and start_prev=="") or (start_seq>1 and core.SHA.fullmatch(start_prev)))
        if witness.get("authority")!=core.AUDIT_WITNESS_AUTHORITY or witness.get("auditMethodVersion")!=core.AUDIT_METHOD_VERSION or witness.get("auditChainDigestVerified") is not True or not start_valid or witness.get("serverAuditWitnessPass") is not True or witness.get("witnessedCheckCount")!=len(core.AUDITED_CHECKS) or not core.SHA.fullmatch(str(witness.get("auditHeadDigest") or "")) or not core.SHA.fullmatch(str(witness.get("auditExportSha256") or "")):
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_SERVER_WITNESS_INVALID")
        by_id[row["clientId"]]=row
    complete=len(rows)==len(core.CLIENTS)
    if existing.get("allAdmittedReceiptsPass") is not True or existing.get("certifiedClientCount")!=len(rows) or existing.get("complete") is not complete or existing.get("externalCertificationPass") is not complete or existing.get("serverAuditWitnessPass") is not complete:
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_COUNT_INVALID")
    return by_id

def merge(matrix_path:Path,campaign_path:Path,receipt_path:Path,audit_path:Path,client:str,progress_path:Path|None,allow_campaign_supersede:bool=False)->dict:
    client=str(client or "").strip().lower()
    if client not in core.CLIENTS: raise RuntimeError("MCP_EXTERNAL_PROGRESS_CLIENT_UNSUPPORTED")
    spec,required,campaign=matrix_contract(matrix_path,campaign_path)
    expected=base_progress(matrix_path,campaign_path,campaign,spec); by_id={}
    if progress_path is not None and progress_path.exists():
        existing=core.load(progress_path,"PROGRESS")
        binding_keys=("matrixAuthority","matrixSha256","campaignAuthority","campaignId","campaignSha256","protocol","transport","endpoint")
        same_campaign=all(existing.get(k)==expected.get(k) for k in binding_keys)
        if not same_campaign:
            if not allow_campaign_supersede or existing.get("complete") is True:
                raise RuntimeError("MCP_EXTERNAL_PROGRESS_CAMPAIGN_DRIFT")
        else:
            by_id=validate_existing(existing,expected)
    row=core.verify_receipt(receipt_path,client,required,str(spec["protocol"]),campaign)
    used={}; used_executions={}; used_evidence={}; used_provider_refs={}
    for existing_client,existing in by_id.items():
        used_executions[existing.get("executionId")]=existing_client
        used_evidence[existing.get("evidenceDigest")]=existing_client
        used_provider_refs[existing.get("providerExecutionRef")]=existing_client
        for existing_check,rid in (existing.get("requestIds") or {}).items():
            used[rid]=f"{existing_client}:{existing_check}"
    if client not in by_id and row["executionId"] in used_executions:
        raise RuntimeError(f"MCP_EXTERNAL_PROGRESS_EXECUTION_REUSE {client}:{used_executions[row['executionId']]}")
    if client not in by_id and row["evidenceDigest"] in used_evidence:
        raise RuntimeError(f"MCP_EXTERNAL_PROGRESS_EVIDENCE_REUSE {client}:{used_evidence[row['evidenceDigest']]}")
    if client not in by_id and row["providerExecutionRef"] in used_provider_refs:
        raise RuntimeError(f"MCP_EXTERNAL_PROGRESS_PROVIDER_EXECUTION_REUSE {client}:{used_provider_refs[row['providerExecutionRef']]}")
    for check,rid in row["requestIds"].items():
        if rid in used and client not in by_id:
            raise RuntimeError(f"MCP_EXTERNAL_PROGRESS_REQUEST_ID_REUSE {client}:{check}:{used[rid]}")
    row["serverAuditWitness"]=core.verify_server_audit(audit_path,row,client)
    if client in by_id and by_id[client]!=row: raise RuntimeError(f"MCP_EXTERNAL_PROGRESS_RECEIPT_REPLACEMENT_FORBIDDEN {client}")
    by_id[client]=row
    rows=[by_id[name] for name in core.CLIENTS if name in by_id]
    expected["clients"]=rows; expected["certifiedClientCount"]=len(rows); expected["complete"]=len(rows)==len(core.CLIENTS)
    expected["externalCertificationPass"]=expected["complete"]; expected["serverAuditWitnessPass"]=expected["complete"]
    return expected

def final_evidence(progress:dict,progress_path:Path)->dict:
    persisted=core.load(progress_path,"PROGRESS")
    if persisted!=progress:
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_FILE_BINDING_INVALID")
    by_id=validate_existing(progress,progress)
    if list(by_id)!=list(core.CLIENTS) or progress.get("complete") is not True: raise RuntimeError("MCP_EXTERNAL_PROGRESS_NOT_COMPLETE")
    return {"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteroperabilityEvidence","authority":core.AUTHORITY,
      "matrixAuthority":progress["matrixAuthority"],"matrixSha256":progress["matrixSha256"],"campaignAuthority":progress["campaignAuthority"],
      "campaignId":progress["campaignId"],"campaignSha256":progress["campaignSha256"],"progressAuthority":AUTHORITY,"progressSha256":core.sha256(progress_path),
      "protocol":progress["protocol"],"transport":progress["transport"],"endpoint":progress["endpoint"],"clients":progress["clients"],
      "certifiedClientCount":4,"allRequiredChecksPass":True,"serverAuditWitnessPass":True,
      "serverAuditWitnessedCheckCount":len(core.AUDITED_CHECKS)*len(core.CLIENTS),
      "externalCertificationPass":True,"runtimeCertified":False,"physicalCertified":False}

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--matrix",type=Path,default=Path("lab/mcp-external-client-interop-matrix.json"))
    p.add_argument("--campaign",type=Path,required=True); p.add_argument("--receipt",type=Path,required=True); p.add_argument("--audit",type=Path,required=True)
    p.add_argument("--client",choices=core.CLIENTS,required=True); p.add_argument("--progress",type=Path,default=Path("lab/mcp-external-client-interop-progress.json"))
    p.add_argument("--evidence-out",type=Path,default=Path("lab/mcp-external-client-interoperability-evidence.json"))
    p.add_argument("--allow-campaign-supersede",action="store_true")
    a=p.parse_args(); out=merge(a.matrix,a.campaign,a.receipt,a.audit,a.client,a.progress,allow_campaign_supersede=a.allow_campaign_supersede)
    a.progress.parent.mkdir(parents=True,exist_ok=True); a.progress.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    if out["complete"]: a.evidence_out.write_text(json.dumps(final_evidence(out,a.progress),indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"authority":AUTHORITY,"campaignId":out["campaignId"],"client":a.client,"certifiedClientCount":out["certifiedClientCount"],"complete":out["complete"],"serverAuditWitnessed":True},sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
