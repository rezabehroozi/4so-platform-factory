#!/usr/bin/env python3
"""Incrementally admit named external MCP client receipts for one campaign.

Each receipt is still independently verified by the canonical all-client sealer
contract. Progress is campaign-bound and append-only: a certified client cannot
be replaced with different evidence inside the same campaign. The fourth valid
client automatically produces the final interoperability evidence consumed by
FINAL_EXACT_RELEASE_ADMISSION_V1.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
import seal_mcp_external_interop as core

AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1"

def matrix_contract(matrix_path:Path, campaign_path:Path):
    matrix=core.load(matrix_path,"MATRIX")
    spec=matrix.get("spec") or {}
    if matrix.get("authority")!=core.MATRIX_AUTHORITY or spec.get("externalCertificationStatus")!="pending":
        raise RuntimeError("MCP_EXTERNAL_MATRIX_STATE_INVALID")
    protocol=str(spec.get("protocol") or "")
    required=list(spec.get("sharedRequiredChecks") or [])
    declared=[r.get("id") for r in spec.get("clients") or [] if isinstance(r,dict)]
    if protocol!="2026-07-28" or len(required)!=7 or len(set(required))!=7 or declared!=list(core.CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_MATRIX_CONTRACT_INVALID")
    campaign=core.verify_campaign(campaign_path,matrix_path,spec)
    return spec,required,campaign

def base_progress(matrix_path:Path,campaign_path:Path,campaign:dict,spec:dict)->dict:
    return {
      "apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropProgress",
      "authority":AUTHORITY,"matrixAuthority":core.MATRIX_AUTHORITY,"matrixSha256":core.sha256(matrix_path),
      "campaignAuthority":core.CAMPAIGN_AUTHORITY,"campaignId":campaign["campaignId"],"campaignSha256":core.sha256(campaign_path),
      "protocol":spec["protocol"],"transport":spec["transport"],"endpoint":campaign["endpoint"],
      "clients":[],"certifiedClientCount":0,"complete":False,"allAdmittedReceiptsPass":True,
      "externalCertificationPass":False,"runtimeCertified":False,"physicalCertified":False
    }

def validate_existing(existing:dict, expected:dict)->dict[str,dict]:
    if existing.get("authority")!=AUTHORITY or existing.get("kind")!="MCPExternalClientInteropProgress":
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_AUTHORITY_INVALID")
    for key in ("matrixAuthority","matrixSha256","campaignAuthority","campaignId","campaignSha256","protocol","transport","endpoint"):
        if existing.get(key)!=expected.get(key):
            raise RuntimeError(f"MCP_EXTERNAL_PROGRESS_CAMPAIGN_DRIFT {key}")
    if existing.get("runtimeCertified") is not False or existing.get("physicalCertified") is not False:
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_SCOPE_INFLATED")
    rows=existing.get("clients")
    if not isinstance(rows,list):
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_CLIENTS_INVALID")
    by_id={}
    order={name:i for i,name in enumerate(core.CLIENTS)}
    last=-1
    for row in rows:
        if not isinstance(row,dict) or row.get("clientId") not in order or row["clientId"] in by_id:
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_CLIENT_IDENTITY_INVALID")
        idx=order[row["clientId"]]
        if idx<=last:
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_CLIENT_ORDER_INVALID")
        last=idx
        checks=row.get("checks")
        if not isinstance(checks,dict) or len(checks)!=7 or any(v is not True for v in checks.values()):
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_CHECKS_INVALID")
        for key in ("challengeSha256","evidenceDigest","receiptSha256"):
            if not core.SHA.fullmatch(str(row.get(key) or "")):
                raise RuntimeError("MCP_EXTERNAL_PROGRESS_DIGEST_INVALID")
        by_id[row["clientId"]]=row
    if existing.get("certifiedClientCount")!=len(rows) or existing.get("complete") is not (len(rows)==4):
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_COUNT_INVALID")
    if existing.get("externalCertificationPass") is not (len(rows)==4):
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_CERTIFICATION_STATE_INVALID")
    return by_id

def merge(matrix_path:Path,campaign_path:Path,receipt_path:Path,client:str,progress_path:Path|None)->dict:
    client=str(client or "").strip().lower()
    if client not in core.CLIENTS:
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_CLIENT_UNSUPPORTED")
    spec,required,campaign=matrix_contract(matrix_path,campaign_path)
    expected=base_progress(matrix_path,campaign_path,campaign,spec)
    by_id={}
    if progress_path is not None and progress_path.exists():
        existing=core.load(progress_path,"PROGRESS")
        by_id=validate_existing(existing,expected)
    row=core.verify_receipt(receipt_path,client,required,str(spec["protocol"]),campaign)
    if client in by_id and by_id[client]!=row:
        raise RuntimeError(f"MCP_EXTERNAL_PROGRESS_RECEIPT_REPLACEMENT_FORBIDDEN {client}")
    by_id[client]=row
    rows=[by_id[name] for name in core.CLIENTS if name in by_id]
    expected["clients"]=rows
    expected["certifiedClientCount"]=len(rows)
    expected["complete"]=len(rows)==len(core.CLIENTS)
    expected["externalCertificationPass"]=expected["complete"]
    return expected

def final_evidence(progress:dict,progress_path:Path)->dict:
    by_id=validate_existing(progress,progress)
    if list(by_id)!=list(core.CLIENTS) or progress.get("complete") is not True:
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_NOT_COMPLETE")
    return {
      "apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteroperabilityEvidence",
      "authority":core.AUTHORITY,"matrixAuthority":progress["matrixAuthority"],"matrixSha256":progress["matrixSha256"],
      "campaignAuthority":progress["campaignAuthority"],"campaignId":progress["campaignId"],"campaignSha256":progress["campaignSha256"],
      "progressAuthority":AUTHORITY,"progressSha256":core.sha256(progress_path),
      "protocol":progress["protocol"],"transport":progress["transport"],"endpoint":progress["endpoint"],
      "clients":progress["clients"],"certifiedClientCount":4,"allRequiredChecksPass":True,
      "externalCertificationPass":True,"runtimeCertified":False,"physicalCertified":False
    }

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--matrix",type=Path,default=Path("lab/mcp-external-client-interop-matrix.json"))
    p.add_argument("--campaign",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    p.add_argument("--client",choices=core.CLIENTS,required=True)
    p.add_argument("--progress",type=Path,default=Path("lab/mcp-external-client-interop-progress.json"))
    p.add_argument("--evidence-out",type=Path,default=Path("lab/mcp-external-client-interoperability-evidence.json"))
    a=p.parse_args()
    out=merge(a.matrix,a.campaign,a.receipt,a.client,a.progress)
    a.progress.parent.mkdir(parents=True,exist_ok=True)
    a.progress.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    if out["complete"]:
        evidence=final_evidence(out,a.progress)
        a.evidence_out.write_text(json.dumps(evidence,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"authority":AUTHORITY,"campaignId":out["campaignId"],"client":a.client,"certifiedClientCount":out["certifiedClientCount"],"complete":out["complete"]},sort_keys=True))
    return 0
if __name__=="__main__": raise SystemExit(main())
