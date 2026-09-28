#!/usr/bin/env python3
"""Seal independently executed named-client MCP interoperability receipts.

The sealer is intentionally incapable of manufacturing client execution.
Each input receipt must be produced by the named external client against the
same protected MCP endpoint and must prove every shared required check.
"""
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path
from urllib.parse import urlsplit

AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROPERABILITY_EVIDENCE_V1"
MATRIX_AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROPERABILITY_MATRIX_V2"
RECEIPT_AUTHORITY="MCP_EXTERNAL_CLIENT_EXECUTION_RECEIPT_V1"
CAMPAIGN_AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROP_CAMPAIGN_V1"
CLIENTS=("chatgpt","claude","gemini","grok")
SHA=re.compile(r"^sha256:[0-9a-f]{64}$")


def load(path:Path,label:str)->dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size<=0 or path.stat().st_size>1024*1024:
        raise RuntimeError(f"{label}_FILE_INVALID")
    value=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value,dict): raise RuntimeError(f"{label}_NOT_OBJECT")
    return value


def sha256(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return "sha256:"+h.hexdigest()


def endpoint(value:str)->str:
    p=urlsplit(str(value or "").strip())
    if p.scheme!="https" or not p.hostname or p.username or p.password or p.query or p.fragment or p.path!="/mcp":
        raise RuntimeError("MCP_EXTERNAL_ENDPOINT_INVALID")
    return p.geturl()


def verify_receipt(path:Path,client:str,required:list[str],protocol:str,campaign:dict)->dict:
    row=load(path,client.upper()+"_RECEIPT")
    if row.get("authority")!=RECEIPT_AUTHORITY or row.get("clientId")!=client:
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_IDENTITY_INVALID {client}")
    if row.get("protocol")!=protocol or row.get("transport")!="streamable-http":
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_PROTOCOL_INVALID {client}")
    challenge=next((x for x in campaign["clients"] if x.get("clientId")==client),None)
    if not challenge:
        raise RuntimeError(f"MCP_EXTERNAL_CAMPAIGN_CLIENT_MISSING {client}")
    if row.get("campaignId")!=campaign.get("campaignId") or row.get("challengeSha256")!=challenge.get("challengeSha256"):
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_CAMPAIGN_BINDING_INVALID {client}")
    ep=endpoint(row.get("endpoint",""))
    if ep!=campaign.get("endpoint"):
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_CAMPAIGN_ENDPOINT_INVALID {client}")
    run_id=str(row.get("executionId") or "").strip()
    if not run_id or len(run_id)>160:
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_EXECUTION_ID_INVALID {client}")
    if row.get("externalExecution") is not True or row.get("credentialedExecution") is not True:
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_NOT_EXTERNAL_CREDENTIALED {client}")
    checks=row.get("checks")
    if not isinstance(checks,dict) or set(checks)!=set(required) or any(checks.get(k) is not True for k in required):
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_REQUIRED_CHECKS_INVALID {client}")
    if row.get("scopeLeakObserved") is not False or row.get("revokedGrantAccepted") is not False or row.get("selfApprovalAccepted") is not False:
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_NEGATIVE_CONTROL_INVALID {client}")
    evidence=str(row.get("evidenceDigest") or "")
    if not SHA.fullmatch(evidence):
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_EVIDENCE_DIGEST_INVALID {client}")
    return {"clientId":client,"endpoint":ep,"executionId":run_id,"campaignId":row["campaignId"],"challengeSha256":row["challengeSha256"],"evidenceDigest":evidence,"receiptSha256":sha256(path),"checks":checks}


def verify_campaign(campaign_path:Path,matrix_path:Path,spec:dict)->dict:
    campaign=load(campaign_path,"CAMPAIGN")
    if campaign.get("authority")!=CAMPAIGN_AUTHORITY or campaign.get("matrixAuthority")!=MATRIX_AUTHORITY:
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_AUTHORITY_INVALID")
    if campaign.get("matrixSha256")!=sha256(matrix_path) or campaign.get("protocol")!=spec.get("protocol") or campaign.get("transport")!=spec.get("transport") or campaign.get("externalExecutionRequired") is not True:
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_MATRIX_BINDING_INVALID")
    if not str(campaign.get("campaignId") or "").startswith("mcp-interop-"):
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_ID_INVALID")
    campaign["endpoint"]=endpoint(campaign.get("endpoint",""))
    rows=campaign.get("clients")
    if not isinstance(rows,list) or [x.get("clientId") for x in rows if isinstance(x,dict)]!=list(CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_CLIENT_SET_INVALID")
    for row in rows:
        challenge=str(row.get("challenge") or "")
        expected="sha256:"+hashlib.sha256(challenge.encode()).hexdigest()
        if len(challenge)<32 or row.get("challengeSha256")!=expected:
            raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_CHALLENGE_INVALID")
    return campaign


def seal(matrix_path:Path,campaign_path:Path,receipt_dir:Path)->dict:
    matrix=load(matrix_path,"MATRIX")
    spec=matrix.get("spec") or {}
    if matrix.get("authority")!=MATRIX_AUTHORITY or spec.get("externalCertificationStatus")!="pending":
        raise RuntimeError("MCP_EXTERNAL_MATRIX_STATE_INVALID")
    protocol=str(spec.get("protocol") or "")
    required=list(spec.get("sharedRequiredChecks") or [])
    if protocol!="2026-07-28" or len(required)!=7 or len(set(required))!=7:
        raise RuntimeError("MCP_EXTERNAL_MATRIX_REQUIRED_CHECKS_INVALID")
    declared=[r.get("id") for r in spec.get("clients") or [] if isinstance(r,dict)]
    if declared!=list(CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_MATRIX_CLIENT_SET_INVALID")
    campaign=verify_campaign(campaign_path,matrix_path,spec)
    rows=[verify_receipt(receipt_dir/(client+".json"),client,required,protocol,campaign) for client in CLIENTS]
    endpoints={r["endpoint"] for r in rows}
    if len(endpoints)!=1:
        raise RuntimeError("MCP_EXTERNAL_RECEIPT_ENDPOINT_DRIFT")
    return {
      "apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteroperabilityEvidence",
      "authority":AUTHORITY,"matrixAuthority":MATRIX_AUTHORITY,"matrixSha256":sha256(matrix_path),
      "campaignAuthority":CAMPAIGN_AUTHORITY,"campaignId":campaign["campaignId"],"campaignSha256":sha256(campaign_path),
      "protocol":protocol,"transport":"streamable-http","endpoint":next(iter(endpoints)),
      "clients":rows,"certifiedClientCount":4,"allRequiredChecksPass":True,
      "externalCertificationPass":True,"runtimeCertified":False,"physicalCertified":False
    }


def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--matrix",type=Path,default=Path("lab/mcp-external-client-interop-matrix.json")); p.add_argument("--campaign",type=Path,required=True); p.add_argument("--receipts",type=Path,required=True); p.add_argument("--out",type=Path)
    a=p.parse_args(); out=seal(a.matrix,a.campaign,a.receipts)
    if a.out:
        a.out.parent.mkdir(parents=True,exist_ok=True); a.out.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print(json.dumps(out,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
