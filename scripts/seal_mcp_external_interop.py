#!/usr/bin/env python3
"""Seal independently executed named-client MCP interoperability receipts.

Named-client evidence is campaign-bound and server-audit-witnessed. A client
receipt alone can never certify C7W: six protected MCP checks must carry unique
server Request-IDs that are observed in the Platform security-audit chain.
OAuth protected-resource discovery remains a public metadata check and is not
expected to create an authenticated audit event.
"""
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path
from urllib.parse import urlsplit

AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROPERABILITY_EVIDENCE_V1"
MATRIX_AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROPERABILITY_MATRIX_V2"
RECEIPT_AUTHORITY="MCP_EXTERNAL_CLIENT_EXECUTION_RECEIPT_V1"
CAMPAIGN_AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROP_CAMPAIGN_V1"
AUDIT_WITNESS_AUTHORITY="MCP_EXTERNAL_SERVER_AUDIT_WITNESS_V1"
AUDIT_METHOD_VERSION="IMMUTABLE_AUTHN_AUTHZ_AUDIT_V1"
CLIENTS=("chatgpt","claude","gemini","grok")
CLIENT_SURFACES={"chatgpt":"ChatGPT custom MCP","claude":"Claude remote MCP","gemini":"Gemini remote MCP","grok":"Grok custom MCP"}
SHA=re.compile(r"^sha256:[0-9a-f]{64}$")
REQUEST_ID=re.compile(r"^[A-Za-z0-9._:-]{8,200}$")
AUDITED_CHECKS=(
    "dedicated-audience-validation",
    "authorization-filtered-tools-list",
    "project-resource-scope-negative-control",
    "revoked-delegation-negative-control",
    "read-only-client-mutation-negative-control",
    "administration-approval-self-approval-negative-control",
)
REQUIRED_CHECKS=("oauth-protected-resource-discovery",)+AUDITED_CHECKS
AUDIT_REQUIREMENTS={
    "dedicated-audience-validation":("AUTHENTICATION","DENY","OIDC_AUTHENTICATION_REJECTED"),
    "authorization-filtered-tools-list":("CAPABILITY_AUTHORIZATION","ALLOW","CAPABILITY_AUTHORIZED"),
    "project-resource-scope-negative-control":("SCOPE_AUTHORIZATION","DENY","PROJECT_ACCESS_DENIED"),
    "revoked-delegation-negative-control":("DELEGATION_AUTHORIZATION","DENY","MCP_DELEGATION_INACTIVE"),
    "read-only-client-mutation-negative-control":("CAPABILITY_AUTHORIZATION","DENY","CAPABILITY_PERMISSION_REQUIRED"),
    "administration-approval-self-approval-negative-control":("APPROVAL_AUTHORIZATION","DENY","SEPARATION_OF_DUTIES_REQUIRED"),
}

def load(path:Path,label:str):
    if path.is_symlink() or not path.is_file() or path.stat().st_size<=0 or path.stat().st_size>4*1024*1024:
        raise RuntimeError(f"{label}_FILE_INVALID")
    value=json.loads(path.read_text(encoding="utf-8"))
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

_AUDIT_REQUIRED=("id","sequence","occurredAt","methodVersion","category","decision","actorId")
_AUDIT_OPTIONAL=("authentication","method","path","statusCode","reasonCode","requestId","scopeType","scopeId","effectiveRole","mappingDigest","previousDigest")
_AUDIT_ALLOWED=set(_AUDIT_REQUIRED+_AUDIT_OPTIONAL+("digest",))

def _go_json_bytes(value:dict)->bytes:
    raw=json.dumps(value,separators=(",",":"),ensure_ascii=False)
    raw=raw.replace("&","\\u0026").replace("<","\\u003c").replace(">","\\u003e").replace("\u2028","\\u2028").replace("\u2029","\\u2029")
    return raw.encode("utf-8")

def audit_event_digest(raw:dict)->str:
    if not isinstance(raw,dict) or set(raw)-_AUDIT_ALLOWED:
        raise RuntimeError("MCP_EXTERNAL_AUDIT_EVENT_FIELDS_INVALID")
    canonical={}
    for key in _AUDIT_REQUIRED:
        if key not in raw:
            raise RuntimeError("MCP_EXTERNAL_AUDIT_EVENT_FIELDS_INVALID")
        canonical[key]=raw[key]
    for key in _AUDIT_OPTIONAL:
        value=raw.get(key)
        if value not in ("",0,None):
            canonical[key]=value
    canonical["digest"]=""
    return "sha256:"+hashlib.sha256(_go_json_bytes(canonical)).hexdigest()

def _request_ids(row:dict,client:str)->dict[str,str]:
    values=row.get("requestIds")
    if not isinstance(values,dict) or set(values)!=set(AUDITED_CHECKS):
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_REQUEST_IDS_INVALID {client}")
    out={str(k):str(v or "").strip() for k,v in values.items()}
    if any(not REQUEST_ID.fullmatch(v) for v in out.values()) or len(set(out.values()))!=len(AUDITED_CHECKS):
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_REQUEST_IDS_INVALID {client}")
    return out

def verify_receipt(path:Path,client:str,required:list[str],protocol:str,campaign:dict)->dict:
    row=load(path,client.upper()+"_RECEIPT")
    if not isinstance(row,dict) or row.get("authority")!=RECEIPT_AUTHORITY or row.get("clientId")!=client:
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_IDENTITY_INVALID {client}")
    if row.get("clientSurface")!=CLIENT_SURFACES[client]:
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_CLIENT_SURFACE_INVALID {client}")
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
    provider_ref=str(row.get("providerExecutionRef") or "").strip()
    if len(provider_ref)<8 or len(provider_ref)>500 or any(ord(ch)<0x21 or ord(ch)>0x7e for ch in provider_ref):
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_PROVIDER_EXECUTION_REF_INVALID {client}")
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
    request_ids=_request_ids(row,client)
    return {"clientId":client,"clientSurface":row["clientSurface"],"endpoint":ep,"executionId":run_id,"providerExecutionRef":provider_ref,"campaignId":row["campaignId"],"challengeSha256":row["challengeSha256"],"evidenceDigest":evidence,"externalReceiptSha256":sha256(path),"checks":checks,"requestIds":request_ids}

def _audit_rows(path:Path)->list[dict]:
    value=load(path,"SECURITY_AUDIT")
    if isinstance(value,dict) and isinstance(value.get("items"),list):
        value=value["items"]
    if not isinstance(value,list) or not value:
        raise RuntimeError("MCP_EXTERNAL_AUDIT_EXPORT_INVALID")
    rows=[]; previous=None
    for raw in value:
        if not isinstance(raw,dict):
            raise RuntimeError("MCP_EXTERNAL_AUDIT_EXPORT_INVALID")
        seq=raw.get("sequence"); digest=str(raw.get("digest") or ""); previous_digest=str(raw.get("previousDigest") or "")
        if type(seq) is not int or seq<=0 or raw.get("methodVersion")!=AUDIT_METHOD_VERSION or not SHA.fullmatch(digest):
            raise RuntimeError("MCP_EXTERNAL_AUDIT_CHAIN_INVALID")
        if previous is not None and (seq!=previous["sequence"]+1 or previous_digest!=previous["digest"]):
            raise RuntimeError("MCP_EXTERNAL_AUDIT_CHAIN_INVALID")
        if previous is None and previous_digest and not SHA.fullmatch(previous_digest):
            raise RuntimeError("MCP_EXTERNAL_AUDIT_CHAIN_INVALID")
        if audit_event_digest(raw)!=digest:
            raise RuntimeError("MCP_EXTERNAL_AUDIT_DIGEST_INVALID")
        rows.append(raw); previous=raw
    return rows

def verify_server_audit(audit_path:Path,receipt:dict,client:str)->dict:
    request_ids=receipt["requestIds"]
    rows=_audit_rows(audit_path)
    matched={}
    for check in AUDITED_CHECKS:
        rid=request_ids[check]
        candidates=[r for r in rows if str(r.get("requestId") or "")==rid and r.get("path")=="/mcp" and r.get("method")=="POST"]
        if not candidates:
            raise RuntimeError(f"MCP_EXTERNAL_AUDIT_REQUEST_NOT_OBSERVED {client}:{check}")
        if len(candidates)!=1:
            raise RuntimeError(f"MCP_EXTERNAL_AUDIT_REQUEST_AMBIGUOUS {client}:{check}")
        category,decision,reason=AUDIT_REQUIREMENTS[check]
        event=candidates[0]
        if event.get("category")!=category or event.get("decision")!=decision or event.get("reasonCode")!=reason:
            raise RuntimeError(f"MCP_EXTERNAL_AUDIT_SEMANTIC_WITNESS_MISSING {client}:{check}")
        matched[check]={"requestId":rid,"sequence":event["sequence"],"digest":event["digest"],"category":category,"decision":decision,"reasonCode":reason}
    head=rows[-1]
    return {
      "authority":AUDIT_WITNESS_AUTHORITY,"clientId":client,
      "auditMethodVersion":AUDIT_METHOD_VERSION,"auditChainDigestVerified":True,
      "auditWindowStartSequence":rows[0]["sequence"],"auditWindowPreviousDigest":str(rows[0].get("previousDigest") or ""),
      "auditExportSha256":sha256(audit_path),"auditHeadSequence":head["sequence"],"auditHeadDigest":head["digest"],
      "witnessedCheckCount":len(AUDITED_CHECKS),"serverAuditWitnessPass":True,"matchedEvents":matched
    }

def verify_campaign(campaign_path:Path,matrix_path:Path,spec:dict)->dict:
    campaign=load(campaign_path,"CAMPAIGN")
    if not isinstance(campaign,dict) or campaign.get("authority")!=CAMPAIGN_AUTHORITY or campaign.get("matrixAuthority")!=MATRIX_AUTHORITY:
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_AUTHORITY_INVALID")
    if campaign.get("matrixSha256")!=sha256(matrix_path) or campaign.get("protocol")!=spec.get("protocol") or campaign.get("transport")!=spec.get("transport") or campaign.get("externalExecutionRequired") is not True:
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_MATRIX_BINDING_INVALID")
    if not str(campaign.get("campaignId") or "").startswith("mcp-interop-"):
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_ID_INVALID")
    campaign["endpoint"]=endpoint(campaign.get("endpoint",""))
    rows=campaign.get("clients")
    if not isinstance(rows,list) or [x.get("clientId") for x in rows if isinstance(x,dict)]!=list(CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_CLIENT_SET_INVALID")
    challenge_values=set(); challenge_digests=set()
    for row in rows:
        challenge=str(row.get("challenge") or "")
        expected="sha256:"+hashlib.sha256(challenge.encode()).hexdigest()
        if len(challenge)<32 or row.get("challengeSha256")!=expected:
            raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_CHALLENGE_INVALID")
        if challenge in challenge_values or expected in challenge_digests:
            raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_CHALLENGE_REUSE")
        challenge_values.add(challenge); challenge_digests.add(expected)
    return campaign

def seal(matrix_path:Path,campaign_path:Path,receipt_dir:Path,audit_dir:Path)->dict:
    matrix=load(matrix_path,"MATRIX")
    spec=matrix.get("spec") or {}
    if matrix.get("authority")!=MATRIX_AUTHORITY or spec.get("externalCertificationStatus")!="pending":
        raise RuntimeError("MCP_EXTERNAL_MATRIX_STATE_INVALID")
    protocol=str(spec.get("protocol") or "")
    required=list(spec.get("sharedRequiredChecks") or [])
    if protocol!="2026-07-28" or required!=list(REQUIRED_CHECKS):
        raise RuntimeError("MCP_EXTERNAL_MATRIX_REQUIRED_CHECKS_INVALID")
    declared=[r.get("id") for r in spec.get("clients") or [] if isinstance(r,dict)]
    surfaces={r.get("id"):r.get("displayName") for r in spec.get("clients") or [] if isinstance(r,dict)}
    if declared!=list(CLIENTS) or surfaces!=CLIENT_SURFACES:
        raise RuntimeError("MCP_EXTERNAL_MATRIX_CLIENT_SET_INVALID")
    campaign=verify_campaign(campaign_path,matrix_path,spec)
    rows=[]; used_request_ids={}; used_execution_ids={}; used_evidence_digests={}; used_provider_execution_refs={}
    for client in CLIENTS:
        row=verify_receipt(receipt_dir/(client+".json"),client,required,protocol,campaign)
        execution_id=row["executionId"]; evidence_digest=row["evidenceDigest"]; provider_ref=row["providerExecutionRef"]
        if execution_id in used_execution_ids:
            raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_EXECUTION_REUSE {client}:{used_execution_ids[execution_id]}")
        if evidence_digest in used_evidence_digests:
            raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_EVIDENCE_REUSE {client}:{used_evidence_digests[evidence_digest]}")
        if provider_ref in used_provider_execution_refs:
            raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_PROVIDER_EXECUTION_REUSE {client}:{used_provider_execution_refs[provider_ref]}")
        used_execution_ids[execution_id]=client; used_evidence_digests[evidence_digest]=client; used_provider_execution_refs[provider_ref]=client
        for check,rid in row["requestIds"].items():
            owner=used_request_ids.get(rid)
            if owner is not None:
                raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_REQUEST_ID_REUSE {client}:{check}:{owner}")
            used_request_ids[rid]=client
        row["serverAuditWitness"]=verify_server_audit(audit_dir/(client+".json"),row,client)
        rows.append(row)
    endpoints={r["endpoint"] for r in rows}
    if len(endpoints)!=1:
        raise RuntimeError("MCP_EXTERNAL_RECEIPT_ENDPOINT_DRIFT")
    return {
      "apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteroperabilityEvidence",
      "authority":AUTHORITY,"matrixAuthority":MATRIX_AUTHORITY,"matrixSha256":sha256(matrix_path),
      "campaignAuthority":CAMPAIGN_AUTHORITY,"campaignId":campaign["campaignId"],"campaignSha256":sha256(campaign_path),
      "protocol":protocol,"transport":"streamable-http","endpoint":next(iter(endpoints)),
      "clients":rows,"certifiedClientCount":4,"allRequiredChecksPass":True,
      "serverAuditWitnessPass":True,"serverAuditWitnessedCheckCount":len(AUDITED_CHECKS)*len(CLIENTS),
      "externalCertificationPass":True,"runtimeCertified":False,"physicalCertified":False
    }

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--matrix",type=Path,default=Path("lab/mcp-external-client-interop-matrix.json"))
    p.add_argument("--campaign",type=Path,required=True)
    p.add_argument("--receipts",type=Path,required=True)
    p.add_argument("--audits",type=Path,required=True)
    p.add_argument("--out",type=Path)
    a=p.parse_args(); out=seal(a.matrix,a.campaign,a.receipts,a.audits)
    if a.out:
        a.out.parent.mkdir(parents=True,exist_ok=True); a.out.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print(json.dumps(out,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
