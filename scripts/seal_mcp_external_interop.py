#!/usr/bin/env python3
"""Seal independently executed named-client MCP interoperability receipts.

Named-client evidence is campaign-bound and server-audit-witnessed. A client
receipt alone can never certify C7W: six protected MCP checks must carry unique
server Request-IDs that are observed in the Platform security-audit chain.
OAuth protected-resource discovery remains a public metadata check and is not
expected to create an authenticated audit event.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROPERABILITY_EVIDENCE_V1"
MATRIX_AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROPERABILITY_MATRIX_V2"
RECEIPT_AUTHORITY="MCP_EXTERNAL_CLIENT_EXECUTION_RECEIPT_V1"
CAMPAIGN_AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROP_CAMPAIGN_V1"
AUDIT_WITNESS_AUTHORITY="MCP_EXTERNAL_SERVER_AUDIT_WITNESS_V1"
AUDIT_METHOD_VERSION="IMMUTABLE_AUTHN_AUTHZ_AUDIT_V1"
INTEROP_BINDING_AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROP_BINDING_V1"
OAUTH_BINDING_AUTHORITY="MCP_EXTERNAL_CLIENT_OAUTH_BINDINGS_V1"
CAMPAIGN_PREFLIGHT_AUTHORITY="MCP_EXTERNAL_CAMPAIGN_LIVE_PREFLIGHT_V1"
CLIENTS=("chatgpt","claude","gemini","grok")
CLIENT_SURFACES={"chatgpt":"ChatGPT custom MCP","claude":"Claude remote MCP","gemini":"Gemini remote MCP","grok":"Grok custom MCP"}
SHA=re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT=re.compile(r"^[0-9a-f]{40}$")
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
OAUTH_CLIENT_AUDITED_CHECKS=tuple(x for x in AUDITED_CHECKS if x!="dedicated-audience-validation")
INTEROP_EVIDENCE_KEYS=frozenset({
    "apiVersion","kind","authority","matrixAuthority","matrixSha256","campaignAuthority","campaignId","campaignSha256",
    "oauthClientBindingAuthority","oauthClientBindingsSha256","oauthClientBindings","trustedClientBindings",
    "sourceCommitSHA","runtimeVersion","protocol","transport","endpoint","clients","certifiedClientCount","allRequiredChecksPass",
    "serverAuditWitnessPass","serverAuditWitnessedCheckCount","externalCertificationPass","runtimeCertified","physicalCertified",
})
PROGRESS_EVIDENCE_KEYS=frozenset({
    "apiVersion","kind","authority","matrixAuthority","matrixSha256","campaignAuthority","campaignId","campaignSha256",
    "oauthClientBindingAuthority","oauthClientBindingsSha256","oauthClientBindings","trustedClientBindings",
    "sourceCommitSHA","runtimeVersion","protocol","transport","endpoint","clients","certifiedClientCount","complete","allAdmittedReceiptsPass",
    "serverAuditWitnessPass","externalCertificationPass","runtimeCertified","physicalCertified",
})
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

def canonical_json_bytes(value:object)->bytes:
    return (json.dumps(value,indent=2,sort_keys=True)+"\n").encode("utf-8")

def _prepare_output_parent(path:Path,label:str)->Path:
    absolute=Path(os.path.abspath(path))
    for parent in reversed(absolute.parents):
        if parent.exists() and (parent.is_symlink() or not parent.is_dir()):
            raise RuntimeError(f"{label}_OUTPUT_PARENT_INVALID")
    absolute.parent.mkdir(parents=True,exist_ok=True)
    if absolute.parent.is_symlink() or not absolute.parent.is_dir():
        raise RuntimeError(f"{label}_OUTPUT_PARENT_INVALID")
    return absolute

def _existing_output_matches(path:Path,raw:bytes,label:str)->None:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label}_OUTPUT_PATH_INVALID")
    if path.read_bytes()!=raw:
        raise RuntimeError(f"{label}_OUTPUT_REPLACEMENT_FORBIDDEN")

def write_json_once_or_identical(path:Path,value:object,label:str)->None:
    path=_prepare_output_parent(path,label); raw=canonical_json_bytes(value)
    if path.exists() or path.is_symlink():
        _existing_output_matches(path,raw,label); return
    fd,temp_name=tempfile.mkstemp(prefix="."+path.name+".tmp.",dir=path.parent)
    temp=Path(temp_name)
    try:
        with os.fdopen(fd,"wb") as fh:
            fh.write(raw); fh.flush(); os.fsync(fh.fileno())
        try:
            os.link(temp,path,follow_symlinks=False)
        except FileExistsError:
            _existing_output_matches(path,raw,label); return
        directory_fd=os.open(path.parent,os.O_RDONLY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    finally:
        if temp.exists(): temp.unlink()

def write_json_atomic_replace(path:Path,value:object,label:str)->None:
    path=_prepare_output_parent(path,label); raw=canonical_json_bytes(value)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"{label}_OUTPUT_PATH_INVALID")
    fd,temp_name=tempfile.mkstemp(prefix="."+path.name+".tmp.",dir=path.parent)
    temp=Path(temp_name)
    try:
        with os.fdopen(fd,"wb") as fh:
            fh.write(raw); fh.flush(); os.fsync(fh.fileno())
        os.replace(temp,path)
        directory_fd=os.open(path.parent,os.O_RDONLY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    finally:
        if temp.exists(): temp.unlink()

def endpoint(value:str)->str:
    p=urlsplit(str(value or "").strip())
    if p.scheme!="https" or not p.hostname or p.username or p.password or p.query or p.fragment or p.path!="/mcp":
        raise RuntimeError("MCP_EXTERNAL_ENDPOINT_INVALID")
    return p.geturl()

def parse_utc_timestamp(value:object,label:str)->datetime:
    raw=str(value or "").strip()
    if not raw:
        raise RuntimeError(f"{label}_TIME_INVALID")
    try:
        parsed=datetime.fromisoformat(raw.replace("Z","+00:00"))
    except ValueError as exc:
        raise RuntimeError(f"{label}_TIME_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset()!=timedelta(0):
        raise RuntimeError(f"{label}_TIME_INVALID")
    return parsed.astimezone(timezone.utc)

def utc_timestamp(value:datetime)->str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00","Z")

def validate_matrix_contract(matrix:object,label:str="MCP_EXTERNAL_MATRIX")->dict:
    if not isinstance(matrix,dict) or matrix.get("authority")!=MATRIX_AUTHORITY or matrix.get("kind")!="MCPExternalClientInteropMatrix":
        raise RuntimeError(f"{label}_AUTHORITY_INVALID")
    spec=matrix.get("spec")
    if not isinstance(spec,dict):
        raise RuntimeError(f"{label}_SPEC_INVALID")
    if spec.get("sourceContractStatus")!="implemented" or spec.get("externalCertificationStatus")!="pending" or spec.get("blocker")!="MCP_EXTERNAL_CLIENT_INTEROP_EVIDENCE_PENDING":
        raise RuntimeError(f"{label}_STATE_INVALID")
    if spec.get("protocol")!="2026-07-28" or spec.get("transport")!="streamable-http" or spec.get("resourcePath")!="/mcp":
        raise RuntimeError(f"{label}_PROTOCOL_INVALID")
    required=list(spec.get("sharedRequiredChecks") or [])
    if required!=list(REQUIRED_CHECKS):
        raise RuntimeError(f"{label}_CHECKS_INVALID")
    rows=spec.get("clients")
    if not isinstance(rows,list) or len(rows)!=len(CLIENTS):
        raise RuntimeError(f"{label}_CLIENT_SET_INVALID")
    ids=[]; surfaces={}
    for row in rows:
        if not isinstance(row,dict):
            raise RuntimeError(f"{label}_CLIENT_SET_INVALID")
        client=str(row.get("id") or "")
        ids.append(client); surfaces[client]=row.get("displayName")
        if row.get("sourceContract")!="ready" or row.get("externalExecution")!="pending":
            raise RuntimeError(f"{label}_CLIENT_STATE_INVALID")
    if ids!=list(CLIENTS) or surfaces!=CLIENT_SURFACES:
        raise RuntimeError(f"{label}_CLIENT_SET_INVALID")
    max_age=spec.get("campaignMaxAgeSeconds"); audit_window=spec.get("executionAuditWindowSeconds")
    if type(max_age) is not int or max_age<3600 or max_age>14*24*3600:
        raise RuntimeError(f"{label}_CAMPAIGN_TTL_INVALID")
    if type(audit_window) is not int or audit_window<60 or audit_window>24*3600 or audit_window>max_age:
        raise RuntimeError(f"{label}_AUDIT_WINDOW_INVALID")
    return spec


def campaign_time_window(campaign:dict,spec:dict,*,now:datetime|None=None)->tuple[datetime,datetime,int]:
    max_age=spec.get("campaignMaxAgeSeconds")
    audit_window=spec.get("executionAuditWindowSeconds")
    if type(max_age) is not int or max_age<3600 or max_age>14*24*3600:
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_TTL_INVALID")
    if type(audit_window) is not int or audit_window<60 or audit_window>24*3600 or audit_window>max_age:
        raise RuntimeError("MCP_EXTERNAL_AUDIT_WINDOW_INVALID")
    created=parse_utc_timestamp(campaign.get("createdAt"),"MCP_EXTERNAL_CAMPAIGN_CREATED_AT")
    expires=parse_utc_timestamp(campaign.get("expiresAt"),"MCP_EXTERNAL_CAMPAIGN_EXPIRES_AT")
    if expires-created!=timedelta(seconds=max_age):
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_WINDOW_INVALID")
    current=(now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if created>current+timedelta(minutes=5):
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_CREATED_IN_FUTURE")
    if current>=expires:
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_EXPIRED")
    return created,expires,audit_window

def interop_binding_digest(campaign_id:str,client:str,challenge_sha256:str)->str:
    campaign_id=str(campaign_id or "").strip(); client=str(client or "").strip().lower(); challenge_sha256=str(challenge_sha256 or "").strip()
    if not campaign_id.startswith("mcp-interop-") or client not in CLIENTS or not SHA.fullmatch(challenge_sha256):
        raise RuntimeError("MCP_EXTERNAL_INTEROP_BINDING_INPUT_INVALID")
    raw=f"{INTEROP_BINDING_AUTHORITY}\n{campaign_id}\n{client}\n{challenge_sha256}".encode("utf-8")
    return "sha256:"+hashlib.sha256(raw).hexdigest()

def validate_oauth_client_id(value:object,label:str)->str:
    client_id=str(value or "").strip()
    if not client_id or len(client_id.encode("utf-8"))>512 or any(ch in client_id for ch in "\r\n\t"):
        raise RuntimeError(f"{label}_OAUTH_CLIENT_INVALID")
    return client_id

def validate_oauth_client_bindings(value:object,label:str)->dict[str,str]:
    if not isinstance(value,dict) or set(value)!=set(CLIENTS):
        raise RuntimeError(f"{label}_OAUTH_CLIENT_BINDINGS_INVALID")
    out={client:validate_oauth_client_id(value.get(client),label+"_"+client.upper()) for client in CLIENTS}
    if len(set(out.values()))!=len(CLIENTS):
        raise RuntimeError(f"{label}_OAUTH_CLIENT_REUSE")
    return out

def campaign_oauth_client_bindings(campaign:dict)->dict[str,str]:
    rows=campaign.get("clients") if isinstance(campaign,dict) else None
    if not isinstance(rows,list):
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_OAUTH_CLIENT_BINDINGS_INVALID")
    return validate_oauth_client_bindings(
        {str(row.get("clientId") or ""):row.get("oauthClientId") for row in rows if isinstance(row,dict)},
        "MCP_EXTERNAL_CAMPAIGN",
    )

def validate_trusted_client_bindings(value:object,label:str)->dict[str,dict]:
    if not isinstance(value,dict) or set(value)!=set(CLIENTS):
        raise RuntimeError(f"{label}_TRUSTED_CLIENT_BINDINGS_INVALID")
    out={}; trusted_ids=set()
    for client in CLIENTS:
        row=value.get(client)
        if not isinstance(row,dict) or set(row)!={"trustedClientId","trustedClientRevision","trustedClientProvider"}:
            raise RuntimeError(f"{label}_TRUSTED_CLIENT_BINDINGS_INVALID")
        trusted_id=str(row.get("trustedClientId") or "").strip()
        revision=row.get("trustedClientRevision")
        provider=str(row.get("trustedClientProvider") or "").strip().lower()
        if not trusted_id or len(trusted_id)>200 or any(ch in trusted_id for ch in "\r\n\t") or type(revision) is not int or revision<=0 or provider!=client:
            raise RuntimeError(f"{label}_TRUSTED_CLIENT_BINDINGS_INVALID")
        if trusted_id in trusted_ids:
            raise RuntimeError(f"{label}_TRUSTED_CLIENT_ID_REUSE")
        trusted_ids.add(trusted_id)
        out[client]={"trustedClientId":trusted_id,"trustedClientRevision":revision,"trustedClientProvider":provider}
    return out

def campaign_trusted_client_bindings(campaign:dict)->dict[str,dict]:
    rows=campaign.get("clients") if isinstance(campaign,dict) else None
    if not isinstance(rows,list):
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_TRUSTED_CLIENT_BINDINGS_INVALID")
    raw={}
    for row in rows:
        if not isinstance(row,dict):
            raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_TRUSTED_CLIENT_BINDINGS_INVALID")
        client=str(row.get("clientId") or "")
        if client in raw:
            raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_TRUSTED_CLIENT_BINDINGS_INVALID")
        raw[client]={"trustedClientId":row.get("trustedClientId"),"trustedClientRevision":row.get("trustedClientRevision"),"trustedClientProvider":row.get("trustedClientProvider")}
    return validate_trusted_client_bindings(raw,"MCP_EXTERNAL_CAMPAIGN")

def validate_interop_binding(row:dict,campaign_id:str,client:str,label:str)->str:
    if not isinstance(row,dict) or row.get("campaignId")!=campaign_id or row.get("clientId")!=client:
        raise RuntimeError(f"{label}_INTEROP_BINDING_INVALID {client}")
    expected=interop_binding_digest(campaign_id,client,str(row.get("challengeSha256") or ""))
    if row.get("interopBindingAuthority")!=INTEROP_BINDING_AUTHORITY or row.get("interopBindingDigest")!=expected:
        raise RuntimeError(f"{label}_INTEROP_BINDING_INVALID {client}")
    return expected

def validate_witness_interop_binding(witness:dict,binding:str,client:str,label:str)->None:
    if not isinstance(witness,dict) or witness.get("clientId")!=client or witness.get("interopBindingAuthority")!=INTEROP_BINDING_AUTHORITY or witness.get("interopBindingDigest")!=binding:
        raise RuntimeError(f"{label}_INTEROP_BINDING_INVALID {client}")

def validate_server_audit_witness(witness:dict,binding:str,client:str,label:str,oauth_client_id:str|None=None,request_ids:dict[str,str]|None=None)->dict:
    validate_witness_interop_binding(witness,binding,client,label)
    start_seq=witness.get("auditWindowStartSequence"); start_prev=str(witness.get("auditWindowPreviousDigest") or ""); head_seq=witness.get("auditHeadSequence")
    start_valid=type(start_seq) is int and start_seq>0 and type(head_seq) is int and head_seq>=start_seq and ((start_seq==1 and start_prev=="") or (start_seq>1 and SHA.fullmatch(start_prev)))
    observed_oauth_client_id=validate_oauth_client_id(witness.get("oauthClientId"),label)
    if oauth_client_id is not None and observed_oauth_client_id!=validate_oauth_client_id(oauth_client_id,label):
        raise RuntimeError(f"{label}_OAUTH_CLIENT_MISMATCH")
    expected_request_ids=None
    if request_ids is not None:
        if not isinstance(request_ids,dict) or set(request_ids)!=set(AUDITED_CHECKS):
            raise RuntimeError(f"{label}_REQUEST_IDS_INVALID")
        expected_request_ids={check:str(request_ids.get(check) or "").strip() for check in AUDITED_CHECKS}
        if any(not REQUEST_ID.fullmatch(value) for value in expected_request_ids.values()) or len(set(expected_request_ids.values()))!=len(AUDITED_CHECKS):
            raise RuntimeError(f"{label}_REQUEST_IDS_INVALID")
    execution_observed=parse_utc_timestamp(witness.get("executionObservedAt"),label+"_EXECUTION")
    audit_window=witness.get("executionAuditWindowSeconds")
    if witness.get("authority")!=AUDIT_WITNESS_AUTHORITY or witness.get("auditMethodVersion")!=AUDIT_METHOD_VERSION or witness.get("auditChainDigestVerified") is not True or not start_valid or witness.get("serverAuditWitnessPass") is not True or witness.get("witnessedCheckCount")!=len(AUDITED_CHECKS) or witness.get("oauthClientWitnessPass") is not True or witness.get("oauthClientWitnessedCheckCount")!=len(OAUTH_CLIENT_AUDITED_CHECKS) or not SHA.fullmatch(str(witness.get("auditHeadDigest") or "")) or not SHA.fullmatch(str(witness.get("auditExportSha256") or "")) or type(audit_window) is not int or audit_window<60 or audit_window>24*3600:
        raise RuntimeError(f"{label}_INVALID")
    matched=witness.get("matchedEvents")
    if not isinstance(matched,dict) or set(matched)!=set(AUDITED_CHECKS):
        raise RuntimeError(f"{label}_INVALID")
    earliest=execution_observed-timedelta(seconds=audit_window)
    latest=execution_observed+timedelta(minutes=5)
    seen_sequences=set(); seen_digests=set(); seen_request_ids=set()
    for check,event in matched.items():
        if not isinstance(event,dict):
            raise RuntimeError(f"{label}_INVALID")
        occurred=parse_utc_timestamp(event.get("occurredAt"),label+"_OCCURRED_AT")
        if occurred<earliest or occurred>latest:
            raise RuntimeError(f"{label}_TIME_WINDOW_INVALID {check}")
        sequence=event.get("sequence"); digest=str(event.get("digest") or ""); request_id=str(event.get("requestId") or "").strip()
        category,decision,reason=AUDIT_REQUIREMENTS[check]
        expected_oauth=observed_oauth_client_id if check in OAUTH_CLIENT_AUDITED_CHECKS else ""
        if type(sequence) is not int or sequence<start_seq or sequence>head_seq or not SHA.fullmatch(digest) or not REQUEST_ID.fullmatch(request_id):
            raise RuntimeError(f"{label}_MATCHED_EVENT_INVALID {check}")
        if sequence in seen_sequences or digest in seen_digests or request_id in seen_request_ids:
            raise RuntimeError(f"{label}_MATCHED_EVENT_REUSE {check}")
        if event.get("category")!=category or event.get("decision")!=decision or event.get("reasonCode")!=reason or str(event.get("oauthClientId") or "").strip()!=expected_oauth or event.get("interopBindingDigest")!=binding:
            raise RuntimeError(f"{label}_MATCHED_EVENT_SEMANTICS_INVALID {check}")
        if expected_request_ids is not None and request_id!=expected_request_ids[check]:
            raise RuntimeError(f"{label}_MATCHED_EVENT_REQUEST_ID_MISMATCH {check}")
        seen_sequences.add(sequence); seen_digests.add(digest); seen_request_ids.add(request_id)
    return witness

_AUDIT_REQUIRED=("id","sequence","occurredAt","methodVersion","category","decision","actorId")
_AUDIT_OPTIONAL=("authentication","method","path","statusCode","reasonCode","requestId","scopeType","scopeId","effectiveRole","mappingDigest","oauthClientId","mcpInteropBindingDigest","previousDigest")
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

def validate_request_ids(row:dict,client:str)->dict[str,str]:
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
    if row.get("sourceCommitSHA")!=campaign.get("sourceCommitSHA") or row.get("runtimeVersion")!=campaign.get("runtimeVersion"):
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_RUNTIME_IDENTITY_INVALID {client}")
    oauth_client_id=validate_oauth_client_id(row.get("oauthClientId"),"MCP_EXTERNAL_RECEIPT")
    if oauth_client_id!=validate_oauth_client_id(challenge.get("oauthClientId"),"MCP_EXTERNAL_CAMPAIGN"):
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_OAUTH_CLIENT_INVALID {client}")
    binding=validate_interop_binding(row,campaign["campaignId"],client,"MCP_EXTERNAL_RECEIPT_SERVER")
    ep=endpoint(row.get("endpoint",""))
    if ep!=campaign.get("endpoint"):
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_CAMPAIGN_ENDPOINT_INVALID {client}")
    run_id=str(row.get("executionId") or "").strip()
    if not run_id or len(run_id)>160:
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_EXECUTION_ID_INVALID {client}")
    spec=campaign.get("_matrixSpec")
    if not isinstance(spec,dict):
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_CAMPAIGN_WINDOW_INVALID {client}")
    created,expires,audit_window=campaign_time_window(campaign,spec)
    executed=parse_utc_timestamp(row.get("executedAt"),"MCP_EXTERNAL_RECEIPT_EXECUTED_AT")
    if executed<created or executed>expires or executed>datetime.now(timezone.utc)+timedelta(minutes=5):
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_EXECUTION_TIME_INVALID {client}")
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
    request_ids=validate_request_ids(row,client)
    trusted=campaign_trusted_client_bindings(campaign)[client]
    return {"clientId":client,"clientSurface":row["clientSurface"],"endpoint":ep,"sourceCommitSHA":row["sourceCommitSHA"],"runtimeVersion":row["runtimeVersion"],"executionId":run_id,"providerExecutionRef":provider_ref,"executedAt":utc_timestamp(executed),"campaignId":row["campaignId"],"challengeSha256":row["challengeSha256"],"oauthClientId":oauth_client_id,**trusted,"interopBindingAuthority":INTEROP_BINDING_AUTHORITY,"interopBindingDigest":binding,"evidenceDigest":evidence,"externalReceiptSha256":sha256(path),"checks":checks,"requestIds":request_ids,"campaignCreatedAt":utc_timestamp(created),"campaignExpiresAt":utc_timestamp(expires),"executionAuditWindowSeconds":audit_window}

def validate_audit_export(path:Path)->list[dict]:
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
        if previous is None and ((seq==1 and previous_digest!="") or (seq>1 and not SHA.fullmatch(previous_digest))):
            raise RuntimeError("MCP_EXTERNAL_AUDIT_CHAIN_INVALID")
        if audit_event_digest(raw)!=digest:
            raise RuntimeError("MCP_EXTERNAL_AUDIT_DIGEST_INVALID")
        rows.append(raw); previous=raw
    return rows

def verify_server_audit(audit_path:Path,receipt:dict,client:str)->dict:
    request_ids=receipt["requestIds"]
    rows=validate_audit_export(audit_path)
    executed=parse_utc_timestamp(receipt.get("executedAt"),"MCP_EXTERNAL_RECEIPT_EXECUTED_AT")
    created=parse_utc_timestamp(receipt.get("campaignCreatedAt"),"MCP_EXTERNAL_CAMPAIGN_CREATED_AT")
    expires=parse_utc_timestamp(receipt.get("campaignExpiresAt"),"MCP_EXTERNAL_CAMPAIGN_EXPIRES_AT")
    audit_window=receipt.get("executionAuditWindowSeconds")
    if type(audit_window) is not int or audit_window<60:
        raise RuntimeError(f"MCP_EXTERNAL_AUDIT_WINDOW_INVALID {client}")
    earliest=executed-timedelta(seconds=audit_window)
    latest=executed+timedelta(minutes=5)
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
        occurred=parse_utc_timestamp(event.get("occurredAt"),"MCP_EXTERNAL_AUDIT_OCCURRED_AT")
        if occurred<created or occurred>expires or occurred<earliest or occurred>latest:
            raise RuntimeError(f"MCP_EXTERNAL_AUDIT_TIME_WINDOW_INVALID {client}:{check}")
        if event.get("category")!=category or event.get("decision")!=decision or event.get("reasonCode")!=reason:
            raise RuntimeError(f"MCP_EXTERNAL_AUDIT_SEMANTIC_WITNESS_MISSING {client}:{check}")
        if event.get("mcpInteropBindingDigest")!=receipt["interopBindingDigest"]:
            raise RuntimeError(f"MCP_EXTERNAL_AUDIT_INTEROP_BINDING_MISSING {client}:{check}")
        observed_oauth=str(event.get("oauthClientId") or "").strip()
        if check in OAUTH_CLIENT_AUDITED_CHECKS:
            if observed_oauth!=receipt["oauthClientId"]:
                raise RuntimeError(f"MCP_EXTERNAL_AUDIT_OAUTH_CLIENT_MISMATCH {client}:{check}")
        elif observed_oauth:
            raise RuntimeError(f"MCP_EXTERNAL_AUDIT_REJECTED_TOKEN_CLIENT_ID_UNEXPECTED {client}:{check}")
        matched[check]={"requestId":rid,"sequence":event["sequence"],"digest":event["digest"],"occurredAt":utc_timestamp(occurred),"category":category,"decision":decision,"reasonCode":reason,"oauthClientId":observed_oauth,"interopBindingDigest":receipt["interopBindingDigest"]}
    head=rows[-1]
    return {
      "authority":AUDIT_WITNESS_AUTHORITY,"clientId":client,"oauthClientId":receipt["oauthClientId"],"interopBindingAuthority":INTEROP_BINDING_AUTHORITY,"interopBindingDigest":receipt["interopBindingDigest"],
      "auditMethodVersion":AUDIT_METHOD_VERSION,"auditChainDigestVerified":True,"oauthClientWitnessPass":True,"oauthClientWitnessedCheckCount":len(OAUTH_CLIENT_AUDITED_CHECKS),
      "auditWindowStartSequence":rows[0]["sequence"],"auditWindowPreviousDigest":str(rows[0].get("previousDigest") or ""),
      "auditExportSha256":sha256(audit_path),"auditHeadSequence":head["sequence"],"auditHeadDigest":head["digest"],
      "executionObservedAt":receipt["executedAt"],"executionAuditWindowSeconds":audit_window,
      "witnessedCheckCount":len(AUDITED_CHECKS),"serverAuditWitnessPass":True,"matchedEvents":matched
    }

def validate_campaign_live_preflight(campaign:dict)->None:
    ep=endpoint(campaign.get("endpoint","")); parsed=urlsplit(ep); base=f"{parsed.scheme}://{parsed.netloc}"
    metadata_url=base+"/.well-known/oauth-protected-resource"
    row=campaign.get("livePreflight")
    if not isinstance(row,dict) or row.get("authority")!=CAMPAIGN_PREFLIGHT_AUTHORITY:
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_PREFLIGHT_INVALID")
    servers=row.get("authorizationServers")
    if not isinstance(servers,list) or not servers:
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_PREFLIGHT_INVALID")
    for value in servers:
        p=urlsplit(str(value or "").strip())
        if p.scheme!="https" or not p.hostname or p.username or p.password or p.query or p.fragment:
            raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_PREFLIGHT_INVALID")
    expected_challenge=f'Bearer resource_metadata="{metadata_url}"'
    if row.get("endpoint")!=ep or row.get("protectedResourceMetadata")!=metadata_url or row.get("resource")!=ep or row.get("scopes")!=["mcp.read","mcp.operate"] or row.get("unauthenticatedStatus")!=401 or row.get("challenge")!=expected_challenge or row.get("protocol")!="2026-07-28":
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_PREFLIGHT_INVALID")

def verify_campaign(campaign_path:Path,matrix_path:Path,spec:dict)->dict:
    matrix=load(matrix_path,"MATRIX")
    canonical_spec=validate_matrix_contract(matrix)
    if spec!=canonical_spec:
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_MATRIX_SPEC_DRIFT")
    campaign=load(campaign_path,"CAMPAIGN")
    if not isinstance(campaign,dict) or campaign.get("authority")!=CAMPAIGN_AUTHORITY or campaign.get("matrixAuthority")!=MATRIX_AUTHORITY:
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_AUTHORITY_INVALID")
    if campaign.get("matrixSha256")!=sha256(matrix_path) or campaign.get("protocol")!=spec.get("protocol") or campaign.get("transport")!=spec.get("transport") or campaign.get("externalExecutionRequired") is not True:
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_MATRIX_BINDING_INVALID")
    source_commit=str(campaign.get("sourceCommitSHA") or "").strip(); runtime_version=str(campaign.get("runtimeVersion") or "").strip()
    if not COMMIT.fullmatch(source_commit) or not runtime_version or len(runtime_version)>128 or any(ch in runtime_version for ch in "\r\n\t"):
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_RUNTIME_IDENTITY_INVALID")
    if not str(campaign.get("campaignId") or "").startswith("mcp-interop-"):
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_ID_INVALID")
    campaign["endpoint"]=endpoint(campaign.get("endpoint",""))
    campaign_time_window(campaign,spec)
    campaign["_matrixSpec"]=spec
    validate_campaign_live_preflight(campaign)
    rows=campaign.get("clients")
    if not isinstance(rows,list) or [x.get("clientId") for x in rows if isinstance(x,dict)]!=list(CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_CLIENT_SET_INVALID")
    if campaign.get("oauthClientBindingAuthority")!=OAUTH_BINDING_AUTHORITY or not SHA.fullmatch(str(campaign.get("oauthClientBindingsSha256") or "")):
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_OAUTH_BINDING_INVALID")
    challenge_values=set(); challenge_digests=set(); oauth_client_ids=set()
    for row in rows:
        challenge=str(row.get("challenge") or "")
        expected="sha256:"+hashlib.sha256(challenge.encode()).hexdigest()
        oauth_client_id=validate_oauth_client_id(row.get("oauthClientId"),"MCP_EXTERNAL_CAMPAIGN")
        if len(challenge)<32 or row.get("challengeSha256")!=expected:
            raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_CHALLENGE_INVALID")
        if row.get("trustedClientProvider")!=row.get("clientId") or not str(row.get("trustedClientId") or "").strip() or type(row.get("trustedClientRevision")) is not int or row["trustedClientRevision"]<=0:
            raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_TRUSTED_CLIENT_READBACK_INVALID")
        if challenge in challenge_values or expected in challenge_digests:
            raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_CHALLENGE_REUSE")
        if oauth_client_id in oauth_client_ids:
            raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_OAUTH_CLIENT_REUSE")
        challenge_values.add(challenge); challenge_digests.add(expected); oauth_client_ids.add(oauth_client_id)
    campaign_trusted_client_bindings(campaign)
    return campaign

def build_interop_evidence(matrix_sha256:str,campaign_id:str,campaign_sha256:str,oauth_binding_sha256:str,source_commit_sha:str,runtime_version:str,protocol:str,transport:str,endpoint_value:str,rows:list[dict])->dict:
    if not SHA.fullmatch(str(matrix_sha256 or "")) or not SHA.fullmatch(str(campaign_sha256 or "")) or not SHA.fullmatch(str(oauth_binding_sha256 or "")):
        raise RuntimeError("MCP_EXTERNAL_EVIDENCE_BINDING_INVALID")
    if not str(campaign_id or "").startswith("mcp-interop-") or protocol!="2026-07-28" or transport!="streamable-http":
        raise RuntimeError("MCP_EXTERNAL_EVIDENCE_BINDING_INVALID")
    source_commit_sha=str(source_commit_sha or "").strip(); runtime_version=str(runtime_version or "").strip()
    if not COMMIT.fullmatch(source_commit_sha) or not runtime_version or len(runtime_version)>128:
        raise RuntimeError("MCP_EXTERNAL_EVIDENCE_RUNTIME_IDENTITY_INVALID")
    if not isinstance(rows,list) or [row.get("clientId") for row in rows if isinstance(row,dict)]!=list(CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_EVIDENCE_CLIENT_SET_INVALID")
    ep=endpoint(endpoint_value)
    return {
      "apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteroperabilityEvidence",
      "authority":AUTHORITY,"matrixAuthority":MATRIX_AUTHORITY,"matrixSha256":matrix_sha256,
      "campaignAuthority":CAMPAIGN_AUTHORITY,"campaignId":campaign_id,"campaignSha256":campaign_sha256,
      "oauthClientBindingAuthority":OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":oauth_binding_sha256,
      "oauthClientBindings":validate_oauth_client_bindings({row["clientId"]:row.get("oauthClientId") for row in rows},"MCP_EXTERNAL_EVIDENCE"),
      "trustedClientBindings":validate_trusted_client_bindings({row["clientId"]:{"trustedClientId":row.get("trustedClientId"),"trustedClientRevision":row.get("trustedClientRevision"),"trustedClientProvider":row.get("trustedClientProvider")} for row in rows},"MCP_EXTERNAL_EVIDENCE"),
      "sourceCommitSHA":source_commit_sha,"runtimeVersion":runtime_version,
      "protocol":protocol,"transport":transport,"endpoint":ep,
      "clients":rows,"certifiedClientCount":len(CLIENTS),"allRequiredChecksPass":True,
      "serverAuditWitnessPass":True,"serverAuditWitnessedCheckCount":len(AUDITED_CHECKS)*len(CLIENTS),
      "externalCertificationPass":True,"runtimeCertified":False,"physicalCertified":False
    }

def seal(matrix_path:Path,campaign_path:Path,receipt_dir:Path,audit_dir:Path)->dict:
    matrix=load(matrix_path,"MATRIX")
    spec=validate_matrix_contract(matrix)
    protocol=str(spec["protocol"])
    required=list(spec["sharedRequiredChecks"])
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
    return build_interop_evidence(
        sha256(matrix_path),campaign["campaignId"],sha256(campaign_path),campaign["oauthClientBindingsSha256"],
        campaign["sourceCommitSHA"],campaign["runtimeVersion"],protocol,"streamable-http",next(iter(endpoints)),rows,
    )

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--matrix",type=Path,default=Path("lab/mcp-external-client-interop-matrix.json"))
    p.add_argument("--campaign",type=Path,required=True)
    p.add_argument("--receipts",type=Path,required=True)
    p.add_argument("--audits",type=Path,required=True)
    p.add_argument("--out",type=Path)
    a=p.parse_args(); out=seal(a.matrix,a.campaign,a.receipts,a.audits)
    if a.out:
        write_json_once_or_identical(a.out,out,"MCP_EXTERNAL_INTEROP_EVIDENCE")
    print(json.dumps(out,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
