#!/usr/bin/env python3
"""Finalize one real external MCP client capture into a canonical C7W receipt.

This tool does not execute an MCP client and cannot manufacture certification.
It only converts an independently produced capture into the strict receipt
format after binding the capture to the one-shot campaign execution packet,
requiring all seven checks to pass and all six protected checks to carry unique
server request IDs.
"""
from __future__ import annotations
import argparse,json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import seal_mcp_external_interop as core

AUTHORITY="MCP_EXTERNAL_CLIENT_CAPTURE_V1"
PACKET_AUTHORITY="MCP_EXTERNAL_CLIENT_EXECUTION_PACKET_V1"

def observation_template(check:dict)->dict:
    expect=check.get("expect") or {}
    if not isinstance(expect,dict) or not expect:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_EXPECT_INVALID")
    out={}
    for key,value in expect.items():
        if key=="scopesContain":
            out["scopes"]=[]
        elif type(value) is bool:
            out[key]=None
        elif type(value) is int:
            out[key]=None
        elif isinstance(value,str):
            out[key]=""
        else:
            raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_PACKET_EXPECT_UNSUPPORTED {key}")
    return out


def validate_observation(check_id:str,check:dict,observed:object)->None:
    expect=check.get("expect") or {}
    if not isinstance(expect,dict) or not expect or not isinstance(observed,dict):
        raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_OBSERVATION_INVALID {check_id}")
    expected_keys={("scopes" if key=="scopesContain" else key) for key in expect}
    if set(observed)!=expected_keys:
        raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_OBSERVATION_FIELDS_INVALID {check_id}")
    for key,wanted in expect.items():
        if key=="scopesContain":
            scopes=observed.get("scopes")
            if (
                not isinstance(scopes,list)
                or any(not isinstance(value,str) or not value for value in scopes)
                or len(scopes)!=len(set(scopes))
                or not set(wanted).issubset(set(scopes))
            ):
                raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_OBSERVATION_MISMATCH {check_id}:scopes")
            continue
        actual=observed.get(key)
        if type(wanted) is bool:
            if type(actual) is not bool or actual is not wanted:
                raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_OBSERVATION_MISMATCH {check_id}:{key}")
        elif type(wanted) is int:
            if type(actual) is not int or actual!=wanted:
                raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_OBSERVATION_MISMATCH {check_id}:{key}")
        elif isinstance(wanted,str):
            if actual!=wanted:
                raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_OBSERVATION_MISMATCH {check_id}:{key}")
        else:
            raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_PACKET_EXPECT_UNSUPPORTED {check_id}:{key}")


def validate_packet(packet:dict)->tuple[str,str]:
    if not isinstance(packet,dict) or packet.get("authority")!=PACKET_AUTHORITY or packet.get("kind")!="MCPExternalClientExecutionPacket":
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_AUTHORITY_INVALID")
    if packet.get("matrixAuthority")!=core.MATRIX_AUTHORITY or packet.get("campaignAuthority")!=core.CAMPAIGN_AUTHORITY:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_SOURCE_AUTHORITY_INVALID")
    if packet.get("protocol")!="2026-07-28" or packet.get("transport")!="streamable-http":
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_PROTOCOL_INVALID")
    source_commit=str(packet.get("sourceCommitSHA") or "").strip().lower()
    runtime_version=str(packet.get("runtimeVersion") or "").strip()
    if not core.COMMIT.fullmatch(source_commit) or not runtime_version or len(runtime_version)>128:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_RUNTIME_IDENTITY_INVALID")
    try:
        endpoint=core.endpoint(packet.get("endpoint",""))
    except RuntimeError as exc:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_ENDPOINT_INVALID") from exc
    client=str(packet.get("clientId") or "").strip().lower()
    if client not in core.CLIENTS or packet.get("clientSurface")!=core.CLIENT_SURFACES[client] or packet.get("secretsIncluded") is not False:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_CLIENT_INVALID")
    if packet.get("runtimeCertified") is not False or packet.get("physicalCertified") is not False:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_SCOPE_INFLATED")
    requirements=packet.get("receiptRequirements")
    expected_requirements={
        "authority":core.RECEIPT_AUTHORITY,
        "captureAuthority":AUTHORITY,
        "serverAuditWitnessAuthority":core.AUDIT_WITNESS_AUTHORITY,
        "interopBindingAuthority":core.INTEROP_BINDING_AUTHORITY,
        "oauthClientId":packet.get("oauthClientId"),
        "oauthClientWitnessedChecks":list(core.OAUTH_CLIENT_AUDITED_CHECKS),
        "executedAtRequired":True,
        "observedRuntimeIdentityRequired":True,
        "structuredResponseObservationRequired":True,
        "allSevenChecksMustPass":True,
        "externalExecution":True,
        "credentialedExecution":True,
    }
    if not isinstance(requirements,dict):
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_REQUIREMENTS_INVALID")
    for key,value in expected_requirements.items():
        if requirements.get(key)!=value:
            raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_PACKET_REQUIREMENTS_INVALID {key}")
    if requirements.get("requestIds")!=list(core.AUDITED_CHECKS):
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_REQUIREMENTS_INVALID requestIds")
    finalizer=str(requirements.get("finalizer") or "")
    if "finalize_mcp_external_client_receipt.py" not in finalizer or "--packet <packet.json>" not in finalizer or "--capture <capture.json>" not in finalizer:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_REQUIREMENTS_INVALID finalizer")
    return client,endpoint

def finalize(packet_path:Path,capture_path:Path)->dict:
    packet=core.load(packet_path,"EXECUTION_PACKET")
    capture=core.load(capture_path,"EXTERNAL_CAPTURE")
    client,packet_endpoint=validate_packet(packet)
    if not isinstance(capture,dict) or capture.get("authority")!=AUTHORITY or capture.get("clientId")!=client:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_IDENTITY_INVALID")
    allowed_capture={"authority","clientId","clientSurface","campaignId","challengeSha256","endpoint","sourceCommitSHA","runtimeVersion","executionId","executedAt","externalExecution","credentialedExecution","checks","providerExecutionRef"}
    if set(capture)!=allowed_capture:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_FIELDS_INVALID")
    provider_ref=str(capture.get("providerExecutionRef") or "").strip()
    if len(provider_ref)<8 or len(provider_ref)>500 or any(ord(ch)<0x21 or ord(ch)>0x7e for ch in provider_ref):
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PROVIDER_EXECUTION_REF_INVALID")
    created=core.parse_utc_timestamp(packet.get("campaignCreatedAt"),"MCP_EXTERNAL_CAPTURE_CAMPAIGN_CREATED_AT")
    expires=core.parse_utc_timestamp(packet.get("campaignExpiresAt"),"MCP_EXTERNAL_CAPTURE_CAMPAIGN_EXPIRES_AT")
    audit_window=packet.get("executionAuditWindowSeconds")
    if type(audit_window) is not int or audit_window<60 or audit_window>24*3600 or created>=expires:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_CAMPAIGN_WINDOW_INVALID")
    executed=core.parse_utc_timestamp(capture.get("executedAt"),"MCP_EXTERNAL_CAPTURE_EXECUTED_AT")
    if executed<created or executed>expires or executed>datetime.now(timezone.utc)+timedelta(minutes=5):
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_EXECUTION_TIME_INVALID")
    for key in ("clientSurface","campaignId","challengeSha256","sourceCommitSHA","runtimeVersion"):
        if capture.get(key)!=packet.get(key):
            raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_BINDING_INVALID {key}")
    try:
        capture_endpoint=core.endpoint(capture.get("endpoint",""))
    except RuntimeError as exc:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_ENDPOINT_INVALID") from exc
    if capture_endpoint!=packet_endpoint:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_BINDING_INVALID endpoint")
    oauth_client_id=str(packet.get("oauthClientId") or "").strip()
    if not oauth_client_id or len(oauth_client_id.encode("utf-8"))>512 or any(ch in oauth_client_id for ch in "\r\n\t"):
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_OAUTH_CLIENT_INVALID")
    binding=core.interop_binding_digest(packet.get("campaignId"),client,packet.get("challengeSha256"))
    if packet.get("interopBindingAuthority")!=core.INTEROP_BINDING_AUTHORITY or packet.get("interopBindingDigest")!=binding:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_SERVER_BINDING_INVALID")
    meta=packet.get("requestMeta") or {}
    expected_meta={
      "io.modelcontextprotocol/protocolVersion":"2026-07-28",
      "io.modelcontextprotocol/clientInfo":{"name":packet["clientSurface"],"version":"external-c7w"},
      "io.modelcontextprotocol/clientCapabilities":{"tools":{}},
      "io.4so/interopCampaignId":packet.get("campaignId"),
      "io.4so/interopClientId":client,
      "io.4so/interopChallengeSha256":packet.get("challengeSha256"),
      "io.4so/sourceCommitSHA":packet.get("sourceCommitSHA"),
      "io.4so/runtimeVersion":packet.get("runtimeVersion"),
    }
    if meta!=expected_meta:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_META_INVALID")
    execution_id=str(capture.get("executionId") or "").strip()
    if not execution_id or len(execution_id)>160:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_EXECUTION_ID_INVALID")
    if capture.get("externalExecution") is not True or capture.get("credentialedExecution") is not True:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_NOT_EXTERNAL_CREDENTIALED")
    packet_checks=packet.get("checks")
    if not isinstance(packet_checks,list):
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_CHECKS_INVALID")
    expected_ids=[str(x.get("id") or "") for x in packet_checks if isinstance(x,dict)]
    if expected_ids!=list(core.REQUIRED_CHECKS):
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_CHECKS_INVALID")
    packet_meta=packet.get("requestMeta")
    expected_packet_meta=expected_meta
    if packet_meta!=expected_packet_meta:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_META_INVALID")
    parsed_endpoint=core.urlsplit(packet_endpoint)
    metadata_url=f"{parsed_endpoint.scheme}://{parsed_endpoint.netloc}/.well-known/oauth-protected-resource"
    canonical_expectations={
        "oauth-protected-resource-discovery":{"httpStatus":200,"resource":packet_endpoint,"scopesContain":["mcp.read","mcp.operate"]},
        "dedicated-audience-validation":{"httpStatus":401,"accepted":False},
        "authorization-filtered-tools-list":{"httpStatus":200,"toolListFilteredByDelegation":True,"sourceCommitSHA":packet["sourceCommitSHA"],"runtimeVersion":packet["runtimeVersion"]},
        "project-resource-scope-negative-control":{"accepted":False,"foreignProjectDataReturned":False},
        "revoked-delegation-negative-control":{"accepted":False},
        "read-only-client-mutation-negative-control":{"accepted":False,"mutationObserved":False},
        "administration-approval-self-approval-negative-control":{"accepted":False,"selfApprovalObserved":False},
    }
    canonical_requests={
        "dedicated-audience-validation":("valid-user-token-wrong-resource-audience","tools/list",None,None),
        "authorization-filtered-tools-list":("campaign-delegated-user","tools/list",None,None),
        "project-resource-scope-negative-control":("project-scoped-delegation","tools/call","ops_search",{"projectId":"<foreign-project-id>","query":"scope-negative-control"}),
        "revoked-delegation-negative-control":("revoked-campaign-delegation","tools/list",None,None),
        "read-only-client-mutation-negative-control":("view-delegation","tools/call","operation_cancel",{"id":"<same-project-operation-id>","expectedRevision":1,"reason":"interop negative control"}),
        "administration-approval-self-approval-negative-control":("administration-delegation-requester","tools/call","managed_okd_install_approve",{"id":"<request-created-by-same-subject>","expectedRevision":1}),
    }
    for row in packet_checks:
        check_id=row["id"]
        if check_id=="authorization-filtered-tools-list":
            capture_runtime=row.get("captureRuntimeIdentityFrom")
            expected_capture_runtime={"sourceCommitSHA":"success-json:result._meta.io.modelcontextprotocol/serverInfo.sourceCommitSHA","runtimeVersion":"success-json:result._meta.io.modelcontextprotocol/serverInfo.version"}
            expect=row.get("expect") or {}
            if capture_runtime!=expected_capture_runtime or expect.get("sourceCommitSHA")!=packet["sourceCommitSHA"] or expect.get("runtimeVersion")!=packet["runtimeVersion"]:
                raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_PACKET_RUNTIME_WITNESS_INVALID {check_id}")
        expected_row_fields={"id","request","expect","serverAuditWitnessRequired"} if check_id=="oauth-protected-resource-discovery" else ({"id","request","expect","captureRuntimeIdentityFrom","serverAudit"} if check_id=="authorization-filtered-tools-list" else {"id","request","expect","serverAudit"})
        if set(row)!=expected_row_fields or row.get("expect")!=canonical_expectations[check_id]:
            raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_PACKET_SEMANTICS_INVALID {check_id}")
        if check_id not in core.AUDITED_CHECKS:
            request=row.get("request") or {}
            if (
                check_id!="oauth-protected-resource-discovery"
                or row.get("serverAuditWitnessRequired") is not False
                or request!={"httpMethod":"GET","url":metadata_url,"credentialProfile":"none","headers":{"Accept":"application/json"}}
            ):
                raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_PACKET_WIRE_INVALID {check_id}")
            continue
        request=row.get("request") or {}
        credential_profile,canonical_method,canonical_tool,canonical_arguments=canonical_requests[check_id]
        expected_audit=core.AUDIT_REQUIREMENTS[check_id]
        if row.get("serverAudit")!={"category":expected_audit[0],"decision":expected_audit[1],"reasonCode":expected_audit[2]} or request.get("credentialProfile")!=credential_profile:
            raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_PACKET_SEMANTICS_INVALID {check_id}")
        headers=request.get("headers") or {}
        rpc=request.get("jsonRpc") or {}
        params=rpc.get("params") or {}
        method=rpc.get("method")
        if method!=canonical_method:
            raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_PACKET_SEMANTICS_INVALID {check_id}")
        expected_header_keys={"Content-Type","Accept","MCP-Protocol-Version","Mcp-Method","Mcp-Interop-Binding"}
        if method=="tools/call":
            expected_header_keys.add("Mcp-Name")
        if (
            request.get("httpMethod")!="POST" or request.get("url")!=packet_endpoint
            or request.get("protocol")!="2026-07-28" or request.get("transport")!="streamable-http"
            or request.get("contentType")!="application/json"
            or set(headers)!=expected_header_keys
            or headers.get("Content-Type")!="application/json"
            or headers.get("Accept")!="application/json, text/event-stream"
            or headers.get("MCP-Protocol-Version")!="2026-07-28"
            or headers.get("Mcp-Method")!=method
            or headers.get("Mcp-Interop-Binding")!=binding
            or rpc.get("jsonrpc")!="2.0" or rpc.get("id")!="<unique-jsonrpc-id>"
            or params.get("_meta")!=expected_packet_meta
        ):
            raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_PACKET_WIRE_INVALID {check_id}")
        if method=="tools/call":
            if params.get("name")!=canonical_tool or params.get("arguments")!=canonical_arguments or headers.get("Mcp-Name")!=canonical_tool:
                raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_PACKET_WIRE_INVALID {check_id}")
        elif method=="tools/list":
            if canonical_tool is not None or canonical_arguments is not None or set(params)!={"_meta"} or "Mcp-Name" in headers:
                raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_PACKET_WIRE_INVALID {check_id}")
        else:
            raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_PACKET_WIRE_INVALID {check_id}")
    observed=capture.get("checks")
    if not isinstance(observed,dict) or set(observed)!=set(expected_ids):
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_CHECK_COVERAGE_INVALID")
    packet_by_id={row["id"]:row for row in packet_checks}
    request_ids={}
    for check_id in expected_ids:
        row=observed.get(check_id)
        expected_fields={"observed","requestId"} if check_id in core.AUDITED_CHECKS else {"observed"}
        if not isinstance(row,dict) or set(row)!=expected_fields:
            raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_CHECK_FIELDS_INVALID {check_id}")
        validate_observation(check_id,packet_by_id[check_id],row.get("observed"))
        rid=str(row.get("requestId") or "").strip()
        if check_id in core.AUDITED_CHECKS:
            if not core.REQUEST_ID.fullmatch(rid):
                raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_REQUEST_ID_INVALID {check_id}")
            request_ids[check_id]=rid
    if len(set(request_ids.values()))!=len(core.AUDITED_CHECKS):
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_REQUEST_ID_REUSE")
    return {
      "authority":core.RECEIPT_AUTHORITY,
      "clientId":client,
      "clientSurface":packet["clientSurface"],
      "sourceCommitSHA":packet["sourceCommitSHA"],
      "runtimeVersion":packet["runtimeVersion"],
      "campaignId":packet["campaignId"],
      "challengeSha256":packet["challengeSha256"],
      "oauthClientId":oauth_client_id,
      "interopBindingAuthority":core.INTEROP_BINDING_AUTHORITY,
      "interopBindingDigest":binding,
      "protocol":packet["protocol"],
      "transport":packet["transport"],
      "endpoint":packet["endpoint"],
      "executionId":execution_id,
      "providerExecutionRef":provider_ref,
      "executedAt":core.utc_timestamp(executed),
      "externalExecution":True,
      "credentialedExecution":True,
      "checks":{name:True for name in expected_ids},
      "requestIds":request_ids,
      "scopeLeakObserved":False,
      "revokedGrantAccepted":False,
      "selfApprovalAccepted":False,
      "evidenceDigest":core.sha256(capture_path),
    }

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--packet",type=Path,required=True)
    p.add_argument("--capture",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    out=finalize(a.packet,a.capture)
    core.write_json_once_or_identical(a.out,out,"MCP_EXTERNAL_CLIENT_RECEIPT")
    print(json.dumps({"authority":core.RECEIPT_AUTHORITY,"clientId":out["clientId"],"executionId":out["executionId"],"evidenceDigest":out["evidenceDigest"]},sort_keys=True))
    return 0
if __name__=="__main__": raise SystemExit(main())
