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
from pathlib import Path
import seal_mcp_external_interop as core

AUTHORITY="MCP_EXTERNAL_CLIENT_CAPTURE_V1"
PACKET_AUTHORITY="MCP_EXTERNAL_CLIENT_EXECUTION_PACKET_V1"

def finalize(packet_path:Path,capture_path:Path)->dict:
    packet=core.load(packet_path,"EXECUTION_PACKET")
    capture=core.load(capture_path,"EXTERNAL_CAPTURE")
    if not isinstance(packet,dict) or packet.get("authority")!=PACKET_AUTHORITY:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_AUTHORITY_INVALID")
    client=str(packet.get("clientId") or "").strip().lower()
    if client not in core.CLIENTS or packet.get("secretsIncluded") is not False:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_CLIENT_INVALID")
    if not isinstance(capture,dict) or capture.get("authority")!=AUTHORITY or capture.get("clientId")!=client:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_IDENTITY_INVALID")
    allowed_capture={"authority","clientId","clientSurface","campaignId","challengeSha256","endpoint","executionId","externalExecution","credentialedExecution","checks","providerExecutionRef"}
    if set(capture)!=allowed_capture:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_FIELDS_INVALID")
    provider_ref=str(capture.get("providerExecutionRef") or "").strip()
    if len(provider_ref)<8 or len(provider_ref)>500 or any(ord(ch)<0x21 or ord(ch)>0x7e for ch in provider_ref):
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PROVIDER_EXECUTION_REF_INVALID")
    for key in ("clientSurface","campaignId","challengeSha256","endpoint"):
        if capture.get(key)!=packet.get(key):
            raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_BINDING_INVALID {key}")
    meta=packet.get("requestMeta") or {}
    expected_meta={
      "io.4so/interopCampaignId":packet.get("campaignId"),
      "io.4so/interopClientId":client,
      "io.4so/interopChallengeSha256":packet.get("challengeSha256"),
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
    if len(expected_ids)!=7 or len(set(expected_ids))!=7:
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_PACKET_CHECKS_INVALID")
    observed=capture.get("checks")
    if not isinstance(observed,dict) or set(observed)!=set(expected_ids):
        raise RuntimeError("MCP_EXTERNAL_CAPTURE_CHECK_COVERAGE_INVALID")
    request_ids={}
    for check_id in expected_ids:
        row=observed.get(check_id)
        expected_fields={"passed","requestId"} if check_id in core.AUDITED_CHECKS else {"passed"}
        if not isinstance(row,dict) or set(row)!=expected_fields:
            raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_CHECK_FIELDS_INVALID {check_id}")
        if row.get("passed") is not True:
            raise RuntimeError(f"MCP_EXTERNAL_CAPTURE_CHECK_NOT_PASS {check_id}")
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
      "campaignId":packet["campaignId"],
      "challengeSha256":packet["challengeSha256"],
      "protocol":packet["protocol"],
      "transport":packet["transport"],
      "endpoint":packet["endpoint"],
      "executionId":execution_id,
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
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"authority":core.RECEIPT_AUTHORITY,"clientId":out["clientId"],"executionId":out["executionId"],"evidenceDigest":out["evidenceDigest"]},sort_keys=True))
    return 0
if __name__=="__main__": raise SystemExit(main())
