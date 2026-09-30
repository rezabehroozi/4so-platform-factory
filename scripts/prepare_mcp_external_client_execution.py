#!/usr/bin/env python3
"""Generate one exact external-client execution packet for a C7W campaign."""
from __future__ import annotations
import argparse,json
from pathlib import Path
from urllib.parse import urlsplit
import seal_mcp_external_interop as core

AUTHORITY="MCP_EXTERNAL_CLIENT_EXECUTION_PACKET_V1"

def packet(matrix_path:Path,campaign_path:Path,client:str)->dict:
    matrix=core.load(matrix_path,"MATRIX"); spec=matrix.get("spec") or {}
    campaign=core.verify_campaign(campaign_path,matrix_path,spec)
    client=str(client or "").strip().lower()
    if client not in core.CLIENTS: raise RuntimeError("MCP_EXTERNAL_EXECUTION_PACKET_CLIENT_INVALID")
    client_spec=next((x for x in spec.get("clients") or [] if isinstance(x,dict) and x.get("id")==client),None)
    if not client_spec or client_spec.get("displayName")!=core.CLIENT_SURFACES[client]:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_PACKET_CLIENT_SURFACE_INVALID")
    challenge=next(x for x in campaign["clients"] if x["clientId"]==client)
    binding=core.interop_binding_digest(campaign["campaignId"],client,challenge["challengeSha256"])
    ep=campaign["endpoint"]; parsed=urlsplit(ep); base=f"{parsed.scheme}://{parsed.netloc}"
    common={"httpMethod":"POST","url":ep,"protocol":spec["protocol"],"transport":spec["transport"],"contentType":"application/json","headers":{"Mcp-Interop-Binding":binding},"captureRequestIdFrom":["response-header:X-Request-ID","success-json:result._meta.io.4so/requestId"]}
    checks=[
      {"id":"oauth-protected-resource-discovery","request":{"httpMethod":"GET","url":base+"/.well-known/oauth-protected-resource","credentialProfile":"none"},"expect":{"httpStatus":200,"resource":ep,"scopesContain":["mcp.read","mcp.operate"]},"serverAuditWitnessRequired":False},
      {"id":"dedicated-audience-validation","request":{**common,"credentialProfile":"valid-user-token-wrong-resource-audience","mcpMethod":"tools/list"},"expect":{"httpStatus":401,"accepted":False},"serverAudit":{"category":"AUTHENTICATION","decision":"DENY","reasonCode":"OIDC_AUTHENTICATION_REJECTED"}},
      {"id":"authorization-filtered-tools-list","request":{**common,"credentialProfile":"campaign-delegated-user","mcpMethod":"tools/list"},"expect":{"httpStatus":200,"toolListFilteredByDelegation":True},"serverAudit":{"category":"CAPABILITY_AUTHORIZATION","decision":"ALLOW","reasonCode":"CAPABILITY_AUTHORIZED"}},
      {"id":"project-resource-scope-negative-control","request":{**common,"credentialProfile":"project-scoped-delegation","mcpMethod":"tools/call","tool":"ops_search","arguments":{"projectId":"<foreign-project-id>","query":"scope-negative-control"}},"expect":{"accepted":False,"foreignProjectDataReturned":False},"serverAudit":{"category":"SCOPE_AUTHORIZATION","decision":"DENY","reasonCode":"PROJECT_ACCESS_DENIED"}},
      {"id":"revoked-delegation-negative-control","request":{**common,"credentialProfile":"revoked-campaign-delegation","mcpMethod":"tools/list"},"expect":{"accepted":False},"serverAudit":{"category":"DELEGATION_AUTHORIZATION","decision":"DENY","reasonCode":"MCP_DELEGATION_INACTIVE"}},
      {"id":"read-only-client-mutation-negative-control","request":{**common,"credentialProfile":"view-delegation","mcpMethod":"tools/call","tool":"operation_cancel","arguments":{"id":"<same-project-operation-id>","expectedRevision":1,"reason":"interop negative control"}},"expect":{"accepted":False,"mutationObserved":False},"serverAudit":{"category":"CAPABILITY_AUTHORIZATION","decision":"DENY","reasonCode":"CAPABILITY_PERMISSION_REQUIRED"}},
      {"id":"administration-approval-self-approval-negative-control","request":{**common,"credentialProfile":"administration-delegation-requester","mcpMethod":"tools/call","tool":"managed_okd_install_approve","arguments":{"id":"<request-created-by-same-subject>","expectedRevision":1}},"expect":{"accepted":False,"selfApprovalObserved":False},"serverAudit":{"category":"APPROVAL_AUTHORIZATION","decision":"DENY","reasonCode":"SEPARATION_OF_DUTIES_REQUIRED"}},
    ]
    return {"apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientExecutionPacket","authority":AUTHORITY,"matrixAuthority":core.MATRIX_AUTHORITY,"campaignAuthority":core.CAMPAIGN_AUTHORITY,"campaignId":campaign["campaignId"],"clientId":client,"clientSurface":core.CLIENT_SURFACES[client],"endpoint":ep,"protocol":spec["protocol"],"transport":spec["transport"],"challenge":challenge["challenge"],"challengeSha256":challenge["challengeSha256"],"interopBindingAuthority":core.INTEROP_BINDING_AUTHORITY,"interopBindingDigest":binding,"requestMeta":{"io.4so/interopCampaignId":campaign["campaignId"],"io.4so/interopClientId":client,"io.4so/interopChallengeSha256":challenge["challengeSha256"]},"checks":checks,"receiptRequirements":{"authority":core.RECEIPT_AUTHORITY,"captureAuthority":"MCP_EXTERNAL_CLIENT_CAPTURE_V1","finalizer":"python3 scripts/finalize_mcp_external_client_receipt.py --packet <packet.json> --capture <capture.json> --out <receipt.json>","requestIds":list(core.AUDITED_CHECKS),"serverAuditWitnessAuthority":core.AUDIT_WITNESS_AUTHORITY,"interopBindingAuthority":core.INTEROP_BINDING_AUTHORITY,"allSevenChecksMustPass":True,"externalExecution":True,"credentialedExecution":True},"secretsIncluded":False,"runtimeCertified":False,"physicalCertified":False}

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--matrix",type=Path,default=Path("lab/mcp-external-client-interop-matrix.json")); p.add_argument("--campaign",type=Path,required=True); p.add_argument("--client",choices=core.CLIENTS,required=True); p.add_argument("--out",type=Path,required=True)
    a=p.parse_args(); out=packet(a.matrix,a.campaign,a.client); core.write_json_once_or_identical(a.out,out,"MCP_EXTERNAL_EXECUTION_PACKET"); print(json.dumps({"authority":AUTHORITY,"clientId":a.client,"campaignId":out["campaignId"]},sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
