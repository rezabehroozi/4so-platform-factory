#!/usr/bin/env python3
"""Generate one exact external-client execution packet for a C7W campaign."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from urllib.parse import urlsplit
import c7w_execution_bindings as execution_bindings
import seal_mcp_external_interop as core

AUTHORITY="MCP_EXTERNAL_CLIENT_EXECUTION_PACKET_V1"
ROOT=Path(__file__).resolve().parents[1]


def _binding_snapshot(campaign:dict)->tuple[dict,str]:
    source_sha=str(campaign.get("sourceCommitSHA") or "").strip().lower()
    embedded_keys={
        "executionBindingAuthority","executionBindingsSha256","executionBindings",
        "credentialProfileContractAuthority","credentialProfileContractSha256",
    }
    if embedded_keys.issubset(set(campaign)):
        document={
            "authority":campaign.get("executionBindingAuthority"),
            "sourceCommitSHA":source_sha,
            "resources":campaign.get("executionBindings"),
            "credentialProfileContractAuthority":campaign.get("credentialProfileContractAuthority"),
            "credentialProfileContractSha256":campaign.get("credentialProfileContractSha256"),
        }
        validated=execution_bindings.validate_document(document,source_sha)
        raw=(json.dumps(validated,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode("utf-8")
        digest="sha256:"+hashlib.sha256(raw).hexdigest()
        if campaign.get("executionBindingsSha256")!=digest:
            raise RuntimeError("MCP_EXTERNAL_EXECUTION_PACKET_BINDINGS_DIGEST_INVALID")
        return validated,digest
    path=ROOT/execution_bindings.DEFAULT_OUTPUT
    return execution_bindings.load(path,source_sha)


def packet(matrix_path:Path,campaign_path:Path,client:str)->dict:
    matrix=core.load(matrix_path,"MATRIX"); spec=matrix.get("spec") or {}
    campaign=core.verify_campaign(campaign_path,matrix_path,spec)
    client=str(client or "").strip().lower()
    if client not in core.CLIENTS: raise RuntimeError("MCP_EXTERNAL_EXECUTION_PACKET_CLIENT_INVALID")
    client_spec=next((x for x in spec.get("clients") or [] if isinstance(x,dict) and x.get("id")==client),None)
    if not client_spec or client_spec.get("displayName")!=core.CLIENT_SURFACES[client]:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_PACKET_CLIENT_SURFACE_INVALID")
    binding_document,binding_sha=_binding_snapshot(campaign)
    resources=binding_document["resources"]
    credential_contract=execution_bindings.credential_contract()
    credential_digest=execution_bindings.credential_contract_digest()
    if (
        binding_document["credentialProfileContractAuthority"]!=credential_contract["authority"]
        or binding_document["credentialProfileContractSha256"]!=credential_digest
    ):
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_PACKET_CREDENTIAL_CONTRACT_INVALID")
    challenge=next(x for x in campaign["clients"] if x["clientId"]==client)
    binding=core.interop_binding_digest(campaign["campaignId"],client,challenge["challengeSha256"])
    ep=campaign["endpoint"]; parsed=urlsplit(ep); base=f"{parsed.scheme}://{parsed.netloc}"
    request_meta={
      "io.modelcontextprotocol/protocolVersion":spec["protocol"],
      "io.modelcontextprotocol/clientInfo":{"name":core.CLIENT_SURFACES[client],"version":"external-c7w"},
      "io.modelcontextprotocol/clientCapabilities":{"tools":{}},
      "io.4so/interopCampaignId":campaign["campaignId"],
      "io.4so/interopClientId":client,
      "io.4so/interopChallengeSha256":challenge["challengeSha256"],
      "io.4so/sourceCommitSHA":campaign["sourceCommitSHA"],
      "io.4so/runtimeVersion":campaign["runtimeVersion"],
    }
    def mcp_request(method:str,credential_profile:str,*,tool:str|None=None,arguments:dict|None=None)->dict:
        if credential_profile not in credential_contract["profiles"]:
            raise RuntimeError("MCP_EXTERNAL_EXECUTION_PACKET_CREDENTIAL_PROFILE_INVALID")
        headers={
          "Content-Type":"application/json",
          "Accept":"application/json, text/event-stream",
          "MCP-Protocol-Version":spec["protocol"],
          "Mcp-Method":method,
          "Mcp-Interop-Binding":binding,
        }
        params={"_meta":request_meta}
        if tool is not None:
            headers["Mcp-Name"]=tool
            params["name"]=tool
            params["arguments"]=dict(arguments or {})
        return {
          "httpMethod":"POST","url":ep,"protocol":spec["protocol"],"transport":spec["transport"],
          "contentType":"application/json","credentialProfile":credential_profile,"headers":headers,
          "jsonRpc":{"jsonrpc":"2.0","id":"<unique-jsonrpc-id>","method":method,"params":params},
          "captureRequestIdFrom":["response-header:X-Request-ID","success-json:result._meta.io.4so/requestId"],
        }
    checks=[
      {"id":"oauth-protected-resource-discovery","request":{"httpMethod":"GET","url":base+"/.well-known/oauth-protected-resource","credentialProfile":"none","headers":{"Accept":"application/json"}},"expect":{"httpStatus":200,"resource":ep,"scopesContain":["mcp.read","mcp.operate"]},"serverAuditWitnessRequired":False},
      {"id":"dedicated-audience-validation","request":mcp_request("tools/list","valid-user-token-wrong-resource-audience"),"expect":{"httpStatus":401,"accepted":False},"serverAudit":{"category":"AUTHENTICATION","decision":"DENY","reasonCode":"OIDC_AUTHENTICATION_REJECTED"}},
      {"id":"authorization-filtered-tools-list","request":mcp_request("tools/list","campaign-delegated-user"),"expect":{"httpStatus":200,"toolListFilteredByDelegation":True,"sourceCommitSHA":campaign["sourceCommitSHA"],"runtimeVersion":campaign["runtimeVersion"]},"captureRuntimeIdentityFrom":{"sourceCommitSHA":"success-json:result._meta.io.modelcontextprotocol/serverInfo.sourceCommitSHA","runtimeVersion":"success-json:result._meta.io.modelcontextprotocol/serverInfo.version"},"serverAudit":{"category":"CAPABILITY_AUTHORIZATION","decision":"ALLOW","reasonCode":"CAPABILITY_AUTHORIZED"}},
      {"id":"project-resource-scope-negative-control","request":mcp_request("tools/call","project-scoped-delegation",tool="ops_search",arguments={"projectId":resources["foreignProjectId"],"query":"scope-negative-control"}),"expect":{"accepted":False,"foreignProjectDataReturned":False},"serverAudit":{"category":"SCOPE_AUTHORIZATION","decision":"DENY","reasonCode":"PROJECT_ACCESS_DENIED"}},
      {"id":"revoked-delegation-negative-control","request":mcp_request("tools/list","revoked-campaign-delegation"),"expect":{"accepted":False},"serverAudit":{"category":"DELEGATION_AUTHORIZATION","decision":"DENY","reasonCode":"MCP_DELEGATION_INACTIVE"}},
      {"id":"read-only-client-mutation-negative-control","request":mcp_request("tools/call","view-delegation",tool="operation_cancel",arguments={"id":resources["sameProjectOperationId"],"expectedRevision":1,"reason":"interop negative control"}),"expect":{"accepted":False,"mutationObserved":False},"serverAudit":{"category":"CAPABILITY_AUTHORIZATION","decision":"DENY","reasonCode":"CAPABILITY_PERMISSION_REQUIRED"}},
      {"id":"administration-approval-self-approval-negative-control","request":mcp_request("tools/call","administration-delegation-requester",tool="managed_okd_install_approve",arguments={"id":resources["selfApprovalRequestId"],"expectedRevision":1}),"expect":{"accepted":False,"selfApprovalObserved":False},"serverAudit":{"category":"APPROVAL_AUTHORIZATION","decision":"DENY","reasonCode":"SEPARATION_OF_DUTIES_REQUIRED"}},
    ]
    profiles={row["request"]["credentialProfile"] for row in checks}
    if profiles!=set(credential_contract["profiles"]):
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_PACKET_CREDENTIAL_PROFILE_SET_INVALID")
    return {
      "apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientExecutionPacket","authority":AUTHORITY,
      "matrixAuthority":core.MATRIX_AUTHORITY,"campaignAuthority":core.CAMPAIGN_AUTHORITY,
      "campaignId":campaign["campaignId"],"campaignCreatedAt":campaign["createdAt"],"campaignExpiresAt":campaign["expiresAt"],
      "executionAuditWindowSeconds":spec["executionAuditWindowSeconds"],"clientId":client,"clientSurface":core.CLIENT_SURFACES[client],
      "endpoint":ep,"sourceCommitSHA":campaign["sourceCommitSHA"],"runtimeVersion":campaign["runtimeVersion"],
      "protocol":spec["protocol"],"transport":spec["transport"],"challenge":challenge["challenge"],"challengeSha256":challenge["challengeSha256"],
      "oauthClientId":challenge["oauthClientId"],"interopBindingAuthority":core.INTEROP_BINDING_AUTHORITY,"interopBindingDigest":binding,
      "executionBindingAuthority":execution_bindings.AUTHORITY,"executionBindingsSha256":binding_sha,"executionBindings":resources,
      "credentialProfileContractAuthority":credential_contract["authority"],"credentialProfileContractSha256":credential_digest,
      "credentialProfileContract":credential_contract,
      "requestMeta":request_meta,"checks":checks,
      "receiptRequirements":{
        "authority":core.RECEIPT_AUTHORITY,"captureAuthority":"MCP_EXTERNAL_CLIENT_CAPTURE_V1",
        "finalizer":"python3 scripts/finalize_mcp_external_client_receipt.py --packet <packet.json> --capture <capture.json> --out <receipt.json>",
        "requestIds":list(core.AUDITED_CHECKS),"serverAuditWitnessAuthority":core.AUDIT_WITNESS_AUTHORITY,
        "interopBindingAuthority":core.INTEROP_BINDING_AUTHORITY,"oauthClientId":challenge["oauthClientId"],
        "oauthClientWitnessedChecks":list(core.OAUTH_CLIENT_AUDITED_CHECKS),
        "executionBindingAuthority":execution_bindings.AUTHORITY,"executionBindingsSha256":binding_sha,
        "credentialProfileContractAuthority":credential_contract["authority"],"credentialProfileContractSha256":credential_digest,
        "executedAtRequired":True,"observedRuntimeIdentityRequired":True,"structuredResponseObservationRequired":True,
        "allSevenChecksMustPass":True,"externalExecution":True,"credentialedExecution":True,
      },
      "secretsIncluded":False,"runtimeCertified":False,"physicalCertified":False,
    }

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--matrix",type=Path,default=Path("lab/mcp-external-client-interop-matrix.json")); p.add_argument("--campaign",type=Path,required=True); p.add_argument("--client",choices=core.CLIENTS,required=True); p.add_argument("--out",type=Path,required=True)
    a=p.parse_args(); out=packet(a.matrix,a.campaign,a.client); core.write_json_once_or_identical(a.out,out,"MCP_EXTERNAL_EXECUTION_PACKET"); print(json.dumps({"authority":AUTHORITY,"clientId":a.client,"campaignId":out["campaignId"]},sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
