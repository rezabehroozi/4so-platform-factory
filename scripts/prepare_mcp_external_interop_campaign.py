#!/usr/bin/env python3
"""Prepare a one-shot named-client MCP interoperability campaign.

Challenges are public non-secret nonces. Their purpose is replay fencing: an
external execution receipt is admissible only for the exact matrix, endpoint,
campaign and per-client challenge that were prepared for that run.
"""
from __future__ import annotations
import argparse, hashlib, json, os, secrets, ssl, subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
import seal_mcp_external_interop as core

AUTHORITY=core.CAMPAIGN_AUTHORITY
MATRIX_AUTHORITY=core.MATRIX_AUTHORITY
CLIENTS=core.CLIENTS
PREFLIGHT_AUTHORITY=core.CAMPAIGN_PREFLIGHT_AUTHORITY
OAUTH_BINDING_AUTHORITY=core.OAUTH_BINDING_AUTHORITY
ROOT=Path(__file__).resolve().parents[1]


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def exact_https_opener(context):
    return build_opener(HTTPSHandler(context=context),RejectRedirects())

def file_sha(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return "sha256:"+h.hexdigest()


def source_commit_sha(explicit:str="")->str:
    value=str(explicit or "").strip().lower()
    if value and not core.COMMIT.fullmatch(value):
        raise RuntimeError("MCP_EXTERNAL_SOURCE_COMMIT_UNAVAILABLE")
    proc=subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,text=True,capture_output=True,check=False)
    observed=proc.stdout.strip().lower() if proc.returncode==0 else ""
    if core.COMMIT.fullmatch(observed):
        if value and value!=observed:
            raise RuntimeError("MCP_EXTERNAL_SOURCE_COMMIT_OVERRIDE_MISMATCH")
        return observed
    if value:
        return value
    raise RuntimeError("MCP_EXTERNAL_SOURCE_COMMIT_UNAVAILABLE")


def runtime_identity_readback(endpoint_url:str,token_env:str,expected_source_sha:str)->dict:
    token_env=str(token_env or "").strip()
    token=str(os.getenv(token_env) or "").strip() if token_env else ""
    if not token or any(ch in token for ch in "\r\n"):
        raise RuntimeError("MCP_EXTERNAL_RUNTIME_IDENTITY_TOKEN_UNAVAILABLE")
    ep=endpoint(endpoint_url); parsed=urlsplit(ep); url=f"{parsed.scheme}://{parsed.netloc}/api/v1/version"
    opener=exact_https_opener(ssl.create_default_context())
    req=Request(url,headers={"Accept":"application/json","Authorization":"Bearer "+token,"User-Agent":"4so-c7w-campaign/1"},method="GET")
    try:
        with opener.open(req,timeout=20) as response:
            if response.status!=200 or response.geturl()!=url:
                raise RuntimeError("MCP_EXTERNAL_RUNTIME_IDENTITY_HTTP_INVALID")
            raw=response.read(64*1024+1)
    except (HTTPError,URLError) as exc:
        raise RuntimeError("MCP_EXTERNAL_RUNTIME_IDENTITY_UNAVAILABLE") from exc
    if len(raw)>64*1024:
        raise RuntimeError("MCP_EXTERNAL_RUNTIME_IDENTITY_TOO_LARGE")
    try:
        value=json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError,json.JSONDecodeError) as exc:
        raise RuntimeError("MCP_EXTERNAL_RUNTIME_IDENTITY_JSON_INVALID") from exc
    version=str(value.get("version") or "").strip() if isinstance(value,dict) else ""
    observed=str(value.get("sourceCommitSHA") or "").strip().lower() if isinstance(value,dict) else ""
    if not isinstance(value,dict) or value.get("product")!="4SO Platform Factory" or not version or len(version)>128 or not core.COMMIT.fullmatch(observed):
        raise RuntimeError("MCP_EXTERNAL_RUNTIME_IDENTITY_CONTRACT_INVALID")
    if observed!=expected_source_sha:
        raise RuntimeError(f"MCP_EXTERNAL_RUNTIME_SOURCE_DRIFT expected={expected_source_sha} observed={observed}")
    return {"authority":"MCP_EXTERNAL_RUNTIME_SOURCE_IDENTITY_V1","product":"4SO Platform Factory","version":version,"sourceCommitSHA":observed}


def endpoint(raw:str)->str:
    p=urlsplit(str(raw or "").strip())
    if p.scheme!="https" or not p.hostname or p.username or p.password or p.query or p.fragment or p.path!="/mcp":
        raise RuntimeError("MCP_EXTERNAL_ENDPOINT_INVALID")
    return p.geturl()


def load_oauth_bindings(path:Path)->tuple[dict[str,str],str]:
    try:
        value,digest=core.load_with_sha256(path,"MCP_EXTERNAL_OAUTH_BINDINGS",max_bytes=64*1024)
    except RuntimeError as exc:
        code=str(exc)
        if "JSON_INVALID" in code:
            raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_JSON_INVALID") from exc
        raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_FILE_INVALID") from exc
    if not isinstance(value,dict) or set(value)!={"authority","clients"} or value.get("authority")!=OAUTH_BINDING_AUTHORITY:
        raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_AUTHORITY_INVALID")
    clients=value.get("clients")
    if not isinstance(clients,dict) or set(clients)!=set(CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_CLIENT_SET_INVALID")
    out={}
    for client in CLIENTS:
        client_id=str(clients.get(client) or "").strip()
        if not client_id or len(client_id.encode("utf-8"))>512 or any(ch in client_id for ch in "\r\n\t"):
            raise RuntimeError(f"MCP_EXTERNAL_OAUTH_BINDINGS_CLIENT_ID_INVALID {client}")
        out[client]=client_id
    if len(set(out.values()))!=len(CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_CLIENT_ID_REUSE")
    return out,digest

def trusted_client_readback(endpoint_url:str,bindings:dict[str,str],token_env:str)->dict[str,dict]:
    token_env=str(token_env or "").strip()
    token=str(os.getenv(token_env) or "").strip() if token_env else ""
    if not token or any(ch in token for ch in "\r\n"):
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_TOKEN_UNAVAILABLE")
    ep=endpoint(endpoint_url); parsed=urlsplit(ep); url=f"{parsed.scheme}://{parsed.netloc}/api/v1/mcp/trusted-clients"
    opener=exact_https_opener(ssl.create_default_context())
    req=Request(url,headers={"Accept":"application/json","Authorization":"Bearer "+token,"User-Agent":"4so-c7w-campaign/1"},method="GET")
    try:
        with opener.open(req,timeout=20) as response:
            if response.status!=200 or response.geturl()!=url:
                raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_READBACK_HTTP_INVALID")
            raw=response.read(2*1024*1024+1)
    except (HTTPError,URLError) as exc:
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_READBACK_UNAVAILABLE") from exc
    if len(raw)>2*1024*1024:
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_READBACK_TOO_LARGE")
    try:
        rows=json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError,json.JSONDecodeError) as exc:
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_READBACK_JSON_INVALID") from exc
    if not isinstance(rows,list):
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_READBACK_CONTRACT_INVALID")
    resolved={}
    for client in CLIENTS:
        wanted=bindings[client]
        matches=[row for row in rows if isinstance(row,dict) and str(row.get("clientId") or "").strip()==wanted]
        if len(matches)!=1:
            raise RuntimeError(f"MCP_EXTERNAL_TRUSTED_CLIENT_READBACK_IDENTITY_INVALID {client}")
        row=matches[0]
        trusted_id=str(row.get("id") or "").strip(); revision=row.get("revision")
        if row.get("state")!="ACTIVE" or str(row.get("provider") or "").strip().lower()!=client or not trusted_id or type(revision) is not int or revision<=0:
            raise RuntimeError(f"MCP_EXTERNAL_TRUSTED_CLIENT_READBACK_IDENTITY_INVALID {client}")
        resolved[client]={"oauthClientId":wanted,"trustedClientId":trusted_id,"trustedClientRevision":revision,"trustedClientProvider":client}
    return resolved

def live_preflight(endpoint_url:str)->dict:
    ep=endpoint(endpoint_url); parsed=urlsplit(ep); base=f"{parsed.scheme}://{parsed.netloc}"
    metadata_url=base+"/.well-known/oauth-protected-resource"
    context=ssl.create_default_context()
    opener=exact_https_opener(context)
    req=Request(metadata_url,headers={"Accept":"application/json","User-Agent":"4so-c7w-campaign/1"},method="GET")
    try:
        with opener.open(req,timeout=20) as response:
            if response.status!=200 or response.geturl()!=metadata_url:
                raise RuntimeError("MCP_EXTERNAL_PREFLIGHT_METADATA_HTTP_INVALID")
            raw=response.read(1024*1024+1)
    except (HTTPError,URLError) as exc:
        raise RuntimeError("MCP_EXTERNAL_PREFLIGHT_METADATA_UNAVAILABLE") from exc
    if len(raw)>1024*1024:
        raise RuntimeError("MCP_EXTERNAL_PREFLIGHT_METADATA_TOO_LARGE")
    try:
        metadata=json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError,json.JSONDecodeError) as exc:
        raise RuntimeError("MCP_EXTERNAL_PREFLIGHT_METADATA_JSON_INVALID") from exc
    if not isinstance(metadata,dict):
        raise RuntimeError("MCP_EXTERNAL_PREFLIGHT_METADATA_CONTRACT_INVALID")
    servers=metadata.get("authorization_servers")
    scopes=metadata.get("scopes_supported")
    def valid_server(value:object)->bool:
        parsed_server=urlsplit(str(value or "").strip())
        return parsed_server.scheme=="https" and bool(parsed_server.hostname) and not parsed_server.username and not parsed_server.password and not parsed_server.query and not parsed_server.fragment
    if metadata.get("resource")!=ep or not isinstance(servers,list) or not servers or any(not valid_server(x) for x in servers) or not isinstance(scopes,list) or not {"mcp.read","mcp.operate"}.issubset(set(scopes)):
        raise RuntimeError("MCP_EXTERNAL_PREFLIGHT_METADATA_CONTRACT_INVALID")

    body=json.dumps({"jsonrpc":"2.0","id":"c7w-preflight","method":"tools/list","params":{"_meta":{}}},separators=(",",":")).encode("utf-8")
    challenge=Request(ep,data=body,headers={"Content-Type":"application/json","Accept":"application/json","MCP-Protocol-Version":"2026-07-28","User-Agent":"4so-c7w-campaign/1"},method="POST")
    try:
        with opener.open(challenge,timeout=20) as response:
            raise RuntimeError(f"MCP_EXTERNAL_PREFLIGHT_UNAUTHENTICATED_ACCEPTED status={response.status}")
    except HTTPError as exc:
        if exc.code!=401:
            raise RuntimeError(f"MCP_EXTERNAL_PREFLIGHT_CHALLENGE_STATUS_INVALID {exc.code}") from exc
        auth=str(exc.headers.get("WWW-Authenticate") or "")
        expected=f'Bearer resource_metadata="{metadata_url}"'
        if auth!=expected:
            raise RuntimeError("MCP_EXTERNAL_PREFLIGHT_CHALLENGE_INVALID") from exc
    except URLError as exc:
        raise RuntimeError("MCP_EXTERNAL_PREFLIGHT_CHALLENGE_UNAVAILABLE") from exc

    return {"authority":PREFLIGHT_AUTHORITY,"endpoint":ep,"protectedResourceMetadata":metadata_url,"resource":ep,"authorizationServers":[str(x) for x in servers],"scopes":["mcp.read","mcp.operate"],"unauthenticatedStatus":401,"challenge":expected,"protocol":"2026-07-28"}


def prepare(matrix_path:Path, endpoint_url:str, preflight:dict, oauth_binding_sha256:str, trusted_clients:dict[str,dict], runtime_identity:dict)->dict:
    if matrix_path.is_symlink() or not matrix_path.is_file():
        raise RuntimeError("MCP_EXTERNAL_MATRIX_FILE_INVALID")
    matrix,matrix_sha256=core.load_with_sha256(matrix_path,"MATRIX")
    spec=core.validate_matrix_contract(matrix,"MCP_EXTERNAL_MATRIX")
    if not core.SHA.fullmatch(str(oauth_binding_sha256 or "")) or not isinstance(trusted_clients,dict) or set(trusted_clients)!=set(CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_READBACK_INVALID")
    source_sha=str((runtime_identity or {}).get("sourceCommitSHA") or "").strip().lower()
    runtime_version=str((runtime_identity or {}).get("version") or "").strip()
    if (runtime_identity or {}).get("authority")!="MCP_EXTERNAL_RUNTIME_SOURCE_IDENTITY_V1" or (runtime_identity or {}).get("product")!="4SO Platform Factory" or not core.COMMIT.fullmatch(source_sha) or not runtime_version:
        raise RuntimeError("MCP_EXTERNAL_RUNTIME_IDENTITY_INVALID")
    max_age=spec.get("campaignMaxAgeSeconds")
    audit_window=spec.get("executionAuditWindowSeconds")
    if type(max_age) is not int or max_age<3600 or max_age>14*24*3600:
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_TTL_INVALID")
    if type(audit_window) is not int or audit_window<60 or audit_window>24*3600 or audit_window>max_age:
        raise RuntimeError("MCP_EXTERNAL_AUDIT_WINDOW_INVALID")
    created=datetime.now(timezone.utc)
    expires=created+timedelta(seconds=max_age)
    campaign_id="mcp-interop-"+secrets.token_hex(16)
    rows=[]
    for client in CLIENTS:
        trusted=trusted_clients[client]
        challenge=secrets.token_urlsafe(32)
        rows.append({"clientId":client,"challenge":challenge,"challengeSha256":"sha256:"+hashlib.sha256(challenge.encode()).hexdigest(),
                     "oauthClientId":trusted["oauthClientId"],"trustedClientId":trusted["trustedClientId"],
                     "trustedClientRevision":trusted["trustedClientRevision"],"trustedClientProvider":trusted["trustedClientProvider"]})
    return {
      "apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropCampaign",
      "authority":AUTHORITY,"campaignId":campaign_id,
      "createdAt":core.utc_timestamp(created),"expiresAt":core.utc_timestamp(expires),
      "matrixAuthority":MATRIX_AUTHORITY,"matrixSha256":matrix_sha256,
      "oauthClientBindingAuthority":OAUTH_BINDING_AUTHORITY,"oauthClientBindingsSha256":oauth_binding_sha256,
      "sourceCommitSHA":source_sha,"runtimeVersion":runtime_version,
      "endpoint":endpoint(endpoint_url),"protocol":spec.get("protocol"),"transport":spec.get("transport"),
      "livePreflight":preflight,"clients":rows,"externalExecutionRequired":True
    }


def resume_existing(matrix_path:Path,endpoint_url:str,out_path:Path,source_sha:str)->dict:
    matrix=core.load(matrix_path,"MATRIX"); spec=matrix.get("spec") or {}
    existing=core.verify_campaign(out_path,matrix_path,spec)
    if existing.get("endpoint")!=endpoint(endpoint_url):
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_RESUME_ENDPOINT_DRIFT")
    try:
        core.validate_evidence_only_source_lineage(ROOT,existing.get("sourceCommitSHA"),source_sha,"MCP_EXTERNAL_CAMPAIGN_RESUME")
    except RuntimeError as exc:
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_RESUME_SOURCE_DRIFT") from exc
    return existing

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--matrix",type=Path,default=Path("lab/mcp-external-client-interop-matrix.json")); p.add_argument("--endpoint",required=True); p.add_argument("--out",type=Path,required=True)
    p.add_argument("--oauth-client-map",type=Path); p.add_argument("--registry-token-env",default="C7W_PLATFORM_ADMIN_TOKEN"); p.add_argument("--source-commit-sha",default="")
    a=p.parse_args(); resumed=False; source_sha=source_commit_sha(a.source_commit_sha)
    matrix=core.load(a.matrix,"MATRIX")
    core.validate_matrix_contract(matrix,"MCP_EXTERNAL_MATRIX")
    if a.out.exists() or a.out.is_symlink():
        out=resume_existing(a.matrix,a.endpoint,a.out,source_sha); resumed=True
    else:
        if a.oauth_client_map is None:
            raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_REQUIRED")
        bindings,binding_sha=load_oauth_bindings(a.oauth_client_map)
        runtime_identity=runtime_identity_readback(a.endpoint,a.registry_token_env,source_sha)
        trusted=trusted_client_readback(a.endpoint,bindings,a.registry_token_env)
        preflight=live_preflight(a.endpoint); out=prepare(a.matrix,a.endpoint,preflight,binding_sha,trusted,runtime_identity)
        core.write_json_once_or_identical(a.out,out,"MCP_EXTERNAL_CAMPAIGN")
    print(json.dumps({"authority":AUTHORITY,"campaignId":out["campaignId"],"matrixSha256":out["matrixSha256"],"sourceCommitSHA":out["sourceCommitSHA"],"runtimeVersion":out["runtimeVersion"],"endpoint":out["endpoint"],"clients":[x["clientId"] for x in out["clients"]],"resumed":resumed},sort_keys=True))
    return 0
if __name__=="__main__": raise SystemExit(main())
