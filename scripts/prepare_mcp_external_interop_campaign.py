#!/usr/bin/env python3
"""Prepare a one-shot named-client MCP interoperability campaign.

Challenges are public non-secret nonces. Their purpose is replay fencing: an
external execution receipt is admissible only for the exact matrix, endpoint,
campaign and per-client challenge that were prepared for that run.
"""
from __future__ import annotations
import argparse, hashlib, json, secrets, ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import seal_mcp_external_interop as core

AUTHORITY=core.CAMPAIGN_AUTHORITY
MATRIX_AUTHORITY=core.MATRIX_AUTHORITY
CLIENTS=core.CLIENTS
PREFLIGHT_AUTHORITY=core.CAMPAIGN_PREFLIGHT_AUTHORITY


def file_sha(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return "sha256:"+h.hexdigest()


def endpoint(raw:str)->str:
    p=urlsplit(str(raw or "").strip())
    if p.scheme!="https" or not p.hostname or p.username or p.password or p.query or p.fragment or p.path!="/mcp":
        raise RuntimeError("MCP_EXTERNAL_ENDPOINT_INVALID")
    return p.geturl()


def live_preflight(endpoint_url:str)->dict:
    ep=endpoint(endpoint_url); parsed=urlsplit(ep); base=f"{parsed.scheme}://{parsed.netloc}"
    metadata_url=base+"/.well-known/oauth-protected-resource"
    context=ssl.create_default_context()
    req=Request(metadata_url,headers={"Accept":"application/json","User-Agent":"4so-c7w-campaign/1"},method="GET")
    try:
        with urlopen(req,timeout=20,context=context) as response:
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
        with urlopen(challenge,timeout=20,context=context) as response:
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


def prepare(matrix_path:Path, endpoint_url:str, preflight:dict)->dict:
    if matrix_path.is_symlink() or not matrix_path.is_file():
        raise RuntimeError("MCP_EXTERNAL_MATRIX_FILE_INVALID")
    matrix=json.loads(matrix_path.read_text(encoding="utf-8"))
    spec=matrix.get("spec") or {}
    if matrix.get("authority")!=MATRIX_AUTHORITY or spec.get("externalCertificationStatus")!="pending":
        raise RuntimeError("MCP_EXTERNAL_MATRIX_STATE_INVALID")
    ids=[x.get("id") for x in spec.get("clients") or [] if isinstance(x,dict)]
    if ids!=list(CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_MATRIX_CLIENT_SET_INVALID")
    campaign_id="mcp-interop-"+secrets.token_hex(16)
    rows=[]
    for client in CLIENTS:
        challenge=secrets.token_urlsafe(32)
        rows.append({"clientId":client,"challenge":challenge,"challengeSha256":"sha256:"+hashlib.sha256(challenge.encode()).hexdigest()})
    return {
      "apiVersion":"platform.4so.io/v1alpha1","kind":"MCPExternalClientInteropCampaign",
      "authority":AUTHORITY,"campaignId":campaign_id,"createdAt":datetime.now(timezone.utc).isoformat(),
      "matrixAuthority":MATRIX_AUTHORITY,"matrixSha256":file_sha(matrix_path),
      "endpoint":endpoint(endpoint_url),"protocol":spec.get("protocol"),"transport":spec.get("transport"),
      "livePreflight":preflight,"clients":rows,"externalExecutionRequired":True
    }


def resume_existing(matrix_path:Path,endpoint_url:str,out_path:Path)->dict:
    matrix=core.load(matrix_path,"MATRIX"); spec=matrix.get("spec") or {}
    existing=core.verify_campaign(out_path,matrix_path,spec)
    if existing.get("endpoint")!=endpoint(endpoint_url):
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_RESUME_ENDPOINT_DRIFT")
    return existing

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--matrix",type=Path,default=Path("lab/mcp-external-client-interop-matrix.json")); p.add_argument("--endpoint",required=True); p.add_argument("--out",type=Path,required=True)
    a=p.parse_args(); resumed=False
    if a.out.exists() or a.out.is_symlink():
        out=resume_existing(a.matrix,a.endpoint,a.out); resumed=True
    else:
        preflight=live_preflight(a.endpoint); out=prepare(a.matrix,a.endpoint,preflight)
        core.write_json_once_or_identical(a.out,out,"MCP_EXTERNAL_CAMPAIGN")
    print(json.dumps({"authority":AUTHORITY,"campaignId":out["campaignId"],"matrixSha256":out["matrixSha256"],"endpoint":out["endpoint"],"clients":[x["clientId"] for x in out["clients"]],"resumed":resumed},sort_keys=True))
    return 0
if __name__=="__main__": raise SystemExit(main())
