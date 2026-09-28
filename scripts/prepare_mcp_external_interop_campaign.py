#!/usr/bin/env python3
"""Prepare a one-shot named-client MCP interoperability campaign.

Challenges are public non-secret nonces. Their purpose is replay fencing: an
external execution receipt is admissible only for the exact matrix, endpoint,
campaign and per-client challenge that were prepared for that run.
"""
from __future__ import annotations
import argparse, hashlib, json, secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROP_CAMPAIGN_V1"
MATRIX_AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROPERABILITY_MATRIX_V2"
CLIENTS=("chatgpt","claude","gemini","grok")


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


def prepare(matrix_path:Path, endpoint_url:str)->dict:
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
      "clients":rows,"externalExecutionRequired":True
    }


def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--matrix",type=Path,default=Path("lab/mcp-external-client-interop-matrix.json")); p.add_argument("--endpoint",required=True); p.add_argument("--out",type=Path,required=True)
    a=p.parse_args(); out=prepare(a.matrix,a.endpoint)
    a.out.parent.mkdir(parents=True,exist_ok=True); a.out.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"authority":AUTHORITY,"campaignId":out["campaignId"],"matrixSha256":out["matrixSha256"],"endpoint":out["endpoint"],"clients":[x["clientId"] for x in out["clients"]]},sort_keys=True))
    return 0
if __name__=="__main__": raise SystemExit(main())
