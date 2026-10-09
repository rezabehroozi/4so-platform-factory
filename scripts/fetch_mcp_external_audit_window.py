#!/usr/bin/env python3
"""Fetch the exact server audit window for one finalized C7W client receipt.

The bearer token is read only from an environment variable so it never appears
in argv. The output is written atomically only after the returned immutable
audit window passes the same chain validator used by the C7W sealer.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import ssl
import time
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

try:
    import seal_mcp_external_interop as core
except ModuleNotFoundError:
    from scripts import seal_mcp_external_interop as core
try:
    import c7w_execution_bindings as execution_bindings
except ModuleNotFoundError:
    from scripts import c7w_execution_bindings as execution_bindings

ROOT=Path(__file__).resolve().parents[1]


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def exact_https_opener(context):
    return build_opener(HTTPSHandler(context=context),RejectRedirects())

def error_code(raw: bytes) -> str:
    try:
        value=json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError,json.JSONDecodeError):
        return ""
    if not isinstance(value,dict):
        return ""
    err=value.get("error")
    if isinstance(err,dict):
        return str(err.get("code") or "")
    return str(value.get("code") or "")


def _verify_snapshot(raw:bytes,receipt:dict,client:str)->dict:
    fd,temp_name=tempfile.mkstemp(prefix=".4so-c7w-audit-verify.")
    temp=Path(temp_name)
    try:
        with os.fdopen(fd,"wb") as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        return core.verify_server_audit(temp,receipt,client)
    finally:
        if temp.exists():
            temp.unlink()


def _existing_witness(path: Path, raw: bytes, receipt: dict, client: str) -> dict:
    try:
        observed=core._stable_file_bytes(path,"MCP_EXTERNAL_AUDIT_EXISTING",max_bytes=4*1024*1024)
    except RuntimeError as exc:
        raise RuntimeError("MCP_EXTERNAL_AUDIT_OUTPUT_PATH_INVALID") from exc
    if observed!=raw:
        raise RuntimeError("MCP_EXTERNAL_AUDIT_OUTPUT_REPLACEMENT_FORBIDDEN")
    witness=_verify_snapshot(observed,receipt,client)
    try:
        rechecked=core._stable_file_bytes(path,"MCP_EXTERNAL_AUDIT_EXISTING",max_bytes=4*1024*1024)
    except RuntimeError as exc:
        raise RuntimeError("MCP_EXTERNAL_AUDIT_OUTPUT_REPLACEMENT_FORBIDDEN") from exc
    if rechecked!=observed:
        raise RuntimeError("MCP_EXTERNAL_AUDIT_OUTPUT_REPLACEMENT_FORBIDDEN")
    return witness

def atomic_write(path: Path, raw: bytes, receipt: dict, client: str) -> dict:
    try:
        value=json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError,json.JSONDecodeError) as exc:
        raise RuntimeError("MCP_EXTERNAL_AUDIT_OUTPUT_JSON_INVALID") from exc
    if core.canonical_json_bytes(value)!=raw:
        raise RuntimeError("MCP_EXTERNAL_AUDIT_OUTPUT_CANONICAL_INVALID")
    _verify_snapshot(raw,receipt,client)
    core.write_json_once_or_identical(path,value,"MCP_EXTERNAL_AUDIT")
    return _existing_witness(path,raw,receipt,client)


def fetch(matrix_path: Path, campaign_path: Path, receipt_path: Path, client: str, token_env: str, out: Path, attempts: int, interval: float) -> dict:
    client=str(client or "").strip().lower()
    if client not in core.CLIENTS:
        raise RuntimeError("MCP_EXTERNAL_AUDIT_CLIENT_INVALID")
    matrix=core.load(matrix_path,"MATRIX")
    spec=matrix.get("spec") if isinstance(matrix,dict) else None
    if matrix.get("authority")!=core.MATRIX_AUTHORITY or not isinstance(spec,dict):
        raise RuntimeError("MCP_EXTERNAL_AUDIT_MATRIX_INVALID")
    required=list(spec.get("sharedRequiredChecks") or [])
    if required!=list(core.REQUIRED_CHECKS):
        raise RuntimeError("MCP_EXTERNAL_AUDIT_MATRIX_CHECKS_INVALID")
    campaign=core.verify_campaign(campaign_path,matrix_path,spec)
    source_sha=str(campaign.get("sourceCommitSHA") or "").strip().lower()
    execution_bindings.source_commit_sha(ROOT,source_sha,require_freeze=True)
    receipt=core.verify_receipt(receipt_path,client,required,str(spec.get("protocol") or ""),campaign)
    endpoint=receipt["endpoint"]
    request_ids=receipt["requestIds"]

    token=str(os.environ.get(token_env) or "").strip()
    if not token or any(ord(ch)<0x21 or ord(ch)>0x7e for ch in token):
        raise RuntimeError(f"MCP_EXTERNAL_AUDIT_TOKEN_ENV_INVALID {token_env}")
    if attempts<1 or attempts>60 or interval<0 or interval>60:
        raise RuntimeError("MCP_EXTERNAL_AUDIT_RETRY_POLICY_INVALID")

    parsed=urlsplit(endpoint)
    base=f"{parsed.scheme}://{parsed.netloc}"
    query=urlencode([("requestId",request_ids[name]) for name in core.AUDITED_CHECKS])
    url=base+"/api/v1/security-audit-events?"+query
    context=ssl.create_default_context()
    opener=exact_https_opener(context)
    last=""

    for attempt in range(1,attempts+1):
        req=Request(
            url,
            headers={
                "Authorization":"Bearer "+token,
                "Accept":"application/json",
                "User-Agent":"4so-c7w-audit-fetch/1",
            },
            method="GET",
        )
        try:
            with opener.open(req,timeout=20) as response:
                if response.status!=200 or response.geturl()!=url:
                    raise RuntimeError(f"MCP_EXTERNAL_AUDIT_HTTP_ORIGIN_INVALID status={response.status}")
                body=response.read(4*1024*1024+1)
                if len(body)>4*1024*1024:
                    raise RuntimeError("MCP_EXTERNAL_AUDIT_RESPONSE_TOO_LARGE")
                try:
                    value=json.loads(body.decode("utf-8"))
                except (UnicodeDecodeError,json.JSONDecodeError) as exc:
                    raise RuntimeError("MCP_EXTERNAL_AUDIT_RESPONSE_JSON_INVALID") from exc
                if not isinstance(value,list) or not value:
                    raise RuntimeError("MCP_EXTERNAL_AUDIT_RESPONSE_INVALID")
                execution_bindings.source_commit_sha(ROOT,source_sha,require_freeze=True)
                canonical=(json.dumps(value,indent=2,sort_keys=True)+"\n").encode("utf-8")
                witness=atomic_write(out,canonical,receipt,client)
                execution_bindings.source_commit_sha(ROOT,source_sha,require_freeze=True)
                return {
                    "clientId":client,
                    "requestIdCount":len(request_ids),
                    "auditEventCount":len(value),
                    "auditExportSha256":witness["auditExportSha256"],
                    "auditHeadSequence":witness["auditHeadSequence"],
                    "auditHeadDigest":witness["auditHeadDigest"],
                    "interopBindingDigest":witness["interopBindingDigest"],
                    "output":str(out),
                }
        except HTTPError as exc:
            body=exc.read(1024*1024)
            code=error_code(body)
            last=f"http={exc.code} code={code or 'UNKNOWN'}"
            retryable=(exc.code==409 and code=="AUDIT_REQUEST_IDS_PENDING") or exc.code in (429,502,503,504)
            if not retryable:
                raise RuntimeError(f"MCP_EXTERNAL_AUDIT_FETCH_FAILED {last}") from exc
        except URLError as exc:
            last=f"network={exc.reason}"
        if attempt<attempts and interval:
            time.sleep(interval)

    raise RuntimeError(f"MCP_EXTERNAL_AUDIT_FETCH_RETRY_EXHAUSTED {last}")


def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--matrix",type=Path,default=Path("lab/mcp-external-client-interop-matrix.json"))
    p.add_argument("--campaign",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    p.add_argument("--client",choices=core.CLIENTS,required=True)
    p.add_argument("--token-env",default="C7W_PLATFORM_ADMIN_TOKEN")
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--attempts",type=int,default=15)
    p.add_argument("--interval-seconds",type=float,default=2.0)
    a=p.parse_args()
    result=fetch(a.matrix,a.campaign,a.receipt,a.client,a.token_env,a.out,a.attempts,a.interval_seconds)
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
