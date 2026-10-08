#!/usr/bin/env python3
"""Idempotently reconcile the four C7W Product trusted-client registrations.

This helper is intentionally narrow: it can create a missing ACTIVE trusted-client
registration for an already-provisioned OAuth client ID, but it never revokes,
rewrites, rotates, or guesses an existing ACTIVE authority row. Conflicts fail
closed and require an operator decision.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request

try:
    import prepare_mcp_external_interop_campaign as campaign
    import seal_mcp_external_interop as core
except ModuleNotFoundError:
    from scripts import prepare_mcp_external_interop_campaign as campaign
    from scripts import seal_mcp_external_interop as core

AUTHORITY="MCP_EXTERNAL_TRUSTED_CLIENT_RECONCILIATION_V1"
CLIENTS=core.CLIENTS
DISPLAY_NAMES={
    "chatgpt":"C7W ChatGPT",
    "claude":"C7W Claude",
    "gemini":"C7W Gemini",
    "grok":"C7W Grok",
}


def _clean_git_env()->dict[str,str]:
    env=os.environ.copy()
    for key in list(env):
        if key.startswith("GIT_"):
            env.pop(key,None)
    return env


def require_repository_root(root:Path)->Path:
    candidate=Path(os.path.abspath(root))
    try:
        proc=subprocess.run(
            ["git","rev-parse","--show-toplevel"],
            cwd=candidate,
            env=_clean_git_env(),
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_REPOSITORY_ROOT_INVALID") from exc
    top=Path(proc.stdout.strip()).resolve() if proc.returncode==0 and proc.stdout.strip() else None
    if proc.returncode!=0 or top is None or candidate.resolve()!=top:
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_REPOSITORY_ROOT_INVALID")
    return top


def require_source_freeze(root:Path)->Path:
    root=require_repository_root(root)
    git_env=_clean_git_env()
    branch=subprocess.run(
        ["git","symbolic-ref","--quiet","--short","HEAD"],
        cwd=root,
        env=git_env,
        text=True,
        capture_output=True,
        check=False,
    )
    if branch.returncode!=0 or branch.stdout.strip()!="main":
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_BRANCH_NOT_MAIN")
    indexed=subprocess.run(
        ["git","ls-files","-v","-z"],
        cwd=root,
        env=git_env,
        capture_output=True,
        check=False,
    )
    if indexed.returncode!=0 or any(raw and not raw.startswith(b"H ") for raw in indexed.stdout.split(b"\x00")):
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_GIT_INDEX_FLAGS_FORBIDDEN")
    allowed=sorted(core.C7W_EVIDENCE_ONLY_PATHS)
    command=["git","status","--porcelain=v1","-z","--untracked-files=all"]
    all_status=subprocess.run(command,cwd=root,env=git_env,capture_output=True,check=False)
    allowed_status=subprocess.run(command+["--",*allowed],cwd=root,env=git_env,capture_output=True,check=False)
    if all_status.returncode!=0 or allowed_status.returncode!=0:
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_GIT_STATUS_UNAVAILABLE")
    all_records={row for row in all_status.stdout.split(b"\x00") if row}
    allowed_records={row for row in allowed_status.stdout.split(b"\x00") if row}
    if all_records-allowed_records:
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_SOURCE_NOT_FROZEN")
    return root


def _token(token_env:str)->str:
    name=str(token_env or "").strip()
    value=str(os.getenv(name) or "").strip() if name else ""
    if not value or any(ch in value for ch in "\r\n"):
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_TOKEN_UNAVAILABLE")
    return value


def _registry_url(endpoint_url:str)->str:
    ep=campaign.endpoint(endpoint_url)
    parsed=urlsplit(ep)
    return f"{parsed.scheme}://{parsed.netloc}/api/v1/mcp/trusted-clients"


def _json_response(response,expected_url:str,label:str,max_bytes:int=2*1024*1024):
    if response.geturl()!=expected_url:
        raise RuntimeError(f"{label}_REDIRECT_FORBIDDEN")
    raw=response.read(max_bytes+1)
    if len(raw)>max_bytes:
        raise RuntimeError(f"{label}_TOO_LARGE")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError,json.JSONDecodeError) as exc:
        raise RuntimeError(f"{label}_JSON_INVALID") from exc


def _private_oauth_map(root:Path,path:Path)->Path:
    root=Path(os.path.abspath(root))
    boundary=Path(os.path.abspath(root/".state"/"private"))
    raw=Path(path)
    absolute=Path(os.path.abspath(raw if raw.is_absolute() else root/raw))
    try:
        absolute.relative_to(boundary)
    except ValueError as exc:
        raise RuntimeError("MCP_EXTERNAL_PRIVATE_INPUT_PATH_INVALID") from exc
    for candidate in (absolute,*absolute.parents):
        if candidate==root:
            break
        if candidate.is_symlink():
            raise RuntimeError("MCP_EXTERNAL_PRIVATE_INPUT_PATH_INVALID")
    if absolute.is_symlink() or not absolute.is_file():
        raise RuntimeError("MCP_EXTERNAL_PRIVATE_INPUT_PATH_INVALID")
    return absolute


def fetch_rows(endpoint_url:str,token_env:str)->list[dict]:
    url=_registry_url(endpoint_url)
    req=Request(
        url,
        headers={
            "Accept":"application/json",
            "Authorization":"Bearer "+_token(token_env),
            "User-Agent":"4so-c7w-trusted-client-reconcile/1",
        },
        method="GET",
    )
    opener=campaign.exact_https_opener(ssl.create_default_context())
    try:
        with opener.open(req,timeout=20) as response:
            if response.status!=200 or response.geturl()!=url:
                raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_LIST_HTTP_INVALID")
            value=_json_response(response,url,"MCP_EXTERNAL_TRUSTED_CLIENT_LIST")
    except HTTPError as exc:
        raise RuntimeError(f"MCP_EXTERNAL_TRUSTED_CLIENT_LIST_HTTP_INVALID status={exc.code}") from exc
    except URLError as exc:
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_LIST_UNAVAILABLE") from exc
    if not isinstance(value,list) or any(not isinstance(row,dict) for row in value):
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_LIST_CONTRACT_INVALID")
    return value


def create_row(endpoint_url:str,row:dict,token_env:str)->dict:
    url=_registry_url(endpoint_url)
    body=json.dumps(row,separators=(",",":"),sort_keys=True).encode("utf-8")
    req=Request(
        url,
        data=body,
        headers={
            "Accept":"application/json",
            "Content-Type":"application/json",
            "Authorization":"Bearer "+_token(token_env),
            "User-Agent":"4so-c7w-trusted-client-reconcile/1",
        },
        method="POST",
    )
    opener=campaign.exact_https_opener(ssl.create_default_context())
    try:
        with opener.open(req,timeout=20) as response:
            if response.status!=201 or response.geturl()!=url:
                raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_CREATE_HTTP_INVALID")
            value=_json_response(response,url,"MCP_EXTERNAL_TRUSTED_CLIENT_CREATE",max_bytes=256*1024)
    except HTTPError as exc:
        raise RuntimeError(f"MCP_EXTERNAL_TRUSTED_CLIENT_CREATE_HTTP_INVALID status={exc.code}") from exc
    except URLError as exc:
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_CREATE_UNAVAILABLE") from exc
    if not isinstance(value,dict):
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_CREATE_CONTRACT_INVALID")
    return value


def reconcile_plan(rows:list[dict],bindings:dict[str,str])->dict:
    if not isinstance(rows,list) or any(not isinstance(row,dict) for row in rows):
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_LIST_CONTRACT_INVALID")
    if not isinstance(bindings,dict) or set(bindings)!=set(CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_CLIENT_SET_INVALID")

    create=[]; ready=[]
    active_rows=[row for row in rows if str(row.get("state") or "").strip().upper()=="ACTIVE"]
    for client in CLIENTS:
        wanted=str(bindings.get(client) or "").strip()
        if not wanted:
            raise RuntimeError(f"MCP_EXTERNAL_OAUTH_BINDINGS_CLIENT_ID_INVALID {client}")

        exact=[row for row in active_rows if str(row.get("clientId") or "").strip()==wanted]
        provider_active=[row for row in active_rows if str(row.get("provider") or "").strip().lower()==client]
        if len(exact)>1 or len(provider_active)>1:
            raise RuntimeError(f"MCP_EXTERNAL_TRUSTED_CLIENT_CONFLICT {client}")
        if exact:
            row=exact[0]
            provider=str(row.get("provider") or "").strip().lower()
            trusted_id=str(row.get("id") or "").strip()
            revision=row.get("revision")
            if provider!=client or not trusted_id or type(revision) is not int or revision<=0:
                raise RuntimeError(f"MCP_EXTERNAL_TRUSTED_CLIENT_CONFLICT {client}")
            if provider_active and str(provider_active[0].get("clientId") or "").strip()!=wanted:
                raise RuntimeError(f"MCP_EXTERNAL_TRUSTED_CLIENT_CONFLICT {client}")
            ready.append(client)
            continue
        if provider_active:
            raise RuntimeError(f"MCP_EXTERNAL_TRUSTED_CLIENT_CONFLICT {client}")
        create.append({
            "clientId":wanted,
            "displayName":DISPLAY_NAMES[client],
            "provider":client,
            "redirectUris":[],
        })
    return {"create":create,"ready":ready}


def preflight_command(root_or_endpoint,endpoint_or_map,oauth_or_token,token_env=None)->list[str]:
    # Backward-compatible three-argument API plus root-bound four-argument API.
    if token_env is None:
        root=Path(".")
        endpoint_url=str(root_or_endpoint)
        oauth_client_map=Path(endpoint_or_map)
        token_name=str(oauth_or_token)
    else:
        root=Path(root_or_endpoint).resolve()
        endpoint_url=str(endpoint_or_map)
        oauth_client_map=Path(oauth_or_token)
        token_name=str(token_env)
    return [
        sys.executable,
        "scripts/c7w_preflight.py",
        "--root",
        str(root),
        "--endpoint",
        endpoint_url,
        "--oauth-client-map",
        str(oauth_client_map),
        "--token-env",
        token_name,
    ]


def reconcile(endpoint_url:str,bindings:dict[str,str],token_env:str)->dict:
    before=fetch_rows(endpoint_url,token_env)
    plan=reconcile_plan(before,bindings)
    created=[]
    for row in plan["create"]:
        try:
            created_row=create_row(endpoint_url,row,token_env)
        except RuntimeError as exc:
            if "status=409" not in str(exc):
                raise
            continue
        created.append(str(created_row.get("provider") or row["provider"]).strip().lower())

    after=fetch_rows(endpoint_url,token_env)
    final=reconcile_plan(after,bindings)
    if final["create"] or set(final["ready"])!=set(CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_RECONCILIATION_INCOMPLETE")

    return {
        "authority":AUTHORITY,
        "trustedClientCount":len(CLIENTS),
        "createdProviders":created,
        "readyProviders":list(CLIENTS),
        "nextActionCode":"RUN_C7W_PREFLIGHT",
        "nextCommand":[],
        "physicalCertified":False,
    }


def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,default=Path("."))
    parser.add_argument("--endpoint",default=os.environ.get("C7W_MCP_ENDPOINT",""),required=False)
    raw_map=os.environ.get("C7W_OAUTH_CLIENT_MAP","").strip()
    parser.add_argument("--oauth-client-map",type=Path,default=Path(raw_map) if raw_map else None)
    parser.add_argument("--token-env",default=os.environ.get("C7W_PLATFORM_ADMIN_TOKEN_ENV","C7W_PLATFORM_ADMIN_TOKEN"))
    args=parser.parse_args()
    if not str(args.endpoint or "").strip() or args.oauth_client_map is None:
        raise RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_RECONCILIATION_INPUTS_MISSING")
    root=require_source_freeze(args.root)
    oauth_path=_private_oauth_map(root,args.oauth_client_map)
    bindings,_=campaign.load_oauth_bindings(oauth_path)
    result=reconcile(args.endpoint,bindings,args.token_env)
    result["workingDirectory"]=str(root)
    result["oauthClientMapPath"]=str(oauth_path)
    result["nextCommand"]=preflight_command(root,args.endpoint,oauth_path,args.token_env)
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
