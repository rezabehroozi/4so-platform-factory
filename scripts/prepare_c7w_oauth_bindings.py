#!/usr/bin/env python3
"""Materialize the private four-client OAuth binding input for C7W.

This helper never registers clients and never stores tokens or client secrets. It
only converts four already-provisioned OAuth client IDs into the canonical
private binding document consumed by C7W preflight.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path

try:
    import seal_mcp_external_interop as core
    import prepare_mcp_external_interop_campaign as campaign
except ModuleNotFoundError:
    from scripts import seal_mcp_external_interop as core
    from scripts import prepare_mcp_external_interop_campaign as campaign

AUTHORITY=core.OAUTH_BINDING_AUTHORITY
CLIENTS=core.CLIENTS
DEFAULT_OUTPUT=Path(".state/private/c7w-oauth-client-bindings.json")
ENV_IDS={client:f"C7W_{client.upper()}_OAUTH_CLIENT_ID" for client in CLIENTS}


def _root_for_output(output:Path,root:Path|None)->Path:
    absolute=Path(os.path.abspath(output))
    if root is not None:
        repo=Path(os.path.abspath(root))
    else:
        parts=absolute.parts
        try:
            index=max(i for i in range(len(parts)-1) if parts[i:i+2]==(".state","private"))
        except ValueError as exc:
            raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_OUTPUT_PATH_INVALID") from exc
        repo=Path(*parts[:index]) if index else Path(absolute.anchor)
    boundary=Path(os.path.abspath(repo/".state"/"private"))
    try:
        absolute.relative_to(boundary)
    except ValueError as exc:
        raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_OUTPUT_PATH_INVALID") from exc
    return repo


def _validate_clients(clients:dict[str,str])->dict[str,str]:
    if not isinstance(clients,dict) or set(clients)!=set(CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_CLIENT_SET_INVALID")
    normalized={}
    for client in CLIENTS:
        value=str(clients.get(client) or "").strip()
        if not value or len(value.encode("utf-8"))>512 or any(ch in value for ch in "\r\n\t"):
            raise RuntimeError(f"MCP_EXTERNAL_OAUTH_BINDINGS_CLIENT_ID_INVALID {client}")
        normalized[client]=value
    if len(set(normalized.values()))!=len(CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_CLIENT_ID_REUSE")
    return normalized


def _ensure_private_directory(root:Path,relative:Path)->Path:
    current=root
    for part in relative.parts:
        current=current/part
        if current.exists() or current.is_symlink():
            if current.is_symlink() or not current.is_dir():
                raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_OUTPUT_PATH_INVALID")
        else:
            current.mkdir(mode=0o700)
        if os.name!="nt":
            current.chmod(0o700)
    return current


def _safe_private_parent(output:Path,root:Path)->None:
    boundary=_ensure_private_directory(root,Path(".state/private"))
    try:
        relative=output.parent.relative_to(boundary)
    except ValueError as exc:
        raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_OUTPUT_PATH_INVALID") from exc
    parent=_ensure_private_directory(boundary,relative)
    if parent.is_symlink() or not parent.is_dir():
        raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_OUTPUT_PATH_INVALID")


def _existing_bytes(output:Path)->bytes|None:
    if not output.exists() and not output.is_symlink():
        return None
    if output.is_symlink():
        raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_OUTPUT_CONFLICT")
    info=output.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_size<=0
        or info.st_size>64*1024
        or (os.name!="nt" and stat.S_IMODE(info.st_mode)&0o077)
    ):
        raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_OUTPUT_CONFLICT")
    return output.read_bytes()


def materialize(output:Path,clients:dict[str,str],*,root:Path|None=None)->dict:
    output=Path(os.path.abspath(output))
    repo=_root_for_output(output,root)
    _safe_private_parent(output,repo)
    normalized=_validate_clients(clients)
    document={"authority":AUTHORITY,"clients":normalized}
    raw=(json.dumps(document,sort_keys=True,separators=(",",":"))+"\n").encode("utf-8")
    existing=_existing_bytes(output)
    if existing is not None:
        if existing!=raw:
            raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_OUTPUT_CONFLICT")
    else:
        fd,temp_name=tempfile.mkstemp(prefix="."+output.name+".tmp.",dir=output.parent)
        temp=Path(temp_name)
        try:
            if os.name!="nt":
                os.fchmod(fd,0o600)
            with os.fdopen(fd,"wb") as handle:
                handle.write(raw); handle.flush(); os.fsync(handle.fileno())
            try:
                os.link(temp,output,follow_symlinks=False)
            except FileExistsError:
                current=_existing_bytes(output)
                if current!=raw:
                    raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_OUTPUT_CONFLICT")
            if os.name!="nt":
                output.chmod(0o600)
                directory_fd=os.open(output.parent,os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            if temp.exists():
                temp.unlink()
    bindings,digest=campaign.load_oauth_bindings(output)
    if bindings!=normalized:
        raise RuntimeError("MCP_EXTERNAL_OAUTH_BINDINGS_VALIDATION_DRIFT")
    return {
        "authority":AUTHORITY,
        "path":str(output),
        "sha256":digest,
        "clientCount":len(bindings),
        "physicalCertified":False,
    }


def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,default=Path("."))
    parser.add_argument("--out",type=Path,default=DEFAULT_OUTPUT)
    for client in CLIENTS:
        parser.add_argument(f"--{client}-client-id",default=os.environ.get(ENV_IDS[client],""))
    args=parser.parse_args()
    clients={client:getattr(args,client+"_client_id") for client in CLIENTS}
    root=Path(os.path.abspath(args.root))
    output=args.out if args.out.is_absolute() else root/args.out
    result=materialize(output,clients,root=root)
    result["nextActionCode"]="RUN_C7W_PREFLIGHT"
    result["nextCommand"]=[
        os.environ.get("PYTHON","python3"),"scripts/c7w_preflight.py","--root",".",
        "--oauth-client-map",str(output),
    ]
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
