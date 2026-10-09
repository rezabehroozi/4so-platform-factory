#!/usr/bin/env python3
"""Materialize non-secret resource bindings required by executable C7W packets.

This file deliberately does not carry OAuth tokens, client secrets or delegation
credentials. It only binds the three runtime resource identifiers that replace
C7W packet placeholders to the exact source revision and credential-profile
contract used by the campaign.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

try:
    import c7w_credential_profiles as profiles
    import seal_mcp_external_interop as core
except ModuleNotFoundError:
    from scripts import c7w_credential_profiles as profiles
    from scripts import seal_mcp_external_interop as core

AUTHORITY="MCP_EXTERNAL_EXECUTION_BINDINGS_V1"
DEFAULT_OUTPUT=Path(".state/private/c7w-execution-bindings.json")
RESOURCE_KEYS=("foreignProjectId","sameProjectOperationId","selfApprovalRequestId")
ENV_RESOURCES={
    "foreignProjectId":"C7W_FOREIGN_PROJECT_ID",
    "sameProjectOperationId":"C7W_SAME_PROJECT_OPERATION_ID",
    "selfApprovalRequestId":"C7W_SELF_APPROVAL_REQUEST_ID",
}
SAFE_VALUE=re.compile(r"^[^\x00-\x20\x7f]{1,256}$")


def credential_contract()->dict:
    value=profiles.contract()
    if not isinstance(value,dict) or value.get("authority")!="MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1":
        raise RuntimeError("MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_INVALID")
    return value


def credential_contract_digest()->str:
    raw=json.dumps(credential_contract(),sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    return "sha256:"+hashlib.sha256(raw).hexdigest()


def _clean_git_env()->dict[str,str]:
    env=os.environ.copy()
    for key in list(env):
        if key.startswith("GIT_"):
            env.pop(key,None)
    return env


def git_head(root:Path)->str:
    root=Path(os.path.abspath(root))
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_GIT_ROOT_INVALID")
    git_env=_clean_git_env()
    try:
        top=subprocess.run(["git","rev-parse","--show-toplevel"],cwd=root,env=git_env,text=True,capture_output=True,check=False)
        top_path=Path(top.stdout.strip()).resolve() if top.returncode==0 and top.stdout.strip() else None
    except (OSError,RuntimeError) as exc:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_GIT_ROOT_INVALID") from exc
    if top.returncode!=0 or top_path is None or top_path!=root.resolve():
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_GIT_ROOT_INVALID")
    try:
        proc=subprocess.run(["git","rev-parse","HEAD"],cwd=root,env=git_env,text=True,capture_output=True,check=False)
    except OSError as exc:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_SOURCE_UNAVAILABLE") from exc
    value=proc.stdout.strip().lower() if proc.returncode==0 else ""
    if not core.COMMIT.fullmatch(value):
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_SOURCE_UNAVAILABLE")
    return value


def _require_source_freeze(root:Path)->None:
    root=Path(os.path.abspath(root))
    git_env=_clean_git_env()
    branch=subprocess.run(["git","symbolic-ref","--quiet","--short","HEAD"],cwd=root,env=git_env,text=True,capture_output=True,check=False)
    if branch.returncode!=0 or branch.stdout.strip()!="main":
        raise RuntimeError("MCP_EXTERNAL_LOCAL_BRANCH_NOT_MAIN")
    indexed=subprocess.run(["git","ls-files","-v","-z"],cwd=root,env=git_env,capture_output=True,check=False)
    if indexed.returncode!=0 or any(raw and not raw.startswith(b"H ") for raw in indexed.stdout.split(b"\x00")):
        raise RuntimeError("MCP_EXTERNAL_LOCAL_GIT_INDEX_FLAGS_FORBIDDEN")
    allowed=sorted(core.C7W_EVIDENCE_ONLY_PATHS)
    command=["git","status","--porcelain=v1","-z","--untracked-files=all"]
    all_status=subprocess.run(command,cwd=root,env=git_env,capture_output=True,check=False)
    allowed_status=subprocess.run(command+["--",*allowed],cwd=root,env=git_env,capture_output=True,check=False)
    if all_status.returncode!=0 or allowed_status.returncode!=0:
        raise RuntimeError("MCP_EXTERNAL_LOCAL_GIT_STATUS_UNAVAILABLE")
    all_records={row for row in all_status.stdout.split(b"\x00") if row}
    allowed_records={row for row in allowed_status.stdout.split(b"\x00") if row}
    if all_records-allowed_records:
        raise RuntimeError("MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN")


def source_commit_sha(root:Path,explicit:str="",*,require_freeze:bool=False)->str:
    value=str(explicit or "").strip().lower()
    if value and not core.COMMIT.fullmatch(value):
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_SOURCE_UNAVAILABLE")
    observed=git_head(root)
    if value and value!=observed:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_SOURCE_MISMATCH")
    if require_freeze:
        _require_source_freeze(root)
    return observed


def validate_resources(value:object)->dict[str,str]:
    if not isinstance(value,dict) or set(value)!=set(RESOURCE_KEYS):
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_RESOURCE_SET_INVALID")
    out={}
    for key in RESOURCE_KEYS:
        item=str(value.get(key) or "").strip()
        if (
            not SAFE_VALUE.fullmatch(item)
            or item.startswith("<")
            or item.endswith(">")
            or "<" in item
            or ">" in item
        ):
            raise RuntimeError(f"MCP_EXTERNAL_EXECUTION_BINDINGS_RESOURCE_INVALID {key}")
        out[key]=item
    if len(set(out.values()))!=len(RESOURCE_KEYS):
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_RESOURCE_REUSE")
    return out


def validate_document(value:object,expected_source_sha:str)->dict:
    if not isinstance(value,dict) or set(value)!={
        "authority","sourceCommitSHA","resources",
        "credentialProfileContractAuthority","credentialProfileContractSha256",
    }:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_FIELDS_INVALID")
    if value.get("authority")!=AUTHORITY:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_AUTHORITY_INVALID")
    source=str(value.get("sourceCommitSHA") or "").strip().lower()
    expected=str(expected_source_sha or "").strip().lower()
    if not core.COMMIT.fullmatch(source) or not core.COMMIT.fullmatch(expected) or source!=expected:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_SOURCE_MISMATCH")
    if value.get("credentialProfileContractAuthority")!=credential_contract()["authority"]:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_CREDENTIAL_CONTRACT_INVALID")
    if value.get("credentialProfileContractSha256")!=credential_contract_digest():
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_CREDENTIAL_CONTRACT_INVALID")
    return {
        "authority":AUTHORITY,
        "sourceCommitSHA":source,
        "resources":validate_resources(value.get("resources")),
        "credentialProfileContractAuthority":value["credentialProfileContractAuthority"],
        "credentialProfileContractSha256":value["credentialProfileContractSha256"],
    }


def canonical_output_path(root:Path,output:Path)->Path:
    root=Path(os.path.abspath(root))
    raw=Path(output)
    absolute=Path(os.path.abspath(raw if raw.is_absolute() else root/raw))
    expected=Path(os.path.abspath(root/DEFAULT_OUTPUT))
    if absolute!=expected:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_OUTPUT_PATH_INVALID")
    return absolute


def _private_output(root:Path,output:Path)->Path:
    root=Path(os.path.abspath(root))
    boundary=Path(os.path.abspath(root/".state"/"private"))
    absolute=Path(os.path.abspath(output if output.is_absolute() else root/output))
    try:
        absolute.relative_to(boundary)
    except ValueError as exc:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_OUTPUT_PATH_INVALID") from exc
    current=root
    for part in Path(".state/private").parts:
        current=current/part
        if current.exists() or current.is_symlink():
            if current.is_symlink() or not current.is_dir():
                raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_OUTPUT_PATH_INVALID")
        else:
            current.mkdir(mode=0o700)
        if os.name!="nt":
            current.chmod(0o700)
    relative=absolute.parent.relative_to(boundary)
    current=boundary
    for part in relative.parts:
        current=current/part
        if current.exists() or current.is_symlink():
            if current.is_symlink() or not current.is_dir():
                raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_OUTPUT_PATH_INVALID")
        else:
            current.mkdir(mode=0o700)
        if os.name!="nt":
            current.chmod(0o700)
    return absolute


def _private_file_snapshot(info)->tuple:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        getattr(info,"st_mtime_ns",int(info.st_mtime*1_000_000_000)),
        getattr(info,"st_ctime_ns",int(info.st_ctime*1_000_000_000)),
    )


def _validate_private_file_info(info)->None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_size<=0
        or info.st_size>64*1024
        or (os.name!="nt" and stat.S_IMODE(info.st_mode)&0o077)
    ):
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_OUTPUT_CONFLICT")


def _existing_bytes(path:Path)->bytes|None:
    try:
        named_before=path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_OUTPUT_CONFLICT") from exc
    _validate_private_file_info(named_before)
    flags=os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_BINARY",0)|getattr(os,"O_NOFOLLOW",0)
    try:
        fd=os.open(path,flags)
    except OSError as exc:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_OUTPUT_CONFLICT") from exc
    try:
        opened=os.fstat(fd)
        _validate_private_file_info(opened)
        if (opened.st_dev,opened.st_ino)!=(named_before.st_dev,named_before.st_ino):
            raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_OUTPUT_CONFLICT")
        chunks=[]
        remaining=64*1024+1
        while remaining>0:
            chunk=os.read(fd,min(65536,remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining-=len(chunk)
        raw=b"".join(chunks)
        finished=os.fstat(fd)
    finally:
        os.close(fd)
    if len(raw)!=opened.st_size or _private_file_snapshot(opened)!=_private_file_snapshot(finished):
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_OUTPUT_CONFLICT")
    try:
        named_after=path.lstat()
    except OSError as exc:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_OUTPUT_CONFLICT") from exc
    if _private_file_snapshot(named_after)!=_private_file_snapshot(opened):
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_OUTPUT_CONFLICT")
    return raw


def materialize(output:Path,resources:dict[str,str],source_commit_sha_value:str,*,root:Path|None=None)->dict:
    root=Path(os.path.abspath(root or Path(".")))
    source=source_commit_sha(root,source_commit_sha_value)
    output=_private_output(root,output)
    document={
        "authority":AUTHORITY,
        "sourceCommitSHA":source,
        "resources":validate_resources(resources),
        "credentialProfileContractAuthority":credential_contract()["authority"],
        "credentialProfileContractSha256":credential_contract_digest(),
    }
    raw=(json.dumps(document,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode("utf-8")
    existing=_existing_bytes(output)
    if existing is None:
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_BINARY",0)
        try:
            fd=os.open(output,flags,0o600)
        except FileExistsError:
            existing=_existing_bytes(output)
        else:
            try:
                with os.fdopen(fd,"wb") as handle:
                    handle.write(raw); handle.flush(); os.fsync(handle.fileno())
            except Exception:
                try: output.unlink()
                except OSError: pass
                raise
            if os.name!="nt":
                output.chmod(0o600)
    if existing is not None and existing!=raw:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_OUTPUT_CONFLICT")
    value,digest=load(output,source)
    if value!=document:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_VALIDATION_DRIFT")
    return {
        "authority":AUTHORITY,
        "path":str(output),
        "sha256":digest,
        "sourceCommitSHA":source,
        "credentialProfileContractAuthority":document["credentialProfileContractAuthority"],
        "credentialProfileContractSha256":document["credentialProfileContractSha256"],
        "resourceCount":len(RESOURCE_KEYS),
        "secretsIncluded":False,
        "physicalCertified":False,
    }


def load(path:Path,expected_source_sha:str)->tuple[dict,str]:
    try:
        value,digest=core.load_with_sha256(path,"MCP_EXTERNAL_EXECUTION_BINDINGS",max_bytes=64*1024)
    except RuntimeError as exc:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_FILE_INVALID") from exc
    return validate_document(value,expected_source_sha),digest


def followup_preflight_command(root:Path,output:Path,endpoint:str,oauth_client_map:Path|None,token_env:str)->list[str]:
    root=Path(root).resolve()
    output=Path(output).resolve()
    command=[sys.executable,str((root/"scripts/c7w_preflight.py").resolve()),"--root",str(root),"--execution-bindings",str(output)]
    if str(endpoint or "").strip():
        command.extend(["--endpoint",str(endpoint).strip()])
    if oauth_client_map is not None:
        command.extend(["--oauth-client-map",str(oauth_client_map)])
    if str(token_env or "").strip():
        command.extend(["--token-env",str(token_env).strip()])
    return command


def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,default=Path("."))
    p.add_argument("--out",type=Path,default=DEFAULT_OUTPUT)
    p.add_argument("--source-commit",default="")
    p.add_argument("--preflight-endpoint",default=os.environ.get("C7W_MCP_ENDPOINT",""))
    raw_oauth=os.environ.get("C7W_OAUTH_CLIENT_MAP","").strip()
    p.add_argument("--preflight-oauth-client-map",type=Path,default=Path(raw_oauth) if raw_oauth else None)
    p.add_argument("--preflight-token-env",default=os.environ.get("C7W_PLATFORM_ADMIN_TOKEN_ENV","C7W_PLATFORM_ADMIN_TOKEN"))
    for key,env_name in ENV_RESOURCES.items():
        p.add_argument("--"+re.sub(r"(?<!^)(?=[A-Z])","-",key).lower(),dest=key,default=os.environ.get(env_name,""))
    args=p.parse_args()
    root=Path(os.path.abspath(args.root))
    source=source_commit_sha(root,args.source_commit)
    output=canonical_output_path(root,args.out)
    resources={key:getattr(args,key) for key in RESOURCE_KEYS}
    result=materialize(output,resources,source,root=root)
    result["nextActionCode"]="RUN_C7W_PREFLIGHT"
    result["nextCommand"]=followup_preflight_command(root,output,args.preflight_endpoint,args.preflight_oauth_client_map,args.preflight_token_env)
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
