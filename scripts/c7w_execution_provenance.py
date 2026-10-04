#!/usr/bin/env python3
"""Validate campaign/receipt execution-resource provenance without import cycles."""
from __future__ import annotations

import hashlib
import json
import re

try:
    import c7w_credential_profiles as credential_profiles
except ModuleNotFoundError:
    from scripts import c7w_credential_profiles as credential_profiles

EXECUTION_BINDING_AUTHORITY="MCP_EXTERNAL_EXECUTION_BINDINGS_V1"
CREDENTIAL_PROFILE_CONTRACT_AUTHORITY="MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1"
EXECUTION_BINDING_FIELDS=(
    "executionBindingAuthority",
    "executionBindingsSha256",
    "executionBindings",
    "credentialProfileContractAuthority",
    "credentialProfileContractSha256",
)
RESOURCE_KEYS=("foreignProjectId","sameProjectOperationId","selfApprovalRequestId")
SHA=re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT=re.compile(r"^[0-9a-f]{40}$")
SAFE_VALUE=re.compile(r"^[^\x00-\x20\x7f]{1,256}$")


def credential_contract_digest()->str:
    value=credential_profiles.contract()
    if not isinstance(value,dict) or value.get("authority")!=CREDENTIAL_PROFILE_CONTRACT_AUTHORITY:
        raise RuntimeError("MCP_EXTERNAL_EXECUTION_BINDING_CREDENTIAL_CONTRACT_INVALID")
    raw=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    return "sha256:"+hashlib.sha256(raw).hexdigest()


def _resources(value:object,label:str)->dict[str,str]:
    if not isinstance(value,dict) or set(value)!=set(RESOURCE_KEYS):
        raise RuntimeError(f"{label}_EXECUTION_BINDING_RESOURCES_INVALID")
    out={}
    for key in RESOURCE_KEYS:
        item=str(value.get(key) or "").strip()
        if not SAFE_VALUE.fullmatch(item) or "<" in item or ">" in item:
            raise RuntimeError(f"{label}_EXECUTION_BINDING_RESOURCE_INVALID {key}")
        out[key]=item
    if len(set(out.values()))!=len(RESOURCE_KEYS):
        raise RuntimeError(f"{label}_EXECUTION_BINDING_RESOURCE_REUSE")
    return out


def projection(value:object,source_sha:str,label:str)->dict:
    if not isinstance(value,dict):
        raise RuntimeError(f"{label}_EXECUTION_BINDING_FIELDS_INVALID")
    present=set(EXECUTION_BINDING_FIELDS).intersection(value)
    if not present:
        return {}
    if present!=set(EXECUTION_BINDING_FIELDS):
        raise RuntimeError(f"{label}_EXECUTION_BINDING_FIELDS_INVALID")
    source=str(source_sha or "").strip().lower()
    if not COMMIT.fullmatch(source):
        raise RuntimeError(f"{label}_EXECUTION_BINDING_SOURCE_INVALID")
    if value.get("executionBindingAuthority")!=EXECUTION_BINDING_AUTHORITY:
        raise RuntimeError(f"{label}_EXECUTION_BINDING_AUTHORITY_INVALID")
    if value.get("credentialProfileContractAuthority")!=CREDENTIAL_PROFILE_CONTRACT_AUTHORITY:
        raise RuntimeError(f"{label}_EXECUTION_BINDING_CREDENTIAL_CONTRACT_INVALID")
    credential_digest=str(value.get("credentialProfileContractSha256") or "")
    if not SHA.fullmatch(credential_digest):
        raise RuntimeError(f"{label}_EXECUTION_BINDING_CREDENTIAL_DIGEST_INVALID")
    if credential_digest!=credential_contract_digest():
        raise RuntimeError(f"{label}_EXECUTION_BINDING_CREDENTIAL_CONTRACT_INVALID")
    resources=_resources(value.get("executionBindings"),label)
    document={
        "authority":EXECUTION_BINDING_AUTHORITY,
        "sourceCommitSHA":source,
        "resources":resources,
        "credentialProfileContractAuthority":CREDENTIAL_PROFILE_CONTRACT_AUTHORITY,
        "credentialProfileContractSha256":credential_digest,
    }
    raw=(json.dumps(document,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode("utf-8")
    digest="sha256:"+hashlib.sha256(raw).hexdigest()
    if value.get("executionBindingsSha256")!=digest:
        raise RuntimeError(f"{label}_EXECUTION_BINDING_DIGEST_INVALID")
    return {
        "executionBindingAuthority":EXECUTION_BINDING_AUTHORITY,
        "executionBindingsSha256":digest,
        "executionBindings":resources,
        "credentialProfileContractAuthority":CREDENTIAL_PROFILE_CONTRACT_AUTHORITY,
        "credentialProfileContractSha256":credential_digest,
    }


def validate_rows(rows:object,source_sha:str,label:str,*,require_bound:bool=False)->dict:
    if not isinstance(rows,list):
        raise RuntimeError(f"{label}_EXECUTION_BINDING_ROWS_INVALID")
    mode=None
    expected=None
    for index,row in enumerate(rows):
        if not isinstance(row,dict):
            raise RuntimeError(f"{label}_EXECUTION_BINDING_ROWS_INVALID")
        client=str(row.get("clientId") or index).strip().upper()
        current=projection(row,source_sha,f"{label}_{client}")
        bound=bool(current)
        if mode is None:
            mode=bound
        elif mode is not bound:
            raise RuntimeError(f"{label}_EXECUTION_BINDING_MIXED")
        if current:
            if expected is None:
                expected=current
            elif current!=expected:
                raise RuntimeError(f"{label}_EXECUTION_BINDING_DRIFT")
    if require_bound and not expected:
        raise RuntimeError(f"{label}_EXECUTION_BINDING_REQUIRED")
    return expected or {}


def validate_receipt_execution_binding(row:object,campaign:object,client:str)->dict:
    client=str(client or "").strip().upper() or "UNKNOWN"
    if not isinstance(campaign,dict):
        raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_EXECUTION_BINDING_FIELDS_INVALID")
    source=str(campaign.get("sourceCommitSHA") or "").strip().lower()
    campaign_projection=projection(campaign,source,"MCP_EXTERNAL_CAMPAIGN")
    receipt_projection=projection(row,source,f"MCP_EXTERNAL_RECEIPT_{client}")
    if not campaign_projection:
        if receipt_projection:
            raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_{client}_EXECUTION_BINDING_DRIFT")
        return {}
    if receipt_projection!=campaign_projection:
        raise RuntimeError(f"MCP_EXTERNAL_RECEIPT_{client}_EXECUTION_BINDING_DRIFT")
    return receipt_projection
