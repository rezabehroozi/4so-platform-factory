#!/usr/bin/env python3
"""Deterministic non-secret request identities for exact C7W execution packets."""
from __future__ import annotations

import hashlib
import re

try:
    import seal_mcp_external_interop as core
except ModuleNotFoundError:
    from scripts import seal_mcp_external_interop as core

AUTHORITY="MCP_EXTERNAL_REQUEST_IDENTITY_V1"
CAMPAIGN_ID=re.compile(r"^mcp-interop-[A-Za-z0-9._:-]{1,160}$")
CHECK_ID=re.compile(r"^[a-z0-9][a-z0-9-]{1,127}$")


def jsonrpc_id(campaign_id:str,client_id:str,challenge_sha256:str,check_id:str)->str:
    campaign=str(campaign_id or "").strip()
    client=str(client_id or "").strip().lower()
    challenge=str(challenge_sha256 or "").strip().lower()
    check=str(check_id or "").strip().lower()
    if not CAMPAIGN_ID.fullmatch(campaign):
        raise RuntimeError("MCP_EXTERNAL_JSONRPC_ID_CAMPAIGN_INVALID")
    if client not in core.CLIENTS:
        raise RuntimeError("MCP_EXTERNAL_JSONRPC_ID_CLIENT_INVALID")
    if not core.SHA.fullmatch(challenge):
        raise RuntimeError("MCP_EXTERNAL_JSONRPC_ID_CHALLENGE_INVALID")
    if not CHECK_ID.fullmatch(check) or check not in core.REQUIRED_CHECKS:
        raise RuntimeError("MCP_EXTERNAL_JSONRPC_ID_CHECK_INVALID")
    raw="\x00".join((AUTHORITY,campaign,client,challenge,check)).encode("utf-8")
    return "c7w-"+hashlib.sha256(raw).hexdigest()[:32]


def validate_packet_ids(packet:dict)->dict[str,str]:
    if not isinstance(packet,dict):
        raise RuntimeError("MCP_EXTERNAL_JSONRPC_PACKET_INVALID")
    campaign=packet.get("campaignId")
    client=packet.get("clientId")
    challenge=packet.get("challengeSha256")
    out={}
    for row in packet.get("checks") or []:
        if not isinstance(row,dict):
            raise RuntimeError("MCP_EXTERNAL_JSONRPC_PACKET_INVALID")
        request=row.get("request") or {}
        rpc=request.get("jsonRpc")
        if rpc is None:
            continue
        check=str(row.get("id") or "")
        expected=jsonrpc_id(campaign,client,challenge,check)
        if not isinstance(rpc,dict) or rpc.get("id")!=expected:
            raise RuntimeError(f"MCP_EXTERNAL_JSONRPC_ID_DRIFT {check}")
        if expected in out.values():
            raise RuntimeError("MCP_EXTERNAL_JSONRPC_ID_REUSE")
        out[check]=expected
    if set(out)!=set(core.AUDITED_CHECKS):
        raise RuntimeError("MCP_EXTERNAL_JSONRPC_ID_COVERAGE_INVALID")
    return out
