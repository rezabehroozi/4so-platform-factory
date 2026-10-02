#!/usr/bin/env python3
"""Fail-closed admission for the final pre-certification Exact Release.

This gate consumes only already-sealed external authorities:
- immutable appliance distribution authority (S1)
- four named external MCP client interoperability evidence (C7W)

It never infers or records Physical PASS.
"""
from __future__ import annotations
import argparse, hashlib, json, re, subprocess
from pathlib import Path
from urllib.parse import urlsplit
try:
    import distribution_transport as transport
except ModuleNotFoundError:
    from scripts import distribution_transport as transport
try:
    import seal_mcp_external_interop as mcp_contract
except ModuleNotFoundError:
    from scripts import seal_mcp_external_interop as mcp_contract

AUTHORITY="FINAL_EXACT_RELEASE_ADMISSION_V1"
S1_AUTHORITY="LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8"
MCP_AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROPERABILITY_EVIDENCE_V1"
MCP_AUDIT_WITNESS_AUTHORITY=mcp_contract.AUDIT_WITNESS_AUTHORITY
MCP_AUDIT_METHOD_VERSION=mcp_contract.AUDIT_METHOD_VERSION
CLIENTS=mcp_contract.CLIENTS
CLIENT_SURFACES=mcp_contract.CLIENT_SURFACES
MCP_AUDITED_CHECKS=mcp_contract.AUDITED_CHECKS
MCP_REQUIRED_CHECKS=mcp_contract.REQUIRED_CHECKS
SHA=mcp_contract.SHA


class Pending(RuntimeError):
    pass


C7W_EVIDENCE_ONLY_PATHS=mcp_contract.C7W_EVIDENCE_ONLY_PATHS


def git_head(root:Path)->str|None:
    proc=subprocess.run(["git","rev-parse","HEAD"],cwd=root,text=True,capture_output=True,check=False)
    value=proc.stdout.strip().lower() if proc.returncode==0 else ""
    return value if mcp_contract.COMMIT.fullmatch(value) else None


def validate_c7w_source_lineage(root:Path,certified_sha:str,release_sha:str)->None:
    mcp_contract.validate_evidence_only_source_lineage(root,certified_sha,release_sha,"MCP_EXTERNAL_INTEROP")

def digest(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""): h.update(block)
    return "sha256:"+h.hexdigest()


def load(path:Path,label:str)->dict:
    if not path.exists():
        raise Pending(f"{label}_PENDING")
    if path.is_symlink() or not path.is_file() or path.stat().st_size<=0 or path.stat().st_size>2*1024*1024:
        raise RuntimeError(f"{label}_FILE_INVALID")
    value=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value,dict): raise RuntimeError(f"{label}_NOT_OBJECT")
    return value


def validate_mcp_projection_identity(value:dict,label:str)->str:
    if value.get("matrixAuthority")!=mcp_contract.MATRIX_AUTHORITY or not SHA.fullmatch(str(value.get("matrixSha256") or "")):
        raise RuntimeError(f"{label}_MATRIX_BINDING_INVALID")
    if value.get("campaignAuthority")!=mcp_contract.CAMPAIGN_AUTHORITY or not str(value.get("campaignId") or "").startswith("mcp-interop-") or not SHA.fullmatch(str(value.get("campaignSha256") or "")):
        raise RuntimeError(f"{label}_CAMPAIGN_BINDING_INVALID")
    if value.get("protocol")!="2026-07-28" or value.get("transport")!="streamable-http":
        raise RuntimeError(f"{label}_PROTOCOL_INVALID")
    try:
        return mcp_contract.endpoint(value.get("endpoint",""))
    except RuntimeError as exc:
        raise RuntimeError(f"{label}_ENDPOINT_INVALID") from exc


def validate_mcp_client_timing(row:dict,endpoint_value:str,label:str)->tuple[str,str,int]:
    try:
        row_endpoint=mcp_contract.endpoint(row.get("endpoint",""))
    except RuntimeError as exc:
        raise RuntimeError(f"{label}_ENDPOINT_INVALID") from exc
    if row_endpoint!=endpoint_value:
        raise RuntimeError(f"{label}_ENDPOINT_DRIFT")
    executed=mcp_contract.parse_utc_timestamp(row.get("executedAt"),label+"_EXECUTED_AT")
    created=mcp_contract.parse_utc_timestamp(row.get("campaignCreatedAt"),label+"_CAMPAIGN_CREATED_AT")
    expires=mcp_contract.parse_utc_timestamp(row.get("campaignExpiresAt"),label+"_CAMPAIGN_EXPIRES_AT")
    audit_window=row.get("executionAuditWindowSeconds")
    campaign_seconds=(expires-created).total_seconds()
    if created>executed or executed>expires or campaign_seconds<3600 or campaign_seconds>14*24*3600:
        raise RuntimeError(f"{label}_CAMPAIGN_WINDOW_INVALID")
    if type(audit_window) is not int or audit_window<60 or audit_window>24*3600 or audit_window>campaign_seconds:
        raise RuntimeError(f"{label}_AUDIT_WINDOW_INVALID")
    witness=row.get("serverAuditWitness") or {}
    if witness.get("executionObservedAt")!=mcp_contract.utc_timestamp(executed) or witness.get("executionAuditWindowSeconds")!=audit_window:
        raise RuntimeError(f"{label}_SERVER_WITNESS_TIME_DRIFT")
    return mcp_contract.utc_timestamp(created),mcp_contract.utc_timestamp(expires),audit_window


def external_client_progress(root:Path)->dict:
    path=root/"lab/mcp-external-client-interop-progress.json"
    if not path.exists():
        return {"authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","certifiedClientCount":0,"certifiedClients":[],"missingClients":list(CLIENTS),"nextClient":CLIENTS[0],"complete":False,"evidenceSealPending":False}
    progress=load(path,"MCP_EXTERNAL_PROGRESS")
    if set(progress)!=set(mcp_contract.PROGRESS_EVIDENCE_KEYS):
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_FIELDS_INVALID")
    if progress.get("authority")!="MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1" or progress.get("kind")!="MCPExternalClientInteropProgress":
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_AUTHORITY_INVALID")
    endpoint_value=validate_mcp_projection_identity(progress,"MCP_EXTERNAL_PROGRESS")
    if progress.get("runtimeCertified") is not False or progress.get("physicalCertified") is not False:
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_SCOPE_INFLATED")
    bindings=progress.get("oauthClientBindings")
    if progress.get("oauthClientBindingAuthority")!=mcp_contract.OAUTH_BINDING_AUTHORITY or not SHA.fullmatch(str(progress.get("oauthClientBindingsSha256") or "")):
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_OAUTH_BINDING_INVALID")
    bindings=mcp_contract.validate_oauth_client_bindings(bindings,"MCP_EXTERNAL_PROGRESS")
    trusted_bindings=mcp_contract.validate_trusted_client_bindings(progress.get("trustedClientBindings"),"MCP_EXTERNAL_PROGRESS")
    rows=progress.get("clients")
    if not isinstance(rows,list):
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_CLIENTS_INVALID")
    seen=set(); provider_refs=set(); execution_ids=set(); evidence_digests=set(); receipt_digests=set(); challenge_digests=set(); request_id_owners={}; campaign_windows=set()
    for row in rows:
        if not isinstance(row,dict):
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_CLIENTS_INVALID")
        client=str(row.get("clientId") or "")
        if client not in CLIENTS or client in seen or row.get("clientSurface")!=CLIENT_SURFACES[client]:
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_CLIENT_IDENTITY_INVALID")
        oauth_client_id=mcp_contract.validate_oauth_client_id(row.get("oauthClientId"),"MCP_EXTERNAL_PROGRESS")
        if oauth_client_id!=bindings[client]:
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_OAUTH_CLIENT_DRIFT")
        trusted=trusted_bindings.get(client) or {}
        if row.get("trustedClientId")!=trusted.get("trustedClientId") or row.get("trustedClientRevision")!=trusted.get("trustedClientRevision") or row.get("trustedClientProvider")!=trusted.get("trustedClientProvider"):
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_TRUSTED_CLIENT_DRIFT")
        execution_id=str(row.get("executionId") or "").strip()
        provider_ref=str(row.get("providerExecutionRef") or "").strip()
        if not execution_id or len(execution_id)>160 or execution_id in execution_ids:
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_EXECUTION_ID_INVALID")
        if len(provider_ref)<8 or len(provider_ref)>500 or any(ord(ch)<0x21 or ord(ch)>0x7e for ch in provider_ref) or provider_ref in provider_refs:
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_PROVIDER_EXECUTION_REF_INVALID")
        checks=row.get("checks")
        if not isinstance(checks,dict) or set(checks)!=set(MCP_REQUIRED_CHECKS) or any(v is not True for v in checks.values()):
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_CHECKS_INVALID")
        mcp_contract.validate_response_observations(
            row.get("responseObservations"),row.get("sourceCommitSHA"),row.get("runtimeVersion"),row.get("endpoint"),
            "MCP_EXTERNAL_PROGRESS_"+client.upper(),
        )
        request_ids=row.get("requestIds")
        if not isinstance(request_ids,dict) or set(request_ids)!=set(MCP_AUDITED_CHECKS) or len(set(str(v or "").strip() for v in request_ids.values()))!=len(MCP_AUDITED_CHECKS) or any(not re.fullmatch(r"[A-Za-z0-9._:-]{8,200}",str(v or "").strip()) for v in request_ids.values()):
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_REQUEST_IDS_INVALID")
        for check,rid_raw in request_ids.items():
            rid=str(rid_raw or "").strip()
            if rid in request_id_owners:
                raise RuntimeError(f"MCP_EXTERNAL_PROGRESS_REQUEST_ID_REUSE {client}:{check}:{request_id_owners[rid]}")
            request_id_owners[rid]=f"{client}:{check}"
        evidence_digest=str(row.get("evidenceDigest") or "")
        receipt_digest=str(row.get("externalReceiptSha256") or row.get("receiptSha256") or "")
        challenge_digest=str(row.get("challengeSha256") or "")
        if not SHA.fullmatch(evidence_digest) or not SHA.fullmatch(receipt_digest) or not SHA.fullmatch(challenge_digest):
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_RECEIPT_BINDING_INVALID")
        binding=mcp_contract.validate_interop_binding(row,progress.get("campaignId"),client,"MCP_EXTERNAL_PROGRESS")
        if evidence_digest in evidence_digests or receipt_digest in receipt_digests or challenge_digest in challenge_digests:
            raise RuntimeError("MCP_EXTERNAL_PROGRESS_EVIDENCE_REUSE")
        witness=row.get("serverAuditWitness") or {}
        timing=validate_mcp_client_timing(row,endpoint_value,"MCP_EXTERNAL_PROGRESS_"+client.upper())
        campaign_windows.add(timing[:2])
        mcp_contract.validate_server_audit_witness(witness,binding,client,"MCP_EXTERNAL_PROGRESS_SERVER_WITNESS",oauth_client_id,request_ids)
        seen.add(client); provider_refs.add(provider_ref); execution_ids.add(execution_id); evidence_digests.add(evidence_digest); receipt_digests.add(receipt_digest); challenge_digests.add(challenge_digest)
    if len(campaign_windows)>1:
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_CAMPAIGN_WINDOW_DRIFT")
    certified=[c for c in CLIENTS if c in seen]
    missing=[c for c in CLIENTS if c not in seen]
    complete=len(missing)==0
    if progress.get("allAdmittedReceiptsPass") is not True or progress.get("certifiedClientCount")!=len(certified) or progress.get("complete") is not complete or progress.get("externalCertificationPass") is not complete or progress.get("serverAuditWitnessPass") is not complete:
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_COUNT_INVALID")
    return {"authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","certifiedClientCount":len(certified),"certifiedClients":certified,"missingClients":missing,"nextClient":missing[0] if missing else None,"complete":complete,"evidenceSealPending":complete}


def public_content_addressed(url:str,sha:str,label:str)->None:
    p=urlsplit(str(url or "").strip())
    d=str(sha or "").removeprefix("sha256:")
    if p.scheme!="https" or not p.hostname or p.username or p.password or p.query or p.fragment:
        raise RuntimeError(f"{label}_HTTPS_INVALID")
    if not re.fullmatch(r"[0-9a-f]{64}",d) or d not in p.path.lower():
        raise RuntimeError(f"{label}_CONTENT_ADDRESS_INVALID")


def verify(root:Path,expected_source_sha:str|None=None)->dict:
    release_source_sha=str(expected_source_sha or "").strip().lower() or git_head(root)
    if release_source_sha is not None and not mcp_contract.COMMIT.fullmatch(release_source_sha):
        raise RuntimeError("FINAL_EXACT_RELEASE_SOURCE_SHA_INVALID")
    lock_path=root/"lab/appliance-bundle-acquisition-lock.json"
    lock=load(lock_path,"APPLIANCE_DISTRIBUTION")
    if lock.get("authority")!=S1_AUTHORITY or lock.get("schemaVersion")!=8:
        raise RuntimeError("APPLIANCE_DISTRIBUTION_AUTHORITY_INVALID")
    if lock.get("status")!="ready":
        raise Pending("APPLIANCE_DISTRIBUTION_PENDING")
    if lock.get("missingAuthorities") or lock.get("partialAuthorities"):
        raise RuntimeError("APPLIANCE_DISTRIBUTION_READY_WITH_OPEN_AUTHORITIES")
    pack=lock.get("inputPack") or {}
    if pack.get("format")!="zip" or pack.get("buildSpecPath")!="build-spec.json" or pack.get("stagingDirectory")!="staging":
        raise RuntimeError("APPLIANCE_INPUT_PACK_AUTHORITY_INVALID")
    if not SHA.fullmatch("sha256:"+str(pack.get("sha256") or "").removeprefix("sha256:")) or not isinstance(pack.get("sizeBytes"),int) or pack["sizeBytes"]<=0:
        raise RuntimeError("APPLIANCE_INPUT_PACK_DIGEST_INVALID")
    transport.validate_locator(pack, expected_sha256=str(pack["sha256"]).removeprefix("sha256:"), expected_size=pack["sizeBytes"], label="APPLIANCE_INPUT_PACK")

    archive=next((x for x in lock.get("resolvedAuthorities") or [] if isinstance(x,dict) and x.get("id")=="management-workload-oci-archive"),None)
    if not archive:
        raise RuntimeError("MANAGEMENT_ARCHIVE_AUTHORITY_MISSING")
    artifacts=archive.get("artifacts") or []
    if len(artifacts)!=1:
        raise RuntimeError("MANAGEMENT_ARCHIVE_ARTIFACT_COVERAGE_INVALID")
    ar=artifacts[0]
    if not re.fullmatch(r"[0-9a-f]{64}",str(ar.get("sha256") or "")) or not isinstance(ar.get("sizeBytes"),int) or ar["sizeBytes"]<=0:
        raise RuntimeError("MANAGEMENT_ARCHIVE_DIGEST_INVALID")
    transport.validate_locator(ar, expected_sha256=ar["sha256"], expected_size=ar["sizeBytes"], label="MANAGEMENT_ARCHIVE")

    matrix_path=root/"lab/mcp-external-client-interop-matrix.json"
    matrix=load(matrix_path,"MCP_EXTERNAL_MATRIX")
    mcp_contract.validate_matrix_contract(matrix,"MCP_EXTERNAL_MATRIX")

    mcp_path=root/"lab/mcp-external-client-interoperability-evidence.json"
    mcp=load(mcp_path,"MCP_EXTERNAL_INTEROP")
    if set(mcp)!=set(mcp_contract.INTEROP_EVIDENCE_KEYS):
        raise RuntimeError("MCP_EXTERNAL_INTEROP_FIELDS_INVALID")
    if mcp.get("authority")!=MCP_AUTHORITY or mcp.get("externalCertificationPass") is not True or mcp.get("allRequiredChecksPass") is not True or mcp.get("certifiedClientCount")!=4:
        raise RuntimeError("MCP_EXTERNAL_INTEROP_AUTHORITY_INVALID")
    endpoint_value=validate_mcp_projection_identity(mcp,"MCP_EXTERNAL_INTEROP")
    certified_source_sha=str(mcp.get("sourceCommitSHA") or "").strip().lower()
    runtime_version=str(mcp.get("runtimeVersion") or "").strip()
    expected_version=(root/"VERSION").read_text(encoding="utf-8").strip()
    if not mcp_contract.COMMIT.fullmatch(certified_source_sha) or runtime_version!=expected_version:
        raise RuntimeError("MCP_EXTERNAL_INTEROP_RUNTIME_IDENTITY_INVALID")
    if release_source_sha is None:
        release_source_sha=certified_source_sha
    validate_c7w_source_lineage(root,certified_source_sha,release_source_sha)
    if mcp.get("matrixSha256")!=digest(matrix_path):
        raise RuntimeError("MCP_EXTERNAL_INTEROP_MATRIX_DRIFT")
    if mcp.get("serverAuditWitnessPass") is not True or mcp.get("serverAuditWitnessedCheckCount") != 24:
        raise Pending("MCP_EXTERNAL_SERVER_AUDIT_WITNESS_PENDING")
    if mcp.get("runtimeCertified") is not False or mcp.get("physicalCertified") is not False:
        raise RuntimeError("MCP_EXTERNAL_INTEROP_SCOPE_INFLATED")
    if mcp.get("campaignAuthority")!="MCP_EXTERNAL_CLIENT_INTEROP_CAMPAIGN_V1" or not SHA.fullmatch(str(mcp.get("campaignSha256") or "")):
        raise RuntimeError("MCP_EXTERNAL_INTEROP_CAMPAIGN_INVALID")
    if mcp.get("oauthClientBindingAuthority")!=mcp_contract.OAUTH_BINDING_AUTHORITY or not SHA.fullmatch(str(mcp.get("oauthClientBindingsSha256") or "")):
        raise RuntimeError("MCP_EXTERNAL_INTEROP_OAUTH_BINDING_INVALID")
    oauth_bindings=mcp_contract.validate_oauth_client_bindings(mcp.get("oauthClientBindings"),"MCP_EXTERNAL_INTEROP")
    trusted_bindings=mcp_contract.validate_trusted_client_bindings(mcp.get("trustedClientBindings"),"MCP_EXTERNAL_INTEROP")
    clients=mcp.get("clients")
    if not isinstance(clients,list) or [x.get("clientId") for x in clients if isinstance(x,dict)]!=list(CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_INTEROP_CLIENT_SET_INVALID")
    provider_refs=set(); execution_ids=set(); evidence_digests=set(); receipt_digests=set(); challenge_digests=set(); request_id_owners={}; campaign_windows=set()
    for row in clients:
        client=str(row.get("clientId") or "")
        if row.get("sourceCommitSHA")!=certified_source_sha or row.get("runtimeVersion")!=runtime_version:
            raise RuntimeError("MCP_EXTERNAL_INTEROP_CLIENT_RUNTIME_IDENTITY_DRIFT")
        if row.get("clientSurface")!=CLIENT_SURFACES.get(client):
            raise RuntimeError("MCP_EXTERNAL_INTEROP_CLIENT_SURFACE_INVALID")
        oauth_client_id=mcp_contract.validate_oauth_client_id(row.get("oauthClientId"),"MCP_EXTERNAL_INTEROP")
        if oauth_client_id!=oauth_bindings.get(client):
            raise RuntimeError("MCP_EXTERNAL_INTEROP_OAUTH_CLIENT_DRIFT")
        trusted=trusted_bindings.get(client) or {}
        if row.get("trustedClientId")!=trusted.get("trustedClientId") or row.get("trustedClientRevision")!=trusted.get("trustedClientRevision") or row.get("trustedClientProvider")!=trusted.get("trustedClientProvider"):
            raise RuntimeError("MCP_EXTERNAL_INTEROP_TRUSTED_CLIENT_DRIFT")
        execution_id=str(row.get("executionId") or "").strip()
        provider_ref=str(row.get("providerExecutionRef") or "").strip()
        if not execution_id or len(execution_id)>160 or execution_id in execution_ids:
            raise RuntimeError("MCP_EXTERNAL_INTEROP_EXECUTION_REUSE")
        if len(provider_ref)<8 or len(provider_ref)>500 or any(ord(ch)<0x21 or ord(ch)>0x7e for ch in provider_ref):
            raise RuntimeError("MCP_EXTERNAL_INTEROP_PROVIDER_EXECUTION_REF_INVALID")
        if provider_ref in provider_refs:
            raise RuntimeError("MCP_EXTERNAL_INTEROP_PROVIDER_EXECUTION_REUSE")
        provider_refs.add(provider_ref)
        checks=row.get("checks")
        if not isinstance(checks,dict) or set(checks)!=set(MCP_REQUIRED_CHECKS) or any(v is not True for v in checks.values()):
            raise RuntimeError("MCP_EXTERNAL_INTEROP_CHECKS_INVALID")
        mcp_contract.validate_response_observations(
            row.get("responseObservations"),row.get("sourceCommitSHA"),row.get("runtimeVersion"),row.get("endpoint"),
            "MCP_EXTERNAL_INTEROP_"+client.upper(),
        )
        request_ids=row.get("requestIds")
        if not isinstance(request_ids,dict) or set(request_ids)!=set(MCP_AUDITED_CHECKS) or len(set(str(v or "").strip() for v in request_ids.values()))!=len(MCP_AUDITED_CHECKS):
            raise RuntimeError("MCP_EXTERNAL_INTEROP_REQUEST_IDS_INVALID")
        for check,rid_raw in request_ids.items():
            rid=str(rid_raw or "").strip()
            if not re.fullmatch(r"[A-Za-z0-9._:-]{8,200}",rid):
                raise RuntimeError("MCP_EXTERNAL_INTEROP_REQUEST_IDS_INVALID")
            if rid in request_id_owners:
                raise RuntimeError(f"MCP_EXTERNAL_INTEROP_REQUEST_ID_REUSE {client}:{check}:{request_id_owners[rid]}")
            request_id_owners[rid]=f"{client}:{check}"
        evidence_digest=str(row.get("evidenceDigest") or "")
        receipt_digest=str(row.get("externalReceiptSha256") or row.get("receiptSha256") or "")
        challenge_digest=str(row.get("challengeSha256") or "")
        if not SHA.fullmatch(evidence_digest) or not SHA.fullmatch(receipt_digest) or not SHA.fullmatch(challenge_digest):
            raise RuntimeError("MCP_EXTERNAL_INTEROP_RECEIPT_BINDING_INVALID")
        binding=mcp_contract.validate_interop_binding(row,mcp.get("campaignId"),client,"MCP_EXTERNAL_INTEROP")
        if evidence_digest in evidence_digests or receipt_digest in receipt_digests or challenge_digest in challenge_digests:
            raise RuntimeError("MCP_EXTERNAL_INTEROP_EVIDENCE_REUSE")
        witness=row.get("serverAuditWitness") or {}
        timing=validate_mcp_client_timing(row,endpoint_value,"MCP_EXTERNAL_INTEROP_"+client.upper())
        campaign_windows.add(timing[:2])
        mcp_contract.validate_server_audit_witness(witness,binding,client,"MCP_EXTERNAL_INTEROP_SERVER_WITNESS",oauth_client_id,request_ids)
        execution_ids.add(execution_id); evidence_digests.add(evidence_digest); receipt_digests.add(receipt_digest); challenge_digests.add(challenge_digest)

    if len(campaign_windows)!=1:
        raise RuntimeError("MCP_EXTERNAL_INTEROP_CAMPAIGN_WINDOW_DRIFT")
    return {
      "apiVersion":"platform.4so.io/v1alpha1","kind":"FinalExactReleaseAdmission",
      "authority":AUTHORITY,"admitted":True,
      "applianceDistributionAuthority":S1_AUTHORITY,"applianceDistributionSha256":digest(lock_path),
      "mcpExternalInteropAuthority":MCP_AUTHORITY,"mcpExternalInteropSha256":digest(mcp_path),
      "physicalCertified":False
    }


def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--root",type=Path,default=Path(".")); p.add_argument("--out",type=Path); p.add_argument("--allow-pending",action="store_true")
    a=p.parse_args()
    try: out=verify(a.root.resolve())
    except Pending as exc:
        if not a.allow_pending: raise
        pending=str(exc)
        status={"authority":AUTHORITY,"admitted":False,"pending":pending,"blockers":[{"code":pending,"detail":"required external closure evidence is not sealed on canonical main"}],"physicalCertified":False}
        if pending=="MCP_EXTERNAL_INTEROP_PENDING":
            status["externalClientProgress"]=external_client_progress(a.root.resolve())
        if a.out:
            mcp_contract.write_json_atomic_replace(a.out,status,"FINAL_EXACT_RELEASE_ADMISSION")
        print(json.dumps(status,sort_keys=True))
        return 3
    if a.out:
        mcp_contract.write_json_atomic_replace(a.out,out,"FINAL_EXACT_RELEASE_ADMISSION")
    print(json.dumps(out,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
