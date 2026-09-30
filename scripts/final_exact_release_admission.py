#!/usr/bin/env python3
"""Fail-closed admission for the final pre-certification Exact Release.

This gate consumes only already-sealed external authorities:
- immutable appliance distribution authority (S1)
- four named external MCP client interoperability evidence (C7W)

It never infers or records Physical PASS.
"""
from __future__ import annotations
import argparse, hashlib, json, re
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


def external_client_progress(root:Path)->dict:
    path=root/"lab/mcp-external-client-interop-progress.json"
    if not path.exists():
        return {"authority":"MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1","certifiedClientCount":0,"certifiedClients":[],"missingClients":list(CLIENTS),"nextClient":CLIENTS[0],"complete":False,"evidenceSealPending":False}
    progress=load(path,"MCP_EXTERNAL_PROGRESS")
    if set(progress)!=set(mcp_contract.PROGRESS_EVIDENCE_KEYS):
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_FIELDS_INVALID")
    if progress.get("authority")!="MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1" or progress.get("kind")!="MCPExternalClientInteropProgress":
        raise RuntimeError("MCP_EXTERNAL_PROGRESS_AUTHORITY_INVALID")
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
    seen=set(); provider_refs=set(); execution_ids=set(); evidence_digests=set(); receipt_digests=set(); challenge_digests=set(); request_id_owners={}
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
        mcp_contract.validate_server_audit_witness(witness,binding,client,"MCP_EXTERNAL_PROGRESS_SERVER_WITNESS",oauth_client_id)
        seen.add(client); provider_refs.add(provider_ref); execution_ids.add(execution_id); evidence_digests.add(evidence_digest); receipt_digests.add(receipt_digest); challenge_digests.add(challenge_digest)
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


def verify(root:Path)->dict:
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

    mcp_path=root/"lab/mcp-external-client-interoperability-evidence.json"
    mcp=load(mcp_path,"MCP_EXTERNAL_INTEROP")
    if set(mcp)!=set(mcp_contract.INTEROP_EVIDENCE_KEYS):
        raise RuntimeError("MCP_EXTERNAL_INTEROP_FIELDS_INVALID")
    if mcp.get("authority")!=MCP_AUTHORITY or mcp.get("externalCertificationPass") is not True or mcp.get("allRequiredChecksPass") is not True or mcp.get("certifiedClientCount")!=4:
        raise RuntimeError("MCP_EXTERNAL_INTEROP_AUTHORITY_INVALID")
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
    provider_refs=set(); execution_ids=set(); evidence_digests=set(); receipt_digests=set(); challenge_digests=set(); request_id_owners={}
    for row in clients:
        client=str(row.get("clientId") or "")
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
        mcp_contract.validate_server_audit_witness(witness,binding,client,"MCP_EXTERNAL_INTEROP_SERVER_WITNESS",oauth_client_id)
        execution_ids.add(execution_id); evidence_digests.add(evidence_digest); receipt_digests.add(receipt_digest); challenge_digests.add(challenge_digest)

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
