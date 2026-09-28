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

AUTHORITY="FINAL_EXACT_RELEASE_ADMISSION_V1"
S1_AUTHORITY="LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8"
MCP_AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROPERABILITY_EVIDENCE_V1"
CLIENTS=("chatgpt","claude","gemini","grok")
SHA=re.compile(r"^sha256:[0-9a-f]{64}$")


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
    if mcp.get("authority")!=MCP_AUTHORITY or mcp.get("externalCertificationPass") is not True or mcp.get("allRequiredChecksPass") is not True or mcp.get("certifiedClientCount")!=4:
        raise RuntimeError("MCP_EXTERNAL_INTEROP_AUTHORITY_INVALID")
    if mcp.get("serverAuditWitnessPass") is not True or mcp.get("serverAuditWitnessedCheckCount") != 24:
        raise Pending("MCP_EXTERNAL_SERVER_AUDIT_WITNESS_PENDING")
    if mcp.get("runtimeCertified") is not False or mcp.get("physicalCertified") is not False:
        raise RuntimeError("MCP_EXTERNAL_INTEROP_SCOPE_INFLATED")
    if mcp.get("campaignAuthority")!="MCP_EXTERNAL_CLIENT_INTEROP_CAMPAIGN_V1" or not SHA.fullmatch(str(mcp.get("campaignSha256") or "")):
        raise RuntimeError("MCP_EXTERNAL_INTEROP_CAMPAIGN_INVALID")
    clients=mcp.get("clients")
    if not isinstance(clients,list) or [x.get("clientId") for x in clients if isinstance(x,dict)]!=list(CLIENTS):
        raise RuntimeError("MCP_EXTERNAL_INTEROP_CLIENT_SET_INVALID")
    for row in clients:
        checks=row.get("checks")
        if not isinstance(checks,dict) or len(checks)!=7 or any(v is not True for v in checks.values()):
            raise RuntimeError("MCP_EXTERNAL_INTEROP_CHECKS_INVALID")
        if not SHA.fullmatch(str(row.get("evidenceDigest") or "")) or not SHA.fullmatch(str(row.get("externalReceiptSha256") or row.get("receiptSha256") or "")) or not SHA.fullmatch(str(row.get("challengeSha256") or "")):
            raise RuntimeError("MCP_EXTERNAL_INTEROP_RECEIPT_BINDING_INVALID")
        witness=row.get("serverAuditWitness") or {}
        if witness.get("authority")!="MCP_EXTERNAL_SERVER_AUDIT_WITNESS_V1" or witness.get("serverAuditWitnessPass") is not True or witness.get("witnessedCheckCount")!=6 or not SHA.fullmatch(str(witness.get("auditHeadDigest") or "")) or not SHA.fullmatch(str(witness.get("auditExportSha256") or "")):
            raise RuntimeError("MCP_EXTERNAL_INTEROP_SERVER_WITNESS_INVALID")

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
        print(json.dumps({"authority":AUTHORITY,"admitted":False,"pending":pending,"blockers":[{"code":pending,"detail":"required external closure evidence is not sealed on canonical main"}],"physicalCertified":False},sort_keys=True))
        return 3
    if a.out:
        a.out.parent.mkdir(parents=True,exist_ok=True); a.out.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print(json.dumps(out,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
