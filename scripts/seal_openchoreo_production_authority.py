#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, ipaddress, json
from pathlib import Path
from openchoreo_runtime_contract import (
    ACQUISITION_AUTHORITY, SOURCE_AUTHORITY, UPSTREAM_COMMIT,
    UPSTREAM_REPOSITORY, VERSION, admit_output_path,
    registry_identity_from_reference,
)

EVIDENCE_AUTHORITY="OPENCHOREO_PRODUCTION_ZOT_SEAL_EVIDENCE_V1"
READBACK_AUTHORITY="OPENCHOREO_PRODUCTION_ZOT_READBACK_EVIDENCE_V1"
SELECTION_KIND="OpenChoreoRuntimeSourceSelection"
DIGEST_KEYS=("chartSha256","valuesSha256","renderManifestSha256")

def load(path:Path,label:str)->dict:
    path=path.expanduser()
    info=path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_size<=0 or info.st_size>16*1024*1024:
        raise RuntimeError(f"{label}_FILE_INVALID")
    value=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value,dict):
        raise RuntimeError(f"{label}_NOT_OBJECT")
    return value

def sha256(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""):
            h.update(block)
    return "sha256:"+h.hexdigest()

def production_registry(identity:str)->str:
    value=str(identity or "").strip().lower()
    if not value or "/" in value or "://" in value:
        raise RuntimeError("OPENCHOREO_PRODUCTION_REGISTRY_IDENTITY_INVALID")
    host=value.rsplit(":",1)[0] if ":" in value else value
    if host=="localhost" or host.endswith(".localhost"):
        raise RuntimeError("OPENCHOREO_PRODUCTION_REGISTRY_EPHEMERAL_FORBIDDEN")
    try:
        ip=ipaddress.ip_address(host)
    except ValueError:
        ip=None
    if ip is not None and (ip.is_loopback or ip.is_unspecified):
        raise RuntimeError("OPENCHOREO_PRODUCTION_REGISTRY_EPHEMERAL_FORBIDDEN")
    return value

def plane_map(rows:list[dict])->dict[str,dict]:
    out={}
    for row in rows:
        if not isinstance(row,dict):
            raise RuntimeError("OPENCHOREO_PRODUCTION_PLANE_INVALID")
        name=str(row.get("name") or "")
        if name in out or name not in {"control-plane","data-plane"}:
            raise RuntimeError("OPENCHOREO_PRODUCTION_PLANE_INVALID")
        out[name]=row
    if set(out)!={"control-plane","data-plane"}:
        raise RuntimeError("OPENCHOREO_PRODUCTION_PLANE_INVALID")
    return out

def promote(runtime_path:Path, acquisition_path:Path, selection_path:Path, expected_registry:str, out_selection:Path, evidence_out:Path, readback_path:Path)->dict:
    runtime=load(runtime_path,"OPENCHOREO_RUNTIME_SOURCE")
    acquisition=load(acquisition_path,"OPENCHOREO_ACQUISITION_RECEIPT")
    selection=load(selection_path,"OPENCHOREO_SOURCE_SELECTION")
    expected_registry=production_registry(expected_registry)

    if acquisition.get("authority")!=ACQUISITION_AUTHORITY or acquisition.get("sourceAuthority")!=SOURCE_AUTHORITY:
        raise RuntimeError("OPENCHOREO_PRODUCTION_ACQUISITION_AUTHORITY_INVALID")
    for key,expected in (("version",VERSION),("upstreamRepository",UPSTREAM_REPOSITORY),("upstreamCommit",UPSTREAM_COMMIT)):
        if acquisition.get(key)!=expected:
            raise RuntimeError(f"OPENCHOREO_PRODUCTION_ACQUISITION_IDENTITY_INVALID {key}")

    required={"authority":SOURCE_AUTHORITY,"version":VERSION,"upstreamRepository":UPSTREAM_REPOSITORY,"upstreamCommit":UPSTREAM_COMMIT,
      "resolved":True,"mirrorReady":True,"buildAuthority":"buildkit","registryAuthority":"zot","externalOidcRequired":True,
      "backstageEnabled":False,"workflowPlaneEnabled":False,"observabilityPlaneEnabled":False,"openChoreoMcpEnabled":False}
    for key,expected in required.items():
        if runtime.get(key)!=expected:
            raise RuntimeError(f"OPENCHOREO_PRODUCTION_RUNTIME_IDENTITY_INVALID {key}")

    registry=production_registry(runtime.get("registryIdentity"))
    if registry!=expected_registry:
        raise RuntimeError("OPENCHOREO_PRODUCTION_REGISTRY_EXPECTATION_MISMATCH")
    if runtime.get("sourceArchiveSha256")!=acquisition.get("sourceArchiveSha256"):
        raise RuntimeError("OPENCHOREO_PRODUCTION_SOURCE_ARCHIVE_MISMATCH")

    acq_planes=plane_map(acquisition.get("planes") or [])
    run_planes=plane_map(runtime.get("planes") or [])
    for name in sorted(acq_planes):
        for key in ("chartRepository","chartName","chartVersion",*DIGEST_KEYS):
            if run_planes[name].get(key)!=acq_planes[name].get(key):
                raise RuntimeError(f"OPENCHOREO_PRODUCTION_PLANE_MISMATCH {name}:{key}")

    acquired={}
    for row in acquisition.get("images") or []:
        source=str(row.get("sourceReference") or "")
        digest=str(row.get("digest") or "").lower()
        if source in acquired or not source.endswith("@"+digest):
            raise RuntimeError("OPENCHOREO_PRODUCTION_ACQUISITION_IMAGE_INVALID")
        acquired[source]=digest

    mirrored={}
    for row in runtime.get("images") or []:
        source=str(row.get("sourceReference") or "")
        digest=str(row.get("digest") or "").lower()
        target=str(row.get("mirrorReference") or "")
        if acquired.get(source)!=digest or source in mirrored or not target.endswith("@"+digest):
            raise RuntimeError("OPENCHOREO_PRODUCTION_IMAGE_MISMATCH")
        if registry_identity_from_reference(target,"OPENCHOREO_PRODUCTION_MIRROR")!=registry:
            raise RuntimeError("OPENCHOREO_PRODUCTION_IMAGE_REGISTRY_MISMATCH")
        mirrored[source]=digest
    if mirrored!=acquired or len(mirrored)!=6:
        raise RuntimeError("OPENCHOREO_PRODUCTION_IMAGE_COVERAGE_INVALID")

    executor_ref=str(runtime.get("executorImageReference") or "")
    executor_digest=str(runtime.get("executorImageDigest") or "").lower()
    if not executor_ref.endswith("@"+executor_digest) or registry_identity_from_reference(executor_ref,"OPENCHOREO_PRODUCTION_EXECUTOR")!=registry or "/openchoreo-runtime@" not in executor_ref:
        raise RuntimeError("OPENCHOREO_PRODUCTION_EXECUTOR_INVALID")

    readback=load(readback_path,"OPENCHOREO_PRODUCTION_ZOT_READBACK")
    if readback.get("authority")!=READBACK_AUTHORITY or readback.get("runtimeSourceAuthority")!=SOURCE_AUTHORITY:
        raise RuntimeError("OPENCHOREO_PRODUCTION_ZOT_READBACK_AUTHORITY_INVALID")
    if readback.get("runtimeSourceSha256")!=sha256(runtime_path) or readback.get("registryAuthority")!="zot" or readback.get("registryIdentity")!=registry:
        raise RuntimeError("OPENCHOREO_PRODUCTION_ZOT_READBACK_BINDING_INVALID")
    if readback.get("imageCount")!=6 or readback.get("readbackCount")!=7 or readback.get("liveRegistryReadbackPass") is not True:
        raise RuntimeError("OPENCHOREO_PRODUCTION_ZOT_READBACK_INCOMPLETE")
    if readback.get("runtimeCertified") is not False or readback.get("physicalCertified") is not False:
        raise RuntimeError("OPENCHOREO_PRODUCTION_ZOT_READBACK_SCOPE_INFLATED")
    expected_readback={row["mirrorReference"]:str(row["digest"]).lower() for row in runtime.get("images") or []}
    expected_readback[executor_ref]=executor_digest
    observed={}
    for row in readback.get("references") or []:
        if not isinstance(row,dict):
            raise RuntimeError("OPENCHOREO_PRODUCTION_ZOT_READBACK_REFERENCE_INVALID")
        ref=str(row.get("reference") or ""); digest=str(row.get("digest") or "").lower()
        if ref in observed:
            raise RuntimeError("OPENCHOREO_PRODUCTION_ZOT_READBACK_REFERENCE_REUSE")
        observed[ref]=digest
    if observed!=expected_readback:
        raise RuntimeError("OPENCHOREO_PRODUCTION_ZOT_READBACK_REFERENCE_MISMATCH")

    if selection.get("apiVersion")!="platform.4so.io/v1alpha1" or selection.get("kind")!=SELECTION_KIND:
        raise RuntimeError("OPENCHOREO_PRODUCTION_SELECTION_AUTHORITY_INVALID")
    current=selection.get("spec") or {}
    for key,expected in (("authority",SOURCE_AUTHORITY),("version",VERSION),("upstreamRepository",UPSTREAM_REPOSITORY),("upstreamCommit",UPSTREAM_COMMIT)):
        if current.get(key)!=expected:
            raise RuntimeError(f"OPENCHOREO_PRODUCTION_SELECTION_IDENTITY_INVALID {key}")
    if current.get("resolved") is True and current!=runtime:
        raise RuntimeError("OPENCHOREO_PRODUCTION_SELECTION_REPLACEMENT_FORBIDDEN")

    out_selection=admit_output_path(out_selection,"OPENCHOREO_PRODUCTION_SELECTION_OUTPUT")
    evidence_out=admit_output_path(evidence_out,"OPENCHOREO_PRODUCTION_EVIDENCE_OUTPUT")
    promoted={"apiVersion":"platform.4so.io/v1alpha1","kind":SELECTION_KIND,"spec":runtime}
    out_selection.parent.mkdir(parents=True,exist_ok=True)
    tmp=out_selection.with_suffix(out_selection.suffix+".tmp")
    tmp.write_text(json.dumps(promoted,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    tmp.replace(out_selection)

    evidence={"apiVersion":"platform.4so.io/v1alpha1","kind":"OpenChoreoProductionZotSealEvidence",
      "authority":EVIDENCE_AUTHORITY,"runtimeSourceAuthority":SOURCE_AUTHORITY,
      "runtimeSourceSha256":sha256(runtime_path),"acquisitionReceiptSha256":sha256(acquisition_path),
      "sourceSelectionSha256":sha256(out_selection),"version":VERSION,"upstreamCommit":UPSTREAM_COMMIT,
      "registryAuthority":"zot","registryIdentity":registry,"imageCount":len(mirrored),
      "zotReadbackAuthority":READBACK_AUTHORITY,"zotReadbackSha256":sha256(readback_path),"liveRegistryReadbackPass":True,"liveRegistryReadbackCount":7,
      "productionSourceSealed":True,"runtimeCertified":False,"physicalCertified":False}
    evidence_out.parent.mkdir(parents=True,exist_ok=True)
    etmp=evidence_out.with_suffix(evidence_out.suffix+".tmp")
    etmp.write_text(json.dumps(evidence,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    etmp.replace(evidence_out)
    return evidence

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--runtime-source",type=Path,required=True)
    p.add_argument("--acquisition-receipt",type=Path,default=Path("lab/openchoreo-runtime-acquisition-receipt.json"))
    p.add_argument("--selection",type=Path,default=Path("runtime/openchoreo/source-selection.json"))
    p.add_argument("--expected-registry-identity",required=True)
    p.add_argument("--out-selection",type=Path,required=True)
    p.add_argument("--evidence-out",type=Path,required=True)
    p.add_argument("--registry-readback-evidence",type=Path,required=True)
    a=p.parse_args()
    try:
        out=promote(a.runtime_source,a.acquisition_receipt,a.selection,a.expected_registry_identity,a.out_selection,a.evidence_out,a.registry_readback_evidence)
    except (RuntimeError,OSError,ValueError,json.JSONDecodeError) as exc:
        print(f"OPENCHOREO_PRODUCTION_ZOT_SEAL_BLOCKED {exc}",file=__import__("sys").stderr)
        return 3
    print(json.dumps(out,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
