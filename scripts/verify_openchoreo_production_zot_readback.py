#!/usr/bin/env python3
"""Live digest readback gate for production OpenChoreo images in product-owned zot."""
from __future__ import annotations
import argparse,json,re,subprocess
from pathlib import Path
import acquire_upstream_helm as helm
from openchoreo_runtime_contract import SOURCE_AUTHORITY,VERSION,UPSTREAM_COMMIT,registry_identity_from_reference
from seal_openchoreo_production_authority import load,production_registry,sha256

AUTHORITY="OPENCHOREO_PRODUCTION_ZOT_READBACK_EVIDENCE_V1"
DIGEST_RE=re.compile(r"^sha256:[0-9a-f]{64}$")

def expected_refs(runtime:dict)->tuple[str,list[tuple[str,str]]]:
    if runtime.get("authority")!=SOURCE_AUTHORITY or runtime.get("version")!=VERSION or runtime.get("upstreamCommit")!=UPSTREAM_COMMIT:
        raise RuntimeError("OPENCHOREO_ZOT_READBACK_RUNTIME_IDENTITY_INVALID")
    if runtime.get("resolved") is not True or runtime.get("mirrorReady") is not True or runtime.get("registryAuthority")!="zot":
        raise RuntimeError("OPENCHOREO_ZOT_READBACK_RUNTIME_NOT_READY")
    registry=production_registry(runtime.get("registryIdentity"))
    rows=[]
    images=runtime.get("images")
    if not isinstance(images,list) or len(images)!=6:
        raise RuntimeError("OPENCHOREO_ZOT_READBACK_IMAGE_COVERAGE_INVALID")
    for row in images:
        if not isinstance(row,dict):
            raise RuntimeError("OPENCHOREO_ZOT_READBACK_IMAGE_INVALID")
        ref=str(row.get("mirrorReference") or "")
        digest=str(row.get("digest") or "").lower()
        if not DIGEST_RE.fullmatch(digest) or not ref.endswith("@"+digest):
            raise RuntimeError("OPENCHOREO_ZOT_READBACK_IMAGE_INVALID")
        if registry_identity_from_reference(ref,"OPENCHOREO_ZOT_READBACK_IMAGE")!=registry:
            raise RuntimeError("OPENCHOREO_ZOT_READBACK_REGISTRY_MISMATCH")
        rows.append((ref,digest))
    executor=str(runtime.get("executorImageReference") or "")
    executor_digest=str(runtime.get("executorImageDigest") or "").lower()
    if not DIGEST_RE.fullmatch(executor_digest) or not executor.endswith("@"+executor_digest) or "/openchoreo-runtime@" not in executor:
        raise RuntimeError("OPENCHOREO_ZOT_READBACK_EXECUTOR_INVALID")
    if registry_identity_from_reference(executor,"OPENCHOREO_ZOT_READBACK_EXECUTOR")!=registry:
        raise RuntimeError("OPENCHOREO_ZOT_READBACK_REGISTRY_MISMATCH")
    rows.append((executor,executor_digest))
    if len({ref for ref,_ in rows})!=7:
        raise RuntimeError("OPENCHOREO_ZOT_READBACK_REFERENCE_REUSE")
    return registry,rows

def verify(runtime_path:Path,digest_reader,tool_identity:str)->dict:
    runtime=load(runtime_path,"OPENCHOREO_ZOT_READBACK_RUNTIME")
    registry,refs=expected_refs(runtime)
    if not callable(digest_reader):
        raise RuntimeError("OPENCHOREO_ZOT_READBACK_READER_REQUIRED")
    tool=str(tool_identity or "").strip()
    if len(tool)<3 or len(tool)>200 or any(ord(ch)<0x20 or ord(ch)>0x7e for ch in tool):
        raise RuntimeError("OPENCHOREO_ZOT_READBACK_TOOL_INVALID")
    observed=[]
    for ref,expected in refs:
        got=str(digest_reader(ref) or "").strip().lower()
        if got!=expected:
            raise RuntimeError("OPENCHOREO_ZOT_READBACK_DIGEST_MISMATCH "+ref)
        observed.append({"reference":ref,"digest":got})
    return {"apiVersion":"platform.4so.io/v1alpha1","kind":"OpenChoreoProductionZotReadbackEvidence",
      "authority":AUTHORITY,"runtimeSourceAuthority":SOURCE_AUTHORITY,"runtimeSourceSha256":sha256(runtime_path),
      "version":VERSION,"upstreamCommit":UPSTREAM_COMMIT,"registryAuthority":"zot","registryIdentity":registry,
      "imageCount":6,"readbackCount":7,"readbackTool":tool,"liveRegistryReadbackPass":True,
      "references":observed,"runtimeCertified":False,"physicalCertified":False}

def crane_reader():
    pinned=helm.require_toolchain()
    crane=str(pinned["crane"][0])
    version=helm.tool_version([crane,"version"],"CRANE")
    def read(ref:str)->str:
        proc=subprocess.run([crane,"digest",ref],text=True,capture_output=True,timeout=300)
        if proc.returncode!=0:
            tail=(proc.stdout+"\n"+proc.stderr)[-4096:].strip()
            raise RuntimeError("OPENCHOREO_ZOT_READBACK_CRANE_FAILED "+ref+" "+tail)
        return (proc.stdout or proc.stderr).strip()
    return read,"crane:"+version

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--runtime-source",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    try:
        reader,tool=crane_reader()
        evidence=verify(a.runtime_source,reader,tool)
        if a.out.is_symlink():
            raise RuntimeError("OPENCHOREO_ZOT_READBACK_OUTPUT_SYMLINK_FORBIDDEN")
        a.out.parent.mkdir(parents=True,exist_ok=True)
        tmp=a.out.with_suffix(a.out.suffix+".tmp")
        tmp.write_text(json.dumps(evidence,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        tmp.replace(a.out)
    except (RuntimeError,OSError,ValueError,json.JSONDecodeError,subprocess.TimeoutExpired) as exc:
        print("OPENCHOREO_PRODUCTION_ZOT_READBACK_BLOCKED "+str(exc),file=__import__("sys").stderr)
        return 3
    print(json.dumps(evidence,sort_keys=True))
    return 0
if __name__=="__main__":
    raise SystemExit(main())
