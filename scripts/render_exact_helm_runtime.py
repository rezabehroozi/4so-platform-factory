#!/usr/bin/env python3
"""Render one exact historical/current Helm runtime source from checked-in bytes.

Raw Helm output is admitted only when it matches the Kubernetes render digest
recorded in that exact source lock. Image references are then digest-pinned with
the exact locked crane tool. Runtime normalization is intentionally separate and
owned by cmd/runtime-normalize-list.
"""
from __future__ import annotations
import argparse, copy, hashlib, json, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import acquire_upstream_helm as helm_acq
import upstream_acquisition_toolchain as tools

AUTHORITY="EXACT_HELM_RUNTIME_RENDER_V1"

def sha(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
    return "sha256:"+h.hexdigest()

def render(component:str,release:str,kube_version:str,out:Path,evidence:Path)->dict:
    base=ROOT/"catalog"/"runtime"/component/release
    lock_path=base/"source-lock.json"; chart=base/"artifact.bin"
    if lock_path.is_symlink() or chart.is_symlink() or not lock_path.is_file() or not chart.is_file():
        raise RuntimeError("EXACT_RUNTIME_SOURCE_FILES_INVALID")
    lock=json.loads(lock_path.read_text())
    if lock.get("component")!=component or str(lock.get("version"))!=release or lock.get("sourceType")!="helm-chart" or lock.get("networkFetchRequired") is not False or lock.get("upstreamVerification")!="sha256-pinned-offline":
        raise RuntimeError("EXACT_RUNTIME_SOURCE_LOCK_INVALID")
    if sha(chart)!=lock.get("upstreamArtifactDigest"):
        raise RuntimeError("EXACT_RUNTIME_ARTIFACT_DIGEST_DRIFT")
    generation=lock.get("generation") or {}
    expected=(generation.get("kubernetesRenderDigests") or {}).get(kube_version)
    if not expected:
        raise RuntimeError("EXACT_RUNTIME_KUBERNETES_RENDER_NOT_ADMITTED")
    with tempfile.TemporaryDirectory(prefix="4so-runtime-tools-") as td:
        tool_dir=Path(td)
        tools.bootstrap(tool_dir)
        resolved=tools.require_toolchain(tool_dir=tool_dir)
        helm_acq.HELM_BIN=str(resolved["helm"][0])
        helm_acq.CRANE_BIN=str(resolved["crane"][0])
        env=helm_acq.helm_env(tool_dir/"helm-home")
        raw=helm_acq.render_chart(chart,str(generation.get("namespace") or "default"),kube_version,[],env)
        raw_digest="sha256:"+hashlib.sha256(helm_acq.canonical_resources(raw)).hexdigest()
        if raw_digest!=expected:
            raise RuntimeError(f"EXACT_RUNTIME_RENDER_DIGEST_DRIFT expected={expected} actual={raw_digest}")
        pinned=copy.deepcopy(raw)
        images=sorted(helm_acq.pin_images(pinned,helm_acq.crane_digest))
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps({"apiVersion":"v1","kind":"List","items":pinned},indent=2,sort_keys=True)+"\n")
        doc={"apiVersion":"platform.4so.io/v1alpha1","kind":"ExactHelmRuntimeRenderEvidence","authority":AUTHORITY,"component":component,"release":release,"kubernetesVersion":kube_version,"sourceLockSha256":sha(lock_path),"artifactSha256":sha(chart),"rawRenderDigest":raw_digest,"pinnedRenderSha256":sha(out),"images":images,"helmVersion":resolved["helm"][1],"craneVersion":resolved["crane"][1],"networkSourceFetchRequired":False}
        evidence.parent.mkdir(parents=True,exist_ok=True); evidence.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n")
        return doc

def main()->int:
    p=argparse.ArgumentParser();p.add_argument("--component",required=True);p.add_argument("--release",required=True);p.add_argument("--kube-version",required=True);p.add_argument("--out",type=Path,required=True);p.add_argument("--evidence",type=Path,required=True);a=p.parse_args()
    d=render(a.component,a.release,a.kube_version,a.out,a.evidence)
    print(f"EXACT_HELM_RUNTIME_RENDER_PASS component={d['component']} release={d['release']} raw={d['rawRenderDigest']} images={len(d['images'])}");return 0
if __name__=="__main__":raise SystemExit(main())
