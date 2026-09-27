#!/usr/bin/env python3
"""Diagnose exact Helm render drift without weakening source-lock admission.

Runs the checked-in chart repeatedly with the exact acquisition toolchain and
reports only structural JSON paths whose rendered values differ. This is a
diagnostic authority, never runtime certification and never a source-lock rewrite.
"""
from __future__ import annotations
import argparse, json, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import acquire_upstream_helm as helm_acq
import upstream_acquisition_toolchain as tools

AUTHORITY="EXACT_HELM_RENDER_DRIFT_DIAGNOSTIC_V1"

def diff(a,b,path="$",out=None):
    out=[] if out is None else out
    if type(a) is not type(b):
        out.append({"path":path,"kind":"type","aType":type(a).__name__,"bType":type(b).__name__}); return out
    if isinstance(a,dict):
        for k in sorted(set(a)|set(b)):
            p=f"{path}.{k}"
            if k not in a: out.append({"path":p,"kind":"missing-a"})
            elif k not in b: out.append({"path":p,"kind":"missing-b"})
            else: diff(a[k],b[k],p,out)
    elif isinstance(a,list):
        if len(a)!=len(b):
            out.append({"path":path,"kind":"length","a":len(a),"b":len(b)})
        for i,(x,y) in enumerate(zip(a,b)): diff(x,y,f"{path}[{i}]",out)
    elif a!=b:
        # Do not emit potentially secret/generated values; structural path is enough.
        out.append({"path":path,"kind":"value"})
    return out

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--component",required=True); p.add_argument("--release",required=True)
    p.add_argument("--kube-version",required=True); p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    base=ROOT/"catalog"/"runtime"/a.component/a.release
    lock=json.loads((base/"source-lock.json").read_text())
    if lock.get("component")!=a.component or str(lock.get("version"))!=a.release or lock.get("sourceType")!="helm-chart":
        raise SystemExit("HELM_DRIFT_SOURCE_LOCK_INVALID")
    generation=lock.get("generation") or {}
    if a.kube_version not in (generation.get("kubernetesRenderDigests") or {}):
        raise SystemExit("HELM_DRIFT_KUBERNETES_RENDER_NOT_ADMITTED")
    with tempfile.TemporaryDirectory(prefix="4so-helm-drift-") as td:
        d=Path(td); tools.bootstrap(d/"tools")
        resolved=tools.require_toolchain(tool_dir=d/"tools")
        helm_acq.HELM_BIN=str(resolved["helm"][0]); helm_acq.CRANE_BIN=str(resolved["crane"][0])
        env=helm_acq.helm_env(d/"helm-home")
        renders=[helm_acq.render_chart(base/"artifact.bin",str(generation.get("namespace") or "default"),a.kube_version,[],env) for _ in range(3)]
    diffs=[]
    for i in range(1,len(renders)):
        diffs.extend(diff(renders[0],renders[i],f"$run0-vs-run{i}"))
    paths=sorted({x["path"].split("]",1)[-1] if "]" in x["path"] else x["path"] for x in diffs})
    doc={"apiVersion":"platform.4so.io/v1alpha1","kind":"ExactHelmRenderDriftDiagnostic","authority":AUTHORITY,
         "component":a.component,"release":a.release,"kubernetesVersion":a.kube_version,
         "helmVersion":resolved["helm"][1],"runCount":3,"deterministic":not bool(diffs),
         "differenceCount":len(diffs),"differencePaths":paths[:200],
         "runtimeCertified":False,"physicalCertified":False}
    a.out.parent.mkdir(parents=True,exist_ok=True); a.out.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n")
    print(json.dumps(doc,sort_keys=True))
    return 0
if __name__=="__main__": raise SystemExit(main())
