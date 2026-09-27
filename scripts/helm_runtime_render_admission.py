#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import acquire_upstream_helm as helm_acq
import upstream_acquisition_toolchain as tools

AUTHORITY="HELM_RUNTIME_RENDER_ADMISSION_V1"
SHA=re.compile(r"^sha256:[0-9a-f]{64}$")
KUBE=re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")

def digest(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):
            h.update(b)
    return "sha256:"+h.hexdigest()

def load_lock(component:str,release:str)->tuple[Path,Path,dict]:
    base=ROOT/"catalog"/"runtime"/component/release
    lock_path=base/"source-lock.json"; artifact=base/"artifact.bin"
    if lock_path.is_symlink() or artifact.is_symlink() or not lock_path.is_file() or not artifact.is_file():
        raise RuntimeError("HELM_RENDER_ADMISSION_SOURCE_INVALID")
    lock=json.loads(lock_path.read_text())
    if lock.get("component")!=component or str(lock.get("version"))!=release or lock.get("sourceType")!="helm-chart" or lock.get("networkFetchRequired") is not False:
        raise RuntimeError("HELM_RENDER_ADMISSION_LOCK_INVALID")
    if digest(artifact)!=lock.get("upstreamArtifactDigest"):
        raise RuntimeError("HELM_RENDER_ADMISSION_ARTIFACT_DRIFT")
    return lock_path,artifact,lock

def value_paths(generation:dict)->list[Path]:
    out=[]
    for row in generation.get("values") or []:
        if not isinstance(row,dict) or set(row)!={"path","sha256"} or not SHA.fullmatch(str(row.get("sha256") or "")):
            raise RuntimeError("HELM_RENDER_ADMISSION_VALUES_INVALID")
        p=(ROOT/str(row["path"])).resolve()
        try:
            p.relative_to(ROOT.resolve())
        except ValueError as exc:
            raise RuntimeError("HELM_RENDER_ADMISSION_VALUE_ESCAPE") from exc
        if p.is_symlink() or not p.is_file() or digest(p)!=row["sha256"]:
            raise RuntimeError("HELM_RENDER_ADMISSION_VALUE_DRIFT")
        out.append(p)
    return out

def create(component:str,release:str)->dict:
    lock_path,artifact,lock=load_lock(component,release)
    generation=lock.get("generation") or {}
    versions=generation.get("kubernetesVersions") or []
    if not isinstance(versions,list) or not versions or len(set(versions))!=len(versions) or not all(KUBE.fullmatch(str(v)) for v in versions):
        raise RuntimeError("HELM_RENDER_ADMISSION_KUBERNETES_WINDOW_INVALID")
    values=value_paths(generation)
    with tempfile.TemporaryDirectory(prefix="4so-helm-admission-") as td:
        d=Path(td); tools.bootstrap(d/"tools")
        resolved=tools.require_toolchain(tool_dir=d/"tools")
        helm_acq.HELM_BIN=str(resolved["helm"][0]); helm_acq.CRANE_BIN=str(resolved["crane"][0])
        if resolved["helm"][1] != generation.get("toolVersion"):
            raise RuntimeError("HELM_RENDER_ADMISSION_TOOL_VERSION_DRIFT")
        env=helm_acq.helm_env(d/"helm-home")
        renders={}
        for version in versions:
            rows=helm_acq.render_chart(artifact,str(generation.get("namespace") or "default"),version,values,env)
            again=helm_acq.render_chart(artifact,str(generation.get("namespace") or "default"),version,values,env)
            a="sha256:"+hashlib.sha256(helm_acq.canonical_resources(rows)).hexdigest()
            b="sha256:"+hashlib.sha256(helm_acq.canonical_resources(again)).hexdigest()
            if a!=b:
                raise RuntimeError(f"HELM_RENDER_ADMISSION_NONDETERMINISTIC {version}")
            renders[version]=a
    return {
        "apiVersion":"platform.4so.io/v1alpha1","kind":"HelmRuntimeRenderAdmission",
        "authority":AUTHORITY,"component":component,"release":release,
        "sourceLockSha256":digest(lock_path),"artifactSha256":digest(artifact),
        "helmVersion":generation.get("toolVersion"),"releaseName":generation.get("releaseName"),
        "namespace":generation.get("namespace"),"includeCRDs":generation.get("includeCRDs"),
        "kubernetesRenderDigests":renders,"networkSourceFetchRequired":False,
        "runtimeCertified":False,"physicalCertified":False,
    }

def verify(component:str,release:str,evidence:dict)->dict[str,str]:
    lock_path,artifact,lock=load_lock(component,release)
    generation=lock.get("generation") or {}
    if evidence.get("authority")!=AUTHORITY or evidence.get("component")!=component or str(evidence.get("release"))!=release:
        raise RuntimeError("HELM_RENDER_ADMISSION_IDENTITY_INVALID")
    if evidence.get("sourceLockSha256")!=digest(lock_path) or evidence.get("artifactSha256")!=digest(artifact):
        raise RuntimeError("HELM_RENDER_ADMISSION_SOURCE_BINDING_INVALID")
    if evidence.get("helmVersion")!=generation.get("toolVersion") or evidence.get("releaseName")!=generation.get("releaseName") or evidence.get("namespace")!=generation.get("namespace") or evidence.get("includeCRDs") is not True:
        raise RuntimeError("HELM_RENDER_ADMISSION_GENERATION_BINDING_INVALID")
    versions=generation.get("kubernetesVersions") or []
    renders=evidence.get("kubernetesRenderDigests") or {}
    if set(renders)!=set(versions) or any(not SHA.fullmatch(str(renders.get(v) or "")) for v in versions):
        raise RuntimeError("HELM_RENDER_ADMISSION_COVERAGE_INVALID")
    if evidence.get("networkSourceFetchRequired") is not False or evidence.get("runtimeCertified") is not False or evidence.get("physicalCertified") is not False:
        raise RuntimeError("HELM_RENDER_ADMISSION_SCOPE_INFLATED")
    return {str(k):str(v) for k,v in renders.items()}

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--component",required=True); p.add_argument("--release",required=True)
    p.add_argument("--out",type=Path); p.add_argument("--verify",type=Path)
    a=p.parse_args()
    if a.verify:
        verify(a.component,a.release,json.loads(a.verify.read_text()))
        print("HELM_RUNTIME_RENDER_ADMISSION_VERIFY_PASS")
        return 0
    doc=create(a.component,a.release)
    out=a.out or ROOT/"catalog"/"runtime"/a.component/a.release/"render-admission.json"
    out.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n")
    print(f"HELM_RUNTIME_RENDER_ADMISSION_PASS component={a.component} release={a.release} evidence={out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
