#!/usr/bin/env python3
"""Render one exact historical/current Helm runtime source from checked-in bytes.

Normal Helm sources must reproduce the raw render digest recorded in their exact
source lock. A narrowly admitted product runtime profile may replace source
generation values only when the upstream default chart is demonstrably
non-deterministic; such profiles must prove repeated deterministic rendering
from the same exact chart bytes and product-owned values.
"""
from __future__ import annotations
import argparse, copy, hashlib, json, os, re, stat, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import acquire_upstream_helm as helm_acq
import upstream_acquisition_toolchain as tools
import helm_runtime_render_admission as render_admission

AUTHORITY="EXACT_HELM_RUNTIME_RENDER_V2"
PROFILE_AUTHORITIES={"victoria-metrics":"VICTORIA_METRICS_RUNTIME_PROFILE_V1","cilium":"CILIUM_RUNTIME_PROFILE_V1"}
SHA_RE=re.compile(r"^sha256:[0-9a-f]{64}$")

def sha(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
    return "sha256:"+h.hexdigest()

def repo_file(rel:str,label:str)->Path:
    if not rel or rel.startswith("/") or "\\" in rel:
        raise RuntimeError(f"{label}_PATH_INVALID")
    p=(ROOT/rel).resolve()
    try:p.relative_to(ROOT.resolve())
    except ValueError as exc: raise RuntimeError(f"{label}_PATH_ESCAPES_REPO") from exc
    try:st=os.lstat(p)
    except OSError as exc: raise RuntimeError(f"{label}_FILE_MISSING") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size<=0:
        raise RuntimeError(f"{label}_FILE_INVALID")
    return p

def source_values(generation:dict)->list[Path]:
    rows=generation.get("values") or []
    if not isinstance(rows,list): raise RuntimeError("EXACT_RUNTIME_SOURCE_VALUES_INVALID")
    out=[]; seen=set()
    for row in rows:
        if not isinstance(row,dict) or set(row)!={"path","sha256"}:
            raise RuntimeError("EXACT_RUNTIME_SOURCE_VALUE_ENTRY_INVALID")
        rel=str(row["path"]); expected=str(row["sha256"])
        if rel in seen or not SHA_RE.fullmatch(expected):
            raise RuntimeError("EXACT_RUNTIME_SOURCE_VALUE_ENTRY_INVALID")
        seen.add(rel)
        p=repo_file(rel,"EXACT_RUNTIME_SOURCE_VALUE")
        if sha(p)!=expected: raise RuntimeError(f"EXACT_RUNTIME_SOURCE_VALUE_DIGEST_DRIFT {rel}")
        out.append(p)
    return out

def runtime_profile(component:str,release:str,locked_values:list[Path])->tuple[dict|None,list[Path]]:
    path=ROOT/"catalog"/"runtime-profiles"/f"{component}.json"
    if not path.exists(): return None,locked_values
    if path.is_symlink() or not path.is_file(): raise RuntimeError("HELM_RUNTIME_PROFILE_FILE_INVALID")
    doc=json.loads(path.read_text())
    if doc.get("apiVersion")!="platform.4so.io/v1alpha1" or doc.get("kind")!="HelmRuntimeProfile":
        raise RuntimeError("HELM_RUNTIME_PROFILE_IDENTITY_INVALID")
    if doc.get("component")!=component or release not in (doc.get("releases") or []):
        raise RuntimeError("HELM_RUNTIME_PROFILE_RELEASE_INVALID")
    expected_authority=PROFILE_AUTHORITIES.get(component)
    if not expected_authority or doc.get("authority")!=expected_authority:
        raise RuntimeError("HELM_RUNTIME_PROFILE_AUTHORITY_INVALID")
    if doc.get("replacesSourceGenerationValues") is not True or locked_values:
        raise RuntimeError("HELM_RUNTIME_PROFILE_SOURCE_VALUE_CONFLICT")
    if doc.get("deterministicRerenderRequired") is not True or doc.get("sourceDefaultRenderDeterministic") is not False:
        raise RuntimeError("HELM_RUNTIME_PROFILE_DETERMINISM_POLICY_INVALID")
    if doc.get("runtimeCertified") is not False or doc.get("physicalCertified") is not False:
        raise RuntimeError("HELM_RUNTIME_PROFILE_SCOPE_INFLATED")
    values=repo_file(str(doc.get("valuesPath") or ""),"HELM_RUNTIME_PROFILE_VALUES")
    if sha(values)!=doc.get("valuesSha256"):
        raise RuntimeError("HELM_RUNTIME_PROFILE_VALUES_DIGEST_DRIFT")
    if component=="cilium":
        text=values.read_text(encoding="utf-8")
        if doc.get("hubbleTLSAutoMethod")!="cronJob" or "method: cronJob" not in text:
            raise RuntimeError("CILIUM_RUNTIME_PROFILE_TLS_METHOD_INVALID")
    if component=="victoria-metrics":
        if doc.get("fullnameOverride")!="vmstack":
            raise RuntimeError("VICTORIA_METRICS_RUNTIME_PROFILE_NAME_OVERRIDE_INVALID")
        text=values.read_text(encoding="utf-8")
        if not re.search(r"(?m)^fullnameOverride:\s*vmstack\s*$",text):
            raise RuntimeError("VICTORIA_METRICS_RUNTIME_PROFILE_NAME_OVERRIDE_MISSING")
    return doc,[values]

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
    source_digest_matrix=generation.get("kubernetesRenderDigests") or {}
    digest_matrix=dict(source_digest_matrix)
    admission_authority=""
    admission_digest=""
    admission_override=False
    admission_path=base/"render-admission.json"
    if admission_path.is_file():
        admission=json.loads(admission_path.read_text())
        admission_matrix=render_admission.verify(component,release,admission)
        if not digest_matrix:
            digest_matrix=admission_matrix
            admission_authority=render_admission.AUTHORITY
            admission_digest=sha(admission_path)
        elif admission.get("sourceGenerationDrift") is True:
            if admission.get("sourceGenerationRenderDigests") != source_digest_matrix:
                raise RuntimeError("EXACT_RUNTIME_RENDER_ADMISSION_SOURCE_MATRIX_DRIFT")
            digest_matrix=admission_matrix
            admission_authority=render_admission.AUTHORITY
            admission_digest=sha(admission_path)
            admission_override=True
    expected=digest_matrix.get(kube_version)
    if not expected or not SHA_RE.fullmatch(str(expected)):
        raise RuntimeError("EXACT_RUNTIME_KUBERNETES_RENDER_NOT_ADMITTED")
    locked_values=source_values(generation)
    profile,values=runtime_profile(component,release,locked_values)
    with tempfile.TemporaryDirectory(prefix="4so-runtime-tools-") as td:
        tool_dir=Path(td)
        tools.bootstrap(tool_dir)
        resolved=tools.require_toolchain(tool_dir=tool_dir)
        helm_acq.HELM_BIN=str(resolved["helm"][0])
        helm_acq.CRANE_BIN=str(resolved["crane"][0])
        env=helm_acq.helm_env(tool_dir/"helm-home")
        raw=helm_acq.render_chart(chart,str(generation.get("namespace") or "default"),kube_version,values,env)
        raw_digest="sha256:"+hashlib.sha256(helm_acq.canonical_resources(raw)).hexdigest()
        source_compared=profile is None and not admission_override
        rerender_verified=False
        if profile is None:
            if raw_digest!=expected:
                raise RuntimeError(f"EXACT_RUNTIME_RENDER_DIGEST_DRIFT expected={expected} actual={raw_digest}")
        else:
            for _ in range(2):
                again=helm_acq.render_chart(chart,str(generation.get("namespace") or "default"),kube_version,values,env)
                again_digest="sha256:"+hashlib.sha256(helm_acq.canonical_resources(again)).hexdigest()
                if again_digest!=raw_digest:
                    raise RuntimeError(f"HELM_RUNTIME_PROFILE_NONDETERMINISTIC expected={raw_digest} actual={again_digest}")
            rerender_verified=True
        pinned=copy.deepcopy(raw)
        images=sorted(helm_acq.pin_images(pinned,helm_acq.crane_digest))
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps({"apiVersion":"v1","kind":"List","items":pinned},indent=2,sort_keys=True)+"\n")
        profile_path=ROOT/"catalog"/"runtime-profiles"/f"{component}.json"
        doc={"apiVersion":"platform.4so.io/v1alpha1","kind":"ExactHelmRuntimeRenderEvidence","authority":AUTHORITY,"component":component,"release":release,"kubernetesVersion":kube_version,"sourceLockSha256":sha(lock_path),"artifactSha256":sha(chart),"sourceGenerationRenderDigest":expected,"sourceGenerationDigestCompared":source_compared,"rawRenderDigest":raw_digest,"pinnedRenderSha256":sha(out),"images":images,"helmVersion":resolved["helm"][1],"craneVersion":resolved["crane"][1],"networkSourceFetchRequired":False,"runtimeProfileAuthority":profile.get("authority") if profile else "","runtimeProfileSha256":sha(profile_path) if profile else "","runtimeValuesSha256":[sha(v) for v in values],"deterministicRerenderVerified":rerender_verified,"renderAdmissionAuthority":admission_authority,"renderAdmissionSha256":admission_digest,"sourceGenerationDriftAdmitted":admission_override}
        evidence.parent.mkdir(parents=True,exist_ok=True); evidence.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n")
        return doc

def main()->int:
    p=argparse.ArgumentParser();p.add_argument("--component",required=True);p.add_argument("--release",required=True);p.add_argument("--kube-version",required=True);p.add_argument("--out",type=Path,required=True);p.add_argument("--evidence",type=Path,required=True);a=p.parse_args()
    d=render(a.component,a.release,a.kube_version,a.out,a.evidence)
    print(f"EXACT_HELM_RUNTIME_RENDER_PASS component={d['component']} release={d['release']} raw={d['rawRenderDigest']} images={len(d['images'])}");return 0
if __name__=="__main__":raise SystemExit(main())
