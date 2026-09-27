#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,os
from pathlib import Path

AUTH="HELM_COMPONENT_RUNTIME_UPGRADE_MATRIX_V1"
ROW_AUTH="HELM_COMPONENT_RUNTIME_UPGRADE_EVIDENCE_V1"
PROFILES={"argocd":("10.2.2","10.2.3"),"capsule":("0.13.10","0.13.11"),"external-secrets":("2.7.0","2.8.0"),"metallb":("0.16.0","0.16.1"),"victoria-metrics":("0.90.1","0.90.2")}
VERSIONS={"1.34.11","1.35.8"}
REQUIRED=("historicalReady","upgradeApplyPass","targetReady","workloadIdentityPreserved","targetImagesVerified","targetReapplyConverged","reverseEdgeRejected")

def load(path:Path)->dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size<=0: raise RuntimeError(f"HELM_UPGRADE_EVIDENCE_PATH_INVALID {path}")
    return json.loads(path.read_text())

def verify_row(r:dict)->None:
    c=r.get("component")
    if r.get("authority")!=ROW_AUTH or c not in PROFILES: raise RuntimeError("HELM_UPGRADE_ROW_AUTHORITY_INVALID")
    f,t=PROFILES[c]
    if (r.get("fromRelease"),r.get("toRelease"))!=(f,t) or r.get("kubernetesVersion") not in VERSIONS:
        raise RuntimeError(f"HELM_UPGRADE_ROW_IDENTITY_INVALID {c}")
    if not all(r.get(k) is True for k in REQUIRED): raise RuntimeError(f"HELM_UPGRADE_ROW_INCOMPLETE {c}")
    if r.get("genericKubernetesRuntimeEvidenceOnly") is not True or any(r.get(k) is not False for k in ("rke2Certified","productTopologyHACertified","physicalCertified")):
        raise RuntimeError(f"HELM_UPGRADE_ROW_SCOPE_INFLATED {c}")
    if not str(r.get("sourceRunId") or "").isdigit() or len(str(r.get("sourceCommitSHA") or ""))!=40:
        raise RuntimeError(f"HELM_UPGRADE_ROW_SOURCE_IDENTITY_INVALID {c}")

def component_from_rows(c:str,rows:list[dict])->dict:
    for r in rows: verify_row(r)
    if {r["kubernetesVersion"] for r in rows}!=VERSIONS or len(rows)!=2:
        raise RuntimeError(f"HELM_UPGRADE_COMPONENT_COVERAGE_INVALID {c}")
    if {r["sourceRunId"] for r in rows}.__len__()!=1 or {r["sourceCommitSHA"] for r in rows}.__len__()!=1:
        raise RuntimeError(f"HELM_UPGRADE_COMPONENT_SOURCE_DRIFT {c}")
    f,t=PROFILES[c]
    return {"component":c,"fromRelease":f,"toRelease":t,"sourceRunId":rows[0]["sourceRunId"],"sourceCommitSHA":rows[0]["sourceCommitSHA"],"matrix":sorted(rows,key=lambda x:x["kubernetesVersion"]),"matrixPass":True}

def merge(existing_path:Path,artifact_dir:Path,out:Path)->dict:
    components={}
    if existing_path.is_file():
        old=load(existing_path)
        if old.get("authority")!=AUTH or old.get("mergeAuthority")!="component-scoped-incremental": raise RuntimeError("HELM_UPGRADE_EXISTING_AUTHORITY_INVALID")
        for c in old.get("components") or []:
            components[c["component"]]=component_from_rows(c["component"],c["matrix"])
    incoming=[]
    if artifact_dir.exists():
        for p in sorted(artifact_dir.rglob("*-upgrade-*.json")):
            incoming.append(load(p))
    for c in PROFILES:
        rows=[r for r in incoming if r.get("component")==c]
        if not rows: continue
        # A component is promotable only when both exact Kubernetes shards from
        # the same run/commit completed. Partial shards never erase older proof.
        if {r.get("kubernetesVersion") for r in rows}==VERSIONS and len(rows)==2:
            components[c]=component_from_rows(c,rows)
    doc={"apiVersion":"platform.4so.io/v1alpha1","kind":"HelmComponentUpgradeRuntimeMatrixEvidence","authority":AUTH,"mergeAuthority":"component-scoped-incremental","components":[components[k] for k in sorted(components)],"matrixPass":bool(components),"genericKubernetesRuntimeEvidenceOnly":True,"rke2Certified":False,"productTopologyHACertified":False,"physicalCertified":False}
    out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n")
    return doc

def update_registry(registry_path:Path,evidence:dict)->dict:
    reg=load(registry_path)
    by={c["component"]:c for c in evidence["components"]}
    for row in reg.get("components") or []:
        c=row.get("component")
        if c not in by: continue
        ev=by[c]
        row["status"]="runtime-evidence-complete"
        row["executedEdges"]=[{"fromRelease":ev["fromRelease"],"toRelease":ev["toRelease"],"authority":AUTH,"evidencePath":"lab/helm-component-upgrade-runtime-matrix-evidence.json","sourceRunId":ev["sourceRunId"],"kubernetesVersions":["1.34.11","1.35.8"],"genericKubernetesRuntimeEvidenceOnly":True,"rke2Certified":False,"physicalCertified":False}]
        row["pendingEdges"]=[]
        row["runtimeUpgradeCertified"]=not bool(row.get("runtimeSuitabilityHeld"))
    rows=reg.get("components") or []
    reg["summary"]["componentsWithAnyRuntimeEvidence"]=sum(bool(x.get("executedEdges")) for x in rows)
    reg["summary"]["fullyRuntimeUpgradeCertifiedComponents"]=sum(x.get("runtimeUpgradeCertified") is True for x in rows)
    reg["summary"]["pendingRuntimeEdges"]=sum(len(x.get("pendingEdges") or []) for x in rows)
    registry_path.write_text(json.dumps(reg,indent=2,sort_keys=True)+"\n")
    return reg

def main()->int:
    p=argparse.ArgumentParser();p.add_argument("--existing",type=Path,default=Path("lab/helm-component-upgrade-runtime-matrix-evidence.json"));p.add_argument("--artifacts",type=Path,required=True);p.add_argument("--out",type=Path,default=Path("lab/helm-component-upgrade-runtime-matrix-evidence.json"));p.add_argument("--registry",type=Path,default=Path("catalog/component-runtime-upgrade-evidence.json"));a=p.parse_args()
    doc=merge(a.existing,a.artifacts,a.out); update_registry(a.registry,doc)
    print("HELM_COMPONENT_UPGRADE_EVIDENCE_MERGE_PASS components="+",".join(x["component"] for x in doc["components"]));return 0
if __name__=="__main__":raise SystemExit(main())
