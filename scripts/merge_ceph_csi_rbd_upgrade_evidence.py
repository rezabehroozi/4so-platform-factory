#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path

AUTH="CEPH_CSI_RBD_RUNTIME_UPGRADE_MATRIX_V1"
ROW_AUTH="CEPH_CSI_RBD_RUNTIME_UPGRADE_EVIDENCE_V1"
VERSIONS={"1.34.11","1.35.8"}
REQUIRED=("historicalReady","upgradeApplyPass","targetReady","driverIdentityPreserved","generatedDeploymentIdentityPreserved","generatedDaemonSetIdentityPreserved","targetSpecReadbackVerified","generatedImagesDigestPinned","targetReapplyConverged","reverseEdgeRejected","semanticNoopSourceRender")

def load(path:Path)->dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size<=0: raise RuntimeError(f"CEPH_RBD_EVIDENCE_PATH_INVALID {path}")
    value=json.loads(path.read_text())
    if not isinstance(value,dict): raise RuntimeError("CEPH_RBD_EVIDENCE_NOT_OBJECT")
    return value

def verify_row(r:dict)->None:
    if r.get("authority")!=ROW_AUTH or r.get("component")!="ceph-csi-rbd" or (r.get("fromRelease"),r.get("toRelease"))!=("1.0.3","1.0.4") or r.get("kubernetesVersion") not in VERSIONS:
        raise RuntimeError("CEPH_RBD_UPGRADE_ROW_IDENTITY_INVALID")
    if not all(r.get(k) is True for k in REQUIRED): raise RuntimeError("CEPH_RBD_UPGRADE_ROW_INCOMPLETE")
    if r.get("genericKubernetesRuntimeEvidenceOnly") is not True or any(r.get(k) is not False for k in ("rke2Certified","productTopologyHACertified","physicalCertified")):
        raise RuntimeError("CEPH_RBD_UPGRADE_ROW_SCOPE_INFLATED")
    if not str(r.get("sourceRunId") or "").isdigit() or len(str(r.get("sourceCommitSHA") or ""))!=40:
        raise RuntimeError("CEPH_RBD_UPGRADE_ROW_SOURCE_INVALID")

def merge(artifact_dir:Path,out:Path)->dict:
    rows=[load(p) for p in sorted(artifact_dir.rglob("ceph-csi-rbd-upgrade-*.json"))]
    for r in rows: verify_row(r)
    if len(rows)!=2 or {r["kubernetesVersion"] for r in rows}!=VERSIONS or len({r["sourceRunId"] for r in rows})!=1 or len({r["sourceCommitSHA"] for r in rows})!=1:
        raise RuntimeError("CEPH_RBD_UPGRADE_MATRIX_COVERAGE_INVALID")
    doc={"apiVersion":"platform.4so.io/v1alpha1","kind":"CephCSIRBDRuntimeUpgradeMatrixEvidence","authority":AUTH,"component":"ceph-csi-rbd","fromRelease":"1.0.3","toRelease":"1.0.4","sourceRunId":rows[0]["sourceRunId"],"sourceCommitSHA":rows[0]["sourceCommitSHA"],"matrix":sorted(rows,key=lambda x:x["kubernetesVersion"]),"matrixPass":True,"genericKubernetesRuntimeEvidenceOnly":True,"rke2Certified":False,"productTopologyHACertified":False,"physicalCertified":False}
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n");return doc

def update_registry(path:Path,evidence:dict)->dict:
    reg=load(path);row=next((r for r in reg.get("components") or [] if r.get("component")=="ceph-csi-rbd"),None)
    if not row or row.get("pendingEdges")!=[{"fromRelease":"1.0.3","toRelease":"1.0.4"}]: raise RuntimeError("CEPH_RBD_REGISTRY_PENDING_EDGE_INVALID")
    row["executedEdges"]=[{"fromRelease":"1.0.3","toRelease":"1.0.4","authority":AUTH,"evidencePath":"lab/ceph-csi-rbd-upgrade-runtime-matrix-evidence.json","sourceRunId":evidence["sourceRunId"],"kubernetesVersions":["1.34.11","1.35.8"],"genericKubernetesRuntimeEvidenceOnly":True,"rke2Certified":False,"physicalCertified":False}]
    row["pendingEdges"]=[];row["status"]="runtime-evidence-complete";row["runtimeUpgradeCertified"]=not bool(row.get("runtimeSuitabilityHeld"))
    rows=reg.get("components") or []
    reg["summary"]["componentsWithAnyRuntimeEvidence"]=sum(bool(x.get("executedEdges")) for x in rows)
    reg["summary"]["fullyRuntimeUpgradeCertifiedComponents"]=sum(x.get("runtimeUpgradeCertified") is True for x in rows)
    reg["summary"]["pendingRuntimeEdges"]=sum(len(x.get("pendingEdges") or []) for x in rows)
    path.write_text(json.dumps(reg,indent=2,sort_keys=True)+"\n");return reg

def main()->int:
    p=argparse.ArgumentParser();p.add_argument("--artifacts",type=Path,required=True);p.add_argument("--out",type=Path,default=Path("lab/ceph-csi-rbd-upgrade-runtime-matrix-evidence.json"));p.add_argument("--registry",type=Path,default=Path("catalog/component-runtime-upgrade-evidence.json"));a=p.parse_args()
    ev=merge(a.artifacts,a.out);update_registry(a.registry,ev);print("CEPH_CSI_RBD_UPGRADE_EVIDENCE_MERGE_PASS");return 0
if __name__=="__main__":raise SystemExit(main())
