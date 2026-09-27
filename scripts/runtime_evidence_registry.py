#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,re
from pathlib import Path

SHA256=re.compile(r"^sha256:[0-9a-f]{64}$")
REGISTRY_AUTH="COMPONENT_RUNTIME_UPGRADE_EVIDENCE_REGISTRY_V1"
OC_AUTH="OC_MIRROR_DISCONNECTED_TRANSPORT_REALISM_V1"

def load(path:Path)->dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size<=0:
        raise RuntimeError(f"RUNTIME_EVIDENCE_PATH_INVALID {path}")
    return json.loads(path.read_text(encoding="utf-8"))

def verify_oc_mirror(root:Path)->dict:
    evidence=load(root/"lab/oc-mirror-disconnected-transport-evidence.json")
    lock=load(root/"lab/managed-okd-oc-mirror-source-lock.json")
    external=load(root/"lab/management-workload-external-image-receipt.json")
    if evidence.get("authority")!=OC_AUTH or evidence.get("kind")!="OcMirrorDisconnectedTransportEvidence":
        raise RuntimeError("OC_MIRROR_TRANSPORT_AUTHORITY_INVALID")
    if evidence.get("targetOKDRelease")!=lock.get("targetOKDRelease"):
        raise RuntimeError("OC_MIRROR_TRANSPORT_RELEASE_DRIFT")
    be=lock.get("binaryEvidence") or {}
    if evidence.get("ocMirrorBinarySha256")!=be.get("binarySha256") or evidence.get("ocMirrorSourceCommitSHA")!=lock.get("upstreamCommitSHA"):
        raise RuntimeError("OC_MIRROR_TRANSPORT_BINARY_BINDING_INVALID")
    zot=next((x for x in external.get("images",[]) if x.get("role")=="zot"),None)
    if not zot or evidence.get("sourceImage")!=zot.get("exactReference"):
        raise RuntimeError("OC_MIRROR_TRANSPORT_SOURCE_IMAGE_DRIFT")
    if evidence.get("destinationRegistryAuthority")!="zot":
        raise RuntimeError("OC_MIRROR_TRANSPORT_REGISTRY_AUTHORITY_INVALID")
    required=("destinationTLSVerified","diskToMirrorPass","registryDigestReadbackPass","transportRealismPass")
    if any(evidence.get(k) is not True for k in required):
        raise RuntimeError("OC_MIRROR_TRANSPORT_REALISM_INCOMPLETE")
    if any(evidence.get(k) is not False for k in ("fullDisconnectedOKDInstallCertified","runtimeCertified","physicalCertified")):
        raise RuntimeError("OC_MIRROR_TRANSPORT_SCOPE_INFLATED")
    if not SHA256.fullmatch(str(evidence.get("mirrorArchiveInventoryDigest") or "")) or int(evidence.get("mirrorArchiveFileCount") or 0)<=0:
        raise RuntimeError("OC_MIRROR_TRANSPORT_ARCHIVE_EVIDENCE_INVALID")
    return evidence

def edge_key(row:dict)->tuple[str,str]:
    return str(row.get("fromRelease") or ""),str(row.get("toRelease") or "")

def verify_upgrade_registry(root:Path)->dict:
    reg=load(root/"catalog/component-runtime-upgrade-evidence.json")
    matrix=load(root/"catalog/component-runtime-upgrade-matrix.json")
    gateway=load(root/"lab/gateway-api-upgrade-runtime-matrix-evidence.json")
    snapshot=load(root/"lab/snapshot-controller-upgrade-runtime-matrix-evidence.json")
    if reg.get("authority")!=REGISTRY_AUTH or reg.get("kind")!="ComponentRuntimeUpgradeEvidenceRegistry" or reg.get("schemaVersion")!=1:
        raise RuntimeError("RUNTIME_UPGRADE_EVIDENCE_REGISTRY_AUTHORITY_INVALID")
    expected_policy={
      "sourcePairAdmissionDoesNotEqualRuntimePass":True,
      "everyAdmittedEdgeRequiresExecutionEvidence":True,
      "genericKubernetesEvidenceDoesNotImplyRKE2Certification":True,
      "runtimeSuitabilityHoldPreventsCertification":True,
      "physicalPassInference":False,
    }
    if reg.get("policy")!=expected_policy:
        raise RuntimeError("RUNTIME_UPGRADE_EVIDENCE_POLICY_INVALID")
    matrix_rows={r["component"]:r for r in matrix.get("components",[]) if isinstance(r,dict)}
    rows={r["component"]:r for r in reg.get("components",[]) if isinstance(r,dict)}
    if set(rows)!=set(matrix_rows):
        raise RuntimeError("RUNTIME_UPGRADE_EVIDENCE_COVERAGE_INVALID")
    pending_total=0; any_evidence=0; full=0
    for name,m in matrix_rows.items():
        r=rows[name]
        if r.get("targetRelease")!=m.get("targetRelease") or r.get("physicalCertified") is not False:
            raise RuntimeError(f"RUNTIME_UPGRADE_EVIDENCE_TARGET_DRIFT {name}")
        admitted={edge_key(e) for e in m.get("admittedEdges",[])}
        executed={edge_key(e) for e in r.get("executedEdges",[])}
        pending={edge_key(e) for e in r.get("pendingEdges",[])}
        if m.get("status")=="install-only-first-product-release":
            if name!="secure-namespace-foundation" or r.get("status")!="install-only-first-product-release" or executed or pending or r.get("runtimeUpgradeCertified") is not False:
                raise RuntimeError("RUNTIME_UPGRADE_FIRST_RELEASE_EVIDENCE_INVALID")
            continue
        if executed & pending or executed|pending != admitted:
            raise RuntimeError(f"RUNTIME_UPGRADE_EDGE_ACCOUNTING_INVALID {name}")
        if executed: any_evidence+=1
        pending_total+=len(pending)
        should_full=bool(admitted) and not pending and not bool(r.get("runtimeSuitabilityHeld"))
        if r.get("runtimeUpgradeCertified") is not should_full:
            raise RuntimeError(f"RUNTIME_UPGRADE_CERTIFICATION_SCOPE_INVALID {name}")
        if should_full: full+=1
        expected_status="partial-runtime-evidence" if executed and pending else "runtime-evidence-complete" if executed else "pending-runtime-evidence"
        if r.get("status")!=expected_status:
            raise RuntimeError(f"RUNTIME_UPGRADE_EVIDENCE_STATUS_INVALID {name}")
        if name=="gateway-api":
            if gateway.get("authority")!="GATEWAY_API_RUNTIME_UPGRADE_MATRIX_V1" or gateway.get("matrixPass") is not True:
                raise RuntimeError("GATEWAY_RUNTIME_UPGRADE_EVIDENCE_INVALID")
            expected={(gateway.get("fromRelease"),gateway.get("toRelease"))}
            if executed!=expected:
                raise RuntimeError("GATEWAY_RUNTIME_UPGRADE_EDGE_BINDING_INVALID")
            if gateway.get("rke2Certified") is not False or gateway.get("productTopologyHACertified") is not False or gateway.get("physicalCertified") is not False:
                raise RuntimeError("GATEWAY_RUNTIME_UPGRADE_SCOPE_INFLATED")
            for e in r.get("executedEdges",[]):
                if e.get("authority")!="GATEWAY_API_RUNTIME_UPGRADE_MATRIX_V1" or e.get("sourceRunId")!=gateway.get("sourceRunId") or e.get("evidencePath")!="lab/gateway-api-upgrade-runtime-matrix-evidence.json" or e.get("genericKubernetesRuntimeEvidenceOnly") is not True or e.get("rke2Certified") is not False or e.get("physicalCertified") is not False:
                    raise RuntimeError("GATEWAY_RUNTIME_UPGRADE_REGISTRY_BINDING_INVALID")
                if sorted(e.get("kubernetesVersions") or [])!=["1.34.11","1.35.8"]:
                    raise RuntimeError("GATEWAY_RUNTIME_UPGRADE_MATRIX_COVERAGE_INVALID")
        elif name=="snapshot-controller":
            if snapshot.get("authority")!="SNAPSHOT_CONTROLLER_RUNTIME_UPGRADE_MATRIX_V1" or snapshot.get("matrixPass") is not True:
                raise RuntimeError("SNAPSHOT_RUNTIME_UPGRADE_EVIDENCE_INVALID")
            expected={(snapshot.get("fromRelease"),snapshot.get("toRelease"))}
            if executed!=expected:
                raise RuntimeError("SNAPSHOT_RUNTIME_UPGRADE_EDGE_BINDING_INVALID")
            if snapshot.get("genericKubernetesRuntimeEvidenceOnly") is not True or snapshot.get("rke2Certified") is not False or snapshot.get("productTopologyHACertified") is not False or snapshot.get("physicalCertified") is not False:
                raise RuntimeError("SNAPSHOT_RUNTIME_UPGRADE_SCOPE_INFLATED")
            versions=sorted(str(x.get("kubernetesVersion") or "") for x in snapshot.get("matrix") or [])
            if versions!=["1.34.11","1.35.8"] or not all(x.get("oldReady") and x.get("upgradeApplyPass") and x.get("targetReady") and x.get("deploymentIdentityPreserved") and x.get("targetReapplyConverged") and x.get("reverseEdgeRejected") for x in snapshot.get("matrix") or []):
                raise RuntimeError("SNAPSHOT_RUNTIME_UPGRADE_MATRIX_COVERAGE_INVALID")
            for e in r.get("executedEdges",[]):
                if e.get("authority")!="SNAPSHOT_CONTROLLER_RUNTIME_UPGRADE_MATRIX_V1" or e.get("sourceRunId")!=snapshot.get("sourceRunId") or e.get("evidencePath")!="lab/snapshot-controller-upgrade-runtime-matrix-evidence.json" or e.get("genericKubernetesRuntimeEvidenceOnly") is not True or e.get("rke2Certified") is not False or e.get("physicalCertified") is not False:
                    raise RuntimeError("SNAPSHOT_RUNTIME_UPGRADE_REGISTRY_BINDING_INVALID")
                if sorted(e.get("kubernetesVersions") or [])!=["1.34.11","1.35.8"]:
                    raise RuntimeError("SNAPSHOT_RUNTIME_UPGRADE_REGISTRY_COVERAGE_INVALID")
        elif executed:
            raise RuntimeError(f"UNSUPPORTED_RUNTIME_UPGRADE_EVIDENCE_CLAIM {name}")
    summary=reg.get("summary") or {}
    expected_summary={"components":len(rows),"upgradeApplicableComponents":sum(1 for r in rows.values() if r.get("status")!="install-only-first-product-release"),"componentsWithAnyRuntimeEvidence":any_evidence,"fullyRuntimeUpgradeCertifiedComponents":full,"pendingRuntimeEdges":pending_total}
    if summary!=expected_summary:
        raise RuntimeError("RUNTIME_UPGRADE_EVIDENCE_SUMMARY_DRIFT")
    return reg

def verify_all(root:Path)->dict:
    return {"ocMirror":verify_oc_mirror(root),"upgradeRegistry":verify_upgrade_registry(root)}

def main()->int:
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,default=Path(__file__).resolve().parents[1]);a=p.parse_args()
    out=verify_all(a.root.resolve())
    print(f"RUNTIME_EVIDENCE_REGISTRY_PASS pendingEdges={out['upgradeRegistry']['summary']['pendingRuntimeEdges']}")
    return 0
if __name__=="__main__": raise SystemExit(main())
