#!/usr/bin/env python3
"""Seal verified management external-image acquisition locks into a Git-safe receipt.

OCI layout bytes remain external artifact inputs. This receipt proves the exact
release/plan/image identities observed by the owner CLI but never substitutes
for the final management workload OCI archive.
"""
from __future__ import annotations
import argparse, hashlib, json, os, stat
from pathlib import Path

AUTHORITY="MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_RECEIPT_V1"
LOCK_AUTHORITY="MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_V2"
ROLES=("forgejo","keycloak","postgresql","zot")

def sha(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
    return "sha256:"+h.hexdigest()

def regular(path: Path, label: str) -> Path:
    st=path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise RuntimeError(f"{label}_NOT_REGULAR {path}")
    return path

def seal(stage: Path, release: Path, plan: Path, out: Path, run_id: str) -> dict:
    release=regular(release,"RELEASE")
    plan=regular(plan,"PLAN")
    rows=[]
    release_digest=sha(release)
    plan_digest=sha(plan)
    for role in ROLES:
        lock=regular(stage/role/"acquisition-lock.json","ACQUISITION_LOCK")
        d=json.loads(lock.read_text())
        if d.get("authority")!=LOCK_AUTHORITY or d.get("role")!=role:
            raise RuntimeError(f"MANAGEMENT_EXTERNAL_LOCK_IDENTITY_INVALID {role}")
        if d.get("releaseArtifactDigest")!=release_digest or d.get("planDigest")!=plan_digest:
            raise RuntimeError(f"MANAGEMENT_EXTERNAL_LOCK_RELEASE_PLAN_DRIFT {role}")
        exact=str(d.get("exactReference") or "")
        manifest=str(d.get("manifestDigest") or "")
        if exact != str(d.get("sourceRepository") or "")+"@"+manifest:
            raise RuntimeError(f"MANAGEMENT_EXTERNAL_LOCK_REFERENCE_INVALID {role}")
        rows.append({
            "role":role,
            "sourceRepository":d["sourceRepository"],
            "sourceTag":d["sourceTag"],
            "selectedVersion":d["selectedVersion"],
            "exactReference":exact,
            "manifestDigest":manifest,
            "tagRootDigest":d["tagRootDigest"],
            "reachableBytes":d["reachableBytes"],
            "lockSha256":sha(lock),
        })
    value={
        "apiVersion":"platform.4so.io/v1alpha1",
        "kind":"ManagementWorkloadExternalImageReceipt",
        "authority":AUTHORITY,
        "schemaVersion":1,
        "releaseArtifactDigest":release_digest,
        "planDigest":plan_digest,
        "sourceRunId":str(run_id),
        "offlineVerified":True,
        "archiveReady":False,
        "runtimeCertified":False,
        "physicalCertified":False,
        "images":rows,
    }
    out.parent.mkdir(parents=True,exist_ok=True)
    if out.is_symlink(): raise RuntimeError("MANAGEMENT_EXTERNAL_RECEIPT_OUTPUT_SYMLINK_FORBIDDEN")
    tmp=out.with_suffix(out.suffix+".tmp")
    tmp.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
    os.replace(tmp,out)
    return value

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--stage",required=True,type=Path)
    p.add_argument("--release",required=True,type=Path)
    p.add_argument("--plan",default="lab/management-workload-image-build-plan.json",type=Path)
    p.add_argument("--out",default="lab/management-workload-external-image-receipt.json",type=Path)
    p.add_argument("--run-id",default="")
    a=p.parse_args()
    try:
        value=seal(a.stage,a.release,a.plan,a.out,a.run_id)
    except Exception as exc:
        print(f"MANAGEMENT_EXTERNAL_IMAGE_RECEIPT_BLOCKED {exc}")
        return 1
    print(f"MANAGEMENT_EXTERNAL_IMAGE_RECEIPT_PASS images={len(value['images'])} release={value['releaseArtifactDigest']}")
    return 0
if __name__=="__main__": raise SystemExit(main())
