#!/usr/bin/env python3
"""Build the deterministic V8 appliance acquisition input-pack from exact staged bytes."""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, stat, zipfile
from pathlib import Path, PurePosixPath

AUTHORITY="LAB_APPLIANCE_INPUT_PACK_BUILD_V1"
LOCK_AUTHORITY="LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8"
ARCHIVE_AUTHORITY="MANAGEMENT_WORKLOAD_OCI_ARCHIVE_RECEIPT_V1"
ZERO="sha256:"+"0"*64

def load(path:Path)->dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size<=0:
        raise RuntimeError(f"INPUT_AUTHORITY_FILE_INVALID {path}")
    v=json.loads(path.read_text())
    if not isinstance(v,dict): raise RuntimeError(f"INPUT_AUTHORITY_NOT_OBJECT {path}")
    return v

def digest(path:Path)->tuple[str,int]:
    if path.is_symlink() or not path.is_file(): raise RuntimeError(f"STAGED_ARTIFACT_INVALID {path}")
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest(),path.stat().st_size

def image_map(doc:dict,key:str)->dict[str,str]:
    rows=doc.get(key)
    if not isinstance(rows,list): raise RuntimeError("IMAGE_RECEIPT_ROWS_INVALID")
    out={}
    for r in rows:
        role=str(r.get("role") or ""); ref=str(r.get("exactReference") or "")
        if not role or "@sha256:" not in ref or role in out: raise RuntimeError("IMAGE_RECEIPT_IDENTITY_INVALID")
        out[role]=ref
    return out

def authorities(root:Path)->tuple[dict,dict,dict,dict]:
    lock=load(root/"lab/appliance-bundle-acquisition-lock.json")
    archive=load(root/"lab/management-workload-oci-archive-receipt.json")
    ext=load(root/"lab/management-workload-external-image-receipt.json")
    prod=load(root/"lab/management-workload-product-image-receipt.json")
    if lock.get("authority")!=LOCK_AUTHORITY or lock.get("status")!="incomplete" or lock.get("inputPack") is not None or lock.get("missingAuthorities")!=[]:
        raise RuntimeError("INPUT_PACK_LOCK_STATE_INVALID")
    partial=lock.get("partialAuthorities") or []
    if len(partial)!=1 or partial[0].get("id")!="management-workload-oci-archive":
        raise RuntimeError("INPUT_PACK_ARCHIVE_PARTIAL_STATE_INVALID")
    if archive.get("authority")!=ARCHIVE_AUTHORITY or archive.get("archiveBuilt") is not True or archive.get("distributionReady") is not False:
        raise RuntimeError("INPUT_PACK_ARCHIVE_RECEIPT_INVALID")
    if archive.get("releaseVersion")!=lock.get("releaseVersion"):
        raise RuntimeError("INPUT_PACK_RELEASE_VERSION_DRIFT")
    return lock,archive,ext,prod

def build_spec(root:Path)->dict:
    lock,archive,ext,prod=authorities(root)
    resolved={r["id"]:r for r in lock["resolvedAuthorities"]}
    required={"rke2-installer-and-offline-artifacts","argocd-install-manifest","argocd-ha-install-manifest","cloudnative-pg-install-manifest","replicated-storage-install-manifest"}
    if set(resolved)!=required: raise RuntimeError("INPUT_PACK_RESOLVED_AUTHORITY_SET_INVALID")
    bindings=[]
    for authority in lock["resolvedAuthorities"]:
        for a in authority["artifacts"]:
            bindings.append({"path":a["stagingPath"],"sha256":"sha256:"+a["sha256"],"sizeBytes":a["sizeBytes"]})
    bindings.append({"path":"workloads/platform-workloads.oci.tar","sha256":archive["archiveSha256"],"sizeBytes":archive["archiveBytes"]})
    bindings=sorted(bindings,key=lambda x:x["path"])
    ex=image_map(ext,"images"); pr=image_map(prod,"productImages")
    if set(ex)!={"forgejo","keycloak","postgresql","zot"} or set(pr)!={"maintenance","platform-agent","platform-api","platform-probe"}:
        raise RuntimeError("INPUT_PACK_CORE_IMAGE_ROLE_SET_INVALID")
    return {
      "apiVersion":"platform.4so.io/v1alpha1","kind":"ApplianceBundleBuild",
      "metadata":{"version":lock["releaseVersion"],"sourceReleaseDigest":ZERO},
      "spec":{
        "sourceArtifacts":bindings,
        "rke2":{"version":resolved["rke2-installer-and-offline-artifacts"]["version"],"installer":"rke2/install.sh","installArtifacts":["rke2/rke2.linux-amd64.tar.gz","rke2/sha256sum-amd64.txt"],"imageArchives":["rke2/rke2-images.linux-amd64.tar.zst"]},
        "workloads":{"imageArchives":["workloads/platform-workloads.oci.tar"],"postgresqlImage":ex["postgresql"],"platformApiImage":pr["platform-api"],"forgejoImage":ex["forgejo"],"zotImage":ex["zot"],"keycloakImage":ex["keycloak"],"maintenanceImage":pr["maintenance"],"gitOpsManifest":"manifests/argocd-install.yaml","gitOpsHAManifest":"manifests/argocd-ha-install.yaml","cloudNativePGManifest":"manifests/cloudnative-pg-install.yaml","storageManifest":"manifests/replicated-storage-install.yaml","fleetAgentImage":pr["platform-agent"],"runtimeProbeImage":pr["platform-probe"]}
      }
    }

def validate_staging(staging:Path,spec:dict)->None:
    expected={b["path"]:(b["sha256"].removeprefix("sha256:"),b["sizeBytes"]) for b in spec["spec"]["sourceArtifacts"]}
    actual=[]
    for p in staging.rglob("*"):
        if p.is_symlink(): raise RuntimeError("INPUT_PACK_STAGING_SYMLINK_FORBIDDEN")
        if p.is_file(): actual.append(p.relative_to(staging).as_posix())
    if set(actual)!=set(expected): raise RuntimeError(f"INPUT_PACK_STAGING_COVERAGE_INVALID missing={sorted(set(expected)-set(actual))} extra={sorted(set(actual)-set(expected))}")
    for rel,(sha,size) in expected.items():
        got,got_size=digest(staging/rel)
        if got!=sha or got_size!=size: raise RuntimeError(f"INPUT_PACK_STAGED_ARTIFACT_DRIFT {rel}")

def write_pack(staging:Path,spec:dict,out:Path)->dict:
    validate_staging(staging,spec)
    out.parent.mkdir(parents=True,exist_ok=True)
    if out.exists() or out.is_symlink(): raise RuntimeError("INPUT_PACK_OUTPUT_EXISTS")
    spec_raw=(json.dumps(spec,indent=2,sort_keys=True)+"\n").encode()
    entries=[("build-spec.json",None)]
    for b in spec["spec"]["sourceArtifacts"]:
        rel=b["path"]; entries.append(("staging/"+rel,staging/rel))
    with zipfile.ZipFile(out,"w",compression=zipfile.ZIP_STORED,allowZip64=True) as z:
        for name,source in sorted(entries,key=lambda row:row[0]):
            pp=PurePosixPath(name)
            if ".." in pp.parts or name.startswith("/"): raise RuntimeError("INPUT_PACK_MEMBER_PATH_INVALID")
            i=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0)); i.create_system=3; i.external_attr=(stat.S_IFREG|0o644)<<16; i.compress_type=zipfile.ZIP_STORED
            if source is None:
                z.writestr(i,spec_raw)
            else:
                i.file_size=source.stat().st_size
                with source.open("rb") as src, z.open(i,"w",force_zip64=True) as dst:
                    shutil.copyfileobj(src,dst,length=4*1024*1024)
    sha,size=digest(out)
    return {"apiVersion":"platform.4so.io/v1alpha1","kind":"ApplianceInputPackReceipt","authority":AUTHORITY,"releaseVersion":spec["metadata"]["version"],"inputPackSha256":"sha256:"+sha,"inputPackBytes":size,"format":"zip","buildSpecPath":"build-spec.json","stagingDirectory":"staging","deterministicZip":True,"distributionReady":False,"runtimeCertified":False,"physicalCertified":False}

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--root",type=Path,default=Path(__file__).resolve().parents[1]); p.add_argument("--staging",type=Path,required=True); p.add_argument("--out",type=Path,required=True); p.add_argument("--receipt",type=Path); a=p.parse_args()
    spec=build_spec(a.root.resolve()); receipt=write_pack(a.staging.resolve(),spec,a.out.resolve())
    if a.receipt:
        a.receipt.parent.mkdir(parents=True,exist_ok=True); a.receipt.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
