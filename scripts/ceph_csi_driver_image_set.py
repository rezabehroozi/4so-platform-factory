#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,re,subprocess,tempfile,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import upstream_acquisition_toolchain as tools
INPUT_AUTH="CEPH_CSI_DRIVER_IMAGE_SET_INPUT_V1"
EVIDENCE_AUTH="CEPH_CSI_DRIVER_IMAGE_SET_V1"
SHA=re.compile(r"^sha256:[0-9a-f]{64}$")
KEYS={"provisioner","attacher","resizer","snapshotter","registrar","snapshot-metadata","plugin","addons"}
def fsha(p): return "sha256:"+hashlib.sha256(p.read_bytes()).hexdigest()
def load_input(p):
    if p.is_symlink() or not p.is_file() or p.stat().st_size<=0: raise RuntimeError("CEPH_CSI_IMAGE_SET_INPUT_PATH_INVALID")
    d=json.loads(p.read_text())
    if d.get("authority")!=INPUT_AUTH or d.get("schemaVersion")!=1 or d.get("cephCSIOperatorRelease")!="1.0.4": raise RuntimeError("CEPH_CSI_IMAGE_SET_INPUT_AUTHORITY_INVALID")
    if d.get("upstreamCommitSHA")!="29a66b683aa8873001c729b7b120e18604cdb445" or d.get("upstreamSourcePath")!="internal/controller/defaults.go": raise RuntimeError("CEPH_CSI_IMAGE_SET_UPSTREAM_BINDING_INVALID")
    rows=d.get("images")
    if not isinstance(rows,list) or {r.get("key") for r in rows if isinstance(r,dict)}!=KEYS: raise RuntimeError("CEPH_CSI_IMAGE_SET_COVERAGE_INVALID")
    for r in rows:
        ref=str(r.get("sourceReference") or "")
        if "@sha256:" in ref or ":" not in ref or "latest" in ref.lower(): raise RuntimeError("CEPH_CSI_IMAGE_SET_SOURCE_REFERENCE_INVALID")
    if d.get("networkResolutionRequired") is not True or d.get("runtimeCertified") is not False or d.get("physicalCertified") is not False: raise RuntimeError("CEPH_CSI_IMAGE_SET_INPUT_SCOPE_INVALID")
    return d
def repo_of(ref):
    slash=ref.rfind("/"); colon=ref.rfind(":")
    if colon<=slash: raise RuntimeError("CEPH_CSI_IMAGE_SET_TAG_REQUIRED")
    return ref[:colon]
def resolve(inp,out):
    src=load_input(inp)
    with tempfile.TemporaryDirectory(prefix="4so-ceph-csi-images-") as td:
        tool_dir=Path(td); tools.bootstrap(tool_dir); resolved=tools.require_toolchain(tool_dir=tool_dir)
        crane=str(resolved["crane"][0]); version=resolved["crane"][1]; rows=[]
        for item in src["images"]:
            digest=subprocess.check_output([crane,"digest",item["sourceReference"]],text=True).strip()
            if not SHA.fullmatch(digest): raise RuntimeError("CEPH_CSI_IMAGE_SET_DIGEST_INVALID "+item["key"])
            rows.append({"key":item["key"],"sourceReference":item["sourceReference"],"exactReference":repo_of(item["sourceReference"])+"@"+digest,"digest":digest})
    d={"apiVersion":"platform.4so.io/v1alpha1","kind":"CephCSIDriverImageSetEvidence","authority":EVIDENCE_AUTH,"schemaVersion":1,"inputAuthority":INPUT_AUTH,"inputSha256":fsha(inp),"cephCSIOperatorRelease":"1.0.4","upstreamCommitSHA":src["upstreamCommitSHA"],"craneVersion":version,"images":sorted(rows,key=lambda x:x["key"]),"allImagesDigestPinned":True,"runtimeCertified":False,"physicalCertified":False}
    out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(d,indent=2,sort_keys=True)+"\n"); return d
def verify(inp,out):
    src=load_input(inp)
    if out.is_symlink() or not out.is_file() or out.stat().st_size<=0: raise RuntimeError("CEPH_CSI_IMAGE_SET_EVIDENCE_PATH_INVALID")
    d=json.loads(out.read_text())
    if d.get("authority")!=EVIDENCE_AUTH or d.get("schemaVersion")!=1 or d.get("inputAuthority")!=INPUT_AUTH or d.get("inputSha256")!=fsha(inp): raise RuntimeError("CEPH_CSI_IMAGE_SET_EVIDENCE_AUTHORITY_INVALID")
    if d.get("cephCSIOperatorRelease")!="1.0.4" or d.get("upstreamCommitSHA")!=src["upstreamCommitSHA"]: raise RuntimeError("CEPH_CSI_IMAGE_SET_EVIDENCE_RELEASE_INVALID")
    source={x["key"]:x["sourceReference"] for x in src["images"]}; rows=d.get("images")
    if not isinstance(rows,list) or {x.get("key") for x in rows if isinstance(x,dict)}!=KEYS: raise RuntimeError("CEPH_CSI_IMAGE_SET_EVIDENCE_COVERAGE_INVALID")
    for row in rows:
        key=row["key"]; digest=str(row.get("digest") or "")
        if row.get("sourceReference")!=source[key] or not SHA.fullmatch(digest) or row.get("exactReference")!=repo_of(source[key])+"@"+digest: raise RuntimeError("CEPH_CSI_IMAGE_SET_EVIDENCE_BINDING_INVALID "+key)
    if d.get("allImagesDigestPinned") is not True or d.get("runtimeCertified") is not False or d.get("physicalCertified") is not False: raise RuntimeError("CEPH_CSI_IMAGE_SET_EVIDENCE_SCOPE_INVALID")
    return d
def main():
    p=argparse.ArgumentParser(); p.add_argument("--input",type=Path,default=ROOT/"catalog/runtime-dependencies/ceph-csi/1.0.4/driver-image-set-input.json"); p.add_argument("--out",type=Path,default=ROOT/"lab/ceph-csi-driver-image-set-evidence.json"); p.add_argument("--resolve",action="store_true"); p.add_argument("--verify",action="store_true"); a=p.parse_args()
    d=resolve(a.input,a.out) if a.resolve else verify(a.input,a.out) if a.verify else p.error("one of --resolve/--verify is required")
    print(f"CEPH_CSI_DRIVER_IMAGE_SET_PASS images={len(d['images'])}"); return 0
if __name__=="__main__": raise SystemExit(main())
