#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,re
from pathlib import Path
AUTHORITY="MANAGED_OKD_OC_MIRROR_V2_SOURCE_LOCK_V1"
SHA=re.compile(r"^[0-9a-f]{40}$")
def verify(path:Path)->dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size<=0 or path.stat().st_size>256*1024: raise RuntimeError("OC_MIRROR_SOURCE_LOCK_FILE_INVALID")
    d=json.loads(path.read_text(encoding="utf-8"))
    if d.get("authority")!=AUTHORITY or d.get("schemaVersion")!=1 or d.get("kind")!="ManagedOKDOcMirrorSourceLock": raise RuntimeError("OC_MIRROR_SOURCE_LOCK_AUTHORITY_INVALID")
    if d.get("targetOKDRelease")!="4.19.0-okd-scos.19" or d.get("upstreamBranch")!="release-4.19": raise RuntimeError("OC_MIRROR_SOURCE_LOCK_RELEASE_INVALID")
    sha=str(d.get("upstreamCommitSHA") or "")
    if not SHA.fullmatch(sha) or d.get("upstreamCommitURL")!=f"https://github.com/openshift/oc-mirror/commit/{sha}": raise RuntimeError("OC_MIRROR_SOURCE_LOCK_COMMIT_INVALID")
    if d.get("upstreamRepository")!="https://github.com/openshift/oc-mirror" or d.get("v2Module")!="github.com/openshift/oc-mirror/v2": raise RuntimeError("OC_MIRROR_SOURCE_LOCK_REPOSITORY_INVALID")
    if d.get("v2GoVersion")!="1.23.7" or d.get("buildTarget")!="v2/build/oc-mirror" or d.get("invocation")!=["oc-mirror","--v2"]: raise RuntimeError("OC_MIRROR_SOURCE_LOCK_BUILD_CONTRACT_INVALID")
    if d.get("sourcePinned") is not True: raise RuntimeError("OC_MIRROR_SOURCE_LOCK_NOT_PINNED")
    if any(d.get(k) is not False for k in ("binaryEvidenceReady","disconnectedToolchainReady","runtimeCertified","physicalCertified")): raise RuntimeError("OC_MIRROR_SOURCE_LOCK_SCOPE_INFLATED")
    return d
def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--lock",type=Path,default=Path("lab/managed-okd-oc-mirror-source-lock.json")); a=p.parse_args()
    d=verify(a.lock); print(f"OC_MIRROR_SOURCE_LOCK_PASS commit={d['upstreamCommitSHA']}"); return 0
if __name__=="__main__": raise SystemExit(main())
