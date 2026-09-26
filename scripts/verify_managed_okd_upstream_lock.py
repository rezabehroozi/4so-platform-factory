#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, re
from pathlib import Path
from urllib.parse import urlsplit

AUTHORITY="MANAGED_OKD_UPSTREAM_TOOLCHAIN_LOCK_V1"
SHA=re.compile(r"^[0-9a-f]{64}$")
EXACT=re.compile(r"^4\.19\.0-okd-scos\.[0-9]+$")


def verify(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0 or path.stat().st_size > 256*1024:
        raise RuntimeError("MANAGED_OKD_TOOLCHAIN_LOCK_FILE_INVALID")
    doc=json.loads(path.read_text(encoding="utf-8"))
    if doc.get("authority")!=AUTHORITY or doc.get("schemaVersion")!=1 or doc.get("kind")!="ManagedOKDUpstreamToolchainLock":
        raise RuntimeError("MANAGED_OKD_TOOLCHAIN_LOCK_AUTHORITY_INVALID")
    exact=str(doc.get("exactRelease") or "")
    if not EXACT.fullmatch(exact) or doc.get("productTargetVersion")!="4.19.0" or doc.get("distribution")!="okd-scos":
        raise RuntimeError("MANAGED_OKD_TOOLCHAIN_LOCK_RELEASE_INVALID")
    expected_roles={"openshift-install","oc-client"}
    rows=doc.get("artifacts")
    if not isinstance(rows,list) or {r.get("role") for r in rows if isinstance(r,dict)}!=expected_roles:
        raise RuntimeError("MANAGED_OKD_TOOLCHAIN_LOCK_ARTIFACT_COVERAGE_INVALID")
    for row in rows:
        allowed={"role","name","url","sha256","sizeBytes","githubAssetId"}
        if set(row)!=allowed:
            raise RuntimeError("MANAGED_OKD_TOOLCHAIN_LOCK_ARTIFACT_FIELDS_INVALID")
        name=str(row["name"]); url=str(row["url"]); sha=str(row["sha256"])
        p=urlsplit(url)
        if p.scheme!="https" or p.netloc!="github.com" or p.query or p.fragment or p.username or p.password:
            raise RuntimeError("MANAGED_OKD_TOOLCHAIN_LOCK_ARTIFACT_URL_INVALID")
        prefix=f"/okd-project/okd/releases/download/{exact}/"
        if not p.path.startswith(prefix) or p.path.rsplit("/",1)[-1]!=name or "latest" in url.lower():
            raise RuntimeError("MANAGED_OKD_TOOLCHAIN_LOCK_ARTIFACT_RELEASE_BINDING_INVALID")
        if not SHA.fullmatch(sha) or not isinstance(row["sizeBytes"],int) or row["sizeBytes"]<=0 or not isinstance(row["githubAssetId"],int) or row["githubAssetId"]<=0:
            raise RuntimeError("MANAGED_OKD_TOOLCHAIN_LOCK_ARTIFACT_DIGEST_INVALID")
    payload=doc.get("releasePayload") or {}
    payload_ref=str(payload.get("reference") or "")
    payload_digest=str(payload.get("digest") or "")
    if payload_ref!="quay.io/okd/scos-release@sha256:d6a4b74886326bd2196bd834f8351a4e142a9ffd278beef1b56f5da9cdb772e2" or payload_digest!="sha256:d6a4b74886326bd2196bd834f8351a4e142a9ffd278beef1b56f5da9cdb772e2" or payload.get("source")!="github-release-body":
        raise RuntimeError("MANAGED_OKD_RELEASE_PAYLOAD_IDENTITY_INVALID")
    if doc.get("machineOS")!={"name":"CentOS Stream CoreOS","version":"9.0.20250827-0"}:
        raise RuntimeError("MANAGED_OKD_MACHINE_OS_IDENTITY_INVALID")
    pending=doc.get("pendingAuthorities")
    pending_ids={r.get("id") for r in pending if isinstance(r,dict)} if isinstance(pending,list) else set()
    machine=doc.get("machineOSArtifact")
    if machine is None:
        if pending_ids!={"fcos","agent-iso-workspace","oc-mirror-v2"}:
            raise RuntimeError("MANAGED_OKD_TOOLCHAIN_LOCK_PENDING_SET_INVALID")
    else:
        if pending_ids!={"agent-iso-workspace","oc-mirror-v2"}:
            raise RuntimeError("MANAGED_OKD_TOOLCHAIN_LOCK_PENDING_SET_INVALID")
        installer_sha=next(r["sha256"] for r in rows if r["role"]=="openshift-install")
        required={"authority":"MANAGED_OKD_MACHINE_OS_DISCOVERY_V1","distribution":"okd-scos","architecture":"x86_64","artifactClass":"metal","streamRelease":"9.0.20250827-0","sourceAuthority":"openshift-install-coreos-print-stream-json","sourceInstallerSHA256":installer_sha,"byteVerified":True}
        if any(machine.get(k)!=v for k,v in required.items()) or machine.get("role")!="disk" or "raw" not in str(machine.get("format") or "") or not SHA.fullmatch(str(machine.get("sha256") or "")) or not isinstance(machine.get("sizeBytes"),int) or machine["sizeBytes"]<=0:
            raise RuntimeError("MANAGED_OKD_MACHINE_OS_ARTIFACT_INVALID")
        mp=urlsplit(str(machine.get("location") or ""))
        if mp.scheme!="https" or not mp.hostname or mp.username or mp.password or mp.query or mp.fragment:
            raise RuntimeError("MANAGED_OKD_MACHINE_OS_ARTIFACT_URL_INVALID")
    if doc.get("connectedToolchainReady") is not True:
        raise RuntimeError("MANAGED_OKD_CONNECTED_TOOLCHAIN_MUST_BE_READY")
    if any(doc.get(k) is not False for k in ("managedInstallContentReady","disconnectedToolchainReady","runtimeCertified","physicalCertified")):
        raise RuntimeError("MANAGED_OKD_TOOLCHAIN_CLAIM_SCOPE_INFLATED")
    return doc


def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--lock",type=Path,default=Path("lab/managed-okd-upstream-toolchain-lock.json")); p.add_argument("--self-test",action="store_true")
    a=p.parse_args(); doc=verify(a.lock)
    print("MANAGED_OKD_UPSTREAM_TOOLCHAIN_LOCK_PASS exactRelease=%s artifacts=%d contentReady=%s disconnectedReady=%s" % (doc["exactRelease"],len(doc["artifacts"]),str(doc["managedInstallContentReady"]).lower(),str(doc["disconnectedToolchainReady"]).lower()))
    return 0
if __name__=="__main__": raise SystemExit(main())
