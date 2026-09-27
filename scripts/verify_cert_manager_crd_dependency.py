#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,re
from pathlib import Path
from urllib.parse import urlsplit

AUTHORITY="CERT_MANAGER_CRD_RUNTIME_DEPENDENCY_LOCK_V1"
SHA=re.compile(r"^[0-9a-f]{64}$")
CRD_KIND=re.compile(r"(?m)^kind:\s*CustomResourceDefinition\s*$")
def crd_names(raw:str)->set[str]:
    names=set()
    for doc in raw.split("\n---"):
        if not CRD_KIND.search(doc):
            continue
        lines=doc.splitlines()
        for i,line in enumerate(lines):
            if line.strip()!="metadata:":
                continue
            for nxt in lines[i+1:i+12]:
                stripped=nxt.strip()
                if stripped.startswith("name:"):
                    names.add(stripped.split(":",1)[1].strip().strip("\\"'"))
                    break
            break
    return names
EXPECTED={
 "certificates.cert-manager.io","certificaterequests.cert-manager.io",
 "issuers.cert-manager.io","clusterissuers.cert-manager.io",
 "orders.acme.cert-manager.io","challenges.acme.cert-manager.io",
}

def digest(path:Path)->tuple[str,int]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size<=0:
        raise RuntimeError(f"CERT_MANAGER_CRD_FILE_INVALID {path}")
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest(),path.stat().st_size

def verify(root:Path,require_bytes:bool=False)->dict:
    path=root/"catalog/runtime-dependencies/cert-manager/crd-runtime-dependency-lock.json"
    if path.is_symlink() or not path.is_file(): raise RuntimeError("CERT_MANAGER_CRD_LOCK_FILE_INVALID")
    d=json.loads(path.read_text(encoding="utf-8"))
    if d.get("authority")!=AUTHORITY or d.get("schemaVersion")!=1 or d.get("kind")!="CertManagerCRDRuntimeDependencyLock" or d.get("component")!="cert-manager":
        raise RuntimeError("CERT_MANAGER_CRD_LOCK_AUTHORITY_INVALID")
    if d.get("expectedCRDs")!=sorted(EXPECTED):
        raise RuntimeError("CERT_MANAGER_CRD_EXPECTED_SET_INVALID")
    rows=d.get("assets")
    if not isinstance(rows,list) or [x.get("release") for x in rows]!=["1.21.0","1.21.1"]:
        raise RuntimeError("CERT_MANAGER_CRD_RELEASE_COVERAGE_INVALID")
    for row in rows:
        release=row["release"]; url=str(row.get("url") or ""); p=urlsplit(url)
        expected_path=f"catalog/runtime-dependencies/cert-manager/{release}/cert-manager.crds.yaml"
        if row.get("name")!="cert-manager.crds.yaml" or row.get("path")!=expected_path:
            raise RuntimeError("CERT_MANAGER_CRD_PATH_INVALID")
        if p.scheme!="https" or p.netloc!="github.com" or p.path!=f"/cert-manager/cert-manager/releases/download/v{release}/cert-manager.crds.yaml" or p.query or p.fragment:
            raise RuntimeError("CERT_MANAGER_CRD_URL_INVALID")
        if not SHA.fullmatch(str(row.get("sha256") or "")) or row.get("sizeBytes")!=997110:
            raise RuntimeError("CERT_MANAGER_CRD_DIGEST_IDENTITY_INVALID")
        target=root/expected_path
        if require_bytes:
            got,size=digest(target)
            if got!=row["sha256"] or size!=row["sizeBytes"]:
                raise RuntimeError(f"CERT_MANAGER_CRD_BYTE_DRIFT {release}")
            raw=target.read_text(encoding="utf-8")
            if len(CRD_KIND.findall(raw))!=6:
                raise RuntimeError(f"CERT_MANAGER_CRD_RESOURCE_COUNT_INVALID {release}")
            names=crd_names(raw)
            if names!=EXPECTED:
                raise RuntimeError(f"CERT_MANAGER_CRD_RESOURCE_IDENTITY_INVALID {release}")
    if d.get("bytesRequiredForRuntime") is not True or d.get("runtimeCertified") is not False or d.get("physicalCertified") is not False:
        raise RuntimeError("CERT_MANAGER_CRD_LOCK_SCOPE_INFLATED")
    return d

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--root",type=Path,default=Path(__file__).resolve().parents[1]); p.add_argument("--require-bytes",action="store_true"); a=p.parse_args()
    d=verify(a.root.resolve(),a.require_bytes)
    print(f"CERT_MANAGER_CRD_DEPENDENCY_PASS assets={len(d['assets'])} bytes={str(a.require_bytes).lower()}")
    return 0
if __name__=="__main__": raise SystemExit(main())
'')
EXPECTED={
 "certificates.cert-manager.io","certificaterequests.cert-manager.io",
 "issuers.cert-manager.io","clusterissuers.cert-manager.io",
 "orders.acme.cert-manager.io","challenges.acme.cert-manager.io",
}

def digest(path:Path)->tuple[str,int]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size<=0:
        raise RuntimeError(f"CERT_MANAGER_CRD_FILE_INVALID {path}")
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest(),path.stat().st_size

def verify(root:Path,require_bytes:bool=False)->dict:
    path=root/"catalog/runtime-dependencies/cert-manager/crd-runtime-dependency-lock.json"
    if path.is_symlink() or not path.is_file(): raise RuntimeError("CERT_MANAGER_CRD_LOCK_FILE_INVALID")
    d=json.loads(path.read_text(encoding="utf-8"))
    if d.get("authority")!=AUTHORITY or d.get("schemaVersion")!=1 or d.get("kind")!="CertManagerCRDRuntimeDependencyLock" or d.get("component")!="cert-manager":
        raise RuntimeError("CERT_MANAGER_CRD_LOCK_AUTHORITY_INVALID")
    if d.get("expectedCRDs")!=sorted(EXPECTED):
        raise RuntimeError("CERT_MANAGER_CRD_EXPECTED_SET_INVALID")
    rows=d.get("assets")
    if not isinstance(rows,list) or [x.get("release") for x in rows]!=["1.21.0","1.21.1"]:
        raise RuntimeError("CERT_MANAGER_CRD_RELEASE_COVERAGE_INVALID")
    for row in rows:
        release=row["release"]; url=str(row.get("url") or ""); p=urlsplit(url)
        expected_path=f"catalog/runtime-dependencies/cert-manager/{release}/cert-manager.crds.yaml"
        if row.get("name")!="cert-manager.crds.yaml" or row.get("path")!=expected_path:
            raise RuntimeError("CERT_MANAGER_CRD_PATH_INVALID")
        if p.scheme!="https" or p.netloc!="github.com" or p.path!=f"/cert-manager/cert-manager/releases/download/v{release}/cert-manager.crds.yaml" or p.query or p.fragment:
            raise RuntimeError("CERT_MANAGER_CRD_URL_INVALID")
        if not SHA.fullmatch(str(row.get("sha256") or "")) or row.get("sizeBytes")!=997110:
            raise RuntimeError("CERT_MANAGER_CRD_DIGEST_IDENTITY_INVALID")
        target=root/expected_path
        if require_bytes:
            got,size=digest(target)
            if got!=row["sha256"] or size!=row["sizeBytes"]:
                raise RuntimeError(f"CERT_MANAGER_CRD_BYTE_DRIFT {release}")
            raw=target.read_text(encoding="utf-8")
            if len(CRD_KIND.findall(raw))!=6:
                raise RuntimeError(f"CERT_MANAGER_CRD_RESOURCE_COUNT_INVALID {release}")
            names={x for x in CRD_NAME.findall(raw) if x in EXPECTED}
            if names!=EXPECTED:
                raise RuntimeError(f"CERT_MANAGER_CRD_RESOURCE_IDENTITY_INVALID {release}")
    if d.get("bytesRequiredForRuntime") is not True or d.get("runtimeCertified") is not False or d.get("physicalCertified") is not False:
        raise RuntimeError("CERT_MANAGER_CRD_LOCK_SCOPE_INFLATED")
    return d

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--root",type=Path,default=Path(__file__).resolve().parents[1]); p.add_argument("--require-bytes",action="store_true"); a=p.parse_args()
    d=verify(a.root.resolve(),a.require_bytes)
    print(f"CERT_MANAGER_CRD_DEPENDENCY_PASS assets={len(d['assets'])} bytes={str(a.require_bytes).lower()}")
    return 0
if __name__=="__main__": raise SystemExit(main())
