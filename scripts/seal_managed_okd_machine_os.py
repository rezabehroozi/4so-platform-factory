#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, re, stat
from pathlib import Path
from urllib.parse import urlsplit

LOCK_AUTHORITY="MANAGED_OKD_UPSTREAM_TOOLCHAIN_LOCK_V1"
DISCOVERY_AUTHORITY="MANAGED_OKD_MACHINE_OS_DISCOVERY_V1"
SHA=re.compile(r"^[0-9a-f]{64}$")

def load_json(path: Path, label: str) -> dict:
    st=path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size<=0 or st.st_size>4*1024*1024:
        raise RuntimeError(f"{label}_FILE_INVALID")
    value=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value,dict):
        raise RuntimeError(f"{label}_NOT_OBJECT")
    return value

def installer(lock: dict) -> dict:
    rows=[r for r in lock.get("artifacts") or [] if isinstance(r,dict) and r.get("role")=="openshift-install"]
    if len(rows)!=1 or not SHA.fullmatch(str(rows[0].get("sha256") or "")):
        raise RuntimeError("MANAGED_OKD_INSTALLER_AUTHORITY_INVALID")
    return rows[0]

def public_https(value: str) -> str:
    p=urlsplit(str(value or "").strip())
    if p.scheme!="https" or not p.hostname or p.username or p.password or p.query or p.fragment:
        raise RuntimeError("MANAGED_OKD_MACHINE_OS_URL_INVALID")
    return p.geturl()

def discover(lock: dict, stream: dict) -> dict:
    if lock.get("authority")!=LOCK_AUTHORITY or lock.get("distribution")!="okd-scos":
        raise RuntimeError("MANAGED_OKD_TOOLCHAIN_LOCK_INVALID")
    payload_component_version=str((lock.get("machineOS") or {}).get("version") or "")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+", payload_component_version):
        raise RuntimeError("MANAGED_OKD_MACHINE_OS_COMPONENT_VERSION_INVALID")
    arch=((stream.get("architectures") or {}).get("x86_64") or {})
    metal=((arch.get("artifacts") or {}).get("metal") or {})
    release=str(metal.get("release") or arch.get("release") or "")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+", release):
        raise RuntimeError("MANAGED_OKD_MACHINE_OS_STREAM_RELEASE_INVALID")
    formats=metal.get("formats")
    if not isinstance(formats,dict) or not formats:
        raise RuntimeError("MANAGED_OKD_MACHINE_OS_FORMATS_MISSING")
    rows=[]
    for fmt_name,fmt in formats.items():
        if not isinstance(fmt,dict):
            continue
        for role,obj in fmt.items():
            if not isinstance(obj,dict):
                continue
            location=str(obj.get("location") or "").strip()
            digest=str(obj.get("sha256") or "").strip().lower()
            if location and SHA.fullmatch(digest):
                rows.append({"format":str(fmt_name),"role":str(role),"location":public_https(location),"sha256":digest})
    rows=[r for r in rows if r["role"]=="disk" and "raw" in r["format"]]
    if not rows:
        raise RuntimeError("MANAGED_OKD_MACHINE_OS_RAW_DISK_MISSING")
    rank={"raw.xz":0,"raw.gz":1,"4k.raw.xz":2,"4k.raw.gz":3}
    selected=sorted(rows,key=lambda r:(rank.get(r["format"],10),r["format"],r["location"]))[0]
    return {
      "authority":DISCOVERY_AUTHORITY,
      "distribution":"okd-scos",
      "architecture":"x86_64",
      "artifactClass":"metal",
      "payloadComponentVersion":payload_component_version,
      "streamRelease":release,
      **selected,
      "sourceAuthority":"openshift-install-coreos-print-stream-json",
      "sourceInstallerSHA256":installer(lock)["sha256"],
    }

def hash_file(path: Path) -> tuple[str,int]:
    st=path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size<=0:
        raise RuntimeError("MANAGED_OKD_MACHINE_OS_BYTES_INVALID")
    h=hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda:fh.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest(),st.st_size

def seal(lock: dict, found: dict, artifact: Path) -> dict:
    actual,size=hash_file(artifact)
    if actual!=found["sha256"]:
        raise RuntimeError(f"MANAGED_OKD_MACHINE_OS_DIGEST_MISMATCH expected={found['sha256']} actual={actual}")
    out=json.loads(json.dumps(lock))
    out["machineOSArtifact"]={**found,"sizeBytes":size,"byteVerified":True}
    out["pendingAuthorities"]=[r for r in (out.get("pendingAuthorities") or []) if r.get("id")!="fcos"]
    out["managedInstallContentReady"]=False
    out["runtimeCertified"]=False
    out["physicalCertified"]=False
    return out

def atomic_json(path: Path, value: dict) -> None:
    tmp=path.with_suffix(path.suffix+".tmp")
    tmp.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    os.replace(tmp,path)

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--lock",type=Path,default=Path("lab/managed-okd-upstream-toolchain-lock.json"))
    p.add_argument("--stream-json",type=Path,required=True)
    p.add_argument("--artifact-file",type=Path)
    p.add_argument("--write",action="store_true")
    p.add_argument("--discover-only",action="store_true")
    a=p.parse_args()
    lock=load_json(a.lock,"MANAGED_OKD_TOOLCHAIN_LOCK")
    stream=load_json(a.stream_json,"MANAGED_OKD_MACHINE_OS_STREAM")
    found=discover(lock,stream)
    if a.discover_only:
        print(json.dumps(found,sort_keys=True)); return 0
    if not a.artifact_file:
        p.error("--artifact-file is required unless --discover-only is used")
    out=seal(lock,found,a.artifact_file)
    if a.write:
        atomic_json(a.lock,out)
    print(json.dumps(out["machineOSArtifact"],sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
