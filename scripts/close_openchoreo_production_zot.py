#!/usr/bin/env python3
"""One-command production Zot closure for the optional OpenChoreo target.

This orchestrator composes the existing exact acquisition, Zot mirror,
BuildKit executor, runtime-source, live-registry readback and production seal
authorities. It cannot infer Runtime or Physical PASS.
"""
from __future__ import annotations
import argparse,json,os,shutil,stat
from pathlib import Path
import mirror_openchoreo_runtime as mirror
import prepare_openchoreo_executor as prepare
import build_openchoreo_executor_image as executor
import seal_openchoreo_runtime as runtime_seal
import verify_openchoreo_production_zot_readback as readback
import seal_openchoreo_production_authority as production

AUTHORITY="OPENCHOREO_PRODUCTION_ZOT_CLOSURE_V1"
ROOT=Path(__file__).resolve().parents[1]

def regular_file(path:Path,label:str,executable:bool=False)->Path:
    path=path.expanduser()
    info=path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size<=0:
        raise RuntimeError(f"{label}_FILE_INVALID")
    if executable and not os.access(path,os.X_OK):
        raise RuntimeError(f"{label}_NOT_EXECUTABLE")
    return path

def regular_dir(path:Path,label:str)->Path:
    path=path.expanduser()
    info=path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"{label}_DIRECTORY_INVALID")
    return path

def registry_contract(prefix:str)->tuple[str,str]:
    prefix=str(prefix or "").strip().rstrip("/")
    if not mirror.PREFIX_RE.fullmatch(prefix) or "://" in prefix:
        raise RuntimeError("OPENCHOREO_PRODUCTION_ZOT_PREFIX_INVALID")
    identity=production.production_registry(prefix.split("/",1)[0])
    return prefix,identity

def plan(workdir:Path,prefix:str)->dict:
    prefix,identity=registry_contract(prefix)
    workdir=workdir.expanduser()
    return {
      "authority":AUTHORITY,
      "registryIdentity":identity,
      "zotRepositoryPrefix":prefix,
      "executorRepository":prefix+"/openchoreo-runtime",
      "steps":[
        "mirror-exact-runtime-images",
        "prepare-offline-executor-context",
        "buildkit-push-executor",
        "seal-runtime-source",
        "live-zot-digest-readback",
        "promote-production-source-authority",
      ],
      "outputs":{
        "mirrorEvidence":str(workdir/"mirror-evidence.json"),
        "executorContext":str(workdir/"executor-context"),
        "executorEvidence":str(workdir/"executor-evidence.json"),
        "runtimeSource":str(workdir/"runtime-source.json"),
        "readbackEvidence":str(workdir/"zot-readback.json"),
        "promotedSelection":str(workdir/"promoted-source-selection.json"),
        "productionEvidence":str(workdir/"production-zot-seal-evidence.json"),
      },
    }

def atomic_copy(source:Path,target:Path,label:str)->None:
    if target.is_symlink():
        raise RuntimeError(f"{label}_OUTPUT_SYMLINK_FORBIDDEN")
    target.parent.mkdir(parents=True,exist_ok=True)
    tmp=target.with_suffix(target.suffix+".tmp")
    if tmp.exists() or tmp.is_symlink():
        tmp.unlink()
    shutil.copyfile(source,tmp)
    os.replace(tmp,target)

def close(*,release:Path,acquisition:Path,acquisition_receipt:Path,toolchain_stage:Path,
          buildctl:Path,buildkit_address:str,zot_prefix:str,selection:Path,workdir:Path,
          canonical_evidence:Path|None,write:bool)->dict:
    release=regular_file(release,"OPENCHOREO_PRODUCTION_RELEASE")
    acquisition=regular_file(acquisition,"OPENCHOREO_PRODUCTION_ACQUISITION")
    acquisition_receipt=regular_file(acquisition_receipt,"OPENCHOREO_PRODUCTION_ACQUISITION_RECEIPT")
    buildctl=regular_file(buildctl,"OPENCHOREO_PRODUCTION_BUILDKIT",True)
    toolchain_stage=regular_dir(toolchain_stage,"OPENCHOREO_PRODUCTION_TOOLCHAIN_STAGE")
    selection=regular_file(selection,"OPENCHOREO_PRODUCTION_SELECTION")
    p=plan(workdir,zot_prefix)
    if workdir.exists():
        if workdir.is_symlink() or not workdir.is_dir() or any(workdir.iterdir()):
            raise RuntimeError("OPENCHOREO_PRODUCTION_WORKDIR_NOT_EMPTY")
    else:
        workdir.mkdir(parents=True)
    o={k:Path(v) for k,v in p["outputs"].items()}

    mirror.mirror(acquisition,p["zotRepositoryPrefix"],o["mirrorEvidence"])
    prepare.prepare(release,acquisition,toolchain_stage,o["executorContext"])
    executor.build(o["executorContext"],buildctl,str(buildkit_address or ""),p["executorRepository"],o["executorEvidence"])
    runtime_seal.seal(acquisition,o["mirrorEvidence"],o["executorEvidence"],o["runtimeSource"])

    reader,tool=readback.crane_reader()
    rb=readback.verify(o["runtimeSource"],reader,tool)
    o["readbackEvidence"].write_text(json.dumps(rb,indent=2,sort_keys=True)+"\n",encoding="utf-8")

    sealed=production.promote(
        o["runtimeSource"],acquisition_receipt,selection,p["registryIdentity"],
        o["promotedSelection"],o["productionEvidence"],o["readbackEvidence"],
    )
    if sealed.get("productionSourceSealed") is not True or sealed.get("liveRegistryReadbackPass") is not True:
        raise RuntimeError("OPENCHOREO_PRODUCTION_SEAL_NOT_PASS")
    if sealed.get("runtimeCertified") is not False or sealed.get("physicalCertified") is not False:
        raise RuntimeError("OPENCHOREO_PRODUCTION_SEAL_SCOPE_INFLATED")

    if write:
        if canonical_evidence is None:
            raise RuntimeError("OPENCHOREO_PRODUCTION_CANONICAL_EVIDENCE_REQUIRED")
        # Publish evidence first. An interruption before selection replacement leaves
        # product runtime authority unresolved rather than optimistically promoted.
        atomic_copy(o["productionEvidence"],canonical_evidence,"OPENCHOREO_PRODUCTION_EVIDENCE")
        atomic_copy(o["promotedSelection"],selection,"OPENCHOREO_PRODUCTION_SELECTION")
    return {**p,"productionSourceSealed":True,"liveRegistryReadbackPass":True,
            "canonicalWritten":bool(write),"runtimeCertified":False,"physicalCertified":False}

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--release",type=Path,required=True)
    p.add_argument("--acquisition",type=Path,required=True)
    p.add_argument("--acquisition-receipt",type=Path,default=ROOT/"lab/openchoreo-runtime-acquisition-receipt.json")
    p.add_argument("--toolchain-stage",type=Path,required=True)
    p.add_argument("--buildctl",type=Path,required=True)
    p.add_argument("--buildkit-address",default="")
    p.add_argument("--zot-repository-prefix",required=True)
    p.add_argument("--selection",type=Path,default=ROOT/"runtime/openchoreo/source-selection.json")
    p.add_argument("--workdir",type=Path,required=True)
    p.add_argument("--canonical-evidence",type=Path,default=ROOT/"lab/openchoreo-production-zot-seal-evidence.json")
    p.add_argument("--preflight",action="store_true")
    p.add_argument("--write",action="store_true")
    a=p.parse_args()
    try:
        if a.preflight:
            regular_file(a.release,"OPENCHOREO_PRODUCTION_RELEASE")
            regular_file(a.acquisition,"OPENCHOREO_PRODUCTION_ACQUISITION")
            regular_file(a.acquisition_receipt,"OPENCHOREO_PRODUCTION_ACQUISITION_RECEIPT")
            regular_dir(a.toolchain_stage,"OPENCHOREO_PRODUCTION_TOOLCHAIN_STAGE")
            regular_file(a.buildctl,"OPENCHOREO_PRODUCTION_BUILDKIT",True)
            regular_file(a.selection,"OPENCHOREO_PRODUCTION_SELECTION")
            print(json.dumps({**plan(a.workdir,a.zot_repository_prefix),"preflightPass":True},sort_keys=True)); return 0
        out=close(release=a.release,acquisition=a.acquisition,acquisition_receipt=a.acquisition_receipt,
          toolchain_stage=a.toolchain_stage,buildctl=a.buildctl,buildkit_address=a.buildkit_address,
          zot_prefix=a.zot_repository_prefix,selection=a.selection,workdir=a.workdir,
          canonical_evidence=a.canonical_evidence,write=a.write)
    except (RuntimeError,OSError,ValueError,json.JSONDecodeError) as exc:
        print("OPENCHOREO_PRODUCTION_ZOT_CLOSURE_BLOCKED "+str(exc),file=__import__("sys").stderr); return 3
    print(json.dumps(out,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
