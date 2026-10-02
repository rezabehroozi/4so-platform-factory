#!/usr/bin/env python3
"""One-command production Zot closure for the optional OpenChoreo target.

This orchestrator composes the existing exact acquisition, Zot mirror,
BuildKit executor, runtime-source, live-registry readback and production seal
authorities. It cannot infer Runtime or Physical PASS.
"""
from __future__ import annotations
import argparse,hashlib,json,os,shutil,stat
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

def sha256(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda:fh.read(1024*1024),b""):
            h.update(block)
    return "sha256:"+h.hexdigest()

def recoverable_workdir(workdir:Path,outputs:dict[str,str])->Path:
    workdir=workdir.expanduser()
    allowed={Path(value).name for value in outputs.values()}
    if workdir.exists():
        if workdir.is_symlink() or not workdir.is_dir():
            raise RuntimeError("OPENCHOREO_PRODUCTION_WORKDIR_INVALID")
        for child in list(workdir.iterdir()):
            if child.name.startswith(".4so-openchoreo-executor-"):
                if child.is_symlink() or not child.is_dir():
                    raise RuntimeError("OPENCHOREO_PRODUCTION_WORKDIR_STAGING_INVALID")
                shutil.rmtree(child)
                continue
            if child.name.endswith(".tmp") and child.name[:-4] in allowed:
                if child.is_symlink() or not child.is_file():
                    raise RuntimeError("OPENCHOREO_PRODUCTION_WORKDIR_STAGING_INVALID")
                child.unlink()
                continue
            if child.name not in allowed:
                raise RuntimeError("OPENCHOREO_PRODUCTION_WORKDIR_UNKNOWN_ENTRY "+child.name)
            if child.is_symlink():
                raise RuntimeError("OPENCHOREO_PRODUCTION_WORKDIR_OUTPUT_SYMLINK "+child.name)
    else:
        workdir.mkdir(parents=True)
    return workdir

def validate_mirror_checkpoint(acquisition:Path,prefix:str,path:Path)->dict:
    row=production.load(path,"OPENCHOREO_PRODUCTION_MIRROR_CHECKPOINT")
    lock,_=prepare.acquisition_payload(acquisition)
    expected=mirror.mirror_plan(lock.get("images") or [],prefix)
    expected_rows=[{"sourceReference":x["sourceReference"],"digest":x["digest"],"mirrorReference":x["mirrorReference"]} for x in expected]
    if (
        row.get("authority")!=mirror.AUTHORITY
        or row.get("acquisitionBundleSha256")!=prepare.digest_path(acquisition)
        or row.get("version")!=lock.get("version")
        or row.get("upstreamCommit")!=lock.get("upstreamCommit")
        or row.get("registryAuthority")!="zot"
        or row.get("registryIdentity")!=prefix.strip().rstrip("/").split("/",1)[0]
        or row.get("mirrorReady") is not True
        or row.get("images")!=expected_rows
    ):
        raise RuntimeError("OPENCHOREO_PRODUCTION_MIRROR_CHECKPOINT_DRIFT")
    return row

def validate_context_checkpoint(release:Path,acquisition:Path,path:Path)->dict:
    lock,_=executor.load_context(path)
    source=lock.get("sourceRelease") or {}
    runtime=lock.get("runtimeAcquisition") or {}
    if source.get("sha256")!=prepare.digest_path(release) or runtime.get("sha256")!=prepare.digest_path(acquisition):
        raise RuntimeError("OPENCHOREO_PRODUCTION_CONTEXT_CHECKPOINT_DRIFT")
    return lock

def validate_executor_checkpoint(context:Path,repository:str,path:Path)->dict:
    row=production.load(path,"OPENCHOREO_PRODUCTION_EXECUTOR_CHECKPOINT")
    lock,ctx_digest=executor.load_context(context)
    registry=repository.split("/",1)[0]
    if (
        row.get("authority")!=executor.AUTHORITY
        or row.get("executorContextSha256")!=ctx_digest
        or row.get("sourceReleaseSha256")!=(lock.get("sourceRelease") or {}).get("sha256")
        or row.get("acquisitionBundleSha256")!=(lock.get("runtimeAcquisition") or {}).get("sha256")
        or row.get("buildAuthority")!="buildkit"
        or row.get("registryAuthority")!="zot"
        or row.get("registryIdentity")!=registry
        or row.get("registryReadback") is not True
        or row.get("mirrorReady") is not True
    ):
        raise RuntimeError("OPENCHOREO_PRODUCTION_EXECUTOR_CHECKPOINT_DRIFT")
    digest=str(row.get("imageDigest") or "").lower()
    ref=str(row.get("imageReference") or "")
    if not executor.DIGEST_RE.fullmatch(digest) or not ref.endswith("@"+digest) or not ref.startswith(repository+"@"):
        raise RuntimeError("OPENCHOREO_PRODUCTION_EXECUTOR_CHECKPOINT_DRIFT")
    return row

def publish_once_or_identical(source:Path,target:Path,label:str)->None:
    raw=regular_file(source,label+"_SOURCE").read_bytes()
    target=target.expanduser()
    if target.is_symlink():
        raise RuntimeError(f"{label}_OUTPUT_SYMLINK_FORBIDDEN")
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists():
        if not target.is_file() or target.read_bytes()!=raw:
            raise RuntimeError(f"{label}_OUTPUT_REPLACEMENT_FORBIDDEN")
        return
    try:
        with target.open("xb") as fh:
            fh.write(raw); fh.flush(); os.fsync(fh.fileno())
    except FileExistsError:
        if target.is_symlink() or not target.is_file() or target.read_bytes()!=raw:
            raise RuntimeError(f"{label}_OUTPUT_REPLACEMENT_FORBIDDEN")

def replace_if_unchanged(source:Path,target:Path,expected_before:bytes,label:str)->None:
    raw=regular_file(source,label+"_SOURCE").read_bytes()
    target=regular_file(target,label+"_TARGET")
    current=target.read_bytes()
    if current==raw:
        return
    if current!=expected_before:
        raise RuntimeError(f"{label}_CONCURRENT_DRIFT")
    tmp=target.with_name("."+target.name+".promote.tmp")
    if tmp.exists() or tmp.is_symlink():
        tmp.unlink()
    with tmp.open("xb") as fh:
        fh.write(raw); fh.flush(); os.fsync(fh.fileno())
    if target.read_bytes()!=expected_before:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"{label}_CONCURRENT_DRIFT")
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
    workdir=recoverable_workdir(workdir,p["outputs"])
    o={k:Path(v) for k,v in p["outputs"].items()}
    selection_before=selection.read_bytes()

    resumed_steps=[]
    if o["mirrorEvidence"].exists():
        validate_mirror_checkpoint(acquisition,p["zotRepositoryPrefix"],o["mirrorEvidence"])
        resumed_steps.append("mirror-exact-runtime-images")
    else:
        mirror.mirror(acquisition,p["zotRepositoryPrefix"],o["mirrorEvidence"])

    if o["executorContext"].exists():
        validate_context_checkpoint(release,acquisition,o["executorContext"])
        resumed_steps.append("prepare-offline-executor-context")
    else:
        prepare.prepare(release,acquisition,toolchain_stage,o["executorContext"])

    if o["executorEvidence"].exists():
        validate_executor_checkpoint(o["executorContext"],p["executorRepository"],o["executorEvidence"])
        resumed_steps.append("buildkit-push-executor")
    else:
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
        # Evidence is write-once; selection is a revision-fenced compare-and-replace.
        # A crash after evidence publication but before selection promotion is
        # therefore safely resumable without replacing either authority.
        publish_once_or_identical(o["productionEvidence"],canonical_evidence,"OPENCHOREO_PRODUCTION_EVIDENCE")
        replace_if_unchanged(o["promotedSelection"],selection,selection_before,"OPENCHOREO_PRODUCTION_SELECTION")
    return {**p,"productionSourceSealed":True,"liveRegistryReadbackPass":True,
            "canonicalWritten":bool(write),"resumedSteps":resumed_steps,
            "runtimeCertified":False,"physicalCertified":False}

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
