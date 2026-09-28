#!/usr/bin/env python3
from __future__ import annotations
import argparse,os,shutil,stat,subprocess,tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def run(*args,check=True):
    return subprocess.run(args,cwd=ROOT,text=True,capture_output=True,check=check)

def safe_rel(raw:str)->Path:
    p=Path(raw)
    if p.is_absolute() or ".." in p.parts or not p.parts: raise RuntimeError("EVIDENCE_PERSIST_PATH_INVALID")
    return p

def copy_outputs(outputs:list[Path],backup:Path)->None:
    for rel in outputs:
        src=ROOT/rel
        st=os.lstat(src)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size<=0:
            raise RuntimeError(f"EVIDENCE_PERSIST_OUTPUT_INVALID {rel}")
        dst=backup/rel;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)

def restore(outputs:list[Path],backup:Path)->None:
    for rel in outputs:
        dst=ROOT/rel;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(backup/rel,dst)

def inputs_changed(source:str,remote:str,inputs:list[Path])->bool:
    if source==remote:return False
    r=run("git","diff","--quiet",source,remote,"--",*[str(x) for x in inputs],check=False)
    if r.returncode not in (0,1): raise RuntimeError("EVIDENCE_PERSIST_INPUT_DIFF_FAILED "+r.stderr.strip())
    return r.returncode==1

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--source-sha",required=True)
    p.add_argument("--message",required=True)
    p.add_argument("--input",action="append",default=[])
    p.add_argument("--output",action="append",default=[])
    p.add_argument("--attempts",type=int,default=3)
    a=p.parse_args()
    if len(a.source_sha)!=40 or not a.output or not a.input or a.attempts<1 or a.attempts>5: raise RuntimeError("EVIDENCE_PERSIST_ARGUMENT_INVALID")
    inputs=[safe_rel(x) for x in a.input];outputs=[safe_rel(x) for x in a.output]
    with tempfile.TemporaryDirectory(prefix="4so-evidence-persist-") as td:
        backup=Path(td);copy_outputs(outputs,backup)
        run("git","config","user.name","4so-evidence-bot");run("git","config","user.email","actions@users.noreply.github.com")
        for attempt in range(1,a.attempts+1):
            run("git","fetch","origin","main")
            remote=run("git","rev-parse","origin/main").stdout.strip()
            if inputs_changed(a.source_sha,remote,inputs):
                print(f"EVIDENCE_PERSIST_SKIP_INPUT_DRIFT source={a.source_sha} remote={remote}")
                return 0
            run("git","reset","--hard",remote)
            restore(outputs,backup)
            run("git","add","--",*[str(x) for x in outputs])
            if run("git","diff","--cached","--quiet",check=False).returncode==0:
                print(f"EVIDENCE_PERSIST_NO_DELTA remote={remote}")
                return 0
            run("git","commit","-m",a.message)
            pushed=run("git","push","origin","HEAD:main",check=False)
            if pushed.returncode==0:
                print(f"EVIDENCE_PERSIST_PASS attempt={attempt} base={remote}")
                return 0
            print(f"EVIDENCE_PERSIST_RETRY attempt={attempt} stderr={pushed.stderr.strip()[:300]}")
        raise RuntimeError("EVIDENCE_PERSIST_PUSH_RETRIES_EXHAUSTED")
if __name__=="__main__":raise SystemExit(main())
