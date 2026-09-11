#!/usr/bin/env python3
"""Offline-only exact release build-toolchain acquisition transaction.

This command never downloads from the network. It verifies a caller-supplied
archive against candidateExactCompiler metadata, atomically installs it into
vendor/toolchains, and only then promotes the lock to admitted.
"""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, shutil, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
LOCK=ROOT/'lab'/'release-build-toolchain-lock.json'
AUTH='RELEASE_BUILD_TOOLCHAIN_AUTHORITY_V1'

def sha256_file(p:pathlib.Path)->str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()

def load():
    d=json.loads(LOCK.read_text())
    if d.get('authority')!=AUTH: raise ValueError('toolchain authority mismatch')
    c=(d.get('spec') or {}).get('candidateExactCompiler') or {}
    for k in ('version','goos','goarch','archiveFile','archiveURL','archiveSha256','archiveSize','localArchivePath'):
        if not c.get(k): raise ValueError(f'candidateExactCompiler.{k} missing')
    return d,c

def verify_archive(p:pathlib.Path,c:dict):
    if not p.is_file(): raise ValueError('candidate archive does not exist')
    if p.stat().st_size != int(c['archiveSize']): raise ValueError(f'archive size mismatch expected={c["archiveSize"]} got={p.stat().st_size}')
    got=sha256_file(p)
    if got != c['archiveSha256']: raise ValueError(f'archive sha256 mismatch expected={c["archiveSha256"]} got={got}')

def install(src:pathlib.Path,d:dict,c:dict):
    verify_archive(src,c)
    dest=ROOT/c['localArchivePath']; dest.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=dest.name+'.',suffix='.tmp',dir=dest.parent); os.close(fd)
    tmp=pathlib.Path(tmp)
    try:
        shutil.copyfile(src,tmp); os.chmod(tmp,0o644); verify_archive(tmp,c); os.replace(tmp,dest)
    finally:
        if tmp.exists(): tmp.unlink()
    spec=d['spec']; spec['admissionStatus']='admitted'; spec.pop('blocker',None); spec.pop('blockedReason',None)
    spec['exactCompiler']={k:c[k] for k in ('version','goos','goarch','archiveFile','archiveSha256','archiveSize','localArchivePath')}
    raw=json.dumps(d,indent=2)+"\n"
    fd,tmpname=tempfile.mkstemp(prefix=LOCK.name+'.',suffix='.tmp',dir=LOCK.parent); os.close(fd)
    t=pathlib.Path(tmpname)
    try: t.write_text(raw); os.replace(t,LOCK)
    finally:
        if t.exists(): t.unlink()
    return dest

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--install'); ap.add_argument('--check',action='store_true'); args=ap.parse_args()
    try: d,c=load()
    except Exception as e: print('RELEASE_BUILD_TOOLCHAIN_ACQUISITION_FAIL',e); return 1
    if args.install:
        try: dest=install(pathlib.Path(args.install).resolve(),d,c)
        except Exception as e: print('RELEASE_BUILD_TOOLCHAIN_ACQUISITION_FAIL',e); return 1
        print(f'RELEASE_BUILD_TOOLCHAIN_ACQUISITION_PASS archive={dest.relative_to(ROOT)} sha256={c["archiveSha256"]}')
        return 0
    if args.check:
        dest=ROOT/c['localArchivePath']
        try: verify_archive(dest,c)
        except Exception as e: print('RELEASE_BUILD_TOOLCHAIN_ACQUISITION_BLOCKED',e); return 2
        print(f'RELEASE_BUILD_TOOLCHAIN_ACQUISITION_PASS archive={dest.relative_to(ROOT)} sha256={c["archiveSha256"]}')
        return 0
    ap.error('one of --install or --check is required')
if __name__=='__main__': raise SystemExit(main())
