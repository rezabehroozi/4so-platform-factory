#!/usr/bin/env python3
"""Fail-closed release build-toolchain admission.

A development compiler may build/test the source, but release admission only
passes when the lock names an exact compiler version and archive SHA-256 and the
active compiler/provenance match. No network download is performed here.
"""
from __future__ import annotations
import argparse, hashlib, json, pathlib, re, subprocess, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
LOCK=ROOT/'lab'/'release-build-toolchain-lock.json'
AUTH='RELEASE_BUILD_TOOLCHAIN_AUTHORITY_V1'
HEX=re.compile(r'^[0-9a-f]{64}$')

def current_go():
    p=subprocess.run(['go','version'],text=True,capture_output=True)
    return p.returncode,(p.stdout or p.stderr).strip()

def validate(lock, *, active=None, archive_path=None):
    errs=[]; spec=lock.get('spec',{})
    if lock.get('authority')!=AUTH: errs.append('authority mismatch')
    policy=spec.get('policy',{})
    if not all(policy.get(k) is True for k in ['supportedToolchainRequired','exactCompilerArchiveDigestRequired','compilerVersionMustMatchBuildProvenance']): errs.append('required fail-closed policy disabled')
    if policy.get('networkAutoDownloadDuringReleaseBuildAllowed') is not False: errs.append('network auto-download must be forbidden')
    status=spec.get('admissionStatus')
    exact=spec.get('exactCompiler') or {}
    if status=='admitted':
        version=exact.get('version',''); sha=exact.get('archiveSha256',''); archive=exact.get('archiveFile','')
        if not version.startswith('go1.'): errs.append('admitted lock missing exact Go version')
        if not HEX.fullmatch(sha): errs.append('admitted lock missing exact compiler archive sha256')
        if not archive: errs.append('admitted lock missing offline archiveFile')
        if active is not None and version not in active: errs.append(f'active compiler mismatch: lock={version} active={active}')
        if archive_path:
            p=pathlib.Path(archive_path)
            if not p.is_file(): errs.append('compiler archive missing')
            else:
                got=hashlib.sha256(p.read_bytes()).hexdigest()
                if got!=sha: errs.append('compiler archive sha256 mismatch')
    elif status=='blocked':
        if spec.get('blocker')!='RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING': errs.append('blocked lock must carry canonical blocker')
        candidate=spec.get('candidateExactCompiler') or {}
        if candidate:
            if not str(candidate.get('version','')).startswith('go1.'): errs.append('candidate exact compiler version invalid')
            if not HEX.fullmatch(str(candidate.get('archiveSha256',''))): errs.append('candidate compiler archive sha256 invalid')
            if not str(candidate.get('archiveURL','')).startswith('https://go.dev/dl/'): errs.append('candidate compiler archive URL must use go.dev/dl')
            if int(candidate.get('archiveSize') or 0) <= 0: errs.append('candidate compiler archive size invalid')
            if not str(candidate.get('localArchivePath','')).startswith('vendor/toolchains/'): errs.append('candidate local archive path must be under vendor/toolchains')
    else: errs.append('admissionStatus must be admitted or blocked')
    return errs

def self_test():
    base=json.loads(LOCK.read_text())
    bad=json.loads(json.dumps(base)); bad['spec']['admissionStatus']='admitted'; bad['spec']['exactCompiler']={'version':'go1.99.1','archiveFile':'go.tar.gz','archiveSha256':'bad'}
    if not validate(bad,active='go version go1.99.1 linux/amd64'): return False
    bad2=json.loads(json.dumps(base)); bad2['spec']['policy']['networkAutoDownloadDuringReleaseBuildAllowed']=True
    if not validate(bad2): return False
    good=json.loads(json.dumps(base)); good['spec']['admissionStatus']='admitted'; good['spec']['exactCompiler']={'version':'go1.99.1','archiveFile':'go1.99.1.linux-amd64.tar.gz','archiveSha256':'a'*64}; good['spec'].pop('blocker',None)
    if validate(good,active='go version go1.99.1 linux/amd64'): return False
    return True

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--self-test',action='store_true'); ap.add_argument('--require-admitted',action='store_true'); ap.add_argument('--archive'); args=ap.parse_args()
    if args.self_test:
        if not self_test(): print('RELEASE_BUILD_TOOLCHAIN_SELF_TEST_FAIL'); return 1
        print('RELEASE_BUILD_TOOLCHAIN_SELF_TEST_PASS'); return 0
    lock=json.loads(LOCK.read_text()); rc,active=current_go(); errs=[] if rc==0 else ['go version unavailable']; errs += validate(lock,active=active if rc==0 else None,archive_path=args.archive)
    status=lock.get('spec',{}).get('admissionStatus')
    if args.require_admitted and status!='admitted': errs.append('release toolchain lock is not admitted')
    if errs:
        print('RELEASE_BUILD_TOOLCHAIN_BLOCKED ' + '; '.join(errs)); return 2 if status=='blocked' else 1
    print(f'RELEASE_BUILD_TOOLCHAIN_PASS status={status} active={active}')
    return 0
if __name__=='__main__': raise SystemExit(main())
