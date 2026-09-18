#!/usr/bin/env python3
"""Fail-closed release build-toolchain admission.

A development compiler may build/test the source, but release admission only
passes when the lock names an exact compiler version and archive SHA-256 and the
active compiler/provenance match. No network download is performed here.
"""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, re, subprocess, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
LOCK=ROOT/'lab'/'release-build-toolchain-lock.json'
AUTH='RELEASE_BUILD_TOOLCHAIN_AUTHORITY_V1'
HEX=re.compile(r'^[0-9a-f]{64}$')

def current_go():
    go_binary=os.environ.get('GO','go').strip() or 'go'
    try:
        p=subprocess.run([go_binary,'version'],text=True,capture_output=True)
    except OSError as exc:
        return 127,f'go unavailable: {exc}'
    return p.returncode,(p.stdout or p.stderr).strip()

def command_first_line(command):
    try:
        p=subprocess.run(command,text=True,capture_output=True)
    except OSError as exc:
        return 127,f'{command[0]} unavailable: {exc}'
    lines=[x.strip() for x in (p.stdout or p.stderr).splitlines() if x.strip()]
    return p.returncode,(lines[0] if lines else '')

def file_sha256(path):
    p=pathlib.Path(path)
    if not p.is_file() or p.is_symlink():
        return ''
    h=hashlib.sha256()
    with p.open('rb') as fh:
        for chunk in iter(lambda: fh.read(1024*1024),b''):
            h.update(chunk)
    return h.hexdigest()

def validate_active_cgo(lock):
    spec=lock.get('spec',{})
    expected=spec.get('exactCGOToolchain') or {}
    if spec.get('admissionStatus')!='admitted':
        return []
    errs=[]
    commands={
        'ccVersion':['gcc','--version'],
        'ldVersion':['ld','--version'],
        'libcVersion':['ldd','--version'],
    }
    for key,cmd in commands.items():
        rc,actual=command_first_line(cmd)
        if rc!=0 or actual!=str(expected.get(key) or ''):
            errs.append(f'active CGO {key} mismatch: lock={expected.get(key)} active={actual}')
    for path_key,digest_key in (('libpqHeaderPath','libpqHeaderSha256'),('libpqLibraryPath','libpqLibrarySha256')):
        path=str(expected.get(path_key) or '')
        actual=file_sha256(path) if path else ''
        wanted=str(expected.get(digest_key) or '')
        if not HEX.fullmatch(wanted) or actual!=wanted:
            errs.append(f'active CGO {digest_key} mismatch: lock={wanted} active={actual}')
    return errs

def validate(lock, *, active=None, archive_path=None):
    errs=[]; spec=lock.get('spec',{})
    if lock.get('authority')!=AUTH: errs.append('authority mismatch')
    policy=spec.get('policy',{})
    if not all(policy.get(k) is True for k in ['supportedToolchainRequired','exactCompilerArchiveDigestRequired','compilerVersionMustMatchBuildProvenance','exactCGOToolchainRequired']): errs.append('required fail-closed policy disabled')
    if policy.get('networkAutoDownloadDuringReleaseBuildAllowed') is not False: errs.append('network auto-download must be forbidden')
    status=spec.get('admissionStatus')
    exact=spec.get('exactCompiler') or {}
    if status=='admitted':
        version=exact.get('version',''); sha=exact.get('archiveSha256',''); archive=exact.get('archiveFile','')
        goos=str(exact.get('goos','')); goarch=str(exact.get('goarch','')); size=int(exact.get('archiveSize') or 0)
        if not version.startswith('go1.'): errs.append('admitted lock missing exact Go version')
        if not HEX.fullmatch(sha): errs.append('admitted lock missing exact compiler archive sha256')
        if not archive: errs.append('admitted lock missing offline archiveFile')
        if goos!='linux' or goarch!='amd64': errs.append('admitted compiler platform must be linux/amd64')
        if size<=0: errs.append('admitted lock missing exact compiler archive size')
        cgo=spec.get('exactCGOToolchain') or {}
        for key in ('ccVersion','ldVersion','libcVersion','libpqHeaderPath','libpqLibraryPath'):
            if not str(cgo.get(key) or '').strip(): errs.append(f'admitted lock missing exact CGO {key}')
        for key in ('libpqHeaderSha256','libpqLibrarySha256'):
            if not HEX.fullmatch(str(cgo.get(key) or '')): errs.append(f'admitted lock missing exact CGO {key}')
        if active is not None:
            match=re.fullmatch(r'go version (\S+) (\S+)/(\S+)', active.strip())
            if match is None or (match.group(1),match.group(2),match.group(3))!=(version,goos,goarch):
                errs.append(f'active compiler mismatch: lock={version} {goos}/{goarch} active={active}')
        if archive_path:
            p=pathlib.Path(archive_path)
            if not p.is_file(): errs.append('compiler archive missing')
            else:
                if p.stat().st_size!=size: errs.append('compiler archive size mismatch')
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
    good=json.loads(json.dumps(base)); good['spec']['admissionStatus']='admitted'; good['spec']['exactCompiler']={'version':'go1.99.1','goos':'linux','goarch':'amd64','archiveFile':'go1.99.1.linux-amd64.tar.gz','localArchivePath':'vendor/toolchains/go1.99.1.linux-amd64.tar.gz','archiveSize':1,'archiveSha256':'a'*64}; good['spec'].pop('blocker',None)
    if validate(good,active='go version go1.99.1 linux/amd64'): return False
    return True

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--self-test',action='store_true'); ap.add_argument('--require-admitted',action='store_true'); ap.add_argument('--archive'); args=ap.parse_args()
    if args.self_test:
        if not self_test(): print('RELEASE_BUILD_TOOLCHAIN_SELF_TEST_FAIL'); return 1
        print('RELEASE_BUILD_TOOLCHAIN_SELF_TEST_PASS'); return 0
    lock=json.loads(LOCK.read_text()); rc,active=current_go(); errs=[] if rc==0 else ['go version unavailable']
    status=lock.get('spec',{}).get('admissionStatus')
    archive_path=args.archive
    if status=='admitted' and not archive_path:
        rel=str(((lock.get('spec') or {}).get('exactCompiler') or {}).get('localArchivePath') or '')
        rel_path=pathlib.PurePosixPath(rel)
        if not rel or rel_path.is_absolute() or '..' in rel_path.parts or not rel.startswith('vendor/toolchains/'):
            errs.append('admitted lock localArchivePath invalid')
        else:
            archive_path=str(ROOT.joinpath(*rel_path.parts))
    errs += validate(lock,active=active if rc==0 else None,archive_path=archive_path)
    if status=='admitted':
        errs += validate_active_cgo(lock)
    if args.require_admitted and status!='admitted': errs.append('release toolchain lock is not admitted')
    if errs:
        print('RELEASE_BUILD_TOOLCHAIN_BLOCKED ' + '; '.join(errs)); return 2 if status=='blocked' else 1
    print(f'RELEASE_BUILD_TOOLCHAIN_PASS status={status} active={active}')
    return 0
if __name__=='__main__': raise SystemExit(main())
