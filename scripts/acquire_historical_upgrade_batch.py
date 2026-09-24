#!/usr/bin/env python3
"""Checkpoint-safe S2 historical-source acquisition for reviewed Helm/OCI predecessors.

The canonical authority is catalog/component-upgrade-source-admission.json.
This runner never selects a previous version itself and never treats acquisition
or source-pair admission as runtime certification.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, stat, subprocess, sys, tempfile
from pathlib import Path
SCRIPT_DIR=Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path: sys.path.insert(0,str(SCRIPT_DIR))
from component_upgrade_source_admission import ROOT, validate as validate_admission

AUTHORITY="HISTORICAL_UPGRADE_STAGED_BATCH_V1"
MANIFEST="stage-manifest.json"
EXACT=re.compile(r"^\d+\.\d+\.\d+$")
SHA=re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE=re.compile(r"^[a-z0-9][a-z0-9-]{0,62}-[0-9]+\.[0-9]+\.[0-9]+\.zip$")

def _json(path:Path): return json.loads(path.read_text())
def _absolute_no_follow(path:Path): return Path(os.path.abspath(os.fspath(path.expanduser())))
def _sha(path:Path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return 'sha256:'+h.hexdigest()
def _regular_file(path:Path,label:str):
    st=path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode): raise RuntimeError(f'{label}_NOT_REAL_FILE {path}')
    return path
def _regular_dir(path:Path,label:str,create=False):
    if create: path.mkdir(parents=True,exist_ok=True)
    st=path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode): raise RuntimeError(f'{label}_NOT_REAL_DIRECTORY {path}')
    return path

def authority(root:Path=ROOT):
    p=root/'catalog/component-upgrade-source-admission.json'; doc=_json(p); errs=validate_admission(doc,root)
    if errs: raise RuntimeError('HISTORICAL_UPGRADE_ADMISSION_INVALID '+'; '.join(errs))
    return doc

def classify(root:Path=ROOT):
    doc=authority(root); helm=[]; tagged=[]; install_only=[]; review=[]; already=[]; waiting_current=[]
    for row in doc['components']:
        name=row['component']; st=row['status']; prev=row['previousVersion']
        if st=='install-only-first-product-release': install_only.append(row); continue
        if st!='admitted-for-acquisition': review.append(row); continue
        comp=_json(root/'catalog/components'/f'{name}.json'); spec=comp.get('spec') or {}; delivery=spec.get('delivery') or {}
        lock=root/'catalog/runtime'/name/prev/'source-lock.json'
        if lock.exists() or lock.is_symlink():
            _regular_file(lock,'HISTORICAL_SOURCE_LOCK')
            already.append(row); continue
        if (spec.get('source') or {}).get('resolved') is not True:
            waiting_current.append(row); continue
        if delivery.get('type')=='helm': helm.append(row)
        else: tagged.append(row)
    key=lambda r:r['component']
    return tuple(sorted(x,key=key) for x in (helm,tagged,install_only,review,already,waiting_current))

def platformctl(path:str|None):
    if path:
        p=_absolute_no_follow(Path(path)); _regular_file(p,'PLATFORMCTL')
        if not os.access(p,os.X_OK): raise RuntimeError(f'PLATFORMCTL_NOT_EXECUTABLE {p}')
        return [str(p)]
    p=ROOT/'bin/platformctl'
    if p.is_file() and not p.is_symlink() and os.access(p,os.X_OK): return [str(p)]
    return ['go','run','./cmd/platformctl']

def run_json(cmd,cwd=ROOT,timeout=240):
    p=subprocess.run(cmd,cwd=cwd,text=True,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
    if p.returncode: raise RuntimeError(f'COMMAND_FAILED rc={p.returncode} cmd={cmd!r}\n{p.stdout[-8000:]}')
    try: out=json.loads(p.stdout.strip())
    except Exception as e: raise RuntimeError(f'COMMAND_JSON_INVALID cmd={cmd!r} output={p.stdout[-2000:]!r}') from e
    if not isinstance(out,dict): raise RuntimeError('COMMAND_JSON_OBJECT_REQUIRED')
    return out

def acquisition_cmd(component,source_kind,out=None,install=False,ctl=None):
    if source_kind=='tagged':
        cmd=[sys.executable,'scripts/acquire_upstream_tagged_source.py','--component',component,'--from-upgrade-admission','--historical']
    else:
        cmd=[sys.executable,'scripts/acquire_upstream_helm.py','--component',component,'--from-upgrade-admission','--historical']
    if out is not None: cmd += ['--out',str(out)]
    if ctl: cmd += ['--platformctl',ctl]
    if install: cmd += ['--install']
    return cmd

def entry(row,bundle:Path,verified:dict):
    name=row['component']; prev=row['previousVersion']; fn=bundle.name
    if fn!=f'{name}-{prev}.zip' or not SAFE.fullmatch(fn): raise RuntimeError(f'HISTORICAL_STAGE_FILENAME_INVALID {fn}')
    if verified.get('valid') is not True or verified.get('component')!=name or str(verified.get('version') or '')!=prev:
        raise RuntimeError(f'HISTORICAL_STAGE_IDENTITY_INVALID {name}')
    if str(verified.get('upstreamUrl') or '')!=row['source']: raise RuntimeError(f'HISTORICAL_STAGE_SOURCE_DRIFT {name}')
    digest=_sha(bundle)
    if verified.get('bundleDigest')!=digest or not SHA.fullmatch(digest): raise RuntimeError(f'HISTORICAL_STAGE_DIGEST_INVALID {name}')
    return {'component':name,'targetRelease':row['targetRelease'],'previousVersion':prev,'source':row['source'],'bundleFile':fn,'bundleDigest':digest,'historical':True}

def manifest(entries):
    return {'apiVersion':'platform.4so.io/v1alpha1','kind':'StagedHistoricalUpgradeBatch','metadata':{'name':'s2-reviewed-historical-sources'},'spec':{'authority':AUTHORITY,'canonicalAuthority':'catalog/component-upgrade-source-admission.json','runtimeCertificationImplied':False,'entries':sorted(entries,key=lambda x:x['component'])}}

def validate_manifest(stage:Path,doc:dict,root:Path=ROOT):
    if doc.get('apiVersion')!='platform.4so.io/v1alpha1' or doc.get('kind')!='StagedHistoricalUpgradeBatch': raise RuntimeError('HISTORICAL_STAGE_TYPE_INVALID')
    spec=doc.get('spec') or {}
    if spec.get('authority')!=AUTHORITY or spec.get('canonicalAuthority')!='catalog/component-upgrade-source-admission.json' or spec.get('runtimeCertificationImplied') is not False: raise RuntimeError('HISTORICAL_STAGE_AUTHORITY_INVALID')
    auth={r['component']:r for r in authority(root)['components']}; seen=set(); out=[]
    for e in spec.get('entries') or []:
        if set(e)!={'component','targetRelease','previousVersion','source','bundleFile','bundleDigest','historical'}: raise RuntimeError('HISTORICAL_STAGE_FIELDS_INVALID')
        n=e['component']; row=auth.get(n)
        if n in seen or not row or row['status']!='admitted-for-acquisition': raise RuntimeError(f'HISTORICAL_STAGE_ADMISSION_INVALID {n}')
        seen.add(n)
        if e['historical'] is not True or e['targetRelease']!=row['targetRelease'] or e['previousVersion']!=row['previousVersion'] or e['source']!=row['source']: raise RuntimeError(f'HISTORICAL_STAGE_BINDING_DRIFT {n}')
        if not EXACT.fullmatch(e['previousVersion']) or not SHA.fullmatch(e['bundleDigest']) or e['bundleFile']!=f"{n}-{e['previousVersion']}.zip" or not SAFE.fullmatch(e['bundleFile']): raise RuntimeError(f'HISTORICAL_STAGE_IDENTITY_INVALID {n}')
        b=stage/e['bundleFile']; _regular_file(b,'HISTORICAL_STAGE_BUNDLE')
        if _sha(b)!=e['bundleDigest']: raise RuntimeError(f'HISTORICAL_STAGE_FILE_DIGEST_MISMATCH {n}')
        out.append(e)
    return sorted(out,key=lambda x:x['component'])

def atomic_json(path:Path,obj):
    raw=(json.dumps(obj,indent=2,sort_keys=True)+'\n').encode(); fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
        os.chmod(tmp,0o644); os.replace(tmp,path)
        if os.name != 'nt':
            d=os.open(path.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
            try: os.fsync(d)
            finally: os.close(d)
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise

def plan(as_json=False):
    helm,tagged,install_only,review,already,waiting_current=classify()
    payload={'helmHistoricalReady':[r['component'] for r in helm],'taggedSourceSetHistoricalReady':[r['component'] for r in tagged],'installOnlyFirstProductRelease':[r['component'] for r in install_only],'reviewRequired':[r['component'] for r in review],'alreadyHistoricalSourceLocked':[r['component'] for r in already],'waitingCurrentSource':[r['component'] for r in waiting_current],'helmReadyCount':len(helm),'taggedReadyCount':len(tagged),'installOnlyCount':len(install_only),'reviewCount':len(review),'waitingCurrentSourceCount':len(waiting_current),'authority':AUTHORITY}
    if as_json: print(json.dumps(payload,indent=2,sort_keys=True))
    else: print(f"HISTORICAL_UPGRADE_BATCH_PLAN helm_ready={len(helm)} tagged_ready={len(tagged)} install_only={len(install_only)} review={len(review)} already_locked={len(already)} waiting_current={len(waiting_current)}")
    return 0

def execute(limit,ctl):
    helm,tagged,install_only,review,already,waiting_current=classify(); work=[(r,'helm') for r in helm]+[(r,'tagged') for r in tagged]; work=work[:limit] if limit>0 else work; done=[]
    for row,kind in work:
        p=subprocess.run(acquisition_cmd(row['component'],kind,install=True,ctl=ctl),cwd=ROOT,text=True)
        if p.returncode: print(f"HISTORICAL_UPGRADE_BATCH_CHECKPOINT failed={row['component']} completed={','.join(done)}",file=sys.stderr); return p.returncode
        done.append(row['component'])
    h2,t2,_,_,_,w2=classify()
    print(f"HISTORICAL_UPGRADE_BATCH_CHECKPOINT_PASS acquired={len(done)} remaining_helm={len(h2)} remaining_tagged={len(t2)} install_only={len(install_only)} waiting_current={len(w2)}")
    return 0

def stage_out(limit,stage:Path,ctl):
    stage=_regular_dir(_absolute_no_follow(stage),'HISTORICAL_STAGE_DIRECTORY',create=True); mp=stage/MANIFEST
    entries=[]
    if mp.exists(): _regular_file(mp,'HISTORICAL_STAGE_MANIFEST'); entries=validate_manifest(stage,_json(mp))
    done={e['component'] for e in entries}; helm,tagged,install_only,review,already,waiting_current=classify(); work=[(r,'helm') for r in helm if r['component'] not in done]+[(r,'tagged') for r in tagged if r['component'] not in done]; work=work[:limit] if limit>0 else work
    ctlprefix=platformctl(ctl)
    for row,kind in work:
        out=stage/f"{row['component']}-{row['previousVersion']}.zip"
        if out.exists():
            _regular_file(out,'HISTORICAL_STAGE_ORPHAN_BUNDLE')
            verified=run_json(ctlprefix+['catalog-bundle','verify','-f',str(out)])
        else:
            p=subprocess.run(acquisition_cmd(row['component'],kind,out=out,ctl=ctl),cwd=ROOT,text=True)
            if p.returncode: return p.returncode
            verified=run_json(ctlprefix+['catalog-bundle','verify','-f',str(out)])
        entries=[e for e in entries if e['component']!=row['component']]+[entry(row,out,verified)]
        atomic_json(mp,manifest(entries))
    staged={e['component'] for e in entries}; print(f"HISTORICAL_UPGRADE_STAGE_PASS staged={len(entries)} remaining_helm={len([r for r in helm if r['component'] not in staged])} remaining_tagged={len([r for r in tagged if r['component'] not in staged])} install_only={len(install_only)} waiting_current={len(waiting_current)} path={stage}")
    return 0

def refresh_derived_handoff():
    p=subprocess.run(
        [sys.executable,'scripts/supply_chain_handoff.py','--write','--plan','lab/supply-chain-handoff-plan.json'],
        cwd=ROOT,text=True
    )
    if p.returncode:
        raise RuntimeError(f'SUPPLY_CHAIN_HANDOFF_REFRESH_FAILED rc={p.returncode}')

def install_staged(stage:Path,ctl):
    stage=_regular_dir(_absolute_no_follow(stage),'HISTORICAL_STAGE_DIRECTORY'); mp=_regular_file(stage/MANIFEST,'HISTORICAL_STAGE_MANIFEST'); entries=validate_manifest(stage,_json(mp)); ctlprefix=platformctl(ctl); installed=[]; skipped=[]
    for e in entries:
        lock=ROOT/'catalog/runtime'/e['component']/e['previousVersion']/'source-lock.json'
        if lock.is_file(): skipped.append(e['component']); continue
        b=stage/e['bundleFile']; verified=run_json(ctlprefix+['catalog-bundle','verify','-f',str(b)])
        if verified.get('valid') is not True or verified.get('component')!=e['component'] or str(verified.get('version') or '')!=e['previousVersion'] or str(verified.get('upstreamUrl') or '')!=e['source'] or verified.get('bundleDigest')!=e['bundleDigest']: raise RuntimeError(f'HISTORICAL_STAGE_VERIFY_DRIFT {e["component"]}')
        p=subprocess.run(ctlprefix+['catalog-bundle','install-historical','-f',str(b),'--repo-root',str(ROOT),'--confirmation','IMPORT-HISTORICAL'],cwd=ROOT,text=True)
        if p.returncode: return p.returncode
        refresh_derived_handoff()
        p=subprocess.run([sys.executable,'scripts/validate_repository.py','.'],cwd=ROOT,text=True)
        if p.returncode: return p.returncode
        installed.append(e['component'])
    print(f"HISTORICAL_UPGRADE_INSTALL_STAGED_PASS installed={len(installed)} skipped={len(skipped)}")
    return 0

def self_test():
    helm,tagged,install_only,review,already,waiting_current=classify()
    assert len(helm)+len(tagged)+len(already)+len(waiting_current)==19 and len(install_only)==1 and not review
    assert {r['component'] for r in tagged}=={'gateway-api','snapshot-controller'}
    for row in tagged:
        recipe=ROOT/'catalog/tagged-source-recipes'/row['component']/f"{row['previousVersion']}.json"
        assert recipe.is_file(), recipe
    for row in waiting_current:
        current=_json(ROOT/'catalog/components'/f"{row['component']}.json")
        assert (current.get('spec',{}).get('source') or {}).get('resolved') is not True
    for row in helm+tagged:
        current=_json(ROOT/'catalog/components'/f"{row['component']}.json")
        assert (current.get('spec',{}).get('source') or {}).get('resolved') is True
    assert install_only[0]['component']=='secure-namespace-foundation'
    print(f'HISTORICAL_UPGRADE_BATCH_SELF_TEST_PASS helm_ready={len(helm)} tagged_ready={len(tagged)} waiting_current={len(waiting_current)} install_only={len(install_only)} already={len(already)}')
    return 0

def main():
    p=argparse.ArgumentParser(); modes=p.add_mutually_exclusive_group(required=True); modes.add_argument('--plan',action='store_true'); modes.add_argument('--execute',action='store_true'); modes.add_argument('--stage-out',type=Path); modes.add_argument('--install-staged',type=Path); modes.add_argument('--self-test',action='store_true'); p.add_argument('--json',action='store_true'); p.add_argument('--limit',type=int,default=0); p.add_argument('--platformctl'); a=p.parse_args()
    try:
        if a.plan: return plan(a.json)
        if a.self_test: return self_test()
        if a.execute: return execute(a.limit,a.platformctl)
        if a.stage_out: return stage_out(a.limit,a.stage_out,a.platformctl)
        return install_staged(a.install_staged,a.platformctl)
    except (RuntimeError,OSError,subprocess.TimeoutExpired,ValueError) as e:
        print('HISTORICAL_UPGRADE_BATCH_BLOCKED '+str(e),file=sys.stderr); return 3
if __name__=='__main__': raise SystemExit(main())
