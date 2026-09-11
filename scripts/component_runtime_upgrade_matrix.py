#!/usr/bin/env python3
"""Build/validate the exact-source-pair component runtime upgrade matrix.

This is an admission authority, not a certification shortcut. An upgrade edge is
admitted only when both from/to releases have independently verified source
locks and distinct exact source digests. A current-only lock therefore remains
PENDING_SOURCE_PAIR and cannot satisfy S2.
"""
from __future__ import annotations
import argparse, hashlib, json, pathlib, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
AUTHORITY="COMPONENT_RUNTIME_UPGRADE_MATRIX_V2"
FIRST_RELEASE_STATUS="install-only-first-product-release"

def upgrade_admission_map():
    p=ROOT/"catalog"/"component-upgrade-source-admission.json"
    if not p.exists(): return {}
    d=json.loads(p.read_text())
    return {str(r.get("component") or ""): r for r in (d.get("components") or [])}

def digest_obj(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()).hexdigest()

def exact_release_key(release):
    text=str(release).strip().lstrip('v')
    parts=text.split('.')
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)

def source_lock(name, release):
    p=ROOT/'catalog'/'runtime'/name/release/'source-lock.json'
    if not p.exists(): return None
    d=json.loads(p.read_text())
    # A sibling path alone is not authority. The lock must bind itself to the
    # exact component/release represented by the path or it is ignored.
    if str(d.get('component') or '') != str(name) or str(d.get('version') or '') != str(release):
        return None
    return {'path':str(p.relative_to(ROOT)),'digest':digest_obj(d),'lock':d}

def build():
    entries=[]
    admissions=upgrade_admission_map()
    for p in sorted((ROOT/'catalog'/'components').glob('*.json')):
        d=json.loads(p.read_text()); name=d['metadata']['name']; release=str(d['spec']['release'])
        cur=source_lock(name,release)
        # Previous versions must be explicitly installed as source-lock siblings;
        # never infer them from chart repositories or mutable tags.
        rt=ROOT/'catalog'/'runtime'/name
        previous=[]
        if rt.exists():
            for q in sorted(rt.iterdir()):
                if q.is_dir() and q.name != release and (q/'source-lock.json').exists():
                    previous.append((q.name,source_lock(name,q.name)))
        edges=[]
        target_key=exact_release_key(release)
        for prev, lock in previous:
            prev_key=exact_release_key(prev)
            # Upgrade admission is directional and exact-version only. Wildcards,
            # aliases and a numerically newer sibling cannot be treated as an
            # upgrade-from edge.
            if not cur or not lock or not target_key or not prev_key or prev_key >= target_key or lock['digest']==cur['digest']:
                continue
            edges.append({'fromRelease':prev,'toRelease':release,'fromSourceLockDigest':lock['digest'],'toSourceLockDigest':cur['digest'],'status':'admitted-source-pair'})
        admission=admissions.get(name) or {}
        first_release=admission.get('status')==FIRST_RELEASE_STATUS
        if first_release:
            status=FIRST_RELEASE_STATUS
            edges=[]
            executor='install-readiness-failure-remove-only'
        else:
            status='admitted-source-pair' if edges else 'pending-source-pair'
            executor='COMPONENT_RUNTIME_UPGRADE_V1'
        entries.append({'component':name,'targetRelease':release,'targetSourceLockDigest':cur['digest'] if cur else '', 'status':status,'admittedEdges':edges,'upgradeExecutor':executor})
    return {
      'apiVersion':'platform.4so.io/v1alpha1','kind':'ComponentRuntimeUpgradeMatrix','authority':AUTHORITY,'schemaVersion':1,
      'policy':{
        'sourcePairRequiredForUpgradeRequiredComponents':True,'firstProductReleaseInstallOnlyAllowed':True,'historicalVersionFabricationForbidden':True,'distinctSourceLockDigestsRequired':True,'mutableTagResolutionForbidden':True,'exactVersionDirectionRequired':True,'sourceLockSelfIdentityRequired':True,
        'downgradeAdmission':'forbidden-by-default','rollbackMeaning':'recovery-evidence-only; no fake rollback promise',
        'stages':['preflight','upgrade','readiness','failure-recovery','remove-old-version'],
        'certificationRule':'source-pair admission does not equal runtime PASS; every admitted edge requires exact execution evidence before S2 closure.'
      },
      'components':entries
    }

def validate(d):
    errs=[]
    if d.get('authority')!=AUTHORITY: errs.append('authority mismatch')
    policy=d.get('policy') or {}
    if policy.get('exactVersionDirectionRequired') is not True or policy.get('sourceLockSelfIdentityRequired') is not True: errs.append('fail-closed upgrade policy missing')
    comps=d.get('components') or []
    expected={json.loads(p.read_text())['metadata']['name'] for p in (ROOT/'catalog'/'components').glob('*.json')}
    actual={x.get('component') for x in comps}
    if actual!=expected: errs.append(f'component coverage mismatch missing={sorted(expected-actual)} extra={sorted(actual-expected)}')
    for c in comps:
        if c.get('status') not in {'pending-source-pair','admitted-source-pair',FIRST_RELEASE_STATUS}: errs.append(f"{c.get('component')}: invalid status")
        if c.get('status')==FIRST_RELEASE_STATUS and (edges or c.get('upgradeExecutor')!='install-readiness-failure-remove-only'): errs.append(f"{c.get('component')}: first release must be install-only without upgrade edge")
        edges=c.get('admittedEdges') or []
        if c.get('status')=='admitted-source-pair' and not edges: errs.append(f"{c.get('component')}: admitted without edge")
        for e in edges:
            if not e.get('fromSourceLockDigest') or not e.get('toSourceLockDigest'): errs.append(f"{c.get('component')}: edge missing exact source lock")
            if e.get('fromSourceLockDigest')==e.get('toSourceLockDigest'): errs.append(f"{c.get('component')}: edge reuses same source lock")
            if e.get('fromRelease')==e.get('toRelease'): errs.append(f"{c.get('component')}: edge versions are identical")
            fk=exact_release_key(e.get('fromRelease')); tk=exact_release_key(e.get('toRelease'))
            if not fk or not tk or fk >= tk: errs.append(f"{c.get('component')}: edge is not a strict exact-version upgrade")
    return errs

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--write',action='store_true'); ap.add_argument('--check',action='store_true'); args=ap.parse_args()
    expected=build(); out=ROOT/'catalog'/'component-runtime-upgrade-matrix.json'
    if args.write:
        out.write_text(json.dumps(expected,indent=2)+"\n")
    if args.check:
        if not out.exists(): print('COMPONENT_RUNTIME_UPGRADE_MATRIX_FAIL missing matrix'); return 1
        actual=json.loads(out.read_text()); errs=validate(actual)
        if digest_obj(actual)!=digest_obj(expected): errs.append('matrix drift: regenerate from current component/source-lock authority')
        if errs:
            print('COMPONENT_RUNTIME_UPGRADE_MATRIX_FAIL ' + '; '.join(errs)); return 1
        admitted=sum(1 for x in actual['components'] if x['status']=='admitted-source-pair')
        install_only=sum(1 for x in actual['components'] if x['status']==FIRST_RELEASE_STATUS)
        pending=sum(1 for x in actual['components'] if x['status']=='pending-source-pair')
        print(f'COMPONENT_RUNTIME_UPGRADE_MATRIX_PASS components={len(actual["components"])} admitted={admitted} pending={pending} install_only_first_release={install_only}')
    return 0
if __name__=='__main__': raise SystemExit(main())
