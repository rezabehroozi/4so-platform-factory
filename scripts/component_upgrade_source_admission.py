#!/usr/bin/env python3
"""Canonical explicit review authority for S2 historical upgrade-source acquisition.

Selection/admission is deliberately separate from byte acquisition and runtime
certification. Product-owned first releases may be install-only certified rather
than inventing a historical predecessor that never existed.
"""
from __future__ import annotations
import argparse, json, pathlib, re
ROOT=pathlib.Path(__file__).resolve().parents[1]
AUTHORITY='COMPONENT_UPGRADE_SOURCE_ADMISSION_V1'
EXACT=re.compile(r'^\d+\.\d+\.\d+$')
ALLOWED={'review-required','admitted-for-acquisition','install-only-first-product-release'}
POLICIES=(
    'explicitHumanOrReleaseReviewRequired','exactPreviousVersionRequired',
    'strictUpgradeDirectionRequired','mutableTagForbidden','admissionDoesNotEqualCertification',
    'reviewEvidenceRequiredForAdmission','firstProductReleaseInstallOnlyAllowed',
    'historicalVersionFabricationForbidden',
)

def key(v):
    if not EXACT.fullmatch(str(v)): return None
    return tuple(map(int,str(v).split('.')))

def load_components(root=ROOT):
    out={}
    for p in sorted((root/'catalog'/'components').glob('*.json')):
        d=json.loads(p.read_text()); out[d['metadata']['name']]=d
    return out

def seed(root=ROOT):
    comps=load_components(root)
    return {
      'apiVersion':'platform.4so.io/v1alpha1','kind':'ComponentUpgradeSourceAdmission',
      'authority':AUTHORITY,'schemaVersion':1,
      'policy':{
        'explicitHumanOrReleaseReviewRequired':True,'exactPreviousVersionRequired':True,
        'strictUpgradeDirectionRequired':True,'mutableTagForbidden':True,
        'admissionDoesNotEqualCertification':True,'reviewEvidenceRequiredForAdmission':True,
        'firstProductReleaseInstallOnlyAllowed':True,'historicalVersionFabricationForbidden':True,
      },
      'components':[{
        'component':n,'targetRelease':str(d['spec']['release']),'status':'review-required',
        'previousVersion':'','source':'','licenseSPDX':'',
        'rationale':'Explicit previous exact release and source require review before historical acquisition.',
        'reviewEvidence':[],
      } for n,d in sorted(comps.items())]
    }

def _valid_review_evidence(rows, *, upstream):
    if not isinstance(rows,list) or not rows: return False
    for ev in rows:
        if not isinstance(ev,dict) or set(ev) != {'kind','reference','summary'}: return False
        if not str(ev.get('summary') or '').strip(): return False
        ref=str(ev.get('reference') or '')
        if upstream:
            if ev.get('kind')!='upstream-release-history' or not ref.startswith('https://'): return False
        else:
            if ev.get('kind')!='product-release-history' or not ref.startswith('repo://'): return False
    return True

def _first_product_release_eligible(name, component, target, root):
    spec=component.get('spec') or {}; src=spec.get('source') or {}
    if target!='1.0.0' or spec.get('versionPolicy')!='exact-embedded-release' or src.get('type')!='embedded-native' or src.get('resolved') is not True:
        return False
    runtime=root/'catalog'/'runtime'/name
    if runtime.exists():
        for child in runtime.iterdir():
            if child.is_dir() and child.name != target and (child/'source-lock.json').exists():
                return False
    return True

def validate(doc,root=ROOT):
    errs=[]; comps=load_components(root)
    if doc.get('authority')!=AUTHORITY or doc.get('kind')!='ComponentUpgradeSourceAdmission' or doc.get('schemaVersion')!=1: errs.append('identity invalid')
    pol=doc.get('policy') or {}
    for k in POLICIES:
        if pol.get(k) is not True: errs.append('policy missing '+k)
    rows=doc.get('components') or []; seen=set()
    for r in rows:
        n=str(r.get('component') or ''); target=str(r.get('targetRelease') or '')
        if n not in comps or n in seen: errs.append('component coverage invalid '+n); continue
        seen.add(n)
        if target!=str(comps[n]['spec']['release']): errs.append(f'{n}: target release drift')
        st=r.get('status'); prev=str(r.get('previousVersion') or ''); src=str(r.get('source') or ''); license_spdx=str(r.get('licenseSPDX') or '')
        evidence=r.get('reviewEvidence')
        if st not in ALLOWED: errs.append(f'{n}: status invalid'); continue
        if st=='admitted-for-acquisition':
            if not key(prev) or not key(target) or key(prev)>=key(target): errs.append(f'{n}: previous version must be exact and lower')
            if not (src.startswith('https://') or src.startswith('oci://')): errs.append(f'{n}: source invalid')
            if not SPDX.fullmatch(license_spdx): errs.append(f'{n}: licenseSPDX required')
            if not str(r.get('rationale') or '').strip(): errs.append(f'{n}: rationale required')
            if not _valid_review_evidence(evidence,upstream=True): errs.append(f'{n}: upstream review evidence required')
        elif st=='install-only-first-product-release':
            if prev or src or license_spdx: errs.append(f'{n}: first product release must not fabricate previousVersion/source/license')
            if not _first_product_release_eligible(n,comps[n],target,root): errs.append(f'{n}: install-only status is not eligible for this component')
            if not str(r.get('rationale') or '').strip(): errs.append(f'{n}: rationale required')
            if not _valid_review_evidence(evidence,upstream=False): errs.append(f'{n}: product release history evidence required')
        else:
            if prev or src or license_spdx: errs.append(f'{n}: review-required row must not pre-authorize previousVersion/source/license')
            if evidence not in ([],None): errs.append(f'{n}: review-required row must not pre-authorize review evidence')
    if seen!=set(comps): errs.append('coverage mismatch')
    return errs

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--check',action='store_true'); ap.add_argument('--seed',action='store_true'); ap.add_argument('--file',default='catalog/component-upgrade-source-admission.json'); a=ap.parse_args(); p=ROOT/a.file
    if a.seed:
        if p.exists(): print('COMPONENT_UPGRADE_SOURCE_ADMISSION_FAIL refusing to overwrite canonical admission'); return 1
        p.write_text(json.dumps(seed(),indent=2)+'\n')
    if a.check:
        if not p.exists(): print('COMPONENT_UPGRADE_SOURCE_ADMISSION_FAIL missing'); return 1
        doc=json.loads(p.read_text()); e=validate(doc)
        if e: print('COMPONENT_UPGRADE_SOURCE_ADMISSION_FAIL '+'; '.join(e)); return 1
        rows=doc['components']; admitted=sum(r['status']=='admitted-for-acquisition' for r in rows); review=sum(r['status']=='review-required' for r in rows); install_only=sum(r['status']=='install-only-first-product-release' for r in rows)
        print(f'COMPONENT_UPGRADE_SOURCE_ADMISSION_PASS components={len(rows)} admitted={admitted} review={review} install_only_first_release={install_only}')
    if not (a.seed or a.check): ap.error('choose --seed or --check')
    return 0
if __name__=='__main__': raise SystemExit(main())
