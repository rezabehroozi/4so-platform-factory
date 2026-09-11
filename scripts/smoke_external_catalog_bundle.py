#!/usr/bin/env python3
from __future__ import annotations
import hashlib, io, json, os, shutil, socket, subprocess, sys, tarfile, tempfile, time, urllib.error, urllib.request, zipfile
from pathlib import Path


def run(*args, expect=0):
    p=subprocess.run(args,text=True,capture_output=True)
    if p.returncode!=expect:
        raise RuntimeError(f"command failed rc={p.returncode} expected={expect}: {' '.join(map(str,args))}\nstdout={p.stdout}\nstderr={p.stderr}")
    return p


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0)); return sock.getsockname()[1]


def req(base, path, method="GET", body=None, headers=None):
    data=None if body is None else json.dumps(body).encode(); h=dict(headers or {})
    if data is not None: h["Content-Type"]="application/json"
    r=urllib.request.Request(base+path,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(r,timeout=5) as resp: return resp.status,json.loads(resp.read() or b"null"),dict(resp.headers)
    except urllib.error.HTTPError as e:
        raw=e.read()
        try: parsed=json.loads(raw or b"null")
        except Exception: parsed={"raw":raw.decode(errors="replace")}
        return e.code,parsed,dict(e.headers)


def start_api(binary, root, state):
    port=free_port(); env=os.environ.copy(); env['PLATFORM_FACTORY_DEVELOPMENT_MODE']='true'; env["PLATFORM_FACTORY_LISTEN"]=f"127.0.0.1:{port}"; env["PLATFORM_FACTORY_STATE_FILE"]=str(state)
    p=subprocess.Popen([str(binary)],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True); base=f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if req(base,"/readyz")[0]==200:return p,base
        except Exception:pass
        time.sleep(.1)
    p.terminate(); raise RuntimeError("rebuilt api not ready")


def stop_api(p):
    p.terminate()
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.wait()


def lifecycle(base, release):
    st,review,_=req(base,f"/api/v1/catalog-releases/{release['id']}/review","POST",{}, {"If-Match":f'"{release["revision"]}"'}); assert st==200,(st,review)
    st,pub,_=req(base,f"/api/v1/catalog-releases/{release['id']}/publish","POST",{}, {"If-Match":f'"{review["revision"]}"'}); assert st==200,(st,pub)
    return pub


def make_chart(path: Path, name: str, version: str):
    files={
        f"{name}/Chart.yaml":f"apiVersion: v2\nname: {name}\nversion: {version}\ntype: application\n",
        f"{name}/values.yaml":"{}\n",
        f"{name}/templates/daemonset.yaml":"{{- /* test fixture only: immutable render evidence is supplied separately */ -}}\n",
    }
    with tarfile.open(path,"w:gz") as tf:
        for entry, text in files.items():
            raw=text.encode(); info=tarfile.TarInfo(entry); info.size=len(raw); info.mode=0o644; info.mtime=0
            tf.addfile(info,io.BytesIO(raw))


def digest(path: Path) -> str:
    return "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()


def write_runtime_certification_registry(repo: Path, component: str, release: str):
    path=repo/'catalog/component-runtime-certification.json'; path.parent.mkdir(parents=True,exist_ok=True)
    stages=['install','readiness','dependency','upgrade','remove','failure']
    doc={
        'apiVersion':'platform.4so.io/v1alpha1',
        'kind':'ComponentRuntimeCertificationRegistry',
        'metadata':{'name':'COMPONENT_RUNTIME_CERTIFICATION_REGISTRY_V1'},
        'spec':{
            'policy':{
                'sourceBinding':'exact-component-release-and-source-lock',
                'executorBinding':'component-owned-no-generic-runtime-certification-claim',
                'requiredLifecycleStages':stages,
                'replacementPolicy':'resolved-source-replacement-denied-without-explicit-versioned-migration',
            },
            'components':[{
                'component':component,
                'release':release,
                'sourceBinding':{'status':'blocked-source-lock','resolved':False,'sourceLockDigest':''},
                'executor':{'status':'source-gated-component-executor','profile':'COMPONENT_RUNTIME_V1','owner':'catalog-component'},
                'lifecycle':[{'name':stage,'status':('pending-upgrade-matrix' if stage=='upgrade' else 'source-gated-component-executor'),'evidenceContract':f'component-{stage}-evidence/v1','authority':('COMPONENT_RUNTIME_UPGRADE_V1' if stage=='upgrade' else 'COMPONENT_RUNTIME_V1')} for stage in stages],
            }],
        },
    }
    path.write_text(json.dumps(doc,indent=2,sort_keys=True)+'\n')


def pin_runtime_certification_release(repo: Path, component: str, release: str):
    path=repo/'catalog/component-runtime-certification.json'
    doc=json.loads(path.read_text())
    rows=[row for row in doc['spec']['components'] if row.get('component')==component]
    assert len(rows)==1,rows
    row=rows[0]
    assert row['sourceBinding']=={'status':'blocked-source-lock','resolved':False,'sourceLockDigest':''},row['sourceBinding']
    row['release']=release
    path.write_text(json.dumps(doc,indent=2,sort_keys=True)+'\n')


def assert_runtime_certification_binding(repo: Path, component: str, release: str, source_lock: str):
    doc=json.loads((repo/'catalog/component-runtime-certification.json').read_text())
    rows=[row for row in doc['spec']['components'] if row.get('component')==component]
    assert len(rows)==1,rows
    row=rows[0]
    assert row['release']==release,row
    assert row['sourceBinding']=={'status':'source-ready','resolved':True,'sourceLockDigest':source_lock},row['sourceBinding']
    assert row['executor']=={'status':'component-install-readiness-dependency-failure-remove-partial','profile':'COMPONENT_RUNTIME_V1','owner':'catalog-component'},row['executor']


def admit_helm_component(repo: Path, component: str, chart: str, version: str, source: str):
    authority = repo/'catalog/upstream-admission.json'
    authority.parent.mkdir(parents=True, exist_ok=True)
    if authority.exists():
        doc=json.loads(authority.read_text())
        rows=doc['spec']['components']
        rows[:]=[row for row in rows if row.get('component') != component]
    else:
        doc={
            'apiVersion':'platform.4so.io/v1alpha1',
            'kind':'CatalogUpstreamAdmission',
            'metadata':{'name':'external-catalog-bundle-smoke-admission'},
            'spec':{
                'components':[],
                'policy':{
                    'allowLatestResolution':False,
                    'autoWidenCatalogConstraint':False,
                    'runtimeCertification':'separate-runtime-evidence-required',
                    'candidateAcquisition':'exact-source-may-be-acquired-before-runtime-clearance',
                    'sourceAuthority':'official-upstream-only',
                    'sourceResolution':'separate-immutable-acquisition-required',
                    'versionSelection':'exact-semver-no-prerelease',
                },
            },
        }
        rows=doc['spec']['components']
    rows.append({
        'catalogConstraint':'1.20.x',
        'chart':chart,
        'component':component,
        'rationale':'external catalog bundle smoke fixture',
        'selectedVersion':version,
        'source':source,
        'status':'ready-for-acquisition',
        'runtimeStatus':'dependency-transition-required',
        'reviewEvidence':[{'kind':'blocker','url':'https://docs.cilium.io/en/stable/operations/upgrade/','summary':'Fixture preserves canonical Gateway API dependency transition hold.'}],
        'upstreamVersion':version,
    })
    rows.sort(key=lambda row: row['component'])
    authority.write_text(json.dumps(doc,indent=2,sort_keys=True)+'\n')


def assemble(ctl: Path, component: Path, artifact: Path, render: Path, images: Path, licenses: Path, sbom: Path, generation: Path, version: str, out: Path):
    return run(
        str(ctl),'catalog-bundle','assemble',
        '--component',str(component),'--artifact',str(artifact),'--render-manifest',str(render),
        '--image-inventory',str(images),'--licenses',str(licenses),'--sbom',str(sbom),'--render-generation',str(generation),
        '--version',version,'--source-type','helm-chart','--source-url','oci://quay.io/cilium/charts/cilium',
        '--source-revision',version,'--upstream-artifact-name',artifact.name,'--artifact-digest',digest(artifact),
        '--bundle-key',f'cilium/{version}','--out',str(out),
    )


def main():
    if len(sys.argv)!=2: raise SystemExit("usage: smoke_external_catalog_bundle.py platformctl")
    ctl=Path(sys.argv[1]).resolve(); root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as td:
        t=Path(td)
        component=t/'component.json'
        fixture=json.loads((root/'catalog/components/cilium.json').read_text())
        src=fixture['spec']['source']; src.update({'type':'helm-chart','resolved':False,'bundleKey':'','artifactDigest':'','renderManifestDigest':'','sourceLockDigest':'','imageInventoryDigest':'','licenseManifestDigest':'','signatureVerification':'required','sbom':'required','provenance':'required'})
        fixture['spec']['release']='1.20.1'; fixture['spec']['versionPolicy']='exact-upstream-admitted-pending-source-acquisition'
        component.write_text(json.dumps(fixture,indent=2)+'\n')

        version='1.20.1'; artifact=t/f'cilium-{version}.tgz'; make_chart(artifact,'cilium',version)
        image='quay.io/cilium/cilium@sha256:'+'a'*64
        render=t/'render.json'; render.write_text(json.dumps([{"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"cilium","namespace":"kube-system"},"spec":{"template":{"spec":{"containers":[{"name":"cilium-agent","image":image}]}}}}],indent=2)+'\n')
        images=t/'images.json'; images.write_text(json.dumps({'images':[{'reference':image}]},indent=2)+'\n')
        licenses=t/'licenses.json'; licenses.write_text('{"licenses":[{"file":"LICENSE","spdxExpression":"Apache-2.0"}]}\n')
        sbom=t/'sbom.json'; sbom.write_text(json.dumps({"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":f"cilium-{version}-test-fixture","packages":[{"SPDXID":"SPDXRef-Package-cilium","name":"cilium","versionInfo":version}]})+'\n')
        generation=t/'render-generation.json'; generation.write_text(json.dumps({"tool":"helm-template","toolVersion":"v3.18.6","releaseName":"platform-factory","namespace":"kube-system","includeCRDs":True,"kubernetesVersions":["1.34.0","1.35.0"],"values":[],"imageResolver":"crane-digest","imageResolverVersion":"v0.20.6"},indent=2)+'\n')
        bundle=t/'bundle.zip'

        p=assemble(ctl,component,artifact,render,images,licenses,sbom,generation,version,bundle)
        assembled=json.loads(p.stdout); assert assembled['assembled'] is True and assembled['offlineReady'] is True and assembled['networkFetchRequired'] is False,assembled
        verified=json.loads(run(str(ctl),'catalog-bundle','verify','-f',str(bundle)).stdout)
        assert verified['valid'] is True and verified['component']=='cilium' and verified['version']==version and verified['sourceType']=='helm-chart' and verified['resourceCount']==1 and verified['imageCount']==1,verified
        with zipfile.ZipFile(bundle) as zin:
            lock=json.loads(zin.read('source-lock.json')); provenance=json.loads(zin.read('provenance.json'))
        assert lock['generation']==provenance['generation'],(lock,provenance)
        assert lock['generation']['tool']=='helm-template' and lock['generation']['namespace']=='kube-system',lock['generation']

        # Helm bundles must fail closed if the generating toolchain/inputs are not bound.
        missing_generation=subprocess.run([
            str(ctl),'catalog-bundle','assemble','--component',str(component),'--artifact',str(artifact),'--render-manifest',str(render),
            '--image-inventory',str(images),'--licenses',str(licenses),'--sbom',str(sbom),'--version',version,'--source-type','helm-chart',
            '--source-url','oci://quay.io/cilium/charts/cilium','--source-revision',version,'--upstream-artifact-name',artifact.name,
            '--artifact-digest',digest(artifact),'--bundle-key',f'cilium/{version}','--out',str(t/'missing-generation.zip')
        ],text=True,capture_output=True)
        assert missing_generation.returncode!=0,(missing_generation.stdout,missing_generation.stderr)

        # The CLI must reject a digest that was not independently pinned to the supplied bytes.
        bad_digest=subprocess.run([
            str(ctl),'catalog-bundle','assemble','--component',str(component),'--artifact',str(artifact),'--render-manifest',str(render),
            '--image-inventory',str(images),'--licenses',str(licenses),'--sbom',str(sbom),'--render-generation',str(generation),'--version',version,'--source-type','helm-chart',
            '--source-url','oci://quay.io/cilium/charts/cilium','--source-revision',version,'--upstream-artifact-name',artifact.name,
            '--artifact-digest','sha256:'+'f'*64,'--bundle-key',f'cilium/{version}','--out',str(t/'bad-digest.zip')
        ],text=True,capture_output=True)
        assert bad_digest.returncode!=0,(bad_digest.stdout,bad_digest.stderr)

        repo=t/'repo'; (repo/'catalog/components').mkdir(parents=True); (repo/'VERSION').write_text('test\n'); shutil.copy2(component,repo/'catalog/components/cilium.json')
        write_runtime_certification_registry(repo,'cilium',version)
        admit_helm_component(repo,'cilium','cilium',version,'oci://quay.io/cilium/charts/cilium')
        installed=json.loads(run(str(ctl),'catalog-bundle','install','-f',str(bundle),'--repo-root',str(repo),'--confirmation','IMPORT').stdout)
        assert installed['installed'] is True and installed['networkFetchRequired'] is False,installed
        retired=json.loads((repo/'catalog/upstream-admission.json').read_text())
        assert not any(row.get('component')=='cilium' for row in retired['spec']['components']),retired
        run(str(ctl),'catalog-bundle','install','-f',str(bundle),'--repo-root',str(repo),'--confirmation','IMPORT')
        resolved=json.loads((repo/'catalog/components/cilium.json').read_text())
        src=resolved['spec']['source']; assert src['resolved'] is True and src['type']=='helm-chart' and src['bundleKey']==f'cilium/{version}' and src['renderManifestDigest'].startswith('sha256:'),src
        assert_runtime_certification_binding(repo,'cilium',version,src['sourceLockDigest'])
        assert resolved['spec']['delivery']['type']=='helm' and resolved['spec']['delivery']['chart']=='cilium',resolved['spec']['delivery']
        for name in ('artifact.bin','bundle-manifest.json','render-manifest.json','source-lock.json','image-inventory.json','licenses.json','sbom.spdx.json','provenance.json'):
            assert (repo/'catalog/runtime/cilium'/version/name).is_file(),name

        # Tamper one payload while keeping the original bundle manifest; verification must fail.
        tampered=t/'tampered.zip'
        with zipfile.ZipFile(bundle) as zin, zipfile.ZipFile(tampered,'w',zipfile.ZIP_DEFLATED) as zout:
            for info in zin.infolist():
                data=zin.read(info.filename)
                if info.filename=='artifact.bin': data=b'TAMPERED\n'
                zout.writestr(info.filename,data)
        bad=subprocess.run([str(ctl),'catalog-bundle','verify','-f',str(tampered)],text=True,capture_output=True)
        assert bad.returncode!=0,(bad.stdout,bad.stderr)

        # Prove import -> rebuild -> runtime catalog/render in an isolated source tree.
        rebuild=t/'rebuild-source'; shutil.copytree(root,rebuild,ignore=shutil.ignore_patterns('.git','bin','dist','release','__pycache__'))
        # Source admission has a separate exact-version pin step before immutable
        # acquisition. Model that source commit consistently across the component
        # and runtime-certification release binding; source remains unresolved.
        shutil.copy2(component,rebuild/'catalog/components/cilium.json')
        pin_runtime_certification_release(rebuild,'cilium',version)
        shutil.rmtree(rebuild/'catalog/runtime/cilium',ignore_errors=True)
        admit_helm_component(rebuild,'cilium','cilium',version,'oci://quay.io/cilium/charts/cilium')
        run(str(ctl),'catalog-bundle','install','-f',str(bundle),'--repo-root',str(rebuild),'--confirmation','IMPORT')
        rebuilt_component=json.loads((rebuild/'catalog/components/cilium.json').read_text())
        assert_runtime_certification_binding(rebuild,'cilium',version,rebuilt_component['spec']['source']['sourceLockDigest'])
        validation=subprocess.run([sys.executable,'scripts/validate_repository.py','.'],cwd=rebuild,text=True,capture_output=True); assert validation.returncode==0,(validation.stdout,validation.stderr)
        retired=json.loads((rebuild/'catalog/upstream-admission.json').read_text())
        assert not any(row.get('component')=='cilium' for row in retired['spec']['components']),retired
        gt=subprocess.run(['go','test','./catalog'],cwd=rebuild,text=True,capture_output=True); assert gt.returncode==0,(gt.stdout,gt.stderr)
        rebuilt_api=t/'platform-api-imported'; build_version=(rebuild/'VERSION').read_text().strip(); build_ldflags=f'-s -w -buildid= -X platform.4so.io/factory/internal/buildinfo.Version={build_version}'; gb=subprocess.run(['go','build','-trimpath','-ldflags',build_ldflags,'-o',str(rebuilt_api),'./cmd/platform-api'],cwd=rebuild,text=True,capture_output=True); assert gb.returncode==0,(gb.stdout,gb.stderr)
        state=t/'imported-api-state.json'; proc,base=start_api(rebuilt_api,rebuild,state)
        try:
            st,org,_=req(base,'/api/v1/organizations','POST',{'name':'external-bundle-smoke','displayName':'External Bundle Smoke'}); assert st==201,(st,org)
            st,signer,_=req(base,'/api/v1/catalog-governance/signing-identity'); assert st==200 and signer.get('available') is True,(st,signer)
            st,key,_=req(base,'/api/v1/catalog-trust-keys','POST',{'organizationId':org['id'],'name':'external-bundle-test-signer','publicKey':signer['publicKey']}); assert st==201,(st,key)
            st,components,_=req(base,'/api/v1/catalog/components'); assert st==200,(st,components)
            selected=[c for c in components if c.get('metadata',{}).get('name')=='cilium']; assert len(selected)==1,selected
            assert selected[0]['spec']['source']['resolved'] is True and selected[0]['spec']['source']['type']=='helm-chart',selected[0]['spec']['source']
            assert selected[0]['spec']['delivery']['type']=='helm' and selected[0]['spec']['delivery']['chart']=='cilium',selected[0]['spec']['delivery']
            st,created,_=req(base,'/api/v1/catalog-releases','POST',{'organizationId':org['id'],'catalogName':'external-test-fixture','catalogVersion':version,'visibility':'PRIVATE','channel':'CANDIDATE','components':selected}); assert st==201,(st,created)
            candidate=lifecycle(base,created['release'])
            st,promoted,_=req(base,f"/api/v1/catalog-releases/{candidate['id']}/promote",'POST',{'channel':'RENDER'}); assert st==201,(st,promoted)
            render_release=lifecycle(base,promoted['release'])
            st,rendered,_=req(base,f"/api/v1/catalog-releases/{render_release['id']}/render",'POST',{'namespace':'external-bundle-smoke'}); assert st==200,(st,rendered)
            assert rendered['resourceCount']==1 and rendered['components'][0]['name']=='cilium',rendered
            assert rendered['components'][0]['sourceEvidence']['sourceType']=='helm-chart',rendered
        finally: stop_api(proc)

        # A different resolved bundle cannot silently replace the imported component.
        version2='1.20.2'; artifact2=t/f'cilium-{version2}.tgz'; make_chart(artifact2,'cilium',version2)
        replacement_component=t/'component-replacement.json'
        replacement_fixture=json.loads(component.read_text()); replacement_fixture['spec']['release']=version2
        replacement_component.write_text(json.dumps(replacement_fixture,indent=2)+'\n')
        sbom.write_text(json.dumps({"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":f"cilium-{version2}-test-fixture","packages":[{"SPDXID":"SPDXRef-Package-cilium","name":"cilium","versionInfo":version2}]})+'\n')
        bundle2=t/'bundle2.zip'; assemble(ctl,replacement_component,artifact2,render,images,licenses,sbom,generation,version2,bundle2)
        replace=subprocess.run([str(ctl),'catalog-bundle','install','-f',str(bundle2),'--repo-root',str(repo),'--confirmation','IMPORT'],text=True,capture_output=True)
        assert replace.returncode!=0,(replace.stdout,replace.stderr)
        print('EXTERNAL_CATALOG_BUNDLE_IMPORT_SMOKE_PASS',verified['bundleDigest'],verified['upstreamArtifactDigest'],verified['resourceCount'],verified['imageCount'])
    return 0

if __name__=='__main__': raise SystemExit(main())
