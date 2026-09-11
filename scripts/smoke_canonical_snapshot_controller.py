#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request, zipfile
from pathlib import Path

EXPECTED_IMAGE='registry.k8s.io/sig-storage/snapshot-controller@sha256:74ca61ab13e978f03cf0f336a607281d15f04cda0a38a881306365473b28a3d8'

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]

def req(base,path,method='GET',body=None,headers=None):
    data=None if body is None else json.dumps(body).encode(); h=dict(headers or {})
    if data is not None: h['Content-Type']='application/json'
    r=urllib.request.Request(base+path,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(r,timeout=5) as resp: return resp.status,json.loads(resp.read() or b'null')
    except urllib.error.HTTPError as e:
        raw=e.read()
        try: parsed=json.loads(raw or b'null')
        except Exception: parsed={'raw':raw.decode(errors='replace')}
        return e.code,parsed

def start(binary,root,state):
    port=free_port(); env=os.environ.copy(); env['PLATFORM_FACTORY_DEVELOPMENT_MODE']='true'; env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}'; env['PLATFORM_FACTORY_STATE_FILE']=str(state)
    p=subprocess.Popen([str(binary)],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True); base=f'http://127.0.0.1:{port}'
    for _ in range(100):
        try:
            if req(base,'/readyz')[0]==200:return p,base
        except Exception:pass
        time.sleep(.1)
    p.terminate(); raise RuntimeError('api not ready')

def stop(p):
    p.terminate()
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.wait()

def lifecycle(base,rel):
    st,r=req(base,f"/api/v1/catalog-releases/{rel['id']}/review",'POST',{}, {'If-Match':f'"{rel["revision"]}"'}); assert st==200,(st,r)
    st,r=req(base,f"/api/v1/catalog-releases/{rel['id']}/publish",'POST',{}, {'If-Match':f'"{r["revision"]}"'}); assert st==200,(st,r)
    return r

def sha(raw): return 'sha256:'+hashlib.sha256(raw).hexdigest()

def main():
    if len(sys.argv)!=2: raise SystemExit('usage: smoke_canonical_snapshot_controller.py platform-api')
    binary=Path(sys.argv[1]).resolve(); root=Path(__file__).resolve().parents[1]
    expected_version=(root/'VERSION').read_text().strip()
    comp=json.loads((root/'catalog/components/snapshot-controller.json').read_text()); src=comp['spec']['source']
    assert comp['spec']['release']=='8.5.0',comp['spec']['release']
    assert src['resolved'] is True and src['type']=='external-tagged-source-set',src
    assert src['bundleKey']=='snapshot-controller/8.5.0',src
    runtime=root/'catalog/runtime/snapshot-controller/8.5.0'
    artifact=(runtime/'artifact.bin').read_bytes(); assert sha(artifact)==src['artifactDigest']
    with zipfile.ZipFile(runtime/'artifact.bin') as z:
        idx=json.loads(z.read('source-index.json'))
        assert idx['component']=='snapshot-controller' and idx['version']=='8.5.0' and idx['upstream']['revision']=='v8.5.0',idx
        assert idx['upstream']['releaseCommitShort']=='5aab051',idx
        assert idx['assembly']['networkFetchRequired'] is False
        assert len(idx['files'])==6,idx['files']
        for f in idx['files']:
            assert sha(z.read(f['path']))==f['sha256'],f
    inventory=json.loads((runtime/'image-inventory.json').read_text())
    refs=[x['reference'] for x in inventory.get('images',[])]
    assert refs==[EXPECTED_IMAGE],refs
    with tempfile.TemporaryDirectory() as td:
        state=Path(td)/'state.json'; p,base=start(binary,root,state)
        try:
            st,ver=req(base,'/api/v1/version'); assert st==200 and ver['version']==expected_version,(st,ver)
            st,org=req(base,'/api/v1/organizations','POST',{'name':'canonical-snapshot-controller-smoke','displayName':'Canonical Snapshot Controller Smoke'}); assert st==201,(st,org)
            st,signer=req(base,'/api/v1/catalog-governance/signing-identity'); assert st==200 and signer.get('available') is True,(st,signer)
            st,key=req(base,'/api/v1/catalog-trust-keys','POST',{'organizationId':org['id'],'name':'canonical-snapshot-signer','publicKey':signer['publicKey']}); assert st==201,(st,key)
            st,components=req(base,'/api/v1/catalog/components'); assert st==200,(st,components)
            selected=[c for c in components if c.get('metadata',{}).get('name')=='snapshot-controller']; assert len(selected)==1,selected
            c=selected[0]; assert c['spec']['source']['resolved'] is True and c['spec']['release']=='8.5.0',c
            st,created=req(base,'/api/v1/catalog-releases','POST',{'organizationId':org['id'],'catalogName':'canonical-snapshot-controller','catalogVersion':'8.5.0','visibility':'PRIVATE','channel':'CANDIDATE','components':selected}); assert st==201,(st,created)
            candidate=lifecycle(base,created['release'])
            st,prom=req(base,f"/api/v1/catalog-releases/{candidate['id']}/promote",'POST',{'channel':'RENDER'}); assert st==201,(st,prom)
            render_rel=lifecycle(base,prom['release'])
            st,rendered=req(base,f"/api/v1/catalog-releases/{render_rel['id']}/render",'POST',{'namespace':'kube-system'}); assert st==200,(st,rendered)
            assert rendered['resourceCount']==9,rendered
            resources=rendered['resources']
            names={(r.get('kind'),r.get('metadata',{}).get('name')) for r in resources}
            required={
                ('CustomResourceDefinition','volumesnapshotclasses.snapshot.storage.k8s.io'),
                ('CustomResourceDefinition','volumesnapshotcontents.snapshot.storage.k8s.io'),
                ('CustomResourceDefinition','volumesnapshots.snapshot.storage.k8s.io'),
                ('Deployment','snapshot-controller'),('ServiceAccount','snapshot-controller'),
                ('ClusterRole','snapshot-controller-runner'),('ClusterRoleBinding','snapshot-controller-role'),
                ('Role','snapshot-controller-leaderelection'),('RoleBinding','snapshot-controller-leaderelection'),
            }
            assert required==names,(required-names,names-required)
            deployment=next(r for r in resources if r.get('kind')=='Deployment')
            assert deployment.get('metadata',{}).get('namespace')=='kube-system',deployment.get('metadata')
            containers=deployment['spec']['template']['spec']['containers']; images=[x.get('image','') for x in containers]
            assert images==[EXPECTED_IMAGE],images
            for image in images:
                assert '@sha256:' in image and ':v8.5.0' not in image,image
            assert rendered['components'][0]['sourceEvidence']['sourceType']=='external-tagged-source-set',rendered['components'][0]
            print('CANONICAL_SNAPSHOT_CONTROLLER_RESOLUTION_SMOKE_PASS',src['artifactDigest'],EXPECTED_IMAGE,rendered['renderedDigest'],rendered['resourceCount'])
        finally: stop(p)
    return 0
if __name__=='__main__': raise SystemExit(main())
