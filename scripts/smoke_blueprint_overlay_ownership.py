#!/usr/bin/env python3
from __future__ import annotations
import json, os, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()

def free_port():
    with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]

def req(url, method='GET', body=None, headers=None):
    data=None if body is None else json.dumps(body).encode(); h=dict(headers or {})
    if data is not None: h['Content-Type']='application/json'
    request=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(request,timeout=5) as response:
            raw=response.read(); return response.status,json.loads(raw or b'null'),dict(response.headers)
    except urllib.error.HTTPError as error:
        raw=error.read()
        try: parsed=json.loads(raw or b'null')
        except Exception: parsed={'raw':raw.decode(errors='replace')}
        return error.code,parsed,dict(error.headers)

def start(binary: Path, root: Path, state: Path):
    port=free_port(); env=os.environ.copy(); env['PLATFORM_FACTORY_DEVELOPMENT_MODE']='true'; env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}'; env['PLATFORM_FACTORY_STATE_FILE']=str(state)
    process=subprocess.Popen([str(binary)],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    base=f'http://127.0.0.1:{port}'
    for _ in range(100):
        try:
            if req(base+'/readyz')[0]==200: return process,base
        except Exception: pass
        time.sleep(.1)
    process.terminate(); raise RuntimeError('api not ready')

def stop(process):
    process.terminate()
    try: process.wait(timeout=5)
    except subprocess.TimeoutExpired: process.kill(); process.wait()

def create_overlay(base, project_id, name, scope, scope_key, changes):
    st,value,_=req(base+'/api/v1/blueprint-overlays','POST',{'projectId':project_id,'name':name,'version':'1.0.0','scope':scope,'scopeKey':scope_key,'changes':changes})
    assert st==201,(st,value); return value

def main():
    if len(sys.argv)!=2: raise SystemExit('usage: smoke_blueprint_overlay_ownership.py platform-api')
    binary=Path(sys.argv[1]).resolve(); root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as temp:
        state=Path(temp)/'control-plane.json'; process,base=start(binary,root,state)
        try:
            st,ver,_=req(base+'/api/v1/version'); assert st==200 and ver['version']==EXPECTED_VERSION,(st,ver)
            st,org,_=req(base+'/api/v1/organizations','POST',{'name':'overlay-smoke','displayName':'Overlay Smoke'}); assert st==201,(st,org)
            st,project,_=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'platform','displayName':'Platform'}); assert st==201,(st,project)
            provider=create_overlay(base,project['id'],'vsphere-provider','PROVIDER','vsphere',[{'path':'/spec/delivery/repository','value':'http://platform-forgejo.platform-system.svc.cluster.local:3000/provider/desired-state.git'},{'path':'/spec/description','value':'Provider baseline'}])
            environment=create_overlay(base,project['id'],'production-environment','ENVIRONMENT','production',[{'path':'/spec/description','value':'Production environment resolved blueprint'},{'path':'/spec/certification/requiredLevel','value':'render'},{'path':'/spec/certification/evidenceRetentionDays','value':730}])
            assert provider['digest'].startswith('sha256:') and environment['digest'].startswith('sha256:')

            blueprint=json.loads((root/'blueprints/enterprise-private-cloud.json').read_text())
            blueprint['metadata']['name']='overlay-smoke'; blueprint['metadata']['version']='1.0.0'
            base_repository=blueprint['spec']['delivery']['repository']; base_description=blueprint['spec']['description']
            body={'projectId':project['id'],'providerOverlayId':provider['id'],'environmentOverlayId':environment['id'],'blueprint':blueprint}
            st,preview,_=req(base+'/api/v1/blueprints/resolve','POST',body); assert st==200,(st,preview)
            resolved=preview['blueprint']; resolution=preview['resolution']
            assert resolved['spec']['delivery']['repository']!=base_repository
            assert resolved['spec']['description']=='Production environment resolved blueprint'
            assert resolved['spec']['certification']['requiredLevel']=='render'
            assert resolution['providerOverlayId']==provider['id'] and resolution['environmentOverlayId']==environment['id']
            owners={row['path']:row['effectiveOwner'] for row in resolution['fields']}
            assert owners['/spec/delivery/repository']=='PROVIDER:vsphere',owners
            assert owners['/spec/description']=='ENVIRONMENT:production',owners

            st,created,_=req(base+'/api/v1/blueprint-releases','POST',body); assert st==201,(st,created)
            release=created['release']
            st,created_view,_=req(base+f"/api/v1/blueprint-releases/{release['id']}"); assert st==200,(st,created_view)
            revision=created_view['revision']
            assert created['baseBlueprint']['spec']['delivery']['repository']==base_repository
            assert created['baseBlueprint']['spec']['description']==base_description
            assert created['blueprint']['spec']['description']=='Production environment resolved blueprint'
            assert revision['providerOverlayId']==provider['id'] and revision['environmentOverlayId']==environment['id']
            for key in ('baseBlueprintDigest','overlayDigest','ownershipDigest'):
                assert revision[key].startswith('sha256:'),(key,revision[key])

            conflict=create_overlay(base,project['id'],'bad-environment','ENVIRONMENT','bad',[{'path':'/spec/delivery/repository','value':'https://git.example.org/forbidden.git'}])
            conflict_body=dict(body); conflict_body['environmentOverlayId']=conflict['id']
            st,error,_=req(base+'/api/v1/blueprints/resolve','POST',conflict_body); assert st==422,(st,error)
            assert 'FIELD_OWNERSHIP_CONFLICT' in json.dumps(error),error

            st,error,_=req(base+'/api/v1/blueprint-overlays','POST',{'projectId':project['id'],'name':'bad-secret','version':'1.0.0','scope':'ENVIRONMENT','scopeKey':'prod','changes':[{'path':'/spec/components/0/settings/apiToken','value':'plaintext-secret-value'}]}); assert st==422,(st,error)
            release_id=release['id']; provider_id=provider['id']; environment_id=environment['id']
        finally: stop(process)

        process,base=start(binary,root,state)
        try:
            st,view,_=req(base+f'/api/v1/blueprint-releases/{release_id}'); assert st==200,(st,view)
            assert view['revision']['providerOverlayId']==provider_id and view['revision']['environmentOverlayId']==environment_id
            assert view['baseBlueprint']['spec']['description']!=view['blueprint']['spec']['description']
            st,overlays,_=req(base+f"/api/v1/blueprint-overlays?projectId={project['id']}"); assert st==200,(st,overlays)
            ids={item['id'] for item in overlays}; assert {provider_id,environment_id}.issubset(ids),ids
            print('BLUEPRINT_OVERLAY_OWNERSHIP_SMOKE_PASS',release_id,view['revision']['overlayDigest'],len(overlays))
        finally: stop(process)
    return 0

if __name__=='__main__': raise SystemExit(main())
