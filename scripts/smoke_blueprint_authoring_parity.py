#!/usr/bin/env python3
from __future__ import annotations
import json, os, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]

def req(url, method='GET', body=None):
    data=None if body is None else json.dumps(body,separators=(',',':')).encode()
    headers={'X-Actor-ID':'author'}
    if data is not None: headers['Content-Type']='application/json'
    r=urllib.request.Request(url,data=data,method=method,headers=headers)
    try:
        with urllib.request.urlopen(r,timeout=5) as resp:
            raw=resp.read(); return resp.status,json.loads(raw or b'null')
    except urllib.error.HTTPError as e:
        raw=e.read()
        try: payload=json.loads(raw or b'null')
        except Exception: payload={'raw':raw.decode(errors='replace')}
        return e.code,payload

def start(binary, root, state):
    port=free_port(); env=os.environ.copy(); env['PLATFORM_FACTORY_DEVELOPMENT_MODE']='true'; env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}'; env['PLATFORM_FACTORY_STATE_FILE']=str(state)
    p=subprocess.Popen([str(binary)],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    base=f'http://127.0.0.1:{port}'
    for _ in range(100):
        try:
            if req(base+'/readyz')[0]==200:return p,base
        except Exception: pass
        time.sleep(.1)
    p.terminate(); raise RuntimeError('api not ready')

def stop(p):
    p.terminate()
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.wait()

def main():
    if len(sys.argv)!=2: raise SystemExit('usage: smoke_blueprint_authoring_parity.py platform-api')
    binary=Path(sys.argv[1]).resolve(); root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as td:
        state=Path(td)/'state.json'; p,base=start(binary,root,state)
        try:
            st,version=req(base+'/api/v1/version'); assert st==200 and version['version']==EXPECTED_VERSION,(st,version)
            st,contract=req(base+'/api/v1/blueprints/authoring-contract'); assert st==200,(st,contract)
            assert contract['method']=='BLUEPRINT_VISUAL_API_AUTHORING_PARITY_V1' and contract['strictUnknownFields'] is True and contract['fieldCount']>=27
            paths={x['path'] for x in contract['fields']}
            for required in ('spec.components[].settings','spec.governance.approvalRequiredFor','spec.tenancy.deletionPolicy','spec.delivery.mode'): assert required in paths,required
            blueprint=json.loads((root/'blueprints/enterprise-private-cloud.json').read_text())
            blueprint['metadata']={'name':'authoring-parity','version':'1.0.0'}
            blueprint['spec']['description']='Visual and API exact authoring parity smoke'
            blueprint['spec']['governance']['approvalRequiredFor']=['low','medium','high','critical']
            for c in blueprint['spec']['components']:
                if c['name']=='metallb': c['settings']={'addressPool':'192.0.2.100-192.0.2.120','speaker':{'mode':'layer2'}}
            st,out=req(base+'/api/v1/blueprints/authoring-roundtrip','POST',blueprint); assert st==200,(st,out)
            assert out['method']==contract['method'] and out['validation']['valid'] is True
            assert out['blueprint']==blueprint,(out['blueprint'],blueprint)
            assert json.loads(out['canonicalJson'])==blueprint
            bad=dict(blueprint); bad['unknownTopLevel']='rejected'
            st,badout=req(base+'/api/v1/blueprints/authoring-roundtrip','POST',bad); assert st==400,(st,badout)
            st,org=req(base+'/api/v1/organizations','POST',{'name':'authoring-parity','displayName':'Authoring Parity'}); assert st==201,(st,org)
            st,project=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'platform','displayName':'Platform'}); assert st==201,(st,project)
            st,created=req(base+'/api/v1/blueprint-releases','POST',{'projectId':project['id'],'blueprint':blueprint}); assert st==201,(st,created)
            rid=created['release']['id']
            st,view=req(base+f'/api/v1/blueprint-releases/{rid}'); assert st==200,(st,view)
            assert view['baseBlueprint']==blueprint and view['blueprint']==blueprint
            print('BLUEPRINT_AUTHORING_PARITY_SMOKE_PASS',contract['fieldCount'],out['digest'],rid)
        finally: stop(p)
    return 0
if __name__=='__main__': raise SystemExit(main())
