#!/usr/bin/env python3
from __future__ import annotations
import json, os, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]

def req(url, method='GET', body=None, headers=None):
    data=None if body is None else json.dumps(body).encode(); h=dict(headers or {})
    if data is not None: h['Content-Type']='application/json'
    request=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(request,timeout=5) as response:
            raw=response.read(); return response.status,json.loads(raw or b'null'),dict(response.headers)
    except urllib.error.HTTPError as error:
        raw=error.read()
        try: body=json.loads(raw or b'null')
        except Exception: body={'raw':raw.decode(errors='replace')}
        return error.code,body,dict(error.headers)

def start(binary: Path, root: Path, state: Path):
    port=free_port(); env=os.environ.copy(); env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}'; env['PLATFORM_FACTORY_STATE_FILE']=str(state);env['PLATFORM_FACTORY_DEVELOPMENT_MODE']='true'
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

def main():
    if len(sys.argv)!=2: raise SystemExit('usage: smoke_blueprint_lifecycle.py platform-api')
    binary=Path(sys.argv[1]).resolve(); root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as temp:
        state=Path(temp)/'control-plane.json'; process,base=start(binary,root,state)
        try:
            st,org,_=req(base+'/api/v1/organizations','POST',{'name':'blueprint-smoke','displayName':'Blueprint Smoke'}); assert st==201,(st,org)
            st,project,_=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'platform','displayName':'Platform'}); assert st==201,(st,project)
            blueprint=json.loads((root/'blueprints/enterprise-private-cloud.json').read_text())
            blueprint['metadata']['name']='lifecycle-smoke'; blueprint['metadata']['version']='1.0.0'
            blueprint['spec']['description']='Lifecycle smoke release'
            st,created,h=req(base+'/api/v1/blueprint-releases','POST',{'projectId':project['id'],'blueprint':blueprint}); assert st==201,(st,created); release=created['release']; assert release['state']=='DRAFT' and h.get('Etag')=='"1"'
            blueprint['spec']['description']='Lifecycle smoke release revision two'
            st,updated,h=req(base+f"/api/v1/blueprint-releases/{release['id']}/draft",'PUT',{'blueprint':blueprint},{'If-Match':'"1"'}); assert st==200,(st,updated); release=updated['release']; assert release['revision']==2 and h.get('Etag')=='"2"'
            st,review,_=req(base+f"/api/v1/blueprint-releases/{release['id']}/review",'POST',{}, {'If-Match':'"2"'}); assert st==200,(st,review); assert review['state']=='REVIEW'
            st,published,_=req(base+f"/api/v1/blueprint-releases/{release['id']}/publish",'POST',{}, {'If-Match':'"3"'}); assert st==200,(st,published); assert published['state']=='PUBLISHED'
            st,rejected,_=req(base+f"/api/v1/blueprint-releases/{release['id']}/draft",'PUT',{'blueprint':blueprint},{'If-Match':'"4"'}); assert st==409,(st,rejected)
            st,clone,_=req(base+f"/api/v1/blueprint-releases/{release['id']}/clone",'POST',{'name':'lifecycle-smoke','version':'1.1.0'}); assert st==201,(st,clone); clone_release=clone['release']; assert clone_release['state']=='DRAFT' and clone_release['upgradeFromIds']==[release['id']]
            st,comparison,_=req(base+'/api/v1/blueprint-releases/compare','POST',{'leftReleaseId':release['id'],'rightReleaseId':clone_release['id']}); assert st==200,(st,comparison); assert comparison['differenceCount']>=1 and comparison['equal'] is False
        finally: stop(process)
        process,base=start(binary,root,state)
        try:
            st,releases,_=req(base+f"/api/v1/blueprint-releases?projectId={project['id']}"); assert st==200,(st,releases); assert len(releases)==2 and any(row['state']=='PUBLISHED' for row in releases)
            print('BLUEPRINT_LIFECYCLE_SMOKE_PASS',release['id'],clone_release['id'],comparison['differenceCount'])
        finally: stop(process)
    return 0

if __name__=='__main__': raise SystemExit(main())
