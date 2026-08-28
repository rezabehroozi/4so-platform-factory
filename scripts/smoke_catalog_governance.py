#!/usr/bin/env python3
from __future__ import annotations
import json, os, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]

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
    port=free_port(); env=os.environ.copy(); env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}'; env['PLATFORM_FACTORY_STATE_FILE']=str(state)
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
    if len(sys.argv)!=2: raise SystemExit('usage: smoke_catalog_governance.py platform-api')
    binary=Path(sys.argv[1]).resolve(); root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as temp:
        state=Path(temp)/'control-plane.json'; process,base=start(binary,root,state)
        try:
            st,org,_=req(base+'/api/v1/organizations','POST',{'name':'catalog-smoke','displayName':'Catalog Smoke'}); assert st==201,(st,org)
            st,project,_=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'platform','displayName':'Platform'}); assert st==201,(st,project)
            st,signer,_=req(base+'/api/v1/catalog-governance/signing-identity'); assert st==200 and signer.get('available') is True,(st,signer)
            st,key,_=req(base+'/api/v1/catalog-trust-keys','POST',{'organizationId':org['id'],'name':'catalog-smoke-signer','publicKey':signer['publicKey']}); assert st==201,(st,key)
            st,components,_=req(base+'/api/v1/catalog/components'); assert st==200 and components,(st,components)
            st,created,_=req(base+'/api/v1/catalog-releases','POST',{'organizationId':org['id'],'catalogName':'private-platform-standard','catalogVersion':'1.0.0','visibility':'PRIVATE','channel':'CANDIDATE','components':components}); assert st==201,(st,created)
            release=created['release']; assert release['state']=='DRAFT' and release['channel']=='CANDIDATE'
            st,review,_=req(base+f"/api/v1/catalog-releases/{release['id']}/review",'POST',{}, {'If-Match':f'"{release["revision"]}"'}); assert st==200,(st,review); assert review['state']=='REVIEW' and review['signature']
            st,published,_=req(base+f"/api/v1/catalog-releases/{release['id']}/publish",'POST',{}, {'If-Match':f'"{review["revision"]}"'}); assert st==200,(st,published); assert published['state']=='PUBLISHED'
            blueprint=json.loads((root/'blueprints/enterprise-private-cloud.json').read_text()); blueprint['metadata']['name']='catalog-bound-smoke'; blueprint['metadata']['version']='1.0.0'; blueprint['spec']['description']='Catalog-bound smoke Blueprint'
            st,bp_created,_=req(base+'/api/v1/blueprint-releases','POST',{'projectId':project['id'],'catalogReleaseId':published['id'],'blueprint':blueprint}); assert st==201,(st,bp_created); bp=bp_created['release']; assert bp['catalogReleaseId']==published['id']
            st,bp_review,_=req(base+f"/api/v1/blueprint-releases/{bp['id']}/review",'POST',{}, {'If-Match':f'"{bp["revision"]}"'}); assert st==200,(st,bp_review)
            st,impact,_=req(base+f"/api/v1/catalog-trust-keys/{key['id']}/impact"); assert st==200,(st,impact); assert len(impact['catalogReleases'])==1 and len(impact['blueprintReleases'])==1
            st,promoted,_=req(base+f"/api/v1/catalog-releases/{published['id']}/promote",'POST',{}); assert st==201,(st,promoted); render=promoted['release']; assert render['channel']=='RENDER' and render['sourceReleaseId']==published['id']
            st,render_review,_=req(base+f"/api/v1/catalog-releases/{render['id']}/review",'POST',{}, {'If-Match':f'"{render["revision"]}"'}); assert st==200,(st,render_review)
            st,blocked,_=req(base+f"/api/v1/catalog-releases/{render['id']}/publish",'POST',{}, {'If-Match':f'"{render_review["revision"]}"'}); assert st==422,(st,blocked); assert blocked['error']['code']=='CATALOG_CHANNEL_ADMISSION_FAILED'

            # Exercise CANDIDATE -> RENDER and prove that digest-shaped metadata
            # cannot cross the RUNTIME authority boundary without a real
            # TARGET_RUNTIME_V1 control-plane certification run.
            foundation=next(c for c in components if c['metadata']['name']=='secure-namespace-foundation')
            st,flow_created,_=req(base+'/api/v1/catalog-releases','POST',{'organizationId':org['id'],'catalogName':'channel-lifecycle-smoke','catalogVersion':'1.0.0','visibility':'PRIVATE','channel':'CANDIDATE','components':[foundation]}); assert st==201,(st,flow_created)
            flow=flow_created['release']

            def review_publish(current):
                st,reviewed,_=req(base+f"/api/v1/catalog-releases/{current['id']}/review",'POST',{}, {'If-Match':f'"{current["revision"]}"'}); assert st==200,(st,reviewed)
                st,pub,_=req(base+f"/api/v1/catalog-releases/{current['id']}/publish",'POST',{}, {'If-Match':f'"{reviewed["revision"]}"'}); assert st==200,(st,pub)
                return pub

            flow=review_publish(flow)
            st,next_release,_=req(base+f"/api/v1/catalog-releases/{flow['id']}/promote",'POST',{'channel':'RENDER'}); assert st==201,(st,next_release)
            flow=review_publish(next_release['release']); assert flow['channel']=='RENDER'

            st,next_release,_=req(base+f"/api/v1/catalog-releases/{flow['id']}/promote",'POST',{'channel':'RUNTIME'}); assert st==201,(st,next_release)
            runtime_draft=next_release['release']
            runtime_component=json.loads(json.dumps(foundation)); runtime_component['spec']['certification']['status']='target-runtime-certified'; runtime_component['spec']['certification']['evidenceDigest']='sha256:'+'a'*64; runtime_component['spec']['certification']['profiles']=['TARGET_RUNTIME_V1']
            st,runtime_detail,_=req(base+f"/api/v1/catalog-releases/{runtime_draft['id']}/draft",'PUT',{'components':[runtime_component]}, {'If-Match':f'"{runtime_draft["revision"]}"'}); assert st==200,(st,runtime_detail)
            st,runtime_review,_=req(base+f"/api/v1/catalog-releases/{runtime_draft['id']}/review",'POST',{}, {'If-Match':f'"{runtime_detail["release"]["revision"]}"'}); assert st==200,(st,runtime_review)
            st,runtime_blocked,_=req(base+f"/api/v1/catalog-releases/{runtime_draft['id']}/publish",'POST',{}, {'If-Match':f'"{runtime_review["revision"]}"'}); assert st==422,(st,runtime_blocked)
            assert runtime_blocked['error']['code']=='CATALOG_CHANNEL_ADMISSION_FAILED' and any('not backed by an active TARGET_RUNTIME_V1' in x for x in runtime_blocked['admission']['blockers']),(st,runtime_blocked)
            flow=runtime_review
        finally: stop(process)
        process,base=start(binary,root,state)
        try:
            st,releases,_=req(base+'/api/v1/catalog-releases'); assert st==200 and len(releases)==5,(st,releases)
            st,detail,_=req(base+f"/api/v1/catalog-releases/{published['id']}"); assert st==200 and detail['trust']['verified'] is True,(st,detail)
            st,revoked,_=req(base+f"/api/v1/catalog-trust-keys/{key['id']}/revoke",'POST',{}, {'If-Match':f'"{key["revision"]}"'}); assert st==200,(st,revoked)
            st,rejected,_=req(base+f"/api/v1/blueprint-releases/{bp_review['id']}/publish",'POST',{}, {'If-Match':f'"{bp_review["revision"]}"'}); assert st==422,(st,rejected)
            print('CATALOG_GOVERNANCE_SMOKE_PASS',published['id'],render['id'],flow['id'],bp['id'])
        finally: stop(process)
    return 0

if __name__=='__main__': raise SystemExit(main())
