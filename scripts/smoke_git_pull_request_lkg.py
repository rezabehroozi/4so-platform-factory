#!/usr/bin/env python3
from __future__ import annotations
import base64, hashlib, json, os, socket, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()
from urllib.parse import parse_qs, unquote, urlparse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def free_port():
    s=socket.socket();s.bind(('127.0.0.1',0));p=s.getsockname()[1];s.close();return p

def request(base,path,method='GET',body=None,headers=None):
    import urllib.request, urllib.error
    raw=None if body is None else json.dumps(body).encode(); h={'Accept':'application/json'};h.update(headers or {})
    if raw is not None:h['Content-Type']='application/json'
    req=urllib.request.Request(base+path,data=raw,method=method,headers=h)
    try:r=urllib.request.urlopen(req,timeout=8);data=r.read();return r.status,(json.loads(data) if data else None),dict(r.headers)
    except urllib.error.HTTPError as e:
        data=e.read();
        try:obj=json.loads(data)
        except Exception:obj={'raw':data.decode(errors='replace')}
        return e.code,obj,dict(e.headers)

def stop(p):
    if p and p.poll() is None:
        p.terminate()
        try:p.wait(5)
        except subprocess.TimeoutExpired:p.kill();p.wait()

def revision(key,suffix):
    spec={'productVersion':EXPECTED_VERSION,'specDigest':'sha256:'+suffix*64,'bundleDigest':'sha256:'+('b' if suffix!='b' else 'c')*64,'publicEndpoint':'https://platform.example.test','gitEndpoint':'https://git.example.test','registryEndpoint':'https://registry.example.test','identityEndpoint':'https://auth.example.test'}
    canonical=json.dumps(spec,separators=(',',':')).encode(); raw=hashlib.sha256(canonical).digest(); digest='sha256:'+raw.hex(); sig=key.sign(raw); pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw); fp='sha256:'+hashlib.sha256(pub).hexdigest();rid='revision-'+raw.hex()[:16]
    desc={'apiVersion':'platform.4so.io/v1alpha1','kind':'PlatformRevision','metadata':{'id':rid},'spec':spec,'integrity':{'digest':digest,'signature':base64.b64encode(sig).decode(),'publicKeyFingerprint':fp}}
    pem='-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(pub).decode()+'\n-----END PUBLIC KEY-----\n'
    state=f'''apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: platform-managed-state\n  namespace: platform-system\n  labels:\n    platform.4so.io/ownership: gitops\n    platform.4so.io/revision: {rid}\ndata:\n  productVersion: {json.dumps(spec['productVersion'])}\n  specDigest: {json.dumps(spec['specDigest'])}\n  bundleDigest: {json.dumps(spec['bundleDigest'])}\n  publicEndpoint: {json.dumps(spec['publicEndpoint'])}\n  gitEndpoint: {json.dumps(spec['gitEndpoint'])}\n  registryEndpoint: {json.dumps(spec['registryEndpoint'])}\n  identityEndpoint: {json.dumps(spec['identityEndpoint'])}\n'''
    marker=f'''apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: platform-gitops-revision\n  namespace: platform-system\n  labels:\n    platform.4so.io/ownership: gitops\n    platform.4so.io/revision: {rid}\ndata:\n  revisionID: {json.dumps(rid)}\n  revisionDigest: {json.dumps(digest)}\n  signature: {json.dumps(base64.b64encode(sig).decode())}\n  publicKeyFingerprint: {json.dumps(fp)}\n'''
    files={'.platform/revision.json':json.dumps(desc,indent=2)+'\n','.platform/revision.sig':base64.b64encode(sig).decode()+'\n','.platform/public-key.pem':pem,'clusters/appliance/platform-managed-state.yaml':state,'clusters/appliance/platform-gitops-revision.yaml':marker,'clusters/appliance/kustomization.yaml':'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - platform-managed-state.yaml\n  - platform-gitops-revision.yaml\n'}
    return {'id':rid,'digest':digest,'fingerprint':fp,'files':files}

class GitState:
    def __init__(self):
        seed={'README.md':'# Managed Platform Desired State\n\nThis repository is generated and managed by 4SO Platform Factory.\n'}; self.lock=threading.Lock(); self.counter=1; self.branches={'main':dict(seed)}; self.heads={'main':'0'*40}; self.snapshots={'0'*40:dict(seed)}; self.prs={}; self.next_pr=1; self.allow_ff=False; self.argo_revision=''; self.argo_sync='OutOfSync'; self.argo_health='Progressing'; self.cas_conflict_once=False
    def commit(self,branch):
        self.counter+=1;sha=f'{self.counter:040x}'[-40:];self.heads[branch]=sha;self.snapshots[sha]=dict(self.branches[branch]);return sha

def git_server(state):
    port=free_port()
    class H(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def sendj(self,code,obj):
            raw=json.dumps(obj).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def authed(self):return self.headers.get('Authorization','').startswith('Basic ')
        def parse_body(self):
            n=int(self.headers.get('Content-Length','0'));return json.loads(self.rfile.read(n) or b'{}')
        def do_GET(self):
            u=urlparse(self.path);path=u.path;q=parse_qs(u.query)
            if path=='/api/v1/version':return self.sendj(200,{'version':'1.20.0'})
            if not self.authed():return self.sendj(401,{'message':'auth'})
            if path=='/api/v1/orgs/platform':return self.sendj(200,{'username':'platform'})
            if path=='/api/v1/repos/platform/desired-state':return self.sendj(200,{'name':'desired-state','html_url':'http://git/platform/desired-state','clone_url':'http://git/platform/desired-state.git','owner':{'login':'platform'},'allow_fast_forward_only_merge':state.allow_ff})
            bp='/api/v1/repos/platform/desired-state/branches/'
            if path.startswith(bp):
                b=unquote(path[len(bp):]);
                with state.lock:sha=state.heads.get(b)
                return self.sendj(200,{'commit':{'id':sha}}) if sha else self.sendj(404,{'message':'branch not found'})
            pref='/api/v1/repos/platform/desired-state/pulls/'
            if path=='/api/v1/repos/platform/desired-state/pulls':
                with state.lock:
                    rows=[]
                    for n,pr in sorted(state.prs.items()):
                        rows.append({'number':n,'html_url':f'http://git/platform/desired-state/pulls/{n}','state':pr['state'],'merged':pr.get('merged',False),'merge_commit_sha':pr.get('merge_commit_sha',''),'base':{'ref':pr['base'],'sha':state.heads.get(pr['base'],'')},'head':{'ref':pr['head'],'sha':state.heads.get(pr['head'],'')}})
                return self.sendj(200,rows)
            if path.startswith(pref):
                rest=path[len(pref):];parts=rest.split('/');
                try:n=int(parts[0])
                except ValueError:return self.sendj(404,{'message':'bad pr'})
                with state.lock:pr=state.prs.get(n); headsha=state.heads.get(pr['head'],'') if pr else ''; basesha=state.heads.get(pr['base'],'') if pr else ''
                if not pr:return self.sendj(404,{'message':'missing'})
                if len(parts)>1 and parts[1]=='reviews':
                    return self.sendj(200,[{'state':'APPROVED','dismissed':False}] if pr.get('approved') else [])
                return self.sendj(200,{'number':n,'html_url':f'http://git/platform/desired-state/pulls/{n}','state':pr['state'],'merged':pr.get('merged',False),'merge_commit_sha':pr.get('merge_commit_sha',''),'base':{'ref':pr['base'],'sha':basesha},'head':{'ref':pr['head'],'sha':headsha}})
            cmp='/api/v1/repos/platform/desired-state/compare/'
            if path.startswith(cmp):
                spec=unquote(path[len(cmp):]);base,head=spec.split('...',1)
                with state.lock:
                    a=state.snapshots.get(base,{});b=state.snapshots.get(head,{})
                    names=sorted({*a.keys(),*b.keys()});changed=[n for n in names if a.get(n)!=b.get(n)]
                return self.sendj(200,{'files':[{'filename':n} for n in changed]})
            cp='/api/v1/repos/platform/desired-state/contents'
            if path==cp or path.startswith(cp+'/'):
                name='' if path==cp else unquote(path[len(cp)+1:]);ref=(q.get('ref') or ['main'])[0]
                with state.lock:
                    files=state.branches.get(ref) if ref in state.branches else state.snapshots.get(ref)
                    if files is None:return self.sendj(404,{'message':'not found'})
                    if name and name in files:
                        content=files[name]
                        return self.sendj(200,{'name':name.rsplit('/',1)[-1],'path':name,'type':'file','sha':'sha-'+hashlib.sha256(content.encode()).hexdigest()[:16],'content':base64.b64encode(content.encode()).decode()})
                    prefix=(name.rstrip('/')+'/') if name else ''
                    children={}
                    for full,content in files.items():
                        if not full.startswith(prefix):continue
                        rest=full[len(prefix):]
                        if not rest:continue
                        first=rest.split('/',1)[0]; child=prefix+first
                        children[child]='dir' if '/' in rest else 'file'
                    if not children:return self.sendj(404,{'message':'not found'})
                    rows=[{'name':child.rsplit('/',1)[-1],'path':child,'type':typ,'sha':'dir' if typ=='dir' else 'sha-'+hashlib.sha256(files[child].encode()).hexdigest()[:16]} for child,typ in sorted(children.items())]
                return self.sendj(200,rows)
            return self.sendj(404,{'message':'not found','path':path})
        def do_POST(self):
            path=urlparse(self.path).path
            if not self.authed():return self.sendj(401,{'message':'auth'})
            if path=='/api/v1/repos/platform/desired-state/branches':
                b=self.parse_body();new=b['new_branch_name'];old=b.get('old_branch_name','main')
                with state.lock:
                    if new in state.branches:return self.sendj(409,{'message':'exists'})
                    state.branches[new]=dict(state.branches[old]);state.heads[new]=state.heads[old]
                return self.sendj(201,{'name':new})
            if path=='/api/v1/repos/platform/desired-state/pulls':
                b=self.parse_body()
                with state.lock:
                    n=state.next_pr;state.next_pr+=1;state.prs[n]={'number':n,'base':b['base'],'head':b['head'],'base_sha':state.heads.get(b['base'],''),'state':'open','approved':False,'merged':False,'merge_commit_sha':''}
                return self.sendj(201,{'number':n,'html_url':f'http://git/platform/desired-state/pulls/{n}','state':'open'})
            pref='/api/v1/repos/platform/desired-state/pulls/'
            if path.startswith(pref) and path.endswith('/reviews'):
                n=int(path[len(pref):].split('/')[0]);b=self.parse_body();
                with state.lock:
                    if n not in state.prs:return self.sendj(404,{'message':'missing'})
                    if b.get('event')!='APPROVED':return self.sendj(400,{'message':'bad event'})
                    state.prs[n]['approved']=True
                return self.sendj(201,{'id':100+n,'state':'APPROVED'})
            if path.startswith(pref) and path.endswith('/merge'):
                n=int(path[len(pref):].split('/')[0]);b=self.parse_body()
                with state.lock:
                    pr=state.prs.get(n)
                    if not pr:return self.sendj(404,{'message':'missing'})
                    headsha=state.heads.get(pr['head'],'')
                    if b.get('head_commit_id') and b.get('head_commit_id')!=headsha:return self.sendj(409,{'message':'head changed'})
                    if b.get('Do')=='fast-forward-only':
                        if not state.allow_ff:return self.sendj(405,{'message':'fast-forward-only disabled'})
                        if state.cas_conflict_once:
                            state.cas_conflict_once=False
                            return self.sendj(409,{'message':'simulated concurrent base update'})
                        if state.heads.get(pr['base'])!=pr.get('base_sha'):return self.sendj(409,{'message':'base moved; ff-only rejected'})
                        state.branches[pr['base']]=dict(state.branches[pr['head']]);state.heads[pr['base']]=headsha;state.snapshots[headsha]=dict(state.branches[pr['base']]);sha=headsha
                    else:
                        if not pr['approved']:return self.sendj(409,{'message':'not approved'})
                        state.branches[pr['base']]=dict(state.branches[pr['head']]);sha=state.commit(pr['base'])
                    pr['state']='closed';pr['merged']=True;pr['merge_commit_sha']=sha
                return self.sendj(200,{'merged':True,'sha':sha})
            if path=='/api/v1/repos/platform/desired-state/contents':
                b=self.parse_body();branch=b.get('branch','main');ops=b.get('files') or []
                with state.lock:
                    if branch not in state.branches:return self.sendj(404,{'message':'branch missing'})
                    updated=dict(state.branches[branch])
                    for op in ops:
                        name=op.get('path','');operation=op.get('operation');content=base64.b64decode(op.get('content','')).decode()
                        if operation not in ('create','update') or not name:return self.sendj(422,{'message':'bad file operation'})
                        updated[name]=content
                    state.branches[branch]=updated;sha=state.commit(branch)
                return self.sendj(201,{'commit':{'sha':sha},'files':[{'path':op.get('path','')} for op in ops]})
            if path.startswith('/api/v1/repos/platform/desired-state/contents/'):
                return self.write_content(path,201)
            return self.sendj(404,{'message':'not found','path':path})
        def do_PATCH(self):
            path=urlparse(self.path).path
            if not self.authed():return self.sendj(401,{'message':'auth'})
            if path=='/api/v1/repos/platform/desired-state':
                b=self.parse_body()
                with state.lock:
                    if b.get('allow_fast_forward_only_merge') is True:state.allow_ff=True
                return self.sendj(200,{'name':'desired-state','allow_fast_forward_only_merge':state.allow_ff})
            return self.sendj(404,{'message':'not found'})
        def do_PUT(self):
            path=urlparse(self.path).path
            if not self.authed():return self.sendj(401,{'message':'auth'})
            if path.startswith('/api/v1/repos/platform/desired-state/contents/'):return self.write_content(path,200)
            return self.sendj(404,{'message':'not found'})
        def write_content(self,path,code):
            name=unquote(path[len('/api/v1/repos/platform/desired-state/contents/'):]);b=self.parse_body();branch=b.get('branch','main');content=base64.b64decode(b['content']).decode()
            with state.lock:
                if branch not in state.branches:return self.sendj(404,{'message':'branch missing'})
                state.branches[branch][name]=content;sha=state.commit(branch)
            return self.sendj(code,{'content':{'path':name},'commit':{'sha':sha}})
    srv=ThreadingHTTPServer(('127.0.0.1',port),H);threading.Thread(target=srv.serve_forever,daemon=True).start();return srv,f'http://127.0.0.1:{port}'

def argo_server(state):
    port=free_port()
    class H(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def sendj(self,code,obj):
            raw=json.dumps(obj).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def do_GET(self):
            path=urlparse(self.path).path
            if path=='/healthz':return self.sendj(200,{'status':'ok'})
            if path=='/api/v1/applications/platform-appliance':
                with state.lock: rev=state.argo_revision; sync=state.argo_sync; health=state.argo_health
                return self.sendj(200,{'metadata':{'name':'platform-appliance'},'status':{'sync':{'status':sync,'revision':rev},'health':{'status':health}}})
            return self.sendj(404,{'message':'not found'})
    srv=ThreadingHTTPServer(('127.0.0.1',port),H);threading.Thread(target=srv.serve_forever,daemon=True).start();return srv,f'http://127.0.0.1:{port}'

def start_api(binary,state_file,git_url,argo_url):
    port=free_port();env=os.environ.copy(); env['PLATFORM_FACTORY_DEVELOPMENT_MODE']='true';env.update({'PLATFORM_FACTORY_LISTEN':f'127.0.0.1:{port}','PLATFORM_FACTORY_STATE_FILE':str(state_file),'PLATFORM_FACTORY_AGENT_MTLS_REQUIRED':'false','PLATFORM_FACTORY_INTERNAL_GIT_URL':git_url,'PLATFORM_FACTORY_INTERNAL_GIT_USERNAME':'admin','PLATFORM_FACTORY_INTERNAL_GIT_PASSWORD':'secret','PLATFORM_FACTORY_INTERNAL_GIT_BOOTSTRAP':'true','PLATFORM_FACTORY_INTERNAL_GITOPS_URL':argo_url});p=subprocess.Popen([str(binary)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);base=f'http://127.0.0.1:{port}'
    for _ in range(100):
        try:
            if request(base,'/readyz')[0]==200:return p,base
        except Exception:pass
        time.sleep(.1)
    stop(p);raise RuntimeError('api not ready')

def admin():return {'X-Actor-ID':'git-admin','X-Actor-Role':'platform-admin'}

def main():
    if len(sys.argv)!=2:raise SystemExit('usage: smoke_git_pull_request_lkg.py platform-api')
    binary=Path(sys.argv[1]).resolve();key=Ed25519PrivateKey.generate();r1=revision(key,'a');r2=revision(key,'c');state=GitState();srv,git_url=git_server(state);argo,argo_url=argo_server(state)
    try:
      with tempfile.TemporaryDirectory() as td:
        sf=Path(td)/'state.json';p,base=start_api(binary,sf,git_url,argo_url)
        try:
            st,v,_=request(base,'/api/v1/version');assert st==200 and v['version']==EXPECTED_VERSION,(st,v)
            st,candidate,h=request(base,'/api/v1/system-services/git/revisions','POST',{'organization':'platform','repository':'desired-state','revisionId':r1['id'],'digest':r1['digest'],'deliveryMode':'PULL_REQUEST','files':r1['files']},{'X-Actor-ID':'publisher'});assert st==202,(st,candidate);pr=candidate['pullRequest'];assert pr['state']=='OPEN' and pr['headBranch'].startswith('platform-revision-'),pr
            st,bad,_=request(base,f"/api/v1/system-services/git/pull-requests/{pr['id']}/merge",'POST',{},dict(admin(),**{'If-Match':str(pr['revision'])}));assert st in (409,422), (st,bad)
            st,pr,_=request(base,f"/api/v1/system-services/git/pull-requests/{pr['id']}/approve",'POST',{},dict(admin(),**{'If-Match':str(pr['revision'])}));assert st==200 and pr['state']=='APPROVED',(st,pr)
            st,merged,_=request(base,f"/api/v1/system-services/git/pull-requests/{pr['id']}/merge",'POST',{},dict(admin(),**{'If-Match':str(pr['revision'])}));assert st==200,(st,merged);managed=merged['managedRevision'];assert managed['deliveryMode']=='PULL_REQUEST' and managed['pullRequestId']==pr['id'] and merged['mergeVerified'] is True,merged
            with state.lock: state.argo_revision=managed['commitSha'];state.argo_sync='Synced';state.argo_health='Healthy'
            st,sync,_=request(base,f"/api/v1/system-services/git/revisions/{managed['id']}/observe-sync",'POST',{},dict(admin(),**{'If-Match':str(managed['revision'])}));assert st==200 and sync['lastKnownGood'] is True and sync['observationAuthority']=='ARGOCD_APPLICATION_STATUS_V1',(st,sync);lkg=sync['revision']
            # Canonical bundle validation must reject incomplete signed revision input before any Git side effect.
            incomplete=dict(r2['files']);incomplete.pop('clusters/appliance/kustomization.yaml')
            with state.lock: before_heads=dict(state.heads);before_prs=len(state.prs)
            st,rejected,_=request(base,'/api/v1/system-services/git/revisions','POST',{'organization':'platform','repository':'desired-state','revisionId':r2['id'],'digest':r2['digest'],'deliveryMode':'PULL_REQUEST','files':incomplete},{'X-Actor-ID':'publisher'});assert st==400 and rejected.get('error',{}).get('code')=='INVALID_SIGNED_GIT_REVISION',(st,rejected)
            with state.lock: assert dict(state.heads)==before_heads and len(state.prs)==before_prs,(state.heads,state.prs)
            # Neither PR nor direct delivery may bless unmanaged drift already present on main.
            with state.lock:
                state.branches['main']['UNMANAGED-DRIFT.txt']='external'; state.commit('main')
            st,drifted_pr,_=request(base,'/api/v1/system-services/git/revisions','POST',{'organization':'platform','repository':'desired-state','revisionId':r2['id'],'digest':r2['digest'],'deliveryMode':'PULL_REQUEST','files':r2['files']},{'X-Actor-ID':'publisher'});assert st==409 and drifted_pr.get('error',{}).get('code')=='GIT_BASE_AUTHORITY_CHANGED',(st,drifted_pr)
            st,drifted,_=request(base,'/api/v1/system-services/git/revisions','POST',{'organization':'platform','repository':'desired-state','revisionId':r2['id'],'digest':r2['digest'],'deliveryMode':'DIRECT_COMMIT','files':r2['files']},{'X-Actor-ID':'publisher'});assert st==409 and drifted.get('error',{}).get('code')=='GIT_BASE_AUTHORITY_CHANGED',(st,drifted)
            with state.lock:
                state.branches['main']=dict(state.snapshots[managed['commitSha']]); state.heads['main']=managed['commitSha']; state.cas_conflict_once=True
            # Simulated branch-CAS conflict must fail without recording authority; retry may reconcile the exact staged commit.
            st,conflicted,_=request(base,'/api/v1/system-services/git/revisions','POST',{'organization':'platform','repository':'desired-state','revisionId':r2['id'],'digest':r2['digest'],'deliveryMode':'DIRECT_COMMIT','files':r2['files']},{'X-Actor-ID':'publisher'});assert st==409 and conflicted.get('error',{}).get('code')=='INTERNAL_GIT_REVISION_FAILED',(st,conflicted)
            st,pub,_=request(base,'/api/v1/system-services/git/revisions','POST',{'organization':'platform','repository':'desired-state','revisionId':r2['id'],'digest':r2['digest'],'deliveryMode':'DIRECT_COMMIT','files':r2['files']},{'X-Actor-ID':'publisher'});assert st==200,(st,pub);r2id=pub['authorityId'];r2rev=pub['authorityRevision']
            st,bad,_=request(base,f'/api/v1/system-services/git/revisions/{r2id}/observe-sync','POST',{},dict(admin(),**{'If-Match':str(r2rev)}));assert st==422 and bad.get('error',{}).get('code')=='GITOPS_REVISION_NOT_HEALTHY',(st,bad)
            st,current,_=request(base,'/api/v1/system-services/git/last-known-good?organization=platform&repository=desired-state&branch=main');assert st==200 and current['revision']['id']==lkg['id'],(st,current)
        finally:stop(p)
        p,base=start_api(binary,sf,git_url,argo_url)
        try:
            st,current,_=request(base,'/api/v1/system-services/git/last-known-good?organization=platform&repository=desired-state&branch=main');assert st==200 and current['revision']['revisionId']==r1['id'],(st,current)
            confirmed=current['revision']; rollback_headers=dict(admin(),**{'X-Confirm-Rollback':f"rollback:{confirmed['id']}:{confirmed['revision']}"})
            # Rollback must not preserve or adopt unmanaged drift merely because the signed descriptor still matches a managed revision.
            with state.lock:
                clean_r2_head=state.heads['main']; state.branches['main']['UNMANAGED-LKG-DRIFT.txt']='external'; state.commit('main')
            st,blocked,_=request(base,'/api/v1/system-services/git/last-known-good/rollback','POST',{'organization':'platform','repository':'desired-state','branch':'main','lkgId':confirmed['id'],'lkgRevision':confirmed['revision'],'commitSha':confirmed['commitSha']},rollback_headers);assert st==409 and blocked.get('error',{}).get('code')=='GIT_BASE_AUTHORITY_CHANGED',(st,blocked)
            with state.lock:
                state.branches['main']=dict(state.snapshots[clean_r2_head]); state.heads['main']=clean_r2_head
            st,rb,_=request(base,'/api/v1/system-services/git/last-known-good/rollback','POST',{'organization':'platform','repository':'desired-state','branch':'main','lkgId':confirmed['id'],'lkgRevision':confirmed['revision'],'commitSha':confirmed['commitSha']},rollback_headers);assert st==200,(st,rb);rolled=rb['rollbackRevision'];assert rolled['revisionId']==r1['id'] and rolled['digest']==r1['digest'] and rolled['source']=='PLATFORM_LKG_ROLLBACK' and rb['requiresSyncObservation'] is True,rb
            st,revlist,_=request(base,'/api/v1/system-services/git/revisions?organization=platform&repository=desired-state');assert st==200 and len(revlist)>=3,(st,revlist)
            st,prs,_=request(base,'/api/v1/system-services/git/pull-requests?organization=platform&repository=desired-state');assert st==200 and prs[-1]['state']=='MERGED',(st,prs)
            print('GIT_PULL_REQUEST_LKG_SMOKE_PASS',prs[-1]['externalNumber'],current['revision']['commitSha'],rolled['commitSha'])
        finally:stop(p)
    finally:srv.shutdown();srv.server_close();argo.shutdown();argo.server_close()
    return 0
if __name__=='__main__':raise SystemExit(main())
