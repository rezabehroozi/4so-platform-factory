#!/usr/bin/env python3
from __future__ import annotations
import base64, datetime as dt, hashlib, json, os, socket, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()
from urllib.parse import unquote, urlparse, parse_qs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from smoke_plan_safety import req, inventory, activate_mutation_rbac, create_and_apply_baseline, free_port, stop

class GitState:
    def __init__(self):
        seed={'README.md':'# Managed Platform Desired State\n\nThis repository is generated and managed by 4SO Platform Factory.\n'}
        self.files=dict(seed); self.head='0'*40; self.changed_files=[]; self.lock=threading.Lock()
        self.branches={'main':self.files}; self.heads={'main':self.head}; self.snapshots={self.head:dict(seed)}; self.counter=1; self.prs={}; self.next_pr=1; self.allow_ff=False
    def commit(self,branch):
        self.counter+=1; sha=f'{self.counter:040x}'[-40:]; self.heads[branch]=sha; self.snapshots[sha]=dict(self.branches[branch])
        if branch=='main': self.files=self.branches['main']; self.head=sha
        return sha
    def sync_main(self):
        self.branches['main']=self.files; self.heads['main']=self.head; self.snapshots[self.head]=dict(self.files)

def revision(private_key, suffix):
    spec={
      'productVersion':EXPECTED_VERSION,'specDigest':'sha256:'+suffix*64,'bundleDigest':'sha256:'+('b' if suffix!='b' else 'c')*64,
      'publicEndpoint':'https://platform.example.test','gitEndpoint':'https://git.example.test','registryEndpoint':'https://registry.example.test','identityEndpoint':'https://auth.example.test'}
    canonical=json.dumps(spec,separators=(',',':'),ensure_ascii=False).encode(); raw_digest=hashlib.sha256(canonical).digest(); digest='sha256:'+raw_digest.hex()
    sig=private_key.sign(raw_digest); pub=private_key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    fingerprint='sha256:'+hashlib.sha256(pub).hexdigest(); rid='revision-'+raw_digest.hex()[:16]
    payload={'apiVersion':'platform.4so.io/v1alpha1','kind':'PlatformRevision','metadata':{'id':rid},'spec':spec,'integrity':{'digest':digest,'signature':base64.b64encode(sig).decode(),'publicKeyFingerprint':fingerprint}}
    pem='-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(pub).decode()+'\n-----END PUBLIC KEY-----\n'
    state_doc=f'''apiVersion: v1
kind: ConfigMap
metadata:
  name: platform-managed-state
  namespace: platform-system
  labels:
    platform.4so.io/ownership: gitops
    platform.4so.io/revision: {rid}
data:
  productVersion: {json.dumps(spec['productVersion'])}
  specDigest: {json.dumps(spec['specDigest'])}
  bundleDigest: {json.dumps(spec['bundleDigest'])}
  publicEndpoint: {json.dumps(spec['publicEndpoint'])}
  gitEndpoint: {json.dumps(spec['gitEndpoint'])}
  registryEndpoint: {json.dumps(spec['registryEndpoint'])}
  identityEndpoint: {json.dumps(spec['identityEndpoint'])}
'''
    marker=f'''apiVersion: v1
kind: ConfigMap
metadata:
  name: platform-gitops-revision
  namespace: platform-system
  labels:
    platform.4so.io/ownership: gitops
    platform.4so.io/revision: {rid}
data:
  revisionID: {json.dumps(rid)}
  revisionDigest: {json.dumps(digest)}
  signature: {json.dumps(base64.b64encode(sig).decode())}
  publicKeyFingerprint: {json.dumps(fingerprint)}
'''
    files={'.platform/revision.json':json.dumps(payload,indent=2,separators=(',', ': '))+'\n','.platform/revision.sig':base64.b64encode(sig).decode()+'\n','.platform/public-key.pem':pem,'clusters/appliance/platform-managed-state.yaml':state_doc,'clusters/appliance/platform-gitops-revision.yaml':marker,'clusters/appliance/kustomization.yaml':'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - platform-managed-state.yaml\n  - platform-gitops-revision.yaml\n'}
    return {'id':rid,'digest':digest,'fingerprint':fingerprint,'files':files}

def start_git(state:GitState):
    port=free_port()
    class H(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def auth(self):
            return self.headers.get('Authorization','').startswith('Basic ')
        def sendj(self,code,obj):
            raw=json.dumps(obj).encode(); self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def do_GET(self):
            u=urlparse(self.path);path=u.path;q=parse_qs(u.query)
            if path=='/api/v1/version': return self.sendj(200,{'version':'15.0.5'})
            if not self.auth(): return self.sendj(401,{'message':'auth required'})
            if path=='/api/v1/orgs/platform': return self.sendj(200,{'username':'platform'})
            if path=='/api/v1/repos/platform/desired-state': return self.sendj(200,{'name':'desired-state','html_url':'https://git.example/platform/desired-state','clone_url':'https://git.example/platform/desired-state.git','owner':{'login':'platform'},'allow_fast_forward_only_merge':state.allow_ff})
            bp='/api/v1/repos/platform/desired-state/branches/'
            if path.startswith(bp):
                branch=unquote(path[len(bp):])
                with state.lock: sha=state.heads.get(branch)
                return self.sendj(200,{'commit':{'id':sha}}) if sha else self.sendj(404,{'message':'branch missing'})
            if path=='/api/v1/repos/platform/desired-state/pulls':
                with state.lock:
                    rows=[{'number':n,'html_url':f'https://git.example/platform/desired-state/pulls/{n}','state':pr['state'],'merged':pr.get('merged',False),'merge_commit_sha':pr.get('merge_commit_sha',''),'base':{'ref':pr['base'],'sha':state.heads.get(pr['base'],'')},'head':{'ref':pr['head'],'sha':state.heads.get(pr['head'],'')}} for n,pr in sorted(state.prs.items())]
                return self.sendj(200,rows)
            pp='/api/v1/repos/platform/desired-state/pulls/'
            if path.startswith(pp):
                rest=path[len(pp):];parts=rest.split('/')
                try:n=int(parts[0])
                except ValueError:return self.sendj(404,{'message':'bad pr'})
                with state.lock:pr=state.prs.get(n); headsha=state.heads.get(pr['head'],'') if pr else ''; basesha=state.heads.get(pr['base'],'') if pr else ''
                if not pr:return self.sendj(404,{'message':'missing'})
                if len(parts)>1 and parts[1]=='reviews':return self.sendj(200,[])
                return self.sendj(200,{'number':n,'html_url':f'https://git.example/platform/desired-state/pulls/{n}','state':pr['state'],'merged':pr.get('merged',False),'merge_commit_sha':pr.get('merge_commit_sha',''),'base':{'ref':pr['base'],'sha':basesha},'head':{'ref':pr['head'],'sha':headsha}})
            cp='/api/v1/repos/platform/desired-state/contents'
            if path==cp or path.startswith(cp+'/'):
                name='' if path==cp else unquote(path[len(cp)+1:]);ref=(q.get('ref') or ['main'])[0]
                with state.lock:
                    files=state.branches.get(ref) if ref in state.branches else state.snapshots.get(ref)
                    if files is None:return self.sendj(404,{'message':'ref missing'})
                    if name and name in files:
                        content=files[name]
                        return self.sendj(200,{'name':name.rsplit('/',1)[-1],'path':name,'type':'file','sha':'sha-'+hashlib.sha256(content.encode()).hexdigest()[:12],'content':base64.b64encode(content.encode()).decode()})
                    prefix=(name.rstrip('/')+'/') if name else ''
                    children={}
                    for full,content in files.items():
                        if not full.startswith(prefix):continue
                        rest=full[len(prefix):]
                        if not rest:continue
                        first=rest.split('/',1)[0];child=prefix+first
                        children[child]='dir' if '/' in rest else 'file'
                    if not children:return self.sendj(404,{'message':'not found'})
                    rows=[{'name':child.rsplit('/',1)[-1],'path':child,'type':typ,'sha':'dir' if typ=='dir' else 'sha-'+hashlib.sha256(files[child].encode()).hexdigest()[:12]} for child,typ in sorted(children.items())]
                return self.sendj(200,rows)
            compare='/api/v1/repos/platform/desired-state/compare/'
            if path.startswith(compare):
                spec=unquote(path[len(compare):]);base,head=spec.split('...',1)
                with state.lock:
                    a=state.snapshots.get(base,{});b=state.snapshots.get(head,{})
                    names=sorted({*a.keys(),*b.keys()}); changed=[n for n in names if a.get(n)!=b.get(n)]
                    if head==state.head and state.changed_files: changed=list(state.changed_files)
                return self.sendj(200,{'files':[{'filename':x} for x in changed]})
            return self.sendj(404,{'message':'not found','path':path})
        def do_POST(self):
            path=urlparse(self.path).path
            if not self.auth(): return self.sendj(401,{'message':'auth required'})
            if path=='/api/v1/repos/platform/desired-state/branches':
                length=int(self.headers.get('Content-Length','0'));body=json.loads(self.rfile.read(length) or b'{}');new=body['new_branch_name'];old=body.get('old_branch_name','main')
                with state.lock:
                    if new in state.branches:return self.sendj(409,{'message':'exists'})
                    if old not in state.branches:return self.sendj(404,{'message':'base missing'})
                    state.branches[new]=dict(state.branches[old]);state.heads[new]=state.heads[old]
                return self.sendj(201,{'name':new})
            if path=='/api/v1/repos/platform/desired-state/pulls':
                length=int(self.headers.get('Content-Length','0'));b=json.loads(self.rfile.read(length) or b'{}')
                with state.lock:
                    n=state.next_pr;state.next_pr+=1;state.prs[n]={'base':b['base'],'head':b['head'],'base_sha':state.heads.get(b['base'],''),'state':'open','merged':False,'merge_commit_sha':''}
                return self.sendj(201,{'number':n,'html_url':f'https://git.example/platform/desired-state/pulls/{n}','state':'open'})
            pp='/api/v1/repos/platform/desired-state/pulls/'
            if path.startswith(pp) and path.endswith('/merge'):
                n=int(path[len(pp):].split('/')[0]);length=int(self.headers.get('Content-Length','0'));b=json.loads(self.rfile.read(length) or b'{}')
                with state.lock:
                    pr=state.prs.get(n)
                    if not pr:return self.sendj(404,{'message':'missing'})
                    headsha=state.heads.get(pr['head'],'')
                    if b.get('Do')!='fast-forward-only' or not state.allow_ff:return self.sendj(405,{'message':'ff-only required'})
                    if b.get('head_commit_id')!=headsha:return self.sendj(409,{'message':'head changed'})
                    if state.heads.get(pr['base'])!=pr.get('base_sha'):return self.sendj(409,{'message':'base moved'})
                    state.branches[pr['base']]=dict(state.branches[pr['head']]);state.heads[pr['base']]=headsha;state.snapshots[headsha]=dict(state.branches[pr['base']]);state.files=state.branches['main'];state.head=state.heads['main'];pr['state']='closed';pr['merged']=True;pr['merge_commit_sha']=headsha
                return self.sendj(200,{'merged':True,'sha':headsha})
            if path=='/api/v1/repos/platform/desired-state/contents': return self.write_files_atomic()
            return self.write_file()
        def do_PATCH(self):
            path=urlparse(self.path).path
            if not self.auth(): return self.sendj(401,{'message':'auth required'})
            if path=='/api/v1/repos/platform/desired-state':
                length=int(self.headers.get('Content-Length','0'));b=json.loads(self.rfile.read(length) or b'{}')
                with state.lock:
                    if b.get('allow_fast_forward_only_merge') is True:state.allow_ff=True
                return self.sendj(200,{'name':'desired-state','allow_fast_forward_only_merge':state.allow_ff})
            return self.sendj(404,{'message':'not found'})
        def do_PUT(self):
            if not self.auth(): return self.sendj(401,{'message':'auth required'})
            return self.write_file()
        def write_files_atomic(self):
            length=int(self.headers.get('Content-Length','0'));body=json.loads(self.rfile.read(length) or b'{}');ops=body.get('files') or [];branch=body.get('branch','main')
            with state.lock:
                if branch not in state.branches:return self.sendj(404,{'message':'branch missing'})
                updated=dict(state.branches[branch])
                for op in ops:
                    if op.get('operation') not in ('create','update') or not op.get('path'): return self.sendj(422,{'message':'bad file operation'})
                    updated[op['path']]=base64.b64decode(op.get('content','')).decode()
                state.branches[branch]=updated;sha=state.commit(branch)
            return self.sendj(201,{'commit':{'sha':sha},'files':[{'path':op.get('path','')} for op in ops]})
        def write_file(self):
            path=urlparse(self.path).path
            prefix='/api/v1/repos/platform/desired-state/contents/'
            if not path.startswith(prefix): return self.sendj(404,{'message':'not found'})
            name=unquote(path[len(prefix):]); length=int(self.headers.get('Content-Length','0')); body=json.loads(self.rfile.read(length) or b'{}'); content=base64.b64decode(body['content']).decode();branch=body.get('branch','main')
            with state.lock:
                if branch not in state.branches:return self.sendj(404,{'message':'branch missing'})
                state.branches[branch][name]=content; sha=state.commit(branch)
            return self.sendj(200 if self.command=='PUT' else 201,{'content':{'path':name},'commit':{'sha':sha}})
    srv=ThreadingHTTPServer(('127.0.0.1',port),H); thread=threading.Thread(target=srv.serve_forever,daemon=True);thread.start();return srv,f'http://127.0.0.1:{port}'

def start_api(binary,state_file,git_url):
    port=free_port();env=os.environ.copy(); env['PLATFORM_FACTORY_DEVELOPMENT_MODE']='true';env.update({'PLATFORM_FACTORY_LISTEN':f'127.0.0.1:{port}','PLATFORM_FACTORY_STATE_FILE':str(state_file),'PLATFORM_FACTORY_AGENT_MTLS_REQUIRED':'false','PLATFORM_FACTORY_PUBLIC_URL':'https://platform.example.test','PLATFORM_FACTORY_FLEET_AGENT_IMAGE':'registry.local/platform-agent@sha256:'+'a'*64,'PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE':'registry.local/platform-probe@sha256:'+'b'*64,'PLATFORM_FACTORY_INTERNAL_GIT_URL':git_url,'PLATFORM_FACTORY_INTERNAL_GIT_USERNAME':'admin','PLATFORM_FACTORY_INTERNAL_GIT_PASSWORD':'secret','PLATFORM_FACTORY_INTERNAL_GIT_BOOTSTRAP':'true'})
    p=subprocess.Popen([str(binary)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);base=f'http://127.0.0.1:{port}'
    for _ in range(100):
        try:
            if req(base+'/readyz')[0]==200:return p,base
        except Exception: pass
        time.sleep(.1)
    stop(p);raise RuntimeError('api not ready')

def claim_cluster(base,project_id,version):
    st,created,_=req(base+'/api/v1/cluster-imports','POST',{'projectId':project_id,'name':'git-drift-cluster','displayName':'Git Drift Cluster'});assert st==201,(st,created);imp=created['import']
    st,_,_=req(base+f"/api/v1/cluster-imports/{imp['id']}/approve",'POST',{}, {'If-Match':'1'});assert st==200
    st,claimed,_=req(base+f"/agent/v1/cluster-imports/{imp['id']}/claim",'POST',{'token':created['enrollmentToken'],'externalUid':'git-drift-uid','agentVersion':version});assert st==200,(st,claimed)
    cluster,token=claimed['cluster'],claimed['agentToken'];activate_mutation_rbac(base,cluster['id'],token,inventory(external_uid='git-drift-uid'))
    return cluster,token

def run_scan(base,project,group,cluster,token,key,live_digest):
    st,created,_=req(base+'/api/v1/drift-scans','POST',{'projectId':project,'fleetGroupId':group,'git':{'organization':'platform','repository':'desired-state','branch':'main'}},{'X-Actor-ID':'operator','Idempotency-Key':key});assert st==201,(st,created);scan=created['driftScan']
    st,task,h=req(base+f"/agent/v1/clusters/{cluster}/drift-tasks/next",headers={'Authorization':'Bearer '+token});assert st==200,(st,task)
    assert task['git']['baseDigest'].startswith('sha256:') and task['git']['currentDigest'].startswith('sha256:'),task['git']
    changes=[{'resource':f"{r['kind']}/{r['name']}",'action':'NOOP','currentDigest':task['desiredDigest'],'desiredDigest':task['desiredDigest'],'reason':'in sync'} for r in task['resources']]
    st,result,_=req(base+f"/agent/v1/clusters/{cluster}/drift-tasks/{scan['id']}/result",'POST',{'clusterId':cluster,'success':True,'observedDigest':task['desiredDigest'],'gitObservedDigest':live_digest,'changes':changes},{'Authorization':'Bearer '+token,'If-Match':h.get('Etag') or h.get('ETag') or f'"{task["scanRevision"]}"'});assert st==200,(st,result)
    return result

def main():
    if len(sys.argv)!=2: raise SystemExit('usage: smoke_git_three_way_drift.py platform-api')
    binary=Path(sys.argv[1]).resolve(); git=GitState(); srv,git_url=start_git(git); key=Ed25519PrivateKey.generate(); rev1=revision(key,'a');rev2=revision(key,'d')
    try:
      with tempfile.TemporaryDirectory() as td:
        state=Path(td)/'state.json';p,base=start_api(binary,state,git_url)
        try:
            st,ver,_=req(base+'/api/v1/version');assert st==200;version=ver['version']
            st,org,_=req(base+'/api/v1/organizations','POST',{'name':'git-drift-smoke','displayName':'Git Drift Smoke'});assert st==201,(st,org)
            st,project,_=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'prod','displayName':'Production'});assert st==201,(st,project)
            cluster,token=claim_cluster(base,project['id'],version);create_and_apply_baseline(base,project['id'],cluster['id'],token,'1.0.0','git-drift-baseline')
            st,group,_=req(base+'/api/v1/fleet-groups','POST',{'projectId':project['id'],'name':'git-drift-fleet','displayName':'Git Drift Fleet','clusterIds':[cluster['id']]},{'X-Actor-ID':'operator','Idempotency-Key':'git-drift-fleet'});assert st==201,(st,group);group=group['fleetGroup']
            st,published,_=req(base+'/api/v1/system-services/git/revisions','POST',{'organization':'platform','repository':'desired-state','revisionId':rev1['id'],'digest':rev1['digest'],'files':rev1['files']},{'X-Actor-ID':'platform-publisher'});assert st==200,(st,published);assert published['publicKeyFingerprint']==rev1['fingerprint'],published
            with git.lock: git.files=dict(rev2['files']);git.head='2'*40;git.changed_files=['.platform/revision.json','.platform/revision.sig','clusters/appliance/platform-managed-state.yaml'];git.sync_main()
            first=run_scan(base,project['id'],group['id'],cluster['id'],token,'git-drift-pending',rev1['digest']);g=first['targets'][0]['git'];assert g['classification']=='EXTERNAL_GIT_CHANGE' and g['currentTrusted'] is True and g['adoptable'] is False,g
            second=run_scan(base,project['id'],group['id'],cluster['id'],token,'git-drift-applied',rev2['digest']);g=second['targets'][0]['git'];assert g['classification']=='EXTERNAL_GIT_APPLIED' and g['adoptable'] is True,g
            st,adopted,_=req(base+f"/api/v1/drift-scans/{second['id']}/adopt-git",'POST',{'clusterId':cluster['id']},{'X-Actor-ID':'operator'});assert st==200 and adopted['overwroteGit'] is False,(st,adopted)
            adopted_id=adopted['authority']['id'];project_id=project['id'];group_id=group['id'];cluster_id=cluster['id']
        finally: stop(p)
        p,base=start_api(binary,state,git_url)
        try:
            st,revisions,_=req(base+'/api/v1/system-services/git/revisions?organization=platform&repository=desired-state');assert st==200 and revisions[-1]['id']==adopted_id,(st,revisions)
            third=run_scan(base,project_id,group_id,cluster_id,token,'git-drift-after-adopt',rev2['digest']);g=third['targets'][0]['git'];assert g['classification']=='IN_SYNC' and g['baseDigest']==rev2['digest']==g['currentDigest']==g['observedDigest'],g
            print('EXTERNAL_GIT_THREE_WAY_DRIFT_SMOKE_PASS',third['id'],g['classification'],revisions[-1]['source'])
        finally: stop(p)
    finally: srv.shutdown();srv.server_close()
    return 0
if __name__=='__main__': raise SystemExit(main())
