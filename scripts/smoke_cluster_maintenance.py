#!/usr/bin/env python3
from __future__ import annotations
import base64,datetime as dt,json,os,socket,subprocess,sys,tempfile,time,urllib.error,urllib.request
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()
from threading import Thread
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding,rsa

def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def b64u(raw:bytes)->str:return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()
class OIDCTestIssuer:
    def __init__(self):
        self.key=rsa.generate_private_key(public_exponent=65537,key_size=2048);self.kid='maintenance-runtime-key';self.port=free_port();self.internal=f'http://127.0.0.1:{self.port}';self.issuer='https://issuer.maintenance-runtime.test';self.client='platform-factory'
        pub=self.key.public_key().public_numbers();self.jwks={'keys':[{'kid':self.kid,'kty':'RSA','use':'sig','n':b64u(pub.n.to_bytes((pub.n.bit_length()+7)//8,'big')),'e':b64u(pub.e.to_bytes((pub.e.bit_length()+7)//8,'big'))}]}
        parent=self
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path!='/protocol/openid-connect/certs':self.send_response(404);self.end_headers();return
                raw=json.dumps(parent.jwks).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def log_message(self,*args):pass
        self.httpd=ThreadingHTTPServer(('127.0.0.1',self.port),H);self.thread=Thread(target=self.httpd.serve_forever,daemon=True);self.thread.start()
    def token(self,subject,role='platform-admin'):
        header=b64u(json.dumps({'alg':'RS256','kid':self.kid},separators=(',',':')).encode());claims=b64u(json.dumps({'sub':subject,'iss':self.issuer,'aud':self.client,'exp':int(time.time())+3600,'groups':['platform-admins'],'realm_access':{'roles':[role]}},separators=(',',':')).encode());signed=(header+'.'+claims).encode();sig=self.key.sign(signed,padding.PKCS1v15(),hashes.SHA256());return header+'.'+claims+'.'+b64u(sig)
    def close(self):self.httpd.shutdown();self.httpd.server_close();self.thread.join(timeout=2)
def bearer(token):return {'Authorization':'Bearer '+token}
def req(url,method='GET',body=None,headers=None):
    data=None if body is None else json.dumps(body).encode();h=dict(headers or {})
    if data is not None:h['Content-Type']='application/json'
    request=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(request,timeout=5) as response:
            raw=response.read();return response.status,json.loads(raw or b'null')
    except urllib.error.HTTPError as e:
        raw=e.read()
        try:value=json.loads(raw or b'null')
        except Exception:value={'raw':raw.decode(errors='replace')}
        return e.code,value
def start(binary,state,oidc):
    port=free_port();env=os.environ.copy();env.update({'PLATFORM_FACTORY_LISTEN':f'127.0.0.1:{port}','PLATFORM_FACTORY_STATE_FILE':str(state),'PLATFORM_FACTORY_AGENT_MTLS_REQUIRED':'false','PLATFORM_FACTORY_PUBLIC_URL':'https://platform.example.test','PLATFORM_FACTORY_FLEET_AGENT_IMAGE':'registry.local/agent@sha256:'+'a'*64,'PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE':'registry.local/probe@sha256:'+'b'*64,'PLATFORM_FACTORY_OIDC_ENABLED':'true','PLATFORM_FACTORY_OIDC_ISSUER':oidc.issuer,'PLATFORM_FACTORY_OIDC_INTERNAL_BASE':oidc.internal,'PLATFORM_FACTORY_OIDC_CLIENT_ID':oidc.client,'PLATFORM_FACTORY_OIDC_REDIRECT_URL':'http://127.0.0.1/callback','PLATFORM_FACTORY_SESSION_SECRET':'maintenance-runtime-smoke-session-secret-0001','PLATFORM_FACTORY_COOKIE_INSECURE':'true','PLATFORM_FACTORY_BOOTSTRAP_TOKEN':'identity-smoke-bootstrap-token-00000001'})
    p=subprocess.Popen([str(binary)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);base=f'http://127.0.0.1:{port}'
    for _ in range(100):
        try:
            if req(base+'/readyz')[0]==200:return p,base
        except Exception:pass
        time.sleep(.1)
    p.terminate();raise RuntimeError('api not ready')
def stop(p):
    p.terminate()
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.wait()
def iso(value):return value.isoformat().replace('+00:00','Z')
def inventory(tag):
    now=dt.datetime.now(dt.timezone.utc)
    return {'observedAt':iso(now),'externalUid':'maintenance-cluster','distribution':'rke2','kubernetesVersion':'v1.34.9+rke2r1','nodes':[{'name':'worker-1','uid':'worker-1','roles':['worker'],'os':'Ubuntu 24.04','architecture':'amd64','kubeletVersion':'v1.34.9','ready':True},{'name':'worker-2','uid':'worker-2','roles':['worker'],'os':'Ubuntu 24.04','architecture':'amd64','kubeletVersion':'v1.34.9','ready':True}],'capacity':{'cpuCapacityMilli':8000,'cpuAllocatableMilli':7000,'memoryCapacityBytes':17179869184,'memoryAllocatableBytes':15032385536,'podsCapacity':220,'podsAllocatable':200},'capabilities':['read-only-inventory','node-maintenance','cluster-maintenance-fenced-report','target-enrollment-principal-isolated','target-mutation-rbac-active'],'addOns':[{'name':'maintenance-marker','namespace':'kube-system','version':tag,'healthy':True}]}
def activate_mutation_rbac(base,cluster_id,token,desired,operator_token):
    initial=json.loads(json.dumps(desired)); initial['capabilities']=[c for c in initial.get('capabilities',[]) if c not in ('target-mutation-rbac-active','target-mutation-rbac-activation-issued')]
    if 'target-enrollment-principal-isolated' not in initial['capabilities']: initial['capabilities'].append('target-enrollment-principal-isolated')
    status,out=req(base+f"/agent/v1/clusters/{cluster_id}/inventory",'POST',initial,{'Authorization':'Bearer '+token}); assert status==200,(status,out)
    status,activation=req(base+f"/api/v1/clusters/{cluster_id}/mutation-rbac-manifest",'POST',{},headers=bearer(operator_token)); assert status==200 and activation.get('activationIssued') is True,(status,activation)
    active=json.loads(json.dumps(desired)); caps=[c for c in active.get('capabilities',[]) if c!='target-mutation-rbac-activation-issued']
    if 'target-enrollment-principal-isolated' not in caps: caps.append('target-enrollment-principal-isolated')
    if 'target-mutation-rbac-active' not in caps: caps.append('target-mutation-rbac-active')
    active['capabilities']=caps
    status,out=req(base+f"/agent/v1/clusters/{cluster_id}/inventory",'POST',active,{'Authorization':'Bearer '+token}); assert status==200,(status,out)
    return out

def main():
    if len(sys.argv)!=2:raise SystemExit('usage: smoke_cluster_maintenance.py platform-api')
    binary=Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as td:
        state=Path(td)/'state.json';oidc=OIDCTestIssuer();tokens={name:oidc.token(name) for name in ['admin','requester','approver','import-approver']};p,base=start(binary,state,oidc)
        try:
            status,mapping=req(base+'/api/v1/identity/group-mappings','POST',{'group':'platform-admins','productRole':'platform-admin'},{'X-Platform-Bootstrap-Token':'identity-smoke-bootstrap-token-00000001'})[:2];assert status in (200,201),(status,mapping)
            status,version=req(base+'/api/v1/version',headers=bearer(tokens['admin']));assert status==200 and version['version']==EXPECTED_VERSION,(status,version)
            status,org=req(base+'/api/v1/organizations','POST',{'name':'maintenance-runtime','displayName':'Maintenance Runtime'},bearer(tokens['admin']));assert status==201,(status,org)
            status,project=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'prod','displayName':'Production'},bearer(tokens['admin']));assert status==201,(status,project)
            status,created=req(base+'/api/v1/cluster-imports','POST',{'projectId':project['id'],'name':'edge-maint','displayName':'Edge Maintenance'},bearer(tokens['admin']));assert status==201,(status,created)
            imp=created['import'];enrollment=created['enrollmentToken']
            status,_=req(base+f"/api/v1/cluster-imports/{imp['id']}/approve",'POST',{}, {**bearer(tokens['import-approver']),'If-Match':f'"{imp["revision"]}"'});assert status==200,status
            status,claimed=req(base+f"/agent/v1/cluster-imports/{imp['id']}/claim",'POST',{'token':enrollment,'externalUid':'maintenance-cluster','agentVersion':EXPECTED_VERSION});assert status==200,(status,claimed)
            cluster=claimed['cluster'];agent=claimed['agentToken']
            inv=activate_mutation_rbac(base,cluster['id'],agent,inventory('initial'),tokens['admin'])
            status,current=req(base+f"/api/v1/clusters/{cluster['id']}",headers=bearer(tokens['admin']));assert status==200,(status,current);cluster=current['cluster']
            status,profile=req(base+f"/api/v1/clusters/{cluster['id']}/maintenance-profile",'PUT',{'environment':'PRODUCTION','defaultDrainTimeoutSeconds':120},bearer(tokens['admin']));assert status==200 and profile['profile']['environment']=='PRODUCTION',(status,profile)
            now=dt.datetime.now(dt.timezone.utc)
            status,window=req(base+f"/api/v1/clusters/{cluster['id']}/maintenance-windows",'POST',{'name':'weekly-prod','startsAt':iso(now-dt.timedelta(minutes=1)),'endsAt':iso(now+dt.timedelta(hours=1)),'maxUnavailable':1,'drainTimeoutSeconds':120},bearer(tokens['admin']));assert status==201 and window['maxUnavailable']==1,(status,window)
            status,created_run=req(base+f"/api/v1/clusters/{cluster['id']}/maintenance-runs",'POST',{'windowId':window['id'],'nodeNames':['worker-1']},{**bearer(tokens['requester']),'Idempotency-Key':'maintenance-run-1'});assert status==201 and created_run['run']['state']=='AWAITING_APPROVAL',(status,created_run)
            run=created_run['run'];op=created_run['operation']
            status,empty=req(base+f"/agent/v1/clusters/{cluster['id']}/maintenance-tasks/next",headers={'Authorization':'Bearer '+agent});assert status==204,(status,empty)
            status,blocked=req(base+f"/api/v1/clusters/{cluster['id']}/maintenance-runs/{run['id']}/approve",'POST',{}, {**bearer(tokens['requester']),'If-Match':f'"{run["revision"]}"'});assert status==403 and blocked.get('error',{}).get('code')=='SEPARATION_OF_DUTIES_REQUIRED',(status,blocked)
            status,approved=req(base+f"/api/v1/clusters/{cluster['id']}/maintenance-runs/{run['id']}/approve",'POST',{}, {**bearer(tokens['approver']),'If-Match':f'"{run["revision"]}"'});assert status==200 and approved['run']['state']=='QUEUED' and approved['operation']['state']=='QUEUED',(status,approved)
            # Approval, window binding, operation linkage and inventory digest survive API restart.
            stop(p);p,base=start(binary,state,oidc)
            status,persisted=req(base+f"/api/v1/clusters/{cluster['id']}/maintenance-runs/{run['id']}",headers=bearer(tokens['admin']));assert status==200 and persisted['run']['state']=='QUEUED' and persisted['run']['inventoryDigest']==cluster['inventoryDigest'] and persisted['run']['nodeUids']=={'worker-1':'worker-1'} and persisted['operation']['id']==op['id'],(status,persisted)
            status,task=req(base+f"/agent/v1/clusters/{cluster['id']}/maintenance-tasks/next",headers={'Authorization':'Bearer '+agent});assert status==200 and task['method']=='KUBERNETES_NODE_MAINTENANCE_V1' and task['nodeNames']==['worker-1'] and task['nodeUids']=={'worker-1':'worker-1'} and task['drainTimeoutSeconds']==120,(status,task)
            result={'operationFenceToken':task['operationFenceToken'],'success':True,'results':[{'nodeName':'worker-1','cordoned':True,'drainAttempted':True,'drained':True,'uncordoned':True,'evictedPods':['app/web-1'],'skippedPods':['kube-system/ds'],'pdbBlockedPods':['app/web-1']}]}
            status,finished=req(base+f"/agent/v1/clusters/{cluster['id']}/maintenance-tasks/{run['id']}/result",'POST',result,{'Authorization':'Bearer '+agent,'If-Match':f'"{task["runRevision"]}"'});assert status==200 and finished['run']['state']=='SUCCEEDED' and finished['operation']['state']=='SUCCEEDED',(status,finished)
            status,runs=req(base+f"/api/v1/clusters/{cluster['id']}/maintenance-runs",headers=bearer(tokens['admin']));assert status==200 and runs['method']=='KUBERNETES_NODE_MAINTENANCE_V1' and runs['runs'][0]['results'][0]['uncordoned'] is True,(status,runs)
            print('CLUSTER_MAINTENANCE_AUTHORITY_RUNTIME_SMOKE_PASS',cluster['id'],run['id'],op['id'])
        finally:
            stop(p);oidc.close()
    return 0
if __name__=='__main__':raise SystemExit(main())
