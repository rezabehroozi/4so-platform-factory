#!/usr/bin/env python3
from __future__ import annotations
import base64,datetime as dt,hashlib,json,os,socket,subprocess,sys,tempfile,time,urllib.error,urllib.request
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()
from threading import Thread
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding,rsa

def free_port():
    with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]
def b64u(raw: bytes)->str:return base64.urlsafe_b64encode(raw).rstrip(b'=') .decode()
class OIDCTestIssuer:
    def __init__(self):
        self.key=rsa.generate_private_key(public_exponent=65537,key_size=2048);self.kid='tenant-runtime-key';self.port=free_port();self.internal=f'http://127.0.0.1:{self.port}';self.issuer='https://issuer.tenant-runtime.test';self.client='platform-factory'
        pub=self.key.public_key().public_numbers();self.jwks={'keys':[{'kid':self.kid,'kty':'RSA','use':'sig','n':b64u(pub.n.to_bytes((pub.n.bit_length()+7)//8,'big')),'e':b64u(pub.e.to_bytes((pub.e.bit_length()+7)//8,'big'))}]}
        parent=self
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path!='/protocol/openid-connect/certs':self.send_response(404);self.end_headers();return
                raw=json.dumps(parent.jwks).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def log_message(self,*args):pass
        self.httpd=ThreadingHTTPServer(('127.0.0.1',self.port),H);self.thread=Thread(target=self.httpd.serve_forever,daemon=True);self.thread.start()
    def token(self,subject,role):
        header=b64u(json.dumps({'alg':'RS256','kid':self.kid},separators=(',',':')).encode());claims=b64u(json.dumps({'sub':subject,'iss':self.issuer,'aud':self.client,'exp':int(time.time())+3600,'groups':['platform-admins'],'realm_access':{'roles':[role]}},separators=(',',':')).encode());signed=(header+'.'+claims).encode();sig=self.key.sign(signed,padding.PKCS1v15(),hashes.SHA256());return header+'.'+claims+'.'+b64u(sig)
    def close(self):self.httpd.shutdown();self.httpd.server_close();self.thread.join(timeout=2)
def bearer(token):return {'Authorization':'Bearer '+token}
def req(url,method='GET',body=None,headers=None):
    data=None if body is None else json.dumps(body).encode(); h=dict(headers or {})
    if data is not None:h['Content-Type']='application/json'
    request=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(request,timeout=5) as response:
            raw=response.read(); return response.status,json.loads(raw or b'null')
    except urllib.error.HTTPError as e:
        raw=e.read()
        try:value=json.loads(raw or b'null')
        except Exception:value={'raw':raw.decode(errors='replace')}
        return e.code,value
def start(binary,state,oidc):
    port=free_port();env=os.environ.copy();env.update({
        'PLATFORM_FACTORY_LISTEN':f'127.0.0.1:{port}',
        'PLATFORM_FACTORY_STATE_FILE':str(state),
        'PLATFORM_FACTORY_AGENT_MTLS_REQUIRED':'false',
        'PLATFORM_FACTORY_PUBLIC_URL':'https://platform.example.test',
        'PLATFORM_FACTORY_FLEET_AGENT_IMAGE':'registry.local/agent@sha256:'+'a'*64,
        'PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE':'registry.local/probe@sha256:'+'b'*64,
        'PLATFORM_FACTORY_OIDC_ENABLED':'true',
        'PLATFORM_FACTORY_OIDC_ISSUER':oidc.issuer,
        'PLATFORM_FACTORY_OIDC_INTERNAL_BASE':oidc.internal,
        'PLATFORM_FACTORY_OIDC_CLIENT_ID':oidc.client,
        'PLATFORM_FACTORY_OIDC_REDIRECT_URL':'http://127.0.0.1/callback',
        'PLATFORM_FACTORY_SESSION_SECRET':'tenant-runtime-smoke-session-secret-0001',
        'PLATFORM_FACTORY_COOKIE_INSECURE':'true','PLATFORM_FACTORY_BOOTSTRAP_TOKEN':'identity-smoke-bootstrap-token-00000001',
    })
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
    return {'observedAt':iso(now),'externalUid':'tenant-runtime-cluster','distribution':'rke2','kubernetesVersion':'v1.34.9+rke2r1','nodes':[{'name':'n1','uid':'n1','roles':['control-plane'],'os':'Ubuntu 24.04','architecture':'amd64','kubeletVersion':'v1.34.9','ready':True}],'capacity':{'cpuCapacityMilli':4000,'cpuAllocatableMilli':3500,'memoryCapacityBytes':8589934592,'memoryAllocatableBytes':7516192768,'podsCapacity':110,'podsAllocatable':100},'storageClasses':[{'name':'replicated','provisioner':'csi.example','reclaimPolicy':'Delete','volumeBindingMode':'Immediate','allowVolumeExpansion':True,'default':True}],'apiResources':[{'apiVersion':'networking.k8s.io/v1','group':'networking.k8s.io','version':'v1','kind':'NetworkPolicy','resource':'networkpolicies','namespaced':True,'verbs':['get','patch']},{'apiVersion':'velero.io/v1','group':'velero.io','version':'v1','kind':'Schedule','resource':'schedules','namespaced':True,'verbs':['get','patch']}],'apiDiscoveryComplete':True,'capabilities':['read-only-inventory','storage-class-inventory','tenant-delete-observed','target-enrollment-principal-isolated','target-mutation-rbac-active'],'addOns':[{'name':'tenant-runtime-marker','namespace':'kube-system','version':tag,'healthy':True}]}

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

def sha(value): return 'sha256:'+hashlib.sha256(value.encode()).hexdigest()
def tenant_result(task,tamper=False):
    evidence=[]
    for r in task['resources']:
        key=f"resource/{r['kind']}/{r['name']}"
        evidence.append({'key':key,'authority':'KUBERNETES_API_READBACK_V1','resource':f"{r['kind']}/{r['name']}",'status':'PASS','digest':sha(key)})
    if task['action']=='SUSPEND':
        evidence.append({'key':'suspension/no-running-pods','authority':'KUBERNETES_API_READBACK_V1','resource':'PodList/'+task['namespace'],'status':'PASS','digest':sha('suspension-zero-pods')})
    evidence.append({'key':'security/pod-security-admission-negative','authority':'KUBERNETES_POD_SECURITY_ADMISSION_V1','status':'PASS','digest':sha('psa-negative')})
    raw=json.dumps(evidence,separators=(',',':'),ensure_ascii=False).encode()
    digest='sha256:'+hashlib.sha256(raw).hexdigest()
    if tamper: digest='sha256:'+'0'*64
    return {'taskFenceToken':task['taskFenceToken'],'action':task['action'],'success':True,'observedDigest':task['desiredDigest'],'evidence':evidence,'evidenceDigest':digest}

def checkpoint(base,project,cluster,token):
    now=dt.datetime.now(dt.timezone.utc)
    status,cp=req(base+'/api/v1/recovery-checkpoints','POST',{'projectId':project,'clusterId':cluster,'provider':'s3','reference':'tenant/protected-delete','evidenceDigest':'sha256:'+'c'*64,'completedAt':iso(now-dt.timedelta(minutes=2)),'expiresAt':iso(now+dt.timedelta(hours=2))},bearer(token))
    assert status==201,(status,cp);return cp

def main():
    if len(sys.argv)!=2:raise SystemExit('usage: smoke_tenant_resize_protected_delete.py platform-api')
    binary=Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as td:
        state=Path(td)/'state.json';oidc=OIDCTestIssuer();
        tokens={name:oidc.token(name,role) for name,role in {'admin':'platform-admin','requester':'platform-admin','approver-resize':'platform-admin','approver-delete':'platform-admin','backup-operator':'platform-admin'}.items()}
        p,base=start(binary,state,oidc)
        try:
            status,mapping=req(base+'/api/v1/identity/group-mappings','POST',{'group':'platform-admins','productRole':'platform-admin'},{'X-Platform-Bootstrap-Token':'identity-smoke-bootstrap-token-00000001'})[:2];assert status in (200,201),(status,mapping)
            status,version=req(base+'/api/v1/version',headers=bearer(tokens['admin']));assert status==200 and version['version']==EXPECTED_VERSION,(status,version)
            status,org=req(base+'/api/v1/organizations','POST',{'name':'tenant-runtime','displayName':'Tenant Runtime'},bearer(tokens['admin']));assert status==201,(status,org)
            status,project=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'customers','displayName':'Customers'},bearer(tokens['admin']));assert status==201,(status,project)
            status,_=req(base+f"/api/v1/organizations/{org['id']}/entitlement",'PUT',{'edition':'service-provider'},{**bearer(tokens['admin']),'If-None-Match':'*'});assert status==200,status
            status,created=req(base+'/api/v1/cluster-imports','POST',{'projectId':project['id'],'name':'shared','displayName':'Shared'},bearer(tokens['admin']));assert status==201,(status,created)
            imp=created['import'];enrollment=created['enrollmentToken']
            status,_=req(base+f"/api/v1/cluster-imports/{imp['id']}/approve",'POST',{}, {**bearer(tokens['approver-resize']),'If-Match':'1'});assert status==200,status
            status,claimed=req(base+f"/agent/v1/cluster-imports/{imp['id']}/claim",'POST',{'token':enrollment,'externalUid':'tenant-runtime-cluster','agentVersion':EXPECTED_VERSION});assert status==200,(status,claimed)
            cluster=claimed['cluster'];agent=claimed['agentToken']
            activate_mutation_rbac(base,cluster['id'],agent,inventory('a'),tokens['admin'])
            status,created=req(base+'/api/v1/tenants','POST',{'projectId':project['id'],'clusterId':cluster['id'],'name':'customer-a','displayName':'Customer A','planName':'small'},{**bearer(tokens['requester']),'Idempotency-Key':'tenant-runtime-1'});assert status==201,(status,created);tenant=created['tenant'];assert tenant['storagePolicy']['storageClass']=='replicated' and tenant['backupPolicy']['provider']=='velero' and tenant['securityPolicy']['podSecurityLevel']=='restricted',tenant
            status,task=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/next",headers={'Authorization':'Bearer '+agent});assert status==200 and task['action']=='PROVISION' and len(task['resources'])==7,(status,task); kinds={(r['kind'],r['name']) for r in task['resources']}; schedule_name='tenant-platform-backup-'+hashlib.sha256(tenant['id'].encode()).hexdigest()[:12]; assert ('Schedule',schedule_name) in kinds and ('NetworkPolicy','tenant-default-deny-all') in kinds and ('NetworkPolicy','tenant-allow-dns-egress') in kinds,kinds
            status,bad=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/{tenant['id']}/result",'POST',tenant_result(task,True),{'Authorization':'Bearer '+agent,'If-Match':f'"{task["tenantRevision"]}"'});assert status==422,(status,bad)
            status,tenant=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/{tenant['id']}/result",'POST',tenant_result(task),{'Authorization':'Bearer '+agent,'If-Match':f'"{task["tenantRevision"]}"'});assert status==200 and tenant['state']=='ACTIVE' and tenant.get('evidenceDigest') and len(tenant.get('evidence',[]))==8,(status,tenant)

            status,resize=req(base+f"/api/v1/tenants/{tenant['id']}/resize",'POST',{'planName':'medium'},{**bearer(tokens['requester']),'If-Match':f'"{tenant["revision"]}"'});assert status==200 and resize['state']=='RESIZE_AWAITING_APPROVAL' and resize['planName']=='small' and resize['pendingPlanName']=='medium',(status,resize)
            status,empty=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/next",headers={'Authorization':'Bearer '+agent});assert status==204,(status,empty)
            status,blocked=req(base+f"/api/v1/tenants/{tenant['id']}/approve",'POST',{}, {**bearer(tokens['requester']),'If-Match':f'"{resize["revision"]}"'});assert status==403 and blocked.get('error',{}).get('code')=='SEPARATION_OF_DUTIES_REQUIRED',(status,blocked)
            status,resize=req(base+f"/api/v1/tenants/{tenant['id']}/approve",'POST',{}, {**bearer(tokens['approver-resize']),'If-Match':f'"{resize["revision"]}"'});assert status==200 and resize['state']=='RESIZE_QUEUED',(status,resize)
            status,task=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/next",headers={'Authorization':'Bearer '+agent});assert status==200 and task['action']=='RESIZE' and task['planName']=='medium' and len(task['resources'])==7,(status,task)
            quota=[r for r in task['resources'] if r['kind']=='ResourceQuota'][0]['object']['spec']['hard'];assert quota['requests.cpu']=='12' and quota['requests.memory']=='32Gi',quota
            status,tenant=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/{tenant['id']}/result",'POST',tenant_result(task),{'Authorization':'Bearer '+agent,'If-Match':f'"{task["tenantRevision"]}"'});assert status==200 and tenant['state']=='ACTIVE' and tenant['planName']=='medium' and not tenant.get('pendingPlanName'),(status,tenant)

            status,suspended=req(base+f"/api/v1/tenants/{tenant['id']}/suspend",'POST',{}, {**bearer(tokens['requester']),'If-Match':f'"{tenant["revision"]}"'});assert status==200 and suspended['state']=='SUSPEND_QUEUED',(status,suspended)
            status,task=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/next",headers={'Authorization':'Bearer '+agent});assert status==200 and task['action']=='SUSPEND' and len(task['resources'])==7,(status,task)
            suspend_quota=[r for r in task['resources'] if r['kind']=='ResourceQuota'][0]['object']['spec']['hard'];assert suspend_quota['pods']=='0',suspend_quota
            suspend_result=tenant_result(task);assert len(suspend_result['evidence'])==9,suspend_result
            status,tenant=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/{tenant['id']}/result",'POST',suspend_result,{'Authorization':'Bearer '+agent,'If-Match':f'"{task["tenantRevision"]}"'});assert status==200 and tenant['state']=='SUSPENDED' and len(tenant.get('evidence',[]))==9,(status,tenant)

            status,resumed=req(base+f"/api/v1/tenants/{tenant['id']}/resume",'POST',{}, {**bearer(tokens['requester']),'If-Match':f'"{tenant["revision"]}"'});assert status==200 and resumed['state']=='RESUME_QUEUED',(status,resumed)
            status,task=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/next",headers={'Authorization':'Bearer '+agent});assert status==200 and task['action']=='RESUME' and len(task['resources'])==7,(status,task)
            status,tenant=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/{tenant['id']}/result",'POST',tenant_result(task),{'Authorization':'Bearer '+agent,'If-Match':f'"{task["tenantRevision"]}"'});assert status==200 and tenant['state']=='ACTIVE' and len(tenant.get('evidence',[]))==8,(status,tenant)

            cp=checkpoint(base,project['id'],cluster['id'],tokens['backup-operator'])
            status,delete=req(base+f"/api/v1/tenants/{tenant['id']}/delete",'POST',{'recoveryCheckpointId':cp['id']},{**bearer(tokens['requester']),'If-Match':f'"{tenant["revision"]}"','X-Confirm-Delete':'delete-tenant-namespace'});assert status==200 and delete['state']=='DELETE_AWAITING_APPROVAL' and delete['recoveryCheckpointId']==cp['id'] and delete.get('destructiveOperationId'),(status,delete)
            opid=delete['destructiveOperationId'];status,op=req(base+f'/api/v1/operations/{opid}',headers=bearer(tokens['admin']));assert status==200 and op['operation']['state']=='AWAITING_APPROVAL',(status,op)
            status,empty=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/next",headers={'Authorization':'Bearer '+agent});assert status==204,(status,empty)

            # Approval state and recovery binding survive API restart.
            stop(p);p,base=start(binary,state,oidc)
            status,delete=req(base+f"/api/v1/tenants/{tenant['id']}",headers=bearer(tokens['admin']));assert status==200 and delete['state']=='DELETE_AWAITING_APPROVAL' and delete['recoveryCheckpointId']==cp['id'] and delete.get('evidenceDigest') and len(delete.get('evidence',[]))==8 and delete['storagePolicy']['storageClass']=='replicated' and delete['backupPolicy']['provider']=='velero' and delete['securityPolicy']['podSecurityLevel']=='restricted',(status,delete)
            status,approved=req(base+f"/api/v1/tenants/{tenant['id']}/approve",'POST',{}, {**bearer(tokens['approver-delete']),'If-Match':f'"{delete["revision"]}"'});assert status==200 and approved['state']=='DELETE_QUEUED' and approved['approvedBy']=='approver-delete',(status,approved)
            status,op=req(base+f'/api/v1/operations/{opid}',headers=bearer(tokens['admin']));assert status==200 and op['operation']['state']=='QUEUED',(status,op)
            status,task=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/next",headers={'Authorization':'Bearer '+agent});assert status==200 and task['action']=='DELETE',(status,task)
            status,deleted=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/{tenant['id']}/result",'POST',{'taskFenceToken':task['taskFenceToken'],'action':'DELETE','success':True,'deleted':True},{'Authorization':'Bearer '+agent,'If-Match':f'"{task["tenantRevision"]}"'});assert status==200 and deleted['state']=='DELETED',(status,deleted)
            print('TENANT_POLICY_EVIDENCE_AUTHORITY_SMOKE_PASS',tenant['id'],tenant.get('evidenceDigest'))
            print('TENANT_RESIZE_PROTECTED_DELETE_RUNTIME_SMOKE_PASS',tenant['id'],opid)
        finally:
            stop(p);oidc.close()
    return 0
if __name__=='__main__':raise SystemExit(main())
