#!/usr/bin/env python3
from __future__ import annotations
import datetime as dt,hashlib,json,os,socket,subprocess,sys,tempfile,time,urllib.error,urllib.request
from pathlib import Path

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()

def free_port():
    with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]
def req(url,method='GET',body=None,headers=None):
    data=None if body is None else json.dumps(body).encode(); h=dict(headers or {})
    if data is not None:h['Content-Type']='application/json'
    r=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(r,timeout=5) as x:
            raw=x.read(); return x.status,json.loads(raw or b'null')
    except urllib.error.HTTPError as e:
        raw=e.read()
        try:v=json.loads(raw or b'null')
        except Exception:v={'raw':raw.decode(errors='replace')}
        return e.code,v
def start(binary,state):
    port=free_port();env=os.environ.copy();env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}';env['PLATFORM_FACTORY_STATE_FILE']=str(state);env['PLATFORM_FACTORY_AGENT_MTLS_REQUIRED']='false';env['PLATFORM_FACTORY_PUBLIC_URL']='https://platform.example.test';env['PLATFORM_FACTORY_FLEET_AGENT_IMAGE']='registry.local/agent@sha256:'+'a'*64;env['PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE']='registry.local/probe@sha256:'+'b'*64
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
def iso(v):return v.isoformat().replace('+00:00','Z')
def inventory(tag):
    now=dt.datetime.now(dt.timezone.utc)
    return {'observedAt':iso(now),'externalUid':'owner-recovery-cluster','distribution':'rke2','kubernetesVersion':'v1.34.9+rke2r1','nodes':[{'name':'n1','uid':'n1','roles':['control-plane'],'os':'Ubuntu 24.04','architecture':'amd64','kubeletVersion':'v1.34.9','ready':True}],'capacity':{'cpuCapacityMilli':4000,'cpuAllocatableMilli':3500,'memoryCapacityBytes':8589934592,'memoryAllocatableBytes':7516192768,'podsCapacity':110,'podsAllocatable':100},'storageClasses':[{'name':'replicated','provisioner':'storage.test/csi','default':True,'allowVolumeExpansion':True}], 'apiResources':[{'apiVersion':'networking.k8s.io/v1','group':'networking.k8s.io','version':'v1','kind':'NetworkPolicy','resource':'networkpolicies','namespaced':True,'verbs':['get','patch']},{'apiVersion':'velero.io/v1','group':'velero.io','version':'v1','kind':'Schedule','resource':'schedules','namespaced':True,'verbs':['get','patch']}], 'apiDiscoveryComplete':True,'capabilities':['read-only-inventory','storage-class-inventory','tenant-delete-observed','target-enrollment-principal-isolated','target-mutation-rbac-active'],'addOns':[{'name':'owner-recovery-marker','namespace':'kube-system','version':tag,'healthy':True}]}

def activate_mutation_rbac(base,cluster_id,token,desired):
    initial=json.loads(json.dumps(desired)); initial['capabilities']=[c for c in initial.get('capabilities',[]) if c not in ('target-mutation-rbac-active','target-mutation-rbac-activation-issued')]
    if 'target-enrollment-principal-isolated' not in initial['capabilities']: initial['capabilities'].append('target-enrollment-principal-isolated')
    st,out=req(base+f"/agent/v1/clusters/{cluster_id}/inventory",'POST',initial,{'Authorization':'Bearer '+token}); assert st==200,(st,out)
    st,activation=req(base+f"/api/v1/clusters/{cluster_id}/mutation-rbac-manifest",'POST',{},headers={'X-Actor-ID':'operator'}); assert st==200 and activation.get('activationIssued') is True,(st,activation)
    active=json.loads(json.dumps(desired)); caps=[c for c in active.get('capabilities',[]) if c!='target-mutation-rbac-activation-issued']
    if 'target-enrollment-principal-isolated' not in caps: caps.append('target-enrollment-principal-isolated')
    if 'target-mutation-rbac-active' not in caps: caps.append('target-mutation-rbac-active')
    active['capabilities']=caps
    st,out=req(base+f"/agent/v1/clusters/{cluster_id}/inventory",'POST',active,{'Authorization':'Bearer '+token}); assert st==200,(st,out)
    return out

def sha(value):return 'sha256:'+hashlib.sha256(value.encode()).hexdigest()
def tenant_result(task):
    evidence=[]
    for r in task['resources']:
        key=f"resource/{r['kind']}/{r['name']}"
        evidence.append({'key':key,'authority':'KUBERNETES_API_READBACK_V1','resource':f"{r['kind']}/{r['name']}",'status':'PASS','digest':sha(key)})
    evidence.append({'key':'security/pod-security-admission-negative','authority':'KUBERNETES_POD_SECURITY_ADMISSION_V1','status':'PASS','digest':sha('psa-negative')})
    raw=json.dumps(evidence,separators=(',',':'),ensure_ascii=False).encode()
    return {'taskFenceToken':task['taskFenceToken'],'action':task['action'],'success':True,'observedDigest':task['desiredDigest'],'evidence':evidence,'evidenceDigest':'sha256:'+hashlib.sha256(raw).hexdigest()}

def checkpoint(base,project,cluster,tag):
    now=dt.datetime.now(dt.timezone.utc);st,cp=req(base+'/api/v1/recovery-checkpoints','POST',{'projectId':project,'clusterId':cluster,'provider':'s3','reference':'owner-recovery/'+tag,'evidenceDigest':'sha256:'+tag*64,'completedAt':iso(now-dt.timedelta(minutes=2)),'expiresAt':iso(now+dt.timedelta(hours=2))},{'X-Actor-ID':'operator'});assert st==201,(st,cp);return cp
def main():
    if len(sys.argv)!=2:raise SystemExit('usage: smoke_owner_destructive_recovery.py platform-api')
    binary=Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as td:
      state=Path(td)/'state.json';p,base=start(binary,state)
      try:
        st,ver=req(base+'/api/v1/version');assert st==200 and ver['version']==EXPECTED_VERSION,(st,ver)
        st,org=req(base+'/api/v1/organizations','POST',{'name':'owner-recovery','displayName':'Owner Recovery'});assert st==201,(st,org)
        st,project=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'prod','displayName':'Production'});assert st==201,(st,project)
        st,_=req(base+f"/api/v1/organizations/{org['id']}/entitlement",'PUT',{'edition':'service-provider'},{'X-Actor-ID':'admin','X-Actor-Role':'platform-admin','If-None-Match':'*'});assert st==200,st
        st,created=req(base+'/api/v1/cluster-imports','POST',{'projectId':project['id'],'name':'runtime','displayName':'Runtime'});assert st==201,(st,created)
        imp=created['import'];enrollment=created['enrollmentToken'];st,_=req(base+f"/api/v1/cluster-imports/{imp['id']}/approve",'POST',{}, {'If-Match':'1'});assert st==200,st
        st,claimed=req(base+f"/agent/v1/cluster-imports/{imp['id']}/claim",'POST',{'token':enrollment,'externalUid':'owner-recovery-cluster','agentVersion':EXPECTED_VERSION});assert st==200,(st,claimed)
        cluster=claimed['cluster'];agent=claimed['agentToken'];activate_mutation_rbac(base,cluster['id'],agent,inventory('a'))
        st,created=req(base+'/api/v1/tenants','POST',{'projectId':project['id'],'clusterId':cluster['id'],'name':'customer-a','displayName':'Customer A','planName':'small'},{'X-Actor-ID':'operator','Idempotency-Key':'owner-recovery-tenant'});assert st==201,(st,created);tenant=created['tenant']
        st,task=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/next",headers={'Authorization':'Bearer '+agent});assert st==200 and task['action']=='PROVISION',(st,task)
        st,tenant=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/{tenant['id']}/result",'POST',tenant_result(task),{'Authorization':'Bearer '+agent,'If-Match':f'"{task["tenantRevision"]}"'});assert st==200 and tenant['state']=='ACTIVE',(st,tenant)
        # Confirmation alone is insufficient: recovery evidence is mandatory.
        st,missing=req(base+f"/api/v1/tenants/{tenant['id']}/delete",'POST',{}, {'X-Actor-ID':'operator','If-Match':f'"{tenant["revision"]}"','X-Confirm-Delete':'delete-tenant-namespace'});assert st==400 and missing.get('error',{}).get('code')=='RECOVERY_CHECKPOINT_REQUIRED',(st,missing)
        cp1=checkpoint(base,project['id'],cluster['id'],'c')
        st,queued=req(base+f"/api/v1/tenants/{tenant['id']}/delete",'POST',{'recoveryCheckpointId':cp1['id']},{'X-Actor-ID':'operator','If-Match':f'"{tenant["revision"]}"','X-Confirm-Delete':'delete-tenant-namespace'});assert st==200 and queued['state']=='DELETE_AWAITING_APPROVAL' and queued.get('destructiveOperationId'),(st,queued)
        op1id=queued['destructiveOperationId'];st,op1=req(base+f'/api/v1/operations/{op1id}');assert st==200 and op1['operation']['state']=='AWAITING_APPROVAL' and op1['operation']['recoveryCheckpointId']==cp1['id'],(st,op1)
        st,queued=req(base+f"/api/v1/tenants/{tenant['id']}/approve",'POST',{}, {'X-Actor-ID':'approver-a','X-Actor-Role':'platform-admin','If-Match':f'"{queued["revision"]}"'});assert st==200 and queued['state']=='DELETE_QUEUED',(st,queued)
        # Inventory drift makes the checkpoint stale immediately before mutation.
        st,_=req(base+f"/agent/v1/clusters/{cluster['id']}/inventory",'POST',inventory('b'),{'Authorization':'Bearer '+agent});assert st==200,st
        st,blocked=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/next",headers={'Authorization':'Bearer '+agent});assert st==422 and blocked.get('error',{}).get('code')=='PREREQUISITE_NOT_SATISFIED',(st,blocked)
        st,current=req(base+f"/api/v1/tenants/{tenant['id']}");assert st==200 and current['state']=='DELETE_QUEUED',(st,current)
        cp2=checkpoint(base,project['id'],cluster['id'],'d')
        st,rebound=req(base+f"/api/v1/tenants/{tenant['id']}/delete",'POST',{'recoveryCheckpointId':cp2['id']},{'X-Actor-ID':'operator','If-Match':f'"{current["revision"]}"','X-Confirm-Delete':'delete-tenant-namespace'});assert st==200 and rebound['state']=='DELETE_AWAITING_APPROVAL' and rebound['destructiveOperationId']!=op1id,(st,rebound)
        st,old=req(base+f'/api/v1/operations/{op1id}');assert st==200 and old['operation']['state']=='CANCELLED',(st,old)
        op2id=rebound['destructiveOperationId'];st,rebound=req(base+f"/api/v1/tenants/{tenant['id']}/approve",'POST',{}, {'X-Actor-ID':'approver-b','X-Actor-Role':'platform-admin','If-Match':f'"{rebound["revision"]}"'});assert st==200 and rebound['state']=='DELETE_QUEUED',(st,rebound)
        st,task=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/next",headers={'Authorization':'Bearer '+agent});assert st==200 and task['action']=='DELETE',(st,task)
        st,running=req(base+f'/api/v1/operations/{op2id}');assert st==200 and running['operation']['state']=='RUNNING',(st,running)
        st,deleted=req(base+f"/agent/v1/clusters/{cluster['id']}/tenant-tasks/{tenant['id']}/result",'POST',{'taskFenceToken':task['taskFenceToken'],'action':'DELETE','success':True,'deleted':True},{'Authorization':'Bearer '+agent,'If-Match':f'"{task["tenantRevision"]}"'});assert st==200 and deleted['state']=='DELETED',(st,deleted)
        st,done=req(base+f'/api/v1/operations/{op2id}');assert st==200 and done['operation']['state']=='SUCCEEDED',(st,done)
        print('OWNER_DESTRUCTIVE_RECOVERY_AUTHORITY_SMOKE_PASS',tenant['id'],op1id,op2id)
      finally: stop(p)
    return 0
if __name__=='__main__':raise SystemExit(main())
