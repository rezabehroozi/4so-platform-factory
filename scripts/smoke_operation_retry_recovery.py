#!/usr/bin/env python3
from __future__ import annotations
import datetime as dt, json, os, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

def free_port():
    with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]
def req(url,method='GET',body=None,headers=None):
    data=None if body is None else json.dumps(body).encode(); h=dict(headers or {})
    if data is not None:h['Content-Type']='application/json'
    r=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(r,timeout=5) as x:
            raw=x.read(); return x.status,json.loads(raw or b'null'),dict(x.headers)
    except urllib.error.HTTPError as e:
        raw=e.read()
        try:v=json.loads(raw or b'null')
        except Exception:v={'raw':raw.decode(errors='replace')}
        return e.code,v,dict(e.headers)
def start(binary,state):
    port=free_port(); env=os.environ.copy();env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}';env['PLATFORM_FACTORY_STATE_FILE']=str(state);env['PLATFORM_FACTORY_DEVELOPMENT_MODE']='true';env['PLATFORM_FACTORY_AGENT_MTLS_REQUIRED']='false';env['PLATFORM_FACTORY_PUBLIC_URL']='https://platform.example.test';env['PLATFORM_FACTORY_FLEET_AGENT_IMAGE']='registry.local/agent@sha256:'+'a'*64;env['PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE']='registry.local/probe@sha256:'+'b'*64
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
def inv(tag='1'):
    now=dt.datetime.now(dt.timezone.utc)
    return {'observedAt':iso(now),'externalUid':'retry-cluster','distribution':'rke2','kubernetesVersion':'v1.34.9+rke2r1','nodes':[{'name':'n1','uid':'n1','roles':['control-plane'],'os':'Ubuntu 24.04','architecture':'amd64','kubeletVersion':'v1.34.9','ready':True}],'capacity':{'cpuCapacityMilli':4000,'cpuAllocatableMilli':3500,'memoryCapacityBytes':8589934592,'memoryAllocatableBytes':7516192768,'podsCapacity':110,'podsAllocatable':100},'capabilities':['read-only-inventory'],'addOns':[{'name':'marker','namespace':'kube-system','version':tag,'healthy':True}]}
def transition(base,op,state):
    st,v,_=req(base+f"/api/v1/operations/{op['id']}/transition",'POST',{'state':state},{'X-Actor-ID':'operator','If-Match':f'"{op["revision"]}"'});assert st==200,(st,v);return v
def main():
    if len(sys.argv)!=2:raise SystemExit('usage: smoke_operation_retry_recovery.py platform-api')
    binary=Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as td:
        state=Path(td)/'state.json';p,base=start(binary,state)
        try:
            st,ver,_=req(base+'/api/v1/version');assert st==200;version=ver['version']
            st,org,_=req(base+'/api/v1/organizations','POST',{'name':'retry-recovery-smoke','displayName':'Retry Recovery Smoke'});assert st==201,(st,org)
            st,project,_=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'prod','displayName':'Production'});assert st==201,(st,project)
            st,created,_=req(base+'/api/v1/cluster-imports','POST',{'projectId':project['id'],'name':'edge-1','displayName':'Edge 1'});assert st==201,(st,created)
            imp=created['import'];token=created['enrollmentToken'];st,_,_=req(base+f"/api/v1/cluster-imports/{imp['id']}/approve",'POST',{}, {'If-Match':'1'});assert st==200
            st,claimed,_=req(base+f"/agent/v1/cluster-imports/{imp['id']}/claim",'POST',{'token':token,'externalUid':'retry-cluster','agentVersion':version});assert st==200,(st,claimed)
            cluster=claimed['cluster'];agent=claimed['agentToken'];st,_,_=req(base+f"/agent/v1/clusters/{cluster['id']}/inventory",'POST',inv(),{'Authorization':'Bearer '+agent});assert st==200
            now=dt.datetime.now(dt.timezone.utc);st,cp,_=req(base+'/api/v1/recovery-checkpoints','POST',{'projectId':project['id'],'clusterId':cluster['id'],'provider':'s3','reference':'backup/retry/001','evidenceDigest':'sha256:'+'d'*64,'completedAt':iso(now-dt.timedelta(minutes=2)),'expiresAt':iso(now+dt.timedelta(hours=2))},{'X-Actor-ID':'operator'});assert st==201,(st,cp)
            # Destructive operation gets a fixed class policy and immutable recovery binding.
            body={'projectId':project['id'],'kind':'cluster.wipe','targetRef':'cluster:'+cluster['id'],'desiredRevision':'sha256:'+'1'*64,'risk':'critical','class':'DESTRUCTIVE','recoveryCheckpointId':cp['id']}
            st,op,_=req(base+'/api/v1/operations','POST',body,{'X-Actor-ID':'operator','Idempotency-Key':'wipe-001'});assert st==201,(st,op);assert op['retryPolicy']['maxAttempts']==2 and op['recoveryEvidenceDigest']==cp['evidenceDigest'],op
            op=transition(base,op,'PLANNING');op=transition(base,op,'QUEUED')
            st,lease,_=req(base+f"/api/v1/operations/{op['id']}/claim",'POST',{'workerId':'worker-a','leaseSeconds':60},{'X-Actor-ID':'operator'});assert st==200,(st,lease)
            st,view,_=req(base+f"/api/v1/operations/{op['id']}");op=view['operation']
            st,op,_=req(base+f"/api/v1/operations/{op['id']}/attempt/start",'POST',{'workerId':'worker-a','fenceToken':lease['fenceToken']},{'X-Actor-ID':'operator','If-Match':f'"{op["revision"]}"'});assert st==200 and op['attempt']==1,(st,op)
            st,op,_=req(base+f"/api/v1/operations/{op['id']}/attempt/failure",'POST',{'workerId':'worker-a','fenceToken':lease['fenceToken'],'failure':{'class':'TRANSIENT_NETWORK','code':'ECONNRESET','message':'connection reset'}},{'X-Actor-ID':'operator','If-Match':f'"{op["revision"]}"'});assert st==200 and op['state']=='RETRY_WAIT',(st,op)
            st,early,_=req(base+f"/api/v1/operations/{op['id']}/claim",'POST',{'workerId':'worker-b','leaseSeconds':60},{'X-Actor-ID':'operator'});assert st in (409,422),(st,early)
            next_at=dt.datetime.fromisoformat(op['nextAttemptAt'].replace('Z','+00:00'));sleep=max(0,(next_at-dt.datetime.now(dt.timezone.utc)).total_seconds()+0.15);time.sleep(sleep)
            st,lease2,_=req(base+f"/api/v1/operations/{op['id']}/claim",'POST',{'workerId':'worker-b','leaseSeconds':60},{'X-Actor-ID':'operator'});assert st==200,(st,lease2)
            st,view,_=req(base+f"/api/v1/operations/{op['id']}");op=view['operation']
            st,op,_=req(base+f"/api/v1/operations/{op['id']}/attempt/start",'POST',{'workerId':'worker-b','fenceToken':lease2['fenceToken']},{'X-Actor-ID':'operator','If-Match':f'"{op["revision"]}"'});assert st==200 and op['attempt']==2,(st,op)
            st,op,_=req(base+f"/api/v1/operations/{op['id']}/attempt/failure",'POST',{'workerId':'worker-b','fenceToken':lease2['fenceToken'],'failure':{'class':'TRANSIENT_NETWORK','code':'ETIMEDOUT','message':'timeout'}},{'X-Actor-ID':'operator','If-Match':f'"{op["revision"]}"'});assert st==200 and op['state']=='FAILED' and op['retryExhausted'],(st,op)
            st,bypass,_=req(base+f"/api/v1/operations/{op['id']}/transition",'POST',{'state':'QUEUED'},{'X-Actor-ID':'operator','If-Match':f'"{op["revision"]}"'});assert st==422 and bypass.get('error',{}).get('code')=='PREREQUISITE_NOT_SATISFIED',(st,bypass)
            exhausted_id=op['id']
            # Stale recovery evidence blocks the first destructive mutation attempt.
            body2=dict(body);body2['desiredRevision']='sha256:'+'2'*64
            st,stale,_=req(base+'/api/v1/operations','POST',body2,{'X-Actor-ID':'operator','Idempotency-Key':'wipe-stale'});assert st==201,(st,stale);stale=transition(base,stale,'PLANNING');stale=transition(base,stale,'QUEUED')
            st,_,_=req(base+f"/agent/v1/clusters/{cluster['id']}/inventory",'POST',inv('changed'),{'Authorization':'Bearer '+agent});assert st==200
            st,sl,_=req(base+f"/api/v1/operations/{stale['id']}/claim",'POST',{'workerId':'worker-c','leaseSeconds':60},{'X-Actor-ID':'operator'});assert st==200,(st,sl)
            st,stale_view,_=req(base+f"/api/v1/operations/{stale['id']}");stale=stale_view['operation']
            st,blocked,_=req(base+f"/api/v1/operations/{stale['id']}/attempt/start",'POST',{'workerId':'worker-c','fenceToken':sl['fenceToken']},{'X-Actor-ID':'operator','If-Match':f'"{stale["revision"]}"'});assert st==422 and blocked.get('error',{}).get('code')=='PREREQUISITE_NOT_SATISFIED',(st,blocked)
            # Safe cancellation drains active work instead of force-killing the lease.
            st,cancelop,_=req(base+'/api/v1/operations','POST',{'projectId':project['id'],'kind':'config.apply','targetRef':'project:'+project['id'],'desiredRevision':'sha256:'+'3'*64,'risk':'medium','class':'MUTATING'},{'X-Actor-ID':'operator','Idempotency-Key':'cancel-001'});assert st==201
            cancelop=transition(base,cancelop,'PLANNING');cancelop=transition(base,cancelop,'QUEUED')
            st,cl,_=req(base+f"/api/v1/operations/{cancelop['id']}/claim",'POST',{'workerId':'worker-d','leaseSeconds':60},{'X-Actor-ID':'operator'});assert st==200
            st,cv,_=req(base+f"/api/v1/operations/{cancelop['id']}");cancelop=cv['operation'];st,cancelop,_=req(base+f"/api/v1/operations/{cancelop['id']}/attempt/start",'POST',{'workerId':'worker-d','fenceToken':cl['fenceToken']},{'X-Actor-ID':'operator','If-Match':f'"{cancelop["revision"]}"'});assert st==200
            st,cancelop,_=req(base+f"/api/v1/operations/{cancelop['id']}/cancel",'POST',{'reason':'operator maintenance abort'},{'X-Actor-ID':'operator','If-Match':f'"{cancelop["revision"]}"'});assert st==200 and cancelop['state']=='CANCEL_REQUESTED' and cancelop['leaseOwner']=='worker-d',(st,cancelop)
            st,cancelop,_=req(base+f"/api/v1/operations/{cancelop['id']}/cancel/ack",'POST',{'workerId':'worker-d','fenceToken':cl['fenceToken']},{'X-Actor-ID':'operator','If-Match':f'"{cancelop["revision"]}"'});assert st==200 and cancelop['state']=='CANCELLED' and not cancelop.get('leaseOwner'),(st,cancelop)
            cancelled_id=cancelop['id']
        finally:stop(p)
        p,base=start(binary,state)
        try:
            st,a,_=req(base+f'/api/v1/operations/{exhausted_id}');assert st==200 and a['operation']['state']=='FAILED' and a['operation']['retryExhausted']
            st,c,_=req(base+f'/api/v1/operations/{cancelled_id}');assert st==200 and c['operation']['state']=='CANCELLED' and c['operation']['cancelReason']=='operator maintenance abort'
            print('BOUNDED_RETRY_DESTRUCTIVE_RECOVERY_SMOKE_PASS',exhausted_id,cancelled_id,a['operation']['attempt'])
        finally:stop(p)
    return 0
if __name__=='__main__':raise SystemExit(main())
