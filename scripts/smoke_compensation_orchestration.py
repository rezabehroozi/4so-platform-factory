#!/usr/bin/env python3
from __future__ import annotations
import base64, json, os, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

def free_port():
    with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]
def req(url,method='GET',body=None,headers=None):
    data=None if body is None else json.dumps(body).encode(); h=dict(headers or {})
    if data is not None: h['Content-Type']='application/json'
    r=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(r,timeout=8) as x:
            raw=x.read(); return x.status,json.loads(raw or b'null'),dict(x.headers)
    except urllib.error.HTTPError as e:
        raw=e.read()
        try:v=json.loads(raw or b'null')
        except Exception:v={'raw':raw.decode(errors='replace')}
        return e.code,v,dict(e.headers)
def start(binary,state):
    port=free_port(); env=os.environ.copy();env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}';env['PLATFORM_FACTORY_STATE_FILE']=str(state);env['PLATFORM_FACTORY_AGENT_MTLS_REQUIRED']='false';env['PLATFORM_FACTORY_PUBLIC_URL']='https://platform.example.test';env['PLATFORM_FACTORY_FLEET_AGENT_IMAGE']='registry.local/agent@sha256:'+'a'*64;env['PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE']='registry.local/probe@sha256:'+'b'*64
    p=subprocess.Popen([str(binary)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);base=f'http://127.0.0.1:{port}'
    for _ in range(120):
        try:
            if req(base+'/readyz')[0]==200:return p,base
        except Exception:pass
        time.sleep(.1)
    out='';
    try: out=p.stdout.read()
    except Exception: pass
    p.terminate();raise RuntimeError('api not ready '+out)
def stop(p):
    p.terminate()
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.wait()
def transition(base,op,state):
    st,v,_=req(base+f"/api/v1/operations/{op['id']}/transition",'POST',{'state':state},{'X-Actor-ID':'operator','If-Match':f'"{op["revision"]}"'});assert st==200,(st,v);return v
def getop(base,opid):
    st,v,_=req(base+f'/api/v1/operations/{opid}');assert st==200,(st,v);return v
def seal_compensation_trace(base,opid,step,worker,fence,suffix):
    payload=json.dumps({'step':step['stepKey'],'attempt':step['attempt'],'result':'ok'},sort_keys=True,separators=(',',':')).encode()
    body={'workerId':worker,'fenceToken':fence,'traceKey':f"{step['stepKey']}-{step['attempt']}-{suffix}",'level':'INFO','eventType':'compensation.result','message':'compensation step completed','evidenceKind':'compensation-result','mediaType':'application/json','payloadBase64':base64.b64encode(payload).decode()}
    st,v,_=req(base+f"/api/v1/operations/{opid}/steps/compensation/{step['stepKey']}/trace",'POST',body,{'X-Actor-ID':'operator'});assert st==201,(st,v);assert v['method']=='OPERATION_STEP_TRACE_EVIDENCE_V1';return v['evidence']['digest'],v

def main():
    if len(sys.argv)!=2: raise SystemExit('usage: smoke_compensation_orchestration.py platform-api')
    binary=Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as td:
        state=Path(td)/'state.json';p,base=start(binary,state)
        try:
            st,ver,_=req(base+'/api/v1/version');assert st==200;version=ver['version']
            st,org,_=req(base+'/api/v1/organizations','POST',{'name':'comp-smoke','displayName':'Compensation Smoke'});assert st==201,(st,org)
            st,project,_=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'prod','displayName':'Production'});assert st==201,(st,project)
            body={'projectId':project['id'],'kind':'platform.compose','targetRef':'cluster:demo','desiredRevision':'sha256:'+'1'*64,'risk':'high','class':'MUTATING'}
            st,op,_=req(base+'/api/v1/operations','POST',body,{'X-Actor-ID':'operator','Idempotency-Key':'comp-main'});assert st==201,(st,op)
            op=transition(base,op,'PLANNING')
            plan={'steps':[
                {'stepKey':'namespace','forwardOrder':1,'strategy':'AUTOMATIC_ROLLBACK','action':'delete namespace','inputDigest':'sha256:'+'a'*64,'maxAttempts':2},
                {'stepKey':'controller','forwardOrder':2,'strategy':'RESTORE_PREVIOUS_REVISION','action':'restore controller','inputDigest':'sha256:'+'b'*64,'maxAttempts':2},
                {'stepKey':'route','forwardOrder':3,'strategy':'AUTOMATIC_ROLLBACK','action':'remove route','inputDigest':'sha256:'+'c'*64,'maxAttempts':2},
            ]}
            st,pv,_=req(base+f"/api/v1/operations/{op['id']}/compensation/plan",'POST',plan,{'X-Actor-ID':'operator','If-Match':f'"{op["revision"]}"'});assert st==200,(st,pv);op=pv['operation'];assert pv['method']=='GENERIC_COMPENSATION_ORCHESTRATION_V1' and op['compensationStepCount']==3
            op=transition(base,op,'QUEUED')
            st,lease,_=req(base+f"/api/v1/operations/{op['id']}/claim",'POST',{'workerId':'forward','leaseSeconds':30},{'X-Actor-ID':'operator'});assert st==200,(st,lease)
            op=getop(base,op['id'])['operation']
            st,op,_=req(base+f"/api/v1/operations/{op['id']}/attempt/start",'POST',{'workerId':'forward','fenceToken':lease['fenceToken']},{'X-Actor-ID':'operator','If-Match':f'"{op["revision"]}"'});assert st==200,(st,op)
            for key in ('namespace','controller','route'):
                st,v,_=req(base+f"/api/v1/operations/{op['id']}/compensation/forward/{key}/complete",'POST',{'workerId':'forward','fenceToken':lease['fenceToken']},{'X-Actor-ID':'operator','If-Match':f'"{op["revision"]}"'});assert st==200,(st,v);op=v['operation']
            st,op,_=req(base+f"/api/v1/operations/{op['id']}/attempt/failure",'POST',{'workerId':'forward','fenceToken':lease['fenceToken'],'failure':{'class':'PERMANENT','code':'APPLY_FAILED','message':'route verification failed'}},{'X-Actor-ID':'operator','If-Match':f'"{op["revision"]}"'});assert st==200 and op['state']=='FAILED',(st,op)
            st,op,_=req(base+f"/api/v1/operations/{op['id']}/compensation/start",'POST',{}, {'X-Actor-ID':'operator','If-Match':f'"{op["revision"]}"'});assert st==200 and op['state']=='ROLLING_BACK',(st,op)
            st,rb,_=req(base+f"/api/v1/operations/{op['id']}/claim",'POST',{'workerId':'rollback-a','leaseSeconds':1},{'X-Actor-ID':'operator'});assert st==200,(st,rb)
            st,v,_=req(base+f"/api/v1/operations/{op['id']}/compensation/claim-next",'POST',{'workerId':'rollback-a','fenceToken':rb['fenceToken']},{'X-Actor-ID':'operator'});assert st==200 and v['step']['stepKey']=='route',(st,v);op=v['operation'];route_step=v['step']
            route_digest,trace_view=seal_compensation_trace(base,op['id'],route_step,'rollback-a',rb['fenceToken'],'first')
            st,v,_=req(base+f"/api/v1/operations/{op['id']}/compensation/route/complete",'POST',{'workerId':'rollback-a','fenceToken':rb['fenceToken'],'evidenceDigest':route_digest},{'X-Actor-ID':'operator'});assert st==200 and v['step']['state']=='SUCCEEDED',(st,v);op=v['operation'];opid=op['id']
        finally:stop(p)
        time.sleep(1.15)
        p,base=start(binary,state)
        try:
            view=getop(base,opid);op=view['operation'];assert op['state']=='ROLLING_BACK' and [x['stepKey'] for x in view['compensation'] if x['state']=='SUCCEEDED']==['route'],view
            st,rb,_=req(base+f"/api/v1/operations/{opid}/claim",'POST',{'workerId':'rollback-b','leaseSeconds':30},{'X-Actor-ID':'operator'});assert st==200,(st,rb)
            st,v,_=req(base+f"/api/v1/operations/{opid}/compensation/claim-next",'POST',{'workerId':'rollback-b','fenceToken':rb['fenceToken']},{'X-Actor-ID':'operator'});assert st==200 and v['step']['stepKey']=='controller',(st,v)
            st,v,_=req(base+f"/api/v1/operations/{opid}/compensation/controller/failure",'POST',{'workerId':'rollback-b','fenceToken':rb['fenceToken'],'failure':{'message':'provider timeout','retryable':True}},{'X-Actor-ID':'operator'});assert st==200 and v['step']['state']=='PENDING' and v['operation']['state']=='ROLLING_BACK',(st,v)
            st,v,_=req(base+f"/api/v1/operations/{opid}/compensation/claim-next",'POST',{'workerId':'rollback-b','fenceToken':rb['fenceToken']},{'X-Actor-ID':'operator'});assert st==200 and v['step']['stepKey']=='controller' and v['step']['attempt']==2,(st,v);controller_step=v['step']
            controller_digest,_=seal_compensation_trace(base,opid,controller_step,'rollback-b',rb['fenceToken'],'retry')
            st,v,_=req(base+f"/api/v1/operations/{opid}/compensation/controller/complete",'POST',{'workerId':'rollback-b','fenceToken':rb['fenceToken'],'evidenceDigest':controller_digest},{'X-Actor-ID':'operator'});assert st==200,(st,v)
            st,v,_=req(base+f"/api/v1/operations/{opid}/compensation/claim-next",'POST',{'workerId':'rollback-b','fenceToken':rb['fenceToken']},{'X-Actor-ID':'operator'});assert st==200 and v['step']['stepKey']=='namespace',(st,v);namespace_step=v['step']
            namespace_digest,_=seal_compensation_trace(base,opid,namespace_step,'rollback-b',rb['fenceToken'],'final')
            st,v,_=req(base+f"/api/v1/operations/{opid}/compensation/namespace/complete",'POST',{'workerId':'rollback-b','fenceToken':rb['fenceToken'],'evidenceDigest':namespace_digest},{'X-Actor-ID':'operator'});assert st==200 and v['operation']['state']=='ROLLED_BACK',(st,v)
            final=getop(base,opid);steps=final['compensation'];assert [x['stepKey'] for x in steps]==['namespace','controller','route'];assert all(x['state']=='SUCCEEDED' for x in steps);assert steps[1]['attempt']==2;assert len(final.get('traces',[]))==3 and all(x.get('evidenceId') for x in final['traces']),final
            # Manual recovery cannot be auto-acknowledged as a clean cancellation.
            st,m,_=req(base+'/api/v1/operations','POST',{'projectId':project['id'],'kind':'provider.cutover','targetRef':'provider:demo','desiredRevision':'sha256:'+'2'*64,'risk':'critical','class':'MUTATING'},{'X-Actor-ID':'operator','Idempotency-Key':'comp-manual'});assert st==201;m=transition(base,m,'PLANNING')
            st,pv,_=req(base+f"/api/v1/operations/{m['id']}/compensation/plan",'POST',{'steps':[{'stepKey':'cutover','forwardOrder':1,'strategy':'MANUAL_RECOVERY','action':'execute provider recovery runbook','inputDigest':'sha256:'+'9'*64,'maxAttempts':1}]},{'X-Actor-ID':'operator','If-Match':f'"{m["revision"]}"'});assert st==200;m=pv['operation'];m=transition(base,m,'QUEUED')
            st,ml,_=req(base+f"/api/v1/operations/{m['id']}/claim",'POST',{'workerId':'manual-forward','leaseSeconds':30},{'X-Actor-ID':'operator'});assert st==200;m=getop(base,m['id'])['operation'];st,m,_=req(base+f"/api/v1/operations/{m['id']}/attempt/start",'POST',{'workerId':'manual-forward','fenceToken':ml['fenceToken']},{'X-Actor-ID':'operator','If-Match':f'"{m["revision"]}"'});assert st==200
            st,v,_=req(base+f"/api/v1/operations/{m['id']}/compensation/forward/cutover/complete",'POST',{'workerId':'manual-forward','fenceToken':ml['fenceToken']},{'X-Actor-ID':'operator','If-Match':f'"{m["revision"]}"'});assert st==200;m=v['operation']
            st,m,_=req(base+f"/api/v1/operations/{m['id']}/cancel",'POST',{'reason':'abort after cutover'},{'X-Actor-ID':'operator','If-Match':f'"{m["revision"]}"'});assert st==200 and m['state']=='CANCEL_REQUESTED'
            st,bad,_=req(base+f"/api/v1/operations/{m['id']}/cancel/ack",'POST',{'workerId':'manual-forward','fenceToken':ml['fenceToken']},{'X-Actor-ID':'operator','If-Match':f'"{m["revision"]}"'});assert st==422 and bad['error']['code']=='PREREQUISITE_NOT_SATISFIED',(st,bad)
            st,m,_=req(base+f"/api/v1/operations/{m['id']}/compensation/start",'POST',{}, {'X-Actor-ID':'operator','If-Match':f'"{m["revision"]}"'});assert st==200 and m['state']=='ROLLING_BACK'
            st,mc,_=req(base+f"/api/v1/operations/{m['id']}/claim",'POST',{'workerId':'manual-rb','leaseSeconds':30},{'X-Actor-ID':'operator'});assert st==200
            st,need,_=req(base+f"/api/v1/operations/{m['id']}/compensation/claim-next",'POST',{'workerId':'manual-rb','fenceToken':mc['fenceToken']},{'X-Actor-ID':'operator'});assert st==422,(st,need)
            finalm=getop(base,m['id']);assert finalm['operation']['state']=='NEEDS_OPERATOR' and finalm['compensation'][0]['state']=='MANUAL_REQUIRED',finalm
            print('GENERIC_COMPENSATION_ORCHESTRATION_SMOKE_PASS',version,opid,m['id'])
        finally:stop(p)
    return 0
if __name__=='__main__': raise SystemExit(main())
