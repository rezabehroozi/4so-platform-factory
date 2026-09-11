#!/usr/bin/env python3
from __future__ import annotations
import base64, hashlib, json, os, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()

METHOD='OPERATION_STEP_TRACE_EVIDENCE_V1'

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); return sock.getsockname()[1]

def req(url,method='GET',body=None,headers=None,raw=False):
    data=None if body is None else json.dumps(body).encode()
    request_headers=dict(headers or {})
    if data is not None: request_headers['Content-Type']='application/json'
    request=urllib.request.Request(url,data=data,headers=request_headers,method=method)
    try:
        with urllib.request.urlopen(request,timeout=8) as response:
            payload=response.read()
            if raw: return response.status,payload,dict(response.headers)
            return response.status,json.loads(payload or b'null'),dict(response.headers)
    except urllib.error.HTTPError as exc:
        payload=exc.read()
        if raw: return exc.code,payload,dict(exc.headers)
        try: value=json.loads(payload or b'null')
        except Exception: value={'raw':payload.decode(errors='replace')}
        return exc.code,value,dict(exc.headers)

def start(binary,state):
    port=free_port(); env=os.environ.copy()
    env['PLATFORM_FACTORY_DEVELOPMENT_MODE']='true'
    env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}'
    env['PLATFORM_FACTORY_STATE_FILE']=str(state)
    env['PLATFORM_FACTORY_AGENT_MTLS_REQUIRED']='false'
    env['PLATFORM_FACTORY_PUBLIC_URL']='https://platform.example.test'
    env['PLATFORM_FACTORY_FLEET_AGENT_IMAGE']='registry.local/agent@sha256:'+'a'*64
    env['PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE']='registry.local/probe@sha256:'+'b'*64
    process=subprocess.Popen([str(binary)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    base=f'http://127.0.0.1:{port}'
    for _ in range(120):
        try:
            if req(base+'/readyz')[0]==200: return process,base
        except Exception: pass
        time.sleep(.1)
    output=''
    try: output=process.stdout.read()
    except Exception: pass
    process.terminate(); raise RuntimeError('api not ready '+output)

def stop(process):
    process.terminate()
    try: process.wait(timeout=5)
    except subprocess.TimeoutExpired: process.kill(); process.wait()

def transition(base,op,state):
    status,value,_=req(base+f"/api/v1/operations/{op['id']}/transition",'POST',{'state':state},{'X-Actor-ID':'trace-operator','If-Match':f'"{op["revision"]}"'})
    assert status==200,(status,value); return value

def get_view(base,operation_id):
    status,value,_=req(base+f'/api/v1/operations/{operation_id}')
    assert status==200,(status,value); return value

def main():
    if len(sys.argv)!=2: raise SystemExit('usage: smoke_operation_step_trace_authority.py platform-api')
    binary=Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as temp:
        state=Path(temp)/'state.json'; process,base=start(binary,state)
        try:
            status,version,_=req(base+'/api/v1/version'); assert status==200 and version['version']==EXPECTED_VERSION,(status,version)
            status,org,_=req(base+'/api/v1/organizations','POST',{'name':'trace-smoke','displayName':'Trace Smoke'}); assert status==201,(status,org)
            status,project,_=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'prod','displayName':'Production'}); assert status==201,(status,project)
            status,op,_=req(base+'/api/v1/operations','POST',{'projectId':project['id'],'kind':'baseline.apply','targetRef':'cluster:trace','desiredRevision':'sha256:'+'1'*64,'risk':'medium','class':'MUTATING'},{'X-Actor-ID':'trace-operator','Idempotency-Key':'trace-authority'}); assert status==201,(status,op)
            op=transition(base,op,'PLANNING'); op=transition(base,op,'QUEUED')
            status,lease,_=req(base+f"/api/v1/operations/{op['id']}/claim",'POST',{'workerId':'trace-worker','leaseSeconds':30},{'X-Actor-ID':'trace-operator'}); assert status==200,(status,lease)
            op=get_view(base,op['id'])['operation']
            status,op,_=req(base+f"/api/v1/operations/{op['id']}/attempt/start",'POST',{'workerId':'trace-worker','fenceToken':lease['fenceToken']},{'X-Actor-ID':'trace-operator','If-Match':f'"{op["revision"]}"'}); assert status==200 and op['attempt']==1,(status,op)
            status,step,_=req(base+f"/api/v1/operations/{op['id']}/steps",'POST',{'workerId':'trace-worker','fenceToken':lease['fenceToken'],'stepKey':'apply-resources','state':'RUNNING'},{'X-Actor-ID':'trace-operator'}); assert status==201 and step['attempt']==1,(status,step)

            payload=json.dumps({'operationId':op['id'],'stepKey':'apply-resources','objects':5,'result':'applied'},sort_keys=True,separators=(',',':')).encode()
            trace_body={'workerId':'trace-worker','fenceToken':lease['fenceToken'],'traceKey':'apply-readback','level':'INFO','eventType':'kubernetes.apply.readback','message':'five resources applied and read back','evidenceKind':'kubernetes-readback','mediaType':'application/json','payloadBase64':base64.b64encode(payload).decode()}
            status,sealed,_=req(base+f"/api/v1/operations/{op['id']}/steps/forward/apply-resources/trace",'POST',trace_body,{'X-Actor-ID':'trace-operator'}); assert status==201,(status,sealed)
            assert sealed['method']==METHOD and sealed['trace']['sequence']==1 and sealed['trace']['attempt']==1,sealed
            evidence=sealed['evidence']; trace=sealed['trace']; expected='sha256:'+hashlib.sha256(payload).hexdigest()
            assert evidence['digest']==expected and evidence['traceId']==trace['id'] and evidence['hasPayload'] is True,sealed

            # Idempotent replay returns exactly the existing append-only trace/evidence pair.
            status,replay,_=req(base+f"/api/v1/operations/{op['id']}/steps/forward/apply-resources/trace",'POST',trace_body,{'X-Actor-ID':'trace-operator'}); assert status==201,(status,replay)
            assert replay['trace']['id']==trace['id'] and replay['evidence']['id']==evidence['id'],replay
            tampered=dict(trace_body); tampered['message']='changed content under same trace key'
            status,conflict,_=req(base+f"/api/v1/operations/{op['id']}/steps/forward/apply-resources/trace",'POST',tampered,{'X-Actor-ID':'trace-operator'}); assert status==409 and conflict['error']['code']=='IDEMPOTENCY_CONFLICT',(status,conflict)

            payload_url=base+f"/api/v1/operations/{op['id']}/evidence/{evidence['id']}/payload"
            status,download,headers=req(payload_url,raw=True); assert status==200 and download==payload,(status,download)
            lowered={k.lower():v for k,v in headers.items()}
            assert lowered.get('x-evidence-digest')==expected and lowered.get('x-operation-step-phase')=='FORWARD' and lowered.get('x-operation-step-key')=='apply-resources' and lowered.get('x-operation-step-attempt')=='1',lowered

            view=get_view(base,op['id']); assert view['traceMethod']==METHOD and len(view['traces'])==1 and view['traces'][0]['evidenceId']==evidence['id'],view
            status,audit,_=req(base+'/api/v1/audit-events?limit=100'); assert status==200,(status,audit)
            linked=[event for event in audit if event.get('action')=='operation_step.trace_sealed' and event.get('resourceId')==trace['id']]
            assert len(linked)==1 and linked[0].get('metadata',{}).get('evidenceId')==evidence['id'] and linked[0].get('metadata',{}).get('stepKey')=='apply-resources',linked
            operation_id=op['id']; evidence_id=evidence['id']
        finally: stop(process)

        # FileStore restart must preserve trace sequence/linkage and the exact sealed payload.
        process,base=start(binary,state)
        try:
            view=get_view(base,operation_id)
            assert view['traceMethod']==METHOD and len(view['traces'])==1 and view['traces'][0]['traceKey']=='apply-readback',view
            restored=[item for item in view['evidence'] if item['id']==evidence_id]; assert len(restored)==1 and restored[0]['hasPayload'] is True,view
            status,download,headers=req(base+f'/api/v1/operations/{operation_id}/evidence/{evidence_id}/payload',raw=True)
            assert status==200 and download==payload,(status,download)
            assert {k.lower():v for k,v in headers.items()}.get('x-evidence-digest')==expected,headers
            print('OPERATION_STEP_TRACE_EVIDENCE_AUTHORITY_SMOKE_PASS',version['version'],operation_id,evidence_id)
        finally: stop(process)
    return 0

if __name__=='__main__': raise SystemExit(main())
