#!/usr/bin/env python3
from __future__ import annotations
import datetime as dt, json, os, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]

def request(url, method='GET', body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    h = dict(headers or {})
    if data is not None: h['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            raw = r.read(); return r.status, json.loads(raw or b'null'), dict(r.headers)
    except urllib.error.HTTPError as e:
        raw=e.read()
        try: parsed=json.loads(raw or b'null')
        except Exception: parsed={'raw': raw.decode(errors='replace')}
        return e.code, parsed, dict(e.headers)

def start(binary, root, state_file):
    port=free_port(); env=os.environ.copy(); env['PLATFORM_FACTORY_DEVELOPMENT_MODE']='true'; env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}'; env['PLATFORM_FACTORY_STATE_FILE']=str(state_file)
    proc=subprocess.Popen([str(binary)], cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    base=f'http://127.0.0.1:{port}'
    for _ in range(100):
        try:
            status, _, _=request(base+'/readyz')
            if status==200: return proc, base
        except Exception: pass
        time.sleep(.1)
    proc.terminate(); raise RuntimeError('API did not become ready')

def stop(proc):
    proc.terminate()
    try: proc.wait(timeout=5)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait()
    return proc.stdout.read() if proc.stdout else ''

def main():
    if len(sys.argv)!=2: raise SystemExit('usage: smoke_service_account_token.py /path/to/platform-api')
    binary=Path(sys.argv[1]).resolve(); root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as td:
        state=Path(td)/'state'/'control-plane.json'; proc,base=start(binary,root,state)
        raw1=raw2=''
        try:
            st,org,_=request(base+'/api/v1/organizations','POST',{'name':'token-smoke','displayName':'Token Smoke'}); assert st==201,(st,org)
            st,p1,_=request(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'prod','displayName':'Prod'}); assert st==201,(st,p1)
            st,p2,_=request(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'other','displayName':'Other'}); assert st==201,(st,p2)
            st,sa,_=request(base+'/api/v1/service-accounts','POST',{'organizationId':org['id'],'projectId':p1['id'],'name':'automation','displayName':'Automation','productRole':'platform-operator'}); assert st==201,(st,sa)
            expires=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=2)).isoformat().replace('+00:00','Z')
            issue_headers={'Idempotency-Key':'service-token-issue-1'}
            st,issued,h=request(base+f"/api/v1/service-accounts/{sa['id']}/tokens",'POST',{'expiresAt':expires,'permissions':['operate']},issue_headers); assert st==201,(st,issued); assert h.get('Cache-Control')=='no-store'
            st,replayed_issue,_=request(base+f"/api/v1/service-accounts/{sa['id']}/tokens",'POST',{'expiresAt':expires,'permissions':['operate']},issue_headers); assert st==409,(st,replayed_issue); assert replayed_issue.get('error',{}).get('code')=='TOKEN_ISSUANCE_ALREADY_COMMITTED',replayed_issue
            raw1=issued['value']; token1=issued['token']; assert raw1.startswith('pft.') and not token1.get('tokenDigest')
            auth={'Authorization':'Bearer '+raw1}
            st,projects,_=request(base+'/api/v1/projects',headers=auth); assert st==200 and [x['id'] for x in projects]==[p1['id']],(st,projects)
            op={'projectId':p1['id'],'kind':'smoke.token','targetRef':'resource/a','desiredRevision':'sha256:'+'a'*64,'risk':'low'}
            st,created,_=request(base+'/api/v1/operations','POST',op,{**auth,'Idempotency-Key':'token-smoke-1'}); assert st==201,(st,created)
            op2=dict(op); op2['projectId']=p2['id']; op2['targetRef']='resource/b'
            st,blocked,_=request(base+'/api/v1/operations','POST',op2,{**auth,'Idempotency-Key':'token-smoke-2'}); assert st==403,(st,blocked)
            rotate_headers={'If-Match':'1','X-Confirm-Rotate':'rotate-api-token','Idempotency-Key':'service-token-rotate-1'}
            st,rotated,h=request(base+f"/api/v1/service-accounts/{sa['id']}/tokens/{token1['id']}/rotate",'POST',{},rotate_headers); assert st==201,(st,rotated); assert h.get('Cache-Control')=='no-store'
            st,replayed_rotate,_=request(base+f"/api/v1/service-accounts/{sa['id']}/tokens/{token1['id']}/rotate",'POST',{},rotate_headers); assert st==409,(st,replayed_rotate); assert replayed_rotate.get('error',{}).get('code')=='TOKEN_ROTATION_ALREADY_COMMITTED',replayed_rotate
            st,tokens,_=request(base+f"/api/v1/service-accounts/{sa['id']}/tokens"); assert st==200,(st,tokens); assert len(tokens)==2,tokens
            raw2=rotated['value']; assert raw2 and raw2!=raw1
            st,_,_=request(base+'/api/v1/projects',headers={'Authorization':'Bearer '+raw1}); assert st==401,st
            st,_,_=request(base+'/api/v1/projects',headers={'Authorization':'Bearer '+raw2}); assert st==200,st
            st,_,_=request(base+f"/api/v1/service-accounts/{sa['id']}/revoke",'POST',None,{'If-Match':'1','X-Confirm-Revoke':'revoke-service-account'}); assert st==200,st
            st,_,_=request(base+'/api/v1/projects',headers={'Authorization':'Bearer '+raw2}); assert st==401,st
        finally:
            logs=stop(proc)
        persisted=state.read_text() if state.exists() else ''
        for secret in (raw1,raw2):
            if secret:
                assert secret not in persisted, 'raw API token persisted in state'
                assert secret not in logs, 'raw API token leaked in logs'
        print('SERVICE_ACCOUNT_API_TOKEN_SMOKE_PASS', sa['id'], token1['id'])
    return 0
if __name__=='__main__': raise SystemExit(main())
