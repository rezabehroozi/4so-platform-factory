#!/usr/bin/env python3
from __future__ import annotations
import base64, json, os, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()
from smoke_plan_safety import req, free_port, stop

class AuthState:
    def __init__(self): self.password='secret-a'; self.lock=threading.Lock()

def start_git(state):
    port=free_port()
    class H(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def sendj(self,code,obj):
            raw=json.dumps(obj).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def authorized(self):
            raw=self.headers.get('Authorization','')
            if not raw.startswith('Basic '): return False
            try:user,password=base64.b64decode(raw[6:]).decode().split(':',1)
            except Exception:return False
            with state.lock:return user=='platform-admin' and password==state.password
        def do_GET(self):
            if self.path=='/api/v1/version':return self.sendj(200,{'version':'15.0.5'})
            if not self.authorized():return self.sendj(401,{'message':'unauthorized'})
            if self.path=='/api/v1/orgs/platform':return self.sendj(200,{'username':'platform'})
            if self.path=='/api/v1/repos/platform/desired-state':return self.sendj(200,{'name':'desired-state','html_url':'https://git.local/platform/desired-state','clone_url':'https://git.local/platform/desired-state.git','owner':{'login':'platform'}})
            return self.sendj(404,{'message':'not found'})
    srv=ThreadingHTTPServer(('127.0.0.1',port),H);threading.Thread(target=srv.serve_forever,daemon=True).start();return srv,f'http://127.0.0.1:{port}'

def start_api(binary,state_file,git_url):
    port=free_port();env=os.environ.copy();env.update({
      'PLATFORM_FACTORY_LISTEN':f'127.0.0.1:{port}','PLATFORM_FACTORY_STATE_FILE':str(state_file),
      'PLATFORM_FACTORY_AGENT_MTLS_REQUIRED':'false','PLATFORM_FACTORY_INTERNAL_GIT_URL':git_url,
      'PLATFORM_FACTORY_INTERNAL_GIT_USERNAME':'platform-admin','PLATFORM_FACTORY_INTERNAL_GIT_PASSWORD':'secret-a',
      'PF_GIT_SECRET_B':'secret-b','PLATFORM_FACTORY_INTERNAL_GIT_BOOTSTRAP':'true'})
    p=subprocess.Popen([str(binary)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);base=f'http://127.0.0.1:{port}'
    for _ in range(100):
        try:
            if req(base+'/readyz')[0]==200:return p,base
        except Exception:pass
        time.sleep(.1)
    out='';
    try:out=p.stdout.read()
    except Exception:pass
    stop(p);raise RuntimeError('api not ready '+out[-1000:])

def main():
    if len(sys.argv)!=2:raise SystemExit('usage: smoke_git_credential_reference.py platform-api')
    binary=Path(sys.argv[1]).resolve();auth=AuthState();srv,git_url=start_git(auth)
    try:
      with tempfile.TemporaryDirectory() as td:
        state=Path(td)/'state.json';p,base=start_api(binary,state,git_url)
        try:
          st,version,_=req(base+'/api/v1/version');assert st==200 and version['version']==EXPECTED_VERSION,(st,version)
          st,authority,_=req(base+'/api/v1/git-authority');assert st==200,(st,authority);assert authority['method']=='GIT_PROVIDER_CREDENTIAL_REFERENCE_V1' and authority['secretMaterialPersisted'] is False
          provider=authority['providers'][0];old=authority['credentials'][0];assert provider['credentialId']==old['id'] and old['secretRef']=='env://PLATFORM_FACTORY_INTERNAL_GIT_PASSWORD'
          st,result,_=req(base+'/api/v1/system-services/git/repositories','POST',{'organization':'platform','name':'desired-state','private':True});assert st==200,(st,result)
          with auth.lock:auth.password='secret-b'
          st,rotated,_=req(base+f"/api/v1/git-credentials/{old['id']}/rotate",'POST',{'secretRef':'env://PF_GIT_SECRET_B'},{'If-Match':f'"{old["revision"]}"'});assert st==200,(st,rotated);new=rotated['replacement'];assert new['rotatedFromId']==old['id']
          st,result,_=req(base+'/api/v1/system-services/git/repositories','POST',{'organization':'platform','name':'desired-state','private':True});assert st==200,(st,result)
          st,authority,_=req(base+'/api/v1/git-authority');assert st==200;assert authority['providers'][0]['credentialId']==new['id']
        finally:stop(p)
        raw=state.read_text();assert 'secret-a' not in raw and 'secret-b' not in raw, 'raw Git secret leaked into durable state'
        p,base=start_api(binary,state,git_url)
        try:
          st,result,_=req(base+'/api/v1/system-services/git/repositories','POST',{'organization':'platform','name':'desired-state','private':True});assert st==200,(st,result)
          st,authority,_=req(base+'/api/v1/git-authority');assert st==200;active=[x for x in authority['credentials'] if x['state']=='ACTIVE'];assert len(active)==1 and active[0]['secretRef']=='env://PF_GIT_SECRET_B'
          current=active[0];st,revoked,_=req(base+f"/api/v1/git-credentials/{current['id']}/revoke",'POST',{}, {'If-Match':f'"{current["revision"]}"'});assert st==200 and revoked['state']=='REVOKED',(st,revoked)
          st,failed,_=req(base+'/api/v1/system-services/git/repositories','POST',{'organization':'platform','name':'desired-state','private':True});assert st==502,(st,failed)
          st,audit,_=req(base+'/api/v1/audit-events?limit=100');assert st==200,(st,audit);dump=json.dumps(audit);assert 'secret-a' not in dump and 'secret-b' not in dump
          print('GIT_PROVIDER_CREDENTIAL_REFERENCE_SMOKE_PASS',provider['id'],old['id'],new['id'],'ROTATED_RESTARTED_REVOKED')
        finally:stop(p)
    finally:srv.shutdown();srv.server_close()
    return 0
if __name__=='__main__':raise SystemExit(main())
