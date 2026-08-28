#!/usr/bin/env python3
from __future__ import annotations
import hashlib, hmac, json, os, socket, subprocess, sys, tempfile, threading, time, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()

AUTH='Bearer notification-smoke-token'
SECRET=b'notification-smoke-hmac-secret'

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]

def req(url, method='GET', body=None, headers=None):
    data=None if body is None else json.dumps(body).encode(); h=dict(headers or {})
    if data is not None: h['Content-Type']='application/json'
    r=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(r,timeout=5) as x:
            b=x.read(); return x.status,json.loads(b or b'null'),dict(x.headers)
    except urllib.error.HTTPError as e:
        b=e.read()
        try:v=json.loads(b or b'null')
        except Exception:v={'raw':b.decode(errors='replace')}
        return e.code,v,dict(e.headers)

class WebhookState:
    def __init__(self): self.status=400; self.requests=[]; self.lock=threading.Lock()

class Handler(BaseHTTPRequestHandler):
    state: WebhookState
    def do_POST(self):
        n=int(self.headers.get('Content-Length','0')); body=self.rfile.read(n)
        expected='sha256='+hmac.new(SECRET,body,hashlib.sha256).hexdigest()
        record={'authorization':self.headers.get('Authorization'),'signature':self.headers.get('X-Platform-Signature'),'eventType':self.headers.get('X-Platform-Event-Type'),'deliveryId':self.headers.get('X-Platform-Delivery-ID'),'body':json.loads(body)}
        assert record['authorization']==AUTH,record
        assert record['signature']==expected,record
        with self.state.lock:
            self.state.requests.append(record); status=self.state.status
        payload=b'accepted' if 200 <= status < 300 else b'permanent failure'
        self.send_response(status); self.send_header('Content-Type','text/plain'); self.send_header('Content-Length',str(len(payload))); self.end_headers(); self.wfile.write(payload)
    def log_message(self,*_): pass

def start_webhook():
    state=WebhookState(); Handler.state=state
    host=socket.gethostbyname(socket.gethostname())
    server=ThreadingHTTPServer(('0.0.0.0',0),Handler); thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    return server,state,f'http://{host}:{server.server_address[1]}/notify'

def notification_secret_prefix(organization_id):
    canonical=''.join(ch if ch.isalnum() and ch.isascii() else '_' for ch in organization_id.upper())
    return 'PLATFORM_FACTORY_NOTIFICATION_SECRET_'+canonical+'_'

def start_api(binary,state_file,credential_org=None):
    port=free_port(); env=os.environ.copy()
    env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}'
    env['PLATFORM_FACTORY_STATE_FILE']=str(state_file)
    env['PLATFORM_FACTORY_AGENT_MTLS_REQUIRED']='false'
    env['PLATFORM_FACTORY_PUBLIC_URL']='https://platform.example.test'
    env['PLATFORM_FACTORY_FLEET_AGENT_IMAGE']='registry.local/platform-agent@sha256:'+'a'*64
    env['PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE']='registry.local/platform-probe@sha256:'+'b'*64
    env['PLATFORM_FACTORY_NOTIFICATION_POLL_INTERVAL']='200ms'
    env['PLATFORM_FACTORY_NOTIFICATION_HEALTH_SCAN_INTERVAL']='500ms'
    if credential_org:
        prefix=notification_secret_prefix(credential_org)
        env[prefix+'SMOKE_AUTH']=AUTH
        env[prefix+'SMOKE_HMAC']=SECRET.decode()
    p=subprocess.Popen([str(binary)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    base=f'http://127.0.0.1:{port}'
    for _ in range(100):
        try:
            if req(base+'/readyz')[0]==200:return p,base
        except Exception: pass
        time.sleep(.1)
    out=''
    try: out=p.stdout.read() if p.stdout else ''
    except Exception: pass
    p.terminate(); raise RuntimeError('api not ready: '+out[-2000:])

def stop(p):
    p.terminate()
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.wait()

def wait_for(fn, timeout=10):
    end=time.time()+timeout; last=None
    while time.time()<end:
        try:
            value=fn(); last=value
            if value:return value
        except Exception as e:last=e
        time.sleep(.15)
    raise AssertionError(f'timeout waiting for condition; last={last!r}')

def main():
    if len(sys.argv)!=2: raise SystemExit('usage: smoke_notification_routing.py platform-api')
    binary=Path(sys.argv[1]).resolve(); webhook,hook_state,endpoint=start_webhook()
    try:
      with tempfile.TemporaryDirectory() as td:
        state_file=Path(td)/'state.json'; p,base=start_api(binary,state_file)
        try:
            st,ver,_=req(base+'/api/v1/version'); assert st==200 and ver['version']==EXPECTED_VERSION,(st,ver)
            st,org,_=req(base+'/api/v1/organizations','POST',{'name':'notification-smoke','displayName':'Notification Smoke'}); assert st==201,(st,org)
        finally: stop(p)

        p,base=start_api(binary,state_file,org['id'])
        try:
            prefix=notification_secret_prefix(org['id'])
            st,project,_=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'prod','displayName':'Production'}); assert st==201,(st,project)
            st,dest,_=req(base+'/api/v1/notification-destinations','POST',{'organizationId':org['id'],'name':'smoke-webhook','kind':'WEBHOOK','endpoint':endpoint,'authorizationEnv':prefix+'SMOKE_AUTH','hmacSecretEnv':prefix+'SMOKE_HMAC','allowHttp':True,'timeoutSeconds':3}); assert st==201,(st,dest)
            st,route,_=req(base+'/api/v1/notification-routes','POST',{'organizationId':org['id'],'projectId':project['id'],'name':'fleet-health-critical','enabled':True,'eventPatterns':['fleet.health.degraded'],'minimumSeverity':'WARNING','destinationIds':[dest['id']]}); assert st==201,(st,route)
            st,created,_=req(base+'/api/v1/cluster-imports','POST',{'projectId':project['id'],'name':'edge-no-inventory','displayName':'Edge Without Inventory'}); assert st==201,(st,created)
            imp=created['import']; enrollment=created['enrollmentToken']
            st,_,_=req(base+f"/api/v1/cluster-imports/{imp['id']}/approve",'POST',{}, {'If-Match':f'"{imp["revision"]}"'}); assert st==200,st
            st,claimed,_=req(base+f"/agent/v1/cluster-imports/{imp['id']}/claim",'POST',{'token':enrollment,'externalUid':'notification-smoke-cluster','agentVersion':EXPECTED_VERSION}); assert st==200,(st,claimed)

            def dead_letter():
                st,ds,_=req(base+f"/api/v1/notification-deliveries?projectId={project['id']}&limit=20")
                if st!=200:return None
                return next((d for d in ds if d['state']=='DEAD_LETTER'),None)
            delivery=wait_for(dead_letter,10)
            st,events,_=req(base+f"/api/v1/notification-events?projectId={project['id']}&limit=20"); assert st==200 and len(events)==1,(st,events)
            event=events[0]; assert event['eventType']=='fleet.health.degraded' and event['sourceEventId'].startswith('derived:fleet-health:'),event
            st,view,_=req(base+f"/api/v1/notification-deliveries/{delivery['id']}"); assert st==200 and len(view['attempts'])==1,(st,view)
            assert view['attempts'][0]['statusCode']==400 and view['attempts'][0]['retryable'] is False,view
            with hook_state.lock:
                assert len(hook_state.requests)==1,hook_state.requests
                assert hook_state.requests[0]['eventType']=='fleet.health.degraded',hook_state.requests[0]
                hook_state.status=204
            st,requeued,_=req(base+f"/api/v1/notification-deliveries/{delivery['id']}/retry",'POST',{}, {'If-Match':f'"{delivery["revision"]}"'}); assert st==200 and requeued['state']=='PENDING',(st,requeued)
            def succeeded():
                st,v,_=req(base+f"/api/v1/notification-deliveries/{delivery['id']}")
                if st==200 and v['delivery']['state']=='SUCCEEDED' and len(v['attempts'])==2:return v
                return None
            final=wait_for(succeeded,10); assert final['attempts'][1]['statusCode']==204 and final['attempts'][1]['success'] is True,final
            delivery_id=delivery['id']; event_id=event['id']; attempts_before=len(final['attempts'])
        finally: stop(p)

        # Restart proves persisted delivery history and derived-event idempotency.
        p,base=start_api(binary,state_file,org['id'])
        try:
            time.sleep(1.2)
            st,events,_=req(base+f"/api/v1/notification-events?projectId={project['id']}&limit=20"); assert st==200 and len(events)==1 and events[0]['id']==event_id,(st,events)
            st,deliveries,_=req(base+f"/api/v1/notification-deliveries?projectId={project['id']}&limit=20"); assert st==200 and len(deliveries)==1 and deliveries[0]['id']==delivery_id and deliveries[0]['state']=='SUCCEEDED',(st,deliveries)
            st,view,_=req(base+f"/api/v1/notification-deliveries/{delivery_id}"); assert st==200 and len(view['attempts'])==attempts_before,(st,view)
            with hook_state.lock: calls=len(hook_state.requests)
            assert calls==2,calls
            print('NOTIFICATION_ACTION_ROUTING_SMOKE_PASS',event_id,delivery_id,calls,len(view['attempts']))
        finally: stop(p)
    finally:
        webhook.shutdown(); webhook.server_close()
    return 0

if __name__=='__main__': raise SystemExit(main())
