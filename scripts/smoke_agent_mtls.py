#!/usr/bin/env python3
from __future__ import annotations
import base64, json, os, socket, ssl, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]


def request(url, method='GET', body=None, headers=None, ca=None, cert=None, key=None):
    data=None if body is None else json.dumps(body).encode()
    h=dict(headers or {})
    if data is not None: h['Content-Type']='application/json'
    ctx=None
    if url.startswith('https://'):
        ctx=ssl.create_default_context(cafile=str(ca))
        ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        if cert:
            ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    req=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(req,timeout=5,context=ctx) as r:
            raw=r.read(); return r.status,json.loads(raw or b'null'),dict(r.headers)
    except urllib.error.HTTPError as e:
        raw=e.read()
        try: parsed=json.loads(raw or b'null')
        except Exception: parsed={'raw':raw.decode(errors='replace')}
        return e.code,parsed,dict(e.headers)


def wait_ready(url, ca=None):
    for _ in range(150):
        try:
            status,_,_=request(url+'/readyz',ca=ca)
            if status==200: return
        except Exception: pass
        time.sleep(.1)
    raise RuntimeError(f'endpoint not ready: {url}')


def csr(tmp: Path, name: str):
    key=tmp/(name+'.key'); req=tmp/(name+'.csr')
    subprocess.run(['openssl','ecparam','-name','prime256v1','-genkey','-noout','-out',str(key)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['openssl','req','-new','-key',str(key),'-subj','/CN='+name,'-out',str(req)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    return key,req


def main():
    if len(sys.argv)!=3:
        raise SystemExit('usage: smoke_agent_mtls.py /path/to/platform-api /path/to/platformctl')
    api=Path(sys.argv[1]).resolve(); ctl=Path(sys.argv[2]).resolve(); root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as td:
        td=Path(td); ca=td/'agent-ca.crt'; cakey=td/'agent-ca.key'; servercert=td/'agent-server.crt'; serverkey=td/'agent-server.key'
        subprocess.run([str(ctl),'agent-pki','init','--server-name','localhost','--out-cert',str(ca),'--out-key',str(cakey),'--out-server-cert',str(servercert),'--out-server-key',str(serverkey),'--confirmation','INIT'],cwd=root,check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        state=td/'state'/'control-plane.json'; http_port=free_port(); agent_port=free_port()
        env=os.environ.copy(); env['PLATFORM_FACTORY_DEVELOPMENT_MODE']='true'; env.update({
          'PLATFORM_FACTORY_LISTEN':f'127.0.0.1:{http_port}',
          'PLATFORM_FACTORY_STATE_FILE':str(state),
          'PLATFORM_FACTORY_AGENT_LISTEN':f'127.0.0.1:{agent_port}',
          'PLATFORM_FACTORY_AGENT_MTLS_REQUIRED':'true',
          'PLATFORM_FACTORY_AGENT_CA_CERT_FILE':str(ca),
          'PLATFORM_FACTORY_AGENT_CA_KEY_FILE':str(cakey),
          'PLATFORM_FACTORY_AGENT_TLS_CERT_FILE':str(servercert),
          'PLATFORM_FACTORY_AGENT_TLS_KEY_FILE':str(serverkey),
          'PLATFORM_FACTORY_AGENT_PUBLIC_URL':f'https://localhost:{agent_port}',
          'PLATFORM_FACTORY_PUBLIC_CA_PEM_B64':base64.b64encode(ca.read_bytes()).decode(),
          'PLATFORM_FACTORY_FLEET_AGENT_IMAGE':'registry.local/platform-agent@sha256:'+'a'*64,
          'PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE':'registry.local/platform-probe@sha256:'+'b'*64,
        })
        proc=subprocess.Popen([str(api)],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        http_base=f'http://127.0.0.1:{http_port}'; agent_base=f'https://localhost:{agent_port}'
        enrollment=agent_token=''
        try:
            wait_ready(http_base); wait_ready(agent_base,ca)
            st,org,_=request(http_base+'/api/v1/organizations','POST',{'name':'mtls-smoke','displayName':'mTLS Smoke'}); assert st==201,(st,org)
            st,project,_=request(http_base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'fleet','displayName':'Fleet'}); assert st==201,(st,project)
            st,created,_=request(http_base+'/api/v1/cluster-imports','POST',{'projectId':project['id'],'name':'mtls-cluster','displayName':'mTLS Cluster','expiresInMinutes':30}); assert st==201,(st,created)
            imp=created['import']; enrollment=created['enrollmentToken']
            st,approved,_=request(http_base+f"/api/v1/cluster-imports/{imp['id']}/approve",'POST',{}, {'If-Match':f'"{imp["revision"]}"'}); assert st==200,(st,approved)
            st,claimed,_=request(agent_base+f"/agent/v1/cluster-imports/{imp['id']}/claim",'POST',{'token':enrollment,'externalUid':'mtls-smoke-cluster-uid','agentVersion':EXPECTED_VERSION},ca=ca); assert st==200,(st,claimed)
            cluster=claimed['cluster']; agent_token=claimed['agentToken']
            key1,csr1=csr(td,'agent-one')
            st,issued,h=request(agent_base+f"/agent/v1/clusters/{cluster['id']}/certificates/issue",'POST',{'csrPem':csr1.read_text()}, {'Authorization':'Bearer '+agent_token},ca=ca); assert st==201,(st,issued); assert h.get('Cache-Control')=='no-store'
            cert1=td/'agent-one.crt'; cert1.write_text(issued['certificatePem'])
            # Bearer is bootstrap-only once mTLS is required.
            st,_,_=request(agent_base+f"/agent/v1/clusters/{cluster['id']}/heartbeat",'POST',{'agentVersion':EXPECTED_VERSION},{'Authorization':'Bearer '+agent_token},ca=ca); assert st==401,st
            st,_,_=request(agent_base+f"/agent/v1/clusters/{cluster['id']}/heartbeat",'POST',{'agentVersion':EXPECTED_VERSION},ca=ca,cert=cert1,key=key1); assert st==200,st
            st,current,_=request(agent_base+f"/agent/v1/clusters/{cluster['id']}/certificates/current",ca=ca,cert=cert1,key=key1); assert st==200 and current['state']=='ACTIVE',(st,current)
            key2,csr2=csr(td,'agent-two')
            st,rotated,_=request(agent_base+f"/agent/v1/clusters/{cluster['id']}/certificates/rotate",'POST',{'csrPem':csr2.read_text()},ca=ca,cert=cert1,key=key1); assert st==200,(st,rotated)
            cert2=td/'agent-two.crt'; cert2.write_text(rotated['certificatePem'])
            st,_,_=request(agent_base+f"/agent/v1/clusters/{cluster['id']}/heartbeat",'POST',{'agentVersion':EXPECTED_VERSION},ca=ca,cert=cert1,key=key1); assert st==401,st
            st,_,_=request(agent_base+f"/agent/v1/clusters/{cluster['id']}/heartbeat",'POST',{'agentVersion':EXPECTED_VERSION},ca=ca,cert=cert2,key=key2); assert st==200,st
            certmeta=rotated['certificate']
            st,revoked,_=request(http_base+f"/api/v1/clusters/{cluster['id']}/agent-certificates/{certmeta['id']}/revoke",'POST',{}, {'If-Match':f'"{certmeta["revision"]}"','X-Confirm-Revoke':'revoke-agent-certificate'}); assert st==200,(st,revoked)
            st,_,_=request(agent_base+f"/agent/v1/clusters/{cluster['id']}/heartbeat",'POST',{'agentVersion':EXPECTED_VERSION},ca=ca,cert=cert2,key=key2); assert st==401,st
            st,record,_=request(http_base+f"/api/v1/clusters/{cluster['id']}"); assert st==200 and len(record.get('agentCertificates',[]))==2,(st,record)
        finally:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
            logs=proc.stdout.read() if proc.stdout else ''
        persisted=state.read_text() if state.exists() else ''
        for secret in (enrollment,agent_token,cakey.read_text(),key1.read_text() if 'key1' in locals() else '',key2.read_text() if 'key2' in locals() else ''):
            if secret:
                assert secret not in logs,'agent secret leaked in API logs'
                assert secret not in persisted,'raw agent secret/private key persisted in control-plane state'
        print('AGENT_MTLS_SMOKE_PASS',cluster['id'],issued['certificate']['id'],rotated['certificate']['id'])
    return 0

if __name__=='__main__': raise SystemExit(main())
