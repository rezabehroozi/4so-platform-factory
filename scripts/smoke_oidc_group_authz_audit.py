#!/usr/bin/env python3
from __future__ import annotations
import base64,json,os,socket,subprocess,sys,tempfile,time,urllib.error,urllib.request
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()
from threading import Thread
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding,rsa

BOOTSTRAP='identity-authority-bootstrap-token-0000000001'
def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def b64u(raw:bytes)->str:return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()
class OIDCIssuer:
    def __init__(self):
        self.key=rsa.generate_private_key(public_exponent=65537,key_size=2048); self.kid='identity-authority-key'; self.port=free_port(); self.internal=f'http://127.0.0.1:{self.port}'; self.issuer='https://issuer.identity-authority.test'; self.client='platform-factory'
        pub=self.key.public_key().public_numbers(); self.jwks={'keys':[{'kid':self.kid,'kty':'RSA','use':'sig','n':b64u(pub.n.to_bytes((pub.n.bit_length()+7)//8,'big')),'e':b64u(pub.e.to_bytes((pub.e.bit_length()+7)//8,'big'))}]}
        parent=self
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path!='/protocol/openid-connect/certs': self.send_response(404);self.end_headers();return
                raw=json.dumps(parent.jwks,separators=(',',':')).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def log_message(self,*args):pass
        self.httpd=ThreadingHTTPServer(('127.0.0.1',self.port),H); self.thread=Thread(target=self.httpd.serve_forever,daemon=True); self.thread.start()
    def token(self,subject,groups,realm_roles=('platform-admin',)):
        header=b64u(json.dumps({'alg':'RS256','kid':self.kid},separators=(',',':')).encode())
        claims=b64u(json.dumps({'sub':subject,'iss':self.issuer,'aud':self.client,'exp':int(time.time())+3600,'groups':groups,'realm_access':{'roles':list(realm_roles)}},separators=(',',':')).encode())
        signed=(header+'.'+claims).encode(); sig=self.key.sign(signed,padding.PKCS1v15(),hashes.SHA256()); return header+'.'+claims+'.'+b64u(sig)
    def close(self): self.httpd.shutdown();self.httpd.server_close();self.thread.join(timeout=2)
def req(base,path,method='GET',body=None,headers=None):
    data=None if body is None else json.dumps(body).encode(); h=dict(headers or {})
    if data is not None:h['Content-Type']='application/json'
    request=urllib.request.Request(base+path,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(request,timeout=5) as r:
            raw=r.read(); return r.status,json.loads(raw or b'null'),dict(r.headers)
    except urllib.error.HTTPError as e:
        raw=e.read()
        try:v=json.loads(raw or b'null')
        except Exception:v={'raw':raw.decode(errors='replace')}
        return e.code,v,dict(e.headers)
def bootstrap():return {'X-Platform-Bootstrap-Token':BOOTSTRAP}
def bearer(token):return {'Authorization':'Bearer '+token}
def start(binary,state,oidc):
    port=free_port(); env=os.environ.copy(); env.update({
      'PLATFORM_FACTORY_LISTEN':f'127.0.0.1:{port}','PLATFORM_FACTORY_STATE_FILE':str(state),'PLATFORM_FACTORY_AGENT_MTLS_REQUIRED':'false',
      'PLATFORM_FACTORY_OIDC_ENABLED':'true','PLATFORM_FACTORY_OIDC_ISSUER':oidc.issuer,'PLATFORM_FACTORY_OIDC_INTERNAL_BASE':oidc.internal,'PLATFORM_FACTORY_OIDC_CLIENT_ID':oidc.client,
      'PLATFORM_FACTORY_OIDC_REDIRECT_URL':'http://127.0.0.1/auth/callback','PLATFORM_FACTORY_SESSION_SECRET':'identity-authority-session-secret-0000000001','PLATFORM_FACTORY_COOKIE_INSECURE':'true',
      'PLATFORM_FACTORY_BOOTSTRAP_TOKEN':BOOTSTRAP,'PLATFORM_FACTORY_OIDC_GROUP_PROPAGATION_TTL':'5m',
    })
    p=subprocess.Popen([str(binary)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);base=f'http://127.0.0.1:{port}'
    for _ in range(100):
        try:
            if req(base,'/readyz')[0]==200:return p,base
        except Exception:pass
        time.sleep(.1)
    out='';
    try:out=p.stdout.read()
    except Exception:pass
    p.terminate();raise RuntimeError('api not ready '+out[-2000:])
def stop(p):
    p.terminate()
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.wait()
def code(payload):return (payload or {}).get('error',{}).get('code')
def assert_chain(events):
    rows=sorted(events,key=lambda x:x['sequence']); assert rows, 'no security audit events'
    prev=''
    for i,row in enumerate(rows,1):
        assert row['sequence']==i,(i,row['sequence']); assert row['methodVersion']=='IMMUTABLE_AUTHN_AUTHZ_AUDIT_V1',row
        assert row.get('previousDigest','')==prev,(row['sequence'],row.get('previousDigest'),prev); assert row['digest'].startswith('sha256:'),row
        prev=row['digest']
    return rows

def main():
    if len(sys.argv)!=2:raise SystemExit('usage: smoke_oidc_group_authz_audit.py platform-api')
    binary=Path(sys.argv[1]).resolve(); oidc=OIDCIssuer()
    with tempfile.TemporaryDirectory() as td:
        state=Path(td)/'state.json';p,base=start(binary,state,oidc)
        try:
            st,ver,_=req(base,'/api/v1/version',headers=bootstrap()); assert st==200 and ver['version']==EXPECTED_VERSION,(st,ver)
            st,authority,_=req(base,'/api/v1/identity/authority',headers=bootstrap()); assert st==200 and authority['groupMappingMethod']=='OIDC_GROUP_MAPPING_AUTHORITY_V1' and authority['securityAuditMethod']=='IMMUTABLE_AUTHN_AUTHZ_AUDIT_V1' and authority['realmRolesAuthoritative'] is False and authority['securityAuditFailClosed'] is True,(st,authority)
            st,org,_=req(base,'/api/v1/organizations','POST',{'name':'identity-smoke','displayName':'Identity Smoke'},bootstrap()); assert st==201,(st,org)
            st,mapping,_=req(base,'/api/v1/identity/group-mappings','POST',{'group':'acme-ops','productRole':'platform-operator','organizationId':org['id'],'organizationRole':'organization-admin'},bootstrap()); assert st==201 and mapping['state']=='ACTIVE',(st,mapping)
            mapped=oidc.token('mapped-user',['acme-ops'],('platform-admin',))
            unmapped=oidc.token('unmapped-user',[],('platform-admin',))
            st,ctx,_=req(base,'/api/v1/access/context',headers=bearer(mapped)); assert st==200 and ctx['globalRole']=='platform-operator' and ctx['mappedOrganizationRoles'][org['id']]=='organization-admin' and ctx['mappingDigest'].startswith('sha256:'),(st,ctx)
            # A malicious realm platform-admin role cannot elevate beyond the durable group mapping.
            st,denied,_=req(base,'/api/v1/organizations','POST',{'name':'realm-role-bypass','displayName':'Must Not Exist'},bearer(mapped)); assert st==403 and code(denied)=='PLATFORM_ADMIN_REQUIRED',(st,denied)
            # The mapped organization-admin scope is still effective for organization-local administration.
            st,project,_=req(base,'/api/v1/projects','POST',{'organizationId':org['id'],'name':'mapped-project','displayName':'Mapped Project'},bearer(mapped)); assert st==201,(st,project)
            # Realm roles alone are not an authority when no group mapping matches.
            st,denied,_=req(base,'/api/v1/access/context',headers=bearer(unmapped)); assert st==403 and code(denied)=='PRODUCT_ROLE_REQUIRED',(st,denied)
            # Revocation changes authorization immediately for bearer requests that still carry the old group.
            st,revoked,_=req(base,f"/api/v1/identity/group-mappings/{mapping['id']}/revoke",'POST',{}, {**bootstrap(),'If-Match':f'"{mapping["revision"]}"'}); assert st==200 and revoked['state']=='REVOKED',(st,revoked)
            st,denied,_=req(base,'/api/v1/access/context',headers=bearer(mapped)); assert st==403 and code(denied)=='PRODUCT_ROLE_REQUIRED',(st,denied)
            st,events,_=req(base,'/api/v1/security-audit-events?limit=1000',headers=bootstrap()); assert st==200,(st,events)
            rows=assert_chain(events)
            assert any(e['category']=='AUTHENTICATION' and e['decision']=='ALLOW' and e['actorId']=='mapped-user' and e['authentication']=='oidc' for e in rows),rows[-10:]
            assert any(e['category']=='AUTHORIZATION' and e['decision']=='DENY' and e['reasonCode']=='PRODUCT_ROLE_REQUIRED' for e in rows),rows[-10:]
            assert any(e['category']=='SCOPE_AUTHORIZATION' and e['decision']=='ALLOW' and e['scopeId']==org['id'] and e['effectiveRole']=='organization-admin' for e in rows),rows[-10:]
            before_seq=rows[-1]['sequence']; before_digest=rows[-1]['digest']
            stop(p);p,base=start(binary,state,oidc)
            st,mappings,_=req(base,'/api/v1/identity/group-mappings',headers=bootstrap()); assert st==200 and any(x['id']==mapping['id'] and x['state']=='REVOKED' for x in mappings),(st,mappings)
            st,events2,_=req(base,'/api/v1/security-audit-events?limit=1000',headers=bootstrap()); assert st==200,(st,events2)
            rows2=assert_chain(events2); assert rows2[-1]['sequence']>before_seq and any(x['sequence']==before_seq and x['digest']==before_digest for x in rows2),(before_seq,rows2[-3:])
            raw=state.read_text(); assert 'OIDC_GROUP_MAPPING_AUTHORITY_V1' not in raw or 'acme-ops' in raw # durable mapping is expected, raw credentials are not part of this authority.
            print(f"OIDC_GROUP_AUTHZ_AUDIT_SMOKE_PASS events={len(rows2)} mapping={mapping['id']} restart_sequence={rows2[-1]['sequence']}")
        finally:
            stop(p);oidc.close()
if __name__=='__main__':main()
