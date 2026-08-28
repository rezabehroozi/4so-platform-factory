#!/usr/bin/env python3
from __future__ import annotations
import json,os,socket,subprocess,sys,tempfile,time,urllib.request
from pathlib import Path

def free_port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def request(url,method='GET',body=None,headers=None):
 data=None if body is None else json.dumps(body).encode()
 h=dict(headers or {})
 if data is not None:h['Content-Type']='application/json'
 req=urllib.request.Request(url,data=data,method=method,headers=h)
 with urllib.request.urlopen(req,timeout=5) as r:return r.status,json.loads(r.read()),dict(r.headers)
def start(binary,root,state_file):
 port=free_port();env=os.environ.copy();env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}';env['PLATFORM_FACTORY_STATE_FILE']=str(state_file)
 proc=subprocess.Popen([str(binary)],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 base=f'http://127.0.0.1:{port}'
 for _ in range(80):
  try:
   status,ready,_=request(base+'/readyz')
   if status==200:return proc,base,ready
  except Exception:time.sleep(.1)
 proc.terminate();raise RuntimeError('API did not become ready')
def stop(proc):
 proc.terminate()
 try:proc.wait(timeout=5)
 except subprocess.TimeoutExpired:proc.kill();proc.wait()
def main():
 if len(sys.argv)!=2:raise SystemExit('usage: smoke_api.py /path/to/platform-api')
 binary=Path(sys.argv[1]).resolve();root=Path(__file__).resolve().parents[1]
 with tempfile.TemporaryDirectory() as td:
  state=Path(td)/'state'/'control-plane.json';proc,base,ready=start(binary,root,state)
  try:
   assert ready['catalogComponents']==19 and ready['catalogDigest'].startswith('sha256:')
   status,summary,_=request(base+'/api/v1/catalog/summary');assert status==200 and summary['componentCount']==19
   blueprint=json.loads((root/'blueprints/enterprise-private-cloud.json').read_text())
   status,validation,_=request(base+'/api/v1/blueprints/validate','POST',blueprint);assert status==200 and validation['valid'] is True
   status,plan,_=request(base+'/api/v1/plans','POST',blueprint);assert status==201 and plan['executable'] is False and len(plan['steps'])==18 and len(plan['blockers'])>=75
   status,profiles,_=request(base+'/api/v1/installations/profiles');assert status==200 and len(profiles)==3 and any(p.get('default') for p in profiles)
   install_request={'profileId':'production-standard-ha','connectivity':'connected','infrastructure':{'provider':'existing-hosts','existingCluster':False,'nodeAddresses':['10.0.0.1','10.0.0.2','10.0.0.3'],'credentialRef':'secret://infra/admin'},'network':{'publicEndpoint':'https://platform.example.test','dnsZone':'example.test','tlsMode':'managed-acme'},'services':{'git':{},'registry':{},'database':{},'objectStorage':{'mode':'external','provider':'s3-compatible','url':'https://s3.example.test','credentialRef':'secret://storage/backup'},'identity':{'adminEmail':'admin@example.test'}},'acceptRisk':True}
   status,install_plan,_=request(base+'/api/v1/installations/plans','POST',install_request);assert status==201 and install_plan['executable'] is False and install_plan['authorityGate']=='blocked-pending-postgresql-runtime' and len(install_plan['steps'])==11
   actor={'X-Actor-ID':'smoke-user'}
   status,org,h=request(base+'/api/v1/organizations','POST',{'name':'smoke-org','displayName':'Smoke Organization'},actor);assert status==201 and h.get('Etag')=='"1"'
   status,project,_=request(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'platform','displayName':'Platform'},actor);assert status==201
   op_body={'projectId':project['id'],'kind':'blueprint.plan','targetRef':'cluster/smoke','desiredRevision':plan['blueprintDigest'],'risk':'high'}
   op_headers={'X-Actor-ID':'smoke-user','Idempotency-Key':'smoke-operation-1'}
   status,op,_=request(base+'/api/v1/operations','POST',op_body,op_headers);assert status==201
   status,replay,h=request(base+'/api/v1/operations','POST',op_body,op_headers);assert status==200 and replay['id']==op['id'] and h.get('Idempotent-Replay')=='true'
   status,cp,_=request(base+'/api/v1/control-plane/summary');assert status==200 and cp['organizations']==1 and cp['operations']==1 and cp['clusterMutationEnabled'] is True
  finally:stop(proc)
  proc,base,ready=start(binary,root,state)
  try:
   status,got,_=request(base+'/api/v1/operations/'+op['id']);assert status==200 and got['operation']['id']==op['id']
   status,audit,_=request(base+'/api/v1/audit-events?limit=100');assert status==200 and len(audit)>=3
   print('API_DURABLE_RESTART_SMOKE_PASS',ready['catalogDigest'],len(plan['steps']),len(plan['blockers']),len(install_plan['steps']),len(install_plan['blockers']),op['id'],len(audit))
  finally:stop(proc)
 return 0
if __name__=='__main__':raise SystemExit(main())
