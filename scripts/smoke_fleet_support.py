#!/usr/bin/env python3
from __future__ import annotations
import datetime as dt, json, os, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]

def req(url, method='GET', body=None, headers=None, raw=False):
    data=None if body is None else json.dumps(body).encode(); h=dict(headers or {})
    if data is not None: h['Content-Type']='application/json'
    r=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(r,timeout=5) as x:
            b=x.read(); return x.status,(b if raw else json.loads(b or b'null')),dict(x.headers)
    except urllib.error.HTTPError as e:
        b=e.read()
        if raw:return e.code,b,dict(e.headers)
        try:v=json.loads(b or b'null')
        except Exception:v={'raw':b.decode(errors='replace')}
        return e.code,v,dict(e.headers)

def start(binary,state):
    port=free_port(); env=os.environ.copy(); env['PLATFORM_FACTORY_DEVELOPMENT_MODE']='true'; env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}'; env['PLATFORM_FACTORY_STATE_FILE']=str(state); env['PLATFORM_FACTORY_AGENT_MTLS_REQUIRED']='false'; env['PLATFORM_FACTORY_PUBLIC_URL']='https://platform.example.test'; env['PLATFORM_FACTORY_FLEET_AGENT_IMAGE']='registry.local/platform-agent@sha256:'+'a'*64; env['PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE']='registry.local/platform-probe@sha256:'+'b'*64
    p=subprocess.Popen([str(binary)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True); base=f'http://127.0.0.1:{port}'
    for _ in range(100):
        try:
            if req(base+'/readyz')[0]==200:return p,base
        except Exception:pass
        time.sleep(.1)
    p.terminate(); raise RuntimeError('api not ready')

def main():
    if len(sys.argv)!=3: raise SystemExit('usage: smoke_fleet_support.py platform-api platformctl')
    api_bin=Path(sys.argv[1]).resolve(); ctl=Path(sys.argv[2]).resolve()
    with tempfile.TemporaryDirectory() as td:
        td=Path(td); state=td/'state.json'; p,base=start(api_bin,state)
        enrollment=agent_token=''
        try:
            st,ver,_=req(base+'/api/v1/version'); assert st==200,(st,ver); version=ver['version']
            st,org,_=req(base+'/api/v1/organizations','POST',{'name':'support-smoke','displayName':'Support Smoke'}); assert st==201,(st,org)
            st,project,_=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'prod','displayName':'Production'}); assert st==201,(st,project)
            st,created,_=req(base+'/api/v1/cluster-imports','POST',{'projectId':project['id'],'name':'edge-1','displayName':'Edge 1'}); assert st==201,(st,created)
            enrollment=created['enrollmentToken']; imp=created['import']
            st,approved,_=req(base+f"/api/v1/cluster-imports/{imp['id']}/approve",'POST',{}, {'If-Match':'1'}); assert st==200,(st,approved)
            st,claimed,_=req(base+f"/agent/v1/cluster-imports/{imp['id']}/claim",'POST',{'token':enrollment,'externalUid':'support-smoke-cluster','agentVersion':version}); assert st==200,(st,claimed)
            cluster=claimed['cluster']; agent_token=claimed['agentToken']
            now=dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00','Z')
            inv={'observedAt':now,'externalUid':'support-smoke-cluster','distribution':'rke2','kubernetesVersion':'v1.34.9+rke2r1','nodes':[{'name':'node-1','uid':'node-1','roles':['control-plane'],'os':'Ubuntu 24.04','architecture':'amd64','kubeletVersion':'v1.34.9','ready':True}], 'storageClasses':[{'name':'replicated','provisioner':'openebs.io/local','reclaimPolicy':'Delete','volumeBindingMode':'WaitForFirstConsumer','allowVolumeExpansion':True,'default':True}], 'capacity':{'cpuCapacityMilli':4000,'cpuAllocatableMilli':3500,'memoryCapacityBytes':8589934592,'memoryAllocatableBytes':7516192768,'podsCapacity':110,'podsAllocatable':100}, 'networking':{'cni':'cilium','ingressControllers':['rke2-ingress-nginx'],'gatewayApi':True}, 'certificates':[{'name':'kubernetes-api','subject':'CN=kubernetes','issuer':'CN=kubernetes-ca','serialNumber':'1','fingerprint':'sha256:'+'a'*64,'notBefore':now,'notAfter':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=180)).isoformat().replace('+00:00','Z')}], 'addOns':[{'name':'cilium','namespace':'kube-system','version':'1.18','healthy':True}], 'capabilities':['read-only-inventory','storage-inventory','capacity-inventory','certificate-inventory','target-enrollment-principal-isolated']}
            st,initial_inventory,_=req(base+f"/agent/v1/clusters/{cluster['id']}/inventory",'POST',inv,{'Authorization':'Bearer '+agent_token}); assert st==200,(st,initial_inventory)
            basis_a=initial_inventory['cluster']['mutationRbacBasisDigest']; assert basis_a.startswith('sha256:'),initial_inventory
            activation_headers={'X-Actor-ID':'support-operator','X-Actor-Role':'platform-admin'}
            st,not_issued,_=req(base+f"/api/v1/clusters/{cluster['id']}/mutation-rbac-manifest",headers=activation_headers); assert st==409 and not_issued.get('error',{}).get('code')=='TARGET_MUTATION_ACTIVATION_NOT_ISSUED',(st,not_issued)
            st,activation_a,_=req(base+f"/api/v1/clusters/{cluster['id']}/mutation-rbac-manifest",'POST',{},headers=activation_headers); assert st==200,(st,activation_a)
            assert activation_a['activationIssuedForDigest']==basis_a and basis_a in activation_a['manifest'],activation_a
            st,retrieved_a,_=req(base+f"/api/v1/clusters/{cluster['id']}/mutation-rbac-manifest",headers=activation_headers); assert st==200 and retrieved_a['activationIssuedForDigest']==basis_a,(st,retrieved_a)
            active_inv=json.loads(json.dumps(inv)); active_inv['observedAt']=dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00','Z'); active_inv['capabilities']=list(inv['capabilities'])+['target-mutation-rbac-active','controlled-baseline-deployment']
            st,active_inventory,_=req(base+f"/agent/v1/clusters/{cluster['id']}/inventory",'POST',active_inv,{'Authorization':'Bearer '+agent_token}); assert st==200,(st,active_inventory)
            assert 'target-mutation-rbac-active' in active_inventory['cluster']['capabilities'] and active_inventory['cluster']['mutationRbacIssuedForDigest']==basis_a,active_inventory
            # Ordinary telemetry/health churn must not invalidate the stable RBAC authority basis.
            telemetry_inv=json.loads(json.dumps(active_inv)); telemetry_inv['observedAt']=dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00','Z'); telemetry_inv['nodes'][0]['ready']=False; telemetry_inv['capacity']['cpuAllocatableMilli']=3000; telemetry_inv['capacity']['podsAllocatable']=95; telemetry_inv['certificates'][0]['notAfter']=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=90)).isoformat().replace('+00:00','Z'); telemetry_inv['addOns'][0]['healthy']=False
            st,telemetry,_=req(base+f"/agent/v1/clusters/{cluster['id']}/inventory",'POST',telemetry_inv,{'Authorization':'Bearer '+agent_token}); assert st==200,(st,telemetry)
            assert telemetry['cluster']['mutationRbacBasisDigest']==basis_a and telemetry['cluster']['mutationRbacIssuedForDigest']==basis_a and 'target-mutation-rbac-active' in telemetry['cluster']['capabilities'],telemetry
            drift_inv=json.loads(json.dumps(telemetry_inv)); drift_inv['observedAt']=dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00','Z'); drift_inv['kubernetesVersion']='v1.34.10+rke2r1'
            st,drifted,_=req(base+f"/agent/v1/clusters/{cluster['id']}/inventory",'POST',drift_inv,{'Authorization':'Bearer '+agent_token}); assert st==200,(st,drifted)
            basis_b=drifted['cluster']['mutationRbacBasisDigest']; assert basis_b!=basis_a and drifted['cluster'].get('mutationRbacIssuedForDigest','')=='' and 'target-mutation-rbac-active' not in drifted['cluster']['capabilities'],drifted
            st,stale_get,_=req(base+f"/api/v1/clusters/{cluster['id']}/mutation-rbac-manifest",headers=activation_headers); assert st==409 and stale_get.get('error',{}).get('code')=='TARGET_MUTATION_ACTIVATION_NOT_ISSUED',(st,stale_get)
            st,activation_b,_=req(base+f"/api/v1/clusters/{cluster['id']}/mutation-rbac-manifest",'POST',{},headers=activation_headers); assert st==200,(st,activation_b)
            assert activation_b['activationIssuedForDigest']==basis_b and basis_b in activation_b['manifest'] and activation_b['activationIssuedForDigest']!=basis_a,activation_b
            st,health,_=req(base+f"/api/v1/fleet/health?projectId={project['id']}"); assert st==200,(st,health); assert health['summary']['total']==1; row=health['clusters'][0]; assert row['storageClassCount']==1 and row['capacity']['cpuAllocatableMilli']==3000 and row['kubernetesSupport']['status'] in ('SUPPORTED','MAINTENANCE','EOL_SOON')
            st,timeline,_=req(base+f"/api/v1/clusters/{cluster['id']}/timeline"); assert st==200 and timeline,(st,timeline)
            st,bundle,h=req(base+'/api/v1/support-bundles','POST',{'profile':'cluster-diagnostics','clusterId':cluster['id']},raw=True); assert st==200,(st,bundle[:200]); assert h.get('Content-Type','').startswith('application/zip')
            assert enrollment.encode() not in bundle and agent_token.encode() not in bundle, 'credential leaked into support bundle'
            bundle_path=td/'support.zip'; bundle_path.write_bytes(bundle)
            out=subprocess.check_output([str(ctl),'support-bundle','verify','-f',str(bundle_path)],text=True); parsed=json.loads(out); assert parsed['valid'] is True and parsed['files']>=3,parsed
            tampered=bytearray(bundle); tampered[len(tampered)//2]^=1; bad=td/'tampered.zip'; bad.write_bytes(tampered)
            cp=subprocess.run([str(ctl),'support-bundle','verify','-f',str(bad)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True); assert cp.returncode!=0,'tampered support bundle accepted'
            st,detail,_=req(base+f"/api/v1/clusters/{cluster['id']}"); assert st==200,(st,detail)
            rev=detail['cluster']['revision']; first_principal=imp['agentServiceAccount']
            st,revoked,_=req(base+f"/api/v1/clusters/{cluster['id']}/revoke",'POST',{}, {'If-Match':str(rev),'X-Actor-ID':'support-admin','X-Actor-Role':'platform-admin','X-Confirm-Revoke':'revoke-cluster-agent'}); assert st==200,(st,revoked)
            assert revoked['hubAgentCredentialRevoked'] is True and revoked['targetRBACRevocationStatus']=='APPLY_REQUIRED',revoked
            fence_digest=revoked['targetRBACRevocationFenceDigest']; assert fence_digest.startswith('sha256:'),revoked
            fence=revoked['targetRBACRevocationManifest']
            assert fence.count('subjects: []')==7,fence
            for binding in ('4so-platform-agent-credential','4so-platform-agent-readonly','4so-platform-provider-manager','4so-platform-baseline-manager','4so-platform-node-maintenance-job-manager','4so-platform-agent-maintenance-manager','4so-platform-agent-tenant-manager'):
                assert f'name: {binding}' in fence,fence
            assert '4so-provider-system' in fence and '4so-platform-baseline' in fence,fence
            st,retrieved,_=req(base+f"/api/v1/clusters/{cluster['id']}/revocation-rbac-manifest",headers={'X-Actor-ID':'support-admin','X-Actor-Role':'platform-admin'}); assert st==200,(st,retrieved)
            assert retrieved['targetRBACRevocationManifest']==fence and retrieved['targetRBACRevocationFenceDigest']==fence_digest,retrieved
            st,old_heartbeat,_=req(base+f"/agent/v1/clusters/{cluster['id']}/heartbeat",'POST',{'agentVersion':version,'externalUid':'support-smoke-cluster'},{'Authorization':'Bearer '+agent_token}); assert st!=200,(st,old_heartbeat)
            st,recreated,_=req(base+'/api/v1/cluster-imports','POST',{'projectId':project['id'],'name':'edge-1','displayName':'Edge 1 re-enrolled'}); assert st==201,(st,recreated)
            replacement_enrollment=recreated['enrollmentToken']; replacement=recreated['import']; assert replacement['agentServiceAccount']!=first_principal,(replacement,first_principal)
            st,approved2,_=req(base+f"/api/v1/cluster-imports/{replacement['id']}/approve",'POST',{}, {'If-Match':'1'}); assert st==200,(st,approved2)
            st,blocked_claim,_=req(base+f"/agent/v1/cluster-imports/{replacement['id']}/claim",'POST',{'token':replacement_enrollment,'externalUid':'support-smoke-cluster','agentVersion':version}); assert st==422 and blocked_claim.get('error',{}).get('code')=='PREREQUISITE_NOT_SATISFIED',(st,blocked_claim)
            revoked_revision=revoked['cluster']['revision']
            st,ack,_=req(base+f"/api/v1/clusters/{cluster['id']}/revocation-rbac-acknowledgement",'POST',{'fenceDigest':fence_digest},{'If-Match':str(revoked_revision),'X-Actor-ID':'support-admin','X-Actor-Role':'platform-admin'}); assert st==200,(st,ack)
            assert ack['targetRBACRevocationStatus']=='ACKNOWLEDGED' and ack['targetRBACRevocationRequired'] is False and ack['targetRBACRevocationFenceDigest']==fence_digest and ack['acknowledgementIsPhysicalProof'] is False,ack
            st,claimed2,_=req(base+f"/agent/v1/cluster-imports/{replacement['id']}/claim",'POST',{'token':replacement_enrollment,'externalUid':'support-smoke-cluster','agentVersion':version}); assert st==200,(st,claimed2)
            assert claimed2['cluster']['id']!=cluster['id'] and claimed2['cluster']['externalUid']==cluster['externalUid'],claimed2
            print('FLEET_SUPPORT_BUNDLE_SMOKE_PASS',cluster['id'],parsed['bundleDigest'],'REENROLL',claimed2['cluster']['id'])
        finally:
            p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
            logs=p.stdout.read() if p.stdout else ''
            for secret in (enrollment,agent_token):
                if secret: assert secret not in logs,'agent credential leaked in logs'
    return 0
if __name__=='__main__': raise SystemExit(main())
