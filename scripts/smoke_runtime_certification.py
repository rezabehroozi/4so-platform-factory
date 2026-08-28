#!/usr/bin/env python3
from __future__ import annotations
import datetime as dt, json, os, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

def free_port():
    with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]

def req(url,method='GET',body=None,headers=None):
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

def start(binary:Path,root:Path,state:Path):
    port=free_port(); env=os.environ.copy()
    env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}'
    env['PLATFORM_FACTORY_STATE_FILE']=str(state)
    env['PLATFORM_FACTORY_AGENT_MTLS_REQUIRED']='false'
    env['PLATFORM_FACTORY_PUBLIC_URL']='https://platform.example.test'
    env['PLATFORM_FACTORY_FLEET_AGENT_IMAGE']='registry.local/platform-agent@sha256:'+'a'*64
    env['PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE']='registry.local/platform-probe@sha256:'+'b'*64
    p=subprocess.Popen([str(binary)],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    base=f'http://127.0.0.1:{port}'
    for _ in range(100):
        try:
            if req(base+'/readyz')[0]==200:return p,base
        except Exception: pass
        time.sleep(.1)
    p.terminate(); raise RuntimeError('api not ready')

def stop(p):
    p.terminate()
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.wait()

def iso(t):return t.isoformat().replace('+00:00','Z')

def inventory(addon='1.18', observability=False, target=False):
    now=dt.datetime.now(dt.timezone.utc)
    return {'observedAt':iso(now),'externalUid':'runtime-cert-smoke-cluster','distribution':'rke2','kubernetesVersion':'v1.34.9+rke2r1','nodes':[{'name':'node-1','uid':'node-1','roles':['control-plane'],'os':'Ubuntu 24.04','architecture':'amd64','kubeletVersion':'v1.34.9','ready':True}], 'storageClasses':[{'name':'replicated','provisioner':'openebs.io/local','reclaimPolicy':'Delete','volumeBindingMode':'WaitForFirstConsumer','allowVolumeExpansion':True,'default':True}], 'capacity':{'cpuCapacityMilli':4000,'cpuAllocatableMilli':3500,'memoryCapacityBytes':8589934592,'memoryAllocatableBytes':7516192768,'podsCapacity':110,'podsAllocatable':100}, 'networking':{'cni':'cilium','ingressControllers':['rke2-ingress-nginx'],'gatewayApi':True}, 'certificates':[{'name':'kubernetes-api','subject':'CN=kubernetes','issuer':'CN=kubernetes-ca','serialNumber':'1','fingerprint':'sha256:'+'a'*64,'notBefore':iso(now-dt.timedelta(days=1)),'notAfter':iso(now+dt.timedelta(days=180))}], 'addOns':[{'name':'cilium','namespace':'kube-system','version':addon,'healthy':True}], 'capabilities':['read-only-inventory','storage-inventory','capacity-inventory','certificate-inventory','target-enrollment-principal-isolated','target-mutation-rbac-active']+(['cert.metrics','cert.logs','cert.alerts'] if observability or target else [])+(['cert.dns','cert.tls','cert.network','cert.tenant-isolation','cert.pvc','cert.snapshot','cert.backup','cert.restore'] if target else [])}

def activate_mutation_rbac(base,cluster_id,token,desired):
    initial=json.loads(json.dumps(desired))
    initial['capabilities']=[c for c in initial.get('capabilities',[]) if c not in ('target-mutation-rbac-active','target-mutation-rbac-activation-issued')]
    if 'target-enrollment-principal-isolated' not in initial['capabilities']: initial['capabilities'].append('target-enrollment-principal-isolated')
    st,out,_=req(base+f"/agent/v1/clusters/{cluster_id}/inventory",'POST',initial,{'Authorization':'Bearer '+token}); assert st==200,(st,out)
    st,activation,_=req(base+f"/api/v1/clusters/{cluster_id}/mutation-rbac-manifest",'POST',{},headers={'X-Actor-ID':'operator'}); assert st==200 and activation.get('activationIssued') is True,(st,activation)
    active=json.loads(json.dumps(desired)); caps=[c for c in active.get('capabilities',[]) if c!='target-mutation-rbac-activation-issued']
    if 'target-enrollment-principal-isolated' not in caps: caps.append('target-enrollment-principal-isolated')
    if 'target-mutation-rbac-active' not in caps: caps.append('target-mutation-rbac-active')
    active['capabilities']=caps
    st,out,_=req(base+f"/agent/v1/clusters/{cluster_id}/inventory",'POST',active,{'Authorization':'Bearer '+token}); assert st==200,(st,out)
    return out

def lifecycle(base,release):
    st,review,_=req(base+f"/api/v1/catalog-releases/{release['id']}/review",'POST',{}, {'If-Match':f'"{release["revision"]}"'}); assert st==200,(st,review)
    st,published,_=req(base+f"/api/v1/catalog-releases/{release['id']}/publish",'POST',{}, {'If-Match':f'"{review["revision"]}"'}); assert st==200,(st,published)
    return published

def published_render(base,org):
    st,signer,_=req(base+'/api/v1/catalog-governance/signing-identity'); assert st==200 and signer.get('available') is True,(st,signer)
    st,key,_=req(base+'/api/v1/catalog-trust-keys','POST',{'organizationId':org['id'],'name':'runtime-cert-signer','publicKey':signer['publicKey']}); assert st==201,(st,key)
    st,components,_=req(base+'/api/v1/catalog/components'); assert st==200
    selected=[c for c in components if c.get('metadata',{}).get('name')=='secure-namespace-foundation']
    assert len(selected)==1 and selected[0]['spec']['source']['resolved'] is True,selected
    st,created,_=req(base+'/api/v1/catalog-releases','POST',{'organizationId':org['id'],'catalogName':'runtime-cert-foundation','catalogVersion':'1.0.0','visibility':'PRIVATE','channel':'CANDIDATE','components':selected}); assert st==201,(st,created)
    candidate=lifecycle(base,created['release'])
    st,promoted,_=req(base+f"/api/v1/catalog-releases/{candidate['id']}/promote",'POST',{'channel':'RENDER'}); assert st==201,(st,promoted)
    return lifecycle(base,promoted['release'])

def main():
    if len(sys.argv)!=2:raise SystemExit('usage: smoke_runtime_certification.py platform-api')
    binary=Path(sys.argv[1]).resolve(); root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as td:
        state=Path(td)/'state.json'; p,base=start(binary,root,state)
        try:
            st,version,_=req(base+'/api/v1/version'); assert st==200; version=version['version']
            st,org,_=req(base+'/api/v1/organizations','POST',{'name':'runtime-cert-smoke','displayName':'Runtime Certification Smoke'}); assert st==201,(st,org)
            st,project,_=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'prod','displayName':'Production'}); assert st==201,(st,project)
            st,created,_=req(base+'/api/v1/cluster-imports','POST',{'projectId':project['id'],'name':'cert-edge','displayName':'Certification Edge'}); assert st==201,(st,created)
            enrollment=created['enrollmentToken']; imp=created['import']
            st,_,_=req(base+f"/api/v1/cluster-imports/{imp['id']}/approve",'POST',{}, {'If-Match':'1'}); assert st==200
            st,claimed,_=req(base+f"/agent/v1/cluster-imports/{imp['id']}/claim",'POST',{'token':enrollment,'externalUid':'runtime-cert-smoke-cluster','agentVersion':version}); assert st==200,(st,claimed)
            cluster=claimed['cluster']; token=claimed['agentToken']
            activate_mutation_rbac(base,cluster['id'],token,inventory())
            release=published_render(base,org)
            st,created_run,_=req(base+'/api/v1/runtime-certifications','POST',{'projectId':project['id'],'clusterId':cluster['id'],'catalogReleaseId':release['id'],'profile':'FOUNDATION_V1','namespace':'4so-cert-foundation'},{'Idempotency-Key':'runtime-cert-foundation-1'}); assert st==201,(st,created_run)
            run=created_run['run']; assert run['state']=='QUEUED' and created_run['externalLiveCertified'] is False,created_run
            st,install,_=req(base+f"/agent/v1/clusters/{cluster['id']}/runtime-certification-tasks/next",headers={'Authorization':'Bearer '+token}); assert st==200 and install['phase']=='INSTALL' and len(install['resources'])==6,(st,install)
            install_result={'taskFenceToken':install['taskFenceToken'],'phase':'INSTALL','success':True,'inventoryDigest':install['inventoryDigest'],'renderedDigest':install['renderedDigest'],'checks':[{'key':'fresh-install-target','status':'PASS','detail':'test harness confirms Agent INSTALL result contract'}]+[{'key':f'apply/{i}','status':'PASS'} for i in range(1,7)]}
            st,checkpointed,_=req(base+f"/agent/v1/clusters/{cluster['id']}/runtime-certification-tasks/{install['runId']}/result",'POST',install_result,{'Authorization':'Bearer '+token,'If-Match':f'"{install["runRevision"]}"'}); assert st==200 and checkpointed['state']=='VERIFYING' and checkpointed['installCheckpointDigest'].startswith('sha256:'),(st,checkpointed)
            run_id=run['id']; checkpoint=checkpointed['installCheckpointDigest']; render_digest=run['renderedDigest']; release_id=release['id']; cluster_id=cluster['id']; project_id=project['id']
        finally:stop(p)

        # Prove durable INSTALL checkpoint survives API restart before VERIFY.
        p,base=start(binary,root,state)
        try:
            st,verify,_=req(base+f"/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/next",headers={'Authorization':'Bearer '+token}); assert st==200 and verify['phase']=='VERIFY' and verify['installCheckpointDigest']==checkpoint,(st,verify)
            verify_result={'taskFenceToken':verify['taskFenceToken'],'phase':'VERIFY','success':True,'inventoryDigest':verify['inventoryDigest'],'renderedDigest':verify['renderedDigest'],'checks':[{'key':'durable-install-checkpoint','status':'PASS','detail':'checkpoint survived restart'}]+[{'key':f'verify/{i}','status':'PASS'} for i in range(1,7)]+[{'key':'nodes-ready','status':'PASS','detail':'ready=1 total=1'},{'key':'cluster-dns-service','status':'PASS','detail':'kube-dns service found'},{'key':'kubernetes-api-tls','status':'PASS','detail':'CA verified API request'}]}
            st,succeeded,_=req(base+f"/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/{verify['runId']}/result",'POST',verify_result,{'Authorization':'Bearer '+token,'If-Match':f'"{verify["runRevision"]}"'}); assert st==200 and succeeded['state']=='SUCCEEDED' and succeeded['evidenceDigest'].startswith('sha256:') and succeeded.get('expiresAt'),(st,succeeded)
            st,report,_=req(base+f"/api/v1/runtime-certifications/{run_id}/report"); assert st==200 and report['claims']['profileCertified']=='FOUNDATION_V1' and report['claims']['externalLiveCertified'] is False and report['claims']['productionReady'] is False,(st,report)
            # TARGET profile must never become green from capability labels alone.
            st,target,_=req(base+'/api/v1/runtime-certifications','POST',{'projectId':project_id,'clusterId':cluster_id,'catalogReleaseId':release_id,'profile':'TARGET_RUNTIME_V1','namespace':'4so-cert-target'},{'Idempotency-Key':'runtime-cert-target-1'}); assert st==201 and target['run']['state']=='BLOCKED' and len(target['run']['checks'])==11,(st,target)
            # OBSERVABILITY_V1 is independent from storage/backup and requires exact executable check evidence.
            st,_,_=req(base+f"/agent/v1/clusters/{cluster_id}/inventory",'POST',inventory('1.18',True),{'Authorization':'Bearer '+token}); assert st==200
            st,obs_created,_=req(base+'/api/v1/runtime-certifications','POST',{'projectId':project_id,'clusterId':cluster_id,'catalogReleaseId':release_id,'profile':'OBSERVABILITY_V1','namespace':'4so-cert-observability'},{'Idempotency-Key':'runtime-cert-observability-1'}); assert st==201 and obs_created['run']['state']=='QUEUED',(st,obs_created)
            st,obs_install,_=req(base+f"/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/next",headers={'Authorization':'Bearer '+token}); assert st==200 and obs_install['profile']=='OBSERVABILITY_V1' and obs_install['phase']=='INSTALL',(st,obs_install)
            obs_install_result={'taskFenceToken':install['taskFenceToken'],'phase':'INSTALL','success':True,'inventoryDigest':obs_install['inventoryDigest'],'renderedDigest':obs_install['renderedDigest'],'checks':[{'key':'fresh-install-target','status':'PASS'}]+[{'key':f'apply/{i}','status':'PASS'} for i in range(1,7)]}
            st,obs_checkpoint,_=req(base+f"/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/{obs_install['runId']}/result",'POST',obs_install_result,{'Authorization':'Bearer '+token,'If-Match':f'"{obs_install["runRevision"]}"'}); assert st==200 and obs_checkpoint['state']=='VERIFYING',(st,obs_checkpoint)
            st,obs_verify,_=req(base+f"/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/next",headers={'Authorization':'Bearer '+token}); assert st==200 and obs_verify['phase']=='VERIFY',(st,obs_verify)
            obs_checks=[{'key':'durable-install-checkpoint','status':'PASS'}]+[{'key':f'verify/{i}','status':'PASS'} for i in range(1,7)]+[{'key':'nodes-ready','status':'PASS'},{'key':'cluster-dns-service','status':'PASS'},{'key':'kubernetes-api-tls','status':'PASS'},{'key':'target-runtime/metrics-query','status':'PASS'},{'key':'target-runtime/logs-push','status':'PASS'},{'key':'target-runtime/logs-query','status':'PASS'},{'key':'target-runtime/alert-fire','status':'PASS'},{'key':'target-runtime/alert-query','status':'PASS'}]
            st,obs_done,_=req(base+f"/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/{obs_verify['runId']}/result",'POST',{'taskFenceToken':obs_verify['taskFenceToken'],'phase':'VERIFY','success':True,'inventoryDigest':obs_verify['inventoryDigest'],'renderedDigest':obs_verify['renderedDigest'],'checks':obs_checks},{'Authorization':'Bearer '+token,'If-Match':f'"{obs_verify["runRevision"]}"'}); assert st==200 and obs_done['state']=='SUCCEEDED' and obs_done['profile']=='OBSERVABILITY_V1',(st,obs_done)
            st,obs_report,_=req(base+f"/api/v1/runtime-certifications/{obs_done['id']}/report"); assert st==200 and obs_report['claims']['profileCertified']=='OBSERVABILITY_V1' and obs_report['claims']['externalLiveCertified'] is False,(st,obs_report)

            # TARGET_RUNTIME_V1 becomes executable only when the authoritative inventory reports every real adapter capability.
            st,_,_=req(base+f"/agent/v1/clusters/{cluster_id}/inventory",'POST',inventory('1.18',target=True),{'Authorization':'Bearer '+token}); assert st==200
            st,target_exec,_=req(base+'/api/v1/runtime-certifications','POST',{'projectId':project_id,'clusterId':cluster_id,'catalogReleaseId':release_id,'profile':'TARGET_RUNTIME_V1','namespace':'4so-cert-target-executable'},{'Idempotency-Key':'runtime-cert-target-executable-1'}); assert st==201 and target_exec['run']['state']=='QUEUED',(st,target_exec)
            st,target_install,_=req(base+f"/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/next",headers={'Authorization':'Bearer '+token}); assert st==200 and target_install['profile']=='TARGET_RUNTIME_V1' and target_install['phase']=='INSTALL',(st,target_install)
            target_install_checks=[{'key':'fresh-install-target','status':'PASS'}]+[{'key':f'apply/{i}','status':'PASS'} for i in range(1,7)]
            st,target_cp,_=req(base+f"/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/{target_install['runId']}/result",'POST',{'taskFenceToken':target_install['taskFenceToken'],'phase':'INSTALL','success':True,'inventoryDigest':target_install['inventoryDigest'],'renderedDigest':target_install['renderedDigest'],'checks':target_install_checks},{'Authorization':'Bearer '+token,'If-Match':f'"{target_install["runRevision"]}"'}); assert st==200 and target_cp['state']=='VERIFYING',(st,target_cp)
            st,target_verify,_=req(base+f"/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/next",headers={'Authorization':'Bearer '+token}); assert st==200 and target_verify['phase']=='VERIFY',(st,target_verify)
            target_checks=[{'key':'durable-install-checkpoint','status':'PASS'}]+[{'key':f'verify/{i}','status':'PASS'} for i in range(1,7)]+[{'key':k,'status':'PASS'} for k in ['nodes-ready','cluster-dns-service','kubernetes-api-tls','target-runtime/metrics-query','target-runtime/logs-push','target-runtime/logs-query','target-runtime/alert-fire','target-runtime/alert-query','target-runtime/network-namespaces','target-runtime/network-default-deny','target-runtime/network-dns-tenant-a','target-runtime/network-dns-tenant-b','target-runtime/network-intra-tenant-allow','target-runtime/network-cross-tenant-deny','target-runtime/network-cross-tenant-explicit-allow','target-runtime/pvc-bind','target-runtime/pvc-io','target-runtime/snapshot-create','target-runtime/snapshot-restore-pvc','target-runtime/snapshot-restore-io','target-runtime/backup-create','target-runtime/restore-validate']]
            # Missing one storage/backup postcondition must be rejected even though every submitted check is PASS.
            st,bad_target,_=req(base+f"/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/{target_verify['runId']}/result",'POST',{'taskFenceToken':target_verify['taskFenceToken'],'phase':'VERIFY','success':True,'inventoryDigest':target_verify['inventoryDigest'],'renderedDigest':target_verify['renderedDigest'],'checks':target_checks[:-1]},{'Authorization':'Bearer '+token,'If-Match':f'"{target_verify["runRevision"]}"'}); assert st==422 and 'restore-validate' in json.dumps(bad_target),(st,bad_target)
            tampered_network=[c for c in target_checks if c['key']!='target-runtime/network-cross-tenant-deny']
            st,bad_network,_=req(base+f"/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/{target_verify['runId']}/result",'POST',{'taskFenceToken':target_verify['taskFenceToken'],'phase':'VERIFY','success':True,'inventoryDigest':target_verify['inventoryDigest'],'renderedDigest':target_verify['renderedDigest'],'checks':tampered_network},{'Authorization':'Bearer '+token,'If-Match':f'"{target_verify["runRevision"]}"'}); assert st==422 and 'network-cross-tenant-deny' in str(bad_network),(st,bad_network)
            st,target_done,_=req(base+f"/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/{target_verify['runId']}/result",'POST',{'taskFenceToken':target_verify['taskFenceToken'],'phase':'VERIFY','success':True,'inventoryDigest':target_verify['inventoryDigest'],'renderedDigest':target_verify['renderedDigest'],'checks':target_checks},{'Authorization':'Bearer '+token,'If-Match':f'"{target_verify["runRevision"]}"'}); assert st==200 and target_done['state']=='SUCCEEDED' and target_done['profile']=='TARGET_RUNTIME_V1',(st,target_done)
            print('NETWORK_TENANT_ISOLATION_AUTHORITY_SMOKE_PASS')
            st,target_report,_=req(base+f"/api/v1/runtime-certifications/{target_done['id']}/report"); assert st==200 and target_report['claims']['profileCertified']=='TARGET_RUNTIME_V1' and target_report['claims']['externalLiveCertified'] is False and target_report['claims']['productionReady'] is False,(st,target_report)
            print('TARGET_RUNTIME_STORAGE_BACKUP_AUTHORITY_SMOKE_PASS',target_done['id'],target_done['evidenceDigest'])

            # Queue another foundation run then mutate inventory: the old run must not execute stale context.
            st,stale_created,_=req(base+'/api/v1/runtime-certifications','POST',{'projectId':project_id,'clusterId':cluster_id,'catalogReleaseId':release_id,'profile':'FOUNDATION_V1','namespace':'4so-cert-stale'},{'Idempotency-Key':'runtime-cert-stale-1'}); assert st==201 and stale_created['run']['state']=='QUEUED',(st,stale_created)
            st,_,_=req(base+f"/agent/v1/clusters/{cluster_id}/inventory",'POST',inventory('1.19'),{'Authorization':'Bearer '+token}); assert st==200
            st,empty,_=req(base+f"/agent/v1/clusters/{cluster_id}/runtime-certification-tasks/next",headers={'Authorization':'Bearer '+token}); assert st==204,(st,empty)
            st,stale,_=req(base+f"/api/v1/runtime-certifications/{stale_created['run']['id']}"); assert st==200 and stale['state']=='FAILED' and 'inventory changed' in stale['lastError'],(st,stale)
            print('RUNTIME_CERTIFICATION_CLOSURE_SMOKE_PASS',run_id,render_digest,checkpoint,succeeded['evidenceDigest'],target['run']['state'],obs_done['evidenceDigest'])
        finally:stop(p)
    return 0

if __name__=='__main__':raise SystemExit(main())
