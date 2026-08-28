#!/usr/bin/env python3
from __future__ import annotations
import datetime as dt, hashlib, json, os, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

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

def start(binary,state):
    port=free_port(); env=os.environ.copy()
    env['PLATFORM_FACTORY_LISTEN']=f'127.0.0.1:{port}'
    env['PLATFORM_FACTORY_STATE_FILE']=str(state)
    env['PLATFORM_FACTORY_AGENT_MTLS_REQUIRED']='false'
    env['PLATFORM_FACTORY_PUBLIC_URL']='https://platform.example.test'
    env['PLATFORM_FACTORY_FLEET_AGENT_IMAGE']='registry.local/platform-agent@sha256:'+'a'*64
    env['PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE']='registry.local/platform-probe@sha256:'+'b'*64
    p=subprocess.Popen([str(binary)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    base=f'http://127.0.0.1:{port}'
    for _ in range(100):
        try:
            if req(base+'/readyz')[0]==200:return p,base
        except Exception:pass
        time.sleep(.1)
    p.terminate(); raise RuntimeError('api not ready')

def stop(p):
    p.terminate()
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.wait()

def iso(t): return t.isoformat().replace('+00:00','Z')

def inventory(addon_version='1.18', external_uid=''):
    now=dt.datetime.now(dt.timezone.utc)
    api=[
      {'apiVersion':'v1','group':'','version':'v1','kind':'ResourceQuota','resource':'resourcequotas','namespaced':True,'verbs':['get','list','patch','delete']},
      {'apiVersion':'v1','group':'','version':'v1','kind':'LimitRange','resource':'limitranges','namespaced':True,'verbs':['get','list','patch','delete']},
      {'apiVersion':'v1','group':'','version':'v1','kind':'ServiceAccount','resource':'serviceaccounts','namespaced':True,'verbs':['get','list','patch','delete']},
      {'apiVersion':'v1','group':'','version':'v1','kind':'ConfigMap','resource':'configmaps','namespaced':True,'verbs':['get','list','patch','delete']},
      {'apiVersion':'networking.k8s.io/v1','group':'networking.k8s.io','version':'v1','kind':'NetworkPolicy','resource':'networkpolicies','namespaced':True,'verbs':['get','list','patch','delete']},
    ]
    payload={'observedAt':iso(now),'distribution':'rke2','kubernetesVersion':'v1.34.9+rke2r1','nodes':[{'name':'node-1','uid':'node-1','roles':['control-plane'],'os':'Ubuntu 24.04','architecture':'amd64','kubeletVersion':'v1.34.9','ready':True}], 'storageClasses':[{'name':'replicated','provisioner':'openebs.io/local','reclaimPolicy':'Delete','volumeBindingMode':'WaitForFirstConsumer','allowVolumeExpansion':True,'default':True}], 'capacity':{'cpuCapacityMilli':4000,'cpuAllocatableMilli':3500,'memoryCapacityBytes':8589934592,'memoryAllocatableBytes':7516192768,'podsCapacity':110,'podsAllocatable':100}, 'networking':{'cni':'cilium','ingressControllers':['rke2-ingress-nginx'],'gatewayApi':True}, 'certificates':[{'name':'kubernetes-api','subject':'CN=kubernetes','issuer':'CN=kubernetes-ca','serialNumber':'1','fingerprint':'sha256:'+'a'*64,'notBefore':iso(now-dt.timedelta(days=1)),'notAfter':iso(now+dt.timedelta(days=180))}], 'addOns':[{'name':'cilium','namespace':'kube-system','version':addon_version,'healthy':True}], 'capabilities':['read-only-inventory','controlled-baseline-deployment','cni-inventory','runtime-probe-image-digest-pinned','storage-class-inventory','capacity-inventory','certificate-inventory','api-surface-inventory','crd-inventory','openapi-schema-authority','strict-schema-dry-run','target-enrollment-principal-isolated','target-mutation-rbac-active'],'apiResources':api,'crds':[],'apiDiscoveryComplete':True,'crdDiscoveryComplete':True,'schemaDiscoveryVersion':'OPENAPI_V3','schemaDiscoveryDigest':'sha256:'+'9'*64,'schemaDiscoveryComplete':True}
    if external_uid:
        payload['externalUid']=external_uid
    return payload


def activate_mutation_rbac(base, cluster_id, agent_token, desired_inventory, actor_headers=None):
    initial=json.loads(json.dumps(desired_inventory))
    initial['capabilities']=[c for c in initial.get('capabilities',[]) if c not in ('target-mutation-rbac-active','target-mutation-rbac-activation-issued')]
    if 'target-enrollment-principal-isolated' not in initial['capabilities']:
        initial['capabilities'].append('target-enrollment-principal-isolated')
    st,reported,_=req(base+f'/agent/v1/clusters/{cluster_id}/inventory','POST',initial,{'Authorization':'Bearer '+agent_token})
    assert st==200,(st,reported)
    headers={'X-Actor-ID':'operator'}
    if actor_headers: headers.update(actor_headers)
    st,activation,_=req(base+f'/api/v1/clusters/{cluster_id}/mutation-rbac-manifest','POST',{},headers=headers)
    assert st==200 and activation.get('activationIssued') is True and activation.get('manifest'),(st,activation)
    active=json.loads(json.dumps(desired_inventory))
    caps=[c for c in active.get('capabilities',[]) if c!='target-mutation-rbac-activation-issued']
    if 'target-enrollment-principal-isolated' not in caps: caps.append('target-enrollment-principal-isolated')
    if 'target-mutation-rbac-active' not in caps: caps.append('target-mutation-rbac-active')
    active['capabilities']=caps
    st,reported,_=req(base+f'/agent/v1/clusters/{cluster_id}/inventory','POST',active,{'Authorization':'Bearer '+agent_token})
    assert st==200,(st,reported)
    return reported

def compatibility_decision(task):
    inv=task.get('inventory') or {}
    kube=str(inv.get('kubernetesVersion') or '').strip().lstrip('v')
    parts=kube.split('.')
    kube_minor=('1.'+parts[1]) if len(parts)>=2 else kube
    arches=sorted({str(n.get('architecture') or '').strip().lower() for n in inv.get('nodes') or [] if str(n.get('architecture') or '').strip()})
    arch=arches[0] if len(arches)==1 else ('mixed' if len(arches)>1 else '')
    raw_dist=str(inv.get('distribution') or '').strip().lower()
    dist='rke2' if 'rke2' in raw_dist else 'kubernetes'
    target={'kubernetesVersion':kube_minor,'architecture':arch,'distribution':dist,'provider':'imported'}
    name='component/secure-namespace-foundation'
    allowed={'architecture':['amd64','arm64'],'distribution':['kubernetes','rke2'],'provider':['cluster-api-topology-v1beta2','imported']}
    checks=[]
    kpass=kube_minor in ('1.34','1.35')
    checks.append({'constraint':name,'dimension':'kubernetes','status':'PASS' if kpass else 'FAIL','target':kube_minor,'allowed':['1.34..1.35'],'authority':'PLATFORM_COMPATIBILITY_MATRIX_V1','message':'Kubernetes minor is admitted' if kpass else 'Kubernetes minor is outside admitted range'})
    for dim in ('architecture','distribution','provider'):
        value=target[dim]; admitted=allowed[dim]
        if not value: status,message='FAIL','target value is required'
        elif value in admitted: status,message='PASS','target is admitted'
        else: status,message='FAIL','target is outside admitted compatibility set'
        checks.append({'constraint':name,'dimension':dim,'status':status,'target':value,'allowed':admitted,'authority':'PLATFORM_COMPATIBILITY_MATRIX_V1','message':message})
    checks=sorted(checks,key=lambda x:(x['constraint'],x['dimension']))
    blockers=sorted([f"{x['constraint']}:{x['dimension']}:{x['message']}" for x in checks if x['status']!='PASS'])
    out={'method':'PLATFORM_COMPATIBILITY_MATRIX_V1','status':'FAIL' if blockers else 'PASS','target':target,'checks':checks}
    if blockers: out['blockers']=blockers
    out['digest']=''
    raw=json.dumps(out,separators=(',',':'),ensure_ascii=False).encode(); out['digest']='sha256:'+hashlib.sha256(raw).hexdigest()
    return out

def redigest_compatibility(impact):
    value=json.loads(json.dumps(impact['compatibility']))
    value['digest']=''
    raw=json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
    impact['compatibility']['digest']='sha256:'+hashlib.sha256(raw).hexdigest()
    return impact

def capability_preflight(task):
    inv=task.get('inventory') or {}; resources=task.get('resources') or []; caps=set(inv.get('capabilities') or [])
    domains=set()
    for r in resources:
        api_version=str(r.get('apiVersion') or ''); group=api_version.split('/')[0] if '/' in api_version else '' ; kind=str(r.get('kind') or '')
        if kind=='NetworkPolicy': domains.add('network')
        elif kind in ('PersistentVolumeClaim','StatefulSet','StorageClass'): domains.add('storage')
        elif kind in ('VolumeSnapshot','VolumeSnapshotClass','VolumeSnapshotContent') or group=='snapshot.storage.k8s.io': domains.update(('storage','snapshot'))
        elif group=='velero.io' or kind in ('Backup','Restore','Schedule','BackupStorageLocation'): domains.add('backup')
        elif group=='gateway.networking.k8s.io' or kind in ('Gateway','HTTPRoute','GRPCRoute'): domains.add('gateway')
        elif group=='cluster.x-k8s.io' or kind=='ClusterClass': domains.add('provider')
        elif group in ('monitoring.coreos.com','operator.victoriametrics.com','loki.grafana.com') or kind in ('ServiceMonitor','PodMonitor','VMServiceScrape','VMPodScrape','VMRule'): domains.add('observability')
    def api_has(group,version,kind,resource,*verbs):
        for item in inv.get('apiResources') or []:
            if item.get('group','')==group and item.get('version','')==version and item.get('kind')==kind and item.get('resource')==resource:
                have=set(item.get('verbs') or []); return all(v in have for v in verbs)
        return False
    def check(key,domain,required,available,authority,impact,detail,evidence):
        status=('PASS' if available else 'FAIL') if required else ('AVAILABLE' if available else 'NOT_REQUIRED')
        row={'key':key,'domain':domain,'required':required,'status':status,'authority':authority,'impact':impact,'detail':detail}
        evidence=sorted(set(x.strip() for x in evidence if str(x).strip()))
        if evidence: row['evidence']=evidence
        return row
    digest=inv.get('digest',''); schema=inv.get('schemaDiscoveryDigest','')
    inventory_ready=bool(str(digest).startswith('sha256:') and 'read-only-inventory' in caps and inv.get('apiDiscoveryComplete') is True and inv.get('schemaDiscoveryComplete') is True)
    rows=[
      check('inventory-authority','core',True,inventory_ready,'CLUSTER_INVENTORY_DIGEST','all plan capability decisions are bound to the same authenticated inventory snapshot',f"inventory={digest} apiDiscovery={str(inv.get('apiDiscoveryComplete') is True).lower()} schemaDiscovery={str(inv.get('schemaDiscoveryComplete') is True).lower()}",[digest,schema]),
      check('baseline-execution','core',True,'controlled-baseline-deployment' in caps,'PLATFORM_AGENT_CAPABILITY','the selected Agent must support the controlled baseline execution contract','controlled-baseline-deployment capability is reported by the connected Agent',['controlled-baseline-deployment']),
    ]
    network_api=api_has('networking.k8s.io','v1','NetworkPolicy','networkpolicies','get','patch'); cni=str((inv.get('networking') or {}).get('cni') or '')
    rows.append(check('network-policy-enforcement','network','network' in domains,bool(cni and 'cni-inventory' in caps and network_api),'KUBERNETES_DISCOVERY+CNI_INVENTORY','NetworkPolicy resources require a discovered CNI and served networking.k8s.io/v1 API',f'cni={cni} networkPolicyAPI={str(network_api).lower()}',[f'cni:{cni}','api:networking.k8s.io/v1/NetworkPolicy']))
    classes=inv.get('storageClasses') or []; storage_evidence=[f"storageClass:{x.get('name','')}@{x.get('provisioner','')}" for x in classes]
    rows.append(check('storage-runtime','storage','storage' in domains,bool(classes and 'storage-class-inventory' in caps),'KUBERNETES_STORAGECLASS_INVENTORY','storage-consuming resources require an admitted StorageClass from the bound inventory',f'storageClasses={len(classes)}',storage_evidence))
    rows.append(check('snapshot-runtime','snapshot','snapshot' in domains,bool('cert.snapshot' in caps and 'storage-backup-adapter-auto-discovered' in caps),'STORAGE_BACKUP_ADAPTER_DISCOVERY','snapshot resources require a discovered CSI VolumeSnapshotClass and executable snapshot adapter','cert.snapshot is published only after matching storage/snapshot adapter discovery',['cert.snapshot','storage-backup-adapter-auto-discovered']))
    rows.append(check('backup-runtime','backup','backup' in domains,bool('cert.backup' in caps and 'cert.restore' in caps and 'storage-backup-adapter-auto-discovered' in caps),'STORAGE_BACKUP_ADAPTER_DISCOVERY','backup/restore resources require an Available Velero BackupStorageLocation discovered by the Agent','cert.backup + cert.restore are published only after Velero and storage adapter discovery',['cert.backup','cert.restore','storage-backup-adapter-auto-discovered']))
    rows.append(check('observability-runtime','observability','observability' in domains,bool({'cert.metrics','cert.logs','cert.alerts'} <= caps),'OBSERVABILITY_ADAPTER_DISCOVERY','observability resources require executable metrics, logs and alerts adapters','metrics/logs/alerts adapter endpoints are discovered or explicitly configured by the Agent',['cert.metrics','cert.logs','cert.alerts']))
    gateway_available=bool((inv.get('networking') or {}).get('gatewayApi') is True and 'gateway-api' in caps and api_has('gateway.networking.k8s.io','v1','Gateway','gateways','get','patch'))
    rows.append(check('gateway-api-runtime','gateway','gateway' in domains,gateway_available,'KUBERNETES_DISCOVERY','Gateway API resources require the v1 API surface on the target cluster',f'gatewayApi={str((inv.get("networking") or {}).get("gatewayApi") is True).lower()}',['gateway.networking.k8s.io/v1']))
    provider_available=api_has('cluster.x-k8s.io','v1beta2','Cluster','clusters','get','patch') and api_has('cluster.x-k8s.io','v1beta2','ClusterClass','clusterclasses','get')
    rows.append(check('provider-runtime','provider','provider' in domains,provider_available,'KUBERNETES_DISCOVERY','provider lifecycle resources require the admitted Cluster API v1beta2 execution surface',f'clusterApiV1beta2={str(provider_available).lower()}',['cluster.x-k8s.io/v1beta2/Cluster','cluster.x-k8s.io/v1beta2/ClusterClass']))
    probe_required=bool({'storage','snapshot','backup'} & domains)
    rows.append(check('runtime-probe-image','runtime',probe_required,'runtime-probe-image-digest-pinned' in caps,'PLATFORM_AGENT_CONFIGURATION','executable storage/backup preflight requires the digest-pinned runtime probe image','Agent reports the probe capability only when its image reference is digest pinned',['runtime-probe-image-digest-pinned']))
    rows=sorted(rows,key=lambda x:x['key'])
    out={'status':'PASS','method':'CLUSTER_CAPABILITY_PREFLIGHT_V1','inventoryDigest':digest,'checks':rows,'digest':''}
    blockers=[f"capability preflight failed: {r['key']} ({r['detail']})" for r in rows if r['required'] and r['status']!='PASS']
    if blockers: out['status']='FAIL'; out['blockers']=sorted(set(blockers))
    raw=json.dumps(out,separators=(',',':'),ensure_ascii=False).encode(); out['digest']='sha256:'+hashlib.sha256(raw).hexdigest()
    return out

def planning_impact(task, changes, approval_ready=True, blockers=None):
    api=[]
    for r in sorted(task.get('resources') or [], key=lambda x: f"{x.get('kind','')}/{x.get('name','')}"):
        api.append({'resource':f"{r.get('kind')}/{r.get('name')}",'apiVersion':r.get('apiVersion',''),'kind':r.get('kind',''),'discoveryStatus':'SERVED','lifecycleStatus':'CURRENT','customResource':False,'schema':{'status':'PASS','method':'KUBE_APISERVER_DRY_RUN_STRICT','httpStatus':200,'schemaIndexVersion':task.get('inventory',{}).get('schemaDiscoveryVersion',''),'schemaIndexDigest':task.get('inventory',{}).get('schemaDiscoveryDigest','')},'severity':'INFO','message':f"{r.get('apiVersion')} {r.get('kind')} is served and has no known lifecycle blocker"})
    changes_by={c.get('resource'):c for c in changes}
    level='NONE'; maintenance='NOT_REQUIRED'; reasons=[]; affected=[]
    rank={'NONE':0,'LOW':1,'MEDIUM':2,'HIGH':3}
    for r in task.get('resources') or []:
        key=f"{r.get('kind')}/{r.get('name')}"; c=changes_by.get(key)
        if not c or str(c.get('action','')).upper()=='NOOP': continue
        kind=r.get('kind'); action=str(c.get('action','')).upper(); lv='LOW'; mt='NOT_REQUIRED'; reason=f'{action} of {key} changes a managed control-plane object without a known pod restart'
        if kind in ('NetworkPolicy','Ingress','Service','Gateway','HTTPRoute'): lv,mt,reason='MEDIUM','RECOMMENDED',f'{action} of {key} can change live traffic behavior'
        elif kind in ('Deployment','StatefulSet','DaemonSet','Pod','Job','CronJob'): lv,mt,reason='MEDIUM','RECOMMENDED',f'{action} of {key} can restart, reschedule or add workload pods'
        elif kind=='CustomResourceDefinition': lv,mt,reason='HIGH','REQUIRED',f'{action} of {key} can change validation/storage semantics for custom resources'
        elif kind in ('ResourceQuota','LimitRange'): reason=f'{action} of {key} changes admission policy for future workload requests'
        if rank[lv]>rank[level]: level=lv
        if {'NOT_REQUIRED':0,'RECOMMENDED':1,'REQUIRED':2}[mt]>{'NOT_REQUIRED':0,'RECOMMENDED':1,'REQUIRED':2}[maintenance]: maintenance=mt
        reasons.append(reason); affected.append(key)
    cap=task.get('inventory',{}).get('capacity') or {}
    schema_version=task.get('inventory',{}).get('schemaDiscoveryVersion','')
    schema_digest=task.get('inventory',{}).get('schemaDiscoveryDigest','')
    rollback_rows=[]
    for r in sorted(task.get('resources') or [], key=lambda x: f"{x.get('kind','')}/{x.get('name','')}"):
        key=f"{r.get('kind')}/{r.get('name')}"
        change=changes_by.get(key) or {'action':'NOOP'}
        action=str(change.get('action') or 'NOOP').upper()
        if action=='ADD':
            row={'resource':key,'changeAction':'ADD','strategy':'DELETE_CREATED_RESOURCE','status':'PASS','authorizationStatus':'PASS','dryRunStatus':'NOT_APPLICABLE','schemaIndexVersion':schema_version,'schemaIndexDigest':schema_digest}
        elif action=='NOOP':
            observed_raw=json.dumps(r.get('object') or {'apiVersion':r.get('apiVersion',''),'kind':r.get('kind',''),'metadata':{'name':r.get('name',''),'namespace':r.get('namespace','')}},separators=(',',':'),ensure_ascii=False).encode()
            observed_digest='sha256:'+hashlib.sha256(observed_raw).hexdigest()
            row={'resource':key,'changeAction':'NOOP','strategy':'NO_ACTION','status':'PASS','authorizationStatus':'NOT_REQUIRED','dryRunStatus':'NOT_REQUIRED','schemaIndexVersion':schema_version,'schemaIndexDigest':schema_digest,'observedUid':'smoke-'+hashlib.sha256(key.encode()).hexdigest()[:16],'observedObjectDigest':observed_digest}
        elif action in ('UPDATE','DELETE'):
            if r.get('kind')=='Secret':
                raise AssertionError(f'generic rollback fixture cannot persist Secret pre-image for {key}')
            restore={'apiVersion':r.get('apiVersion',''),'kind':r.get('kind',''),'metadata':{'name':r.get('name',''),'namespace':r.get('namespace','')}}
            restore_raw=json.dumps(restore,separators=(',',':'),ensure_ascii=False).encode()
            restore_digest='sha256:'+hashlib.sha256(restore_raw).hexdigest()
            row={'resource':key,'changeAction':action,'strategy':'RESTORE_PREIMAGE','status':'PASS','authorizationStatus':'PASS','dryRunStatus':'PASS','httpStatus':200,'schemaIndexVersion':schema_version,'schemaIndexDigest':schema_digest,'observedUid':'smoke-'+hashlib.sha256(key.encode()).hexdigest()[:16],'observedObjectDigest':restore_digest,'restoreObjectDigest':restore_digest,'restoreObject':restore}
        else:
            raise AssertionError(f'unsupported planning smoke action {action} for {key}')
        rollback_rows.append(row)
    rollback={'status':'PASS','method':'KUBE_ROLLBACK_FEASIBILITY_V1','resources':rollback_rows,'digest':''}
    rollback_raw=json.dumps(rollback,separators=(',',':'),ensure_ascii=False).encode()
    rollback['digest']='sha256:'+hashlib.sha256(rollback_raw).hexdigest()
    deployment_id=task.get('deploymentId','')
    if not deployment_id: raise AssertionError('planning evidence fixture requires deploymentId')
    evidence_artifacts=[]
    for r in sorted(task.get('resources') or [], key=lambda x: f"{x.get('kind','')}/{x.get('name','')}"):
        resource=f"{r.get('kind')}/{r.get('name')}"
        key='resource-readback-'+''.join(ch.lower() if ch.isalnum() else '-' for ch in resource).strip('-')
        source=f"kubernetes://kubernetes.default.svc/planned/{r.get('apiVersion','')}/{r.get('namespace','')}/{r.get('kind','')}/{r.get('name','')}"
        evidence_artifacts.append({'key':key,'kind':'KUBE_RESOURCE_READBACK','resource':resource,'authority':'KUBERNETES_API_SERVER','sourceLocation':source,'outputLocation':f'/api/v1/baseline-deployments/{deployment_id}/evidence/{key}','mediaType':'application/json','phase':'POST_APPLY','required':True,'retentionDays':90})
    evidence_artifacts.append({'key':'baseline-convergence','kind':'BASELINE_CONVERGENCE','authority':'PLATFORM_AGENT','sourceLocation':'platform-agent://baseline-convergence','outputLocation':f'/api/v1/baseline-deployments/{deployment_id}/evidence/baseline-convergence','mediaType':'application/json','phase':'POST_APPLY','required':True,'retentionDays':90})
    evidence={'status':'PASS','method':'BASELINE_EVIDENCE_COLLECTION_V1','requiredCount':len(evidence_artifacts),'artifacts':evidence_artifacts,'digest':''}
    evidence_raw=json.dumps(evidence,separators=(',',':'),ensure_ascii=False).encode()
    evidence['digest']='sha256:'+hashlib.sha256(evidence_raw).hexdigest()
    impact={'schemaVersion':6,'inventoryDigest':task.get('inventory',{}).get('digest',''),'compatibility':compatibility_decision(task),'capability':capability_preflight(task),'api':api,'capacity':{'demandDeltaKnown':True,'cpuRequestDeltaMilli':0,'memoryRequestDeltaBytes':0,'podReplicaDelta':0,'workloadResources':0,'cpuAllocatableCeilingMilli':cap.get('cpuAllocatableMilli',0),'memoryAllocatableCeilingBytes':cap.get('memoryAllocatableBytes',0),'podsAllocatableCeiling':cap.get('podsAllocatable',0),'ceilingCheck':'NOT_APPLICABLE','currentUsageKnown':False},'disruption':{'level':level,'maintenanceRecommendation':maintenance},'rollback':rollback,'evidence':evidence,'approvalReady':approval_ready,'digest':''}
    if reasons: impact['disruption']['reasons']=sorted(set(reasons)); impact['disruption']['affectedResources']=sorted(set(affected))
    if blockers: impact['blockers']=list(blockers)
    raw=json.dumps(impact,separators=(',',':'),ensure_ascii=False).encode()
    impact['digest']='sha256:'+hashlib.sha256(raw).hexdigest()
    return impact

def post_task_result(base,cluster_id,agent_token,task,result):
    result=dict(result)
    result['taskFenceToken']=task['taskFenceToken']
    return req(base+f"/agent/v1/clusters/{cluster_id}/baseline-tasks/{task['deploymentId']}/result",'POST',result,{'Authorization':'Bearer '+agent_token,'If-Match':f'"{task["deploymentRevision"]}"'})

def collected_evidence(task):
    out=[]
    for spec in task.get('evidencePlan',{}).get('artifacts',[]):
        payload={'key':spec['key'],'status':'PASS'}
        raw=json.dumps(payload,separators=(',',':'),ensure_ascii=False).encode()
        out.append({'key':spec['key'],'kind':spec['kind'],'resource':spec.get('resource',''),'authority':spec['authority'],'digest':'sha256:'+hashlib.sha256(raw).hexdigest(),'mediaType':spec['mediaType'],'location':spec['outputLocation'],'size':len(raw),'required':spec['required'],'retentionDays':spec['retentionDays'],'payload':payload})
    return out

def create_and_apply_baseline(base, project_id, cluster_id, agent_token, version, key):
    st,created,_=req(base+'/api/v1/baseline-deployments','POST',{'projectId':project_id,'clusterId':cluster_id,'baselineId':'secure-namespace-foundation','baselineVersion':version},{'X-Actor-ID':'operator','Idempotency-Key':key}); assert st==201,(st,created)
    dep=created['deployment']
    st,plan,_=req(base+f'/agent/v1/clusters/{cluster_id}/baseline-tasks/next',headers={'Authorization':'Bearer '+agent_token}); assert st==200 and plan['action']=='PLAN',(st,plan)
    st,planned,_=post_task_result(base,cluster_id,agent_token,plan,(lambda ch:{'action':'PLAN','success':True,'changes':ch,'impact':planning_impact(plan,ch)})([{'resource':'ConfigMap/4so-baseline-revision','action':'ADD','desiredDigest':dep['desiredDigest']}])); assert st==200 and planned['state']=='AWAITING_APPROVAL',(st,planned)
    st,approved,_=req(base+f"/api/v1/baseline-deployments/{dep['id']}/approve",'POST',{}, {'X-Actor-ID':'approver','X-Actor-Role':'platform-admin','If-Match':f'"{planned["revision"]}"'}); assert st==200 and approved['state']=='QUEUED',(st,approved)
    st,apply,_=req(base+f'/agent/v1/clusters/{cluster_id}/baseline-tasks/next',headers={'Authorization':'Bearer '+agent_token}); assert st==200 and apply['action']=='APPLY',(st,apply)
    st,done,_=post_task_result(base,cluster_id,agent_token,apply,{'action':'APPLY','success':True,'observedDigest':apply['desiredDigest'],'evidence':collected_evidence(apply)}); assert st==200 and done['state']=='SUCCEEDED',(st,done)
    return done

def main():
    if len(sys.argv)!=2: raise SystemExit('usage: smoke_plan_safety.py platform-api')
    binary=Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as td:
        state=Path(td)/'state.json'; p,base=start(binary,state); enrollment=agent_token=''
        try:
            st,ver,_=req(base+'/api/v1/version'); assert st==200; version=ver['version']
            st,org,_=req(base+'/api/v1/organizations','POST',{'name':'plan-safety-smoke','displayName':'Plan Safety Smoke'}); assert st==201,(st,org)
            st,project,_=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'prod','displayName':'Production'}); assert st==201,(st,project)
            st,created,_=req(base+'/api/v1/cluster-imports','POST',{'projectId':project['id'],'name':'edge-1','displayName':'Edge 1'}); assert st==201,(st,created)
            enrollment=created['enrollmentToken']; imp=created['import']
            st,_,_=req(base+f"/api/v1/cluster-imports/{imp['id']}/approve",'POST',{}, {'If-Match':'1'}); assert st==200
            st,claimed,_=req(base+f"/agent/v1/cluster-imports/{imp['id']}/claim",'POST',{'token':enrollment,'externalUid':'plan-safety-cluster','agentVersion':version}); assert st==200,(st,claimed)
            cluster=claimed['cluster']; agent_token=claimed['agentToken']
            activate_mutation_rbac(base,cluster['id'],agent_token,inventory(external_uid='plan-safety-cluster'))
            stable=create_and_apply_baseline(base,project['id'],cluster['id'],agent_token,'1.0.0','safe-baseline-100')

            now=dt.datetime.now(dt.timezone.utc); start_at=now+dt.timedelta(minutes=30); end_at=now+dt.timedelta(hours=2)
            st,cp,_=req(base+'/api/v1/recovery-checkpoints','POST',{'projectId':project['id'],'clusterId':cluster['id'],'provider':'s3','reference':'backup/edge-1/001','evidenceDigest':'sha256:'+'d'*64,'completedAt':iso(now-dt.timedelta(minutes=5)),'expiresAt':iso(now+dt.timedelta(hours=4))},{'X-Actor-ID':'operator'}); assert st==201,(st,cp)
            st,group,_=req(base+'/api/v1/fleet-groups','POST',{'projectId':project['id'],'name':'safe-fleet','displayName':'Safe Fleet','clusterIds':[cluster['id']]},{'X-Actor-ID':'operator','Idempotency-Key':'safe-fleet'}); assert st==201,(st,group); group=group['fleetGroup']
            st,created_campaign,_=req(base+'/api/v1/upgrade-campaigns','POST',{'projectId':project['id'],'fleetGroupId':group['id'],'baselineId':'secure-namespace-foundation','targetVersion':'1.1.0','canaryCount':1,'waveSize':1,'haltAfterFailures':1,'maintenanceWindowStart':iso(start_at),'maintenanceWindowEnd':iso(end_at),'recoveryCheckpointIds':[cp['id']]},{'X-Actor-ID':'operator','Idempotency-Key':'safe-upgrade'}); assert st==201,(st,created_campaign)
            campaign=created_campaign['campaign']; assert campaign['planContextDigest'].startswith('sha256:') and campaign['targetInventoryDigests'][cluster['id']],campaign
            st,approved_campaign,_=req(base+f"/api/v1/upgrade-campaigns/{campaign['id']}/approve",'POST',{}, {'X-Actor-ID':'approver','X-Actor-Role':'platform-admin','If-Match':f'"{campaign["revision"]}"'}); assert st==200,(st,approved_campaign)
            st,blocked,_=req(base+f"/api/v1/upgrade-campaigns/{campaign['id']}/advance",'POST',{}, {'X-Actor-ID':'operator','If-Match':f'"{approved_campaign["revision"]}"'}); assert st==409 and blocked.get('error',{}).get('code')=='MAINTENANCE_WINDOW_CLOSED',(st,blocked)

            # Prove an approved baseline cannot silently APPLY after its observed inventory changes.
            st,created_import2,_=req(base+'/api/v1/cluster-imports','POST',{'projectId':project['id'],'name':'edge-2','displayName':'Edge 2'}); assert st==201,(st,created_import2)
            enrollment2=created_import2['enrollmentToken']; imp2=created_import2['import']
            st,_,_=req(base+f"/api/v1/cluster-imports/{imp2['id']}/approve",'POST',{}, {'If-Match':'1'}); assert st==200
            st,claimed2,_=req(base+f"/agent/v1/cluster-imports/{imp2['id']}/claim",'POST',{'token':enrollment2,'externalUid':'plan-safety-cluster-2','agentVersion':version}); assert st==200,(st,claimed2)
            cluster2=claimed2['cluster']; token2=claimed2['agentToken']
            activate_mutation_rbac(base,cluster2['id'],token2,inventory(external_uid='plan-safety-cluster-2'))
            st,created2,_=req(base+'/api/v1/baseline-deployments','POST',{'projectId':project['id'],'clusterId':cluster2['id'],'baselineId':'secure-namespace-foundation','baselineVersion':'1.0.0'},{'X-Actor-ID':'operator','Idempotency-Key':'safe-baseline-edge2'}); assert st==201,(st,created2); dep2=created2['deployment']
            st,plan2,_=req(base+f'/agent/v1/clusters/{cluster2["id"]}/baseline-tasks/next',headers={'Authorization':'Bearer '+token2}); assert st==200 and plan2['action']=='PLAN',(st,plan2)
            st,planned2,_=post_task_result(base,cluster2['id'],token2,plan2,(lambda ch:{'action':'PLAN','success':True,'changes':ch,'impact':planning_impact(plan2,ch)})([{'resource':'ConfigMap/4so-baseline-revision','action':'ADD','desiredDigest':dep2['desiredDigest']}])); assert st==200,(st,planned2)
            st,approved2,_=req(base+f"/api/v1/baseline-deployments/{dep2['id']}/approve",'POST',{}, {'X-Actor-ID':'approver-2','X-Actor-Role':'platform-admin','If-Match':f'"{planned2["revision"]}"'}); assert st==200 and approved2['state']=='QUEUED',(st,approved2)
            drift_inventory=inventory('1.19', external_uid='plan-safety-cluster-2')
            st,drifted_authority,_=req(base+f"/agent/v1/clusters/{cluster2['id']}/inventory",'POST',drift_inventory,{'Authorization':'Bearer '+token2}); assert st==200,(st,drifted_authority)
            # Add-on/runtime telemetry drift changes the task inventory digest and forces
            # plan revalidation, but it must not revoke stable mutation RBAC authority.
            assert drifted_authority['cluster'].get('mutationRbacIssuedForDigest','').startswith('sha256:') and 'target-mutation-rbac-active' in drifted_authority['cluster'].get('capabilities',[]),drifted_authority
            st,replanned,_=req(base+f'/agent/v1/clusters/{cluster2["id"]}/baseline-tasks/next',headers={'Authorization':'Bearer '+token2}); assert st==200 and replanned['action']=='PLAN' and replanned['deploymentId']==dep2['id'],(st,replanned)
            st,dep_after,_=req(base+f"/api/v1/baseline-deployments/{dep2['id']}"); assert st==200 and dep_after['state']=='PLANNING' and not dep_after.get('approvedBy') and dep_after['planRevalidationCount']>=1,(st,dep_after)

            # Mutating the campaign target inventory invalidates its old recovery checkpoint/context.
            st,_,_=req(base+f"/agent/v1/clusters/{cluster['id']}/inventory",'POST',inventory('1.19', external_uid='plan-safety-cluster'),{'Authorization':'Bearer '+agent_token}); assert st==200,st
            st,stale,_=req(base+f"/api/v1/upgrade-campaigns/{campaign['id']}/revalidate",'POST',{'maintenanceWindowStart':iso(start_at),'maintenanceWindowEnd':iso(end_at),'recoveryCheckpointIds':[cp['id']]},{'X-Actor-ID':'operator','If-Match':f'"{approved_campaign["revision"]}"'}); assert st==422 and stale.get('error',{}).get('code')=='PREREQUISITE_NOT_SATISFIED',(st,stale)
            now2=dt.datetime.now(dt.timezone.utc)
            st,cp2,_=req(base+'/api/v1/recovery-checkpoints','POST',{'projectId':project['id'],'clusterId':cluster['id'],'provider':'s3','reference':'backup/edge-1/002','evidenceDigest':'sha256:'+'e'*64,'completedAt':iso(now2-dt.timedelta(minutes=1)),'expiresAt':iso(now2+dt.timedelta(hours=5))},{'X-Actor-ID':'operator'}); assert st==201,(st,cp2)
            new_start=now2+dt.timedelta(minutes=45); new_end=now2+dt.timedelta(hours=2)
            st,revalidated,_=req(base+f"/api/v1/upgrade-campaigns/{campaign['id']}/revalidate",'POST',{'maintenanceWindowStart':iso(new_start),'maintenanceWindowEnd':iso(new_end),'recoveryCheckpointIds':[cp2['id']]},{'X-Actor-ID':'operator','If-Match':f'"{approved_campaign["revision"]}"'}); assert st==200 and revalidated['state']=='AWAITING_APPROVAL' and revalidated['planRevalidationCount']>=1,(st,revalidated)
            assert revalidated['planContextDigest']!=campaign['planContextDigest']
            campaign_id=campaign['id']; cp2_id=cp2['id']; plan_context=revalidated['planContextDigest']
        finally:
            stop(p)
        p,base=start(binary,state)
        try:
            st,persisted,_=req(base+f'/api/v1/upgrade-campaigns/{campaign_id}'); assert st==200 and persisted['planContextDigest']==plan_context and persisted['planRevalidationCount']>=1,(st,persisted)
            st,persisted_cp,_=req(base+f'/api/v1/recovery-checkpoints/{cp2_id}'); assert st==200 and persisted_cp['state']=='VERIFIED',(st,persisted_cp)
            print('PLAN_SAFETY_MAINTENANCE_SMOKE_PASS',campaign_id,plan_context,stable['id'])
        finally:
            stop(p)
    return 0
if __name__=='__main__': raise SystemExit(main())
