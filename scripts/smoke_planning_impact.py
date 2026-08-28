#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, sys, tempfile
from pathlib import Path
from smoke_plan_safety import req, start, stop, inventory, planning_impact, post_task_result



def redigest_capability(impact):
    value=json.loads(json.dumps(impact['capability']))
    value['digest']=''
    raw=json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
    impact['capability']['digest']='sha256:'+hashlib.sha256(raw).hexdigest()

def redigest_rollback(impact):
    value=json.loads(json.dumps(impact['rollback']))
    value['digest']=''
    raw=json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
    impact['rollback']['digest']='sha256:'+hashlib.sha256(raw).hexdigest()
    return impact


def redigest(impact):
    value=json.loads(json.dumps(impact))
    value['digest']=''
    raw=json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
    impact['digest']='sha256:'+hashlib.sha256(raw).hexdigest()
    return impact


def claim_cluster(base, project_id, name, version):
    st, created, _=req(base+'/api/v1/cluster-imports','POST',{'projectId':project_id,'name':name,'displayName':name})
    assert st==201,(st,created)
    imp=created['import']
    st,_,_=req(base+f"/api/v1/cluster-imports/{imp['id']}/approve",'POST',{}, {'If-Match':'1'})
    assert st==200,st
    st,claimed,_=req(base+f"/agent/v1/cluster-imports/{imp['id']}/claim",'POST',{'token':created['enrollmentToken'],'externalUid':'planning-impact-'+name,'agentVersion':version})
    assert st==200,(st,claimed)
    cluster,token=claimed['cluster'],claimed['agentToken']
    activated=inventory(external_uid='planning-impact-'+name)
    initial=json.loads(json.dumps(activated))
    initial['capabilities']=[c for c in initial.get('capabilities',[]) if c!='target-mutation-rbac-active']
    st,reported,_=req(base+f"/agent/v1/clusters/{cluster['id']}/inventory",'POST',initial,{'Authorization':'Bearer '+token})
    assert st==200,(st,reported)
    st,activation,_=req(base+f"/api/v1/clusters/{cluster['id']}/mutation-rbac-manifest",'POST',{},headers={'X-Actor-ID':'operator'})
    assert st==200 and '4so-platform-baseline-manager' in activation.get('manifest',''),(st,activation)
    st,reported,_=req(base+f"/agent/v1/clusters/{cluster['id']}/inventory",'POST',activated,{'Authorization':'Bearer '+token})
    assert st==200,(st,reported)
    return cluster,token


def plan_all_adds(task):
    return [{'resource':f"{r['kind']}/{r['name']}",'action':'ADD','desiredDigest':task['desiredDigest']} for r in task.get('resources',[])]


def main():
    if len(sys.argv)!=2: raise SystemExit('usage: smoke_planning_impact.py platform-api')
    binary=Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as td:
        state=Path(td)/'state.json'; p,base=start(binary,state)
        try:
            st,ver,_=req(base+'/api/v1/version'); assert st==200,(st,ver); version=ver['version']
            st,org,_=req(base+'/api/v1/organizations','POST',{'name':'planning-impact-smoke','displayName':'Planning Impact Smoke'}); assert st==201,(st,org)
            st,project,_=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'prod','displayName':'Production'}); assert st==201,(st,project)
            cluster,token=claim_cluster(base,project['id'],'impact-a',version)
            st,created,_=req(base+'/api/v1/baseline-deployments','POST',{'projectId':project['id'],'clusterId':cluster['id'],'baselineId':'secure-namespace-foundation','baselineVersion':'1.0.0'},{'X-Actor-ID':'operator','Idempotency-Key':'planning-impact-good'}); assert st==201,(st,created)
            dep=created['deployment']
            st,task,_=req(base+f"/agent/v1/clusters/{cluster['id']}/baseline-tasks/next",headers={'Authorization':'Bearer '+token}); assert st==200 and task['action']=='PLAN',(st,task)
            assert task['inventory']['apiDiscoveryComplete'] is True and task['inventory']['crdDiscoveryComplete'] is True,task['inventory']
            assert len(task['inventory']['apiResources'])>=5,task['inventory']
            changes=plan_all_adds(task); impact=planning_impact(task,changes)
            st,planned,_=post_task_result(base,cluster['id'],token,task,{'action':'PLAN','success':True,'changes':changes,'impact':impact})
            assert st==200 and planned['state']=='AWAITING_APPROVAL',(st,planned)
            assert planned['planImpactDigest']==planned['planImpact']['digest'] and planned['planImpact']['approvalReady'] is True,planned
            assert len(planned['planImpact']['api'])==len(task['resources']),planned['planImpact']
            assert all(row.get('schema',{}).get('status')=='PASS' and row.get('schema',{}).get('method')=='KUBE_APISERVER_DRY_RUN_STRICT' and row.get('schema',{}).get('httpStatus')==200 for row in planned['planImpact']['api']),planned['planImpact']['api']
            assert all(row.get('schema',{}).get('schemaIndexVersion')==task['inventory']['schemaDiscoveryVersion'] and row.get('schema',{}).get('schemaIndexDigest')==task['inventory']['schemaDiscoveryDigest'] for row in planned['planImpact']['api']),planned['planImpact']['api']
            compatibility=planned['planImpact']['compatibility']
            assert compatibility['status']=='PASS' and compatibility['method']=='PLATFORM_COMPATIBILITY_MATRIX_V1',compatibility
            assert compatibility['target']=={'kubernetesVersion':'1.34','architecture':'amd64','distribution':'rke2','provider':'imported'},compatibility
            assert len(compatibility['checks'])==4 and all(row.get('status')=='PASS' for row in compatibility['checks']),compatibility
            capability=planned['planImpact']['capability']
            assert capability['status']=='PASS' and capability['method']=='CLUSTER_CAPABILITY_PREFLIGHT_V1',capability
            required=[row for row in capability['checks'] if row.get('required')]
            assert required and all(row.get('status')=='PASS' for row in required),capability
            network=[row for row in capability['checks'] if row.get('key')=='network-policy-enforcement']
            assert network and network[0].get('required') is True and network[0].get('status')=='PASS',capability
            assert any(e.startswith('cni:') for e in network[0].get('evidence',[])),network[0]
            rollback=planned['planImpact']['rollback']
            assert rollback['status']=='PASS' and rollback['method']=='KUBE_ROLLBACK_FEASIBILITY_V1',rollback
            assert len(rollback['resources'])==len(task['resources']) and all(row.get('status')=='PASS' and row.get('strategy')=='DELETE_CREATED_RESOURCE' and row.get('authorizationStatus')=='PASS' for row in rollback['resources']),rollback
            assert planned['planImpact']['disruption']['level']=='MEDIUM',planned['planImpact']['disruption']
            assert planned['planImpact']['disruption']['maintenanceRecommendation']=='RECOMMENDED',planned['planImpact']['disruption']
            assert planned['planImpact']['capacity']['currentUsageKnown'] is False,planned['planImpact']['capacity']
            assert planned['planImpact']['capacity']['demandDeltaKnown'] is True,planned['planImpact']['capacity']
            st,audit,_=req(base+'/api/v1/audit-events?limit=100'); assert st==200,(st,audit)
            event=next((e for e in audit if e.get('resourceId')==dep['id'] and e.get('action')=='baseline_deployment.awaiting_approval'),None)
            assert event and event.get('metadata',{}).get('planImpactDigest')==planned['planImpactDigest'],event
            st,approved,_=req(base+f"/api/v1/baseline-deployments/{dep['id']}/approve",'POST',{}, {'X-Actor-ID':'approver','X-Actor-Role':'platform-admin','If-Match':f'"{planned["revision"]}"'})
            assert st==200 and approved['state']=='QUEUED',(st,approved)
            good_id=dep['id']; good_digest=planned['planImpactDigest']

            # A self-consistent but semantically tampered impact must be rejected by API authority.
            cluster2,token2=claim_cluster(base,project['id'],'impact-b',version)
            st,created2,_=req(base+'/api/v1/baseline-deployments','POST',{'projectId':project['id'],'clusterId':cluster2['id'],'baselineId':'secure-namespace-foundation','baselineVersion':'1.0.0'},{'X-Actor-ID':'operator','Idempotency-Key':'planning-impact-tamper'}); assert st==201,(st,created2)
            dep2=created2['deployment']
            st,task2,_=req(base+f"/agent/v1/clusters/{cluster2['id']}/baseline-tasks/next",headers={'Authorization':'Bearer '+token2}); assert st==200,(st,task2)
            changes2=plan_all_adds(task2); tampered=planning_impact(task2,changes2)
            tampered['api'][0]['message']='tampered agent claim'; redigest(tampered)
            st,rejected,_=post_task_result(base,cluster2['id'],token2,task2,{'action':'PLAN','success':True,'changes':changes2,'impact':tampered})
            assert st==422 and rejected.get('error',{}).get('code')=='PLAN_IMPACT_INVALID',(st,rejected)

            # Schema evidence is independently inventory-bound; a self-redigested schema authority tamper is rejected.
            cluster3,token3=claim_cluster(base,project['id'],'impact-c',version)
            st,created3,_=req(base+'/api/v1/baseline-deployments','POST',{'projectId':project['id'],'clusterId':cluster3['id'],'baselineId':'secure-namespace-foundation','baselineVersion':'1.0.0'},{'X-Actor-ID':'operator','Idempotency-Key':'planning-impact-schema-tamper'}); assert st==201,(st,created3)
            dep3=created3['deployment']
            st,task3,_=req(base+f"/agent/v1/clusters/{cluster3['id']}/baseline-tasks/next",headers={'Authorization':'Bearer '+token3}); assert st==200,(st,task3)
            changes3=plan_all_adds(task3); schema_tampered=planning_impact(task3,changes3)
            schema_tampered['api'][0]['schema']['schemaIndexDigest']='sha256:'+'1'*64; redigest(schema_tampered)
            st,rejected_schema,_=post_task_result(base,cluster3['id'],token3,task3,{'action':'PLAN','success':True,'changes':changes3,'impact':schema_tampered})
            assert st==422 and rejected_schema.get('error',{}).get('code')=='PLAN_IMPACT_INVALID',(st,rejected_schema)

            # Rollback feasibility is independently semantic-bound; self-redigested authorization tamper is rejected.
            cluster4,token4=claim_cluster(base,project['id'],'impact-d',version)
            st,created4,_=req(base+'/api/v1/baseline-deployments','POST',{'projectId':project['id'],'clusterId':cluster4['id'],'baselineId':'secure-namespace-foundation','baselineVersion':'1.0.0'},{'X-Actor-ID':'operator','Idempotency-Key':'planning-impact-rollback-tamper'}); assert st==201,(st,created4)
            st,task4,_=req(base+f"/agent/v1/clusters/{cluster4['id']}/baseline-tasks/next",headers={'Authorization':'Bearer '+token4}); assert st==200,(st,task4)
            changes4=plan_all_adds(task4); rollback_tampered=planning_impact(task4,changes4)
            rollback_tampered['rollback']['resources'][0]['authorizationStatus']='DENIED'
            redigest_rollback(rollback_tampered); redigest(rollback_tampered)
            st,rejected_rollback,_=post_task_result(base,cluster4['id'],token4,task4,{'action':'PLAN','success':True,'changes':changes4,'impact':rollback_tampered})
            assert st==422 and rejected_rollback.get('error',{}).get('code')=='PLAN_IMPACT_INVALID',(st,rejected_rollback)


            cluster5,token5=claim_cluster(base,project['id'],'impact-e',version)
            st,created5,_=req(base+'/api/v1/baseline-deployments','POST',{'projectId':project['id'],'clusterId':cluster5['id'],'baselineId':'secure-namespace-foundation','baselineVersion':'1.0.0'},{'X-Actor-ID':'operator','Idempotency-Key':'planning-impact-capability-tamper'}); assert st==201,(st,created5)
            st,task5,_=req(base+f"/agent/v1/clusters/{cluster5['id']}/baseline-tasks/next",headers={'Authorization':'Bearer '+token5}); assert st==200 and task5['action']=='PLAN',(st,task5)
            changes5=plan_all_adds(task5); capability_tampered=planning_impact(task5,changes5)
            capability_tampered['capability']['checks'][0]['detail']='self-redigested-tamper'
            redigest_capability(capability_tampered); redigest(capability_tampered)
            st,rejected_capability,_=post_task_result(base,cluster5['id'],token5,task5,{'action':'PLAN','success':True,'changes':changes5,'impact':capability_tampered})
            assert st==422 and rejected_capability.get('error',{}).get('code')=='PLAN_IMPACT_INVALID',(st,rejected_capability)

            cluster6,token6=claim_cluster(base,project['id'],'impact-f',version)
            st,created6,_=req(base+'/api/v1/baseline-deployments','POST',{'projectId':project['id'],'clusterId':cluster6['id'],'baselineId':'secure-namespace-foundation','baselineVersion':'1.0.0'},{'X-Actor-ID':'operator','Idempotency-Key':'planning-impact-compatibility-tamper'}); assert st==201,(st,created6)
            st,task6,_=req(base+f"/agent/v1/clusters/{cluster6['id']}/baseline-tasks/next",headers={'Authorization':'Bearer '+token6}); assert st==200 and task6['action']=='PLAN',(st,task6)
            changes6=plan_all_adds(task6); compatibility_tampered=planning_impact(task6,changes6)
            compatibility_tampered['compatibility']['checks'][0]['message']='self-redigested compatibility tamper'
            from smoke_plan_safety import redigest_compatibility
            redigest_compatibility(compatibility_tampered); redigest(compatibility_tampered)
            st,rejected_compatibility,_=post_task_result(base,cluster6['id'],token6,task6,{'action':'PLAN','success':True,'changes':changes6,'impact':compatibility_tampered})
            assert st==422 and rejected_compatibility.get('error',{}).get('code')=='PLAN_IMPACT_INVALID',(st,rejected_compatibility)
        finally:
            stop(p)

        # Durable evidence survives restart without re-analysis drift.
        p,base=start(binary,state)
        try:
            st,persisted,_=req(base+f'/api/v1/baseline-deployments/{good_id}'); assert st==200,(st,persisted)
            assert persisted['state']=='QUEUED' and persisted['planImpactDigest']==good_digest,persisted
            assert persisted['planImpact']['disruption']['maintenanceRecommendation']=='RECOMMENDED',persisted['planImpact']
            print('PLANNING_IMPACT_DISRUPTION_SMOKE_PASS',good_id,good_digest,persisted['planImpact']['disruption']['level'])
        finally:
            stop(p)
    return 0

if __name__=='__main__': raise SystemExit(main())
