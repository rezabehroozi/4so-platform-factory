#!/usr/bin/env python3
from __future__ import annotations
import datetime as dt, sys, tempfile
from pathlib import Path

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()
from smoke_plan_safety import req, start, stop, iso, inventory, activate_mutation_rbac, create_and_apply_baseline, post_task_result, planning_impact, collected_evidence


def claim_cluster(base, project_id, name, version):
    st, created, _ = req(base+'/api/v1/cluster-imports','POST',{'projectId':project_id,'name':name,'displayName':name})
    assert st == 201, (st, created)
    enrollment, imp = created['enrollmentToken'], created['import']
    st, _, _ = req(base+f"/api/v1/cluster-imports/{imp['id']}/approve",'POST',{}, {'If-Match':'1'})
    assert st == 200, st
    st, claimed, _ = req(base+f"/agent/v1/cluster-imports/{imp['id']}/claim",'POST',{'token':enrollment,'externalUid':'upgrade-control-'+name,'agentVersion':version})
    assert st == 200, (st, claimed)
    cluster, token = claimed['cluster'], claimed['agentToken']
    activate_mutation_rbac(base,cluster['id'],token,inventory(external_uid='upgrade-control-'+name))
    create_and_apply_baseline(base, project_id, cluster['id'], token, '1.0.0', 'control-baseline-'+name)
    return cluster, token


def advance(base, campaign):
    st, value, _ = req(base+f"/api/v1/upgrade-campaigns/{campaign['id']}/advance",'POST',{}, {'X-Actor-ID':'operator','If-Match':f'"{campaign["revision"]}"'})
    assert st == 200, (st, value)
    return value


def complete_active(base, campaign, cluster_id, token):
    st, task, _ = req(base+f'/agent/v1/clusters/{cluster_id}/baseline-tasks/next',headers={'Authorization':'Bearer '+token})
    assert st == 200 and task['action'] == 'PLAN', (st, task)
    st, planned, _ = post_task_result(base,cluster_id,token,task,(lambda ch:{'action':'PLAN','success':True,'changes':ch,'impact':planning_impact(task,ch)})([{'resource':'ResourceQuota/4so-baseline-quota','action':'UPDATE','desiredDigest':task['desiredDigest']}]))
    assert st == 200 and planned['state'] == 'AWAITING_APPROVAL', (st, planned)
    campaign = advance(base, campaign)
    st, task, _ = req(base+f'/agent/v1/clusters/{cluster_id}/baseline-tasks/next',headers={'Authorization':'Bearer '+token})
    assert st == 200 and task['action'] == 'APPLY', (st, task)
    st, done, _ = post_task_result(base,cluster_id,token,task,{'action':'APPLY','success':True,'observedDigest':task['desiredDigest'],'evidence':collected_evidence(task)})
    assert st == 200 and done['state'] == 'SUCCEEDED', (st, done)
    campaign = advance(base, campaign)
    st, verification, _ = req(base+f'/agent/v1/clusters/{cluster_id}/runtime-verification-tasks/next',headers={'Authorization':'Bearer '+token})
    assert st == 200, (st, verification)
    checks=[{'key':'baseline-digest-equality','status':'PASS'},{'key':'baseline-resources-present','status':'PASS'},{'key':'nodes-ready','status':'PASS'},{'key':'probe-job-created','status':'PASS'},{'key':'probe-job-completed','status':'PASS'},{'key':'cluster-dns','status':'PASS'},{'key':'kubernetes-api-service-tcp','status':'PASS'}]
    st, verified, _ = req(base+f"/agent/v1/clusters/{cluster_id}/runtime-verification-tasks/{verification['verificationId']}/result",'POST',{'taskFenceToken':verification['taskFenceToken'],'success':True,'observedDigest':verification['desiredDigest'],'checks':checks},{'Authorization':'Bearer '+token,'If-Match':f'"{verification["verificationRevision"]}"'})
    assert st == 200 and verified['state'] == 'SUCCEEDED', (st, verified)
    return advance(base, campaign)


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: smoke_upgrade_control.py platform-api')
    binary=Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as td:
        state=Path(td)/'state.json'
        p,base=start(binary,state)
        try:
            st,ver,_=req(base+'/api/v1/version'); assert st==200; version=ver['version']; assert version==EXPECTED_VERSION,version
            st,org,_=req(base+'/api/v1/organizations','POST',{'name':'upgrade-control-smoke','displayName':'Upgrade Control Smoke'}); assert st==201,(st,org)
            st,project,_=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'prod','displayName':'Production'}); assert st==201,(st,project)
            cluster_tokens=[]
            for name in ('edge-a','edge-b','edge-c'):
                cluster_tokens.append(claim_cluster(base,project['id'],name,version))
            now=dt.datetime.now(dt.timezone.utc)
            checkpoint_ids=[]
            for i,(cluster,_) in enumerate(cluster_tokens):
                st,cp,_=req(base+'/api/v1/recovery-checkpoints','POST',{'projectId':project['id'],'clusterId':cluster['id'],'provider':'s3','reference':f'upgrade-control/{cluster["id"]}/backup','evidenceDigest':'sha256:'+format(9400+i,'064x'),'completedAt':iso(now-dt.timedelta(minutes=5)),'expiresAt':iso(now+dt.timedelta(hours=4))},{'X-Actor-ID':'operator'})
                assert st==201,(st,cp); checkpoint_ids.append(cp['id'])
            st,g,_=req(base+'/api/v1/fleet-groups','POST',{'projectId':project['id'],'name':'control-fleet','displayName':'Control Fleet','clusterIds':[c['id'] for c,_ in cluster_tokens]},{'X-Actor-ID':'operator','Idempotency-Key':'control-fleet'}); assert st==201,(st,g); group=g['fleetGroup']
            st,created,_=req(base+'/api/v1/upgrade-campaigns','POST',{'projectId':project['id'],'fleetGroupId':group['id'],'baselineId':'secure-namespace-foundation','targetVersion':'1.1.0','canaryCount':1,'waveSize':1,'haltAfterFailures':1,'maintenanceWindowStart':iso(now-dt.timedelta(minutes=1)),'maintenanceWindowEnd':iso(now+dt.timedelta(hours=2)),'recoveryCheckpointIds':checkpoint_ids},{'X-Actor-ID':'operator','Idempotency-Key':'upgrade-control-campaign'}); assert st==201,(st,created)
            campaign=created['campaign']
            st,campaign,_=req(base+f"/api/v1/upgrade-campaigns/{campaign['id']}/approve",'POST',{}, {'X-Actor-ID':'approver','X-Actor-Role':'platform-admin','If-Match':f'"{campaign["revision"]}"'}); assert st==200,(st,campaign)
            campaign=advance(base,campaign)
            wave1=next(t for t in campaign['targets'] if t['wave']==1)
            token_by_id={c['id']:token for c,token in cluster_tokens}
            assert wave1['state']=='PLANNING',wave1
            st,campaign,_=req(base+f"/api/v1/upgrade-campaigns/{campaign['id']}/pause",'POST',{'reason':'maintenance observation'},{'X-Actor-ID':'operator','If-Match':f'"{campaign["revision"]}"'}); assert st==200 and campaign['state']=='PAUSE_REQUESTED',(st,campaign)
            campaign=complete_active(base,campaign,wave1['clusterId'],token_by_id[wave1['clusterId']])
            assert campaign['state']=='PAUSED' and campaign['currentWave']==1 and campaign['pauseCount']==1,campaign
            campaign_id=campaign['id']; started_at=campaign['startedAt']; paused_revision=campaign['revision']
        finally:
            stop(p)

        # First restart proves PAUSED/currentWave/StartedAt durability.
        p,base=start(binary,state)
        try:
            st,campaign,_=req(base+f'/api/v1/upgrade-campaigns/{campaign_id}'); assert st==200 and campaign['state']=='PAUSED' and campaign['revision']==paused_revision,(st,campaign)
            assert campaign['currentWave']==1 and campaign['startedAt']==started_at,campaign
            st,campaign,_=req(base+f"/api/v1/upgrade-campaigns/{campaign_id}/resume",'POST',{}, {'X-Actor-ID':'operator','If-Match':f'"{campaign["revision"]}"'}); assert st==200 and campaign['state']=='QUEUED',(st,campaign)
            assert campaign['currentWave']==1 and campaign['startedAt']==started_at,campaign
            campaign=advance(base,campaign)
            assert campaign['currentWave']==2 and campaign['state']=='RUNNING',campaign
            campaign=advance(base,campaign)
            wave2=next(t for t in campaign['targets'] if t['wave']==2)
            assert wave2['state']=='PLANNING',wave2
            st,campaign,_=req(base+f"/api/v1/upgrade-campaigns/{campaign_id}/cancel",'POST',{'reason':'bounded rollout cancel'},{'X-Actor-ID':'operator','If-Match':f'"{campaign["revision"]}"'}); assert st==200 and campaign['state']=='CANCEL_REQUESTED',(st,campaign)
            campaign=complete_active(base,campaign,wave2['clusterId'],token_by_id[wave2['clusterId']])
            assert campaign['state']=='CANCELLED' and campaign['cancelledAt'] and campaign['finishedAt'],campaign
            wave3=next(t for t in campaign['targets'] if t['wave']==3)
            assert wave3['state']=='PENDING' and not wave3.get('upgradeDeploymentId'),wave3
            assert sum(1 for t in campaign['targets'] if t['state']=='SUCCEEDED')==2,campaign['targets']
            cancelled_revision=campaign['revision']
        finally:
            stop(p)

        # Second restart proves terminal bounded-cancel durability.
        p,base=start(binary,state)
        try:
            st,persisted,_=req(base+f'/api/v1/upgrade-campaigns/{campaign_id}'); assert st==200,(st,persisted)
            assert persisted['state']=='CANCELLED' and persisted['revision']==cancelled_revision,persisted
            wave3=next(t for t in persisted['targets'] if t['wave']==3)
            assert wave3['state']=='PENDING' and not wave3.get('upgradeDeploymentId'),wave3
            print('UPGRADE_PAUSE_RESUME_CANCEL_SMOKE_PASS',campaign_id,persisted['currentWave'],persisted['pauseCount'])
        finally:
            stop(p)
    return 0

if __name__=='__main__':
    raise SystemExit(main())
