#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, sys, tempfile
from pathlib import Path
from smoke_plan_safety import req, start, stop, inventory, activate_mutation_rbac, planning_impact, post_task_result, collected_evidence


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: smoke_evidence_collection_completion.py platform-api')
    binary=Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as td:
        p,base=start(binary,Path(td)/'state.json')
        try:
            st,ver,_=req(base+'/api/v1/version'); assert st==200,(st,ver); version=ver['version']
            st,org,_=req(base+'/api/v1/organizations','POST',{'name':'evidence-authority-smoke','displayName':'Evidence Authority Smoke'}); assert st==201,(st,org)
            st,project,_=req(base+'/api/v1/projects','POST',{'organizationId':org['id'],'name':'prod','displayName':'Production'}); assert st==201,(st,project)
            st,created,_=req(base+'/api/v1/cluster-imports','POST',{'projectId':project['id'],'name':'evidence-cluster','displayName':'Evidence Cluster'}); assert st==201,(st,created)
            imp=created['import']
            st,_,_=req(base+f"/api/v1/cluster-imports/{imp['id']}/approve",'POST',{}, {'If-Match':'1'}); assert st==200,st
            st,claimed,_=req(base+f"/agent/v1/cluster-imports/{imp['id']}/claim",'POST',{'token':created['enrollmentToken'],'externalUid':'evidence-authority-cluster','agentVersion':version}); assert st==200,(st,claimed)
            cluster,token=claimed['cluster'],claimed['agentToken']
            activate_mutation_rbac(base,cluster['id'],token,inventory(external_uid='evidence-authority-cluster'))
            st,created_dep,_=req(base+'/api/v1/baseline-deployments','POST',{'projectId':project['id'],'clusterId':cluster['id'],'baselineId':'secure-namespace-foundation','baselineVersion':'1.0.0'},{'X-Actor-ID':'operator','Idempotency-Key':'evidence-authority-baseline'}); assert st==201,(st,created_dep)
            dep=created_dep['deployment']
            st,plan,_=req(base+f"/agent/v1/clusters/{cluster['id']}/baseline-tasks/next",headers={'Authorization':'Bearer '+token}); assert st==200 and plan['action']=='PLAN',(st,plan)
            changes=[{'resource':f"{r['kind']}/{r['name']}",'action':'ADD','desiredDigest':plan['desiredDigest']} for r in plan.get('resources',[])]
            impact=planning_impact(plan,changes)
            evidence_plan=impact['evidence']
            assert evidence_plan['status']=='PASS' and evidence_plan['method']=='BASELINE_EVIDENCE_COLLECTION_V1' and evidence_plan['requiredCount']==len(plan['resources'])+1,evidence_plan
            assert all(a['required'] and a['retentionDays']==90 and a['outputLocation'].startswith(f"/api/v1/baseline-deployments/{dep['id']}/evidence/") for a in evidence_plan['artifacts']),evidence_plan
            st,planned,_=post_task_result(base,cluster['id'],token,plan,{'action':'PLAN','success':True,'changes':changes,'impact':impact}); assert st==200 and planned['state']=='AWAITING_APPROVAL',(st,planned)
            st,approved,_=req(base+f"/api/v1/baseline-deployments/{dep['id']}/approve",'POST',{}, {'X-Actor-ID':'approver','X-Actor-Role':'platform-admin','If-Match':f'"{planned["revision"]}"'}); assert st==200 and approved['state']=='QUEUED',(st,approved)
            st,apply,_=req(base+f"/agent/v1/clusters/{cluster['id']}/baseline-tasks/next",headers={'Authorization':'Bearer '+token}); assert st==200 and apply['action']=='APPLY',(st,apply)
            assert apply.get('evidencePlan',{}).get('digest')==evidence_plan['digest'] and apply.get('planImpactDigest')==planned['planImpactDigest'],apply

            # Missing completion evidence must not be accepted as a successful APPLY.
            st,rejected,_=post_task_result(base,cluster['id'],token,apply,{'action':'APPLY','success':True,'observedDigest':apply['desiredDigest']})
            assert st==422 and rejected.get('error',{}).get('code') in ('VALIDATION_FAILED','VALIDATION_ERROR'),(st,rejected)

            evidence=collected_evidence(apply)
            tampered=json.loads(json.dumps(evidence))
            tampered[0]['payload']={'key':tampered[0]['key'],'status':'TAMPERED'}
            st,rejected2,_=post_task_result(base,cluster['id'],token,apply,{'action':'APPLY','success':True,'observedDigest':apply['desiredDigest'],'evidence':tampered})
            assert st==422,(st,rejected2)

            st,done,_=post_task_result(base,cluster['id'],token,apply,{'action':'APPLY','success':True,'observedDigest':apply['desiredDigest'],'evidence':evidence})
            assert st==200 and done['state']=='SUCCEEDED' and done.get('evidenceDigest','').startswith('sha256:') and len(done.get('evidence',[]))==len(evidence),(st,done)
            first=done['evidence'][0]
            assert first.get('collectedAt') and first.get('retainUntil'),first
            st,payload,h=req(base+first['location'])
            assert st==200 and h.get('X-Evidence-Digest')==first['digest'] and h.get('X-Evidence-Authority')==first['authority'] and h.get('X-Evidence-Retain-Until'),(st,payload,h)
            raw=json.dumps(payload,separators=(',',':'),ensure_ascii=False).encode()
            assert 'sha256:'+hashlib.sha256(raw).hexdigest()==first['digest'],(payload,first)
            print('EVIDENCE_COLLECTION_COMPLETION_AUTHORITY_SMOKE_PASS',dep['id'],done['evidenceDigest'],len(done['evidence']))
        finally:
            stop(p)
    return 0

if __name__=='__main__': raise SystemExit(main())
