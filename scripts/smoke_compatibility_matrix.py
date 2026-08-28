#!/usr/bin/env python3
from __future__ import annotations
import json, sys, tempfile
from pathlib import Path

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip()
from smoke_plan_safety import req, start, stop
from smoke_planning_impact import claim_cluster


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: smoke_compatibility_matrix.py platform-api')
    binary = Path(sys.argv[1]).resolve()
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as td:
        state = Path(td) / 'state.json'
        p, base = start(binary, state)
        try:
            st, ver, _ = req(base + '/api/v1/version')
            assert st == 200 and ver['version'] == EXPECTED_VERSION, (st, ver)
            blueprint = json.loads((root / 'blueprints/enterprise-private-cloud.json').read_text())
            target = {'kubernetesVersion':'v1.34.9','architecture':'amd64','distribution':'rke2','provider':'imported'}
            st, out, _ = req(base + '/api/v1/compatibility/evaluate', 'POST', {'blueprint':blueprint,'target':target})
            assert st == 200 and out['authority'] == 'PLATFORM_COMPATIBILITY_MATRIX_V1' and out['serverReconstructed'] is True, (st, out)
            decision = out['decision']
            assert decision['status'] == 'PASS' and decision['target'] == {'kubernetesVersion':'1.34','architecture':'amd64','distribution':'rke2','provider':'imported'}, decision
            assert decision['digest'].startswith('sha256:') and all(x['status']=='PASS' for x in decision['checks']), decision
            bad_target = dict(target); bad_target['provider'] = 'unsupported-provider'
            st, rejected, _ = req(base + '/api/v1/compatibility/evaluate', 'POST', {'blueprint':blueprint,'target':bad_target})
            assert st == 422 and rejected['decision']['status'] == 'FAIL', (st, rejected)
            assert any(x['dimension']=='provider' and x['status']=='FAIL' for x in rejected['decision']['checks']), rejected

            st, org, _ = req(base + '/api/v1/organizations', 'POST', {'name':'compatibility-smoke','displayName':'Compatibility Smoke'})
            assert st == 201, (st, org)
            st, project, _ = req(base + '/api/v1/projects', 'POST', {'organizationId':org['id'],'name':'platform','displayName':'Platform'})
            assert st == 201, (st, project)
            management, token = claim_cluster(base, project['id'], 'compatibility-management', ver['version'])
            profile_payload = {
                'projectId':project['id'],'managementClusterId':management['id'],'name':'capi-standard','displayName':'CAPI Standard',
                'clusterClassName':'standard','workerClassName':'worker-standard','defaultKubernetesVersion':'v1.34.9',
                'kubernetesSeries':['v1.34','v1.35'],'architectures':['amd64'],'distributionProfiles':['rke2'],'maxWorkerReplicas':20,
            }
            st, created, _ = req(base + '/api/v1/provider-profiles', 'POST', profile_payload, {'X-Actor-ID':'admin','X-Actor-Role':'platform-admin','Idempotency-Key':'compat-profile'})
            assert st == 201, (st, created)
            profile = created['providerProfile']
            assert profile['architectures'] == ['amd64'] and profile['distributionProfiles'] == ['rke2'], profile
            st, task, headers = req(base + f"/agent/v1/clusters/{management['id']}/provider-profile-tasks/next", headers={'Authorization':'Bearer '+token})
            assert st == 200 and task['profileId'] == profile['id'], (st, task)
            st, ready, _ = req(base + f"/agent/v1/clusters/{management['id']}/provider-profile-tasks/{profile['id']}/result", 'POST', {'taskFenceToken':task['taskFenceToken'],'success':True,'observedDigest':'sha256:'+'a'*64,'observedVersion':'cluster.x-k8s.io/v1beta2'}, {'Authorization':'Bearer '+token,'If-Match':str(task['profileRevision'])})
            assert st == 200 and ready['state'] == 'READY', (st, ready)
            cluster_payload = {'projectId':project['id'],'providerProfileId':profile['id'],'name':'compatible-a','displayName':'Compatible A','kubernetesVersion':'v1.34.9','architecture':'amd64','distribution':'rke2','controlPlaneReplicas':3,'workerReplicas':3}
            st, created_cluster, _ = req(base + '/api/v1/provider-clusters', 'POST', cluster_payload, {'X-Actor-ID':'operator','Idempotency-Key':'compat-cluster'})
            assert st == 201, (st, created_cluster)
            cluster = created_cluster['providerCluster']
            assert cluster['compatibility']['method'] == 'PLATFORM_COMPATIBILITY_MATRIX_V1' and cluster['compatibility']['status'] == 'PASS', cluster
            assert cluster['compatibility']['target'] == {'kubernetesVersion':'1.34','architecture':'amd64','distribution':'rke2','provider':'cluster-api-topology-v1beta2'}, cluster['compatibility']
            incompatible = dict(cluster_payload); incompatible.update({'name':'arm64-denied','displayName':'ARM64 denied','architecture':'arm64'})
            st, denied, _ = req(base + '/api/v1/provider-clusters', 'POST', incompatible, {'X-Actor-ID':'operator','Idempotency-Key':'compat-cluster-denied'})
            assert st == 422 and denied.get('error',{}).get('code') == 'VALIDATION_FAILED', (st, denied)
            cluster_id = cluster['id']; digest = cluster['compatibility']['digest']
        finally:
            stop(p)
        p, base = start(binary, state)
        try:
            st, persisted, _ = req(base + f'/api/v1/provider-clusters/{cluster_id}')
            assert st == 200 and persisted['compatibility']['status'] == 'PASS' and persisted['compatibility']['digest'] == digest, (st, persisted)
            assert persisted['desired']['architecture'] == 'amd64' and persisted['desired']['distribution'] == 'rke2', persisted
            print('COMPATIBILITY_MATRIX_AUTHORITY_SMOKE_PASS', cluster_id, digest)
        finally:
            stop(p)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
