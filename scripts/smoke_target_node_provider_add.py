#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import sys
import tempfile
from pathlib import Path

from smoke_cluster_maintenance import OIDCTestIssuer, activate_mutation_rbac, bearer, inventory, req, start, stop

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / "VERSION").read_text().strip()


def enroll(base, project_id, name, external_uid, creator_token, approver_token):
    status, created = req(base + "/api/v1/cluster-imports", "POST", {"projectId": project_id, "name": name, "displayName": name}, bearer(creator_token))
    assert status == 201, (status, created)
    imp, enrollment = created["import"], created["enrollmentToken"]
    status, _ = req(base + f"/api/v1/cluster-imports/{imp['id']}/approve", "POST", {}, {**bearer(approver_token), "If-Match": f'"{imp["revision"]}"'})
    assert status == 200, status
    status, claimed = req(base + f"/agent/v1/cluster-imports/{imp['id']}/claim", "POST", {"token": enrollment, "externalUid": external_uid, "agentVersion": EXPECTED_VERSION})
    assert status == 200, (status, claimed)
    return claimed["cluster"], claimed["agentToken"]


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: smoke_target_node_provider_add.py platform-api")
    binary = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as td:
        state = Path(td) / "state.json"
        oidc = OIDCTestIssuer()
        tokens = {name: oidc.token(name) for name in ("admin", "operator", "approver")}
        process, base = start(binary, state, oidc)
        try:
            status, mapping = req(base + "/api/v1/identity/group-mappings", "POST", {"group": "platform-admins", "productRole": "platform-admin"}, {"X-Platform-Bootstrap-Token": "identity-smoke-bootstrap-token-00000001"})[:2]
            assert status in (200, 201), (status, mapping)
            status, version = req(base + "/api/v1/version", headers=bearer(tokens["admin"]))
            assert status == 200 and version["version"] == EXPECTED_VERSION, (status, version)
            status, org = req(base + "/api/v1/organizations", "POST", {"name": "provider-add-runtime", "displayName": "Provider Add Runtime"}, bearer(tokens["admin"]))
            assert status == 201, (status, org)
            status, project = req(base + "/api/v1/projects", "POST", {"organizationId": org["id"], "name": "prod", "displayName": "Production"}, bearer(tokens["admin"]))
            assert status == 201, (status, project)

            management, management_agent = enroll(base, project["id"], "management", "provider-add-management", tokens["admin"], tokens["approver"])
            management_inventory = inventory("provider-add-management")
            management_inventory["externalUid"] = "provider-add-management"
            management_inventory["observedAt"] = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
            management_inventory["capabilities"].append("provider-machine-lifecycle-v1")
            activate_mutation_rbac(base, management["id"], management_agent, management_inventory, tokens["admin"])

            profile_body = {"projectId": project["id"], "managementClusterId": management["id"], "name": "runtime-standard", "displayName": "Runtime Standard", "clusterClassName": "runtime-standard", "workerClassName": "worker-standard", "defaultKubernetesVersion": "v1.34.9", "kubernetesSeries": ["v1.34"], "maxWorkerReplicas": 8}
            status, created_profile = req(base + "/api/v1/provider-profiles", "POST", profile_body, {**bearer(tokens["admin"]), "Idempotency-Key": "provider-add-profile"})
            assert status == 201, (status, created_profile)
            profile = created_profile["providerProfile"]
            status, profile_task = req(base + f"/agent/v1/clusters/{management['id']}/provider-profile-tasks/next", headers={"Authorization": "Bearer " + management_agent})
            assert status == 200, (status, profile_task)
            status, profile = req(base + f"/agent/v1/clusters/{management['id']}/provider-profile-tasks/{profile['id']}/result", "POST", {"taskFenceToken": profile_task["taskFenceToken"], "success": True, "observedDigest": "sha256:" + "c" * 64, "observedVersion": "cluster.x-k8s.io/v1beta2"}, {"Authorization": "Bearer " + management_agent, "If-Match": f'"{profile_task["profileRevision"]}"'})
            assert status == 200 and profile["state"] == "READY", (status, profile)

            cluster_body = {"projectId": project["id"], "providerProfileId": profile["id"], "name": "customer-runtime", "displayName": "Customer Runtime", "kubernetesVersion": "v1.34.9", "controlPlaneReplicas": 3, "workerReplicas": 3}
            status, created_provider = req(base + "/api/v1/provider-clusters", "POST", cluster_body, {**bearer(tokens["operator"]), "Idempotency-Key": "provider-add-cluster"})
            assert status == 201, (status, created_provider)
            provider = created_provider["providerCluster"]
            status, provider = req(base + f"/api/v1/provider-clusters/{provider['id']}/approve", "POST", {}, {**bearer(tokens["approver"]), "If-Match": f'"{provider["revision"]}"'})
            assert status == 200, (status, provider)
            status, task = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/next", headers={"Authorization": "Bearer " + management_agent})
            assert status == 200 and task["action"] == "APPLY", (status, task)
            status, provider = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/{provider['id']}/result", "POST", {"taskFenceToken": task["taskFenceToken"], "action": "APPLY", "success": True, "observedDigest": task["desiredDigest"], "phase": "Provisioning"}, {"Authorization": "Bearer " + management_agent, "If-Match": f'"{task["clusterRevision"]}"'})
            assert status == 200, (status, provider)
            status, task = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/next", headers={"Authorization": "Bearer " + management_agent})
            assert status == 200 and task["action"] == "INSPECT", (status, task)
            status, provider = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/{provider['id']}/result", "POST", {"taskFenceToken": task["taskFenceToken"], "action": "INSPECT", "success": True, "ready": True, "observedDigest": task["desiredDigest"], "phase": "Provisioned"}, {"Authorization": "Bearer " + management_agent, "If-Match": f'"{task["clusterRevision"]}"'})
            assert status == 200 and provider["state"] == "ACTIVE" and provider["applied"]["workerReplicas"] == 3, (status, provider)

            target, target_agent = enroll(base, project["id"], "customer-target", "provider-add-target", tokens["admin"], tokens["approver"])
            target_inventory = inventory("provider-add-target")
            target_inventory["externalUid"] = "provider-add-target"
            target_inventory["observedAt"] = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
            status, _ = req(base + f"/agent/v1/clusters/{target['id']}/inventory", "POST", target_inventory, {"Authorization": "Bearer " + target_agent})
            assert status == 200, status
            status, current = req(base + f"/api/v1/clusters/{target['id']}", headers=bearer(tokens["admin"]))
            assert status == 200, (status, current)
            target = current["cluster"]

            status, pre = req(base + f"/api/v1/clusters/{target['id']}/node-lifecycle-authority", headers=bearer(tokens["admin"]))
            assert status == 200 and pre["providerBindingReady"] is False, (status, pre)
            add_pre = next(action for action in pre["actions"] if action["action"] == "ADD")
            assert add_pre["executable"] is False and "TARGET_NODE_PROVIDER_BINDING_PENDING" in add_pre.get("blockers", []), add_pre

            status, bound = req(base + f"/api/v1/clusters/{target['id']}/provider-binding", "POST", {"providerClusterId": provider["id"]}, {**bearer(tokens["admin"]), "If-Match": f'"{target["revision"]}"'})
            assert status == 200 and bound["authority"] == "TARGET_NODE_PROVIDER_BINDING_AUTHORITY_V1", (status, bound)
            status, post = req(base + f"/api/v1/clusters/{target['id']}/node-lifecycle-authority", headers=bearer(tokens["admin"]))
            assert status == 200 and post["providerBindingReady"] is True, (status, post)
            actions = {action["action"]: action for action in post["actions"]}
            assert actions["ADD"]["executable"] is True and actions["REMOVE"]["executable"] is True and actions["REPLACE"]["executable"] is True, actions

            add_headers = {**bearer(tokens["operator"]), "Idempotency-Key": "target-node-add-runtime"}
            status, add = req(base + f"/api/v1/clusters/{target['id']}/node-lifecycle-actions", "POST", {"action": "ADD"}, add_headers)
            assert status == 202 and add["providerCluster"]["desired"]["workerReplicas"] == 4 and add["idempotentReplay"] is False, (status, add)
            status, replay = req(base + f"/api/v1/clusters/{target['id']}/node-lifecycle-actions", "POST", {"action": "ADD"}, add_headers)
            assert status == 200 and replay["idempotentReplay"] is True and replay["providerCluster"]["desired"]["workerReplicas"] == 4, (status, replay)
            provider_add = add["providerCluster"]
            status, _ = req(base + f"/api/v1/provider-clusters/{provider_add['id']}/approve", "POST", {}, {**bearer(tokens["approver"]), "If-Match": f'"{provider_add["revision"]}"'})
            assert status == 200, status
            status, add_task = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/next", headers={"Authorization": "Bearer " + management_agent})
            assert status == 200 and add_task["action"] == "APPLY" and not add_task.get("targetNodeMutation", {}).get("action"), (status, add_task)
            status, _ = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/{provider_add['id']}/result", "POST", {"taskFenceToken":add_task["taskFenceToken"],"action":"APPLY","success":True,"observedDigest":add_task["desiredDigest"],"phase":"ScalingWorkers"}, {"Authorization":"Bearer "+management_agent,"If-Match":f'"{add_task["clusterRevision"]}"'})
            assert status == 200, status
            status, add_inspect = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/next", headers={"Authorization": "Bearer " + management_agent})
            assert status == 200 and add_inspect["action"] == "INSPECT", (status, add_inspect)
            status, add_done = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/{provider_add['id']}/result", "POST", {"taskFenceToken":add_inspect["taskFenceToken"],"action":"INSPECT","success":True,"ready":True,"observedDigest":add_inspect["desiredDigest"],"phase":"Provisioned"}, {"Authorization":"Bearer "+management_agent,"If-Match":f'"{add_inspect["clusterRevision"]}"'})
            assert status == 200 and add_done["state"] == "ACTIVE" and add_done["applied"]["workerReplicas"] == 4, (status, add_done)
            status, replay_after = req(base + f"/api/v1/clusters/{target['id']}/node-lifecycle-actions", "POST", {"action": "ADD"}, add_headers)
            assert status == 200 and replay_after["idempotentReplay"] is True and replay_after["providerCluster"]["desired"]["workerReplicas"] == 4, (status, replay_after)
            print("TARGET_NODE_PROVIDER_ADD_RUNTIME_SMOKE_PASS", target["id"], provider["id"], add["plan"]["planDigest"])

            status, profile_out = req(base + f"/api/v1/clusters/{target['id']}/maintenance-profile", "PUT", {"environment": "PRODUCTION", "defaultDrainTimeoutSeconds": 120}, bearer(tokens["admin"]))
            assert status == 200, (status, profile_out)
            now = dt.datetime.now(dt.timezone.utc)
            status, window = req(base + f"/api/v1/clusters/{target['id']}/maintenance-windows", "POST", {"name": "provider-machine-runtime", "startsAt": (now-dt.timedelta(minutes=1)).isoformat().replace("+00:00","Z"), "endsAt": (now+dt.timedelta(hours=1)).isoformat().replace("+00:00","Z"), "maxUnavailable": 1, "drainTimeoutSeconds": 120}, bearer(tokens["admin"]))
            assert status == 201, (status, window)
            replace_headers = {**bearer(tokens["operator"]), "Idempotency-Key": "target-node-replace-runtime"}
            status, replace = req(base + f"/api/v1/clusters/{target['id']}/node-lifecycle-actions", "POST", {"action": "REPLACE", "nodeName": "worker-1", "windowId": window["id"]}, replace_headers)
            assert status == 202 and replace["providerCluster"]["pendingAction"] == "TARGET_NODE_REPLACE" and replace["providerCluster"]["desired"]["workerReplicas"] == 4, (status, replace)
            provider_replace = replace["providerCluster"]
            status, approved_replace = req(base + f"/api/v1/provider-clusters/{provider_replace['id']}/approve", "POST", {}, {**bearer(tokens["approver"]), "If-Match": f'"{provider_replace["revision"]}"'})
            assert status == 200, (status, approved_replace)
            status, replace_task = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/next", headers={"Authorization": "Bearer " + management_agent})
            assert status == 200 and replace_task["targetNodeMutation"]["authority"] == "TARGET_NODE_PROVIDER_MACHINE_LIFECYCLE_V1" and replace_task["targetNodeMutation"]["nodeUid"] == "worker-1", (status, replace_task)
            mutation = dict(replace_task["targetNodeMutation"]); mutation.update({"machineName":"machine-worker-1","machineUid":"machine-uid-worker-1","machineResourceVersion":"51","machineSetName":"md-0-abc","machineDeploymentName":"md-0","evidenceDigest":"sha256:"+"e"*64})
            status, replacing = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/{provider_replace['id']}/result", "POST", {"taskFenceToken":replace_task["taskFenceToken"],"action":"APPLY","success":True,"observedDigest":replace_task["desiredDigest"],"phase":"Replacing","targetNodeMutation":mutation}, {"Authorization":"Bearer "+management_agent,"If-Match":f'"{replace_task["clusterRevision"]}"'})
            assert status == 200 and replacing["state"] == "RECONCILING", (status, replacing)
            status, replace_inspect = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/next", headers={"Authorization":"Bearer "+management_agent})
            assert status == 200 and replace_inspect["action"] == "INSPECT" and replace_inspect["targetNodeMutation"]["machineUid"] == "machine-uid-worker-1", (status, replace_inspect)
            status, replaced = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/{provider_replace['id']}/result", "POST", {"taskFenceToken":replace_inspect["taskFenceToken"],"action":"INSPECT","success":True,"ready":True,"observedDigest":replace_inspect["desiredDigest"],"phase":"Provisioned","targetNodeMutation":mutation}, {"Authorization":"Bearer "+management_agent,"If-Match":f'"{replace_inspect["clusterRevision"]}"'})
            assert status == 200 and replaced["state"] == "ACTIVE" and replaced["applied"]["workerReplicas"] == 4, (status, replaced)
            print("TARGET_NODE_PROVIDER_MACHINE_RUNTIME_SMOKE_PASS", target["id"], provider["id"], mutation["evidenceDigest"])

            # Certificate Renewal is a healthy one-for-one exact CAPI Machine replacement.
            cert_headers = {**bearer(tokens["operator"]), "Idempotency-Key": "target-node-certificate-renewal-runtime"}
            status, cert = req(base + f"/api/v1/clusters/{target['id']}/node-lifecycle-actions", "POST", {"action": "CERTIFICATE_RENEWAL", "nodeName": "worker-2", "windowId": window["id"]}, cert_headers)
            assert status == 202 and cert["providerCluster"]["pendingAction"] == "TARGET_NODE_CERTIFICATE_RENEWAL", (status, cert)
            provider_cert = cert["providerCluster"]
            status, _ = req(base + f"/api/v1/provider-clusters/{provider_cert['id']}/approve", "POST", {}, {**bearer(tokens["approver"]), "If-Match": f'"{provider_cert["revision"]}"'})
            assert status == 200, status
            status, cert_task = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/next", headers={"Authorization": "Bearer " + management_agent})
            assert status == 200 and cert_task["action"] == "APPLY" and cert_task["targetNodeMutation"]["action"] == "CERTIFICATE_RENEWAL", (status, cert_task)
            cert_mutation = dict(cert_task["targetNodeMutation"]); cert_mutation.update({"machineName":"machine-worker-2","machineUid":"machine-uid-worker-2","machineResourceVersion":"61","machineSetName":"md-0-def","machineDeploymentName":"md-0","evidenceDigest":"sha256:"+"c"*64})
            status, _ = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/{provider_cert['id']}/result", "POST", {"taskFenceToken":cert_task["taskFenceToken"],"action":"APPLY","success":True,"observedDigest":cert_task["desiredDigest"],"phase":"RenewingCertificateByReplacement","targetNodeMutation":cert_mutation}, {"Authorization":"Bearer "+management_agent,"If-Match":f'"{cert_task["clusterRevision"]}"'})
            assert status == 200, status
            status, cert_inspect = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/next", headers={"Authorization":"Bearer "+management_agent})
            assert status == 200 and cert_inspect["action"] == "INSPECT" and cert_inspect["targetNodeMutation"]["action"] == "CERTIFICATE_RENEWAL", (status, cert_inspect)
            status, cert_done = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/{provider_cert['id']}/result", "POST", {"taskFenceToken":cert_inspect["taskFenceToken"],"action":"INSPECT","success":True,"ready":True,"observedDigest":cert_inspect["desiredDigest"],"phase":"Provisioned","targetNodeMutation":cert_mutation}, {"Authorization":"Bearer "+management_agent,"If-Match":f'"{cert_inspect["clusterRevision"]}"'})
            assert status == 200 and cert_done["state"] == "ACTIVE", (status, cert_done)

            # Remediation is intentionally admitted only for a NotReady worker.
            remediation_inventory = inventory("provider-remediation")
            remediation_inventory["externalUid"] = "provider-add-target"
            remediation_inventory["observedAt"] = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
            remediation_inventory["nodes"][0]["ready"] = False
            status, _ = req(base + f"/agent/v1/clusters/{target['id']}/inventory", "POST", remediation_inventory, {"Authorization": "Bearer " + target_agent})
            assert status == 200, status
            status, healthy_reject = req(base + f"/api/v1/clusters/{target['id']}/node-lifecycle-actions", "POST", {"action": "REMEDIATE", "nodeName": "worker-2", "windowId": window["id"]}, {**bearer(tokens["operator"]), "Idempotency-Key": "target-node-remediation-healthy-negative"})
            assert status in (409, 412, 422) and healthy_reject.get("error"), (status, healthy_reject)
            remediate_headers = {**bearer(tokens["operator"]), "Idempotency-Key": "target-node-remediation-runtime"}
            status, remediate = req(base + f"/api/v1/clusters/{target['id']}/node-lifecycle-actions", "POST", {"action": "REMEDIATE", "nodeName": "worker-1", "windowId": window["id"]}, remediate_headers)
            assert status == 202 and remediate["providerCluster"]["pendingAction"] == "TARGET_NODE_REMEDIATE", (status, remediate)
            provider_remediate = remediate["providerCluster"]
            status, _ = req(base + f"/api/v1/provider-clusters/{provider_remediate['id']}/approve", "POST", {}, {**bearer(tokens["approver"]), "If-Match": f'"{provider_remediate["revision"]}"'})
            assert status == 200, status
            status, remediation_task = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/next", headers={"Authorization": "Bearer " + management_agent})
            assert status == 200 and remediation_task["action"] == "APPLY" and remediation_task["targetNodeMutation"]["action"] == "REMEDIATE", (status, remediation_task)
            remediation_mutation = dict(remediation_task["targetNodeMutation"]); remediation_mutation.update({"machineName":"machine-worker-1-unhealthy","machineUid":"machine-uid-worker-1-unhealthy","machineResourceVersion":"71","machineSetName":"md-0-ghi","machineDeploymentName":"md-0","evidenceDigest":"sha256:"+"d"*64})
            status, _ = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/{provider_remediate['id']}/result", "POST", {"taskFenceToken":remediation_task["taskFenceToken"],"action":"APPLY","success":True,"observedDigest":remediation_task["desiredDigest"],"phase":"RemediatingByReplacement","targetNodeMutation":remediation_mutation}, {"Authorization":"Bearer "+management_agent,"If-Match":f'"{remediation_task["clusterRevision"]}"'})
            assert status == 200, status
            status, remediation_inspect = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/next", headers={"Authorization":"Bearer "+management_agent})
            assert status == 200 and remediation_inspect["action"] == "INSPECT" and remediation_inspect["targetNodeMutation"]["action"] == "REMEDIATE", (status, remediation_inspect)
            status, remediation_done = req(base + f"/agent/v1/clusters/{management['id']}/provider-cluster-tasks/{provider_remediate['id']}/result", "POST", {"taskFenceToken":remediation_inspect["taskFenceToken"],"action":"INSPECT","success":True,"ready":True,"observedDigest":remediation_inspect["desiredDigest"],"phase":"Provisioned","targetNodeMutation":remediation_mutation}, {"Authorization":"Bearer "+management_agent,"If-Match":f'"{remediation_inspect["clusterRevision"]}"'})
            assert status == 200 and remediation_done["state"] == "ACTIVE", (status, remediation_done)
            print("TARGET_NODE_G3_FULL_LIFECYCLE_RUNTIME_SMOKE_PASS", target["id"], provider["id"], cert_mutation["evidenceDigest"], remediation_mutation["evidenceDigest"])
        finally:
            stop(process)
            oidc.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
