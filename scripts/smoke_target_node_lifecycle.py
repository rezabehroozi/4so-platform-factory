#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import sys
import tempfile
from pathlib import Path

from smoke_cluster_maintenance import OIDCTestIssuer, activate_mutation_rbac, bearer, inventory, req, start, stop

EXPECTED_VERSION = (Path(__file__).resolve().parents[1] / "VERSION").read_text().strip()


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: smoke_target_node_lifecycle.py platform-api")
    binary = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as td:
        state = Path(td) / "state.json"
        oidc = OIDCTestIssuer()
        tokens = {name: oidc.token(name) for name in ("admin", "import-approver", "requester", "approver")}
        process, base = start(binary, state, oidc)
        try:
            status, mapping = req(
                base + "/api/v1/identity/group-mappings",
                "POST",
                {"group": "platform-admins", "productRole": "platform-admin"},
                {"X-Platform-Bootstrap-Token": "identity-smoke-bootstrap-token-00000001"},
            )[:2]
            assert status in (200, 201), (status, mapping)
            status, version = req(base + "/api/v1/version", headers=bearer(tokens["admin"]))
            assert status == 200 and version["version"] == EXPECTED_VERSION, (status, version)
            status, org = req(base + "/api/v1/organizations", "POST", {"name": "node-lifecycle-runtime", "displayName": "Node Lifecycle Runtime"}, bearer(tokens["admin"]))
            assert status == 201, (status, org)
            status, project = req(base + "/api/v1/projects", "POST", {"organizationId": org["id"], "name": "prod", "displayName": "Production"}, bearer(tokens["admin"]))
            assert status == 201, (status, project)
            status, created = req(base + "/api/v1/cluster-imports", "POST", {"projectId": project["id"], "name": "lifecycle", "displayName": "Lifecycle"}, bearer(tokens["admin"]))
            assert status == 201, (status, created)
            imp, enrollment = created["import"], created["enrollmentToken"]
            status, _ = req(base + f"/api/v1/cluster-imports/{imp['id']}/approve", "POST", {}, {**bearer(tokens["import-approver"]), "If-Match": f'"{imp["revision"]}"'})
            assert status == 200, status
            status, claimed = req(base + f"/agent/v1/cluster-imports/{imp['id']}/claim", "POST", {"token": enrollment, "externalUid": "node-lifecycle-runtime", "agentVersion": EXPECTED_VERSION})
            assert status == 200, (status, claimed)
            cluster, agent = claimed["cluster"], claimed["agentToken"]
            desired = inventory("target-node-lifecycle")
            desired["externalUid"] = "node-lifecycle-runtime"
            desired["observedAt"] = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
            desired["capabilities"].extend(["target-node-host-maintenance-executor-v1", "target-node-os-patch"])
            activate_mutation_rbac(base, cluster["id"], agent, desired, tokens["admin"])

            status, authority = req(base + f"/api/v1/clusters/{cluster['id']}/node-lifecycle-authority", headers=bearer(tokens["admin"]))
            assert status == 200 and authority["authority"] == "TARGET_NODE_LIFECYCLE_AUTHORITY_V1", (status, authority)
            assert authority["physicalCertificationStatus"] == "DEFERRED_UNTIL_DEVELOPMENT_CLOSURE", authority
            actions = {entry["action"]: entry for entry in authority["actions"]}
            assert len(actions) == 7 and actions["DRAIN"]["executable"] is True, actions
            for pending in ("ADD", "REMOVE", "REPLACE", "CERTIFICATE_RENEWAL", "REMEDIATE"):
                assert actions[pending]["executable"] is False and (actions[pending].get("blockers") or actions[pending].get("missingCapabilities")), (pending, actions[pending])
            assert actions["OS_PATCH"]["executable"] is True and actions["OS_PATCH"].get("blockers", []) == [], actions["OS_PATCH"]

            status, drain = req(base + f"/api/v1/clusters/{cluster['id']}/node-lifecycle-plans", "POST", {"action": "DRAIN", "nodeName": "worker-1"}, bearer(tokens["admin"]))
            assert status == 200 and drain["executable"] is True and drain["nodeUid"] == "worker-1" and drain["planDigest"].startswith("sha256:"), (status, drain)
            status, patch = req(base + f"/api/v1/clusters/{cluster['id']}/node-lifecycle-plans", "POST", {"action": "OS_PATCH", "nodeName": "worker-1"}, bearer(tokens["admin"]))
            assert status == 200 and patch["executable"] is True and patch["executor"] == "cluster-agent-host-maintenance-job" and patch.get("blockers", []) == [], (status, patch)
            status, unknown = req(base + f"/api/v1/clusters/{cluster['id']}/node-lifecycle-plans", "POST", {"action": "DRAIN", "nodeName": "ghost"}, bearer(tokens["admin"]))
            assert status != 200, (status, unknown)

            status, profile = req(base + f"/api/v1/clusters/{cluster['id']}/maintenance-profile", "PUT", {"environment": "PRODUCTION", "defaultDrainTimeoutSeconds": 120}, bearer(tokens["admin"]))
            assert status == 200, (status, profile)
            now = dt.datetime.now(dt.timezone.utc)
            status, window = req(base + f"/api/v1/clusters/{cluster['id']}/maintenance-windows", "POST", {"name": "os-patch", "startsAt": (now-dt.timedelta(minutes=1)).isoformat().replace("+00:00","Z"), "endsAt": (now+dt.timedelta(hours=2)).isoformat().replace("+00:00","Z"), "maxUnavailable": 1, "drainTimeoutSeconds": 120}, bearer(tokens["admin"]))
            assert status == 201, (status, window)
            status, created_run = req(base + f"/api/v1/clusters/{cluster['id']}/maintenance-runs", "POST", {"windowId": window["id"], "action": "OS_PATCH", "nodeNames": ["worker-1"]}, {**bearer(tokens["requester"]), "Idempotency-Key": "os-patch-runtime-1"})
            assert status == 201 and created_run["run"]["action"] == "OS_PATCH" and created_run["run"]["hostActionTimeoutSeconds"] == 3600, (status, created_run)
            run = created_run["run"]
            status, denied = req(base + f"/api/v1/clusters/{cluster['id']}/maintenance-runs/{run['id']}/approve", "POST", {}, {**bearer(tokens["requester"]), "If-Match": f'"{run["revision"]}"'})
            assert status == 403, (status, denied)
            status, approved = req(base + f"/api/v1/clusters/{cluster['id']}/maintenance-runs/{run['id']}/approve", "POST", {}, {**bearer(tokens["approver"]), "If-Match": f'"{run["revision"]}"'})
            assert status == 200 and approved["run"]["state"] == "QUEUED", (status, approved)
            status, task = req(base + f"/agent/v1/clusters/{cluster['id']}/maintenance-tasks/next", headers={"Authorization": "Bearer "+agent})
            assert status == 200 and task["action"] == "OS_PATCH" and task["hostActionTimeoutSeconds"] == 3600, (status, task)
            missing = {"operationFenceToken": task["operationFenceToken"], "success": True, "results": [{"nodeName": "worker-1", "cordoned": True, "drainAttempted": True, "drained": True, "uncordoned": True}]}
            status, rejected = req(base + f"/agent/v1/clusters/{cluster['id']}/maintenance-tasks/{run['id']}/result", "POST", missing, {"Authorization": "Bearer "+agent, "If-Match": f'"{task["runRevision"]}"'})
            assert status == 422, (status, rejected)
            valid = {"operationFenceToken": task["operationFenceToken"], "success": True, "results": [{"nodeName": "worker-1", "cordoned": True, "drainAttempted": True, "drained": True, "uncordoned": True, "hostActionAttempted": True, "hostActionSucceeded": True, "hostActionAuthority": "TARGET_NODE_HOST_MAINTENANCE_EXECUTOR_V1", "hostActionEvidence": "Job/4so-os-patch-runtime@uid:sha256:" + "a"*64, "rebootRequired": True}]}
            status, finished = req(base + f"/agent/v1/clusters/{cluster['id']}/maintenance-tasks/{run['id']}/result", "POST", valid, {"Authorization": "Bearer "+agent, "If-Match": f'"{task["runRevision"]}"'})
            assert status == 200 and finished["run"]["state"] == "SUCCEEDED" and finished["run"]["results"][0]["rebootRequired"] is True, (status, finished)
            print("TARGET_NODE_OS_PATCH_RUNTIME_SMOKE_PASS", cluster["id"], run["id"], patch["planDigest"])
        finally:
            stop(process)
            oidc.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
