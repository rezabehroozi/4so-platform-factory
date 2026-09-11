#!/usr/bin/env python3
"""C4 live end-to-end UX certification over real loopback authorities.

This drives the actual Operator Console and Bootstrap Installer against their real
HTTP APIs. It intentionally uses API/agent calls only for external actors such as
cluster agents and rollback workers; operator mutations under certification are
performed through the browser UI.

This is source/extracted-artifact UX certification, not Exact-SHA Physical PASS.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

from playwright.sync_api import sync_playwright

from smoke_ui_live import api_req, start as start_api, stop as stop_api, inline_console, install_real_api_bridge
from smoke_upgrade_control import claim_cluster, complete_active, advance
from smoke_plan_safety import req as upgrade_req, iso
from oci_smoke_fixture import workload_repositories, write_workload_oci_archive

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = (ROOT / "VERSION").read_text().strip()


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def confirm(page) -> None:
    page.locator("#confirm-dialog[open] #confirm-accept").click()
    page.wait_for_timeout(160)


def create_installer_bundle(root: Path) -> Path:
    bundle = root / "bundle"
    artifacts = bundle / "artifacts"
    artifacts.mkdir(parents=True)
    refs = write_workload_oci_archive(artifacts / "workloads.oci.tar", workload_repositories())

    def manifest(name: str, ref: str) -> bytes:
        return (
            "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n"
            f"      containers:\n        - name: {name}\n          image: {ref}\n"
        ).encode()

    files = {
        "install.sh": b"#!/bin/sh\nexit 0\n",
        "rke2.tar.gz": b"rke2",
        "rke2-images.tar.zst": b"rke2-images",
        "workloads.oci.tar": (artifacts / "workloads.oci.tar").read_bytes(),
        "argocd-install.yaml": manifest("argocd", refs["registry.local/argocd"]),
        "cnpg-install.yaml": manifest("cnpg", refs["registry.local/cnpg"]),
        "storage-install.yaml": manifest("storage", refs["registry.local/storage"]),
    }
    for name, data in files.items():
        (artifacts / name).write_bytes(data)
    images = sorted(refs.values())
    index_artifacts = ["artifacts/" + name for name in files]
    index = {
        "version": EXPECTED_VERSION,
        "images": images,
        "artifacts": index_artifacts,
        "artifactDigests": {"artifacts/" + name: sha(data) for name, data in files.items()},
    }
    (artifacts / "airgap-index.json").write_text(json.dumps(index, sort_keys=True) + "\n")
    files["airgap-index.json"] = (artifacts / "airgap-index.json").read_bytes()
    release_digest = "sha256:" + "7" * 64
    bundle_manifest = {
        "apiVersion": "platform.4so.io/v1alpha1",
        "kind": "ApplianceBundle",
        "metadata": {"version": EXPECTED_VERSION, "sourceReleaseDigest": release_digest},
        "spec": {
            "rke2": {
                "version": "test",
                "installer": {"path": "artifacts/install.sh", "sha256": sha(files["install.sh"])},
                "installArtifacts": [{"path": "artifacts/rke2.tar.gz", "sha256": sha(files["rke2.tar.gz"])}],
                "imageArchives": [{"path": "artifacts/rke2-images.tar.zst", "sha256": sha(files["rke2-images.tar.zst"])}],
            },
            "airgap": {
                "complete": True,
                "index": {"path": "artifacts/airgap-index.json", "sha256": sha(files["airgap-index.json"])},
                "requiredImages": images,
            },
            "workloads": {
                "imageArchives": [{"path": "artifacts/workloads.oci.tar", "sha256": sha(files["workloads.oci.tar"])}],
                "postgresqlImage": refs["registry.local/postgres"],
                "platformApiImage": refs["registry.local/platform-api"],
                "forgejoImage": refs["registry.local/forgejo"],
                "zotImage": refs["registry.local/zot"],
                "keycloakImage": refs["registry.local/keycloak"],
                "maintenanceImage": refs["registry.local/maintenance"],
                "gitOpsManifest": {"path": "artifacts/argocd-install.yaml", "sha256": sha(files["argocd-install.yaml"])},
                "cloudNativePGManifest": {"path": "artifacts/cnpg-install.yaml", "sha256": sha(files["cnpg-install.yaml"])},
                "storageManifest": {"path": "artifacts/storage-install.yaml", "sha256": sha(files["storage-install.yaml"])},
                "fleetAgentImage": refs["registry.local/platform-agent"],
                "runtimeProbeImage": refs["registry.local/platform-probe"],
            },
        },
    }
    manifest_raw = (json.dumps(bundle_manifest, indent=2, sort_keys=True) + "\n").encode()
    (bundle / "bundle.json").write_bytes(manifest_raw)
    artifacts_lock = []
    for rel in sorted(["artifacts/" + name for name in files]):
        raw = (bundle / rel).read_bytes()
        artifacts_lock.append({"path": rel, "sha256": sha(raw), "size": len(raw)})
    lock = {
        "apiVersion": "platform.4so.io/v1alpha1",
        "kind": "ApplianceBundleLock",
        "metadata": {"bundleVersion": EXPECTED_VERSION, "sourceReleaseDigest": release_digest},
        "manifestDigest": sha(manifest_raw),
        "artifacts": artifacts_lock,
        "requiredImages": images,
    }
    (bundle / "bundle.lock.json").write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
    return bundle


def inline_installer(root: Path) -> str:
    static = root / "cmd/platform-installer/static"
    html = (static / "index.html").read_text(encoding="utf-8")
    css = (static / "styles.css").read_text(encoding="utf-8")
    js = (static / "app.js").read_text(encoding="utf-8")
    html = html.replace('<link rel="stylesheet" href="/styles.css">', f"<style>{css}</style>")
    return html.replace('<script src="/app.js"></script>', "<script>" + js.replace("</script>", "<\\/script>") + "</script>")


def start_installer(binary: Path, root: Path):
    bundle = create_installer_bundle(root)
    token = "".join(("c4-bootstrap-", "fixture-token-", "not-a-secret"))
    port = free_port()
    env = os.environ.copy()
    env.update(
        {
            "PLATFORM_INSTALLER_LISTEN": f"127.0.0.1:{port}",
            "PLATFORM_INSTALLER_BUNDLE_DIR": str(bundle),
            "PLATFORM_INSTALLER_STATE_DIR": str(root / "state"),
            "PLATFORM_INSTALLER_SIMULATION": "true",
            "PLATFORM_INSTALLER_SIMULATION_ROOT": str(root / "host"),
            "PLATFORM_INSTALLER_ALLOW_EXECUTION": "true",
            "PLATFORM_INSTALLER_BOOTSTRAP_TOKEN": token,
        }
    )
    process = subprocess.Popen([str(binary)], cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            with urllib.request.urlopen(base + "/healthz", timeout=1) as response:
                if response.status == 200:
                    return process, base, token
        except Exception:
            pass
        time.sleep(0.1)
    process.terminate()
    raise RuntimeError("installer did not become ready")


def stop_process(process) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def seed_blueprint(api_base: str, project_id: str):
    blueprint = json.loads((ROOT / "blueprints/enterprise-private-cloud.json").read_text())
    blueprint["metadata"]["name"] = "c4-publish-smoke"
    blueprint["metadata"]["version"] = "1.0.0"
    blueprint["spec"]["description"] = "C4 live UI Blueprint publish"
    status, created = api_req(api_base, "/api/v1/blueprint-releases", "POST", {"projectId": project_id, "blueprint": blueprint})
    assert status == 201, (status, created)
    return created["release"]


def seed_recovery_operation(api_base: str, project_id: str):
    headers = {"X-Actor-ID": "c4-operator", "Idempotency-Key": "c4-recovery-operation"}
    status, op = api_req(
        api_base,
        "/api/v1/operations",
        "POST",
        {
            "projectId": project_id,
            "kind": "c4.failed.recovery",
            "targetRef": "project:" + project_id,
            "desiredRevision": "sha256:" + "8" * 64,
            "risk": "high",
            "class": "MUTATING",
        },
        headers,
    )
    assert status == 201, (status, op)
    status, op = api_req(api_base, f"/api/v1/operations/{op['id']}/transition", "POST", {"state": "PLANNING"}, {"X-Actor-ID": "c4-operator", "If-Match": f'"{op["revision"]}"'})
    assert status == 200, (status, op)
    status, planned = api_req(
        api_base,
        f"/api/v1/operations/{op['id']}/compensation/plan",
        "POST",
        {
            "steps": [
                {
                    "stepKey": "apply-config",
                    "forwardOrder": 1,
                    "strategy": "AUTOMATIC_ROLLBACK",
                    "action": "restore previous config",
                    "inputDigest": "sha256:" + "9" * 64,
                    "maxAttempts": 2,
                }
            ]
        },
        {"X-Actor-ID": "c4-operator", "If-Match": f'"{op["revision"]}"'},
    )
    assert status == 200, (status, planned)
    op = planned["operation"]
    status, op = api_req(api_base, f"/api/v1/operations/{op['id']}/transition", "POST", {"state": "QUEUED"}, {"X-Actor-ID": "c4-operator", "If-Match": f'"{op["revision"]}"'})
    assert status == 200, (status, op)
    status, lease = api_req(api_base, f"/api/v1/operations/{op['id']}/claim", "POST", {"workerId": "c4-forward", "leaseSeconds": 60}, {"X-Actor-ID": "c4-forward"})
    assert status == 200, (status, lease)
    status, view = api_req(api_base, f"/api/v1/operations/{op['id']}")
    op = view["operation"]
    status, op = api_req(api_base, f"/api/v1/operations/{op['id']}/attempt/start", "POST", {"workerId": "c4-forward", "fenceToken": lease["fenceToken"]}, {"X-Actor-ID": "c4-forward", "If-Match": f'"{op["revision"]}"'})
    assert status == 200, (status, op)
    status, completed = api_req(api_base, f"/api/v1/operations/{op['id']}/compensation/forward/apply-config/complete", "POST", {"workerId": "c4-forward", "fenceToken": lease["fenceToken"]}, {"X-Actor-ID": "c4-forward", "If-Match": f'"{op["revision"]}"'})
    assert status == 200, (status, completed)
    op = completed["operation"]
    status, op = api_req(
        api_base,
        f"/api/v1/operations/{op['id']}/attempt/failure",
        "POST",
        {"workerId": "c4-forward", "fenceToken": lease["fenceToken"], "failure": {"class": "PERMANENT", "code": "C4_FAIL", "message": "synthetic operator recovery certification failure"}},
        {"X-Actor-ID": "c4-forward", "If-Match": f'"{op["revision"]}"'},
    )
    assert status == 200 and op["state"] == "FAILED", (status, op)
    return op


def complete_recovery(api_base: str, operation_id: str):
    status, lease = api_req(api_base, f"/api/v1/operations/{operation_id}/claim", "POST", {"workerId": "c4-rollback", "leaseSeconds": 60}, {"X-Actor-ID": "c4-rollback"})
    assert status == 200, (status, lease)
    status, claim = api_req(api_base, f"/api/v1/operations/{operation_id}/compensation/claim-next", "POST", {"workerId": "c4-rollback", "fenceToken": lease["fenceToken"]}, {"X-Actor-ID": "c4-rollback"})
    assert status == 200, (status, claim)
    step = claim["step"]
    payload = json.dumps({"restored": True, "step": step["stepKey"]}, sort_keys=True).encode()
    status, sealed = api_req(
        api_base,
        f"/api/v1/operations/{operation_id}/steps/compensation/{step['stepKey']}/trace",
        "POST",
        {
            "workerId": "c4-rollback",
            "fenceToken": lease["fenceToken"],
            "traceKey": "c4-rollback-evidence",
            "level": "INFO",
            "eventType": "compensation.readback",
            "message": "previous configuration restored and read back",
            "evidenceKind": "compensation-readback",
            "mediaType": "application/json",
            "payloadBase64": base64.b64encode(payload).decode(),
        },
        {"X-Actor-ID": "c4-rollback"},
    )
    assert status == 201, (status, sealed)
    digest = sealed["evidence"]["digest"]
    status, finished = api_req(
        api_base,
        f"/api/v1/operations/{operation_id}/compensation/{step['stepKey']}/complete",
        "POST",
        {"workerId": "c4-rollback", "fenceToken": lease["fenceToken"], "evidenceDigest": digest},
        {"X-Actor-ID": "c4-rollback"},
    )
    assert status == 200 and finished["operation"]["state"] == "ROLLED_BACK", (status, finished)
    return finished["operation"], sealed["evidence"]


def run_console_journeys(api_binary: Path, evidence_dir: Path, browser_executable: str):
    with tempfile.TemporaryDirectory() as td:
        process, browser_base, api_base = start_api(api_binary, ROOT, Path(td) / "state.json")
        try:
            status, version = api_req(api_base, "/api/v1/version")
            assert status == 200 and version["version"] == EXPECTED_VERSION, (status, version)
            status, org = api_req(api_base, "/api/v1/organizations", "POST", {"name": "c4-ux", "displayName": "C4 UX"})
            assert status == 201, (status, org)
            status, project = api_req(api_base, "/api/v1/projects", "POST", {"organizationId": org["id"], "name": "prod", "displayName": "Production"})
            assert status == 201, (status, project)
            draft = seed_blueprint(api_base, project["id"])

            # Seed fleet prerequisites through external agent authority. Operator campaign mutation remains UI-driven.
            cluster_tokens = [claim_cluster(api_base, project["id"], name, EXPECTED_VERSION) for name in ("c4-edge-a", "c4-edge-b")]
            now = dt.datetime.now(dt.timezone.utc)
            checkpoint_ids = []
            for i, (cluster, _token) in enumerate(cluster_tokens):
                status, cp = api_req(api_base, "/api/v1/recovery-checkpoints", "POST", {"projectId": project["id"], "clusterId": cluster["id"], "provider": "s3", "reference": f"c4/{cluster['id']}/backup", "evidenceDigest": "sha256:" + format(9900 + i, "064x"), "completedAt": iso(now - dt.timedelta(minutes=5)), "expiresAt": iso(now + dt.timedelta(hours=3))}, {"X-Actor-ID": "c4-operator"})
                assert status == 201, (status, cp)
                checkpoint_ids.append(cp["id"])
            status, group_result = api_req(api_base, "/api/v1/fleet-groups", "POST", {"projectId": project["id"], "name": "c4-fleet", "displayName": "C4 Fleet", "clusterIds": [cluster["id"] for cluster, _ in cluster_tokens]}, {"X-Actor-ID": "c4-operator", "Idempotency-Key": "c4-fleet"})
            assert status == 201, (status, group_result)
            group = group_result["fleetGroup"]
            recovery_op = seed_recovery_operation(api_base, project["id"])

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, executable_path=browser_executable, args=["--no-sandbox"])
                context = browser.new_context(viewport={"width": 1440, "height": 1000})
                page = context.new_page()
                page.set_default_timeout(8000)
                errors = []
                page.on("pageerror", lambda exc: errors.append(f"pageerror:{exc}"))
                page.on("console", lambda msg: errors.append(f"console:{msg.text}") if msg.type == "error" else None)
                transport = "browser-http-direct"
                try:
                    page.goto(browser_base + "/", wait_until="networkidle")
                except Exception as exc:
                    if "ERR_BLOCKED_BY_ADMINISTRATOR" not in str(exc):
                        raise
                    page.close()
                    page = context.new_page(); page.set_default_timeout(8000)
                    errors = []; transport = "playwright-python-real-api-bridge"
                    page.on("pageerror", lambda exc: errors.append(f"pageerror:{exc}"))
                    page.on("console", lambda msg: errors.append(f"console:{msg.text}") if msg.type == "error" else None)
                    install_real_api_bridge(page, api_base)
                    page.set_content(inline_console(ROOT), wait_until="load")
                    page.wait_for_timeout(300)

                # Select the authoritative C1 global organization/project scope first.
                page.locator("#global-organization-scope").wait_for(state="visible")
                page.wait_for_function("orgId => Array.from(document.querySelector('#global-organization-scope').options).some(o => o.value === orgId)", arg=org["id"])
                page.locator("#global-organization-scope").select_option(org["id"] )
                page.wait_for_function("projectId => Array.from(document.querySelector('#global-project-scope').options).some(o => o.value === projectId)", arg=project["id"])
                page.locator("#global-project-scope").select_option(project["id"] )
                page.wait_for_function("projectId => document.querySelector('#global-project-scope').value === projectId && document.querySelector('#global-scope')?.dataset.ready === 'true'", arg=project["id"])

                # 1) Create/import platform through real Console mutation + approval.
                page.evaluate("() => navigate('clusters')")
                page.wait_for_timeout(300)
                page.locator("#clusters details.action-console").first.evaluate("el => el.open = true")
                page.locator("#cluster-name").fill("c4-ui-import")
                page.locator("#cluster-display-name").fill("C4 UI Import")
                page.locator("#cluster-expiration").select_option("30")
                page.locator("#cluster-import-form button[type='submit']").click()
                import_card = page.locator("#cluster-import-grid .resource-card").filter(has_text="C4 UI Import").filter(has_text="PENDING_APPROVAL")
                import_card.wait_for(state="visible")
                import_card.locator("[data-import-action='approve']").click()
                confirm(page)
                approved_card = page.locator("#cluster-import-grid .resource-card").filter(has_text="C4 UI Import").filter(has_text="APPROVED")
                approved_card.wait_for(state="visible")

                # 2) Blueprint review/publish through UI against real persisted release.
                page.evaluate("() => navigate('blueprints')")
                page.wait_for_timeout(350)
                card = page.locator("#blueprint-release-grid .resource-card").filter(has_text="c4-publish-smoke").filter(has_text="DRAFT")
                card.wait_for(state="visible")
                card.locator("[data-blueprint-action='review']").click(); confirm(page)
                review_card = page.locator("#blueprint-release-grid .resource-card").filter(has_text="c4-publish-smoke").filter(has_text="REVIEW")
                review_card.wait_for(state="visible")
                review_card.locator("[data-blueprint-action='publish']").click(); confirm(page)
                published = page.locator("#blueprint-release-grid .resource-card").filter(has_text="c4-publish-smoke").filter(has_text="PUBLISHED")
                published.wait_for(state="visible")

                # 3) Fleet upgrade campaign created/approved/advanced from Console; agent completes target work.
                page.evaluate("() => navigate('fleet')")
                page.wait_for_timeout(450)
                page.wait_for_timeout(250)
                group_card = page.locator("#fleet-group-grid .resource-card").filter(has_text="C4 Fleet")
                try:
                    group_card.wait_for(state="visible")
                except Exception:
                    debug = page.evaluate("() => ({globalScope:state.globalScope,fleetProject:document.querySelector('#fleet-project')?.value,projects:state.projects.map(p=>({id:p.id,org:p.organizationId})),groups:state.fleetGroups.map(g=>({id:g.id,projectId:g.projectId,displayName:g.displayName,clusterIds:g.clusterIds})),grid:document.querySelector('#fleet-group-grid')?.innerText,errors:document.querySelector('#fleet-group-grid')?.innerHTML})")
                    raise AssertionError(f"Fleet group not visible: {debug}")
                group_card.locator("[data-fleet-action='upgrade']").click()
                dialog = page.locator("#detail-dialog[open]")
                dialog.wait_for(state="visible")
                # Keep the live smoke inside the maintenance window; the product default intentionally starts in the future.
                browser_now = dt.datetime.now(dt.timezone.utc)
                local_value = lambda value: value.astimezone().replace(tzinfo=None).isoformat(timespec="minutes")
                dialog.locator('[data-field="maintenanceWindowStart"]').fill(local_value(browser_now - dt.timedelta(minutes=1)))
                dialog.locator('[data-field="maintenanceWindowEnd"]').fill(local_value(browser_now + dt.timedelta(hours=2)))
                # Checkpoint selects are already populated with the seeded verified checkpoints.
                dialog.locator("[data-dialog-submit]").click()
                confirm(page)
                campaign_card = page.locator("#upgrade-campaign-grid .resource-card").filter(has_text="AWAITING_APPROVAL")
                campaign_card.wait_for(state="visible")
                campaign_card.locator("[data-upgrade-action='approve']").click(); confirm(page)
                queued = page.locator("#upgrade-campaign-grid .resource-card").filter(has_text="QUEUED")
                queued.wait_for(state="visible")
                queued.locator("[data-upgrade-action='advance']").click()
                page.wait_for_timeout(250)
                status, campaigns = api_req(api_base, f"/api/v1/upgrade-campaigns?projectId={project['id']}")
                assert status == 200 and len(campaigns) == 1, (status, campaigns)
                campaign = campaigns[0]
                token_by_id = {cluster["id"]: token for cluster, token in cluster_tokens}
                # Advance/complete each wave through the real agent task authority, then observe terminal state in UI.
                while campaign["state"] not in ("SUCCEEDED", "FAILED", "CANCELLED"):
                    active = next((t for t in campaign["targets"] if t["state"] == "PLANNING"), None)
                    if active:
                        campaign = complete_active(api_base, campaign, active["clusterId"], token_by_id[active["clusterId"]])
                    else:
                        campaign = advance(api_base, campaign)
                assert campaign["state"] == "SUCCEEDED", campaign
                page.evaluate("() => loadFleet()")
                page.wait_for_timeout(350)
                success_campaign = page.locator("#upgrade-campaign-grid .resource-card").filter(has_text="SUCCEEDED")
                success_campaign.wait_for(state="visible")

                # 4) Failed operation recovery starts from UI, worker executes compensation, UI exposes evidence.
                page.evaluate("() => navigate('operations')")
                page.wait_for_timeout(350)
                op_row = page.locator("#operation-grid tr[data-record-row]").filter(has_text="c4.failed.recovery")
                op_row.wait_for(state="visible")
                recover = op_row.locator("[data-operation-action='recover']")
                assert recover.count() == 1, op_row.inner_text()
                recover.click(); confirm(page)
                page.wait_for_timeout(250)
                status, started = api_req(api_base, f"/api/v1/operations/{recovery_op['id']}")
                assert status == 200 and started["operation"]["state"] == "ROLLING_BACK", (status, started)
                rolled_back, evidence = complete_recovery(api_base, recovery_op["id"])
                page.evaluate("() => loadOperations()")
                page.wait_for_timeout(350)
                rolled_row = page.locator("#operation-grid tr[data-record-row]").filter(has_text="c4.failed.recovery").filter(has_text="ROLLED_BACK")
                rolled_row.wait_for(state="visible")
                rolled_row.locator("[data-operation-id]").click()
                page.wait_for_timeout(150)
                detail = page.locator("#detail-dialog[open]").inner_text()
                assert "Compensation" in detail and "compensation-readback" in detail and evidence["digest"] in detail, detail
                page.locator('#detail-dialog button[value="close"]').click()

                screenshot = evidence_dir / "c4-console-workflows-1440x1000.png"
                page.screenshot(path=str(screenshot), full_page=True)
                if errors:
                    raise AssertionError(errors)
                context.close(); browser.close()

            return {
                "createImportPlatform": "PASS",
                "blueprintPublish": "PASS",
                "fleetUpgrade": "PASS",
                "failedOperationRecovery": "PASS",
                "projectId": project["id"],
                "fleetGroupId": group["id"],
                "recoveryOperationId": recovery_op["id"],
                "transport": transport,
                "screenshot": str(evidence_dir / "c4-console-workflows-1440x1000.png"),
            }
        finally:
            stop_api(process)


def run_disconnected_installer(installer_binary: Path, evidence_dir: Path, browser_executable: str):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        process, base, token = start_installer(installer_binary, root)
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, executable_path=browser_executable, args=["--no-sandbox"])
                context = browser.new_context(viewport={"width": 1440, "height": 1000})
                page = context.new_page(); page.set_default_timeout(8000)
                errors = []
                page.on("pageerror", lambda exc: errors.append(f"pageerror:{exc}"))
                page.on("console", lambda msg: errors.append(f"console:{msg.text}") if msg.type == "error" else None)
                transport = "browser-http-direct"
                try:
                    page.goto(base + "/", wait_until="networkidle")
                except Exception as exc:
                    if "ERR_BLOCKED_BY_ADMINISTRATOR" not in str(exc):
                        raise
                    page.close()
                    page = context.new_page(); page.set_default_timeout(8000)
                    errors = []; transport = "playwright-python-real-installer-bridge"
                    page.on("pageerror", lambda exc: errors.append(f"pageerror:{exc}"))
                    page.on("console", lambda msg: errors.append(f"console:{msg.text}") if msg.type == "error" else None)
                    install_real_api_bridge(page, base)
                    page.set_content(inline_installer(ROOT), wait_until="load")
                    page.wait_for_timeout(250)
                page.locator("#bootstrap-token").fill(token)
                page.locator("#confirm-connect").click()
                page.wait_for_function("() => document.querySelector('#connection-label')?.textContent === 'Connected'")
                page.locator("#verify-bundle").click()
                page.wait_for_timeout(250)
                bundle_text = page.locator("#bundle-status").inner_text()
                assert "verified" in bundle_text.lower() or "sha256:" in bundle_text.lower(), bundle_text

                page.locator("#nav [data-page='installation']").click()
                page.wait_for_timeout(150)
                page.locator("#profile").select_option("evaluation-single-node")
                page.locator("#connectivity").select_option("disconnected")
                page.locator("#nodes").fill("127.0.0.1")
                page.locator("#credential-ref").fill("secret://installer/ssh-private-key")
                page.locator("#ssh-user").fill("root")
                page.locator("#endpoint").fill("https://platform.example.test")
                page.locator("#dns-zone").fill("example.test")
                page.locator("#tls-mode").select_option("bootstrap-self-signed")
                page.locator('[data-service="identity"] [data-input="adminEmail"]').fill("admin@example.test")
                required_service_inputs = page.locator("#service-editor input:required")
                for index in range(required_service_inputs.count()):
                    service_input = required_service_inputs.nth(index)
                    field = service_input.get_attribute("data-input") or ""
                    if field in ("url", "issuerUrl"):
                        value = f"https://{service_input.locator('xpath=ancestor::section[1]').get_attribute('data-service') or 'service'}.example.test"
                    elif field == "credentialRef":
                        service = service_input.locator('xpath=ancestor::section[1]').get_attribute('data-service') or 'service'
                        value = f"secret://installer/{service}-credential"
                    else:
                        value = "c4-value"
                    service_input.fill(value)
                page.locator("#accept-risk").check()
                page.locator("#create-plan").click()
                page.wait_for_timeout(600)
                if page.locator("#plan-panel").get_attribute("hidden") is not None:
                    debug = page.evaluate("() => ({toasts:document.querySelector('#toast-region')?.innerText, connectError:document.querySelector('#connect-error')?.innerText, profile:document.querySelector('#profile')?.value, connectivity:document.querySelector('#connectivity')?.value, plannedRequest:state.plannedRequest, connected:state.connected, valid:document.querySelector('#installation-form')?.checkValidity(), invalid:Array.from(document.querySelectorAll('#installation-form :invalid')).map(el=>({id:el.id,tag:el.tagName,value:el.value,required:el.required}))})")
                    raise AssertionError(f"Installer plan was not created: {debug}")
                plan_text = page.locator("#plan-panel").inner_text()
                assert "EXECUTION READY" in plan_text and "disconnected" in page.locator("#connectivity").input_value(), plan_text
                page.wait_for_function("() => !document.querySelector('#preflight-panel')?.hidden")
                preflight_text = page.locator("#preflight-panel").inner_text()
                assert "PASSED" in preflight_text, preflight_text
                screenshot = evidence_dir / "c4-disconnected-installer-1440x1000.png"
                page.screenshot(path=str(screenshot), full_page=True)
                if errors:
                    raise AssertionError(errors)
                context.close(); browser.close()
                return {"disconnectedBundle": "PASS", "transport": transport, "screenshot": str(screenshot)}
        finally:
            stop_process(process)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("platform_api")
    parser.add_argument("platform_installer")
    parser.add_argument("--evidence-dir", default="")
    args = parser.parse_args()
    api_binary = Path(args.platform_api).resolve()
    installer_binary = Path(args.platform_installer).resolve()
    chromium = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    if not chromium:
        raise SystemExit("C4_E2E_BROWSER_MISSING")
    evidence_dir = Path(args.evidence_dir).resolve() if args.evidence_dir else Path(tempfile.mkdtemp(prefix="4so-c4-e2e-"))
    evidence_dir.mkdir(parents=True, exist_ok=True)
    console = run_console_journeys(api_binary, evidence_dir, chromium)
    installer = run_disconnected_installer(installer_binary, evidence_dir, chromium)
    report = {
        "schemaVersion": 1,
        "authority": "OPERATOR_CONSOLE_WORKFLOW_E2E_CERTIFICATION_V1",
        "version": EXPECTED_VERSION,
        "mode": "live-loopback-real-authority",
        "authorityMocked": False,
        "externalPhysicalRuntimeCertified": False,
        "journeys": {**console, **installer},
        "status": "PASS",
    }
    report_path = evidence_dir / "c4-workflow-e2e-certification.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("C4_WORKFLOW_E2E_CERTIFICATION_PASS", report_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
