#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import json
import hashlib
import zipfile
import os
import stat
import subprocess
import sys
import tempfile


def run(command: list[str], *, expect: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != expect:
        raise SystemExit(f"COMMAND_FAILED {command} rc={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}")
    return result




def make_release_archive(root: Path, version: str) -> tuple[Path, str]:
    archive = root / "release.zip"
    release_name = "installer-smoke-fixture"
    release_root = f"4so-platform-factory-{version}-{release_name}"
    version_raw = (version + "\n").encode()
    release_name_raw = (release_name + "\n").encode()
    manifest_raw = (json.dumps({
        "schemaVersion": 2,
        "product": "4SO Platform Factory",
        "version": version,
        "releaseName": release_name,
        "fileCount": 2,
        "files": [
            {
                "path": "VERSION",
                "sha256": hashlib.sha256(version_raw).hexdigest(),
                "size": len(version_raw),
                "mode": "0o644",
            },
            {
                "path": "RELEASE-NAME",
                "sha256": hashlib.sha256(release_name_raw).hexdigest(),
                "size": len(release_name_raw),
                "mode": "0o644",
            },
        ],
    }, sort_keys=True) + "\n").encode()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        for relative, raw in (("VERSION", version_raw), ("RELEASE-NAME", release_name_raw), ("ARTIFACT-MANIFEST.json", manifest_raw)):
            info = zipfile.ZipInfo(f"{release_root}/{relative}")
            info.create_system = 3
            info.external_attr = ((stat.S_IFREG | 0o644) & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_STORED
            zf.writestr(info, raw)
    digest = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
    return archive, digest

def image(name: str, digit: str) -> str:
    return f"registry.local/{name}@sha256:{digit * 64}"


def manifest(name: str, digit: str) -> str:
    return (
        "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n"
        f"      containers:\n        - name: {name}\n          image: {image(name, digit)}\n"
    )


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: smoke_installer_host.py PLATFORMCTL PLATFORM_INSTALLER")
    ctl = str(Path(sys.argv[1]).resolve())
    installer = str(Path(sys.argv[2]).resolve())
    project_root = Path(__file__).resolve().parents[1]
    version = (project_root / "VERSION").read_text(encoding="utf-8").strip()
    if run([installer, "--version"]).stdout.strip() != version:
        raise SystemExit("INSTALLER_VERSION_OUTPUT_INVALID")

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        release_archive, release_digest = make_release_archive(root, version)
        staging = root / "staging"
        files = {
            "rke2/install.sh": "#!/bin/sh\nexit 0\n",
            "rke2/rke2.tar.gz": "rke2",
            "rke2/images.tar.zst": "rke2-images",
            "workloads/images.tar.zst": "workloads",
            "manifests/argocd.yaml": manifest("argocd", "1"),
            "manifests/cnpg.yaml": manifest("cnpg", "2"),
            "manifests/ocm.yaml": manifest("ocm", "3"),
            "manifests/storage.yaml": manifest("storage", "4"),
        }
        for relative, content in files.items():
            path = staging / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        build_spec = {
            "apiVersion": "platform.4so.io/v1alpha1",
            "kind": "ApplianceBundleBuild",
            "metadata": {"version": version, "sourceReleaseDigest": release_digest},
            "spec": {
                "rke2": {
                    "version": "v1.34.0+rke2r1",
                    "installer": "rke2/install.sh",
                    "installArtifacts": ["rke2/rke2.tar.gz"],
                    "imageArchives": ["rke2/images.tar.zst"],
                },
                "workloads": {
                    "imageArchives": ["workloads/images.tar.zst"],
                    "postgresqlImage": image("postgres", "a"),
                    "platformApiImage": image("api", "b"),
                    "forgejoImage": image("forgejo", "c"),
                    "zotImage": image("zot", "d"),
                    "keycloakImage": image("keycloak", "e"),
                    "maintenanceImage": image("maintenance", "f"),
                    "gitOpsManifest": "manifests/argocd.yaml",
                    "cloudNativePGManifest": "manifests/cnpg.yaml",
                    "ocmManifest": "manifests/ocm.yaml",
                    "storageManifest": "manifests/storage.yaml",
                    "fleetAgentImage": image("agent", "9"),
                    "runtimeProbeImage": image("probe", "8"),
                },
            },
        }
        build_spec_path = root / "bundle-build.json"
        build_spec_path.write_text(json.dumps(build_spec, indent=2) + "\n", encoding="utf-8")
        bundle = root / "bundle-source"
        run([ctl, "appliance-bundle", "build", "--spec", str(build_spec_path), "--staging", str(staging), "--out", str(bundle), "--release-artifact", str(release_archive)])

        target = root / "target-root"
        target.mkdir()
        old_binary = target / "usr/local/bin/platform-installer"
        old_binary.parent.mkdir(parents=True)
        old_binary.write_text("previous-binary", encoding="utf-8")
        old_binary.chmod(0o755)
        old_bundle = target / "opt/4so-platform-factory/bundle"
        old_bundle.mkdir(parents=True)
        (old_bundle / "previous-marker").write_text("previous", encoding="utf-8")

        deployment = {
            "apiVersion": "platform.4so.io/v1alpha1",
            "kind": "InstallerHostDeployment",
            "metadata": {"name": "smoke-field-installer", "version": version},
            "spec": {
                "installerBinary": installer,
                "bundleDirectory": str(bundle),
                "listen": "127.0.0.1:9080",
                "executionEnabled": False,
                "allowInsecureHttp": False,
                "tls": {},
                "health": {"path": "/healthz", "timeoutSeconds": 30, "intervalMilliseconds": 500},
                "admission": {"allowDowngrade": False},
                "service": {"enable": True, "start": True},
            },
        }
        deployment_path = root / "host-deployment.json"
        deployment_path.write_text(json.dumps(deployment, indent=2) + "\n", encoding="utf-8")

        admission = json.loads(run([ctl, "installer-host", "preflight", "--spec", str(deployment_path), "--root", str(target)]).stdout)
        if not admission.get("ready") or admission.get("upgradeMode") not in {"INSTALL", "REPAIR", "REINSTALL", "UPGRADE"} or not admission.get("digest"):
            raise SystemExit("INSTALLER_HOST_ADMISSION_INVALID")
        if not any(check.get("id") == "capacity" and check.get("status") in {"PASS", "WARNING"} for check in admission.get("checks", [])):
            raise SystemExit("INSTALLER_HOST_CAPACITY_ADMISSION_INVALID")

        plan = json.loads(run([ctl, "installer-host", "plan", "--spec", str(deployment_path), "--root", str(target)]).stdout)
        if plan["version"] != version or plan["confirmation"] != "DEPLOY" or not plan["bundle"]["verified"]:
            raise SystemExit("INSTALLER_HOST_PLAN_INVALID")
        if plan.get("schemaVersion") != 3 or plan.get("health", {}).get("url") != "http://127.0.0.1:9080/healthz":
            raise SystemExit("INSTALLER_HOST_READINESS_PLAN_INVALID")
        if not plan.get("service", {}).get("enable") or not plan.get("service", {}).get("start"):
            raise SystemExit("INSTALLER_HOST_SERVICE_INTENT_INVALID")
        if not plan.get("admission", {}).get("ready") or not plan.get("admission", {}).get("digest"):
            raise SystemExit("INSTALLER_HOST_PLAN_ADMISSION_INVALID")
        run([ctl, "installer-host", "apply", "--spec", str(deployment_path), "--root", str(target), "--confirmation", "WRONG"], expect=1)
        state = json.loads(run([ctl, "installer-host", "apply", "--spec", str(deployment_path), "--root", str(target), "--confirmation", "DEPLOY"]).stdout)
        if state["status"] != "STAGED" or state["activated"]:
            raise SystemExit("INSTALLER_HOST_STAGE_INVALID")
        state_path = Path(state["plan"]["paths"]["state"])
        if stat.S_IMODE(state_path.stat().st_mode) != 0o600:
            raise SystemExit("INSTALLER_HOST_STATE_PERMISSION_INVALID")
        observed = json.loads(run([ctl, "installer-host", "status", "--state", str(state_path)]).stdout)
        if observed["schemaVersion"] != 4 or observed["status"] != "STAGED" or observed.get("recoveryRequired", False):
            raise SystemExit("INSTALLER_HOST_JOURNAL_STATUS_INVALID")
        if "backups-prepared" not in observed.get("completedSteps", []) or "bundle-installed" not in observed.get("completedSteps", []):
            raise SystemExit("INSTALLER_HOST_CHECKPOINTS_INVALID")
        run([ctl, "installer-host", "recover", "--state", str(state_path), "--confirmation", "RECOVER"], expect=1)
        env = Path(state["plan"]["paths"]["environment"]).read_text(encoding="utf-8")
        if str(target) in env or "BOOTSTRAP_TOKEN" in env:
            raise SystemExit("INSTALLER_HOST_ENV_INVALID")
        result = json.loads(run([ctl, "installer-host", "verify", "--state", str(state_path)]).stdout)
        if not result["valid"] or not result["stagedOnly"]:
            raise SystemExit("INSTALLER_HOST_VERIFY_INVALID")
        if not result.get("admissionReady") or result.get("admissionDigest") != state.get("plan", {}).get("admission", {}).get("digest"):
            raise SystemExit("INSTALLER_HOST_VERIFY_ADMISSION_INVALID")
        run([ctl, "installer-host", "rollback", "--state", str(state_path), "--confirmation", "WRONG"], expect=1)
        rolled = json.loads(run([ctl, "installer-host", "rollback", "--state", str(state_path), "--confirmation", "ROLLBACK"]).stdout)
        if rolled["status"] != "ROLLED_BACK":
            raise SystemExit("INSTALLER_HOST_ROLLBACK_INVALID")
        if old_binary.read_text(encoding="utf-8") != "previous-binary":
            raise SystemExit("INSTALLER_HOST_BINARY_ROLLBACK_INVALID")
        if (old_bundle / "previous-marker").read_text(encoding="utf-8") != "previous":
            raise SystemExit("INSTALLER_HOST_BUNDLE_ROLLBACK_INVALID")

    print("INSTALLER_HOST_DEPLOYMENT_SMOKE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
