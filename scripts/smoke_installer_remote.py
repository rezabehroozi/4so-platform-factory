#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import base64
import json
import hashlib
import zipfile
import os
import stat
import subprocess
import sys
import tempfile


def run(command: list[str], *, env: dict[str, str], expect: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=True, check=False, env=env)
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
        raise SystemExit("usage: smoke_installer_remote.py PLATFORMCTL PLATFORM_INSTALLER")
    ctl = str(Path(sys.argv[1]).resolve())
    installer = str(Path(sys.argv[2]).resolve())
    project_root = Path(__file__).resolve().parents[1]
    version = (project_root / "VERSION").read_text(encoding="utf-8").strip()
    if subprocess.check_output([ctl, "version"], text=True).strip() != version:
        raise SystemExit("PLATFORMCTL_VERSION_OUTPUT_INVALID")

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
                "rke2": {"version": "v1.34.0+rke2r1", "installer": "rke2/install.sh", "installArtifacts": ["rke2/rke2.tar.gz"], "imageArchives": ["rke2/images.tar.zst"]},
                "workloads": {
                    "imageArchives": ["workloads/images.tar.zst"],
                    "postgresqlImage": image("postgres", "a"), "platformApiImage": image("api", "b"),
                    "forgejoImage": image("forgejo", "c"), "zotImage": image("zot", "d"), "keycloakImage": image("keycloak", "e"),
                    "maintenanceImage": image("maintenance", "f"), "gitOpsManifest": "manifests/argocd.yaml", "cloudNativePGManifest": "manifests/cnpg.yaml",
                    "ocmManifest": "manifests/ocm.yaml",
                    "storageManifest": "manifests/storage.yaml", "fleetAgentImage": image("agent", "9"), "runtimeProbeImage": image("probe", "8")
                },
            },
        }
        build_path = root / "bundle-build.json"
        build_path.write_text(json.dumps(build_spec, indent=2) + "\n", encoding="utf-8")
        bundle = root / "bundle"
        env = os.environ.copy()
        run([ctl, "appliance-bundle", "build", "--spec", str(build_path), "--staging", str(staging), "--out", str(bundle), "--release-artifact", str(release_archive)], env=env)

        target_root = root / "remote-root"
        target_root.mkdir()
        deployment = {
            "apiVersion": "platform.4so.io/v1alpha1", "kind": "InstallerHostDeployment",
            "metadata": {"name": "remote-smoke-installer", "version": version},
            "spec": {
                "installerBinary": installer, "bundleDirectory": str(bundle), "listen": "127.0.0.1:9080",
                "executionEnabled": False, "allowInsecureHttp": False, "tls": {},
                "health": {"path": "/healthz", "timeoutSeconds": 30, "intervalMilliseconds": 500},
                "admission": {"allowDowngrade": False}, "service": {"enable": True, "start": True}
            }
        }
        deployment_path = root / "deployment.json"
        deployment_path.write_text(json.dumps(deployment, indent=2) + "\n", encoding="utf-8")

        identity = root / "id_ed25519"
        identity.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nsmoke-only\n-----END OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
        identity.chmod(0o600)
        known = root / "known_hosts"
        encoded = base64.b64encode(b"4so-remote-smoke-host-key-material").decode("ascii")
        known.write_text(f"remote-node.test ssh-ed25519 {encoded}\n", encoding="utf-8")
        known.chmod(0o600)

        fake_bin = root / "fake-bin"
        fake_bin.mkdir()
        ssh_log = root / "ssh.log"
        fake_ssh = fake_bin / "ssh"
        fake_ssh.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\nprintf '%q ' \"$@\" >> \"$FAKE_SSH_LOG\"\nprintf '\\n' >> \"$FAKE_SSH_LOG\"\ncmd=\"${!#}\"\nexec bash -c \"$cmd\"\n",
            encoding="utf-8",
        )
        fake_ssh.chmod(0o755)
        env["PATH"] = str(fake_bin) + os.pathsep + env.get("PATH", "")
        env["FAKE_SSH_LOG"] = str(ssh_log)

        remote = {
            "apiVersion": "platform.4so.io/v1alpha1", "kind": "InstallerRemoteBootstrap",
            "metadata": {"name": "remote-smoke", "version": version},
            "spec": {
                "target": {"host": "remote-node.test", "user": "root", "identityFile": str(identity), "knownHostsFile": str(known), "root": str(target_root)},
                "platformctlBinary": ctl, "deploymentSpec": str(deployment_path)
            }
        }
        remote_path = root / "remote-bootstrap.json"
        remote_path.write_text(json.dumps(remote, indent=2) + "\n", encoding="utf-8")

        admission = json.loads(run([ctl, "installer-remote", "preflight", "--spec", str(remote_path)], env=env).stdout)
        if not admission.get("ready") or not admission.get("digest"):
            raise SystemExit("REMOTE_INSTALLER_PREFLIGHT_INVALID")
        plan = json.loads(run([ctl, "installer-remote", "plan", "--spec", str(remote_path)], env=env).stdout)
        if plan.get("version") != version or plan.get("target", {}).get("host") != "remote-node.test":
            raise SystemExit("REMOTE_INSTALLER_PLAN_INVALID")
        if not plan.get("stageManifestDigest", "").startswith("sha256:") or not plan.get("target", {}).get("trust"):
            raise SystemExit("REMOTE_INSTALLER_STAGE_OR_TRUST_INVALID")
        if "identityFile" in json.dumps(plan) or "knownHostsFile" in json.dumps(plan):
            raise SystemExit("REMOTE_INSTALLER_CREDENTIAL_PATH_LEAK")
        run([ctl, "installer-remote", "apply", "--spec", str(remote_path), "--confirmation", "WRONG"], env=env, expect=1)
        result = json.loads(run([ctl, "installer-remote", "apply", "--spec", str(remote_path), "--confirmation", "DEPLOY"], env=env).stdout)
        if result.get("state", {}).get("status") != "STAGED":
            raise SystemExit("REMOTE_INSTALLER_APPLY_INVALID")
        observed = json.loads(run([ctl, "installer-remote", "status", "--spec", str(remote_path)], env=env).stdout)
        if observed.get("status") != "STAGED" or observed.get("schemaVersion") != 4:
            raise SystemExit("REMOTE_INSTALLER_STATUS_INVALID")
        verified = json.loads(run([ctl, "installer-remote", "verify", "--spec", str(remote_path)], env=env).stdout)
        if not verified.get("valid") or not verified.get("stagedOnly"):
            raise SystemExit("REMOTE_INSTALLER_VERIFY_INVALID")
        rolled = json.loads(run([ctl, "installer-remote", "rollback", "--spec", str(remote_path), "--confirmation", "ROLLBACK"], env=env).stdout)
        if rolled.get("status") != "ROLLED_BACK":
            raise SystemExit("REMOTE_INSTALLER_ROLLBACK_INVALID")

        log = ssh_log.read_text(encoding="utf-8")
        for required in ("StrictHostKeyChecking=yes", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "IdentitiesOnly=yes"):
            if required not in log:
                raise SystemExit(f"REMOTE_INSTALLER_SSH_CONTRACT_MISSING {required}")
        for forbidden in ("accept-new", "StrictHostKeyChecking=no", "sshpass", "sudo", " scp "):
            if forbidden in log:
                raise SystemExit(f"REMOTE_INSTALLER_SSH_UNSAFE {forbidden}")
        # Temporary payload stage must be cleaned after plan/apply.
        remote_stage_parent = target_root / "var/lib/4so-platform-installer/remote-bootstrap"
        if remote_stage_parent.exists() and any(remote_stage_parent.iterdir()):
            raise SystemExit("REMOTE_INSTALLER_STAGE_NOT_CLEANED")
        state_path = target_root / "var/lib/4so-platform-installer/host-deployment.json"
        if state_path.exists() and stat.S_IMODE(state_path.stat().st_mode) != 0o600:
            raise SystemExit("REMOTE_INSTALLER_REMOTE_STATE_PERMISSION_INVALID")

    print("REMOTE_INSTALLER_BOOTSTRAP_SMOKE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
