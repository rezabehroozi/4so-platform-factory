import base64
import hashlib
import importlib.util
import json
import jsonschema
import io
import tarfile
import os
import stat
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("lab_runner_contract", ROOT / "scripts" / "lab_runner.py")
lab = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(lab)


class LabRunnerContractTests(unittest.TestCase):
    def _release(self, root: Path) -> Path:
        version = "9.9.9"
        name = "test-release"
        archive = root / "release.zip"
        prefix = f"4so-platform-factory-{version}-{name}"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr(prefix + "/VERSION", version + "\n")
            zf.writestr(prefix + "/RELEASE-NAME", name + "\n")
        return archive

    def _spec(self, root: Path) -> dict:
        identity = root / "id"
        identity.write_text("dummy-private-key", encoding="utf-8")
        identity.chmod(0o600)
        known = root / "known_hosts"
        known.write_text("example.invalid ssh-ed25519 AAAA\n", encoding="utf-8")
        return {
            "apiVersion": "platform.4so.io/v1alpha1",
            "kind": "LabExecution",
            "metadata": {"name": "contract-test"},
            "spec": {
                "releaseArtifact": str(self._release(root)),
                "serverTier": "current-import-minimum",
                "ssh": {"user": "root", "identityFile": str(identity), "knownHostsFile": str(known)},
                "servers": [
                    {"role": "management-primary", "host": "mgmt.example.invalid"},
                    {"role": "okd-control-1", "host": "okd1.example.invalid"},
                    {"role": "okd-control-2", "host": "okd2.example.invalid"},
                    {"role": "okd-control-3", "host": "okd3.example.invalid"},
                ],
                "management": {
                    "publicEndpoint": "https://mgmt.example.invalid",
                    "adminEmail": "admin@mgmt.example.invalid",
                    "dnsZone": "example.invalid",
                },
                "ai": {"provider": "none"},
            },
        }


    def _production_ha_spec(self, root: Path) -> dict:
        spec = self._spec(root)
        spec["spec"]["serverTier"] = "production-ha"
        spec["spec"]["servers"] = [
            {"role": "management-1", "host": "mgmt1.example.invalid"},
            {"role": "management-2", "host": "mgmt2.example.invalid"},
            {"role": "management-3", "host": "mgmt3.example.invalid"},
            {"role": "okd-control-1", "host": "okd1.example.invalid"},
            {"role": "okd-control-2", "host": "okd2.example.invalid"},
            {"role": "okd-control-3", "host": "okd3.example.invalid"},
        ]
        spec["spec"]["management"] = {
            "publicEndpoint": "https://factory.example.invalid",
            "adminEmail": "admin@factory.example.invalid",
            "dnsZone": "example.invalid",
            "storageClass": "replicated-rwx",
            "clusterNodeAddresses": ["10.77.35.11", "10.77.35.12", "10.77.35.13"],
            "clusterInterface": "ens35",
            "storageDataDevices": ["/dev/sdb", "/dev/sdc", "/dev/sdd"],
            "storageDeviceMode": "format-empty",
            "objectStorage": {
                "url": "https://s3.example.invalid",
                "bucket": "platform-backups",
                "prefix": "factory",
                "region": "lab",
                "credentialRef": "external-secret://platform-system/s3-credentials",
            },
        }
        return spec

    def test_production_ha_schema_matches_runtime_topology_contract(self):
        with tempfile.TemporaryDirectory() as td:
            spec = self._production_ha_spec(Path(td))
            schema = json.loads((ROOT / "schemas" / "lab-execution.schema.json").read_text(encoding="utf-8"))
            jsonschema.Draft202012Validator(schema).validate(spec)

            missing = json.loads(json.dumps(spec))
            missing["spec"]["management"].pop("clusterInterface")
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.Draft202012Validator(schema).validate(missing)

            missing = json.loads(json.dumps(spec))
            missing["spec"]["management"].pop("storageDataDevices")
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.Draft202012Validator(schema).validate(missing)

    def test_lab_schema_rejects_duplicate_ha_devices_and_cluster_addresses(self):
        with tempfile.TemporaryDirectory() as td:
            spec = self._production_ha_spec(Path(td))
            schema = json.loads((ROOT / "schemas" / "lab-execution.schema.json").read_text(encoding="utf-8"))
            validator = jsonschema.Draft202012Validator(schema)

            duplicate_ips = json.loads(json.dumps(spec))
            duplicate_ips["spec"]["management"]["clusterNodeAddresses"] = ["10.77.35.11", "10.77.35.11", "10.77.35.13"]
            with self.assertRaises(jsonschema.ValidationError):
                validator.validate(duplicate_ips)

            duplicate_devices = json.loads(json.dumps(spec))
            duplicate_devices["spec"]["management"]["storageDataDevices"] = ["/dev/sdb", "/dev/sdb"]
            with self.assertRaises(jsonschema.ValidationError):
                validator.validate(duplicate_devices)

    def test_management_admin_email_is_required_before_server_driven_install(self):
        with tempfile.TemporaryDirectory() as td:
            spec = self._spec(Path(td))
            spec["spec"]["management"].pop("adminEmail")
            with self.assertRaisesRegex(SystemExit, "adminEmail is required"):
                lab.validate_spec(spec)

    def test_management_dns_zone_is_required_before_server_driven_install(self):
        with tempfile.TemporaryDirectory() as td:
            spec = self._spec(Path(td))
            spec["spec"]["management"].pop("dnsZone")
            with self.assertRaisesRegex(SystemExit, "dnsZone"):
                lab.validate_spec(spec)

    def test_three_node_management_inputs_fail_closed_before_field_campaign(self):
        with tempfile.TemporaryDirectory() as td:
            spec = self._production_ha_spec(Path(td))
            for field, expected in (("dnsZone", "dnsZone"), ("publicEndpoint", "publicEndpoint"), ("clusterNodeAddresses", "clusterNodeAddresses"), ("clusterInterface", "clusterInterface"), ("storageDataDevices", "storageDataDevices"), ("storageDeviceMode", "storageDeviceMode"), ("objectStorage", "objectStorage")):
                changed = json.loads(json.dumps(spec))
                changed["spec"]["management"].pop(field)
                with self.subTest(field=field):
                    with self.assertRaisesRegex(SystemExit, expected):
                        lab.validate_spec(changed)
            changed = json.loads(json.dumps(spec))
            changed["spec"]["management"]["objectStorage"].pop("bucket")
            with self.assertRaisesRegex(SystemExit, "object-storage bucket"):
                lab.validate_spec(changed)
            changed = json.loads(json.dumps(spec))
            changed["spec"]["management"]["objectStorage"]["credentialRef"] = "external-secret://other/s3"
            with self.assertRaisesRegex(SystemExit, "external-secret://platform-system"):
                lab.validate_spec(changed)

    def test_install_request_is_exact_bundle_disconnected_and_carries_identity_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            single = lab.validate_spec(self._spec(Path(td)))
            single_req = lab._install_request(single)
            self.assertEqual("disconnected", single_req["connectivity"])
            self.assertEqual("admin@mgmt.example.invalid", single_req["services"]["identity"]["adminEmail"])
            self.assertEqual("example.invalid", single_req["network"]["dnsZone"])
            self.assertEqual("evaluation-single-node", single_req["profileId"])
        with tempfile.TemporaryDirectory() as td:
            ha = lab.validate_spec(self._production_ha_spec(Path(td)))
            ha_req = lab._install_request(ha)
            self.assertEqual("disconnected", ha_req["connectivity"])
            self.assertEqual("production-standard-ha", ha_req["profileId"])
            self.assertEqual("example.invalid", ha_req["network"]["dnsZone"])
            self.assertEqual(["10.77.35.11", "10.77.35.12", "10.77.35.13"], ha_req["infrastructure"]["clusterNodeAddresses"])
            self.assertEqual("ens35", ha_req["infrastructure"]["clusterInterface"])
            self.assertEqual(["/dev/sdb", "/dev/sdc", "/dev/sdd"], ha_req["infrastructure"]["storageDataDevices"])
            self.assertEqual("format-empty", ha_req["infrastructure"]["storageDeviceMode"])
            self.assertEqual("platform-backups", ha_req["services"]["objectStorage"]["bucket"])
            self.assertEqual("admin@factory.example.invalid", ha_req["services"]["identity"]["adminEmail"])

    def test_installer_access_token_export_is_private_sealed_and_resume_replaceable(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            canonical = root / "installer.token"
            canonical.write_text("old-private-bootstrap-token-abcdefghijklmnopqrstuvwxyz\n", encoding="utf-8")
            canonical.chmod(0o400)
            export = root / "installer.token.export.1"
            export.write_text("new-private-bootstrap-token-abcdefghijklmnopqrstuvwxyz\n", encoding="utf-8")
            export.chmod(0o600)
            token, fingerprint = lab._promote_installer_token_export(export, canonical)
            self.assertEqual("new-private-bootstrap-token-abcdefghijklmnopqrstuvwxyz", token)
            self.assertRegex(fingerprint, r"^sha256:[0-9a-f]{64}$")
            self.assertFalse(export.exists())
            self.assertEqual(0o400, stat.S_IMODE(canonical.stat().st_mode))
            self.assertEqual((token, fingerprint), lab._read_private_installer_token(canonical, require_read_only=True))

    def test_installer_access_token_rejects_symlink_and_broad_permissions(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target"
            target.write_text("private-bootstrap-token-abcdefghijklmnopqrstuvwxyz\n", encoding="utf-8")
            target.chmod(0o600)
            link = root / "token-link"
            link.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "non-symlink"):
                lab._read_private_installer_token(link, require_read_only=False)
            target.chmod(0o640)
            with self.assertRaisesRegex(RuntimeError, "group/other"):
                lab._read_private_installer_token(target, require_read_only=False)


    def test_runtime_json_loader_rejects_symlink_and_oversized_state(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "state.json"
            target.write_text('{"ok":true}\n', encoding="utf-8")
            target.chmod(0o600)
            link = root / "state-link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "bounded regular non-symlink"):
                lab._load_runtime_json_object(link, label="runtime state")
            oversized = root / "oversized.json"
            with oversized.open("wb") as out:
                out.truncate(lab.MAX_RUNTIME_JSON_BYTES + 1)
            with self.assertRaisesRegex(RuntimeError, "bounded regular non-symlink"):
                lab._load_runtime_json_object(oversized, label="runtime state")

    def test_bundle_acquisition_pinned_https_connection_rejects_proxy_tunnel(self):
        pinned = ((lab.socket.AF_INET, lab.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),)
        conn = lab._PinnedHTTPSConnection("downloads.example.com", pinned_infos=pinned, context=object())
        conn._tunnel_host = "proxy.example.invalid"
        with self.assertRaisesRegex(OSError, "proxy tunnels are not permitted"):
            conn.connect()

    def test_bundle_acquisition_pinned_https_connection_resolves_default_timeout_sentinel(self):
        # http.client passes the _GLOBAL_DEFAULT_TIMEOUT sentinel whenever the caller
        # supplied no explicit timeout; a pinned socket must resolve it instead of
        # raising TypeError out of the acquisition path.
        pinned = ((lab.socket.AF_INET, lab.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),)
        seen = []

        class FakeSocket:
            def settimeout(self, timeout):
                seen.append(timeout)

            def connect(self, address):
                seen.append(address)

            def setsockopt(self, *args):
                pass

            def close(self):
                pass

        class FakeTLSContext:
            def wrap_socket(self, sock, *, server_hostname):
                seen.append(server_hostname)
                return sock

        with mock.patch.object(lab.socket, "socket", return_value=FakeSocket()):
            conn = lab._PinnedHTTPSConnection("downloads.example.com.", pinned_infos=pinned, context=FakeTLSContext())
            conn.connect()
        self.assertEqual([lab.socket.getdefaulttimeout(), ("8.8.8.8", 443), "downloads.example.com"], seen)

    def test_pinned_control_plane_https_connection_keeps_supplied_tls_context(self):
        pinned = ((lab.socket.AF_INET, lab.socket.SOCK_STREAM, 6, "", ("127.0.0.1", 6443)),)
        seen = []

        class FakeSocket:
            def settimeout(self, timeout):
                pass

            def connect(self, address):
                seen.append(address)

            def setsockopt(self, *args):
                pass

            def close(self):
                pass

        class FakeContext:
            def wrap_socket(self, sock, *, server_hostname):
                seen.append(server_hostname)
                return sock

        context = FakeContext()
        with mock.patch.object(lab.socket, "socket", return_value=FakeSocket()):
            conn = lab._PinnedControlPlaneHTTPSConnection("factory.example.invalid", pinned_infos=pinned, context=context, timeout=5)
            conn.connect()
        # The supplied context is the exact Lab control-plane TLS policy; it must be
        # used verbatim rather than replaced by a stdlib-copied default context.
        self.assertIs(context, conn._context)
        self.assertEqual([("127.0.0.1", 6443), "factory.example.invalid"], seen)

    def test_pinned_socket_dial_closes_descriptor_when_tls_setup_fails(self):
        pinned = ((lab.socket.AF_INET, lab.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),)
        closed = []

        class FakeSocket:
            def settimeout(self, timeout):
                pass

            def connect(self, address):
                pass

            def setsockopt(self, *args):
                pass

            def close(self):
                closed.append(True)

        class ExplodingContext:
            def wrap_socket(self, sock, *, server_hostname):
                raise ValueError("unsupported TLS server name")

        with mock.patch.object(lab.socket, "socket", return_value=FakeSocket()):
            with self.assertRaisesRegex(ValueError, "unsupported TLS server name"):
                lab._pinned_socket(pinned, timeout=1, context=ExplodingContext(), server_hostname="downloads.example.com")
        self.assertEqual([True], closed)

    def _plan_spec_with_locked_bundle_authority(self, root: Path, *, resolved_ids: list[str], missing_ids: list[str], tamper_manifest_sha: bool = False) -> dict:
        version = "9.9.9"
        spec = self._spec(root)
        release_root = root / "release-tree"
        plan = self._image_plan_value(version)
        manifest_by_authority = {row["sourceAuthority"]: row["manifestPath"] for row in plan["derivedManifestImageSets"]}
        resolved = []
        for index, authority_id in enumerate(resolved_ids):
            path = manifest_by_authority.get(authority_id, f"fixture/{index}-{authority_id}.bin")
            resolved.append({
                "id": authority_id,
                "kind": "kubernetes-manifest" if authority_id in manifest_by_authority else "release-artifact",
                "provider": "fixture-provider",
                "version": "v1.0.0",
                "scope": "fixture-scope",
                "artifacts": [{
                    "name": Path(path).name,
                    "stagingPath": path,
                    "sha256": f"{index + 1:064x}",
                    "sizeBytes": 100 + index,
                    "urls": [f"https://downloads.example.invalid/{index}-{authority_id}"],
                }],
            })
        lock_path = self._write_acquisition_lock(release_root, version=version, status="incomplete", missing=missing_ids, resolved=resolved)
        lock_value = json.loads(lock_path.read_text(encoding="utf-8"))
        by_id = {row.get("id"): row for row in lock_value.get("resolvedAuthorities", []) if isinstance(row, dict)}
        for row in plan["derivedManifestImageSets"]:
            authority = by_id.get(row["sourceAuthority"])
            artifacts = authority.get("artifacts", []) if isinstance(authority, dict) else []
            if len(artifacts) == 1:
                row["sourceManifestSha256"] = "sha256:" + artifacts[0]["sha256"]
                row["sourceManifestBytes"] = artifacts[0]["sizeBytes"]
        if tamper_manifest_sha:
            plan["derivedManifestImageSets"][0]["sourceManifestSha256"] = "sha256:" + "e" * 64
        archive = root / "locked-release.zip"
        prefix = f"4so-platform-factory-{version}-plan"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr(prefix + "/VERSION", version + "\n")
            zf.writestr(prefix + "/RELEASE-NAME", "plan\n")
            zf.writestr(prefix + "/" + lab.BUNDLE_ACQUISITION_LOCK_REL, lock_path.read_bytes())
            zf.writestr(prefix + "/" + lab.MANAGEMENT_WORKLOAD_IMAGE_PLAN_REL, json.dumps(plan, separators=(",", ":")))
        spec["spec"]["releaseArtifact"] = str(archive)
        return spec

    def test_plan_projects_exact_management_workload_image_plan_without_acquisition_authority(self):
        # Planning runs against the shipped incomplete acquisition state. It must emit
        # the exact image-plan projection bound to the same lock instead of crashing,
        # and it must never claim the bundle itself is acquired.
        manifests = ["argocd-install-manifest", "argocd-ha-install-manifest", "cloudnative-pg-install-manifest", "replicated-storage-install-manifest"]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec = self._plan_spec_with_locked_bundle_authority(
                root, resolved_ids=manifests, missing_ids=["management-workload-oci-archive", "rke2-installer-and-offline-artifacts"]
            )
            plan = lab.plan_document(spec)
            acquisition = plan["bundleAcquisition"]
            self.assertEqual("incomplete", acquisition["status"])
            self.assertEqual(["management-workload-oci-archive", "rke2-installer-and-offline-artifacts"], sorted(acquisition["missingAuthorities"]))
            projection = acquisition["managementWorkloadImagePlan"]
            self.assertIsNotNone(projection)
            self.assertEqual(lab.MANAGEMENT_WORKLOAD_IMAGE_PLAN_AUTHORITY, projection["authority"])
            self.assertEqual(lab.MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY, projection["manifestImageResolutionAuthority"])
            self.assertRegex(projection["digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(projection["sourceBindingDigest"], r"^sha256:[0-9a-f]{64}$")
            lock, lock_digest = lab._load_exact_bundle_acquisition_lock(
                Path(spec["spec"]["releaseArtifact"]), "9.9.9", plan["releaseSha256"]
            )
            image_plan, _ = lab._load_exact_management_workload_image_plan(Path(spec["spec"]["releaseArtifact"]), "9.9.9", plan["releaseSha256"])
            self.assertEqual(lab._verify_management_workload_image_plan_lock_binding(image_plan, lock), projection["sourceBindingDigest"])
            self.assertEqual(lock_digest, acquisition["lockDigest"])

    def test_plan_drops_image_plan_source_binding_until_manifest_authorities_resolve(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec = self._plan_spec_with_locked_bundle_authority(
                root,
                resolved_ids=["cloudnative-pg-install-manifest", "replicated-storage-install-manifest"],
                missing_ids=["management-workload-oci-archive", "argocd-install-manifest", "argocd-ha-install-manifest", "rke2-installer-and-offline-artifacts"],
            )
            plan = lab.plan_document(spec)
            acquisition = plan["bundleAcquisition"]
            self.assertEqual("incomplete", acquisition["status"])
            projection = acquisition["managementWorkloadImagePlan"]
            self.assertIsNotNone(projection)
            # A plan may show what is pending, but it cannot present an unbound
            # manifest source set as if it had been locked.
            self.assertEqual("", projection["sourceBindingDigest"])

    def test_plan_fails_closed_on_image_plan_lock_drift(self):
        manifests = ["argocd-install-manifest", "argocd-ha-install-manifest", "cloudnative-pg-install-manifest", "replicated-storage-install-manifest"]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec = self._plan_spec_with_locked_bundle_authority(
                root,
                resolved_ids=manifests,
                missing_ids=["management-workload-oci-archive", "rke2-installer-and-offline-artifacts"],
                tamper_manifest_sha=True,
            )
            plan = lab.plan_document(spec)
            acquisition = plan["bundleAcquisition"]
            self.assertEqual("invalid", acquisition["status"])
            self.assertEqual([lab.BUNDLE_SOURCE_LOCKS_BLOCKER], acquisition["missingAuthorities"])
            self.assertIn("drifts from acquisition lock", acquisition["error"])
            self.assertNotIn("managementWorkloadImagePlan", acquisition)

    def test_shipped_plan_projector_matches_execution_authority(self):
        # The plan-time and acquisition-time projections of the same exact release must
        # stay byte-identical; a shared owner is the only authority.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manifests = ["argocd-install-manifest", "argocd-ha-install-manifest", "cloudnative-pg-install-manifest", "replicated-storage-install-manifest"]
            spec = self._plan_spec_with_locked_bundle_authority(
                root, resolved_ids=manifests, missing_ids=["management-workload-oci-archive", "rke2-installer-and-offline-artifacts"]
            )
            plan = lab.plan_document(spec)
            artifact = Path(spec["spec"]["releaseArtifact"])
            version, sha = "9.9.9", plan["releaseSha256"]
            lock, _ = lab._load_exact_bundle_acquisition_lock(artifact, version, sha)
            self.assertEqual(plan["bundleAcquisition"]["managementWorkloadImagePlan"], lab._management_workload_image_plan_projection(artifact, version, sha, lock))
            # Once the workload archive itself is locked there is no pending image plan
            # to project, and neither path may invent one.
            archive_lock = {
                **lock,
                "missingAuthorities": ["rke2-installer-and-offline-artifacts"],
                "resolvedAuthorities": list(lock["resolvedAuthorities"]) + [{
                    "id": "management-workload-oci-archive", "kind": "oci-archive", "provider": "4so", "version": "v1.0.0", "scope": "fixture",
                    "artifacts": [{"name": "platform-workloads.oci.tar", "stagingPath": "workloads/platform-workloads.oci.tar", "sha256": "c" * 64, "sizeBytes": 4096, "urls": ["https://downloads.example.invalid/workloads.tar"]}],
                }],
            }
            self.assertIsNone(lab._management_workload_image_plan_projection(artifact, version, sha, archive_lock))

    def test_inventory_digest_is_order_independent_and_plan_bound(self):
        with tempfile.TemporaryDirectory() as td:
            spec = self._spec(Path(td))
            body = lab.validate_spec(spec)
            digest = lab._server_inventory_digest(body)
            self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")
            spec["spec"]["servers"] = list(reversed(spec["spec"]["servers"]))
            reordered = lab.validate_spec(spec)
            self.assertEqual(digest, lab._server_inventory_digest(reordered))
            plan = lab.plan_document(spec)
            self.assertEqual(digest, plan["serverInventoryDigest"])
            self.assertEqual(lab.EXACT_RELEASE_SNAPSHOT_AUTHORITY, plan["releaseArtifactAuthority"])
            self.assertEqual(lab.EXACT_RELEASE_EXECUTION_AUTHORITY, plan["releaseExecutionAuthority"])

    def test_exact_release_snapshot_isolated_from_source_path_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = self._release(root)
            snapshot = root / "state" / "release-artifact.zip"
            root_name, version, digest = lab._snapshot_release_artifact(source, snapshot)
            self.assertEqual("9.9.9", version)
            self.assertEqual(0, snapshot.stat().st_mode & 0o222)
            replacement = root / "replacement.zip"
            prefix = "4so-platform-factory-8.8.8-replaced"
            with zipfile.ZipFile(replacement, "w") as zf:
                zf.writestr(prefix + "/VERSION", "8.8.8\n")
                zf.writestr(prefix + "/RELEASE-NAME", "replaced\n")
            os.replace(replacement, source)
            self.assertEqual((root_name, version, digest), lab._release_identity(snapshot))
            self.assertNotEqual(digest, lab._release_identity(source)[2])

    def test_exact_release_snapshot_rejects_same_inode_metadata_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = self._release(root)
            target = root / "state" / "release-artifact.zip"
            original_fstat = lab.os.fstat
            calls = 0

            def drifting_fstat(fd):
                nonlocal calls
                current = original_fstat(fd)
                calls += 1
                if calls == 2:
                    return SimpleNamespace(
                        st_mode=current.st_mode,
                        st_size=current.st_size,
                        st_ino=current.st_ino,
                        st_dev=current.st_dev,
                        st_mtime_ns=current.st_mtime_ns + 1,
                        st_ctime_ns=current.st_ctime_ns,
                    )
                return current

            with mock.patch.object(lab.os, "fstat", side_effect=drifting_fstat):
                with self.assertRaisesRegex(SystemExit, "changed while snapshotting"):
                    lab._snapshot_release_artifact(source, target)

    def test_release_identity_binds_version_and_digest_to_one_open_inode(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = self._release(root)
            original_fstat = lab.os.fstat
            calls = 0

            def drifting_fstat(fd):
                nonlocal calls
                current = original_fstat(fd)
                calls += 1
                if calls == 2:
                    return SimpleNamespace(
                        st_mode=current.st_mode,
                        st_size=current.st_size,
                        st_ino=current.st_ino,
                        st_dev=current.st_dev,
                        st_mtime_ns=current.st_mtime_ns,
                        st_ctime_ns=current.st_ctime_ns + 1,
                    )
                return current

            with mock.patch.object(lab.os, "fstat", side_effect=drifting_fstat):
                with self.assertRaisesRegex(SystemExit, "changed while reading identity"):
                    lab._release_identity(source)

    def test_exact_release_execution_rejects_path_replacement_after_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = self._release(root)
            _, _, expected = lab._release_identity(source)
            replacement = root / "replacement.zip"
            prefix = "4so-platform-factory-8.8.8-replaced"
            with zipfile.ZipFile(replacement, "w") as zf:
                zf.writestr(prefix + "/VERSION", "8.8.8\n")
                zf.writestr(prefix + "/RELEASE-NAME", "replaced\n")
            os.replace(replacement, source)
            with self.assertRaisesRegex(SystemExit, "execution digest does not match exact release authority"):
                lab._safe_extract(source, root / "out", expected_sha256=expected)

    def test_exact_release_execution_rejects_same_inode_drift_while_extracting(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = self._release(root)
            _, _, expected = lab._release_identity(source)
            original_fstat = lab.os.fstat
            calls = 0

            def drifting_fstat(fd):
                nonlocal calls
                current = original_fstat(fd)
                calls += 1
                # opened, post-hash, post-extract, final: perturb the post-extract check only.
                if calls == 3:
                    return SimpleNamespace(
                        st_mode=current.st_mode,
                        st_size=current.st_size,
                        st_ino=current.st_ino,
                        st_dev=current.st_dev,
                        st_mtime_ns=current.st_mtime_ns,
                        st_ctime_ns=current.st_ctime_ns + 1,
                    )
                return current

            with mock.patch.object(lab.os, "fstat", side_effect=drifting_fstat):
                with self.assertRaisesRegex(SystemExit, "changed while extracting"):
                    lab._safe_extract(source, root / "out", expected_sha256=expected)

    def test_persistent_release_snapshot_refuses_state_rebind(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec = self._spec(root)
            target = root / "state" / "release-artifact.zip"
            snap_spec, first = lab._spec_with_persistent_release_snapshot(spec, target)
            self.assertEqual(str(target.resolve()), snap_spec["spec"]["releaseArtifact"])
            _, second = lab._spec_with_persistent_release_snapshot(spec, target)
            self.assertEqual(first, second)

            other = root / "other.zip"
            prefix = "4so-platform-factory-8.8.8-other-release"
            with zipfile.ZipFile(other, "w") as zf:
                zf.writestr(prefix + "/VERSION", "8.8.8\n")
                zf.writestr(prefix + "/RELEASE-NAME", "other-release\n")
            spec["spec"]["releaseArtifact"] = str(other)
            with self.assertRaisesRegex(SystemExit, "already bound to a different exact release"):
                lab._spec_with_persistent_release_snapshot(spec, target)

    def test_ssh_snapshot_rejects_same_inode_ctime_drift_even_when_mtime_and_size_match(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec = self._spec(root)
            source = Path(spec["spec"]["ssh"]["knownHostsFile"])
            target = root / "state" / "known_hosts"
            original_fstat = lab.os.fstat
            calls = 0

            def drifting_fstat(fd):
                nonlocal calls
                current = original_fstat(fd)
                calls += 1
                # The first fstat is the opened source identity and the second is
                # the post-copy stability check. Preserve inode/size/mtime while
                # changing only ctime to emulate same-inode overwrite + mtime restore.
                if calls == 2:
                    return SimpleNamespace(
                        st_mode=current.st_mode,
                        st_size=current.st_size,
                        st_ino=current.st_ino,
                        st_dev=current.st_dev,
                        st_mtime_ns=current.st_mtime_ns,
                        st_ctime_ns=current.st_ctime_ns + 1,
                    )
                return current

            with mock.patch.object(lab.os, "fstat", side_effect=drifting_fstat):
                with self.assertRaisesRegex(SystemExit, "changed while snapshotting"):
                    lab._snapshot_ssh_file(source, target, label="ssh.knownHostsFile", private=False)

    def test_ssh_credentials_are_snapshotted_as_exact_bytes_and_rebind_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec = self._spec(root)
            state = root / "state"
            state.mkdir()
            snap_spec, binding = lab._spec_with_persistent_ssh_snapshots(spec, state)
            identity_snapshot = Path(snap_spec["spec"]["ssh"]["identityFile"])
            known_snapshot = Path(snap_spec["spec"]["ssh"]["knownHostsFile"])
            self.assertEqual("dummy-private-key", identity_snapshot.read_text(encoding="utf-8"))
            self.assertEqual("example.invalid ssh-ed25519 AAAA\n", known_snapshot.read_text(encoding="utf-8"))
            self.assertEqual(0, identity_snapshot.stat().st_mode & 0o222)
            self.assertEqual(0, known_snapshot.stat().st_mode & 0o222)
            self.assertEqual(lab.SSH_CREDENTIAL_SNAPSHOT_AUTHORITY, binding["authority"])
            self.assertRegex(binding["bindingDigest"], r"^sha256:[0-9a-f]{64}$")

            Path(spec["spec"]["ssh"]["knownHostsFile"]).write_text(
                "attacker.invalid ssh-ed25519 BBBB\n", encoding="utf-8"
            )
            self.assertEqual("example.invalid ssh-ed25519 AAAA\n", known_snapshot.read_text(encoding="utf-8"))
            with self.assertRaisesRegex(SystemExit, "already bound to different SSH credential/host-trust bytes"):
                lab._spec_with_persistent_ssh_snapshots(spec, state)

    def test_ssh_snapshot_rejects_symlink_source_and_run_binding_contains_byte_authority(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec = self._spec(root)
            original = Path(spec["spec"]["ssh"]["knownHostsFile"])
            target = root / "other-known-hosts"
            target.write_text("example.invalid ssh-ed25519 CCCC\n", encoding="utf-8")
            original.unlink()
            original.symlink_to(target)
            state = root / "state"
            state.mkdir()
            with self.assertRaisesRegex(SystemExit, "regular non-symlink"):
                lab._spec_with_persistent_ssh_snapshots(spec, state)

            # Restore a regular file and prove the physical run-state binding carries byte authority.
            original.unlink()
            original.write_text("example.invalid ssh-ed25519 AAAA\n", encoding="utf-8")
            snap_spec, ssh_binding = lab._spec_with_persistent_ssh_snapshots(spec, state)
            artifact_sha = lab._release_identity(Path(snap_spec["spec"]["releaseArtifact"]))[2]
            preflight = {"bundleBinding": {
                "mode": "provided",
                "bundleDigest": "sha256:" + "1" * 64,
                "bundleLockDigest": "sha256:" + "2" * 64,
            }}
            binding = lab._run_state_binding(snap_spec, preflight, artifact_sha, ssh_binding)
            self.assertEqual(2, binding["schemaVersion"])
            self.assertEqual(lab.SSH_CREDENTIAL_SNAPSHOT_AUTHORITY, binding["sshCredentialBinding"]["authority"])
            self.assertRegex(binding["sshCredentialBinding"]["knownHostsFile"]["sha256"], r"^sha256:[0-9a-f]{64}$")

    def test_run_state_lock_fences_concurrent_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            with lab._exclusive_run_state(state):
                with self.assertRaisesRegex(SystemExit, "already active"):
                    with lab._exclusive_run_state(state):
                        self.fail("second state lock must never be acquired")

    def test_run_state_binding_is_immutable_for_release_topology_spec_and_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec = self._spec(root)
            body = lab.validate_spec(spec)
            artifact_sha = lab._release_identity(Path(body["releaseArtifact"]))[2]
            preflight = {
                "bundleBinding": {
                    "mode": "provided",
                    "bundleDigest": "sha256:" + "1" * 64,
                    "bundleLockDigest": "sha256:" + "2" * 64,
                }
            }
            binding = lab._run_state_binding(spec, preflight, artifact_sha)
            state = root / "state"
            state.mkdir()
            self.assertEqual("created", lab._bind_or_verify_run_state(state, binding))
            self.assertEqual("reused", lab._bind_or_verify_run_state(state, binding))
            self.assertEqual(lab.RUN_STATE_BINDING_AUTHORITY, binding["authority"])
            self.assertRegex(binding["bindingDigest"], r"^sha256:[0-9a-f]{64}$")

            changed = json.loads(json.dumps(binding))
            changed["bundleBinding"]["bundleDigest"] = "sha256:" + "3" * 64
            with self.assertRaisesRegex(SystemExit, "already bound to different release/topology/spec/ssh/bundle authority"):
                lab._bind_or_verify_run_state(state, changed)

            # AI is advisory and intentionally excluded from the physical run-state digest.
            ai_changed = json.loads(json.dumps(spec))
            ai_changed["spec"]["ai"] = {"provider": "codex-cli", "maxTurns": 2}
            self.assertEqual(
                lab._execution_spec_digest(spec, artifact_sha),
                lab._execution_spec_digest(ai_changed, artifact_sha),
            )
            topology_changed = json.loads(json.dumps(spec))
            topology_changed["spec"]["servers"][0]["host"] = "different.example.invalid"
            self.assertNotEqual(
                lab._execution_spec_digest(spec, artifact_sha),
                lab._execution_spec_digest(topology_changed, artifact_sha),
            )

    def test_atomic_lab_writes_ignore_precreated_predictable_tmp_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            victim = root / "victim"
            victim.write_text("DO-NOT-CLOBBER", encoding="utf-8")

            source = self._release(root)
            state = root / "state"
            state.mkdir()
            (state / "release-artifact.zip.tmp").symlink_to(victim)
            lab._snapshot_release_artifact(source, state / "release-artifact.zip")
            self.assertEqual("DO-NOT-CLOBBER", victim.read_text(encoding="utf-8"))

            (state / "evidence.json.tmp").symlink_to(victim)
            lab._write_json(state / "evidence.json", {"ok": True})
            self.assertEqual("DO-NOT-CLOBBER", victim.read_text(encoding="utf-8"))
            self.assertEqual({"ok": True}, json.loads((state / "evidence.json").read_text()))

    def test_release_archive_rejects_duplicate_and_non_regular_members(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = "4so-platform-factory-9.9.9-test-release"
            duplicate = root / "duplicate.zip"
            with zipfile.ZipFile(duplicate, "w") as zf:
                zf.writestr(prefix + "/VERSION", "9.9.9\n")
                zf.writestr(prefix + "/VERSION", "9.9.9\n")
                zf.writestr(prefix + "/RELEASE-NAME", "test-release\n")
            with self.assertRaisesRegex(SystemExit, "duplicate path"):
                lab._release_identity(duplicate)

            symlink = root / "symlink.zip"
            with zipfile.ZipFile(symlink, "w") as zf:
                zf.writestr(prefix + "/VERSION", "9.9.9\n")
                zf.writestr(prefix + "/RELEASE-NAME", "test-release\n")
                info = zipfile.ZipInfo(prefix + "/payload")
                info.create_system = 3
                info.external_attr = ((stat.S_IFLNK | 0o777) & 0xFFFF) << 16
                zf.writestr(info, "VERSION")
            with self.assertRaisesRegex(SystemExit, "non-regular entry"):
                lab._release_identity(symlink)

    def test_inventory_rejects_same_physical_host_for_multiple_roles(self):
        with tempfile.TemporaryDirectory() as td:
            spec = self._spec(Path(td))
            spec["spec"]["servers"][1]["host"] = spec["spec"]["servers"][0]["host"].upper()
            with self.assertRaisesRegex(SystemExit, "distinct host"):
                lab.validate_spec(spec)

    def test_ssh_remote_script_places_option_terminator_before_destination_and_quotes_command(self):
        body = {"ssh": {"knownHostsFile": "/tmp/known", "identityFile": "/tmp/id"}}
        command = lab._ssh_command(body, "example.invalid", "printf '%s\n' 'hello world'")
        marker = command.index("--")
        self.assertEqual("root@example.invalid", command[marker + 1])
        remote_argv = command[marker + 2:]
        self.assertEqual("sh", remote_argv[0])
        # OpenSSH concatenates every argv after destination into the remote command.
        self.assertNotEqual("--", remote_argv[0])
        payload = " ".join(remote_argv)
        import subprocess
        result = subprocess.run(["sh", "-c", payload], text=True, capture_output=True, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("hello world\n", result.stdout)

    def test_boot_id_parser_requires_real_uuid(self):
        valid = {"status": "PASS", "outputTail": "boot=01234567-89ab-cdef-0123-456789abcdef\n"}
        self.assertEqual("01234567-89ab-cdef-0123-456789abcdef", lab._boot_id_from_result(valid))
        self.assertEqual("", lab._boot_id_from_result({"status": "FAIL", "outputTail": valid["outputTail"]}))
        self.assertEqual("", lab._boot_id_from_result({"status": "PASS", "outputTail": "not-a-boot-id"}))


    def test_m03_plan_is_bound_only_to_production_ha(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            minimum = lab.plan_document(self._spec(root))
            self.assertEqual(["M00", "M01"], [row["id"] for row in minimum["matrixRows"]])
            production = lab.plan_document(self._production_ha_spec(root))
            self.assertEqual(["M00", "M02", "M03"], [row["id"] for row in production["matrixRows"]])
            m03 = next(row for row in production["matrixRows"] if row["id"] == "M03")
            self.assertEqual("production-ha", m03["serverTier"])
            self.assertEqual("IMPLEMENTED", m03["automationStatus"])
            self.assertIn("PostgreSQL primary restart/failover", m03["actions"])

    def test_m03_private_output_never_exposes_password_or_ca_payload(self):
        password = "a" * 48
        ca = b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
        ca_b64 = base64.b64encode(ca).decode()
        output = (
            "M03_ROLE=pf_cert_0123456789abcdef\n"
            "M03_DATABASE=pf_cert_0123456789abcdef\n"
            f"M03_PASSWORD={password}\n"
            "M03_SERVICE_IP=10.43.0.10\n"
            f"M03_CA_B64={ca_b64}\n"
        )
        parsed = lab._parse_m03_bootstrap_output(output)
        self.assertEqual("pf_cert_0123456789abcdef", parsed["M03_ROLE"])
        safe = lab._sanitize_private_stage_output(output)
        self.assertNotIn(password, safe)
        self.assertNotIn(ca_b64, safe)
        self.assertIn("M03_PASSWORD=[REDACTED]", safe)
        self.assertIn("M03_CA_B64=[OMITTED]", safe)

    def test_m03_sealed_evidence_rejects_digest_tamper_or_plaintext_credential(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "m03.json"
            artifact_sha = "a" * 64
            evidence = {
                "schemaVersion": 2,
                "mode": "runtime",
                "releaseEvidenceAuthority": lab.M03_EXACT_RELEASE_EVIDENCE_AUTHORITY,
                "releaseArtifactDigest": "sha256:" + artifact_sha,
                "status": "PASS",
                "runtimeCertified": True,
                "aiRunPostgresDurabilityAuthority": lab.AI_RUN_POSTGRES_DURABILITY_AUTHORITY,
                "aiRunPostgresDurabilityCertified": True,
                "target": "postgresql://pf_cert:***@platform-postgresql-rw.platform-system.svc:5432/pf_cert",
                "checks": [
                    {"name": "migration", "status": "PASS", "detail": "ok", "durationMs": 1},
                    {"name": "ai-run-atomic-result-commit", "status": "PASS", "detail": "ok", "durationMs": 1},
                    {"name": "ai-run-post-restart-durability", "status": "PASS", "detail": "ok", "durationMs": 1},
                    {"name": "ai-run-post-restore-durability", "status": "PASS", "detail": "ok", "durationMs": 1},
                ],
            }
            canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
            evidence["evidenceDigest"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
            path.write_text(json.dumps(evidence), encoding="utf-8")
            ok, detail, file_digest = lab._validate_m03_evidence(path, artifact_sha)
            self.assertTrue(ok, detail)
            self.assertRegex(file_digest, r"^sha256:[0-9a-f]{64}$")
            ok, detail, _ = lab._validate_m03_evidence(path, "b" * 64)
            self.assertFalse(ok)
            self.assertIn("exact release", detail)
            missing_authority = dict(evidence)
            missing_authority.pop("aiRunPostgresDurabilityAuthority", None)
            unsigned_missing = dict(missing_authority)
            unsigned_missing.pop("evidenceDigest", None)
            missing_authority["evidenceDigest"] = "sha256:" + hashlib.sha256(json.dumps(unsigned_missing, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            path.write_text(json.dumps(missing_authority), encoding="utf-8")
            ok, detail, _ = lab._validate_m03_evidence(path, artifact_sha)
            self.assertFalse(ok)
            self.assertIn("durable PostgreSQL AI", detail)
            evidence["target"] = "postgresql://pf_cert:plaintext-secret@db.example/pf_cert"
            unsigned = dict(evidence)
            unsigned.pop("evidenceDigest", None)
            evidence["evidenceDigest"] = "sha256:" + hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            path.write_text(json.dumps(evidence), encoding="utf-8")
            ok, detail, _ = lab._validate_m03_evidence(path, artifact_sha)
            self.assertFalse(ok)
            self.assertIn("credential", detail)


    def _resolved_authorities(self, ids: list[str]) -> list[dict]:
        out = []
        for index, authority_id in enumerate(ids):
            out.append({
                "id": authority_id,
                "kind": "kubernetes-manifest" if authority_id.endswith("manifest") else "release-artifact",
                "provider": "fixture-provider",
                "version": "v1.0.0",
                "scope": "fixture-scope",
                "artifacts": [{
                    "name": f"artifact-{index}.bin",
                    "urls": [f"https://downloads.example.invalid/{index}-{authority_id}"],
                    "sha256": f"{index + 1:064x}",
                    "sizeBytes": 100 + index,
                    "stagingPath": f"fixture/{index}-{authority_id}.bin",
                }],
            })
        return out

    def _management_oci_archive(self, repositories: list[str]) -> tuple[bytes, dict[str, str]]:
        blobs: dict[str, bytes] = {}
        refs: dict[str, str] = {}
        descriptors = []
        for repo in repositories:
            config = json.dumps({"repository": repo}, sort_keys=True, separators=(",", ":")).encode()
            config_digest = hashlib.sha256(config).hexdigest()
            blobs[config_digest] = config
            manifest = {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + config_digest, "size": len(config)},
                "layers": [],
            }
            raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            digest = hashlib.sha256(raw).hexdigest()
            blobs[digest] = raw
            ref = repo + "@sha256:" + digest
            refs[repo] = ref
            descriptors.append({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:" + digest,
                "size": len(raw),
                "annotations": {
                    "io.containerd.image.name": ref,
                    "org.opencontainers.image.ref.name": ref,
                },
            })
        inventory = {"authority": "MANAGEMENT_WORKLOAD_OCI_ARCHIVE_INVENTORY_V2", "schemaVersion": 2, "importAddressabilityAuthority": "MANAGEMENT_WORKLOAD_OCI_IMPORT_ADDRESSABILITY_V2", "images": sorted(refs.values())}
        index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "annotations": {"org.opencontainers.image.created.by": "4so-lab-fixture"}, "manifests": sorted(descriptors, key=lambda row: row["digest"])}
        files = {
            "oci-layout": json.dumps({"imageLayoutVersion": "1.0.0"}, sort_keys=True, separators=(",", ":")).encode(),
            "index.json": json.dumps(index, sort_keys=True, separators=(",", ":")).encode(),
            "4so-image-inventory.json": json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode(),
        }
        files.update({"blobs/sha256/" + digest: raw for digest, raw in blobs.items()})
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name in sorted(files):
                raw = files[name]
                info = tarfile.TarInfo(name=name); info.size = len(raw); info.mode = 0o644; info.mtime = 0; info.uid = 0; info.gid = 0
                tf.addfile(info, io.BytesIO(raw))
        return buf.getvalue(), refs

    def _write_acquisition_lock(self, release_root: Path, *, version: str, status: str = "incomplete", pack: dict | None = None, missing: list[str] | None = None, resolved: list[dict] | None = None, partial: list[dict] | None = None) -> Path:
        path = release_root / "lab" / "appliance-bundle-acquisition-lock.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        required = sorted(lab._BUNDLE_REQUIRED_SOURCE_AUTHORITIES)
        if status == "ready":
            missing = [] if missing is None else missing
            resolved = self._resolved_authorities(required) if resolved is None else resolved
        else:
            missing = required if missing is None else missing
            resolved = [] if resolved is None else resolved
        partial = [] if partial is None else partial
        value = {
            "authority": lab.BUNDLE_ACQUISITION_AUTHORITY,
            "schemaVersion": 8,
            "releaseVersion": version,
            "status": status,
            "inputPack": pack,
            "resolvedAuthorities": resolved,
            "partialAuthorities": partial,
            "missingAuthorities": missing,
            "derivedAuthorities": ["digest-pinned-core-workload-images"],
        }
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def _image_plan_value(self, version: str) -> dict:
        return {
            "authority": lab.MANAGEMENT_WORKLOAD_IMAGE_PLAN_AUTHORITY,
            "schemaVersion": 5,
            "releaseVersion": version,
            "targetPlatform": {"os":"linux","architecture":"amd64"},
            "archiveStagingPath": "workloads/platform-workloads.oci.tar",
            "coreImages": [
                {"role":"postgresql","ownership":"external","repository":"docker.io/library/postgres","registryEndpoint":"registry-1.docker.io","registryRepository":"library/postgres","version":"17.11","tag":"17.11-bookworm","selectionChannel":"postgresql-17-patch","selectionEvidenceURL":"https://www.postgresql.org/docs/17/release-17-11.html","state":"pending","blocker":"EXACT_DIGEST_AND_RUNTIME_COMPATIBILITY_PENDING"},
                {"role":"forgejo","ownership":"external","repository":"codeberg.org/forgejo/forgejo","registryEndpoint":"data.forgejo.org","registryRepository":"forgejo/forgejo","version":"15.0.7","tag":"15.0.7","selectionChannel":"forgejo-lts","selectionEvidenceURL":"https://forgejo.org/releases/","state":"pending","blocker":"EXACT_DIGEST_AND_RUNTIME_COMPATIBILITY_PENDING"},
                {"role":"zot","ownership":"external","repository":"ghcr.io/project-zot/zot-linux-amd64","registryEndpoint":"ghcr.io","registryRepository":"project-zot/zot-linux-amd64","version":"2.1.20","tag":"v2.1.20","selectionChannel":"zot-stable","selectionEvidenceURL":"https://github.com/project-zot/zot/releases/tag/v2.1.20","state":"pending","blocker":"EXACT_DIGEST_AND_RUNTIME_COMPATIBILITY_PENDING"},
                {"role":"keycloak","ownership":"external","repository":"quay.io/keycloak/keycloak","registryEndpoint":"quay.io","registryRepository":"keycloak/keycloak","version":"26.7.3","tag":"26.7.3","selectionChannel":"keycloak-current-security","selectionEvidenceURL":"https://www.keycloak.org/2026/08/keycloak-2673-released","state":"pending","blocker":"EXACT_DIGEST_AND_RUNTIME_COMPATIBILITY_PENDING"},
                {"role":"platform-api","ownership":"product","repository":"platform.4so.local/management/platform-api","state":"pending","sourceReleaseMember":"bin/linux-amd64/platform-api","containerRecipe":"deploy/images/Dockerfile.api-release","baseImageRole":"api-runtime-base","blocker":"API_RUNTIME_DEPENDENCY_CLOSURE_AND_EXACT_RELEASE_IMAGE_BUILD_PENDING"},
                {"role":"maintenance","ownership":"product","repository":"platform.4so.local/management/maintenance","state":"pending","containerRecipe":"deploy/images/Dockerfile.maintenance","baseImageRole":"maintenance-toolchain-base","blocker":"MAINTENANCE_TOOLSET_BASE_DIGEST_AND_EXACT_IMAGE_BUILD_PENDING"},
                {"role":"platform-agent","ownership":"product","repository":"platform.4so.local/management/platform-agent","state":"pending","sourceReleaseMember":"bin/linux-amd64/platform-agent","containerRecipe":"deploy/images/Dockerfile.agent-release","baseImageRole":"static-runtime-base","blocker":"CA_TRUST_BASE_DIGEST_AND_EXACT_RELEASE_IMAGE_BUILD_PENDING"},
                {"role":"platform-probe","ownership":"product","repository":"platform.4so.local/management/platform-probe","state":"pending","sourceReleaseMember":"bin/linux-amd64/platform-probe","containerRecipe":"deploy/images/Dockerfile.probe-release","baseImageRole":"static-runtime-base","blocker":"RUNTIME_BASE_DIGEST_AND_EXACT_RELEASE_IMAGE_BUILD_PENDING"}
            ],
            "baseImages": [
                {"role":"api-runtime-base","state":"pending","blocker":"EXACT_DIGEST_FULL_DYNAMIC_DEPENDENCY_AND_NONROOT_COMPATIBILITY_PENDING"},
                {"role":"static-runtime-base","state":"pending","blocker":"EXACT_DIGEST_CA_TRUST_AND_NONROOT_COMPATIBILITY_PENDING"},
                {"role":"maintenance-toolchain-base","state":"pending","blocker":"EXACT_DIGEST_REQUIRED_TOOLSET_AND_ROOT_OVERRIDE_COMPATIBILITY_PENDING"}
            ],
            "derivedManifestImageSets": [
                {"sourceAuthority":"argocd-install-manifest","manifestPath":"manifests/argocd-install.yaml","sourceManifestSha256":"sha256:a32bf36a437071a1f563ebf9e81c8a39fba9057c17db7d5d041afb7b6e3f4afe","sourceManifestBytes":1917766,"resolvedManifestPath":"runtime-manifests/argocd-install.yaml","resolutionLockPath":"runtime-manifests/argocd-install.image-lock.json","state":"pending","blocker":"EXACT_MANIFEST_IMAGE_DIGEST_RESOLUTION_PENDING"},
                {"sourceAuthority":"argocd-ha-install-manifest","manifestPath":"manifests/argocd-ha-install.yaml","sourceManifestSha256":"sha256:65d9d4ff520ddb40bad2c39b1f44188ceecfe96b5dd29c8ead569b52d6c6b8c6","sourceManifestBytes":1969264,"resolvedManifestPath":"runtime-manifests/argocd-ha-install.yaml","resolutionLockPath":"runtime-manifests/argocd-ha-install.image-lock.json","state":"pending","blocker":"EXACT_MANIFEST_IMAGE_DIGEST_RESOLUTION_PENDING"},
                {"sourceAuthority":"cloudnative-pg-install-manifest","manifestPath":"manifests/cloudnative-pg-install.yaml","sourceManifestSha256":"sha256:f8bede43fe4ee0d478c2355b204a36876b2ae4faac60f2a9452280b293da3b88","sourceManifestBytes":1262410,"resolvedManifestPath":"runtime-manifests/cloudnative-pg-install.yaml","resolutionLockPath":"runtime-manifests/cloudnative-pg-install.image-lock.json","state":"pending","blocker":"EXACT_MANIFEST_IMAGE_DIGEST_RESOLUTION_PENDING"},
                {"sourceAuthority":"replicated-storage-install-manifest","manifestPath":"manifests/replicated-storage-install.yaml","sourceManifestSha256":"sha256:41648963af867ac1d0c85755fb53cf61cacd57c9bb22e1942e3fb0439eeb04fd","sourceManifestBytes":207054,"resolvedManifestPath":"runtime-manifests/replicated-storage-install.yaml","resolutionLockPath":"runtime-manifests/replicated-storage-install.image-lock.json","state":"pending","blocker":"EXACT_MANIFEST_IMAGE_DIGEST_RESOLUTION_PENDING"}
            ],
            "manifestImageResolutionAuthority": lab.MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY,
            "externalVersionSelectionAuthority": "MANAGEMENT_WORKLOAD_EXTERNAL_VERSION_SELECTION_V1",
            "externalAcquisitionAuthority": "MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_V2",
            "assemblyAuthority": lab.MANAGEMENT_WORKLOAD_OCI_ASSEMBLY_AUTHORITY,
            "inventoryAuthority": "MANAGEMENT_WORKLOAD_OCI_ARCHIVE_INVENTORY_V2",
            "importAddressabilityAuthority": "MANAGEMENT_WORKLOAD_OCI_IMPORT_ADDRESSABILITY_V2",
            "productImageCertificationAuthority": "MANAGEMENT_WORKLOAD_PRODUCT_IMAGE_CERTIFICATION_V1",
        }

    def _release_with_acquisition_lock(self, root: Path, lock_path: Path) -> Path:
        version = "9.9.9"
        name = "test-release"
        archive = root / "release.zip"
        prefix = f"4so-platform-factory-{version}-{name}"
        plan = self._image_plan_value(version)
        lock_value = json.loads(lock_path.read_text(encoding="utf-8"))
        by_id = {row.get("id"): row for row in lock_value.get("resolvedAuthorities", []) if isinstance(row, dict)}
        for row in plan["derivedManifestImageSets"]:
            authority = by_id.get(row["sourceAuthority"])
            artifacts = authority.get("artifacts", []) if isinstance(authority, dict) else []
            if len(artifacts) == 1:
                row["sourceManifestSha256"] = "sha256:" + artifacts[0]["sha256"]
                row["sourceManifestBytes"] = artifacts[0]["sizeBytes"]
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr(prefix + "/VERSION", version + "\n")
            zf.writestr(prefix + "/RELEASE-NAME", name + "\n")
            zf.writestr(prefix + "/" + lab.BUNDLE_ACQUISITION_LOCK_REL, lock_path.read_bytes())
            zf.writestr(prefix + "/" + lab.MANAGEMENT_WORKLOAD_IMAGE_PLAN_REL, json.dumps(plan, separators=(",", ":")))
        return archive

    def _ready_source_fixture(self):
        image_keys = (
            "postgresqlImage", "platformApiImage", "forgejoImage", "zotImage",
            "keycloakImage", "maintenanceImage", "fleetAgentImage", "runtimeProbeImage",
        )
        repos = {key: f"registry.example/{key.lower()}" for key in image_keys}
        archive, refs_by_repo = self._management_oci_archive(list(repos.values()))
        image_refs = {key: refs_by_repo[repos[key]] for key in image_keys}
        files = {
            "rke2/install.sh": b"#!/bin/sh\nexit 0\n",
            "rke2/rke2.linux-amd64.tar.gz": b"fixture-rke2-server-tar",
            "rke2/rke2-images.linux-amd64.tar.zst": b"fixture-rke2-offline-images",
            "rke2/sha256sum-amd64.txt": b"fixture-checksum-file",
            "workloads/platform-workloads.oci.tar": archive,
            "manifests/argocd-install.yaml": b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: fixture-argocd\n",
            "manifests/argocd-ha-install.yaml": b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: fixture-argocd-ha\n",
            "manifests/cloudnative-pg-install.yaml": b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: fixture-cnpg\n",
            "manifests/replicated-storage-install.yaml": b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: fixture-storage\n",
        }
        def artifact(path):
            payload = files[path]
            return {"name": Path(path).name, "stagingPath": path, "urls": ["https://downloads.example.invalid/" + path], "sha256": hashlib.sha256(payload).hexdigest(), "sizeBytes": len(payload)}
        resolved = [
            {"id":"rke2-installer-and-offline-artifacts","kind":"release-artifact-set","provider":"rke2","version":"v1.0.0","scope":"fixture","artifacts":[artifact("rke2/install.sh"), artifact("rke2/rke2.linux-amd64.tar.gz"), artifact("rke2/sha256sum-amd64.txt"), artifact("rke2/rke2-images.linux-amd64.tar.zst")]},
            {"id":"management-workload-oci-archive","kind":"oci-archive","provider":"4so","version":"v1.0.0","scope":"fixture","artifacts":[artifact("workloads/platform-workloads.oci.tar")]},
            {"id":"argocd-install-manifest","kind":"kubernetes-manifest","provider":"argocd","version":"v1.0.0","scope":"fixture","artifacts":[artifact("manifests/argocd-install.yaml")]},
            {"id":"argocd-ha-install-manifest","kind":"kubernetes-manifest","provider":"argocd","version":"v1.0.0","scope":"fixture","artifacts":[artifact("manifests/argocd-ha-install.yaml")]},
            {"id":"cloudnative-pg-install-manifest","kind":"kubernetes-manifest","provider":"cnpg","version":"v1.0.0","scope":"fixture","artifacts":[artifact("manifests/cloudnative-pg-install.yaml")]},
            {"id":"replicated-storage-install-manifest","kind":"kubernetes-manifest","provider":"longhorn","version":"v1.0.0","scope":"fixture","artifacts":[artifact("manifests/replicated-storage-install.yaml")]},
        ]
        workloads = {"imageArchives": ["workloads/platform-workloads.oci.tar"], **image_refs, "gitOpsManifest": "manifests/argocd-install.yaml", "gitOpsHAManifest": "manifests/argocd-ha-install.yaml", "cloudNativePGManifest": "manifests/cloudnative-pg-install.yaml", "storageManifest": "manifests/replicated-storage-install.yaml"}
        build_spec = {"apiVersion":"platform.4so.io/v1alpha1","kind":"ApplianceBundleBuild","metadata":{"version":"9.9.9","sourceReleaseDigest":"sha256:"+"0"*64},"spec":{"rke2":{"version":"v1.0.0","installer":"rke2/install.sh","installArtifacts":["rke2/rke2.linux-amd64.tar.gz","rke2/sha256sum-amd64.txt"],"imageArchives":["rke2/rke2-images.linux-amd64.tar.zst"]},"workloads":workloads}}
        return resolved, files, build_spec

    def _materialize_ready_source_fixture(self, pack_root: Path, files: dict[str, bytes], build_spec: dict):
        staging = pack_root / "staging"
        staging.mkdir(parents=True, exist_ok=True)
        for rel, payload in files.items():
            target = staging / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        (pack_root / "build-spec.json").write_text(json.dumps(build_spec), encoding="utf-8")

    def _fixture_manifest_resolution(self, pack_root: Path, image_plan: dict) -> dict:
        staging = pack_root / "staging"
        archive_refs = sorted(lab._inspect_management_workload_oci_archive(staging / "workloads/platform-workloads.oci.tar"))
        if not archive_refs:
            raise AssertionError("fixture workload OCI archive must contain at least one exact image")
        exact_fixture = archive_refs[0]
        source_fixture = lab._image_repository(exact_fixture) + ":fixture"
        rows = []
        for item in image_plan["derivedManifestImageSets"]:
            source = staging / item["manifestPath"]
            source_raw = source.read_bytes()
            resolved_raw = source_raw + b"# digest-pinned fixture\n"
            resolved = staging / item["resolvedManifestPath"]
            lock_path = staging / item["resolutionLockPath"]
            resolved.parent.mkdir(parents=True, exist_ok=True); lock_path.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_bytes(resolved_raw)
            resolved_sha = hashlib.sha256(resolved_raw).hexdigest()
            lock_value = {
                "authority": lab.MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY, "schemaVersion": 1,
                "sourceManifestSha256": "sha256:" + hashlib.sha256(source_raw).hexdigest(), "sourceManifestBytes": len(source_raw),
                "resolvedManifestSha256": "sha256:" + resolved_sha, "resolvedManifestBytes": len(resolved_raw), "images": [{"source":source_fixture,"exact":exact_fixture}],
            }
            lock_raw = (json.dumps(lock_value, separators=(",", ":")) + "\n").encode()
            lock_path.write_bytes(lock_raw)
            rows.append({
                "sourceAuthority": item["sourceAuthority"], "sourcePath": item["manifestPath"],
                "sourceSha256": lock_value["sourceManifestSha256"], "sourceBytes": len(source_raw),
                "resolvedPath": item["resolvedManifestPath"], "resolvedSha256": lock_value["resolvedManifestSha256"], "resolvedBytes": len(resolved_raw),
                "lockPath": item["resolutionLockPath"], "lockSha256": "sha256:" + hashlib.sha256(lock_raw).hexdigest(), "lockBytes": len(lock_raw),
                "images": [exact_fixture],
            })
        proof = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return {"authority": lab.MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY, "sourceBindingDigest": "sha256:" + "b"*64, "rows": rows, "digest": "sha256:" + proof}


    def test_management_oci_archive_enforces_bounded_streaming_entry_count(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            raw, _ = self._management_oci_archive([f"registry.example/image-{i}" for i in range(8)])
            archive = root / "bounded.oci.tar"
            archive.write_bytes(raw)
            with mock.patch.object(lab, "MAX_MANAGEMENT_WORKLOAD_OCI_ENTRIES", 2):
                with self.assertRaisesRegex(RuntimeError, "too many entries"):
                    lab._inspect_management_workload_oci_archive(archive)

    def test_management_oci_archive_requires_containerd_import_addressability(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            raw, _ = self._management_oci_archive([f"registry.example/image-{i}" for i in range(8)])
            source = io.BytesIO(raw)
            files: dict[str, bytes] = {}
            with tarfile.open(fileobj=source, mode="r:") as tf:
                for member in tf.getmembers():
                    stream = tf.extractfile(member)
                    if member.isfile() and stream is not None:
                        files[member.name] = stream.read()
            index = json.loads(files["index.json"])
            index["manifests"][0].pop("annotations", None)
            files["index.json"] = json.dumps(index, sort_keys=True, separators=(",", ":")).encode()
            bad = root / "unaddressable.oci.tar"
            with tarfile.open(bad, mode="w", format=tarfile.USTAR_FORMAT) as tf:
                for name in sorted(files):
                    payload = files[name]
                    info = tarfile.TarInfo(name=name)
                    info.size = len(payload); info.mode = 0o644; info.uid = 0; info.gid = 0; info.mtime = 0
                    tf.addfile(info, io.BytesIO(payload))
            with self.assertRaisesRegex(RuntimeError, "not import-addressable"):
                lab._inspect_management_workload_oci_archive(bad)


    def test_management_oci_archive_rejects_substring_spoofed_media_type_and_open_schema(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            raw, _ = self._management_oci_archive([f"registry.example/image-{i}" for i in range(8)])
            source = io.BytesIO(raw)
            files: dict[str, bytes] = {}
            with tarfile.open(fileobj=source, mode="r:") as tf:
                for member in tf.getmembers():
                    stream = tf.extractfile(member)
                    if member.isfile() and stream is not None:
                        files[member.name] = stream.read()
            index = json.loads(files["index.json"])
            index["manifests"][0]["mediaType"] = "application/x-image.manifest.v1+json-evil"
            index["manifests"][0]["unexpectedField"] = "must-fail"
            files["index.json"] = json.dumps(index, sort_keys=True, separators=(",", ":")).encode()
            bad = root / "spoofed-media.oci.tar"
            with tarfile.open(bad, mode="w", format=tarfile.USTAR_FORMAT) as tf:
                for name in sorted(files):
                    payload = files[name]
                    info = tarfile.TarInfo(name=name)
                    info.size = len(payload); info.mode = 0o644; info.uid = 0; info.gid = 0; info.mtime = 0
                    tf.addfile(info, io.BytesIO(payload))
            with self.assertRaisesRegex(RuntimeError, "descriptor is invalid"):
                lab._inspect_management_workload_oci_archive(bad)

    def test_bundle_acquisition_incomplete_exact_release_lock_blocks_even_if_extracted_copy_is_replaced(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec = self._spec(root)
            release_root = root / "release-root"
            lock_path = self._write_acquisition_lock(release_root, version="9.9.9")
            artifact = self._release_with_acquisition_lock(root, lock_path)
            spec["spec"]["releaseArtifact"] = str(artifact)
            body = lab.validate_spec(spec, require_bundle=True)

            # Forge the mutable extracted copy after the exact ZIP has been sealed.
            # Physical acquisition must ignore it and consume the lock bytes inside
            # the exact release artifact instead.
            pack = {
                "urls": ["https://downloads.example.invalid/forged-pack.zip"],
                "sha256": "b" * 64,
                "sizeBytes": 123,
                "format": "zip",
                "buildSpecPath": "build-spec.json",
                "stagingDirectory": "staging",
            }
            self._write_acquisition_lock(release_root, version="9.9.9", status="ready", pack=pack, missing=[])
            with mock.patch.object(lab, "_download_locked_input_pack") as download:
                bundle, evidence = lab._auto_acquire_bundle(body, artifact, release_root, root / "state")
            self.assertIsNone(bundle)
            self.assertEqual("BLOCKED", evidence["status"])
            self.assertEqual(lab.BUNDLE_SOURCE_LOCKS_BLOCKER, evidence["blocker"])
            self.assertEqual(lab.BUNDLE_ACQUISITION_EXACT_RELEASE_AUTHORITY, evidence["exactReleaseBindingAuthority"])
            self.assertEqual(sorted(lab._BUNDLE_REQUIRED_SOURCE_AUTHORITIES), evidence["missingAuthorities"])
            download.assert_not_called()

    def test_shipped_acquisition_lock_v8_tracks_source_and_derived_truth(self):
        release_root = ROOT
        lock, _ = lab._load_bundle_acquisition_lock(release_root, (release_root / "VERSION").read_text(encoding="utf-8").strip())
        self.assertEqual("incomplete", lock["status"])
        self.assertEqual(5, len(lock["resolvedAuthorities"]))
        self.assertEqual(1, len(lock["partialAuthorities"]))
        self.assertEqual(0, len(lock["missingAuthorities"]))
        archive = lock["partialAuthorities"][0]
        self.assertEqual("management-workload-oci-archive", archive["id"])
        self.assertEqual([], archive["artifacts"])
        self.assertEqual(1, len(archive["pendingArtifacts"]))
        self.assertIn("archiveBuilt must not imply distributionReady", archive["pendingArtifacts"][0]["reason"])
        self.assertEqual(["digest-pinned-core-workload-images"], lock["derivedAuthorities"])
        by_id = {item["id"]: item for item in lock["resolvedAuthorities"]}
        storage = by_id["replicated-storage-install-manifest"]
        self.assertEqual("longhorn", storage["provider"])
        self.assertEqual("41648963af867ac1d0c85755fb53cf61cacd57c9bb22e1942e3fb0439eeb04fd", storage["artifacts"][0]["sha256"])
        cnpg = by_id["cloudnative-pg-install-manifest"]
        self.assertEqual("v1.30.0", cnpg["version"])
        self.assertEqual("f8bede43fe4ee0d478c2355b204a36876b2ae4faac60f2a9452280b293da3b88", cnpg["artifacts"][0]["sha256"])
        rke2 = by_id["rke2-installer-and-offline-artifacts"]
        self.assertEqual(4, len(rke2["artifacts"]))
        rke2_install = {item["stagingPath"]: item for item in rke2["artifacts"]}["rke2/install.sh"]
        self.assertEqual("2d24db2184dd6b1a5e281fa45cc9a8234c889394721746f89b5fe953fdaaf40a", rke2_install["sha256"])
        self.assertEqual(25288, rke2_install["sizeBytes"])
        self.assertEqual("https://raw.githubusercontent.com/rancher/rke2/d419f09226d50a4777d348e5c53ea1bce3849b77/install.sh", rke2_install["urls"][0])
        argocd = by_id["argocd-install-manifest"]
        argocd_install = argocd["artifacts"][0]
        self.assertEqual("a32bf36a437071a1f563ebf9e81c8a39fba9057c17db7d5d041afb7b6e3f4afe", argocd_install["sha256"])
        self.assertEqual(1917766, argocd_install["sizeBytes"])
        self.assertEqual("https://raw.githubusercontent.com/argoproj/argo-cd/e95e1be88a2da6c06bff5c2fe1791e4d233ed810/manifests/install.yaml", argocd_install["urls"][0])
        argocd_ha = by_id["argocd-ha-install-manifest"]
        argocd_ha_install = argocd_ha["artifacts"][0]
        self.assertEqual("65d9d4ff520ddb40bad2c39b1f44188ceecfe96b5dd29c8ead569b52d6c6b8c6", argocd_ha_install["sha256"])
        self.assertEqual(1969264, argocd_ha_install["sizeBytes"])
        self.assertEqual("https://raw.githubusercontent.com/argoproj/argo-cd/e95e1be88a2da6c06bff5c2fe1791e4d233ed810/manifests/ha/install.yaml", argocd_ha_install["urls"][0])

    def test_shipped_management_workload_image_build_plan_is_explicit_and_incomplete(self):
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        plan, digest = lab._load_management_workload_image_plan(ROOT, version)
        self.assertEqual(lab.MANAGEMENT_WORKLOAD_IMAGE_PLAN_AUTHORITY, plan["authority"])
        self.assertEqual(lab.MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY, plan["manifestImageResolutionAuthority"])
        self.assertEqual(lab.MANAGEMENT_WORKLOAD_OCI_ASSEMBLY_AUTHORITY, plan["assemblyAuthority"])
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(15, len(plan["pendingResolution"]))
        self.assertEqual({"postgresql","forgejo","zot","keycloak","platform-api","maintenance","platform-agent","platform-probe","api-runtime-base","static-runtime-base","maintenance-toolchain-base","manifest:argocd-install-manifest","manifest:argocd-ha-install-manifest","manifest:cloudnative-pg-install-manifest","manifest:replicated-storage-install-manifest"}, {row["role"] for row in plan["pendingResolution"]})
        postgresql = next(row for row in plan["pendingResolution"] if row["role"] == "postgresql")
        self.assertEqual("17.11", postgresql["version"])
        self.assertEqual("17.11-bookworm", postgresql["tag"])
        self.assertEqual("registry-1.docker.io", postgresql["registryEndpoint"])
        forgejo = next(row for row in plan["pendingResolution"] if row["role"] == "forgejo")
        self.assertEqual("data.forgejo.org", forgejo["registryEndpoint"])

    def test_manifest_image_resolution_rejects_repository_absent_from_exact_oci_archive(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); pack_root = root / "pack"
            resolved, files, build_spec = self._ready_source_fixture()
            self._materialize_ready_source_fixture(pack_root, files, build_spec)
            lock_path = self._write_acquisition_lock(root, version="9.9.9", status="ready", pack={"urls":["https://downloads.example.invalid/pack.zip"],"sha256":"a"*64,"sizeBytes":1,"format":"zip","buildSpecPath":"build-spec.json","stagingDirectory":"staging"}, missing=[], resolved=resolved)
            lock = json.loads(lock_path.read_text())
            image_plan = self._image_plan_value("9.9.9")
            by_id = {row["id"]: row for row in resolved}
            for item in image_plan["derivedManifestImageSets"]:
                artifact = by_id[item["sourceAuthority"]]["artifacts"][0]
                item["sourceManifestSha256"] = "sha256:" + artifact["sha256"]
                item["sourceManifestBytes"] = artifact["sizeBytes"]
            inspect_value = {
                "authority": lab.MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY,
                "schemaVersion": 1,
                "images": ["registry.example/not-in-archive:v1"],
            }
            with mock.patch.object(lab, "_run", return_value={"status":"PASS","outputTail":json.dumps(inspect_value)}) as run:
                with self.assertRaisesRegex(RuntimeError, "absent from the exact management workload OCI archive"):
                    lab._resolve_acquired_manifest_images(
                        pack_root, {"stagingDirectory":"staging"}, lock, image_plan, Path("/fake/platformctl"), cwd=root,
                    )
            self.assertEqual(1, run.call_count)

    def test_management_workload_image_plan_rejects_acquisition_manifest_drift(self):
        plan = self._image_plan_value("9.9.9")
        resolved = []
        for row in plan["derivedManifestImageSets"]:
            resolved.append({"id":row["sourceAuthority"],"artifacts":[{"stagingPath":row["manifestPath"],"sha256":row["sourceManifestSha256"].removeprefix("sha256:"),"sizeBytes":row["sourceManifestBytes"]}]})
        lock = {"resolvedAuthorities": resolved}
        digest = lab._verify_management_workload_image_plan_lock_binding(plan, lock)
        self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")
        lock["resolvedAuthorities"][0]["artifacts"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "drifts from acquisition lock"):
            lab._verify_management_workload_image_plan_lock_binding(plan, lock)

    def test_management_workload_image_build_plan_rejects_mutable_role_drift(self):
        value = self._image_plan_value("9.9.9")
        value["coreImages"][0]["repository"] = "evil.invalid/postgres"
        with self.assertRaisesRegex(RuntimeError, "external core image role postgresql version/transport contract is invalid"):
            lab._parse_management_workload_image_plan(json.dumps(value).encode(), "9.9.9")
        value = self._image_plan_value("9.9.9")
        value["coreImages"][4]["sourceReleaseMember"] = "bin/linux-amd64/platform-probe"
        with self.assertRaisesRegex(RuntimeError, "exact-release binary contract is invalid"):
            lab._parse_management_workload_image_plan(json.dumps(value).encode(), "9.9.9")

    def test_bundle_acquisition_lock_rejects_overlap_or_silent_authority_omission(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            required = sorted(lab._BUNDLE_REQUIRED_SOURCE_AUTHORITIES)
            resolved = self._resolved_authorities([required[0]])
            self._write_acquisition_lock(root, version="9.9.9", missing=required, resolved=resolved)
            with self.assertRaisesRegex(RuntimeError, "more than one resolved/partial/missing"):
                lab._load_bundle_acquisition_lock(root, "9.9.9")
            self._write_acquisition_lock(root, version="9.9.9", missing=required[1:-1], resolved=resolved)
            with self.assertRaisesRegex(RuntimeError, "complete canonical source-authority set"):
                lab._load_bundle_acquisition_lock(root, "9.9.9")

    def test_partial_authority_prevents_ready_state_and_is_structured_in_blocked_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            required = sorted(lab._BUNDLE_REQUIRED_SOURCE_AUTHORITIES)
            partial = [{
                "id": required[0],
                "kind": "release-artifact-set",
                "provider": "fixture-provider",
                "version": "v1.0.0",
                "scope": "fixture-scope",
                "artifacts": [],
                "pendingArtifacts": [{
                    "name": "install.sh",
                    "reason": "byte-lock-pending",
                    "sourceRef": "https://github.com/example/project/blob/0123456789abcdef0123456789abcdef01234567/install.sh",
                    "contentAddress": "git-sha1:" + "a" * 40,
                    "stagingPath": "fixture/install.sh",
                }],
            }]
            missing = required[1:]
            self._write_acquisition_lock(root, version="9.9.9", missing=missing, partial=partial)
            lock, _ = lab._load_bundle_acquisition_lock(root, "9.9.9")
            self.assertEqual(required[0], lock["partialAuthorities"][0]["id"])
            value = json.loads((root / "lab" / "appliance-bundle-acquisition-lock.json").read_text())
            value["status"] = "ready"
            value["inputPack"] = {"urls":["https://downloads.example.invalid/pack.zip"],"sha256":"b"*64,"sizeBytes":123,"format":"zip","buildSpecPath":"build-spec.json","stagingDirectory":"staging"}
            (root / "lab" / "appliance-bundle-acquisition-lock.json").write_text(json.dumps(value))
            with self.assertRaisesRegex(RuntimeError, "fully resolved"):
                lab._load_bundle_acquisition_lock(root, "9.9.9")

    def test_bundle_acquisition_ready_lock_rejects_non_https_or_query_bearing_source(self):
        with tempfile.TemporaryDirectory() as td:
            release_root = Path(td)
            base = {
                "urls": ["http://downloads.example.invalid/bundle.zip"],
                "sha256": "a" * 64,
                "sizeBytes": 100,
                "format": "zip",
                "buildSpecPath": "build-spec.json",
                "stagingDirectory": "staging",
            }
            self._write_acquisition_lock(release_root, version="9.9.9", status="ready", pack=base, missing=[])
            with self.assertRaisesRegex(RuntimeError, "HTTPS"):
                lab._load_bundle_acquisition_lock(release_root, "9.9.9")
            base["urls"] = ["https://downloads.example.invalid/bundle.zip?token=secret"]
            self._write_acquisition_lock(release_root, version="9.9.9", status="ready", pack=base, missing=[])
            with self.assertRaisesRegex(RuntimeError, "without credentials/query/fragment"):
                lab._load_bundle_acquisition_lock(release_root, "9.9.9")

    def test_bundle_input_pack_normalization_binds_exact_release_digest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pack_root = root / "pack"
            (pack_root / "staging").mkdir(parents=True)
            build_spec = {
                "apiVersion": "platform.4so.io/v1alpha1",
                "kind": "ApplianceBundleBuild",
                "metadata": {"version": "9.9.9", "sourceReleaseDigest": "sha256:" + "0" * 64},
                "spec": {"placeholder": True},
            }
            (pack_root / "build-spec.json").write_text(json.dumps(build_spec), encoding="utf-8")
            out = root / "generated.json"
            generated, staging = lab._normalize_acquired_build_spec(
                pack_root,
                {"buildSpecPath": "build-spec.json", "stagingDirectory": "staging"},
                version="9.9.9",
                artifact_sha="a" * 64,
                out_path=out,
            )
            self.assertEqual(out, generated)
            self.assertEqual(pack_root / "staging", staging)
            value = json.loads(out.read_text())
            self.assertEqual("sha256:" + "a" * 64, value["metadata"]["sourceReleaseDigest"])


    def test_bundle_verify_binding_rejects_other_release_even_when_lock_is_valid(self):
        result = {
            "status": "PASS",
            "outputTail": json.dumps({
                "verified": True,
                "version": "9.9.9",
                "sourceReleaseDigest": "sha256:" + "b" * 64,
                "bundleDigest": "sha256:" + "c" * 64,
                "lockDigest": "sha256:" + "d" * 64,
                "lockRequired": True,
            }),
        }
        ok, detail = lab._bundle_verify_binding(result, version="9.9.9", artifact_sha="a" * 64)
        self.assertFalse(ok)
        self.assertIn("sourceReleaseDigest", detail)
        value = json.loads(result["outputTail"])
        value["sourceReleaseDigest"] = "sha256:" + "a" * 64
        result["outputTail"] = json.dumps(value)
        self.assertTrue(lab._bundle_verify_binding(result, version="9.9.9", artifact_sha="a" * 64)[0])

    def test_bundle_auto_acquisition_ready_path_builds_and_verifies_with_exact_release(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec = self._spec(root)
            body = lab.validate_spec(spec, require_bundle=True)
            release_root = root / "release-root"
            (release_root / "bin" / "linux-amd64").mkdir(parents=True)
            (release_root / "bin" / "linux-amd64" / "platformctl").write_text("fake", encoding="utf-8")
            pack = {
                "urls": ["https://downloads.example.invalid/factory-bundle-inputs.zip"],
                "sha256": "b" * 64,
                "sizeBytes": 123,
                "format": "zip",
                "buildSpecPath": "build-spec.json",
                "stagingDirectory": "staging",
            }
            resolved, files, build_spec = self._ready_source_fixture()
            lock_path = self._write_acquisition_lock(release_root, version="9.9.9", status="ready", pack=pack, missing=[], resolved=resolved)
            artifact = self._release_with_acquisition_lock(root, lock_path)
            body["releaseArtifact"] = str(artifact)

            def fake_download(_pack, output):
                output.write_bytes(b"pack")
                return "https://downloads.example.invalid/factory-bundle-inputs.zip", "sha256:" + "b" * 64

            def fake_extract(_archive, dest):
                pack_root = dest / "fixture"
                self._materialize_ready_source_fixture(pack_root, files, build_spec)
                return pack_root

            def fake_run(stage, command, **kwargs):
                output = "ok"
                if stage == "bundle-auto-build":
                    bundle = Path(command[command.index("--out") + 1])
                    bundle.mkdir(parents=True, exist_ok=True)
                if stage == "bundle-auto-verify":
                    output = json.dumps({
                        "verified": True,
                        "version": "9.9.9",
                        "sourceReleaseDigest": "sha256:" + lab._sha256(Path(body["releaseArtifact"])),
                        "bundleDigest": "sha256:" + "c" * 64,
                        "lockDigest": "sha256:" + "d" * 64,
                        "lockRequired": True,
                    })
                return {"stage": stage, "command": command, "returnCode": 0, "durationSeconds": 0, "outputTail": output, "fingerprint": stage, "status": "PASS"}

            def fake_resolve(pack_root, _pack, _lock, image_plan, _platformctl, **_kwargs):
                return self._fixture_manifest_resolution(pack_root, image_plan)

            with mock.patch.object(lab, "_download_locked_input_pack", side_effect=fake_download), \
                 mock.patch.object(lab, "_safe_extract_input_pack", side_effect=fake_extract), \
                 mock.patch.object(lab, "_resolve_acquired_manifest_images", side_effect=fake_resolve), \
                 mock.patch.object(lab, "_run", side_effect=fake_run) as run:
                bundle, evidence = lab._auto_acquire_bundle(body, Path(body["releaseArtifact"]), release_root, root / "state")
            self.assertIsNotNone(bundle)
            self.assertEqual("PASS", evidence["status"])
            self.assertEqual(9, evidence["sourceBindingArtifactCount"])
            self.assertEqual(2, evidence["sourceBindingDerivedAuthorityCount"])
            self.assertEqual(lab.MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY, evidence["manifestImageResolutionAuthority"])
            self.assertRegex(evidence["manifestImageResolutionDigest"], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(evidence["sourceBindingDigest"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(2, run.call_count)
            build_command = run.call_args_list[0].args[1]
            self.assertIn("--release-artifact", build_command)
            generated = json.loads((root / "state" / "bundle-build.json").read_text())
            self.assertEqual("sha256:" + lab._sha256(Path(body["releaseArtifact"])), generated["metadata"]["sourceReleaseDigest"])
            bindings = generated["spec"]["sourceArtifacts"]
            self.assertEqual(9, len(bindings))
            self.assertEqual(sorted(row["path"] for row in bindings), [row["path"] for row in bindings])
            self.assertTrue(all(row["sha256"].startswith("sha256:") and row["sizeBytes"] > 0 for row in bindings))
            workloads = generated["spec"]["workloads"]
            self.assertEqual("runtime-manifests/argocd-install.yaml", workloads["gitOpsManifest"])
            self.assertEqual("runtime-manifests/cloudnative-pg-install.yaml", workloads["cloudNativePGManifest"])
            self.assertEqual("runtime-manifests/replicated-storage-install.yaml", workloads["storageManifest"])

    def test_normalized_acquisition_rejects_pack_self_asserted_source_bindings(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); pack_root = root / "pack"
            resolved, files, build_spec = self._ready_source_fixture()
            build_spec["spec"]["sourceArtifacts"] = [{"path":"manifests/argocd-install.yaml","sha256":"sha256:" + "0"*64,"sizeBytes":1}]
            self._materialize_ready_source_fixture(pack_root, files, build_spec)
            with self.assertRaisesRegex(RuntimeError, "must not self-assert sourceArtifacts"):
                lab._normalize_acquired_build_spec(
                    pack_root, {"buildSpecPath":"build-spec.json","stagingDirectory":"staging"},
                    version="9.9.9", artifact_sha="a"*64, out_path=root/"generated.json",
                    lock={"resolvedAuthorities": resolved},
                )

    def test_ready_source_binding_rechecks_generated_manifest_resolution_bytes_before_build(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); pack_root = root / "pack"
            resolved, files, build_spec = self._ready_source_fixture()
            self._materialize_ready_source_fixture(pack_root, files, build_spec)
            lock_path = self._write_acquisition_lock(root, version="9.9.9", status="ready", pack={"urls":["https://downloads.example.invalid/pack.zip"],"sha256":"a"*64,"sizeBytes":1,"format":"zip","buildSpecPath":"build-spec.json","stagingDirectory":"staging"}, missing=[], resolved=resolved)
            lock = json.loads(lock_path.read_text())
            image_plan = self._image_plan_value("9.9.9")
            by_id = {row["id"]: row for row in resolved}
            for item in image_plan["derivedManifestImageSets"]:
                artifact = by_id[item["sourceAuthority"]]["artifacts"][0]
                item["sourceManifestSha256"] = "sha256:" + artifact["sha256"]
                item["sourceManifestBytes"] = artifact["sizeBytes"]
            derived = self._fixture_manifest_resolution(pack_root, image_plan)
            generated, _ = lab._normalize_acquired_build_spec(
                pack_root, {"buildSpecPath":"build-spec.json","stagingDirectory":"staging"},
                version="9.9.9", artifact_sha="a"*64, out_path=root/"generated.json", lock=lock, derived_manifest_resolution=derived,
            )
            proof = lab._verify_input_pack_source_bindings(pack_root, {"stagingDirectory":"staging","buildSpecPath":"build-spec.json"}, lock, generated, derived_manifest_resolution=derived)
            self.assertEqual(2, proof["derivedAuthorityCount"])
            self.assertEqual(lab.MANAGEMENT_WORKLOAD_MANIFEST_IMAGE_RESOLUTION_AUTHORITY, proof["manifestImageResolution"]["authority"])
            target = pack_root / "staging" / derived["rows"][0]["resolvedPath"]
            target.write_bytes(target.read_bytes() + b"# post-resolution substitution\n")
            with self.assertRaisesRegex(RuntimeError, "changed after manifest image resolution"):
                lab._verify_input_pack_source_bindings(pack_root, {"stagingDirectory":"staging","buildSpecPath":"build-spec.json"}, lock, generated, derived_manifest_resolution=derived)

    def test_bundle_auto_acquisition_tampered_source_blocks_before_first_build_command(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec = self._spec(root)
            body = lab.validate_spec(spec, require_bundle=True)
            release_root = root / "release-root"
            (release_root / "bin" / "linux-amd64").mkdir(parents=True)
            (release_root / "bin" / "linux-amd64" / "platformctl").write_text("fake", encoding="utf-8")
            pack = {
                "urls": ["https://downloads.example.invalid/factory-bundle-inputs.zip"],
                "sha256": "b" * 64,
                "sizeBytes": 123,
                "format": "zip",
                "buildSpecPath": "build-spec.json",
                "stagingDirectory": "staging",
            }
            resolved, files, build_spec = self._ready_source_fixture()
            lock_path = self._write_acquisition_lock(release_root, version="9.9.9", status="ready", pack=pack, missing=[], resolved=resolved)
            artifact = self._release_with_acquisition_lock(root, lock_path)
            body["releaseArtifact"] = str(artifact)

            def fake_download(_pack, output):
                output.write_bytes(b"pack")
                return "https://downloads.example.invalid/factory-bundle-inputs.zip", "sha256:" + "b" * 64

            def fake_extract(_archive, dest):
                pack_root = dest / "fixture"
                self._materialize_ready_source_fixture(pack_root, files, build_spec)
                target = pack_root / "staging" / "manifests" / "argocd-install.yaml"
                target.write_bytes(b"x" * len(files["manifests/argocd-install.yaml"]))
                return pack_root

            with mock.patch.object(lab, "_download_locked_input_pack", side_effect=fake_download), \
                 mock.patch.object(lab, "_safe_extract_input_pack", side_effect=fake_extract), \
                 mock.patch.object(lab, "_run") as run:
                bundle, evidence = lab._auto_acquire_bundle(body, Path(body["releaseArtifact"]), release_root, root / "state")
            self.assertIsNone(bundle)
            self.assertEqual("BLOCKED", evidence["status"])
            self.assertEqual("LAB_BUNDLE_IMMUTABLE_ACQUISITION_FAILED", evidence["blocker"])
            self.assertIn("does not match management workload image plan", evidence["outputTail"])
            run.assert_not_called()

    def test_ready_source_binding_rejects_authority_byte_tamper_before_build(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pack_root = root / "pack"
            resolved, files, build_spec = self._ready_source_fixture()
            self._materialize_ready_source_fixture(pack_root, files, build_spec)
            generated, _ = lab._normalize_acquired_build_spec(pack_root, {"buildSpecPath":"build-spec.json","stagingDirectory":"staging"}, version="9.9.9", artifact_sha="a"*64, out_path=root/"generated.json")
            (pack_root / "staging" / "manifests" / "argocd-install.yaml").write_bytes(b"x" * len(files["manifests/argocd-install.yaml"]))
            lock = {"resolvedAuthorities": resolved}
            with self.assertRaisesRegex(RuntimeError, "sha256 mismatch"):
                lab._verify_input_pack_source_bindings(pack_root, {"stagingDirectory":"staging"}, lock, generated)

    def test_ready_source_binding_rejects_duplicate_image_references_across_archives(self):
        # Two workload archives may not present the same image reference twice: that
        # is an assembled bundle, not one exact admitted authority set.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pack_root = root / "pack"
            resolved, files, build_spec = self._ready_source_fixture()
            self._materialize_ready_source_fixture(pack_root, files, build_spec)
            copy_rel = "workloads/platform-workloads-copy.oci.tar"
            payload = files["workloads/platform-workloads.oci.tar"]
            (pack_root / "staging" / copy_rel).write_bytes(payload)
            for row in resolved:
                if row["id"] == "management-workload-oci-archive":
                    row["artifacts"].append({"name": Path(copy_rel).name, "stagingPath": copy_rel, "urls": ["https://downloads.example.invalid/" + copy_rel], "sha256": hashlib.sha256(payload).hexdigest(), "sizeBytes": len(payload)})
            build_spec["spec"]["workloads"]["imageArchives"] = sorted(["workloads/platform-workloads.oci.tar", copy_rel])
            (pack_root / "build-spec.json").write_text(json.dumps(build_spec), encoding="utf-8")
            generated, _ = lab._normalize_acquired_build_spec(pack_root, {"buildSpecPath":"build-spec.json","stagingDirectory":"staging"}, version="9.9.9", artifact_sha="a"*64, out_path=root/"generated.json")
            with self.assertRaisesRegex(RuntimeError, "duplicate image references"):
                lab._verify_input_pack_source_bindings(pack_root, {"stagingDirectory":"staging"}, {"resolvedAuthorities": resolved}, generated)

    def test_ready_source_binding_rejects_build_spec_path_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pack_root = root / "pack"
            resolved, files, build_spec = self._ready_source_fixture()
            build_spec["spec"]["workloads"]["gitOpsManifest"] = "manifests/evil.yaml"
            files["manifests/evil.yaml"] = b"apiVersion: v1\nkind: Secret\n"
            self._materialize_ready_source_fixture(pack_root, files, build_spec)
            generated, _ = lab._normalize_acquired_build_spec(pack_root, {"buildSpecPath":"build-spec.json","stagingDirectory":"staging"}, version="9.9.9", artifact_sha="a"*64, out_path=root/"generated.json")
            with self.assertRaisesRegex(RuntimeError, "does not exactly match locked/derived staging paths"):
                lab._verify_input_pack_source_bindings(pack_root, {"stagingDirectory":"staging"}, {"resolvedAuthorities": resolved}, generated)

    def test_ready_source_binding_rejects_derived_core_image_semantic_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); pack_root = root / "pack"
            resolved, files, build_spec = self._ready_source_fixture()
            wrong_archive, _ = self._management_oci_archive([f"registry.example/wrong-{i}" for i in range(8)])
            files["workloads/platform-workloads.oci.tar"] = wrong_archive
            archive_authority = next(row for row in resolved if row["id"] == "management-workload-oci-archive")
            archive_authority["artifacts"][0]["sha256"] = hashlib.sha256(wrong_archive).hexdigest()
            archive_authority["artifacts"][0]["sizeBytes"] = len(wrong_archive)
            self._materialize_ready_source_fixture(pack_root, files, build_spec)
            generated, _ = lab._normalize_acquired_build_spec(pack_root, {"buildSpecPath":"build-spec.json","stagingDirectory":"staging"}, version="9.9.9", artifact_sha="a"*64, out_path=root/"generated.json")
            with self.assertRaisesRegex(RuntimeError, "derived core workload image authority"):
                lab._verify_input_pack_source_bindings(pack_root, {"stagingDirectory":"staging"}, {"resolvedAuthorities": resolved}, generated)

    def test_ready_source_binding_rejects_unowned_ocm_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pack_root = root / "pack"
            resolved, files, build_spec = self._ready_source_fixture()
            build_spec["spec"]["workloads"]["ocmManifest"] = "manifests/ocm.yaml"
            files["manifests/ocm.yaml"] = b"apiVersion: v1\nkind: ConfigMap\n"
            self._materialize_ready_source_fixture(pack_root, files, build_spec)
            generated, _ = lab._normalize_acquired_build_spec(pack_root, {"buildSpecPath":"build-spec.json","stagingDirectory":"staging"}, version="9.9.9", artifact_sha="a"*64, out_path=root/"generated.json")
            with self.assertRaisesRegex(RuntimeError, "ocmManifest is not admitted"):
                lab._verify_input_pack_source_bindings(pack_root, {"stagingDirectory":"staging"}, {"resolvedAuthorities": resolved}, generated)

    def test_bundle_acquisition_rejects_non_public_https_destinations_and_dns_rebinding(self):
        for raw in (
            "https://127.0.0.1/pack.zip",
            "https://169.254.169.254/latest/meta-data",
            "https://10.0.0.8/pack.zip",
            "https://[::1]/pack.zip",
            "https://localhost/pack.zip",
        ):
            with self.assertRaisesRegex(RuntimeError, "public|localhost|non-public"):
                lab._validate_public_https_urls([raw], label="negative-control")

        private_resolution = [(lab.socket.AF_INET, lab.socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]
        with mock.patch.object(lab.socket, "getaddrinfo", return_value=private_resolution):
            with self.assertRaisesRegex(RuntimeError, "resolves to a non-public address"):
                lab._validate_public_https_url("https://downloads.example.com/pack.zip", label="runtime", resolve=True)
            handler = lab._PublicHTTPSRedirectHandler()
            request = lab.urllib.request.Request("https://downloads.example.com/start")
            with self.assertRaisesRegex(RuntimeError, "resolves to a non-public address"):
                handler.redirect_request(request, None, 302, "Found", {}, "https://redirect.example.com/asset?signature=opaque")

        global_resolution = [(lab.socket.AF_INET, lab.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        with mock.patch.object(lab.socket, "getaddrinfo", side_effect=[global_resolution, private_resolution]):
            handler = lab._PublicHTTPSRedirectHandler()
            redirected = handler.redirect_request(request, None, 302, "Found", {}, "https://redirect.example.com/asset?signature=opaque")
            pinned_handler = lab._PinnedPublicHTTPSHandler()
            with self.assertRaisesRegex(RuntimeError, "resolves to a non-public address"):
                pinned_handler.https_open(redirected)

    def test_m03_certifier_private_transport_keeps_dsns_out_of_environment_and_command_result(self):
        primary = "postgresql://cert:fixture-alpha-7K2@db.example/platform"
        admin = "postgresql://admin:fixture-beta-9M4@db.example/postgres"
        env, payload = lab._m03_certifier_private_transport(
            {"POSTGRES_CERT_DSN": "stale", "POSTGRES_CERT_ADMIN_DSN": "stale-admin", "KEEP": "1"},
            primary, admin,
        )
        self.assertNotIn("POSTGRES_CERT_DSN", env)
        self.assertNotIn("POSTGRES_CERT_ADMIN_DSN", env)
        self.assertEqual("1", env["KEEP"])
        self.assertEqual({"dsn": primary, "adminDsn": admin}, json.loads(payload))

        secret = "private-input-fixture"
        result = lab._run(
            "private-stdin-test",
            [lab.sys.executable, "-c", "import sys; data=sys.stdin.read(); print('bytes='+str(len(data)))"],
            cwd=ROOT, timeout=10, input_text=secret,
        )
        self.assertEqual("PASS", result["status"])
        self.assertNotIn(secret, json.dumps(result, sort_keys=True))
        self.assertIn(f"bytes={len(secret)}", result["outputTail"])

    def test_bundle_acquisition_pinned_https_connection_does_not_reresolve_dns(self):
        pinned = ((lab.socket.AF_INET, lab.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),)
        calls = []

        class FakeSocket:
            def settimeout(self, timeout):
                calls.append(("timeout", timeout))

            def bind(self, source):
                calls.append(("bind", source))

            def connect(self, address):
                calls.append(("connect", address))

            def setsockopt(self, *args):
                calls.append(("setsockopt", args))

            def close(self):
                calls.append(("close", None))

        class FakeTLSContext:
            def wrap_socket(self, sock, *, server_hostname):
                calls.append(("tls", server_hostname))
                return sock

        fake_socket = FakeSocket()
        with mock.patch.object(lab.socket, "socket", return_value=fake_socket), mock.patch.object(lab.socket, "getaddrinfo", side_effect=AssertionError("unexpected second DNS lookup")):
            conn = lab._PinnedHTTPSConnection("downloads.example.com", pinned_infos=pinned, timeout=3, context=FakeTLSContext())
            conn.connect()
        self.assertIn(("connect", ("8.8.8.8", 443)), calls)
        self.assertEqual(1, calls.count(("tls", "downloads.example.com")), calls)

    def test_bundle_acquisition_canonical_paths_reject_backslash_whitespace_and_nul(self):
        for raw in ("staging\\manifest.yaml", " staging/manifest.yaml", "staging/manifest.yaml ", "staging/\x00manifest.yaml"):
            with self.assertRaisesRegex(ValueError, "canonical relative path"):
                lab._safe_relative_path(raw, label="negative-control")

    def test_bundle_acquisition_lock_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "lab" / "appliance-bundle-acquisition-lock.json"
            path.parent.mkdir(parents=True)
            path.write_text('{"authority":"LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8","authority":"AMBIGUOUS","schemaVersion":8}', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "duplicate JSON key"):
                lab._load_bundle_acquisition_lock(root, "9.9.9")

    def test_bundle_input_pack_build_spec_rejects_non_object_and_duplicate_keys_without_system_exit(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pack_root = root / "pack"
            pack_root.mkdir()
            (pack_root / "staging").mkdir()
            spec = pack_root / "build-spec.json"
            pack = {"buildSpecPath":"build-spec.json","stagingDirectory":"staging"}
            spec.write_text('[]', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "must be a JSON object"):
                lab._normalize_acquired_build_spec(pack_root, pack, version="9.9.9", artifact_sha="a"*64, out_path=root/"generated.json")
            spec.write_text('{"metadata":{"version":"9.9.9","version":"evil","sourceReleaseDigest":"sha256:' + '0'*64 + '"}}', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "duplicate JSON key"):
                lab._normalize_acquired_build_spec(pack_root, pack, version="9.9.9", artifact_sha="a"*64, out_path=root/"generated.json")

    def test_bundle_input_pack_extract_rejects_duplicate_paths_and_unpacked_size_overflow(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            duplicate = root / "duplicate.zip"
            with zipfile.ZipFile(duplicate, "w") as zf:
                zf.writestr("pack/build-spec.json", "{}")
                zf.writestr("pack/build-spec.json", "{\"x\":1}")
            with self.assertRaisesRegex(RuntimeError, "duplicates archive path"):
                lab._safe_extract_input_pack(duplicate, root / "out-duplicate")
            oversized = root / "oversized.zip"
            with zipfile.ZipFile(oversized, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("pack/build-spec.json", "12345")
            with mock.patch.object(lab, "MAX_BUNDLE_INPUT_PACK_UNPACKED_BYTES", 4):
                with self.assertRaisesRegex(RuntimeError, "unpacked-size limit"):
                    lab._safe_extract_input_pack(oversized, root / "out-oversized")

    def test_ready_source_binding_rejects_unowned_pack_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pack_root = root / "pack"
            resolved, files, build_spec = self._ready_source_fixture()
            self._materialize_ready_source_fixture(pack_root, files, build_spec)
            extra = pack_root / "staging" / "workloads" / "unowned.txt"
            extra.write_text("unowned", encoding="utf-8")
            generated, _ = lab._normalize_acquired_build_spec(pack_root, {"buildSpecPath":"build-spec.json","stagingDirectory":"staging"}, version="9.9.9", artifact_sha="a"*64, out_path=root/"generated.json")
            with self.assertRaisesRegex(RuntimeError, "file ownership mismatch"):
                lab._verify_input_pack_source_bindings(pack_root, {"buildSpecPath":"build-spec.json","stagingDirectory":"staging"}, {"resolvedAuthorities": resolved}, generated)

    def test_ready_source_binding_accepts_exact_owned_pack_file_set(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pack_root = root / "pack"
            resolved, files, build_spec = self._ready_source_fixture()
            self._materialize_ready_source_fixture(pack_root, files, build_spec)
            generated, _ = lab._normalize_acquired_build_spec(pack_root, {"buildSpecPath":"build-spec.json","stagingDirectory":"staging"}, version="9.9.9", artifact_sha="a"*64, out_path=root/"generated.json")
            result = lab._verify_input_pack_source_bindings(pack_root, {"buildSpecPath":"build-spec.json","stagingDirectory":"staging"}, {"resolvedAuthorities": resolved}, generated)
            self.assertEqual(9, result["artifactCount"])
            self.assertEqual(1, result["derivedAuthorityCount"])
            self.assertRegex(result["bindingDigest"], r"^sha256:[0-9a-f]{64}$")

    def test_m02_interrupt_point_requires_active_replay_safe_running_step(self):
        active = {
            "bootstrapActive": True,
            "run": {
                "state": "RUNNING",
                "steps": [
                    {"key": "verify-ha-quorum", "state": "SUCCEEDED"},
                    {"key": "deploy-foundation", "state": "RUNNING"},
                ],
            },
        }
        self.assertEqual("deploy-foundation", lab._active_bootstrap_step(active))
        active["bootstrapActive"] = False
        self.assertEqual("", lab._active_bootstrap_step(active))
        active["bootstrapActive"] = True
        active["run"]["steps"][1]["key"] = "install-rke2"
        self.assertEqual("", lab._active_bootstrap_step(active))

    def test_m02_reboot_requires_outage_degraded_quorum_and_full_recovery(self):
        before = "01234567-89ab-cdef-0123-456789abcdef"
        after = "fedcba98-7654-3210-fedc-ba9876543210"
        run_results = [
            {"status":"PASS","outputTail":before,"returnCode":0},
            {"status":"PASS","outputTail":"scheduled","returnCode":0},
            {"status":"FAIL","outputTail":"ssh unavailable","returnCode":255},
            {"status":"PASS","outputTail":after,"returnCode":0},
            {"status":"PASS","outputTail":"active","returnCode":0},
        ]
        degraded = {"status":"PASS","outputTail":"degraded quorum","returnCode":0}
        full = {"status":"PASS","outputTail":"full recovery","returnCode":0}
        body = {"ssh": {"knownHostsFile":"/tmp/known","identityFile":"/tmp/id"}}
        with mock.patch.object(lab, "_run", side_effect=run_results), \
             mock.patch.object(lab, "_ha_runtime_probe", side_effect=[degraded, full]) as probe, \
             mock.patch.object(lab.time, "sleep", return_value=None):
            results = lab._reboot_ha_peer(body, "management-3", "m3.example.invalid", "management-1", "m1.example.invalid", timeout=30)
        self.assertTrue(all(item["status"] == "PASS" for item in results))
        self.assertEqual(2, probe.call_count)
        self.assertFalse(probe.call_args_list[0].kwargs["require_full_recovery"])
        self.assertTrue(probe.call_args_list[1].kwargs["require_full_recovery"])

    def test_reboot_requires_boot_id_change_and_service_recovery(self):
        before = "01234567-89ab-cdef-0123-456789abcdef"
        after = "fedcba98-7654-3210-fedc-ba9876543210"
        passes = [
            {"status": "PASS", "outputTail": before, "returnCode": 0},
            {"status": "PASS", "outputTail": "scheduled", "returnCode": 0},
            {"status": "FAIL", "outputTail": "ssh down", "returnCode": 255},
            {"status": "PASS", "outputTail": after, "returnCode": 0},
            {"status": "PASS", "outputTail": "active", "returnCode": 0},
        ]
        body = {"ssh": {"knownHostsFile": "/tmp/known", "identityFile": "/tmp/id"}}
        with mock.patch.object(lab, "_run", side_effect=passes), mock.patch.object(lab.time, "sleep", return_value=None):
            results = lab._reboot_management_host(body, "management-primary", "mgmt.example.invalid", timeout=30)
        self.assertEqual(4, len(results))
        self.assertTrue(all(item["status"] == "PASS" for item in results))
        self.assertEqual(after, lab._boot_id_from_result(results[2]))


if __name__ == "__main__":
    unittest.main()

    def test_three_node_management_rejects_unsafe_cluster_and_storage_topology(self):
        with tempfile.TemporaryDirectory() as td:
            base = self._production_ha_spec(Path(td))
            cases = [
                ("cluster-count", lambda spec: spec["spec"]["management"].__setitem__("clusterNodeAddresses", ["10.77.35.11", "10.77.35.12"]), "clusterNodeAddresses"),
                ("cluster-duplicate", lambda spec: spec["spec"]["management"].__setitem__("clusterNodeAddresses", ["10.77.35.11", "10.77.35.11", "10.77.35.13"]), "unique"),
                ("cluster-hostname", lambda spec: spec["spec"]["management"].__setitem__("clusterNodeAddresses", ["node-a", "10.77.35.12", "10.77.35.13"]), "literal IPv4"),
                ("interface", lambda spec: spec["spec"]["management"].__setitem__("clusterInterface", "ens35;reboot"), "clusterInterface"),
                ("storage-relative", lambda spec: spec["spec"]["management"].__setitem__("storageDataDevices", ["sdb"]), "canonical Linux /dev paths"),
                ("storage-traversal", lambda spec: spec["spec"]["management"].__setitem__("storageDataDevices", ["/dev/disk/by-id/../sdb"]), "canonical Linux /dev paths"),
                ("storage-duplicate", lambda spec: spec["spec"]["management"].__setitem__("storageDataDevices", ["/dev/sdb", "/dev/sdb"]), "unique"),
                ("storage-mode", lambda spec: spec["spec"]["management"].__setitem__("storageDeviceMode", "reuse-any"), "format-empty"),
            ]
            for name, mutate, expected in cases:
                changed = json.loads(json.dumps(base))
                mutate(changed)
                with self.subTest(name=name):
                    with self.assertRaisesRegex(SystemExit, expected):
                        lab.validate_spec(changed)
