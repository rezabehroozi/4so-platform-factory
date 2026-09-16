import copy
import subprocess
import json
import tempfile
import importlib.util
import io
import sys
import tarfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("catalog_upstream_admission", ROOT / "scripts" / "catalog_upstream_admission.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
sys.path.insert(0, str(ROOT / "scripts"))
acquire_spec = importlib.util.spec_from_file_location("acquire_upstream_helm", ROOT / "scripts" / "acquire_upstream_helm.py")
acquire_mod = importlib.util.module_from_spec(acquire_spec)
acquire_spec.loader.exec_module(acquire_mod)


class CatalogUpstreamAdmissionTests(unittest.TestCase):
    def test_authority_exactly_covers_unresolved_helm_components(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        unresolved = mod.unresolved_helm_components(ROOT)
        self.assertEqual({r["component"] for r in rows}, set(unresolved))
        self.assertEqual(17, sum(r["status"] == "ready-for-acquisition" for r in rows))
        self.assertEqual(3, sum(r["runtimeStatus"] != "eligible-after-source-resolution" for r in rows))


    def test_runtime_review_rows_remain_acquisition_ready_with_structured_blocker_evidence(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        by_name = {r["component"]: r for r in rows}
        for name in ("kyverno", "metallb"):
            row = by_name[name]
            self.assertEqual("ready-for-acquisition", row["status"])
            self.assertEqual("review-required", row["runtimeStatus"])
            self.assertRegex(row["selectedVersion"], r"^[0-9]+\.[0-9]+\.[0-9]+$")
            self.assertEqual(row["selectedVersion"], row["upstreamVersion"])
            self.assertTrue(any(e["kind"] == "blocker" for e in row["reviewEvidence"]))

    def test_kgateway_gateway_api_compatibility_is_exactly_admitted(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        row = next(r for r in rows if r["component"] == "kgateway")
        self.assertEqual("ready-for-acquisition", row["status"])
        self.assertEqual("2.4.1", row["selectedVersion"])
        component = mod.unresolved_helm_components(ROOT)["kgateway"]["spec"]
        self.assertEqual("2.4.1", component["release"])
        self.assertEqual("exact-upstream-admitted-pending-source-acquisition", component["versionPolicy"])
        gateway = json.loads((ROOT / "catalog" / "components" / "gateway-api.json").read_text())["spec"]
        self.assertEqual("1.5.1", gateway["release"])

    def test_loki_community_migration_is_exact_but_still_unresolved(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        row = next(r for r in rows if r["component"] == "loki")
        self.assertEqual("ready-for-acquisition", row["status"])
        self.assertEqual("18.12.1", row["selectedVersion"])
        self.assertEqual("https://grafana-community.github.io/helm-charts", row["source"])
        self.assertTrue(any(e["kind"] == "source-migration" for e in row["reviewEvidence"]))
        spec = mod.unresolved_helm_components(ROOT)["loki"]["spec"]
        self.assertEqual("18.12.1", spec["release"])
        self.assertFalse(spec["source"]["resolved"])

    def test_ceph_csi_operator_managed_architecture_is_exact_but_unresolved(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        by_name = {r["component"]: r for r in rows}
        for name, chart, source in (
            ("ceph-csi-operator", "ceph-csi-operator", "https://ceph.github.io/ceph-csi-operator/"),
            ("ceph-csi-rbd", "ceph-csi-drivers", "https://ceph.github.io/ceph-csi-operator-charts"),
        ):
            row = by_name[name]
            self.assertEqual("ready-for-acquisition", row["status"])
            self.assertEqual("1.0.4", row["selectedVersion"])
            self.assertEqual(chart, row["chart"])
            self.assertEqual(source, row["source"])
            spec = mod.unresolved_helm_components(ROOT)[name]["spec"]
            self.assertEqual("1.0.4", spec["release"])
            self.assertFalse(spec["source"]["resolved"])
        driver = mod.unresolved_helm_components(ROOT)["ceph-csi-rbd"]["spec"]
        self.assertIn("ceph-csi-operator", driver["dependencies"])
        self.assertEqual("driver/rbd.csi.ceph.com", driver["readiness"][0])

    def test_cilium_source_is_acquirable_while_runtime_stays_fail_closed_until_gateway_api_161(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        cilium = next(r for r in rows if r["component"] == "cilium")
        self.assertEqual("ready-for-acquisition", cilium["status"])
        self.assertEqual("dependency-transition-required", cilium["runtimeStatus"])
        self.assertEqual("1.20.1", cilium["selectedVersion"])
        gateway = json.loads((ROOT / "catalog" / "components" / "gateway-api.json").read_text())["spec"]
        self.assertEqual("1.5.1", gateway["release"])
        self.assertTrue(gateway["source"]["resolved"])

    def test_grafana_migration_is_exact_but_still_unresolved(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        row = next(r for r in rows if r["component"] == "grafana")
        self.assertEqual("ready-for-acquisition", row["status"])
        self.assertEqual("12.10.0", row["selectedVersion"])
        self.assertEqual("https://grafana-community.github.io/helm-charts", row["source"])
        self.assertTrue(any(e["kind"] == "source-migration" for e in row["reviewEvidence"]))
        spec = mod.unresolved_helm_components(ROOT)["grafana"]["spec"]
        self.assertFalse(spec["source"]["resolved"])
        self.assertEqual("exact-upstream-admitted-pending-source-acquisition", spec["versionPolicy"])

    def test_ready_rows_are_exact_pins_but_not_resolved_sources(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        components = mod.unresolved_helm_components(ROOT)
        for row in rows:
            if row["status"] != "ready-for-acquisition":
                continue
            comp = components[row["component"]]["spec"]
            self.assertEqual(row["selectedVersion"], comp["release"])
            self.assertFalse(comp["source"]["resolved"])
            self.assertEqual("", comp["source"]["sourceLockDigest"])
            self.assertEqual("candidate", comp["certification"]["status"])
            self.assertEqual("", comp["certification"]["evidenceDigest"])

    def test_runtime_holds_do_not_clear_source_or_certification_gates(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        components = mod.unresolved_helm_components(ROOT)
        held = [r for r in rows if r["runtimeStatus"] != "eligible-after-source-resolution"]
        self.assertEqual(3, len(held))
        for row in held:
            spec = components[row["component"]]["spec"]
            self.assertEqual("ready-for-acquisition", row["status"])
            self.assertFalse(spec["source"]["resolved"])
            self.assertEqual("", spec["source"]["sourceLockDigest"])
            self.assertEqual("exact-upstream-admitted-pending-source-acquisition", spec["versionPolicy"])
            self.assertEqual("candidate", spec["certification"]["status"])

    def test_constraint_match_does_not_widen_minor_series(self):
        self.assertTrue(mod.constraint_matches("1.21.x", "1.21.1"))
        self.assertFalse(mod.constraint_matches("1.21.x", "1.22.0"))
        self.assertFalse(mod.constraint_matches("1.21.x", "1.21.0-rc.1"))

    def test_command_uses_authority_not_repeated_version_or_source(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        row = next(r for r in rows if r["status"] == "ready-for-acquisition")
        cmd = mod.acquisition_command(row)
        self.assertIn("--from-admission", cmd)
        self.assertIn("--component", cmd)
        self.assertNotIn(str(row["source"]), cmd)
        self.assertNotIn(str(row["selectedVersion"]), cmd)

    def test_all_ready_rows_have_canonical_license_authority(self):
        _, rows = mod.validate(ROOT, ROOT / 'catalog' / 'upstream-admission.json')
        ready = [r for r in rows if r['status'] == 'ready-for-acquisition']
        self.assertEqual(17, len(ready))
        for row in ready:
            self.assertRegex(str(row.get('licenseSPDX') or ''), r'^[A-Za-z0-9][A-Za-z0-9.+-]*$')

    def test_alloy_license_override_is_canonical_and_applied(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        alloy = next(r for r in rows if r["component"] == "alloy")
        self.assertEqual("Apache-2.0", alloy["licenseSPDX"])
        from types import SimpleNamespace
        args = SimpleNamespace(from_upgrade_admission=False, historical=False, from_admission=True, component="alloy", authority=str(ROOT / "catalog" / "upstream-admission.json"), version=None, source=None, upstream_version=None, license_spdx=None)
        acquire_mod.apply_admission(args)
        self.assertEqual("Apache-2.0", args.license_spdx)

    def test_symlinked_canonical_authority_is_rejected(self):
        authority = (ROOT / "catalog" / "upstream-admission.json").read_text()
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside_td:
            repo = Path(td)
            (repo / "catalog").mkdir()
            target = Path(outside_td) / "authority.json"
            target.write_text(authority)
            link = repo / "catalog" / "upstream-admission.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "UPSTREAM_ADMISSION_AUTHORITY_PATH_INVALID"):
                mod.load_authority(link, repo)

    def test_https_index_redirect_cannot_downgrade_integrity_anchor(self):
        acquire_mod.require_https_response(
            "https://charts.example.test/index.yaml",
            "https://cdn.example.test/index.yaml",
        )
        for final_url in ("http://charts.example.test/index.yaml", "file:///tmp/index.yaml", ""):
            with self.assertRaisesRegex(RuntimeError, "UPSTREAM_HTTPS_DOWNGRADE_DENIED"):
                acquire_mod.require_https_response("https://charts.example.test/index.yaml", final_url)

    def test_bounded_read_rejects_oversized_upstream_metadata(self):
        self.assertEqual(b"abc", acquire_mod.bounded_read(io.BytesIO(b"abc"), 3, "FIXTURE"))
        with self.assertRaisesRegex(RuntimeError, "FIXTURE_TOO_LARGE"):
            acquire_mod.bounded_read(io.BytesIO(b"abcd"), 3, "FIXTURE")

    def test_chart_metadata_rejects_member_and_metadata_limits(self):
        with tempfile.TemporaryDirectory() as td:
            chart = Path(td) / "fixture.tgz"
            with tarfile.open(chart, "w:gz") as tf:
                payload = b"apiVersion: v2\nname: fixture\nversion: 1.2.3\n"
                info = tarfile.TarInfo("fixture/Chart.yaml")
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
                values = b"x: y\n"
                info = tarfile.TarInfo("fixture/values.yaml")
                info.size = len(values)
                tf.addfile(info, io.BytesIO(values))

            old_members = acquire_mod.MAX_CHART_MEMBERS
            old_metadata = acquire_mod.MAX_CHART_METADATA_BYTES
            try:
                acquire_mod.MAX_CHART_MEMBERS = 1
                with self.assertRaisesRegex(RuntimeError, "HELM_CHART_MEMBER_LIMIT_EXCEEDED"):
                    acquire_mod.chart_metadata(chart)

                acquire_mod.MAX_CHART_MEMBERS = old_members
                acquire_mod.MAX_CHART_METADATA_BYTES = 8
                with self.assertRaisesRegex(RuntimeError, "HELM_CHART_METADATA_TOO_LARGE"):
                    acquire_mod.chart_metadata(chart)
            finally:
                acquire_mod.MAX_CHART_MEMBERS = old_members
                acquire_mod.MAX_CHART_METADATA_BYTES = old_metadata

            self.assertEqual("fixture", acquire_mod.chart_metadata(chart)["name"])

    def test_runtime_hold_does_not_block_exact_source_acquisition_admission(self):
        proc = subprocess.run(
            ["python3", "scripts/acquire_upstream_helm.py", "--from-admission", "--component", "cilium"],
            cwd=ROOT, text=True, capture_output=True,
        )
        self.assertEqual(3, proc.returncode)
        self.assertNotIn("UPSTREAM_ADMISSION_NOT_READY", proc.stderr)
        self.assertIn("ACQUISITION_TOOLCHAIN_TOOL_MISSING", proc.stderr)

    def test_acquisition_rejects_direct_version_source_bypass_before_tool_or_network_use(self):
        proc = subprocess.run(
            [
                "python3", "scripts/acquire_upstream_helm.py",
                "--component", "alloy",
                "--version", "1.11.0",
                "--source", "https://grafana.github.io/helm-charts",
            ],
            cwd=ROOT, text=True, capture_output=True,
        )
        self.assertEqual(3, proc.returncode)
        self.assertIn("UPSTREAM_ADMISSION_REQUIRED", proc.stderr)
        self.assertNotIn("HELM_REQUIRED", proc.stderr)
        self.assertNotIn("CRANE_REQUIRED", proc.stderr)

    def test_acquisition_rejects_alternate_authority_before_tool_or_network_use(self):
        authority = json.loads((ROOT / "catalog" / "upstream-admission.json").read_text())
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(authority, handle)
            alternate = Path(handle.name)
        try:
            proc = subprocess.run(
                [
                    "python3", "scripts/acquire_upstream_helm.py",
                    "--from-admission",
                    "--authority", str(alternate),
                    "--component", "alloy",
                ],
                cwd=ROOT, text=True, capture_output=True,
            )
        finally:
            alternate.unlink(missing_ok=True)
        self.assertEqual(3, proc.returncode)
        self.assertIn("UPSTREAM_ADMISSION_AUTHORITY_OVERRIDE_DENIED", proc.stderr)
        self.assertNotIn("HELM_REQUIRED", proc.stderr)
        self.assertNotIn("CRANE_REQUIRED", proc.stderr)


if __name__ == "__main__":
    unittest.main()
