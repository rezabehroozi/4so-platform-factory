import argparse
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


validator = load("validate_repository_wave2", "scripts/validate_repository.py")
upgrade = load("upgrade_admission_wave2", "scripts/component_upgrade_source_admission.py")
acquire = load("acquire_upstream_wave2", "scripts/acquire_upstream_helm.py")


class AcquisitionWave2RegressionTests(unittest.TestCase):
    def test_runtime_hold_may_persist_after_exact_source_is_locked(self):
        self.assertTrue(validator.runtime_holds_partition_valid({"kyverno"}, set(), {"kyverno"}))
        self.assertTrue(validator.runtime_holds_partition_valid({"kyverno"}, {"kyverno"}, set()))
        self.assertFalse(validator.runtime_holds_partition_valid({"kyverno"}, set(), set()))

    def test_every_reviewed_historical_edge_has_explicit_license_authority(self):
        doc = json.loads((ROOT / "catalog/component-upgrade-source-admission.json").read_text())
        self.assertEqual([], upgrade.validate(doc, ROOT))
        for row in doc["components"]:
            if row["status"] == "admitted-for-acquisition":
                self.assertRegex(row.get("licenseSPDX", ""), r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")

    def test_historical_acquisition_applies_reviewed_license_authority(self):
        args = argparse.Namespace(
            from_upgrade_admission=True,
            historical=True,
            from_admission=False,
            component="alloy",
            version=None,
            source=None,
            upstream_version=None,
            license_spdx=None,
            values=[],
            authority=str(ROOT / "catalog/upstream-admission.json"),
        )
        acquire.apply_admission(args)
        self.assertEqual("Apache-2.0", args.license_spdx)

    def test_ceph_csi_driver_uses_official_operator_chart_repository(self):
        doc = json.loads((ROOT / "catalog/upstream-admission.json").read_text())
        rows = (doc.get("spec") or {}).get("components") or []
        row = next(r for r in rows if r["component"] == "ceph-csi-rbd")
        self.assertEqual("https://ceph.github.io/ceph-csi-operator/", row["source"])

    def test_external_dns_reviewed_predecessor_exists_in_upstream_history(self):
        doc = json.loads((ROOT / "catalog/component-upgrade-source-admission.json").read_text())
        row = next(r for r in doc["components"] if r["component"] == "external-dns")
        self.assertEqual("1.20.0", row["previousVersion"])
        self.assertIn("CHANGELOG", row["reviewEvidence"][0]["reference"])

    def test_divergent_kubernetes_renders_are_recorded_not_rejected_as_source_acquisition(self):
        low = [{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"demo"},"spec":{"replicas":1}}]
        high = [{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"demo"},"spec":{"replicas":2}}]
        evidence = acquire.kubernetes_render_evidence(
            {"1.34.0": low, "1.35.0": high}
        )
        self.assertEqual({"1.34.0", "1.35.0"}, set(evidence))
        self.assertNotEqual(evidence["1.34.0"], evidence["1.35.0"])
        for digest in evidence.values():
            self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")

    def test_openchoreo_acquisition_profile_has_non_placeholder_product_owned_oidc_render_binding(self):
        values = (ROOT / "runtime/openchoreo/control-plane-values.yaml").read_text()
        self.assertNotIn(".invalid", values)
        self.assertIn("security:", values)
        self.assertIn("oidc:", values)
        self.assertIn("auth.render.4so.test/realms/platform", values)

    def test_loki_render_profile_is_canonical_authority_not_cli_only_input(self):
        doc = json.loads((ROOT / "catalog/upstream-admission.json").read_text())
        rows = (doc.get("spec") or {}).get("components") or []
        row = next(r for r in rows if r["component"] == "loki")
        self.assertEqual(["runtime/catalog-values/loki-source-render.yaml"], row.get("valuesFiles"))
        path = ROOT / row["valuesFiles"][0]
        self.assertTrue(path.is_file())
        text = path.read_text()
        self.assertIn("deploymentMode: SingleBinary", text)
        self.assertIn("type: filesystem", text)

    def test_current_admission_applies_canonical_loki_values(self):
        args = argparse.Namespace(
            from_upgrade_admission=False,
            historical=False,
            from_admission=True,
            component="loki",
            version=None,
            source=None,
            upstream_version=None,
            license_spdx=None,
            values=[],
            authority=str(ROOT / "catalog/upstream-admission.json"),
        )
        acquire.apply_admission(args)
        self.assertEqual(["runtime/catalog-values/loki-source-render.yaml"], args.values)
        self.assertEqual("Apache-2.0", args.license_spdx)

    def test_canonical_bundle_image_inventory_is_not_union_of_uncarried_render(self):
        source = (ROOT / "scripts/acquire_upstream_helm.py").read_text()
        self.assertIn("images = sorted(pin_images(resources, crane_digest))", source)
        self.assertNotIn("pin_images(max_resources, crane_digest)", source)

    def test_openchoreo_data_plane_values_match_v13_supported_surface(self):
        values = (ROOT / "runtime/openchoreo/data-plane-values.yaml").read_text()
        self.assertNotIn("kube-prometheus-stack:", values)
        self.assertIn("clusterAgent:", values)
        self.assertIn("gateway:", values)


if __name__ == "__main__":
    unittest.main()
