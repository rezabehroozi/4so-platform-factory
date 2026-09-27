import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "runtime_dependency_transition_readiness",
    ROOT / "scripts" / "runtime_dependency_transition_readiness.py",
)
mod = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(mod)


class RuntimeDependencyTransitionReadinessTests(unittest.TestCase):
    def test_current_transition_is_prepared_but_not_runtime_certified(self):
        receipt = mod.verify(ROOT)
        self.assertEqual("RUNTIME_DEPENDENCY_TRANSITION_READINESS_V1", receipt["authority"])
        self.assertTrue(receipt["sourceClosureReady"])
        self.assertTrue(receipt["transitionExecutionReady"])
        self.assertTrue(receipt["singleNodeRKE2Certified"])
        self.assertFalse(receipt["productTopologyHACertified"])
        self.assertEqual("36246011111", receipt["runtimeEvidence"]["sourceRunId"])
        current = json.loads((ROOT / "catalog" / "components" / "gateway-api.json").read_text())
        expected_mutated = current["spec"]["release"] == "1.6.1"
        self.assertEqual(expected_mutated, receipt["currentGatewayApiMutationPerformed"])
        self.assertEqual(expected_mutated, receipt["ciliumReleased"])
        self.assertFalse(receipt["runtimeCertified"])
        self.assertFalse(receipt["physicalCertified"])
        self.assertEqual(["metallb"] if expected_mutated else ["cilium", "metallb"], receipt["remainingRuntimeSuitabilityHolds"])

    def test_target_gateway_assets_are_exactly_two_and_digest_bound(self):
        receipt = mod.verify(ROOT)
        rows = receipt["targetGatewayApi"]["assets"]
        self.assertEqual(["experimental-install.yaml", "standard-install.yaml"], [r["name"] for r in rows])
        self.assertTrue(all(r["sha256"].startswith("sha256:") and r["sizeBytes"] > 0 for r in rows))

    def test_current_gateway_api_truth_matches_catalog_authority(self):
        receipt = mod.verify(ROOT)
        current = json.loads((ROOT / "catalog" / "components" / "gateway-api.json").read_text())
        self.assertIn(current["spec"]["release"], {"1.5.1", "1.6.1"})
        self.assertEqual(current["spec"]["release"], receipt["currentGatewayApi"]["release"])
        self.assertEqual("1.6.1", receipt["targetGatewayApi"]["release"])
        expected_mutated = current["spec"]["release"] == "1.6.1"
        self.assertEqual(expected_mutated, receipt["currentGatewayApiMutationPerformed"])
        self.assertEqual(expected_mutated, receipt["ciliumReleased"])


if __name__ == "__main__":
    unittest.main()
