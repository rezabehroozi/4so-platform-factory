import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class NetworkStackKindToolchainTests(unittest.TestCase):
    def test_kind_matrix_is_exact_and_claim_scoped(self):
        doc=json.loads((ROOT/"runtime/network-stack-kind-toolchain.json").read_text())
        spec=doc["spec"]
        self.assertEqual("NETWORK_STACK_KIND_RUNTIME_TOOLCHAIN_V1", spec["authority"])
        self.assertEqual("0.33.0", spec["kind"]["version"])
        self.assertEqual(
            "aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d",
            spec["kind"]["sha256"],
        )
        self.assertEqual(
            {"1.34.11","1.35.8"},
            {row["version"] for row in spec["kubernetes"]},
        )
        self.assertTrue(all("@sha256:" in row["nodeImage"] for row in spec["kubernetes"]))
        profile=spec["runtimeProfile"]
        self.assertEqual(2, profile["nodeCount"])
        self.assertTrue(profile["defaultCNIDisabled"])
        self.assertTrue(profile["kubeProxyEnabled"])
        claims=spec["claimPolicy"]
        self.assertTrue(claims["genericKubernetesRuntimeEvidenceOnly"])
        self.assertFalse(claims["rke2Certified"])
        self.assertFalse(claims["physicalCertified"])
        self.assertFalse(claims["runtimeHoldAutoRelease"])

if __name__ == "__main__":
    unittest.main()
