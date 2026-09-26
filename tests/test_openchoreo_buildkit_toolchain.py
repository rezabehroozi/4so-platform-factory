import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class OpenChoreoBuildKitToolchainTests(unittest.TestCase):
    def test_exact_buildkit_toolchain_is_pinned(self):
        doc = json.loads((ROOT / "runtime" / "openchoreo" / "buildkit-toolchain.json").read_text())
        spec = doc["spec"]
        self.assertEqual("OPENCHOREO_BUILDKIT_TOOLCHAIN_AUTHORITY_V1", spec["authority"])
        self.assertEqual("0.33.0", spec["version"])
        self.assertEqual("linux-amd64", spec["platform"])
        self.assertEqual(
            "b6242896d343100808dcbe37565caf381e0a444a6a83d7255926bb1519248ead",
            spec["asset"]["sha256"],
        )
        self.assertEqual(["bin/buildctl", "bin/buildkitd"], spec["requiredMembers"])
        self.assertFalse(spec["networkPolicy"]["buildContextNetworkRequired"])
        self.assertFalse(spec["networkPolicy"]["baseImageRequired"])
        self.assertTrue(spec["networkPolicy"]["registryPushRequired"])
        self.assertFalse(spec["runtimeCertified"])
        self.assertFalse(spec["physicalCertified"])

    def test_ephemeral_workflow_does_not_commit_runtime_source_authority(self):
        source = (ROOT / ".github" / "workflows" / "openchoreo-runtime-realism.yml").read_text()
        self.assertIn("OPENCHOREO_RUNTIME_REALISM_EVIDENCE_V1", source)
        self.assertIn("ephemeral-local-zot", source)
        self.assertIn("productionSourceSealed", source)
        self.assertIn("git add lab/openchoreo-runtime-realism-receipt.json", source)
        self.assertIn("git push origin HEAD:main", source)
        self.assertNotIn("git add runtime/openchoreo/source-selection.json", source)
        self.assertNotIn("git add runtime/openchoreo/", source)

    def test_durable_runtime_realism_receipt_never_claims_production_or_physical_pass(self):
        path = ROOT / "lab" / "openchoreo-runtime-realism-receipt.json"
        if not path.exists():
            self.skipTest("runtime-realism receipt is generated only after the external-byte workflow succeeds")
        receipt = json.loads(path.read_text())
        self.assertEqual("OPENCHOREO_RUNTIME_REALISM_EVIDENCE_V1", receipt["authority"])
        self.assertEqual("ephemeral-local-zot", receipt["registryMode"])
        self.assertTrue(receipt["runtimeRealismPass"])
        self.assertFalse(receipt["productionSourceSealed"])
        self.assertFalse(receipt["runtimeCertified"])
        self.assertFalse(receipt["physicalCertified"])
        self.assertRegex(receipt["sourceRunId"], r"^[0-9]+$")
        self.assertRegex(receipt["sourceCommitSHA"], r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
