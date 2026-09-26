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
        self.assertNotIn("git push", source)
        self.assertNotIn("git commit", source)
        self.assertNotIn("runtime/openchoreo/source-selection.json", source.split("Upload J8 runtime-realism evidence")[-1])


if __name__ == "__main__":
    unittest.main()
