import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class MCPExternalClientMatrixTests(unittest.TestCase):
    def test_shared_checks_are_partitioned_without_local_false_pass(self):
        doc = json.loads((ROOT / "lab" / "mcp-external-client-interop-matrix.json").read_text())
        spec = doc["spec"]
        required = set(spec["sharedRequiredChecks"])
        baseline = set(spec["baselineHarnessChecks"])
        fixture = set(spec["fixtureBoundHarnessChecks"])
        credentialed = set(spec["credentialedExternalChecks"])
        self.assertEqual(required, baseline | fixture | credentialed)
        self.assertFalse(baseline & fixture)
        self.assertFalse(baseline & credentialed)
        self.assertFalse(fixture & credentialed)
        self.assertIn("--token <scoped-mcp-read-token>", spec["localBlackBoxHarness"])
        self.assertEqual("pending", spec["externalCertificationStatus"])
        self.assertTrue(all(row["externalExecution"] == "pending" for row in spec["clients"]))
        self.assertIn("real credentialed external execution", spec["truthRule"])


if __name__ == "__main__":
    unittest.main()
