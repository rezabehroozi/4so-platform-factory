import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "management_product_image_evidence",
    ROOT / "scripts" / "management_product_image_evidence.py",
)
mod = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(mod)


class ManagementProductImageEvidenceTests(unittest.TestCase):
    def test_self_test(self):
        self.assertEqual(0, mod.self_test())

    def test_maintenance_toolset_authority_matches_product_runtime_contract(self):
        doc = json.loads((ROOT / "catalog" / "management-maintenance-toolset.json").read_text())
        self.assertEqual("MANAGEMENT_MAINTENANCE_TOOLSET_AUTHORITY_V1", doc["authority"])
        self.assertEqual("65532:65532", doc["defaultRuntimeUser"])
        self.assertTrue(doc["rootOverrideRequired"])
        self.assertFalse(doc["networkPackageInstallationAllowed"])
        self.assertEqual(
            {
                "aws","cat","cmp","cp","createdb","cut","dropdb","find","gunzip","gzip",
                "mkdir","pg_dump","pg_restore","psql","rm","sha256sum","tar","tr","wc",
            },
            set(doc["requiredExecutables"]),
        )

    def test_mutable_image_reference_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "REFERENCE_INVALID"):
            mod.exact_ref("platform.4so.local/management/platform-api:latest", "TEST")

    def test_false_runtime_probe_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "PROBE_INCOMPLETE"):
            mod.validate_probe({"execution": False}, {"execution"}, "TEST")

    def test_current_authorities_bind_external_receipt_to_plan(self):
        plan, external, toolset = mod.authorities(ROOT)
        self.assertEqual("MANAGEMENT_WORKLOAD_IMAGE_BUILD_PLAN_V5", plan["authority"])
        self.assertEqual("MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_RECEIPT_V1", external["authority"])
        self.assertEqual("MANAGEMENT_MAINTENANCE_TOOLSET_AUTHORITY_V1", toolset["authority"])


    def test_api_runtime_base_recipe_is_offline_composition(self):
        text = (ROOT / "deploy" / "images" / "Dockerfile.api-runtime-base").read_text()
        self.assertIn("ARG CA_RUNTIME_IMAGE", text)
        self.assertIn("ARG POSTGRES_RUNTIME_IMAGE", text)
        self.assertIn("COPY --from=ca /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt", text)
        self.assertIn("USER 65532:65532", text)
        lowered = text.lower()
        for forbidden in ("apt-get", "apt install", "apk add", "dnf install", "yum install", "curl http", "wget http"):
            self.assertNotIn(forbidden, lowered)

    def test_api_runtime_base_rejects_non_distroless_ca_authority(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "lab").mkdir()
            (root / "catalog").mkdir()
            plan = {
                "authority": "MANAGEMENT_WORKLOAD_IMAGE_BUILD_PLAN_V5",
                "schemaVersion": 5,
                "releaseVersion": "9.9.9",
            }
            plan_path = root / "lab" / "management-workload-image-build-plan.json"
            plan_path.write_text(json.dumps(plan))
            postgres_ref = "docker.io/library/postgres@sha256:" + "a" * 64
            external = {
                "authority": "MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_RECEIPT_V1",
                "offlineVerified": True,
                "planDigest": mod.digest(plan_path),
                "images": [{"role": "postgresql", "exactReference": postgres_ref}],
            }
            (root / "lab" / "management-workload-external-image-receipt.json").write_text(json.dumps(external))
            toolset = {
                "authority": "MANAGEMENT_MAINTENANCE_TOOLSET_AUTHORITY_V1",
                "schemaVersion": 1,
                "awsCli": {"repository": "public.ecr.aws/aws-cli/aws-cli", "version": "2.37.1"},
            }
            (root / "catalog" / "management-maintenance-toolset.json").write_text(json.dumps(toolset))
            payload = {
                "releaseArtifactDigest": "sha256:" + "b" * 64,
                "baseImages": [
                    {
                        "role": "api-runtime-base",
                        "exactReference": "platform.4so.local/management/api-runtime-base@sha256:" + "c" * 64,
                        "composition": {
                            "postgresqlSourceReference": postgres_ref,
                            "caSourceReference": "docker.io/library/debian@sha256:" + "d" * 64,
                        },
                        "compatibilityProbe": {"nonRoot": True, "dynamicDependencyClosure": True, "caTrust": True},
                    },
                    {
                        "role": "static-runtime-base",
                        "exactReference": "gcr.io/distroless/static-debian12@sha256:" + "e" * 64,
                        "compatibilityProbe": {"nonRoot": True, "agentExecution": True, "probeExecution": True, "caTrust": True},
                    },
                    {
                        "role": "maintenance-toolchain-base",
                        "exactReference": "platform.4so.local/management/maintenance-runtime-base@sha256:" + "f" * 64,
                        "composition": {
                            "postgresqlSourceReference": postgres_ref,
                            "awsCliSourceReference": "public.ecr.aws/aws-cli/aws-cli@sha256:" + "1" * 64,
                            "awsCliVersion": "2.37.1",
                        },
                        "compatibilityProbe": {"defaultNonRootToolset": True, "rootOverrideToolset": True, "postgresqlClientMajor": True, "awsCliVersion": True},
                    },
                ],
                "productImages": [],
            }
            input_path = root / "input.json"
            input_path.write_text(json.dumps(payload))
            with self.assertRaisesRegex(RuntimeError, "MANAGEMENT_API_BASE_CA_SOURCE_INVALID"):
                mod.seal(root, input_path, root / "receipt.json", "123")


if __name__ == "__main__":
    unittest.main()
