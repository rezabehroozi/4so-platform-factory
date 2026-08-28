import copy
import subprocess
import json
import tempfile
import importlib.util
import sys
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
        self.assertEqual(9, sum(r["status"] == "ready-for-acquisition" for r in rows))

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

    def test_review_rows_remain_fail_closed_on_catalog_constraint(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        components = mod.unresolved_helm_components(ROOT)
        for row in rows:
            if row["status"] == "ready-for-acquisition":
                continue
            self.assertEqual(row["catalogConstraint"], components[row["component"]]["spec"]["release"])

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

    def test_acquisition_refuses_review_required_component_before_tool_or_network_use(self):
        proc = subprocess.run(
            ["python3", "scripts/acquire_upstream_helm.py", "--from-admission", "--component", "cilium"],
            cwd=ROOT, text=True, capture_output=True,
        )
        self.assertEqual(3, proc.returncode)
        self.assertIn("UPSTREAM_ADMISSION_NOT_READY cilium:dependency-review-required", proc.stderr)
        self.assertNotIn("HELM_REQUIRED", proc.stderr)

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
