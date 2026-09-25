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
        self.assertTrue(all(r["status"] == "ready-for-acquisition" for r in rows))

    def test_named_source_authorities_survive_progressive_acquisition(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        by_name = {r["component"]: r for r in rows}
        components = {}
        for path in (ROOT / "catalog/components").glob("*.json"):
            doc=json.loads(path.read_text()); components[doc["metadata"]["name"]]=doc["spec"]
        expected = {
            "ceph-csi-rbd": ("1.0.4", "https://ceph.github.io/ceph-csi-operator/"),
            "loki": ("18.12.1", "https://grafana-community.github.io/helm-charts"),
            "cilium": ("1.20.1", "https://helm.cilium.io"),
            "grafana": ("12.10.0", "https://grafana-community.github.io/helm-charts"),
        }
        for name,(version,source) in expected.items():
            spec=components[name]
            self.assertEqual(version,spec["release"])
            if spec["source"]["resolved"]:
                self.assertNotIn(name,by_name)
                self.assertTrue((ROOT / "catalog/runtime" / name / version / "source-lock.json").is_file())
            else:
                self.assertEqual(source,by_name[name]["source"])
                self.assertEqual(version,by_name[name]["selectedVersion"])
                self.assertEqual("ready-for-acquisition",by_name[name]["status"])

    def test_runtime_suitability_holds_persist_independent_of_source_acquisition(self):
        registry=json.loads((ROOT/"catalog/component-runtime-certification.json").read_text())
        holds={r["component"]:r for r in registry["spec"]["runtimeSuitabilityHolds"]}
        self.assertEqual({"cilium","kyverno","metallb"},set(holds))
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        by_name={r["component"]:r for r in rows}
        for name,hold in holds.items():
            spec=json.loads((ROOT/"catalog/components"/f"{name}.json").read_text())["spec"]
            self.assertIn(hold["status"],{"dependency-transition-required","review-required"})
            self.assertEqual("candidate",spec["certification"]["status"])
            if spec["source"]["resolved"]:
                self.assertNotIn(name,by_name)
                self.assertTrue(spec["source"]["sourceLockDigest"].startswith("sha256:"))
            else:
                self.assertEqual("ready-for-acquisition",by_name[name]["status"])
                self.assertEqual(hold["status"],by_name[name]["runtimeStatus"])

    def test_ready_rows_are_exact_pins_and_carry_license_authority(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        components = mod.unresolved_helm_components(ROOT)
        for row in rows:
            self.assertEqual("ready-for-acquisition", row["status"])
            comp = components[row["component"]]["spec"]
            self.assertEqual(row["selectedVersion"], comp["release"])
            self.assertFalse(comp["source"]["resolved"])
            self.assertEqual("", comp["source"]["sourceLockDigest"])
            self.assertRegex(str(row.get("licenseSPDX") or ""), r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
            for value in row.get("valuesFiles") or []:
                self.assertTrue((ROOT/value).is_file(), value)

    def test_live_admission_applies_canonical_license_and_values(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        self.assertTrue(rows)
        row=rows[0]
        from types import SimpleNamespace
        args = SimpleNamespace(from_upgrade_admission=False, historical=False, from_admission=True, component=row["component"], authority=str(ROOT / "catalog" / "upstream-admission.json"), version=None, source=None, upstream_version=None, license_spdx=None, values=[])
        acquire_mod.apply_admission(args)
        self.assertEqual(row["licenseSPDX"], args.license_spdx)
        self.assertEqual(row.get("valuesFiles") or [], [str(v) for v in args.values])

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
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        ready = [r for r in rows if r["status"] == "ready-for-acquisition"]
        self.assertEqual(len(rows), len(ready))
        for row in ready:
            self.assertRegex(
                str(row.get("licenseSPDX") or ""),
                r"^[A-Za-z0-9][A-Za-z0-9.+-]*$",
            )

    def test_live_license_and_values_override_is_canonical_and_applied(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        self.assertTrue(rows)
        row = rows[0]
        from types import SimpleNamespace

        args = SimpleNamespace(
            from_upgrade_admission=False,
            historical=False,
            from_admission=True,
            component=row["component"],
            authority=str(ROOT / "catalog" / "upstream-admission.json"),
            version=None,
            source=None,
            upstream_version=None,
            license_spdx=None,
            values=[],
        )
        acquire_mod.apply_admission(args)
        self.assertEqual(row["licenseSPDX"], args.license_spdx)
        self.assertEqual(row.get("valuesFiles") or [], [str(v) for v in args.values])

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
        self.assertRegex(
            proc.stderr,
            r"ACQUISITION_TOOLCHAIN_(?:TOOL_MISSING|VERSION_MISMATCH)",
            "the source-admission check must pass before the exact acquisition toolchain fails closed",
        )

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
)

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
        self.assertRegex(
            proc.stderr,
            r"ACQUISITION_TOOLCHAIN_(?:TOOL_MISSING|VERSION_MISMATCH)",
            "the source-admission check must pass before the exact acquisition toolchain fails closed",
        )

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
)

    def test_live_license_and_values_override_is_canonical_and_applied(self):
        _, rows = mod.validate(ROOT, ROOT / "catalog" / "upstream-admission.json")
        self.assertTrue(rows)
        row = rows[0]
        from types import SimpleNamespace
        args = SimpleNamespace(from_upgrade_admission=False, historical=False, from_admission=True, component=row["component"], authority=str(ROOT / "catalog" / "upstream-admission.json"), version=None, source=None, upstream_version=None, license_spdx=None, values=[])
        acquire_mod.apply_admission(args)
        self.assertEqual(row["licenseSPDX"], args.license_spdx)
        self.assertEqual(row.get("valuesFiles") or [], [str(v) for v in args.values])

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
        self.assertRegex(
            proc.stderr,
            r"ACQUISITION_TOOLCHAIN_(?:TOOL_MISSING|VERSION_MISMATCH)",
            "the source-admission check must pass before the exact acquisition toolchain fails closed",
        )

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
)

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
        self.assertRegex(
            proc.stderr,
            r"ACQUISITION_TOOLCHAIN_(?:TOOL_MISSING|VERSION_MISMATCH)",
            "the source-admission check must pass before the exact acquisition toolchain fails closed",
        )

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
