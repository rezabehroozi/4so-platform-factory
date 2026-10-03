import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=str(ROOT/"scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0,SCRIPTS)
SPEC=importlib.util.spec_from_file_location("seal_final_exact_release_native_order_test",ROOT/"scripts/seal_final_exact_release.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9NativeAdmissionOrderTests(unittest.TestCase):
    def test_fresh_execute_checks_final_admission_before_host_or_environment(self):
        source_sha="a"*40
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            out=root/"lab/final-exact-release-evidence.json"
            with (
                mock.patch.object(mod,"git_source",return_value=source_sha),
                mock.patch.object(mod,"exact_source_admission",side_effect=mod.admission.Pending("MCP_EXTERNAL_INTEROP_PENDING")) as admission_call,
                mock.patch.object(mod,"require_exact_release_host",side_effect=AssertionError("host must not run before final admission")) as host_call,
                mock.patch.object(mod,"require_exact_release_environment",side_effect=AssertionError("environment must not run before final admission")) as environment_call,
            ):
                with self.assertRaisesRegex(mod.admission.Pending,"MCP_EXTERNAL_INTEROP_PENDING"):
                    mod.execute(root,out)
            admission_call.assert_called_once_with(root.resolve(),source_sha)
            host_call.assert_not_called()
            environment_call.assert_not_called()

    def test_resume_checks_final_admission_before_host_or_environment(self):
        source_sha="b"*40
        digest="sha256:"+"c"*64
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/"VERSION").write_text("0.0.1\n",encoding="utf-8")
            (root/"RELEASE-NAME").write_text("test\n",encoding="utf-8")
            out=root/"lab/final-exact-release-evidence.json"; out.parent.mkdir(parents=True)
            release_name="4so-platform-factory-0.0.1-test.zip"
            evidence={
                "apiVersion":"platform.4so.io/v1alpha1",
                "kind":"FinalExactReleaseEvidence",
                "authority":mod.AUTHORITY,
                "sourceExecutionAuthority":mod.EXECUTION_AUTHORITY,
                "sourceWorkspaceAuthority":mod.SOURCE_WORKSPACE_AUTHORITY,
                "sourceCommitSHA":source_sha,
                "version":"0.0.1",
                "releaseName":"test",
                "releaseArchive":release_name,
                "releaseArchivePath":f"release/exact-sha/{source_sha}/{release_name}",
                "releaseArchiveSha256":digest,
                "releaseArchiveBytes":1,
                "artifactManifestSha256":digest,
                "buildProvenanceSha256":digest,
                "sbomSha256":digest,
                "admissionAuthority":mod.admission.AUTHORITY,
                "applianceDistributionSha256":digest,
                "mcpExternalInteropSha256":digest,
                "fullVerifierAuthority":mod.FULL_VERIFIER_AUTHORITY,
                "fullVerifierPass":True,
                "physicalCertified":False,
            }
            self.assertEqual(set(evidence),mod.FINAL_EVIDENCE_KEYS)
            out.write_text(json.dumps(evidence),encoding="utf-8")
            with (
                mock.patch.object(mod,"git_source_for_resume",return_value=source_sha),
                mock.patch.object(mod,"validate_final_evidence_lineage"),
                mock.patch.object(mod,"exact_source_admission",side_effect=mod.admission.Pending("MCP_EXTERNAL_INTEROP_PENDING")) as admission_call,
                mock.patch.object(mod,"require_exact_release_host",side_effect=AssertionError("host must not run before final admission")) as host_call,
                mock.patch.object(mod,"require_exact_release_environment",side_effect=AssertionError("environment must not run before final admission")) as environment_call,
            ):
                with self.assertRaisesRegex(mod.admission.Pending,"MCP_EXTERNAL_INTEROP_PENDING"):
                    mod.resume_existing_evidence(root,out)
            admission_call.assert_called_once_with(root,source_sha)
            host_call.assert_not_called()
            environment_call.assert_not_called()

    def test_admission_result_must_be_exact_authority_and_non_physical(self):
        valid={"authority":mod.admission.AUTHORITY,"admitted":True,"physicalCertified":False}
        self.assertIs(mod.require_valid_final_admission(valid),valid)
        for patch in (
            {"authority":"wrong"},
            {"admitted":False},
            {"physicalCertified":True},
        ):
            candidate=dict(valid); candidate.update(patch)
            with self.assertRaisesRegex(RuntimeError,"FINAL_EXACT_RELEASE_ADMISSION_INVALID"):
                mod.require_valid_final_admission(candidate)


if __name__=="__main__":
    unittest.main()
