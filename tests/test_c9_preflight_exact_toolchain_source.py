import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SEAL_SPEC=importlib.util.spec_from_file_location("seal_final_exact_release_exact_toolchain_test",ROOT/"scripts"/"seal_final_exact_release.py")
sealer=importlib.util.module_from_spec(SEAL_SPEC); SEAL_SPEC.loader.exec_module(sealer)
PRE_SPEC=importlib.util.spec_from_file_location("c9_preflight_exact_toolchain_test",ROOT/"scripts"/"c9_preflight.py")
mod=importlib.util.module_from_spec(PRE_SPEC); PRE_SPEC.loader.exec_module(mod)


class C9PreflightExactToolchainSourceTests(unittest.TestCase):
    def admitted(self):
        return {
            "authority":sealer.admission.AUTHORITY,
            "admitted":True,
            "physicalCertified":False,
        }

    def ready_environment(self):
        return {
            "authority":sealer.ENVIRONMENT_PREFLIGHT_AUTHORITY,
            "ready":True,
            "requiredHost":"linux-amd64-exact-toolchain",
            "missingHostTools":[],
            "blockers":[],
            "physicalCertified":False,
        }

    def test_preflight_uses_exact_source_toolchain_lock_for_environment(self):
        source_sha="a"*40
        lock={"authority":sealer.TOOLCHAIN_AUTHORITY,"spec":{"admissionStatus":"admitted"}}
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            with (
                mock.patch.object(sealer,"git_source",return_value=source_sha),
                mock.patch.object(sealer,"exact_source_admission",return_value=self.admitted()),
                mock.patch.object(sealer,"exact_source_toolchain_lock",return_value=(lock,"sha256:"+"b"*64)) as lock_owner,
                mock.patch.object(sealer,"exact_release_environment_preflight",return_value=self.ready_environment()) as environment_owner,
            ):
                result=mod.preflight(root)
        lock_owner.assert_called_once_with(root,source_sha)
        environment_owner.assert_called_once_with(root,toolchain_lock=lock)
        self.assertTrue(result["ready"])
        self.assertEqual("RUN_C9_SEAL",result["nextActionCode"])

    def test_preflight_turns_exact_toolchain_source_failure_into_source_authority_handoff(self):
        source_sha="c"*40
        code="FINAL_EXACT_RELEASE_TOOLCHAIN_LOCK_SOURCE_OBJECT_INVALID"
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            with (
                mock.patch.object(sealer,"git_source",return_value=source_sha),
                mock.patch.object(sealer,"exact_source_admission",return_value=self.admitted()),
                mock.patch.object(sealer,"exact_source_toolchain_lock",side_effect=RuntimeError(code)),
                mock.patch.object(sealer,"exact_release_environment_preflight",side_effect=AssertionError("filesystem environment must not run when exact toolchain source is invalid")),
            ):
                result=mod.preflight(root)
        self.assertFalse(result["ready"])
        self.assertEqual([code],result["blockers"])
        self.assertEqual("INSPECT_C9_SOURCE_AUTHORITY",result["nextActionCode"])
        self.assertEqual([],result["requiredInputs"])
        self.assertEqual(["git","status","--short","--","lab/release-build-toolchain-lock.json"],result["nextCommand"])

    def test_toolchain_source_blocker_precedes_host_transition(self):
        result=mod.enrich({
            "authority":sealer.ENVIRONMENT_PREFLIGHT_AUTHORITY,
            "ready":False,
            "requiredHost":"linux-amd64-exact-toolchain",
            "missingHostTools":[],
            "blockers":[
                "FINAL_EXACT_RELEASE_LINUX_AMD64_HOST_REQUIRED",
                "FINAL_EXACT_RELEASE_TOOLCHAIN_AUTHORITY_INVALID",
            ],
            "physicalCertified":False,
        })
        self.assertEqual("INSPECT_C9_SOURCE_AUTHORITY",result["nextActionCode"])
        self.assertEqual([],result["requiredInputs"])
        self.assertEqual(["git","status","--short","--","lab/release-build-toolchain-lock.json"],result["nextCommand"])


if __name__=="__main__":
    unittest.main()
