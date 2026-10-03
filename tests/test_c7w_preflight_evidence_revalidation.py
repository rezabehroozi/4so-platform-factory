import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_preflight_evidence_revalidation",ROOT/"scripts"/"c7w_preflight.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WPreflightEvidenceRevalidationTests(unittest.TestCase):
    def test_existing_final_evidence_routes_through_status_before_git_handoff(self):
        source_sha="a"*40
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            lab=root/"lab"; lab.mkdir()
            progress=lab/mod.PROGRESS_REL.name; progress.write_text("{}\n",encoding="utf-8")
            evidence=lab/mod.EVIDENCE_REL.name; evidence.write_text("{}\n",encoding="utf-8")
            state=root/f".state/c7w-external-interop-{source_sha[:12]}"
            state.mkdir(parents=True)

            with (
                mock.patch.object(mod,"git_source_commit",return_value=source_sha),
                mock.patch.object(mod.runner,"git_handoff",side_effect=AssertionError("preflight must not bypass bulk status revalidation")),
            ):
                out=mod._existing_state_handoff(root)

        self.assertFalse(out["ready"])
        self.assertEqual("RUN_C7W_STATUS",out["nextActionCode"])
        self.assertEqual(mod.runner.runner_command(Path(f".state/c7w-external-interop-{source_sha[:12]}"),"status"),out["nextCommand"])
        self.assertIn("REVALIDATION",out["blockers"][0])


if __name__=="__main__":
    unittest.main()
