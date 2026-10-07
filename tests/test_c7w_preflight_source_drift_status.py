import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_preflight_source_drift",ROOT/"scripts/c7w_preflight.py")
mod=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(mod)


class C7WPreflightSourceDriftStatusTests(unittest.TestCase):
    def test_stale_complete_evidence_routes_to_certified_state_status(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            certified="1"*40
            current="2"*40
            lab=root/"lab"; lab.mkdir()
            progress=lab/mod.PROGRESS_REL.name
            evidence=lab/mod.EVIDENCE_REL.name
            progress.write_text(json.dumps({"sourceCommitSHA":certified}),encoding="utf-8")
            evidence.write_text(json.dumps({"sourceCommitSHA":certified}),encoding="utf-8")
            state=root/f".state/c7w-external-interop-{certified[:12]}"
            state.mkdir(parents=True)
            with (
                mock.patch.object(mod,"git_source_commit",return_value=current),
                mock.patch.object(mod,"canonical_artifact_source_sha",side_effect=RuntimeError("MCP_EXTERNAL_PREFLIGHT_EVIDENCE_SOURCE_DELTA_NOT_EVIDENCE_ONLY")),
            ):
                out=mod._existing_state_handoff(root)
        self.assertEqual("RUN_C7W_STATUS",out["nextActionCode"])
        self.assertEqual(certified,out["certifiedSourceCommitSHA"])
        self.assertEqual(current,out["sourceCommitSHA"])
        self.assertEqual(str(Path(f".state/c7w-external-interop-{certified[:12]}")),out["stateDir"])
        self.assertEqual("status",out["nextCommand"][-1])

    def test_stale_incomplete_progress_routes_to_certified_state_status(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            certified="3"*40
            current="4"*40
            lab=root/"lab"; lab.mkdir()
            progress=lab/mod.PROGRESS_REL.name
            progress.write_text(json.dumps({"sourceCommitSHA":certified}),encoding="utf-8")
            state=root/f".state/c7w-external-interop-{certified[:12]}"
            state.mkdir(parents=True)
            with (
                mock.patch.object(mod,"git_source_commit",return_value=current),
                mock.patch.object(mod,"canonical_artifact_source_sha",side_effect=RuntimeError("MCP_EXTERNAL_PREFLIGHT_PROGRESS_SOURCE_DELTA_NOT_EVIDENCE_ONLY")),
            ):
                out=mod._existing_state_handoff(root)
        self.assertEqual("RUN_C7W_STATUS",out["nextActionCode"])
        self.assertEqual(certified,out["certifiedSourceCommitSHA"])
        self.assertEqual(current,out["sourceCommitSHA"])
        self.assertEqual("status",out["nextCommand"][-1])

    def test_stale_evidence_without_progress_never_routes_to_status(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            certified="5"*40
            current="6"*40
            lab=root/"lab"; lab.mkdir()
            evidence=lab/mod.EVIDENCE_REL.name
            evidence.write_text(json.dumps({"sourceCommitSHA":certified}),encoding="utf-8")
            state=root/f".state/c7w-external-interop-{certified[:12]}"
            state.mkdir(parents=True)
            with (
                mock.patch.object(mod,"git_source_commit",return_value=current),
                mock.patch.object(mod,"canonical_artifact_source_sha",side_effect=RuntimeError("MCP_EXTERNAL_PREFLIGHT_EVIDENCE_SOURCE_DELTA_NOT_EVIDENCE_ONLY")),
            ):
                out=mod._existing_state_handoff(root)
        self.assertEqual("INSPECT_C7W_CANONICAL_EVIDENCE",out["nextActionCode"])
        self.assertIn("MCP_EXTERNAL_CANONICAL_EVIDENCE_WITHOUT_PROGRESS",out["blockers"])
        self.assertNotIn("RUN_C7W_STATUS",json.dumps(out))


if __name__=="__main__":
    unittest.main()
