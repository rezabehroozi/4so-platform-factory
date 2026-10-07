import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_stale_complete_progress",ROOT/"scripts/run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(mod)


class StaleCompleteProgressRecoveryTests(unittest.TestCase):
    def args(self,root:Path,state:Path):
        progress=root/mod.CANONICAL_PROGRESS_REL
        progress.parent.mkdir(parents=True,exist_ok=True)
        progress.write_text("{}",encoding="utf-8")
        return SimpleNamespace(
            matrix=root/mod.CANONICAL_MATRIX_REL,
            state_dir=state,
            progress_out=progress,
            evidence_out=root/mod.CANONICAL_EVIDENCE_REL,
        )

    def complete(self):
        return {
            "certified":list(mod.core.CLIENTS),
            "missing":[],
            "complete":True,
            "nextClient":None,
            "campaignPrepared":True,
            "campaignId":"mcp-interop-stale",
            "sourceCommitSHA":"1"*40,
            "runtimeVersion":"test",
        }

    def test_tracked_stale_complete_progress_is_retired_before_rerun(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve(); state=root/".state/c7w-external-interop-stale"; state.mkdir(parents=True)
            args=self.args(root,state)
            with (
                mock.patch.object(mod,"progress_status",return_value=self.complete()),
                mock.patch.object(mod.core,"load",return_value={"sourceCommitSHA":"1"*40}),
                mock.patch.object(mod,"require_active_campaign_source",side_effect=RuntimeError("MCP_EXTERNAL_LOCAL_ACTIVE_CAMPAIGN_SOURCE_DELTA_NOT_EVIDENCE_ONLY")),
                mock.patch.object(mod,"complete_bulk_artifacts_present",return_value=True),
                mock.patch.object(mod.subprocess,"run",return_value=SimpleNamespace(returncode=0,stdout=str(mod.CANONICAL_PROGRESS_REL)+"\n")),
            ):
                with mock.patch.object(Path,"cwd",return_value=root):
                    out=mod.status(args)
        self.assertEqual("RETIRE_STALE_C7W_PROGRESS",out["nextActionCode"])
        self.assertEqual(["git","rm","-f","--",str(mod.CANONICAL_PROGRESS_REL)],out["nextCommand"])
        self.assertEqual(["git","commit","-m","evidence: retire stale complete MCP interoperability progress"],out["followupCommand"])
        self.assertEqual("scripts/c7w_preflight.py",out["rerunCommand"][1])
        self.assertEqual(str(root),out["rerunCommand"][-1])

    def test_untracked_stale_complete_progress_uses_scoped_git_clean(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve(); state=root/".state/c7w-external-interop-stale"; state.mkdir(parents=True)
            args=self.args(root,state)
            with (
                mock.patch.object(mod,"progress_status",return_value=self.complete()),
                mock.patch.object(mod.core,"load",return_value={"sourceCommitSHA":"1"*40}),
                mock.patch.object(mod,"require_active_campaign_source",side_effect=RuntimeError("MCP_EXTERNAL_LOCAL_ACTIVE_CAMPAIGN_SOURCE_DELTA_NOT_EVIDENCE_ONLY")),
                mock.patch.object(mod,"complete_bulk_artifacts_present",return_value=True),
                mock.patch.object(mod.subprocess,"run",return_value=SimpleNamespace(returncode=1,stdout="")),
            ):
                with mock.patch.object(Path,"cwd",return_value=root):
                    out=mod.status(args)
        self.assertEqual("RETIRE_STALE_C7W_PROGRESS",out["nextActionCode"])
        self.assertEqual(["git","clean","-f","--",str(mod.CANONICAL_PROGRESS_REL)],out["nextCommand"])
        self.assertNotIn("followupCommand",out)
        self.assertEqual("scripts/c7w_preflight.py",out["rerunCommand"][1])

    def test_stale_complete_progress_never_retires_without_bulk_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve(); state=root/".state/c7w-external-interop-stale"; state.mkdir(parents=True)
            args=self.args(root,state)
            with (
                mock.patch.object(mod,"progress_status",return_value=self.complete()),
                mock.patch.object(mod.core,"load",return_value={"sourceCommitSHA":"1"*40}),
                mock.patch.object(mod,"require_active_campaign_source",side_effect=RuntimeError("MCP_EXTERNAL_LOCAL_ACTIVE_CAMPAIGN_SOURCE_DELTA_NOT_EVIDENCE_ONLY")),
                mock.patch.object(mod,"complete_bulk_artifacts_present",return_value=False),
            ):
                with mock.patch.object(Path,"cwd",return_value=root):
                    out=mod.status(args)
        self.assertEqual("RESTORE_C7W_BULK_STATE",out["nextActionCode"])
        self.assertNotIn("git clean",str(out))
        self.assertNotIn("git rm",str(out))


if __name__=="__main__":
    unittest.main()
