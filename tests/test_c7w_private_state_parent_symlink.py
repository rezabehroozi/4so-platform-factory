import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]


def load(name,relative):
    spec=importlib.util.spec_from_file_location(name,ROOT/relative)
    mod=importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


preflight=load("c7w_preflight_parent_symlink",Path("scripts/c7w_preflight.py"))
reconcile=load("c7w_reconcile_parent_symlink",Path("scripts/reconcile_c7w_trusted_clients.py"))
runner=load("c7w_runner_parent_symlink",Path("scripts/run_mcp_external_interop.py"))


class C7WPrivateStateParentSymlinkTests(unittest.TestCase):
    def fixture(self):
        td=tempfile.TemporaryDirectory()
        root=Path(td.name).resolve()
        private=root/".state/private"
        private.mkdir(parents=True)
        oauth=private/"oauth.json"
        oauth.write_text("{}",encoding="utf-8")
        return td,root,oauth

    def symlinked_state(self,root):
        original=Path.is_symlink
        state=(root/".state").resolve()
        def fake(path):
            candidate=Path(path)
            return candidate.resolve()==state or original(candidate)
        return mock.patch.object(Path,"is_symlink",fake)

    def test_preflight_rejects_symlinked_state_parent(self):
        td,root,oauth=self.fixture()
        with td,self.symlinked_state(root):
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_PRIVATE_INPUT_PATH_INVALID"):
                preflight.private_input_path(root,oauth)

    def test_trusted_client_reconcile_rejects_symlinked_state_parent(self):
        td,root,oauth=self.fixture()
        with td,self.symlinked_state(root):
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_PRIVATE_INPUT_PATH_INVALID"):
                reconcile._private_oauth_map(root,oauth)

    def test_runner_status_rejects_symlinked_state_parent(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            state=root/".state/c7w"
            state.mkdir(parents=True)
            args=SimpleNamespace(
                matrix=runner.CANONICAL_MATRIX_REL,
                state_dir=state,
                progress_out=root/"progress.json",
                evidence_out=root/"evidence.json",
            )
            value={
                "certified":[],
                "missing":list(runner.core.CLIENTS),
                "complete":False,
                "nextClient":runner.core.CLIENTS[0],
                "campaignPrepared":True,
            }
            with self.symlinked_state(root),mock.patch.object(runner,"progress_status",return_value=value):
                with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_STATE_PARENT_INVALID"):
                    runner.status(args)

    def test_preflight_existing_state_rejects_symlinked_state_parent_handoff(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            source_sha="a"*40
            state=root/f".state/c7w-external-interop-{source_sha[:12]}"
            state.mkdir(parents=True)
            with self.symlinked_state(root),mock.patch.object(preflight,"git_source_commit",return_value=source_sha):
                out=preflight._existing_state_handoff(root)
            self.assertIsNotNone(out)
            self.assertEqual(["MCP_EXTERNAL_LOCAL_STATE_DIR_INVALID"],out["blockers"])
            self.assertEqual("INSPECT_C7W_LOCAL_STATE",out["nextActionCode"])


if __name__=="__main__":
    unittest.main()
