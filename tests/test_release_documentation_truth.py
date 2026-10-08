import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validate_repository", ROOT / "scripts" / "validate_repository.py")
VALIDATE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(VALIDATE)


class ReleaseDocumentationTruthTest(unittest.TestCase):
    def fixture(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        (root / "internal/targetmodel").mkdir(parents=True)
        (root / "docs").mkdir()
        (root / "internal/targetmodel/program.go").write_text('package targetmodel\nconst ProgramAuthorityMethod = "PROGRAM_PHASE_MODEL_V57"\n', encoding="utf-8")
        (root / "docs/PROGRAM_STATUS.md").write_text('# Current Program Status - PROGRAM_PHASE_MODEL_V57\nRelease **0.0.351**\n', encoding="utf-8")
        (root / "README.md").write_text('PROGRAM_PHASE_MODEL_V57\nCurrent status: `docs/PROGRAM_STATUS.md`.\n', encoding="utf-8")
        (root / "CHANGELOG.md").write_text('# Changelog\n\n## 0.0.351 - current\n\n## 0.0.350 - old\n', encoding="utf-8")
        return temp, root

    def validate(self, root):
        errors = []
        VALIDATE.validate_release_documentation_truth(root, '0.0.351', 'release-truth-v57', errors)
        return errors

    def test_current_surfaces_converge(self):
        temp, root = self.fixture()
        with temp:
            self.assertEqual(self.validate(root), [])

    def test_missing_current_readme_status_link_is_rejected(self):
        temp, root = self.fixture()
        with temp:
            (root / 'README.md').write_text('PROGRAM_PHASE_MODEL_V57\n', encoding='utf-8')
            self.assertIn('CURRENT_README_PROGRAM_STATUS_LINK_MISSING', [code for code, _ in self.validate(root)])

    def test_stale_top_changelog_is_rejected(self):
        temp, root = self.fixture()
        with temp:
            (root / 'CHANGELOG.md').write_text('# Changelog\n\n## 0.0.350 - stale\n', encoding='utf-8')
            self.assertIn('CURRENT_CHANGELOG_TOP_VERSION_MISMATCH', [code for code, _ in self.validate(root)])

    def test_missing_current_program_status_is_rejected(self):
        temp, root = self.fixture()
        with temp:
            (root / 'docs/PROGRAM_STATUS.md').unlink()
            self.assertIn('CURRENT_PROGRAM_STATUS_MISSING', [code for code, _ in self.validate(root)])

    def test_program_status_authority_mismatch_is_rejected(self):
        temp, root = self.fixture()
        with temp:
            (root / 'docs/PROGRAM_STATUS.md').write_text('# wrong\nRelease **0.0.351**\n', encoding='utf-8')
            self.assertIn('CURRENT_PROGRAM_STATUS_AUTHORITY_MISMATCH', [code for code, _ in self.validate(root)])

    def test_core_closure_workflow_mutation_authority_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for rel in VALIDATE.CORE_LOCAL_ONLY_WORKFLOWS:
                path=root/rel
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text(
                    "name: local-only\n\non:\n  workflow_dispatch:\n\npermissions:\n  contents: read\n\njobs:\n  local-only-authority-notice:\n    runs-on: ubuntu-latest\n",
                    encoding="utf-8",
                )
            errors=[]
            VALIDATE.validate_core_local_only_workflows(root,errors)
            self.assertEqual([],errors)

            drift=root/VALIDATE.CORE_LOCAL_ONLY_WORKFLOWS[0]
            drift.write_text(drift.read_text(encoding="utf-8")+"\n# regression\npermissions:\n  contents: write\n",encoding="utf-8")
            errors=[]
            VALIDATE.validate_core_local_only_workflows(root,errors)
            self.assertIn("CORE_LOCAL_ONLY_WORKFLOW_MUTATION_FORBIDDEN",[code for code,_ in errors])

            drift.write_text(
                "name: stale-local-only\n\non:\n  workflow_dispatch:\n\npermissions:\n  contents: read\n\njobs:\n  local-only-authority-notice:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo make c7w-status /secure/client.capture.json\n",
                encoding="utf-8",
            )
            errors=[]
            VALIDATE.validate_core_local_only_workflows(root,errors)
            stale=[detail for code,detail in errors if code=="CORE_LOCAL_ONLY_WORKFLOW_STALE_HANDOFF"]
            self.assertEqual(2,len(stale))
            self.assertTrue(any("make c7w-" in detail for detail in stale))
            self.assertTrue(any("/secure/" in detail for detail in stale))

    def test_remote_ci_repository_mutation_authority_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            workflows=root/'.github'/'workflows'
            workflows.mkdir(parents=True)
            (workflows/'read-only.yml').write_text("permissions:\n  contents: read\n",encoding='utf-8')
            errors=[]
            VALIDATE.validate_no_remote_ci_mutation_authority(root,errors)
            self.assertEqual([],errors)

            (workflows/'writer.yml').write_text("permissions:\n  contents :   write   # forbidden\njobs:\n  writer:\n    steps:\n      - run: git   push origin HEAD:main\n",encoding='utf-8')
            (workflows/'write-all.yml').write_text("permissions: write-all\n",encoding='utf-8')
            (workflows/'inline-write.yml').write_text("permissions: { contents: write, issues: read }\n",encoding='utf-8')
            errors=[]
            VALIDATE.validate_no_remote_ci_mutation_authority(root,errors)
            blocked=[detail for code,detail in errors if code=='REMOTE_CI_MUTATION_AUTHORITY_FORBIDDEN']
            self.assertEqual(4,len(blocked))
            self.assertTrue(any(detail.endswith(':contents-write') for detail in blocked))
            self.assertTrue(any(detail.endswith(':inline-contents-write') for detail in blocked))
            self.assertTrue(any(detail.endswith(':git-push') for detail in blocked))
            self.assertTrue(any(detail.endswith(':write-all') for detail in blocked))

    def test_windows_local_execution_contract_gate_rejects_drift(self):
        errors=[]
        VALIDATE.validate_windows_local_execution_contract(ROOT,errors)
        self.assertEqual([],errors)

        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for rel,required in VALIDATE.WINDOWS_LOCAL_EXECUTION_CONTRACTS.items():
                path=root/rel
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text("\n".join(required)+"\n",encoding="utf-8")
            errors=[]
            VALIDATE.validate_windows_local_execution_contract(root,errors)
            self.assertEqual([],errors)

            broken=root/"scripts/run_smoke_shard.py"
            broken.write_text("CREATE_NEW_PROCESS_GROUP\n",encoding="utf-8")
            errors=[]
            VALIDATE.validate_windows_local_execution_contract(root,errors)
            self.assertIn("WINDOWS_LOCAL_EXECUTION_CONTRACT_DRIFT",[code for code,_ in errors])

    def test_windows_local_c7w_contract_tracks_root_aware_c9_handoff(self):
        required=VALIDATE.WINDOWS_LOCAL_EXECUTION_CONTRACTS["scripts/run_mcp_external_interop.py"]
        self.assertIn('def c9_handoff(source_sha:str,root:Path|None=None)->dict:',required)
        self.assertIn('def c9_preflight_command(root:Path|None=None)->list[str]:',required)
        self.assertNotIn('def c9_handoff(source_sha:str)->dict:',required)
        self.assertNotIn('def c9_preflight_command()->list[str]:',required)

    def test_program_status_version_mismatch_is_rejected(self):
        temp, root = self.fixture()
        with temp:
            (root / 'docs/PROGRAM_STATUS.md').write_text('# Current Program Status - PROGRAM_PHASE_MODEL_V57\nRelease **0.0.350**\n', encoding='utf-8')
            self.assertIn('CURRENT_PROGRAM_STATUS_VERSION_MISMATCH', [code for code, _ in self.validate(root)])


if __name__ == '__main__':
    unittest.main()
