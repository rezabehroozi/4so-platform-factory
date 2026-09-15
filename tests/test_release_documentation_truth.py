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

    def test_program_status_version_mismatch_is_rejected(self):
        temp, root = self.fixture()
        with temp:
            (root / 'docs/PROGRAM_STATUS.md').write_text('# Current Program Status - PROGRAM_PHASE_MODEL_V57\nRelease **0.0.350**\n', encoding='utf-8')
            self.assertIn('CURRENT_PROGRAM_STATUS_VERSION_MISMATCH', [code for code, _ in self.validate(root)])


if __name__ == '__main__':
    unittest.main()
